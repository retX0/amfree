/*
 * debugserver.c — Spawn debugserver, connect via RSP, thread-hijack.
 */
#include "inject.h"
#include "shellcode/data_layout.h"
#include "mach_utils.h"
#include "rsp.h"

#include <fcntl.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define DEBUGSERVER_SUFFIX                                                     \
  "SharedFrameworks/LLDB.framework/Versions/A/Resources/debugserver"

#define DEBUGSERVER_FALLBACK                                                   \
  "/Applications/Xcode.app/Contents/" DEBUGSERVER_SUFFIX

#define RSP_PORT 23479

/* Resolve debugserver from the active Xcode, falling back to the hardcoded path. */
static int resolve_debugserver(char *path, size_t path_sz) {
  char developer_dir[1024];
  int wrote;
  FILE *fp = popen("/usr/bin/xcode-select -p 2>/dev/null", "r");
  if (fp) {
    int got = fgets(developer_dir, sizeof(developer_dir), fp) != NULL;
    pclose(fp);

    if (got) {
      developer_dir[strcspn(developer_dir, "\n")] = '\0';
      wrote = snprintf(path, path_sz, "%s/../%s", developer_dir, DEBUGSERVER_SUFFIX);
      if (wrote >= 0 && (size_t)wrote < path_sz && access(path, X_OK) == 0)
        return 0;
    }
  }

  wrote = snprintf(path, path_sz, "%s", DEBUGSERVER_FALLBACK);
  if (wrote < 0 || (size_t)wrote >= path_sz)
    return -1;

  return access(path, X_OK) == 0 ? 0 : -1;
}

/* ==== Step 4: Spawn debugserver ==== */
int spawn_debugserver(inject_ctx_t *ctx, pid_t *ds_pid) {
  char ds_path[1024];
  char pid_arg[32], port_arg[32];
  if (resolve_debugserver(ds_path, sizeof(ds_path)) < 0) {
    fprintf(stderr,
            "[-] could not locate executable debugserver (last checked: %s)\n",
            ds_path);
    return -1;
  }

  snprintf(pid_arg, sizeof(pid_arg), "--attach=%d", ctx->pid);
  snprintf(port_arg, sizeof(port_arg), "localhost:%d", RSP_PORT);

  *ds_pid = fork();
  if (*ds_pid == 0) {
    int devnull = open("/dev/null", O_RDWR);
    dup2(devnull, STDOUT_FILENO);
    dup2(devnull, STDERR_FILENO);
    close(devnull);
    execl(ds_path, "debugserver", port_arg, pid_arg, NULL);
    _exit(127);
  }
  if (*ds_pid < 0) {
    perror("[-] fork");
    return -1;
  }
  VLOG("[*] debugserver pid: %d\n", *ds_pid);
  return 0;
}

/* ==== Steps 5-8: Connect, hijack thread, install hook, resume ==== */
int hijack_and_install(inject_ctx_t *ctx, pid_t ds_pid) {
  char rsp_buf[65536];
  char *saved_copy = NULL;
  int ret = -1;

  int sock = rsp_connect(RSP_PORT);
  if (sock < 0) {
    fprintf(stderr, "[-] connect failed\n");
    return -1;
  }
  VLOG("[*] connected\n");

  usleep(200000);
  rsp_send(sock, "QStartNoAckMode");
  rsp_recv(sock, rsp_buf, sizeof(rsp_buf));

  rsp_send(sock, "?");
  char *reply = rsp_recv(sock, rsp_buf, sizeof(rsp_buf));
  if (!reply || reply[0] != 'T') {
    fprintf(stderr, "[-] stop query failed\n");
    goto cleanup;
  }
  VLOG("[*] amfid stopped\n");

  /* Abort all threads out of any Mach traps (e.g. mach_msg_receive).
   * Without this, setting PC via RSP has no effect because the thread
   * remains blocked in the kernel and never returns to userspace. */
  {
    thread_act_array_t threads;
    mach_msg_type_number_t tcount;
    kern_return_t tkr = task_threads(ctx->task, &threads, &tcount);
    if (tkr == KERN_SUCCESS) {
      for (mach_msg_type_number_t i = 0; i < tcount; i++) {
        thread_abort_safely(threads[i]);
        mach_port_deallocate(mach_task_self(), threads[i]);
      }
      vm_deallocate(mach_task_self(), (vm_address_t)threads,
                    tcount * sizeof(thread_t));
      VLOG("[*] aborted %u threads from kernel traps\n", tcount);
    }
  }

  /* Save registers */
  rsp_send(sock, "g");
  char *saved_regs = rsp_recv(sock, rsp_buf, sizeof(rsp_buf));
  if (!saved_regs) {
    fprintf(stderr, "[-] read regs failed\n");
    goto cleanup;
  }
  saved_copy = strdup(saved_regs);

  /* Write type encoding */
  kern_return_t kr = remote_write(ctx->task, ctx->data_page + DP_TYPE_ENCODING,
                                  ctx->type_enc, strlen(ctx->type_enc) + 1);
  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "[-] write type_enc failed\n");
    goto cleanup;
  }

  /* Set registers for class_replaceMethod(cls, sel, imp, types) */
  rsp_set_reg(sock, 0x00, ctx->cls, rsp_buf, sizeof(rsp_buf));
  rsp_set_reg(sock, 0x01, ctx->sel, rsp_buf, sizeof(rsp_buf));
  rsp_set_reg(sock, 0x02, (uint64_t)ctx->code_page, rsp_buf, sizeof(rsp_buf));
  rsp_set_reg(sock, 0x03, (uint64_t)ctx->data_page + 0x100, rsp_buf, sizeof(rsp_buf));
  rsp_set_reg(sock, 0x08, (uint64_t)(uintptr_t)ctx->fn_replace, rsp_buf, sizeof(rsp_buf));
  rsp_set_reg(sock, 0x20, (uint64_t)ctx->code_page + ctx->setup_offset, rsp_buf, sizeof(rsp_buf));
  rsp_set_reg(sock, 0x1e, (uint64_t)ctx->code_page + ctx->brk_offset, rsp_buf, sizeof(rsp_buf));
  rsp_set_reg(sock, 0x1f, (uint64_t)ctx->data_page + PAGE_SIZE - 256, rsp_buf, sizeof(rsp_buf));
  VLOG("[*] registers set, pc → setup code\n");

  /* Continue and let setup code run (paciza + blr + b . — three insns). */
  uint64_t brk_addr = (uint64_t)ctx->code_page + ctx->setup_offset + 8;

  rsp_send(sock, "c");
  usleep(100000);  /* 100ms is plenty for three instructions + class_replaceMethod */

  char ctrl_c = 0x03;
  write(sock, &ctrl_c, 1);
  reply = rsp_recv(sock, rsp_buf, sizeof(rsp_buf));
  if (!reply) {
    fprintf(stderr, "[-] no stop reply\n");
    goto cleanup;
  }

  rsp_send(sock, "p20");
  reply = rsp_recv(sock, rsp_buf, sizeof(rsp_buf));
  uint64_t stop_pc = reply ? rsp_decode_u64(reply) : 0;

  if (stop_pc != brk_addr) {
    fprintf(stderr, "[-] setup code did not reach spin loop "
                    "(pc=0x%llx, expected=0x%llx)\n",
            stop_pc, brk_addr);
    goto cleanup;
  }
  VLOG("[*] pc = 0x%llx (spin @ 0x%llx) OK\n", stop_pc, brk_addr);

  /* Read return value */
  rsp_send(sock, "p0");
  reply = rsp_recv(sock, rsp_buf, sizeof(rsp_buf));
  uint64_t ret_imp = reply ? rsp_decode_u64(reply) : 0;
  VLOG("[*] class_replaceMethod returned: 0x%llx\n", ret_imp);

  /* Write original IMP to data_page[8] */
  kr = remote_write(ctx->task, ctx->data_page + DP_OFF(orig_imp), &ctx->orig_imp, sizeof(ctx->orig_imp));
  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "[-] write old IMP failed\n");
    goto cleanup;
  }

  ret = 0;

cleanup:
  /* Restore registers */
  if (saved_copy) {
    size_t gl = 1 + strlen(saved_copy) + 1;
    char *gcmd = malloc(gl);
    snprintf(gcmd, gl, "G%s", saved_copy);
    rsp_send(sock, gcmd);
    free(gcmd);
    char *g_reply = rsp_recv(sock, rsp_buf, sizeof(rsp_buf));
    VLOG("[*] G reply: %s\n", g_reply ? g_reply : "NULL");
  }

  /* Detach + kill debugserver.
   * CS_DEBUGGED is a sticky flag in XNU — ptrace(PT_DETACH)
   * does not clear it, so the hook remains executable. */
  rsp_send(sock, "D");
  rsp_recv(sock, rsp_buf, sizeof(rsp_buf));
  kill(ds_pid, SIGKILL);
  waitpid(ds_pid, NULL, 0);
  VLOG("[*] debugserver detached and killed\n");

  free(saved_copy);
  close(sock);
  return ret;
}
