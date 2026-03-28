/*
 * main.c — Entry point for amfid bypass injector.
 *
 * Usage:
 *   sudo amfree --path <dir>          Install hook or update allowlist
 *   sudo amfree --list                List currently allowed paths
 */
#include "allowlist.h"
#include "inject.h"
#include "mach_utils.h"
#include "remote_macho.h"

#include <fcntl.h>
#include <getopt.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int g_verbose = 0;

static void save_state(inject_ctx_t *ctx) {
  FILE *fp = fopen(STATE_FILE, "w");
  if (fp) {
    fprintf(fp, "pid=%d\ndata_page=0x%llx\ncode_page=0x%llx\nold_imp=0x%llx\n",
            ctx->pid, (uint64_t)ctx->data_page, (uint64_t)ctx->code_page, ctx->orig_imp);
    fclose(fp);
    printf("[+] state -> %s\n", STATE_FILE);
  }
}

static int cmd_install(const char *allowlist, size_t al_len) {
  inject_ctx_t ctx = {0};
  ctx.pid = find_amfid_pid();
  if (ctx.pid < 0) {
    fprintf(stderr, "[-] amfid not found\n");
    return 1;
  }
  VLOG("[*] amfid pid: %d\n", ctx.pid);

  kern_return_t kr = task_for_pid(mach_task_self(), ctx.pid, &ctx.task);
  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "[-] task_for_pid: %s\n", mach_error_string(kr));
    return 1;
  }

  if (resolve_objc(&ctx) < 0) return 1;
  if (build_code_page(&ctx, al_len > 0 ? allowlist : NULL, al_len) < 0) return 1;

  pid_t ds_pid = -1;
  if (spawn_debugserver(&ctx, &ds_pid) < 0) return 1;
  if (hijack_and_install(&ctx, ds_pid) < 0) return 1;

  printf("\n[+] hook installed!\n");
  printf("[+] code page: 0x%llx\n", (uint64_t)ctx.code_page);
  printf("[+] data page: 0x%llx\n", (uint64_t)ctx.data_page);

  save_state(&ctx);
  return 0;
}

int main(int argc, char **argv) {
  static struct option long_options[] = {
      {"path",         required_argument, NULL, 'p'},
      {"list",         no_argument,       NULL, 'l'},
      {"verbose",      no_argument,       NULL, 'v'},
      {"hook-verbose", required_argument, NULL, 'V'},
      {"help",         no_argument,       NULL, 'h'},
      {NULL, 0, NULL, 0}
  };

  char allowlist_buf[4096] = {0};
  size_t al_len = 0;
  int do_list = 0;
  int set_hook_verbose = -1;  /* -1 = not requested, 0 = off, 1 = on */
  int opt;

  while ((opt = getopt_long(argc, argv, "p:lvh", long_options, NULL)) != -1) {
    switch (opt) {
    case 'p': {
      size_t plen = strlen(optarg);
      if (al_len + plen + 1 < sizeof(allowlist_buf)) {
        memcpy(allowlist_buf + al_len, optarg, plen);
        al_len += plen;
        allowlist_buf[al_len++] = '\n';
      }
      break;
    }
    case 'l':
      do_list = 1;
      break;
    case 'v':
      g_verbose = 1;
      break;
    case 'V':
      if (strcmp(optarg, "on") == 0 || strcmp(optarg, "1") == 0)
        set_hook_verbose = 1;
      else if (strcmp(optarg, "off") == 0 || strcmp(optarg, "0") == 0)
        set_hook_verbose = 0;
      else {
        fprintf(stderr, "[-] --hook-verbose expects 'on' or 'off'\n");
        return 1;
      }
      break;
    case 'h':
    default:
      printf("Usage: %s [-v] [--path <dir>]... [--list] [--hook-verbose on|off]\n\n"
             "  -p, --path <dir>        Allow binaries under <dir> to bypass AMFI.\n"
             "                          Updates in-place if hook is already active.\n"
             "  -l, --list              List currently allowed paths.\n"
             "      --hook-verbose V    Set hook verbose logging (on/off).\n"
             "  -v, --verbose           Print detailed debug information.\n",
             argv[0]);
      return opt == 'h' ? 0 : 1;
    }
  }

  /* Reject unknown trailing positional arguments */
  if (optind < argc) {
    fprintf(stderr, "[-] unexpected argument '%s'\n", argv[optind]);
    return 1;
  }

  if (do_list)
    return allowlist_list();

  if (set_hook_verbose >= 0)
    return hook_set_verbose(set_hook_verbose);

  /* Fall back to /tmp/amfid_allowlist if no --path given */
  if (al_len == 0) {
    int al_fd = open("/tmp/amfid_allowlist", O_RDONLY);
    if (al_fd >= 0) {
      off_t sz = lseek(al_fd, 0, SEEK_END);
      if (sz > 0 && (size_t)sz < sizeof(allowlist_buf)) {
        lseek(al_fd, 0, SEEK_SET);
        al_len = read(al_fd, allowlist_buf, sz);
      }
      close(al_fd);
    }
  }

  /* If hook is already active, do incremental update */
  hook_state_t st;
  if (al_len > 0 && is_hook_active(&st)) {
    VLOG("[*] hook active (pid %d), updating allowlist\n", st.pid);
    return allowlist_update(&st, allowlist_buf, al_len);
  }

  return cmd_install(allowlist_buf, al_len);
}
