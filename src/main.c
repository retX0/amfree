/*
 * main.c — Entry point for amfid bypass injector.
 *
 * Usage: sudo ./inject --path <dir> [--path <dir>]...
 */
#include "inject.h"
#include "mach_utils.h"
#include "remote_macho.h"

#include <getopt.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int g_verbose = 0;

int main(int argc, char **argv) {
  /* Parse --path / -p arguments */
  static struct option long_options[] = {
      {"path",    required_argument, NULL, 'p'},
      {"verbose", no_argument,       NULL, 'v'},
      {"help",    no_argument,       NULL, 'h'},
      {NULL, 0, NULL, 0}
  };

  char allowlist_buf[4096] = {0};
  size_t al_len = 0;
  int opt;
  while ((opt = getopt_long(argc, argv, "p:vh", long_options, NULL)) != -1) {
    switch (opt) {
    case 'p': {
      size_t plen = strlen(optarg);
      if (al_len + plen + 1 < sizeof(allowlist_buf)) {
        memcpy(allowlist_buf + al_len, optarg, plen);
        al_len += plen;
        allowlist_buf[al_len++] = '\n';
      }
      VLOG("[*] allowlist: %s\n", optarg);
      break;
    }
    case 'v':
      g_verbose = 1;
      break;
    case 'h':
    default:
      printf("Usage: %s [-v] [--path <dir>]...\n\n"
             "  -p, --path <dir>  Allow binaries under <dir> to bypass AMFI.\n"
             "                    Can be specified multiple times.\n"
             "                    If not specified, reads from /tmp/amfid_allowlist.\n"
             "  -v, --verbose     Print detailed debug information.\n",
             argv[0]);
      return opt == 'h' ? 0 : 1;
    }
  }

  /* Fall back to /tmp/amfid_allowlist if no --path given */
  if (al_len == 0) {
    int al_fd = open("/tmp/amfid_allowlist", O_RDONLY);
    if (al_fd >= 0) {
      off_t sz = lseek(al_fd, 0, SEEK_END);
      if (sz > 0 && (size_t)sz < sizeof(allowlist_buf)) {
        lseek(al_fd, 0, SEEK_SET);
        al_len = read(al_fd, allowlist_buf, sz);
        VLOG("[*] loaded allowlist from /tmp/amfid_allowlist (%zu bytes)\n", al_len);
      }
      close(al_fd);
    }
  }

  /* ==== Step 1: Find amfid ==== */
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

  /* ==== Step 2: Resolve ObjC method ==== */
  if (resolve_objc(&ctx) < 0) return 1;

  /* ==== Step 3: Build code + data pages ==== */
  if (build_code_page(&ctx, al_len > 0 ? allowlist_buf : NULL, al_len) < 0) return 1;

  /* ==== Step 4-8: Debugserver → thread hijack → install ==== */
  pid_t ds_pid = -1;
  if (spawn_debugserver(&ctx, &ds_pid) < 0) return 1;
  if (hijack_and_install(&ctx, ds_pid) < 0) return 1;

  printf("\n[+] hook installed!\n");
  printf("[+] code page: 0x%llx\n", (uint64_t)ctx.code_page);
  printf("[+] data page: 0x%llx\n", (uint64_t)ctx.data_page);

  /* Write state file */
  FILE *fp = fopen("/tmp/amfid_hook.txt", "w");
  if (fp) {
    fprintf(fp, "pid=%d\ndata_page=0x%llx\ncode_page=0x%llx\nold_imp=0x%llx\n",
            ctx.pid, (uint64_t)ctx.data_page, (uint64_t)ctx.code_page, ctx.orig_imp);
    fclose(fp);
    printf("[+] state → /tmp/amfid_hook.txt\n");
  }
  return 0;
}
