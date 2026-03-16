/*
 * allowlist.c — State file I/O, list, and incremental allowlist update.
 */
#include "allowlist.h"
#include "mach_utils.h"
#include "shellcode/data_layout.h"

#include <libproc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- State file I/O ---- */

static int load_state(hook_state_t *st) {
  FILE *fp = fopen(STATE_FILE, "r");
  if (!fp) return -1;
  memset(st, 0, sizeof(*st));
  int pid_tmp = 0;
  if (fscanf(fp, "pid=%d\n", &pid_tmp) == 1) st->pid = pid_tmp;
  fscanf(fp, "data_page=0x%llx\n", &st->data_page);
  fscanf(fp, "code_page=0x%llx\n", &st->code_page);
  fscanf(fp, "old_imp=0x%llx\n", &st->old_imp);
  fclose(fp);
  return (st->pid > 0 && st->data_page) ? 0 : -1;
}

int is_hook_active(hook_state_t *st) {
  if (load_state(st) < 0) return 0;
  char name[256];
  if (proc_name(st->pid, name, sizeof(name)) <= 0) return 0;
  return strcmp(name, "amfid") == 0;
}

/* ---- List ---- */

int allowlist_list(void) {
  hook_state_t st;
  if (!is_hook_active(&st)) {
    fprintf(stderr, "[-] no active hook (run with --path first)\n");
    return 1;
  }

  mach_port_t task;
  kern_return_t kr = task_for_pid(mach_task_self(), st.pid, &task);
  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "[-] task_for_pid: %s\n", mach_error_string(kr));
    return 1;
  }

  uint64_t al_ptr = 0, al_size = 0;
  remote_read(task, st.data_page + DP_ALLOWLIST_PTR, &al_ptr, 8);
  remote_read(task, st.data_page + DP_ALLOWLIST_SIZE, &al_size, 8);

  if (!al_ptr || !al_size) {
    printf("(no paths in allowlist)\n");
    return 0;
  }

  char *buf = calloc(1, al_size + 1);
  remote_read(task, al_ptr, buf, al_size);

  printf("amfid hook active (pid %d)\n", st.pid);
  printf("allowed paths:\n");
  char *line = buf;
  while (line < buf + al_size) {
    char *nl = strchr(line, '\n');
    if (nl) *nl = '\0';
    if (*line) printf("  %s\n", line);
    if (!nl) break;
    line = nl + 1;
  }

  free(buf);
  return 0;
}

/* ---- Incremental update ---- */

int allowlist_update(hook_state_t *st, const char *new_paths, size_t new_len) {
  mach_port_t task;
  kern_return_t kr = task_for_pid(mach_task_self(), st->pid, &task);
  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "[-] task_for_pid: %s\n", mach_error_string(kr));
    return 1;
  }

  /* Read existing allowlist */
  uint64_t old_ptr = 0, old_size = 0;
  remote_read(task, st->data_page + DP_ALLOWLIST_PTR, &old_ptr, 8);
  remote_read(task, st->data_page + DP_ALLOWLIST_SIZE, &old_size, 8);

  /* Merge: existing + new */
  size_t merged_len = old_size + new_len;
  char *merged = calloc(1, merged_len + 1);
  if (old_ptr && old_size)
    remote_read(task, old_ptr, merged, old_size);
  memcpy(merged + old_size, new_paths, new_len);

  /* Allocate new allowlist page in amfid */
  mach_vm_address_t new_page = remote_alloc(task, PAGE_SIZE,
                                             VM_PROT_READ | VM_PROT_WRITE);
  if (!new_page) {
    fprintf(stderr, "[-] remote_alloc failed\n");
    free(merged);
    return 1;
  }
  kr = remote_write(task, new_page, merged, merged_len);
  free(merged);
  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "[-] write allowlist failed\n");
    return 1;
  }
  remote_protect(task, new_page, PAGE_SIZE, VM_PROT_READ);

  /* Update data page pointers */
  uint64_t sz = merged_len;
  remote_write(task, st->data_page + DP_ALLOWLIST_PTR, &new_page, 8);
  remote_write(task, st->data_page + DP_ALLOWLIST_SIZE, &sz, 8);

  printf("[+] allowlist updated (pid %d, %zu bytes)\n", st->pid, merged_len);
  return 0;
}
