#pragma once

#include <mach/mach.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define STATE_FILE "/tmp/amfid_hook.txt"

typedef struct {
  pid_t pid;
  uint64_t data_page;
  uint64_t code_page;
  uint64_t old_imp;
} hook_state_t;

/*
 * Check if the saved hook state is still active (amfid PID matches).
 * Populates `st` on success.  Returns 1 if active, 0 if not.
 */
int is_hook_active(hook_state_t *st);

/*
 * List currently allowed paths by reading amfid's memory.
 * Returns 0 on success.
 */
int allowlist_list(void);

/*
 * Incremental update: merge `new_paths` into the existing allowlist
 * without re-installing the hook.  Returns 0 on success.
 */
int allowlist_update(hook_state_t *st, const char *new_paths, size_t new_len);
