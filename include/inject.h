/*
 * inject.h — Shared types and declarations for amfid bypass.
 */
#ifndef INJECT_H
#define INJECT_H

#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

/* Verbose logging: prints only when -v is given. */
extern int g_verbose;
#define VLOG(...) do { if (g_verbose) printf(__VA_ARGS__); } while (0)

/* Hook code data slot — offset computed at runtime. */
extern uint64_t _dp_slot;

/* Context passed between stages. */
typedef struct {
  pid_t pid;
  mach_port_t task;

  /* ObjC resolution */
  uint64_t cls;           /* AMFIPathValidator_macos class ptr */
  uint64_t sel;           /* validateWithError: selector */
  uint64_t orig_imp;      /* original IMP address */
  const char *type_enc;   /* method type encoding */
  void *fn_replace;       /* class_replaceMethod function ptr */

  /* Remote pages */
  mach_vm_address_t data_page;
  mach_vm_address_t code_page;

  /* Code page offsets */
  size_t setup_offset;
  size_t brk_offset;
} inject_ctx_t;

/* hook_install.c */
int resolve_objc(inject_ctx_t *ctx);
int build_code_page(inject_ctx_t *ctx, const char *allowlist, size_t al_len);

/* debugserver.c */
int spawn_debugserver(inject_ctx_t *ctx, pid_t *ds_pid);
int hijack_and_install(inject_ctx_t *ctx, pid_t ds_pid);

#endif /* INJECT_H */
