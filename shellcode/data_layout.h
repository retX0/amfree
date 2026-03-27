/*
 * data_layout.h — Data page layout for the amfid hook.
 *
 * Shared between hook_entry.S (ARM64 shellcode), hook_body.c, and
 * the C injector code. The struct is the single source of truth.
 */
#pragma once

/* Target ObjC class. */
#define AMFI_CLASS_NAME "AMFIPathValidator_macos"

/*
 * IVAR_CODE_OFFSET — offset of the _code ivar in AMFIPathValidator_macos.
 * Extracted at build time by shellcode/probe_ivar.m and passed via -D.
 */
#ifndef IVAR_CODE_OFFSET
#error "IVAR_CODE_OFFSET must be defined by the Makefile (extracted by probe_ivar)"
#endif

/* ObjC type encoding is stored far into the page, not in the struct. */
#define DP_TYPE_ENCODING 0x100

#ifndef __ASSEMBLER__
#include <stddef.h>
#include <stdint.h>

typedef struct __attribute__((packed)) {
  uint64_t _pad0;          /* 0x00 */
  uint64_t orig_imp;       /* 0x08 — original validateWithError: IMP */
  uint64_t dlsym;          /* 0x10 — dlsym function pointer */
  uint64_t verbose;        /* 0x18 — verbose logging flag (1 = on) */
  uint64_t _reserved;      /* 0x20 */
  uint64_t allowlist_size; /* 0x28 — allowlist byte length */
  uint64_t allowlist_ptr;  /* 0x30 — allowlist memory address */
} data_page_t;

/* Single source of truth — all offset access goes through this. */
#define DP_OFF(field) offsetof(data_page_t, field)

#endif /* __ASSEMBLER__ */
