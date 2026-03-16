/*
 * data_layout.h — Data page layout for the amfid hook.
 *
 * Shared between hook.S (ARM64 shellcode) and C injector code.
 * All offsets are relative to the data page base.
 */
#pragma once

/* Target ObjC class. */
#define AMFI_CLASS_NAME  "AMFIPathValidator_macos"

/* Data page slot offsets */
#define DP_ORIG_IMP         0x08    /* Original validateWithError: IMP */
#define DP_SEC_COPY_PATH    0x10    /* SecCodeCopyPath function pointer */
#define DP_URL_GET_REP      0x18    /* CFURLGetFileSystemRepresentation */
#define DP_CF_RELEASE       0x20    /* CFRelease */
#define DP_ALLOWLIST_SIZE   0x28    /* Allowlist byte length (uint64) */
#define DP_ALLOWLIST_PTR    0x30    /* Allowlist memory address */
#define DP_TYPE_ENCODING    0x100   /* ObjC type encoding string */

/*
 * IVAR_CODE_OFFSET — offset of the _code ivar in AMFIPathValidator_macos.
 * Extracted at build time by shellcode/probe_ivar.m and passed via -D.
 */
#ifndef IVAR_CODE_OFFSET
#error "IVAR_CODE_OFFSET must be defined by the Makefile (extracted by probe_ivar)"
#endif
