/*
 * hook_install.c — Resolve ObjC method + build code/data pages in amfid.
 */
#include "inject.h"
#include "shellcode/data_layout.h"
#include "mach_utils.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <mach-o/getsect.h>
#include <objc/runtime.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "remote_macho.h"

extern const struct mach_header_64 _mh_execute_header;

/* ==== Step 2: Resolve ObjC class, selector, IMP ==== */
int resolve_objc(inject_ctx_t *ctx) {
  mach_vm_address_t dylib_base = 0;
  ctx->orig_imp = find_method_imp(ctx->task, &dylib_base);
  if (!ctx->orig_imp) {
    fprintf(stderr, "[-] find_method_imp failed\n");
    return -1;
  }
  VLOG("[*] validateWithError: IMP: 0x%llx\n", ctx->orig_imp);

  Class cls = objc_getClass("AMFIPathValidator_macos");
  SEL sel = sel_registerName("validateWithError:");
  Method method = class_getInstanceMethod(cls, sel);
  if (!method) {
    fprintf(stderr, "[-] no Method\n");
    return -1;
  }
  ctx->cls = (uint64_t)cls;
  ctx->sel = (uint64_t)sel;
  VLOG("[*] Class: %p  SEL: %p\n", (void *)cls, (void *)sel);

  ctx->type_enc = method_getTypeEncoding(method);
  VLOG("[*] type encoding: %s\n", ctx->type_enc);

  void *libobjc = dlopen("/usr/lib/libobjc.A.dylib", RTLD_LAZY);
  ctx->fn_replace = dlsym(libobjc, "class_replaceMethod");
  if (!ctx->fn_replace) {
    fprintf(stderr, "[-] no class_replaceMethod\n");
    return -1;
  }
  VLOG("[*] class_replaceMethod: %p\n", ctx->fn_replace);
  return 0;
}

/* ==== Step 3: Build code + data pages in amfid ==== */
int build_code_page(inject_ctx_t *ctx, const char *allowlist, size_t al_len) {
  kern_return_t kr;

  /* Allocate pages */
  ctx->data_page = remote_alloc(ctx->task, PAGE_SIZE, VM_PROT_READ | VM_PROT_WRITE);
  ctx->code_page = remote_alloc(ctx->task, PAGE_SIZE, VM_PROT_READ | VM_PROT_WRITE);
  if (!ctx->data_page || !ctx->code_page) {
    fprintf(stderr, "[-] remote_alloc failed\n");
    return -1;
  }
  VLOG("[*] data page: 0x%llx\n", ctx->data_page);
  VLOG("[*] code page: 0x%llx\n", ctx->code_page);

  /* Get hook code from __DATA,inject section */
  unsigned long sc_size;
  uint8_t *sc_template =
      getsectiondata(&_mh_execute_header, "__DATA", "inject", &sc_size);
  if (!sc_template) {
    fprintf(stderr, "[-] no __DATA,inject\n");
    return -1;
  }
  VLOG("[*] hook code: %lu bytes\n", sc_size);

  /* Setup code: paciza + call + b . */
  uint32_t setup_code[] = {
      0xDAC123E2, /* paciza x2           */
      0xD63F0100, /* blr    x8           */
      0x14000000, /* b      .            */
  };

  uint8_t *buf = calloc(1, PAGE_SIZE);
  memcpy(buf, sc_template, sc_size);
  ctx->setup_offset = (sc_size + 3) & ~3;
  ctx->brk_offset = ctx->setup_offset + 2 * 4;
  memcpy(buf + ctx->setup_offset, setup_code, sizeof(setup_code));

  /* Patch data_page pointer slot */
  uint64_t slot_dp = (uint64_t)ctx->data_page;
  memcpy(buf + SLOT_DATA_PAGE_PTR, &slot_dp, 8);

  /* Patch LDR instruction with correct offset */
  {
    uint32_t sentinel = 0xf94002d6; /* ldr x22, [x22, #0] */
    size_t ldr_off = 0;
    for (size_t i = 0; i <= sc_size - 4; i += 4) {
      uint32_t w;
      memcpy(&w, buf + i, 4);
      if (w == sentinel) { ldr_off = i; break; }
    }
    if (!ldr_off) {
      fprintf(stderr, "[-] LDR sentinel not found\n");
      free(buf);
      return -1;
    }
    uint32_t imm12 = (uint32_t)(SLOT_DATA_PAGE_PTR / 8);
    uint32_t ldr_instr = sentinel | (imm12 << 10);
    memcpy(buf + ldr_off, &ldr_instr, 4);
    VLOG("[*] patched LDR at 0x%zx: imm12=%u\n", ldr_off, imm12);
  }

  /* Write API function pointers to data page */
  uint64_t addr_copyPath = (uint64_t)dlsym(RTLD_DEFAULT, "SecCodeCopyPath");
  uint64_t addr_getRep   = (uint64_t)dlsym(RTLD_DEFAULT, "CFURLGetFileSystemRepresentation");
  uint64_t addr_release  = (uint64_t)dlsym(RTLD_DEFAULT, "CFRelease");

  kr  = remote_write(ctx->task, ctx->data_page + DP_SEC_COPY_PATH, &addr_copyPath, 8);
  kr |= remote_write(ctx->task, ctx->data_page + DP_URL_GET_REP, &addr_getRep, 8);
  kr |= remote_write(ctx->task, ctx->data_page + DP_CF_RELEASE, &addr_release, 8);
  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "[-] failed to write API ptrs\n");
    free(buf);
    return -1;
  }

  /* Write allowlist */
  if (allowlist && al_len > 0) {
    mach_vm_address_t remote_al = remote_alloc(ctx->task, PAGE_SIZE,
                                                VM_PROT_READ | VM_PROT_WRITE);
    kr = remote_write(ctx->task, remote_al, allowlist, al_len);
    if (kr != KERN_SUCCESS) {
      fprintf(stderr, "[-] failed to write allowlist\n");
      free(buf);
      return -1;
    }
    /* Tighten to read-only now that data is written */
    remote_protect(ctx->task, remote_al, PAGE_SIZE, VM_PROT_READ);
    uint64_t al_sz = (uint64_t)al_len;
    remote_write(ctx->task, ctx->data_page + DP_ALLOWLIST_SIZE, &al_sz, 8);
    uint64_t al_ptr = (uint64_t)remote_al;
    remote_write(ctx->task, ctx->data_page + DP_ALLOWLIST_PTR, &al_ptr, 8);
    VLOG("[*] allowlist %zu bytes at 0x%llx\n", al_len, (uint64_t)remote_al);
  } else {
    printf("[!] no allowlist — validations will use original result\n");
  }

  /* Write code page and make executable */
  kr = remote_write(ctx->task, ctx->code_page, buf, PAGE_SIZE);
  free(buf);
  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "[-] code write failed\n");
    return -1;
  }

  kr = remote_protect(ctx->task, ctx->code_page, PAGE_SIZE,
                      VM_PROT_READ | VM_PROT_EXECUTE);
  if (kr != KERN_SUCCESS) {
    fprintf(stderr, "[-] RX failed\n");
    return -1;
  }
  VLOG("[*] code page → RX\n");
  return 0;
}
