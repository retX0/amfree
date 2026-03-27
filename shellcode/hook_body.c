/*
 * hook_body.c — C implementation of the amfid hook logic.
 *
 * Called from hook_entry.S with:
 *   x0 = self (AMFIPathValidator_macos instance)
 *   x1 = _cmd (validateWithError: selector)
 *   x2 = err_ptr (NSError **)
 *   x3 = data_page pointer
 *
 * IMPORTANT: This code is copied verbatim into amfid's address space.
 * We can't call framework functions directly (bl is PC-relative, would
 * jump to garbage after relocation). Instead, data_page carries a dlsym
 * pointer — we resolve everything at runtime inside amfid.
 *
 * String literals are embedded in the instruction stream via inline asm
 * (adr + .asciz). The adr instruction is PC-relative, so it survives
 * relocation. No __cstring or __const section references.
 */

#include "data_layout.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Opaque types */
typedef const void *CFTypeRef;
typedef const void *CFURLRef;
typedef const void *SecStaticCodeRef;

/* dlsym signature */
typedef void *(*DlsymFn)(void *handle, const char *symbol);
#define RTLD_DEFAULT ((void *)-2)

/* Resolved function types */
typedef bool (*ValidateIMP)(void *self, void *_cmd, void **err);
typedef int32_t (*SecCodeCopyPathFn)(SecStaticCodeRef, uint32_t, CFURLRef *);
typedef bool (*CFURLGetFSRepFn)(CFURLRef, bool, uint8_t *, long);
typedef void (*CFReleaseFn)(CFTypeRef);
typedef int (*StrncmpFn)(const char *, const char *, unsigned long);
typedef unsigned long (*StrlenFn)(const char *);
typedef int (*DprintfFn)(int, const char *, ...);

#define STDERR_FD 2

/*
 * STRIP_PAC — strip Pointer Authentication Code bits from a pointer.
 * dlsym inside arm64e amfid returns PAC-signed pointers; our arm64-compiled
 * code uses plain BLR which would jump to the corrupted address. XPACI
 * zeros the PAC field for instruction-address pointers.
 */
#define STRIP_PAC(ptr)                                                         \
  ({                                                                           \
    uint64_t _p = (uint64_t)(ptr);                                             \
    __asm__ volatile("xpaci %0" : "+r"(_p));                                   \
    (void *)_p;                                                                \
  })

/*
 * _ASM_STR — base macro: embed a string in the code stream via inline asm.
 * 'term' controls the terminator: "\\0" for plain strings,
 * "\\n\\0" for LOG (auto-appends newline).
 * NOTE: use %%s (not %s) for format specifiers — % is an asm escape char.
 */
#define _ASM_STR(var, str, term)                                               \
  const char *var;                                                             \
  __asm__ volatile("adr %0, 1f \n"                                             \
                   "b 2f \n"                                                   \
                   "1: .ascii \"" str term "\" \n"                             \
                   ".align 2 \n"                                               \
                   "2: \n"                                                     \
                   : "=r"(var))

#define INLINE_STR(var, str) _ASM_STR(var, str, "\\0")

/* LOG — always prints (errors/diagnostics), essential for debugging */
#define LOG(fmt, ...)                                                          \
  do {                                                                         \
    if (log_fn) {                                                              \
      _ASM_STR(_lfmt, fmt, "\\n\\0");                                          \
      log_fn(STDERR_FD, _lfmt, ##__VA_ARGS__);                                 \
    }                                                                          \
  } while (0)

/* VLOG — verbose only (info/success paths), gated by data_page->verbose */
#define VLOG(fmt, ...)                                                         \
  do {                                                                         \
    if (verbose && log_fn) {                                                   \
      _ASM_STR(_lfmt, fmt, "\\n\\0");                                          \
      log_fn(STDERR_FD, _lfmt, ##__VA_ARGS__);                                 \
    }                                                                          \
  } while (0)

/* ---------- hook entry point ---------- */

__attribute__((section("__DATA,inject"), used, noinline)) bool
hook_body(void *self, void *_cmd, void **err, data_page_t *dp) {
  DlsymFn my_dlsym = (DlsymFn)STRIP_PAC(dp->dlsym);
  int verbose = (int)dp->verbose;

  /* Resolve dprintf for logging (syslog crashes due to PAC in arm64e amfid) */
  INLINE_STR(s_log, "dprintf");
  DprintfFn log_fn = (DprintfFn)STRIP_PAC(my_dlsym(RTLD_DEFAULT, s_log));

  LOG("[amfree] hook_body called");
  /* 1. Call original validateWithError: */
  ValidateIMP orig = (ValidateIMP)STRIP_PAC(dp->orig_imp);
  bool result = orig(self, _cmd, err);
  if (result) {
    VLOG("[amfree] orig returned true (valid)");
    return true;
  }

  /* 2. Read _code ivar (SecStaticCodeRef) from self */
  SecStaticCodeRef code =
      *(SecStaticCodeRef *)((char *)self + IVAR_CODE_OFFSET);
  if (!code) {
    LOG("[amfree] _code ivar is NULL");
    return false;
  }

  /* 3. Resolve API functions via dlsym (all need PAC stripping) */
  INLINE_STR(s_copypath, "SecCodeCopyPath");
  INLINE_STR(s_getrep, "CFURLGetFileSystemRepresentation");
  INLINE_STR(s_release, "CFRelease");
  INLINE_STR(s_strncmp, "strncmp");
  INLINE_STR(s_strlen, "strlen");

  SecCodeCopyPathFn copyPath =
      (SecCodeCopyPathFn)STRIP_PAC(my_dlsym(RTLD_DEFAULT, s_copypath));
  CFURLGetFSRepFn getRep = (CFURLGetFSRepFn)STRIP_PAC(my_dlsym(RTLD_DEFAULT, s_getrep));
  CFReleaseFn cfRelease = (CFReleaseFn)STRIP_PAC(my_dlsym(RTLD_DEFAULT, s_release));
  StrncmpFn my_strncmp = (StrncmpFn)STRIP_PAC(my_dlsym(RTLD_DEFAULT, s_strncmp));
  StrlenFn my_strlen = (StrlenFn)STRIP_PAC(my_dlsym(RTLD_DEFAULT, s_strlen));

  if (!copyPath || !getRep || !cfRelease || !my_strncmp || !my_strlen) {
    LOG("[amfree] dlsym failed for one or more symbols");
    return false;
  }

  /* 4. Get the binary's file path */
  CFURLRef url = NULL;
  if (copyPath(code, 0, &url) != 0 || !url) {
    LOG("[amfree] SecCodeCopyPath failed");
    return false;
  }

  uint8_t path[128];
  bool ok = getRep(url, true, path, sizeof(path));
  cfRelease(url);

  if (!ok) {
    LOG("[amfree] CFURLGetFileSystemRepresentation failed");
    return false;
  }

  VLOG("[amfree] validating: %%s", (const char *)path);

  /* 5. Match path against allowlist (newline-separated path prefixes) */
  const char *al = (const char *)dp->allowlist_ptr;
  uint64_t al_size = dp->allowlist_size;
  if (!al || al_size == 0) {
    LOG("[amfree] no allowlist");
    return false;
  }

  unsigned long path_len = my_strlen((const char *)path);
  const char *end = al + al_size;

  for (const char *p = al; p < end;) {
    if (*p <= ' ') {
      p++;
      continue;
    }
    const char *line = p;
    while (p < end && *p != '\n')
      p++;
    unsigned long len = (unsigned long)(p - line);
    if (len <= path_len && my_strncmp((const char *)path, line, len) == 0) {
      VLOG("[amfree] ALLOWED: %%s", (const char *)path);
      if (err)
        *err = NULL;
      return true;
    }
  }

  LOG("[amfree] DENIED: %%s", (const char *)path);
  return false;
}
