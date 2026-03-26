/*
 * hook.S — call-through hook + path prefix matching
 *
 * Data page layout defined in data_layout.h.
 *
 * Flow:
 *   1. Call original validateWithError: (computes cdhash)
 *   2. If original returned YES → return YES (don't interfere)
 *   3. Get binary path via SecCodeCopyPath
 *   4. Compare path against allowlist prefixes
 *   5. If match → return YES
 *   6. Else → return original NO
 */

#include "data_layout.h"

.section __DATA,inject,regular
.align 4
.global _hook_entry

_hook_entry:
    stp     x29, x30, [sp, #-192]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]

    mov     x19, x0             /* self */
    mov     x20, x1             /* _cmd */
    mov     x21, x2             /* err_ptr */

    /* Load data_page pointer */
    .word   0x90000016          /* adrp x22, #0 */
    .word   0xf94002d6          /* ldr x22, [x22, #0] — patched */

    /* Step 1: Call original validateWithError: */
    mov     x0, x19
    mov     x1, x20
    mov     x2, x21
    ldr     x16, [x22, #DP_ORIG_IMP]
    blr     x16

    /* Save original return in x23 */
    mov     w23, w0

    /* Step 2: If original returned YES, just return YES */
    cbnz    w23, _return_result

    /* Step 3: Get path — read _code from self+8 */
    ldr     x0, [x19, #IVAR_CODE_OFFSET]  /* SecStaticCodeRef (_code ivar) */
    cbz     x0, _return_result  /* no code → return original NO */

    /* SecCodeCopyPath(code, 0, &url) */
    str     xzr, [sp, #64]     /* clear url slot */
    mov     x1, xzr
    add     x2, sp, #64
    ldr     x16, [x22, #DP_SEC_COPY_PATH]
    blr     x16

    /* Check if SecCodeCopyPath succeeded */
    cbnz    w0, _return_result  /* error → return original NO */
    ldr     x0, [sp, #64]      /* url */
    cbz     x0, _return_result

    /* CFURLGetFileSystemRepresentation(url, true, buf, bufsize) */
    mov     x24, x0             /* save url for CFRelease */
    mov     w1, #1              /* resolveAgainstBase = true */
    add     x2, sp, #80        /* path buffer at sp+80 */
    mov     x3, #100            /* buffer size */
    ldr     x16, [x22, #DP_URL_GET_REP]
    blr     x16

    /* Save GetRep result before CFRelease clobbers w0 */
    str     w0, [sp, #72]

    /* Release the URL */
    mov     x0, x24
    ldr     x16, [x22, #DP_CF_RELEASE]
    blr     x16

    /* If representation failed, return original */
    ldr     w0, [sp, #72]
    cbz     w0, _return_result

    /* Step 4: Compare path against allowlist.
     * Allowlist is a newline-separated list of path prefixes.
     * x2 = path string (at sp+80)
     * x3 = allowlist ptr (from data_page+0x30)
     * x4 = allowlist size (from data_page+0x28)
     */
    add     x2, sp, #80        /* path we got */
    ldr     x3, [x22, #DP_ALLOWLIST_PTR]
    cbz     x3, _return_result  /* no allowlist → return original */
    ldr     x4, [x22, #DP_ALLOWLIST_SIZE]
    cbz     x4, _return_result

    /* Iterate allowlist lines */
    add     x5, x3, x4         /* x5 = end of allowlist */

_next_line:
    cmp     x3, x5
    b.ge    _return_result      /* end of allowlist, no match */

    /* Skip leading whitespace/newlines */
_skip_ws:
    cmp     x3, x5
    b.ge    _return_result
    ldrb    w6, [x3]
    cmp     w6, #'\n'
    b.eq    _skip_ws_next
    cmp     w6, #'\r'
    b.eq    _skip_ws_next
    cmp     w6, #' '
    b.eq    _skip_ws_next
    b       _compare_prefix
_skip_ws_next:
    add     x3, x3, #1
    b       _skip_ws

_compare_prefix:
    /* x3 = start of allowlist entry, x2 = path string */
    mov     x7, x2             /* x7 = path cursor */
    mov     x8, x3             /* x8 = allowlist cursor */

_cmp_loop:
    cmp     x8, x5
    b.ge    _match              /* allowlist entry ended → prefix match! */
    ldrb    w9, [x8]
    cmp     w9, #'\n'
    b.eq    _match              /* newline = end of entry → prefix match! */
    cmp     w9, #'\r'
    b.eq    _match
    cmp     w9, #0
    b.eq    _match              /* null = end of entry → match */

    ldrb    w10, [x7]
    cmp     w10, #0
    b.eq    _no_match           /* path ended before prefix → no match */

    cmp     w9, w10             /* compare characters */
    b.ne    _no_match

    add     x7, x7, #1
    add     x8, x8, #1
    b       _cmp_loop

_match:
    /* Prefix matched! Clear error and return YES */
    cbz     x21, 1f
    str     xzr, [x21]
1:
    mov     w23, #1
    b       _return_result

_no_match:
    /* Skip to next line */
    cmp     x3, x5
    b.ge    _return_result
    ldrb    w6, [x3]
    cmp     w6, #'\n'
    b.eq    _found_newline
    cmp     w6, #0
    b.eq    _return_result
    add     x3, x3, #1
    b       _no_match

_found_newline:
    add     x3, x3, #1
    b       _next_line

_return_result:
    mov     w0, w23

    ldp     x23, x24, [sp, #48]
    ldp     x21, x22, [sp, #32]
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #192
    ret

.align 3
_dp_slot:
    .quad 0
