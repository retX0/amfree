/*
 * hook_entry.S — Minimal assembly trampoline for the amfid hook.
 *
 * Loads the data_page pointer via patched ADRP+LDR (same sentinel
 * mechanism as before), then calls hook_body() in C.
 */

.section __DATA,inject,regular
.align 4
.global _hook_entry

_hook_entry:
    stp     x29, x30, [sp, #-32]!
    mov     x29, sp
    str     x22, [sp, #16]

    /* Load data_page pointer — ADRP+LDR patched by hook_install.c */
    .word   0x90000016          /* adrp x22, #0 */
    .word   0xf94002d6          /* ldr x22, [x22, #0] — patched imm12 */

    /* x0=self, x1=_cmd, x2=err already in position from caller */
    mov     x3, x22             /* 4th arg: data_page pointer */
    bl      _hook_body

    ldr     x22, [sp, #16]
    ldp     x29, x30, [sp], #32
    ret

/* _dp_slot — data page pointer, offset computed at runtime by hook_install.c */
.align 3
.global __dp_slot
__dp_slot:
    .quad 0

