.global _start
_start:
    // Load constant 0x1 into register x0-x9.
    mov x0, 0x1
    mov x1, 0x1
    mov x2, 0x1
    mov x3, 0x1
    mov x4, 0x1
    mov x5, 0x1
    mov x6, 0x1
    mov x7, 0x1
    mov x8, 0x1
    mov x9, 0x1
    // Then break.
    brk #0
.text
