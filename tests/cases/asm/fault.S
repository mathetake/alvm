.global _start
_start:
    // Try loading the invalid address like -1
    mov x0, #-1
    ldr x1, [x0]
    brk #0
.text
