.global _start
_start:
    // Make the invalid syscall on aarch64.
    mov x8, 0x1337
    svc 0
    brk #0
.text
