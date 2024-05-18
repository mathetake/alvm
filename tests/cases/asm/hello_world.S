.global _start

_start:
    // Load the file descriptor for stdout (1) into x0
    mov x0, #1

    // Load the address of the message into x1
    adr x1, message

    // Load the length of the message into x2
    mov x2, #14

    // Specify the syscall number for sys_write (64) in x8
    mov x8, #64

    // Make the syscall
    svc #0

    // Exit the program
    // Load the exit syscall number (93) into x8
    mov x8, #93

    // Set the exit status in x0
    mov x0, #0

    // Make the syscall
    svc #0

.text

message:
    .ascii "Hello, world!\n"
