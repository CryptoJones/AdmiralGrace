    .text
    .globl main
    .type main, @function
main:
    movl $1, %eax
    jmp shared
    .globl helper
    .type helper, @function
helper:
    movl $2, %eax
shared:
    ret
    .p2align 4, 0x90
.Lorphan:
    movl $3, %eax
    ret
