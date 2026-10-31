@ The flows the ARM decoder has to read right: a call and a return under a
@ condition, a Thumb `blx` into ARM code that no symbol names, and a load
@ from the literal pool. Linked with `.text` at 0x20000 and `_start` the
@ entry; `arm_flows_stripped.elf` is the same with every symbol removed.
.syntax unified
.text
.global _start

.arm
.align 2
.type armfn, %function
armfn:
    cmp r0, #0
    blne helper              @ a call under a condition is still a call
    bxne lr                  @ a return under a condition falls through too
    bx lr
.type helper, %function
helper:
    add r0, r0, #1
    bx lr

.thumb
.align 2
.type _start, %function
.thumb_func
_start:
    push {r4, lr}
    blx 1f                   @ into ARM code with no symbol: the blx switches
    ldr r1, 2f               @ the literal pool, by its address
    pop {r4, pc}
.align 2
2:  .word 0x12345678

.arm
.align 2
1:  mov r0, #7
    bx lr
