# The entry of mips_nopic.elf: code that is not position-independent sets
# the global pointer from the linker's `_gp`, then calls main.
    .text
    .globl __start
    .ent __start
__start:
    lui $gp, %hi(_gp)
    addiu $gp, $gp, %lo(_gp)
    jal main
    nop
1:  b 1b
    nop
    .end __start
