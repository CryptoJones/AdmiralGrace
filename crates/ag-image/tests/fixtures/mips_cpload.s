# A position-independent function with GCC's prologue, `.cpload $25`: the
# global pointer computed into gp itself from the function's own address in
# t9, then a call to the import through the GOT.
    .text
    .abicalls
    .globl gcc_style
    .ent gcc_style
gcc_style:
    .set noreorder
    .cpload $25
    .set reorder
    lw $25, %call16(puts)($gp)
    jalr $25
    nop
    jr $ra
    nop
    .end gcc_style
