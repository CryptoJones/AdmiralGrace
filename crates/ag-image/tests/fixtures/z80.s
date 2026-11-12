    .area CODE (ABS)
    .org 0x4000
add:
    add a, b
    ret
sub:
    sub b
    ret
max:
    cp b
    jr nc, maxdone
    ld a, b
maxdone:
    ret
sum:
    ld a, #0x00
    ld b, #0x03
sumloop:
    call add
    dec b
    jr nz, sumloop
    ret
