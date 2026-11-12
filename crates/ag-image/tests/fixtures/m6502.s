.setcpu "6502"
.export add, sub, max, sum
.segment "CODE"
add:
    clc
    adc $00
    rts
sub:
    sec
    sbc $00
    rts
max:
    cmp $00
    bcs maxdone
    lda $00
maxdone:
    rts
sum:
    lda #$00
    ldx #$03
sumloop:
    sta $00
    jsr add
    dex
    bne sumloop
    rts
