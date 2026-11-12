/* A small program for the RISC-V fixtures: a leaf, a loop, a call,
   multiply/divide and bit-manipulation, so the listing, the graph and
   the lift have something to show. Built as a static executable with no
   C library, for RV32 and RV64 alike. */
__attribute__((noinline)) int add(int a, int b) { return a + b; }

int sum(const int *values, int count) {
    int total = 0;
    for (int i = 0; i < count; i++) {
        total = add(total, values[i]);
    }
    return total;
}

__attribute__((noinline)) int muldiv(int a, int b) {
    return (a * b) / (b | 1);
}

/* The bit-manipulation extension: clz, cpop and andn. The specification
   decodes these but leaves their p-code unimplemented, so this function
   disassembles and the lift refuses it. */
__attribute__((noinline)) unsigned bits(unsigned x, unsigned y) {
    return __builtin_clz(x) + __builtin_popcount(x) + (x & ~y);
}
