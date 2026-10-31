// Branches decided whatever the input: the arithmetic opaque predicates
// over a value the compiler cannot see through, and the flag shapes an
// obfuscator writes in assembly, kept there so the compiler does not fold
// them away.
//
// Built with:
//   gcc -O0 -fno-inline -fno-pic -no-pie -nostdlib -static -o opaque.elf opaque.c
volatile int input;
int result;

// x * (x + 1) is even, so the product's low bit is always clear.
int even_product(int n) {
    int x = input;
    int r = n;
    if ((x * (x + 1)) % 2 == 0) {
        r = r + 1;
    } else {
        r = r - 7;
    }
    return r;
}

// x * x + x is x * (x + 1) again.
int even_sum(int n) {
    int x = input;
    int r = n;
    if (((x * x + x) & 1) != 0) {
        r = r * 3;
    }
    return r + 2;
}

// x | 1 is odd, so it is never 0.
int never_zero(int n) {
    int x = input;
    __asm__ goto("mov %0, %%eax\n\t"
                 "or $1, %%eax\n\t"
                 "jz %l[zero]" : : "m"(x) : "eax", "cc" : zero);
    return n + 3;
zero:
    return 99;
}

// x * x read unsigned is never below 0.
int square_below(int n) {
    int x = input;
    __asm__ goto("mov %0, %%eax\n\t"
                 "imul %%eax, %%eax\n\t"
                 "cmp $0, %%eax\n\t"
                 "jb %l[below]" : : "m"(x) : "eax", "cc" : below);
    return n - 1;
below:
    return 77;
}

// The register is zeroed and tested: the jump is never taken.
int zeroed(int n) {
    __asm__ goto("xor %%eax, %%eax\n\t"
                 "test %%eax, %%eax\n\t"
                 "jnz %l[away]" : : : "eax", "cc" : away);
    return n + 5;
away:
    return 0;
}

// The carry is set and the jump on it always taken.
int carried(int n) {
    __asm__ goto("stc\n\t"
                 "jc %l[over]" : : : "cc" : over);
    return 1;
over:
    return n + 4;
}

// A register compared with itself is equal to itself.
int itself(int n) {
    __asm__ goto("cmp %%edi, %%edi\n\t"
                 "jne %l[differ]" : : : "cc" : differ);
    return n * 2;
differ:
    return -1;
}

// A branch the input decides is no opaque predicate.
int honest(int n) {
    int x = input;
    if (x > n) {
        return x;
    }
    return n;
}

void _start(void) {
    result = even_product(1) + even_sum(2) + never_zero(3) + square_below(4) + zeroed(5)
        + carried(6) + itself(7) + honest(8);
    for (;;) {
    }
}
