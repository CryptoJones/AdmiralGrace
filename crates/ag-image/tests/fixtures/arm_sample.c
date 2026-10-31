/* A small program for the ARM fixtures: a leaf, a loop, a call and a
   switch, so the listing, the graph and the mode switch have something
   to show. Built as an object file: no linker, no C library. */
__attribute__((noinline)) int add(int a, int b) { return a + b; }

int sum(const int *values, int count) {
    int total = 0;
    for (int i = 0; i < count; i++) {
        total = add(total, values[i]);
    }
    return total;
}

int classify(int kind) {
    switch (kind) {
    case 0: return 10;
    case 1: return 20;
    case 2: return 30;
    case 3: return 40;
    case 4: return 50;
    default: return -1;
    }
}

__attribute__((target("arm"))) int other_mode(int a) { return add(a, 7) * 3; }
