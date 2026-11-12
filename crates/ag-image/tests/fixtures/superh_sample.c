/* A small program for the SuperH fixture: a leaf, a subtraction, a
   compare-and-branch, and a loop with a call, so the listing and the graph
   have something to show. Built for the SH4 core with no C library:
   sh4-linux-gnu-gcc -O1 -nostdlib -static -Wl,-e,sum -Ttext=0x4000. The
   big-endian twin is the same source built -mb. */
__attribute__((noinline)) int add(int a, int b) { return a + b; }
__attribute__((noinline)) int sub(int a, int b) { return a - b; }
__attribute__((noinline)) int max(int a, int b) { return a > b ? a : b; }
int sum(const int *values, int count) {
    int total = 0;
    for (int i = 0; i < count; i++) total = add(total, values[i]);
    return total;
}