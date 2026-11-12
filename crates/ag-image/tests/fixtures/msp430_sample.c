/* A small program for the MSP430 fixture: a leaf, a subtraction, a
   compare-and-branch, and a loop with a call, so the listing, the graph
   and the lift have something to show. Built for the 16-bit core with no
   C library: clang --target=msp430 -O1 -c, then ld.lld -e sum
   --image-base=0x4000 -Ttext=0x4000. */
__attribute__((noinline)) int add(int a, int b) { return a + b; }
__attribute__((noinline)) int sub(int a, int b) { return a - b; }
__attribute__((noinline)) int max(int a, int b) { return a > b ? a : b; }
int sum(const int *values, int count) {
    int total = 0;
    for (int i = 0; i < count; i++) total = add(total, values[i]);
    return total;
}
