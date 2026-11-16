/* A small program for the PowerPC fixtures: a leaf, a subtraction, a
   compare-and-branch, a loop with a call, and a floating-point leaf the
   lift refuses. Built for the 32-bit and 64-bit cores, big- and
   little-endian, with no C library: clang --target=powerpc-linux-gnu
   (or powerpc64-linux-gnu, powerpc64le-linux-gnu) -O1 -nostdlib -static
   -Wl,-e,sum -Ttext=0x20000. README.md has the recipe. */
__attribute__((noinline)) int add(int a, int b) { return a + b; }
__attribute__((noinline)) int sub(int a, int b) { return a - b; }
__attribute__((noinline)) int max(int a, int b) { return a > b ? a : b; }
int sum(const int *values, int count) {
    int total = 0;
    for (int i = 0; i < count; i++) total = add(total, values[i]);
    return total;
}
__attribute__((noinline)) double fp(double a, double b) { return a * b + a; }
