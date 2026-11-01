/* The MIPS fixtures' C source: an import called through the GOT, a global
 * read through the global pointer, a loop with a call, and a string.
 * Built as position-independent little-endian code into mips_pic.elf, and
 * as big-endian code that is not into mips_nopic.elf; README.md has the
 * recipe. */
extern int puts(const char *);
int counter;
static int table[4] = {1, 2, 3, 4};
int add(int a, int b) { return a + b; }
int sum(int n) {
    int s = 0;
    for (int i = 0; i < n; i++) s = add(s, i);
    counter = s;
    return s;
}
int main(void) {
    puts("hello");
    return sum(table[2]);
}
