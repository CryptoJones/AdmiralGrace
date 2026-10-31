// The inlined memory operations a compiler writes: `rep movsb` and
// `rep stosb` for memcpy and memset of a size it does not know, and the
// constant stores that put a string on the stack.
//
// Built with:
//   gcc -O1 -mstringop-strategy=rep_byte -fno-pic -no-pie -nostdlib -static -o builtins.elf builtins.c
char sink[64];

__attribute__((noinline)) void consume(const char *text) {
    for (int i = 0; text[i] != 0; i++) {
        sink[i] = text[i];
    }
}

void rep_copy(char *dst, const char *src, unsigned long n) {
    __builtin_memcpy(dst, src, n);
}

void rep_fill(char *dst, int c, unsigned long n) {
    __builtin_memset(dst, c, n);
}

void stack_string(void) {
    char s[] = "hello, world";
    consume(s);
}

void _start(void) {
    rep_copy(sink, "def", 3);
    rep_fill(sink, 1, 16);
    stack_string();
    __asm__ volatile("mov $60, %eax\n syscall");
}
