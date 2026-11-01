// Types the code says without the analyst's words, for type propagation
// (#370): a helper taking a string from two callers, a buffer filled by
// fgets and one by memcpy, an array filled in a loop, a structure passed
// by its address to a function with a known prototype, and one passed to a
// function of the image's own, which no prototype types.
// The library's functions are stubs of its own, so their names are in the
// image; at -O0 every local lives in its stack slot.
//
// Built with:
//   gcc -O0 -fno-pic -no-pie -nostdlib -static -fno-builtin -fno-stack-protector -o propagate.elf propagate.c
typedef struct file FILE;

struct timeval {
    long tv_sec;
    long tv_usec;
};

static char heap[256];

__attribute__((noinline)) unsigned long strlen(const char *s) {
    unsigned long n = 0;
    while (s[n])
        n++;
    return n;
}

__attribute__((noinline)) void *memcpy(void *dst, const void *src, unsigned long n) {
    char *d = dst;
    const char *s = src;
    for (unsigned long i = 0; i < n; i++)
        d[i] = s[i];
    return dst;
}

__attribute__((noinline)) char *fgets(char *s, int size, FILE *stream) {
    for (int i = 0; i + 1 < size; i++)
        s[i] = heap[i];
    s[size - 1] = 0;
    return stream ? s : 0;
}

__attribute__((noinline)) int gettimeofday(struct timeval *tv, void *tz) {
    tv->tv_sec = 1;
    tv->tv_usec = 2;
    return tz != 0;
}

__attribute__((noinline)) long measure(char *s) {
    return strlen(s) + 1;
}

__attribute__((noinline)) long greet(void) {
    return measure("hello");
}

__attribute__((noinline)) long part(void) {
    return measure("goodbye");
}

__attribute__((noinline)) long line(FILE *f) {
    char buf[64];
    fgets(buf, 64, f);
    return buf[0];
}

__attribute__((noinline)) int sum(int n) {
    int a[8];
    for (int i = 0; i < 8; i++)
        a[i] = i * n;
    int total = 0;
    for (int i = 0; i < 8; i++)
        total += a[i];
    return total;
}

__attribute__((noinline)) long now(void) {
    struct timeval tv;
    gettimeofday(&tv, 0);
    return tv.tv_sec + tv.tv_usec;
}

__attribute__((noinline)) long copy(const char *src) {
    char tmp[32];
    memcpy(tmp, src, 32);
    return tmp[0];
}

struct pair {
    int a;
    long b;
};

__attribute__((noinline)) void fill(struct pair *p) {
    p->a = 1;
    p->b = 2;
}

__attribute__((noinline)) long pairs(void) {
    struct pair s;
    fill(&s);
    return s.a + s.b;
}

void _start(void) {
    greet();
    part();
    line((FILE *)heap);
    sum(3);
    now();
    copy("source");
    pairs();
    __asm__ volatile("mov $60, %eax\n syscall");
}
