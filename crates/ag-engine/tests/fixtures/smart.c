// A structure the code fills after allocating it, and one it reads
// through a parameter, for the smart structures (#369): at -O0 every
// access is a plain load or store through the pointer.
//
// Built with:
//   gcc -O0 -fno-pic -no-pie -nostdlib -static -fno-builtin -o smart.elf smart.c
struct conn {
    int fd;              // 0x00
    unsigned short port; // 0x04
    char flags;          // 0x06
    char *name;          // 0x08
    long count;          // 0x10
    int slots[4];        // 0x18
};                       // 0x28 bytes

static char heap[4096];
static unsigned long used;

__attribute__((noinline)) void *malloc(unsigned long n) {
    void *p = heap + used;
    used += (n + 15) & ~15ul;
    return p;
}

__attribute__((noinline)) void *calloc(unsigned long n, unsigned long size) {
    char *p = malloc(n * size);
    for (unsigned long i = 0; i < n * size; i++)
        p[i] = 0;
    return p;
}

__attribute__((noinline)) struct conn *make_conn(int fd, char *name) {
    struct conn *c = malloc(sizeof(struct conn));
    c->fd = fd;
    c->port = 80;
    c->flags = 1;
    c->name = name;
    c->count = 0;
    return c;
}

__attribute__((noinline)) long read_conn(struct conn *c, long i) {
    long total = c->count;
    if (c->port > 1024)
        total += 1;
    total += c->slots[i];
    total += *c->name;
    return total + c->fd;
}

__attribute__((noinline)) int *make_pair(void) {
    int *pair = calloc(2, 8);
    pair[0] = 1;
    pair[3] = 2;
    return pair;
}

__attribute__((noinline)) long open_conn(int fd) {
    struct conn *c = make_conn(fd, "conn");
    c->slots[2] = 7;
    return read_conn(c, 2);
}

long sink;

void _start(void) {
    sink = open_conn(3);
    sink = (long)make_pair();
    __asm__ volatile("mov $60, %eax\n syscall");
}
