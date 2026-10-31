// Functions to inline into their callers: two that call each other, one
// that jumps into the middle of a loop, which is not lifted, and their
// caller.
//
// Built with:
//   gcc -O0 -fno-inline -fno-pic -no-pie -nostdlib -static -o inline.elf inline.c
int result;

int pong(int n);

int ping(int n) {
    int r = n;
    if (n > 0) {
        r = pong(n - 1) + 1;
    }
    return r;
}

int pong(int n) {
    int r = 1;
    if (n > 0) {
        r = ping(n - 1) + 7;
    }
    return r;
}

int tangle(int n) {
    int i = n;
    if (n > 5) {
        goto inside;
    }
    while (i < 10) {
        i = i + 2;
    inside:
        i = i + 1;
    }
    return i;
}

int start(int n) {
    return ping(n) + tangle(n);
}

void _start(void) {
    result = start(3);
    for (;;) {
    }
}
