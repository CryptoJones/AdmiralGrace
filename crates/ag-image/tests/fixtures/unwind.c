/* Three functions and no symbols: what the unwind data alone says of an
   image. Built with the compiler's default unwind tables and then stripped
   of every symbol, so the functions are known only from `.eh_frame`,
   `.pdata` or `__unwind_info`. */
int counter = 41;

static int add(int a, int b) {
    return a + b;
}

static long sum_to(int n) {
    long total = 0;
    for (int i = 1; i <= n; i++) {
        total = total + i;
    }
    return total;
}

int main(void) {
    int total = 0;
    for (int i = 0; i < 3; i++) {
        total = add(total, i);
    }
    return total + counter + (int)sum_to(3);
}
