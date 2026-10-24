int counter = 41;
const char *greeting = "hello";

int add(int a, int b) {
    return a + b;
}

int main(void) {
    int total = 0;
    for (int i = 0; i < 3; i++) {
        total = add(total, i);
    }
    return total + counter + greeting[0];
}
