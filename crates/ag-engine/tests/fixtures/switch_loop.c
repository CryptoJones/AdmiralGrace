int counter = 7;
int sink = 0;

int scan(int n) {
    int i;
    for (i = 0; i < n; i++) {
        switch (i & 7) {
        case 0: sink += 1; break;
        case 1: sink += 2; break;
        case 2: sink += 3; break;
        case 3: sink += 4; break;
        case 4: goto out;
        case 5: sink += 6; break;
        default: sink += 7; break;
        }
    }
out:
    return sink;
}

int main(void) {
    return scan(counter);
}
