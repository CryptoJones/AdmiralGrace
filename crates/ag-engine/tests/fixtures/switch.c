int counter = 7;

int classify(int code) {
    switch (code) {
    case 0: return 10;
    case 1: return 20;
    case 2: return counter;
    case 3: return 40;
    case 4: return 50;
    case 5: return 60;
    default: return -1;
    }
}

int main(void) {
    return classify(counter);
}
