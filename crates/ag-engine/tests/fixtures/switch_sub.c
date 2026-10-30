int counter = 7;

int classify(int code) {
    switch (code) {
    case 3: return 10;
    case 4: return 20;
    case 5: return counter;
    case 6: return 40;
    case 7: return 50;
    case 8: return 60;
    default: return -1;
    }
}

int main(void) {
    return classify(counter);
}
