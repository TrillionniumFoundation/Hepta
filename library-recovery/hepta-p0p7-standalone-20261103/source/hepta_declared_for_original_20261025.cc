
extern "C" int original_twice(int n) {
    int total = 0;
    for (int i = 0; i < n; ++i) { total = total + i; }
    for (int i = 0; i < n; ++i) { total = total + i; }
    return total;
}
extern "C" int original_nested(int n) {
    int total = 0;
    for (int i = 0; i < n; ++i) {
        for (int i = 0; i < 2; ++i) { total = total + 1; }
    }
    return total;
}
extern "C" int original_shadow(int i) {
    int total = 0;
    for (int i = 0; i < 4; ++i) { total = total + i; }
    return total + i;
}
extern "C" unsigned int original_unsigned(unsigned int n) {
    unsigned int total = 0;
    for (unsigned int i = 0; i < n; ++i) { total = total + i; }
    return total;
}
