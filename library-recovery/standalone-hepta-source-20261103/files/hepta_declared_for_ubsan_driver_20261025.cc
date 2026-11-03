
extern "C" int original_twice(int), normalized_twice(int);
extern "C" int original_nested(int), normalized_nested(int);
extern "C" int original_shadow(int), normalized_shadow(int);
extern "C" unsigned int original_unsigned(unsigned int), normalized_unsigned(unsigned int);
int main() {
    for (int n = -128; n <= 500; ++n) {
        if (original_twice(n) != normalized_twice(n)) return 1;
        if (original_nested(n) != normalized_nested(n)) return 2;
        if (original_shadow(n) != normalized_shadow(n)) return 3;
        if (n >= 0 && original_unsigned((unsigned int)n) != normalized_unsigned((unsigned int)n)) return 4;
    }
    return 0;
}
