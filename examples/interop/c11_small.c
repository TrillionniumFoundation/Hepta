/* Defined-input arithmetic only; overflow and invalid inputs are outside the
   independent C differential domain. C++/pointer semantics are not involved. */
int add(int a, int b) { return a + b; }
int bigger(int a, int b) { if (a > b) return a; else return b; }
int sum_to(int n) {
    int total = 0;
    for (int i = 0; i < n; ++i) { total += i; }
    return total;
}
