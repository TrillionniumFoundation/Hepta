
extern "C" int normalized_twice(int n) {
    int total=0;
    int hepta_for_72_i=0;
    while (hepta_for_72_i<n) {total=total+hepta_for_72_i;hepta_for_72_i=hepta_for_72_i+1;}
    int hepta_for_127_i=0;
    while (hepta_for_127_i<n) {total=total+hepta_for_127_i;hepta_for_127_i=hepta_for_127_i+1;}
    return total;
}
extern "C" int normalized_nested(int n) {
    int total=0;
    int hepta_for_261_i=0;
    while (hepta_for_261_i<n) {
        int hepta_for_299_i=0;
        while (hepta_for_299_i<2) {total=total+1;hepta_for_299_i=hepta_for_299_i+1;}
        hepta_for_261_i=hepta_for_261_i+1;
    }
    return total;
}
extern "C" int normalized_shadow(int i) {
    int total=0;
    int hepta_for_439_i=0;
    while (hepta_for_439_i<4) {total=total+hepta_for_439_i;hepta_for_439_i=hepta_for_439_i+1;}
    return total+i;
}
extern "C" unsigned int normalized_unsigned(unsigned int n) {
    unsigned int total=0;
    unsigned int hepta_for_615_i=0;
    while (hepta_for_615_i<n) {total=total+hepta_for_615_i;hepta_for_615_i=hepta_for_615_i+1;}
    return total;
}
extern "C" int wrong_nested(int n) { return normalized_nested(n) + 1; }
