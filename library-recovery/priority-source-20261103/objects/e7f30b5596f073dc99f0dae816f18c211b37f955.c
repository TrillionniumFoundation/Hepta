unsigned int hia_mix(unsigned int x) {
    return (x ^ 255u) + (x - 3u);
}
