// Complete source unit for the selected scalar value-class migration profile.
struct ScalarState {
    unsigned int word;
    unsigned long long wide;
    int balance;
    long long position;

    ScalarState(unsigned int word, unsigned long long wide,
                int balance, long long position) noexcept
        : word(word), wide(wide), balance(balance), position(position) {}
    ~ScalarState() noexcept = default;

    unsigned int add_word(unsigned int receiver) noexcept {
        word = word + receiver;
        return word;
    }
    unsigned long long mix(unsigned long long delta) noexcept {
        wide = (wide ^ delta) + 1ULL;
        return wide;
    }
    int clamp_balance(int lower, int upper) noexcept {
        if (balance < lower) {
            balance = lower;
        } else {
            if (balance > upper) {
                balance = upper;
            }
        }
        return balance;
    }
    long long replace_position(long long next) noexcept {
        position = next;
        return position;
    }
    unsigned int word_value() const noexcept { return word; }
    unsigned long long wide_value() const noexcept { return wide; }
    int balance_value() const noexcept { return balance; }
    long long position_value() const noexcept { return position; }
    void set_word(unsigned int next) noexcept { word = next; }
};
