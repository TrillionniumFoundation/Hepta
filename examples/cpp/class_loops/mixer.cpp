// A complete scalar state machine. Its implementation is replaced by Hepta;
// this source is used only by the independent native reference executable.
struct Mixer {
    unsigned int state;

    Mixer(unsigned int seed) noexcept: state(seed) {}

    unsigned int advance(unsigned int count) noexcept {
        unsigned int state = this->state;
        for (unsigned int i = 0; i < count; ++i) {
            state = state * 1664525u + 1013904223u;
        }
        this->state = state;
        return this->state;
    }

    unsigned int checksum(unsigned int count) const noexcept {
        unsigned int acc = state;
        unsigned int n = count;
        while (n > 0u) {
            acc = acc ^ n;
            n = n - 1u;
        }
        return acc;
    }

    unsigned int drain(unsigned int count) noexcept {
        unsigned int n = count;
        if (n > 0u) {
            do {
                state = state + n;
                --n;
            } while (n > 0u);
        }
        return state;
    }

    unsigned int shadowed(unsigned int count) const noexcept {
        unsigned int acc = state;
        for (unsigned int state = 0; state < count; ++state) {
            acc = acc ^ state;
        }
        for (unsigned int state = 0; state < count; ++state) {
            acc = acc + state;
        }
        return acc;
    }
};
