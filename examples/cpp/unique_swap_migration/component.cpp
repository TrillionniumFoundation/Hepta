// Authored integration component using the captured default-deleter library.
#include <memory>

unsigned long long run_reset(unsigned long left, unsigned long right, unsigned char value,
                             unsigned long index, unsigned int reject, unsigned int early) noexcept {
    try {
        if (left > 4096) { return 4001; }
        if (right > 4096) { return 4001; }
        std::unique_ptr<unsigned char[]> source(left == 0 ? nullptr : new unsigned char[left]{});
        std::unique_ptr<unsigned char[]> destination(right == 0 ? nullptr : new unsigned char[right]{});
        source.swap(source);
        source.swap(destination);
        if (index < right) { source[index] = value; }
        if (reject == 1) { throw 7; }
        if (early == 1) { return 2001; }
        destination.reset(source.release());
        source.swap(destination);
        if (index < right) { source[index] = value; }
        destination.swap(source);
        source.swap(source);
        source.reset();
        if (reject == 2) { throw 8; }
        if (early == 4) { destination.reset(source.release()); return 2005; }
        destination.reset(destination.release());
        if (early == 2) { destination.reset(); return 2002; }
        if (early == 3) { destination.reset(nullptr); return 2004; }
        if (index >= right) { return 2003; }
        return static_cast<unsigned long long>(destination[index]) * 3 + left + right;
    } catch (int code) {
        return 1000 + static_cast<unsigned long long>(code);
    } catch (...) {
        return 1001;
    }
}
