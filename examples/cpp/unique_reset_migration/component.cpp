// A project component using the actual toolchain's std::unique_ptr implementation.
#include <memory>

unsigned long long run_reset(unsigned long left, unsigned long right, unsigned char value,
                             unsigned long index, unsigned int reject, unsigned int early) noexcept {
    try {
        if (left > 4096) { return 4001; }
        if (right > 4096) { return 4001; }
        std::unique_ptr<unsigned char[]> source(left == 0 ? nullptr : new unsigned char[left]{});
        std::unique_ptr<unsigned char[]> destination(right == 0 ? nullptr : new unsigned char[right]{});
        if (index < left) { source[index] = value; }
        if (reject == 1) { throw 7; }
        if (early == 1) { return 2001; }
        destination.reset(source.release());
        destination.reset(destination.release());
        if (early == 2) { destination.reset(); return 2002; }
        if (early == 3) { destination.reset(nullptr); return 2004; }
        if (index >= left) { return 2003; }
        return static_cast<unsigned long long>(destination[index]) * 3 + left + right;
    } catch (int code) {
        return 1000 + static_cast<unsigned long long>(code);
    } catch (...) {
        return 1001;
    }
}
