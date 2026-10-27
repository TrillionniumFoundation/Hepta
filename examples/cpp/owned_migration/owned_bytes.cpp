// Complete source profile: one exclusive zero-initialized byte-array owner.
class OwnedBytes {
    unsigned char* data_;
    unsigned long size_;
public:
    OwnedBytes(unsigned long size, bool reject)
        : data_(size == 0 ? nullptr : new unsigned char[size]{}), size_(size) {
        if (reject) {
            delete[] data_;
            data_ = nullptr;
            size_ = 0;
            throw 2;
        }
    }
    OwnedBytes(OwnedBytes&& other) noexcept : data_(other.data_), size_(other.size_) {
        other.data_ = nullptr;
        other.size_ = 0;
    }
    OwnedBytes(const OwnedBytes&) = delete;
    OwnedBytes& operator=(const OwnedBytes&) = delete;
    OwnedBytes& operator=(OwnedBytes&&) = delete;
    ~OwnedBytes() noexcept { delete[] data_; }

    unsigned long size() const noexcept { return size_; }
    const unsigned char* data() const noexcept { return data_; }
    void fill(unsigned char value) noexcept {
        for (unsigned long i = 0; i < size_; ++i) { data_[i] = value; }
    }
    unsigned char get(unsigned long index) const noexcept { return data_[index]; }
    void set(unsigned long index, unsigned char value) noexcept { data_[index] = value; }
};

unsigned long long run_owned(unsigned long size, unsigned char value, unsigned long index,
                             bool reject_constructor, bool early) noexcept {
    try {
        OwnedBytes first(size, reject_constructor);
        first.fill(value);
        if (size != 0) { first.set(0, value ^ 90); }
        OwnedBytes second(static_cast<OwnedBytes&&>(first));
        if (early) { return 2002; }
        if (index >= second.size()) { return 2003; }
        const unsigned char* borrowed = second.data();
        return static_cast<unsigned long long>(borrowed[index]) + second.get(index) + second.size();
    } catch (int code) {
        return 1000 + static_cast<unsigned long long>(code);
    } catch (...) {
        return 1001;
    }
}
