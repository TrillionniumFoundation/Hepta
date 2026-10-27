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

class PairedBytes {
    OwnedBytes left_;
    OwnedBytes right_;
public:
    PairedBytes(unsigned long left, unsigned long right, unsigned int reject)
        : left_(left, reject == 1), right_(right, reject == 2) {
        if (reject == 3) { throw 3; }
    }
    PairedBytes(PairedBytes&& other) noexcept
        : left_(static_cast<OwnedBytes&&>(other.left_)), right_(static_cast<OwnedBytes&&>(other.right_)) {}
    PairedBytes(const PairedBytes&) = delete;
    PairedBytes& operator=(const PairedBytes&) = delete;
    PairedBytes& operator=(PairedBytes&&) = delete;
    ~PairedBytes() noexcept = default;
    void prepare(unsigned char value) noexcept {
        left_.fill(value);
        right_.fill(static_cast<unsigned char>(static_cast<unsigned int>(value) ^ 37U));
        if (left_.size() != 0) { left_.set(0, static_cast<unsigned char>(static_cast<unsigned int>(value) ^ 91U)); }
    }
    unsigned long limit() const noexcept {
        if (left_.size() < right_.size()) { return left_.size(); }
        return right_.size();
    }
    unsigned long long score(unsigned long index) const noexcept {
        const unsigned long long weighted = static_cast<unsigned long long>(left_.data()[index]) * 3ULL;
        return weighted + right_.get(index) + left_.size() + right_.size();
    }
};
unsigned long long run_pair(unsigned long left, unsigned long right, unsigned char value,
                            unsigned long index, unsigned int reject, unsigned int early) noexcept {
    try {
        PairedBytes first(left, right, reject);
        first.prepare(value);
        if (early == 1) { return 2001; }
        PairedBytes second(static_cast<PairedBytes&&>(first));
        if (early == 2) { return 2002; }
        if (index >= second.limit()) { return 2003; }
        return second.score(index);
    } catch (int code) { return 1000 + static_cast<unsigned long long>(code); }
      catch (...) { return 1001; }
}
