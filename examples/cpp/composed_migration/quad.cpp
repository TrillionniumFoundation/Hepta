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

class QuadBytes {
    OwnedBytes head_;
    OwnedBytes body_;
    OwnedBytes tail_;
    OwnedBytes extra_;
public:
    QuadBytes(unsigned long left, unsigned long right, unsigned int reject)
        : head_(right, reject == 1), body_(left, reject == 2), tail_(right + 1UL, reject == 3), extra_(left + 2UL, reject == 4) {
        if (reject == 5) { throw 5; }
    }
    QuadBytes(QuadBytes&& other) noexcept
        : head_(static_cast<OwnedBytes&&>(other.head_)), body_(static_cast<OwnedBytes&&>(other.body_)),
          tail_(static_cast<OwnedBytes&&>(other.tail_)), extra_(static_cast<OwnedBytes&&>(other.extra_)) {}
    QuadBytes(const QuadBytes&) = delete;
    QuadBytes& operator=(const QuadBytes&) = delete;
    QuadBytes& operator=(QuadBytes&&) = delete;
    ~QuadBytes() noexcept = default;
    void prepare(unsigned char value) noexcept {
        body_.fill(static_cast<unsigned char>(static_cast<unsigned int>(value) ^ 19U));
        head_.fill(value);
        extra_.fill(static_cast<unsigned char>(static_cast<unsigned int>(value) ^ 61U));
        tail_.fill(static_cast<unsigned char>(static_cast<unsigned int>(value) ^ 173U));
        if (body_.size() != 0) { body_.set(0, static_cast<unsigned char>(static_cast<unsigned int>(value) ^ 7U)); }
    }
    unsigned long limit() const noexcept {
        if (head_.size() < body_.size()) { return head_.size(); }
        return body_.size();
    }
    unsigned long long score(unsigned long index) const noexcept {
        const unsigned long long outer = static_cast<unsigned long long>(head_.get(index)) + tail_.data()[index];
        return outer * 7ULL + body_.get(index) + tail_.size() + extra_.get(0);
    }
};
unsigned long long run_quad(unsigned long left, unsigned long right, unsigned char value,
                              unsigned long index, unsigned int reject, unsigned int early) noexcept {
    try {
        QuadBytes first(left, right, reject);
        if (early == 1) { return 4001; }
        first.prepare(value);
        QuadBytes second(static_cast<QuadBytes&&>(first));
        if (index >= second.limit()) { return 4003; }
        if (early == 2) { return 4002; }
        const unsigned long long answer = second.score(index);
        return answer + 17ULL;
    } catch (int code) { return 1000 + static_cast<unsigned long long>(code); }
      catch (...) { return 1001; }
}
