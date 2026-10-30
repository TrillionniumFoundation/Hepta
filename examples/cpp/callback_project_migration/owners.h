#pragma once
#include <memory>
#if PROJECT_VARIANT == 1
#define PROJECT_XOR 37U
#define PROJECT_WEIGHT 3ULL
#elif PROJECT_VARIANT == 2
#define PROJECT_XOR 11U
#define PROJECT_WEIGHT 5ULL
#else
#error Explicit PROJECT_VARIANT 1 or 2 required
#endif
// Complete default-deleter std::unique_ptr<byte[]> profile.
class OwnedBytes {
    std::unique_ptr<unsigned char[]> data_;
    unsigned long size_;
public:
    OwnedBytes(unsigned long size, bool reject)
        : data_(size == 0 ? nullptr : new unsigned char[size]{}), size_(size) {
        if (reject) { throw 2; }
    }
    OwnedBytes(OwnedBytes&& other) noexcept
        : data_(static_cast<std::unique_ptr<unsigned char[]>&&>(other.data_)), size_(other.size_) {
        other.size_ = 0;
    }
    OwnedBytes(const OwnedBytes&) = delete;
    OwnedBytes& operator=(const OwnedBytes&) = delete;
    OwnedBytes& operator=(OwnedBytes&&) = delete;
    ~OwnedBytes() noexcept = default;

    unsigned long size() const noexcept { return size_; }
    const unsigned char* data() const noexcept { return data_.get(); }
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
        right_.fill(static_cast<unsigned char>(static_cast<unsigned int>(value) ^ PROJECT_XOR));
        if (left_.size() != 0) { left_.set(0, static_cast<unsigned char>(static_cast<unsigned int>(value) ^ 91U)); }
    }
    unsigned long limit() const noexcept {
        if (left_.size() < right_.size()) { return left_.size(); }
        return right_.size();
    }
    unsigned long long score(unsigned long index) const noexcept {
        const unsigned long long weighted = static_cast<unsigned long long>(left_.data()[index]) * PROJECT_WEIGHT;
        return weighted + right_.get(index) + left_.size() + right_.size();
    }
};
unsigned long long read_pair(const PairedBytes& borrowed, unsigned long index, bool reject) noexcept;
unsigned long long consume_pair(PairedBytes owned,
    unsigned long long (*callback)(const PairedBytes&, unsigned long, bool) noexcept,
    unsigned long index, unsigned int early) noexcept;
unsigned long long run_pair(unsigned long left, unsigned long right, unsigned char value,
    unsigned long index, unsigned int reject, unsigned int early) noexcept;
