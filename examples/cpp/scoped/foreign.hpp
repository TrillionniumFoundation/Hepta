#pragma once
#include <cstddef>
#include <cstdint>
#include <vector>

namespace scoped_example {
// Protocol probes, separate from the unmodified std::vector integration.
struct Audit {
    std::uint64_t members_constructed = 0;
    std::uint64_t members_destroyed = 0;
    std::uint64_t objects_constructed = 0;
    std::uint64_t objects_destroyed = 0;
    std::uint64_t final_calls = 0;
    std::uint64_t output_seen_before_publication = 0;
};
extern Audit audit;
extern std::int64_t* watched_output;
inline constexpr std::int64_t output_sentinel = -4444;

struct Member {
    Member() noexcept;
    ~Member() noexcept;
};

class Probe {
    Member member;
    std::vector<std::int64_t> values;
    std::uint64_t mode;
public:
    Probe(std::size_t count, std::int64_t initial, std::uint64_t mode);
    Probe(const Probe&) = delete;
    Probe(Probe&&) = delete;
    ~Probe() noexcept;
    void append(const std::int64_t& value);
    const std::int64_t& at(std::size_t index) const;
};

struct Pair { std::int64_t first; std::uint64_t second; };
class PairOwner {
    Pair value;
public:
    explicit PairOwner(Pair initial) noexcept : value(initial) {}
    ~PairOwner() noexcept;
    const Pair& get() const noexcept { return value; }
};

std::int64_t native_vector(std::size_t count, std::int64_t initial,
                           std::int64_t appended, std::size_t index);
}
