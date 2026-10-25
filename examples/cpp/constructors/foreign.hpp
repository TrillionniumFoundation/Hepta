#pragma once
#include <boost/math/distributions/students_t.hpp>
#include <boost/version.hpp>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <span>
#include <type_traits>
#include <vector>

namespace hepta_ctor_example {
using Student = boost::math::students_t_distribution<double>;
using IntVector = std::vector<std::int64_t>;
// This is the installed upstream Boost.Math type, not a test replacement.
static_assert(!std::is_default_constructible_v<Student>);
static_assert(std::is_constructible_v<Student, double>);

struct Config { std::uint64_t tag; std::int64_t bias; };

// This small class is an authored lifetime/POD/span probe, not an upstream
// library. Its constructor copies the span before the call ends.
class SpanOwner {
    Config config_;
    IntVector values_;
public:
    SpanOwner() = delete;
    SpanOwner(Config config, std::span<const std::int64_t> values);
    ~SpanOwner() noexcept;
    std::size_t size() const noexcept { return values_.size(); }
    std::int64_t at(std::size_t index) const { return values_.at(index); }
    std::uint64_t tag() const noexcept { return config_.tag; }
    std::int64_t bias() const noexcept { return config_.bias; }
};

// A noexcept object constructor does not make wrapper allocations infallible.
class NoThrowValue {
    std::uint64_t value_;
public:
    NoThrowValue() = delete;
    explicit NoThrowValue(std::uint64_t value) noexcept;
    ~NoThrowValue() noexcept;
    std::uint64_t value() const noexcept { return value_; }
};
std::uint64_t live_span_owners() noexcept;
std::uint64_t live_nothrow_values() noexcept;

// Separate translation-unit functions keep native lifecycle operations
// observable with no LTO. Benchmarks do not include the Hepta roundtrip.
IntVector* native_vector_new(std::size_t count);
void native_vector_destroy(IntVector* object) noexcept;
std::size_t native_vector_size(const IntVector& object) noexcept;
Student* native_student_new(double degrees);
void native_student_destroy(Student* object) noexcept;
double native_student_degrees(const Student& object);
}
