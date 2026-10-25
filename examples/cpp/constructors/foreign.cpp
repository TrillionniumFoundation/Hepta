#include "foreign.hpp"

namespace hepta_ctor_example {
namespace {
std::atomic<std::uint64_t> span_owners{0};
std::atomic<std::uint64_t> nothrow_values{0};
}
SpanOwner::SpanOwner(Config config, std::span<const std::int64_t> values)
    : config_(config) {
    if (!values.empty()) values_.assign(values.begin(), values.end());
    ++span_owners;
}
SpanOwner::~SpanOwner() noexcept { --span_owners; }
NoThrowValue::NoThrowValue(std::uint64_t value) noexcept : value_(value) { ++nothrow_values; }
NoThrowValue::~NoThrowValue() noexcept { --nothrow_values; }
std::uint64_t live_span_owners() noexcept { return span_owners.load(); }
std::uint64_t live_nothrow_values() noexcept { return nothrow_values.load(); }
IntVector* native_vector_new(std::size_t count) { return new IntVector(count); }
void native_vector_destroy(IntVector* object) noexcept { delete object; }
std::size_t native_vector_size(const IntVector& object) noexcept { return object.size(); }
Student* native_student_new(double degrees) { return new Student(degrees); }
void native_student_destroy(Student* object) noexcept { delete object; }
double native_student_degrees(const Student& object) { return object.degrees_of_freedom(); }
}
