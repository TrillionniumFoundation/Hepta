#include "foreign.hpp"
#include <stdexcept>

namespace scoped_example {
Audit audit;
std::int64_t* watched_output = nullptr;

Member::Member() noexcept { ++audit.members_constructed; }
Member::~Member() noexcept { ++audit.members_destroyed; }
Probe::Probe(std::size_t count, std::int64_t initial, std::uint64_t failure)
    : values(count, initial), mode(failure) {
    if (mode == 1) throw std::runtime_error("constructor rejected after member construction");
    ++audit.objects_constructed;
}
Probe::~Probe() noexcept {
    if (watched_output && *watched_output == output_sentinel)
        ++audit.output_seen_before_publication;
    ++audit.objects_destroyed;
}
void Probe::append(const std::int64_t& value) {
    values.push_back(value);
    if (mode == 2) throw std::runtime_error("method rejected after local mutation");
}
const std::int64_t& Probe::at(std::size_t index) const {
    ++audit.final_calls;
    if (mode == 3) throw std::runtime_error("final method rejected");
    return values.at(index);
}
PairOwner::~PairOwner() noexcept {
    // A returned reference must be materialized before this destructor runs.
    value = Pair{-999, 0};
}
std::int64_t native_vector(std::size_t count, std::int64_t initial,
                           std::int64_t appended, std::size_t index) {
    std::vector<std::int64_t> values(count, initial);
    values.push_back(appended);
    return values.at(index);
}
}
