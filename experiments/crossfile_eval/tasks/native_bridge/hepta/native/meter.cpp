#include "api.h"
#include <vector>
#include <numeric>
static uint64_t calls;
extern "C" void cf_c_reset(void);
class Meter {
    std::vector<int64_t> values;
public:
    explicit Meter(int64_t value) : values{value, value + 1} {}
    int64_t scaled(int64_t factor) const { return std::accumulate(values.begin(), values.end(), int64_t{0}) * factor; }
};
extern "C" ForeignResult cpp_scale(int64_t value, int64_t factor) {
    ++calls;
    if (factor < 0 || value < -10000 || value > 10000) return ForeignResult{0, 1};
    try { return ForeignResult{Meter(value).scaled(factor), 0}; }
    catch (...) { return ForeignResult{0, 2}; }
}
extern "C" uint64_t cf_cpp_calls(void) { return calls; }
extern "C" void cf_native_reset(void) { calls = 0; cf_c_reset(); }
