#include "abi.h"
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef hepta_AbiRecord AbiRecord;
typedef hepta_AbiPair AbiPair;
typedef hepta_AbiFloatPair AbiFloatPair;

/* Real C definitions called by the compiled Hepta module. */
int32_t c_add(int32_t a, int32_t b) { return a + b; }

AbiRecord c_record(AbiRecord value) {
    value.tag += 1;
    value.count ^= UINT64_C(0xfedcba9876543210);
    value.score *= 2.0;
    return value;
}

#ifdef HEPTA_LAYOUT_PROBE
#define DECLARE_LAYOUT(T) \
    extern size_t hepta_layout_##T##_size(void); \
    extern size_t hepta_layout_##T##_align(void)
DECLARE_LAYOUT(AbiRecord);
DECLARE_LAYOUT(AbiPair);
DECLARE_LAYOUT(AbiFloatPair);
extern size_t hepta_layout_AbiRecord_tag(void);
extern size_t hepta_layout_AbiRecord_count(void);
extern size_t hepta_layout_AbiRecord_score(void);
extern size_t hepta_layout_AbiPair_low(void);
extern size_t hepta_layout_AbiPair_high(void);
extern size_t hepta_layout_AbiFloatPair_x(void);
extern size_t hepta_layout_AbiFloatPair_y(void);

static void check_layout(void) {
#define CHECK_LAYOUT(T) \
    assert(sizeof(T) == hepta_layout_##T##_size()); \
    assert(_Alignof(T) == hepta_layout_##T##_align())
    CHECK_LAYOUT(AbiRecord);
    CHECK_LAYOUT(AbiPair);
    CHECK_LAYOUT(AbiFloatPair);
#define CHECK_OFFSET(T, f) assert(offsetof(T, f) == hepta_layout_##T##_##f())
    CHECK_OFFSET(AbiRecord, tag);
    CHECK_OFFSET(AbiRecord, count);
    CHECK_OFFSET(AbiRecord, score);
    CHECK_OFFSET(AbiPair, low);
    CHECK_OFFSET(AbiPair, high);
    CHECK_OFFSET(AbiFloatPair, x);
    CHECK_OFFSET(AbiFloatPair, y);
}
#endif

int main(void) {
    const uint64_t large = UINT64_C(0x12345678abcdef01);
    AbiRecord first = hepta_make_record(UINT32_C(0xab12), large, 1.25);
    assert(first.tag == UINT32_C(0xab12));
    assert(first.count == large);
    assert(first.score == 1.25);
    AbiRecord echoed = hepta_echo_record(first);
    assert(echoed.tag == first.tag && echoed.count == large && echoed.score == 1.25);
    AbiPair small = {UINT32_C(0x12345678), UINT32_C(0x90abcdef)};
    AbiPair small_out = hepta_echo_pair(small);
    assert(small_out.low == small.low && small_out.high == small.high);
    AbiFloatPair floats = {-0.5, 1048576.25};
    AbiFloatPair floats_out = hepta_echo_float_pair(floats);
    assert(floats_out.x == floats.x && floats_out.y == floats.y);
    assert(hepta_call_c_add(-1234, 5678) == 4444);
    AbiRecord from_c = hepta_call_c_record(first);
    assert(from_c.tag == first.tag + 1);
    assert(from_c.count == (large ^ UINT64_C(0xfedcba9876543210)));
    assert(from_c.score == 2.5);
#ifdef HEPTA_LAYOUT_PROBE
    check_layout();
    puts("{\"status\":\"passed\",\"bidirectional_c_calls\":true,\"struct_by_value\":true,\"layout_compared\":true}");
#else
    puts("{\"status\":\"passed\",\"bidirectional_c_calls\":true,\"struct_by_value\":true,\"layout_compared\":false}");
#endif
    return 0;
}
