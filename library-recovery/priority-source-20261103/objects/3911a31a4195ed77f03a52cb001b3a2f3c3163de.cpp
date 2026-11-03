// Deliberately tiny C++-to-C ABI lifetime probe; NOT a third-party library migration.
#include <cstdint>
#include <climits>
#include <memory>
#include <new>
#include <stdexcept>
#include <array>
#include <limits>
#include <mutex>

namespace {
constexpr std::size_t CAPACITY=16;
struct Resource {
    explicit Resource(std::int32_t value) : value_(value) { ++constructed; }
    ~Resource() noexcept { ++destroyed; }
    std::int32_t value_;
    static inline std::uint64_t constructed=0;
    static inline std::uint64_t destroyed=0;
};
struct Slot {
    std::unique_ptr<Resource> owner;
    std::uint64_t generation=0;
};
std::mutex mtx;
std::array<Slot,CAPACITY> slots;
std::uint64_t encode(std::size_t index,std::uint64_t gen) {
    return (gen << 8) | static_cast<std::uint64_t>(index+1);
}
Slot* decode(std::uint64_t handle) {
    const std::uint64_t index_byte=handle & 255u;
    if(index_byte==0 || index_byte>CAPACITY) return nullptr;
    Slot &slot=slots[index_byte-1];
    if(!slot.owner || slot.generation!=(handle>>8)) return nullptr;
    return &slot;
}
}

extern "C" {
// 0 means failed creation. The returned integer is opaque to the C consumer.
std::uint64_t hia_cpp_new(std::int32_t initial) noexcept {
    try {
        std::lock_guard<std::mutex> lock(mtx);
        for(std::size_t i=0;i<CAPACITY;i++){
            Slot &slot=slots[i];
            if(!slot.owner){
                if(slot.generation>=((std::numeric_limits<std::uint64_t>::max)() >> 8)-1u) return 0;
                auto created=std::make_unique<Resource>(initial);
                ++slot.generation;
                slot.owner=std::move(created);
                return encode(i,slot.generation);
            }
        }
    } catch(...) { return 0; }
    return 0;
}

// status: 0=OK, 1=stale, 2=bad outptr, 3=explicit exception, 4=range.
int hia_cpp_step(std::uint64_t handle,std::int32_t delta,std::int32_t *out) noexcept {
    if(!out) return 2;
    try {
        std::lock_guard<std::mutex> lock(mtx);
        Slot *slot=decode(handle);
        if(!slot) return 1;
        if(delta==INT32_MIN) throw std::runtime_error("deliberate exception boundary test");
        const std::int64_t value=static_cast<std::int64_t>(slot->owner->value_)+delta;
        if(value<INT32_MIN || value>INT32_MAX) return 4;
        slot->owner->value_=static_cast<std::int32_t>(value);
        *out=slot->owner->value_;
        return 0;
    } catch(...) { return 3; }
}

int hia_cpp_delete(std::uint64_t handle) noexcept {
    try {
        std::lock_guard<std::mutex> lock(mtx);
        Slot *slot=decode(handle);
        if(!slot) return 1;
        slot->owner.reset();
        return 0;
    } catch(...) { return 3; }
}

std::uint64_t hia_cpp_constructed() noexcept {
    std::lock_guard<std::mutex> lock(mtx); return Resource::constructed;
}
std::uint64_t hia_cpp_destroyed() noexcept {
    std::lock_guard<std::mutex> lock(mtx); return Resource::destroyed;
}
}
