#ifndef HEPTA_CONSTEXPR_BRANCHES_HPP
#define HEPTA_CONSTEXPR_BRANCHES_HPP

template<class T, unsigned Mode>
T adjust(T value) noexcept {
    if constexpr (sizeof(T) == 4) {
        if constexpr (Mode == 0) {
            return value + 3;
        } else {
            return value + 7;
        }
    } else {
        if constexpr (Mode == 0) {
            return value + 11;
        } else {
            return value + 13;
        }
    }
}

template<unsigned Mode>
unsigned scoped(unsigned value) noexcept {
    unsigned result = value;
    if constexpr (Mode == 0) {
        unsigned value = 7;
        result += value;
    } else {
        unsigned value = 11;
        result += value;
    }
    if constexpr (Mode == 9) {
        throw 17;
    }
    return result + value;
}

template<class T>
T scalar_only(T value) noexcept {
    if constexpr (sizeof(T) == 4) {
        return value + 19;
    } else {
        // This discarded branch has a distinct object lifecycle. The scalar
        // migration profile must reject if an instance actually selects it.
        struct Resource {
            T& target;
            explicit Resource(T& item) noexcept : target(item) { target += 23; }
            ~Resource() noexcept { target += 29; }
        };
        Resource resource(value);
        return value;
    }
}

#endif
