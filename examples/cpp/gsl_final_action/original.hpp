#pragma once
#include "selected_gsl.hpp"
#include "callback.hpp"
#include <cstdint>
using GslGuard = gsl::final_action<GslCallback>;
unsigned long long gsl_consume(GslGuard owner, GslState* state,
                               unsigned int mode);
extern "C" std::uint64_t original_case(std::uint64_t seed,
    std::uint64_t tag, std::uint32_t mode, std::uint32_t field) noexcept;
