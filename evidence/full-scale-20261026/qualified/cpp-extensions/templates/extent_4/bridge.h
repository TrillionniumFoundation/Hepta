// C ABI declarations. See contract.json for caller obligations.
#pragma once
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
#define HEPTA_CPP_NOEXCEPT noexcept
extern "C" {
#else
#define HEPTA_CPP_NOEXCEPT
#endif
uint32_t hepta_cpp_sized_add(uint32_t value) HEPTA_CPP_NOEXCEPT;
int32_t hepta_cpp_sized_Array_new(uint64_t* out) HEPTA_CPP_NOEXCEPT;
int32_t hepta_cpp_sized_Array_destroy(uint64_t handle) HEPTA_CPP_NOEXCEPT;
int32_t hepta_cpp_sized_Array_fill(uint64_t handle, uint32_t value) HEPTA_CPP_NOEXCEPT;
int32_t hepta_cpp_sized_Array_at(uint64_t handle, size_t index, uint32_t* out) HEPTA_CPP_NOEXCEPT;
int32_t hepta_cpp_sized_Counted_new(uint32_t reject, uint64_t* out) HEPTA_CPP_NOEXCEPT;
int32_t hepta_cpp_sized_Counted_destroy(uint64_t handle) HEPTA_CPP_NOEXCEPT;
int32_t hepta_cpp_sized_Counted_fill(uint64_t handle, uint32_t value) HEPTA_CPP_NOEXCEPT;
int32_t hepta_cpp_sized_Counted_at(uint64_t handle, size_t index, uint32_t* out) HEPTA_CPP_NOEXCEPT;
int32_t hepta_cpp_sized_array_roundtrip(uint32_t value, size_t index, uint32_t* out) HEPTA_CPP_NOEXCEPT;
int32_t hepta_cpp_sized_counted_roundtrip(uint32_t reject, uint32_t value, size_t index, uint32_t* out) HEPTA_CPP_NOEXCEPT;
#ifdef __cplusplus
}
#endif
#undef HEPTA_CPP_NOEXCEPT
