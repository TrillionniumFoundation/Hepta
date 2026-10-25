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
int32_t hepta_cpp_json_upgrade_Document_parse(const uint8_t* text, size_t text_len, uint64_t* out) HEPTA_CPP_NOEXCEPT;
int32_t hepta_cpp_json_upgrade_Document_destroy(uint64_t handle) HEPTA_CPP_NOEXCEPT;
int32_t hepta_cpp_json_upgrade_Document_replace(uint64_t handle, size_t index, int64_t value) HEPTA_CPP_NOEXCEPT;
int32_t hepta_cpp_json_upgrade_Document_sum(uint64_t handle, int64_t* out) HEPTA_CPP_NOEXCEPT;
int32_t hepta_cpp_json_upgrade_replace_sum(const uint8_t* text, size_t text_len, size_t index, int64_t value, int64_t* out) HEPTA_CPP_NOEXCEPT;
#ifdef __cplusplus
}
#endif
#undef HEPTA_CPP_NOEXCEPT
