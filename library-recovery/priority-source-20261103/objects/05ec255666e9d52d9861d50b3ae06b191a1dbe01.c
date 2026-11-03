/* GENERATED FROM VERIFIED HIA PILOT SCALAR PROFILE; NOT A SAFETY CERTIFICATE. */
#include <stdint.h>
#include <limits.h>
_Static_assert(CHAR_BIT == 8 && sizeof(uint32_t)==4 && sizeof(uint64_t)==8, "unsupported ABI");
uint32_t hia_mix(uint32_t x) {
  uint32_t t1 = (uint32_t)(255ULL);
  uint32_t t2 = (uint32_t)((x ^ t1));
  uint32_t t3 = (uint32_t)(3ULL);
  uint32_t t4 = (uint32_t)((x - t3));
  uint32_t t5 = (uint32_t)((t2 + t4));
  return t5;
}
