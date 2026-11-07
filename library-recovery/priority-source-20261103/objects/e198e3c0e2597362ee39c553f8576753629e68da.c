/* GENERATED FROM VERIFIED HIA PILOT SCALAR PROFILE; NOT A SAFETY CERTIFICATE. */
typedef __UINT8_TYPE__ uint8_t;
typedef __UINT32_TYPE__ uint32_t;
typedef __UINT64_TYPE__ uint64_t;
#define CHAR_BIT __CHAR_BIT__
_Static_assert(CHAR_BIT == 8 && sizeof(uint32_t)==4 && sizeof(uint64_t)==8, "unsupported ABI");
uint32_t hia_add_zero(uint32_t x) {
  uint32_t t1 = (uint32_t)(0ULL);
  uint32_t t2 = (uint32_t)((x + t1));
  return t2;
}
