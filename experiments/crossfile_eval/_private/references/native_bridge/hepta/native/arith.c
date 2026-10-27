#include "api.h"
static uint64_t calls;
int64_t c_adjust(int64_t a, int64_t b) { ++calls; return a * 3 + b; }
uint64_t cf_c_calls(void) { return calls; }
void cf_c_reset(void) { calls = 0; }
