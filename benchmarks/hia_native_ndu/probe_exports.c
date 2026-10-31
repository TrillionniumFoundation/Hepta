#include "metrics.h"
void probe_begin(uint64_t fail) { metrics_begin(fail); }
void probe_end(struct metrics *out) { metrics_end(out); }
