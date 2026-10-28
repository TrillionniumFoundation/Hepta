
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
typedef uint64_t (*transition_fn)(uint64_t, uint64_t);
typedef struct {
  uint64_t *data;
  uint64_t size;
  _Atomic uint64_t progress;
  _Atomic unsigned cancel;
} state;
static _Atomic uint64_t live, allocations, frees, refusals;
state *hs_new(uint64_t n, unsigned fail_at) {
  if (n == 0 || n > 65536) return NULL;
  if (fail_at == 1) { atomic_fetch_add(&refusals, 1); return NULL; }
  state *s = calloc(1, sizeof(state));
  if (!s) { atomic_fetch_add(&refusals, 1); return NULL; }
  atomic_fetch_add(&live, 1); atomic_fetch_add(&allocations, 1);
  s->data = fail_at == 2 ? NULL : calloc(n, sizeof(uint64_t));
  if (!s->data) {
    free(s); atomic_fetch_sub(&live, 1); atomic_fetch_add(&frees, 1);
    atomic_fetch_add(&refusals, 1); return NULL;
  }
  atomic_fetch_add(&live, 1); atomic_fetch_add(&allocations, 1);
  s->size = n; return s;
}
state *hs_clone(state *s) {
  state *copy = hs_new(s->size, 0);
  if (copy) memcpy(copy->data, s->data, s->size * sizeof(uint64_t));
  return copy;
}
void hs_free(state *s) {
  if (!s) return;
  free(s->data); free(s);
  atomic_fetch_sub(&live, 2); atomic_fetch_add(&frees, 2);
}
uint64_t hs_identity(state *s) { return (uint64_t)(uintptr_t)s->data; }
uint64_t hs_read(state *s, uint64_t i) { return s->data[i]; }
void hs_write(state *s, uint64_t i, uint64_t v) { s->data[i] = v; }
void hs_reset(state *s) {
  atomic_store(&s->progress, 0); atomic_store(&s->cancel, 0);
}
int hs_apply(state *s, uint64_t slot, uint64_t count, uint64_t delta, transition_fn f) {
  if (!s || !f || slot >= s->size) return -1;
  uint64_t initial = atomic_load_explicit(&s->progress, memory_order_relaxed);
  for (uint64_t i = 0; i < count; ++i) {
    if (atomic_load_explicit(&s->cancel, memory_order_relaxed)) return 0;
    s->data[slot] = f(s->data[slot], delta);
    atomic_store_explicit(&s->progress, initial+i+1, memory_order_release);
  }
  return 1;
}
void hs_cancel(state *s) { atomic_store_explicit(&s->cancel, 1, memory_order_release); }
uint64_t hs_progress(state *s) { return atomic_load_explicit(&s->progress, memory_order_acquire); }
uint64_t hs_live(void) { return atomic_load(&live); }
uint64_t hs_allocations(void) { return atomic_load(&allocations); }
uint64_t hs_frees(void) { return atomic_load(&frees); }
uint64_t hs_refusals(void) { return atomic_load(&refusals); }
