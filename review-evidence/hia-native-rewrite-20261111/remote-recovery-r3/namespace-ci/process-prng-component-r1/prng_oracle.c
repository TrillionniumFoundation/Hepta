/* NEW development oracle. This translation unit includes the original,
 * byte-pinned public-domain SQLite 3.46.1 random.c without modifying its text.
 * Controlled initialization/mutex/VFS dependencies do not claim OS authority.
 * Compile -Wl,-Bsymbolic-functions so host SQLite cannot interpose these peers.
 */
#include "sqliteInt.h"
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include "random.c"

_Static_assert(CHAR_BIT == 8, "byte");
_Static_assert(sizeof(int) == 4, "selected Linux int");
_Static_assert(sizeof(u32) == 4, "word");
_Static_assert(sizeof(struct sqlite3PrngType) == 132, "selected C layout");
_Static_assert(offsetof(struct sqlite3PrngType, n) == 128, "selected n offset");
static uint32_t init_bits;
static uint32_t entropy_bits;
static uint32_t entropy_prefix;
static uint32_t have_vfs;
static unsigned char seed[44];
static uint64_t held;
static sqlite3_mutex mutex_object = { 0x50524e47 };
static sqlite3_vfs vfs_object = { 0x564653 };
static unsigned char trace_rows[16][384];
static uint64_t trace_count;

static int from_bits(uint32_t value){
  int result;
  memcpy(&result, &value, 4);
  return result;
}
static void wr64(unsigned char *p, uint64_t value){
  memcpy(p, &value, 8);
}
static unsigned char *start_event(uint64_t op, uint64_t aux){
  unsigned char *row;
  assert(trace_count < 16);
  row = trace_rows[trace_count++];
  memset(row, 0, 384);
  wr64(row, op);
  wr64(row+16, aux);
  wr64(row+24, held);
  wr64(row+40, trace_count);
  memcpy(row+64, &sqlite3Prng, 132);
  return row;
}
static void finish_event(unsigned char *row, uint32_t result){
  wr64(row+8, result);
  wr64(row+32, held);
  memcpy(row+196, &sqlite3Prng, 132);
}

int sqlite3_initialize(void){
  unsigned char *row = start_event(10, 0);
  finish_event(row, init_bits);
  return from_bits(init_bits);
}
sqlite3_mutex *sqlite3MutexAlloc(int id){
  unsigned char *row = start_event(20, (uint32_t)id);
  assert(id == SQLITE_MUTEX_STATIC_PRNG);
  finish_event(row, 0);
  return &mutex_object;
}
void sqlite3_mutex_enter(sqlite3_mutex *mutex){
  unsigned char *row = start_event(21, 0);
  assert(mutex == &mutex_object && held == 0);
  held = 1;
  finish_event(row, 0);
}
void sqlite3_mutex_leave(sqlite3_mutex *mutex){
  unsigned char *row = start_event(50, 0);
  assert(mutex == &mutex_object && held == 1);
  held = 0;
  finish_event(row, 0);
}
sqlite3_vfs *sqlite3_vfs_find(const char *name){
  unsigned char *row = start_event(30, 0);
  assert(name == NULL && held == 1);
  finish_event(row, have_vfs);
  return have_vfs ? &vfs_object : NULL;
}
int sqlite3OsRandomness(sqlite3_vfs *vfs, int n, char *out){
  unsigned char *row = start_event(40, (uint32_t)n);
  assert(vfs == &vfs_object && held == 1 && n == 44);
  assert((unsigned char *)out == (unsigned char *)&sqlite3Prng.s[4]);
  memcpy(out, seed, entropy_prefix);
  memcpy(row+328, out, 44);
  finish_event(row, entropy_bits);
  return from_bits(entropy_bits);
}

int hia_prng_oracle_reset(void){
  const uint32_t endian = 1;
  if(*(const unsigned char *)&endian != 1) return -1;
  memset(&sqlite3Prng, 0, sizeof(sqlite3Prng));
  memset(&sqlite3SavedPrng, 0, sizeof(sqlite3SavedPrng));
  memset(trace_rows, 0, sizeof(trace_rows));
  memset(seed, 0, sizeof(seed));
  trace_count = held = init_bits = 0;
  entropy_bits = entropy_prefix = 44;
  have_vfs = 1;
  return 0;
}
int hia_prng_oracle_configure(uint32_t init, uint32_t vfs,
                            uint32_t randomness_result, uint32_t written_prefix,
                            const void *seed_bytes, uint64_t seed_extent){
  if(vfs > 1 || written_prefix > 44 || seed_extent != 44 || !seed_bytes || held)
    return -1;
  init_bits = init;
  have_vfs = vfs;
  entropy_bits = randomness_result;
  entropy_prefix = written_prefix;
  memcpy(seed, seed_bytes, 44);
  trace_count = 0;
  memset(trace_rows, 0, sizeof(trace_rows));
  return 0;
}
int hia_prng_oracle_call(uint32_t api, uint32_t n_bits, uint32_t destination,
                       void *output, uint64_t output_extent){
  int n = from_bits(n_bits);
  if(held || destination > 1) return -1;
  if(api == 1){
    if(destination && n > 0 && (!output || output_extent < (uint32_t)n))
      return -1;
    sqlite3_randomness(n, destination ? output : NULL);
  }else if(api == 2){
    if(n_bits || destination) return -1;
    sqlite3PrngSaveState();
  }else if(api == 3){
    if(n_bits || destination) return -1;
    sqlite3PrngRestoreState();
  }else{
    return -1;
  }
  return held == 0 ? 0 : -1;
}
uint64_t hia_prng_oracle_events(void){ return trace_count; }
int hia_prng_oracle_event(uint64_t number, void *output, uint64_t extent){
  if(number >= trace_count || !output || extent != 384) return -1;
  memcpy(output, trace_rows[number], 384);
  return 0;
}
int hia_prng_oracle_state(void *current, void *saved, uint64_t extent){
  if(!current || !saved || extent != 132) return -1;
  memcpy(current, &sqlite3Prng, 132);
  memcpy(saved, &sqlite3SavedPrng, 132);
  return 0;
}
/* Private counter-near-wrap and saved-state boundary fixtures only.
 * This is not a public SQLite or namespace admission surface.
 */
int hia_prng_oracle_private_state(const void *current, const void *saved,
                                  uint64_t extent){
  if(!current || !saved || extent != 132 || held) return -1;
  memcpy(&sqlite3Prng, current, 132);
  memcpy(&sqlite3SavedPrng, saved, 132);
  return 0;
}
