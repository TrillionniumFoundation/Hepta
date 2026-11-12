/* Development-only dependency declarations for the exact SQLite random.c.
 * No PRNG algorithm appears here. The five typed effects are controlled peers.
 */
#ifndef HIA_RANDOM_ORACLE_SQLITEINT_H
#define HIA_RANDOM_ORACLE_SQLITEINT_H
#include <assert.h>
#include <stdint.h>
#include <string.h>
typedef uint32_t u32;
typedef unsigned char u8;
typedef struct sqlite3_mutex { uint64_t identity; } sqlite3_mutex;
typedef struct sqlite3_vfs { uint64_t identity; } sqlite3_vfs;
#define SQLITE_WSD
#define SQLITE_THREADSAFE 1
#define SQLITE_MUTEX_STATIC_PRNG 5
#define GLOBAL(type, name) name
#define NEVER(value) (value)
int sqlite3_initialize(void);
sqlite3_mutex *sqlite3MutexAlloc(int);
void sqlite3_mutex_enter(sqlite3_mutex *);
void sqlite3_mutex_leave(sqlite3_mutex *);
sqlite3_vfs *sqlite3_vfs_find(const char *);
int sqlite3OsRandomness(sqlite3_vfs *, int, char *);
#endif
