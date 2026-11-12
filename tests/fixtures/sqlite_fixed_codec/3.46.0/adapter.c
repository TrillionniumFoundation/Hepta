/* Authored build adapter: does not modify the two upstream function bodies. */
#define SQLITE_PRIVATE
#define testcase(X)
typedef unsigned char u8;
typedef unsigned int u32;
#include "codec.inc"
