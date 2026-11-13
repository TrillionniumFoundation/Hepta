/* Independent test adapter. Compile separately against each exact upstream
 * checksum.inc and decode-frame.inc. No HIA code is linked into this oracle.
 */
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error This qualification adapter is explicitly limited to little-endian hosts
#endif

typedef uint8_t u8;
typedef uint32_t u32;
#define SQLITE_BIGENDIAN 0
#define WAL_FRAME_HDRSIZE 24
#define BYTESWAP32(x) (((u32)(x)>>24) | (((u32)(x)>>8)&0xff00u) | (((u32)(x)<<8)&0xff0000u) | ((u32)(x)<<24))

typedef struct {
  struct { u32 aFrameCksum[2]; u32 aSalt[2]; u8 bigEndCksum; } hdr;
  int szPage;
} Wal;

/* Only the upstream helper's documented big-endian word load is adapted. */
static u32 sqlite3Get4byte(const u8 *p){
  return ((u32)p[0]<<24) | ((u32)p[1]<<16) | ((u32)p[2]<<8) | p[3];
}

#include "checksum.inc"
#include "decode-frame.inc"

int oracle_checksum(const u8 *raw, size_t n, int order, u32 s0, u32 s1, u32 *out){
  u32 aligned[16384], initial[2];
  if(!raw || !out || n<8 || n>65536 || (n&7) || (order!=0 && order!=1))return -1;
  memcpy(aligned,raw,n);initial[0]=s0;initial[1]=s1;
  walChecksumBytes(order==SQLITE_BIGENDIAN,(u8*)aligned,(int)n,initial,out);
  return 1;
}

int oracle_frame(const u8 *raw, size_t n, int order, u32 page_size,
                 u32 seed0, u32 seed1, u32 salt0, u32 salt1, u32 *out){
  Wal w={0};u32 aligned[16390];u8 salts[8];u32 page=0,commit=0;int rc,i;
  if(!raw || !out || page_size<512 || page_size>65536 || (page_size&(page_size-1))
     || n!=page_size+24 || (order!=0 && order!=1))return -1;
  memcpy(aligned,raw,n);
  for(i=0;i<4;i++){salts[i]=(u8)(salt0>>(24-8*i));salts[4+i]=(u8)(salt1>>(24-8*i));}
  memcpy(w.hdr.aSalt,salts,8);w.hdr.aFrameCksum[0]=seed0;w.hdr.aFrameCksum[1]=seed1;
  w.hdr.bigEndCksum=(u8)order;w.szPage=(int)page_size;
  rc=walDecodeFrame(&w,&page,&commit,(u8*)aligned+24,(u8*)aligned);
  out[0]=w.hdr.aFrameCksum[0];out[1]=w.hdr.aFrameCksum[1];out[2]=page;out[3]=commit;
  return rc;
}
