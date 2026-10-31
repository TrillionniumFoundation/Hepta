SQLITE_PRIVATE u32 sqlite3Get4byte(const u8 *p){
#if SQLITE_BYTEORDER==4321
  u32 x;
  memcpy(&x,p,4);
  return x;
#elif SQLITE_BYTEORDER==1234 && GCC_VERSION>=4003000
  u32 x;
  memcpy(&x,p,4);
  return __builtin_bswap32(x);
#elif SQLITE_BYTEORDER==1234 && MSVC_VERSION>=1300
  u32 x;
  memcpy(&x,p,4);
  return _byteswap_ulong(x);
#else
  testcase( p[0]&0x80 );
  return ((unsigned)p[0]<<24) | (p[1]<<16) | (p[2]<<8) | p[3];
#endif
}
SQLITE_PRIVATE void sqlite3Put4byte(unsigned char *p, u32 v){
#if SQLITE_BYTEORDER==4321
  memcpy(p,&v,4);
#elif SQLITE_BYTEORDER==1234 && GCC_VERSION>=4003000
  u32 x = __builtin_bswap32(v);
  memcpy(p,&x,4);
#elif SQLITE_BYTEORDER==1234 && MSVC_VERSION>=1300
  u32 x = _byteswap_ulong(v);
  memcpy(p,&x,4);
#else
  p[0] = (u8)(v>>24);
  p[1] = (u8)(v>>16);
  p[2] = (u8)(v>>8);
  p[3] = (u8)v;
#endif
}
