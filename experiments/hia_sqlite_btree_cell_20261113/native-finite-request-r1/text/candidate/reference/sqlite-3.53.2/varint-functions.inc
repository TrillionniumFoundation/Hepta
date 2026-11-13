#define SLOT_2_0     0x001fc07f
#define SLOT_4_2_0   0xf01fc07f

u8 sqlite3GetVarint(const unsigned char *p, u64 *v){
  u32 a,b,s;

  if( ((signed char*)p)[0]>=0 ){
    *v = *p;
    return 1;
  }
  if( ((signed char*)p)[1]>=0 ){
    *v = ((u32)(p[0]&0x7f)<<7) | p[1];
    return 2;
  }

  /* Verify that constants are precomputed correctly */
  assert( SLOT_2_0 == ((0x7f<<14) | (0x7f)) );
  assert( SLOT_4_2_0 == ((0xfU<<28) | (0x7f<<14) | (0x7f)) );

  a = ((u32)p[0])<<14;
  b = p[1];
  p += 2;
  a |= *p;
  /* a: p0<<14 | p2 (unmasked) */
  if (!(a&0x80))
  {
    a &= SLOT_2_0;
    b &= 0x7f;
    b = b<<7;
    a |= b;
    *v = a;
    return 3;
  }

  /* CSE1 from below */
  a &= SLOT_2_0;
  p++;
  b = b<<14;
  b |= *p;
  /* b: p1<<14 | p3 (unmasked) */
  if (!(b&0x80))
  {
    b &= SLOT_2_0;
    /* moved CSE1 up */
    /* a &= (0x7f<<14)|(0x7f); */
    a = a<<7;
    a |= b;
    *v = a;
    return 4;
  }

  /* a: p0<<14 | p2 (masked) */
  /* b: p1<<14 | p3 (unmasked) */
  /* 1:save off p0<<21 | p1<<14 | p2<<7 | p3 (masked) */
  /* moved CSE1 up */
  /* a &= (0x7f<<14)|(0x7f); */
  b &= SLOT_2_0;
  s = a;
  /* s: p0<<14 | p2 (masked) */

  p++;
  a = a<<14;
  a |= *p;
  /* a: p0<<28 | p2<<14 | p4 (unmasked) */
  if (!(a&0x80))
  {
    /* we can skip these cause they were (effectively) done above
    ** while calculating s */
    /* a &= (0x7f<<28)|(0x7f<<14)|(0x7f); */
    /* b &= (0x7f<<14)|(0x7f); */
    b = b<<7;
    a |= b;
    s = s>>18;
    *v = ((u64)s)<<32 | a;
    return 5;
  }

  /* 2:save off p0<<21 | p1<<14 | p2<<7 | p3 (masked) */
  s = s<<7;
  s |= b;
  /* s: p0<<21 | p1<<14 | p2<<7 | p3 (masked) */

  p++;
  b = b<<14;
  b |= *p;
  /* b: p1<<28 | p3<<14 | p5 (unmasked) */
  if (!(b&0x80))
  {
    /* we can skip this cause it was (effectively) done above in calc'ing s */
    /* b &= (0x7f<<28)|(0x7f<<14)|(0x7f); */
    a &= SLOT_2_0;
    a = a<<7;
    a |= b;
    s = s>>18;
    *v = ((u64)s)<<32 | a;
    return 6;
  }

  p++;
  a = a<<14;
  a |= *p;
  /* a: p2<<28 | p4<<14 | p6 (unmasked) */
  if (!(a&0x80))
  {
    a &= SLOT_4_2_0;
    b &= SLOT_2_0;
    b = b<<7;
    a |= b;
    s = s>>11;
    *v = ((u64)s)<<32 | a;
    return 7;
  }

  /* CSE2 from below */
  a &= SLOT_2_0;
  p++;
  b = b<<14;
  b |= *p;
  /* b: p3<<28 | p5<<14 | p7 (unmasked) */
  if (!(b&0x80))
  {
    b &= SLOT_4_2_0;
    /* moved CSE2 up */
    /* a &= (0x7f<<14)|(0x7f); */
    a = a<<7;
    a |= b;
    s = s>>4;
    *v = ((u64)s)<<32 | a;
    return 8;
  }

  p++;
  a = a<<15;
  a |= *p;
  /* a: p4<<29 | p6<<15 | p8 (unmasked) */

  /* moved CSE2 up */
  /* a &= (0x7f<<29)|(0x7f<<15)|(0xff); */
  b &= SLOT_2_0;
  b = b<<8;
  a |= b;

  s = s<<4;
  b = p[-4];
  b &= 0x7f;
  b = b>>3;
  s |= b;

  *v = ((u64)s)<<32 | a;

  return 9;
}

u8 sqlite3GetVarint32(const unsigned char *p, u32 *v){
  u64 v64;
  u8 n;

  /* Assume that the single-byte case has already been handled by
  ** the getVarint32() macro */
  assert( (p[0] & 0x80)!=0 );

  if( (p[1] & 0x80)==0 ){
    /* This is the two-byte case */
    *v = ((p[0]&0x7f)<<7) | p[1];
    return 2;
  }
  if( (p[2] & 0x80)==0 ){
    /* This is the three-byte case */
    *v = ((p[0]&0x7f)<<14) | ((p[1]&0x7f)<<7) | p[2];
    return 3;
  }
  /* four or more bytes */
  n = sqlite3GetVarint(p, &v64);
  assert( n>3 && n<=9 );
  if( (v64 & SQLITE_MAX_U32)!=v64 ){
    *v = 0xffffffff;
  }else{
    *v = (u32)v64;
  }
  return n;
}
