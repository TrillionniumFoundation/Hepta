static void walChecksumBytes(
  int nativeCksum, /* True for native byte-order, false for non-native */
  u8 *a,           /* Content to be checksummed */
  int nByte,       /* Bytes of content in a[].  Must be a multiple of 8. */
  const u32 *aIn,  /* Initial checksum value input */
  u32 *aOut        /* OUT: Final checksum value output */
){
  u32 s1, s2;
  u32 *aData = (u32 *)a;
  u32 *aEnd = (u32 *)&a[nByte];

  if( aIn ){
    s1 = aIn[0];
    s2 = aIn[1];
  }else{
    s1 = s2 = 0;
  }

  assert( nByte>=8 );
  assert( (nByte&0x00000007)==0 );
  assert( nByte<=65536 );
  assert( nByte%4==0 );

  if( !nativeCksum ){
    do {
      s1 += BYTESWAP32(aData[0]) + s2;
      s2 += BYTESWAP32(aData[1]) + s1;
      aData += 2;
    }while( aData<aEnd );
  }else if( nByte%64==0 ){
    do {
      s1 += *aData++ + s2;
      s2 += *aData++ + s1;
      s1 += *aData++ + s2;
      s2 += *aData++ + s1;
      s1 += *aData++ + s2;
      s2 += *aData++ + s1;
      s1 += *aData++ + s2;
      s2 += *aData++ + s1;
      s1 += *aData++ + s2;
      s2 += *aData++ + s1;
      s1 += *aData++ + s2;
      s2 += *aData++ + s1;
      s1 += *aData++ + s2;
      s2 += *aData++ + s1;
      s1 += *aData++ + s2;
      s2 += *aData++ + s1;
    }while( aData<aEnd );
  }else{
    do {
      s1 += *aData++ + s2;
      s2 += *aData++ + s1;
    }while( aData<aEnd );
  }
  assert( aData==aEnd );

  aOut[0] = s1;
  aOut[1] = s2;
}
