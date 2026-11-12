/* NEW controlled oracle; every marked SQLite function/table is exact 3.46.1.
 * Only the raw osStat provider and the outer bounded test ABI are new.
 * No actual filesystem syscall occurs in this policy comparison.
 */
#define _GNU_SOURCE 1
#define SQLITE_ASCII 1
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
typedef unsigned char u8;
typedef uint32_t u32;
typedef int64_t sqlite_int64;
#define ALWAYS(x) (x)
#define testcase(x) ((void)0)
#define ArraySize(a) ((int)(sizeof(a)/sizeof((a)[0])))
#define UpperToLower sqlite3UpperToLower
#define sqlite3StrNICmp sqlite3_strnicmp
#define sqlite3Isdigit(x) (sqlite3CtypeMap[(unsigned char)(x)]&0x04)
#define sqlite3Isxdigit(x) (sqlite3CtypeMap[(unsigned char)(x)]&0x08)
#define SQLITE_OK 0
#define SQLITE_IOERR_FSTAT 1802
#define SQLITE_OPEN_DELETEONCLOSE 8
#define SQLITE_OPEN_URI 64
#define SQLITE_OPEN_MAIN_JOURNAL 2048
#define SQLITE_OPEN_WAL 524288
#define MAX_PATHNAME 512
typedef struct {
  uint64_t kind;
  int64_t result;
  uint64_t error, mode, size, nlink, dev, ino, uid, gid;
} RawReturn;
static const RawReturn *script;
static uint64_t script_count, cursor, event_count, used, capacity, failed;
static unsigned char *events;
static void word(unsigned char *p,uint64_t x){
  for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(x>>(8*i));
}
static void event(const char *path){
  uint64_t n=strlen(path);
  if(n>UINT64_MAX-48 || used>capacity || n+48>capacity-used){failed=1;return;}
  uint64_t h[6]={29,0,0,0,0,n};
  for(unsigned i=0;i<6;i++)word(events+used+8*i,h[i]);
  if(n)memcpy(events+used+48,path,(size_t)n);
  used+=48+n;event_count++;
}
static int osStat(const char *path,struct stat *s){
  event(path);
  if(cursor>=script_count){failed=2;errno=EINVAL;return -1;}
  RawReturn r=script[cursor++];
  if(r.kind!=29){failed=3;errno=EINVAL;return -1;}
  if(r.result<0){errno=(int)r.error;return -1;}
  if(r.result!=0){failed=4;errno=EINVAL;return -1;}
  memset(s,0,sizeof(*s));s->st_mode=(mode_t)r.mode;s->st_size=(off_t)r.size;
  s->st_nlink=(nlink_t)r.nlink;s->st_dev=(dev_t)r.dev;s->st_ino=(ino_t)r.ino;
  s->st_uid=(uid_t)r.uid;s->st_gid=(gid_t)r.gid;return 0;
}
/* BEGIN EXACT 0 global.c 2013c4f51e859f030169202a7a8d1adedf577c97427f962c4eb4e06e4c2e0d88 */
const unsigned char sqlite3UpperToLower[] = {
#ifdef SQLITE_ASCII
      0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17,
     18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
     36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
     54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 97, 98, 99,100,101,102,103,
    104,105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,
    122, 91, 92, 93, 94, 95, 96, 97, 98, 99,100,101,102,103,104,105,106,107,
    108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,
    126,127,128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143,
    144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,
    162,163,164,165,166,167,168,169,170,171,172,173,174,175,176,177,178,179,
    180,181,182,183,184,185,186,187,188,189,190,191,192,193,194,195,196,197,
    198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,
    216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,
    234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,
    252,253,254,255,
#endif
#ifdef SQLITE_EBCDIC
      0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15, /* 0x */
     16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, /* 1x */
     32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, /* 2x */
     48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, /* 3x */
     64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, /* 4x */
     80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, /* 5x */
     96, 97, 98, 99,100,101,102,103,104,105,106,107,108,109,110,111, /* 6x */
    112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127, /* 7x */
    128,129,130,131,132,133,134,135,136,137,138,139,140,141,142,143, /* 8x */
    144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159, /* 9x */
    160,161,162,163,164,165,166,167,168,169,170,171,140,141,142,175, /* Ax */
    176,177,178,179,180,181,182,183,184,185,186,187,188,189,190,191, /* Bx */
    192,129,130,131,132,133,134,135,136,137,202,203,204,205,206,207, /* Cx */
    208,145,146,147,148,149,150,151,152,153,218,219,220,221,222,223, /* Dx */
    224,225,162,163,164,165,166,167,168,169,234,235,236,237,238,239, /* Ex */
    240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255, /* Fx */
#endif
/* All of the upper-to-lower conversion data is above.  The following
** 18 integers are completely unrelated.  They are appended to the
** sqlite3UpperToLower[] array to avoid UBSAN warnings.  Here's what is
** going on:
**
** The SQL comparison operators (<>, =, >, <=, <, and >=) are implemented
** by invoking sqlite3MemCompare(A,B) which compares values A and B and
** returns negative, zero, or positive if A is less then, equal to, or
** greater than B, respectively.  Then the true false results is found by
** consulting sqlite3aLTb[opcode], sqlite3aEQb[opcode], or 
** sqlite3aGTb[opcode] depending on whether the result of compare(A,B)
** is negative, zero, or positive, where opcode is the specific opcode.
** The only works because the comparison opcodes are consecutive and in
** this order: NE EQ GT LE LT GE.  Various assert()s throughout the code
** ensure that is the case.
**
** These elements must be appended to another array.  Otherwise the
** index (here shown as [256-OP_Ne]) would be out-of-bounds and thus
** be undefined behavior.  That's goofy, but the C-standards people thought
** it was a good idea, so here we are.
*/
/* NE  EQ  GT  LE  LT  GE  */
   1,  0,  0,  1,  1,  0,  /* aLTb[]: Use when compare(A,B) less than zero */
   0,  1,  0,  1,  0,  1,  /* aEQb[]: Use when compare(A,B) equals zero */
   1,  0,  1,  0,  0,  1   /* aGTb[]: Use when compare(A,B) greater than zero*/
};
/* END EXACT 0 */

/* BEGIN EXACT 1 global.c f2723e818f17b70b77054fc24ee1952989cddd2e4e0dbdcd092f51250cf56cb9 */
const unsigned char sqlite3CtypeMap[256] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* 00..07    ........ */
  0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00,  /* 08..0f    ........ */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* 10..17    ........ */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* 18..1f    ........ */
  0x01, 0x00, 0x80, 0x00, 0x40, 0x00, 0x00, 0x80,  /* 20..27     !"#$%&' */
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* 28..2f    ()*+,-./ */
  0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,  /* 30..37    01234567 */
  0x0c, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  /* 38..3f    89:;<=>? */

  0x00, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x0a, 0x02,  /* 40..47    @ABCDEFG */
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  /* 48..4f    HIJKLMNO */
  0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,  /* 50..57    PQRSTUVW */
  0x02, 0x02, 0x02, 0x80, 0x00, 0x00, 0x00, 0x40,  /* 58..5f    XYZ[\]^_ */
  0x80, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x22,  /* 60..67    `abcdefg */
  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,  /* 68..6f    hijklmno */
  0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,  /* 70..77    pqrstuvw */
  0x22, 0x22, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00,  /* 78..7f    xyz{|}~. */

  0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,  /* 80..87    ........ */
  0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,  /* 88..8f    ........ */
  0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,  /* 90..97    ........ */
  0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,  /* 98..9f    ........ */
  0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,  /* a0..a7    ........ */
  0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,  /* a8..af    ........ */
  0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,  /* b0..b7    ........ */
  0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,  /* b8..bf    ........ */

  0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,  /* c0..c7    ........ */
  0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,  /* c8..cf    ........ */
  0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,  /* d0..d7    ........ */
  0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,  /* d8..df    ........ */
  0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,  /* e0..e7    ........ */
  0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,  /* e8..ef    ........ */
  0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,  /* f0..f7    ........ */
  0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40   /* f8..ff    ........ */
};
/* END EXACT 1 */

/* BEGIN EXACT 2 util.c 6401ad7bdb40dffe8e88c36b3215a749ae3dcb9a94c5914dd3d2300987cc92fa */
int sqlite3Strlen30(const char *z){
  if( z==0 ) return 0;
  return 0x3fffffff & (int)strlen(z);
}
/* END EXACT 2 */

/* BEGIN EXACT 3 util.c 1c0c82e131eedfa9d1c2c2326651b8921ca996d9e1ebae91573b42e3a9b01a26 */
int sqlite3_strnicmp(const char *zLeft, const char *zRight, int N){
  register unsigned char *a, *b;
  if( zLeft==0 ){
    return zRight ? -1 : 0;
  }else if( zRight==0 ){
    return 1;
  }
  a = (unsigned char *)zLeft;
  b = (unsigned char *)zRight;
  while( N-- > 0 && *a!=0 && UpperToLower[*a]==UpperToLower[*b]){ a++; b++; }
  return N<0 ? 0 : UpperToLower[*a] - UpperToLower[*b];
}
/* END EXACT 3 */

/* BEGIN EXACT 4 util.c 31f7bfd19c63c61ad7e24d43f0537874e1a89cad421ae65c5e158f1f2fde6d1d */
u8 sqlite3HexToInt(int h){
  assert( (h>='0' && h<='9') ||  (h>='a' && h<='f') ||  (h>='A' && h<='F') );
#ifdef SQLITE_ASCII
  h += 9*(1&(h>>6));
#endif
#ifdef SQLITE_EBCDIC
  h += 9*(1&~(h>>4));
#endif
  return (u8)(h & 0xf);
}
/* END EXACT 4 */

/* BEGIN EXACT 5 util.c 3b05027a8f1395bebe3951a32b0fe3b694a11a41440140c0dedd3b851442c66c */
int sqlite3GetInt32(const char *zNum, int *pValue){
  sqlite_int64 v = 0;
  int i, c;
  int neg = 0;
  if( zNum[0]=='-' ){
    neg = 1;
    zNum++;
  }else if( zNum[0]=='+' ){
    zNum++;
  }
#ifndef SQLITE_OMIT_HEX_INTEGER
  else if( zNum[0]=='0'
        && (zNum[1]=='x' || zNum[1]=='X')
        && sqlite3Isxdigit(zNum[2])
  ){
    u32 u = 0;
    zNum += 2;
    while( zNum[0]=='0' ) zNum++;
    for(i=0; i<8 && sqlite3Isxdigit(zNum[i]); i++){
      u = u*16 + sqlite3HexToInt(zNum[i]);
    }
    if( (u&0x80000000)==0 && sqlite3Isxdigit(zNum[i])==0 ){
      memcpy(pValue, &u, 4);
      return 1;
    }else{
      return 0;
    }
  }
#endif
  if( !sqlite3Isdigit(zNum[0]) ) return 0;
  while( zNum[0]=='0' ) zNum++;
  for(i=0; i<11 && (c = zNum[i] - '0')>=0 && c<=9; i++){
    v = v*10 + c;
  }

  /* The longest decimal representation of a 32 bit integer is 10 digits:
  **
  **             1234567890
  **     2^31 -> 2147483648
  */
  testcase( i==10 );
  if( i>10 ){
    return 0;
  }
  testcase( v-neg==2147483647 );
  if( v-neg>2147483647 ){
    return 0;
  }
  if( neg ){
    v = -v;
  }
  *pValue = (int)v;
  return 1;
}
/* END EXACT 5 */

/* BEGIN EXACT 6 util.c 20042b7851ea69a72807a545765bb184956f1dde79aeb7ac99e4e6b5b6c36a26 */
int sqlite3Atoi(const char *z){
  int x = 0;
  sqlite3GetInt32(z, &x);
  return x;
}
/* END EXACT 6 */

/* BEGIN EXACT 7 pragma.c 382237003a655c37f956dbbb48e10a4facb8c1d39d469894315c473ad464b2ae */
static u8 getSafetyLevel(const char *z, int omitFull, u8 dflt){
                             /* 123456789 123456789 123 */
  static const char zText[] = "onoffalseyestruextrafull";
  static const u8 iOffset[] = {0, 1, 2,  4,    9,  12,  15,   20};
  static const u8 iLength[] = {2, 2, 3,  5,    3,   4,   5,    4};
  static const u8 iValue[] =  {1, 0, 0,  0,    1,   1,   3,    2};
                            /* on no off false yes true extra full */
  int i, n;
  if( sqlite3Isdigit(*z) ){
    return (u8)sqlite3Atoi(z);
  }
  n = sqlite3Strlen30(z);
  for(i=0; i<ArraySize(iLength); i++){
    if( iLength[i]==n && sqlite3StrNICmp(&zText[iOffset[i]],z,n)==0
     && (!omitFull || iValue[i]<=1)
    ){
      return iValue[i];
    }
  }
  return dflt;
}
/* END EXACT 7 */

/* BEGIN EXACT 8 pragma.c 364af4a65c5e2cb9c346c88847f3e6db5656046f98c3118d0f399627c3afc7a9 */
u8 sqlite3GetBoolean(const char *z, u8 dflt){
  return getSafetyLevel(z,1,dflt)!=0;
}
/* END EXACT 8 */

/* BEGIN EXACT 9 main.c cf6a2fb778e7c5b0ec338c581dd2301e289cbfab5e6d1c5846aea348c184c9cd */
static const char *databaseName(const char *zName){
  while( zName[-1]!=0 || zName[-2]!=0 || zName[-3]!=0 || zName[-4]!=0 ){
    zName--;
  }
  return zName;
}
/* END EXACT 9 */

/* BEGIN EXACT 10 main.c 5436facc9fa926f17dd2dbca593c7cfa5047757f4448fc70bef06ae8fa9a3fbb */
static const char *uriParameter(const char *zFilename, const char *zParam){
  zFilename += sqlite3Strlen30(zFilename) + 1;
  while( ALWAYS(zFilename!=0) && zFilename[0] ){
    int x = strcmp(zFilename, zParam);
    zFilename += sqlite3Strlen30(zFilename) + 1;
    if( x==0 ) return zFilename;
    zFilename += sqlite3Strlen30(zFilename) + 1;
  }
  return 0;
}
/* END EXACT 10 */

/* BEGIN EXACT 11 main.c c42737fb5e037d825a804ea884167814cc26205f5b397308f9631efa789eb1cc */
const char *sqlite3_uri_parameter(const char *zFilename, const char *zParam){
  if( zFilename==0 || zParam==0 ) return 0;
  zFilename = databaseName(zFilename);
  return uriParameter(zFilename, zParam);
}
/* END EXACT 11 */

/* BEGIN EXACT 12 main.c d62c492f9b36b5703256db95542d998ef18304e66ea81d6c326a729396753b14 */
int sqlite3_uri_boolean(const char *zFilename, const char *zParam, int bDflt){
  const char *z = sqlite3_uri_parameter(zFilename, zParam);
  bDflt = bDflt!=0;
  return z ? sqlite3GetBoolean(z, bDflt) : bDflt;
}
/* END EXACT 12 */

/* BEGIN EXACT 13 os_unix.c 79c1993d9e8fa1e903e1f61050ee7942620386ccc224639a0f1001d7da3f071a */
static int getFileMode(
  const char *zFile,              /* File name */
  mode_t *pMode,                  /* OUT: Permissions of zFile */
  uid_t *pUid,                    /* OUT: uid of zFile. */
  gid_t *pGid                     /* OUT: gid of zFile. */
){
  struct stat sStat;              /* Output of stat() on database file */
  int rc = SQLITE_OK;
  if( 0==osStat(zFile, &sStat) ){
    *pMode = sStat.st_mode & 0777;
    *pUid = sStat.st_uid;
    *pGid = sStat.st_gid;
  }else{
    rc = SQLITE_IOERR_FSTAT;
  }
  return rc;
}
/* END EXACT 13 */

/* BEGIN EXACT 14 os_unix.c 3a930c4b89e868948ed674cb98c04f48b47620af49e3b129477d6e95d723a8b9 */
static int findCreateFileMode(
  const char *zPath,              /* Path of file (possibly) being created */
  int flags,                      /* Flags passed as 4th argument to xOpen() */
  mode_t *pMode,                  /* OUT: Permissions to open file with */
  uid_t *pUid,                    /* OUT: uid to set on the file */
  gid_t *pGid                     /* OUT: gid to set on the file */
){
  int rc = SQLITE_OK;             /* Return Code */
  *pMode = 0;
  *pUid = 0;
  *pGid = 0;
  if( flags & (SQLITE_OPEN_WAL|SQLITE_OPEN_MAIN_JOURNAL) ){
    char zDb[MAX_PATHNAME+1];     /* Database file path */
    int nDb;                      /* Number of valid bytes in zDb */

    /* zPath is a path to a WAL or journal file. The following block derives
    ** the path to the associated database file from zPath. This block handles
    ** the following naming conventions:
    **
    **   "<path to db>-journal"
    **   "<path to db>-wal"
    **   "<path to db>-journalNN"
    **   "<path to db>-walNN"
    **
    ** where NN is a decimal number. The NN naming schemes are
    ** used by the test_multiplex.c module.
    **
    ** In normal operation, the journal file name will always contain
    ** a '-' character.  However in 8+3 filename mode, or if a corrupt
    ** rollback journal specifies a super-journal with a goofy name, then
    ** the '-' might be missing or the '-' might be the first character in
    ** the filename.  In that case, just return SQLITE_OK with *pMode==0.
    */
    nDb = sqlite3Strlen30(zPath) - 1;
    while( nDb>0 && zPath[nDb]!='.' ){
      if( zPath[nDb]=='-' ){
        memcpy(zDb, zPath, nDb);
        zDb[nDb] = '\0';
        rc = getFileMode(zDb, pMode, pUid, pGid);
        break;
      }
      nDb--;
    }
  }else if( flags & SQLITE_OPEN_DELETEONCLOSE ){
    *pMode = 0600;
  }else if( flags & SQLITE_OPEN_URI ){
    /* If this is a main database file and the file was opened using a URI
    ** filename, check for the "modeof" parameter. If present, interpret
    ** its value as a filename and try to copy the mode, uid and gid from
    ** that file.  */
    const char *z = sqlite3_uri_parameter(zPath, "modeof");
    if( z ){
      rc = getFileMode(z, pMode, pUid, pGid);
    }
  }
  return rc;
}
/* END EXACT 14 */

uint64_t oracle_abi(void){
  return sizeof(RawReturn)==80 && sizeof(struct stat)==144 &&
    sizeof(mode_t)==4 && sizeof(uid_t)==4 && sizeof(gid_t)==4 && sizeof(int)==4
      ? UINT64_C(0x31304d434e414948) : 0;
}
int oracle_run(uint64_t op,const unsigned char *area,uint64_t area_bytes,
    uint64_t filename_offset,uint64_t present,
    const unsigned char *key,uint64_t key_bytes,uint64_t key_present,
    uint64_t flags,uint64_t default_value,uint64_t initial_errno,
    const RawReturn *returns,uint64_t count,unsigned char *trace,
    uint64_t trace_capacity,uint64_t *result,
    unsigned char *value_out,uint64_t value_capacity){
  if(op<1 || op>3 || present>1 || key_present>1 || !result ||
    (!returns && count) || (!trace && trace_capacity) || flags>UINT32_MAX ||
    default_value>UINT32_MAX || initial_errno>4095 || area_bytes>SIZE_MAX-1 ||
    key_bytes>SIZE_MAX-1 || (present && (!area || filename_offset>=area_bytes)) ||
    (!present && (area_bytes || filename_offset)) ||
    (!key_present && key_bytes) || (key_bytes && !key) || (op==1 && !present))return -1;
  if(key_bytes && memchr(key,0,(size_t)key_bytes))return -1;
  char *names=malloc((size_t)area_bytes+1),*param=malloc((size_t)key_bytes+1);
  if(!names || !param){free(names);free(param);return -1;}
  if(area_bytes)memcpy(names,area,(size_t)area_bytes);
  names[area_bytes]=0;
  if(key_bytes)memcpy(param,key,(size_t)key_bytes);
  param[key_bytes]=0;
  memset(result,0,16*sizeof(*result));
  const char *filename=present?names+filename_offset:0;
  const char *parameter=key_present?param:0;
  script=returns;script_count=count;cursor=event_count=used=failed=0;
  events=trace;capacity=trace_capacity;errno=(int)initial_errno;
  if(op==1){
    mode_t mode=0;uid_t uid=0;gid_t gid=0;
    int rc=findCreateFileMode(filename,(int)(uint32_t)flags,&mode,&uid,&gid);
    result[0]=(uint32_t)rc;result[1]=mode;result[2]=uid;result[3]=gid;
  }else if(op==2){
    const char *value=sqlite3_uri_parameter(filename,parameter);
    if(value){
      size_t n=strlen(value);
      if(n>value_capacity || n==value_capacity || !value_out){failed=5;}
      else{
        memcpy(value_out,value,n+1);
        result[5]=1;result[7]=(uint64_t)(value-names);result[8]=n;
      }
    }
  }else{
    result[6]=(uint32_t)sqlite3_uri_boolean(filename,parameter,(int)(uint32_t)default_value);
  }
  result[4]=(uint32_t)errno;result[9]=cursor;result[10]=event_count;
  result[11]=used;result[12]=failed;result[13]=count;
  result[14]=cursor==count;result[15]=op;
  script=NULL;events=NULL;free(param);free(names);return 0;
}
