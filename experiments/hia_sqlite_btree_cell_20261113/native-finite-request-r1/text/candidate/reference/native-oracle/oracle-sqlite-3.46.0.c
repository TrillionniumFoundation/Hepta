/* Development reference oracle for SQLite 3.46.0 selected valid cells.
 * The full upstream excerpts below are byte-for-byte originals.
 * This ordinary-data harness is not the SQLite engine or a malformed-input
 * parser. Only the frozen independently admitted valid-cell matrix may call it.
 */
#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef NDEBUG
#error "Reference cell assertions must remain enabled"
#endif

/* Standalone fundamental aliases; their required widths are asserted below. */
typedef long long sqlite_int64;
typedef unsigned long long sqlite_uint64;

/* Keep the two reference libraries' non-public helper symbols distinct. */
#define sqlite3GetVarint hia_oracle_3460_GetVarint
#define sqlite3GetVarint32 hia_oracle_3460_GetVarint32

/* BEGIN original primitives */
#ifndef UINT32_TYPE
# ifdef HAVE_UINT32_T
#  define UINT32_TYPE uint32_t
# else
#  define UINT32_TYPE unsigned int
# endif
#endif
#ifndef UINT16_TYPE
# ifdef HAVE_UINT16_T
#  define UINT16_TYPE uint16_t
# else
#  define UINT16_TYPE unsigned short int
# endif
#endif
#ifndef INT16_TYPE
# ifdef HAVE_INT16_T
#  define INT16_TYPE int16_t
# else
#  define INT16_TYPE short int
# endif
#endif
#ifndef UINT8_TYPE
# ifdef HAVE_UINT8_T
#  define UINT8_TYPE uint8_t
# else
#  define UINT8_TYPE unsigned char
# endif
#endif
#ifndef INT8_TYPE
# ifdef HAVE_INT8_T
#  define INT8_TYPE int8_t
# else
#  define INT8_TYPE signed char
# endif
#endif
#ifndef LONGDOUBLE_TYPE
# define LONGDOUBLE_TYPE long double
#endif
typedef sqlite_int64 i64;          /* 8-byte signed integer */
typedef sqlite_uint64 u64;         /* 8-byte unsigned integer */
typedef UINT32_TYPE u32;           /* 4-byte unsigned integer */
typedef UINT16_TYPE u16;           /* 2-byte unsigned integer */
typedef INT16_TYPE i16;            /* 2-byte signed integer */
typedef UINT8_TYPE u8;             /* 1-byte unsigned integer */
typedef INT8_TYPE i8;              /* 1-byte signed integer */

#define getVarint32(A,B)  \
  (u8)((*(A)<(u8)0x80)?((B)=(u32)*(A)),1:sqlite3GetVarint32((A),(u32 *)&(B)))
#define getVarint32NR(A,B) \
  B=(u32)*(A);if(B>=0x80)sqlite3GetVarint32((A),(u32*)&(B))
#define putVarint32(A,B)  \
  (u8)(((u32)(B)<(u32)0x80)?(*(A)=(unsigned char)(B)),1:\
  sqlite3PutVarint((A),(B)))
#define getVarint    sqlite3GetVarint
#define putVarint    sqlite3PutVarint

#define UNUSED_PARAMETER(x) (void)(x)
#define UNUSED_PARAMETER2(x,y) UNUSED_PARAMETER(x),UNUSED_PARAMETER(y)

#define SQLITE_MAX_U32  ((((u64)1)<<32)-1)
/* END original primitives */

/* Opaque declarations complete the unchanged structures' pointer types.
 * No object behind these opaque pointers is opened or dereferenced here. */
typedef u32 Pgno;
typedef struct MemPage MemPage;
typedef struct BtShared BtShared;
typedef struct CellInfo CellInfo;
typedef struct Pager Pager;
typedef struct sqlite3 sqlite3;
typedef struct BtCursor BtCursor;
typedef struct sqlite3_mutex sqlite3_mutex;
typedef struct Bitvec Bitvec;
typedef struct BtLock BtLock;
typedef struct Btree Btree;
typedef struct PgHdr DbPage;

_Static_assert(CHAR_BIT == 8, "eight-bit bytes");
_Static_assert(sizeof(u8) == 1 && sizeof(u16) == 2 && sizeof(u32) == 4, "original unsigned widths");
_Static_assert(sizeof(u64) == 8 && sizeof(i64) == 8, "original 64-bit widths");
_Static_assert(sizeof(uint32_t) == 4 && sizeof(uint64_t) == 8, "export widths");
_Static_assert((i64)-1 < 0 && (u64)-1 > 0, "original signedness");
_Static_assert(sizeof(uintptr_t) == sizeof(void *), "pointer observation width");

/* Coverage and mutex scaffolding only. No database mutex is implemented.
 * All pBt->mutex fields are NULL in the admitted single-threaded data fixture. */
static int oracle_mutex_held(sqlite3_mutex *mutex){ return mutex == NULL; }
#define sqlite3_mutex_held(P) oracle_mutex_held(P)
#define testcase(X) ((void)0)
#define SQLITE_NOINLINE __attribute__((noinline))

/* BEGIN complete original structures */
struct MemPage {
  u8 isInit;           /* True if previously initialized. MUST BE FIRST! */
  u8 intKey;           /* True if table b-trees.  False for index b-trees */
  u8 intKeyLeaf;       /* True if the leaf of an intKey table */
  Pgno pgno;           /* Page number for this page */
  /* Only the first 8 bytes (above) are zeroed by pager.c when a new page
  ** is allocated. All fields that follow must be initialized before use */
  u8 leaf;             /* True if a leaf page */
  u8 hdrOffset;        /* 100 for page 1.  0 otherwise */
  u8 childPtrSize;     /* 0 if leaf==1.  4 if leaf==0 */
  u8 max1bytePayload;  /* min(maxLocal,127) */
  u8 nOverflow;        /* Number of overflow cell bodies in aCell[] */
  u16 maxLocal;        /* Copy of BtShared.maxLocal or BtShared.maxLeaf */
  u16 minLocal;        /* Copy of BtShared.minLocal or BtShared.minLeaf */
  u16 cellOffset;      /* Index in aData of first cell pointer */
  int nFree;           /* Number of free bytes on the page. -1 for unknown */
  u16 nCell;           /* Number of cells on this page, local and ovfl */
  u16 maskPage;        /* Mask for page offset */
  u16 aiOvfl[4];       /* Insert the i-th overflow cell before the aiOvfl-th
                       ** non-overflow cell */
  u8 *apOvfl[4];       /* Pointers to the body of overflow cells */
  BtShared *pBt;       /* Pointer to BtShared that this page is part of */
  u8 *aData;           /* Pointer to disk image of the page data */
  u8 *aDataEnd;        /* One byte past the end of the entire page - not just
                       ** the usable space, the entire page.  Used to prevent
                       ** corruption-induced buffer overflow. */
  u8 *aCellIdx;        /* The cell index area */
  u8 *aDataOfst;       /* Same as aData for leaves.  aData+4 for interior */
  DbPage *pDbPage;     /* Pager page handle */
  u16 (*xCellSize)(MemPage*,u8*);             /* cellSizePtr method */
  void (*xParseCell)(MemPage*,u8*,CellInfo*); /* btreeParseCell method */
};

struct BtShared {
  Pager *pPager;        /* The page cache */
  sqlite3 *db;          /* Database connection currently using this Btree */
  BtCursor *pCursor;    /* A list of all open cursors */
  MemPage *pPage1;      /* First page of the database */
  u8 openFlags;         /* Flags to sqlite3BtreeOpen() */
#ifndef SQLITE_OMIT_AUTOVACUUM
  u8 autoVacuum;        /* True if auto-vacuum is enabled */
  u8 incrVacuum;        /* True if incr-vacuum is enabled */
  u8 bDoTruncate;       /* True to truncate db on commit */
#endif
  u8 inTransaction;     /* Transaction state */
  u8 max1bytePayload;   /* Maximum first byte of cell for a 1-byte payload */
  u8 nReserveWanted;    /* Desired number of extra bytes per page */
  u16 btsFlags;         /* Boolean parameters.  See BTS_* macros below */
  u16 maxLocal;         /* Maximum local payload in non-LEAFDATA tables */
  u16 minLocal;         /* Minimum local payload in non-LEAFDATA tables */
  u16 maxLeaf;          /* Maximum local payload in a LEAFDATA table */
  u16 minLeaf;          /* Minimum local payload in a LEAFDATA table */
  u32 pageSize;         /* Total number of bytes on a page */
  u32 usableSize;       /* Number of usable bytes on each page */
  int nTransaction;     /* Number of open transactions (read + write) */
  u32 nPage;            /* Number of pages in the database */
  void *pSchema;        /* Pointer to space allocated by sqlite3BtreeSchema() */
  void (*xFreeSchema)(void*);  /* Destructor for BtShared.pSchema */
  sqlite3_mutex *mutex; /* Non-recursive mutex required to access this object */
  Bitvec *pHasContent;  /* Set of pages moved to free-list this transaction */
#ifndef SQLITE_OMIT_SHARED_CACHE
  int nRef;             /* Number of references to this structure */
  BtShared *pNext;      /* Next on a list of sharable BtShared structs */
  BtLock *pLock;        /* List of locks held on this shared-btree struct */
  Btree *pWriter;       /* Btree with currently open write transaction */
#endif
  u8 *pTmpSpace;        /* Temp space sufficient to hold a single cell */
  int nPreformatSize;   /* Size of last cell written by TransferRow() */
};

struct CellInfo {
  i64 nKey;      /* The key for INTKEY tables, or nPayload otherwise */
  u8 *pPayload;  /* Pointer to the start of payload */
  u32 nPayload;  /* Bytes of payload */
  u16 nLocal;    /* Amount of payload held locally, not on overflow */
  u16 nSize;     /* Size of the cell content on the main b-tree page */
};
/* END complete original structures */

/* BEGIN complete original varint functions */
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
/* END complete original varint functions */

/* BEGIN complete original cell functions */
static SQLITE_NOINLINE void btreeParseCellAdjustSizeForOverflow(
  MemPage *pPage,         /* Page containing the cell */
  u8 *pCell,              /* Pointer to the cell text. */
  CellInfo *pInfo         /* Fill in this structure */
){
  /* If the payload will not fit completely on the local page, we have
  ** to decide how much to store locally and how much to spill onto
  ** overflow pages.  The strategy is to minimize the amount of unused
  ** space on overflow pages while keeping the amount of local storage
  ** in between minLocal and maxLocal.
  **
  ** Warning:  changing the way overflow payload is distributed in any
  ** way will result in an incompatible file format.
  */
  int minLocal;  /* Minimum amount of payload held locally */
  int maxLocal;  /* Maximum amount of payload held locally */
  int surplus;   /* Overflow payload available for local storage */

  minLocal = pPage->minLocal;
  maxLocal = pPage->maxLocal;
  surplus = minLocal + (pInfo->nPayload - minLocal)%(pPage->pBt->usableSize-4);
  testcase( surplus==maxLocal );
  testcase( surplus==maxLocal+1 );
  if( surplus <= maxLocal ){
    pInfo->nLocal = (u16)surplus;
  }else{
    pInfo->nLocal = (u16)minLocal;
  }
  pInfo->nSize = (u16)(&pInfo->pPayload[pInfo->nLocal] - pCell) + 4;
}

static void btreeParseCellPtrNoPayload(
  MemPage *pPage,         /* Page containing the cell */
  u8 *pCell,              /* Pointer to the cell text. */
  CellInfo *pInfo         /* Fill in this structure */
){
  assert( sqlite3_mutex_held(pPage->pBt->mutex) );
  assert( pPage->leaf==0 );
  assert( pPage->childPtrSize==4 );
#ifndef SQLITE_DEBUG
  UNUSED_PARAMETER(pPage);
#endif
  pInfo->nSize = 4 + getVarint(&pCell[4], (u64*)&pInfo->nKey);
  pInfo->nPayload = 0;
  pInfo->nLocal = 0;
  pInfo->pPayload = 0;
  return;
}

static void btreeParseCellPtr(
  MemPage *pPage,         /* Page containing the cell */
  u8 *pCell,              /* Pointer to the cell text. */
  CellInfo *pInfo         /* Fill in this structure */
){
  u8 *pIter;              /* For scanning through pCell */
  u32 nPayload;           /* Number of bytes of cell payload */
  u64 iKey;               /* Extracted Key value */

  assert( sqlite3_mutex_held(pPage->pBt->mutex) );
  assert( pPage->leaf==0 || pPage->leaf==1 );
  assert( pPage->intKeyLeaf );
  assert( pPage->childPtrSize==0 );
  pIter = pCell;

  /* The next block of code is equivalent to:
  **
  **     pIter += getVarint32(pIter, nPayload);
  **
  ** The code is inlined to avoid a function call.
  */
  nPayload = *pIter;
  if( nPayload>=0x80 ){
    u8 *pEnd = &pIter[8];
    nPayload &= 0x7f;
    do{
      nPayload = (nPayload<<7) | (*++pIter & 0x7f);
    }while( (*pIter)>=0x80 && pIter<pEnd );
  }
  pIter++;

  /* The next block of code is equivalent to:
  **
  **     pIter += getVarint(pIter, (u64*)&pInfo->nKey);
  **
  ** The code is inlined and the loop is unrolled for performance.
  ** This routine is a high-runner.
  */
  iKey = *pIter;
  if( iKey>=0x80 ){
    u8 x;
    iKey = (iKey<<7) ^ (x = *++pIter);
    if( x>=0x80 ){
      iKey = (iKey<<7) ^ (x = *++pIter);
      if( x>=0x80 ){
        iKey = (iKey<<7) ^ 0x10204000 ^ (x = *++pIter);
        if( x>=0x80 ){
          iKey = (iKey<<7) ^ 0x4000 ^ (x = *++pIter);
          if( x>=0x80 ){
            iKey = (iKey<<7) ^ 0x4000 ^ (x = *++pIter);
            if( x>=0x80 ){
              iKey = (iKey<<7) ^ 0x4000 ^ (x = *++pIter);
              if( x>=0x80 ){
                iKey = (iKey<<7) ^ 0x4000 ^ (x = *++pIter);
                if( x>=0x80 ){
                  iKey = (iKey<<8) ^ 0x8000 ^ (*++pIter);
                }
              }
            }
          }
        }
      }else{
        iKey ^= 0x204000;
      }
    }else{
      iKey ^= 0x4000;
    }
  }
  pIter++;

  pInfo->nKey = *(i64*)&iKey;
  pInfo->nPayload = nPayload;
  pInfo->pPayload = pIter;
  testcase( nPayload==pPage->maxLocal );
  testcase( nPayload==(u32)pPage->maxLocal+1 );
  if( nPayload<=pPage->maxLocal ){
    /* This is the (easy) common case where the entire payload fits
    ** on the local page.  No overflow is required.
    */
    pInfo->nSize = nPayload + (u16)(pIter - pCell);
    if( pInfo->nSize<4 ) pInfo->nSize = 4;
    pInfo->nLocal = (u16)nPayload;
  }else{
    btreeParseCellAdjustSizeForOverflow(pPage, pCell, pInfo);
  }
}

static void btreeParseCellPtrIndex(
  MemPage *pPage,         /* Page containing the cell */
  u8 *pCell,              /* Pointer to the cell text. */
  CellInfo *pInfo         /* Fill in this structure */
){
  u8 *pIter;              /* For scanning through pCell */
  u32 nPayload;           /* Number of bytes of cell payload */

  assert( sqlite3_mutex_held(pPage->pBt->mutex) );
  assert( pPage->leaf==0 || pPage->leaf==1 );
  assert( pPage->intKeyLeaf==0 );
  pIter = pCell + pPage->childPtrSize;
  nPayload = *pIter;
  if( nPayload>=0x80 ){
    u8 *pEnd = &pIter[8];
    nPayload &= 0x7f;
    do{
      nPayload = (nPayload<<7) | (*++pIter & 0x7f);
    }while( *(pIter)>=0x80 && pIter<pEnd );
  }
  pIter++;
  pInfo->nKey = nPayload;
  pInfo->nPayload = nPayload;
  pInfo->pPayload = pIter;
  testcase( nPayload==pPage->maxLocal );
  testcase( nPayload==(u32)pPage->maxLocal+1 );
  if( nPayload<=pPage->maxLocal ){
    /* This is the (easy) common case where the entire payload fits
    ** on the local page.  No overflow is required.
    */
    pInfo->nSize = nPayload + (u16)(pIter - pCell);
    if( pInfo->nSize<4 ) pInfo->nSize = 4;
    pInfo->nLocal = (u16)nPayload;
  }else{
    btreeParseCellAdjustSizeForOverflow(pPage, pCell, pInfo);
  }
}
/* END complete original cell functions */

/* Export projection, in order:
 * [nKey_bits, payload_is_NULL, payload_page_offset, nPayload, nLocal, nSize].
 * pPayload NULL is a distinct bit; its offset is encoded as zero.
 * Return 0 means the original cell function returned with a valid projection.
 * Return 1 is a harness context refusal before a cell function is called.
 * Return 2 preserves the observed scalar fields with UINT64_MAX offset when
 * a non-NULL original pPayload unexpectedly lies outside the supplied page.
 * These guards do not replace independent complete-cell admission.
 */
uint32_t oracle_cell(const unsigned char *page, uint64_t page_bytes,
                     uint64_t usable, uint64_t kind, uint64_t cell_offset,
                     uint64_t *out6){
  BtShared shared = {0};
  BtShared *pBt = &shared;
  MemPage page_state = {0};
  MemPage *pPage = &page_state;
  CellInfo info;
  uint64_t key_bits;
  uintptr_t base, payload;

  if( page == NULL || out6 == NULL
      || page_bytes < 512 || page_bytes > 65536
      || (page_bytes & (page_bytes-1)) != 0
      || usable < 480 || usable > page_bytes || page_bytes-usable > 255
      || (kind != 2 && kind != 5 && kind != 10 && kind != 13)
      || cell_offset > usable-4 ){
    return 1;
  }
  pBt->pageSize = (u32)page_bytes;
  pBt->usableSize = (u32)usable;
/* BEGIN original local payload limits */
  pBt->maxLocal = (u16)((pBt->usableSize-12)*64/255 - 23);
  pBt->minLocal = (u16)((pBt->usableSize-12)*32/255 - 23);
  pBt->maxLeaf = (u16)(pBt->usableSize - 35);
  pBt->minLeaf = (u16)((pBt->usableSize-12)*32/255 - 23);
/* END original local payload limits */

  /* Ordinary MemPage fixture initialization follows original decodeFlags.
   * Only the fields used by the original four functions are required.
   * The full original structures above, including unused fields, are retained. */
  pPage->pBt = pBt;
  pPage->isInit = 1;
  pPage->leaf = (kind == 10 || kind == 13);
  pPage->intKey = (kind == 5 || kind == 13);
  pPage->intKeyLeaf = (kind == 13);
  pPage->childPtrSize = pPage->leaf ? 0 : 4;
  pPage->minLocal = pPage->intKey ? pBt->minLeaf : pBt->minLocal;
  pPage->maxLocal = pPage->intKey ? pBt->maxLeaf : pBt->maxLocal;
  pPage->aData = (u8 *)page;
  pPage->aDataEnd = (u8 *)page + page_bytes;
  memset(&info, 0xa5, sizeof(info));

  if( kind == 5 ){
    btreeParseCellPtrNoPayload(pPage, (u8 *)page + cell_offset, &info);
  }else if( kind == 13 ){
    btreeParseCellPtr(pPage, (u8 *)page + cell_offset, &info);
  }else{
    btreeParseCellPtrIndex(pPage, (u8 *)page + cell_offset, &info);
  }

  memcpy(&key_bits, &info.nKey, sizeof(key_bits));
  out6[0] = key_bits;
  out6[1] = info.pPayload == NULL;
  out6[2] = info.pPayload == NULL ? 0 : UINT64_MAX;
  out6[3] = info.nPayload;
  out6[4] = info.nLocal;
  out6[5] = info.nSize;
  if( info.pPayload != NULL ){
    base = (uintptr_t)page;
    payload = (uintptr_t)info.pPayload;
    if( base > UINTPTR_MAX-page_bytes || payload < base || payload > base+page_bytes ){
      return 2;
    }
    out6[2] = payload-base;
  }
  return 0;
}
