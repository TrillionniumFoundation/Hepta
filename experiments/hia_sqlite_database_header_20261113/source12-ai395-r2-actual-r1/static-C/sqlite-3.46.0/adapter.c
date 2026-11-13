/* Finite page-one byte-admission reference, not an SQLite engine.
 * Complete original lockBtree and data structures are retained below.
 * Pager, lock and WAL effects are successful fixture providers with raw events.
 */
#include <assert.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef NDEBUG
#error "Original assertions must remain enabled"
#endif
#if defined(SQLITE_OMIT_WAL) || defined(SQLITE_OMIT_AUTOVACUUM)
#error "WAL and autovacuum byte branches are required"
#endif
#define SQLITE_DEBUG 1
#define SQLITE_BYTEORDER 1234
#define GCC_VERSION (__GNUC__*1000000 + __GNUC_MINOR__*1000 + __GNUC_PATCHLEVEL__)
#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "Frozen little-endian reference host required"
#endif
typedef long long sqlite_int64;
typedef unsigned long long sqlite_uint64;

/* original primitives */
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

/* finite wrapper opaque context declarations */

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
_Static_assert(CHAR_BIT==8 && sizeof(int)==4, "byte/int widths");
_Static_assert(sizeof(u8)==1 && sizeof(u16)==2 && sizeof(u32)==4, "unsigned widths");
_Static_assert(sizeof(u64)==8 && sizeof(i64)==8, "64-bit widths");
_Static_assert(sizeof(uintptr_t)==sizeof(void*), "pointer observation width");
static int oracle_mutex_held(sqlite3_mutex *p){ return p==NULL; }
#define sqlite3_mutex_held(P) oracle_mutex_held(P)

/* complete original structures */
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

/* original macro MX_CELL_SIZE */
#define MX_CELL_SIZE(pBt)  ((int)(pBt->pageSize-8))

/* original macro BTS_READ_ONLY */
#define BTS_READ_ONLY        0x0001   /* Underlying file is readonly */

/* original macro BTS_PAGESIZE_FIXED */
#define BTS_PAGESIZE_FIXED   0x0002   /* Page size can no longer be changed */

/* original macro BTS_NO_WAL */
#define BTS_NO_WAL           0x0020   /* Do not open write-ahead-log files */

/* original SQLITE_ResetDatabase */
#define SQLITE_ResetDatabase  0x02000000  /* Reset the database */

/* reference helper symbol namespace */
#define sqlite3Get4byte hia_header_3460_Get4byte

/* complete original endian macros */
#define get2byte(x)   ((x)[0]<<8 | (x)[1])
#define put2byte(p,v) ((p)[0] = (u8)((v)>>8), (p)[1] = (u8)(v))
#define get4byte sqlite3Get4byte
#define put4byte sqlite3Put4byte

/*
** get2byteAligned(), unlike get2byte(), requires that its argument point to a
** two-byte aligned address.  get2byteAligned() is only used for accessing the
** cell addresses in a btree header.
*/
#if SQLITE_BYTEORDER==4321
# define get2byteAligned(x)  (*(u16*)(x))
#elif SQLITE_BYTEORDER==1234 && GCC_VERSION>=4008000
# define get2byteAligned(x)  __builtin_bswap16(*(u16*)(x))
#elif SQLITE_BYTEORDER==1234 && MSVC_VERSION>=1300
# define get2byteAligned(x)  _byteswap_ushort(*(u16*)(x))
#else
# define get2byteAligned(x)  ((x)[0]<<8 | (x)[1])
#endif

/* complete original sqlite3Get4byte */
u32 sqlite3Get4byte(const u8 *p){
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

/* successful fixture effect providers */

/* Fixed build defaults and result aliases. No engine error logging or real
 * synchronous setting is supplied by this finite reference context.
 */
#define SQLITE_OK 0
#define SQLITE_NOTADB 26
#define SQLITE_CORRUPT_BKPT 11
#define SQLITE_MAX_PAGE_SIZE 65536
#define SQLITE_DEFAULT_SYNCHRONOUS 2
#define SQLITE_DEFAULT_WAL_SYNCHRONOUS 2
static const u8 zMagicHeader[16] = "SQLite format 3";

/* These two external context shells are deliberately NOT the original
 * SQLite Pager or connection structures. writable_schema is a supplied,
 * already-resolved capability, not an emulated SQL connection policy.
 */
typedef struct HeaderFixture HeaderFixture;
struct sqlite3 { u64 flags; int writable_schema; };
struct Pager { HeaderFixture *fixture; };
struct HeaderFixture {
  Pager pager;
  sqlite3 db;
  BtShared shared;
  MemPage page;
  u8 header[100];
  u32 file_pages;
  int wal_ready;
  uint64_t *events;
  u64 event_words;
  u64 event_used;
  u64 counts[9];
  u64 sync_argument;
  u64 resize_page;
  u64 resize_reserve;
};
static void header_event(HeaderFixture *f,u64 code,u64 a,u64 b){
  assert(code>0 && code<9);
  if(f->event_used+3>f->event_words) abort();
  f->events[f->event_used++]=code;
  f->events[f->event_used++]=a;
  f->events[f->event_used++]=b;
  f->counts[code]++;
}
static int sqlite3PagerSharedLock(Pager *p){
  header_event(p->fixture,1,0,0); return SQLITE_OK;
}
static int btreeGetPage(BtShared *p,Pgno number,MemPage **result,int noContent){
  HeaderFixture *f=p->pPager->fixture;
  assert(number==1 && noContent==0 && p==&f->shared);
  header_event(f,2,number,(u64)noContent);
  *result=&f->page; return SQLITE_OK;
}
static void sqlite3PagerPagecount(Pager *p,int *result){
  HeaderFixture *f=p->fixture;
  header_event(f,3,f->file_pages,0);
  memcpy(result,&f->file_pages,sizeof(f->file_pages));
}
static int sqlite3PagerOpenWal(Pager *p,int *alreadyOpen){
  HeaderFixture *f=p->fixture;
  header_event(f,4,(u64)f->wal_ready,0);
  *alreadyOpen=f->wal_ready; return SQLITE_OK;
}
static void setDefaultSyncFlag(BtShared *p,u8 flags){
  HeaderFixture *f=p->pPager->fixture;
  header_event(f,5,flags,0); f->sync_argument=flags;
}
static void releasePageOne(MemPage *p){
  HeaderFixture *f=p->pBt->pPager->fixture;
  assert(p==&f->page);
  header_event(f,6,p->pgno,0);
}
static void freeTempSpace(BtShared *p){
  HeaderFixture *f=p->pPager->fixture;
  assert(p->pTmpSpace==NULL);
  header_event(f,7,0,0);
}
static int sqlite3PagerSetPagesize(Pager *p,u32 *pageSize,int reserve){
  HeaderFixture *f=p->fixture;
  header_event(f,8,*pageSize,(u64)reserve);
  f->resize_page=*pageSize; f->resize_reserve=(u64)reserve;
  return SQLITE_OK;
}
static int sqlite3WritableSchema(sqlite3 *db){
  assert(db->writable_schema==0 || db->writable_schema==1);
  return db->writable_schema;
}

/* complete original lockBtree */
static int lockBtree(BtShared *pBt){
  int rc;              /* Result code from subfunctions */
  MemPage *pPage1;     /* Page 1 of the database file */
  u32 nPage;           /* Number of pages in the database */
  u32 nPageFile = 0;   /* Number of pages in the database file */

  assert( sqlite3_mutex_held(pBt->mutex) );
  assert( pBt->pPage1==0 );
  rc = sqlite3PagerSharedLock(pBt->pPager);
  if( rc!=SQLITE_OK ) return rc;
  rc = btreeGetPage(pBt, 1, &pPage1, 0);
  if( rc!=SQLITE_OK ) return rc;

  /* Do some checking to help insure the file we opened really is
  ** a valid database file.
  */
  nPage = get4byte(28+(u8*)pPage1->aData);
  sqlite3PagerPagecount(pBt->pPager, (int*)&nPageFile);
  if( nPage==0 || memcmp(24+(u8*)pPage1->aData, 92+(u8*)pPage1->aData,4)!=0 ){
    nPage = nPageFile;
  }
  if( (pBt->db->flags & SQLITE_ResetDatabase)!=0 ){
    nPage = 0;
  }
  if( nPage>0 ){
    u32 pageSize;
    u32 usableSize;
    u8 *page1 = pPage1->aData;
    rc = SQLITE_NOTADB;
    /* EVIDENCE-OF: R-43737-39999 Every valid SQLite database file begins
    ** with the following 16 bytes (in hex): 53 51 4c 69 74 65 20 66 6f 72 6d
    ** 61 74 20 33 00. */
    if( memcmp(page1, zMagicHeader, 16)!=0 ){
      goto page1_init_failed;
    }

#ifdef SQLITE_OMIT_WAL
    if( page1[18]>1 ){
      pBt->btsFlags |= BTS_READ_ONLY;
    }
    if( page1[19]>1 ){
      goto page1_init_failed;
    }
#else
    if( page1[18]>2 ){
      pBt->btsFlags |= BTS_READ_ONLY;
    }
    if( page1[19]>2 ){
      goto page1_init_failed;
    }

    /* If the read version is set to 2, this database should be accessed
    ** in WAL mode. If the log is not already open, open it now. Then
    ** return SQLITE_OK and return without populating BtShared.pPage1.
    ** The caller detects this and calls this function again. This is
    ** required as the version of page 1 currently in the page1 buffer
    ** may not be the latest version - there may be a newer one in the log
    ** file.
    */
    if( page1[19]==2 && (pBt->btsFlags & BTS_NO_WAL)==0 ){
      int isOpen = 0;
      rc = sqlite3PagerOpenWal(pBt->pPager, &isOpen);
      if( rc!=SQLITE_OK ){
        goto page1_init_failed;
      }else{
        setDefaultSyncFlag(pBt, SQLITE_DEFAULT_WAL_SYNCHRONOUS+1);
        if( isOpen==0 ){
          releasePageOne(pPage1);
          return SQLITE_OK;
        }
      }
      rc = SQLITE_NOTADB;
    }else{
      setDefaultSyncFlag(pBt, SQLITE_DEFAULT_SYNCHRONOUS+1);
    }
#endif

    /* EVIDENCE-OF: R-15465-20813 The maximum and minimum embedded payload
    ** fractions and the leaf payload fraction values must be 64, 32, and 32.
    **
    ** The original design allowed these amounts to vary, but as of
    ** version 3.6.0, we require them to be fixed.
    */
    if( memcmp(&page1[21], "\100\040\040",3)!=0 ){
      goto page1_init_failed;
    }
    /* EVIDENCE-OF: R-51873-39618 The page size for a database file is
    ** determined by the 2-byte integer located at an offset of 16 bytes from
    ** the beginning of the database file. */
    pageSize = (page1[16]<<8) | (page1[17]<<16);
    /* EVIDENCE-OF: R-25008-21688 The size of a page is a power of two
    ** between 512 and 65536 inclusive. */
    if( ((pageSize-1)&pageSize)!=0
     || pageSize>SQLITE_MAX_PAGE_SIZE
     || pageSize<=256
    ){
      goto page1_init_failed;
    }
    assert( (pageSize & 7)==0 );
    /* EVIDENCE-OF: R-59310-51205 The "reserved space" size in the 1-byte
    ** integer at offset 20 is the number of bytes of space at the end of
    ** each page to reserve for extensions.
    **
    ** EVIDENCE-OF: R-37497-42412 The size of the reserved region is
    ** determined by the one-byte unsigned integer found at an offset of 20
    ** into the database file header. */
    usableSize = pageSize - page1[20];
    if( (u32)pageSize!=pBt->pageSize ){
      /* After reading the first page of the database assuming a page size
      ** of BtShared.pageSize, we have discovered that the page-size is
      ** actually pageSize. Unlock the database, leave pBt->pPage1 at
      ** zero and return SQLITE_OK. The caller will call this function
      ** again with the correct page-size.
      */
      releasePageOne(pPage1);
      pBt->usableSize = usableSize;
      pBt->pageSize = pageSize;
      pBt->btsFlags |= BTS_PAGESIZE_FIXED;
      freeTempSpace(pBt);
      rc = sqlite3PagerSetPagesize(pBt->pPager, &pBt->pageSize,
                                   pageSize-usableSize);
      return rc;
    }
    if( nPage>nPageFile ){
      if( sqlite3WritableSchema(pBt->db)==0 ){
        rc = SQLITE_CORRUPT_BKPT;
        goto page1_init_failed;
      }else{
        nPage = nPageFile;
      }
    }
    /* EVIDENCE-OF: R-28312-64704 However, the usable size is not allowed to
    ** be less than 480. In other words, if the page size is 512, then the
    ** reserved space size cannot exceed 32. */
    if( usableSize<480 ){
      goto page1_init_failed;
    }
    pBt->btsFlags |= BTS_PAGESIZE_FIXED;
    pBt->pageSize = pageSize;
    pBt->usableSize = usableSize;
#ifndef SQLITE_OMIT_AUTOVACUUM
    pBt->autoVacuum = (get4byte(&page1[36 + 4*4])?1:0);
    pBt->incrVacuum = (get4byte(&page1[36 + 7*4])?1:0);
#endif
  }

  /* maxLocal is the maximum amount of payload to store locally for
  ** a cell.  Make sure it is small enough so that at least minFanout
  ** cells can will fit on one page.  We assume a 10-byte page header.
  ** Besides the payload, the cell must store:
  **     2-byte pointer to the cell
  **     4-byte child pointer
  **     9-byte nKey value
  **     4-byte nData value
  **     4-byte overflow page pointer
  ** So a cell consists of a 2-byte pointer, a header which is as much as
  ** 17 bytes long, 0 to N bytes of payload, and an optional 4 byte overflow
  ** page pointer.
  */
  pBt->maxLocal = (u16)((pBt->usableSize-12)*64/255 - 23);
  pBt->minLocal = (u16)((pBt->usableSize-12)*32/255 - 23);
  pBt->maxLeaf = (u16)(pBt->usableSize - 35);
  pBt->minLeaf = (u16)((pBt->usableSize-12)*32/255 - 23);
  if( pBt->maxLocal>127 ){
    pBt->max1bytePayload = 127;
  }else{
    pBt->max1bytePayload = (u8)pBt->maxLocal;
  }
  assert( pBt->maxLeaf + 23 <= MX_CELL_SIZE(pBt) );
  pBt->pPage1 = pPage1;
  pBt->nPage = nPage;
  return SQLITE_OK;

page1_init_failed:
  releasePageOne(pPage1);
  pBt->pPage1 = 0;
  return rc;
}

/* raw context and event observation API */

/* Independent transport refusal precedes every output or event write. */
static int header_span(const void *p,u64 bytes){
  uintptr_t a=(uintptr_t)p;
  return p!=NULL && bytes<=(u64)UINTPTR_MAX && a<=UINTPTR_MAX-(uintptr_t)bytes;
}
static int header_overlap(const void *a,u64 an,const void *b,u64 bn){
  return (uintptr_t)a<(uintptr_t)b+(uintptr_t)bn
      && (uintptr_t)b<(uintptr_t)a+(uintptr_t)an;
}
/* command[7] = current page, current usable, logical file pages,
 * flags(reset,writable,no_wal,read_only,auto,incr), wal_ready, zero, zero.
 * out[32] contains raw original fields; events[32] stores triples
 * (code,arg0,arg1), leaving its unused tail seed unchanged.
 * Return1 refuses transport before writes. Return0 means original lockBtree
 * ran; its actual semantic rc, including format failures, is out[0].
 */
uint32_t oracle_lock_btree(const unsigned char *header,uint64_t header_bytes,
                          const uint64_t *command,uint64_t command_words,
                          uint64_t *out,uint64_t out_words,
                          uint64_t *events,uint64_t event_words){
  HeaderFixture f={0};
  int rc;
  u64 flags;
  if(header_bytes!=100 || command_words!=7 || out_words!=32 || event_words!=32)
    return 1;
  if(!header_span(header,100) || !header_span(command,56)
      || !header_span(out,256) || !header_span(events,256))
    return 1;
  if(((uintptr_t)command|((uintptr_t)out)|((uintptr_t)events))&7u)
    return 1;
  if(header_overlap(header,100,command,56) || header_overlap(header,100,out,256)
      || header_overlap(header,100,events,256) || header_overlap(command,56,out,256)
      || header_overlap(command,56,events,256) || header_overlap(out,256,events,256))
    return 1;
  if(command[0]<512 || command[0]>65536 || (command[0]&(command[0]-1))
      || command[1]>command[0] || command[0]-command[1]>255
      || command[2]>UINT32_MAX || command[3]>63 || command[4]>1
      || command[5]!=0 || command[6]!=0)
    return 1;
  flags=command[3];
  f.events=events; f.event_words=event_words; f.sync_argument=UINT64_MAX;
  f.file_pages=(u32)command[2]; f.wal_ready=(int)command[4];
  f.pager.fixture=&f; f.shared.pPager=&f.pager; f.shared.db=&f.db;
  f.shared.pageSize=(u32)command[0]; f.shared.usableSize=(u32)command[1];
  f.shared.btsFlags=(u16)(((flags&4)?BTS_NO_WAL:0)|((flags&8)?BTS_READ_ONLY:0));
  f.shared.autoVacuum=(u8)((flags>>4)&1); f.shared.incrVacuum=(u8)((flags>>5)&1);
  f.db.flags=(flags&1)?SQLITE_ResetDatabase:0;
  f.db.writable_schema=(int)((flags>>1)&1);
  memcpy(f.header,header,100);
  f.page.aData=f.header; f.page.aDataEnd=f.header+100;
  f.page.pBt=&f.shared; f.page.pgno=1;
  rc=lockBtree(&f.shared);
  for(unsigned i=0;i<32;i++)out[i]=0;
  out[0]=(u64)(unsigned)rc; out[1]=(f.shared.pPage1!=NULL);
  out[2]=(f.shared.btsFlags&BTS_READ_ONLY)!=0;
  out[3]=f.shared.pageSize; out[4]=f.shared.usableSize;
  out[5]=f.shared.nPage; out[6]=f.shared.autoVacuum; out[7]=f.shared.incrVacuum;
  out[8]=(f.shared.btsFlags&BTS_PAGESIZE_FIXED)!=0;
  out[9]=f.shared.maxLocal; out[10]=f.shared.minLocal;
  out[11]=f.shared.maxLeaf; out[12]=f.shared.minLeaf;
  out[13]=f.shared.max1bytePayload; out[14]=f.shared.btsFlags;
  out[15]=f.db.flags; out[16]=f.sync_argument;
  out[17]=f.counts[1]; out[18]=f.counts[2]; out[19]=f.counts[3];
  out[20]=f.counts[4]; out[21]=f.counts[6]; out[22]=f.counts[7];
  out[23]=f.counts[8]; out[24]=f.resize_reserve; out[25]=f.resize_page;
  out[26]=f.event_used/3;
  return 0;
}
