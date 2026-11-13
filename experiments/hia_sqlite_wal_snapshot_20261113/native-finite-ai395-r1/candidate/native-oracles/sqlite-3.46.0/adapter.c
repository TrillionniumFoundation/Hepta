/* Finite in-memory test transport; no HIA code, SQLite pager, OS locks or SQL.
 * The complete selected original wal.c bodies below are byte-exact.
 * Compile separately for each version with assertions enabled.
 */
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error This finite oracle requires a little-endian host
#endif
#ifdef NDEBUG
#error Original assertions must remain enabled
#endif
#define SQLITE_DEBUG 1
#define SQLITE_ENABLE_EXPENSIVE_ASSERT 1
#define SQLITE_BYTEORDER 1234
#define SQLITE_BIGENDIAN 0
#define GCC_VERSION (__GNUC__*1000000+__GNUC_MINOR__*1000+__GNUC_PATCHLEVEL__)
#define MSVC_VERSION 0
#define SQLITE_NOINLINE __attribute__((noinline))
#define SQLITE_NO_TSAN
#define SQLITE_OK 0
#define SQLITE_ERROR 1
#define SQLITE_BUSY 5
#define SQLITE_NOMEM 7
#define SQLITE_NOMEM_BKPT SQLITE_NOMEM
#define SQLITE_READONLY 8
#define SQLITE_CORRUPT_BKPT 11
#define SQLITE_CANTOPEN_BKPT 14
#define SQLITE_IOERR_SHORT_READ (10 | (2<<8))
#define SQLITE_NOTICE_RECOVER_WAL (27 | (1<<8))
#define SQLITE_MAX_PAGE_SIZE 65536
#define SQLITE_SHM_NLOCK 8
#define SQLITE_SHM_UNLOCK 1
#define SQLITE_SHM_LOCK 2
#define SQLITE_SHM_SHARED 4
#define SQLITE_SHM_EXCLUSIVE 8
#define MIN(A,B) ((A)<(B)?(A):(B))
#define testcase(X) ((void)(X))
#define NEVER(X) ((X)?(assert(0),1):0)
#define ALWAYS(X) ((X)?1:(assert(0),0))
#define VVA_ONLY(X) X
#define WALTRACE(X) do {} while(0)
#define CORRUPT_DB 0
/* These single-thread transport loads/stores do not qualify concurrency. */
#define AtomicLoad(P) __atomic_load_n((P), __ATOMIC_RELAXED)
#define AtomicStore(P,V) __atomic_store_n((P),(V),__ATOMIC_RELAXED)
#define ORACLE_MAX_WAL_BYTES (8ULL<<20)
#define ORACLE_MAX_READ_WORDS 32772ULL

typedef uint8_t u8;
typedef uint16_t u16;
typedef int16_t i16;
typedef uint32_t u32;
typedef int64_t i64;
typedef uint64_t u64;
typedef int64_t sqlite3_int64;
typedef uint64_t sqlite3_uint64;
typedef uint32_t Pgno;
typedef struct Wal Wal;
typedef struct sqlite3_vfs sqlite3_vfs;
/* Deliberately a finite file-view transport, not a real sqlite3_file layout. */
typedef struct sqlite3_file {
  const u8 *bytes;
  u64 length;
  u64 *read_pairs;
  u64 read_words;
  u64 read_calls;
  u64 read_bytes;
  u64 size_calls;
  u64 read_errors;
  u64 last_offset;
  u64 last_size;
} sqlite3_file;

static void *sqlite3_malloc64(sqlite3_uint64 n){
  if(n>(64ULL<<20))return NULL;
  return malloc((size_t)n);
}
static void *sqlite3MallocZero(sqlite3_uint64 n){
  if(n>(64ULL<<20))return NULL;
  return calloc(1,(size_t)n);
}
static void *sqlite3Realloc(void *p,sqlite3_uint64 n){
  if(n>(64ULL<<20))return NULL;
  return realloc(p,(size_t)n);
}
static void sqlite3_free(void *p){free(p);}
static int sqlite3FaultSim(int code){(void)code;return 0;}
static void sqlite3_log(int code,const char *fmt,...){(void)code;(void)fmt;}
static int sqlite3OsFileSize(sqlite3_file *f,i64 *n){
  assert(f && n && f->length<=ORACLE_MAX_WAL_BYTES);
  f->size_calls++;*n=(i64)f->length;return SQLITE_OK;
}
static int sqlite3OsRead(sqlite3_file *f,void *dst,int amount,i64 offset){
  assert(f && dst && amount>0 && offset>=0);
  assert(f->read_calls<f->read_words/2);
  f->read_pairs[2*f->read_calls]=(u64)offset;
  f->read_pairs[2*f->read_calls+1]=(u64)amount;
  f->read_calls++;f->last_offset=(u64)offset;f->last_size=(u64)amount;
  if((u64)offset>f->length || (u64)amount>f->length-(u64)offset){
    u64 available=(u64)offset<f->length?f->length-(u64)offset:0;
    memset(dst,0,(size_t)amount);
    if(available)memcpy(dst,f->bytes+(u64)offset,(size_t)available);
    f->read_bytes+=available;f->read_errors++;
    return SQLITE_IOERR_SHORT_READ;
  }
  memcpy(dst,f->bytes+(u64)offset,(size_t)amount);
  f->read_bytes+=(u64)amount;return SQLITE_OK;
}
/* WAL_HEAPMEMORY_MODE makes these genuine VFS paths unreachable. */
static int sqlite3OsShmMap(sqlite3_file *f,int page,int size,int write,
                          void volatile **out){
  (void)f;(void)page;(void)size;(void)write;(void)out;abort();
}
static void sqlite3OsShmBarrier(sqlite3_file *f){(void)f;abort();}
static int sqlite3OsShmLock(sqlite3_file *f,int offset,int count,int flags){
  (void)f;(void)offset;(void)count;(void)flags;abort();
}

#define sqlite3Get4byte oracle_sqlite3460_Get4byte

/* BEGIN ORIGINAL wal.c version-lock-definitions */
#define WAL_MAX_VERSION      3007000
#define WALINDEX_MAX_VERSION 3007000

/*
** Index numbers for various locking bytes.   WAL_NREADER is the number
** of available reader locks and should be at least 3.  The default
** is SQLITE_SHM_NLOCK==8 and  WAL_NREADER==5.
**
** Technically, the various VFSes are free to implement these locks however
** they see fit.  However, compatibility is encouraged so that VFSes can
** interoperate.  The standard implementation used on both unix and windows
** is for the index number to indicate a byte offset into the
** WalCkptInfo.aLock[] array in the wal-index header.  In other words, all
** locks are on the shm file.  The WALINDEX_LOCK_OFFSET constant (which
** should be 120) is the location in the shm file for the first locking
** byte.
*/
#define WAL_WRITE_LOCK         0
#define WAL_ALL_BUT_WRITE      1
#define WAL_CKPT_LOCK          1
#define WAL_RECOVER_LOCK       2
#define WAL_READ_LOCK(I)       (3+(I))
#define WAL_NREADER            (SQLITE_SHM_NLOCK-3)


/* Object declarations */
typedef struct WalIndexHdr WalIndexHdr;
typedef struct WalIterator WalIterator;
typedef struct WalCkptInfo WalCkptInfo;
/* END ORIGINAL version-lock-definitions */

/* BEGIN ORIGINAL wal.c WalIndexHdr */
struct WalIndexHdr {
  u32 iVersion;                   /* Wal-index version */
  u32 unused;                     /* Unused (padding) field */
  u32 iChange;                    /* Counter incremented each transaction */
  u8 isInit;                      /* 1 when initialized */
  u8 bigEndCksum;                 /* True if checksums in WAL are big-endian */
  u16 szPage;                     /* Database page size in bytes. 1==64K */
  u32 mxFrame;                    /* Index of last valid frame in the WAL */
  u32 nPage;                      /* Size of database in pages */
  u32 aFrameCksum[2];             /* Checksum of last frame in log */
  u32 aSalt[2];                   /* Two salt values copied from WAL header */
  u32 aCksum[2];                  /* Checksum over all prior fields */
};
/* END ORIGINAL WalIndexHdr */

/* BEGIN ORIGINAL wal.c WalCkptInfo */
struct WalCkptInfo {
  u32 nBackfill;                  /* Number of WAL frames backfilled into DB */
  u32 aReadMark[WAL_NREADER];     /* Reader marks */
  u8 aLock[SQLITE_SHM_NLOCK];     /* Reserved space for locks */
  u32 nBackfillAttempted;         /* WAL frames perhaps written, or maybe not */
  u32 notUsed0;                   /* Available for future enhancements */
};
#define READMARK_NOT_USED  0xffffffff
/* END ORIGINAL WalCkptInfo */

/* BEGIN ORIGINAL wal.c wal-macros-Wal-and-ht_slot */
#define WALINDEX_LOCK_OFFSET (sizeof(WalIndexHdr)*2+offsetof(WalCkptInfo,aLock))
#define WALINDEX_HDR_SIZE    (sizeof(WalIndexHdr)*2+sizeof(WalCkptInfo))

/* Size of header before each frame in wal */
#define WAL_FRAME_HDRSIZE 24

/* Size of write ahead log header, including checksum. */
#define WAL_HDRSIZE 32

/* WAL magic value. Either this value, or the same value with the least
** significant bit also set (WAL_MAGIC | 0x00000001) is stored in 32-bit
** big-endian format in the first 4 bytes of a WAL file.
**
** If the LSB is set, then the checksums for each frame within the WAL
** file are calculated by treating all data as an array of 32-bit
** big-endian words. Otherwise, they are calculated by interpreting
** all data as 32-bit little-endian words.
*/
#define WAL_MAGIC 0x377f0682

/*
** Return the offset of frame iFrame in the write-ahead log file,
** assuming a database page size of szPage bytes. The offset returned
** is to the start of the write-ahead log frame-header.
*/
#define walFrameOffset(iFrame, szPage) (                               \
  WAL_HDRSIZE + ((iFrame)-1)*(i64)((szPage)+WAL_FRAME_HDRSIZE)         \
)

/*
** An open write-ahead log file is represented by an instance of the
** following object.
*/
struct Wal {
  sqlite3_vfs *pVfs;         /* The VFS used to create pDbFd */
  sqlite3_file *pDbFd;       /* File handle for the database file */
  sqlite3_file *pWalFd;      /* File handle for WAL file */
  u32 iCallback;             /* Value to pass to log callback (or 0) */
  i64 mxWalSize;             /* Truncate WAL to this size upon reset */
  int nWiData;               /* Size of array apWiData */
  int szFirstBlock;          /* Size of first block written to WAL file */
  volatile u32 **apWiData;   /* Pointer to wal-index content in memory */
  u32 szPage;                /* Database page size */
  i16 readLock;              /* Which read lock is being held.  -1 for none */
  u8 syncFlags;              /* Flags to use to sync header writes */
  u8 exclusiveMode;          /* Non-zero if connection is in exclusive mode */
  u8 writeLock;              /* True if in a write transaction */
  u8 ckptLock;               /* True if holding a checkpoint lock */
  u8 readOnly;               /* WAL_RDWR, WAL_RDONLY, or WAL_SHM_RDONLY */
  u8 truncateOnCommit;       /* True to truncate WAL file on commit */
  u8 syncHeader;             /* Fsync the WAL header if true */
  u8 padToSectorBoundary;    /* Pad transactions out to the next sector */
  u8 bShmUnreliable;         /* SHM content is read-only and unreliable */
  WalIndexHdr hdr;           /* Wal-index header for current transaction */
  u32 minFrame;              /* Ignore wal frames before this one */
  u32 iReCksum;              /* On commit, recalculate checksums from here */
  const char *zWalName;      /* Name of WAL file */
  u32 nCkpt;                 /* Checkpoint sequence counter in the wal-header */
#ifdef SQLITE_USE_SEH
  u32 lockMask;              /* Mask of locks held */
  void *pFree;               /* Pointer to sqlite3_free() if exception thrown */
  u32 *pWiValue;             /* Value to write into apWiData[iWiPg] */
  int iWiPg;                 /* Write pWiValue into apWiData[iWiPg] */
  int iSysErrno;             /* System error code following exception */
#endif
#ifdef SQLITE_DEBUG
  int nSehTry;               /* Number of nested SEH_TRY{} blocks */
  u8 lockError;              /* True if a locking error has occurred */
#endif
#ifdef SQLITE_ENABLE_SNAPSHOT
  WalIndexHdr *pSnapshot;    /* Start transaction here if not NULL */
#endif
#ifdef SQLITE_ENABLE_SETLK_TIMEOUT
  sqlite3 *db;
#endif
};

/*
** Candidate values for Wal.exclusiveMode.
*/
#define WAL_NORMAL_MODE     0
#define WAL_EXCLUSIVE_MODE  1
#define WAL_HEAPMEMORY_MODE 2

/*
** Possible values for WAL.readOnly
*/
#define WAL_RDWR        0    /* Normal read/write connection */
#define WAL_RDONLY      1    /* The WAL file is readonly */
#define WAL_SHM_RDONLY  2    /* The SHM file is readonly */

/*
** Each page of the wal-index mapping contains a hash-table made up of
** an array of HASHTABLE_NSLOT elements of the following type.
*/
typedef u16 ht_slot;
/* END ORIGINAL wal-macros-Wal-and-ht_slot */

/* BEGIN ORIGINAL wal.c hash-constants */
#define HASHTABLE_NPAGE      4096                 /* Must be power of 2 */
#define HASHTABLE_HASH_1     383                  /* Should be prime */
#define HASHTABLE_NSLOT      (HASHTABLE_NPAGE*2)  /* Must be a power of 2 */

/*
** The block of page numbers associated with the first hash-table in a
** wal-index is smaller than usual. This is so that there is a complete
** hash-table on each aligned 32KB page of the wal-index.
*/
#define HASHTABLE_NPAGE_ONE  (HASHTABLE_NPAGE - (WALINDEX_HDR_SIZE/sizeof(u32)))

/* The wal-index is divided into pages of WALINDEX_PGSZ bytes each. */
#define WALINDEX_PGSZ   (                                         \
    sizeof(ht_slot)*HASHTABLE_NSLOT + HASHTABLE_NPAGE*sizeof(u32) \
)
/* END ORIGINAL hash-constants */

/* BEGIN ORIGINAL wal.c SEH-definitions */
#ifdef SQLITE_USE_SEH
#include <Windows.h>

/* Beginning of a block of code in which an exception might occur */
# define SEH_TRY    __try { \
   assert( walAssertLockmask(pWal) && pWal->nSehTry==0 ); \
   VVA_ONLY(pWal->nSehTry++);

/* The end of a block of code in which an exception might occur */
# define SEH_EXCEPT(X) \
   VVA_ONLY(pWal->nSehTry--); \
   assert( pWal->nSehTry==0 ); \
   } __except( sehExceptionFilter(pWal, GetExceptionCode(), GetExceptionInformation() ) ){ X }

/* Simulate a memory-mapping fault in the -shm file for testing purposes */
# define SEH_INJECT_FAULT sehInjectFault(pWal) 

/*
** The second argument is the return value of GetExceptionCode() for the 
** current exception. Return EXCEPTION_EXECUTE_HANDLER if the exception code
** indicates that the exception may have been caused by accessing the *-shm 
** file mapping. Or EXCEPTION_CONTINUE_SEARCH otherwise.
*/
static int sehExceptionFilter(Wal *pWal, int eCode, EXCEPTION_POINTERS *p){
  VVA_ONLY(pWal->nSehTry--);
  if( eCode==EXCEPTION_IN_PAGE_ERROR ){
    if( p && p->ExceptionRecord && p->ExceptionRecord->NumberParameters>=3 ){
      /* From MSDN: For this type of exception, the first element of the
      ** ExceptionInformation[] array is a read-write flag - 0 if the exception
      ** was thrown while reading, 1 if while writing. The second element is
      ** the virtual address being accessed. The "third array element specifies
      ** the underlying NTSTATUS code that resulted in the exception". */
      pWal->iSysErrno = (int)p->ExceptionRecord->ExceptionInformation[2];
    }
    return EXCEPTION_EXECUTE_HANDLER;
  }
  return EXCEPTION_CONTINUE_SEARCH;
}

/*
** If one is configured, invoke the xTestCallback callback with 650 as
** the argument. If it returns true, throw the same exception that is
** thrown by the system if the *-shm file mapping is accessed after it
** has been invalidated.
*/
static void sehInjectFault(Wal *pWal){
  int res;
  assert( pWal->nSehTry>0 );

  res = sqlite3FaultSim(650);
  if( res!=0 ){
    ULONG_PTR aArg[3];
    aArg[0] = 0;
    aArg[1] = 0;
    aArg[2] = (ULONG_PTR)res;
    RaiseException(EXCEPTION_IN_PAGE_ERROR, 0, 3, (const ULONG_PTR*)aArg);
  }
}

/*
** There are two ways to use this macro. To set a pointer to be freed
** if an exception is thrown:
**
**   SEH_FREE_ON_ERROR(0, pPtr);
**
** and to cancel the same:
**
**   SEH_FREE_ON_ERROR(pPtr, 0);
**
** In the first case, there must not already be a pointer registered to
** be freed. In the second case, pPtr must be the registered pointer.
*/
#define SEH_FREE_ON_ERROR(X,Y) \
  assert( (X==0 || Y==0) && pWal->pFree==X ); pWal->pFree = Y

/*
** There are two ways to use this macro. To arrange for pWal->apWiData[iPg]
** to be set to pValue if an exception is thrown:
**
**   SEH_SET_ON_ERROR(iPg, pValue);
**
** and to cancel the same:
**
**   SEH_SET_ON_ERROR(0, 0);
*/
#define SEH_SET_ON_ERROR(X,Y)  pWal->iWiPg = X; pWal->pWiValue = Y

#else
# define SEH_TRY          VVA_ONLY(pWal->nSehTry++);
# define SEH_EXCEPT(X)    VVA_ONLY(pWal->nSehTry--); assert( pWal->nSehTry==0 );
# define SEH_INJECT_FAULT assert( pWal->nSehTry>0 );
# define SEH_FREE_ON_ERROR(X,Y)
# define SEH_SET_ON_ERROR(X,Y)
#endif /* ifdef SQLITE_USE_SEH */
/* END ORIGINAL SEH-definitions */

/* BEGIN ORIGINAL wal.c BYTESWAP32 */
#define BYTESWAP32(x) ( \
    (((x)&0x000000FF)<<24) + (((x)&0x0000FF00)<<8)  \
  + (((x)&0x00FF0000)>>8)  + (((x)&0xFF000000)>>24) \
)
/* END ORIGINAL BYTESWAP32 */

/* BEGIN ORIGINAL wal.c WalHashLoc */
typedef struct WalHashLoc WalHashLoc;
struct WalHashLoc {
  volatile ht_slot *aHash;  /* Start of the wal-index hash table */
  volatile u32 *aPgno;      /* aPgno[1] is the page of first frame indexed */
  u32 iZero;                /* One less than the frame number of first indexed*/
};
/* END ORIGINAL WalHashLoc */

/* BEGIN ORIGINAL util.c sqlite3Get4byte */
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
/* END ORIGINAL sqlite3Get4byte */

/* BEGIN ORIGINAL wal.c walIndexPageRealloc */
static SQLITE_NOINLINE int walIndexPageRealloc(
  Wal *pWal,               /* The WAL context */
  int iPage,               /* The page we seek */
  volatile u32 **ppPage    /* Write the page pointer here */
){
  int rc = SQLITE_OK;

  /* Enlarge the pWal->apWiData[] array if required */
  if( pWal->nWiData<=iPage ){
    sqlite3_int64 nByte = sizeof(u32*)*(iPage+1);
    volatile u32 **apNew;
    apNew = (volatile u32 **)sqlite3Realloc((void *)pWal->apWiData, nByte);
    if( !apNew ){
      *ppPage = 0;
      return SQLITE_NOMEM_BKPT;
    }
    memset((void*)&apNew[pWal->nWiData], 0,
           sizeof(u32*)*(iPage+1-pWal->nWiData));
    pWal->apWiData = apNew;
    pWal->nWiData = iPage+1;
  }

  /* Request a pointer to the required page from the VFS */
  assert( pWal->apWiData[iPage]==0 );
  if( pWal->exclusiveMode==WAL_HEAPMEMORY_MODE ){
    pWal->apWiData[iPage] = (u32 volatile *)sqlite3MallocZero(WALINDEX_PGSZ);
    if( !pWal->apWiData[iPage] ) rc = SQLITE_NOMEM_BKPT;
  }else{
    rc = sqlite3OsShmMap(pWal->pDbFd, iPage, WALINDEX_PGSZ,
        pWal->writeLock, (void volatile **)&pWal->apWiData[iPage]
    );
    assert( pWal->apWiData[iPage]!=0
         || rc!=SQLITE_OK
         || (pWal->writeLock==0 && iPage==0) );
    testcase( pWal->apWiData[iPage]==0 && rc==SQLITE_OK );
    if( rc==SQLITE_OK ){
      if( iPage>0 && sqlite3FaultSim(600) ) rc = SQLITE_NOMEM;
    }else if( (rc&0xff)==SQLITE_READONLY ){
      pWal->readOnly |= WAL_SHM_RDONLY;
      if( rc==SQLITE_READONLY ){
        rc = SQLITE_OK;
      }
    }
  }

  *ppPage = pWal->apWiData[iPage];
  assert( iPage==0 || *ppPage || rc!=SQLITE_OK );
  return rc;
}
/* END ORIGINAL walIndexPageRealloc */

/* BEGIN ORIGINAL wal.c walIndexPage */
static int walIndexPage(
  Wal *pWal,               /* The WAL context */
  int iPage,               /* The page we seek */
  volatile u32 **ppPage    /* Write the page pointer here */
){
  SEH_INJECT_FAULT;
  if( pWal->nWiData<=iPage || (*ppPage = pWal->apWiData[iPage])==0 ){
    return walIndexPageRealloc(pWal, iPage, ppPage);
  }
  return SQLITE_OK;
}
/* END ORIGINAL walIndexPage */

/* BEGIN ORIGINAL wal.c walCkptInfo */
static volatile WalCkptInfo *walCkptInfo(Wal *pWal){
  assert( pWal->nWiData>0 && pWal->apWiData[0] );
  SEH_INJECT_FAULT;
  return (volatile WalCkptInfo*)&(pWal->apWiData[0][sizeof(WalIndexHdr)/2]);
}
/* END ORIGINAL walCkptInfo */

/* BEGIN ORIGINAL wal.c walIndexHdr */
static volatile WalIndexHdr *walIndexHdr(Wal *pWal){
  assert( pWal->nWiData>0 && pWal->apWiData[0] );
  SEH_INJECT_FAULT;
  return (volatile WalIndexHdr*)pWal->apWiData[0];
}
/* END ORIGINAL walIndexHdr */

/* BEGIN ORIGINAL wal.c walChecksumBytes */
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
/* END ORIGINAL walChecksumBytes */

/* BEGIN ORIGINAL wal.c walShmBarrier */
static void walShmBarrier(Wal *pWal){
  if( pWal->exclusiveMode!=WAL_HEAPMEMORY_MODE ){
    sqlite3OsShmBarrier(pWal->pDbFd);
  }
}
/* END ORIGINAL walShmBarrier */

/* BEGIN ORIGINAL wal.c walIndexWriteHdr */
static SQLITE_NO_TSAN void walIndexWriteHdr(Wal *pWal){
  volatile WalIndexHdr *aHdr = walIndexHdr(pWal);
  const int nCksum = offsetof(WalIndexHdr, aCksum);

  assert( pWal->writeLock );
  pWal->hdr.isInit = 1;
  pWal->hdr.iVersion = WALINDEX_MAX_VERSION;
  walChecksumBytes(1, (u8*)&pWal->hdr, nCksum, 0, pWal->hdr.aCksum);
  /* Possible TSAN false-positive.  See tag-20200519-1 */
  memcpy((void*)&aHdr[1], (const void*)&pWal->hdr, sizeof(WalIndexHdr));
  walShmBarrier(pWal);
  memcpy((void*)&aHdr[0], (const void*)&pWal->hdr, sizeof(WalIndexHdr));
}
/* END ORIGINAL walIndexWriteHdr */

/* BEGIN ORIGINAL wal.c walDecodeFrame */
static int walDecodeFrame(
  Wal *pWal,                      /* The write-ahead log */
  u32 *piPage,                    /* OUT: Database page number for frame */
  u32 *pnTruncate,                /* OUT: New db size (or 0 if not commit) */
  u8 *aData,                      /* Pointer to page data (for checksum) */
  u8 *aFrame                      /* Frame data */
){
  int nativeCksum;                /* True for native byte-order checksums */
  u32 *aCksum = pWal->hdr.aFrameCksum;
  u32 pgno;                       /* Page number of the frame */
  assert( WAL_FRAME_HDRSIZE==24 );

  /* A frame is only valid if the salt values in the frame-header
  ** match the salt values in the wal-header.
  */
  if( memcmp(&pWal->hdr.aSalt, &aFrame[8], 8)!=0 ){
    return 0;
  }

  /* A frame is only valid if the page number is greater than zero.
  */
  pgno = sqlite3Get4byte(&aFrame[0]);
  if( pgno==0 ){
    return 0;
  }

  /* A frame is only valid if a checksum of the WAL header,
  ** all prior frames, the first 16 bytes of this frame-header,
  ** and the frame-data matches the checksum in the last 8
  ** bytes of this frame-header.
  */
  nativeCksum = (pWal->hdr.bigEndCksum==SQLITE_BIGENDIAN);
  walChecksumBytes(nativeCksum, aFrame, 8, aCksum, aCksum);
  walChecksumBytes(nativeCksum, aData, pWal->szPage, aCksum, aCksum);
  if( aCksum[0]!=sqlite3Get4byte(&aFrame[16])
   || aCksum[1]!=sqlite3Get4byte(&aFrame[20])
  ){
    /* Checksum failed. */
    return 0;
  }

  /* If we reach this point, the frame is valid.  Return the page number
  ** and the new database size.
  */
  *piPage = pgno;
  *pnTruncate = sqlite3Get4byte(&aFrame[4]);
  return 1;
}
/* END ORIGINAL walDecodeFrame */

/* BEGIN ORIGINAL wal.c walLockExclusive */
static int walLockExclusive(Wal *pWal, int lockIdx, int n){
  int rc;
  if( pWal->exclusiveMode ) return SQLITE_OK;
  rc = sqlite3OsShmLock(pWal->pDbFd, lockIdx, n,
                        SQLITE_SHM_LOCK | SQLITE_SHM_EXCLUSIVE);
  WALTRACE(("WAL%p: acquire EXCLUSIVE-%s cnt=%d %s\n", pWal,
            walLockName(lockIdx), n, rc ? "failed" : "ok"));
  VVA_ONLY( pWal->lockError = (u8)(rc!=SQLITE_OK && (rc&0xFF)!=SQLITE_BUSY); )
#ifdef SQLITE_USE_SEH
  if( rc==SQLITE_OK ){
    pWal->lockMask |= (((1<<n)-1) << (SQLITE_SHM_NLOCK+lockIdx));
  }
#endif
  return rc;
}
/* END ORIGINAL walLockExclusive */

/* BEGIN ORIGINAL wal.c walUnlockExclusive */
static void walUnlockExclusive(Wal *pWal, int lockIdx, int n){
  if( pWal->exclusiveMode ) return;
  (void)sqlite3OsShmLock(pWal->pDbFd, lockIdx, n,
                         SQLITE_SHM_UNLOCK | SQLITE_SHM_EXCLUSIVE);
#ifdef SQLITE_USE_SEH
  pWal->lockMask &= ~(((1<<n)-1) << (SQLITE_SHM_NLOCK+lockIdx));
#endif
  WALTRACE(("WAL%p: release EXCLUSIVE-%s cnt=%d\n", pWal,
             walLockName(lockIdx), n));
}
/* END ORIGINAL walUnlockExclusive */

/* BEGIN ORIGINAL wal.c walHash */
static int walHash(u32 iPage){
  assert( iPage>0 );
  assert( (HASHTABLE_NSLOT & (HASHTABLE_NSLOT-1))==0 );
  return (iPage*HASHTABLE_HASH_1) & (HASHTABLE_NSLOT-1);
}
/* END ORIGINAL walHash */

/* BEGIN ORIGINAL wal.c walNextHash */
static int walNextHash(int iPriorHash){
  return (iPriorHash+1)&(HASHTABLE_NSLOT-1);
}
/* END ORIGINAL walNextHash */

/* BEGIN ORIGINAL wal.c walHashGet */
static int walHashGet(
  Wal *pWal,                      /* WAL handle */
  int iHash,                      /* Find the iHash'th table */
  WalHashLoc *pLoc                /* OUT: Hash table location */
){
  int rc;                         /* Return code */

  rc = walIndexPage(pWal, iHash, &pLoc->aPgno);
  assert( rc==SQLITE_OK || iHash>0 );

  if( pLoc->aPgno ){
    pLoc->aHash = (volatile ht_slot *)&pLoc->aPgno[HASHTABLE_NPAGE];
    if( iHash==0 ){
      pLoc->aPgno = &pLoc->aPgno[WALINDEX_HDR_SIZE/sizeof(u32)];
      pLoc->iZero = 0;
    }else{
      pLoc->iZero = HASHTABLE_NPAGE_ONE + (iHash-1)*HASHTABLE_NPAGE;
    }
  }else if( NEVER(rc==SQLITE_OK) ){
    rc = SQLITE_ERROR;
  }
  return rc;
}
/* END ORIGINAL walHashGet */

/* BEGIN ORIGINAL wal.c walFramePage */
static int walFramePage(u32 iFrame){
  int iHash = (iFrame+HASHTABLE_NPAGE-HASHTABLE_NPAGE_ONE-1) / HASHTABLE_NPAGE;
  assert( (iHash==0 || iFrame>HASHTABLE_NPAGE_ONE)
       && (iHash>=1 || iFrame<=HASHTABLE_NPAGE_ONE)
       && (iHash<=1 || iFrame>(HASHTABLE_NPAGE_ONE+HASHTABLE_NPAGE))
       && (iHash>=2 || iFrame<=HASHTABLE_NPAGE_ONE+HASHTABLE_NPAGE)
       && (iHash<=2 || iFrame>(HASHTABLE_NPAGE_ONE+2*HASHTABLE_NPAGE))
  );
  assert( iHash>=0 );
  return iHash;
}
/* END ORIGINAL walFramePage */

/* BEGIN ORIGINAL wal.c walFramePgno */
static u32 walFramePgno(Wal *pWal, u32 iFrame){
  int iHash = walFramePage(iFrame);
  SEH_INJECT_FAULT;
  if( iHash==0 ){
    return pWal->apWiData[0][WALINDEX_HDR_SIZE/sizeof(u32) + iFrame - 1];
  }
  return pWal->apWiData[iHash][(iFrame-1-HASHTABLE_NPAGE_ONE)%HASHTABLE_NPAGE];
}
/* END ORIGINAL walFramePgno */

/* BEGIN ORIGINAL wal.c walCleanupHash */
static void walCleanupHash(Wal *pWal){
  WalHashLoc sLoc;                /* Hash table location */
  int iLimit = 0;                 /* Zero values greater than this */
  int nByte;                      /* Number of bytes to zero in aPgno[] */
  int i;                          /* Used to iterate through aHash[] */

  assert( pWal->writeLock );
  testcase( pWal->hdr.mxFrame==HASHTABLE_NPAGE_ONE-1 );
  testcase( pWal->hdr.mxFrame==HASHTABLE_NPAGE_ONE );
  testcase( pWal->hdr.mxFrame==HASHTABLE_NPAGE_ONE+1 );

  if( pWal->hdr.mxFrame==0 ) return;

  /* Obtain pointers to the hash-table and page-number array containing
  ** the entry that corresponds to frame pWal->hdr.mxFrame. It is guaranteed
  ** that the page said hash-table and array reside on is already mapped.(1)
  */
  assert( pWal->nWiData>walFramePage(pWal->hdr.mxFrame) );
  assert( pWal->apWiData[walFramePage(pWal->hdr.mxFrame)] );
  i = walHashGet(pWal, walFramePage(pWal->hdr.mxFrame), &sLoc);
  if( NEVER(i) ) return; /* Defense-in-depth, in case (1) above is wrong */

  /* Zero all hash-table entries that correspond to frame numbers greater
  ** than pWal->hdr.mxFrame.
  */
  iLimit = pWal->hdr.mxFrame - sLoc.iZero;
  assert( iLimit>0 );
  for(i=0; i<HASHTABLE_NSLOT; i++){
    if( sLoc.aHash[i]>iLimit ){
      sLoc.aHash[i] = 0;
    }
  }

  /* Zero the entries in the aPgno array that correspond to frames with
  ** frame numbers greater than pWal->hdr.mxFrame.
  */
  nByte = (int)((char *)sLoc.aHash - (char *)&sLoc.aPgno[iLimit]);
  assert( nByte>=0 );
  memset((void *)&sLoc.aPgno[iLimit], 0, nByte);

#ifdef SQLITE_ENABLE_EXPENSIVE_ASSERT
  /* Verify that the every entry in the mapping region is still reachable
  ** via the hash table even after the cleanup.
  */
  if( iLimit ){
    int j;           /* Loop counter */
    int iKey;        /* Hash key */
    for(j=0; j<iLimit; j++){
      for(iKey=walHash(sLoc.aPgno[j]);sLoc.aHash[iKey];iKey=walNextHash(iKey)){
        if( sLoc.aHash[iKey]==j+1 ) break;
      }
      assert( sLoc.aHash[iKey]==j+1 );
    }
  }
#endif /* SQLITE_ENABLE_EXPENSIVE_ASSERT */
}
/* END ORIGINAL walCleanupHash */

/* BEGIN ORIGINAL wal.c walIndexAppend */
static int walIndexAppend(Wal *pWal, u32 iFrame, u32 iPage){
  int rc;                         /* Return code */
  WalHashLoc sLoc;                /* Wal-index hash table location */

  rc = walHashGet(pWal, walFramePage(iFrame), &sLoc);

  /* Assuming the wal-index file was successfully mapped, populate the
  ** page number array and hash table entry.
  */
  if( rc==SQLITE_OK ){
    int iKey;                     /* Hash table key */
    int idx;                      /* Value to write to hash-table slot */
    int nCollide;                 /* Number of hash collisions */

    idx = iFrame - sLoc.iZero;
    assert( idx <= HASHTABLE_NSLOT/2 + 1 );

    /* If this is the first entry to be added to this hash-table, zero the
    ** entire hash table and aPgno[] array before proceeding.
    */
    if( idx==1 ){
      int nByte = (int)((u8*)&sLoc.aHash[HASHTABLE_NSLOT] - (u8*)sLoc.aPgno);
      assert( nByte>=0 );
      memset((void*)sLoc.aPgno, 0, nByte);
    }

    /* If the entry in aPgno[] is already set, then the previous writer
    ** must have exited unexpectedly in the middle of a transaction (after
    ** writing one or more dirty pages to the WAL to free up memory).
    ** Remove the remnants of that writers uncommitted transaction from
    ** the hash-table before writing any new entries.
    */
    if( sLoc.aPgno[idx-1] ){
      walCleanupHash(pWal);
      assert( !sLoc.aPgno[idx-1] );
    }

    /* Write the aPgno[] array entry and the hash-table slot. */
    nCollide = idx;
    for(iKey=walHash(iPage); sLoc.aHash[iKey]; iKey=walNextHash(iKey)){
      if( (nCollide--)==0 ) return SQLITE_CORRUPT_BKPT;
    }
    sLoc.aPgno[idx-1] = iPage;
    AtomicStore(&sLoc.aHash[iKey], (ht_slot)idx);

#ifdef SQLITE_ENABLE_EXPENSIVE_ASSERT
    /* Verify that the number of entries in the hash table exactly equals
    ** the number of entries in the mapping region.
    */
    {
      int i;           /* Loop counter */
      int nEntry = 0;  /* Number of entries in the hash table */
      for(i=0; i<HASHTABLE_NSLOT; i++){ if( sLoc.aHash[i] ) nEntry++; }
      assert( nEntry==idx );
    }

    /* Verify that the every entry in the mapping region is reachable
    ** via the hash table.  This turns out to be a really, really expensive
    ** thing to check, so only do this occasionally - not on every
    ** iteration.
    */
    if( (idx&0x3ff)==0 ){
      int i;           /* Loop counter */
      for(i=0; i<idx; i++){
        for(iKey=walHash(sLoc.aPgno[i]);
            sLoc.aHash[iKey];
            iKey=walNextHash(iKey)){
          if( sLoc.aHash[iKey]==i+1 ) break;
        }
        assert( sLoc.aHash[iKey]==i+1 );
      }
    }
#endif /* SQLITE_ENABLE_EXPENSIVE_ASSERT */
  }

  return rc;
}
/* END ORIGINAL walIndexAppend */

/* BEGIN ORIGINAL wal.c walIndexRecover */
static int walIndexRecover(Wal *pWal){
  int rc;                         /* Return Code */
  i64 nSize;                      /* Size of log file */
  u32 aFrameCksum[2] = {0, 0};
  int iLock;                      /* Lock offset to lock for checkpoint */

  /* Obtain an exclusive lock on all byte in the locking range not already
  ** locked by the caller. The caller is guaranteed to have locked the
  ** WAL_WRITE_LOCK byte, and may have also locked the WAL_CKPT_LOCK byte.
  ** If successful, the same bytes that are locked here are unlocked before
  ** this function returns.
  */
  assert( pWal->ckptLock==1 || pWal->ckptLock==0 );
  assert( WAL_ALL_BUT_WRITE==WAL_WRITE_LOCK+1 );
  assert( WAL_CKPT_LOCK==WAL_ALL_BUT_WRITE );
  assert( pWal->writeLock );
  iLock = WAL_ALL_BUT_WRITE + pWal->ckptLock;
  rc = walLockExclusive(pWal, iLock, WAL_READ_LOCK(0)-iLock);
  if( rc ){
    return rc;
  }

  WALTRACE(("WAL%p: recovery begin...\n", pWal));

  memset(&pWal->hdr, 0, sizeof(WalIndexHdr));

  rc = sqlite3OsFileSize(pWal->pWalFd, &nSize);
  if( rc!=SQLITE_OK ){
    goto recovery_error;
  }

  if( nSize>WAL_HDRSIZE ){
    u8 aBuf[WAL_HDRSIZE];         /* Buffer to load WAL header into */
    u32 *aPrivate = 0;            /* Heap copy of *-shm hash being populated */
    u8 *aFrame = 0;               /* Malloc'd buffer to load entire frame */
    int szFrame;                  /* Number of bytes in buffer aFrame[] */
    u8 *aData;                    /* Pointer to data part of aFrame buffer */
    int szPage;                   /* Page size according to the log */
    u32 magic;                    /* Magic value read from WAL header */
    u32 version;                  /* Magic value read from WAL header */
    int isValid;                  /* True if this frame is valid */
    u32 iPg;                      /* Current 32KB wal-index page */
    u32 iLastFrame;               /* Last frame in wal, based on nSize alone */

    /* Read in the WAL header. */
    rc = sqlite3OsRead(pWal->pWalFd, aBuf, WAL_HDRSIZE, 0);
    if( rc!=SQLITE_OK ){
      goto recovery_error;
    }

    /* If the database page size is not a power of two, or is greater than
    ** SQLITE_MAX_PAGE_SIZE, conclude that the WAL file contains no valid
    ** data. Similarly, if the 'magic' value is invalid, ignore the whole
    ** WAL file.
    */
    magic = sqlite3Get4byte(&aBuf[0]);
    szPage = sqlite3Get4byte(&aBuf[8]);
    if( (magic&0xFFFFFFFE)!=WAL_MAGIC
     || szPage&(szPage-1)
     || szPage>SQLITE_MAX_PAGE_SIZE
     || szPage<512
    ){
      goto finished;
    }
    pWal->hdr.bigEndCksum = (u8)(magic&0x00000001);
    pWal->szPage = szPage;
    pWal->nCkpt = sqlite3Get4byte(&aBuf[12]);
    memcpy(&pWal->hdr.aSalt, &aBuf[16], 8);

    /* Verify that the WAL header checksum is correct */
    walChecksumBytes(pWal->hdr.bigEndCksum==SQLITE_BIGENDIAN,
        aBuf, WAL_HDRSIZE-2*4, 0, pWal->hdr.aFrameCksum
    );
    if( pWal->hdr.aFrameCksum[0]!=sqlite3Get4byte(&aBuf[24])
     || pWal->hdr.aFrameCksum[1]!=sqlite3Get4byte(&aBuf[28])
    ){
      goto finished;
    }

    /* Verify that the version number on the WAL format is one that
    ** are able to understand */
    version = sqlite3Get4byte(&aBuf[4]);
    if( version!=WAL_MAX_VERSION ){
      rc = SQLITE_CANTOPEN_BKPT;
      goto finished;
    }

    /* Malloc a buffer to read frames into. */
    szFrame = szPage + WAL_FRAME_HDRSIZE;
    aFrame = (u8 *)sqlite3_malloc64(szFrame + WALINDEX_PGSZ);
    SEH_FREE_ON_ERROR(0, aFrame);
    if( !aFrame ){
      rc = SQLITE_NOMEM_BKPT;
      goto recovery_error;
    }
    aData = &aFrame[WAL_FRAME_HDRSIZE];
    aPrivate = (u32*)&aData[szPage];

    /* Read all frames from the log file. */
    iLastFrame = (nSize - WAL_HDRSIZE) / szFrame;
    for(iPg=0; iPg<=(u32)walFramePage(iLastFrame); iPg++){
      u32 *aShare;
      u32 iFrame;                 /* Index of last frame read */
      u32 iLast = MIN(iLastFrame, HASHTABLE_NPAGE_ONE+iPg*HASHTABLE_NPAGE);
      u32 iFirst = 1 + (iPg==0?0:HASHTABLE_NPAGE_ONE+(iPg-1)*HASHTABLE_NPAGE);
      u32 nHdr, nHdr32;
      rc = walIndexPage(pWal, iPg, (volatile u32**)&aShare);
      assert( aShare!=0 || rc!=SQLITE_OK );
      if( aShare==0 ) break;
      SEH_SET_ON_ERROR(iPg, aShare);
      pWal->apWiData[iPg] = aPrivate;

      for(iFrame=iFirst; iFrame<=iLast; iFrame++){
        i64 iOffset = walFrameOffset(iFrame, szPage);
        u32 pgno;                 /* Database page number for frame */
        u32 nTruncate;            /* dbsize field from frame header */

        /* Read and decode the next log frame. */
        rc = sqlite3OsRead(pWal->pWalFd, aFrame, szFrame, iOffset);
        if( rc!=SQLITE_OK ) break;
        isValid = walDecodeFrame(pWal, &pgno, &nTruncate, aData, aFrame);
        if( !isValid ) break;
        rc = walIndexAppend(pWal, iFrame, pgno);
        if( NEVER(rc!=SQLITE_OK) ) break;

        /* If nTruncate is non-zero, this is a commit record. */
        if( nTruncate ){
          pWal->hdr.mxFrame = iFrame;
          pWal->hdr.nPage = nTruncate;
          pWal->hdr.szPage = (u16)((szPage&0xff00) | (szPage>>16));
          testcase( szPage<=32768 );
          testcase( szPage>=65536 );
          aFrameCksum[0] = pWal->hdr.aFrameCksum[0];
          aFrameCksum[1] = pWal->hdr.aFrameCksum[1];
        }
      }
      pWal->apWiData[iPg] = aShare;
      SEH_SET_ON_ERROR(0,0);
      nHdr = (iPg==0 ? WALINDEX_HDR_SIZE : 0);
      nHdr32 = nHdr / sizeof(u32);
#ifndef SQLITE_SAFER_WALINDEX_RECOVERY
      /* Memcpy() should work fine here, on all reasonable implementations.
      ** Technically, memcpy() might change the destination to some
      ** intermediate value before setting to the final value, and that might
      ** cause a concurrent reader to malfunction.  Memcpy() is allowed to
      ** do that, according to the spec, but no memcpy() implementation that
      ** we know of actually does that, which is why we say that memcpy()
      ** is safe for this.  Memcpy() is certainly a lot faster.
      */
      memcpy(&aShare[nHdr32], &aPrivate[nHdr32], WALINDEX_PGSZ-nHdr);
#else
      /* In the event that some platform is found for which memcpy()
      ** changes the destination to some intermediate value before
      ** setting the final value, this alternative copy routine is
      ** provided.
      */
      {
        int i;
        for(i=nHdr32; i<WALINDEX_PGSZ/sizeof(u32); i++){
          if( aShare[i]!=aPrivate[i] ){
            /* Atomic memory operations are not required here because if
            ** the value needs to be changed, that means it is not being
            ** accessed concurrently. */
            aShare[i] = aPrivate[i];
          }
        }
      }
#endif
      SEH_INJECT_FAULT;
      if( iFrame<=iLast ) break;
    }

    SEH_FREE_ON_ERROR(aFrame, 0);
    sqlite3_free(aFrame);
  }

finished:
  if( rc==SQLITE_OK ){
    volatile WalCkptInfo *pInfo;
    int i;
    pWal->hdr.aFrameCksum[0] = aFrameCksum[0];
    pWal->hdr.aFrameCksum[1] = aFrameCksum[1];
    walIndexWriteHdr(pWal);

    /* Reset the checkpoint-header. This is safe because this thread is
    ** currently holding locks that exclude all other writers and
    ** checkpointers. Then set the values of read-mark slots 1 through N.
    */
    pInfo = walCkptInfo(pWal);
    pInfo->nBackfill = 0;
    pInfo->nBackfillAttempted = pWal->hdr.mxFrame;
    pInfo->aReadMark[0] = 0;
    for(i=1; i<WAL_NREADER; i++){
      rc = walLockExclusive(pWal, WAL_READ_LOCK(i), 1);
      if( rc==SQLITE_OK ){
        if( i==1 && pWal->hdr.mxFrame ){
          pInfo->aReadMark[i] = pWal->hdr.mxFrame;
        }else{
          pInfo->aReadMark[i] = READMARK_NOT_USED;
        }
        SEH_INJECT_FAULT;
        walUnlockExclusive(pWal, WAL_READ_LOCK(i), 1);
      }else if( rc!=SQLITE_BUSY ){
        goto recovery_error;
      }
    }

    /* If more than one frame was recovered from the log file, report an
    ** event via sqlite3_log(). This is to help with identifying performance
    ** problems caused by applications routinely shutting down without
    ** checkpointing the log file.
    */
    if( pWal->hdr.nPage ){
      sqlite3_log(SQLITE_NOTICE_RECOVER_WAL,
          "recovered %d frames from WAL file %s",
          pWal->hdr.mxFrame, pWal->zWalName
      );
    }
  }

recovery_error:
  WALTRACE(("WAL%p: recovery %s\n", pWal, rc ? "failed" : "ok"));
  walUnlockExclusive(pWal, iLock, WAL_READ_LOCK(0)-iLock);
  return rc;
}
/* END ORIGINAL walIndexRecover */

/* BEGIN ORIGINAL wal.c walFindFrame */
static int walFindFrame(
  Wal *pWal,                      /* WAL handle */
  Pgno pgno,                      /* Database page number to read data for */
  u32 *piRead                     /* OUT: Frame number (or zero) */
){
  u32 iRead = 0;                  /* If !=0, WAL frame to return data from */
  u32 iLast = pWal->hdr.mxFrame;  /* Last page in WAL for this reader */
  int iHash;                      /* Used to loop through N hash tables */
  int iMinHash;

  /* This routine is only be called from within a read transaction. */
  assert( pWal->readLock>=0 || pWal->lockError );

  /* If the "last page" field of the wal-index header snapshot is 0, then
  ** no data will be read from the wal under any circumstances. Return early
  ** in this case as an optimization.  Likewise, if pWal->readLock==0,
  ** then the WAL is ignored by the reader so return early, as if the
  ** WAL were empty.
  */
  if( iLast==0 || (pWal->readLock==0 && pWal->bShmUnreliable==0) ){
    *piRead = 0;
    return SQLITE_OK;
  }

  /* Search the hash table or tables for an entry matching page number
  ** pgno. Each iteration of the following for() loop searches one
  ** hash table (each hash table indexes up to HASHTABLE_NPAGE frames).
  **
  ** This code might run concurrently to the code in walIndexAppend()
  ** that adds entries to the wal-index (and possibly to this hash
  ** table). This means the value just read from the hash
  ** slot (aHash[iKey]) may have been added before or after the
  ** current read transaction was opened. Values added after the
  ** read transaction was opened may have been written incorrectly -
  ** i.e. these slots may contain garbage data. However, we assume
  ** that any slots written before the current read transaction was
  ** opened remain unmodified.
  **
  ** For the reasons above, the if(...) condition featured in the inner
  ** loop of the following block is more stringent that would be required
  ** if we had exclusive access to the hash-table:
  **
  **   (aPgno[iFrame]==pgno):
  **     This condition filters out normal hash-table collisions.
  **
  **   (iFrame<=iLast):
  **     This condition filters out entries that were added to the hash
  **     table after the current read-transaction had started.
  */
  iMinHash = walFramePage(pWal->minFrame);
  for(iHash=walFramePage(iLast); iHash>=iMinHash; iHash--){
    WalHashLoc sLoc;              /* Hash table location */
    int iKey;                     /* Hash slot index */
    int nCollide;                 /* Number of hash collisions remaining */
    int rc;                       /* Error code */
    u32 iH;

    rc = walHashGet(pWal, iHash, &sLoc);
    if( rc!=SQLITE_OK ){
      return rc;
    }
    nCollide = HASHTABLE_NSLOT;
    iKey = walHash(pgno);
    SEH_INJECT_FAULT;
    while( (iH = AtomicLoad(&sLoc.aHash[iKey]))!=0 ){
      u32 iFrame = iH + sLoc.iZero;
      if( iFrame<=iLast && iFrame>=pWal->minFrame && sLoc.aPgno[iH-1]==pgno ){
        assert( iFrame>iRead || CORRUPT_DB );
        iRead = iFrame;
      }
      if( (nCollide--)==0 ){
        *piRead = 0;
        return SQLITE_CORRUPT_BKPT;
      }
      iKey = walNextHash(iKey);
    }
    if( iRead ) break;
  }

#ifdef SQLITE_ENABLE_EXPENSIVE_ASSERT
  /* If expensive assert() statements are available, do a linear search
  ** of the wal-index file content. Make sure the results agree with the
  ** result obtained using the hash indexes above.  */
  {
    u32 iRead2 = 0;
    u32 iTest;
    assert( pWal->bShmUnreliable || pWal->minFrame>0 );
    for(iTest=iLast; iTest>=pWal->minFrame && iTest>0; iTest--){
      if( walFramePgno(pWal, iTest)==pgno ){
        iRead2 = iTest;
        break;
      }
    }
    assert( iRead==iRead2 );
  }
#endif

  *piRead = iRead;
  return SQLITE_OK;
}
/* END ORIGINAL walFindFrame */


_Static_assert(sizeof(WalIndexHdr)==48,"Original WAL header layout differs");
_Static_assert(WALINDEX_HDR_SIZE==136,"Original WAL index header differs");
_Static_assert(WALINDEX_PGSZ==32768,"Original WAL index page differs");
_Static_assert(WAL_NREADER==5,"Original reader-slot count differs");

/* Raw oracle ABI:
 * raw,n are one complete captured finite WAL byte view (0..8 MiB).
 * target_page==0 asks for recovery only; otherwise it is a nonzero u32 page.
 * out32 has 32 aligned u64s; read_pairs records every actual read(offset,size).
 * read_words must be >=2*(n/536+2), <=32772, even. Unused read words are untouched.
 * Return 0 after actual original calls; 1 scalar transport refusal before any
 * output write; 2 memory-provider setup failure (not a successful oracle).
 * All 32 raw words and complete read buffers must be saved before projection.
 */
static int oracle_range_valid(const void *p,u64 n){
  return n==0 || (p && (uintptr_t)p<=UINTPTR_MAX-(uintptr_t)n);
}
static int oracle_ranges_overlap(const void *a,u64 an,const void *b,u64 bn){
  if(!an || !bn)return 0;
  return (uintptr_t)a<(uintptr_t)b+bn && (uintptr_t)b<(uintptr_t)a+an;
}
uint32_t oracle_wal_recover_find(const u8 *raw,u64 n,u64 target_page,
                               u64 *out32,u64 *read_pairs,u64 read_words){
  Wal w;
  sqlite3_file file;
  volatile u32 *first=0;
  u64 result[32]={0};
  u32 found=0;
  int setup_rc,rc,find_rc=-1,i;
  if(n>ORACLE_MAX_WAL_BYTES || target_page>UINT32_MAX
     || !out32 || !read_pairs || ((uintptr_t)out32&7) || ((uintptr_t)read_pairs&7)
     || read_words<2*(n/536+2) || read_words>ORACLE_MAX_READ_WORDS || (read_words&1)
     || !oracle_range_valid(raw,n) || !oracle_range_valid(out32,sizeof(result))
     || !oracle_range_valid(read_pairs,read_words*sizeof(u64))
     || oracle_ranges_overlap(raw,n,out32,sizeof(result))
     || oracle_ranges_overlap(raw,n,read_pairs,read_words*sizeof(u64))
     || oracle_ranges_overlap(out32,sizeof(result),read_pairs,read_words*sizeof(u64))
  )return 1;
  memset(&w,0,sizeof(w));memset(&file,0,sizeof(file));
  file.bytes=raw;file.length=n;file.read_pairs=read_pairs;file.read_words=read_words;
  w.pWalFd=&file;w.exclusiveMode=WAL_HEAPMEMORY_MODE;
  w.writeLock=1;w.readLock=1;w.minFrame=1;w.nSehTry=1;
  w.zWalName="finite-in-memory-oracle";
  setup_rc=walIndexPage(&w,0,&first);
  if(setup_rc!=SQLITE_OK || !first){
    for(i=0;i<w.nWiData;i++)sqlite3_free((void*)w.apWiData[i]);
    sqlite3_free((void*)w.apWiData);
    return 2;
  }
  rc=walIndexRecover(&w);
  if(rc==SQLITE_OK && target_page){
    find_rc=walFindFrame(&w,(Pgno)target_page,&found);
  }
  result[0]=(u32)rc;
  result[1]=find_rc<0?UINT64_MAX:(u64)(u32)find_rc;
  result[2]=w.hdr.mxFrame;
  result[3]=w.hdr.nPage;
  result[4]=w.szPage;
  result[5]=w.hdr.szPage;
  result[6]=w.hdr.bigEndCksum;
  result[7]=w.nCkpt;
  result[8]=w.hdr.aFrameCksum[0];
  result[9]=w.hdr.aFrameCksum[1];
  result[10]=sqlite3Get4byte((const u8*)w.hdr.aSalt);
  result[11]=sqlite3Get4byte((const u8*)w.hdr.aSalt+4);
  result[12]=w.hdr.isInit;
  result[13]=w.hdr.iVersion;
  result[14]=w.hdr.aCksum[0];
  result[15]=w.hdr.aCksum[1];
  result[16]=found;
  result[17]=found?(u64)walFrameOffset(found,w.szPage)+WAL_FRAME_HDRSIZE:0;
  result[18]=file.read_calls;
  result[19]=file.read_bytes;
  result[20]=file.size_calls;
  result[21]=(u64)w.nWiData;
  result[22]=file.last_offset;
  result[23]=file.last_size;
  result[24]=file.read_errors;
  /* 25..31 are explicit zero reserved words. */
  for(i=0;i<w.nWiData;i++)sqlite3_free((void*)w.apWiData[i]);
  sqlite3_free((void*)w.apWiData);
  memcpy(out32,result,sizeof(result));
  return 0;
}
