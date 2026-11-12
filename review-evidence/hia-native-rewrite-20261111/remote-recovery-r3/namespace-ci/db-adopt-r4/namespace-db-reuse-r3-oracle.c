/* NEW independent development oracle, not a native namespace backend.
 * Fifteen policy functions below are byte-for-byte extracts of
 * sqlite/sqlite src/os_unix.c @ f3d536d37825302e31ed0eddd811c689f38f85a3,
 * git blob9e7ba05d6882b1f3c310b99102e8ecbf7f830af2.
 * Their syscall providers, serialized mutex macros, allocator bookkeeping,
 * and diagnostic/mmap boundaries are explicit test stand-ins.
 * No policy branch is selected from HIA output.
 */
#define _GNU_SOURCE 1
#define NDEBUG 1
#define SQLITE_MAX_MMAP_SIZE 0
#define OS_VXWORKS 0
#define SQLITE_ENABLE_LOCKING_STYLE 0
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <assert.h>
typedef uint64_t u64;
typedef uint64_t sqlite3_uint64;
typedef struct { int unused; } sqlite3_file;
typedef struct { int unused; } sqlite3_vfs;
typedef struct { int unused; } sqlite3_mutex;
typedef struct unixFile unixFile;
typedef struct unixInodeInfo unixInodeInfo;
typedef struct UnixUnusedFd UnixUnusedFd;
struct unixFileId { dev_t dev; u64 ino; };
struct UnixUnusedFd { int fd; int flags; UnixUnusedFd *pNext; };
struct unixInodeInfo {
  struct unixFileId fileId;
  sqlite3_mutex *pLockMutex;
  int nShared, nLock;
  unsigned char eFileLock, bProcessLock;
  UnixUnusedFd *pUnused;
  int nRef;
  void *pShmNode;
  unixInodeInfo *pNext, *pPrev;
};
struct unixFile {
  void const *pMethod;
  sqlite3_vfs *pVfs;
  unixInodeInfo *pInode;
  int h;
  unsigned char eFileLock;
  unsigned short ctrlFlags;
  int lastErrno;
  void *lockingContext;
  UnixUnusedFd *pPreallocatedUnused;
  char const *zPath;
  void *pShm;
};
static unixInodeInfo *inodeList;
static struct { int bCoreMutex; } sqlite3GlobalConfig;
#define SQLITE_OK 0
#define SQLITE_OPEN_READONLY 1
#define SQLITE_OPEN_READWRITE 2
#define SQLITE_PERM 3
#define SQLITE_BUSY 5
#define SQLITE_NOMEM_BKPT 7
#define SQLITE_IOERR 10
#define SQLITE_IOERR_CLOSE (SQLITE_IOERR | (16<<8))
#define SQLITE_IOERR_UNLOCK (SQLITE_IOERR | (8<<8))
#define SQLITE_IOERR_RDLOCK (SQLITE_IOERR | (9<<8))
#define SQLITE_IOERR_CHECKRESERVEDLOCK (SQLITE_IOERR | (14<<8))
#define SQLITE_IOERR_LOCK (SQLITE_IOERR | (15<<8))
#define SQLITE_MUTEX_FAST 1
#define NO_LOCK 0
#define SHARED_LOCK 1
#define RESERVED_LOCK 2
#define PENDING_LOCK 3
#define EXCLUSIVE_LOCK 4
#define PENDING_BYTE 0x40000000
#define RESERVED_BYTE (PENDING_BYTE+1)
#define SHARED_FIRST (PENDING_BYTE+2)
#define SHARED_SIZE 510
#define UNIXFILE_EXCL 0x01
#define UNIXFILE_RDONLY 0x02
#define UNIXFILE_DELETE 0x20
#define ALWAYS(x) (x)
#define OSTRACE(x) ((void)0)
#define OpenCounter(x) ((void)0)
#define SimulateIOError(x) ((void)0)
#define sqlite3_mutex_enter(x) ((void)0)
#define sqlite3_mutex_leave(x) ((void)0)
#define sqlite3_mutex_free(x) ((void)0)
#define sqlite3_mutex_held(x) 1
#define sqlite3_mutex_notheld(x) 1
#define unixFileMutexHeld(x) 1
#define unixFileMutexNotheld(x) 1
#define unixMutexHeld() 1
#define unixEnterMutex() ((void)0)
#define unixLeaveMutex() ((void)0)
#define verifyDbFile(x) ((void)0)
static sqlite3_mutex *sqlite3_mutex_alloc(int id) {
  (void)id; return (sqlite3_mutex*)(uintptr_t)1;
}
typedef struct Allocation Allocation;
struct Allocation { void *p; int retired; Allocation *next; };
static Allocation *allocations;
static void *tracked_malloc(sqlite3_uint64 bytes) {
  if (bytes > SIZE_MAX) return 0;
  void *p = malloc((size_t)bytes);
  if (!p) return 0;
  Allocation *a = malloc(sizeof(*a));
  if (!a) { free(p); return 0; }
  a->p=p; a->retired=0; a->next=allocations; allocations=a;
  return p;
}
static void tracked_free(void *p) {
  if (!p) return;
  for (Allocation *a=allocations;a;a=a->next) {
    if (a->p==p) {
      if (a->retired) abort();
      a->retired=1;
      return;
    }
  }
  abort();
}
#define sqlite3_malloc64 tracked_malloc
#define sqlite3_free tracked_free
/* Freed bytes remain quarantined until oracle_reset solely for complete
 * observation. Every real algorithmic free is marked and double-free refused.
 * This is not a physical allocator or a recovered production memory owner. */
typedef struct { uint64_t number,op,error; } Fault;
typedef struct { uint64_t number,op,fd,type,start,length,raw_result,error; } Event;
typedef struct { unixFile *file; int active; uint64_t logical,token,flags; } File;
static Fault *faults; static size_t fault_count;
static Event *events; static size_t event_count;
static File *files; static size_t file_count;
static dev_t fixture_dev;
static ino_t fixture_ino;
static mode_t fixture_mode;
static uid_t fixture_uid;
static gid_t fixture_gid;
static int fixture_getlk_type=F_UNLCK;
static uint64_t ignored_close_errors;
typedef struct { UnixUnusedFd *record; uint64_t token; } TakenUnused;
static TakenUnused *taken; static size_t taken_count;
static uint64_t reusable_stat_calls;
static int oracle_stat(const char *path,struct stat *s) {
  /* Controlled successful stat for the explicitly selected same-inode scope.
   * The future complete lookup owner must handle real path/stat/mutex admission. */
  if (!path) abort();
  reusable_stat_calls++;
  memset(s,0,sizeof(*s));
  s->st_dev=fixture_dev;s->st_ino=fixture_ino;s->st_mode=fixture_mode;
  s->st_uid=fixture_uid;s->st_gid=fixture_gid;s->st_nlink=1;s->st_size=4096;
  return 0;
}
#define osStat oracle_stat

static int record_io(int op,int fd,int type,int64_t start,int64_t length) {
  uint64_t number=(uint64_t)event_count+1;
  int error=0;
  for(size_t i=0;i<fault_count;i++) {
    if(faults[i].number==number && (faults[i].op==0 || faults[i].op==(uint64_t)op)) {
      error=(int)faults[i].error;break;
    }
  }
  if(event_count==SIZE_MAX/sizeof(Event)) abort();
  Event *next=realloc(events,(event_count+1)*sizeof(Event));
  if(!next) abort();
  events=next;
  events[event_count++]=(Event){number,(uint64_t)op,(uint64_t)fd,(uint64_t)type,
    (uint64_t)start,(uint64_t)length,error?UINT64_MAX:0,(uint64_t)error};
  errno=error;
  return error?-1:0;
}
static int oracle_fstat(int fd,struct stat *s) {
  int rc=record_io(15,fd,0,0,0);
  if(rc) return rc;
  memset(s,0,sizeof(*s));
  s->st_dev=fixture_dev;s->st_ino=fixture_ino;s->st_mode=fixture_mode;
  s->st_uid=fixture_uid;s->st_gid=fixture_gid;s->st_nlink=1;s->st_size=4096;
  return 0;
}
static int oracle_fcntl(int fd,int cmd,struct flock *lock) {
  int op=(cmd==F_GETLK?23:17);
  int rc=record_io(op,fd,lock->l_type,lock->l_start,lock->l_len);
  if(rc==0 && cmd==F_GETLK) {
    lock->l_type=(short)fixture_getlk_type;
    lock->l_pid=(fixture_getlk_type==F_UNLCK?0:731);
  }
  return rc;
}
static int oracle_close_fd(int fd) { return record_io(8,fd,0,0,0); }
static void unixLogErrorAtLine(int code,char const *operation,char const *path,int line) {
  (void)code;(void)operation;(void)path;(void)line;ignored_close_errors++;
}
#define osFstat oracle_fstat
#define osFcntl oracle_fcntl
#define osClose oracle_close_fd
#define osSetPosixAdvisoryLock(h,x,t) osFcntl(h,F_SETLK,x)
/* BEGIN exact original policy functions, in their original dependency order. */

static int sqliteErrorFromPosixError(int posixError, int sqliteIOErr) {
  assert( (sqliteIOErr == SQLITE_IOERR_LOCK) ||
          (sqliteIOErr == SQLITE_IOERR_UNLOCK) ||
          (sqliteIOErr == SQLITE_IOERR_RDLOCK) ||
          (sqliteIOErr == SQLITE_IOERR_CHECKRESERVEDLOCK) );
  switch (posixError) {
  case EACCES:
  case EAGAIN:
  case ETIMEDOUT:
  case EBUSY:
  case EINTR:
  case ENOLCK:
    /* random NFS retry error, unless during file system support
     * introspection, in which it actually means what it says */
    return SQLITE_BUSY;
  
  case EPERM:
    return SQLITE_PERM;
  
  default:
    return sqliteIOErr;
  }
}

static void robust_close(unixFile *pFile, int h, int lineno){
  if( osClose(h) ){
    unixLogErrorAtLine(SQLITE_IOERR_CLOSE, "close",
                       pFile ? pFile->zPath : 0, lineno);
  }
}

static void storeLastErrno(unixFile *pFile, int error){
  pFile->lastErrno = error;
}

static void closePendingFds(unixFile *pFile){
  unixInodeInfo *pInode = pFile->pInode;
  UnixUnusedFd *p;
  UnixUnusedFd *pNext;
  assert( unixFileMutexHeld(pFile) );
  for(p=pInode->pUnused; p; p=pNext){
    pNext = p->pNext;
    robust_close(pFile, p->fd, __LINE__);
    sqlite3_free(p);
  }
  pInode->pUnused = 0;
}

static void releaseInodeInfo(unixFile *pFile){
  unixInodeInfo *pInode = pFile->pInode;
  assert( unixMutexHeld() );
  assert( unixFileMutexNotheld(pFile) );
  if( ALWAYS(pInode) ){
    pInode->nRef--;
    if( pInode->nRef==0 ){
      assert( pInode->pShmNode==0 );
      sqlite3_mutex_enter(pInode->pLockMutex);
      closePendingFds(pFile);
      sqlite3_mutex_leave(pInode->pLockMutex);
      if( pInode->pPrev ){
        assert( pInode->pPrev->pNext==pInode );
        pInode->pPrev->pNext = pInode->pNext;
      }else{
        assert( inodeList==pInode );
        inodeList = pInode->pNext;
      }
      if( pInode->pNext ){
        assert( pInode->pNext->pPrev==pInode );
        pInode->pNext->pPrev = pInode->pPrev;
      }
      sqlite3_mutex_free(pInode->pLockMutex);
      sqlite3_free(pInode);
    }
  }
}

static int findInodeInfo(
  unixFile *pFile,               /* Unix file with file desc used in the key */
  unixInodeInfo **ppInode        /* Return the unixInodeInfo object here */
){
  int rc;                        /* System call return code */
  int fd;                        /* The file descriptor for pFile */
  struct unixFileId fileId;      /* Lookup key for the unixInodeInfo */
  struct stat statbuf;           /* Low-level file information */
  unixInodeInfo *pInode = 0;     /* Candidate unixInodeInfo object */

  assert( unixMutexHeld() );

  /* Get low-level information about the file that we can used to
  ** create a unique name for the file.
  */
  fd = pFile->h;
  rc = osFstat(fd, &statbuf);
  if( rc!=0 ){
    storeLastErrno(pFile, errno);
#if defined(EOVERFLOW) && defined(SQLITE_DISABLE_LFS)
    if( pFile->lastErrno==EOVERFLOW ) return SQLITE_NOLFS;
#endif
    return SQLITE_IOERR;
  }

#ifdef __APPLE__
  /* On OS X on an msdos filesystem, the inode number is reported
  ** incorrectly for zero-size files.  See ticket #3260.  To work
  ** around this problem (we consider it a bug in OS X, not SQLite)
  ** we always increase the file size to 1 by writing a single byte
  ** prior to accessing the inode number.  The one byte written is
  ** an ASCII 'S' character which also happens to be the first byte
  ** in the header of every SQLite database.  In this way, if there
  ** is a race condition such that another thread has already populated
  ** the first page of the database, no damage is done.
  */
  if( statbuf.st_size==0 && (pFile->fsFlags & SQLITE_FSFLAGS_IS_MSDOS)!=0 ){
    do{ rc = osWrite(fd, "S", 1); }while( rc<0 && errno==EINTR );
    if( rc!=1 ){
      storeLastErrno(pFile, errno);
      return SQLITE_IOERR;
    }
    rc = osFstat(fd, &statbuf);
    if( rc!=0 ){
      storeLastErrno(pFile, errno);
      return SQLITE_IOERR;
    }
  }
#endif

  memset(&fileId, 0, sizeof(fileId));
  fileId.dev = statbuf.st_dev;
#if OS_VXWORKS
  fileId.pId = pFile->pId;
#else
  fileId.ino = (u64)statbuf.st_ino;
#endif
  assert( unixMutexHeld() );
  pInode = inodeList;
  while( pInode && memcmp(&fileId, &pInode->fileId, sizeof(fileId)) ){
    pInode = pInode->pNext;
  }
  if( pInode==0 ){
    pInode = sqlite3_malloc64( sizeof(*pInode) );
    if( pInode==0 ){
      return SQLITE_NOMEM_BKPT;
    }
    memset(pInode, 0, sizeof(*pInode));
    memcpy(&pInode->fileId, &fileId, sizeof(fileId));
    if( sqlite3GlobalConfig.bCoreMutex ){
      pInode->pLockMutex = sqlite3_mutex_alloc(SQLITE_MUTEX_FAST);
      if( pInode->pLockMutex==0 ){
        sqlite3_free(pInode);
        return SQLITE_NOMEM_BKPT;
      }
    }
    pInode->nRef = 1;
    assert( unixMutexHeld() );
    pInode->pNext = inodeList;
    pInode->pPrev = 0;
    if( inodeList ) inodeList->pPrev = pInode;
    inodeList = pInode;
  }else{
    pInode->nRef++;
  }
  *ppInode = pInode;
  return SQLITE_OK;
}

static int unixCheckReservedLock(sqlite3_file *id, int *pResOut){
  int rc = SQLITE_OK;
  int reserved = 0;
  unixFile *pFile = (unixFile*)id;

  SimulateIOError( return SQLITE_IOERR_CHECKRESERVEDLOCK; );

  assert( pFile );
  assert( pFile->eFileLock<=SHARED_LOCK );
  sqlite3_mutex_enter(pFile->pInode->pLockMutex);

  /* Check if a thread in this process holds such a lock */
  if( pFile->pInode->eFileLock>SHARED_LOCK ){
    reserved = 1;
  }

  /* Otherwise see if some other process holds it.
  */
#ifndef __DJGPP__
  if( !reserved && !pFile->pInode->bProcessLock ){
    struct flock lock;
    lock.l_whence = SEEK_SET;
    lock.l_start = RESERVED_BYTE;
    lock.l_len = 1;
    lock.l_type = F_WRLCK;
    if( osFcntl(pFile->h, F_GETLK, &lock) ){
      rc = SQLITE_IOERR_CHECKRESERVEDLOCK;
      storeLastErrno(pFile, errno);
    } else if( lock.l_type!=F_UNLCK ){
      reserved = 1;
    }
  }
#endif

  sqlite3_mutex_leave(pFile->pInode->pLockMutex);
  OSTRACE(("TEST WR-LOCK %d %d %d (unix)\n", pFile->h, rc, reserved));

  *pResOut = reserved;
  return rc;
}

static int unixFileLock(unixFile *pFile, struct flock *pLock){
  int rc;
  unixInodeInfo *pInode = pFile->pInode;
  assert( pInode!=0 );
  assert( sqlite3_mutex_held(pInode->pLockMutex) );
  if( (pFile->ctrlFlags & (UNIXFILE_EXCL|UNIXFILE_RDONLY))==UNIXFILE_EXCL ){
    if( pInode->bProcessLock==0 ){
      struct flock lock;
      assert( pInode->nLock==0 );
      lock.l_whence = SEEK_SET;
      lock.l_start = SHARED_FIRST;
      lock.l_len = SHARED_SIZE;
      lock.l_type = F_WRLCK;
      rc = osSetPosixAdvisoryLock(pFile->h, &lock, pFile);
      if( rc<0 ) return rc;
      pInode->bProcessLock = 1;
      pInode->nLock++;
    }else{
      rc = 0;
    }
  }else{
    rc = osSetPosixAdvisoryLock(pFile->h, pLock, pFile);
  }
  return rc;
}

static int unixLock(sqlite3_file *id, int eFileLock){
  /* The following describes the implementation of the various locks and
  ** lock transitions in terms of the POSIX advisory shared and exclusive
  ** lock primitives (called read-locks and write-locks below, to avoid
  ** confusion with SQLite lock names). The algorithms are complicated
  ** slightly in order to be compatible with Windows95 systems simultaneously
  ** accessing the same database file, in case that is ever required.
  **
  ** Symbols defined in os.h identify the 'pending byte' and the 'reserved
  ** byte', each single bytes at well known offsets, and the 'shared byte
  ** range', a range of 510 bytes at a well known offset.
  **
  ** To obtain a SHARED lock, a read-lock is obtained on the 'pending
  ** byte'.  If this is successful, 'shared byte range' is read-locked
  ** and the lock on the 'pending byte' released.  (Legacy note:  When
  ** SQLite was first developed, Windows95 systems were still very common,
  ** and Windows95 lacks a shared-lock capability.  So on Windows95, a
  ** single randomly selected by from the 'shared byte range' is locked.
  ** Windows95 is now pretty much extinct, but this work-around for the
  ** lack of shared-locks on Windows95 lives on, for backwards
  ** compatibility.)
  **
  ** A process may only obtain a RESERVED lock after it has a SHARED lock.
  ** A RESERVED lock is implemented by grabbing a write-lock on the
  ** 'reserved byte'.
  **
  ** An EXCLUSIVE lock may only be requested after either a SHARED or
  ** RESERVED lock is held. An EXCLUSIVE lock is implemented by obtaining
  ** a write-lock on the entire 'shared byte range'. Since all other locks
  ** require a read-lock on one of the bytes within this range, this ensures
  ** that no other locks are held on the database.
  **
  ** If a process that holds a RESERVED lock requests an EXCLUSIVE, then
  ** a PENDING lock is obtained first. A PENDING lock is implemented by
  ** obtaining a write-lock on the 'pending byte'. This ensures that no new
  ** SHARED locks can be obtained, but existing SHARED locks are allowed to
  ** persist. If the call to this function fails to obtain the EXCLUSIVE
  ** lock in this case, it holds the PENDING lock instead. The client may
  ** then re-attempt the EXCLUSIVE lock later on, after existing SHARED
  ** locks have cleared.
  */
  int rc = SQLITE_OK;
  unixFile *pFile = (unixFile*)id;
  unixInodeInfo *pInode;
  struct flock lock;
  int tErrno = 0;

  assert( pFile );
  OSTRACE(("LOCK    %d %s was %s(%s,%d) pid=%d (unix)\n", pFile->h,
      azFileLock(eFileLock), azFileLock(pFile->eFileLock),
      azFileLock(pFile->pInode->eFileLock), pFile->pInode->nShared,
      osGetpid(0)));

  /* If there is already a lock of this type or more restrictive on the
  ** unixFile, do nothing. Don't use the end_lock: exit path, as
  ** unixEnterMutex() hasn't been called yet.
  */
  if( pFile->eFileLock>=eFileLock ){
    OSTRACE(("LOCK    %d %s ok (already held) (unix)\n", pFile->h,
            azFileLock(eFileLock)));
    return SQLITE_OK;
  }

  /* Make sure the locking sequence is correct.
  **  (1) We never move from unlocked to anything higher than shared lock.
  **  (2) SQLite never explicitly requests a pending lock.
  **  (3) A shared lock is always held when a reserve lock is requested.
  */
  assert( pFile->eFileLock!=NO_LOCK || eFileLock==SHARED_LOCK );
  assert( eFileLock!=PENDING_LOCK );
  assert( eFileLock!=RESERVED_LOCK || pFile->eFileLock==SHARED_LOCK );

  /* This mutex is needed because pFile->pInode is shared across threads
  */
  pInode = pFile->pInode;
  sqlite3_mutex_enter(pInode->pLockMutex);

  /* If some thread using this PID has a lock via a different unixFile*
  ** handle that precludes the requested lock, return BUSY.
  */
  if( (pFile->eFileLock!=pInode->eFileLock &&
          (pInode->eFileLock>=PENDING_LOCK || eFileLock>SHARED_LOCK))
  ){
    rc = SQLITE_BUSY;
    goto end_lock;
  }

  /* If a SHARED lock is requested, and some thread using this PID already
  ** has a SHARED or RESERVED lock, then increment reference counts and
  ** return SQLITE_OK.
  */
  if( eFileLock==SHARED_LOCK &&
      (pInode->eFileLock==SHARED_LOCK || pInode->eFileLock==RESERVED_LOCK) ){
    assert( eFileLock==SHARED_LOCK );
    assert( pFile->eFileLock==0 );
    assert( pInode->nShared>0 );
    pFile->eFileLock = SHARED_LOCK;
    pInode->nShared++;
    pInode->nLock++;
    goto end_lock;
  }


  /* A PENDING lock is needed before acquiring a SHARED lock and before
  ** acquiring an EXCLUSIVE lock.  For the SHARED lock, the PENDING will
  ** be released.
  */
  lock.l_len = 1L;
  lock.l_whence = SEEK_SET;
  if( eFileLock==SHARED_LOCK
   || (eFileLock==EXCLUSIVE_LOCK && pFile->eFileLock==RESERVED_LOCK)
  ){
    lock.l_type = (eFileLock==SHARED_LOCK?F_RDLCK:F_WRLCK);
    lock.l_start = PENDING_BYTE;
    if( unixFileLock(pFile, &lock) ){
      tErrno = errno;
      rc = sqliteErrorFromPosixError(tErrno, SQLITE_IOERR_LOCK);
      if( rc!=SQLITE_BUSY ){
        storeLastErrno(pFile, tErrno);
      }
      goto end_lock;
    }else if( eFileLock==EXCLUSIVE_LOCK ){
      pFile->eFileLock = PENDING_LOCK;
      pInode->eFileLock = PENDING_LOCK;
    }
  }


  /* If control gets to this point, then actually go ahead and make
  ** operating system calls for the specified lock.
  */
  if( eFileLock==SHARED_LOCK ){
    assert( pInode->nShared==0 );
    assert( pInode->eFileLock==0 );
    assert( rc==SQLITE_OK );

    /* Now get the read-lock */
    lock.l_start = SHARED_FIRST;
    lock.l_len = SHARED_SIZE;
    if( unixFileLock(pFile, &lock) ){
      tErrno = errno;
      rc = sqliteErrorFromPosixError(tErrno, SQLITE_IOERR_LOCK);
    }

    /* Drop the temporary PENDING lock */
    lock.l_start = PENDING_BYTE;
    lock.l_len = 1L;
    lock.l_type = F_UNLCK;
    if( unixFileLock(pFile, &lock) && rc==SQLITE_OK ){
      /* This could happen with a network mount */
      tErrno = errno;
      rc = SQLITE_IOERR_UNLOCK;
    }

    if( rc ){
      if( rc!=SQLITE_BUSY ){
        storeLastErrno(pFile, tErrno);
      }
      goto end_lock;
    }else{
      pFile->eFileLock = SHARED_LOCK;
      pInode->nLock++;
      pInode->nShared = 1;
    }
  }else if( eFileLock==EXCLUSIVE_LOCK && pInode->nShared>1 ){
    /* We are trying for an exclusive lock but another thread in this
    ** same process is still holding a shared lock. */
    rc = SQLITE_BUSY;
  }else{
    /* The request was for a RESERVED or EXCLUSIVE lock.  It is
    ** assumed that there is a SHARED or greater lock on the file
    ** already.
    */
    assert( 0!=pFile->eFileLock );
    lock.l_type = F_WRLCK;

    assert( eFileLock==RESERVED_LOCK || eFileLock==EXCLUSIVE_LOCK );
    if( eFileLock==RESERVED_LOCK ){
      lock.l_start = RESERVED_BYTE;
      lock.l_len = 1L;
    }else{
      lock.l_start = SHARED_FIRST;
      lock.l_len = SHARED_SIZE;
    }

    if( unixFileLock(pFile, &lock) ){
      tErrno = errno;
      rc = sqliteErrorFromPosixError(tErrno, SQLITE_IOERR_LOCK);
      if( rc!=SQLITE_BUSY ){
        storeLastErrno(pFile, tErrno);
      }
    }
  }


#ifdef SQLITE_DEBUG
  /* Set up the transaction-counter change checking flags when
  ** transitioning from a SHARED to a RESERVED lock.  The change
  ** from SHARED to RESERVED marks the beginning of a normal
  ** write operation (not a hot journal rollback).
  */
  if( rc==SQLITE_OK
   && pFile->eFileLock<=SHARED_LOCK
   && eFileLock==RESERVED_LOCK
  ){
    pFile->transCntrChng = 0;
    pFile->dbUpdate = 0;
    pFile->inNormalWrite = 1;
  }
#endif

  if( rc==SQLITE_OK ){
    pFile->eFileLock = eFileLock;
    pInode->eFileLock = eFileLock;
  }

end_lock:
  sqlite3_mutex_leave(pInode->pLockMutex);
  OSTRACE(("LOCK    %d %s %s (unix)\n", pFile->h, azFileLock(eFileLock),
      rc==SQLITE_OK ? "ok" : "failed"));
  return rc;
}

static void setPendingFd(unixFile *pFile){
  unixInodeInfo *pInode = pFile->pInode;
  UnixUnusedFd *p = pFile->pPreallocatedUnused;
  assert( unixFileMutexHeld(pFile) );
  p->pNext = pInode->pUnused;
  pInode->pUnused = p;
  pFile->h = -1;
  pFile->pPreallocatedUnused = 0;
}

static int posixUnlock(sqlite3_file *id, int eFileLock, int handleNFSUnlock){
  unixFile *pFile = (unixFile*)id;
  unixInodeInfo *pInode;
  struct flock lock;
  int rc = SQLITE_OK;

  assert( pFile );
  OSTRACE(("UNLOCK  %d %d was %d(%d,%d) pid=%d (unix)\n", pFile->h, eFileLock,
      pFile->eFileLock, pFile->pInode->eFileLock, pFile->pInode->nShared,
      osGetpid(0)));

  assert( eFileLock<=SHARED_LOCK );
  if( pFile->eFileLock<=eFileLock ){
    return SQLITE_OK;
  }
  pInode = pFile->pInode;
  sqlite3_mutex_enter(pInode->pLockMutex);
  assert( pInode->nShared!=0 );
  if( pFile->eFileLock>SHARED_LOCK ){
    assert( pInode->eFileLock==pFile->eFileLock );

#ifdef SQLITE_DEBUG
    /* When reducing a lock such that other processes can start
    ** reading the database file again, make sure that the
    ** transaction counter was updated if any part of the database
    ** file changed.  If the transaction counter is not updated,
    ** other connections to the same file might not realize that
    ** the file has changed and hence might not know to flush their
    ** cache.  The use of a stale cache can lead to database corruption.
    */
    pFile->inNormalWrite = 0;
#endif

    /* downgrading to a shared lock on NFS involves clearing the write lock
    ** before establishing the readlock - to avoid a race condition we downgrade
    ** the lock in 2 blocks, so that part of the range will be covered by a
    ** write lock until the rest is covered by a read lock:
    **  1:   [WWWWW]
    **  2:   [....W]
    **  3:   [RRRRW]
    **  4:   [RRRR.]
    */
    if( eFileLock==SHARED_LOCK ){
#if !defined(__APPLE__) || !SQLITE_ENABLE_LOCKING_STYLE
      (void)handleNFSUnlock;
      assert( handleNFSUnlock==0 );
#endif
#if defined(__APPLE__) && SQLITE_ENABLE_LOCKING_STYLE
      if( handleNFSUnlock ){
        int tErrno;               /* Error code from system call errors */
        off_t divSize = SHARED_SIZE - 1;
      
        lock.l_type = F_UNLCK;
        lock.l_whence = SEEK_SET;
        lock.l_start = SHARED_FIRST;
        lock.l_len = divSize;
        if( unixFileLock(pFile, &lock)==(-1) ){
          tErrno = errno;
          rc = SQLITE_IOERR_UNLOCK;
          storeLastErrno(pFile, tErrno);
          goto end_unlock;
        }
        lock.l_type = F_RDLCK;
        lock.l_whence = SEEK_SET;
        lock.l_start = SHARED_FIRST;
        lock.l_len = divSize;
        if( unixFileLock(pFile, &lock)==(-1) ){
          tErrno = errno;
          rc = sqliteErrorFromPosixError(tErrno, SQLITE_IOERR_RDLOCK);
          if( IS_LOCK_ERROR(rc) ){
            storeLastErrno(pFile, tErrno);
          }
          goto end_unlock;
        }
        lock.l_type = F_UNLCK;
        lock.l_whence = SEEK_SET;
        lock.l_start = SHARED_FIRST+divSize;
        lock.l_len = SHARED_SIZE-divSize;
        if( unixFileLock(pFile, &lock)==(-1) ){
          tErrno = errno;
          rc = SQLITE_IOERR_UNLOCK;
          storeLastErrno(pFile, tErrno);
          goto end_unlock;
        }
      }else
#endif /* defined(__APPLE__) && SQLITE_ENABLE_LOCKING_STYLE */
      {
        lock.l_type = F_RDLCK;
        lock.l_whence = SEEK_SET;
        lock.l_start = SHARED_FIRST;
        lock.l_len = SHARED_SIZE;
        if( unixFileLock(pFile, &lock) ){
          /* In theory, the call to unixFileLock() cannot fail because another
          ** process is holding an incompatible lock. If it does, this
          ** indicates that the other process is not following the locking
          ** protocol. If this happens, return SQLITE_IOERR_RDLOCK. Returning
          ** SQLITE_BUSY would confuse the upper layer (in practice it causes
          ** an assert to fail). */
          rc = SQLITE_IOERR_RDLOCK;
          storeLastErrno(pFile, errno);
          goto end_unlock;
        }
      }
    }
    lock.l_type = F_UNLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = PENDING_BYTE;
    lock.l_len = 2L;  assert( PENDING_BYTE+1==RESERVED_BYTE );
    if( unixFileLock(pFile, &lock)==0 ){
      pInode->eFileLock = SHARED_LOCK;
    }else{
      rc = SQLITE_IOERR_UNLOCK;
      storeLastErrno(pFile, errno);
      goto end_unlock;
    }
  }
  if( eFileLock==NO_LOCK ){
    /* Decrement the shared lock counter.  Release the lock using an
    ** OS call only when all threads in this same process have released
    ** the lock.
    */
    pInode->nShared--;
    if( pInode->nShared==0 ){
      lock.l_type = F_UNLCK;
      lock.l_whence = SEEK_SET;
      lock.l_start = lock.l_len = 0L;
      if( unixFileLock(pFile, &lock)==0 ){
        pInode->eFileLock = NO_LOCK;
      }else{
        rc = SQLITE_IOERR_UNLOCK;
        storeLastErrno(pFile, errno);
        pInode->eFileLock = NO_LOCK;
        pFile->eFileLock = NO_LOCK;
      }
    }

    /* Decrement the count of locks against this same file.  When the
    ** count reaches zero, close any other file descriptors whose close
    ** was deferred because of outstanding locks.
    */
    pInode->nLock--;
    assert( pInode->nLock>=0 );
    if( pInode->nLock==0 ) closePendingFds(pFile);
  }

end_unlock:
  sqlite3_mutex_leave(pInode->pLockMutex);
  if( rc==SQLITE_OK ){
    pFile->eFileLock = eFileLock;
  }
  return rc;
}

static int unixUnlock(sqlite3_file *id, int eFileLock){
#if SQLITE_MAX_MMAP_SIZE>0
  assert( eFileLock==SHARED_LOCK || ((unixFile *)id)->nFetchOut==0 );
#endif
  return posixUnlock(id, eFileLock, 0);
}

static int closeUnixFile(sqlite3_file *id){
  unixFile *pFile = (unixFile*)id;
#if SQLITE_MAX_MMAP_SIZE>0
  unixUnmapfile(pFile);
#endif
  if( pFile->h>=0 ){
    robust_close(pFile, pFile->h, __LINE__);
    pFile->h = -1;
  }
#if OS_VXWORKS
  if( pFile->pId ){
    if( pFile->ctrlFlags & UNIXFILE_DELETE ){
      osUnlink(pFile->pId->zCanonicalName);
    }
    vxworksReleaseFileId(pFile->pId);
    pFile->pId = 0;
  }
#endif
#ifdef SQLITE_UNLINK_AFTER_CLOSE
  if( pFile->ctrlFlags & UNIXFILE_DELETE ){
    osUnlink(pFile->zPath);
    sqlite3_free(*(char**)&pFile->zPath);
    pFile->zPath = 0;
  }
#endif
  OSTRACE(("CLOSE   %-3d\n", pFile->h));
  OpenCounter(-1);
  sqlite3_free(pFile->pPreallocatedUnused);
  memset(pFile, 0, sizeof(unixFile));
  return SQLITE_OK;
}

static int unixClose(sqlite3_file *id){
  int rc = SQLITE_OK;
  unixFile *pFile = (unixFile *)id;
  unixInodeInfo *pInode = pFile->pInode;

  assert( pInode!=0 );
  verifyDbFile(pFile);
  unixUnlock(id, NO_LOCK);
  assert( unixFileMutexNotheld(pFile) );
  unixEnterMutex();

  /* unixFile.pInode is always valid here. Otherwise, a different close
  ** routine (e.g. nolockClose()) would be called instead.
  */
  assert( pFile->pInode->nLock>0 || pFile->pInode->bProcessLock==0 );
  sqlite3_mutex_enter(pInode->pLockMutex);
  if( pInode->nLock ){
    /* If there are outstanding locks, do not actually close the file just
    ** yet because that would clear those locks.  Instead, add the file
    ** descriptor to pInode->pUnused list.  It will be automatically closed
    ** when the last lock is cleared.
    */
    setPendingFd(pFile);
  }
  sqlite3_mutex_leave(pInode->pLockMutex);
  releaseInodeInfo(pFile);
  assert( pFile->pShm==0 );
  rc = closeUnixFile(id);
  unixLeaveMutex();
  return rc;
}

static UnixUnusedFd *findReusableFd(const char *zPath, int flags){
  UnixUnusedFd *pUnused = 0;

  /* Do not search for an unused file descriptor on vxworks. Not because
  ** vxworks would not benefit from the change (it might, we're not sure),
  ** but because no way to test it is currently available. It is better
  ** not to risk breaking vxworks support for the sake of such an obscure
  ** feature.  */
#if !OS_VXWORKS
  struct stat sStat;                   /* Results of stat() call */

  unixEnterMutex();

  /* A stat() call may fail for various reasons. If this happens, it is
  ** almost certain that an open() call on the same path will also fail.
  ** For this reason, if an error occurs in the stat() call here, it is
  ** ignored and -1 is returned. The caller will try to open a new file
  ** descriptor on the same path, fail, and return an error to SQLite.
  **
  ** Even if a subsequent open() call does succeed, the consequences of
  ** not searching for a reusable file descriptor are not dire.  */
  if( inodeList!=0 && 0==osStat(zPath, &sStat) ){
    unixInodeInfo *pInode;

    pInode = inodeList;
    while( pInode && (pInode->fileId.dev!=sStat.st_dev
                     || pInode->fileId.ino!=(u64)sStat.st_ino) ){
       pInode = pInode->pNext;
    }
    if( pInode ){
      UnixUnusedFd **pp;
      assert( sqlite3_mutex_notheld(pInode->pLockMutex) );
      sqlite3_mutex_enter(pInode->pLockMutex);
      flags &= (SQLITE_OPEN_READONLY|SQLITE_OPEN_READWRITE);
      for(pp=&pInode->pUnused; *pp && (*pp)->flags!=flags; pp=&((*pp)->pNext));
      pUnused = *pp;
      if( pUnused ){
        *pp = pUnused->pNext;
      }
      sqlite3_mutex_leave(pInode->pLockMutex);
    }
  }
  unixLeaveMutex();
#endif    /* if !OS_VXWORKS */
  return pUnused;
}

/* END exact original policy functions. The following exports are test transport. */
static File *selected(uint64_t handle) {
  for(size_t i=0;i<file_count;i++)if(files[i].logical==handle && files[i].active)return &files[i];
  return 0;
}
void oracle_reset(uint64_t dev,uint64_t ino,uint64_t mode,uint64_t uid,uint64_t gid) {
  while(allocations){Allocation *a=allocations;allocations=a->next;free(a->p);free(a);}
  free(files);files=0;file_count=0;
  free(events);events=0;event_count=0;
  free(faults);faults=0;fault_count=0;
  free(taken);taken=0;taken_count=0;reusable_stat_calls=0;
  inodeList=0;fixture_dev=(dev_t)dev;fixture_ino=(ino_t)ino;
  fixture_mode=(mode_t)mode;fixture_uid=(uid_t)uid;fixture_gid=(gid_t)gid;
  fixture_getlk_type=F_UNLCK;ignored_close_errors=0;
}
int oracle_add_fault(uint64_t number,uint64_t op,uint64_t error) {
  if(number==0 || error==0 || error>4095 || fault_count==SIZE_MAX/sizeof(Fault))return -1;
  for(size_t i=0;i<fault_count;i++)if(faults[i].number==number)return -1;
  Fault *next=realloc(faults,(fault_count+1)*sizeof(Fault));
  if(!next)return -1;
  faults=next;faults[fault_count++]=(Fault){number,op,error};return 0;
}
int oracle_getlk_kind(int kind) {
  if(kind!=F_UNLCK && kind!=F_RDLCK && kind!=F_WRLCK)return -1;
  fixture_getlk_type=kind;return 0;
}
int oracle_register(uint64_t handle,uint64_t token,uint64_t flags) {
  if(handle==0 || token>INT32_MAX || flags>3 || selected(handle))return -1000;
  for(size_t i=0;i<file_count;i++)if(files[i].token==token && files[i].active)return -1000;
  unixFile *p=tracked_malloc(sizeof(*p));
  if(!p)return SQLITE_NOMEM_BKPT;
  memset(p,0,sizeof(*p));p->h=(int)token;p->zPath="issued-test-db";
  p->ctrlFlags=(unsigned short)(((flags&1)?UNIXFILE_RDONLY:0)|((flags&2)?UNIXFILE_EXCL:0));
  for(size_t i=0;i<taken_count;i++) {
    if(taken[i].record && taken[i].token==token) {
      if(taken[i].record->flags!=((flags&1)?1:2)) return -1001;
      p->pPreallocatedUnused=taken[i].record;
      taken[i].record=0;
      break;
    }
  }
  if(!p->pPreallocatedUnused) {
    p->pPreallocatedUnused=tracked_malloc(sizeof(UnixUnusedFd));
    if(!p->pPreallocatedUnused)return SQLITE_NOMEM_BKPT;
    memset(p->pPreallocatedUnused,0,sizeof(UnixUnusedFd));
  }
  p->pPreallocatedUnused->fd=p->h;p->pPreallocatedUnused->flags=(flags&1)?1:2;
  int rc=findInodeInfo(p,&p->pInode);
  if(rc!=SQLITE_OK)return rc;
  File *next=realloc(files,(file_count+1)*sizeof(File));
  if(!next)abort();
  files=next;files[file_count++]=(File){p,1,handle,token,flags};
  return rc;
}
int oracle_lock(uint64_t handle,int level) {
  File *f=selected(handle);if(!f)return -1000;
  return unixLock((sqlite3_file*)f->file,level);
}
int oracle_unlock(uint64_t handle,int level) {
  File *f=selected(handle);if(!f)return -1000;
  return unixUnlock((sqlite3_file*)f->file,level);
}
int oracle_reserved(uint64_t handle,int *result) {
  File *f=selected(handle);if(!f)return -1000;
  return unixCheckReservedLock((sqlite3_file*)f->file,result);
}
int oracle_close(uint64_t handle) {
  File *f=selected(handle);if(!f)return -1000;
  int rc=unixClose((sqlite3_file*)f->file);
  f->active=0;return rc;
}
uint64_t oracle_take_unused(uint64_t flags) {
  if(flags>UINT32_MAX) abort();
  UnixUnusedFd *p=findReusableFd("issued-test-db",(int)(uint32_t)flags);
  if(!p)return 0;
  if(p->fd<=0 || taken_count==SIZE_MAX/sizeof(TakenUnused))abort();
  TakenUnused *next=realloc(taken,(taken_count+1)*sizeof(TakenUnused));
  if(!next)abort();
  taken=next;taken[taken_count++]=(TakenUnused){p,(uint64_t)p->fd};
  return (uint64_t)p->fd;
}
uint64_t oracle_reusable_stats(void) { return reusable_stat_calls; }
uint64_t oracle_events(void) { return event_count; }
int oracle_event(uint64_t index,uint64_t *out) {
  if(index>=event_count || !out)return -1;
  memcpy(out,&events[index],sizeof(Event));return 0;
}
uint64_t oracle_files(void) { return file_count; }
int oracle_file(uint64_t index,uint64_t *out) {
  if(index>=file_count || !out)return -1;
  File *f=&files[index];
  out[0]=f->logical;out[1]=f->token;out[2]=f->active;out[3]=f->flags;
  out[4]=f->active?f->file->eFileLock:0;
  out[5]=f->active?(uint64_t)f->file->lastErrno:0;
  return 0;
}
int oracle_group(uint64_t *out) {
  if(!out)return -1;
  memset(out,0,10*sizeof(uint64_t));
  if(inodeList) {
    if(inodeList->pNext) return -2; /* One selected inode per independent case. */
    out[0]=1;out[1]=inodeList->fileId.dev;out[2]=inodeList->fileId.ino;
    out[3]=(uint64_t)inodeList->nRef;out[4]=(uint64_t)inodeList->nShared;
    out[5]=(uint64_t)inodeList->nLock;out[6]=inodeList->eFileLock;
    out[7]=inodeList->bProcessLock;
    for(UnixUnusedFd *p=inodeList->pUnused;p;p=p->pNext)out[8]++;
  }
  out[9]=ignored_close_errors;
  return 0;
}
int oracle_unused(uint64_t index,uint64_t *out) {
  if(!inodeList || !out)return -1;
  UnixUnusedFd *p=inodeList->pUnused;
  while(p && index){p=p->pNext;index--;}
  if(!p)return -1;
  out[0]=(uint64_t)p->fd;out[1]=(uint64_t)p->flags;return 0;
}
uint64_t oracle_abi(void) {
  if(sizeof(struct stat)!=144 || sizeof(struct flock)!=32 || sizeof(Event)!=64)return 0;
  return UINT64_C(0x31304f4344414948); /* HIADCO01 in little endian */
}
