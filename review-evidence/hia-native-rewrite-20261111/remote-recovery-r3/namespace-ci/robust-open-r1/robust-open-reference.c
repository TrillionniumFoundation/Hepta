/* NEW controlled reference shim around the exact SQLite 3.46.1 robust_open.
 * All decisions below the marker remain original C. Provider scripts contain
 * only raw syscall/log returns, never HIA decisions or expected HIA state.
 * This shared library does not perform actual filesystem syscalls.
 */
#define _GNU_SOURCE 1
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#define SQLITE_DEFAULT_FILE_PERMISSIONS 0644
#define SQLITE_MINIMUM_FILE_DESCRIPTOR 3
#define SQLITE_WARNING 28
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
static void event(uint64_t kind,uint64_t a,uint64_t b,uint64_t c,uint64_t d,
                  const unsigned char *bytes,uint64_t n){
  if(n>UINT64_MAX-48 || used>capacity || n+48>capacity-used){failed=1;return;}
  uint64_t h[6]={kind,a,b,c,d,n};
  for(unsigned i=0;i<6;i++)word(events+used+8*i,h[i]);
  if(n)memcpy(events+used+48,bytes,(size_t)n);
  used+=48+n;event_count++;
}
static RawReturn take(uint64_t kind){
  RawReturn out={kind,-1,EINVAL,0,0,0,0,0,0,0};
  if(cursor>=script_count){failed=2;return out;}
  out=script[cursor++];
  if(out.kind!=kind){failed=3;out.result=-1;out.error=EINVAL;}
  if(out.result<0)errno=(int)out.error;
  return out;
}
static int osOpen(const char *path,int flags,mode_t mode){
  event(28,(uint32_t)flags,(uint32_t)mode,0,0,(const unsigned char*)path,strlen(path));
  RawReturn r=take(28);return (int)r.result;
}
static int osUnlink(const char *path){
  event(9,0,0,0,0,(const unsigned char*)path,strlen(path));
  RawReturn r=take(9);return (int)r.result;
}
static int osClose(int fd){
  event(8,(uint32_t)fd,0,0,0,0,0);
  RawReturn r=take(8);return (int)r.result;
}
static int osFstat(int fd,struct stat *s){
  event(15,(uint32_t)fd,0,0,0,0,0);
  RawReturn r=take(15);
  if(r.result==0){
    memset(s,0,sizeof(*s));s->st_mode=(mode_t)r.mode;s->st_size=(off_t)r.size;
    s->st_nlink=(nlink_t)r.nlink;s->st_dev=(dev_t)r.dev;s->st_ino=(ino_t)r.ino;
    s->st_uid=(uid_t)r.uid;s->st_gid=(gid_t)r.gid;
  }
  return (int)r.result;
}
static int osFchmod(int fd,mode_t mode){
  event(21,(uint32_t)fd,(uint32_t)mode,0,0,0,0);
  RawReturn r=take(21);return (int)r.result;
}
static void sqlite3_log(int code,const char *fmt,...){
  va_list ap,again;va_start(ap,fmt);va_copy(again,ap);
  int n=vsnprintf(NULL,0,fmt,ap);va_end(ap);
  if(n<0){failed=4;va_end(again);return;}
  char *buf=malloc((size_t)n+1);
  if(!buf){failed=5;va_end(again);return;}
  int got=vsnprintf(buf,(size_t)n+1,fmt,again);va_end(again);
  if(got!=n){failed=6;free(buf);return;}
  event(10028,(uint32_t)code,0,0,0,(unsigned char*)buf,(uint64_t)n);free(buf);
  RawReturn r=take(10028);
  errno=(int)r.error;
}
/* BEGIN EXACT SQLite 3.46.1 policy function. */
static int robust_open(const char *z, int f, mode_t m){
  int fd;
  mode_t m2 = m ? m : SQLITE_DEFAULT_FILE_PERMISSIONS;
  while(1){
#if defined(O_CLOEXEC)
    fd = osOpen(z,f|O_CLOEXEC,m2);
#else
    fd = osOpen(z,f,m2);
#endif
    if( fd<0 ){
      if( errno==EINTR ) continue;
      break;
    }
    if( fd>=SQLITE_MINIMUM_FILE_DESCRIPTOR ) break;
    if( (f & (O_EXCL|O_CREAT))==(O_EXCL|O_CREAT) ){
      (void)osUnlink(z);
    }
    osClose(fd);
    sqlite3_log(SQLITE_WARNING,
                "attempt to open \"%s\" as file descriptor %d", z, fd);
    fd = -1;
    if( osOpen("/dev/null", O_RDONLY, m)<0 ) break;
  }
  if( fd>=0 ){
    if( m!=0 ){
      struct stat statbuf;
      if( osFstat(fd, &statbuf)==0
       && statbuf.st_size==0
       && (statbuf.st_mode&0777)!=m
      ){
        osFchmod(fd, m);
      }
    }
#if defined(FD_CLOEXEC) && (!defined(O_CLOEXEC) || O_CLOEXEC==0)
    osFcntl(fd, F_SETFD, osFcntl(fd, F_GETFD, 0) | FD_CLOEXEC);
#endif
  }
  return fd;
}

/* END EXACT SQLite 3.46.1 policy function. */
uint64_t oracle_abi(void){
  return sizeof(RawReturn)==80 && sizeof(struct stat)==144 &&
    O_CLOEXEC==524288 && O_EXCL==128 && O_CREAT==64 && O_RDONLY==0
    ? UINT64_C(0x31304f524e414948) : 0;
}
int oracle_run(const unsigned char *path,uint64_t path_bytes,
               uint64_t flags,uint64_t mode,uint64_t initial_errno,
               const RawReturn *returns,uint64_t count,
               unsigned char *trace,uint64_t trace_capacity,uint64_t *result){
  if(!path || !result || (!returns && count) || (!trace && trace_capacity) ||
     path_bytes>SIZE_MAX-1 || flags>UINT32_MAX || mode>UINT32_MAX || initial_errno>4095)
    return -1;
  if(memchr(path,0,(size_t)path_bytes))return -1;
  char *name=malloc((size_t)path_bytes+1);if(!name)return -1;
  memcpy(name,path,(size_t)path_bytes);name[path_bytes]=0;
  script=returns;script_count=count;cursor=event_count=used=failed=0;
  events=trace;capacity=trace_capacity;errno=(int)initial_errno;
  int fd=robust_open(name,(int)(uint32_t)flags,(mode_t)mode);
  int final_errno=errno;free(name);
  result[0]=(uint64_t)(int64_t)fd;result[1]=(uint64_t)(uint32_t)final_errno;
  result[2]=cursor;result[3]=event_count;result[4]=used;result[5]=failed;
  result[6]=count;result[7]=cursor==count;
  script=NULL;events=NULL;return 0;
}
