"""Exact SQLite unixOpen bodies with explicit deterministic foreign effects.

Only the test scaffold supplies effects. The six original selected C bodies are
copied byte for byte from the pinned os_unix.c. This oracle neither performs
namespace syscalls nor supplies evidence of native Store completion.
"""
from __future__ import annotations
import ctypes,hashlib,json,subprocess
from pathlib import Path
ORIGINAL_GIT="9e7ba05d6882b1f3c310b99102e8ecbf7f830af2"
ORIGINAL_SHA256="83e4f995c0cfc1362b46320d979b38349ac5b1c6a7c0b12cbc2c4577c6c13ef9"
FUNCTIONS=("static int fileHasMoved(","static void verifyDbFile(",
    "static int robustFchown(","static void robust_close(",
    "static int fillInUnixFile(","static int unixOpen(")
PRELUDE=r'''
#define _GNU_SOURCE 1
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <setjmp.h>
#define SQLITE_ENABLE_LOCKING_STYLE 0
#define OS_VXWORKS 0
#define SQLITE_MAX_MMAP_SIZE 0x7fffffff
#define HAVE_FCHOWN 1
#define MAX_PATHNAME 512
#define SQLITE_OK 0
#define SQLITE_ERROR 1
#define SQLITE_NOMEM_BKPT 7
#define SQLITE_IOERR 10
#define SQLITE_CANTOPEN_BKPT 14
#define SQLITE_READONLY_DIRECTORY 1544
#define SQLITE_IOERR_CLOSE 4106
#define SQLITE_WARNING 28
#define SQLITE_OPEN_READONLY 1
#define SQLITE_OPEN_READWRITE 2
#define SQLITE_OPEN_CREATE 4
#define SQLITE_OPEN_DELETEONCLOSE 8
#define SQLITE_OPEN_EXCLUSIVE 16
#define SQLITE_OPEN_URI 64
#define SQLITE_OPEN_MAIN_DB 256
#define SQLITE_OPEN_TEMP_DB 512
#define SQLITE_OPEN_TRANSIENT_DB 1024
#define SQLITE_OPEN_MAIN_JOURNAL 2048
#define SQLITE_OPEN_TEMP_JOURNAL 4096
#define SQLITE_OPEN_SUBJOURNAL 8192
#define SQLITE_OPEN_SUPER_JOURNAL 16384
#define SQLITE_OPEN_WAL 524288
#define SQLITE_POWERSAFE_OVERWRITE (oracle_psow)
#define UNIXFILE_EXCL 1
#define UNIXFILE_RDONLY 2
#define UNIXFILE_PERSIST_WAL 4
#define UNIXFILE_DIRSYNC 8
#define UNIXFILE_PSOW 16
#define UNIXFILE_DELETE 32
#define UNIXFILE_URI 64
#define UNIXFILE_NOLOCK 128
#define O_BINARY 0
#define DOTLOCK_SUFFIX ".lock"
#define OSTRACE(x) ((void)0)
#define OpenCounter(x) (oracle_open_counter += (x))
#define storeLastErrno(p,e) ((p)->lastErrno=(e))
typedef uint64_t u64;
typedef int64_t i64;
typedef int64_t sqlite3_int64;
typedef unsigned char u8;
typedef struct sqlite3_io_methods {int tag;} sqlite3_io_methods;
typedef struct sqlite3_file {const sqlite3_io_methods *pMethods;} sqlite3_file;
typedef struct sqlite3_vfs {
  int mxPathname; const char *zName; void *pAppData;
} sqlite3_vfs;
typedef struct unixShm unixShm;
typedef struct unixInodeInfo {
  struct {dev_t dev;u64 ino;} fileId;
  u64 identity;
} unixInodeInfo;
typedef struct UnixUnusedFd UnixUnusedFd;
struct UnixUnusedFd {int fd;int flags;UnixUnusedFd *pNext;};
'''
SCAFFOLD=r'''
typedef const sqlite3_io_methods *(*finder_type)(const char*,unixFile*);
typedef void (*oracle_callback)(u64,u64,const u64*,const unsigned char*,u64,u64*,unsigned char*,u64);
static oracle_callback callback;
static jmp_buf escape;
static int oracle_errno_view;
static unixFile file_state;
static sqlite3_vfs vfs;
static const sqlite3_io_methods posixIoMethods={2},nolockIoMethods={1},dotlockIoMethods={3};
static struct {i64 szMmap;} sqlite3GlobalConfig;
static pid_t randomnessPid;
static u64 oracle_open_counter,oracle_psow,oracle_vfsid,oracle_pathlease,oracle_mutex,oracle_tempdirlease;
static u64 original_bytes,original_offset,getpid_count,robust_count;
static const unsigned char *original_base;
static int out_flags,out_requested;
static unixInodeInfo inode_state;
static struct {UnixUnusedFd value;u64 id;int live;int initialized;} unused[4];
static size_t unused_count;
static struct {int fd;u64 token;} fd_map[8];
static size_t fd_count;
static u64 result[8];
static unsigned char result_data[512];
static void oracle_snapshot(u64 *out);
static u64 q(const unsigned char *p,size_t n){u64 v;memcpy(&v,p+n,8);return v;}
static void issue(u64 op,u64 stage,u64 a,u64 b,u64 c,u64 d,u64 e,u64 f,
                  const unsigned char *path,u64 n){
  const u64 args[6]={a,b,c,d,e,f};
  memset(result,0,sizeof(result));memset(result_data,0,sizeof(result_data));
  oracle_errno_view=errno;
  if(op==11 && file_state.pPreallocatedUnused){
    for(size_t i=0;i<unused_count;i++)if(&unused[i].value==file_state.pPreallocatedUnused)unused[i].initialized=1;
  }
  callback(op,stage,args,path,n,result,result_data,sizeof(result_data));
  if(result[7]==UINT64_MAX)longjmp(escape,1);
  assert(result[0]<=4095 && result[7]<=sizeof(result_data));
  errno=(int)result[0];oracle_errno_view=errno;
}
static u64 ptr_id(const UnixUnusedFd *p){
  if(!p)return 0;
  for(size_t i=0;i<unused_count;i++)if(&unused[i].value==p)return unused[i].id;
  abort();
}
static size_t ptr_index(const UnixUnusedFd *p){
  for(size_t i=0;i<unused_count;i++)if(&unused[i].value==p)return i;
  abort();
}
static void remember_fd(int fd,u64 token){
  for(size_t i=0;i<fd_count;i++)if(fd_map[i].fd==fd){fd_map[i].token=token;return;}
  assert(fd_count<8);fd_map[fd_count].fd=fd;fd_map[fd_count++].token=token;
}
static u64 fd_token(int fd){
  for(size_t i=0;i<fd_count;i++)if(fd_map[i].fd==fd)return fd_map[i].token;
  abort();
}
static UnixUnusedFd *make_unused(u64 id,int initialized,int fd,int flags){
  assert(id && unused_count<4);
  size_t i=unused_count++;unused[i].id=id;unused[i].live=1;unused[i].initialized=initialized;
  unused[i].value.fd=fd;unused[i].value.flags=flags;unused[i].value.pNext=NULL;
  return &unused[i].value;
}
static int osGetpid(int ignored){
  (void)ignored;issue(1,getpid_count++==0?10:11,0,0,0,0,0,0,NULL,0);
  return (int)result[1];
}
static void sqlite3_randomness(int n,void *p){
  assert(n==0 && p==NULL);issue(2,12,0,0,0,0,0,0,NULL,0);
}
static void *sqlite3_malloc64(u64 n){
  issue(4,21,n,0,0,0,0,0,NULL,0);
  return result[1] ? make_unused(result[2],0,0,0) : NULL;
}
static void sqlite3_free(void *p){
  const u64 id=ptr_id((UnixUnusedFd*)p);
  const u64 stage=p && p!=file_state.pPreallocatedUnused ? 34:80;
  issue(18,stage,id,0,0,0,0,0,NULL,0);
  if(p)unused[ptr_index((UnixUnusedFd*)p)].live=0;
}
static UnixUnusedFd *findReusableFd(const char *path,int flags){
  issue(3,robust_count?33:20,(uint32_t)flags,0,0,0,0,0,
        (const unsigned char*)path,strlen(path));
  if(!result[1])return NULL;
  remember_fd((int)result[3],result[2]);
  return make_unused(result[1],1,(int)result[3],(int)result[4]);
}
static int unixGetTempname(int n,char *path){
  issue(5,22,(u64)n,oracle_tempdirlease,0,0,0,0,NULL,0);
  if(result[1]==0){assert(result[7]<=(u64)n);memcpy(path,result_data,(size_t)result[7]);}
  return (int)result[1];
}
static int findCreateFileMode(const char *path,int flags,mode_t *mode,uid_t *uid,gid_t *gid){
  const unsigned char *bytes;u64 n,offset;
  if(original_base){
    bytes=original_base;n=original_bytes;offset=(const unsigned char*)path-original_base;
  }else{
    bytes=(const unsigned char*)path;n=strlen(path)+2;offset=0;
  }
  issue(6,30,(uint32_t)flags,offset,1,0,0,0,bytes,n);
  *mode=(mode_t)result[2];*uid=(uid_t)result[3];*gid=(gid_t)result[4];
  return (int)result[1];
}
static int robust_open(const char *path,int flags,int mode){
  issue(7,robust_count++?35:31,(uint32_t)flags,(uint32_t)mode,0,0,0,0,
        (const unsigned char*)path,strlen(path));
  if(!result[1])return -1;
  remember_fd((int)result[2],result[1]);return (int)result[2];
}
static int osAccess(const char *path,int flags){
  issue(8,32,(uint32_t)flags,0,0,0,0,0,(const unsigned char*)path,strlen(path));
  return result[1] ? -1:0;
}
static uid_t osGeteuid(void){issue(9,40,0,0,0,0,0,0,NULL,0);return (uid_t)result[1];}
static int osFchown(int fd,uid_t uid,gid_t gid){
  issue(10,41,fd_token(fd),uid,gid,0,0,0,NULL,0);return result[1] ? -1:0;
}
static int osUnlink(const char *path){
  issue(11,50,0,0,0,0,0,0,(const unsigned char*)path,strlen(path));
  return result[1] ? -1:0;
}
static int sqlite3_uri_boolean(const char *path,const char *key,int dflt){
  assert(strcmp(key,"psow")==0);
  issue(12,60,path?original_offset:0,path?1:0,(uint32_t)dflt,0,0,0,
        path?original_base:NULL,path?original_bytes:0);
  return (int)result[1];
}
static void unixEnterMutex(void){assert(oracle_mutex==0);oracle_mutex=1;}
static void unixLeaveMutex(void){assert(oracle_mutex==1);oracle_mutex=0;}
static int findInodeInfo(unixFile *p,unixInodeInfo **out){
  const u64 flags=((p->ctrlFlags&UNIXFILE_RDONLY)?1:0)|((p->ctrlFlags&UNIXFILE_EXCL)?2:0);
  issue(13,61,fd_token(p->h),flags,ptr_id(p->pPreallocatedUnused),0,0,0,NULL,0);
  if(result[1]){
    if(result[1]==SQLITE_IOERR)storeLastErrno(p,errno);
    return (int)result[1];
  }
  inode_state.identity=result[3];inode_state.fileId.dev=(dev_t)result[4];
  inode_state.fileId.ino=result[5];*out=&inode_state;return 0;
}
static int osClose(int fd){
  issue(14,62,fd_token(fd),0,0,0,0,0,NULL,0);return result[1] ? -1:0;
}
static int osFstat(int fd,struct stat *out){
  issue(15,70,fd_token(fd),0,0,0,0,0,NULL,0);memset(out,0,sizeof(*out));
  out->st_ino=(ino_t)result[2];out->st_nlink=(nlink_t)result[3];
  return result[1] ? -1:0;
}
static int osStat(const char *path,struct stat *out){
  issue(16,71,0,0,0,0,0,0,(const unsigned char*)path,strlen(path));memset(out,0,sizeof(*out));
  out->st_ino=(ino_t)result[2];out->st_nlink=(nlink_t)result[3];
  return result[1] ? -1:0;
}
static int unixLogErrorAtLine(int code,const char *what,const char *path,int line){
  (void)line;
  u64 stage=strcmp(what,"open")==0?36:63;
  issue(17,stage,(uint32_t)code,stage==36?5:6,0,0,0,0,
        (const unsigned char*)path,path?strlen(path):0);
  return (int)result[1];
}
#define unixLogError(code,what,path) unixLogErrorAtLine(code,what,path,__LINE__)
static void sqlite3_log(int code,const char *format,...){
  u64 reason=0;
  if(strcmp(format,"cannot fstat db file %s")==0)reason=1;
  else if(strcmp(format,"file unlinked while open: %s")==0)reason=2;
  else if(strcmp(format,"multiple links to file: %s")==0)reason=3;
  else if(strcmp(format,"file renamed while open: %s")==0)reason=4;
  assert(reason);
  va_list ap;va_start(ap,format);const char *path=va_arg(ap,const char*);va_end(ap);
  issue(17,72,(uint32_t)code,reason,0,0,0,0,
        (const unsigned char*)path,path?strlen(path):0);
}
static char *sqlite3_snprintf(int n,char *s,const char *fmt,...){
  va_list ap;va_start(ap,fmt);vsnprintf(s,(size_t)n,fmt,ap);va_end(ap);return s;
}
static const sqlite3_io_methods *reference_finder(const char *path,unixFile *p){
  (void)path;(void)p;return &posixIoMethods;
}
static finder_type finder=reference_finder;
static void oracle_snapshot(u64 *out){
  memset(out,0,32*sizeof(u64));
  out[0]=(uint32_t)file_state.h;
  out[1]=file_state.pVfs?oracle_vfsid:0;
  out[2]=file_state.zPath?oracle_pathlease:0;
  out[3]=file_state.ctrlFlags;
  out[4]=(u64)file_state.mmapSizeMax;
  out[5]=(uint32_t)file_state.lastErrno;
  out[6]=file_state.pMethod==&posixIoMethods?2:file_state.pMethod==&nolockIoMethods?1:0;
  out[7]=file_state.pInode?file_state.pInode->identity:0;
  out[8]=file_state.pInode?(u64)file_state.pInode->fileId.dev:0;
  out[9]=file_state.pInode?file_state.pInode->fileId.ino:0;
  out[10]=ptr_id(file_state.pPreallocatedUnused);
  if(file_state.pPreallocatedUnused){
    size_t i=ptr_index(file_state.pPreallocatedUnused);
    out[11]=unused[i].live;
    out[12]=(uint32_t)unused[i].value.fd;
    out[13]=(uint32_t)unused[i].value.flags;
    out[14]=unused[i].initialized || file_state.pVfs!=NULL;
  }
  out[15]=oracle_open_counter;out[16]=(uint32_t)randomnessPid;
  out[17]=(uint32_t)out_flags;out[18]=out_requested;
  out[19]=(uint32_t)oracle_errno_view;out[20]=oracle_mutex;
  out[21]=file_state.eFileLock;out[22]=file_state.szChunk;out[23]=file_state.nFetchOut;
  out[24]=(u64)file_state.mmapSize;out[25]=(u64)file_state.mmapSizeActual;
  out[26]=file_state.pMapRegion!=NULL;out[27]=file_state.pShm!=NULL;
  out[28]=(uint32_t)file_state.sectorSize;out[29]=(uint32_t)file_state.deviceCharacteristics;
  out[30]=file_state.lockingContext!=NULL;
}
'''
TAIL=r'''
void hia_unixopen_snapshot(u64 *out){oracle_snapshot(out);}
u64 hia_unixopen_sizeof_unused(void){return sizeof(UnixUnusedFd);}
int hia_unixopen_reference(const unsigned char *s,size_t size,oracle_callback fn,u64 *final){
  assert(size>=512 && q(s,64)==size-512);
  _Static_assert(sizeof(UnixUnusedFd)==16,"selected ABI");
  _Static_assert(O_RDONLY==0 && O_RDWR==2 && O_CREAT==64 && O_EXCL==128 && O_NOFOLLOW==131072,"selected POSIX flags");
  callback=fn;memset(&file_state,0,sizeof(file_state));memset(&inode_state,0,sizeof(inode_state));
  memset(unused,0,sizeof(unused));memset(fd_map,0,sizeof(fd_map));unused_count=fd_count=0;
  getpid_count=robust_count=oracle_mutex=0;
  oracle_vfsid=q(s,80);oracle_pathlease=q(s,40);oracle_psow=q(s,104);
  oracle_open_counter=q(s,144);randomnessPid=(pid_t)q(s,120);oracle_tempdirlease=q(s,136);
  sqlite3GlobalConfig.szMmap=(i64)q(s,96);
  original_base=q(s,56)?NULL:s+512;original_bytes=q(s,64);original_offset=q(s,192);
  vfs.mxPathname=(int)q(s,128);vfs.zName=q(s,88)?"unix-excl":"unix";vfs.pAppData=&finder;
  out_flags=(int)(uint32_t)q(s,200);out_requested=(int)q(s,72);
  errno=(int)q(s,112);
  const char *path=original_base?(const char*)original_base+original_offset:NULL;
  if(setjmp(escape))return -3;
  int rc=unixOpen(&vfs,path,(sqlite3_file*)&file_state,(int)(uint32_t)q(s,48),out_requested?&out_flags:NULL);
  if(file_state.pPreallocatedUnused){
    size_t i=ptr_index(file_state.pPreallocatedUnused);
    if(rc==0 || file_state.pVfs)unused[i].initialized=1;
  }
  oracle_errno_view=errno;oracle_snapshot(final);return rc;
}
'''
def extract(original:bytes,marker:str)->bytes:
    key=marker.encode("ascii");start=original.find(key)
    assert start>=0,marker
    end=original.find(b"\n}\n",start);assert end>=0,marker
    return original[start:end+3]
def build(original:Path,output:Path):
    raw=original.read_bytes();assert hashlib.sha256(raw).hexdigest()==ORIGINAL_SHA256
    assert hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()==ORIGINAL_GIT
    first=raw.index(b"typedef struct unixFile unixFile;")
    stop=raw.index(b"\n};",first)+3
    struct=raw[first:stop]
    bodies=[extract(raw,name) for name in FUNCTIONS]
    output.mkdir(parents=True,exist_ok=True)
    source=PRELUDE.encode()+b"\n"+struct+b"\n"+SCAFFOLD.encode()+b"\n"+b"\n#undef assert\n#define assert(x) ((void)0)\n"+b"\n".join(bodies)+b"\n#undef assert\n#define assert(x) ((x)?(void)0:abort())\n"+TAIL.encode()
    cpath=output/"unixopen-reference.c";cpath.write_bytes(source)
    so=output/"unixopen-reference.so"
    command=["cc","-std=c11","-O0","-g","-shared","-fPIC","-Wall","-Wextra","-Werror","-o",str(so),str(cpath)]
    try:result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,check=False)
    except subprocess.TimeoutExpired as error:
        (output/"cc.stdout").write_bytes(error.stdout or b"")
        (output/"cc.stderr").write_bytes(error.stderr or b"")
        (output/"cc-timeout.json").write_text(json.dumps(dict(command=command,timeout=60,
            status="FAIL_TIMEOUT_ORIGINAL_OUTPUT_PRESERVED"))+"\n")
        raise
    (output/"cc.stdout").write_bytes(result.stdout);(output/"cc.stderr").write_bytes(result.stderr)
    report={"schema":"hia.namespace.unixopen.reference-c-build.v1","command":command,"returncode":result.returncode,
        "source_sha256":hashlib.sha256(source).hexdigest(),"original_sha256":ORIGINAL_SHA256,
        "original_git":ORIGINAL_GIT,"bodies":[{"marker":name,"bytes":len(body),"sha256":hashlib.sha256(body).hexdigest()}
            for name,body in zip(FUNCTIONS,bodies,strict=True)],"all_bodies_copied_without_edits":True,"original_C_assertions":"release-disabled; scaffold assertions remain active",
        "foreign_effects":True,"actual_namespace_syscalls":0}
    (output/"build.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    assert result.returncode==0,result.stderr.decode("utf-8","replace")
    return so,report
CALLBACK=ctypes.CFUNCTYPE(None,ctypes.c_uint64,ctypes.c_uint64,ctypes.POINTER(ctypes.c_uint64),
    ctypes.c_void_p,ctypes.c_uint64,ctypes.POINTER(ctypes.c_uint64),ctypes.c_void_p,ctypes.c_uint64)
class Reference:
    def __init__(self,library:Path):
        self.lib=ctypes.CDLL(str(library),use_errno=True)
        self.lib.hia_unixopen_reference.argtypes=[ctypes.c_void_p,ctypes.c_size_t,CALLBACK,ctypes.POINTER(ctypes.c_uint64)]
        self.lib.hia_unixopen_reference.restype=ctypes.c_int
        self.lib.hia_unixopen_snapshot.argtypes=[ctypes.POINTER(ctypes.c_uint64)]
        self.lib.hia_unixopen_sizeof_unused.restype=ctypes.c_uint64
        assert self.lib.hia_unixopen_sizeof_unused()==16
    def run(self,wire:bytes,provider):
        events=[];errors=[]
        @CALLBACK
        def callback(op,stage,args,path,count,result,payload,capacity):
            try:
                snapshot=(ctypes.c_uint64*32)();self.lib.hia_unixopen_snapshot(snapshot)
                request={"op":int(op),"stage":int(stage),"args":[int(args[i]) for i in range(6)],
                    "path":ctypes.string_at(path,count) if count else b"","state_before":list(snapshot)}
                reply=provider(request);assert len(reply["values"])==6
                data=reply.get("payload",b"");assert isinstance(data,bytes) and len(data)<=capacity
                values=[reply["errno"],*reply["values"],len(data)]
                for i,value in enumerate(values):result[i]=value
                if data:ctypes.memmove(payload,data,len(data))
                events.append({"request":request,"reply":reply})
            except BaseException as error:
                errors.append(error)
                # A failing test never becomes a successful transcript.
                for i in range(8):result[i]=0
                result[7]=(1<<64)-1
        source=ctypes.create_string_buffer(wire)
        final=(ctypes.c_uint64*32)()
        rc=self.lib.hia_unixopen_reference(source,len(wire),callback,final)
        if errors:raise errors[0]
        return {"rc":int(rc),"state":list(final),"events":events}
