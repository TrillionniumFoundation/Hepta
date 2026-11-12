/* Development-only fixed physical-after backend image runner.
 * New source only: no C compilation or target execution is claimed.
 * No Graph/Code/ELF/path-name/hash interpretation. All policies are HIA.
 * Small-case full-CAS harness remains the independent per-entry evidence gate.
 * This runner saves all actual image/input bytes, native header returns,
 * complete controller commands/ACKs, and every final slot byte.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef uint64_t U;
typedef U (*Entry)(void *, U, void *, U, void *, U);
typedef struct { unsigned char *map,*data; U total,middle,size; int live,ro; } Buffer;
typedef struct { unsigned char *map; U size; Entry entry; } Image;
static Buffer slots[64], reply;
static Image images[24];
static int owned_file=-1;
static U raw_syscalls=0,driver=20;
static int tracefd=-1,finalfd=-1;
static U entered=0,commands=0,stage=0,active_role=0;
static const unsigned char guard[16]={160,161,162,163,164,165,166,167,168,169,170,171,172,173,174,175};

static void fatal(U code) {
 U error[8]={0x3152454d45414948ULL,1,code,stage,active_role,entered,commands,(U)errno};
 const unsigned char *p=(const unsigned char *)error; size_t n=sizeof(error);
 while(n){ssize_t r=write(2,p,n);if(r<0&&errno==EINTR)continue;if(r<=0)break;p+=r;n-=(size_t)r;}
 if(owned_file>=0){int doomed=owned_file;owned_file=-1;(void)close(doomed);}
 _exit(126);
}
static void require(int yes,U code){if(!yes)fatal(code);}
static void allwrite(int fd,const void *data,U count){
 const unsigned char *p=data;
 while(count){size_t n=count>(U)SSIZE_MAX?(size_t)SSIZE_MAX:(size_t)count;ssize_t got=write(fd,p,n);
  if(got<0&&errno==EINTR)continue;require(got>0,1);p+=got;count-=(U)got;}
}
static void allread(int fd,void *data,U count){
 unsigned char *p=data;
 while(count){size_t n=count>(U)SSIZE_MAX?(size_t)SSIZE_MAX:(size_t)count;ssize_t got=read(fd,p,n);
  if(got<0&&errno==EINTR)continue;require(got>0,2);p+=got;count-=(U)got;}
}
static void record(U kind,const void *raw,U bytes){
 U h[2]={kind,bytes};allwrite(tracefd,h,16);allwrite(tracefd,raw,bytes);
}
static void protect(Buffer *b,int ro){
 require(b->live&&(ro==0||ro==1),3);
 require(mprotect(b->map+4096,(size_t)b->middle,ro?PROT_READ:(PROT_READ|PROT_WRITE))==0,4);
 b->ro=ro;
}
static void check(Buffer *b){
 require(b->live,5);
 require(memcmp(b->data-16,guard,16)==0&&memcmp(b->data+b->size,guard,16)==0,6);
}
static Buffer allocate(U size){
 require(size<=UINT64_MAX-8192-32-4095,7);
 U middle=(size+32+4095)&~4095ULL,total=middle+8192;
 unsigned char *p=mmap(0,(size_t)total,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 require(p!=MAP_FAILED,8);
 require(mprotect(p+4096,(size_t)middle,PROT_READ|PROT_WRITE)==0,9);
 Buffer b={p,p+4112,total,middle,size,1,0};
 memcpy(b.data-16,guard,16);memcpy(b.data+size,guard,16);return b;
}
static void closebuffer(Buffer *b){
 if(!b->live)return;check(b);
 unsigned char *p=b->map;U n=b->total;
 memset(b,0,sizeof(*b));require(munmap(p,(size_t)n)==0,10);
}
static Buffer *slot(U n){require(n<64&&slots[n].live,11);return &slots[n];}
static unsigned char *span(U id,U at,U n){
 Buffer *b=slot(id);require(at<=b->size&&n<=b->size-at,12);check(b);return b->data+at;
}
static U file_size(int fd){
 struct stat st;require(fstat(fd,&st)==0&&S_ISREG(st.st_mode)&&st.st_size>=0,13);return (U)st.st_size;
}
static Buffer input_file(const char *path){
 int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);require(fd>=0,14);
 U n=file_size(fd);Buffer b=allocate(n);allread(fd,b.data,n);
 unsigned char extra;ssize_t got;
 do{got=read(fd,&extra,1);}while(got<0&&errno==EINTR);
 require(got==0&&file_size(fd)==n,15);require(close(fd)==0,16);protect(&b,1);return b;
}
static void load_image(U role,const char *path){
 int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);require(fd>=0,17);
 U n=file_size(fd);require(n>0&&n<=(1ULL<<20),18);
 unsigned char *p=mmap(0,(size_t)n,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 require(p!=MAP_FAILED,19);allread(fd,p,n);
 unsigned char extra;ssize_t got;do{got=read(fd,&extra,1);}while(got<0&&errno==EINTR);
 require(got==0&&file_size(fd)==n,20);require(close(fd)==0,21);
 U head[4]={1,16+n,role,n};allwrite(tracefd,head,32);allwrite(tracefd,p,n);
 require(mprotect(p,(size_t)n,PROT_READ|PROT_EXEC)==0,22);
 images[role]=(Image){p,n,(Entry)(void *)p};
}
static U call_image(U role,Buffer *a,U at,U n,Buffer *b,U bn,Buffer *w,U wn,U firstid,U secondid,U workid){
 require(role>=1&&role<=23&&images[role].entry,23);
 require(a->live&&b->live&&w->live&&a!=b&&a!=w&&b!=w,24);
 require(at<=a->size&&n<=a->size-at&&bn<=b->size&&wn<=w->size,25);
 require(a->ro&& !w->ro,26);
 if(role!=7&&role!=11&&role!=16&&role!=19&&role!=20&&role!=22&&role!=23)require(b->ro,27);else require(!b->ro,28);
 check(a);check(b);check(w);
 U serial=++entered;active_role=role;
 U before[16]={serial,role,firstid,at,n,secondid,bn,workid,wn,(U)a->ro,(U)b->ro,(U)w->ro,0,0,0,0};
 record(3,before,sizeof(before));
 U returned=images[role].entry(a->data+at,n,b->data,bn,w->data,wn);
 check(a);check(b);check(w);
 Buffer *event=(role==11||role==16||role==20||role==22||role==23)?b:w;U extent=(role==11||role==16||role==20||role==22||role==23)?bn:wn;
 U observed=extent<128?extent:128;
 U after[6]={4,32+observed,serial,role,returned,observed};
 allwrite(tracefd,after,sizeof(after));allwrite(tracefd,event->data,observed);
 active_role=0;return returned;
}
static int zeros(const U *p,U first){for(U i=first;i<12;i++)if(p[i])return 0;return 1;}
static void save_final(U returned,const U *event){
 U count=0;for(U i=0;i<64;i++)if(slots[i].live)count++;
 U h[8]={0x3153584d45414948ULL,1,entered,commands,returned,count,128,0};
 allwrite(finalfd,h,sizeof(h));allwrite(finalfd,event,128);
 for(U i=0;i<64;i++)if(slots[i].live){
  Buffer *b=&slots[i];check(b);U row[8]={i,b->size,(U)b->ro,1,0,0,0,0};
  allwrite(finalfd,row,sizeof(row));allwrite(finalfd,b->data,b->size);
 }
 require(fsync(finalfd)==0&&fsync(tracefd)==0,29);
}
int main(int argc,char **argv){
 require(argc==28,30);
 require(sizeof(void *)==8&&sizeof(U)==8&&sizeof(struct stat)==144,31);
 U test=1;require(*(unsigned char *)&test==1&&sysconf(_SC_PAGESIZE)==4096,32);
 char *parent_end=0;errno=0;unsigned long expected_parent=strtoul(argv[27],&parent_end,10);
 require(errno==0&&parent_end!=argv[27]&&*parent_end==0&&expected_parent>1&&expected_parent<=INT_MAX,33);
 pid_t parent=(pid_t)expected_parent;require(getppid()==parent,33);
 require(prctl(PR_SET_PDEATHSIG,SIGKILL,0,0,0)==0&&getppid()==parent,34);
 struct rlimit cpu={90,90},address={1ULL<<30,1ULL<<30},core={0,0};
 require(setrlimit(RLIMIT_CPU,&cpu)==0&&setrlimit(RLIMIT_AS,&address)==0&&setrlimit(RLIMIT_CORE,&core)==0,35);
 alarm(180);
 tracefd=open(argv[2],O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);require(tracefd>=0,36);
 finalfd=open(argv[3],O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);require(finalfd>=0,37);
 require(getrlimit(RLIMIT_CPU,&cpu)==0&&getrlimit(RLIMIT_AS,&address)==0&&getrlimit(RLIMIT_CORE,&core)==0,38);
 U limits[8]={cpu.rlim_cur,cpu.rlim_max,address.rlim_cur,address.rlim_max,core.rlim_cur,core.rlim_max,180,4096};
 record(8,limits,sizeof(limits));
 for(U i=1;i<=23;i++)load_image(i,argv[3+i]);
 slots[0]=allocate(0);protect(&slots[0],1);
 slots[1]=input_file(argv[1]);record(2,slots[1].data,slots[1].size);
 slots[2]=allocate(1<<20);slots[3]=allocate(128);
 U lease=0,sequence=0,event[16],returned=0;Buffer *first=&slots[1];
 for(;;){
  stage=1;
  require(driver==20||driver==23,56);
  returned=call_image(driver,first,0,first->size,&slots[3],128,&slots[2],1<<20,first==&reply?64:1,3,2);
  if(first==&reply)closebuffer(&reply);
  memcpy(event,slots[3].data,sizeof(event));
  if(returned==0xfffffffdULL){record(7,event,128);save_final(returned,event);break;}
  require(returned==128&&event[0]==0x3130454443414948ULL&&event[2]!=0,39);
  U op=event[1],*a=event+4;
  if(!lease)lease=event[2];require(event[2]==lease,40);
  if(op==7){
   require(driver==20&&owned_file<0&&event[3]==sequence&&slot(a[2])->ro,41);span(a[2],a[3],a[4]);
   record(7,event,128);save_final(returned,event);break;
  }
  require(sequence!=UINT64_MAX&&event[3]==sequence+1,42);sequence=event[3];
  record(5,event,128);U answer=0,observed=0;unsigned char bytes[256];
  stage=op;
  if(op==1){
   U role=a[0],src=a[1],at=a[2],n=a[3],second=a[4],bn=a[5],work=a[6],wn=a[7];
   require(((driver==20&&role>=1&&role<=21&&role!=20)||(driver==23&&(role==19||role==22)))&&src!=second&&src!=work&&second!=work&&work>=4&&a[10]<=256&&a[11]==0,43);
   Buffer *f=slot(src),*b=slot(second),*w=slot(work);
   span(src,at,n);span(second,0,bn);span(work,0,wn);span(a[8],a[9],a[10]);require(!w->ro,44);
   int prior=f->ro,prior_second=b->ro;
   int two_read=role!=7&&role!=11&&role!=16&&role!=19&&role!=22;
   if(!two_read)require(second>=4&&!prior_second,45);
   protect(f,1);if(two_read)protect(b,1);
   answer=call_image(role,f,at,n,b,bn,w,wn,src,second,work);
   protect(f,prior);if(two_read)protect(b,prior_second);
   observed=a[10];memcpy(bytes,span(a[8],a[9],observed),(size_t)observed);
  }else if(op==2){
   U target=a[0],size=a[1];require(target>=3&&target<64&&size>0&&zeros(a,2),46);
   Buffer old=slots[target];require(!old.live||size>old.size,47);
   Buffer next=allocate(size);
   if(old.live){check(&old);memcpy(next.data,old.data,(size_t)old.size);}
   slots[target]=next;closebuffer(&old);
  }else if(op==3){
   require(a[0]>=4&&zeros(a,3)&&!slot(a[0])->ro,48);
   memset(span(a[0],a[1],a[2]),0,(size_t)a[2]);check(slot(a[0]));
  }else if(op==4){
   require(a[2]>=4&&a[0]!=a[2]&&zeros(a,5)&&!slot(a[2])->ro,49);
   unsigned char *s=span(a[0],a[1],a[4]),*d=span(a[2],a[3],a[4]);
   memcpy(d,s,(size_t)a[4]);check(slot(a[2]));
  }else if(op==5){
   require(a[0]>=4&&zeros(a,1),50);Buffer *b=slot(a[0]);closebuffer(b);
  }else if(op==6){
   require(a[0]>=4&&a[1]<=1&&zeros(a,2),51);protect(slot(a[0]),(int)a[1]);
  }else if(op==8){
   require(zeros(a,1)&&owned_file<0&&((driver==20&&a[0]==23)||(driver==23&&a[0]==20)),57);
   driver=a[0];
  }else if(op==14){
   require(a[2]<=256&&zeros(a,3),52);observed=a[2];memcpy(bytes,span(a[0],a[1],observed),(size_t)observed);
  }else if(op==19){
   require(driver==23,58);
   U primitive=a[0],result=0,prior=(U)(int64_t)owned_file;
   int saved_errno=0;const unsigned char *syscall_payload=0;U syscall_payload_n=0;
   if(primitive==1){
    require(owned_file<0&&a[3]>0&&a[4]==O_CLOEXEC&&zeros(a,5),60);
    Buffer *p=slot(a[1]);require(p->ro,61);
    unsigned char *name=span(a[1],a[2],a[3]);require(name[a[3]-1]==0&&memchr(name,0,(size_t)a[3]-1)==0,62);
    syscall_payload=name;syscall_payload_n=a[3];
    int fd=openat(AT_FDCWD,(const char *)name,(int)a[4]);saved_errno=fd<0?errno:0;
    result=(U)(int64_t)fd;
    if(fd>=0){owned_file=fd;answer=1;}else answer=0-(U)saved_errno;
   }else if(primitive==2){
    require(owned_file>=0&&a[1]==1&&a[2]>=4&&a[4]<=(U)SSIZE_MAX&&zeros(a,5),63);
    Buffer *b=slot(a[2]);require(!b->ro,64);unsigned char *target=span(a[2],a[3],a[4]);
    ssize_t got=read(owned_file,target,(size_t)a[4]);saved_errno=got<0?errno:0;
    result=(U)(int64_t)got;answer=got<0?0-(U)saved_errno:(U)got;check(b);
    if(got>=0){syscall_payload=target;syscall_payload_n=(U)got;}
   }else if(primitive==3){
    require(owned_file>=0&&a[1]==1&&zeros(a,2),65);
    int fd=owned_file;owned_file=-1;
    int code=close(fd);saved_errno=code<0?errno:0;result=(U)(int64_t)code;
    answer=code<0?0-(U)saved_errno:(U)code;
   }else if(primitive==4){
    require(owned_file>=0&&a[1]==1&&a[2]>=4&&a[4]==144&&zeros(a,5),66);
    Buffer *b=slot(a[2]);require(!b->ro,67);unsigned char *target=span(a[2],a[3],144);
    memset(target,0,144);
    int code=fstat(owned_file,(struct stat *)(void *)target);saved_errno=code<0?errno:0;
    result=(U)(int64_t)code;answer=code<0?0-(U)saved_errno:(U)code;check(b);
    observed=144;memcpy(bytes,target,144);syscall_payload=target;syscall_payload_n=144;
   }else fatal(68);
   raw_syscalls++;U raw[8]={raw_syscalls,sequence,primitive,prior,result,(U)saved_errno,answer,(U)(int64_t)owned_file};
   record(9,raw,sizeof(raw));record(11,syscall_payload,syscall_payload_n);
  }else fatal(53);
  commands++;
  reply=allocate(64+observed);
  U ack[8]={0x3130414443414948ULL,lease,sequence,op,0,answer,observed,0};
  memcpy(reply.data,ack,64);memcpy(reply.data+64,bytes,(size_t)observed);protect(&reply,1);
  record(6,reply.data,reply.size);first=&reply;
 }
 if(owned_file>=0){int fd=owned_file;owned_file=-1;int code=close(fd);U raw[4]={1,(U)(int64_t)fd,(U)(int64_t)code,code<0?(U)errno:0};record(10,raw,sizeof(raw));}
 for(U i=0;i<64;i++)closebuffer(&slots[i]);closebuffer(&reply);
 for(U i=1;i<=23;i++){void *p=images[i].map;U n=images[i].size;images[i].map=0;require(munmap(p,(size_t)n)==0,54);}
 int tf=tracefd,ff=finalfd;tracefd=finalfd=-1;require(close(tf)==0&&close(ff)==0,55);
 alarm(0);return returned==0xfffffffdULL?2:0;
}
