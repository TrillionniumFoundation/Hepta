/* Fixed raw-word SysV calls, sealed image identity, and retained observations. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <link.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define INPUTS 64
#define SAMPLES 21
#define WARMUPS 3
#define ITERATIONS UINT64_C(1048576)
#define CHECKSUM_SEED UINT64_C(0x0123456789abcdef)
typedef uint64_t (*raw_word_fn)(uint64_t, uint64_t);
static volatile uint64_t observed;

/* SHA-256 binds the bytes copied into the sealed image before dlopen. */
static uint32_t rotate(uint32_t a, unsigned n) { return (a >> n) | (a << (32 - n)); }
static const uint32_t constants[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
static void compress(uint32_t h[8], const unsigned char block[64]) {
    uint32_t w[64];
    for (unsigned i = 0; i < 16; ++i)
        w[i] = ((uint32_t)block[4*i] << 24) | ((uint32_t)block[4*i+1] << 16) |
               ((uint32_t)block[4*i+2] << 8) | block[4*i+3];
    for (unsigned i = 16; i < 64; ++i) {
        uint32_t x = w[i-15], y = w[i-2];
        w[i] = w[i-16] + (rotate(x,7) ^ rotate(x,18) ^ (x>>3)) + w[i-7] +
               (rotate(y,17) ^ rotate(y,19) ^ (y>>10));
    }
    uint32_t a=h[0],b=h[1],c=h[2],d=h[3],e=h[4],f=h[5],g=h[6],q=h[7];
    for (unsigned i = 0; i < 64; ++i) {
        uint32_t t1=q+(rotate(e,6)^rotate(e,11)^rotate(e,25))+((e&f)^((~e)&g))+constants[i]+w[i];
        uint32_t t2=(rotate(a,2)^rotate(a,13)^rotate(a,22))+((a&b)^(a&c)^(b&c));
        q=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=q;
}
static void digest(const unsigned char *bytes, size_t n, char hex[65]) {
    uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    size_t offset=0;
    for (; n-offset >= 64; offset+=64) compress(h,bytes+offset);
    unsigned char final[128]={0};
    size_t tail=n-offset, padded=tail<56?64:128;
    memcpy(final,bytes+offset,tail);final[tail]=0x80;
    uint64_t bits=(uint64_t)n*8;
    for (unsigned i=0;i<8;++i) final[padded-1-i]=(unsigned char)(bits>>(8*i));
    compress(h,final);if(padded==128)compress(h,final+64);
    for(unsigned i=0;i<8;++i) snprintf(hex+8*i,9,"%08" PRIx32,h[i]);
}
static void fail(const char *what) { fprintf(stderr,"%s\n",what);exit(1); }
static uint64_t word(const unsigned char *p) {
    uint64_t v=0;for(unsigned i=0;i<8;++i)v|=(uint64_t)p[i]<<(8*i);return v;
}
static unsigned char *read_file(const char *path,size_t cap,size_t *size) {
    int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
    struct stat before,after;
    if(fd<0||fstat(fd,&before)||!S_ISREG(before.st_mode)||before.st_size<0||
       (uint64_t)before.st_size>cap)fail("file admission failed");
    *size=(size_t)before.st_size;
    unsigned char *data=malloc(*size+1);if(!data)fail("allocation failed");
    size_t n=0;
    while(n<*size){ssize_t got=read(fd,data+n,*size-n);if(got<0&&errno==EINTR)continue;
        if(got<=0)fail("short file read");
        n+=(size_t)got;}
    unsigned char extra;ssize_t end;
    do{end=read(fd,&extra,1);}while(end<0&&errno==EINTR);
    if(end!=0||fstat(fd,&after)||before.st_dev!=after.st_dev||before.st_ino!=after.st_ino||
       before.st_size!=after.st_size||before.st_mtim.tv_sec!=after.st_mtim.tv_sec||
       before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec||before.st_ctim.tv_sec!=after.st_ctim.tv_sec||
       before.st_ctim.tv_nsec!=after.st_ctim.tv_nsec)fail("file changed while reading");
    if(close(fd))fail("file close failed");
    return data;
}
static uint64_t now(void) {
    struct timespec value;if(clock_gettime(CLOCK_MONOTONIC_RAW,&value))fail("clock failed");
    return (uint64_t)value.tv_sec*UINT64_C(1000000000)+(uint64_t)value.tv_nsec;
}
static uint64_t number(const char *s) {
    if(!s[0])fail("missing integer");
    for(const char *p=s;*p;++p)if(*p<'0'||*p>'9')fail("invalid integer");
    errno=0;char *end;unsigned long long n=strtoull(s,&end,10);
    if(errno||*end)fail("integer overflow");
    return (uint64_t)n;
}
static void check_inputs(raw_word_fn fn,const uint64_t inputs[INPUTS][3],int emit) {
    for(unsigned i=0;i<INPUTS;++i){uint64_t actual=fn(inputs[i][0],inputs[i][1]);
        if(actual!=inputs[i][2])fail("valid input returned wrong word");
        if(emit)printf("{\"kind\":\"input\",\"index\":%u,\"a\":%" PRIu64
                       ",\"b\":%" PRIu64 ",\"result\":%" PRIu64 "}\n",
                       i,inputs[i][0],inputs[i][1],actual);}
}
int main(int argc,char **argv) {
    if(argc!=7&&argc!=9)fail("usage: driver functional|measure library symbol sha256 inputs traps [iterations batches]");
    int measuring=!strcmp(argv[1],"measure");
    if((!measuring&&strcmp(argv[1],"functional"))||(measuring?argc!=9:argc!=7))fail("invalid mode");
    if(measuring&&(number(argv[7])!=ITERATIONS||number(argv[8])!=SAMPLES))fail("fixed protocol dimensions required");
    for(const char *p=argv[3];*p;++p)if(!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||
        (*p>='0'&&*p<='9')||*p=='_'))fail("invalid symbol");
    if(!argv[3][0]||strlen(argv[4])!=64)fail("invalid image binding");
    char self[65];digest((const unsigned char*)"",0,self);
    if(strcmp(self,"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"))fail("SHA256 empty self check");
    digest((const unsigned char*)"abc",3,self);
    if(strcmp(self,"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"))fail("SHA256 abc self check");
    size_t size,input_size,trap_size;
    unsigned char *bytes=read_file(argv[2],64u*1024u*1024u,&size);
    unsigned char *input_bytes=read_file(argv[5],INPUTS*24u,&input_size);
    unsigned char *trap_bytes=read_file(argv[6],16u*16u,&trap_size);
    if(input_size!=INPUTS*24u||trap_size%16)fail("invalid input matrix dimensions");
    char image_hash[65],input_hash[65],trap_hash[65];
    digest(bytes,size,image_hash);digest(input_bytes,input_size,input_hash);digest(trap_bytes,trap_size,trap_hash);
    if(strcmp(image_hash,argv[4]))fail("image SHA256 differs before load");
    int fd=memfd_create("hia-signed-benchmark",MFD_CLOEXEC|MFD_ALLOW_SEALING);
    if(fd<0)fail("sealed image unavailable");
    size_t done=0;
    while(done<size){ssize_t put=write(fd,bytes+done,size-done);if(put<0&&errno==EINTR)continue;
        if(put<=0)fail("sealed image copy failed");
        done+=(size_t)put;}
    int seals=F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL;
    if(fcntl(fd,F_ADD_SEALS,seals)||fcntl(fd,F_GET_SEALS)!=seals)fail("image seals failed");
    free(bytes);
    char path[80];snprintf(path,sizeof(path),"/proc/self/fd/%d",fd);
    void *library=dlopen(path,RTLD_NOW|RTLD_LOCAL);
    if(!library){fprintf(stderr,"%s\n",dlerror());fail("sealed image load failed");}
    void *address=dlsym(library,argv[3]);if(!address)fail("entry symbol absent");
    raw_word_fn fn;
    _Static_assert(sizeof(fn)==sizeof(address),"Linux x86-64 function pointer representation required");
    memcpy(&fn,&address,sizeof(fn));
    struct link_map *expected_map=NULL;void *actual_map=NULL;Dl_info info;
    if(dlinfo(library,RTLD_DI_LINKMAP,&expected_map)||!expected_map||
       !dladdr1(address,&info,&actual_map,RTLD_DL_LINKMAP)||!info.dli_fbase||
       actual_map!=(void*)expected_map)fail("entry does not belong to sealed image");
    cpu_set_t affinity;CPU_ZERO(&affinity);
    if(sched_getaffinity(0,sizeof(affinity),&affinity))fail("CPU affinity unavailable");
    printf("{\"kind\":\"binding\",\"artifact_sha256\":\"%s\",\"artifact_bytes\":%zu,"
           "\"input_sha256\":\"%s\",\"trap_sha256\":\"%s\",\"symbol\":\"%s\","
           "\"sealed\":true,\"entry_owner\":\"sealed_image\",\"image_base\":%" PRIuPTR
           ",\"symbol_address\":%" PRIuPTR ",\"symbol_offset\":%" PRIuPTR ",\"cpu\":%d,\"affinity_count\":%d}\n",
           image_hash,size,input_hash,trap_hash,argv[3],(uintptr_t)info.dli_fbase,(uintptr_t)address,
           (uintptr_t)address-(uintptr_t)info.dli_fbase,
           sched_getcpu(),CPU_COUNT(&affinity));
    uint64_t inputs[INPUTS][3];
    for(unsigned i=0;i<INPUTS;++i)for(unsigned j=0;j<3;++j)inputs[i][j]=word(input_bytes+24*i+8*j);
    free(input_bytes);
    check_inputs(fn,inputs,!measuring);
    if(!measuring){
        for(size_t i=0;i<trap_size/16;++i){
            uint64_t a=word(trap_bytes+16*i),b=word(trap_bytes+16*i+8);
            fflush(stdout);pid_t pid=fork();if(pid<0)fail("trap fork failed");
            if(pid==0){struct rlimit limit={0,0};if(setrlimit(RLIMIT_CORE,&limit))_exit(119);
                signal(SIGABRT,SIG_DFL);alarm(2);observed=fn(a,b);_exit(120);}
            int status;pid_t waited;
            do{waited=waitpid(pid,&status,0);}while(waited<0&&errno==EINTR);
            if(waited!=pid||!WIFSIGNALED(status)||WTERMSIG(status)!=SIGABRT)fail("invalid input did not abort");
            printf("{\"kind\":\"trap\",\"index\":%zu,\"a\":%" PRIu64
                   ",\"b\":%" PRIu64 ",\"signal\":%d}\n",i,a,b,WTERMSIG(status));
        }
        printf("{\"kind\":\"functional\",\"inputs\":%d,\"traps\":%zu}\n",INPUTS,trap_size/16);
    }else{
        uint64_t sum=0;for(unsigned i=0;i<INPUTS;++i)sum+=inputs[i][2];
        uint64_t expected=CHECKSUM_SEED+sum*(ITERATIONS/INPUTS);
        for(int batch=-WARMUPS;batch<SAMPLES;++batch){
            check_inputs(fn,inputs,0);
            uint64_t value=CHECKSUM_SEED;int cpu_before=sched_getcpu();uint64_t start=now();
            for(uint64_t i=0;i<ITERATIONS;++i){unsigned index=(unsigned)(i&(INPUTS-1));
                value+=fn(inputs[index][0],inputs[index][1]);}
            uint64_t elapsed=now()-start;int cpu_after=sched_getcpu();observed=value;
            if(value!=expected||!elapsed)fail("timed checksum or clock mismatch");
            printf("{\"kind\":\"sample\",\"batch\":%d,\"warmup\":%s,\"elapsed_ns\":%" PRIu64
                   ",\"calls\":%" PRIu64 ",\"checksum\":%" PRIu64 ",\"cpu_before\":%d,\"cpu_after\":%d}\n",
                   batch,batch<0?"true":"false",elapsed,ITERATIONS,value,cpu_before,cpu_after);
            fflush(stdout);
        }
    }
    free(trap_bytes);if(dlclose(library)||close(fd))fail("loaded image cleanup failed");return 0;
}
