/* Input-only native target for the 36 declared cold-transport controls.
 * This is a test executable, never a product fallback or a transport owner.
 * It records actual kernel identities and emits complete binary bytes.
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int full_write(int fd,const void *data,size_t size) {
    size_t at=0;
    while(at<size) {
        ssize_t n=write(fd,(const unsigned char *)data+at,size-at);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)return -1;
        at+=(size_t)n;
    }
    return 0;
}
static int word(int fd,uint64_t value) { return full_write(fd,&value,8); }
static int save_identity(void) {
    uint64_t values[4]={(uint64_t)getpid(),(uint64_t)getppid(),
        (uint64_t)getpgrp(),(uint64_t)getsid(0)};
    int fd=open("identity.bin",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if(fd<0)return -1;
    int failed=full_write(fd,values,sizeof values);
    if(close(fd)!=0)failed=-1;
    return failed;
}
static _Noreturn void pause_forever(void) { for(;;)pause(); }
static int output_pattern(int fd) {
    static const unsigned char seed[]={
        0,255,128,10,13,0,'H','I','A','O','B','R','0','2',
        'H','I','A','O','B','R','0','3',0,254,1,2,3,127
    };
    unsigned char bytes[4096];
    size_t offset=0;
    while(offset<98347) {
        size_t size=98347-offset;if(size>sizeof bytes)size=sizeof bytes;
        for(size_t i=0;i<size;++i)bytes[i]=seed[(offset+i)%sizeof seed];
        if(full_write(fd,bytes,size))return -1;
        offset+=size;
    }
    return 0;
}
static int descriptor(const char *text) {
    char *end=NULL;errno=0;
    long value=strtol(text,&end,10);
    if(errno||!end||*end||value<3||value>2147483647L)return -1;
    return (int)value;
}
static int extent(const char *path) {
    const char prefix[]="/proc/self/fd/";
    if(strncmp(path,prefix,sizeof prefix-1)!=0)return 76;
    int fd=descriptor(path+sizeof prefix-1);
    struct stat info;
    if(fd<0||fstat(fd,&info)!=0||info.st_size<0)return 77;
    int seals=fcntl(fd,F_GET_SEALS);
    if(seals<0)return 78;
    if(word(1,(uint64_t)fd)||word(1,(uint64_t)info.st_size)
       ||word(1,(uint64_t)seals))return 79;
    unsigned char buffer[32768];off_t at=0;
    while(at<info.st_size) {
        ssize_t n=pread(fd,buffer,sizeof buffer,at);
        if(n<0&&errno==EINTR)continue;
        if(n<=0||full_write(1,buffer,(size_t)n))return 80;
        at+=n;
    }
    return 0;
}
int main(int argc,char **argv,char **environment) {
    if(save_identity()!=0)return 71;
    const char *mode=argc>2&&strcmp(argv[1],"--ct36")==0?argv[2]:"argv";
    if(strcmp(mode,"env")==0) {
        for(char **p=environment;*p;++p)
            if(full_write(1,*p,strlen(*p)+1))return 72;
        return 0;
    }
    if(strcmp(mode,"argv")==0) {
        if(word(1,(uint64_t)argc))return 72;
        for(int i=0;i<argc;++i)
            if(word(1,strlen(argv[i]))||full_write(1,argv[i],strlen(argv[i])))return 72;
        return 0;
    }
    if(strcmp(mode,"echo")==0||strcmp(mode,"both")==0||strcmp(mode,"eof")==0) {
        unsigned char buffer[8192];uint64_t total=0;
        for(;;) {
            ssize_t n=read(0,buffer,sizeof buffer);
            if(n<0&&errno==EINTR)continue;
            if(n<0)return 73;
            if(!n)break;
            total+=(uint64_t)n;
            if(strcmp(mode,"eof")!=0&&full_write(1,buffer,(size_t)n))return 74;
            if(strcmp(mode,"both")==0&&full_write(2,buffer,(size_t)n))return 75;
        }
        if(strcmp(mode,"eof")==0)return word(1,total)?74:0;
        return 0;
    }
    if(strcmp(mode,"stdout")==0)return output_pattern(1)?74:0;
    if(strcmp(mode,"stderr")==0)return output_pattern(2)?75:0;
    if(strcmp(mode,"early-close")==0) {
        if(close(0)!=0)return 76;
        const unsigned char out[]={'e','a','r','l','y',0,255};
        const unsigned char err[]={'c','l','o','s','e','d',0,128};
        return full_write(1,out,sizeof out)||full_write(2,err,sizeof err)?77:0;
    }
    if(strcmp(mode,"nonzero")==0) {
        const unsigned char out[]={'n','o','n','z','e','r','o',0,255};
        if(full_write(1,out,sizeof out)||full_write(2,out,sizeof out))return 77;
        return 37;
    }
    if(strcmp(mode,"sigill")==0) {
        const unsigned char out[]={'b','e','f','o','r','e','-','s','i','g','i','l','l',0};
        if(full_write(1,out,sizeof out))return 77;
        if(raise(SIGILL)!=0)return 78;
        return 79;
    }
    if(strcmp(mode,"partial")==0) {
        const unsigned char out[]={'p','a','r','t','i','a','l',0,255,'H','I','A','O','B','R','0','2'};
        const unsigned char err[]={'e','r','r',0,128,254};
        if(full_write(1,out,sizeof out)||full_write(2,err,sizeof err))return 77;
        pause_forever();
    }
    if(strcmp(mode,"pause")==0)pause_forever();
    if(strcmp(mode,"wait-close")==0) {
        if(close(0)!=0||close(1)!=0||close(2)!=0)return 77;
        pause_forever();
    }
    if(strcmp(mode,"borrowed")==0) {
        if(argc<4||argc>5)return 64;
        const unsigned char content[]={'b','o','r','r','o','w','e','d',0,255,128};
        for(int i=3;i<argc;++i) {
            int fd=descriptor(argv[i]);struct stat info;
            if(fd<0||fstat(fd,&info)!=0)return 81;
            if(pwrite(fd,content,sizeof content,0)!=(ssize_t)sizeof content)return 82;
            if(word(1,(uint64_t)fd)||word(1,(uint64_t)info.st_dev)
               ||word(1,(uint64_t)info.st_ino)||word(1,(uint64_t)info.st_size))return 83;
        }
        return 0;
    }
    if(strcmp(mode,"identity")==0) {
        uint64_t values[4]={(uint64_t)getpid(),(uint64_t)getppid(),
            (uint64_t)getpgrp(),(uint64_t)getsid(0)};
        return full_write(1,values,sizeof values)?77:0;
    }
    if(strcmp(mode,"extent")==0)return extent(argv[0]);
    return 64;
}
