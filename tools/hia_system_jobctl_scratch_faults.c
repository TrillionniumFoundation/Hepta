#define _GNU_SOURCE
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
static int fired, sync_count, write_count;
static int selected(const char *name){const char *v=getenv("SC_FAULT");return !fired&&v&&!strcmp(v,name);}
static int error(void){fired=1;const char *n=getenv("SC_FAULT_ERRNO");errno=n?atoi(n):EIO;return -1;}
static int is_tmp(int fd){char link[64],path[4096];int n=snprintf(link,sizeof link,"/proc/self/fd/%d",fd);(void)n;ssize_t length=readlink(link,path,sizeof(path)-1);if(length<0)return 0;path[length]=0;return strstr(path,"/engine-scratch.tmp-")||strstr(path,"/engine-scratch.retained.tmp-");}
int fsync(int fd){int(*real)(int)=dlsym(RTLD_NEXT,"fsync");char name[32];sync_count++;snprintf(name,sizeof name,"fsync-%d",sync_count);if(selected(name))return error();return real(fd);}
int open64(const char *path,int flags,...){mode_t mode=0;if(flags&O_CREAT){va_list ap;va_start(ap,flags);mode=va_arg(ap,mode_t);va_end(ap);}int(*real)(const char*,int,...)=dlsym(RTLD_NEXT,"open64");
if((strstr(path,"/engine-scratch.tmp-")&&selected("tmp-open"))||(selected("state-open")&&strlen(path)>=6&&!strcmp(path+strlen(path)-6,"/state"))||(selected("root-open")&&!strcmp(path,"/")))return error();return real(path,flags,mode);}
int openat(int dir,const char *path,int flags,...){mode_t mode=0;if(flags&O_CREAT){va_list ap;va_start(ap,flags);mode=va_arg(ap,mode_t);va_end(ap);}int(*real)(int,const char*,int,...)=dlsym(RTLD_NEXT,"openat");if(selected("leaf-open")&&!strcmp(path,"engine-scratch"))return error();return real(dir,path,flags,mode);}
ssize_t write(int fd,const void *bytes,size_t size){ssize_t(*real)(int,const void*,size_t)=dlsym(RTLD_NEXT,"write");if(is_tmp(fd)){char name[32];write_count++;snprintf(name,sizeof name,"write-%d",write_count);if(selected(name)){if(getenv("SC_FAULT_ZERO")){fired=1;return 0;}return error();}}return real(fd,bytes,size);}
int rename(const char *old,const char *new){int(*real)(const char*,const char*)=dlsym(RTLD_NEXT,"rename");if(selected("rename")&&strstr(old,"/engine-scratch.tmp-"))return error();return real(old,new);}
struct dirent64 *readdir64(DIR *dir){struct dirent64*(*real)(DIR*)=dlsym(RTLD_NEXT,"readdir64");if(selected("readdir")){error();return NULL;}return real(dir);}

__attribute__((destructor)) static void report_fault(void){const char *p=getenv("SC_FAULT_LOG");if(!p)return;int fd=syscall(SYS_openat,AT_FDCWD,p,O_WRONLY|O_CREAT|O_TRUNC,0600);if(fd>=0){char c=fired?'1':'0';syscall(SYS_write,fd,&c,1);syscall(SYS_close,fd);}}
