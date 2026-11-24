#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <stdint.h>
#include <errno.h>
#include <sys/stat.h>

extern char **environ;
static unsigned long number(const char *key){const char *s=getenv(key);return s?strtoul(s,0,10):0;}
static int enabled(const char *key){return number(key)!=0;}
static void all(int fd,const void *data,size_t size){const unsigned char *p=data;while(size){ssize_t n=write(fd,p,size);if(n<0&&errno==EINTR)continue;if(n<=0)_exit(91);p+=n;size-=(size_t)n;}}
static void delay(unsigned long ms){while(ms){unsigned long n=ms>100?100:ms;usleep((useconds_t)(n*1000));ms-=n;}}
static void save(const char *path,const char *data){int fd=open(path,O_WRONLY|O_CREAT|O_TRUNC,0600);if(fd<0)_exit(92);all(fd,data,strlen(data));close(fd);}
int main(int argc,char **argv){
 const char *binding=getenv("HEPTA_RUNTIME_ENGINE_SCRATCH");
 if(binding&&enabled("QA_CLAIM")){
  int fd=open("/state/engine-scratch/claim.json",O_WRONLY|O_CREAT|O_EXCL,0600);if(fd<0)return 93;
  char id[64];int n=snprintf(id,sizeof id,",\"worker_pid\":%ld,\"engine\":\"jadx\"}\n",(long)getpid());
  const char *prefix="{\"schema\":\"hepta.rea.engine-scratch-claim.v1\",\"owner\":";
  all(fd,prefix,strlen(prefix));all(fd,binding,strlen(binding));all(fd,id,(size_t)n);close(fd);
  mkdir("/state/engine-scratch/nested",0700);save("/state/engine-scratch/nested/content","scratch bytes\n");
 }
 if(enabled("QA_ENV"))for(char **e=environ;*e;e++){all(1,*e,strlen(*e));all(1,"\0",1);}
 if(enabled("QA_ARGV"))for(int i=0;i<argc;i++){all(1,argv[i],strlen(argv[i]));all(1,"\0",1);}
 if(enabled("QA_STDIN")){unsigned char b[8192];ssize_t n;while((n=read(0,b,sizeof b))>0)all(1,b,(size_t)n);}
 unsigned long out=number("QA_OUT"),err=number("QA_ERR");unsigned char stdout_data[8192],stderr_data[8192];memset(stdout_data,'o',sizeof stdout_data);memset(stderr_data,'e',sizeof stderr_data);
 while(out||err){size_t n=out>sizeof stdout_data?sizeof stdout_data:out;if(n)all(1,stdout_data,n);out-=n;n=err>sizeof stderr_data?sizeof stderr_data:err;if(n)all(2,stderr_data,n);err-=n;}
 if(enabled("QA_DESCENDANT")){
  pid_t child=fork();if(child<0)return 94;
  if(child==0){if(enabled("QA_DESC_STDERR_CLOSE"))close(2);delay(number("QA_DESC_MS")?number("QA_DESC_MS"):1000);_exit(0);}
 }
 char pid[64];snprintf(pid,sizeof pid,"%ld\n",(long)getpid());save("/state/ready",pid);
 delay(number("QA_SLEEP_MS"));
 if(number("QA_SIGNAL"))raise((int)number("QA_SIGNAL"));
 return (int)number("QA_EXIT");
}
