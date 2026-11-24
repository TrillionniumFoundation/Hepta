#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <stdint.h>
#include <errno.h>

static unsigned long number(const char *key){const char *s=getenv(key);return s?strtoul(s,0,10):0;}
static const char *setting(const char *key,const char *def){const char *s=getenv(key);return s?s:def;}
static void all(int fd,const void *data,size_t size){const unsigned char *p=data;while(size){ssize_t n=write(fd,p,size);if(n<0&&errno==EINTR)continue;if(n<=0)_exit(91);p+=n;size-=(size_t)n;}}
static void counter(const char *name){int fd=open(name,O_WRONLY|O_CREAT|O_APPEND,0600);if(fd<0)_exit(92);all(fd,"1",1);close(fd);}
int main(int argc,char **argv){
 if(argc<2)return 90;
 const char *base=strrchr(argv[0],'/');base=base?base+1:argv[0];
 if(!strcmp(base,"systemd-run")){
  counter("/var/lib/qa-probes/launch-count");
  int fd=open("/var/lib/qa-probes/launch-argv",O_WRONLY|O_CREAT|O_TRUNC,0600);if(fd<0)return 92;
  for(int i=0;i<argc;i++){all(fd,argv[i],strlen(argv[i])+1);}
  close(fd);
  const char *mode=setting("HIA_START_RUN_MODE","normal");
  if(!strcmp(mode,"stdin")){unsigned char b[8192];ssize_t n;while((n=read(0,b,sizeof b))>0)all(1,b,(size_t)n);}
  unsigned long out=number("HIA_START_OUT"),err=number("HIA_START_ERR");unsigned char data[65536];memset(data,'q',sizeof data);
  while(out||err){size_t n=out>sizeof data?sizeof data:out;all(1,data,n);out-=n;n=err>sizeof data?sizeof data:err;all(2,data,n);err-=n;}
  if(!strcmp(mode,"stderr-invalid")){const unsigned char b[]={0xff,0xe1,0x80,'\r','\n','x',0};all(2,b,sizeof b);}
  unsigned long delay=number("HIA_START_DELAY_MS");while(delay){unsigned long ms=delay>100?100:delay;usleep((useconds_t)(ms*1000));delay-=ms;}
  int sig=(int)number("HIA_START_CHILD_SIGNAL");if(sig)raise(sig);
  return (int)number("HIA_START_RUN_RC");
 }
 if(!strcmp(argv[1],"stop")){
  counter("/var/lib/qa-probes/stop-count");
  return (int)number("HIA_START_STOP_RC");
 }
 if(strcmp(argv[1],"show"))return 93;
 counter("/var/lib/qa-probes/show-count");
 const char *unit=argv[argc-1];size_t len=strlen(unit);if(len<19||strncmp(unit,"hepta-job-",10)||strcmp(unit+len-8,".service"))return 94;
 char id[128];size_t n=len-18;if(n>=sizeof id)return 94;memcpy(id,unit+10,n);id[n]=0;
 char path[512];snprintf(path,sizeof path,"/var/lib/hepta-runtime-jobctl/%s/record.json",id);
 int fd=open(path,O_RDONLY);if(fd<0)return 95;char record[2097152];ssize_t got=read(fd,record,sizeof record-1);close(fd);if(got<0)return 95;record[got]=0;
 const char *nonce=strstr(record,"\"nonce\":\"");if(!nonce)return 96;nonce+=9;const char *end=strchr(nonce,'"');if(!end||(size_t)(end-nonce)>256)return 96;
 const char *load=setting("HIA_START_LOAD","loaded");
 printf("LoadState=%s\nActiveState=active\nSubState=running\nResult=success\n",load);
 const char *inv=setting("HIA_START_INVOCATION","fixture-invocation");
 const char *bad=setting("HIA_START_DESCRIPTION","match");
 printf("InvocationID=%s\nDescription=Hepta Runtime %s %.*s%s\nExecMainStatus=0\nExecMainCode=0\n",inv,id,(int)(end-nonce),nonce,strcmp(bad,"match")?"wrong":"");
 return (int)number("HIA_START_SHOW_RC");
}
