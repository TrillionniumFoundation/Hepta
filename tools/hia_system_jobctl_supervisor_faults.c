#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

/* Qualification only: inject into the syscall stream of this tracer's child.
 * Neither product uses this file. No process selected by an external PID is
 * inspected, and the kernel kills the owned child if the tracer disappears. */
static const char *selected,*effect;
static int fired,parent_syncs,tmp_opens,tmp_syncs,renames,tmp_writes,ready_observed;
static int trace_string(pid_t pid,unsigned long at,char *out,size_t cap){
 size_t used=0;while(used<cap){errno=0;long value=ptrace(PTRACE_PEEKDATA,pid,(void *)(at+used),0);if(errno)return 0;
  for(size_t i=0;i<sizeof value&&used<cap;i++,used++){out[used]=(char)((unsigned long)value>>(8*i));if(!out[used])return 1;}}
 out[cap-1]=0;return 0;
}
static int fd_path(pid_t pid,long fd,char *out,size_t size){char link[128];snprintf(link,sizeof link,"/proc/%ld/fd/%ld",(long)pid,fd);ssize_t n=readlink(link,out,size-1);if(n<0)return 0;out[n]=0;return 1;}
static int suffix(const char *p,const char *s){size_t a=strlen(p),b=strlen(s);return a>=b&&!memcmp(p+a-b,s,b);}
static int wanted(const char *kind,int n){char b[128];if(n)snprintf(b,sizeof b,"%s.%d",kind,n);else snprintf(b,sizeof b,"%s",kind);return !strcmp(selected,b);}
static int choose_fault(pid_t pid,const struct user_regs_struct *r){
 char path[8192];long call=(long)r->orig_rax;
 if(call==SYS_wait4){
  if(r->rdx&WNOHANG)return wanted("wait.try",0);
  return wanted("wait.block",0);
 }
 if(call==SYS_waitid){
  if(r->r10&WNOHANG)return wanted("wait.try",0);
  return wanted("wait.block",0);
 }
 if(call==SYS_kill||call==SYS_pidfd_send_signal)return wanted("kill",0);
 if(call==SYS_fsync&&fd_path(pid,(long)r->rdi,path,sizeof path)){
  if(suffix(path,"/state/stdout.log"))return wanted("sync.stdout",0);
  if(suffix(path,"/state/stderr.log"))return wanted("sync.stderr",0);
  if(suffix(path,"/state"))return wanted("sync.parent",++parent_syncs);
  if(strstr(path,"/state/exit.tmp-"))return wanted("sync.tmp",++tmp_syncs);
 }
 if(call==SYS_openat&&trace_string(pid,r->rsi,path,sizeof path)){
  if(!strcmp(path,"/state/stdout.log"))return wanted("open.stdout",0);
  if(!strcmp(path,"/state/stderr.log"))return wanted("open.stderr",0);
  if(!strcmp(path,"/state"))return wanted("open.parent",0);
  if(strstr(path,"/state/exit.tmp-"))return wanted("open.tmp",++tmp_opens);
 }
 if(call==SYS_rename&&trace_string(pid,r->rsi,path,sizeof path)){
  if(!strcmp(path,"/state/exit.json")||!strcmp(path,"/state/exit.witness"))return wanted("rename",++renames);
 }
 if(call==SYS_write&&fd_path(pid,(long)r->rdi,path,sizeof path)){
  if(suffix(path,"/state/stdout.log"))return wanted("write.stdout",0);
  if(suffix(path,"/state/stderr.log"))return wanted("write.stderr",0);
  if(strstr(path,"/state/exit.tmp-")){
   /* The pathname is reused for witness publication; count successful opens,
    * not serde's implementation-specific number of individual writes. */
   tmp_writes++;(void)tmp_writes;return wanted("write.tmp",tmp_opens);
  }
 }
 if(call==SYS_read&&r->rdx==8192&&fd_path(pid,(long)r->rdi,path,sizeof path)&&!strncmp(path,"pipe:[",6))return wanted("read.pipe",0);
 /* Rust startup separately polls fd 0/1/2 to repair absent standard streams.
  * The original Capture::poll owns exactly its two output readers. */
 if(call==SYS_poll&&r->rsi==2)return wanted("poll",0);
 return 0;
}
int main(int argc,char **argv){
 if(argc<5)return 250;
 selected=argv[1];effect=argv[2];const char *marker=argv[3];
 pid_t child=fork();if(child<0)return 251;
 if(child==0){if(ptrace(PTRACE_TRACEME,0,0,0)<0)_exit(252);raise(SIGSTOP);execv(argv[4],argv+4);_exit(253);}
 int status;if(waitpid(child,&status,0)!=child||!WIFSTOPPED(status))return 251;
 if(ptrace(PTRACE_SETOPTIONS,child,0,PTRACE_O_TRACESYSGOOD|PTRACE_O_EXITKILL)<0)return 251;
 int entry=1,override=0,deliver=0;long forced=0;int result=251;
 for(;;){
  if(ptrace(PTRACE_SYSCALL,child,0,deliver)<0)break;
  pid_t observed;do{observed=waitpid(child,&status,0);}while(observed<0&&errno==EINTR);
  if(observed!=child)break;
  if(WIFEXITED(status)){result=WEXITSTATUS(status);break;}
  if(WIFSIGNALED(status)){result=128+WTERMSIG(status);break;}
  if(!WIFSTOPPED(status))break;
  int sig=WSTOPSIG(status);deliver=0;
  if(sig==(SIGTRAP|0x80)){
   struct user_regs_struct regs;if(ptrace(PTRACE_GETREGS,child,0,&regs)<0)break;
   if(entry){
    if(!ready_observed&&(!strncmp(selected,"wait.",5)||!strcmp(selected,"kill"))&&(regs.orig_rax==SYS_wait4||regs.orig_rax==SYS_waitid)){
     /* Hold the parent's first observation until this test workload has
      * published readiness. This makes its live/original identity explicit. */
     for(int i=0;i<2000&&access("/state/ready",F_OK)!=0;i++)usleep(1000);
     if(access("/state/ready",F_OK)!=0)return 249;
     ready_observed=1;
    }
    if(!fired&&choose_fault(child,&regs)){
     if(!strcmp(effect,"short")&&regs.orig_rax==SYS_write&&regs.rdx<=1){/* wait for a splittable write */}
     else{
      fired=1;
      if(!strcmp(effect,"short")){if(regs.orig_rax!=SYS_write)return 254;regs.rdx/=2;}
      else{forced=!strcmp(effect,"eintr")?-EINTR:!strcmp(effect,"zero")?0:-EIO;regs.orig_rax=(unsigned long)-1;override=1;}
      if(ptrace(PTRACE_SETREGS,child,0,&regs)<0)break;
     }
    }
   }else if(override){regs.rax=(unsigned long)forced;override=0;if(ptrace(PTRACE_SETREGS,child,0,&regs)<0)break;}
   entry=!entry;
  }else if(sig!=SIGTRAP&&sig!=SIGSTOP)deliver=sig;
 }
 int fd=open(marker,O_WRONLY|O_CREAT|O_TRUNC,0600);if(fd>=0){const char b=fired?'1':'0';if(write(fd,&b,1)!=1)result=255;close(fd);}else result=255;
 return result;
}
