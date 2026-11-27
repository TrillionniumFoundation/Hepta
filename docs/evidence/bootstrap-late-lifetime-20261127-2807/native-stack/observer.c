/* Development observation only. Never a native source-authority input. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
typedef void Obj;
static ssize_t (*next_write)(int,const void *,size_t);
static int (*gil_ensure)(void), (*is_finalizing)(void);
static void (*gil_release)(int), (*decref)(Obj*), (*err_clear)(void);
static void (*err_fetch)(Obj**,Obj**,Obj**), (*err_restore)(Obj*,Obj*,Obj*);
static Obj *(*thread_get)(void), *(*thread_frame)(Obj*), *(*frame_back)(Obj*);
static Obj *(*frame_code)(Obj*), *(*get_attr)(Obj*,const char*), *(*frame_var)(Obj*,const char*);
static int (*frame_line)(Obj*), (*frame_lasti)(Obj*);
static const char *(*utf8)(Obj*);
static const char *late_path;
static int trace_fd=-1, late_fd=-1;
static __thread int inside;
static void raw(const void *p,size_t n) {
    const char *s=p;
    while(n){ssize_t k=next_write(trace_fd,s,n);if(k<0&&errno==EINTR)continue;if(k<=0)break;s+=k;n-=(size_t)k;}
}
static void lit(const char *s){raw(s,strlen(s));}
static void string(const char *s) {
    if(!s){lit("null");return;}
    lit("\"");
    for(const unsigned char *p=(const unsigned char*)s;*p;p++){
        unsigned char c=*p;
        if(c=='"'||c=='\\'){char x[2]={'\\',(char)c};raw(x,2);}
        else if(c<32||c>=127){char x[7];snprintf(x,sizeof x,"\\u%04x",c);raw(x,6);}
        else raw(p,1);
    }
    lit("\"");
}
static void need(void **target,const char *name) {
    *target=dlsym(RTLD_DEFAULT,name);
    if(!*target){const char *m="late diagnostic missing Python symbol\n";syscall(SYS_write,2,m,strlen(m));_exit(125);}
}
__attribute__((constructor)) static void begin(void) {
    *(void**)(&next_write)=dlsym(RTLD_NEXT,"write");
    late_path=getenv("HIA_BOOTSTRAP_DIAG_LATE_FILE");
    const char *trace=getenv("HIA_BOOTSTRAP_DIAG_TRACE_FILE");
    if(!next_write||!late_path||!trace)_exit(124);
    trace_fd=open(trace,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
    if(trace_fd<0)_exit(123);
#define N(x,s) need((void**)&(x),s)
    N(gil_ensure,"PyGILState_Ensure");N(gil_release,"PyGILState_Release");
    N(is_finalizing,"Py_IsFinalizing");N(thread_get,"PyThreadState_Get");
    N(thread_frame,"PyThreadState_GetFrame");N(frame_back,"PyFrame_GetBack");
    N(frame_code,"PyFrame_GetCode");N(frame_line,"PyFrame_GetLineNumber");
    N(frame_lasti,"PyFrame_GetLasti");N(frame_var,"PyFrame_GetVarString");
    N(get_attr,"PyObject_GetAttrString");N(utf8,"PyUnicode_AsUTF8");
    N(decref,"Py_DecRef");N(err_fetch,"PyErr_Fetch");
    N(err_restore,"PyErr_Restore");N(err_clear,"PyErr_Clear");
#undef N
}
static int target(int fd) {
    if(late_fd>=0)return fd==late_fd;
    char link[64],path[4096];
    int n=snprintf(link,sizeof link,"/proc/self/fd/%d",fd);
    if(n<=0||(size_t)n>=sizeof link)return 0;
    ssize_t k=readlink(link,path,sizeof path-1);
    if(k<0)return 0;
    path[k]=0;
    if(strcmp(path,late_path))return 0;
    late_fd=fd;return 1;
}
static void record(const void *buf,size_t count) {
    if(count&&((const char*)buf)[count-1]=='\n')count--;
    lit("{\"row\":");raw(buf,count);
    if(is_finalizing()){lit(",\"diagnostic_refusal\":\"interpreter_finalizing\"}\n");return;}
    int state=gil_ensure();
    Obj *et=NULL,*ev=NULL,*tb=NULL;
    err_fetch(&et,&ev,&tb);
    Obj *frame=thread_frame(thread_get());
    lit(",\"stack\":[");
    int first=1;
    while(frame){
        Obj *co=frame_code(frame);
        Obj *name=get_attr(co,"co_name"),*file=get_attr(co,"co_filename");
        const char *ns=name?utf8(name):NULL,*fs=file?utf8(file):NULL;
        if(!first)lit(",");first=0;
        lit("{\"function\":");string(ns);lit(",\"filename\":");string(fs);
        char number[100];
        int n=snprintf(number,sizeof number,",\"line\":%d,\"lasti\":%d",
                       frame_line(frame),frame_lasti(frame));
        raw(number,(size_t)n);
        if(ns&&!strcmp(ns,"run")){
            Obj *identity=frame_var(frame,"current_id");
            if(identity){lit(",\"current_id\":");string(utf8(identity));decref(identity);}
            else err_clear();
        }
        lit("}");
        if(name)decref(name);if(file)decref(file);if(co)decref(co);
        Obj *back=frame_back(frame);decref(frame);frame=back;
    }
    lit("]}\n");
    err_clear();err_restore(et,ev,tb);
    gil_release(state);
}
ssize_t write(int fd,const void *buf,size_t count) {
    if(!next_write)return syscall(SYS_write,fd,buf,count);
    ssize_t result=next_write(fd,buf,count);
    int saved=errno;
    if(!inside&&result>0&&target(fd)){
        inside=1;record(buf,(size_t)result);inside=0;
    }
    errno=saved;return result;
}
