/* Root-only, isolated real-FD controls for R3's atomic host handoff.
 * Includes the exact production bridge so the real static function is tested.
 * No HIA image is executed; no process is forked or signalled. Synthetic fact
 * rows are only supplied to validation and never presented as kernel receipts.
 */
#define PY_SSIZE_T_CLEAN
#define _GNU_SOURCE 1
#include "hia_cold_native_transport_python.c"
#include <stdio.h>

static int fail_line;
#define REQUIRE(x) do { if(!(x)){fail_line=__LINE__;goto done;} } while(0)
static int alive_fd(int fd) {return fd>=0&&fcntl(fd,F_GETFD)>=0;}
static void empty_session(Session *s,Profile *p,int fds[9]) {
    memset(s,0,sizeof *s);memset(p,0,sizeof *p);
    p->unknown=PyExc_RuntimeError;s->profile=p;
    for(unsigned i=0;i<9;++i){s->raw_fds[i]=-1;fds[i]=-1;}
}
static int no_adoption(const Session *s) {
    if(s->handoff)return 0;
    for(unsigned i=0;i<9;++i)if(s->raw_fds[i]!=-1)return 0;
    return 1;
}
static int dispose(Session *s) {
    int okay=1;
    for(unsigned i=0;i<9;++i)if(s->raw_fds[i]>=0){
        int fd=s->raw_fds[i];s->raw_fds[i]=-1;
        if(close(fd)!=0)okay=0;
    }
    Py_CLEAR(s->pending);Py_CLEAR(s->caller);
    for(unsigned i=0;i<3;++i)Py_CLEAR(s->streams[i]);
    Py_CLEAR(s->owner);
    return okay;
}
static PyObject *binary_writer(int fd) {
    PyObject *io=PyImport_ImportModule("io");
    if(!io)return NULL;
    PyObject *open=get_module_attr(io,"open");Py_DECREF(io);
    if(!open)return NULL;
    PyObject *file=PyObject_CallFunction(open,"isi",fd,"wb",-1);Py_DECREF(open);
    return file;
}
static int run_control(unsigned which,FILE *report) {
    Session s;Profile p;int facts[9],a=-1,b=-1,c=-1,failed=1,number_reused=0;
    empty_session(&s,&p,facts);
    struct hia_cold_snapshot f={0};f.fds=facts;
    const char *names[]={
      "HOF-01-raw-before-real-closed-stream",
      "HOF-02-raw-before-live-stream-fd-mismatch",
      "HOF-03-existing-raw-owner-conflict",
      "HOF-04-second-handoff-refused",
      "HOF-05-live-child-without-Popen-owner-refused",
      "HOF-06-owner-sync-error-before-adoption",
      "HOF-07-real-raw-and-canonical-stream-commit",
      "HOF-08-empty-commit"};
    int rc=-99,actual_pending=0;
    if(which!=7){
        a=open("/dev/null",O_RDONLY|O_CLOEXEC);REQUIRE(a>=3);facts[0]=a;
    }
    if(which==0||which==1||which==6){
        b=open("/dev/null",O_WRONLY|O_CLOEXEC);REQUIRE(b>=3);
        s.streams[0]=binary_writer(b);REQUIRE(s.streams[0]);
        facts[2]=b;
        if(which==0){
            PyObject *closed=PyObject_CallMethod(s.streams[0],"close",NULL);
            REQUIRE(closed);Py_DECREF(closed);
            REQUIRE(!alive_fd(b));b=-1;
        }else if(which==1){
            c=open("/dev/null",O_WRONLY|O_CLOEXEC);REQUIRE(c>=3);
            facts[2]=c;
        }
    }else if(which==2){
        b=open("/dev/null",O_RDONLY|O_CLOEXEC);REQUIRE(b>=3);
        s.raw_fds[0]=b;b=-1;
    }else if(which==3){
        REQUIRE(host_handoff(&s,&f)==0);
        REQUIRE(s.handoff&&s.raw_fds[0]==a);
    }else if(which==4){
        f.pid=getpid(); /* real value; deliberately not a claimed child owner */
    }else if(which==5){
        PyObject *module=PyImport_ImportModule("subprocess");REQUIRE(module);
        PyObject *kind=get_module_attr(module,"Popen");Py_DECREF(module);REQUIRE(kind);
        PyObject *new=get_module_attr(kind,"__new__");REQUIRE(new);
        s.owner=PyObject_CallOneArg(new,kind);Py_DECREF(new);Py_DECREF(kind);REQUIRE(s.owner);
        f.pid=getpid(); /* original empty Popen has no pid instance attribute */
    }
    rc=host_handoff(&s,&f);
    actual_pending=s.pending!=NULL;
    if(which==0||which==1||which==4||which==5){
        REQUIRE(rc==-1&&actual_pending&&no_adoption(&s)&&alive_fd(a));
        if(which==0)REQUIRE(PyErr_GivenExceptionMatches(s.pending,PyExc_ValueError));
        if(which==5)REQUIRE(PyErr_GivenExceptionMatches(s.pending,PyExc_AttributeError));
        /* Retire the dispatcher's old generation, then use that actual integer
           for a different real resource. Disposing this rejected Session must
           not close the replacement; no stale number was adopted. */
        int old=a;REQUIRE(close(a)==0);a=-1;
        int fresh=open("/dev/null",O_RDONLY|O_CLOEXEC);REQUIRE(fresh>=3);
        if(fresh!=old){REQUIRE(dup2(fresh,old)==old);REQUIRE(close(fresh)==0);}
        a=old;number_reused=1;
        if(s.streams[0])b=-1; /* dispose retires the wrapper's actual FD */
        REQUIRE(dispose(&s)&&alive_fd(a));
    }else if(which==2){
        REQUIRE(rc==-1&&actual_pending&&s.handoff==0&&s.raw_fds[0]>=3
                &&s.raw_fds[0]!=a&&alive_fd(a)&&alive_fd(s.raw_fds[0]));
    }else if(which==3){
        REQUIRE(rc==-1&&actual_pending&&s.handoff&&s.raw_fds[0]==a&&alive_fd(a));
        a=-1; /* only the already successful Session owns this generation */
    }else if(which==6){
        REQUIRE(rc==0&&!actual_pending&&s.handoff&&s.raw_fds[0]==a
                &&s.raw_fds[2]==-1&&alive_fd(a)&&alive_fd(b));
        a=-1;b=-1; /* actual ownership now belongs to Session/wrapper */
    }else{
        REQUIRE(rc==0&&!actual_pending&&s.handoff);
        for(unsigned i=0;i<9;++i)REQUIRE(s.raw_fds[i]==-1);
    }
    failed=0;
done:
    if(PyErr_Occurred()){PyErr_Print();failed=1;}
    /* On both success and unexpected assertion failure, close each actual
       generation through its sole current owner. */
    if(s.streams[0])b=-1;
    for(unsigned slot=0;slot<9;++slot)if(s.raw_fds[slot]>=0){
        if(s.raw_fds[slot]==a)a=-1;
        if(s.raw_fds[slot]==b)b=-1;
        if(s.raw_fds[slot]==c)c=-1;
    }
    if(!dispose(&s))failed=1;
    if(a>=0&&close(a)!=0)failed=1;
    if(b>=0&&close(b)!=0)failed=1;
    if(c>=0&&close(c)!=0)failed=1;
    if(fprintf(report,"%s{\"id\":\"%s\",\"passed\":%s,\"handoff_return\":%d,"
                      "\"actual_pending\":%s,\"real_number_reuse_checked\":%s,"
                      "\"failure_line\":%d}",
             which?",":"",names[which],failed?"false":"true",rc,
             actual_pending?"true":"false",number_reused?"true":"false",
             failed?fail_line:0)<0)return 1;
    return failed;
}
int main(int argc,char **argv) {
    if(argc!=3)return 64;
    PyConfig config;PyConfig_InitIsolatedConfig(&config);
    config.site_import=0;config.write_bytecode=0;
    PyStatus status=PyConfig_SetBytesString(&config,&config.program_name,argv[1]);
    if(!PyStatus_Exception(status))status=PyConfig_SetBytesString(&config,&config.executable,argv[1]);
    if(!PyStatus_Exception(status))status=Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);
    if(PyStatus_Exception(status))Py_ExitStatusException(status);
    FILE *report=fopen(argv[2],"wx");if(!report)return 65;
    int failed=0;
    if(fputs("{\"schema\":\"hepta.cold-native-transport.handoff-controls.r3\","
             "\"scope\":\"ISOLATED_REAL_FD_VALIDATION_NOT_PRODUCT_QUALIFICATION\","
             "\"planned\":8,\"controls\":[",report)<0)failed=1;
    for(unsigned i=0;i<8;++i)failed|=run_control(i,report);
    if(fprintf(report,"],\"status\":\"%s\",\"whole_native\":false}\n",
               failed?"HOLD":"CONTROLS_PASS")<0)failed=1;
    if(fclose(report)!=0)failed=1;
    if(Py_FinalizeEx()<0)failed=1;
    return failed?1:0;
}
