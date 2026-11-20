/* Explicit CPython 3.14 hosted bridge for the R3 native HIA child policy.
 *
 * Each Session is GC-tracked and owns a real subprocess.Popen object created
 * with __new__. No old run, Popen.__init__, communicate, wait, or __exit__ body
 * is called. HIA issues every process/IO/cleanup action. The existing Popen
 * finalizer is deliberately still a hosted provider after a real handoff.
 *
 * This is a candidate, not proof of Python stack/GC/reflection equivalence.
 */
#define PY_SSIZE_T_CLEAN
#define _GNU_SOURCE 1
#include <Python.h>
#include "hia_cold_native_transport.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
    PyObject *unknown, *profile_type, *session_type;
} module_state;
typedef struct {
    PyObject_HEAD
    PyObject *policy_bytes, *subprocess, *io, *os, *raw_io, *builtins;
    PyObject *popen_class, *io_open, *fileio_class, *buffered_reader, *buffered_writer;
    PyObject *identity, *unknown;
    void *mapping;
    size_t mapping_bytes;
    hia_cold_policy policy;
    pid_t creator_pid;
    unsigned long creator_thread;
    uint64_t nonce, calls, entries, completed, handed_off, unknowns;
    unsigned initialized;
} Profile;
typedef struct {
    PyObject_HEAD
    Profile *profile;
    PyObject *executable, *input, *cwd, *timeout, *arguments;
    PyObject *output_fd, *snapshot_fd;
    PyObject *owner, *args, *audit_args, *environment;
    PyObject *streams[3], *encoded_cwd, *encoded_args, *encoded_environment;
    PyObject *pending, *caller;
    struct hia_cold_config config;
    struct hia_cold_host host;
    struct hia_cold_result result;
    char **arguments_native, **environment_native;
    int borrowed[2], raw_fds[9];
    int stream_fds[3], residual_fds[9];
    uint64_t residual_fd_mask;
    unsigned linked, started, finished, handoff;
    uint64_t wait_start_ns, wait_clock_ns;
    double wait_timeout_seconds;
    unsigned wait_timeout_observed;
    pid_t creator_pid;
    unsigned long creator_thread;
    PyThreadState *released;
} Session;
static PyObject *get_module_attr(PyObject *module,const char *name) {
    return PyObject_GetAttrString(module,name);
}
static int set_object(PyObject *owner,const char *name,PyObject *value) {
    return PyObject_SetAttrString(owner,name,value);
}
static int set_long(PyObject *owner,const char *name,long long value) {
    PyObject *number=PyLong_FromLongLong(value);
    if(!number)return -1;
    int rc=set_object(owner,name,number);Py_DECREF(number);return rc;
}
static int profile_capabilities_current(Profile *p) {
    if(!p||!p->unknown||!p->policy_bytes||!p->identity||!p->subprocess
       ||!p->io||!p->os||!p->raw_io||!p->builtins||!p->popen_class||!p->io_open
       ||!p->fileio_class||!p->buffered_reader||!p->buffered_writer||!p->mapping||p->mapping==MAP_FAILED
       ||!p->mapping_bytes||!p->policy){
        PyErr_SetString(PyExc_RuntimeError,"native cold Profile has no complete live capability binding");
        return 0;
    }
    if(p->creator_pid!=getpid()||p->creator_thread!=PyThread_get_thread_ident()){
        PyErr_SetString(p->unknown,"native cold profile crossed its admitted process/thread");
        return 0;
    }
    struct binding {PyObject *module;const char *name;PyObject *expected;} checks[]={
        {p->subprocess,"Popen",p->popen_class},
        {p->io,"open",p->io_open},{p->raw_io,"open",p->io_open},
        {p->builtins,"open",p->io_open},
        {p->io,"FileIO",p->fileio_class},{p->raw_io,"FileIO",p->fileio_class},
        {p->io,"BufferedReader",p->buffered_reader},{p->raw_io,"BufferedReader",p->buffered_reader},
        {p->io,"BufferedWriter",p->buffered_writer},{p->raw_io,"BufferedWriter",p->buffered_writer}
    };
    for(size_t i=0;i<sizeof checks/sizeof checks[0];++i){
        PyObject *value=get_module_attr(checks[i].module,checks[i].name);
        if(!value)return 0;
        int same=value==checks[i].expected;Py_DECREF(value);
        if(!same){
            PyErr_SetString(p->unknown,"native cold profile's captured host capability changed");
            return 0;
        }
    }
    return 1;
}
static int profile_current(Profile *p) {
    if(!p||!p->initialized){
        PyErr_SetString(PyExc_RuntimeError,"native cold Profile is uninitialized or cleared");
        return 0;
    }
    return profile_capabilities_current(p);
}
static int profile_traverse(Profile *p,visitproc visit,void *arg) {
    Py_VISIT(Py_TYPE(p));
    Py_VISIT(p->policy_bytes);Py_VISIT(p->subprocess);Py_VISIT(p->io);Py_VISIT(p->os);Py_VISIT(p->raw_io);Py_VISIT(p->builtins);
    Py_VISIT(p->popen_class);Py_VISIT(p->io_open);Py_VISIT(p->fileio_class);
    Py_VISIT(p->buffered_reader);Py_VISIT(p->buffered_writer);
    Py_VISIT(p->identity);Py_VISIT(p->unknown);return 0;
}
static int profile_clear(Profile *p) {
    p->initialized=0;
    Py_CLEAR(p->policy_bytes);Py_CLEAR(p->subprocess);Py_CLEAR(p->io);Py_CLEAR(p->os);Py_CLEAR(p->raw_io);Py_CLEAR(p->builtins);
    Py_CLEAR(p->popen_class);Py_CLEAR(p->io_open);Py_CLEAR(p->fileio_class);
    Py_CLEAR(p->buffered_reader);Py_CLEAR(p->buffered_writer);
    Py_CLEAR(p->identity);Py_CLEAR(p->unknown);return 0;
}
static void profile_dealloc(Profile *p) {
    PyObject *raised=PyErr_GetRaisedException();
    PyTypeObject *type=Py_TYPE(p);
    PyObject_GC_UnTrack(p);
    if(p->mapping&&p->mapping!=MAP_FAILED)munmap(p->mapping,p->mapping_bytes);
    profile_clear(p);
    if(PyErr_Occurred())PyErr_WriteUnraisable(NULL);
    type->tp_free((PyObject *)p);Py_DECREF(type);
    if(PyErr_Occurred())PyErr_WriteUnraisable(NULL);
    PyErr_SetRaisedException(raised);
}
static int profile_init(Profile *p,PyObject *args,PyObject *kwargs) {
    static char *keys[]={"policy_bytes","source_identity_sha256",NULL};
    PyObject *bytes,*identity;
    if(!PyArg_ParseTupleAndKeywords(args,kwargs,"OO:Profile",keys,&bytes,&identity))return -1;
    if(p->mapping||p->policy_bytes){PyErr_SetString(PyExc_RuntimeError,"Profile is single-initialization");return -1;}
    if(!PyBytes_CheckExact(bytes)||PyBytes_GET_SIZE(bytes)<=0||!PyUnicode_CheckExact(identity)||PyUnicode_GET_LENGTH(identity)!=64){
        PyErr_SetString(PyExc_TypeError,"Profile requires exact policy bytes and the immutable admitted identity digest");return -1;
    }
    module_state *m=PyType_GetModuleState(Py_TYPE(p));
    if(!m)return -1;
    p->unknown=Py_NewRef(m->unknown);
    p->policy_bytes=Py_NewRef(bytes);p->identity=Py_NewRef(identity);
    p->subprocess=PyImport_ImportModule("subprocess");if(!p->subprocess)return -1;
    p->io=PyImport_ImportModule("io");if(!p->io)return -1;
    p->os=PyImport_ImportModule("os");if(!p->os)return -1;
    p->raw_io=PyImport_ImportModule("_io");if(!p->raw_io)return -1;
    p->builtins=PyImport_ImportModule("builtins");if(!p->builtins)return -1;
    p->popen_class=get_module_attr(p->subprocess,"Popen");
    p->io_open=get_module_attr(p->io,"open");
    p->fileio_class=get_module_attr(p->io,"FileIO");
    p->buffered_reader=get_module_attr(p->io,"BufferedReader");
    p->buffered_writer=get_module_attr(p->io,"BufferedWriter");
    if(!p->popen_class||!p->io_open||!p->fileio_class||!p->buffered_reader||!p->buffered_writer)return -1;
    p->mapping_bytes=(size_t)PyBytes_GET_SIZE(bytes);
    p->mapping=mmap(NULL,p->mapping_bytes,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if(p->mapping==MAP_FAILED){p->mapping=NULL;PyErr_SetFromErrno(PyExc_OSError);return -1;}
    memcpy(p->mapping,PyBytes_AS_STRING(bytes),p->mapping_bytes);
    if(mprotect(p->mapping,p->mapping_bytes,PROT_READ|PROT_EXEC)!=0){
        PyErr_SetFromErrno(PyExc_OSError);return -1;
    }
    _Static_assert(sizeof p->policy==sizeof p->mapping,"native SysV code pointer");
    memcpy(&p->policy,&p->mapping,sizeof p->policy);
    p->creator_pid=getpid();p->creator_thread=PyThread_get_thread_ident();p->nonce=1;
    if(!profile_capabilities_current(p))return -1;
    p->initialized=1;
    return 0;
}
static int session_traverse(Session *s,visitproc visit,void *arg) {
    Py_VISIT(Py_TYPE(s));
    Py_VISIT(s->profile);Py_VISIT(s->executable);Py_VISIT(s->input);Py_VISIT(s->cwd);
    Py_VISIT(s->timeout);Py_VISIT(s->arguments);Py_VISIT(s->output_fd);Py_VISIT(s->snapshot_fd);
    Py_VISIT(s->owner);Py_VISIT(s->args);Py_VISIT(s->audit_args);Py_VISIT(s->environment);
    for(unsigned i=0;i<3;++i)Py_VISIT(s->streams[i]);
    Py_VISIT(s->encoded_cwd);Py_VISIT(s->encoded_args);Py_VISIT(s->encoded_environment);Py_VISIT(s->pending);Py_VISIT(s->caller);
    return 0;
}
static int session_clear_with_context(Session *s,PyObject *unraisable_context) {
    PyObject *raised=PyErr_GetRaisedException();
    /* Only descriptors genuinely transferred to this visible owner are here.
       Popen's parent stream wrappers own their own numbers. No descriptor is
       blindly retried after an earlier close claim. */
    for(unsigned i=0;i<9;++i)if(s->raw_fds[i]>=0){
        int fd=s->raw_fds[i];s->raw_fds[i]=-1;
        if(close(fd)!=0){PyErr_SetFromErrno(PyExc_OSError);PyErr_WriteUnraisable(unraisable_context);}
    }
    for(unsigned i=0;i<9;++i)if(s->residual_fd_mask&(UINT64_C(1)<<i)){
        int fd=s->residual_fds[i];
        s->residual_fd_mask&=~(UINT64_C(1)<<i);s->residual_fds[i]=-1;
        if(close(fd)!=0){PyErr_SetFromErrno(PyExc_OSError);PyErr_WriteUnraisable(unraisable_context);}
    }
    Py_CLEAR(s->pending);Py_CLEAR(s->caller);
    for(unsigned i=0;i<3;++i)Py_CLEAR(s->streams[i]);
    Py_CLEAR(s->owner);
    Py_CLEAR(s->args);Py_CLEAR(s->audit_args);Py_CLEAR(s->environment);
    Py_CLEAR(s->encoded_args);Py_CLEAR(s->encoded_cwd);Py_CLEAR(s->encoded_environment);
    Py_CLEAR(s->executable);Py_CLEAR(s->input);Py_CLEAR(s->cwd);Py_CLEAR(s->timeout);
    Py_CLEAR(s->arguments);Py_CLEAR(s->output_fd);Py_CLEAR(s->snapshot_fd);Py_CLEAR(s->profile);
    if(PyErr_Occurred())PyErr_WriteUnraisable(unraisable_context);
    PyErr_SetRaisedException(raised);
    return 0;
}
static int session_clear(Session *s) {
    return session_clear_with_context(s,(PyObject *)s);
}
static void session_dealloc(Session *s) {
    PyObject *raised=PyErr_GetRaisedException();
    PyTypeObject *type=Py_TYPE(s);
    PyObject_GC_UnTrack(s);
    hia_cold_transport_release(&s->result);
    free(s->arguments_native);s->arguments_native=NULL;
    free(s->environment_native);s->environment_native=NULL;
    /* A refcount-zero object is never exposed through unraisablehook. */
    session_clear_with_context(s,NULL);
    if(PyErr_Occurred())PyErr_WriteUnraisable(NULL);
    type->tp_free((PyObject *)s);Py_DECREF(type);
    if(PyErr_Occurred())PyErr_WriteUnraisable(NULL);
    PyErr_SetRaisedException(raised);
}
static PyObject *handled_enter(Session *s) {
    PyObject *old=PyErr_GetHandledException();
    PyErr_SetHandledException(s->pending?s->pending:s->caller);
    return old;
}
static void handled_leave(PyObject *old) {
    PyErr_SetHandledException(old);Py_XDECREF(old);
}
static unsigned take_error(Session *s) {
    PyObject *error=PyErr_GetRaisedException();
    if(!error){
        PyErr_SetString(PyExc_SystemError,"native host capability failed without an exception");
        error=PyErr_GetRaisedException();
    }
    if(!error){PyErr_NoMemory();error=PyErr_GetRaisedException();}
    unsigned tag=PyErr_GivenExceptionMatches(error,PyExc_KeyboardInterrupt)
        ?HCT_PY_KEYBOARD:HCT_PY_EXCEPTION;
    Py_XSETREF(s->pending,error);
    return tag;
}
static int sync_owner(Session *s,const struct hia_cold_snapshot *f) {
    if(!s->owner)return 0;
    if(f->pid>0){
        PyObject *old=get_module_attr(s->owner,"pid");
        if(!old)return -1;
        int unset=old==Py_None;Py_DECREF(old);
        if(unset&&set_long(s->owner,"pid",f->pid)<0)return -1;
        if(set_object(s->owner,"_child_created",Py_True)<0)return -1;
    }
    if(f->reaped){
        long code=WIFEXITED(f->wait_status)?WEXITSTATUS(f->wait_status):-WTERMSIG(f->wait_status);
        if(set_long(s->owner,"returncode",code)<0)return -1;
    }
    if(f->keyboard_wait_done){
        PyObject *zero=PyFloat_FromDouble(0.0);if(!zero)return -1;
        int rc=set_object(s->owner,"_sigint_wait_secs",zero);Py_DECREF(zero);if(rc<0)return -1;
    }
    return 0;
}
static int bind_wait_timeout(Session *s,const struct hia_cold_snapshot *f) {
    if(!f->wait_clock_observed)return 0;
    if(f->wait_clock_observed!=1||!f->clock_started
       ||f->clock_start_ns>(uint64_t)PyTime_MAX||f->wait_clock_ns>(uint64_t)PyTime_MAX){
        PyErr_SetString(PyExc_OverflowError,"native wait clock facts exceed the admitted CPython monotonic range");
        return -1;
    }
    if(s->wait_timeout_observed){
        if(s->wait_start_ns!=f->clock_start_ns||s->wait_clock_ns!=f->wait_clock_ns){
            PyErr_SetString(s->profile->unknown,"native wait clock receipt changed after its first issue");
            return -1;
        }
        return 0;
    }
    double timeout=PyFloat_AsDouble(s->timeout);
    if(PyErr_Occurred())return -1;
    /* Match the two floating operations in communicate/_remaining_time.
       Converting one integer nanosecond difference is not equivalent. */
    volatile double start=PyTime_AsSecondsDouble((PyTime_t)f->clock_start_ns);
    volatile double end=start+timeout;
    double now=PyTime_AsSecondsDouble((PyTime_t)f->wait_clock_ns);
    s->wait_timeout_seconds=end-now;
    s->wait_start_ns=f->clock_start_ns;s->wait_clock_ns=f->wait_clock_ns;
    s->wait_timeout_observed=1;
    return 0;
}
static int make_pending(Session *s,const struct hia_cold_snapshot *f) {
    if(s->pending||f->outcome==HCT_RETURNED)return 0;
    if(f->outcome==HCT_EXEC_ERROR&&!f->reaped&&!f->owner_lost)return 0;
    if(f->outcome==HCT_TIMEOUT_WAIT){
        if(!s->wait_timeout_observed||!f->wait_clock_observed){
            PyErr_SetString(s->profile->unknown,"wait timeout has no actual first-wait clock receipt");
            return -1;
        }
        PyObject *kind=get_module_attr(s->profile->subprocess,"TimeoutExpired");
        if(!kind)return -1;
        PyObject *remaining=PyFloat_FromDouble(s->wait_timeout_seconds);
        PyObject *error=remaining?PyObject_CallFunctionObjArgs(kind,s->args,remaining,NULL):NULL;
        Py_DECREF(kind);Py_XDECREF(remaining);
        if(!error)return -1;
        /* _wait raises with its actual remaining-time positional argument;
           _communicate catches that same object and changes only .timeout.
           Both stream attributes retain the constructor's default None. */
        PyErr_SetObject((PyObject *)Py_TYPE(error),error);Py_DECREF(error);
        (void)take_error(s);
        PyObject *old=handled_enter(s);
        int changed=set_object(s->pending,"timeout",s->timeout);
        handled_leave(old);
        /* A real setter error remains raised with the actual pending error as
           context; host_before captures it through the unchanged error path. */
        return changed;
    }else if(f->outcome==HCT_TIMEOUT_IO){
        PyObject *kind=get_module_attr(s->profile->subprocess,"TimeoutExpired");
        if(!kind)return -1;
        PyObject *out=f->stdout_reads?PyBytes_FromStringAndSize((const char *)f->stdout_bytes,(Py_ssize_t)f->stdout_size):Py_NewRef(Py_None);
        PyObject *err=f->stderr_reads?PyBytes_FromStringAndSize((const char *)f->stderr_bytes,(Py_ssize_t)f->stderr_size):Py_NewRef(Py_None);
        PyObject *arguments=out&&err?PyTuple_Pack(2,s->args,s->timeout):NULL;
        PyObject *keywords=arguments?Py_BuildValue("{s:O,s:O}","output",out,"stderr",err):NULL;
        PyObject *error=keywords?PyObject_Call(kind,arguments,keywords):NULL;
        Py_DECREF(kind);Py_XDECREF(out);Py_XDECREF(err);
        Py_XDECREF(arguments);Py_XDECREF(keywords);
        if(!error)return -1;
        PyErr_SetObject((PyObject *)Py_TYPE(error),error);Py_DECREF(error);
    }else if(f->outcome==HCT_EXEC_ERROR){
        PyObject *filename=Py_None;
        if(f->stage==2)filename=s->cwd;
        else if(f->stage==6&&s->args)filename=PyList_GET_ITEM(s->args,0);
        errno=(int)f->error;
        PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError,filename);
    }else if(f->outcome==HCT_CUSTODY_LOST||f->outcome==HCT_POLICY_LOST){
        PyErr_SetString(s->profile->unknown,"native child custody or policy receipt is unknown");
    }else if(f->stage==HCT_IMAGE_WRITE&&f->error==EIO){
        PyErr_SetString(PyExc_OSError,"short observer image write");
    }else if(f->stage==HCT_SEAL_GET&&f->error==EIO){
        PyErr_SetString(PyExc_OSError,"observer image sealing failed");
    }else{
        errno=f->error&&f->error<4096?(int)f->error:EIO;
        PyErr_SetFromErrno(PyExc_OSError);
    }
    (void)take_error(s);return 0;
}
static unsigned host_before(void *context,unsigned action,unsigned arg,
                            const struct hia_cold_snapshot *f) {
    Session *s=context;
    PyObject *old=handled_enter(s);
    unsigned error=0;
    if(sync_owner(s,f)<0)error=take_error(s);
    else if(bind_wait_timeout(s,f)<0)error=take_error(s);
    else if(make_pending(s,f)<0)error=take_error(s);
    else {
        /* A real handled pending exception remains active during cleanup,
           while ordinary business effects see the original caller state. */
        PyErr_SetHandledException(s->pending?s->pending:s->caller);
        if(PyErr_CheckSignals()<0)error=take_error(s);
    }
    handled_leave(old);(void)action;(void)arg;return error;
}
static int make_argv(Session *s,int descriptor) {
    PyObject *path=PyUnicode_FromFormat("/proc/self/fd/%d",descriptor);
    if(!path)return -1;
    s->args=PyList_New(1);
    if(!s->args){Py_DECREF(path);return -1;}
    PyList_SET_ITEM(s->args,0,path);
    PyObject *iter=PyObject_GetIter(s->arguments);if(!iter)return -1;
    PyObject *item;
    while((item=PyIter_Next(iter))){
        int rc=PyList_Append(s->args,item);Py_DECREF(item);
        if(rc<0){Py_DECREF(iter);return -1;}
    }
    Py_DECREF(iter);return PyErr_Occurred()?-1:0;
}
static int init_owner(Session *s,const struct hia_cold_snapshot *f) {
    Profile *p=s->profile;
    if(make_argv(s,f->fds[0])<0)return -1;
    if(s->linked)s->environment=Py_NewRef(Py_None);
    else s->environment=Py_BuildValue("{s:s,s:s,s:s,s:s}","PATH","/usr/bin:/bin",
        "LANG","C.UTF-8","LC_ALL","C.UTF-8","TZ","UTC");
    if(!s->environment)return -1;
    PyObject *clean=get_module_attr(p->subprocess,"_cleanup");
    if(!clean)return -1;
    PyObject *done=PyObject_CallNoArgs(clean);Py_DECREF(clean);
    if(!done)return -1;Py_DECREF(done);
    PyObject *newfunc=get_module_attr(p->popen_class,"__new__");
    if(!newfunc)return -1;
    s->owner=PyObject_CallOneArg(newfunc,p->popen_class);Py_DECREF(newfunc);
    if(!s->owner)return -1;
    PyObject *threading=get_module_attr(p->subprocess,"threading");
    PyObject *lock_type=threading?get_module_attr(threading,"Lock"):NULL;
    Py_XDECREF(threading);
    PyObject *lock=lock_type?PyObject_CallNoArgs(lock_type):NULL;Py_XDECREF(lock_type);
    if(!lock)return -1;
    int rc=set_object(s->owner,"_waitpid_lock",lock);Py_DECREF(lock);if(rc<0)return -1;
    if(set_object(s->owner,"_input",Py_None)<0
       ||set_object(s->owner,"_communication_started",Py_False)<0
       ||set_object(s->owner,"args",s->args)<0
       ||set_object(s->owner,"stdin",Py_None)<0||set_object(s->owner,"stdout",Py_None)<0
       ||set_object(s->owner,"stderr",Py_None)<0||set_object(s->owner,"pid",Py_None)<0
       ||set_object(s->owner,"returncode",Py_None)<0||set_object(s->owner,"encoding",Py_None)<0
       ||set_object(s->owner,"errors",Py_None)<0||set_long(s->owner,"pipesize",-1)<0
       ||set_object(s->owner,"text_mode",Py_None)<0
       ||set_object(s->owner,"_closed_child_pipe_fds",Py_False)<0)return -1;
    PyObject *quarter=PyFloat_FromDouble(0.25);if(!quarter)return -1;
    rc=set_object(s->owner,"_sigint_wait_secs",quarter);Py_DECREF(quarter);return rc;
}
/* The admitted binary subset of CPython 3.14 _io.open is split at the
 * actual Raw FileIO success boundary. A supplied-fd FileIO init failure leaves
 * the caller's fd unclaimed; after success its real raw object owns the fd.
 * No fd-number probing or dup is used to guess which branch happened. */
static void chain_raised(PyObject *prior) {
    if(!prior)return;
    PyObject *current=PyErr_GetRaisedException();
    if(current){PyException_SetContext(current,prior);PyErr_SetRaisedException(current);}
    else PyErr_SetRaisedException(prior);
}
static int wrap_stream(Session *s,unsigned slot,int descriptor,unsigned *ownership) {
    unsigned index=slot==2?0:slot==3?1:2;
    const char *rawmode=slot==2?"w":"r",*mode=slot==2?"wb":"rb";
    const char *name=slot==2?"stdin":slot==3?"stdout":"stderr";
    PyObject *raw=NULL,*modeobj=NULL,*value=NULL,*buffer=NULL;
    *ownership=0;
    if(s->streams[index]){
        PyErr_SetString(s->profile->unknown,"stream slot already has an actual owner");
        return -1;
    }
    raw=PyObject_CallFunction(s->profile->fileio_class,"isOO",descriptor,rawmode,Py_True,Py_None);
    if(!raw)return -1; /* supplied-fd FileIO did not take ownership on failure */
    if((PyObject *)Py_TYPE(raw)!=s->profile->fileio_class){
        PyErr_SetString(s->profile->unknown,"noncanonical raw owner returned by admitted FileIO");
        goto raw_error;
    }
    modeobj=PyUnicode_FromString(mode);if(!modeobj)goto raw_error;
    value=PyObject_CallMethod(raw,"_isatty_open_only",NULL);
    if(!value)goto raw_error;
    int isatty=PyObject_IsTrue(value);Py_CLEAR(value);
    if(isatty<0)goto raw_error;
    value=get_module_attr(raw,"_blksize");if(!value)goto raw_error;
    long buffering=PyLong_AsLong(value);Py_CLEAR(value);
    if(buffering==-1&&PyErr_Occurred())goto raw_error;
    if(buffering>8192*1024)buffering=8192*1024;
    if(buffering<128*1024)buffering=128*1024; /* exact CPython 3.14 DEFAULT_BUFFER_SIZE */
    PyObject *expected=slot==2?s->profile->buffered_writer:s->profile->buffered_reader;
    buffer=PyObject_CallFunction(expected,"Oi",raw,(int)buffering);
    if(!buffer)goto raw_error;
    Py_CLEAR(raw);Py_CLEAR(modeobj);
    s->streams[index]=buffer;s->stream_fds[index]=descriptor;
    if((PyObject *)Py_TYPE(buffer)!=expected){
        PyErr_SetString(s->profile->unknown,"native bridge requires the actual canonical binary stream owner");
        return -1;
    }
    return set_object(s->owner,name,buffer);
raw_error: {
    /* Preserve the exact prior exception and real close-error context order,
       just as _io.open's error path. The extra actual .closed query is an
       explicit canonical-owner admission boundary, never fd-number inference. */
    PyObject *prior=PyErr_GetRaisedException();
    *ownership=1;
    PyObject *closed_result=PyObject_CallMethod(raw,"close",NULL);
    chain_raised(prior);Py_XDECREF(closed_result);
    PyObject *primary=PyErr_GetRaisedException();
    PyObject *closed=get_module_attr(raw,"closed");
    if(closed==Py_True){
        *ownership=3;
        Py_CLEAR(raw);
    }else{
        /* An unconfirmed close remains owned by a visible GC-tracked Session.
           It is not published as Popen.stdin/stdout/stderr, and the HIA close
           claim prevents a retry by raw fd. A finalizer remains hosted. */
        s->streams[index]=raw;s->stream_fds[index]=descriptor;raw=NULL;
        if(closed&&closed!=Py_False){
            PyErr_SetString(s->profile->unknown,"raw close state is not an exact bool");
        }
    }
    Py_XDECREF(closed);Py_XDECREF(value);Py_XDECREF(modeobj);
    chain_raised(primary);
    return -1;
}
}
static unsigned host_wrap(void *context,unsigned slot,int descriptor,unsigned *ownership,
                          const struct hia_cold_snapshot *f) {
    Session *s=context;PyObject *old=handled_enter(s);
    *ownership=0;
    int rc;
    if((slot!=2&&slot!=3&&slot!=5)||!f||!f->fds||descriptor<3||f->fds[slot]!=descriptor){
        PyErr_SetString(s->profile->unknown,"raw ownership request differs from its actual issued slot");rc=-1;
    }else rc=wrap_stream(s,slot,descriptor,ownership);
    unsigned error=rc<0?take_error(s):0;
    handled_leave(old);(void)f;return error;
}
static int audit_process(Session *s) {
    s->audit_args=PySequence_List(s->args);if(!s->audit_args)return -1;
    return PySys_Audit("subprocess.Popen","OOOO",PyList_GET_ITEM(s->audit_args,0),
                       s->audit_args,s->cwd,s->environment);
}
static int prepare_environment(Session *s) {
    if(s->linked)return 0;
    PyObject *items=PyMapping_Items(s->environment);if(!items)return -1;
    Py_ssize_t count=PyList_GET_SIZE(items);
    s->encoded_environment=PyList_New(0);
    if(!s->encoded_environment){Py_DECREF(items);return -1;}
    if((size_t)count>SIZE_MAX/sizeof(char *)-1){Py_DECREF(items);PyErr_NoMemory();return -1;}
    s->environment_native=calloc((size_t)count+1,sizeof(char *));
    if(!s->environment_native){Py_DECREF(items);PyErr_NoMemory();return -1;}
    for(Py_ssize_t i=0;i<count;++i){
        PyObject *pair=PyList_GET_ITEM(items,i);
        PyObject *encode=get_module_attr(s->profile->os,"fsencode");
        PyObject *key=encode?PyObject_CallOneArg(encode,PyTuple_GET_ITEM(pair,0)):NULL;
        Py_XDECREF(encode);
        if(!key){Py_DECREF(items);return -1;}
        if(!PyBytes_CheckExact(key)){
            Py_DECREF(key);Py_DECREF(items);PyErr_SetString(s->profile->unknown,"environment fsencode returned noncanonical bytes");return -1;
        }
        if(memchr(PyBytes_AS_STRING(key),'=',(size_t)PyBytes_GET_SIZE(key))){
            Py_DECREF(key);Py_DECREF(items);PyErr_SetString(PyExc_ValueError,"illegal environment variable name");return -1;
        }
        encode=get_module_attr(s->profile->os,"fsencode");
        PyObject *value=encode?PyObject_CallOneArg(encode,PyTuple_GET_ITEM(pair,1)):NULL;
        Py_XDECREF(encode);
        if(!value){Py_DECREF(key);Py_DECREF(items);return -1;}
        if(!PyBytes_CheckExact(value)||memchr(PyBytes_AS_STRING(key),0,(size_t)PyBytes_GET_SIZE(key))
            ||memchr(PyBytes_AS_STRING(value),0,(size_t)PyBytes_GET_SIZE(value))){
            Py_DECREF(key);Py_DECREF(value);Py_DECREF(items);
            PyErr_SetString(PyExc_ValueError,"embedded null byte");return -1;
        }
        Py_ssize_t kn=PyBytes_GET_SIZE(key),vn=PyBytes_GET_SIZE(value);
        if(kn>PY_SSIZE_T_MAX-vn-1){Py_DECREF(key);Py_DECREF(value);Py_DECREF(items);PyErr_NoMemory();return -1;}
        PyObject *entry=PyBytes_FromStringAndSize(NULL,kn+1+vn);
        if(!entry){Py_DECREF(key);Py_DECREF(value);Py_DECREF(items);return -1;}
        memcpy(PyBytes_AS_STRING(entry),PyBytes_AS_STRING(key),(size_t)kn);
        PyBytes_AS_STRING(entry)[kn]='=';
        memcpy(PyBytes_AS_STRING(entry)+kn+1,PyBytes_AS_STRING(value),(size_t)vn);
        Py_DECREF(key);Py_DECREF(value);
        if(PyList_Append(s->encoded_environment,entry)<0){Py_DECREF(entry);Py_DECREF(items);return -1;}
        s->environment_native[i]=PyBytes_AS_STRING(entry);Py_DECREF(entry);
    }
    Py_DECREF(items);s->config.environment=s->environment_native;return 0;
}
static int prepare_operands(Session *s) {
    if(prepare_environment(s)<0)return -1;
    if(!PyUnicode_FSConverter(s->cwd,&s->encoded_cwd))return -1;
    Py_ssize_t count=PyList_GET_SIZE(s->audit_args);
    s->encoded_args=PyTuple_New(count);if(!s->encoded_args)return -1;
    if((size_t)count>SIZE_MAX/sizeof(char *)){PyErr_NoMemory();return -1;}
    s->arguments_native=calloc((size_t)count? (size_t)count:1,sizeof(char *));
    if(!s->arguments_native){PyErr_NoMemory();return -1;}
    for(Py_ssize_t i=0;i<count;++i){
        PyObject *encoded=NULL;
        if(!PyUnicode_FSConverter(PyList_GET_ITEM(s->audit_args,i),&encoded))return -1;
        PyTuple_SET_ITEM(s->encoded_args,i,encoded);
        if(memchr(PyBytes_AS_STRING(encoded),0,(size_t)PyBytes_GET_SIZE(encoded))){
            PyErr_SetString(PyExc_ValueError,"embedded null byte");return -1;
        }
        if(i)s->arguments_native[i-1]=PyBytes_AS_STRING(encoded);
    }
    PyObject *borrowed[2]={s->output_fd,s->snapshot_fd};
    size_t used=0;
    for(unsigned i=0;i<(s->linked?2:1);++i)if(borrowed[i]!=Py_None){
        int fd=PyLong_AsInt(borrowed[i]);if(fd==-1&&PyErr_Occurred())return -1;
        if(fd<3){PyErr_SetString(PyExc_ValueError,"native profile pass_fds must name live outer descriptors >= 3");return -1;}
        int duplicate=0;
        for(size_t j=0;j<used;++j)if(s->borrowed[j]==fd)duplicate=1;
        if(!duplicate)s->borrowed[used++]=fd;
    }
    s->config.cwd=PyBytes_AS_STRING(s->encoded_cwd);
    s->config.arguments=(const char *const *)s->arguments_native;
    s->config.argument_count=count>0?(size_t)count-1:0;
    s->config.pass_fds=s->borrowed;s->config.pass_fd_count=used;
    return 0;
}
static unsigned host_perform(void *context,unsigned action,unsigned arg,
                             const struct hia_cold_snapshot *f) {
    Session *s=context;PyObject *old=handled_enter(s);int rc=0;
    if(action==HCT_HOST_INIT)rc=init_owner(s,f);
    else if(action==HCT_HOST_WRAP){
        PyErr_SetString(s->profile->unknown,"raw stream construction requires its explicit ownership-receipt capability");rc=-1;
    }
    else if(action==HCT_HOST_AUDIT)rc=audit_process(s);
    else if(action==HCT_HOST_PREPARE)rc=prepare_operands(s);
    else if(action==HCT_HOST_ENTER){
        if(set_object(s->owner,"_closed_child_pipe_fds",Py_True)<0)rc=-1;
        else{
            PyObject *entered=PyObject_CallMethod(s->owner,"__enter__",NULL);
            if(!entered)rc=-1;
            else{if(entered!=s->owner){PyErr_SetString(s->profile->unknown,"Popen context returned another owner");rc=-1;}Py_DECREF(entered);}
        }
        if(!rc){
            /* These were _execute_child temporaries. The parent no longer
               needs their encoded pointers after the exec handshake. */
            Py_CLEAR(s->audit_args);Py_CLEAR(s->encoded_cwd);Py_CLEAR(s->encoded_args);Py_CLEAR(s->encoded_environment);
            free(s->environment_native);s->environment_native=NULL;s->config.environment=NULL;
            free(s->arguments_native);s->arguments_native=NULL;
            s->config.arguments=NULL;s->config.argument_count=0;s->config.cwd=NULL;
        }
    }else if(action==HCT_HOST_FLUSH){
        PyObject *done=PyObject_CallMethod(s->streams[0],"flush",NULL);
        if(!done){
            if(PyErr_ExceptionMatches(PyExc_BrokenPipeError))PyErr_Clear();
            else rc=-1;
        }else Py_DECREF(done);
        if(!rc&&(set_object(s->owner,"_input",s->input)<0
                ||set_long(s->owner,"_input_offset",0)<0))rc=-1;
    }else{PyErr_SetString(s->profile->unknown,"unknown hosted mechanical action");rc=-1;}
    unsigned error=rc<0?take_error(s):0;
    handled_leave(old);return error;
}
static unsigned host_close(void *context,unsigned slot,int fd,int *retired,
                           const struct hia_cold_snapshot *f) {
    Session *s=context;PyObject *old=handled_enter(s);unsigned error=0;
    *retired=0;
    unsigned index=slot==2?0:slot==3?1:slot==5?2:3;
    if(index<3&&s->streams[index]){
        PyObject *done=PyObject_CallMethod(s->streams[index],"close",NULL);
        PyObject *raised=NULL;
        if(!done)raised=PyErr_GetRaisedException();else Py_DECREF(done);
        PyObject *closed=get_module_attr(s->streams[index],"closed");
        if(!closed){
            Py_XDECREF(raised);error=take_error(s);
        }else{
            if(closed!=Py_True&&closed!=Py_False){
                PyErr_SetString(s->profile->unknown,"binary stream close did not expose a boolean physical state");
                Py_XDECREF(raised);error=take_error(s);
            }else if(raised){
                *retired=closed==Py_True;
                int suppress=!f->context_entered
                    &&PyErr_GivenExceptionMatches(raised,PyExc_OSError);
                if(suppress){
                    /* The constructor's exact except OSError discards this
                       error; the previously pending exception remains active. */
                    PyObject *number=PyObject_GetAttrString(raised,"errno");
                    long value=number&&PyLong_CheckExact(number)?PyLong_AsLong(number):0;
                    Py_XDECREF(number);
                    if(PyErr_Occurred())PyErr_Clear();
                    error=value>0&&value<4096?(unsigned)value:EIO;
                    Py_DECREF(raised);
                }else{
                    PyErr_SetRaisedException(raised);error=take_error(s);
                }
            }else *retired=closed==Py_True;
            Py_DECREF(closed);
        }
    }else{
        PyThreadState *thread=PyEval_SaveThread();
        int rc=close(fd),number=errno;
        PyEval_RestoreThread(thread);
        *retired=1;
        if(rc!=0){
            error=number>0?(unsigned)number:EIO;
            if(!(f->phase==53&&!f->context_entered&&slot!=0&&slot!=7&&slot!=8)){
                errno=(int)error;PyErr_SetFromErrno(PyExc_OSError);(void)take_error(s);
            }
        }
    }
    handled_leave(old);return error;
}
static unsigned host_error(void *context,unsigned action,unsigned arg,unsigned error,
                           const struct hia_cold_snapshot *f) {
    Session *s=context;
    if(error==HCT_PY_EXCEPTION||error==HCT_PY_KEYBOARD)return error;
    if(error==EINTR){
        PyObject *old=handled_enter(s);unsigned result=error;
        if(PyErr_CheckSignals()<0)result=take_error(s);
        handled_leave(old);return result;
    }
    if(action==HCT_STDIN_WRITE&&error==EPIPE)return error;
    if(action==HCT_KILL&&error==ESRCH)return error;
    if(action==HCT_CLOSE){
        /* host_close already captured or deliberately suppressed the actual
           Python exception. Do not manufacture a second exception identity. */
        return error;
    }
    PyObject *old=handled_enter(s);
    errno=(int)error;PyErr_SetFromErrno(PyExc_OSError);
    (void)take_error(s);
    handled_leave(old);(void)arg;(void)f;return error;
}
static int host_handoff(void *context,const struct hia_cold_snapshot *f) {
    Session *s=context;PyObject *old=handled_enter(s);int rc=0;
    int adopted[9];
    for(unsigned slot=0;slot<9;++slot)adopted[slot]=s->raw_fds[slot];
    /* Validation owns no new raw number. A later fileno/owner failure cannot
       leave a Session alias to a number still governed by dispatcher cleanup. */
    if(s->handoff){
        PyErr_SetString(s->profile->unknown,"a Session cannot accept a second resource handoff");
        (void)take_error(s);rc=-1;
    }
    if(!rc&&sync_owner(s,f)<0){(void)take_error(s);rc=-1;}
    if(!rc&&f->pid>0&&!f->reaped&&!f->owner_lost&&!s->owner){
        PyErr_SetString(s->profile->unknown,"handoff has no real Popen child owner");
        (void)take_error(s);rc=-1;
    }
    if(!rc)for(unsigned slot=0;slot<9;++slot)if(f->fds[slot]>=0){
        unsigned index=slot==2?0:slot==3?1:slot==5?2:3;
        if(index<3&&s->streams[index]){
            PyObject *actual=PyObject_CallMethod(s->streams[index],"fileno",NULL);
            if(!actual){(void)take_error(s);rc=-1;break;}
            long fd=PyLong_AsLong(actual);Py_DECREF(actual);
            if(PyErr_Occurred()){(void)take_error(s);rc=-1;break;}
            if(fd!=f->fds[slot]){
                PyErr_SetString(s->profile->unknown,"handoff stream does not own the actual remaining descriptor");
                (void)take_error(s);rc=-1;break;
            }
        }else{
            if(adopted[slot]>=0&&adopted[slot]!=f->fds[slot]){
                PyErr_SetString(s->profile->unknown,"handoff attempted to replace a live raw descriptor owner");
                (void)take_error(s);rc=-1;break;
            }
            adopted[slot]=f->fds[slot];
        }
    }
    /* Restore the caller state before the commit. There are no allocations,
       Python calls, decrefs, error paths or FD operations after this boundary. */
    handled_leave(old);
    if(rc)return -1;
    for(unsigned slot=0;slot<9;++slot)s->raw_fds[slot]=adopted[slot];
    s->handoff=1;
    return 0;
}
static void host_block_enter(void *context) {
    Session *s=context;s->released=PyEval_SaveThread();
}
static void host_block_leave(void *context) {
    Session *s=context;PyThreadState *thread=s->released;s->released=NULL;PyEval_RestoreThread(thread);
}
/* Result slots are the dispatcher's actual still-owned resources. Preserve
 * them even if every fallible host_handoff was refused. This terminal adoption
 * performs no allocation, call, decref or syscall, never changes HIA success,
 * and does not replace an existing raw or canonical stream owner. */
static void keep_terminal_fds(Session *s) {
    for(unsigned slot=0;slot<9;++slot){
        int fd=s->result.remaining_fds[slot];
        if(fd<0)continue;
        int already=0;
        for(unsigned i=0;i<9;++i)
            if(s->raw_fds[i]==fd || ((s->residual_fd_mask&(UINT64_C(1)<<i))&&s->residual_fds[i]==fd))
                already=1;
        for(unsigned i=0;i<3;++i)if(s->streams[i]&&s->stream_fds[i]==fd)already=1;
        if(!already){
            s->residual_fds[slot]=fd;s->residual_fd_mask|=UINT64_C(1)<<slot;
        }
    }
}
static PyObject *session_run(Session *s,PyObject *unused) {
    (void)unused;
    if(!s->profile||!s->profile->initialized){
        PyErr_SetString(PyExc_RuntimeError,"native cold Session has no live Profile");
        return NULL;
    }
    if(s->started||s->creator_pid!=getpid()||s->creator_thread!=PyThread_get_thread_ident()
        ||!profile_current(s->profile)){
        if(!PyErr_Occurred())PyErr_SetString(s->profile->unknown,"Session is single-use in its original process/thread");
        return NULL;
    }
    s->started=1;s->caller=PyErr_GetHandledException();
    ++s->profile->calls;
    int rc=hia_cold_transport_run(s->profile->policy,&s->config,&s->result,NULL,0);
    keep_terminal_fds(s);
    s->finished=1;s->profile->entries+=s->result.action_count;
    if(s->result.policy_complete)++s->profile->completed;
    if(s->result.handed_off)++s->profile->handed_off;
    if(rc<0)++s->profile->unknowns;
    struct hia_cold_snapshot terminal={0};
    terminal.pid=s->result.child_pid;terminal.reaped=s->result.reaped;
    terminal.owner_lost=s->result.owner_lost;terminal.wait_status=s->result.wait_status;
    terminal.outcome=s->result.outcome;terminal.error=s->result.primary_errno;
    terminal.stage=s->result.primary_stage;
    terminal.stdout_bytes=s->result.stdout_bytes;terminal.stderr_bytes=s->result.stderr_bytes;
    terminal.stdout_size=s->result.stdout_size;terminal.stderr_size=s->result.stderr_size;
    terminal.stdout_reads=s->result.stdout_reads;terminal.stderr_reads=s->result.stderr_reads;
    PyObject *old=handled_enter(s);
    if(sync_owner(s,&terminal)<0)(void)take_error(s);
    if(rc<0){
        PyErr_SetHandledException(s->pending?s->pending:s->caller);
        PyErr_SetString(s->profile->unknown,"native policy did not establish an acknowledged terminal child result");
        (void)take_error(s);
    }else if(make_pending(s,&terminal)<0)(void)take_error(s);
    handled_leave(old);
    if(s->pending){
        PyObject *error=s->pending;s->pending=NULL;
        Py_CLEAR(s->caller);hia_cold_transport_release(&s->result);
        PyErr_SetRaisedException(error);return NULL;
    }
    if(rc!=0||s->result.outcome!=HCT_RETURNED||!s->result.reaped
        ||s->result.final_fd_mask||s->result.handed_off){
        Py_CLEAR(s->caller);hia_cold_transport_release(&s->result);
        PyErr_SetString(s->profile->unknown,"native terminal receipt is not a complete returned invocation");return NULL;
    }
    PyObject *out=PyBytes_FromStringAndSize((const char *)s->result.stdout_bytes,(Py_ssize_t)s->result.stdout_size);
    PyObject *err=PyBytes_FromStringAndSize((const char *)s->result.stderr_bytes,(Py_ssize_t)s->result.stderr_size);
    PyObject *kind=out&&err?get_module_attr(s->profile->subprocess,"CompletedProcess"):NULL;
    PyObject *code=kind?PyLong_FromLong(s->result.returncode):NULL;
    PyObject *result=code?PyObject_CallFunctionObjArgs(kind,s->args,code,out,err,NULL):NULL;
    Py_XDECREF(out);Py_XDECREF(err);Py_XDECREF(kind);Py_XDECREF(code);
    Py_CLEAR(s->caller);hia_cold_transport_release(&s->result);
    return result;
}
static PyObject *session_receipt(Session *s,PyObject *unused) {
    (void)unused;
    return Py_BuildValue("{s:O,s:O,s:K,s:K,s:i,s:i,s:i,s:i,s:K,s:K,s:L,s:O,s:K}",
        "started",s->started?Py_True:Py_False,"finished",s->finished?Py_True:Py_False,
        "nonce",(unsigned long long)s->result.nonce,"entries",(unsigned long long)s->result.action_count,
        "outcome",(int)s->result.outcome,"policy_complete",(int)s->result.policy_complete,
        "reaped",(int)s->result.reaped,"owner_lost",(int)s->result.owner_lost,
        "final_fd_mask",(unsigned long long)s->result.final_fd_mask,
        "handoff_fd_mask",(unsigned long long)s->result.handoff_fd_mask,
        "handoff_pid",(long long)s->result.handoff_pid,"handed_off",s->result.handed_off?Py_True:Py_False,
        "residual_fd_mask",(unsigned long long)s->residual_fd_mask);
}
static PyObject *profile_session(Profile *p,PyObject *args) {
    PyObject *executable,*input,*cwd,*timeout,*arguments,*output,*snapshot_fd;
    int linked;
    if(!PyArg_ParseTuple(args,"OOOOOOOp:session",&executable,&input,&cwd,&timeout,
                         &arguments,&output,&snapshot_fd,&linked))return NULL;
    if(!profile_current(p))return NULL;
    if(!PyBytes_CheckExact(executable)||!PyBytes_CheckExact(input)){
        PyErr_SetString(PyExc_TypeError,"explicit native cold profile requires exact executable/request bytes");return NULL;
    }
    if(!PyFloat_CheckExact(timeout)&&!PyLong_CheckExact(timeout)){
        PyErr_SetString(PyExc_TypeError,"explicit native cold timeout must be an exact finite int or float");return NULL;
    }
    double seconds=PyFloat_AsDouble(timeout);
    if(PyErr_Occurred())return NULL;
    if(!isfinite(seconds)||seconds>9223372036.0){
        PyErr_SetString(PyExc_ValueError,"native cold timeout is outside the admitted finite nanosecond range");return NULL;
    }
    uint64_t ns=seconds<=0?0:(uint64_t)(seconds*1000000000.0);
    if(p->nonce==UINT64_MAX){PyErr_SetString(p->unknown,"native cold nonce space exhausted");return NULL;}
    module_state *m=PyType_GetModuleState(Py_TYPE(p));if(!m)return NULL;
    Session *s=(Session *)((PyTypeObject *)m->session_type)->tp_alloc((PyTypeObject *)m->session_type,0);
    if(!s)return NULL;
    for(unsigned i=0;i<9;++i)s->raw_fds[i]=-1;
    s->profile=(Profile *)Py_NewRef(p);s->executable=Py_NewRef(executable);s->input=Py_NewRef(input);
    s->cwd=Py_NewRef(cwd);s->timeout=Py_NewRef(timeout);s->arguments=Py_NewRef(arguments);
    s->output_fd=Py_NewRef(output);s->snapshot_fd=Py_NewRef(snapshot_fd);s->linked=(unsigned)linked;
    s->creator_pid=getpid();s->creator_thread=PyThread_get_thread_ident();
    s->host=(struct hia_cold_host){s,host_before,host_perform,host_close,host_error,host_handoff,
                                  host_block_enter,host_block_leave,host_wrap};
    s->config=(struct hia_cold_config){
        (const unsigned char *)PyBytes_AS_STRING(executable),(size_t)PyBytes_GET_SIZE(executable),
        (const unsigned char *)PyBytes_AS_STRING(input),(size_t)PyBytes_GET_SIZE(input),
        NULL,NULL,0,NULL,0,ns,++p->nonce,(unsigned)linked,&s->host,NULL
    };
    return (PyObject *)s;
}
static PyObject *profile_statistics(Profile *p,PyObject *unused) {
    (void)unused;
    if(!profile_current(p))return NULL;
    return Py_BuildValue("{s:K,s:K,s:K,s:K,s:K,s:L,s:O}",
        "calls",(unsigned long long)p->calls,"entries",(unsigned long long)p->entries,
        "policy_complete",(unsigned long long)p->completed,"handed_off",(unsigned long long)p->handed_off,
        "unknown",(unsigned long long)p->unknowns,"creator_pid",(long long)p->creator_pid,
        "source_identity_sha256",p->identity?p->identity:Py_None);
}
static PyMethodDef profile_methods[]={
    {"session",(PyCFunction)profile_session,METH_VARARGS,NULL},
    {"statistics",(PyCFunction)profile_statistics,METH_NOARGS,NULL},{NULL,NULL,0,NULL}};
static PyMethodDef session_methods[]={
    {"run",(PyCFunction)session_run,METH_NOARGS,NULL},
    {"receipt",(PyCFunction)session_receipt,METH_NOARGS,NULL},{NULL,NULL,0,NULL}};
static PyType_Slot profile_slots[]={
    {Py_tp_init,profile_init},{Py_tp_new,PyType_GenericNew},{Py_tp_dealloc,profile_dealloc},
    {Py_tp_traverse,profile_traverse},{Py_tp_clear,profile_clear},{Py_tp_methods,profile_methods},{0,NULL}};
static PyObject *session_new(PyTypeObject *type,PyObject *args,PyObject *kwargs){
    (void)type;(void)args;(void)kwargs;
    PyErr_SetString(PyExc_TypeError,"Session objects are created only by an admitted Profile.session");return NULL;
}
static PyType_Slot session_slots[]={
    {Py_tp_new,session_new},
    {Py_tp_dealloc,session_dealloc},{Py_tp_traverse,session_traverse},{Py_tp_clear,session_clear},
    {Py_tp_methods,session_methods},{0,NULL}};
static PyType_Spec profile_spec={"_hia_cold_native_transport.Profile",sizeof(Profile),0,
    Py_TPFLAGS_DEFAULT|Py_TPFLAGS_HAVE_GC,profile_slots};
static PyType_Spec session_spec={"_hia_cold_native_transport.Session",sizeof(Session),0,
    Py_TPFLAGS_DEFAULT|Py_TPFLAGS_HAVE_GC,session_slots};
static int module_traverse(PyObject *module,visitproc visit,void *arg){
    module_state *m=PyModule_GetState(module);Py_VISIT(m->unknown);Py_VISIT(m->profile_type);Py_VISIT(m->session_type);return 0;
}
static int module_clear(PyObject *module){
    module_state *m=PyModule_GetState(module);Py_CLEAR(m->unknown);Py_CLEAR(m->profile_type);Py_CLEAR(m->session_type);return 0;
}
static int module_exec(PyObject *module){
    module_state *m=PyModule_GetState(module);
    m->unknown=PyErr_NewException("_hia_cold_native_transport.NativeColdTransportUnknown",PyExc_RuntimeError,NULL);
    m->profile_type=PyType_FromModuleAndSpec(module,&profile_spec,NULL);
    m->session_type=PyType_FromModuleAndSpec(module,&session_spec,NULL);
    if(!m->unknown||!m->profile_type||!m->session_type)return -1;
    if(PyModule_AddObjectRef(module,"NativeColdTransportUnknown",m->unknown)<0
       ||PyModule_AddObjectRef(module,"Profile",m->profile_type)<0
       ||PyModule_AddObjectRef(module,"Session",m->session_type)<0
       ||PyModule_AddIntConstant(module,"ABI",3)<0
       ||PyModule_AddIntConstant(module,"ACTIONS",25)<0
       ||PyModule_AddIntConstant(module,"MAJOR",PY_MAJOR_VERSION)<0
       ||PyModule_AddIntConstant(module,"MINOR",PY_MINOR_VERSION)<0)return -1;
    return 0;
}
static PyModuleDef_Slot module_slots[]={{Py_mod_exec,module_exec},{0,NULL}};
static struct PyModuleDef definition={PyModuleDef_HEAD_INIT,"_hia_cold_native_transport",NULL,
    sizeof(module_state),NULL,module_slots,module_traverse,module_clear,NULL};
PyMODINIT_FUNC PyInit__hia_cold_native_transport(void){return PyModuleDef_Init(&definition);}
