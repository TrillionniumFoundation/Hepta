/* Mechanical Slot continuation transport.
 *
 * CPython 3.11--3.14, GIL-enabled Linux; not the limited/stable ABI.
 * No Slot business graph, SQLite, provider policy, traceback editing or GC
 * collection lives here.  The admitted HIA image issues every effect.
 *
 * Public Vectorcall arguments remain borrowed from the real caller.  This
 * extension never steals or clears that vector.  Equivalence of that ownership
 * boundary to a direct interpreter CALL is an explicit qualification question.
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <frameobject.h>
#include <structmember.h>
#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>

#if PY_VERSION_HEX < 0x030b0000 || PY_VERSION_HEX >= 0x030f0000
#error "Slot mechanical transport currently supports CPython 3.11 through 3.14"
#endif
#ifdef Py_GIL_DISABLED
#error "Slot mechanical transport has not admitted the free-threaded profile"
#endif

enum { INITIALIZE=0, CLAIM=1, SUCCEEDED=2, RAISED=3, FINALIZE=4 };
enum { ISSUED=1, CLAIMED=2, RETURNED=4, PROPAGATE=5,
       READY_RETURN=6, READY_PROPAGATE=7 };
enum { AND_OPEN=28, AND_KEYS=29, AND_FALSE=30, AND_UNWIND=37,
       ITER_OPEN=74, ITER_NEXT=75, ITER_FOLD=76, ITER_DONE=77, ITER_UNWIND=83,
       LEASE_OPEN=127, LEASE_TRUTH=128, LEASE_RELEASE=129,
       LEASE_CHECK=130, LEASE_UNWIND=132 };


/* Revalidate immutable, already admitted file observations.  The caller owns
 * schema/digest admission and the live authority scope.  This primitive neither
 * decodes a manifest nor manufactures authority; it repeats the actual POSIX
 * reads and exact byte/stat comparisons without rebuilding Python snapshots.
 * Only exact immutable str/bytes are retained, never a provider or scope. */
#define ADMISSION_FILES_NAME "hepta.slot.mechanical.file-observations.v1"
typedef struct {
    PyObject *path, *encoded, *raw, *content_error, *identity_error;
    struct stat expected;
    Py_ssize_t limit;
    int canonical;
} AdmissionFile;
typedef struct {
    PyInterpreterState *interpreter; /* identity only; no owning Python edge */
    Py_ssize_t count;
    AdmissionFile *files;
} AdmissionFiles;
static void admission_files_free(AdmissionFiles *files) {
    if (files == NULL) return;
    for (Py_ssize_t i=0;i<files->count;i++) {
        AdmissionFile *f=&files->files[i];
        Py_XDECREF(f->path); Py_XDECREF(f->encoded);
        Py_XDECREF(f->raw); Py_XDECREF(f->content_error); Py_XDECREF(f->identity_error);
    }
    PyMem_Free(files->files); PyMem_Free(files);
}
static void admission_files_destroy(PyObject *capsule) {
    AdmissionFiles *files=PyCapsule_GetPointer(capsule,ADMISSION_FILES_NAME);
    if (files != NULL) admission_files_free(files);
    else PyErr_WriteUnraisable(capsule);
}
static int admission_changed(AdmissionFile *f) {
    PyErr_SetObject(PyExc_ValueError,f->identity_error); return -1;
}
static int admission_content_changed(AdmissionFile *f) {
    PyErr_SetObject(PyExc_ValueError,f->content_error); return -1;
}
static int admission_stat_equal(const struct stat *a,const struct stat *b) {
    return a->st_dev==b->st_dev && a->st_ino==b->st_ino &&
        a->st_size==b->st_size && a->st_mtim.tv_sec==b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec==b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec==b->st_ctim.tv_sec &&
        a->st_ctim.tv_nsec==b->st_ctim.tv_nsec && a->st_mode==b->st_mode &&
        a->st_uid==b->st_uid && a->st_nlink==b->st_nlink;
}
/* Match POSIX builtin I/O: other threads can run during filesystem calls.
 * The immutable observation table survives reentry; no descriptor is cached. */
static int admission_open(const char *path) {
    int result,saved_errno;
    Py_BEGIN_ALLOW_THREADS
    result=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK); saved_errno=errno;
    Py_END_ALLOW_THREADS
    errno=saved_errno; return result;
}
static int admission_fstat(int fd,struct stat *value) {
    int result,saved_errno;
    Py_BEGIN_ALLOW_THREADS
    result=fstat(fd,value); saved_errno=errno;
    Py_END_ALLOW_THREADS
    errno=saved_errno; return result;
}
static int admission_lstat(const char *path,struct stat *value) {
    int result,saved_errno;
    Py_BEGIN_ALLOW_THREADS
    result=lstat(path,value); saved_errno=errno;
    Py_END_ALLOW_THREADS
    errno=saved_errno; return result;
}
static ssize_t admission_read(int fd,char *buffer,size_t count) {
    ssize_t result; int saved_errno;
    Py_BEGIN_ALLOW_THREADS
    result=read(fd,buffer,count); saved_errno=errno;
    Py_END_ALLOW_THREADS
    errno=saved_errno; return result;
}
static int admission_close(int fd) {
    int result,saved_errno;
    Py_BEGIN_ALLOW_THREADS
    result=close(fd); saved_errno=errno;
    Py_END_ALLOW_THREADS
    errno=saved_errno; return result;
}
static int admission_canonical(AdmissionFile *f) {
    const char *path=PyBytes_AS_STRING(f->encoded);
    char *resolved; int same,saved_errno;
    Py_BEGIN_ALLOW_THREADS
    resolved=realpath(path,NULL); saved_errno=errno;
    Py_END_ALLOW_THREADS
    errno=saved_errno;
    if (resolved == NULL) {
        PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError,f->path); return -1;
    }
    same=strcmp(path,resolved)==0; free(resolved);
    if (!same) {
        PyErr_SetString(PyExc_ValueError,
                       "Slot authority must use its exact canonical package path");
        return -1;
    }
    return 0;
}
static int admission_file_check(AdmissionFile *f) {
    const char *path=PyBytes_AS_STRING(f->encoded),*expected=PyBytes_AS_STRING(f->raw);
    Py_ssize_t length=PyBytes_GET_SIZE(f->raw),position=0;
    struct stat before,after,path_before,path_after;
    char buffer[65536]; int fd=-1,result=-1;
    if (f->canonical) {
        if (admission_canonical(f)<0) return -1;
        if (admission_lstat(path,&path_before)<0) {
            PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError,f->path); return -1;
        }
    }
    do { fd=admission_open(path); }
    while (fd<0 && errno==EINTR && PyErr_CheckSignals()==0);
    if (fd<0) {
        if (!PyErr_Occurred()) PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError,f->path);
        return -1;
    }
    if (admission_fstat(fd,&before)<0) {
        PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError,f->path); goto done;
    }
    if (!S_ISREG(before.st_mode) || before.st_nlink!=1 ||
        (before.st_uid!=0 && before.st_uid!=getuid()) ||
        (before.st_mode & 0022) || before.st_size<=0 || before.st_size>f->limit) {
        PyErr_SetString(PyExc_ValueError,
                       "native helper input must be an owned bounded ordinary file");
        goto done;
    }
    if (f->canonical && (before.st_dev!=path_before.st_dev || before.st_ino!=path_before.st_ino)) {
        admission_changed(f); goto done;
    }
    if (before.st_size!=length) { admission_content_changed(f); goto done; }
    while (position<length) {
        size_t wanted=(size_t)(length-position);
        ssize_t count;
        if (wanted>sizeof(buffer)) wanted=sizeof(buffer);
        count=admission_read(fd,buffer,wanted);
        if (count<0) {
            if (errno==EINTR && PyErr_CheckSignals()==0) continue;
            if (!PyErr_Occurred()) PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError,f->path);
            goto done;
        }
        if (PyErr_CheckSignals()<0) goto done;
        if (count==0 || memcmp(buffer,expected+position,(size_t)count)!=0) {
            admission_content_changed(f); goto done;
        }
        position+=count;
    }
    for (;;) {
        ssize_t count=admission_read(fd,buffer,1);
        if (count<0) {
            if (errno==EINTR && PyErr_CheckSignals()==0) continue;
            if (!PyErr_Occurred()) PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError,f->path);
            goto done;
        }
        if (count!=0) { admission_content_changed(f); goto done; }
        break;
    }
    if (admission_fstat(fd,&after)<0) {
        PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError,f->path); goto done;
    }
    if (!admission_stat_equal(&before,&after) ||
        !admission_stat_equal(&before,&f->expected)) {
        admission_changed(f); goto done;
    }
    if (f->canonical) {
        if (admission_lstat(path,&path_after)<0) {
            PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError,f->path); goto done;
        }
        if (!admission_stat_equal(&after,&path_after)) { admission_changed(f); goto done; }
        if (admission_canonical(f)<0) goto done;
    }
    result=0;
done:
    /* A descriptor close is attempted exactly once, including EINTR. */
    if (admission_close(fd)<0) {
        PyErr_SetFromErrnoWithFilenameObject(PyExc_OSError,f->path); result=-1;
    }
    return result;
}
static int admission_files_check(AdmissionFiles *files) {
    if (files->interpreter!=PyThreadState_GetInterpreter(PyThreadState_Get())) {
        PyErr_SetString(PyExc_ValueError,"file observations belong to their original interpreter");
        return -1;
    }
    for (Py_ssize_t i=0;i<files->count;i++)
        if (PyErr_CheckSignals()<0 || admission_file_check(&files->files[i])<0) return -1;
    return PyErr_CheckSignals();
}
static int admission_time(PyObject *value,struct timespec *result) {
    PyObject *scale=PyLong_FromLong(1000000000),*pair;
    long long seconds; long nanos;
    if (scale==NULL) return -1;
    pair=PyNumber_Divmod(value,scale); Py_DECREF(scale);
    if (pair==NULL) return -1;
    seconds=PyLong_AsLongLong(PyTuple_GET_ITEM(pair,0));
    nanos=PyLong_AsLong(PyTuple_GET_ITEM(pair,1)); Py_DECREF(pair);
    if (PyErr_Occurred()) return -1;
    result->tv_sec=(time_t)seconds; result->tv_nsec=nanos;
    return 0;
}
static int admission_stat(PyObject *values,struct stat *s) {
    unsigned long long fields[8]={0};
    if (!PyTuple_CheckExact(values) || PyTuple_GET_SIZE(values)!=8) {
        PyErr_SetString(PyExc_TypeError,"file observations require eight exact stat fields"); return -1;
    }
    for (int i=0;i<8;i++) {
        PyObject *value=PyTuple_GET_ITEM(values,i);
        if (!PyLong_CheckExact(value)) {
            PyErr_SetString(PyExc_TypeError,"file observation stat fields must be exact integers"); return -1;
        }
        if (i==3 || i==4) continue;
        fields[i]=PyLong_AsUnsignedLongLong(value);
        if (PyErr_Occurred()) return -1;
    }
    if (admission_time(PyTuple_GET_ITEM(values,3),&s->st_mtim)<0 ||
        admission_time(PyTuple_GET_ITEM(values,4),&s->st_ctim)<0) return -1;
    s->st_dev=(dev_t)fields[0]; s->st_ino=(ino_t)fields[1]; s->st_size=(off_t)fields[2];
    s->st_mode=(mode_t)fields[5]; s->st_uid=(uid_t)fields[6]; s->st_nlink=(nlink_t)fields[7];
    if ((unsigned long long)s->st_dev!=fields[0] || (unsigned long long)s->st_ino!=fields[1] ||
        s->st_size<0 || (unsigned long long)s->st_size!=fields[2] ||
        (unsigned long long)s->st_mode!=fields[5] || (unsigned long long)s->st_uid!=fields[6] ||
        (unsigned long long)s->st_nlink!=fields[7]) {
        PyErr_SetString(PyExc_OverflowError,"file observation stat field exceeds its native type"); return -1;
    }
    return 0;
}
static PyObject *admission_files(PyObject *module,PyObject *rows) {
    AdmissionFiles *files=NULL; Py_ssize_t count; PyObject *capsule;
    (void)module;
    if (!PyTuple_CheckExact(rows) || (count=PyTuple_GET_SIZE(rows))<1) {
        PyErr_SetString(PyExc_TypeError,"file observations require a nonempty exact tuple"); return NULL;
    }
    if ((size_t)count>SIZE_MAX/sizeof(AdmissionFile)) return PyErr_NoMemory();
    files=PyMem_Calloc(1,sizeof(*files));
    if (files==NULL) return PyErr_NoMemory();
    files->files=PyMem_Calloc((size_t)count,sizeof(AdmissionFile));
    if (files->files==NULL) { PyMem_Free(files); return PyErr_NoMemory(); }
    files->count=count; files->interpreter=PyThreadState_GetInterpreter(PyThreadState_Get());
    for (Py_ssize_t i=0;i<count;i++) {
        PyObject *row=PyTuple_GET_ITEM(rows,i),*path,*raw,*limit,*canonical,*message,*identity_message;
        AdmissionFile *f=&files->files[i]; long flag;
        if (!PyTuple_CheckExact(row) || PyTuple_GET_SIZE(row)!=7) {
            PyErr_SetString(PyExc_TypeError,"file observation rows require seven exact fields"); goto fail;
        }
        path=PyTuple_GET_ITEM(row,0); raw=PyTuple_GET_ITEM(row,1);
        limit=PyTuple_GET_ITEM(row,3); canonical=PyTuple_GET_ITEM(row,4); message=PyTuple_GET_ITEM(row,5);
        identity_message=PyTuple_GET_ITEM(row,6);
        if (!PyUnicode_CheckExact(path) || !PyBytes_CheckExact(raw) ||
            !PyLong_CheckExact(limit) || !PyLong_CheckExact(canonical) ||
            !PyUnicode_CheckExact(message) || !PyUnicode_CheckExact(identity_message)) {
            PyErr_SetString(PyExc_TypeError,"file observations accept only exact immutable fields"); goto fail;
        }
        f->path=Py_NewRef(path); f->raw=Py_NewRef(raw); f->content_error=Py_NewRef(message);
        f->identity_error=Py_NewRef(identity_message);
        f->encoded=PyUnicode_EncodeFSDefault(path);
        if (f->encoded==NULL) goto fail;
        if (PyBytes_GET_SIZE(f->encoded)==0 ||
            strlen(PyBytes_AS_STRING(f->encoded))!=(size_t)PyBytes_GET_SIZE(f->encoded)) {
            PyErr_SetString(PyExc_ValueError,"file observation path must be nonempty and NUL-free"); goto fail;
        }
        f->limit=PyLong_AsSsize_t(limit); flag=PyLong_AsLong(canonical);
        if (PyErr_Occurred()) goto fail;
        if (f->limit<1 || PyBytes_GET_SIZE(raw)<1 || PyBytes_GET_SIZE(raw)>f->limit || (flag!=0 && flag!=1)) {
            PyErr_SetString(PyExc_ValueError,"file observation extent or canonical flag differs"); goto fail;
        }
        f->canonical=(int)flag;
        if (admission_stat(PyTuple_GET_ITEM(row,2),&f->expected)<0) goto fail;
    }
    if (admission_files_check(files)<0) goto fail;
    capsule=PyCapsule_New(files,ADMISSION_FILES_NAME,admission_files_destroy);
    if (capsule==NULL) goto fail;
    return capsule;
fail:
    admission_files_free(files); return NULL;
}
static PyObject *admission_check(PyObject *module,PyObject *capsule) {
    AdmissionFiles *files; (void)module;
    files=PyCapsule_GetPointer(capsule,ADMISSION_FILES_NAME);
    if (files==NULL || admission_files_check(files)<0) return NULL;
    Py_RETURN_NONE;
}

typedef struct {
    PyObject *session_type, *method_type, *iterator_type, *current, *loss_name;
    PyObject *foreign_observed_names, *foreign_ambient_names, *confirmed_names;
    pid_t counter_pid;
    unsigned long long public_calls[16], raw_frame_calls[16];
    unsigned long long initialized_calls[16], final_receipts[16];
    int counter_overflow;
} ModuleState;

typedef struct {
    PyObject_HEAD
    vectorcallfunc vectorcall;
    PyObject *module, *function, *binding, *frame_type, *unknown, *admission;
    int mode;
} Method;

typedef struct Session {
    PyObject_HEAD
    PyObject *module, *function, *binding, *frame_type, *unknown, *admission;
    PyObject *frame, *record, *series, *ambient, *ambient_exit;
    PyObject *series_exit, *pending, *pending_exit, *context_token;
    PyObject *sql_attempt, *retained_frame, *iterator_custody;
    PyFrameObject *caller_identity; /* borrowed; valid only during outer call */
    void *iterator_identity;        /* borrowed; never an owning registry key */
    unsigned long thread;
    pid_t pid;
    int mode, active, started, initiating, initialized, effect_started;
    int outcome_unconfirmed, foreign_open, ambient_open, series_open;
    int ready_outcome, final_receipt, failed, iterator_live, iterator_exhausted;
} Session;

typedef struct {
    PyObject_HEAD
    Session *session;
    PyObject *iterator;
    int exhausted;
} Iteration;

static ModuleState *state(PyObject *module) {
    return (ModuleState *)PyModule_GetState(module);
}
/* Read-only process-local evidence. No reset API, Python allocation, tracing,
 * altered result or simulated work occurs when recording an entry. Forked
 * children start their own PID epoch; inherited parent counts are not theirs.
 * Saturation is explicitly reported and makes qualification refuse. */
static ModuleState *counter_state(PyObject *module) {
    ModuleState *m=state(module);
    pid_t pid=getpid();
    if (m->counter_pid != pid) {
        m->counter_pid=pid;
        memset(m->public_calls,0,sizeof(m->public_calls));
        memset(m->raw_frame_calls,0,sizeof(m->raw_frame_calls));
        memset(m->initialized_calls,0,sizeof(m->initialized_calls));
        memset(m->final_receipts,0,sizeof(m->final_receipts));
        m->counter_overflow=0;
    }
    return m;
}
static void counter_add(ModuleState *m,unsigned long long *counts,int mode) {
    if (mode < 1 || mode > 15 || counts[mode] == ULLONG_MAX) {
        m->counter_overflow=1;
        return;
    }
    counts[mode]++;
}
static PyObject *counter_list(unsigned long long *values) {
    PyObject *result=PyList_New(16);
    if (result == NULL) return NULL;
    for (int i=0;i<16;i++) {
        PyObject *value=PyLong_FromUnsignedLongLong(values[i]);
        if (value == NULL) { Py_DECREF(result); return NULL; }
        PyList_SET_ITEM(result,i,value);
    }
    return result;
}
static PyObject *execution_counters(PyObject *module,PyObject *unused) {
    ModuleState *m=counter_state(module);
    PyObject *public=counter_list(m->public_calls),*raw=NULL,*init=NULL,*final=NULL,*result=NULL;
    if (public != NULL) raw=counter_list(m->raw_frame_calls);
    if (raw != NULL) init=counter_list(m->initialized_calls);
    if (init != NULL) final=counter_list(m->final_receipts);
    if (final != NULL)
        result=Py_BuildValue("{s:s,s:l,s:O,s:O,s:O,s:O,s:O}",
            "schema","hepta.slot.mechanical.execution-counters.v1",
            "pid",(long)m->counter_pid,
            "overflow",m->counter_overflow ? Py_True : Py_False,
            "public_calls",public,"raw_frame_calls",raw,
            "initialized",init,"final_receipts",final);
    Py_XDECREF(public); Py_XDECREF(raw); Py_XDECREF(init); Py_XDECREF(final);
    return result;
}
/* Match an immediate Python method CALL: the receiver and arguments remain
 * borrowed from their real owners. Generic descriptor lookup is retained,
 * while ordinary function descriptors need no temporary PyMethod or tuple.
 * Names and keyword tuples contain no provider objects or captured outcomes. */
static PyObject *call_named(const char *name,PyObject *const *args,
                            size_t positional,PyObject *keywords) {
    PyObject *attribute=PyUnicode_InternFromString(name),*answer;
    if (attribute == NULL) return NULL;
    answer=PyObject_VectorcallMethod(attribute,args,
             positional|PY_VECTORCALL_ARGUMENTS_OFFSET,keywords);
    Py_DECREF(attribute);
    return answer;
}
static PyObject *call0(PyObject *value, const char *name) {
    if (value == NULL) return PyObject_CallMethod(value,name,NULL);
    return call_named(name,&value,1,NULL);
}
static PyObject *call1(PyObject *value, const char *name, PyObject *arg) {
    PyObject *args[]={value,arg};
    if (value == NULL || arg == NULL)
        return PyObject_CallMethod(value,name,"(O)",arg);
    return call_named(name,args,2,NULL);
}
static PyObject *call2(PyObject *value,const char *name,PyObject *a,PyObject *b) {
    PyObject *args[]={value,a,b};
    if (value == NULL || a == NULL || b == NULL)
        return PyObject_CallMethod(value,name,"OO",a,b);
    return call_named(name,args,3,NULL);
}
static PyObject *call3(PyObject *value,const char *name,
                       PyObject *a,PyObject *b,PyObject *c) {
    PyObject *args[]={value,a,b,c};
    if (value == NULL || a == NULL || b == NULL || c == NULL)
        return PyObject_CallMethod(value,name,"OOO",a,b,c);
    return call_named(name,args,4,NULL);
}
static int discard(PyObject *value) {
    if (value == NULL) return -1;
    Py_DECREF(value);
    return 0;
}
static int set_flag(PyObject *value, const char *name, int flag) {
    return PyObject_SetAttrString(value, name, flag ? Py_True : Py_False);
}
static int flag(PyObject *value, const char *name) {
    PyObject *found=PyObject_GetAttrString(value,name);
    int result;
    if (found == NULL) return -1;
    if (found != Py_True && found != Py_False) {
        Py_DECREF(found);
        PyErr_Format(PyExc_TypeError,"mechanical flag %s is not an exact bool",name);
        return -1;
    }
    result=found == Py_True;
    Py_DECREF(found);
    return result;
}
static long number(PyObject *value,const char *name) {
    PyObject *found=PyObject_GetAttrString(value,name);
    long result;
    if (found == NULL) return -1;
    if (!PyLong_CheckExact(found)) {
        Py_DECREF(found);
        PyErr_Format(PyExc_TypeError,"mechanical number %s is not an exact int",name);
        return -1;
    }
    result=PyLong_AsLong(found);
    Py_DECREF(found);
    return result;
}
static int unknown(Session *s,const char *message) {
    PyErr_SetString(s->unknown ? s->unknown : PyExc_RuntimeError,message);
    return -1;
}
static PyObject *foreign(Session *s,int observed) {
    ModuleState *m=state(s->module);
    PyObject *args[]={s->record,observed ? Py_True : Py_False,Py_True};
    return call_named("foreign",args,1,
        observed ? m->foreign_observed_names : m->foreign_ambient_names);
}
static int check(Session *s) {
    if (!s->active || s->pid != getpid() ||
        s->thread != PyThread_get_thread_ident())
        return unknown(s,"Slot mechanical activation is stale or transferred");
    if (s->record != NULL &&
        discard(call1(s->record,"check",s->unknown)) < 0) return -1;
    if (s->series != NULL && discard(call0(s->series,"check")) < 0) return -1;
    return 0;
}
static Session *current(PyObject *module,int caller_required) {
    ModuleState *m=state(module);
    PyObject *value=NULL;
    Session *s;
    if (PyContextVar_Get(m->current,Py_None,&value) < 0) return NULL;
    if (value == Py_None || Py_TYPE(value) != (PyTypeObject *)m->session_type) {
        Py_DECREF(value);
        PyErr_SetString(PyExc_RuntimeError,"no actual Slot mechanical invocation");
        return NULL;
    }
    s=(Session *)value; /* new reference owned by the caller */
    if (!s->active || s->pid != getpid() ||
        s->thread != PyThread_get_thread_ident() ||
        (caller_required && (!s->started ||
                             PyEval_GetFrame() != s->caller_identity))) {
        unknown(s,"Slot mechanical token is not in its actual continuation");
        Py_DECREF(s);
        return NULL;
    }
    return s;
}
static int receipt(Session *s,long *phase,long *port) {
    PyObject *r=PyObject_GetAttrString(s->frame,"receipt");
    if (r == NULL) return -1;
    if (r == Py_None) {
        Py_DECREF(r);
        return unknown(s,"Slot controller has no receipt");
    }
    *phase=number(r,"phase"); *port=number(r,"port");
    Py_DECREF(r);
    return PyErr_Occurred() ? -1 : 0;
}
/* Preserve an actual unknown's real frame without normal-path ownership.
 * The slot is pre-reserved in Session. No frame-id reconstruction or locals
 * dictionary is used, and no traceback is shortened or reassigned. */
static void keep_unknown_frame(Session *s) {
    PyObject *kind=NULL,*error=NULL,*tb=NULL,*loss=NULL;
    int pending=0;
    PyErr_Fetch(&kind,&error,&tb);
    if (s->record != NULL) {
        loss=PyObject_GetAttrString(s->record,"loss");
        if (loss != NULL && loss != Py_None) pending=1;
        Py_XDECREF(loss);
        if (PyErr_Occurred()) PyErr_Clear();
    }
    if (pending && s->retained_frame == NULL && s->started &&
        PyEval_GetFrame() == s->caller_identity)
        s->retained_frame=Py_NewRef((PyObject *)s->caller_identity);
    PyErr_Restore(kind,error,tb);
}
static PyObject *failure(Session *s) {
    keep_unknown_frame(s);
    Py_DECREF(s);
    return NULL;
}
static int native_event(Session *s,int event,int observation) {
    PyObject *value=NULL,*event_value,*observation_value;
    if (check(s) < 0) return -1;
    event_value=PyLong_FromLong(event);
    observation_value=PyLong_FromLong(observation);
    if (event_value != NULL && observation_value != NULL)
        value=call2(s->frame,"call",event_value,observation_value);
    Py_XDECREF(event_value); Py_XDECREF(observation_value);
    return discard(value);
}
static int exit_activation(PyObject *exit,PyObject *error) {
    PyObject *tb=NULL,*answer;
    if (error == NULL || error == Py_None)
        answer=PyObject_CallFunctionObjArgs(exit,Py_None,Py_None,Py_None,NULL);
    else {
        tb=PyException_GetTraceback(error);
        if (tb == NULL && PyErr_Occurred()) return -1;
        answer=PyObject_CallFunctionObjArgs(exit,(PyObject *)Py_TYPE(error),
                                           error,tb ? tb : Py_None,NULL);
        Py_XDECREF(tb);
    }
    if (answer == NULL) return -1;
    /* The existing exact private activations never suppress. */
    if (answer != Py_False) {
        Py_DECREF(answer);
        PyErr_SetString(PyExc_RuntimeError,"Slot mechanical activation suppressed an outcome");
        return -1;
    }
    Py_DECREF(answer);
    return 0;
}
static int finish_foreign(Session *s,PyObject *error) {
    if (!s->foreign_open || !s->effect_started)
        return unknown(s,"Slot outcome has no started foreign expression");
    /* This is an actually returned/raised expression, before any new
     * bookkeeping allocation. It is not an exception-class inference. */
    s->outcome_unconfirmed=1;
    s->effect_started=0;
    s->foreign_open=0; /* exit can fail after it has already reset its token */
    return exit_activation(s->pending_exit,error);
}
static int acknowledge(Session *s,int observation) {
    if (finish_foreign(s,NULL) < 0) return -1;
    if (native_event(s,SUCCEEDED,observation) < 0) return -1;
    s->outcome_unconfirmed=0;
    Py_CLEAR(s->pending_exit);
    Py_CLEAR(s->pending);
    return check(s);
}
static int claim(Session *s,long *port) {
    long phase;
    PyObject *activation=NULL,*exit=NULL,*entered=NULL;
    if (!s->initialized || s->ready_outcome || s->final_receipt || s->failed ||
        s->foreign_open || s->effect_started)
        return unknown(s,"Slot mechanical claim is reused or not live");
    if (receipt(s,&phase,port) < 0) return -1;
    if (phase != ISSUED || *port < 1 || *port > 136)
        return unknown(s,"Slot effect is not newly issued");
    if (native_event(s,CLAIM,0) < 0) return -1;
    activation=foreign(s,1);
    if (activation == NULL) return -1;
    /* Resolve exit before entering, matching the preparation order of with. */
    exit=PyObject_GetAttrString(activation,"__exit__");
    if (exit == NULL) { Py_DECREF(activation); return -1; }
    if (PyObject_SetAttrString(s->frame,"_pending_foreign",activation) < 0) {
        Py_DECREF(exit); Py_DECREF(activation); return -1;
    }
    s->pending=activation; s->pending_exit=exit;
    entered=call0(activation,"__enter__");
    if (entered == NULL) return -1;
    Py_DECREF(entered);
    s->foreign_open=1;
    if (check(s) < 0) return -1;
    s->effect_started=1;
    return 0;
}
static int claim_exact(Session *s,long expected) {
    long port;
    if (claim(s,&port) < 0) return -1;
    if (port != expected) {
        s->effect_started=0;
        return unknown(s,"HIA issued a different expression continuation");
    }
    return 0;
}
static int live_port(Session *s,long expected) {
    long phase,port;
    if (check(s) < 0 || receipt(s,&phase,&port) < 0) return -1;
    if (!s->effect_started || !s->foreign_open ||
        phase != CLAIMED || port != expected)
        return unknown(s,"expression has no exact current HIA claim");
    return 0;
}
static int finalize(Session *s,int want) {
    long phase,port;
    if (s->foreign_open || s->effect_started || s->outcome_unconfirmed ||
        s->final_receipt)
        return unknown(s,"Slot mechanical completion is not ready");
    if (receipt(s,&phase,&port) < 0) return -1;
    if (port != 0 || phase != want)
        return unknown(s,"Slot HIA issued a different completion outcome");
    if (check(s) < 0 ||
        discard(call0(s->series,"prepare_completion")) < 0 ||
        native_event(s,FINALIZE,0) < 0) return -1;
    if (receipt(s,&phase,&port) < 0) return -1;
    if (phase != (want == READY_RETURN ? RETURNED : PROPAGATE) || port != 0)
        return unknown(s,"Slot HIA final receipt is unconfirmed");
    if (set_flag(s->frame,"finished",1) < 0) return -1;
    s->final_receipt=phase;
    /* This runs only in outer C after the actual Python continuation has
     * returned/unwound. Existing handled tracebacks keep their normal locals;
     * no local, traceback or GC state is cleared to manufacture this boundary.
     * DeliveryRecord.terminal is set only after one final actual loss check. */
    if (check(s) < 0) return -1;
    {
        ModuleState *m=counter_state(s->module);
        counter_add(m,m->final_receipts,s->mode);
    }
    return 0;
}

/* Exception triples are carried unchanged through mechanical cleanup. */
typedef struct { PyObject *kind,*error,*tb; } ErrorState;
static void fetch_error(ErrorState *e) {
    e->kind=e->error=e->tb=NULL;
    PyErr_Fetch(&e->kind,&e->error,&e->tb);
    PyErr_NormalizeException(&e->kind,&e->error,&e->tb);
}
static void restore_error(ErrorState *e) {
    PyErr_Restore(e->kind,e->error,e->tb);
    e->kind=e->error=e->tb=NULL;
}
static void clear_error(ErrorState *e) {
    Py_CLEAR(e->kind); Py_CLEAR(e->error); Py_CLEAR(e->tb);
}
static int pending_completed(Session *s) {
    PyObject *holder;
    int completed;
    if (s->pending == NULL) return 1;
    holder=PyObject_GetAttrString(s->pending,"pending_resources");
    if (holder == NULL) return -1;
    if (holder == Py_None) { Py_DECREF(holder); return 0; }
    completed=flag(holder,"completed");
    Py_DECREF(holder);
    return completed;
}
static int abort_session(Session *s,PyObject *error) {
    int completed;
    if (s->frame == NULL || s->record == NULL) return 0;
    if (s->outcome_unconfirmed) {
        completed=pending_completed(s);
        if (completed < 0) return -1;
        if (!completed && discard(call1(s->record,"publish",error)) < 0)
            return -1;
    }
    if (discard(call1(s->record,"failed",error)) < 0) return -1;
    if (s->pending != NULL && discard(call1(s->pending,"failed",error)) < 0)
        return -1;
    if (s->series != NULL && discard(call1(s->series,"failed",error)) < 0)
        return -1;
    {
        PyObject *loss=PyObject_GetAttrString(s->record,"loss");
        int lost;
        if (loss == NULL) return -1;
        lost=loss != Py_None; Py_DECREF(loss);
        if (lost) {
            PyObject *rejections=PyObject_GetAttrString(s->frame,"_mechanical_rejections");
            if (rejections == NULL) return -1;
            if (set_flag(s->frame,"fenced",1) < 0 ||
                set_flag(s->frame,"native_failed",1) < 0) {
                Py_DECREF(rejections); return -1;
            }
            {
                PyObject *answer=call3(s->record,"propagate",error,s->unknown,rejections);
                Py_DECREF(rejections);
                if (discard(answer) < 0) return -1;
            }
        }
    }
    s->failed=1;
    return 0;
}
static int close_scopes(Session *s,PyObject *error) {
    ErrorState replacement={NULL,NULL,NULL};
    PyObject *active_error=Py_XNewRef(error);
    PyObject *old_handled=PyErr_GetHandledException();
    int failed_exit=0;
    /* Each enclosing scope is left even when an inner cleanup raises. */
    if (s->foreign_open) {
        PyObject *value;
        s->foreign_open=0;
        value=call2(s->frame,"_mechanical_abandon_foreign",s->pending,
                    active_error ? active_error : Py_None);
        if (discard(value) < 0) {
            fetch_error(&replacement); failed_exit=1;
            Py_XSETREF(active_error,Py_XNewRef(replacement.error));
            PyErr_SetHandledException(active_error);
        }
    }
    if (s->series_open) {
        s->series_open=0;
        if (exit_activation(s->series_exit,active_error) < 0) {
            clear_error(&replacement); fetch_error(&replacement); failed_exit=1;
            Py_XSETREF(active_error,Py_XNewRef(replacement.error));
            PyErr_SetHandledException(active_error);
        }
    }
    if (s->ambient_open) {
        s->ambient_open=0;
        if (exit_activation(s->ambient_exit,active_error) < 0) {
            clear_error(&replacement); fetch_error(&replacement); failed_exit=1;
            Py_XSETREF(active_error,Py_XNewRef(replacement.error));
        }
    }
    PyErr_SetHandledException(old_handled);
    Py_XDECREF(old_handled); Py_XDECREF(active_error);
    if (failed_exit) { restore_error(&replacement); return -1; }
    return 0;
}
static int session_traverse(Session *s,visitproc visit,void *arg) {
    Py_VISIT(Py_TYPE(s));
    Py_VISIT(s->module); Py_VISIT(s->function); Py_VISIT(s->binding);
    Py_VISIT(s->frame_type); Py_VISIT(s->unknown); Py_VISIT(s->admission);
    Py_VISIT(s->frame); Py_VISIT(s->record); Py_VISIT(s->series);
    Py_VISIT(s->ambient); Py_VISIT(s->ambient_exit); Py_VISIT(s->series_exit);
    Py_VISIT(s->pending); Py_VISIT(s->pending_exit); Py_VISIT(s->context_token);
    Py_VISIT(s->sql_attempt); Py_VISIT(s->retained_frame);
    Py_VISIT(s->iterator_custody);
    return 0;
}
static int session_clear(Session *s) {
    /* Only reference release. No SQL, image call, receipt, or invented close. */
    s->active=0; s->caller_identity=NULL; s->iterator_identity=NULL;
    Py_CLEAR(s->function); Py_CLEAR(s->binding); Py_CLEAR(s->frame_type);
    Py_CLEAR(s->admission); Py_CLEAR(s->frame); Py_CLEAR(s->record);
    Py_CLEAR(s->series); Py_CLEAR(s->ambient); Py_CLEAR(s->ambient_exit);
    Py_CLEAR(s->series_exit); Py_CLEAR(s->pending); Py_CLEAR(s->pending_exit);
    Py_CLEAR(s->context_token); Py_CLEAR(s->sql_attempt);
    Py_CLEAR(s->retained_frame); Py_CLEAR(s->iterator_custody);
    Py_CLEAR(s->unknown); Py_CLEAR(s->module);
    return 0;
}
static void session_dealloc(Session *s) {
    PyTypeObject *type=Py_TYPE(s);
    PyObject_GC_UnTrack(s);
    session_clear(s);
    type->tp_free((PyObject *)s);
    Py_DECREF(type);
}
static Session *new_session(Method *method,PyObject *existing) {
    ModuleState *m=state(method->module);
    Session *s=(Session *)PyType_GenericAlloc((PyTypeObject *)m->session_type,0);
    if (s == NULL) return NULL;
    s->module=Py_NewRef(method->module); s->function=Py_NewRef(method->function);
    s->binding=Py_NewRef(method->binding); s->frame_type=Py_NewRef(method->frame_type);
    s->unknown=Py_NewRef(method->unknown); s->admission=Py_NewRef(method->admission);
    s->frame=existing ? Py_NewRef(existing) : NULL;
    s->mode=method->mode; s->pid=getpid();
    s->thread=PyThread_get_thread_ident(); s->active=1;
    return s;
}
static PyObject *invoke(Method *method,PyObject *const *args,size_t nargsf,
                        PyObject *kwnames,PyObject *existing,
                        PyObject *tuple_args,PyObject *dict_kw) {
    Session *s=new_session(method,existing);
    PyObject *answer=NULL,*handled=PyErr_GetHandledException();
    ErrorState error={NULL,NULL,NULL};
    int lost=0;
    if (s == NULL) { Py_XDECREF(handled); return NULL; }
    s->context_token=PyContextVar_Set(state(s->module)->current,(PyObject *)s);
    if (s->context_token == NULL) goto done;
    /* The function itself performs real Python argument binding. start() is
     * its first statement; no admission/native entry precedes that binding. */
    if (tuple_args != NULL)
        answer=PyObject_Call(s->function,tuple_args,dict_kw);
    else answer=PyObject_Vectorcall(s->function,args,nargsf,kwnames);
    s->caller_identity=NULL; /* actual continuation no longer executing */
    if (answer != NULL && (!s->started || s->ready_outcome != READY_RETURN)) {
        Py_CLEAR(answer);
        unknown(s,"Slot continuation returned without its HIA ready receipt");
    }
    if (answer == NULL) {
        fetch_error(&error);
        if (error.error == NULL) {
            PyErr_SetString(PyExc_SystemError,"Slot continuation failed without an exception");
            fetch_error(&error);
        }
        PyErr_SetHandledException(error.error);
    }
    /* Provider code and ordinary fast-local release have now left the one
     * real continuation. Keep the actual ambient/SQL responsibility active
     * through that release and through FINALIZE; per-port ACK is insufficient.
     * A retained original handled traceback is not edited or forced to release.
     */
    if (s->record != NULL &&
        ((answer != NULL && s->ready_outcome == READY_RETURN) ||
         (answer == NULL && s->ready_outcome == READY_PROPAGATE))) {
        if (finalize(s,s->ready_outcome) < 0) {
            Py_CLEAR(answer); clear_error(&error); fetch_error(&error);
            PyErr_SetHandledException(error.error);
        }
    }
    if (answer == NULL) {
        if (s->record != NULL && abort_session(s,error.error) < 0) {
            clear_error(&error); fetch_error(&error);
            PyErr_SetHandledException(error.error);
        }
    } else if (check(s) < 0) {
        Py_CLEAR(answer); fetch_error(&error);
        PyErr_SetHandledException(error.error);
        if (abort_session(s,error.error) < 0) {
            clear_error(&error); fetch_error(&error);
        }
    }
    if (s->record != NULL && s->final_receipt &&
        (answer != NULL || s->final_receipt == PROPAGATE)) {
        if (check(s) < 0) {
            Py_CLEAR(answer); clear_error(&error); fetch_error(&error);
        } else {
            PyObject *args[]={s->record,Py_True};
            PyObject *result=call_named("confirmed",args,1,state(s->module)->confirmed_names);
            if (discard(result) < 0) {
                Py_CLEAR(answer); clear_error(&error); fetch_error(&error);
            }
        }
    }
    if (error.error != NULL) PyErr_SetHandledException(error.error);
    if (close_scopes(s,error.error) < 0) {
        Py_CLEAR(answer); clear_error(&error); fetch_error(&error);
    }
    if (s->record != NULL) {
        PyObject *loss=PyObject_GetAttrString(s->record,"loss");
        if (loss == NULL) {
            Py_CLEAR(answer); clear_error(&error); fetch_error(&error);
        } else { lost=loss != Py_None; Py_DECREF(loss); }
        if (discard(call0(s->record,"retire")) < 0) {
            Py_CLEAR(answer); clear_error(&error); fetch_error(&error);
            lost=1; /* failed retirement cannot authorize dropping custody */
        } else {
            int retired=flag(s->record,"retired");
            if (retired < 0) {
                Py_CLEAR(answer); clear_error(&error); fetch_error(&error);
                lost=1;
            } else if (!retired) {
                /* A real pending handoff/outcome also retains custody if its
                 * later loss bookkeeping could not finish. No error-class
                 * inference or fabricated terminal acknowledgement. */
                lost=1;
            }
        }
    }
    if (s->context_token != NULL) {
        if (PyContextVar_Reset(state(s->module)->current,s->context_token) < 0) {
            Py_CLEAR(answer); clear_error(&error); fetch_error(&error);
        }
        Py_CLEAR(s->context_token);
    }
    s->active=0;
    if (!lost && s->frame != NULL &&
        PyObject_SetAttrString(s->frame,"_mechanical_session",Py_None) < 0) {
        Py_CLEAR(answer); clear_error(&error); fetch_error(&error);
    }
    if (error.error != NULL) restore_error(&error);
done:
    PyErr_SetHandledException(handled);
    Py_XDECREF(handled);
    if (!lost) session_clear(s);
    Py_DECREF(s);
    return answer;
}
static PyObject *method_vectorcall(PyObject *object,PyObject *const *args,
                                    size_t nargsf,PyObject *kwnames) {
    Method *method=(Method *)object;
    ModuleState *m=counter_state(method->module);
    counter_add(m,m->public_calls,method->mode);
    return invoke(method,args,nargsf,kwnames,NULL,NULL,NULL);
}
static int method_traverse(Method *m,visitproc visit,void *arg) {
    Py_VISIT(Py_TYPE(m));
    Py_VISIT(m->module); Py_VISIT(m->function); Py_VISIT(m->binding);
    Py_VISIT(m->frame_type); Py_VISIT(m->unknown); Py_VISIT(m->admission);
    return 0;
}
static int method_clear(Method *m) {
    Py_CLEAR(m->function); Py_CLEAR(m->binding); Py_CLEAR(m->frame_type);
    Py_CLEAR(m->unknown); Py_CLEAR(m->admission); Py_CLEAR(m->module);
    return 0;
}
static void method_dealloc(Method *m) {
    PyTypeObject *type=Py_TYPE(m);
    PyObject_GC_UnTrack(m); method_clear(m); type->tp_free((PyObject *)m);
    Py_DECREF(type);
}
static PyObject *method_get(PyObject *self,PyObject *instance,PyObject *owner) {
    if (instance == NULL || instance == Py_None) return Py_NewRef(self);
    return PyMethod_New(self,instance);
}
static PyObject *method_meta(Method *self,void *name) {
    return PyObject_GetAttrString(self->function,(const char *)name);
}
static PyObject *method_signature(Method *self,void *unused) {
    PyObject *inspect=PyImport_ImportModule("inspect"),*result;
    if (inspect == NULL) return NULL;
    result=PyObject_CallMethod(inspect,"signature","O",self->function);
    Py_DECREF(inspect); return result;
}
static PyGetSetDef method_getsets[]={
    {"__name__",(getter)method_meta,NULL,NULL,"__name__"},
    {"__qualname__",(getter)method_meta,NULL,NULL,"__qualname__"},
    {"__module__",(getter)method_meta,NULL,NULL,"__module__"},
    {"__doc__",(getter)method_meta,NULL,NULL,"__doc__"},
    {"__code__",(getter)method_meta,NULL,NULL,"__code__"},
    {"__defaults__",(getter)method_meta,NULL,NULL,"__defaults__"},
    {"__kwdefaults__",(getter)method_meta,NULL,NULL,"__kwdefaults__"},
    {"__signature__",(getter)method_signature,NULL,NULL,NULL},
    {NULL}
};
static PyObject *bind_method(PyObject *module,PyObject *args) {
    PyObject *function,*binding,*frame_type,*unknown_type,*admission,*code,*flags;
    Method *result;
    int mode; long bits;
    if (!PyArg_ParseTuple(args,"OOOOOi:bind",&function,&binding,&frame_type,
                         &unknown_type,&admission,&mode)) return NULL;
    if (!PyFunction_Check(function) || !PyType_Check(frame_type) ||
        !PyExceptionClass_Check(unknown_type) || !PyCallable_Check(admission) ||
        mode < 1 || mode > 15) {
        PyErr_SetString(PyExc_TypeError,"invalid mechanical continuation binding");
        return NULL;
    }
    code=PyObject_GetAttrString(function,"__code__");
    if (code == NULL) return NULL;
    flags=PyObject_GetAttrString(code,"co_flags"); Py_DECREF(code);
    if (flags == NULL) return NULL;
    bits=PyLong_AsLong(flags); Py_DECREF(flags);
    if (PyErr_Occurred()) return NULL;
    if (bits & (CO_GENERATOR|CO_COROUTINE|CO_ASYNC_GENERATOR)) {
        PyErr_SetString(PyExc_TypeError,"Slot continuation must be a real non-generator function");
        return NULL;
    }
    result=(Method *)PyType_GenericAlloc((PyTypeObject *)state(module)->method_type,0);
    if (result == NULL) return NULL;
    result->vectorcall=method_vectorcall;
    result->module=Py_NewRef(module); result->function=Py_NewRef(function);
    result->binding=Py_NewRef(binding); result->frame_type=Py_NewRef(frame_type);
    result->unknown=Py_NewRef(unknown_type); result->admission=Py_NewRef(admission);
    result->mode=mode;
    return (PyObject *)result;
}
static PyObject *run_frame(PyObject *module,PyObject *args) {
    PyObject *frame,*function,*positional,*keywords,*admission,*unknown_type;
    PyObject *binding=Py_None,*type;
    Method *method; long mode; PyObject *answer,*bind_args;
    if (!PyArg_ParseTuple(args,"OOOOOO:run_frame",&frame,&function,&positional,
                         &keywords,&admission,&unknown_type)) return NULL;
    if (!PyTuple_CheckExact(positional) || !PyDict_CheckExact(keywords)) {
        PyErr_SetString(PyExc_TypeError,"raw Slot arguments require a tuple and dict");
        return NULL;
    }
    {
        PyObject *series=PyObject_GetAttrString(frame,"series");
        int entered;
        if (series == NULL) return NULL;
        entered=flag(series,"entered"); Py_DECREF(series);
        if (entered < 0) return NULL;
        if (entered) {
            PyErr_SetString(unknown_type,"Slot controller invocation cannot be reused or re-entered");
            return NULL;
        }
    }
    mode=number(frame,"mode");
    if (PyErr_Occurred()) return NULL;
    if (mode < 1 || mode > 15) {
        PyErr_SetString(unknown_type,"raw Slot frame has an invalid mode");
        return NULL;
    }
    type=(PyObject *)Py_TYPE(frame);
    bind_args=Py_BuildValue("(OOOOOi)",function,binding,type,unknown_type,admission,(int)mode);
    if (bind_args == NULL) return NULL;
    method=(Method *)bind_method(module,bind_args); Py_DECREF(bind_args);
    if (method == NULL) return NULL;
    {
        ModuleState *m=counter_state(module);
        counter_add(m,m->raw_frame_calls,(int)mode);
    }
    answer=invoke(method,NULL,0,NULL,frame,positional,keywords);
    Py_DECREF(method);
    return answer;
}

static PyObject *start(PyObject *module,PyObject *mode_object) {
    Session *s=current(module,0);
    PyObject *code=NULL,*actual=NULL,*image=NULL,*empty=NULL,*args=NULL,*kw=NULL;
    PyObject *answer=NULL;
    long mode;
    if (s == NULL) return NULL;
    if (!PyLong_CheckExact(mode_object)) {
        PyErr_SetString(PyExc_TypeError,"Slot mode must be an exact integer");
        return failure(s);
    }
    mode=PyLong_AsLong(mode_object);
    if (PyErr_Occurred()) return failure(s);
    if (mode != s->mode || s->started || s->initiating) {
        unknown(s,"Slot mechanical invocation was started twice or changed mode");
        return failure(s);
    }
    s->initiating=1;
    s->caller_identity=PyEval_GetFrame();
    if (s->caller_identity == NULL) {
        unknown(s,"Slot continuation has no real Python frame"); return failure(s);
    }
    actual=(PyObject *)PyFrame_GetCode(s->caller_identity);
    code=PyObject_GetAttrString(s->function,"__code__");
    if (actual == NULL || code == NULL) goto error;
    if (actual != code) { unknown(s,"Slot start is outside its bound continuation"); goto error; }
    Py_CLEAR(actual); Py_CLEAR(code);
    s->started=1;
    /* Both are after the genuine original signature has bound. */
    if (discard(PyObject_CallNoArgs(s->admission)) < 0) goto error;
    if (s->frame == NULL) {
        image=call0(s->binding,"check");
        if (image == NULL) goto error;
        empty=PyDict_New();
        if (empty == NULL) goto error;
        args=PyTuple_Pack(3,image,mode_object,empty);
        kw=Py_BuildValue("{s:O}","mechanical",Py_True);
        if (args == NULL || kw == NULL) goto error;
        s->frame=PyObject_Call(s->frame_type,args,kw);
        if (s->frame == NULL) goto error;
        Py_CLEAR(image); Py_CLEAR(empty); Py_CLEAR(args); Py_CLEAR(kw);
    } else {
        /* The raw Frame's caller data is private argument staging. The
         * bound real continuation now owns its business fast locals. */
        empty=PyDict_New();
        if (empty == NULL || PyObject_SetAttrString(s->frame,"data",empty) < 0) goto error;
        Py_CLEAR(empty);
    }
    s->record=PyObject_GetAttrString(s->frame,"_delivery");
    s->series=PyObject_GetAttrString(s->frame,"series");
    if (s->record == NULL || s->series == NULL) goto error;
    if (PyObject_SetAttrString(s->frame,"_mechanical_session",(PyObject *)s) < 0 ||
        check(s) < 0) goto error;
    if (flag(s->series,"entered") != 0) {
        if (!PyErr_Occurred()) unknown(s,"Slot operation series is already entered");
        goto error;
    }
    s->ambient=foreign(s,0);
    if (s->ambient == NULL) goto error;
    s->ambient_exit=PyObject_GetAttrString(s->ambient,"__exit__");
    s->series_exit=PyObject_GetAttrString(s->series,"__exit__");
    if (s->ambient_exit == NULL || s->series_exit == NULL) goto error;
    if (discard(call0(s->ambient,"__enter__")) < 0) goto error;
    s->ambient_open=1;
    if (discard(call0(s->series,"__enter__")) < 0) goto error;
    s->series_open=1;
    if (native_event(s,INITIALIZE,0) < 0) goto error;
    s->initialized=1;
    {
        ModuleState *m=counter_state(module);
        counter_add(m,m->initialized_calls,s->mode);
    }
    answer=Py_NewRef(Py_None);
error:
    Py_XDECREF(actual); Py_XDECREF(code); Py_XDECREF(image);
    Py_XDECREF(empty); Py_XDECREF(args); Py_XDECREF(kw);
    s->initiating=0;
    if (answer == NULL) return failure(s);
    Py_DECREF(s); return answer;
}
static PyObject *begin(PyObject *module,PyObject *unused) {
    Session *s=current(module,1); long port;
    if (s == NULL) return NULL;
    if (claim(s,&port) < 0) return failure(s);
    Py_DECREF(s); return PyLong_FromLong(port);
}
static PyObject *ack(PyObject *module,PyObject *value) {
    Session *s=current(module,1); long observation;
    if (s == NULL) return NULL;
    if (!PyLong_CheckExact(value)) {
        PyErr_SetString(PyExc_TypeError,"Slot observation must be an exact integer");
        return failure(s);
    }
    observation=PyLong_AsLong(value);
    if (PyErr_Occurred()) return failure(s);
    if ((observation != 0 && observation != 1) ||
        acknowledge(s,(int)observation) < 0) {
        if (!PyErr_Occurred()) unknown(s,"Slot observation is not boolean");
        return failure(s);
    }
    Py_DECREF(s); Py_RETURN_NONE;
}
static PyObject *returned(PyObject *module,PyObject *value) {
    Session *s=current(module,1);
    if (s == NULL) return NULL;
    long phase,port;
    if (acknowledge(s,0) < 0 || receipt(s,&phase,&port) < 0) return failure(s);
    if (phase != READY_RETURN || port != 0 || s->ready_outcome) {
        unknown(s,"Slot return has no unique complete READY_RETURN receipt");
        return failure(s);
    }
    s->ready_outcome=READY_RETURN;
    /* No Session result slot or extra Python local retains this value. */
    Py_DECREF(s); return Py_NewRef(value);
}
static PyObject *propagating(PyObject *module,PyObject *unused) {
    Session *s=current(module,1);
    if (s == NULL) return NULL;
    long phase,port;
    if (check(s) < 0 || receipt(s,&phase,&port) < 0) return failure(s);
    if (phase != READY_PROPAGATE || port != 0 || s->ready_outcome ||
        s->foreign_open || s->effect_started || s->outcome_unconfirmed) {
        unknown(s,"Slot error has no unique complete READY_PROPAGATE receipt");
        return failure(s);
    }
    s->ready_outcome=READY_PROPAGATE;
    Py_DECREF(s); Py_RETURN_NONE;
}
static PyObject *failed(PyObject *module,PyObject *unused) {
    Session *s=current(module,1); PyObject *error,*loss; long phase,port;
    if (s == NULL) return NULL;
    if (!s->effect_started || !s->foreign_open || s->final_receipt) {
        Py_DECREF(s); Py_RETURN_FALSE;
    }
    loss=PyObject_GetAttrString(s->record,"loss");
    if (loss == NULL) return failure(s);
    if (loss != Py_None) {
        Py_DECREF(loss); keep_unknown_frame(s); Py_DECREF(s); Py_RETURN_FALSE;
    }
    Py_DECREF(loss);
    if (flag(s->frame,"native_failed") != 0) {
        if (PyErr_Occurred()) return failure(s);
        Py_DECREF(s); Py_RETURN_FALSE;
    }
    error=PyErr_GetHandledException();
    if (error == NULL) {
        unknown(s,"Slot failure has no actual handled exception"); return failure(s);
    }
    if (finish_foreign(s,error) < 0) { Py_DECREF(error); return failure(s); }
    Py_DECREF(error);
    if (native_event(s,RAISED,0) < 0) return failure(s);
    s->outcome_unconfirmed=0;
    Py_CLEAR(s->pending_exit); Py_CLEAR(s->pending);
    if (receipt(s,&phase,&port) < 0) return failure(s);
    if (phase != ISSUED && phase != READY_PROPAGATE) {
        unknown(s,"Slot HIA did not issue an exception continuation"); return failure(s);
    }
    Py_DECREF(s); Py_RETURN_TRUE;
}
static PyObject *pending(PyObject *module,PyObject *unused) {
    Session *s=current(module,1); long phase,port;
    if (s == NULL) return NULL;
    if (receipt(s,&phase,&port) < 0 || check(s) < 0) return failure(s);
    if (phase != ISSUED && phase != READY_PROPAGATE) {
        unknown(s,"Slot exception has an invalid phase"); return failure(s);
    }
    Py_DECREF(s); return PyBool_FromLong(phase == ISSUED);
}
static PyObject *bad_port(PyObject *module,PyObject *port) {
    Session *s=current(module,1);
    if (s == NULL) return NULL;
    s->effect_started=0;
    unknown(s,"Slot continuation has no literal for the issued HIA port");
    return failure(s);
}
static PyObject *sql_prepare(PyObject *module,PyObject *unused) {
    Session *s=current(module,1);
    if (s == NULL) return NULL;
    if (live_port(s,2) < 0 || s->sql_attempt != NULL) {
        if (!PyErr_Occurred()) unknown(s,"Slot SQL attempt already exists");
        return failure(s);
    }
    s->sql_attempt=call0(s->series,"prepare_sql");
    if (s->sql_attempt == NULL ||
        PyObject_SetAttrString(s->frame,"_sql_attempt",s->sql_attempt) < 0) return failure(s);
    Py_DECREF(s); Py_RETURN_NONE;
}
static PyObject *sql_borrow(PyObject *module,PyObject *value) {
    Session *s=current(module,1); PyObject *result;
    if (s == NULL) return NULL;
    if (live_port(s,2) < 0 || s->sql_attempt == NULL) {
        if (!PyErr_Occurred()) unknown(s,"Slot SQL borrow has no prepared attempt");
        return failure(s);
    }
    result=call1(s->sql_attempt,"borrow_store",value);
    if (result == NULL) return failure(s);
    if (result != value) {
        Py_DECREF(result); unknown(s,"Slot SQL borrow changed the receiver"); return failure(s);
    }
    Py_DECREF(s); return result;
}
static PyObject *sql_arguments(PyObject *module,PyObject *value) {
    Session *s=current(module,1); PyObject *result;
    if (s == NULL) return NULL;
    if (live_port(s,4) < 0 || s->sql_attempt == NULL) {
        if (!PyErr_Occurred()) unknown(s,"Slot SQL arguments have no prepared attempt");
        return failure(s);
    }
    result=call1(s->sql_attempt,"arguments",value);
    if (result == NULL) return failure(s);
    if (result != value) {
        Py_DECREF(result); unknown(s,"Slot SQL guard changed its original arguments"); return failure(s);
    }
    Py_DECREF(s); return result;
}
static PyObject *and_true(PyObject *module,PyObject *unused) {
    Session *s=current(module,1);
    if (s == NULL) return NULL;
    /* Reached only after the real Python AND consumed exactly one truth. */
    if (live_port(s,AND_OPEN) < 0 || acknowledge(s,1) < 0 ||
        claim_exact(s,AND_KEYS) < 0) return failure(s);
    Py_DECREF(s); Py_RETURN_NONE;
}
static PyObject *keep_rhs(PyObject *module,PyObject *const *args,Py_ssize_t nargs) {
    Session *s=current(module,1);
    if (s == NULL) return NULL;
    if (nargs != 2 || args[0] != Py_None || live_port(s,AND_KEYS) < 0) {
        if (!PyErr_Occurred()) unknown(s,"Slot AND RHS has no selected continuation");
        return failure(s);
    }
    Py_DECREF(s); return Py_NewRef(args[1]);
}
static PyObject *and_done(PyObject *module,PyObject *unused) {
    Session *s=current(module,1); long phase,port;
    if (s == NULL) return NULL;
    if (receipt(s,&phase,&port) < 0) return failure(s);
    if (port == AND_OPEN) {
        if (live_port(s,AND_OPEN) < 0 || acknowledge(s,0) < 0 ||
            claim_exact(s,AND_FALSE) < 0 || acknowledge(s,0) < 0) return failure(s);
    } else if (port == AND_KEYS) {
        if (live_port(s,AND_KEYS) < 0 || acknowledge(s,0) < 0) return failure(s);
    } else {
        unknown(s,"Slot AND completed outside its HIA expression"); return failure(s);
    }
    Py_DECREF(s); Py_RETURN_NONE;
}
static PyObject *lease_open(PyObject *module,PyObject *unused) {
    Session *s=current(module,1);
    if (s == NULL) return NULL;
    /* Python has already evaluated self._call, and keeps that exact callable
     * on its real value stack before evaluating any conditional argument. */
    if (live_port(s,LEASE_OPEN) < 0 || acknowledge(s,0) < 0 ||
        claim_exact(s,LEASE_TRUTH) < 0) return failure(s);
    Py_DECREF(s); Py_RETURN_NONE;
}
static PyObject *lease_opcode(PyObject *module,PyObject *const *args,Py_ssize_t nargs) {
    Session *s=current(module,1); int truth; long port;
    if (s == NULL) return NULL;
    if (nargs != 2 || args[0] != Py_None || live_port(s,LEASE_TRUTH) < 0) {
        if (!PyErr_Occurred()) unknown(s,"Slot lease choice has no current claim");
        return failure(s);
    }
    truth=PyObject_IsTrue(args[1]);
    if (truth < 0 || acknowledge(s,truth) < 0 || claim(s,&port) < 0) return failure(s);
    if (port != LEASE_RELEASE && port != LEASE_CHECK) {
        unknown(s,"HIA did not issue a lease call operand"); return failure(s);
    }
    Py_DECREF(s);
    return PyLong_FromLong(port == LEASE_RELEASE ? 14 : 13);
}
static int iteration_traverse(Iteration *self,visitproc visit,void *arg) {
    Py_VISIT(Py_TYPE(self));
    Py_VISIT(self->session); Py_VISIT(self->iterator); return 0;
}
static int iteration_clear(Iteration *self) {
    if (self->session != NULL && self->session->iterator_identity == self) {
        Session *s=self->session;
        PyObject *kind=NULL,*error=NULL,*tb=NULL,*loss=NULL;
        int retain=0;
        /* This is the exact private DeliveryRecord slot, using a name reserved
         * at module initialization. Preserve any real in-flight provider
         * exception; no original traceback or exception field is modified. */
        PyErr_Fetch(&kind,&error,&tb);
        if (s->record != NULL)
            loss=PyObject_GetAttr(s->record,state(s->module)->loss_name);
        if (loss == NULL && PyErr_Occurred()) {
            /* A failed private custody read cannot authorize releasing the
             * only pre-reserved iterator obligation. This is not a loss
             * classification from the exception's type. */
            PyErr_Clear(); retain=1;
        } else if (loss != NULL) {
            retain=loss != Py_None;
        }
        Py_XDECREF(loss);
        s->iterator_identity=NULL;
        s->iterator_live=0;
        /* Healthy/error-confirmable loop exit releases this extra mechanical
         * reference BEFORE the actual iterator reference below. Its last
         * release remains at the real Python loop unwind. A known loss keeps
         * custody instead; the disappeared Python operand stack is not
         * reconstructed later. */
        if (!retain) Py_CLEAR(s->iterator_custody);
        PyErr_Restore(kind,error,tb);
    }
    Py_CLEAR(self->iterator); Py_CLEAR(self->session);
    return 0;
}
static void iteration_dealloc(Iteration *self) {
    PyTypeObject *type=Py_TYPE(self);
    PyObject_GC_UnTrack(self); iteration_clear(self); type->tp_free((PyObject *)self);
    Py_DECREF(type);
}
static PyObject *iteration_next(Iteration *self) {
    Session *s=self->session; PyObject *value; long port;
    if (s == NULL || self->iterator == NULL || self->exhausted) return NULL;
    if (!s->active || PyEval_GetFrame() != s->caller_identity ||
        s->iterator_identity != self || !s->iterator_live) {
        unknown(s,"Slot iterator is outside its actual continuation"); return NULL;
    }
    if (claim(s,&port) < 0) { keep_unknown_frame(s); return NULL; }
    if (port != ITER_NEXT) {
        s->effect_started=0; unknown(s,"HIA did not issue a next-row request");
        return NULL;
    }
    value=PyIter_Next(self->iterator);
    if (value != NULL) return value; /* Python stores row before item() ACK. */
    if (PyErr_Occurred()) return NULL; /* real provider error, Python catches */
    self->exhausted=1; s->iterator_exhausted=1;
    if (acknowledge(s,1) < 0 || claim_exact(s,ITER_DONE) < 0) {
        keep_unknown_frame(s); return NULL;
    }
    /* Real END_FOR pops this GC-visible wrapper and its real iterator. */
    return NULL;
}
static PyObject *iteration_open(PyObject *module,PyObject *value) {
    Session *s=current(module,1);
    Iteration *it;
    if (s == NULL) return NULL;
    if (live_port(s,ITER_OPEN) < 0 || s->iterator_live) {
        if (!PyErr_Occurred()) unknown(s,"Slot cursor iterator is already live");
        return failure(s);
    }
    it=(Iteration *)PyType_GenericAlloc((PyTypeObject *)state(module)->iterator_type,0);
    if (it == NULL) return failure(s);
    it->session=(Session *)Py_NewRef((PyObject *)s);
    it->iterator=PyObject_GetIter(value);
    if (it->iterator == NULL) { Py_DECREF(it); return failure(s); }
    s->iterator_custody=Py_NewRef(it->iterator); /* pre-reserved Session slot */
    s->iterator_identity=it; s->iterator_live=1; s->iterator_exhausted=0;
    if (acknowledge(s,0) < 0) { Py_DECREF(it); return failure(s); }
    Py_DECREF(s); return (PyObject *)it;
}
static PyObject *iteration_item(PyObject *module,PyObject *unused) {
    Session *s=current(module,1);
    if (s == NULL) return NULL;
    if (live_port(s,ITER_NEXT) < 0 || !s->iterator_live ||
        acknowledge(s,0) < 0 || claim_exact(s,ITER_FOLD) < 0) return failure(s);
    Py_DECREF(s); Py_RETURN_NONE;
}
static PyObject *iteration_end(PyObject *module,PyObject *unused) {
    Session *s=current(module,1);
    if (s == NULL) return NULL;
    if (s->iterator_live || !s->iterator_exhausted ||
        live_port(s,ITER_DONE) < 0 || acknowledge(s,0) < 0) {
        if (!PyErr_Occurred()) unknown(s,"Slot iterator did not leave its real loop");
        return failure(s);
    }
    Py_DECREF(s); Py_RETURN_NONE;
}
static PyObject *unwind(PyObject *module,PyObject *unused) {
    Session *s=current(module,1); long phase,port;
    if (s == NULL) return NULL;
    if (receipt(s,&phase,&port) < 0 || phase != CLAIMED ||
        (port != ITER_UNWIND && port != AND_UNWIND && port != LEASE_UNWIND)) {
        if (!PyErr_Occurred()) unknown(s,"HIA did not issue mechanical expression unwind");
        return failure(s);
    }
    if (port == ITER_UNWIND && s->iterator_live) {
        unknown(s,"real Python loop still retains the cursor iterator");
        return failure(s);
    }
    /* Python already unwound its actual operand/for stack. No fabricated
     * exception, original-local clear, or generator.throw is performed. */
    if (acknowledge(s,0) < 0) return failure(s);
    Py_DECREF(s); Py_RETURN_NONE;
}

static PyMethodDef methods[]={
    {"admission_files",admission_files,METH_O,NULL},
    {"admission_check",admission_check,METH_O,NULL},
    {"execution_counters",execution_counters,METH_NOARGS,NULL},
    {"bind",bind_method,METH_VARARGS,NULL},
    {"run_frame",run_frame,METH_VARARGS,NULL},
    {"start",start,METH_O,NULL},{"begin",begin,METH_NOARGS,NULL},
    {"ack",ack,METH_O,NULL},{"returned",returned,METH_O,NULL},
    {"propagating",propagating,METH_NOARGS,NULL},
    {"failed",failed,METH_NOARGS,NULL},{"pending",pending,METH_NOARGS,NULL},
    {"bad_port",bad_port,METH_O,NULL},
    {"sql_prepare",sql_prepare,METH_NOARGS,NULL},
    {"sql_borrow",sql_borrow,METH_O,NULL},{"sql_arguments",sql_arguments,METH_O,NULL},
    {"and_true",and_true,METH_NOARGS,NULL},
    {"keep_rhs",(PyCFunction)(void(*)(void))keep_rhs,METH_FASTCALL,NULL},
    {"and_done",and_done,METH_NOARGS,NULL},
    {"lease_open",lease_open,METH_NOARGS,NULL},
    {"lease_opcode",(PyCFunction)(void(*)(void))lease_opcode,METH_FASTCALL,NULL},
    {"iteration_open",iteration_open,METH_O,NULL},
    {"iteration_item",iteration_item,METH_NOARGS,NULL},
    {"iteration_end",iteration_end,METH_NOARGS,NULL},
    {"unwind",unwind,METH_NOARGS,NULL},
    {NULL,NULL,0,NULL}
};
static PyType_Slot session_slots[]={
    {Py_tp_dealloc,session_dealloc},{Py_tp_traverse,session_traverse},
    {Py_tp_clear,session_clear},{0,NULL}
};
static PyType_Spec session_spec={
    "hepta._hia_slot_mechanical.Session",sizeof(Session),0,
    Py_TPFLAGS_DEFAULT|Py_TPFLAGS_HAVE_GC,session_slots
};
static PyType_Slot method_slots[]={
    {Py_tp_dealloc,method_dealloc},{Py_tp_traverse,method_traverse},
    {Py_tp_clear,method_clear},{Py_tp_descr_get,method_get},
    {Py_tp_getset,method_getsets},{Py_tp_call,PyVectorcall_Call},{0,NULL}
};
static PyType_Spec method_spec={
    "hepta._hia_slot_mechanical.Continuation",sizeof(Method),0,
    Py_TPFLAGS_DEFAULT|Py_TPFLAGS_HAVE_GC,method_slots
};
static PyType_Slot iteration_slots[]={
    {Py_tp_dealloc,iteration_dealloc},{Py_tp_traverse,iteration_traverse},
    {Py_tp_clear,iteration_clear},{Py_tp_iter,PyObject_SelfIter},
    {Py_tp_iternext,iteration_next},{0,NULL}
};
static PyType_Spec iteration_spec={
    "hepta._hia_slot_mechanical.CursorIteration",sizeof(Iteration),0,
    Py_TPFLAGS_DEFAULT|Py_TPFLAGS_HAVE_GC,iteration_slots
};
static int module_traverse(PyObject *module,visitproc visit,void *arg) {
    ModuleState *m=state(module);
    Py_VISIT(m->session_type); Py_VISIT(m->method_type);
    Py_VISIT(m->iterator_type); Py_VISIT(m->current); Py_VISIT(m->loss_name);
    Py_VISIT(m->foreign_observed_names); Py_VISIT(m->foreign_ambient_names);
    Py_VISIT(m->confirmed_names); return 0;
}
static int module_clear(PyObject *module) {
    ModuleState *m=state(module);
    Py_CLEAR(m->session_type); Py_CLEAR(m->method_type);
    Py_CLEAR(m->iterator_type); Py_CLEAR(m->current); Py_CLEAR(m->loss_name);
    Py_CLEAR(m->foreign_observed_names); Py_CLEAR(m->foreign_ambient_names);
    Py_CLEAR(m->confirmed_names); return 0;
}
static int module_exec(PyObject *module) {
    ModuleState *m=state(module);
    m->session_type=PyType_FromModuleAndSpec(module,&session_spec,NULL);
    m->method_type=PyType_FromModuleAndSpec(module,&method_spec,NULL);
    m->iterator_type=PyType_FromModuleAndSpec(module,&iteration_spec,NULL);
    m->current=PyContextVar_New("hia.slot.mechanical.actual",NULL);
    m->loss_name=PyUnicode_InternFromString("loss");
    m->foreign_observed_names=Py_BuildValue("(ss)","capture_resources","weak_registered_resources");
    m->foreign_ambient_names=Py_BuildValue("(s)","observation");
    m->confirmed_names=Py_BuildValue("(s)","terminal");
    if (!m->session_type || !m->method_type || !m->iterator_type || !m->current ||
        !m->loss_name || !m->foreign_observed_names || !m->foreign_ambient_names ||
        !m->confirmed_names) return -1;
    ((PyTypeObject *)m->method_type)->tp_vectorcall_offset=offsetof(Method,vectorcall);
    ((PyTypeObject *)m->method_type)->tp_flags|=Py_TPFLAGS_HAVE_VECTORCALL;
    PyType_Modified((PyTypeObject *)m->method_type);
    if (PyModule_AddStringConstant(module,"ABI","hepta.slot.mechanical.cpython-gil-linux.v1") < 0 ||
        PyModule_AddIntConstant(module,"MAJOR",PY_MAJOR_VERSION) < 0 ||
        PyModule_AddIntConstant(module,"MINOR",PY_MINOR_VERSION) < 0 ||
        PyModule_AddIntConstant(module,"PORTS",136) < 0 ||
        PyModule_AddIntConstant(module,"MODES",15) < 0) return -1;
    return 0;
}
static PyModuleDef_Slot module_slots[]={
    {Py_mod_exec,module_exec},
#if PY_VERSION_HEX >= 0x030c0000
    {Py_mod_multiple_interpreters,Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
#endif
#if PY_VERSION_HEX >= 0x030d0000
    {Py_mod_gil,Py_MOD_GIL_USED},
#endif
    {0,NULL}
};
static struct PyModuleDef definition={
    PyModuleDef_HEAD_INIT,"_hia_slot_mechanical",NULL,sizeof(ModuleState),
    methods,module_slots,module_traverse,module_clear,NULL
};
PyMODINIT_FUNC PyInit__hia_slot_mechanical(void) {
    return PyModuleDef_Init(&definition);
}
