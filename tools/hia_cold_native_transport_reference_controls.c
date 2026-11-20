/* R4 isolated ownership controls. Includes the exact production bridge.
 * Root compiles/runs this file. No gc.collect, traceback clearing, finalizer
 * normalization, child process, native HIA execution or policy timing is used.
 * The short-response callback below tests only the real rc<0 ownership branch.
 */
#define PY_SSIZE_T_CLEAN
#define _GNU_SOURCE 1
#include "hia_cold_native_transport_python.c"
#include <stdio.h>

typedef struct {
    const char *id;
    int passed, line, weak_dead, type_visited, raised_same, handled_same;
    long long before_refs, after_refs, before_type_refs, after_type_refs;
    Py_ssize_t unraisable_start, unraisable_end;
} Row;
static int failed_line;
#define CHECK(x) do { if(!(x)){failed_line=__LINE__;goto done;} } while(0)
static PyObject *probe_class, *probe_globals, *events, *policy_bytes, *identity;
static PyObject *extension_module;
static module_state *extension_state;

static uint64_t short_response(const void *a,uint64_t b,void *c,uint64_t d,void *e,uint64_t f) {
    (void)a;(void)b;(void)c;(void)d;(void)e;(void)f;
    return 0; /* Deliberate typed policy refusal, before any issued effect. */
}
static PyObject *error_instance(const char *label) {
    return PyObject_CallFunction(probe_class,"s",label);
}
static int weak_is_dead(PyObject *weak) {
    PyObject *object=NULL;
    int rc=PyWeakref_GetRef(weak,&object);
    Py_XDECREF(object);
    return rc==0;
}
static int handled_is(PyObject *expected) {
    PyObject *value=PyErr_GetHandledException();
    int same=value==expected;
    Py_XDECREF(value);
    return same;
}
static Profile *real_profile(void) {
    return (Profile *)PyObject_CallFunctionObjArgs(extension_state->profile_type,
                                                  policy_bytes,identity,NULL);
}
static Session *empty_heap_session(void) {
    PyTypeObject *type=(PyTypeObject *)extension_state->session_type;
    Session *s=(Session *)type->tp_alloc(type,0);
    if(s)for(unsigned i=0;i<9;++i)s->raw_fds[i]=-1;
    return s;
}
typedef struct {PyObject *expected;unsigned count;} Visit;
static int seen_type(PyObject *object,void *context) {
    Visit *value=context;
    if(object==value->expected)++value->count;
    return 0;
}
static void init_stack(Session *s,Profile *p) {
    memset(s,0,sizeof *s);memset(p,0,sizeof *p);
    for(unsigned i=0;i<9;++i)s->raw_fds[i]=-1;
    p->unknown=probe_class;s->profile=p;
}
static void dispose_stack(Session *s) {
    Py_CLEAR(s->pending);Py_CLEAR(s->caller);
    for(unsigned i=0;i<3;++i)Py_CLEAR(s->streams[i]);
    Py_CLEAR(s->owner);
}
static int event_count(Py_ssize_t *out) {
    if(!PyList_CheckExact(events))return 0;
    *out=PyList_GET_SIZE(events);return 1;
}
static int run_one(unsigned which,Row *row) {
    static const char *ids[]={
      "REF-01-empty-handled-state",
      "REF-02-existing-caller",
      "REF-03-pending-over-caller",
      "REF-04-host-before-repeat",
      "REF-05-host-perform-error",
      "REF-06-host-error-eintr",
      "REF-07-handoff-before-commit",
      "REF-08-real-close-callback",
      "REF-09-profile-heap-type",
      "REF-10-session-heap-type",
      "REF-11-profile-init-refusal",
      "REF-12-clear-preserves-raised",
      "REF-13-dealloc-preserves-raised",
      "REF-14-profile-dealloc-preserves-raised",
      "REF-15-session-run-refusal",
      "REF-16-uninitialized-profile",
      "REF-17-cleared-profile",
      "REF-18-session-without-live-profile"};
    memset(row,0,sizeof *row);row->id=ids[which];
    row->before_refs=row->after_refs=row->before_type_refs=row->after_type_refs=-1;
    PyObject *saved_raised=PyErr_GetRaisedException();
    PyObject *saved_handled=PyErr_GetHandledException();
    PyObject *caller=NULL,*pending=NULL,*weak=NULL,*weak2=NULL,*raised=NULL,*result=NULL;
    PyObject *caught=NULL,*arguments=NULL,*empty=NULL,*cwd=NULL,*timeout=NULL,*temporary_handled=NULL;
    Profile *profile=NULL;Session *heap=NULL;
    Session stack;Profile borrowed;int fd=-1,failed=1;
    init_stack(&stack,&borrowed);
    CHECK(event_count(&row->unraisable_start));
    caller=error_instance("caller");pending=error_instance("pending");
    CHECK(caller&&pending);
    weak=PyWeakref_NewRef(caller,NULL);weak2=PyWeakref_NewRef(pending,NULL);
    CHECK(weak&&weak2);
    PyErr_SetHandledException(NULL);
    if(which<=7){
        stack.caller=which==0?NULL:Py_NewRef(caller);
        if(which==0||which==2||which==3)stack.pending=Py_NewRef(pending);
        if(which!=0)PyErr_SetHandledException(caller);
        PyObject *subject=stack.pending?pending:caller;
        row->before_refs=Py_REFCNT(subject);
        if(which<=2){
            for(unsigned i=0;i<64;++i){
                temporary_handled=handled_enter(&stack);
                CHECK(handled_is(stack.pending?pending:stack.caller));
                handled_leave(temporary_handled);temporary_handled=NULL;
                CHECK(handled_is(which==0?NULL:caller));
                CHECK(Py_REFCNT(subject)==row->before_refs);
            }
        }else if(which==3){
            struct hia_cold_snapshot f={0};
            for(unsigned i=0;i<64;++i){
                CHECK(host_before(&stack,HCT_CLOCK,0,&f)==0);
                CHECK(handled_is(caller));
                CHECK(Py_REFCNT(subject)==row->before_refs);
            }
        }else if(which==4){
            struct hia_cold_snapshot f={0};
            CHECK(host_perform(&stack,UINT_MAX,0,&f)==HCT_PY_EXCEPTION);
            CHECK(stack.pending&&PyErr_GivenExceptionMatches(stack.pending,probe_class));
            CHECK(handled_is(caller));
            /* The actual new exception owns its actual caller context until it
               is normally released; it is not erased to match a count. */
            Py_CLEAR(stack.pending);
            CHECK(Py_REFCNT(caller)==row->before_refs);
        }else if(which==5){
            struct hia_cold_snapshot f={0};
            CHECK(host_error(&stack,HCT_WAIT_BLOCK,0,EINTR,&f)==EINTR);
            CHECK(handled_is(caller));
        }else if(which==6){
            int facts[9];for(unsigned i=0;i<9;++i)facts[i]=-1;
            struct hia_cold_snapshot f={0};f.fds=facts;
            CHECK(host_handoff(&stack,&f)==0&&stack.handoff);
            CHECK(handled_is(caller));
        }else{
            struct hia_cold_snapshot f={0};int retired=0;
            fd=open("/dev/null",O_RDONLY|O_CLOEXEC);CHECK(fd>=3);
            int number=fd;
            unsigned error=host_close(&stack,0,fd,&retired,&f);
            if(retired)fd=-1;
            CHECK(error==0&&retired&&fcntl(number,F_GETFD)==-1&&errno==EBADF);
            CHECK(handled_is(caller));
        }
        row->after_refs=Py_REFCNT(subject);
        CHECK(row->before_refs==row->after_refs);
        row->handled_same=handled_is(which==0?NULL:caller);
        CHECK(row->handled_same);
    }else if(which==8||which==9){
        PyTypeObject *kind=(PyTypeObject *)(which==8?extension_state->profile_type:extension_state->session_type);
        row->before_type_refs=Py_REFCNT(kind);
        Visit visited={(PyObject *)kind,0};
        if(which==8){
            profile=(Profile *)kind->tp_alloc(kind,0);CHECK(profile);
            CHECK(Py_REFCNT(kind)==row->before_type_refs+1);
            CHECK(profile_traverse(profile,seen_type,&visited)==0);
            row->type_visited=visited.count==1;CHECK(row->type_visited);
            Py_CLEAR(profile);
        }else{
            heap=empty_heap_session();CHECK(heap);
            CHECK(Py_REFCNT(kind)==row->before_type_refs+1);
            CHECK(session_traverse(heap,seen_type,&visited)==0);
            row->type_visited=visited.count==1;CHECK(row->type_visited);
            Py_CLEAR(heap);
        }
        row->after_type_refs=Py_REFCNT(kind);CHECK(row->after_type_refs==row->before_type_refs);
    }else if(which==10){
        row->before_type_refs=Py_REFCNT(extension_state->profile_type);
        empty=PyBytes_FromStringAndSize("",0);CHECK(empty);
        result=PyObject_CallFunctionObjArgs(extension_state->profile_type,empty,identity,NULL);
        CHECK(!result&&PyErr_ExceptionMatches(PyExc_TypeError));
        caught=PyErr_GetRaisedException();CHECK(caught);
        Py_CLEAR(caught);
        row->after_type_refs=Py_REFCNT(extension_state->profile_type);
        CHECK(row->before_type_refs==row->after_type_refs);
    }else if(which==11||which==12){
        heap=empty_heap_session();CHECK(heap);
        /* Real EBADF after a real, already retired generation. No descriptor
           number is reused before the one failing close attempt. */
        fd=open("/dev/null",O_RDONLY|O_CLOEXEC);CHECK(fd>=3);
        int number=fd;CHECK(close(fd)==0);fd=-1;heap->raw_fds[0]=number;
        raised=error_instance("raised-on-entry");CHECK(raised);
        row->before_refs=Py_REFCNT(raised);
        PyErr_SetRaisedException(Py_NewRef(raised));
        if(which==11)CHECK(session_clear(heap)==0);
        else Py_CLEAR(heap);
        caught=PyErr_GetRaisedException();CHECK(caught);
        row->raised_same=caught==raised;CHECK(row->raised_same);
        Py_CLEAR(caught);
        row->after_refs=Py_REFCNT(raised);CHECK(row->before_refs==row->after_refs);
        CHECK(PyList_GET_SIZE(events)==row->unraisable_start+1);
        PyObject *event=PyList_GET_ITEM(events,row->unraisable_start);
        PyObject *context=PyDict_GetItemString(event,"object_id");
        CHECK(context);
        if(which==12)CHECK(context==Py_None);
        else {PyObject *number=PyLong_FromVoidPtr(heap);CHECK(number);int same=PyObject_RichCompareBool(context,number,Py_EQ);Py_DECREF(number);CHECK(same==1);}
        if(heap)for(unsigned i=0;i<9;++i)CHECK(heap->raw_fds[i]==-1);
    }else if(which==13){
        PyTypeObject *kind=(PyTypeObject *)extension_state->profile_type;
        profile=(Profile *)kind->tp_alloc(kind,0);CHECK(profile);
        raised=error_instance("profile-raised");CHECK(raised);
        PyErr_SetRaisedException(Py_NewRef(raised));Py_CLEAR(profile);
        caught=PyErr_GetRaisedException();CHECK(caught);
        row->raised_same=caught==raised;CHECK(row->raised_same);Py_CLEAR(caught);
    }else if(which==14){
        profile=real_profile();CHECK(profile);
        empty=PyBytes_FromStringAndSize("",0);cwd=PyUnicode_FromString("/");
        timeout=PyFloat_FromDouble(20.0);arguments=PyTuple_New(0);
        CHECK(empty&&cwd&&timeout&&arguments);
        result=PyTuple_Pack(8,empty,empty,cwd,timeout,arguments,Py_None,Py_None,Py_False);
        CHECK(result);
        heap=(Session *)profile_session(profile,result);Py_CLEAR(result);CHECK(heap);
        hia_cold_policy actual_policy=profile->policy;
        profile->policy=short_response;
        PyErr_SetHandledException(caller);row->before_refs=Py_REFCNT(caller);
        result=session_run(heap,NULL);
        profile->policy=actual_policy;
        CHECK(!result&&PyErr_Occurred());
        caught=PyErr_GetRaisedException();CHECK(caught);
        CHECK(PyErr_GivenExceptionMatches(caught,profile->unknown));
        CHECK(heap->finished&&profile->unknowns==1&&heap->result.action_count==0);
        CHECK(heap->result.final_fd_mask==0&&heap->result.child_pid==0);
        CHECK(handled_is(caller));
        Py_CLEAR(heap);Py_CLEAR(caught);
        row->after_refs=Py_REFCNT(caller);CHECK(row->before_refs==row->after_refs);
        row->handled_same=handled_is(caller);
    }else if(which==15){
        PyTypeObject *kind=(PyTypeObject *)extension_state->profile_type;
        profile=(Profile *)kind->tp_alloc(kind,0);CHECK(profile);
        CHECK(!profile_current(profile)&&PyErr_ExceptionMatches(PyExc_RuntimeError));
        caught=PyErr_GetRaisedException();CHECK(caught);Py_CLEAR(caught);
        result=profile_statistics(profile,NULL);
        CHECK(!result&&PyErr_ExceptionMatches(PyExc_RuntimeError));
        caught=PyErr_GetRaisedException();CHECK(caught);Py_CLEAR(caught);
    }else if(which==16){
        profile=real_profile();CHECK(profile&&profile->initialized);
        CHECK(profile_clear(profile)==0&&!profile->initialized);
        CHECK(!profile_current(profile)&&PyErr_ExceptionMatches(PyExc_RuntimeError));
        caught=PyErr_GetRaisedException();CHECK(caught);Py_CLEAR(caught);
        result=profile_statistics(profile,NULL);
        CHECK(!result&&PyErr_ExceptionMatches(PyExc_RuntimeError));
        caught=PyErr_GetRaisedException();CHECK(caught);Py_CLEAR(caught);
    }else{
        heap=empty_heap_session();CHECK(heap);
        result=session_run(heap,NULL);
        CHECK(!result&&PyErr_ExceptionMatches(PyExc_RuntimeError));
        caught=PyErr_GetRaisedException();CHECK(caught);Py_CLEAR(caught);
        profile=real_profile();CHECK(profile);
        heap->profile=(Profile *)Py_NewRef(profile);CHECK(profile_clear(profile)==0);
        result=session_run(heap,NULL);
        CHECK(!result&&PyErr_ExceptionMatches(PyExc_RuntimeError));
        caught=PyErr_GetRaisedException();CHECK(caught);Py_CLEAR(caught);
    }
    dispose_stack(&stack);
    PyErr_SetHandledException(NULL);
    Py_CLEAR(caller);Py_CLEAR(pending);
    row->weak_dead=weak_is_dead(weak)&&weak_is_dead(weak2);CHECK(row->weak_dead);
    CHECK(event_count(&row->unraisable_end));
    if(which!=11&&which!=12)CHECK(row->unraisable_end==row->unraisable_start);
    failed=0;
done:
    if(PyErr_Occurred()){PyErr_Print();failed=1;}
    if(temporary_handled){handled_leave(temporary_handled);temporary_handled=NULL;}
    dispose_stack(&stack);
    PyErr_SetHandledException(saved_handled);Py_XDECREF(saved_handled);
    Py_XDECREF(result);Py_XDECREF(caught);Py_XDECREF(heap);Py_XDECREF(profile);
    Py_XDECREF(arguments);Py_XDECREF(empty);Py_XDECREF(cwd);Py_XDECREF(timeout);
    Py_XDECREF(caller);Py_XDECREF(pending);Py_XDECREF(raised);Py_XDECREF(weak);Py_XDECREF(weak2);
    if(fd>=0&&close(fd)!=0)failed=1;
    if(PyErr_Occurred()){PyErr_Print();failed=1;}
    PyErr_SetRaisedException(saved_raised);
    row->passed=!failed;row->line=failed?failed_line:0;
    return failed;
}
static PyObject *read_bytes(const char *path) {
    FILE *file=fopen(path,"rb");if(!file)return NULL;
    if(fseek(file,0,SEEK_END)!=0){fclose(file);return NULL;}
    long size=ftell(file);if(size<=0||fseek(file,0,SEEK_SET)!=0){fclose(file);return NULL;}
    PyObject *value=PyBytes_FromStringAndSize(NULL,size);
    if(!value){fclose(file);return NULL;}
    size_t count=fread(PyBytes_AS_STRING(value),1,(size_t)size,file);
    int bad=ferror(file)||count!=(size_t)size;int rc=fclose(file);
    if(bad||rc!=0){Py_DECREF(value);return NULL;}
    return value;
}
int main(int argc,char **argv) {
    if(argc!=5)return 64; /* PYTHON POLICY SOURCE_ID REPORT */
    if(PyImport_AppendInittab("_hia_cold_native_transport",PyInit__hia_cold_native_transport)<0)return 65;
    PyConfig config;PyConfig_InitIsolatedConfig(&config);
    config.site_import=0;config.write_bytecode=0;
    PyStatus status=PyConfig_SetBytesString(&config,&config.program_name,argv[1]);
    if(!PyStatus_Exception(status))status=PyConfig_SetBytesString(&config,&config.executable,argv[1]);
    if(!PyStatus_Exception(status))status=Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);if(PyStatus_Exception(status))Py_ExitStatusException(status);
    int failed=1;FILE *report=NULL;PyObject *old_hook=NULL,*sys=NULL,*json=NULL,*serialized=NULL;
    Row rows[18];memset(rows,0,sizeof rows);
    extension_module=PyImport_ImportModule("_hia_cold_native_transport");
    if(!extension_module)goto done;
    extension_state=PyModule_GetState(extension_module);if(!extension_state)goto done;
    policy_bytes=read_bytes(argv[2]);identity=PyUnicode_FromString(argv[3]);
    if(!policy_bytes||!identity||PyUnicode_GET_LENGTH(identity)!=64)goto done;
    probe_globals=PyDict_New();if(!probe_globals)goto done;
    if(PyDict_SetItemString(probe_globals,"__builtins__",PyEval_GetBuiltins())<0)goto done;
    PyObject *executed=PyRun_String(
      "import sys\n"
      "class ProbeError(RuntimeError):\n"
      "    __slots__ = ('__weakref__',)\n"
      "events = []\n"
      "def hook(record):\n"
      "    events.append({'exception_type': type(record.exc_value).__module__ + '.' + type(record.exc_value).__qualname__,"
      " 'message': str(record.exc_value), 'errno': getattr(record.exc_value, 'errno', None),"
      " 'exception_id': id(record.exc_value), 'object_type': None if record.object is None else type(record.object).__module__ + '.' + type(record.object).__qualname__,"
      " 'object_id': None if record.object is None else id(record.object), 'traceback_present': record.exc_traceback is not None})\n",
      Py_file_input,probe_globals,probe_globals);
    if(!executed)goto done;Py_DECREF(executed);
    probe_class=PyDict_GetItemString(probe_globals,"ProbeError");
    events=PyDict_GetItemString(probe_globals,"events");
    PyObject *hook=PyDict_GetItemString(probe_globals,"hook");
    if(!probe_class||!events||!hook)goto done;
    sys=PyImport_ImportModule("sys");if(!sys)goto done;
    old_hook=PyObject_GetAttrString(sys,"unraisablehook");if(!old_hook)goto done;
    if(PyObject_SetAttrString(sys,"unraisablehook",hook)<0)goto done;
    failed=0;
    for(unsigned i=0;i<18;++i)failed|=run_one(i,&rows[i]);
    if(PyObject_SetAttrString(sys,"unraisablehook",old_hook)<0){failed=1;goto done;}
    json=PyImport_ImportModule("json");if(!json){failed=1;goto done;}
    serialized=PyObject_CallMethod(json,"dumps","(O)",events);if(!serialized){failed=1;goto done;}
    const char *event_text=PyUnicode_AsUTF8(serialized);if(!event_text){failed=1;goto done;}
    report=fopen(argv[4],"wx");if(!report){failed=1;goto done;}
    if(fprintf(report,"{\"schema\":\"hepta.cold-native-transport.reference-controls.r4\","
                      "\"scope\":\"ISOLATED_C_API_OWNERSHIP_NOT_CT36_OR_COLD_QUALIFICATION\","
                      "\"planned\":18,\"controls\":[")<0)failed=1;
    for(unsigned i=0;i<18;++i){
        Row *r=&rows[i];
        if(fprintf(report,"%s{\"id\":\"%s\",\"passed\":%s,\"failure_line\":%d,"
              "\"before_refs\":%lld,\"after_refs\":%lld,\"before_type_refs\":%lld,\"after_type_refs\":%lld,"
              "\"weak_dead\":%s,\"type_visited\":%s,\"raised_same\":%s,\"handled_same\":%s,"
              "\"unraisable_start\":%zd,\"unraisable_end\":%zd}",
              i?",":"",r->id,r->passed?"true":"false",r->line,r->before_refs,r->after_refs,
              r->before_type_refs,r->after_type_refs,r->weak_dead?"true":"false",
              r->type_visited?"true":"false",r->raised_same?"true":"false",r->handled_same?"true":"false",
              r->unraisable_start,r->unraisable_end)<0)failed=1;
    }
    if(fprintf(report,"],\"unraisables\":%s,\"explicit_collect_calls\":0,\"tracebacks_modified\":false,"
                      "\"whole_native\":false,\"status\":\"%s\"}\n",
               event_text,failed?"HOLD":"CONTROLS_PASS")<0)failed=1;
done:
    if(PyErr_Occurred()){PyErr_Print();failed=1;}
    if(sys&&old_hook&&PyObject_SetAttrString(sys,"unraisablehook",old_hook)<0){PyErr_Print();failed=1;}
    if(report&&fclose(report)!=0)failed=1;
    Py_XDECREF(serialized);Py_XDECREF(json);Py_XDECREF(old_hook);Py_XDECREF(sys);
    Py_CLEAR(policy_bytes);Py_CLEAR(identity);Py_CLEAR(probe_globals);
    probe_class=NULL;events=NULL;extension_state=NULL;
    Py_CLEAR(extension_module);
    if(Py_FinalizeEx()<0)failed=1;
    return failed?1:0;
}
