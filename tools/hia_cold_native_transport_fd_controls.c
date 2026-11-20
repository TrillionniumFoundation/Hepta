/* Root-only FD ownership controls for the explicit hosted cold transport.
 * Includes the exact production bridge; never changes the production policy.
 * Allocation faults hit the real CPython 3.14 Buffered buffer allocation.
 * No gc.collect, traceback mutation, resource-number probing as ownership,
 * provider replacement in the admitted production Profile, or fake terminal.
 */
#define PY_SSIZE_T_CLEAN
#define _GNU_SOURCE 1
#include "hia_cold_native_transport_python.c"
#include <stdio.h>
#include <signal.h>

typedef struct {
    const char *id;int passed,line,slot,fd,live_before,live_after,close_errno;
    unsigned ownership,audit_calls,allocation_hits,before_failures,handoff_failures;
    int error_expected,context_expected,policy_complete,reaped,owner_lost,child_created;
    uint64_t entries,final_mask,residual_mask;
    PyObject *error_observation;
} Row;
static PyObject *probe_class,*probe_globals,*policy_bytes,*identity,*target_bytes;
static PyObject *extension_module,*describe_error,*unraisables;
static module_state *extension_state;
static int failed_line,audit_fd=-1;
static unsigned audit_active,audit_calls;
static PyObject *audit_error;
#define CHECK(x) do {if(!(x)){failed_line=__LINE__;goto done;}} while(0)
typedef struct {
    PyMemAllocatorEx previous;unsigned armed,hits,close_first;
    int descriptor,closed_rc,closed_errno;
} Allocation;
static Allocation allocation;
static int fd_live(int fd) {errno=0;return fcntl(fd,F_GETFD)>=0;}
static void *fault_malloc(void *context,size_t count) {
    Allocation *a=context;
    if(a->armed&&count==128*1024){
        a->armed=0;++a->hits;
        if(a->close_first){a->closed_rc=close(a->descriptor);a->closed_errno=errno;}
        return NULL;
    }
    return a->previous.malloc(a->previous.ctx,count);
}
static void *fault_calloc(void *context,size_t n,size_t size) {
    Allocation *a=context;
    return a->previous.calloc(a->previous.ctx,n,size);
}
static void *fault_realloc(void *context,void *pointer,size_t size) {
    Allocation *a=context;
    return a->previous.realloc(a->previous.ctx,pointer,size);
}
static void fault_free(void *context,void *pointer) {
    Allocation *a=context;a->previous.free(a->previous.ctx,pointer);
}
static void arm_allocation(int descriptor,int close_first) {
    memset(&allocation,0,sizeof allocation);
    PyMem_GetAllocator(PYMEM_DOMAIN_MEM,&allocation.previous);
    allocation.armed=1;allocation.descriptor=descriptor;allocation.close_first=(unsigned)close_first;
    PyMemAllocatorEx replacement={&allocation,fault_malloc,fault_calloc,fault_realloc,fault_free};
    PyMem_SetAllocator(PYMEM_DOMAIN_MEM,&replacement);
}
static void disarm_allocation(void) {
    PyMem_SetAllocator(PYMEM_DOMAIN_MEM,&allocation.previous);allocation.armed=0;
}
static int audit_hook(const char *event,PyObject *args,void *unused) {
    (void)unused;
    if(audit_active&&strcmp(event,"open")==0&&PyTuple_Check(args)&&PyTuple_GET_SIZE(args)>0){
        PyObject *path=PyTuple_GET_ITEM(args,0);
        if(PyLong_CheckExact(path)){
            long fd=PyLong_AsLong(path);
            if(fd==-1&&PyErr_Occurred())return -1;
            if(fd==audit_fd){
                ++audit_calls;PyErr_SetObject(probe_class,audit_error);return -1;
            }
        }
    }
    return 0;
}
static Profile *real_profile(void) {
    return (Profile *)PyObject_CallFunctionObjArgs(extension_state->profile_type,policy_bytes,identity,NULL);
}
static Session *real_session(Profile *p) {
    PyObject *empty=PyBytes_FromStringAndSize("",0),*cwd=PyUnicode_FromString("/"),*timeout=PyFloat_FromDouble(20.0);
    PyObject *args=PyTuple_New(0),*bundle=NULL,*answer=NULL;
    if(empty&&cwd&&timeout&&args)
        bundle=PyTuple_Pack(8,target_bytes,empty,cwd,timeout,args,Py_None,Py_None,Py_False);
    if(bundle)answer=profile_session(p,bundle);
    Py_XDECREF(bundle);Py_XDECREF(args);Py_XDECREF(timeout);Py_XDECREF(cwd);Py_XDECREF(empty);
    return (Session *)answer;
}
static Session *empty_session(Profile *p) {
    PyTypeObject *type=(PyTypeObject *)extension_state->session_type;
    Session *s=(Session *)type->tp_alloc(type,0);
    if(s){
        for(unsigned i=0;i<9;++i){s->raw_fds[i]=-1;s->result.remaining_fds[i]=-1;}
        s->profile=(Profile *)Py_NewRef(p);
    }
    return s;
}
static int record_error(Row *row,PyObject *error) {
    if(!error)return 1;
    row->error_observation=PyObject_CallOneArg(describe_error,error);
    return row->error_observation!=NULL;
}
static void init_stack(Session *s,Profile *p) {
    memset(s,0,sizeof *s);for(unsigned i=0;i<9;++i)s->raw_fds[i]=-1;
    s->profile=p;
}
static void dispose_stack(Session *s) {
    Py_CLEAR(s->pending);Py_CLEAR(s->caller);
    for(unsigned i=0;i<3;++i)Py_CLEAR(s->streams[i]);
    Py_CLEAR(s->owner);Py_CLEAR(s->args);Py_CLEAR(s->environment);
}
static unsigned fail_before_count,fail_handoff_count;
static unsigned fail_final_memfd(void *context,unsigned action,unsigned arg,const struct hia_cold_snapshot *f) {
    unsigned result=host_before(context,action,arg,f);
    if(result)return result;
    if(action==HCT_CLOSE&&arg==0&&f->reaped){
        ++fail_before_count;
        PyErr_SetString(probe_class,"FD control: actual final-memfd close capability refused");
        return take_error(context);
    }
    return 0;
}
static int refuse_handoff(void *context,const struct hia_cold_snapshot *f) {
    (void)f;++fail_handoff_count;
    PyErr_SetString(probe_class,"FD control: actual handoff capability refused before commit");
    (void)take_error(context);return -1;
}
static int run_one(unsigned which,Row *row) {
    static const char *ids[]={
        "FD-01-canonical-stdin","FD-02-canonical-stdout","FD-03-canonical-stderr",
        "FD-04-fileio-audit-refusal","FD-05-buffer-allocation-stdin",
        "FD-06-buffer-allocation-stdout","FD-07-buffer-allocation-stderr",
        "FD-08-raw-close-error-context","FD-09-issued-slot-mismatch",
        "FD-10-stream-already-owned","FD-11-terminal-residual",
        "FD-12-terminal-existing-raw","FD-13-terminal-existing-stream",
        "FD-14-two-terminal-residuals","FD-15-residual-dealloc-raised",
        "FD-16-real-policy-return","FD-17-real-policy-buffer-error",
        "FD-18-real-policy-all-handoffs-refused"};
    memset(row,0,sizeof *row);row->id=ids[which];row->slot=-1;row->fd=-1;
    PyObject *saved_raised=PyErr_GetRaisedException(),*saved_handled=PyErr_GetHandledException();
    PyObject *error=NULL,*context=NULL,*value=NULL,*returned=NULL,*old=NULL,*marker=NULL;
    Profile *p=NULL;Session *heap=NULL;Session stack;
    int fd=-1,other=-1,failed=1,allocator_set=0,stack_ready=0;
    unsigned ownership=0;int facts[9];for(unsigned i=0;i<9;++i)facts[i]=-1;
    struct hia_cold_snapshot f={0};f.fds=facts;
    PyErr_SetHandledException(NULL);
    p=real_profile();CHECK(p);
    init_stack(&stack,p);stack_ready=1;
    if(which<10){
        unsigned slots[3]={2,3,5};
        unsigned slot=which<3?slots[which]:which>=4&&which<=6?slots[which-4]:2;
        unsigned index=slot==2?0:slot==3?1:2;
        row->slot=(int)slot;
        fd=open("/dev/null",(slot==2?O_WRONLY:O_RDONLY)|O_CLOEXEC);CHECK(fd>=3);
        row->fd=fd;facts[slot]=fd;row->live_before=fd_live(fd);CHECK(row->live_before);
        /* This is an actual Popen object for the original successful attribute
           assignment. No __init__ or whole old subprocess method is executed. */
        PyObject *newfunc=get_module_attr(p->popen_class,"__new__");
        CHECK(newfunc);
        stack.owner=PyObject_CallOneArg(newfunc,p->popen_class);Py_DECREF(newfunc);
        CHECK(stack.owner);
        if(which==3){
            audit_error=PyObject_CallFunction(probe_class,"s","FileIO actual audit refusal");CHECK(audit_error);
            audit_fd=fd;audit_calls=0;audit_active=1;
        }
        if(which>=4&&which<=7){
            arm_allocation(fd,which==7);allocator_set=1;
        }
        if(which==8)facts[slot]=-1;
        unsigned number=host_wrap(&stack,slot,fd,&ownership,&f);
        if(allocator_set){disarm_allocation();allocator_set=0;}
        audit_active=0;
        row->ownership=ownership;row->allocation_hits=allocation.hits;row->audit_calls=audit_calls;
        row->close_errno=allocation.close_first?allocation.closed_errno:0;
        if(stack.streams[index]||(ownership&2))fd=-1;
        error=Py_XNewRef(stack.pending);
        CHECK(record_error(row,error));
        if(which<3){
            CHECK(number==0&&ownership==0&&stack.streams[index]);
            CHECK((PyObject *)Py_TYPE(stack.streams[index])==(slot==2?p->buffered_writer:p->buffered_reader));
            value=get_module_attr(stack.streams[index],"raw");CHECK(value);
            CHECK((PyObject *)Py_TYPE(value)==p->fileio_class);
            PyObject *closefd=get_module_attr(value,"closefd");CHECK(closefd==Py_True);Py_DECREF(closefd);Py_CLEAR(value);
            int retired=0;CHECK(host_close(&stack,slot,row->fd,&retired,&f)==0&&retired);
            row->live_after=fd_live(row->fd);CHECK(!row->live_after&&errno==EBADF);
        }else if(which==3){
            CHECK(number==HCT_PY_EXCEPTION&&ownership==0&&error==audit_error&&audit_calls==1);
            CHECK(!stack.streams[index]);row->error_expected=1;
            row->live_after=fd_live(row->fd);CHECK(row->live_after);
        }else if(which<=7){
            CHECK(number==HCT_PY_EXCEPTION&&ownership==3&&allocation.hits==1&&!stack.streams[index]&&error);
            row->live_after=fd_live(row->fd);CHECK(!row->live_after&&errno==EBADF);
            if(which==7){
                CHECK(allocation.closed_rc==0&&PyErr_GivenExceptionMatches(error,PyExc_OSError));
                context=PyException_GetContext(error);CHECK(context&&PyErr_GivenExceptionMatches(context,PyExc_MemoryError));
                value=PyObject_GetAttrString(error,"errno");CHECK(value);
                CHECK(PyLong_AsLong(value)==EBADF&&!PyErr_Occurred());Py_CLEAR(value);
                row->context_expected=1;
            }else CHECK(PyErr_GivenExceptionMatches(error,PyExc_MemoryError));
            row->error_expected=1;
        }else if(which==8){
            CHECK(number==HCT_PY_EXCEPTION&&ownership==0&&!stack.streams[index]);
            CHECK(error&&PyErr_GivenExceptionMatches(error,p->unknown));row->error_expected=1;
            row->live_after=fd_live(row->fd);CHECK(row->live_after);
        }else{
            CHECK(number==0&&ownership==0&&stack.streams[index]);Py_CLEAR(error);
            number=host_wrap(&stack,slot,row->fd,&ownership,&f);
            error=Py_XNewRef(stack.pending);CHECK(record_error(row,error));
            CHECK(number==HCT_PY_EXCEPTION&&ownership==0&&error&&PyErr_GivenExceptionMatches(error,p->unknown));
            row->error_expected=1;row->live_after=fd_live(row->fd);CHECK(row->live_after);
        }
    }else if(which<=14){
        heap=empty_session(p);CHECK(heap);
        fd=open("/dev/null",O_RDONLY|O_CLOEXEC);CHECK(fd>=3);
        row->fd=fd;row->live_before=fd_live(fd);CHECK(row->live_before);
        heap->result.remaining_fds[0]=fd;row->slot=0;
        if(which==11)heap->raw_fds[0]=fd;
        if(which==12){
            /* The actual stream already owns this descriptor. */
            heap->streams[1]=PyObject_CallFunction(p->fileio_class,"isOO",fd,"r",Py_True,Py_None);
            CHECK(heap->streams[1]);heap->stream_fds[1]=fd;
        }
        if(which==13){
            other=open("/dev/null",O_RDONLY|O_CLOEXEC);CHECK(other>=3&&other!=fd);
            heap->result.remaining_fds[8]=other;
        }
        keep_terminal_fds(heap);
        row->residual_mask=heap->residual_fd_mask;
        CHECK(heap->residual_fd_mask==((which==11||which==12)?0:which==13?257:1));
        CHECK(!heap->handoff&&!heap->result.policy_complete);
        int number=fd,number2=other;fd=-1;other=-1;
        if(which==14){
            marker=PyObject_CallFunction(probe_class,"s","raised before residual deallocation");CHECK(marker);
            PyErr_SetRaisedException(Py_NewRef(marker));
        }
        Py_CLEAR(heap);
        if(which==14){old=PyErr_GetRaisedException();CHECK(old==marker);Py_CLEAR(old);row->error_expected=1;}
        row->live_after=fd_live(number);CHECK(!row->live_after&&errno==EBADF);
        if(number2>=0)CHECK(!fd_live(number2)&&errno==EBADF);
    }else{
        heap=real_session(p);CHECK(heap);
        if(which==16){arm_allocation(-1,0);allocator_set=1;}
        if(which==17){
            fail_before_count=fail_handoff_count=0;
            heap->host.before=fail_final_memfd;heap->host.handoff=refuse_handoff;
        }
        returned=session_run(heap,NULL);
        if(allocator_set){disarm_allocation();allocator_set=0;}
        error=PyErr_GetRaisedException();CHECK(record_error(row,error));
        row->allocation_hits=allocation.hits;
        row->before_failures=fail_before_count;row->handoff_failures=fail_handoff_count;
        row->policy_complete=(int)heap->result.policy_complete;row->reaped=(int)heap->result.reaped;
        row->owner_lost=(int)heap->result.owner_lost;row->child_created=(int)heap->result.spawned;
        row->entries=heap->result.action_count;row->final_mask=heap->result.final_fd_mask;
        row->residual_mask=heap->residual_fd_mask;
        CHECK(row->entries>0);
        if(which==15){
            CHECK(returned&&!error&&row->policy_complete&&row->reaped&&row->child_created
                  &&row->final_mask==0&&row->residual_mask==0&&!heap->result.handed_off);
            value=get_module_attr(returned,"returncode");CHECK(value&&PyLong_AsLong(value)==0&&!PyErr_Occurred());Py_CLEAR(value);
        }else if(which==16){
            CHECK(!returned&&error&&PyErr_GivenExceptionMatches(error,PyExc_MemoryError));
            CHECK(allocation.hits==1&&row->policy_complete&&!row->child_created
                  &&row->final_mask==0&&row->residual_mask==0&&!heap->result.handed_off);
            row->error_expected=1;
        }else{
            CHECK(!returned&&error&&PyErr_GivenExceptionMatches(error,p->unknown));
            CHECK(!row->policy_complete&&row->reaped&&row->child_created&&!row->owner_lost
                  &&row->final_mask==1&&row->residual_mask==1&&!heap->result.handed_off);
            CHECK(fail_before_count==1&&fail_handoff_count>=2);
            row->fd=heap->residual_fds[0];row->live_before=fd_live(row->fd);CHECK(row->live_before);
            CHECK(heap->raw_fds[0]==-1&&heap->result.remaining_fds[0]==row->fd);
            Py_CLEAR(heap);
            row->live_after=fd_live(row->fd);CHECK(!row->live_after&&errno==EBADF);
            row->error_expected=1;
        }
    }
    failed=0;
done:
    if(allocator_set)disarm_allocation();
    audit_active=0;audit_fd=-1;Py_CLEAR(audit_error);
    if(PyErr_Occurred()){PyErr_Print();failed=1;}
    if(fd>=0&&close(fd)!=0)failed=1;
    if(other>=0&&close(other)!=0)failed=1;
    Py_XDECREF(old);Py_XDECREF(marker);Py_XDECREF(returned);Py_XDECREF(value);
    Py_XDECREF(context);Py_XDECREF(error);Py_XDECREF(heap);
    if(stack_ready)dispose_stack(&stack);
    Py_XDECREF(p);
    PyErr_SetHandledException(saved_handled);Py_XDECREF(saved_handled);
    PyErr_SetRaisedException(saved_raised);
    row->passed=!failed;row->line=failed?failed_line:0;
    return failed;
}
static PyObject *read_bytes(const char *path) {
    FILE *f=fopen(path,"rb");if(!f)return PyErr_SetFromErrno(PyExc_OSError);
    if(fseek(f,0,SEEK_END)!=0){fclose(f);return PyErr_SetFromErrno(PyExc_OSError);}
    long size=ftell(f);if(size<0||fseek(f,0,SEEK_SET)!=0){fclose(f);return PyErr_SetFromErrno(PyExc_OSError);}
    PyObject *raw=PyBytes_FromStringAndSize(NULL,(Py_ssize_t)size);
    if(raw&&fread(PyBytes_AS_STRING(raw),1,(size_t)size,f)!=(size_t)size){Py_CLEAR(raw);PyErr_SetString(PyExc_OSError,"short control input");}
    if(fclose(f)!=0&&raw){Py_CLEAR(raw);PyErr_SetFromErrno(PyExc_OSError);}
    return raw;
}
int main(int argc,char **argv) {
    if(argc!=6)return 64; /* PYTHON POLICY SOURCE_ID TARGET REPORT */
    /* This isolated test process establishes the explicit Linux profile;
       the production dispatcher never mutates its caller's dispositions. */
    struct sigaction ignored,children;memset(&ignored,0,sizeof ignored);memset(&children,0,sizeof children);
    sigemptyset(&ignored.sa_mask);sigemptyset(&children.sa_mask);
    ignored.sa_handler=SIG_IGN;children.sa_handler=SIG_DFL;
    if(sigaction(SIGPIPE,&ignored,NULL)!=0||sigaction(SIGCHLD,&children,NULL)!=0)return 65;
    if(PyImport_AppendInittab("_hia_cold_native_transport",PyInit__hia_cold_native_transport)<0)return 65;
    PyConfig config;PyConfig_InitIsolatedConfig(&config);config.site_import=0;config.write_bytecode=0;
    PyStatus status=PyConfig_SetBytesString(&config,&config.program_name,argv[1]);
    if(!PyStatus_Exception(status))status=PyConfig_SetBytesString(&config,&config.executable,argv[1]);
    if(!PyStatus_Exception(status))status=Py_InitializeFromConfig(&config);PyConfig_Clear(&config);
    if(PyStatus_Exception(status))Py_ExitStatusException(status);
    int failed=1;FILE *report=NULL;PyObject *sys=NULL,*old_hook=NULL,*json=NULL,*serialized=NULL,*rows=NULL;
    Row observations[18];memset(observations,0,sizeof observations);
    extension_module=PyImport_ImportModule("_hia_cold_native_transport");if(!extension_module)goto done;
    extension_state=PyModule_GetState(extension_module);if(!extension_state)goto done;
    policy_bytes=read_bytes(argv[2]);identity=PyUnicode_FromString(argv[3]);target_bytes=read_bytes(argv[4]);
    if(!policy_bytes||!identity||!target_bytes||!PyBytes_GET_SIZE(target_bytes))goto done;
    probe_globals=PyDict_New();if(!probe_globals)goto done;
    if(PyDict_SetItemString(probe_globals,"__builtins__",PyEval_GetBuiltins())<0)goto done;
    PyObject *executed=PyRun_String(
      "import sys\n"
      "class ProbeError(RuntimeError): pass\n"
      "unraisables = []\n"
      "def describe(error):\n"
      "    seen = set()\n"
      "    def visit(value):\n"
      "        if value is None: return None\n"
      "        if id(value) in seen: return {'cycle_id': id(value)}\n"
      "        seen.add(id(value))\n"
      "        frames = []\n"
      "        tb = value.__traceback__\n"
      "        while tb is not None:\n"
      "            frames.append({'filename': tb.tb_frame.f_code.co_filename, 'name': tb.tb_frame.f_code.co_name, 'line': tb.tb_lineno, 'lasti': tb.tb_lasti})\n"
      "            tb = tb.tb_next\n"
      "        return {'id': id(value), 'type': type(value).__module__ + '.' + type(value).__qualname__, 'args': repr(value.args), 'message': str(value), 'errno': getattr(value, 'errno', None), 'filename': getattr(value, 'filename', None), 'suppress_context': value.__suppress_context__, 'traceback': frames, 'cause': visit(value.__cause__), 'context': visit(value.__context__)}\n"
      "    return visit(error)\n"
      "def hook(record):\n"
      "    unraisables.append({'exception': describe(record.exc_value), 'object_id': None if record.object is None else id(record.object), 'traceback_present': record.exc_traceback is not None})\n",
      Py_file_input,probe_globals,probe_globals);
    if(!executed)goto done;Py_DECREF(executed);
    probe_class=PyDict_GetItemString(probe_globals,"ProbeError");
    describe_error=PyDict_GetItemString(probe_globals,"describe");
    unraisables=PyDict_GetItemString(probe_globals,"unraisables");
    PyObject *hook=PyDict_GetItemString(probe_globals,"hook");
    if(!probe_class||!describe_error||!unraisables||!hook||PySys_AddAuditHook(audit_hook,NULL)<0)goto done;
    sys=PyImport_ImportModule("sys");if(!sys)goto done;
    old_hook=get_module_attr(sys,"unraisablehook");if(!old_hook)goto done;
    if(set_object(sys,"unraisablehook",hook)<0)goto done;
    failed=0;
    for(unsigned i=0;i<18;++i){
        memset(&allocation,0,sizeof allocation);audit_calls=0;fail_before_count=fail_handoff_count=0;failed_line=0;
        failed|=run_one(i,&observations[i]);
    }
    if(set_object(sys,"unraisablehook",old_hook)<0){failed=1;goto done;}
    rows=PyList_New(0);if(!rows){failed=1;goto done;}
    for(unsigned i=0;i<18;++i){
        Row *r=&observations[i];
        PyObject *item=Py_BuildValue("{s:s,s:O,s:i,s:i,s:i,s:i,s:i,s:i,s:I,s:I,s:I,s:I,s:I,s:i,s:i,s:i,s:i,s:i,s:i,s:K,s:K,s:K,s:O}",
          "id",r->id,"passed",r->passed?Py_True:Py_False,"failure_line",r->line,"slot",r->slot,"fd",r->fd,
          "live_before",r->live_before,"live_after",r->live_after,"close_errno",r->close_errno,
          "ownership",r->ownership,"audit_calls",r->audit_calls,"allocation_hits",r->allocation_hits,
          "before_failures",r->before_failures,"handoff_failures",r->handoff_failures,
          "error_expected",r->error_expected,"context_expected",r->context_expected,
          "policy_complete",r->policy_complete,"reaped",r->reaped,"owner_lost",r->owner_lost,"child_created",r->child_created,
          "entries",(unsigned long long)r->entries,"final_mask",(unsigned long long)r->final_mask,
          "residual_mask",(unsigned long long)r->residual_mask,"error",r->error_observation?r->error_observation:Py_None);
        if(!item||PyList_Append(rows,item)<0){Py_XDECREF(item);failed=1;goto done;}Py_DECREF(item);
    }
    PyObject *document=Py_BuildValue("{s:s,s:s,s:i,s:O,s:O,s:i,s:O,s:O,s:s}",
       "schema","hepta.cold-native-transport.fd-controls.v1","scope","ACTUAL_FD_CUSTODY_NOT_CT36_OR_COLD_QUALIFICATION",
       "planned",18,"controls",rows,"unraisables",unraisables,"explicit_collect_calls",0,
       "tracebacks_modified",Py_False,"whole_native",Py_False,"status",failed?"HOLD":"CONTROLS_PASS");
    if(!document){failed=1;goto done;}
    json=PyImport_ImportModule("json");serialized=json?PyObject_CallMethod(json,"dumps","(O)",document):NULL;
    Py_DECREF(document);if(!serialized){failed=1;goto done;}
    const char *raw=PyUnicode_AsUTF8(serialized);if(!raw){failed=1;goto done;}
    report=fopen(argv[5],"wx");if(!report){failed=1;goto done;}
    if(fprintf(report,"%s\n",raw)<0)failed=1;
done:
    audit_active=0;Py_CLEAR(audit_error);
    if(PyErr_Occurred()){PyErr_Print();failed=1;}
    if(sys&&old_hook&&set_object(sys,"unraisablehook",old_hook)<0){PyErr_Print();failed=1;}
    if(report&&fclose(report)!=0)failed=1;
    for(unsigned i=0;i<18;++i)Py_XDECREF(observations[i].error_observation);
    Py_XDECREF(rows);Py_XDECREF(serialized);Py_XDECREF(json);Py_XDECREF(old_hook);Py_XDECREF(sys);
    Py_CLEAR(policy_bytes);Py_CLEAR(identity);Py_CLEAR(target_bytes);
    probe_class=NULL;describe_error=NULL;unraisables=NULL;extension_state=NULL;
    Py_CLEAR(probe_globals);Py_CLEAR(extension_module);
    if(Py_FinalizeEx()<0)failed=1;return failed?1:0;
}
