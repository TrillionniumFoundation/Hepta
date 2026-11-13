/* Raw facts and one-effect cache/monitor leaves for HCLICD01.
 *
 * PRIVATE UNEXECUTED SOURCE. HIA, not this file, owns CALL specialization
 * and the selected adaptive counter arithmetic. There is no call to
 * _Py_Specialize_Call, EvalFrame, a Python JSON body or a replacement
 * callable. Borrowed callable/function pointers remain rooted in the real
 * operand stack until the later CALL owner transfers them.
 *
 * The three additional function addresses and the actual instrumentation
 * MISSING object need a separately admitted exact-runtime table. This
 * source does not manufacture that table or infer data addresses from a
 * neighbouring symbol. The previous finite runtime admission is unchanged.
 */
#if PY_VERSION_HEX == 0x030c0ef0
#define CJD_MAGIC UINT64_C(0x31304443494c4348) /* HCLICD01 */
enum { CJD_NEW=0, CJD_ACTIVE=1, CJD_DONE=2, CJD_BLOCKED=3 };

typedef struct {
    uint32_t (*function_version)(PyFunctionObject *);
    int (*instrumentation_two)(PyThreadState *, int, _PyInterpreterFrame *,
                               _Py_CODEUNIT *, PyObject *, PyObject *);
    void (*instrumentation_exc_two)(PyThreadState *, int, _PyInterpreterFrame *,
                                   _Py_CODEUNIT *, PyObject *, PyObject *);
    PyObject *instrumentation_missing; /* exact mapped _PyInstrumentation_MISSING */
    uint64_t admitted[6];              /* profile, anchor, three functions, data */
    int ready;
} CJRuntime312Call;
static CJRuntime312Call cj312_call_runtime;

typedef struct {
    uint64_t magic, permission;
    CJBodyMachine312 *parent;
    CJContext *ctx;
    PyThreadState *thread;
    _PyInterpreterFrame *frame;
    CJActiveFrame312 *owner;
    _Py_CODEUNIT *instruction;
    _PyCallCache *cache;
    PyObject *kwnames;                 /* original borrowed CALL local */
    PyObject *callable;                /* borrowed current physical stack item */
    PyObject **args;
    PyFunctionObject *version_function; /* borrowed until version/cache transaction */
    int original_top, base, total_args, is_method, oparg;
    uint64_t pc, observed_opcode, observed_counter, observed_kind;
    uint64_t force_call, instrumented, monitor_attempted, monitor_returned;
    uint64_t observations, facts_read, version_attempted, version_returned;
    uint64_t version_written, opcode_written, counter_written;
    uint64_t version, selected_opcode, selected_counter, claimed;
    uint64_t issued, consumed, attempts, returns, native_attempts, native_returns;
    uint64_t result_status, failure_reason, owner_lost, in_transaction;
    PyObject *unexpected_error;
    CJHiaEntry entry;
    _Alignas(uint64_t) unsigned char state[512];
} CJCallDispatch312;

static int cjd_fast_opcode(uint64_t op) {
    switch (op) {
    case CALL_PY_EXACT_ARGS: case CALL_PY_WITH_DEFAULTS:
    case CALL_BOUND_METHOD_EXACT_ARGS: case CALL_BUILTIN_CLASS:
    case CALL_BUILTIN_FAST_WITH_KEYWORDS:
    case CALL_METHOD_DESCRIPTOR_FAST_WITH_KEYWORDS:
    case CALL_NO_KW_BUILTIN_FAST: case CALL_NO_KW_BUILTIN_O:
    case CALL_NO_KW_ISINSTANCE: case CALL_NO_KW_LEN: case CALL_NO_KW_LIST_APPEND:
    case CALL_NO_KW_METHOD_DESCRIPTOR_FAST: case CALL_NO_KW_METHOD_DESCRIPTOR_NOARGS:
    case CALL_NO_KW_METHOD_DESCRIPTOR_O: case CALL_NO_KW_STR_1:
    case CALL_NO_KW_TUPLE_1: case CALL_NO_KW_TYPE_1:
        return 1;
    default: return 0;
    }
}

static int cjd_live(CJCallDispatch312 *d) {
    if (!PyGILState_Check()) return 0;
    if (!d || d->magic!=CJD_MAGIC || d->owner_lost || !d->parent || !d->ctx ||
            !d->owner || !d->thread || PyThreadState_Get()!=d->thread ||
            cj312_active_frame!=d->owner || !cjb_owner_current(d->parent) ||
            d->owner!=&d->parent->activation.active || d->owner->frame!=d->frame ||
            d->frame->prev_instr!=d->instruction || d->frame->stacktop!=-1 ||
            d->owner->top!=d->original_top || d->owner->pending_stack_owner ||
            d->owner->pending_stack_base || d->frame->f_code!=d->parent->code)
        return 0;
    return 1;
}

static uint64_t cjd_block(CJCallDispatch312 *d, uint64_t reason) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    d->failure_reason=reason;
    if (d->thread && PyThreadState_Get()!=d->thread) {
        d->owner_lost=1; d->permission=CJD_BLOCKED; return CJ_REFUSAL;
    }
    if (PyErr_Occurred()) {
        if (d->in_transaction && !d->ctx->raised) {
            d->ctx->raised=PyErr_GetRaisedException(); d->in_transaction=0;
        }
        else if (!d->ctx->external) d->ctx->external=PyErr_GetRaisedException();
        else if (!d->unexpected_error) d->unexpected_error=PyErr_GetRaisedException();
        else d->owner_lost=1;
    }
    if (!cjd_live(d)) d->owner_lost=1;
    d->permission=CJD_BLOCKED;
    return CJ_REFUSAL; /* no stack/reference cleanup and no safe Python return */
}

static int cjd_state_bound(CJCallDispatch312 *d) {
    return cjp_get(d->state,0)==CJD_MAGIC &&
        cjp_get(d->state,384)==(uintptr_t)d->parent->gen &&
        cjp_get(d->state,392)==(uintptr_t)d->parent->code &&
        cjp_get(d->state,400)==d->pc &&
        cjp_get(d->state,48)==(uintptr_t)d->ctx->raised;
}

/* Re-observation after the instrumented callback deliberately reads the
 * actual stack again, as TARGET(CALL) does after GO_TO_INSTRUCTION. No
 * extra object reference protects the previous function/argument. */
static int cjd_stack(CJCallDispatch312 *d) {
    if (!cjd_live(d)) return 0;
    PyObject *method=d->frame->localsplus[d->base];
    int is_method=method!=NULL, count=d->oparg+is_method;
    PyObject **args=d->frame->localsplus+d->original_top-count;
    PyObject *callable=method ? method : d->frame->localsplus[d->base+1];
    if (!callable || count<0 || d->kwnames && PyTuple_GET_SIZE(d->kwnames)>count)
        return 0;
    for (int n=0;n<count;n++) if (!args[n]) return 0;
    d->callable=callable; d->args=args; d->total_args=count; d->is_method=is_method;
    return 1;
}

static uint64_t cjd_prepare(CJCallDispatch312 *d, CJBodyMachine312 *m,
                              CJHiaEntry entry, uint64_t deopt_to_call) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!d || !m || !entry || deopt_to_call>1 || m->magic!=CJB_MAGIC ||
            m->permission!=CJB_EFFECT_READY || !cjb_observe_owner(m) ||
            m->activation.permission!=CJA_ACTIVE || m->ctx->slot || m->ctx->raised ||
            m->ctx->external || PyErr_Occurred() || !cj312_call_runtime.ready ||
            m->activation.active.pending_stack_owner || m->activation.active.pending_stack_base ||
            cjp_get(m->state,8)!=43 || cjp_get(m->state,64)!=240 ||
            cjp_get(m->state,72)!=(uintptr_t)m->gen ||
            cjp_get(m->state,80)!=cjp_get(m->state,208) ||
            cjp_get(m->state,88)!=cjp_get(m->state,216) ||
            cjp_get(m->state,96)!=cjp_get(m->state,144) || cjp_get(m->state,104))
        return CJ_REFUSAL;
    /* Py_STATS changes visible counters. It has no implemented claim here;
     * the fixed runtime's build profile must be independently admitted. */
#ifdef Py_STATS
    return CJ_REFUSAL;
#endif
    for (size_t n=0;n<sizeof(*d);n++) if (((unsigned char *)d)[n]) return CJ_REFUSAL;
    uint64_t pc=cjp_get(m->state,144), nargs=cjp_get(m->state,208);
    CJActiveFrame312 *owner=&m->activation.active;
    if (pc>=m->units || m->units-pc<=4 || nargs>=INT_MAX ||
            cjp_get(m->packet,64+pc*64)!=CALL ||
            cjp_get(m->packet,64+pc*64+8)!=nargs ||
            cjp_get(m->packet,64+pc*64+16)!=pc+4 ||
            cjp_get(m->packet,64+pc*64+56)!=1 ||
            owner->top<(int)m->locals ||
            (uint64_t)(owner->top-(int)m->locals)<nargs+2 ||
            m->activation.frame->prev_instr!=_PyCode_CODE(m->code)+pc)
        return CJ_REFUSAL;
    PyObject *kw=(PyObject *)(uintptr_t)cjp_get(m->state,216);
    if (kw && (!PyTuple_CheckExact(kw) || PyTuple_GET_SIZE(kw)>INT_MAX)) return CJ_REFUSAL;
    uint64_t addresses[6]={(uintptr_t)d,(uintptr_t)m,(uintptr_t)m->ctx,
        (uintptr_t)m->state,(uintptr_t)m->packet,(uintptr_t)m->trace};
    uint64_t sizes[6]={sizeof(*d),sizeof(*m),sizeof(*m->ctx),CJB_STATE_BYTES,
        m->packet_bytes,m->trace_capacity*CJB_TRACE_BYTES};
    for (unsigned i=0;i<6;i++) {
        if (!sizes[i]) continue;
        if (!cjp_span(addresses[i],sizes[i])) return CJ_REFUSAL;
        for (unsigned j=0;j<i;j++) if (sizes[j] && !cjp_disjoint(addresses[i],sizes[i],addresses[j],sizes[j]))
            return CJ_REFUSAL;
    }
    d->magic=CJD_MAGIC; d->parent=m; d->ctx=m->ctx; d->thread=m->thread;
    d->frame=m->activation.frame; d->owner=owner; d->instruction=_PyCode_CODE(m->code)+pc;
    d->cache=(_PyCallCache *)(d->instruction+1); d->kwnames=kw; d->pc=pc;
    d->original_top=owner->top; d->oparg=(int)nargs; d->base=owner->top-(int)nargs-2;
    d->entry=entry; d->force_call=deopt_to_call;
    cjp_put(d->state,0,CJD_MAGIC); cjp_put(d->state,200,deopt_to_call);
    cjp_put(d->state,384,(uintptr_t)m->gen); cjp_put(d->state,392,(uintptr_t)m->code);
    cjp_put(d->state,400,pc);
    return cjd_stack(d) ? 0 : cjd_block(d,1);
}

static void cjd_facts(CJCallDispatch312 *d, uint64_t answer[8]) {
    PyObject *callable=d->callable;
    const int mask=METH_VARARGS|METH_FASTCALL|METH_NOARGS|METH_O|METH_KEYWORDS|METH_METHOD;
    if (PyCFunction_CheckExact(callable)) {
        answer[0]=1; answer[1]=PyCFunction_GET_FUNCTION(callable)!=NULL;
        answer[2]=PyCFunction_GET_FLAGS(callable)&mask;
        answer[3]=callable==d->thread->interp->callable_cache.len;
        answer[4]=callable==d->thread->interp->callable_cache.isinstance;
    }
    else if (PyFunction_Check(callable) ||
             (PyMethod_Check(callable) && PyFunction_Check(((PyMethodObject *)callable)->im_func))) {
        int bound=PyMethod_Check(callable);
        PyFunctionObject *function=(PyFunctionObject *)(bound ?
            ((PyMethodObject *)callable)->im_func : callable);
        PyCodeObject *code=(PyCodeObject *)function->func_code;
        answer[0]=2; answer[1]=(uint64_t)code->co_flags;
        answer[2]=(uint64_t)code->co_kwonlyargcount; answer[3]=(uint64_t)code->co_argcount;
        answer[4]=function->func_defaults ? (uint64_t)PyTuple_GET_SIZE(function->func_defaults) : 0;
        answer[5]=d->thread->interp->eval_frame==NULL; answer[6]=bound;
        answer[7]=(uint64_t)d->total_args+bound;
        d->version_function=function;
    }
    else if (PyType_Check(callable)) {
        PyTypeObject *type=(PyTypeObject *)callable;
        answer[0]=3; answer[1]=type->tp_new==PyBaseObject_Type.tp_new;
        answer[2]=!!(type->tp_flags&Py_TPFLAGS_IMMUTABLETYPE);
        answer[3]=type==&PyUnicode_Type ? 1 : type==&PyType_Type ? 2 : type==&PyTuple_Type ? 3 : 0;
        answer[4]=type->tp_vectorcall!=NULL;
    }
    else if (Py_IS_TYPE(callable,&PyMethodDescr_Type)) {
        answer[0]=4; answer[1]=((PyMethodDescrObject *)callable)->d_method->ml_flags&mask;
        answer[2]=callable==d->thread->interp->callable_cache.list_append;
        answer[3]=d->instruction[4].op.code==POP_TOP;
    }
    d->observed_kind=answer[0];
}

static uint64_t cjd_leaf(CJCallDispatch312 *d) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!d || d->magic!=CJD_MAGIC || !cjd_live(d) || !cjd_state_bound(d) ||
            d->permission==CJD_DONE || d->permission==CJD_BLOCKED ||
            d->ctx->slot || d->ctx->external || PyErr_Occurred() ||
            cjp_get(d->state,24)!=1 || cjp_get(d->state,112) ||
            d->issued!=d->consumed || d->issued==UINT64_MAX ||
            cjp_get(d->state,16)!=d->issued+1 || cjp_get(d->state,32)!=d->consumed)
        return d && d->magic==CJD_MAGIC ? cjd_block(d,2) : CJ_REFUSAL;
    uint64_t op=cjp_get(d->state,64), arg=cjp_get(d->state,72), phase=cjp_get(d->state,8);
    if (op<1 || op>7 || ((op<5) && arg)) return cjd_block(d,3);
    for (unsigned n=80;n<112;n+=8) if (cjp_get(d->state,n)) return cjd_block(d,3);
    switch (op) {
    case 1:
        if (d->ctx->raised || (phase!=1 && phase!=10)) return cjd_block(d,4);
        break;
    case 2:
        if (phase!=2 || d->ctx->raised || d->force_call || d->monitor_attempted ||
                !d->observations || d->observed_opcode!=INSTRUMENTED_CALL ||
                !cj312_call_runtime.instrumentation_two || !cj312_call_runtime.instrumentation_missing)
            return cjd_block(d,5);
        break;
    case 3:
        if (phase!=3 || d->ctx->raised || !d->observations ||
                (d->observed_counter>>4) || d->facts_read ||
                (!d->force_call && d->observed_opcode!=CALL)) return cjd_block(d,6);
        break;
    case 4:
        if (phase!=4 || d->ctx->raised || d->observed_kind!=2 || !d->facts_read ||
                !d->version_function || d->version_attempted || !cj312_call_runtime.function_version)
            return cjd_block(d,7);
        break;
    case 5:
        if (phase!=5 || d->ctx->raised || !d->version_returned || !d->version ||
                d->version_written || arg!=d->version || arg>UINT32_MAX) return cjd_block(d,8);
        break;
    case 6:
        if (phase!=6 || d->ctx->raised || !d->facts_read || d->opcode_written ||
                (arg!=CALL && !cjd_fast_opcode(arg)) ||
                cjp_get(d->state,168)!=arg) return cjd_block(d,9);
        break;
    case 7:
        if (d->ctx->raised || arg>UINT16_MAX ||
                !((phase==7 && d->opcode_written && !d->counter_written &&
                    arg==cjp_get(d->state,176)) ||
                  (phase==8 && !d->facts_read && (d->observed_counter>>4) &&
                    arg==d->observed_counter-16) ||
                  (phase==11 && d->monitor_returned && !d->force_call &&
                    arg==((d->observed_counter+16)&65535)))) return cjd_block(d,10);
        break;
    }
    if (!cjp_increment(&d->attempts)) return cjd_block(d,11);
    d->issued=cjp_get(d->state,16); d->consumed=d->issued;
    cjp_put(d->state,32,d->consumed); cjp_put(d->state,40,op);
    uint64_t answer[8]={0};
    PyObject *incoming=d->ctx->raised; d->ctx->raised=NULL;
    d->in_transaction=1; PyErr_SetRaisedException(incoming);
    switch (op) {
    case 1:
        if (!cjd_stack(d)) return cjd_block(d,12);
        d->observations++; d->observed_opcode=d->instruction->op.code;
        d->observed_counter=d->cache->counter;
        answer[0]=d->observed_opcode; answer[1]=d->observed_counter;
        answer[2]=d->total_args; answer[3]=d->kwnames!=NULL; answer[4]=d->instruction->op.arg;
        d->permission=CJD_ACTIVE;
        break;
    case 2: {
        PyObject *arg0=d->total_args ? d->args[0] : cj312_call_runtime.instrumentation_missing;
        d->monitor_attempted=1;
        int result=cj312_call_runtime.instrumentation_two(d->thread,PY_MONITORING_EVENT_CALL,
                           d->frame,d->instruction,d->callable,arg0);
        d->monitor_returned=1; d->instrumented=1;
        answer[0]=(uint64_t)(int64_t)result;
        break;
    }
    case 3:
        d->facts_read=1; cjd_facts(d,answer);
        break;
    case 4:
        d->version_attempted=1;
        d->version=cj312_call_runtime.function_version(d->version_function);
        d->version_returned=1; answer[0]=d->version;
        break;
    case 5:
        /* Original write_u32: low 16 bits then high 16 bits. */
        d->cache->func_version[0]=(uint16_t)arg;
        d->cache->func_version[1]=(uint16_t)(arg>>16);
        d->version_written=1;
        break;
    case 6:
        d->instruction->op.code=(uint8_t)arg;
        d->selected_opcode=arg; d->opcode_written=1;
        break;
    case 7:
        d->cache->counter=(uint16_t)arg; d->selected_counter=arg;
        if (phase==11) d->force_call=1;
        if (phase==7) {
            d->counter_written=1;
            /* A real DISPATCH_SAME_OPARG begins from the newly written
             * opcode, not the old INSTRUMENTED_CALL local. */
            d->force_call=0; d->instrumented=0;
            d->facts_read=0; d->version_attempted=0; d->version_returned=0;
            d->version_written=0; d->opcode_written=0; d->counter_written=0;
            d->version_function=NULL; d->version=0; d->observed_kind=0;
        }
        break;
    }
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (PyThreadState_Get()!=d->thread) return cjd_block(d,13);
    d->ctx->raised=PyErr_GetRaisedException(); d->in_transaction=0;
    if (!cjp_increment(&d->returns)) return cjd_block(d,14);
    if (!cjd_live(d)) return cjd_block(d,15);
    for (unsigned n=0;n<8;n++) cjp_put(d->state,256+n*8,answer[n]);
    cjp_put(d->state,48,(uintptr_t)d->ctx->raised);
    return 0;
}

/* No callback, operand mutation or ownership transfer occurs between
 * dispatch completion and the selected generic/fast CALL owner. */
static uint64_t cjd_run(CJCallDispatch312 *d) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!d || d->magic!=CJD_MAGIC || d->claimed || d->permission==CJD_DONE ||
            d->permission==CJD_BLOCKED || !d->entry) return CJ_REFUSAL;
    for (;;) {
        if (!cjd_live(d) || !cjd_state_bound(d) || d->ctx->external || d->ctx->slot ||
                PyErr_Occurred() || !cjp_increment(&d->native_attempts)) return cjd_block(d,16);
        unsigned char output=0;
        uint32_t status=d->entry(d->parent->packet,d->parent->packet_bytes,&output,1,d->state,512);
        if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
        if (PyThreadState_Get()!=d->thread) return cjd_block(d,17);
        if (!cjp_increment(&d->native_returns)) return cjd_block(d,18);
        cjb_trace_child(d->parent,15,d->state,64);
        if (PyErr_Occurred() || !cjd_live(d) || !cjd_state_bound(d)) return cjd_block(d,19);
        if (status==2) {
            uint64_t result=cjd_leaf(d);
            cjb_trace_child(d->parent,16,d->state,64);
            if (result) return result;
            continue;
        }
        if ((status!=0 && status!=1 && status!=3) || cjp_get(d->state,24) ||
                cjp_get(d->state,112)!=(status==0 ? 1 : status==1 ? 2 : 3) ||
                d->issued!=d->consumed || d->attempts!=d->returns ||
                d->native_attempts!=d->native_returns ||
                (status==1 ? (!d->ctx->raised || !d->monitor_returned) : d->ctx->raised!=NULL) ||
                (status==0 && cjp_get(d->state,8)!=8) ||
                (status==3 && (!cjd_fast_opcode(cjp_get(d->state,120)) || d->force_call)))
            return cjd_block(d,20);
        d->permission=CJD_DONE; d->result_status=status;
        return status;
    }
}
#endif
