/* Raw same-C-entry owner for the original JSON generator CALL prologue.
 *
 * PRIVATE SOURCE WIP. HIA selects every closure slot, RETURN_GENERATOR
 * transition and ordinary error-monitor/clear sequence. This owner uses
 * the actual thread frame returned by cj312_push_and_init. It adds no
 * _PyEval_EvalFrameDefault call, C-recursion decrement, generator wrapper
 * or protective object references. The original parent frame remains
 * published while its thread child is current.
 *
 * A complete admitted packet for one of the original JSON generators is
 * required before activation. Arbitrary foreign function bodies and the
 * full adaptive/instrumented CALL dispatcher remain separate OPEN ports.
 * A failed link keeps the C owner blocked; it is not safe Python return.
 */
#if PY_VERSION_HEX == 0x030c0ef0
#define CJT_MAGIC UINT64_C(0x31305250494c4348) /* HCLIPR01 */
enum { CJT_NEW=0, CJT_ENTERED=1, CJT_UNLINKED=2, CJT_DONE=3, CJT_BLOCKED=4 };

typedef struct {
    uint64_t magic, permission;
    CJCallLease312 *call;
    unsigned char *call_state;
    CJBodyMachine312 *parent;
    CJContext *ctx;
    PyThreadState *thread;
    _PyCFrame *shared;
    _PyInterpreterFrame *frame, *parent_frame, *parent_previous;
    _Py_CODEUNIT *parent_following;
    CJActiveFrame312 active;
    CJActiveFrame312 *parent_active;
    _PyErr_StackItem *handled;
    CJInlineActivation312 parents;       /* read-only suspended-parent view */
    PyCodeObject *code;                  /* actual frame owns it until move/drop */
    const unsigned char *packet;
    uint64_t packet_bytes, units, pc, following, nlocals, framesize;
    PyObject *result;                    /* original owned local gen */
    uint64_t closure_index, closure_count, make_attempted, make_returned;
    uint64_t entered, py_entered, stack_live, moved, popped, published_monitor;
    uint64_t entry_error, raised_monitor, unwind_monitor;
    uint64_t clear_counter, clear_attempted, clear_returned, code_released;
    uint64_t issued, consumed, attempts, returns, owner_lost, failure_reason;
    uint64_t native_attempts, native_returns;
    uint64_t in_transaction;
    PyObject *unexpected_error;          /* retained only on a protocol failure */
    _Alignas(uint64_t) unsigned char state[512];
    CJHiaEntry entry;
} CJCallPrologue312;

/* Read only retained pointers, and never interpret current TLS as our
 * owner. Once pop_frame runs, the old thread-frame storage is not read. */
static int cjt_live(CJCallPrologue312 *t) {
    if (!PyGILState_Check()) return 0;
    if (!t || t->magic!=CJT_MAGIC || t->owner_lost || !t->parent || !t->call ||
            !t->thread || PyThreadState_Get()!=t->thread ||
            t->thread->cframe!=t->shared || t->thread->exc_info!=t->handled ||
            t->parent_frame->previous!=t->parent_previous ||
            t->parent_active!=&t->parent->activation.active ||
            t->parent_active->pending_stack_owner || t->parent_active->pending_stack_base)
        return 0;
    if (!t->entered) return cjc_live(t->call);
    if (t->parent_frame->prev_instr!=t->parent_following-1 ||
            t->parent_frame->return_offset!=0) return 0;
    if (t->popped) {
        return t->shared->current_frame==t->parent_frame &&
            cj312_active_frame==t->parent_active &&
            t->parent_frame->stacktop==-1 && t->parent_active->top==t->call->base &&
            !t->py_entered && !t->stack_live && !t->clear_counter &&
            cjb_owner_current(t->parent);
    }
    if (t->parent_frame->stacktop!=t->call->base ||
            t->parent_active->top!=t->call->base || !cji_parent_chain(&t->parents) ||
            t->frame->previous!=t->parent_frame || t->frame->owner!=FRAME_OWNED_BY_THREAD ||
            (PyObject **)t->frame+t->framesize!=t->thread->datastack_top ||
            cj312_active_frame!=(t->stack_live ? &t->active : t->parent_active)) return 0;
    if (t->permission==CJT_UNLINKED) {
        return t->shared->current_frame==t->parent_frame && !t->py_entered &&
            t->clear_counter && t->frame->stacktop==(int)t->nlocals &&
            (!t->stack_live || t->active.previous==t->parent_active);
    }
    if (t->shared->current_frame!=t->frame || !t->py_entered ||
            t->frame->f_code!=t->code ||
            t->frame->stacktop!=((t->stack_live && !t->moved && !t->published_monitor)
                                 ? -1 : (int)t->nlocals) ||
            (t->stack_live && (t->active.frame!=t->frame ||
                t->active.top!=(int)t->nlocals || t->active.previous!=t->parent_active ||
                t->active.pending_stack_owner || t->active.pending_stack_base))) return 0;
    return 1;
}

static uint64_t cjt_block(CJCallPrologue312 *t, uint64_t reason) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    t->failure_reason=reason;
    if (t->thread && PyThreadState_Get()!=t->thread) {
        t->owner_lost=1; t->permission=CJT_BLOCKED;
        return CJ_REFUSAL;
    }
    if (PyErr_Occurred()) {
        if (t->in_transaction && !t->ctx->raised) {
            t->ctx->raised=PyErr_GetRaisedException(); t->in_transaction=0;
        }
        else if (!t->ctx->external) t->ctx->external=PyErr_GetRaisedException();
        else if (!t->unexpected_error) t->unexpected_error=PyErr_GetRaisedException();
        else t->owner_lost=1; /* no overwrite and no safe Python return */
    }
    if (!cjt_live(t)) t->owner_lost=1;
    t->permission=CJT_BLOCKED;
    return CJ_REFUSAL;
}

static int cjt_state_bound(CJCallPrologue312 *t) {
    return cjp_get(t->state,0)==CJT_MAGIC && cjp_get(t->state,120)==(uintptr_t)t->frame &&
        cjp_get(t->state,128)==(uintptr_t)t->code && cjp_get(t->state,144)==t->units &&
        cjp_get(t->state,48)==(uintptr_t)t->ctx->raised &&
        cjp_get(t->state,56)==(uintptr_t)(t->result ? t->result : t->ctx->slot);
}

static uint64_t cjt_prepare(CJCallPrologue312 *t, CJCallLease312 *call,
                              unsigned char *call_state,
                              CJHiaEntry entry, const unsigned char *packet,
                              uint64_t packet_bytes) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!t || !call || !call_state || !entry || !packet || call->magic!=CJC_MAGIC ||
            call->permission!=CJC_INLINE_REQUIRED || call->route!=1 || !call->child ||
            (!call->binder_returned && !call->fast_frame_ready) || !call->stack_committed || call->ctx->slot ||
            call->ctx->raised || call->ctx->external || call->result ||
            PyErr_Occurred() || !cjc_live(call) || packet_bytes<64 ||
            cjp_get(packet,0)!=CJB_PACKET_MAGIC || cjp_get(packet,8)!=31214 ||
            cjp_get(packet,56)!=1 || call->child_completed ||
            call->issued!=call->consumed || call->issued==UINT64_MAX ||
            call->leaf_attempts==UINT64_MAX || cjp_get(call_state,0)!=CJC_MAGIC ||
            cjp_get(call_state,8)!=6 || cjp_get(call_state,24)!=1 ||
            cjp_get(call_state,64)!=CJC_INLINE_CHILD || cjp_get(call_state,72)!=(uintptr_t)call->child ||
            cjp_get(call_state,16)!=call->issued+1 || cjp_get(call_state,32)!=call->consumed ||
            cjp_get(call_state,48) || cjp_get(call_state,56) || cjp_get(call_state,112))
        return CJ_REFUSAL;
    for (size_t n=0; n<sizeof(*t); n++) if (((unsigned char *)t)[n]) return CJ_REFUSAL;
    _PyInterpreterFrame *frame=call->child;
    PyCodeObject *code=frame->f_code;
    uint64_t units=cjp_get(packet,16);
    if (!units || units>(UINT64_MAX-64)/64 || packet_bytes!=64+units*64 ||
            !code || (uint64_t)Py_SIZE(code)!=units || code->co_nlocalsplus<0 ||
            frame->owner!=FRAME_OWNED_BY_THREAD || frame->stacktop!=code->co_nlocalsplus ||
            frame->prev_instr!=_PyCode_CODE(code)-1 || frame->frame_obj ||
            !PyFunction_Check(frame->f_funcobj) || !(code->co_flags&CO_GENERATOR) ||
            code->co_flags&(CO_COROUTINE|CO_ASYNC_GENERATOR) ||
            code->co_framesize<FRAME_SPECIALS_SIZE ||
            (PyObject **)frame+code->co_framesize!=call->thread->datastack_top ||
            cjp_get(packet,40)!=(uint64_t)code->co_nlocalsplus ||
            cjp_get(packet,48)!=(uint64_t)code->co_stacksize ||
            call->instruction+4>=_PyCode_CODE(call->frame->f_code)+Py_SIZE(call->frame->f_code))
        return CJ_REFUSAL;
    uint64_t addresses[8]={(uintptr_t)t,(uintptr_t)call,(uintptr_t)call->parent,
        (uintptr_t)call->ctx,(uintptr_t)packet,(uintptr_t)call_state,
        (uintptr_t)call->parent->state,(uintptr_t)call->parent->trace};
    uint64_t sizes[8]={sizeof(*t),sizeof(*call),sizeof(*call->parent),sizeof(*call->ctx),packet_bytes,
        CJC_STATE_BYTES,CJB_STATE_BYTES,call->parent->trace_capacity*CJB_TRACE_BYTES};
    for (unsigned i=0;i<8;i++) {
        if (!sizes[i]) continue;
        if (!cjp_span(addresses[i],sizes[i])) return CJ_REFUSAL;
        for (unsigned j=0;j<i;j++) if (sizes[j] && !cjp_disjoint(addresses[i],sizes[i],addresses[j],sizes[j]))
            return CJ_REFUSAL;
    }
    t->magic=CJT_MAGIC; t->call=call; t->call_state=call_state; t->parent=call->parent; t->ctx=call->ctx;
    t->thread=call->thread; t->shared=cja_current_cframe(&call->parent->activation);
    t->frame=frame; t->code=code; t->parent_frame=call->frame;
    t->parent_previous=call->frame->previous; t->parent_active=call->owner;
    t->parent_following=call->instruction+4; t->handled=t->thread->exc_info;
    t->packet=packet; t->packet_bytes=packet_bytes; t->units=units;
    t->nlocals=(uint64_t)code->co_nlocalsplus; t->framesize=(uint64_t)code->co_framesize;
    t->entry=entry;
    t->parents.parent=&t->parent->activation; t->parents.thread=t->thread;
    t->parents.shared=t->shared; t->parents.root=&t->parent->activation;
    while (t->parents.root->inlined) t->parents.root=t->parents.root->inlined->parent;
    cjp_put(t->state,0,CJT_MAGIC); cjp_put(t->state,120,(uintptr_t)frame);
    cjp_put(t->state,128,(uintptr_t)code); cjp_put(t->state,144,units);
    /* The CALL child's one-use permission is consumed before activation.
     * Its ACK is delayed until actual pop/parent restoration completes. */
    call->leaf_attempts++; call->issued=cjp_get(call_state,16); call->consumed=call->issued;
    return 0;
}

static void cjt_reply(CJCallPrologue312 *t, const uint64_t answer[8]) {
    for (unsigned n=0;n<8;n++) cjp_put(t->state,256+8*n,answer[n]);
    cjp_put(t->state,48,(uintptr_t)t->ctx->raised);
    cjp_put(t->state,56,(uintptr_t)(t->result ? t->result : t->ctx->slot));
}

static uint64_t cjt_leaf(CJCallPrologue312 *t) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!t || t->magic!=CJT_MAGIC || t->permission==CJT_DONE ||
            t->permission==CJT_BLOCKED || !cjt_live(t) || !cjt_state_bound(t) ||
            PyErr_Occurred() || t->ctx->slot || t->ctx->external ||
            cjp_get(t->state,24)!=1 || cjp_get(t->state,112) ||
            t->issued!=t->consumed || t->issued==UINT64_MAX ||
            cjp_get(t->state,16)!=t->issued+1 || cjp_get(t->state,32)!=t->consumed)
        return t && t->magic==CJT_MAGIC ? cjt_block(t,1) : CJ_REFUSAL;
    uint64_t op=cjp_get(t->state,64), a=cjp_get(t->state,72), b=cjp_get(t->state,80);
    if (op<1 || op>12 || cjp_get(t->state,88) || cjp_get(t->state,96) ||
            cjp_get(t->state,104) || ((op<2 || op>5) && op!=12 && (a||b)))
        return cjt_block(t,2);
    switch (op) {
    case 1:
        if (t->entered || t->permission!=CJT_NEW || t->ctx->raised || t->result)
            return cjt_block(t,3);
        break;
    case 12:
        if (!t->stack_live || t->make_attempted || t->ctx->raised || t->result ||
                a>=t->units || (b!=COPY_FREE_VARS && b!=EXTENDED_ARG) ||
                cjp_get(t->packet,64+a*64)!=b || cjp_get(t->packet,64+a*64+56)!=1 ||
                cjp_get(t->packet,64+a*64+32)!=UINT64_MAX ||
                _PyCode_CODE(t->code)[a].op.code!=b) return cjt_block(t,4);
        break;
    case 2:
        if (!t->stack_live || t->make_attempted || t->ctx->raised || t->result ||
                a!=t->closure_index || b!=t->closure_count || a>=b ||
                t->frame->prev_instr->op.code!=COPY_FREE_VARS ||
                b!=(uint64_t)t->code->co_nfreevars || b>t->nlocals ||
                !PyTuple_CheckExact(((PyFunctionObject *)t->frame->f_funcobj)->func_closure) ||
                PyTuple_GET_SIZE(((PyFunctionObject *)t->frame->f_funcobj)->func_closure)!=(Py_ssize_t)b)
            return cjt_block(t,5);
        break;
    case 3:
        if (!t->stack_live || t->make_attempted || t->ctx->raised || t->result || b ||
                a>=t->units || cjp_get(t->packet,64+a*64)!=RETURN_GENERATOR ||
                cjp_get(t->packet,64+a*64+32)!=UINT64_MAX ||
                cjp_get(t->packet,64+a*64+56)!=1 ||
                _PyCode_CODE(t->code)[a].op.code!=RETURN_GENERATOR ||
                a>=(uint64_t)t->code->_co_firsttraceable ||
                t->closure_index!=t->closure_count) return cjt_block(t,6);
        break;
    case 4:
        if (!t->make_returned || t->result || !t->ctx->raised || t->entry_error ||
                t->raised_monitor || a!=t->pc || b || !_PyFrame_IsIncomplete(t->frame))
            return cjt_block(t,7);
        break;
    case 5:
        if (!t->raised_monitor || t->unwind_monitor || t->result || !t->ctx->raised ||
                a!=t->pc || b || t->active.top!=(int)t->nlocals) return cjt_block(t,8);
        break;
    case 6:
        if (!t->make_returned || !t->result || t->ctx->raised || t->moved ||
                !t->stack_live || t->active.top!=(int)t->nlocals || t->frame->frame_obj)
            return cjt_block(t,9);
        break;
    case 7:
        if (!t->moved || !t->result || t->ctx->raised || t->popped || !t->py_entered)
            return cjt_block(t,10);
        break;
    case 8:
        if ((!t->entry_error && !t->unwind_monitor) || !t->ctx->raised || t->result ||
                !t->py_entered || t->clear_counter || t->moved || t->popped)
            return cjt_block(t,11);
        break;
    case 9:
        if (t->permission!=CJT_UNLINKED || !t->clear_counter || t->clear_attempted ||
                !t->ctx->raised || t->result || t->popped) return cjt_block(t,12);
        break;
    case 10:
        if (!t->clear_returned || t->code_released || !t->ctx->raised || t->result ||
                !t->clear_counter || t->popped) return cjt_block(t,13);
        break;
    case 11:
        if (!t->code_released || !t->clear_counter || t->popped || !t->ctx->raised || t->result)
            return cjt_block(t,14);
        break;
    }
    if (!cjp_increment(&t->attempts)) return cjt_block(t,15);
    t->issued=cjp_get(t->state,16); t->consumed=t->issued;
    cjp_put(t->state,32,t->consumed); cjp_put(t->state,40,op);
    uint64_t answer[8]={0};
    PyObject *incoming=t->ctx->raised; t->ctx->raised=NULL;
    PyErr_SetRaisedException(incoming);
    t->in_transaction=1;
    switch (op) {
    case 1: {
        t->entered=1; t->permission=CJT_ENTERED;
        t->parent_frame->return_offset=0;
        t->parent_frame->stacktop=t->parent_active->top;
        t->parent_frame->prev_instr=t->parent_following-1;
        t->frame->previous=t->parent_frame;
        t->shared->current_frame=t->frame;
        t->py_entered=1;
        t->entry_error=cja_enter_recursive_py(t->thread)!=0;
        if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
        if (PyThreadState_Get()!=t->thread || !cjt_live(t)) return cjt_block(t,16);
        if (!t->entry_error) {
            t->active.frame=t->frame; t->active.top=t->frame->stacktop;
            t->active.previous=t->parent_active;
            t->frame->stacktop=-1; cj312_active_frame=&t->active; t->stack_live=1;
        }
        answer[0]=t->entry_error; answer[1]=t->nlocals; answer[2]=t->nlocals;
        break;
    }
    case 12:
        t->pc=a; t->frame->prev_instr=_PyCode_CODE(t->code)+a;
        if (b==COPY_FREE_VARS) {
            t->closure_count=cjp_get(t->packet,64+a*64+8); t->closure_index=0;
        }
        break;
    case 2: {
        PyObject *closure=((PyFunctionObject *)t->frame->f_funcobj)->func_closure;
        PyObject *cell=PyTuple_GET_ITEM(closure,(Py_ssize_t)a);
        /* Actual frame slot, no temporary closure/cell owner is acquired. */
        t->frame->localsplus[t->nlocals-b+a]=Py_NewRef(cell);
        t->closure_index++; answer[0]=t->closure_index;
        break;
    }
    case 3:
        t->pc=a; t->frame->prev_instr=_PyCode_CODE(t->code)+a;
        t->make_attempted=1;
        t->result=cj312_runtime.make_coro((PyFunctionObject *)t->frame->f_funcobj);
        t->make_returned=1;
        break;
    case 4:
        t->raised_monitor=1;
        cja_monitor_raise(t->thread,t->frame,_PyCode_CODE(t->code)+t->pc);
        break;
    case 5:
        t->unwind_monitor=1;
        t->published_monitor=1;
        t->frame->stacktop=t->active.top;
        cja_monitor_unwind(t->thread,t->frame,_PyCode_CODE(t->code)+t->pc);
        if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
        if (PyThreadState_Get()!=t->thread || !cjt_live(t))
            return cjt_block(t,17);
        t->frame->stacktop=-1;
        t->published_monitor=0;
        break;
    case 6: {
        t->frame->stacktop=t->active.top;
        _PyInterpreterFrame *destination=(_PyInterpreterFrame *)((PyGenObject *)t->result)->gi_iframe;
        /* Exact _PyFrame_Copy body: memcpy moves the existing frame-owned
         * references, and only the destination previous pointer is NULL. */
        Py_ssize_t size=((char *)&t->frame->localsplus[t->frame->stacktop])-(char *)t->frame;
        memcpy(destination,t->frame,(size_t)size);
        destination->previous=NULL;
        ((PyGenObject *)t->result)->gi_frame_state=FRAME_CREATED;
        destination->owner=FRAME_OWNED_BY_GENERATOR;
        t->moved=1; answer[0]=1;
        break;
    }
    case 7:
        t->thread->py_recursion_remaining++; t->py_entered=0;
        cj312_runtime.pop_frame(t->thread,t->frame); t->popped=1;
        t->shared->current_frame=t->parent_frame;
        if (t->stack_live) { cj312_active_frame=t->parent_active; t->stack_live=0; }
        t->parent_active->top=t->parent_frame->stacktop; t->parent_frame->stacktop=-1;
        t->ctx->slot=t->result; t->result=NULL;
        t->permission=CJT_DONE; answer[0]=1;
        break;
    case 8:
        t->frame->stacktop=(int)t->nlocals;
        t->thread->py_recursion_remaining++; t->py_entered=0;
        t->shared->current_frame=t->parent_frame;
        t->thread->c_recursion_remaining--; t->clear_counter=1;
        t->permission=CJT_UNLINKED;
        break;
    case 9:
        t->clear_attempted=1;
        cj312_runtime.clear_frame(t->frame);
        t->clear_returned=1;
        break;
    case 10:
        /* clear_thread_frame releases f_code after ClearExceptCode, while
         * its C-recursion decrement is still active. Do not reverse it. */
        t->code_released=1;
        Py_DECREF(t->code);
        break;
    case 11:
        t->thread->c_recursion_remaining++; t->clear_counter=0;
        cj312_runtime.pop_frame(t->thread,t->frame); t->popped=1;
        t->parent_frame->return_offset=0;
        if (t->stack_live) { cj312_active_frame=t->parent_active; t->stack_live=0; }
        t->parent_active->top=t->parent_frame->stacktop; t->parent_frame->stacktop=-1;
        t->permission=CJT_DONE; answer[0]=1;
        break;
    }
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (PyThreadState_Get()!=t->thread) return cjt_block(t,18);
    t->ctx->raised=PyErr_GetRaisedException();
    t->in_transaction=0;
    if (!cjp_increment(&t->returns)) return cjt_block(t,19);
    if (!cjt_live(t)) return cjt_block(t,20);
    cjt_reply(t,answer);
    return 0;
}

/* Remains private until original CALL dispatch and complete packet
 * admission supply its actual thread frame. Runs no retained Python body. */
static uint64_t cjt_run(CJCallPrologue312 *t) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!t || t->magic!=CJT_MAGIC || t->permission!=CJT_NEW) return CJ_REFUSAL;
    for (;;) {
        if (!cjt_live(t) || !cjt_state_bound(t) || PyErr_Occurred() || t->ctx->external)
            return cjt_block(t,21);
        if (!cjp_increment(&t->native_attempts)) return cjt_block(t,22);
        unsigned char output=0;
        uint32_t status=t->entry(t->packet,t->packet_bytes,&output,1,t->state,sizeof(t->state));
        if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
        if (PyThreadState_Get()!=t->thread) return cjt_block(t,23);
        if (!cjp_increment(&t->native_returns)) return cjt_block(t,24);
        /* Parent trace is byte-only here; observing it as current while
         * the thread child is linked would be a false ownership failure. */
        cjb_trace_child(t->parent,10,t->state,sizeof(t->state)/8);
        if (!cjt_live(t) || !cjt_state_bound(t) || PyErr_Occurred()) return cjt_block(t,25);
        if (status==2) {
            uint64_t result=cjt_leaf(t);
            cjb_trace_child(t->parent,11,t,sizeof(*t)/8);
            if (result) return result;
            continue;
        }
        if (status>1 || t->permission!=CJT_DONE || !t->popped || t->py_entered ||
                t->stack_live || t->clear_counter || t->result || t->ctx->external ||
                cjp_get(t->state,112)!=(status ? 2 : 1) || cjp_get(t->state,24) ||
                t->issued!=t->consumed || t->attempts!=t->returns ||
                t->native_attempts!=t->native_returns ||
                (status ? (!t->ctx->raised || t->ctx->slot || !t->code_released || t->moved) :
                          (t->ctx->raised || !t->ctx->slot || !t->moved || t->code_released)))
            return cjt_block(t,26);
        CJCallLease312 *call=t->call;
        if (call->permission!=CJC_INLINE_REQUIRED || call->child!=t->frame ||
                call->child_completed || call->issued!=call->consumed ||
                cjp_get(t->call_state,16)!=call->consumed ||
                cjp_get(t->call_state,24)!=1 || cjp_get(t->call_state,64)!=CJC_INLINE_CHILD ||
                call->leaf_returns==UINT64_MAX) return cjt_block(t,27);
        call->completed_child=(uintptr_t)call->child; call->child=NULL;
        call->child_completed=1;
        call->child_following=(uint64_t)(t->parent_following-_PyCode_CODE(t->parent_frame->f_code));
        call->result_moved=status==0; call->permission=CJC_DONE; call->leaf_returns++;
        cjp_put(t->call_state,32,call->consumed); cjp_put(t->call_state,40,CJC_INLINE_CHILD);
        uint64_t answer[8]={status,call->child_following,call->child_following-1,status,0,0,0,0};
        for (unsigned n=0;n<8;n++) cjp_put(t->call_state,256+n*8,answer[n]);
        cjp_put(t->call_state,48,(uintptr_t)t->ctx->raised);
        cjp_put(t->call_state,56,(uintptr_t)t->ctx->slot);
        if (!cjc_live(call)) return cjt_block(t,28);
        return status;
    }
}
#endif
