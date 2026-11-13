/* HIA-selected SEND/SEND_GEN primitives and port241's retained ledger.
 *
 * Private unexecuted source. There is no public entry or retained-body
 * fallback. HIA chooses adaptive cache writes, inline versus iterator/send
 * call, StopIteration monitor/fetch, v release and stack commit. This file
 * performs each selected primitive with the original active stack roots.
 *
 * CJB_CHILD_REQUIRED is an internal scheduling event. The outer C driver
 * must admit/prepare the actual child, call cjb_send_bind_child(), iterate
 * that child's HIA body in the SAME C entry, then cjb_send_resume_child().
 * Neither this event nor a broken owner authorizes return to Python.
 * Exact foreign generators/coroutines which original SEND would inline
 * cannot be redirected to tp_iternext merely because admission is pending.
 */
#if PY_VERSION_HEX == 0x030c0ef0
#define CJS_MAGIC UINT64_C(0x31304453494c4348) /* HCLISD01 */
#define CJS_STATE_BYTES 512
enum { CJS_NEW=0, CJS_ACTIVE=1, CJS_INLINED=2, CJS_DONE=3, CJS_BLOCKED=4 };
enum {
    CJS_BEGIN=1, CJS_CACHE=2, CJS_INLINE=3, CJS_ITERNEXT=4,
    CJS_SEND_METHOD=5, CJS_STOP_MATCH=6, CJS_MONITOR_RAISE=7,
    CJS_FETCH_STOP=8, CJS_DROP_VALUE=9, CJS_COMMIT=10,
    CJS_MOVE_RESULT=11, CJS_ERROR=12
};

typedef struct {
    uint64_t magic, permission;
    CJBodyMachine312 *parent;
    CJContext *ctx;
    PyThreadState *thread;
    PyGenObject *gen;
    _PyInterpreterFrame *frame;
    CJActiveFrame312 *owner;
    _Py_CODEUNIT *instruction;
    PyObject *receiver;                 /* borrowed actual stack root */
    PyObject *value;                    /* original owned v in its slot */
    PyObject *result;                   /* original owned local retval */
    int original_top, base;
    uint64_t pc, following, oparg, facts, mode, counter;
    uint64_t begun, route, primitive, primitive_returned, stop_match;
    uint64_t matched, monitored, fetched, flow;
    int fetch_status;
    uint64_t value_released, stack_committed, result_moved;
    uint64_t issued, consumed, leaf_attempts, leaf_returns;
    uint64_t owner_lost, failure_reason, inline_started, inline_returned;
    uintptr_t last_released;
    int last_top;
    CJBodyMachine312 *child;            /* complete retaining owner holds it */
    CJInlineActivation312 inline_owner;
} CJSendLease312;

struct CJBodySend312 {
    uint64_t permission, completed;
    CJHiaEntry entry;
    uint64_t native_attempts, native_returns;
    _Alignas(uint64_t) unsigned char state[CJS_STATE_BYTES];
    CJSendLease312 lease;
};

static int cjs_live(CJSendLease312 *s) {
    if (!PyGILState_Check()) return 0;
    if (!s || s->magic != CJS_MAGIC || s->owner_lost || !s->parent || !s->ctx ||
            !s->owner || PyThreadState_Get() != s->thread ||
            cj312_active_frame != s->owner || !cjb_owner_current(s->parent) ||
            s->owner != &s->parent->activation.active || s->owner->frame != s->frame ||
            s->frame != (_PyInterpreterFrame *)s->gen->gi_iframe ||
            s->frame->stacktop != -1 || s->gen->gi_frame_state != FRAME_EXECUTING)
        return 0;
    if (s->inline_started) {
        CJInlineActivation312 *i = &s->inline_owner;
        if (!s->inline_returned || !s->child || i->magic != CJI_MAGIC ||
                !i->returned || i->blocked || i->parent != &s->parent->activation ||
                i->child != &s->child->activation ||
                s->owner->top != s->base || s->owner->pending_stack_owner ||
                s->owner->pending_stack_base ||
                s->frame->prev_instr != _PyCode_CODE(s->frame->f_code) + i->resume_pc - 1)
            return 0;
    }
    else {
        if (s->frame->prev_instr != s->instruction) return 0;
        if (s->stack_committed) {
            if (s->owner->top != s->base || s->owner->pending_stack_owner ||
                    s->owner->pending_stack_base) return 0;
        }
        else if (s->owner->top != s->original_top ||
                (s->value_released ? (s->owner->pending_stack_owner != s ||
                                      s->owner->pending_stack_base != s->base)
                                   : (s->owner->pending_stack_owner != NULL ||
                                      s->owner->pending_stack_base != 0))) return 0;
    }
    s->last_top = s->owner->top;
    return 1;
}

static uint64_t cjs_block(CJSendLease312 *s, uint64_t reason) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    s->permission = CJS_BLOCKED; s->failure_reason = reason;
    if (!cjs_live(s)) s->owner_lost = 1;
    /* The enclosing driver retains every object/frame/raw result. A link
     * failure neither discards an owner nor manufactures an ordinary E. */
    return CJ_REFUSAL;
}

static int cjs_state_bound(CJSendLease312 *s, const unsigned char *w) {
    return cjp_get(w, 0) == CJS_MAGIC &&
        cjp_get(w, 120) == (uintptr_t)s->gen &&
        cjp_get(w, 128) == (uintptr_t)s->frame->f_code &&
        cjp_get(w, 136) == s->pc && cjp_get(w, 144) == s->oparg &&
        cjp_get(w, 152) == s->following &&
        cjp_get(w, 48) == (uintptr_t)s->ctx->raised &&
        cjp_get(w, 56) == (uintptr_t)(s->result ? s->result : s->ctx->slot);
}

static void cjs_reply(CJSendLease312 *s, unsigned char *w, const uint64_t answer[8]) {
    for (unsigned i=0; i<8; i++) cjp_put(w, 256+i*8, answer[i]);
    cjp_put(w, 48, (uintptr_t)s->ctx->raised);
    cjp_put(w, 56, (uintptr_t)(s->result ? s->result : s->ctx->slot));
}

static uint64_t cjs_prepare(CJBodyMachine312 *m, CJBodySend312 *u) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!m || !u || !u->entry || !cjb_observe_owner(m) || m->ctx->raised ||
            m->ctx->slot || m->ctx->external || PyErr_Occurred() ||
            m->activation.permission != CJA_ACTIVE || m->activation.active.pending_stack_owner ||
            m->activation.active.pending_stack_base || cjp_get(m->state, 8) != 41 ||
            cjp_get(m->state, 64) != 241 || cjp_get(m->state, 72) != (uintptr_t)m->gen ||
            cjp_get(m->state, 80) != 1 ||
            cjp_get(m->state, 88) != cjp_get(m->state, 144) ||
            cjp_get(m->state, 96) != cjp_get(m->state, 192) ||
            cjp_get(m->state, 200) != SEND || cjp_get(m->state, 104)) return CJ_REFUSAL;
    CJSendLease312 *s = &u->lease;
    for (size_t n=0; n<sizeof(*s); n++) if (((unsigned char *)s)[n]) return CJ_REFUSAL;
    for (unsigned n=0; n<CJS_STATE_BYTES; n++) if (u->state[n]) return CJ_REFUSAL;
    uint64_t pc=cjp_get(m->state,144), oparg=cjp_get(m->state,208);
    CJActiveFrame312 *owner=&m->activation.active;
    _PyInterpreterFrame *frame=m->activation.frame;
    if (pc >= m->units || m->units-pc <= 2 ||
            cjp_get(m->state,152)!=pc || cjp_get(m->state,184)!=pc+2 ||
            oparg>UINT64_MAX-(pc+2) || cjp_get(m->state,192)!=pc+2+oparg ||
            cjp_get(m->state,192)>=m->units ||
            cjp_get(m->packet,64+pc*64) != SEND ||
            cjp_get(m->packet,64+pc*64+8) != oparg ||
            cjp_get(m->packet,64+pc*64+56) != 1 ||
            frame->prev_instr != _PyCode_CODE(m->code)+pc ||
            frame->prev_instr->op.arg != (oparg & 255) ||
            (frame->prev_instr->op.code != SEND && frame->prev_instr->op.code != SEND_GEN) ||
            owner->top - (int)m->locals < 2 ||
            !frame->localsplus[owner->top-1] || !frame->localsplus[owner->top-2])
        return CJ_REFUSAL;
    s->magic=CJS_MAGIC; s->parent=m; s->ctx=m->ctx; s->thread=m->thread;
    s->gen=m->gen; s->frame=frame; s->owner=owner; s->instruction=frame->prev_instr;
    s->original_top=owner->top; s->base=owner->top-1; s->last_top=owner->top;
    s->receiver=frame->localsplus[owner->top-2]; s->value=frame->localsplus[owner->top-1];
    s->pc=pc; s->following=pc+2; s->oparg=oparg;
    cjp_put(u->state,0,CJS_MAGIC); cjp_put(u->state,120,(uintptr_t)m->gen);
    cjp_put(u->state,128,(uintptr_t)m->code); cjp_put(u->state,136,pc);
    cjp_put(u->state,144,oparg); cjp_put(u->state,152,s->following);
    return 0;
}

/* One raw operation, independent sequence consumed before installing E.
 * No raised error crosses the next HIA call. Handled-exception context is
 * the original interpreter chain; no synthetic except block is entered. */
static uint64_t cjs_leaf(CJSendLease312 *s, unsigned char *w) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!s || s->magic != CJS_MAGIC || !w || !cjs_live(s) ||
            PyErr_Occurred() || s->ctx->external || s->ctx->slot ||
            s->permission == CJS_DONE || s->permission == CJS_BLOCKED ||
            s->permission == CJS_INLINED || !cjs_state_bound(s,w) ||
            cjp_get(w,112) || cjp_get(w,24) != 1 || s->issued != s->consumed ||
            s->issued == UINT64_MAX || cjp_get(w,16) != s->issued+1 ||
            cjp_get(w,32) != s->consumed)
        return s && s->magic == CJS_MAGIC ? cjs_block(s,1) : CJ_REFUSAL;
    uint64_t op=cjp_get(w,64), a=cjp_get(w,72), b=cjp_get(w,80),
             c=cjp_get(w,88), d=cjp_get(w,96);
    if (op<CJS_BEGIN || op>CJS_ERROR || cjp_get(w,104) ||
            (op != CJS_CACHE && (a || b || c || d)) ||
            (op != CJS_BEGIN && !s->begun)) return cjs_block(s,2);
    switch (op) {
    case CJS_BEGIN:
        if (s->begun || s->permission != CJS_NEW || s->ctx->raised) return cjs_block(s,3);
        break;
    case CJS_CACHE:
        if (s->route || s->primitive || s->ctx->raised || s->result ||
                (a!=SEND && a!=SEND_GEN) || b>65535 ||
                c!=s->instruction->op.code || d!=((_PySendCache *)(s->instruction+1))->counter)
            return cjs_block(s,4);
        break;
    case CJS_INLINE:
        if (s->route || s->primitive || s->result || s->ctx->raised ||
                !(s->facts&3) || !(s->facts&4) || !(s->facts&8)) return cjs_block(s,5);
        /* No acknowledgement until the actual child closes. The body
         * effect has already been consumed, so it cannot be issued again. */
        return CJB_CHILD_REQUIRED;
    case CJS_ITERNEXT:
    case CJS_SEND_METHOD:
        if (s->route || s->primitive || s->ctx->raised || s->result ||
                ((s->facts&3) && (s->facts&4) && (s->facts&8)) ||
                (op==CJS_ITERNEXT ? (!(s->facts&16) || !(s->facts&32)) :
                                   ((s->facts&16) && (s->facts&32)))) return cjs_block(s,6);
        break;
    case CJS_STOP_MATCH:
        if (s->route!=2 || !s->primitive_returned || s->result || s->matched ||
                s->monitored || s->fetched || s->value_released) return cjs_block(s,7);
        break;
    case CJS_MONITOR_RAISE:
        if (s->route!=2 || !s->matched || !s->stop_match || s->monitored ||
                s->fetched || s->result || !s->ctx->raised) return cjs_block(s,8);
        break;
    case CJS_FETCH_STOP:
        if (s->route!=2 || !s->matched || (s->stop_match && !s->monitored) ||
                s->fetched || s->result || s->value_released) return cjs_block(s,9);
        break;
    case CJS_DROP_VALUE:
        if (s->route!=2 || !s->primitive_returned || !s->result || s->ctx->raised ||
                s->value_released || s->stack_committed ||
                (s->fetched && s->fetch_status)) return cjs_block(s,10);
        break;
    case CJS_COMMIT:
        if (s->route!=2 || !s->value_released || s->stack_committed ||
                !s->result || s->ctx->raised) return cjs_block(s,11);
        break;
    case CJS_MOVE_RESULT:
        if (s->route!=2 || !s->stack_committed || s->result_moved ||
                !s->result || s->ctx->raised) return cjs_block(s,12);
        break;
    case CJS_ERROR:
        if (s->route!=2 || !s->fetched || s->fetch_status!=-1 || s->result ||
                !s->ctx->raised || s->value_released || s->stack_committed)
            return cjs_block(s,13);
        break;
    }
    if (!cjp_increment(&s->leaf_attempts)) return cjs_block(s,14);
    s->issued=cjp_get(w,16); s->consumed=s->issued;
    cjp_put(w,32,s->consumed); cjp_put(w,40,op);
    uint64_t answer[8]={0};
    PyObject *incoming=s->ctx->raised; s->ctx->raised=NULL;
    PyErr_SetRaisedException(incoming);
    switch (op) {
    case CJS_BEGIN: {
        s->begun=1; s->permission=CJS_ACTIVE;
        int gen=Py_IS_TYPE(s->receiver,&PyGen_Type);
        int coro=Py_IS_TYPE(s->receiver,&PyCoro_Type);
        int executable=(gen || coro) && ((PyGenObject *)s->receiver)->gi_frame_state<FRAME_EXECUTING;
        s->facts=(uint64_t)gen | ((uint64_t)coro<<1) |
            ((uint64_t)(s->thread->interp->eval_frame==NULL)<<2) |
            ((uint64_t)executable<<3) | ((uint64_t)Py_IsNone(s->value)<<4) |
            ((uint64_t)(PyIter_Check(s->receiver)!=0)<<5);
        s->mode=s->instruction->op.code;
        s->counter=((_PySendCache *)(s->instruction+1))->counter;
        answer[0]=(uint64_t)s->original_top; answer[1]=(uintptr_t)s->receiver;
        answer[2]=(uintptr_t)s->value; answer[3]=s->mode; answer[4]=s->counter;
        answer[5]=s->facts; answer[6]=s->following;
        break;
    }
    case CJS_CACHE:
        s->instruction->op.code=(uint8_t)a;
        ((_PySendCache *)(s->instruction+1))->counter=(uint16_t)b;
        s->mode=a; s->counter=b; answer[0]=a; answer[1]=b;
        break;
    case CJS_ITERNEXT:
        s->route=2; s->primitive=op;
        s->result=Py_TYPE(s->receiver)->tp_iternext(s->receiver);
        s->primitive_returned=1;
        break;
    case CJS_SEND_METHOD:
        s->route=2; s->primitive=op;
        s->result=PyObject_CallMethodOneArg(s->receiver,&_Py_ID(send),s->value);
        s->primitive_returned=1;
        break;
    case CJS_STOP_MATCH:
        s->matched=1; s->stop_match=PyErr_ExceptionMatches(PyExc_StopIteration)!=0;
        answer[0]=s->stop_match;
        break;
    case CJS_MONITOR_RAISE:
        s->monitored=1;
        cja_monitor_raise(s->thread,s->frame,s->instruction);
        break;
    case CJS_FETCH_STOP:
        s->fetched=1; s->fetch_status=_PyGen_FetchStopIterationValue(&s->result);
        answer[0]=(uint64_t)(int64_t)s->fetch_status;
        break;
    case CJS_DROP_VALUE: {
        PyObject *value=s->value;
        s->owner->pending_stack_owner=s; s->owner->pending_stack_base=s->base;
        s->value_released=1; s->last_released=(uintptr_t)value; s->value=NULL;
        /* The actual original slot is deliberately NOT zeroed. */
        Py_DECREF(value);
        answer[0]=1;
        break;
    }
    case CJS_COMMIT:
        s->owner->top=s->base; s->owner->pending_stack_owner=NULL;
        s->owner->pending_stack_base=0; s->stack_committed=1;
        answer[0]=(uint64_t)s->base;
        break;
    case CJS_MOVE_RESULT:
        s->ctx->slot=s->result; s->result=NULL; s->result_moved=1;
        s->flow=s->fetched ? 0 : 1; s->permission=CJS_DONE;
        break;
    case CJS_ERROR:
        s->permission=CJS_DONE; answer[0]=(uint64_t)s->original_top;
        break;
    }
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (PyThreadState_Get()!=s->thread) return cjs_block(s,15);
    s->ctx->raised=PyErr_GetRaisedException();
    if (!cjp_increment(&s->leaf_returns)) return cjs_block(s,16);
    if (!cjs_live(s)) return cjs_block(s,17);
    cjs_reply(s,w,answer);
    return 0;
}

static uint64_t cjb_attach_send(CJBodyMachine312 *m, CJBodySend312 *u, CJHiaEntry entry) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!m || m->magic!=CJB_MAGIC || m->permission!=CJB_READY ||
            m->hia_attempts || m->activation_attempts || m->send || !u || !entry ||
            !cjb_observe_owner(m)) return CJ_REFUSAL;
    uint64_t addresses[8]={(uintptr_t)m,(uintptr_t)m->ctx,(uintptr_t)m->packet,
        (uintptr_t)m->state,(uintptr_t)m->trace,(uintptr_t)u,(uintptr_t)m->unpack,
        m->unpack ? (uintptr_t)m->unpack->trace : 0};
    uint64_t sizes[8]={sizeof(*m),sizeof(*m->ctx),m->packet_bytes,CJB_STATE_BYTES,
        m->trace_capacity*CJB_TRACE_BYTES,sizeof(*u),m->unpack ? sizeof(*m->unpack) : 0,
        m->unpack ? m->unpack->trace_capacity*CJU_TRACE_BYTES : 0};
    for (unsigned i=0; i<8; i++) {
        if (!sizes[i]) continue;
        if (!cjp_span(addresses[i],sizes[i])) return CJ_REFUSAL;
        for (unsigned j=0; j<i; j++) if (sizes[j] &&
            !cjp_disjoint(addresses[i],sizes[i],addresses[j],sizes[j])) return CJ_REFUSAL;
    }
    for (size_t n=0; n<sizeof(*u); n++) if (((unsigned char *)u)[n]) return CJ_REFUSAL;
    u->entry=entry; m->send=u;
    return 0;
}

/* No recursive evaluator/pump call occurs here. This loop performs only
 * the current SEND continuation; an inlined body returns a scheduling
 * event to the outer iterative C driver while all owners remain retained. */
static uint64_t cjb_send_continue(CJBodyMachine312 *m) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    CJBodySend312 *u=m->send; CJSendLease312 *s=&u->lease;
    for (;;) {
        if (!cjs_live(s) || PyErr_Occurred() || !cjs_state_bound(s,u->state) ||
                s->ctx->external || s->owner_lost) return cjb_refuse(m,CJB_BAD_OWNER);
        if (!cjp_increment(&u->native_attempts)) return cjb_refuse(m,CJB_COUNTER);
        unsigned char output=0;
        uint32_t status=u->entry(m->packet,m->packet_bytes,&output,1,u->state,CJS_STATE_BYTES);
        if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
        if (PyThreadState_Get()!=m->thread) return cjb_refuse(m,CJB_BAD_OWNER);
        if (!cjp_increment(&u->native_returns)) return cjb_refuse(m,CJB_COUNTER);
        cjb_trace_child(m,6,u->state,sizeof(u->state)/8);
        if (PyErr_Occurred() || !cjs_live(s) || !cjs_state_bound(s,u->state))
            return cjb_refuse(m,CJB_BAD_NATIVE);
        if (status==2) {
            uint64_t result=cjs_leaf(s,u->state);
            if (result==CJB_GIL_UNAVAILABLE) return result;
            cjb_trace_child(m,7,s,sizeof(*s)/8);
            if (result==CJB_CHILD_REQUIRED) {
                m->permission=CJB_CHILD_REQUIRED;
                return CJB_CHILD_REQUIRED;
            }
            if (result) return cjb_refuse(m,CJB_BAD_LEAF);
            continue;
        }
        if (status>1 || s->permission!=CJS_DONE || cjp_get(u->state,112)!=(status ? 2 : 1) ||
                cjp_get(u->state,24) || s->issued!=s->consumed ||
                s->leaf_attempts!=s->leaf_returns || u->native_attempts!=u->native_returns ||
                s->result || s->ctx->external ||
                (status ? (!s->ctx->raised || s->ctx->slot) :
                          (s->ctx->raised || !s->ctx->slot || !s->result_moved)) ||
                m->activation.active.pending_stack_owner ||
                u->completed==UINT64_MAX) return cjb_refuse(m,CJB_BAD_EXIT);
        uint64_t answer[8]={0,0,s->flow,0,0,0,0,0};
        if (s->inline_returned) {
            uint64_t actual_pc=status ? s->inline_owner.failure_pc : s->inline_owner.resume_pc-1;
            answer[3]=actual_pc; answer[4]=actual_pc;
            answer[7]=1;
        }
        u->permission=2; u->completed++;
        cjb_reply(m,answer);
        return cjb_complete(m,0);
    }
}

static uint64_t cjb_send_241(CJBodyMachine312 *m) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    CJBodySend312 *u=m->send;
    if (!u) { m->missing_port=241; m->permission=CJB_PORT_REQUIRED; return CJB_PORT_REQUIRED; }
    if (u->permission!=0 && u->permission!=2) return cjb_refuse(m,CJB_BAD_REPLY);
    if (u->permission==2) {
        CJSendLease312 *old=&u->lease;
        if (old->permission!=CJS_DONE || old->result || old->owner_lost ||
                old->owner!=&m->activation.active || !cjb_observe_owner(m) ||
                m->ctx->slot || m->ctx->raised || m->activation.active.pending_stack_owner)
            return cjb_refuse(m,CJB_BAD_OWNER);
        /* Full terminal state and lease have already been recorded. No
         * Python reference remains owned by these reusable fixed bytes. */
        cjb_trace_child(m,8,old,sizeof(*old)/8);
        memset(u->state,0,sizeof(u->state)); memset(old,0,sizeof(*old));
    }
    uint64_t pc=cjp_get(m->state,144);
    if (pc>=m->units || !cjb_observe_owner(m)) return cjb_refuse(m,CJB_BAD_OWNER);
    m->activation.frame->prev_instr=_PyCode_CODE(m->code)+pc;
    uint64_t prepared=cjs_prepare(m,u);
    if (prepared) return cjb_refuse(m,CJB_BAD_INPUT);
    uint64_t consumed=cjb_consume(m,241);
    if (consumed) return consumed;
    u->permission=1;
    return cjb_send_continue(m);
}

/* The prepared child and its code packet are admitted by the retaining
 * driver, not inferred from an address in HIA output. The child generator
 * is still owned by the actual receiver slot and receives the original v.
 * Ordinary foreign generator/coroutine body admission remains an explicit
 * prerequisite; rejecting a private attachment is not a public fallback. */
static uint64_t cjb_send_bind_child(CJBodyMachine312 *m, CJBodyMachine312 *child) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!m || m->magic!=CJB_MAGIC || m->permission!=CJB_CHILD_REQUIRED || !m->send)
        return CJ_REFUSAL;
    CJBodySend312 *u=m->send; CJSendLease312 *s=&u->lease; unsigned char *w=u->state;
    if (!child || child->gen!=(PyGenObject *)s->receiver || !cjs_live(s) ||
            s->permission!=CJS_ACTIVE || s->route || s->inline_started ||
            s->ctx->raised || s->ctx->slot || s->result || PyErr_Occurred() ||
            !cjs_state_bound(s,w) || cjp_get(w,24)!=1 || cjp_get(w,64)!=CJS_INLINE ||
            cjp_get(w,8)!=20 || cjp_get(w,112) || cjp_get(w,16)!=s->issued+1 ||
            cjp_get(w,32)!=s->consumed || s->issued!=s->consumed ||
            s->issued==UINT64_MAX || s->leaf_attempts==UINT64_MAX)
        return cjb_refuse(m,CJB_BAD_INPUT);
    uint64_t bound=cjb_attach_inline(child,m,&s->inline_owner,CJI_SEND,s->following,s->oparg);
    if (bound) return bound;
    s->leaf_attempts++; s->issued=cjp_get(w,16); s->consumed=s->issued;
    s->route=1; s->inline_started=1; s->child=child; s->permission=CJS_INLINED;
    /* No ACK yet. No parent native/leaf step may run while child is current. */
    return 0;
}

static uint64_t cjb_send_resume_child(CJBodyMachine312 *m) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!m || m->magic!=CJB_MAGIC || m->permission!=CJB_CHILD_REQUIRED || !m->send)
        return CJ_REFUSAL;
    CJBodySend312 *u=m->send; CJSendLease312 *s=&u->lease;
    CJBodyMachine312 *child=s->child; CJInlineActivation312 *i=&s->inline_owner;
    if (!child || child->permission!=CJB_DONE || s->permission!=CJS_INLINED ||
            !s->inline_started || s->inline_returned || !i->returned || i->blocked ||
            i->child!=&child->activation || child->activation.inlined!=i ||
            child->activation.quarantine_failure || child->ctx->external ||
            child->ctx->phase || s->ctx->slot || s->ctx->raised || s->ctx->external ||
            PyErr_Occurred() || PyThreadState_Get()!=s->thread ||
            !cjb_owner_current(m) || m->activation.active.pending_stack_owner ||
            cjp_get(u->state,24)!=1 || cjp_get(u->state,64)!=CJS_INLINE ||
            cjp_get(u->state,16)!=s->consumed || s->issued!=s->consumed ||
            child->result_status>3 || child->result_status==2 ||
            (child->result_status==1 ? (!child->ctx->raised || child->ctx->slot) :
                                      (child->ctx->raised || !child->ctx->slot)))
        return cjb_refuse(m,CJB_BAD_EXIT);
    /* Complete bytes precede transfer. The terminal child is single-use;
     * the enclosing driver's ownership ledger must record the transfer. */
    cjb_trace_child(m,9,child->state,CJB_STATE_BYTES/8);
    s->inline_returned=1; s->stack_committed=1;
    s->ctx->slot=child->ctx->slot; child->ctx->slot=NULL;
    s->ctx->raised=child->ctx->raised; child->ctx->raised=NULL;
    cjp_put(child->state,48,0); cjp_put(child->state,320,0);
    s->result_moved=s->ctx->slot!=NULL; s->flow=child->result_status==3;
    s->permission=CJS_DONE;
    if (!cjp_increment(&s->leaf_returns)) return cjb_refuse(m,CJB_COUNTER);
    cjp_put(u->state,32,s->consumed); cjp_put(u->state,40,CJS_INLINE);
    uint64_t answer[8]={child->result_status,i->resume_pc,i->failure_pc,
                       child->result_status==1,0,0,0,0};
    cjs_reply(s,u->state,answer);
    if (!cjs_live(s)) return cjb_refuse(m,CJB_BAD_OWNER);
    m->permission=CJB_EFFECT_READY;
    return cjb_send_continue(m);
}
#endif
