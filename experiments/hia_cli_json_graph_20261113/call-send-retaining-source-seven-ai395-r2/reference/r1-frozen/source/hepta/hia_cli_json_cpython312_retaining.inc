/* Continuous, non-recursive C retaining driver for the new HIA body.
 *
 * REBUILD_FROM_PRESERVED_BASELINE_UNEXECUTED. PRIVATE: no Python-callable
 * entry is exported. Each native step is the independently admitted HIA
 * entry; every object primitive remains selected by that HIA request.
 * Child scheduling transfers no extra PyObject reference and never calls
 * _PyEval_EvalFrameDefault. RETURN_GENERATOR uses the actual thread-frame
 * prologue; SEND uses the actual receiver generator in this same C entry.
 *
 * The caller retains the images, registry/code owners, root context and
 * the entire supplied C arena until structural closure. Arena capacity is
 * a finite experiment resource, NOT a public JSON nesting/size restriction.
 * An unadmitted child, missing port, no-GIL or corrupted interpreter link
 * remains an INTERNAL blocked owner. None permits this C owner to return
 * to Python. This file intentionally has no wrapper that could mistake a
 * heap-retained linked activation for a safe Python return. General-body
 * admission and the outer blocked-owner policy remain explicit OPEN work.
 */
#if PY_VERSION_HEX == 0x030c0ef0
#define CJR_MAGIC UINT64_C(0x31305452494c4348) /* HCLIRT01 */
enum { CJR_NEW=0, CJR_READY=1, CJR_RUNNING=2, CJR_DONE=3, CJR_BLOCKED=4 };
enum {
    CJR_BAD_PREPARE=1, CJR_BAD_CURRENT=2, CJR_BAD_NATIVE=3,
    CJR_UNKNOWN_PACKET=4, CJR_ARENA_EXHAUSTED=5, CJR_BAD_CHILD=6,
    CJR_MISSING_PORT=7, CJR_UNCLOSED_LINK=8, CJR_COUNT_OVERFLOW=9,
    CJR_GIL_LOST=10, CJR_BAD_RETURN=11
};

typedef struct {
    PyCodeObject *code;             /* borrowed exact independently admitted code */
    const unsigned char *packet;
    uint64_t packet_bytes;
} CJRetainingPacket312;

typedef struct {
    CJHiaEntry body, unpack, send, call_dispatch, call, call_fast, call_prologue;
} CJRetainingEntries312;

typedef struct {
    CJBodyMachine312 body;
    CJContext child_context;
    CJBodyUnpack312 unpack;
    CJBodySend312 send;
    CJBodyCall312 call;
    _Alignas(uint64_t) unsigned char state[CJB_STATE_BYTES];
    uint64_t generation, parent_index, child_transferred;
} CJRetainingNode312;

typedef struct {
    CJRetainingNode312 *node;
    unsigned char *body_trace, *unpack_trace;
    uint64_t body_capacity, unpack_capacity;
} CJRetainingSlot312;

typedef struct {
    uint64_t magic, permission, failure_reason, safe_python_return;
    PyThreadState *thread;
    _PyCFrame *caller_cframe;
    _PyInterpreterFrame *caller_frame;
    _PyErr_StackItem *caller_exc;
    CJActiveFrame312 *caller_active;
    const CJRetainingPacket312 *packets;
    uint64_t packet_count;
    CJRetainingEntries312 entries;
    CJRetainingSlot312 *slots;
    uint64_t slot_count, current, highest_used;
    uint64_t body_steps, body_dispatches, child_prepares, child_closes;
    uint64_t prologue_calls, prologue_returns, epoch;
    uint64_t body_trace_dropped, unpack_trace_dropped;
    uint64_t result_status, native_status, last_node_permission;
    unsigned char *trace;
    uint64_t trace_capacity, trace_written, trace_dropped;
} CJRetainingDriver312;

/* Observer records contain complete bytes before a dead child C arena is
 * reused. They do not acquire a Python reference. Overflow loses observer
 * rows only; a finite qualification must separately require zero dropped.
 */
static void cjr_bytes(CJRetainingDriver312 *r, uint64_t kind, uint64_t index,
                       const void *data, uint64_t bytes) {
    const unsigned char *p=data;
    for (uint64_t at=0;at<bytes;at+=(CJB_TRACE_WORDS-5)*8) {
        if (r->trace_written>=r->trace_capacity) {
            if (r->trace_dropped!=UINT64_MAX) r->trace_dropped++;
            continue;
        }
        uint64_t row[CJB_TRACE_WORDS]={0};
        uint64_t count=bytes-at;
        if (count>(CJB_TRACE_WORDS-5)*8) count=(CJB_TRACE_WORDS-5)*8;
        row[0]=kind; row[1]=index; row[2]=bytes; row[3]=at; row[4]=count;
        memcpy(row+5,p+at,count);
        memcpy(r->trace+r->trace_written*CJB_TRACE_BYTES,row,sizeof(row));
        r->trace_written++;
    }
}

static uint64_t cjr_block(CJRetainingDriver312 *r, uint64_t reason) {
    /* Scalar-only on the no-GIL path. No PyErr/TLS walk or invented unlink. */
    r->permission=CJR_BLOCKED; r->failure_reason=reason; r->safe_python_return=0;
    return CJR_BLOCKED;
}

static const CJRetainingPacket312 *cjr_packet(CJRetainingDriver312 *r,
                                               PyCodeObject *code) {
    const CJRetainingPacket312 *found=NULL;
    for (uint64_t n=0;n<r->packet_count;n++) {
        if (r->packets[n].code!=code) continue;
        if (found) return NULL;
        found=r->packets+n;
    }
    return found;
}

static int cjr_context_empty(const CJContext *c) {
    if (c->phase || c->list || c->saved_size || c->saved_allocated || c->saved_items ||
            c->displaced_size || c->displaced_items || c->slot || c->raised || c->external)
        return 0;
    for (unsigned n=0;n<8;n++) if (c->cells[n]) return 0;
    for (unsigned n=0;n<CJ_TEMP_WORDS;n++) if (c->temporary_array[n]) return 0;
    return 1;
}

static uint64_t cjr_prepare_node(CJRetainingDriver312 *r, uint64_t index,
                                   PyGenObject *gen, CJContext *ctx,
                                   PyObject *send_argument, uint64_t throwflag) {
    CJRetainingSlot312 *slot=r->slots+index; CJRetainingNode312 *n=slot->node;
    const CJRetainingPacket312 *packet=cjr_packet(r,((_PyInterpreterFrame *)gen->gi_iframe)->f_code);
    if (!packet) return CJR_UNKNOWN_PACKET;
    if (!ctx) {
        ctx=&n->child_context;
        if (hia_cli_json_leaf_init(ctx,sizeof(*ctx))) return CJR_BAD_PREPARE;
    }
    if (cjb_prepare(&n->body,ctx,gen,send_argument,throwflag,r->entries.body,
            packet->packet,packet->packet_bytes,n->state,slot->body_trace,slot->body_capacity) ||
        cjb_attach_unpack(&n->body,&n->unpack,r->entries.unpack,slot->unpack_trace,slot->unpack_capacity) ||
        cjb_attach_send(&n->body,&n->send,r->entries.send) ||
        cjb_attach_call(&n->body,&n->call,r->entries.call_dispatch,r->entries.call,
            r->entries.call_fast,r->entries.call_prologue))
        return CJR_BAD_PREPARE;
    n->generation=++r->epoch;
    return 0;
}

/* Admission precedes any activation. The runtime/code/image proof is an
 * external prerequisite, not inferred from these pointer/layout checks.
 * All supplied metadata spans, each node and every trace span are distinct.
 */
static uint64_t cjr_prepare(CJRetainingDriver312 *r,
                              const CJRetainingEntries312 *entries,
                              const CJRetainingPacket312 *packets, uint64_t packet_count,
                              CJRetainingSlot312 *slots, uint64_t slot_count,
                              PyGenObject *gen, CJContext *root_context,
                              PyObject *send_argument, uint64_t throwflag,
                              unsigned char *trace, uint64_t trace_capacity) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!r || !entries || !packets || !packet_count || !slots || !slot_count ||
            !gen || !PyGen_CheckExact(gen) || !root_context || PyErr_Occurred() ||
            !cj312_runtime.ready || !cj312_control_runtime.ready || !cj312_call_runtime.ready ||
            !entries->body || !entries->unpack || !entries->send ||
            !entries->call_dispatch || !entries->call || !entries->call_fast || !entries->call_prologue ||
            throwflag>1 || packet_count>UINT64_MAX/sizeof(*packets) ||
            slot_count>UINT64_MAX/sizeof(*slots) || trace_capacity>UINT64_MAX/CJB_TRACE_BYTES ||
            (!trace_capacity && trace)) return CJ_REFUSAL;
    for (size_t at=0;at<sizeof(*r);at++) if (((unsigned char *)r)[at]) return CJ_REFUSAL;
    uint64_t fixed_address[6]={(uintptr_t)r,(uintptr_t)entries,(uintptr_t)packets,
        (uintptr_t)slots,(uintptr_t)root_context,(uintptr_t)trace};
    uint64_t fixed_size[6]={sizeof(*r),sizeof(*entries),packet_count*sizeof(*packets),
        slot_count*sizeof(*slots),sizeof(*root_context),trace_capacity*CJB_TRACE_BYTES};
    for (unsigned x=0;x<6;x++) {
        if (!fixed_size[x]) continue;
        if (!cjp_span(fixed_address[x],fixed_size[x])) return CJ_REFUSAL;
        for (unsigned y=0;y<x;y++) if (fixed_size[y] &&
                !cjp_disjoint(fixed_address[x],fixed_size[x],fixed_address[y],fixed_size[y])) return CJ_REFUSAL;
    }
    for (uint64_t x=0;x<slot_count;x++) {
        CJRetainingSlot312 *s=slots+x;
        if (!s->node || s->body_capacity>UINT64_MAX/CJB_TRACE_BYTES ||
                s->unpack_capacity>UINT64_MAX/CJU_TRACE_BYTES ||
                (!s->body_capacity && s->body_trace) || (!s->unpack_capacity && s->unpack_trace)) return CJ_REFUSAL;
        uint64_t address[3]={(uintptr_t)s->node,(uintptr_t)s->body_trace,(uintptr_t)s->unpack_trace};
        uint64_t sizes[3]={sizeof(*s->node),s->body_capacity*CJB_TRACE_BYTES,s->unpack_capacity*CJU_TRACE_BYTES};
        for (unsigned a=0;a<3;a++) {
            if (!sizes[a]) continue;
            if (!cjp_span(address[a],sizes[a])) return CJ_REFUSAL;
            for (unsigned b=0;b<6;b++) if (fixed_size[b] &&
                    !cjp_disjoint(address[a],sizes[a],fixed_address[b],fixed_size[b])) return CJ_REFUSAL;
            for (unsigned b=0;b<a;b++) if (sizes[b] &&
                    !cjp_disjoint(address[a],sizes[a],address[b],sizes[b])) return CJ_REFUSAL;
            for (uint64_t y=0;y<x;y++) {
                uint64_t other[3]={(uintptr_t)slots[y].node,(uintptr_t)slots[y].body_trace,(uintptr_t)slots[y].unpack_trace};
                uint64_t lengths[3]={sizeof(*slots[y].node),slots[y].body_capacity*CJB_TRACE_BYTES,
                    slots[y].unpack_capacity*CJU_TRACE_BYTES};
                for (unsigned b=0;b<3;b++) if (lengths[b] &&
                        !cjp_disjoint(address[a],sizes[a],other[b],lengths[b])) return CJ_REFUSAL;
            }
            for (uint64_t p=0;p<packet_count;p++) if (packets[p].packet_bytes &&
                    !cjp_disjoint(address[a],sizes[a],(uintptr_t)packets[p].packet,packets[p].packet_bytes)) return CJ_REFUSAL;
        }
        for (size_t at=0;at<sizeof(*s->node);at++) if (((unsigned char *)s->node)[at]) return CJ_REFUSAL;
    }
    for (uint64_t p=0;p<packet_count;p++) {
        const CJRetainingPacket312 *q=packets+p;
        if (!q->code || !PyCode_Check(q->code) || !q->packet || q->packet_bytes<64 ||
                !cjp_span((uintptr_t)q->packet,q->packet_bytes) ||
                cjp_get(q->packet,0)!=CJB_PACKET_MAGIC || cjp_get(q->packet,8)!=31214 ||
                cjp_get(q->packet,16)!=(uint64_t)Py_SIZE(q->code) || cjp_get(q->packet,56)!=1 ||
                (uint64_t)Py_SIZE(q->code)>(UINT64_MAX-64)/64 ||
                q->packet_bytes!=64+(uint64_t)Py_SIZE(q->code)*64) return CJ_REFUSAL;
        for (unsigned x=0;x<6;x++) if (fixed_size[x] &&
                !cjp_disjoint((uintptr_t)q->packet,q->packet_bytes,fixed_address[x],fixed_size[x])) return CJ_REFUSAL;
        for (uint64_t earlier=0;earlier<p;earlier++) if (packets[earlier].code==q->code) return CJ_REFUSAL;
    }
    r->magic=CJR_MAGIC; r->thread=PyThreadState_Get();
    r->caller_cframe=r->thread->cframe; r->caller_frame=r->caller_cframe->current_frame;
    r->caller_exc=r->thread->exc_info; r->caller_active=cj312_active_frame;
    r->packets=packets; r->packet_count=packet_count; r->entries=*entries;
    r->slots=slots; r->slot_count=slot_count; r->trace=trace; r->trace_capacity=trace_capacity;
    uint64_t result=cjr_prepare_node(r,0,gen,root_context,send_argument,throwflag);
    if (result) return cjr_block(r,result);
    slots[0].node->parent_index=UINT64_MAX;
    r->permission=CJR_READY;
    return 0;
}

/* Only after the child terminal bytes are captured and the actual parent
 * port has moved its single result/error owner. No DECREF, allocation or
 * Python callback occurs between that move, clearing these owner-free C
 * records and the next parent's HIA-selected stack push/error continuation.
 */
static uint64_t cjr_release_child(CJRetainingDriver312 *r) {
    uint64_t index=r->current;
    CJRetainingNode312 *n=r->slots[index].node;
    if (!index || n->parent_index!=index-1 || n->child_transferred ||
            n->body.permission!=CJB_DONE || !cjr_context_empty(n->body.ctx) ||
            n->body.activation.c_entered || n->body.activation.py_entered ||
            n->body.activation.exc_linked || n->body.activation.stack_live ||
            n->body.activation.quarantine_failure || n->body.unexpected_error ||
            n->call.lease.result || n->call.lease.child || n->call.dispatch.unexpected_error ||
            n->call.prologue.result || n->call.prologue.unexpected_error ||
            n->send.lease.result) return cjr_block(r,CJR_BAD_RETURN);
    n->child_transferred=1;
    cjr_bytes(r,10,index,n,sizeof(*n));
    cjr_bytes(r,11,index,r->slots[index].body_trace,n->body.trace_written*CJB_TRACE_BYTES);
    cjr_bytes(r,12,index,r->slots[index].unpack_trace,n->unpack.trace_written*CJU_TRACE_BYTES);
    if (!cjb_add_count(&r->body_trace_dropped,n->body.trace_dropped) ||
            !cjb_add_count(&r->unpack_trace_dropped,n->unpack.trace_dropped) ||
            !cjp_increment(&r->child_closes)) return cjr_block(r,CJR_COUNT_OVERFLOW);
    /* Only borrowed addresses remain in n. The parent SEND lease retains
     * its historical child address for diagnostics, but no later primitive
     * may walk it after the parent port is terminal. */
    memset(n,0,sizeof(*n));
    r->current=index-1;
    return 0;
}

static uint64_t cjr_close_root(CJRetainingDriver312 *r) {
    CJBodyMachine312 *m=&r->slots[0].node->body;
    if (r->current || m->permission!=CJB_DONE || !cjb_owner_current(m) ||
            PyErr_Occurred() || m->ctx->external || m->unexpected_error ||
            m->activation.c_entered || m->activation.py_entered ||
            m->activation.exc_linked || m->activation.stack_live ||
            m->activation.quarantine_failure || m->call->lease.result || m->call->lease.child ||
            m->call->dispatch.unexpected_error || m->call->prologue.result ||
            m->call->prologue.unexpected_error || m->send->lease.result ||
            r->child_prepares!=r->child_closes || r->prologue_calls!=r->prologue_returns ||
            r->thread->cframe!=r->caller_cframe ||
            r->caller_cframe->current_frame!=r->caller_frame ||
            r->thread->exc_info!=r->caller_exc || cj312_active_frame!=r->caller_active)
        return cjr_block(r,CJR_UNCLOSED_LINK);
    cjr_bytes(r,20,0,r->slots[0].node,sizeof(*r->slots[0].node));
    cjr_bytes(r,21,0,r->slots[0].body_trace,m->trace_written*CJB_TRACE_BYTES);
    cjr_bytes(r,22,0,r->slots[0].unpack_trace,m->unpack->trace_written*CJU_TRACE_BYTES);
    if (!cjb_add_count(&r->body_trace_dropped,m->trace_dropped) ||
            !cjb_add_count(&r->unpack_trace_dropped,m->unpack->trace_dropped))
        return cjr_block(r,CJR_COUNT_OVERFLOW);
    r->result_status=m->result_status; r->permission=CJR_DONE; r->safe_python_return=1;
    return CJR_DONE;
}

/* One continuous private C invocation. The loop is only a mechanical
 * scheduler for HIA effect/child/terminal permissions. It performs no JSON
 * graph choice or reference-release plan and never recursively invokes
 * itself. A second invocation cannot restart a consumed/blocked owner.
 */
static uint64_t cjr_run(CJRetainingDriver312 *r) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!r || r->magic!=CJR_MAGIC || r->permission!=CJR_READY ||
            r->current || r->body_steps || r->body_dispatches ||
            PyThreadState_Get()!=r->thread || PyErr_Occurred()) return CJ_REFUSAL;
    r->permission=CJR_RUNNING;
    for (;;) {
        if (!PyGILState_Check()) return cjr_block(r,CJR_GIL_LOST);
        if (PyThreadState_Get()!=r->thread || r->current>=r->slot_count)
            return cjr_block(r,CJR_BAD_CURRENT);
        CJRetainingNode312 *n=r->slots[r->current].node;
        CJBodyMachine312 *m=&n->body;
        r->last_node_permission=m->permission;
        if (m->permission==CJB_READY) {
            if (!cjp_increment(&r->body_steps)) return cjr_block(r,CJR_COUNT_OVERFLOW);
            r->native_status=cjb_hia_step(m);
            if (m->permission==CJB_READY) return cjr_block(r,CJR_BAD_NATIVE);
            continue;
        }
        if (m->permission==CJB_EFFECT_READY) {
            if (!cjp_increment(&r->body_dispatches)) return cjr_block(r,CJR_COUNT_OVERFLOW);
            r->native_status=cjb_dispatch_known(m);
            if (m->permission==CJB_EFFECT_READY) return cjr_block(r,CJR_BAD_NATIVE);
            continue;
        }
        if (m->permission==CJB_CHILD_REQUIRED) {
            if (cjp_get(m->state,64)==240 && m->call && m->call->stage==3) {
                _PyInterpreterFrame *child=m->call->lease.child;
                const CJRetainingPacket312 *p=child ? cjr_packet(r,child->f_code) : NULL;
                if (!p) return cjr_block(r,CJR_UNKNOWN_PACKET);
                if (!cjp_increment(&r->prologue_calls)) return cjr_block(r,CJR_COUNT_OVERFLOW);
                r->native_status=cjb_call_original_generator(m,p->packet,p->packet_bytes);
                if (!cjp_increment(&r->prologue_returns)) return cjr_block(r,CJR_COUNT_OVERFLOW);
                if (r->native_status || m->permission!=CJB_READY) return cjr_block(r,CJR_BAD_CHILD);
                continue; /* owned result -> next HIA -> actual parent push */
            }
            if (cjp_get(m->state,64)!=241 || cjp_get(m->state,8)!=41 || !m->send ||
                    m->send->lease.inline_started || !m->send->lease.receiver ||
                    !PyGen_CheckExact(m->send->lease.receiver)) return cjr_block(r,CJR_BAD_CHILD);
            if (r->current==r->slot_count-1) return cjr_block(r,CJR_ARENA_EXHAUSTED);
            if (r->epoch==UINT64_MAX) return cjr_block(r,CJR_COUNT_OVERFLOW);
            uint64_t next=r->current+1;
            CJRetainingNode312 *child=r->slots[next].node;
            uint64_t prepared=cjr_prepare_node(r,next,(PyGenObject *)m->send->lease.receiver,NULL,NULL,0);
            if (prepared) return cjr_block(r,prepared);
            child->parent_index=r->current;
            if (cjb_send_bind_child(m,&child->body)) return cjr_block(r,CJR_BAD_CHILD);
            if (!cjp_increment(&r->child_prepares)) return cjr_block(r,CJR_COUNT_OVERFLOW);
            r->current=next;
            if (next>r->highest_used) r->highest_used=next;
            continue;
        }
        if (m->permission==CJB_DONE) {
            if (!r->current) return cjr_close_root(r);
            if (n->parent_index!=r->current-1) return cjr_block(r,CJR_BAD_CHILD);
            CJBodyMachine312 *parent=&r->slots[n->parent_index].node->body;
            /* Child originals precede the actual single-owner transfer. */
            cjr_bytes(r,8,r->current,n,sizeof(*n));
            if (cjb_send_resume_child(parent) || parent->permission!=CJB_READY)
                return cjr_block(r,CJR_BAD_RETURN);
            if (cjr_release_child(r)) return CJR_BLOCKED;
            continue;
        }
        return cjr_block(r,m->permission==CJB_PORT_REQUIRED ? CJR_MISSING_PORT : CJR_UNCLOSED_LINK);
    }
}
#endif
