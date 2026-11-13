/* Actual parent HIA port240 and its retained CALL/child ledgers.
 *
 * Private source only. No exported evaluator entry, generation or native
 * qualification accompanies this file. A CHILD_REQUIRED result remains
 * inside the retaining C driver: parent, child and every owner address
 * stay alive. It does not authorize a Python return while a frame is linked.
 *
 * The generic/instrumented CALL path is connected to its actual post-call
 * monitor/DECREF order, original specialized families and the admitted
 * original-generator prologue. Other Python function bodies retain an
 * explicit unclosed route, never evaluated through a new EvalFrame entry.
 */
#if PY_VERSION_HEX == 0x030c0ef0
struct CJBodyCall312 {
    uint64_t permission, stage, completed, native_attempts, native_returns;
    CJHiaEntry dispatch_entry, call_entry, fast_entry, prologue_entry;
    CJCallDispatch312 dispatch;
    CJCallLease312 lease;
    _Alignas(uint64_t) unsigned char state[1024];
    CJFastCall312 fast;
    CJCallPrologue312 prologue;
};

static uint64_t cjb_attach_call(CJBodyMachine312 *m, CJBodyCall312 *u,
                                 CJHiaEntry dispatch, CJHiaEntry call,
                                 CJHiaEntry fast, CJHiaEntry prologue) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!m || m->magic!=CJB_MAGIC || m->permission!=CJB_READY ||
            m->hia_attempts || m->activation_attempts || m->call || !u ||
            !dispatch || !call || !fast || !prologue || !cjb_observe_owner(m) ||
            m->trace_capacity>UINT64_MAX/CJB_TRACE_BYTES) return CJ_REFUSAL;
    uint64_t addresses[6]={(uintptr_t)m,(uintptr_t)m->ctx,(uintptr_t)m->packet,
        (uintptr_t)m->state,(uintptr_t)m->trace,(uintptr_t)u};
    uint64_t sizes[6]={sizeof(*m),sizeof(*m->ctx),m->packet_bytes,CJB_STATE_BYTES,
        m->trace_capacity*CJB_TRACE_BYTES,sizeof(*u)};
    for (unsigned i=0;i<6;i++) {
        if (!sizes[i]) continue;
        if (!cjp_span(addresses[i],sizes[i])) return CJ_REFUSAL;
        for (unsigned j=0;j<i;j++) if (sizes[j] && !cjp_disjoint(addresses[i],sizes[i],addresses[j],sizes[j]))
            return CJ_REFUSAL;
    }
    for (size_t n=0;n<sizeof(*u);n++) if (((unsigned char *)u)[n]) return CJ_REFUSAL;
    u->dispatch_entry=dispatch; u->call_entry=call; u->fast_entry=fast; u->prologue_entry=prologue;
    m->call=u;
    return 0;
}

static int cjb_call_state_bound(CJBodyCall312 *u) {
    CJCallLease312 *c=&u->lease;
    return cjp_get(u->state,0)==CJC_MAGIC &&
        cjp_get(u->state,120)==(uintptr_t)c->gen &&
        cjp_get(u->state,128)==(uintptr_t)c->frame->f_code &&
        cjp_get(u->state,136)==(uint64_t)(c->instruction-_PyCode_CODE(c->frame->f_code)) &&
        cjp_get(u->state,144)==(uint64_t)c->oparg &&
        cjp_get(u->state,152)==(uintptr_t)c->kwnames &&
        cjp_get(u->state,240)==c->instrumented &&
        cjp_get(u->state,48)==(uintptr_t)c->ctx->raised &&
        cjp_get(u->state,56)==(uintptr_t)(c->result ? c->result : c->ctx->slot);
}

static uint64_t cjb_call_finish(CJBodyMachine312 *m, uint64_t status,
                                  uint64_t preflight_error) {
    CJBodyCall312 *u=m->call; CJCallLease312 *c=&u->lease;
    if (!cjb_observe_owner(m) || m->ctx->external ||
            m->activation.active.pending_stack_owner ||
            m->activation.active.pending_stack_base || PyErr_Occurred() || (status>1 && status!=4) ||
            u->completed==UINT64_MAX || u->permission!=1 ||
            (status==1 ? (!m->ctx->raised || m->ctx->slot) :
             status==4 ? (m->ctx->raised || m->ctx->slot) : (m->ctx->raised || !m->ctx->slot)))
        return cjb_refuse(m,CJB_BAD_EXIT);
    uint64_t answer[8]={0,0,preflight_error ? 0 : c->route,0,0,0,0,0};
    if (!preflight_error) {
        if (!cjc_live(c) || !cjb_call_state_bound(u) ||
                c->issued!=c->consumed || c->leaf_attempts!=c->leaf_returns ||
                c->result || c->child || !c->stack_committed || c->owner_lost ||
                cjp_get(u->state,24) || cjp_get(u->state,112)!=(status==4 ? 4 : status ? 2 : 1) ||
                (c->route!=1 && c->route!=2) ||
                (c->route==1 && c->child_completed &&
                    (u->prologue.permission!=CJT_DONE || !u->prologue.popped ||
                     u->prologue.clear_counter || u->prologue.in_transaction ||
                     u->prologue.unexpected_error || !cjt_live(&u->prologue))))
            return cjb_refuse(m,CJB_BAD_EXIT);
        if (c->fast_mode) {
            CJFastCall312 *f=&u->fast;
            if (f->magic!=CJF_MAGIC || f->call!=c || f->state!=u->state ||
                    f->in_transaction || f->recursive_entered || f->deoptimized ||
                    !cjf_bound(f) || f->permission==CJF_BLOCKED ||
                    (status==4 && (f->mode!=CALL_NO_KW_LIST_APPEND || !f->append_consumed ||
                        !f->self_released || c->committed_top!=c->base ||
                        cjp_get(u->state,576)!=(uint64_t)(c->instruction-_PyCode_CODE(m->code))+5)))
                return cjb_refuse(m,CJB_BAD_EXIT);
            f->permission=CJF_DONE;
            answer[2]=status==4 ? 3 : cjp_get(u->state,552) ? 2 : 1;
            if (status==4) answer[5]=cjp_get(u->state,576);
            cjb_trace_child(m,25,f,sizeof(*f)/8);
        }
        if (c->child_completed) {
            answer[3]=c->child_following-1; answer[4]=c->child_following-1;
            answer[7]=1;
        }
        c->permission=CJC_DONE;
        cjb_trace_child(m,17,u->state,sizeof(u->state)/8);
        cjb_trace_child(m,18,c,sizeof(*c)/8);
    }
    else if (u->dispatch.permission!=CJD_DONE || u->dispatch.result_status!=1 ||
            u->stage!=1 || c->magic || !u->dispatch.monitor_returned ||
            u->dispatch.claimed || !cjd_live(&u->dispatch))
        return cjb_refuse(m,CJB_BAD_EXIT);
    u->permission=2; u->completed++;
    cjb_reply(m,answer);
    return cjb_complete(m,0);
}

static uint64_t cjb_call_continue(CJBodyMachine312 *m) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!m || m->magic!=CJB_MAGIC || m->permission!=CJB_EFFECT_READY || !m->call)
        return CJ_REFUSAL;
    CJBodyCall312 *u=m->call; CJCallLease312 *c=&u->lease;
    if (u->permission!=1 || !u->call_entry || !u->fast_entry || !u->dispatch_entry ||
            !cjb_observe_owner(m) || m->ctx->external || PyErr_Occurred())
        return cjb_refuse(m,CJB_BAD_INPUT);
dispatch_again:
    if (u->stage==1) {
        uint64_t status=cjd_run(&u->dispatch);
        if (status==1) return cjb_call_finish(m,1,1);
        if (status!=0 && status!=3) return cjb_refuse(m,CJB_BAD_REPLY);
        uint64_t prepared=cjc_prepare(c,m,u->state,&u->dispatch);
        if (prepared) return cjb_refuse(m,CJB_BAD_INPUT);
        if (status==3) {
            if (cjf_prepare(&u->fast,c,u->state)) return cjb_refuse(m,CJB_BAD_INPUT);
            u->stage=5;
        }
        else u->stage=2;
    }
    if (u->stage!=2 && u->stage!=5) return cjb_refuse(m,CJB_BAD_REPLY);
    for (;;) {
        if (!cjc_live(c) || !cjb_call_state_bound(u) || m->ctx->external ||
                PyErr_Occurred() || !cjp_increment(&u->native_attempts))
            return cjb_refuse(m,CJB_BAD_OWNER);
        unsigned char output=0;
        CJHiaEntry entry=u->stage==5 ? u->fast_entry : u->call_entry;
        uint64_t state_bytes=u->stage==5 ? 1024 : CJC_STATE_BYTES;
        uint32_t status=entry(m->packet,m->packet_bytes,&output,1,u->state,state_bytes);
        if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
        if (PyThreadState_Get()!=m->thread) return cjb_refuse(m,CJB_BAD_OWNER);
        if (!cjp_increment(&u->native_returns)) return cjb_refuse(m,CJB_COUNTER);
        cjb_trace_child(m,19,u->state,state_bytes/8);
        if (PyErr_Occurred() || !cjc_live(c) || !cjb_call_state_bound(u))
            return cjb_refuse(m,CJB_BAD_NATIVE);
        if (status==2) {
            uint64_t result=u->stage==5 ? cjf_leaf(&u->fast) : cjc_leaf(c,u->state);
            cjb_trace_child(m,20,u->state,state_bytes/8);
            if (result==CJC_INLINE_REQUIRED) {
                u->stage=3; m->permission=CJB_CHILD_REQUIRED;
                return CJB_CHILD_REQUIRED;
            }
            if (result) return cjb_refuse(m,CJB_BAD_REPLY);
            continue;
        }
        if (status==3 && u->stage==5) {
            if (!u->fast.deoptimized || c->ctx->raised || c->ctx->slot || c->result || c->child ||
                    c->begun || c->owner->pending_stack_owner || c->owner->top!=c->original_top ||
                    cjp_get(u->state,112)!=3 || cjp_get(u->state,24) ||
                    c->issued!=c->consumed || c->leaf_attempts!=c->leaf_returns)
                return cjb_refuse(m,CJB_BAD_EXIT);
            cjb_trace_child(m,26,c,sizeof(*c)/8);
            cjb_trace_child(m,27,&u->fast,sizeof(u->fast)/8);
            cjb_trace_child(m,28,&u->dispatch,sizeof(u->dispatch)/8);
            memset(c,0,sizeof(*c)); memset(&u->fast,0,sizeof(u->fast));
            memset(&u->dispatch,0,sizeof(u->dispatch)); memset(u->state,0,sizeof(u->state));
            if (cjd_prepare(&u->dispatch,m,u->dispatch_entry,1)) return cjb_refuse(m,CJB_BAD_INPUT);
            u->stage=1;
            goto dispatch_again; /* same parent effect, no C evaluator recursion */
        }
        if ((status!=0 && status!=1 && !(status==4 && u->stage==5)) || u->native_attempts!=u->native_returns)
            return cjb_refuse(m,CJB_BAD_NATIVE);
        return cjb_call_finish(m,status,0);
    }
}

static uint64_t cjb_call_240(CJBodyMachine312 *m) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    CJBodyCall312 *u=m->call;
    if (!u) { m->missing_port=240; m->permission=CJB_PORT_REQUIRED; return CJB_PORT_REQUIRED; }
    if (u->permission!=0 && u->permission!=2) return cjb_refuse(m,CJB_BAD_REPLY);
    if (u->permission==2) {
        if (!cjb_observe_owner(m) || m->ctx->slot || m->ctx->raised ||
                m->ctx->external || u->lease.child || u->lease.result ||
                u->lease.owner_lost || u->dispatch.unexpected_error ||
                u->prologue.result || u->prologue.unexpected_error ||
                m->activation.active.pending_stack_owner)
            return cjb_refuse(m,CJB_BAD_OWNER);
        /* The complete prior bytes are recorded before any reusable lease
         * reset. A finished child has already popped or moved its frame. */
        cjb_trace_child(m,21,&u->dispatch,sizeof(u->dispatch)/8);
        cjb_trace_child(m,22,&u->prologue,sizeof(u->prologue)/8);
        memset(&u->dispatch,0,sizeof(u->dispatch)); memset(&u->lease,0,sizeof(u->lease));
        memset(u->state,0,sizeof(u->state)); memset(&u->prologue,0,sizeof(u->prologue));
        memset(&u->fast,0,sizeof(u->fast));
    }
    uint64_t pc=cjp_get(m->state,144);
    if (pc>=m->units || !cjb_observe_owner(m)) return cjb_refuse(m,CJB_BAD_OWNER);
    m->activation.frame->prev_instr=_PyCode_CODE(m->code)+pc;
    uint64_t prepared=cjd_prepare(&u->dispatch,m,u->dispatch_entry,0);
    if (prepared) return cjb_refuse(m,CJB_BAD_INPUT);
    uint64_t consumed=cjb_consume(m,240);
    if (consumed) return consumed;
    u->permission=1; u->stage=1;
    return cjb_call_continue(m);
}

/* The retaining driver supplies an independently admitted complete packet
 * for this ACTUAL binder-produced code. Original generator construction
 * runs in the parent's existing C entry. A non-generator thread child
 * cannot be redirected here or evaluated through an extra EvalFrame call.
 */
static uint64_t cjb_call_original_generator(CJBodyMachine312 *m,
                              const unsigned char *packet, uint64_t packet_bytes) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!m || m->magic!=CJB_MAGIC || m->permission!=CJB_CHILD_REQUIRED || !m->call)
        return CJ_REFUSAL;
    CJBodyCall312 *u=m->call;
    if (u->permission!=1 || u->stage!=3 || !u->prologue_entry)
        return cjb_refuse(m,CJB_BAD_REPLY);
    uint64_t prepared=cjt_prepare(&u->prologue,&u->lease,u->state,
                                    u->prologue_entry,packet,packet_bytes);
    if (prepared) return prepared; /* pending actual thread owner stays live */
    uint64_t status=cjt_run(&u->prologue);
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (PyThreadState_Get()!=m->thread) return cjb_refuse(m,CJB_BAD_OWNER);
    cjb_trace_child(m,23,u->prologue.state,64);
    cjb_trace_child(m,24,&u->prologue,sizeof(u->prologue)/8);
    if (status>1 || u->prologue.permission!=CJT_DONE || !u->prologue.popped ||
            u->prologue.owner_lost || u->prologue.unexpected_error || !cjt_live(&u->prologue) ||
            !u->lease.child_completed || u->lease.child || !cjc_live(&u->lease))
        return cjb_refuse(m,CJB_BAD_EXIT);
    u->stage=u->lease.fast_mode ? 5 : 2; m->permission=CJB_EFFECT_READY;
    /* The owned result stays in ctx->slot. The following pure HIA/reply
     * path reaches parent STACK_PUSH_SLOT before any Python callback. */
    return cjb_call_continue(m);
}
#endif
