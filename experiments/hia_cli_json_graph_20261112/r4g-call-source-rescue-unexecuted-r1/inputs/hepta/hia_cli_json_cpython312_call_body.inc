/* Actual-stack mechanical leaves for the HIA post-dispatch CALL plan.
 *
 * PRIVATE, UNCOMPILED SOURCE WIP.  No Python entry and no dispatcher route
 * invokes these functions yet.  The initial adaptive/instrumented CALL
 * dispatch and the inlined child owner remain separate unfinished ports.
 * They must be implemented before this post-dispatch component can be
 * activated.  In particular, a normal Python function is not evaluated by
 * adding an _PyEval_EvalFrameDefault C entry, and no old JSON body fallback
 * is provided.  The original 17 CLI / 46 trace population is unchanged.
 *
 * Included after CJBodyMachine312, cjb_observe_owner and the body ledger.
 * HIA owns method normalization selection, normal/foreign call selection,
 * callable-first/arguments-forward cleanup, stack COMMIT and result move.
 * This file provides only the indicated C primitive at each selected leaf.
 * No operand array, Python handle table or protective argument reference is
 * constructed.  A fixed C lease must remain alive on every partial error.
 *
 * The original stack top remains active through every foreign callback in
 * normalization, binding, vectorcall and DECREF.  The physical slots may
 * already contain transferred or released references; pending_stack_owner
 * therefore remains this lease until HIA requests COMMIT.  Existing UNPACK
 * quarantine's top-1 predicate is NOT valid for this arbitrary CALL tail;
 * that owner transfer remains blocked until a typed outer quarantine exists.
 *
 * Derived ordering: PSF-licensed CPython v3.12.14 generated_cases.c.h CALL,
 * and its original ceval.c _PyEvalFramePushAndInit argument-binding helper.
 */

#if PY_VERSION_HEX == 0x030c0ef0
#define CJC_MAGIC UINT64_C(0x31304c43494c4348) /* HCLICL01 */
#define CJC_STATE_BYTES 512
enum {
    CJC_NEW=0, CJC_ACTIVE=1, CJC_COMMITTED=2, CJC_DONE=3,
    CJC_BLOCKED=4, CJC_INLINE_REQUIRED=5
};
enum {
    CJC_BEGIN=1, CJC_NORMALIZE_METHOD=2, CJC_CALL_FACTS=3,
    CJC_VECTORCALL=4, CJC_DROP_CALLABLE=5, CJC_DROP_ARGUMENT=6,
    CJC_COMMIT=7, CJC_BIND_PYTHON=8, CJC_INLINE_CHILD=9,
    CJC_MOVE_RESULT=10
};

typedef struct {
    uint64_t magic, permission;
    CJBodyMachine312 *parent;           /* enclosing owner strongly retains */
    CJContext *ctx;
    PyThreadState *thread;
    PyGenObject *gen;
    _PyInterpreterFrame *frame;
    CJActiveFrame312 *owner;            /* exact original identity, not TLS */
    _Py_CODEUNIT *instruction;
    PyObject *kwnames;                  /* borrowed from original co_consts */
    PyObject *callable;                 /* actual original stack owner */
    PyObject **args;                    /* points into actual localsplus */
    PyObject *result;                   /* owned vectorcall result */
    _PyInterpreterFrame *child;         /* thread frame owns transferred args */
    int original_top, base, arg_base, oparg, total_args, kwcount, is_method;
    uint64_t begun, normalized, facts, route;
    uint64_t exact_function, default_evaluator, standard_vectorcall;
    uint64_t vector_attempted, vector_returned;
    uint64_t binder_attempted, binder_returned;
    uint64_t callable_released, arguments_released, stack_committed, result_moved;
    uint64_t issued, consumed, leaf_attempts, leaf_returns;
    uint64_t owner_lost, failure_reason;
    uintptr_t last_released;            /* address only after DECREF */
    int last_observed_top;
} CJCallLease312;

/* No current TLS pointer is walked until it equals our retained owner.
 * This component is only valid while the parent is still current.  The
 * later inlined-child driver needs its own suspended-parent predicates. */
static int cjc_live(CJCallLease312 *c) {
    if (!PyGILState_Check()) return 0;
    if (!c || c->magic != CJC_MAGIC || !c->parent || !c->ctx ||
            !c->owner || c->owner_lost ||
            PyThreadState_Get() != c->thread || cj312_active_frame != c->owner)
        return 0;
    if (!cjb_owner_current(c->parent) ||
            c->owner != &c->parent->activation.active || c->owner->frame != c->frame ||
            c->frame != (_PyInterpreterFrame *)c->gen->gi_iframe ||
            c->frame->prev_instr != c->instruction ||
            c->frame->stacktop != -1 || c->gen->gi_frame_state != FRAME_EXECUTING)
        return 0;
    if (c->stack_committed) {
        if (c->owner->top != c->base || c->owner->pending_stack_owner ||
                c->owner->pending_stack_base) return 0;
    }
    else if (c->owner->top != c->original_top ||
            (c->begun ? (c->owner->pending_stack_owner != c ||
                          c->owner->pending_stack_base != c->base)
                      : c->owner->pending_stack_owner != NULL)) return 0;
    c->last_observed_top = c->owner->top;
    return 1;
}

static uint64_t cjc_block(CJCallLease312 *c, uint64_t reason) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    c->failure_reason = reason;
    c->permission = CJC_BLOCKED;
    if (!cjc_live(c)) c->owner_lost = 1;
    /* Neither stale stack slots nor an actual child frame are guessed
     * clear. A blocked lease is retained, not a safe Python-return path. */
    return CJ_REFUSAL;
}

/* This initializer is intentionally not called by port240 yet. Its caller
 * must have completed the original adaptive/instrumented dispatch, and
 * must supply the remaining normal-CALL continuation at this same opcode.
 * No such admission ticket is currently manufactured by the WIP driver.
 */
static uint64_t cjc_prepare(CJCallLease312 *c, CJBodyMachine312 *m,
                              unsigned char *state) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!c || !m || !state || m->magic != CJB_MAGIC ||
            m->permission != CJB_EFFECT_READY || !cjb_observe_owner(m) ||
            m->activation.permission != CJA_ACTIVE ||
            m->activation.active.pending_stack_owner || m->ctx->raised ||
            m->ctx->slot || m->ctx->external || PyErr_Occurred() ||
            cjp_get(m->state, 8) != 43 || cjp_get(m->state, 64) != 240 ||
            cjp_get(m->state, 72) != (uintptr_t)m->gen ||
            cjp_get(m->state, 80) != cjp_get(m->state, 208) ||
            cjp_get(m->state, 88) != cjp_get(m->state, 216) ||
            cjp_get(m->state, 96) != cjp_get(m->state, 144) || cjp_get(m->state, 104))
        return CJ_REFUSAL;
    if (m->trace_capacity > UINT64_MAX / CJB_TRACE_BYTES ||
            (m->unpack && m->unpack->trace_capacity > UINT64_MAX / CJU_TRACE_BYTES))
        return CJ_REFUSAL;
    uint64_t addresses[9] = {(uintptr_t)c, (uintptr_t)state, (uintptr_t)m,
        (uintptr_t)m->ctx, (uintptr_t)m->state, (uintptr_t)m->packet,
        (uintptr_t)m->trace, (uintptr_t)m->unpack,
        m->unpack ? (uintptr_t)m->unpack->trace : 0};
    uint64_t sizes[9] = {sizeof(*c), CJC_STATE_BYTES, sizeof(*m), sizeof(*m->ctx),
        CJB_STATE_BYTES, m->packet_bytes, m->trace_capacity*CJB_TRACE_BYTES,
        m->unpack ? sizeof(*m->unpack) : 0,
        m->unpack ? m->unpack->trace_capacity*CJU_TRACE_BYTES : 0};
    for (unsigned i = 0; i < 9; i++) {
        if (!sizes[i]) continue;
        if (!cjp_span(addresses[i], sizes[i])) return CJ_REFUSAL;
        for (unsigned j = 0; j < i; j++)
            if (sizes[j] && !cjp_disjoint(addresses[i], sizes[i], addresses[j], sizes[j]))
                return CJ_REFUSAL;
    }
    for (size_t i = 0; i < sizeof(*c); i++)
        if (((const unsigned char *)c)[i]) return CJ_REFUSAL;
    for (unsigned i = 0; i < CJC_STATE_BYTES; i++) if (state[i]) return CJ_REFUSAL;
    uint64_t pc = cjp_get(m->state, 144), nargs = cjp_get(m->state, 208);
    CJActiveFrame312 *owner = &m->activation.active;
    if (pc >= m->units || nargs > INT_MAX ||
            cjp_get(m->packet, 64 + pc*64) != CALL ||
            cjp_get(m->packet, 64 + pc*64 + 8) != nargs ||
            cjp_get(m->packet, 64 + pc*64 + 56) != 1 ||
            owner->top < (int)m->locals ||
            (uint64_t)(owner->top - (int)m->locals) < nargs + 2)
        return CJ_REFUSAL;
    _PyInterpreterFrame *frame = m->activation.frame;
    if (frame->prev_instr != _PyCode_CODE(m->code) + pc) return CJ_REFUSAL;
    PyObject *kw = (PyObject *)(uintptr_t)cjp_get(m->state, 216);
    if (kw && (!PyTuple_CheckExact(kw) || PyTuple_GET_SIZE(kw) > INT_MAX))
        return CJ_REFUSAL;
    const int top = owner->top, n = (int)nargs, base = top - n - 2;
    PyObject *method = frame->localsplus[base];
    PyObject *callable = method ? method : frame->localsplus[base + 1];
    int total = n + (method != NULL), arg_base = top - total;
    int kwcount = kw ? (int)PyTuple_GET_SIZE(kw) : 0;
    if (!callable || kwcount > total) return CJ_REFUSAL;
    for (int i = arg_base; i < top; i++)
        if (!frame->localsplus[i]) return CJ_REFUSAL;
    c->magic = CJC_MAGIC; c->parent = m; c->ctx = m->ctx; c->thread = m->thread;
    c->gen = m->gen; c->frame = frame; c->owner = owner;
    c->instruction = frame->prev_instr; c->kwnames = kw; c->callable = callable;
    c->args = frame->localsplus + arg_base; c->original_top = top; c->base = base;
    c->arg_base = arg_base; c->oparg = n; c->total_args = total; c->kwcount = kwcount;
    c->is_method = method != NULL; c->last_observed_top = top;
    cjp_put(state, 0, CJC_MAGIC);
    cjp_put(state, 120, (uintptr_t)m->gen); cjp_put(state, 128, (uintptr_t)m->code);
    cjp_put(state, 136, pc); cjp_put(state, 144, nargs);
    cjp_put(state, 152, (uintptr_t)kw);
    return 0;
}

static void cjc_metadata(CJCallLease312 *c, uint64_t answer[8]) {
    answer[0] = (uint64_t)c->original_top;
    answer[1] = (uint64_t)c->base;
    answer[2] = (uintptr_t)c->callable;
    answer[3] = (uint64_t)c->arg_base;
    answer[4] = (uint64_t)c->total_args;
    answer[5] = (uint64_t)c->kwcount;
    answer[6] = (uint64_t)c->is_method;
    answer[7] = Py_IS_TYPE(c->callable, &PyMethod_Type);
}

/* One selected raw primitive. The independent C ledger consumes sequence
 * BEFORE installing E and before the primitive can invoke a callback.
 * The original current error is restored only for that C transaction and
 * then captured/cleared before HIA. Handled-exception state is untouched.
 */
static uint64_t cjc_leaf(CJCallLease312 *c, unsigned char *state) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!c || c->magic != CJC_MAGIC || !state ||
            !cjc_live(c) || PyErr_Occurred() || c->ctx->external || c->ctx->slot ||
            c->permission == CJC_DONE || c->permission == CJC_BLOCKED ||
            cjp_get(state, 0) != CJC_MAGIC || cjp_get(state, 112) ||
            cjp_get(state, 120) != (uintptr_t)c->gen ||
            cjp_get(state, 128) != (uintptr_t)c->frame->f_code ||
            cjp_get(state, 136) != (uint64_t)(c->instruction - _PyCode_CODE(c->frame->f_code)) ||
            cjp_get(state, 144) != (uint64_t)c->oparg ||
            cjp_get(state, 152) != (uintptr_t)c->kwnames ||
            cjp_get(state, 48) != (uintptr_t)c->ctx->raised ||
            cjp_get(state, 56) != (uintptr_t)c->result ||
            cjp_get(state, 24) != 1 || c->issued != c->consumed ||
            c->issued == UINT64_MAX || cjp_get(state, 16) != c->issued + 1 ||
            cjp_get(state, 32) != c->consumed)
        return c && c->magic == CJC_MAGIC ? cjc_block(c, 1) : CJ_REFUSAL;
    uint64_t op = cjp_get(state, 64), arg = cjp_get(state, 72);
    if (op < CJC_BEGIN || op > CJC_MOVE_RESULT ||
            (op != CJC_DROP_ARGUMENT && op != CJC_INLINE_CHILD && arg))
        return cjc_block(c, 2);
    for (unsigned at = 80; at < 112; at += 8)
        if (cjp_get(state, at)) return cjc_block(c, 2);
    if (op != CJC_BEGIN && !c->begun) return cjc_block(c, 3);
    switch (op) {
    case CJC_BEGIN:
        if (c->begun || c->permission != CJC_NEW || c->ctx->raised) return cjc_block(c, 4);
        break;
    case CJC_NORMALIZE_METHOD:
        if (c->normalized || c->facts || c->is_method || c->ctx->raised ||
                !Py_IS_TYPE(c->callable, &PyMethod_Type)) return cjc_block(c, 5);
        break;
    case CJC_CALL_FACTS:
        if (c->facts || c->ctx->raised || c->route || c->result || c->child)
            return cjc_block(c, 6);
        break;
    case CJC_VECTORCALL:
        if (!c->facts || c->route ||
                (c->exact_function && c->default_evaluator && c->standard_vectorcall) ||
                c->vector_attempted || c->binder_attempted ||
                c->ctx->raised || c->result || c->child) return cjc_block(c, 7);
        break;
    case CJC_DROP_CALLABLE:
        if (c->route != 2 || !c->vector_returned || c->callable_released ||
                c->arguments_released || c->stack_committed) return cjc_block(c, 8);
        break;
    case CJC_DROP_ARGUMENT:
        if (c->route != 2 || !c->callable_released || c->stack_committed ||
                arg != c->arguments_released || arg >= (uint64_t)c->total_args)
            return cjc_block(c, 9);
        break;
    case CJC_BIND_PYTHON:
        if (!c->facts || c->route || !c->exact_function ||
                !c->default_evaluator || !c->standard_vectorcall ||
                c->binder_attempted || c->vector_attempted ||
                c->ctx->raised || c->result || c->child ||
                !Py_IS_TYPE(c->callable, &PyFunction_Type) ||
                c->thread->interp->eval_frame != NULL ||
                ((PyFunctionObject *)c->callable)->vectorcall != _PyFunction_Vectorcall)
            return cjc_block(c, 10);
        break;
    case CJC_COMMIT:
        if (c->stack_committed ||
                (c->route == 1 ? (!c->binder_returned ||
                                  (!!c->child == !!c->ctx->raised)) :
                  (c->route != 2 || !c->vector_returned || !c->callable_released ||
                   c->arguments_released != (uint64_t)c->total_args)))
            return cjc_block(c, 11);
        break;
    case CJC_INLINE_CHILD:
        if (c->route != 1 || !c->stack_committed || !c->child ||
                arg != (uintptr_t)c->child || c->ctx->raised || c->result)
            return cjc_block(c, 12);
        /* No fake ACK, no _PyEval_EvalFrameDefault fallback, no ordinary
         * Python return. The actual bound child frame and parent remain
         * retained for the missing inlined driver. This effect is not yet
         * consumed and cannot cause binding to be executed a second time. */
        c->permission = CJC_INLINE_REQUIRED;
        return CJC_INLINE_REQUIRED;
    case CJC_MOVE_RESULT:
        if (c->route != 2 || !c->stack_committed || c->result_moved || c->child)
            return cjc_block(c, 13);
        break;
    }

    if (!cjp_increment(&c->leaf_attempts)) return cjc_block(c, 14);
    c->issued = cjp_get(state, 16); c->consumed = c->issued;
    cjp_put(state, 32, c->consumed); cjp_put(state, 40, op);
    uint64_t answer[8] = {0};
    PyObject *incoming = c->ctx->raised; c->ctx->raised = NULL;
    PyErr_SetRaisedException(incoming);
    switch (op) {
    case CJC_BEGIN:
        c->begun = 1; c->permission = CJC_ACTIVE;
        c->owner->pending_stack_owner = c;
        c->owner->pending_stack_base = c->base;
        cjc_metadata(c, answer);
        break;
    case CJC_NORMALIZE_METHOD: {
        PyObject *old_method = c->callable;
        PyObject *self = ((PyMethodObject *)old_method)->im_self;
        PyObject *function = ((PyMethodObject *)old_method)->im_func;
        c->normalized = 1; c->is_method = 1;
        c->args--; c->arg_base--; c->total_args++;
        c->args[0] = Py_NewRef(self);
        c->args[-1] = Py_NewRef(function);
        /* Save the ownership move before the original method DECREF can
         * invoke its weakref callbacks. No extra callable owner is added. */
        c->callable = function;
        c->last_released = (uintptr_t)old_method;
        Py_DECREF(old_method);
        break;
    }
    case CJC_CALL_FACTS:
        c->facts = 1;
        c->exact_function = Py_IS_TYPE(c->callable, &PyFunction_Type);
        c->default_evaluator = c->thread->interp->eval_frame == NULL;
        c->standard_vectorcall = c->exact_function &&
            ((PyFunctionObject *)c->callable)->vectorcall == _PyFunction_Vectorcall;
        answer[0] = c->exact_function;
        answer[1] = c->default_evaluator;
        answer[2] = c->standard_vectorcall;
        break;
    case CJC_VECTORCALL:
        c->route = 2; c->vector_attempted = 1;
        c->result = PyObject_Vectorcall(c->callable, c->args,
            (size_t)(c->total_args - c->kwcount) | PY_VECTORCALL_ARGUMENTS_OFFSET,
            c->kwnames);
        c->vector_returned = 1;
        break;
    case CJC_DROP_CALLABLE: {
        PyObject *value = c->callable;
        c->callable_released = 1; c->last_released = (uintptr_t)value;
        c->callable = NULL;
        Py_DECREF(value);
        answer[0] = c->callable_released;
        break;
    }
    case CJC_DROP_ARGUMENT: {
        PyObject *value = c->args[arg];
        /* Do not zero the actual operand slot: original CALL leaves its
         * released bytes there until the final stack shrink/result store. */
        c->arguments_released++; c->last_released = (uintptr_t)value;
        Py_DECREF(value);
        answer[0] = c->arguments_released;
        break;
    }
    case CJC_BIND_PYTHON: {
        PyFunctionObject *function = (PyFunctionObject *)c->callable;
        int flags = ((PyCodeObject *)function->func_code)->co_flags;
        PyObject *locals = flags & CO_OPTIMIZED ? NULL : Py_NewRef(function->func_globals);
        c->route = 1; c->binder_attempted = 1;
        c->child = cj312_push_and_init(c->thread, function, locals, c->args,
            (size_t)(c->total_args - c->kwcount), c->kwnames);
        c->binder_returned = 1;
        /* Original binder consumes the argument/function owners on its
         * selected path; the caller has no subsequent DECREF loop. */
        c->callable = NULL;
        answer[0] = (uintptr_t)c->child;
        break;
    }
    case CJC_COMMIT:
        c->owner->top = c->base;
        c->owner->pending_stack_owner = NULL;
        c->owner->pending_stack_base = 0;
        c->stack_committed = 1; c->permission = CJC_COMMITTED;
        answer[0] = (uint64_t)c->base;
        break;
    case CJC_MOVE_RESULT:
        c->ctx->slot = c->result; c->result = NULL;
        c->result_moved = 1; c->permission = CJC_DONE;
        break;
    }
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (PyThreadState_Get() != c->thread) return cjc_block(c, 15);
    c->ctx->raised = PyErr_GetRaisedException();
    if (!cjp_increment(&c->leaf_returns)) return cjc_block(c, 16);
    if (!cjc_live(c)) return cjc_block(c, 17);
    if (op == CJC_NORMALIZE_METHOD) cjc_metadata(c, answer);
    for (unsigned i = 0; i < 8; i++) cjp_put(state, 256 + i*8, answer[i]);
    cjp_put(state, 48, (uintptr_t)c->ctx->raised);
    cjp_put(state, 56, (uintptr_t)(c->result ? c->result : c->ctx->slot));
    return 0;
}
#endif
