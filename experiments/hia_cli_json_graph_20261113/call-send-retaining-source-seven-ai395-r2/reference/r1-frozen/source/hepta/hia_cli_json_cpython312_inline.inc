/* Mechanical DISPATCH_INLINED owner for an admitted original JSON generator.
 *
 * Source WIP, no exported activation or executable qualification. HIA owns
 * selection of SEND versus FOR_ITER and the child's bytecode/exit plan.
 * These leaves transfer the ORIGINAL owned stack argument, interpreter links
 * and Python-recursion accounting. They do not add an EvalFrame C entry or
 * a protective generator/value reference, and never run a retained body.
 *
 * An ordinary bound PyFunction thread-frame and its RETURN_GENERATOR
 * prologue are a distinct unfinished port; do not cast it to this lease.
 * The complete retaining driver must keep every parent/child activation,
 * context, generator, packet and image alive until a real structural close.
 * A broken link is not repaired and does not grant a safe Python return.
 */

#define CJI_MAGIC UINT64_C(0x31304e49494c4348) /* HCLIIN01 */
enum { CJI_SEND=1, CJI_FOR_ITER=2 };

struct CJInlineActivation312 {
    uint64_t magic, kind, attached, entered, returned, blocked;
    CJEvalActivation312 *child;          /* same object as caller's run */
    CJEvalActivation312 *parent;         /* original suspended parent */
    CJEvalActivation312 *root;           /* actual existing C-stack entry */
    PyThreadState *thread;
    _PyCFrame *shared;
    CJActiveFrame312 *parent_owner;
    _PyInterpreterFrame *parent_frame;
    _PyInterpreterFrame *parent_previous;
    PyGenObject *gen;                    /* borrowed from parent receiver */
    _PyInterpreterFrame *frame;
    _Py_CODEUNIT *parent_instruction;
    _Py_CODEUNIT *parent_following;
    _PyErr_StackItem *parent_exc;
    PyObject *argument;                  /* original SEND stack owner */
    int parent_top_before, parent_top_after, child_top_before;
    uint16_t return_offset;              /* original frame field conversion */
    uint64_t selected_exit;
    uintptr_t last_result;               /* address only, not another owner */
    uint64_t resume_pc;                  /* original next_instr after child */
    uint64_t failure_pc;                 /* parent next_instr-1 on error */
};

static _PyCFrame *cji_cframe(const CJEvalActivation312 *run) {
    return run->inlined->shared;
}

/* Walk only the retained, already constructed activation chain. Every
 * suspended parent has a published real stack pointer; only the current
 * child uses the -1 sentinel. There is no user-controlled depth bound. */
static int cji_parent_chain(const CJInlineActivation312 *i) {
    const CJEvalActivation312 *p = i->parent;
    while (p) {
        if (p->quarantine_failure || p->permission != CJA_ACTIVE ||
                p->tstate != i->thread || !p->py_entered || !p->exc_linked ||
                !p->stack_live || p->clear_counter_entered || p->clear_frame_returned ||
                p->active.frame != p->frame || p->active.pending_stack_owner ||
                p->active.pending_stack_base || p->active.previous != p->previous_active ||
                p->frame != (_PyInterpreterFrame *)p->gen->gi_iframe ||
                p->gen->gi_frame_state != FRAME_EXECUTING ||
                p->gen->gi_exc_state.previous_item != p->previous_exc ||
                p->frame->stacktop != p->active.top ||
                p->active.top < p->frame->f_code->co_nlocalsplus ||
                p->active.top > p->frame->f_code->co_nlocalsplus + p->frame->f_code->co_stacksize)
            return 0;
        if (p->inlined) {
            const CJInlineActivation312 *j = p->inlined;
            if (j->magic != CJI_MAGIC || !j->entered || j->returned || j->blocked ||
                    j->child != p || j->root != i->root || j->shared != i->shared ||
                    j->thread != i->thread || !j->parent ||
                    j->parent_frame != j->parent->frame ||
                    j->parent_owner != &j->parent->active ||
                    p->c_entered || p->frame->previous != j->parent_frame ||
                    p->previous_active != j->parent_owner ||
                    p->previous_exc != &j->parent->gen->gi_exc_state)
                return 0;
            p = j->parent;
        }
        else {
            if (p != i->root || !p->c_entered || i->shared != &p->cframe ||
                    p->frame->previous != &p->entry_frame ||
                    p->cframe.previous != p->previous_cframe ||
                    p->previous_cframe->current_frame != p->previous_frame ||
                    p->entry_frame.previous != p->previous_frame)
                return 0;
            p = NULL;
        }
    }
    return 1;
}

static int cji_links(const CJEvalActivation312 *run) {
    if (!PyGILState_Check()) return 0;
    const CJInlineActivation312 *i = run->inlined;
    if (!i || i->magic != CJI_MAGIC || i->child != run || !i->entered ||
            i->returned || i->blocked || run->quarantine_failure ||
            PyThreadState_Get() != i->thread || run->tstate != i->thread ||
            i->thread->cframe != i->shared || i->shared->current_frame != run->frame ||
            run->c_entered || !run->py_entered || !run->exc_linked ||
            run->gen != i->gen || run->frame != i->frame ||
            run->frame->previous != i->parent_frame ||
            i->parent_frame->previous != i->parent_previous ||
            i->parent_frame->prev_instr != i->parent_following - 1 ||
            i->parent_frame->return_offset != i->return_offset ||
            run->previous_frame != i->parent_frame || run->previous_cframe != i->shared ||
            run->previous_exc != i->parent_exc || run->previous_active != i->parent_owner ||
            i->thread->exc_info != &i->gen->gi_exc_state ||
            i->gen->gi_exc_state.previous_item != i->parent_exc ||
            i->gen->gi_frame_state != FRAME_EXECUTING ||
            cj312_active_frame != (run->stack_live ? &run->active : i->parent_owner) ||
            (run->stack_live && (run->frame->stacktop != -1 ||
                run->active.frame != run->frame || run->active.previous != i->parent_owner ||
                run->active.top < run->frame->f_code->co_nlocalsplus ||
                run->active.top > run->frame->f_code->co_nlocalsplus + run->frame->f_code->co_stacksize)))
        return 0;
    return cji_parent_chain(i);
}

/* Attach before entry, without transferring any Python reference. The
 * future route must also bind/admit the original code packet and dynamic
 * adaptive/instrumented dispatch before asking this leaf to enter. */
static uint64_t cji_attach(CJInlineActivation312 *i, CJEvalActivation312 *child,
                            CJEvalActivation312 *parent, PyGenObject *gen,
                            uint64_t kind, uint64_t following, uint64_t oparg) {
    if (!PyGILState_Check()) return CJ_REFUSAL;
    if (!i || !child || !parent || child == parent || !gen ||
            child->permission != CJA_NEW || child->inlined ||
            parent->permission != CJA_ACTIVE || !parent->stack_live || !cja_links(parent) ||
            parent->active.pending_stack_owner || parent->active.pending_stack_base ||
            !PyGen_CheckExact(gen) || (kind != CJI_SEND && kind != CJI_FOR_ITER) ||
            PyErr_Occurred() || parent->tstate->interp->eval_frame != NULL)
        return CJ_REFUSAL;
    for (size_t n = 0; n < sizeof(*i); n++) if (((unsigned char *)i)[n]) return CJ_REFUSAL;
    _PyInterpreterFrame *frame = (_PyInterpreterFrame *)gen->gi_iframe;
    _PyInterpreterFrame *caller = parent->frame;
    int top = parent->active.top, count = kind == CJI_SEND ? 2 : 1;
    if (frame == caller || frame->previous || gen->gi_exc_state.previous_item ||
            frame->owner != FRAME_OWNED_BY_GENERATOR ||
            (gen->gi_frame_state != FRAME_CREATED && gen->gi_frame_state != FRAME_SUSPENDED) ||
            frame->stacktop < frame->f_code->co_nlocalsplus ||
            frame->stacktop >= frame->f_code->co_nlocalsplus + frame->f_code->co_stacksize ||
            top - caller->f_code->co_nlocalsplus < count ||
            caller->localsplus[top-count] != (PyObject *)gen ||
            !following || following > (uint64_t)Py_SIZE(caller->f_code))
        return CJ_REFUSAL;
    /* Validate the exact encoded offset conversion before retaining it.
     * This mirrors the uint16_t frame field, not a new JSON input cap. */
    uint16_t offset = (uint16_t)oparg;
    if (following > UINT64_MAX-offset || following+offset >= (uint64_t)Py_SIZE(caller->f_code))
        return CJ_REFUSAL;
    PyObject *argument = kind == CJI_SEND ? caller->localsplus[top-1] : Py_None;
    if (!argument) return CJ_REFUSAL;
    CJEvalActivation312 *root = parent;
    while (root->inlined) {
        if (root == child || !root->inlined->parent) return CJ_REFUSAL;
        root = root->inlined->parent;
    }
    if (root == child || !root->c_entered) return CJ_REFUSAL;
    i->magic = CJI_MAGIC; i->kind = kind; i->attached = 1;
    i->child = child; i->parent = parent; i->root = root;
    i->thread = parent->tstate; i->shared = cja_current_cframe(parent);
    i->parent_owner = &parent->active; i->parent_frame = caller;
    i->parent_previous = caller->previous; i->gen = gen; i->frame = frame;
    i->parent_instruction = caller->prev_instr;
    i->parent_following = _PyCode_CODE(caller->f_code) + following;
    i->parent_exc = parent->tstate->exc_info; i->argument = argument;
    i->parent_top_before = top; i->parent_top_after = top - (kind == CJI_SEND);
    i->child_top_before = frame->stacktop; i->return_offset = offset;
    child->inlined = i;
    return 0;
}

static uint64_t cji_enter(CJEvalActivation312 *run, CJContext *ctx,
                           PyGenObject *gen, PyObject *send_argument, int throwflag) {
    if (!PyGILState_Check()) return CJ_REFUSAL;
    CJInlineActivation312 *i = run->inlined;
    if (!i || i->magic != CJI_MAGIC || !i->attached || i->child != run ||
            i->entered || i->returned || i->blocked || run->permission != CJA_NEW ||
            !ctx || ctx->magic != CJ_CTX || ctx->profile != 31214 ||
            ctx->raised || ctx->slot || ctx->external || PyErr_Occurred() ||
            gen != i->gen || send_argument || throwflag ||
            PyThreadState_Get() != i->thread || !cja_links(i->parent) ||
            i->parent_owner->pending_stack_owner || i->parent_owner->pending_stack_base ||
            i->parent_owner->top != i->parent_top_before ||
            i->parent_frame->prev_instr != i->parent_instruction ||
            i->frame->stacktop != i->child_top_before || i->frame->previous ||
            gen->gi_exc_state.previous_item ||
            (gen->gi_frame_state != FRAME_CREATED && gen->gi_frame_state != FRAME_SUSPENDED) ||
            (i->kind == CJI_SEND && i->parent_frame->localsplus[i->parent_top_before-1] != i->argument))
        return CJ_REFUSAL;
    i->entered = 1; run->permission = CJA_ACTIVE;
    run->tstate = i->thread; run->gen = gen; run->frame = i->frame;
    run->previous_cframe = i->shared; run->previous_frame = i->parent_frame;
    run->previous_active = i->parent_owner; run->previous_exc = i->parent_exc;
    run->initial_state = gen->gi_frame_state;
    run->send_was_null = 0; run->throwflag = 0;
    run->preflight_send_status = PYGEN_ERROR;

    /* Exact original SEND/FOR_ITER_GEN transition order. SEND moves the
     * existing owned v; FOR_ITER_GEN writes immortal None without INCREF.
     * No function capable of invoking Python occurs before recursion entry. */
    i->parent_frame->return_offset = i->return_offset;
    i->parent_owner->top = i->parent_top_after;
    i->frame->localsplus[i->frame->stacktop++] = i->argument;
    gen->gi_frame_state = FRAME_EXECUTING;
    gen->gi_exc_state.previous_item = i->parent_exc;
    i->thread->exc_info = &gen->gi_exc_state; run->exc_linked = 1;
    i->parent_frame->stacktop = i->parent_top_after;
    i->parent_frame->prev_instr = i->parent_following - 1;
    i->frame->previous = i->parent_frame;
    i->shared->current_frame = i->frame;

    /* DISPATCH_INLINED goes to start_frame: Python recursion only. No
     * trampoline, C-recursion decrement or _PyEval_EvalFrameDefault call. */
    run->py_entered = 1;
    int recursive_error = cja_enter_recursive_py(i->thread);
    if (!PyGILState_Check()) { i->blocked = 1; return CJ_REFUSAL; }
    if (PyThreadState_Get() != i->thread || !cji_links(run)) {
        i->blocked = 1; run->quarantine_failure = 1;
        if (PyThreadState_Get() == i->thread) ctx->raised = PyErr_GetRaisedException();
        return CJ_REFUSAL;
    }
    if (recursive_error) {
        run->permission = CJA_ENTRY_ERROR;
        ctx->raised = PyErr_GetRaisedException();
        return 0;
    }
    run->original_instruction = (uint64_t)(int64_t)_PyInterpreterFrame_LASTI(i->frame);
    cja_start_operand_register(run);
    ctx->raised = PyErr_GetRaisedException();
    return 0;
}

/* A raw owned result is kept in ctx->slot across clear, just like the
 * original evaluator local retval. The integrating port must push it into
 * the resumed parent before any Python callback or another body step. */
static uint64_t cji_finish(CJEvalActivation312 *run, CJContext *ctx,
                            uint64_t selected_exit) {
    if (!PyGILState_Check()) return CJ_REFUSAL;
    CJInlineActivation312 *i = run->inlined;
    int error = selected_exit == CJA_ERROR || selected_exit == CJA_EARLY_ERROR;
    if (!i || i->magic != CJI_MAGIC || !ctx || ctx->external || PyErr_Occurred() ||
            i->returned || i->blocked || run->quarantine_failure ||
            run->clear_counter_entered || run->clear_frame_returned ||
            selected_exit > CJA_EARLY_ERROR ||
            (selected_exit == CJA_EARLY_ERROR ? run->permission != CJA_ENTRY_ERROR : run->permission != CJA_ACTIVE) ||
            !cji_links(run) || (run->stack_live && run->active.pending_stack_owner) ||
            (error ? (!ctx->raised || ctx->slot) : (ctx->raised || !ctx->slot)))
        return CJ_REFUSAL;
    _PyInterpreterFrame *frame = i->frame;
    int top = run->stack_live ? run->active.top : frame->stacktop;
    if (top < frame->f_code->co_nlocalsplus ||
            top > frame->f_code->co_nlocalsplus + frame->f_code->co_stacksize ||
            ((selected_exit == CJA_RETURN || selected_exit == CJA_ERROR) &&
             top != frame->f_code->co_nlocalsplus)) return CJ_REFUSAL;

    run->permission = CJA_FINISHED; i->selected_exit = selected_exit;
    i->last_result = (uintptr_t)ctx->slot;
    PyObject *incoming = ctx->raised; ctx->raised = NULL;
    PyErr_SetRaisedException(incoming);
    if (selected_exit == CJA_YIELD) {
        i->gen->gi_frame_state = FRAME_SUSPENDED;
        frame->stacktop = top;
        i->thread->exc_info = i->gen->gi_exc_state.previous_item;
        i->gen->gi_exc_state.previous_item = NULL; run->exc_linked = 0;
        i->thread->py_recursion_remaining++; run->py_entered = 0;
        i->shared->current_frame = frame->previous;
        frame->previous = NULL;
    }
    else {
        frame->stacktop = top;
        i->thread->py_recursion_remaining++; run->py_entered = 0;
        i->shared->current_frame = frame->previous;
        i->gen->gi_frame_state = FRAME_CLEARED;
        i->thread->exc_info = i->gen->gi_exc_state.previous_item;
        i->gen->gi_exc_state.previous_item = NULL; run->exc_linked = 0;
        run->clear_counter_entered = 1;
        i->thread->c_recursion_remaining--;
        cj312_runtime.clear_frame(frame);
        run->clear_frame_returned = 1;
        if (!PyGILState_Check()) { i->blocked = 1; run->quarantine_failure = 1; return CJ_REFUSAL; }
        if (PyThreadState_Get() != i->thread) { i->blocked = 1; run->quarantine_failure = 1; return CJ_REFUSAL; }
        if (i->thread->cframe != i->shared || i->shared->current_frame != i->parent_frame ||
                i->parent_frame->previous != i->parent_previous ||
                i->parent_frame->prev_instr != i->parent_following-1 ||
                i->parent_frame->return_offset != i->return_offset ||
                frame->previous != i->parent_frame || i->gen->gi_frame_state != FRAME_CLEARED ||
                i->thread->exc_info != i->parent_exc || i->gen->gi_exc_state.previous_item ||
                cj312_active_frame != (run->stack_live ? &run->active : i->parent_owner) ||
                (run->stack_live && run->active.previous != i->parent_owner) || !cji_parent_chain(i)) {
            i->blocked = 1; run->quarantine_failure = 1;
            ctx->raised = PyErr_GetRaisedException();
            return CJ_REFUSAL;
        }
        i->thread->c_recursion_remaining++; run->clear_counter_entered = 0;
        frame->previous = NULL;
    }
    /* Return jumps by return_offset; YIELD resumes the following opcode;
     * exit_unwind resets return_offset and resumes with the same error. */
    if (error) i->parent_frame->return_offset = 0;
    else if (selected_exit == CJA_RETURN)
        i->parent_frame->prev_instr += i->parent_frame->return_offset;
    i->resume_pc = (uint64_t)(i->parent_frame->prev_instr + 1 - _PyCode_CODE(i->parent_frame->f_code));
    i->failure_pc = (uint64_t)(i->parent_following - 1 - _PyCode_CODE(i->parent_frame->f_code));
    if (run->stack_live) { cj312_active_frame = run->active.previous; run->stack_live = 0; }
    i->parent_owner->top = i->parent_frame->stacktop;
    i->parent_frame->stacktop = -1;
    i->returned = 1;
    ctx->raised = PyErr_GetRaisedException();
    return 0;
}
