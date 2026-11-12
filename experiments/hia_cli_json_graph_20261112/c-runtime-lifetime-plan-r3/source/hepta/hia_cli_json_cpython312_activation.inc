/* Exact-3.12.14 evaluator-frame mechanics for the pending whole C driver.
 *
 * These helpers do not execute a JSON bytecode, select a JSON branch, call
 * a retained JSON body, choose a handler or walk a reference-release plan.
 * The HIA continuation selects ordinary unwind/pop/return/yield events.
 * This file supplies the actual interpreter links and the original runtime
 * recursion accounting while those events execute in the same C call.
 *
 * Normal unhandled errors reach finish only AFTER HIA has popped the real
 * operand stack in reverse order. A recursion failure at evaluator entry
 * is a distinct original exit_unwind route: it goes directly to the actual
 * frame clearer, with the still-live operands retained. It must not be
 * relabelled as an ordinary body error or sent through a handler table.
 *
 * Not compiled or executed. There is no public selector for this source.
 * The body CALL/SEND/UNPACK routing and instruction monitoring schedule are
 * still incomplete. The driver must not invoke an old JSON body as fallback.
 *
 * Runtime sequences derive from PSF-licensed v3.12.14 Objects/genobject.c,
 * Python/ceval.c and Python/generated_cases.c.h; retained full sources and
 * exact derivation records accompany this independent source checkpoint.
 */

#if PY_VERSION_HEX == 0x030c0ef0
#include "internal/pycore_ceval.h"
#include "internal/pycore_instruments.h"

typedef struct {
    int (*instrument)(PyCodeObject *, PyInterpreterState *);
    int (*instrumentation_arg)(PyThreadState *, int, _PyInterpreterFrame *,
                              _Py_CODEUNIT *, PyObject *);
    int (*handle_pending)(PyThreadState *);
    void (*chain_stack_item)(PyObject *);
    uint64_t admitted[6];
    int ready;
} CJRuntime312Control;
static CJRuntime312Control cj312_control_runtime;

/* A second, explicitly admitted table supplements the original twelve-word
 * runtime table. The caller must independently check each ELF symbol/span,
 * full mapped-image bytes and live instruction bytes, as for that table.
 * No Python callback or function outside that same mapped CPython executable
 * or shared runtime library is valid.
 * It is not sufficient merely to pass a nonzero address to this function. */
uint64_t hia_cli_json_bind_runtime_312_control(const uint64_t *words,
                                             uint64_t count) {
    if (!PyGILState_Check() || PyErr_Occurred() || !cj312_runtime.ready ||
            !words || count != 6 || words[0] != 31214 ||
            words[1] != (uintptr_t)_PyEval_EvalFrameDefault)
        return CJ_REFUSAL;
    if (cj312_control_runtime.ready)
        return memcmp(words, cj312_control_runtime.admitted,
                      sizeof(cj312_control_runtime.admitted)) == 0 ? 0 : CJ_REFUSAL;
    Dl_info reference;
    if (!dladdr((void *)(uintptr_t)words[1], &reference) || !reference.dli_fbase)
        return CJ_REFUSAL;
    for (unsigned i = 2; i < 6; i++) {
        Dl_info actual;
        if (!words[i] || !dladdr((void *)(uintptr_t)words[i], &actual) ||
                actual.dli_fbase != reference.dli_fbase)
            return CJ_REFUSAL;
    }
    cj312_control_runtime.instrument = (void *)(uintptr_t)words[2];
    cj312_control_runtime.instrumentation_arg = (void *)(uintptr_t)words[3];
    cj312_control_runtime.handle_pending = (void *)(uintptr_t)words[4];
    cj312_control_runtime.chain_stack_item = (void *)(uintptr_t)words[5];
    memcpy(cj312_control_runtime.admitted, words,
           sizeof(cj312_control_runtime.admitted));
    cj312_control_runtime.ready = 1;
    return 0;
}

/* The nine monitor helpers below retain their complete original bodies.
 * Only their local names and the one admitted private function address are
 * substituted. They neither replace a monitoring error with the saved one
 * nor add a synthetic handled-exception context around a callback. */
#include "hia_cli_json_cpython312_monitor.inc"

enum {
    CJA_NEW=0, CJA_ACTIVE=1, CJA_ENTRY_ERROR=2, CJA_FINISHED=3,
    CJA_PREFLIGHT_TERMINAL=4, CJA_QUARANTINED=5
};
enum {
    CJA_RETURN=0, CJA_ERROR=1, CJA_YIELD=2, CJA_EARLY_ERROR=3
};

typedef struct {
    uint64_t permission;
    PyThreadState *tstate;               /* borrowed runtime structures */
    PyGenObject *gen;
    _PyInterpreterFrame *frame;
    _PyCFrame cframe;                    /* MUST live for the whole C call */
    _PyInterpreterFrame entry_frame;     /* same real CSTACK trampoline */
    _PyCFrame *previous_cframe;
    _PyErr_StackItem *previous_exc;
    CJActiveFrame312 active;
    int c_entered;
    int py_entered;
    int exc_linked;
    int stack_live;
    int initial_state;
    int send_was_null;
    int throwflag;
    int preflight_send_status;
    uint64_t original_instruction;
} CJEvalActivation312;

static int cja_links(const CJEvalActivation312 *run) {
    return run->tstate->cframe == &run->cframe &&
        run->cframe.previous == run->previous_cframe &&
        run->cframe.current_frame == run->frame &&
        run->frame->previous == &run->entry_frame &&
        run->entry_frame.previous == run->previous_cframe->current_frame &&
        run->tstate->exc_info == &run->gen->gi_exc_state &&
        run->gen->gi_exc_state.previous_item == run->previous_exc &&
        run->gen->gi_frame_state == FRAME_EXECUTING &&
        (!run->stack_live || (run->frame->stacktop == -1 &&
            cj312_active_frame == &run->active &&
            run->active.frame == run->frame &&
            run->active.top >= run->frame->f_code->co_nlocalsplus &&
            run->active.top <= run->frame->f_code->co_nlocalsplus +
                               run->frame->f_code->co_stacksize));
}

/* Original _Py_EnterRecursivePy, using the already admitted actual check.
 * Never restore a saved counter value: a foreign callback can legitimately
 * change the recursion limit. The matching original increments must apply
 * to the resulting live counter, not erase that change. */
static int cja_enter_recursive_py(PyThreadState *tstate) {
    return (tstate->py_recursion_remaining-- <= 0) &&
        cj312_runtime.check_recursive_py(tstate);
}

static void cja_start_operand_register(CJEvalActivation312 *run) {
    run->active.frame = run->frame;
    run->active.top = run->frame->stacktop;
    run->active.previous = cj312_active_frame;
    cj312_active_frame = &run->active;
    /* _PyFrame_GetStackPointer has this exact visible sentinel. */
    run->frame->stacktop = -1;
    run->stack_live = 1;
}

/* This is the mechanical entry selected by HIA port243. send_argument is
 * borrowed, as in gen_send_ex2. It is not an extra owner/copy of the input.
 * HIA must distinguish ACTIVE, ENTRY_ERROR and PREFLIGHT_TERMINAL replies.
 * ENTRY_ERROR is not a request to enter the normal exception table.
 * On success the C caller keeps run alive until finish/quarantine returns;
 * returning to Python while it is ACTIVE would leave dangling C pointers.
 *
 * No partial/inexact generator is accepted as a JSON generator. This is
 * admission of the internal original-generator object, not a restriction
 * on the values/foreign objects being serialized inside its real frame. */
static uint64_t cja_enter(CJEvalActivation312 *run, CJContext *ctx,
                           PyGenObject *gen, PyObject *send_argument,
                           int throwflag) {
    if (!run || !ctx || !gen || !PyGILState_Check() || PyErr_Occurred() ||
            !cj312_runtime.ready || !cj312_control_runtime.ready ||
            run->permission != CJA_NEW || ctx->magic != CJ_CTX ||
            ctx->profile != 31214 || ctx->slot || ctx->external ||
            !PyGen_CheckExact(gen) || (throwflag != 0 && throwflag != 1) ||
            (!!ctx->raised != throwflag))
        return CJ_REFUSAL;
    PyThreadState *tstate = PyThreadState_Get();
    _PyInterpreterFrame *frame = (_PyInterpreterFrame *)gen->gi_iframe;
    /* eval_frame replacement requires its own admitted dispatch port.
     * That integration remains OPEN; this helper must not silently bypass
     * a user-installed evaluator or call the old JSON body as fallback. */
    if (tstate->interp->eval_frame != NULL || !tstate->cframe ||
            !tstate->interp->interpreter_trampoline)
        return CJ_REFUSAL;
    run->permission = CJA_ACTIVE; /* consume before any object operation */
    run->tstate = tstate;
    run->gen = gen;
    run->frame = frame;
    run->initial_state = gen->gi_frame_state;
    run->send_was_null = send_argument == NULL;
    run->throwflag = throwflag;
    run->preflight_send_status = PYGEN_ERROR;

    PyObject *incoming = ctx->raised;
    ctx->raised = NULL;
    PyErr_SetRaisedException(incoming);  /* steals, including NULL */
    if (gen->gi_frame_state == FRAME_CREATED && send_argument &&
            send_argument != Py_None) {
        PyErr_SetString(PyExc_TypeError,
            "can't send non-None value to a just-started generator");
        goto preflight_terminal;
    }
    if (gen->gi_frame_state == FRAME_EXECUTING) {
        PyErr_SetString(PyExc_ValueError, "generator already executing");
        goto preflight_terminal;
    }
    if (gen->gi_frame_state >= FRAME_COMPLETED) {
        if (send_argument && !throwflag) {
            ctx->slot = Py_NewRef(Py_None);
            run->preflight_send_status = PYGEN_RETURN;
        }
        goto preflight_terminal;
    }
    if (gen->gi_frame_state != FRAME_CREATED &&
            gen->gi_frame_state != FRAME_SUSPENDED)
        goto protocol_refusal;
    if (gen->gi_exc_state.previous_item || frame->previous ||
            frame->owner != FRAME_OWNED_BY_GENERATOR ||
            frame->stacktop < frame->f_code->co_nlocalsplus ||
            frame->stacktop >= frame->f_code->co_nlocalsplus + frame->f_code->co_stacksize)
        goto protocol_refusal;

    /* Original gen_send_ex2 acquires and pushes the argument before it
     * changes the handled-exception chain or generator execution state. */
    frame->localsplus[frame->stacktop++] =
        Py_NewRef(send_argument ? send_argument : Py_None);
    run->previous_exc = tstate->exc_info;
    gen->gi_exc_state.previous_item = run->previous_exc;
    tstate->exc_info = &gen->gi_exc_state;
    run->exc_linked = 1;
    if (throwflag) cj312_control_runtime.chain_stack_item(NULL);
    gen->gi_frame_state = FRAME_EXECUTING;

    /* Original _PyEval_EvalFrameDefault builds a real C-stack trampoline.
     * Its previous link is the actual pre-existing interpreter frame;
     * this is not a copied frame object or a Python transport wrapper. */
    run->previous_cframe = tstate->cframe;
    run->cframe.previous = run->previous_cframe;
    tstate->cframe = &run->cframe;
    run->entry_frame.f_code = tstate->interp->interpreter_trampoline;
    run->entry_frame.prev_instr =
        _PyCode_CODE(tstate->interp->interpreter_trampoline);
    run->entry_frame.stacktop = 0;
    run->entry_frame.owner = FRAME_OWNED_BY_CSTACK;
    run->entry_frame.return_offset = 0;
    run->entry_frame.previous = run->previous_cframe->current_frame;
    frame->previous = &run->entry_frame;
    run->cframe.current_frame = frame;
    run->c_entered = 1;
    tstate->c_recursion_remaining -= 1; /* PY_EVAL_C_STACK_UNITS - 1 */
    if (_Py_EnterRecursiveCallTstate(tstate, "")) {
        /* Keep these otherwise surprising decrements: the original error
         * exit then performs its ordinary leave/+2 accounting. */
        tstate->c_recursion_remaining--;
        tstate->py_recursion_remaining--;
        run->py_entered = 1;
        run->permission = CJA_ENTRY_ERROR;
        goto returned;
    }
    run->py_entered = 1;
    if (cja_enter_recursive_py(tstate)) {
        run->permission = CJA_ENTRY_ERROR;
        goto returned;
    }
    if (throwflag) {
        /* Original throw entry deliberately ignores Instrument's integer
         * return and then monitors the active original raised exception. */
        cj312_control_runtime.instrument(frame->f_code, tstate->interp);
        cja_monitor_throw(tstate, frame, frame->prev_instr);
    }
    run->original_instruction = (uint64_t)(int64_t)_PyInterpreterFrame_LASTI(frame);
    cja_start_operand_register(run);
returned:
    ctx->raised = PyErr_GetRaisedException();
    return 0;
preflight_terminal:
    run->permission = CJA_PREFLIGHT_TERMINAL;
    ctx->raised = PyErr_GetRaisedException();
    return 0;
protocol_refusal:
    ctx->raised = PyErr_GetRaisedException();
    run->permission = CJA_QUARANTINED;
    return CJ_REFUSAL;
}

/* HIA selects one of the four exit events. Runtime entry failure clears
 * the entire live frame directly. Ordinary unhandled failure may not use
 * that shortcut: its real operand stack must already be empty after the
 * HIA-selected reverse pop plan. The raw owned retval survives clear. */
static uint64_t cja_finish(CJEvalActivation312 *run, CJContext *ctx,
                            uint64_t selected_exit) {
    if (!run || !ctx || !PyGILState_Check() || PyErr_Occurred() ||
            ctx->external || selected_exit > CJA_EARLY_ERROR ||
            (selected_exit == CJA_EARLY_ERROR ? run->permission != CJA_ENTRY_ERROR
                                             : run->permission != CJA_ACTIVE) ||
            !run->c_entered || !run->py_entered || !run->exc_linked ||
            !cja_links(run))
        return CJ_REFUSAL;
    const int is_error = selected_exit == CJA_ERROR || selected_exit == CJA_EARLY_ERROR;
    if (is_error ? (ctx->slot || !ctx->raised) : (!ctx->slot || ctx->raised))
        return CJ_REFUSAL;
    _PyInterpreterFrame *frame = run->frame;
    int top = run->stack_live ? run->active.top : frame->stacktop;
    if ((selected_exit == CJA_RETURN || selected_exit == CJA_ERROR) &&
            top != frame->f_code->co_nlocalsplus)
        return CJ_REFUSAL;
    if (top < frame->f_code->co_nlocalsplus ||
            top > frame->f_code->co_nlocalsplus + frame->f_code->co_stacksize)
        return CJ_REFUSAL;

    run->permission = CJA_FINISHED; /* no second clear after a partial error */
    PyObject *incoming = ctx->raised;
    ctx->raised = NULL;
    PyErr_SetRaisedException(incoming);
    PyThreadState *tstate = run->tstate;
    PyGenObject *gen = run->gen;
    if (selected_exit == CJA_YIELD) {
        /* YIELD_VALUE cannot synthesize a new Python exception here. */
        gen->gi_frame_state = FRAME_SUSPENDED;
        frame->stacktop = top;
        tstate->exc_info = gen->gi_exc_state.previous_item;
        gen->gi_exc_state.previous_item = NULL;
        run->exc_linked = 0;
        tstate->py_recursion_remaining++;
        run->py_entered = 0;
        run->cframe.current_frame = frame->previous;
        frame->previous = NULL;
    }
    else {
        /* RETURN_* and exit_unwind unlink before clear_gen_frame. */
        frame->stacktop = top;
        tstate->py_recursion_remaining++;
        run->py_entered = 0;
        run->cframe.current_frame = frame->previous;
        gen->gi_frame_state = FRAME_CLEARED;
        tstate->exc_info = gen->gi_exc_state.previous_item;
        gen->gi_exc_state.previous_item = NULL;
        run->exc_linked = 0;
        tstate->c_recursion_remaining--;
        cj312_runtime.clear_frame(frame);
        tstate->c_recursion_remaining++;
        frame->previous = NULL;
    }
    if (run->stack_live) {
        cj312_active_frame = run->active.previous;
        run->stack_live = 0;
    }
    /* The trampoline's temporary push/pop has no calls or reference-count
     * operation between them; ctx->slot remains the single result owner. */
    run->entry_frame.return_offset = 0;
    tstate->cframe = run->previous_cframe;
    tstate->c_recursion_remaining += 2;
    run->c_entered = 0;
    ctx->raised = PyErr_GetRaisedException();
    return 0;
}

/* Private-protocol failure cannot return with pointers to our C-stack lease
 * in the interpreter. Restore only structural links and accounted counters,
 * retaining every object/reference in the raw context and actual frame.
 * The failed generator remains EXECUTING so nobody can resume its old body.
 * The caller MUST retain the generator and request as quarantined evidence.
 * This is not ordinary exception completion or a public serialization path. */
static void cja_quarantine(CJEvalActivation312 *run) {
    if (!run || !run->tstate) return;
    PyThreadState *tstate = run->tstate;
    if (run->stack_live) {
        run->frame->stacktop = run->active.top;
        cj312_active_frame = run->active.previous;
        run->stack_live = 0;
    }
    if (run->exc_linked) {
        tstate->exc_info = run->previous_exc;
        run->gen->gi_exc_state.previous_item = NULL;
        run->exc_linked = 0;
    }
    if (run->py_entered) {
        tstate->py_recursion_remaining++;
        run->py_entered = 0;
    }
    if (run->c_entered) {
        tstate->cframe = run->previous_cframe;
        tstate->c_recursion_remaining += 2;
        run->frame->previous = NULL;
        run->c_entered = 0;
    }
    run->permission = CJA_QUARANTINED;
}

#else
uint64_t hia_cli_json_bind_runtime_312_control(const uint64_t *words,
                                             uint64_t count) {
    (void)words;
    (void)count;
    return CJ_REFUSAL;
}
#endif
