/* One-shot C transport for the HIA-selected 3.12 generator lifetime plan.
 *
 * This file is included after the raw leaves in hia_cli_json_cpython.c.
 * It does not choose an instruction, a JSON branch, an exception handler,
 * a reference-release order or a fallback body.  The admitted HIA image
 * makes those decisions.  Between its entry and its named leaves there
 * are only C integer/pointer copies and writes to already-owned buffers.
 * In particular, no Python list append, exception handler, ctypes callback
 * or Python bytecode instruction is inserted between two release leaves.
 *
 * This implements the terminal/yield component only.  The complete body
 * driver, its CALL/SEND/UNPACK ports, evaluator entry and monitoring are
 * separate work.  It never claims that this pump supplies those mechanisms.
 * The caller retains the actual generator, parent, raw context, mapped HIA
 * image and all buffers for the whole invocation and for any quarantine.
 *
 * Source-only development: not compiled, installed or executed.
 */

#define CJ_PUMP_MAGIC UINT64_C(0x31504d50494c4348) /* HCLIPMP1 */
#define CJ_LIFETIME_MAGIC UINT64_C(0x31464c47494c4348) /* HCLIGLF1 */
#define CJ_PUMP_WORDS 64
#define CJ_PUMP_TRACE_WORDS 32
#define CJ_PUMP_TRACE_BYTES (CJ_PUMP_TRACE_WORDS * 8)

enum {
    CJP_MAGIC=0, CJP_PROFILE=1, CJP_COMPONENT=2, CJP_PERMISSION=3,
    CJP_CONTEXT=4, CJP_CONTEXT_BYTES=5, CJP_ENTRY=6,
    CJP_STATE=7, CJP_STATE_BYTES=8,
    CJP_GENERATOR=9, CJP_CODE=10, CJP_PARENT=11,
    CJP_INSTRUCTION=12, CJP_MODE=13, CJP_TRACEBACK_HANDLED=14,
    CJP_TRACE=15, CJP_TRACE_CAPACITY=16, CJP_TRACE_STRIDE=17,
    CJP_RESULT_STATUS=20, CJP_NATIVE_ATTEMPTS=21, CJP_NATIVE_RETURNS=22,
    CJP_EFFECT_ATTEMPTS=23, CJP_EFFECT_RETURNS=24,
    CJP_LAST_ISSUED=25, CJP_LAST_CONSUMED=26,
    CJP_TRACE_WRITTEN=27, CJP_TRACE_DROPPED=28,
    CJP_BLOCKED_OPERATION=29, CJP_REFUSAL_REASON=30,
    CJP_RESULT_ADDRESS=31, CJP_ERROR_ADDRESS=32, CJP_EXTERNAL_ADDRESS=33,
    CJP_STATE_BEFORE=34, CJP_STATE_AFTER=35,
    CJP_TOP_BEFORE=36, CJP_TOP_AFTER=37,
    CJP_LAST_NATIVE_RETURN=38, CJP_LAST_LEAF_RETURN=39,
    CJP_LAST_LEAF_MARKER=40, CJP_UNEXPECTED_PYERR=41
};

enum {
    CJP_NEW=0, CJP_RUNNING=1, CJP_CLOSED=2, CJP_QUARANTINED=3
};

enum {
    CJP_BAD_SHAPE=1, CJP_BAD_CONTEXT=2, CJP_BAD_FRAME=3,
    CJP_BAD_STATE=4, CJP_BAD_NATIVE_STATUS=5, CJP_BAD_PERMISSION=6,
    CJP_BAD_LEAF=7, CJP_BAD_TERMINAL=8, CJP_UNEXPECTED_ERROR=9,
    CJP_COUNTER_EXHAUSTED=10
};

typedef uint32_t (*CJHiaEntry)(const void *, uint64_t,
                              void *, uint64_t, void *, uint64_t);

static uint64_t cjp_get(const unsigned char *state, size_t at) {
    uint64_t value;
    memcpy(&value, state + at, sizeof(value));
    return value;
}

static void cjp_put(unsigned char *state, size_t at, uint64_t value) {
    memcpy(state + at, &value, sizeof(value));
}

static int cjp_span(uint64_t address, uint64_t bytes) {
    return address && bytes && address <= UINT64_MAX - bytes;
}

static int cjp_disjoint(uint64_t a, uint64_t an, uint64_t b, uint64_t bn) {
    return a + an <= b || b + bn <= a;
}

#if PY_VERSION_HEX == 0x030c0ef0
static void cjp_observe(uint64_t *request, CJContext *ctx, PyGenObject *gen) {
    request[CJP_RESULT_ADDRESS] = (uintptr_t)ctx->slot;
    request[CJP_ERROR_ADDRESS] = (uintptr_t)ctx->raised;
    request[CJP_EXTERNAL_ADDRESS] = (uintptr_t)ctx->external;
    request[CJP_STATE_AFTER] = (uint64_t)(int64_t)gen->gi_frame_state;
    _PyInterpreterFrame *frame = (_PyInterpreterFrame *)gen->gi_iframe;
    /* stacktop remains a plain storage word even after ClearExceptCode.
     * Do not dereference locals, f_funcobj or frame_obj after that clear. */
    request[CJP_TOP_AFTER] = (uint64_t)(int64_t)frame->stacktop;
}

static uint64_t cjp_refuse(uint64_t *request, CJContext *ctx,
                           PyGenObject *gen, uint64_t reason) {
    /* No release or replay on a partial/unknown transaction.  Owners which
     * a leaf committed remain in their original context or actual frame.
     * An unexpected C error is separately acquired, never substituted for
     * the original business exception already owned by ctx->raised. */
    if (PyErr_Occurred()) {
        request[CJP_UNEXPECTED_PYERR] = 1;
        if (!ctx->external) ctx->external = PyErr_GetRaisedException();
        else {
            /* A second unexpected error is another explicit owned audit
             * word.  It must remain quarantined with this request.  This
             * branch is private-protocol failure, not an error fallback. */
            request[42] = (uintptr_t)PyErr_GetRaisedException();
        }
    }
    cjp_observe(request, ctx, gen);
    request[CJP_REFUSAL_REASON] = reason;
    request[CJP_PERMISSION] = CJP_QUARANTINED;
    return CJ_REFUSAL;
}

static int cjp_increment(uint64_t *value) {
    if (*value == UINT64_MAX) return 0;
    (*value)++;
    return 1;
}

static void cjp_trace(uint64_t *request, const unsigned char *state,
                      uint64_t kind, uint64_t returned,
                      const CJFrame *effect, CJContext *ctx,
                      PyGenObject *gen) {
    uint64_t index = request[CJP_TRACE_WRITTEN];
    if (index >= request[CJP_TRACE_CAPACITY]) {
        /* A finite observer's full trace can be incomplete without imposing
         * a new limit on the JSON value or stopping its lifetime plan.
         * Qualification must reject any nonzero omitted-record count. */
        if (request[CJP_TRACE_DROPPED] != UINT64_MAX)
            request[CJP_TRACE_DROPPED]++;
        return;
    }
    uint64_t row[CJ_PUMP_TRACE_WORDS] = {0};
    row[0] = kind;                    /* 1 HIA return, 2 leaf return */
    row[1] = returned;
    row[2] = cjp_get(state, 8);        /* HIA following phase */
    row[3] = cjp_get(state, 16);       /* HIA sequence */
    row[4] = cjp_get(state, 64);       /* HIA operation */
    for (unsigned i = 0; i < 5; i++) row[5+i] = cjp_get(state, 72+i*8);
    if (effect) {
        row[10] = effect->marker;
        row[11] = effect->raised;
        row[12] = effect->captured;
        for (unsigned i = 0; i < 8; i++) row[13+i] = effect->result[i];
    }
    row[21] = (uintptr_t)ctx->slot;
    row[22] = (uintptr_t)ctx->raised;
    row[23] = (uintptr_t)ctx->external;
    row[24] = (uint64_t)(int64_t)gen->gi_frame_state;
    row[25] = (uint64_t)(int64_t)((_PyInterpreterFrame *)gen->gi_iframe)->stacktop;
    row[26] = request[CJP_NATIVE_RETURNS];
    row[27] = request[CJP_EFFECT_RETURNS];
    row[28] = request[CJP_LAST_CONSUMED];
    unsigned char *target = (unsigned char *)(uintptr_t)request[CJP_TRACE];
    memcpy(target + index * CJ_PUMP_TRACE_BYTES, row, sizeof(row));
    request[CJP_TRACE_WRITTEN] = index + 1;
}

static int cjp_lifetime_shape(const uint64_t *request,
                              const unsigned char *state) {
    return cjp_get(state, 0) == CJ_LIFETIME_MAGIC &&
        cjp_get(state, 120) == request[CJP_GENERATOR] &&
        cjp_get(state, 128) == request[CJP_CODE] &&
        cjp_get(state, 136) == request[CJP_PARENT] &&
        cjp_get(state, 144) == request[CJP_INSTRUCTION] &&
        cjp_get(state, 152) == request[CJP_MODE] &&
        cjp_get(state, 176) == request[CJP_TRACEBACK_HANDLED];
}

static int cjp_lifetime_effect(const uint64_t *request,
                               const unsigned char *state, CJFrame *frame,
                               int *framed) {
    uint64_t operation = cjp_get(state, 64), phase = cjp_get(state, 8);
    frame->abi = CJ_ABI;
    frame->context = request[CJP_CONTEXT];
    frame->op = operation;
    frame->a = cjp_get(state, 72);
    frame->b = cjp_get(state, 80);
    frame->c = cjp_get(state, 88);
    frame->d = cjp_get(state, 96);
    frame->e = cjp_get(state, 104);
    *framed = 0;
    if (frame->c || frame->d || frame->e) return 0;
    switch (operation) {
        case CJ_PY312_FRAME_INFO:
            return phase == 2 && frame->a == request[CJP_GENERATOR] && !frame->b;
        case CJ_IDENTITIES:
            return phase == 10 && !frame->a && !frame->b;
        case CJ_PY312_FRAME_TRACEBACK:
            *framed = 1;
            return phase == 20 && frame->a == request[CJP_GENERATOR] &&
                frame->b == request[CJP_INSTRUCTION];
        case CJ_PY312_STACK_POP:
            *framed = 1;
            return phase == 21 && frame->a == request[CJP_GENERATOR] && !frame->b;
        case CJ_DROP_SLOT:
            *framed = phase == 22;
            return (phase == 22 || phase == 31) && !frame->a && !frame->b;
        case CJ_PY312_FRAME_CLEAR:
            return phase == 30 && frame->a == request[CJP_GENERATOR] &&
                frame->b == request[CJP_PARENT];
        case CJ_PY312_CLEAR_EXC_STATE:
            return phase == 32 && frame->a == request[CJP_GENERATOR] && !frame->b;
        case CJ_PY312_SUSPEND_AT:
            return phase == 50 && frame->a == request[CJP_GENERATOR] &&
                frame->b == request[CJP_INSTRUCTION];
        default:
            return 0;
    }
}
#endif

/* Exactly64 uint64 words.  Outputs20..63 must initially be zero; the caller
 * must preserve this whole request, raw context and actual generator on a
 * refusal.  A successful C return is only protocol closure; word20 separately
 * records the ordinary exhausted/error/yielded status0/1/3. */
uint64_t hia_cli_json_py312_lifetime_run(uint64_t *request, uint64_t words) {
#if PY_VERSION_HEX == 0x030c0ef0
    if (!request || words != CJ_PUMP_WORDS || !PyGILState_Check() ||
            PyErr_Occurred() || !cj312_runtime.ready ||
            request[CJP_MAGIC] != CJ_PUMP_MAGIC || request[CJP_PROFILE] != 31214 ||
            request[CJP_COMPONENT] != 1 || request[CJP_PERMISSION] != CJP_NEW)
        return CJ_REFUSAL;
    for (unsigned i = 18; i < CJ_PUMP_WORDS; i++)
        if (request[i]) return CJ_REFUSAL;
    if (request[CJP_CONTEXT_BYTES] != sizeof(CJContext) ||
            request[CJP_STATE_BYTES] != 512 || !request[CJP_ENTRY] ||
            !request[CJP_GENERATOR] || !request[CJP_CODE] ||
            request[CJP_MODE] > 2 || request[CJP_TRACEBACK_HANDLED] > 1 ||
            (request[CJP_MODE] != 1 && request[CJP_TRACEBACK_HANDLED]) ||
            request[CJP_TRACE_STRIDE] != CJ_PUMP_TRACE_BYTES ||
            request[CJP_TRACE_CAPACITY] > UINT64_MAX / CJ_PUMP_TRACE_BYTES ||
            (!request[CJP_TRACE_CAPACITY] && request[CJP_TRACE]))
        return CJ_REFUSAL;
    uint64_t addresses[4] = {(uintptr_t)request, request[CJP_CONTEXT],
                            request[CJP_STATE], request[CJP_TRACE]};
    uint64_t lengths[4] = {CJ_PUMP_WORDS * 8, sizeof(CJContext), 512,
                          request[CJP_TRACE_CAPACITY] * CJ_PUMP_TRACE_BYTES};
    unsigned spans = request[CJP_TRACE_CAPACITY] ? 4 : 3;
    for (unsigned i = 0; i < spans; i++) {
        if (!cjp_span(addresses[i], lengths[i])) return CJ_REFUSAL;
        for (unsigned j = 0; j < i; j++)
            if (!cjp_disjoint(addresses[i], lengths[i], addresses[j], lengths[j]))
                return CJ_REFUSAL;
    }
    CJContext *ctx = (CJContext *)(uintptr_t)request[CJP_CONTEXT];
    PyGenObject *gen = (PyGenObject *)(uintptr_t)request[CJP_GENERATOR];
    unsigned char *state = (unsigned char *)(uintptr_t)request[CJP_STATE];
    if (ctx->magic != CJ_CTX || ctx->profile != 31214 || ctx->external ||
            !PyGen_CheckExact(gen)) return CJ_REFUSAL;
    _PyInterpreterFrame *owned = (_PyInterpreterFrame *)gen->gi_iframe;
    if ((gen->gi_frame_state != FRAME_CREATED && gen->gi_frame_state != FRAME_SUSPENDED) ||
            gen->gi_exc_state.previous_item || owned->previous ||
            owned->f_code != (PyCodeObject *)(uintptr_t)request[CJP_CODE] ||
            request[CJP_INSTRUCTION] >= (uint64_t)Py_SIZE(owned->f_code) ||
            owned->stacktop < owned->f_code->co_nlocalsplus ||
            owned->stacktop > owned->f_code->co_nlocalsplus + owned->f_code->co_stacksize)
        return CJ_REFUSAL;
    unsigned char fresh[512] = {0};
    cjp_put(fresh, 0, CJ_LIFETIME_MAGIC);
    cjp_put(fresh, 120, request[CJP_GENERATOR]);
    cjp_put(fresh, 128, request[CJP_CODE]);
    cjp_put(fresh, 136, request[CJP_PARENT]);
    cjp_put(fresh, 144, request[CJP_INSTRUCTION]);
    cjp_put(fresh, 152, request[CJP_MODE]);
    cjp_put(fresh, 176, request[CJP_TRACEBACK_HANDLED]);
    if (memcmp(state, fresh, sizeof(fresh))) return CJ_REFUSAL;
    if (request[CJP_MODE] == 1 ? (ctx->slot || !ctx->raised)
                                : (!ctx->slot || ctx->raised))
        return CJ_REFUSAL;

    request[CJP_PERMISSION] = CJP_RUNNING;  /* consume before the first call */
    request[CJP_STATE_BEFORE] = (uint64_t)(int64_t)gen->gi_frame_state;
    request[CJP_TOP_BEFORE] = (uint64_t)(int64_t)owned->stacktop;
    CJHiaEntry entry = (CJHiaEntry)(uintptr_t)request[CJP_ENTRY];
    for (;;) {
        cjp_put(state, 48, (uintptr_t)ctx->raised);
        cjp_put(state, 320, (uintptr_t)ctx->slot);
        if (!cjp_increment(&request[CJP_NATIVE_ATTEMPTS]))
            return cjp_refuse(request, ctx, gen, CJP_COUNTER_EXHAUSTED);
        uint32_t status = entry(NULL, 0, NULL, 0, state, 512);
        request[CJP_NATIVE_RETURNS]++;
        request[CJP_LAST_NATIVE_RETURN] = status;
        cjp_trace(request, state, 1, status, NULL, ctx, gen);
        if (PyErr_Occurred())
            return cjp_refuse(request, ctx, gen, CJP_UNEXPECTED_ERROR);
        if (!cjp_lifetime_shape(request, state))
            return cjp_refuse(request, ctx, gen, CJP_BAD_STATE);
        if (status == 2) {
            uint64_t sequence = cjp_get(state, 16), operation = cjp_get(state, 64);
            request[CJP_BLOCKED_OPERATION] = operation;
            if (cjp_get(state, 24) != 1 ||
                    request[CJP_LAST_ISSUED] == UINT64_MAX ||
                    sequence != request[CJP_LAST_ISSUED] + 1 ||
                    sequence <= request[CJP_LAST_CONSUMED])
                return cjp_refuse(request, ctx, gen, CJP_BAD_PERMISSION);
            request[CJP_LAST_ISSUED] = sequence;
            CJFrame effect = {0};
            int framed = 0;
            if (!cjp_lifetime_effect(request, state, &effect, &framed))
                return cjp_refuse(request, ctx, gen, CJP_BAD_LEAF);
            request[CJP_LAST_CONSUMED] = sequence; /* never retry a leaf */
            if (!cjp_increment(&request[CJP_EFFECT_ATTEMPTS]))
                return cjp_refuse(request, ctx, gen, CJP_COUNTER_EXHAUSTED);
            uint64_t returned = framed ? hia_cli_json_leaf_in_generator(
                &effect, (PyObject *)gen,
                (PyObject *)(uintptr_t)request[CJP_PARENT], request[CJP_INSTRUCTION])
                : hia_cli_json_leaf(&effect);
            request[CJP_EFFECT_RETURNS]++;
            request[CJP_LAST_LEAF_RETURN] = returned;
            request[CJP_LAST_LEAF_MARKER] = effect.marker;
            cjp_trace(request, state, 2, returned, &effect, ctx, gen);
            if (PyErr_Occurred())
                return cjp_refuse(request, ctx, gen, CJP_UNEXPECTED_ERROR);
            if (returned != 0 || effect.marker != 2 ||
                    effect.captured != (uintptr_t)ctx->raised)
                return cjp_refuse(request, ctx, gen, CJP_BAD_LEAF);
            for (unsigned i = 0; i < 8; i++)
                cjp_put(state, 256 + i * 8, effect.result[i]);
            cjp_put(state, 48, (uintptr_t)ctx->raised);
            cjp_put(state, 320, (uintptr_t)ctx->slot);
            cjp_put(state, 32, sequence);
            cjp_put(state, 40, operation);
            request[CJP_BLOCKED_OPERATION] = 0;
            continue;
        }
        if (status != 0 && status != 1 && status != 3)
            return cjp_refuse(request, ctx, gen, CJP_BAD_NATIVE_STATUS);
        if (cjp_get(state, 24) != 0 || cjp_get(state, 112) != (uint64_t)status + 1 ||
                (status == 0 && (request[CJP_MODE] != 0 || ctx->slot || ctx->raised)) ||
                (status == 1 && (request[CJP_MODE] != 1 || ctx->slot || !ctx->raised)) ||
                (status == 3 && (request[CJP_MODE] != 2 || !ctx->slot || ctx->raised)) ||
                gen->gi_exc_state.previous_item || owned->previous ||
                (status == 3 ? gen->gi_frame_state != FRAME_SUSPENDED
                             : gen->gi_frame_state != FRAME_CLEARED))
            return cjp_refuse(request, ctx, gen, CJP_BAD_TERMINAL);
        cjp_observe(request, ctx, gen);
        request[CJP_RESULT_STATUS] = status;
        request[CJP_PERMISSION] = CJP_CLOSED;
        return 0;
    }
#else
    (void)request;
    (void)words;
    return CJ_REFUSAL;
#endif
}
