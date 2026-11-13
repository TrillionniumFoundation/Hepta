/* HIA body transport and actual evaluator entry/exit, CPython 3.12.14.
 *
 * Private source WIP: none of the functions in this include is exported.
 * No wrapper can currently activate this driver from Python. CALL/SEND,
 * the complete monitoring schedule and the blocked-quarantine outer-driver
 * obligation remain OPEN. Returning CJB_LINKED_BLOCKED to the retaining C
 * owner is NOT permission to return to Python. No abort, spin, replacement
 * exception, old JSON body or speculative DECREF is supplied for that case.
 *
 * HIA selects every bytecode, effect, handler, reverse pop and exit kind.
 * This transport consumes each effect before its single C transaction,
 * copies the actual reply and records attempts/returns independently. The
 * already-admitted image, packet, buffers, context, generator and activation
 * lease must be retained by one enclosing C owner. They are borrowed here.
 * An observer's full trace increments omitted rows and never limits JSON.
 */

#define CJB_MAGIC UINT64_C(0x334d4243494c4348) /* HCLICBM3 */
#define CJB_STATE_MAGIC UINT64_C(0x33594442494c4348) /* HCLIBDY3 */
#define CJB_PACKET_MAGIC UINT64_C(0x31334342494c4348) /* HCLIBC31 */
#define CJB_STATE_BYTES 1024
#define CJB_TRACE_WORDS 40
#define CJB_TRACE_BYTES (CJB_TRACE_WORDS * 8)

#if PY_VERSION_HEX == 0x030c0ef0
enum {
    CJB_NEW=0, CJB_READY=1, CJB_EFFECT_READY=2, CJB_DONE=3,
    CJB_REFUSED=4, CJB_LINKED_BLOCKED=5, CJB_PORT_REQUIRED=6,
    CJB_GIL_UNAVAILABLE=7, CJB_CHILD_REQUIRED=8
};
enum {
    CJB_BAD_INPUT=1, CJB_BAD_REPLY=2, CJB_BAD_NATIVE=3,
    CJB_COUNTER=4, CJB_BAD_OWNER=5, CJB_BAD_LEAF=6,
    CJB_MISSING_PORT=7, CJB_BAD_EXIT=8, CJB_UNEXPECTED_PYERR=9
};

typedef struct CJBodySend312 CJBodySend312;
typedef struct CJBodyCall312 CJBodyCall312;

typedef struct {
    uint64_t permission, completed;
    CJHiaEntry entry;
    unsigned char *trace;
    uint64_t trace_capacity, trace_written, trace_dropped;
    uint64_t native_attempts, native_returns, leaf_attempts, leaf_returns;
    uint64_t request[CJU_REQUEST_WORDS];
    _Alignas(uint64_t) unsigned char state[512];
    _Alignas(uint64_t) unsigned char lease[CJU_LEASE_BYTES];
} CJBodyUnpack312;

typedef struct {
    uint64_t magic, permission;
    CJEvalActivation312 activation;  /* address stays fixed while linked */
    CJContext *ctx;                  /* retained by the enclosing owner */
    PyGenObject *gen;
    PyCodeObject *code;
    PyObject *send_argument;         /* borrowed, original send convention */
    PyThreadState *thread;
    _PyCFrame *caller_cframe;
    _PyInterpreterFrame *caller_frame;
    _PyErr_StackItem *caller_exc;
    CJActiveFrame312 *caller_active;
    CJHiaEntry entry;
    const unsigned char *packet;
    uint64_t packet_bytes;
    unsigned char *state;
    uint64_t units, locals, stacksize;
    unsigned char *trace;
    uint64_t trace_capacity, trace_written, trace_dropped;
    uint64_t hia_attempts, hia_returns, effect_attempts, effect_returns;
    uint64_t issued, consumed, last_native, last_effect, last_marker;
    uint64_t refusal_reason, missing_port, owner_lost;
    uint64_t activation_attempts, activation_returns;
    uint64_t finish_attempts, finish_returns;
    uint64_t last_permission, last_links, last_pending;
    int last_top;
    uint64_t result_status, pygen_status;
    PyObject *unexpected_error;     /* owned only on a protocol failure */
    CJFrame last_leaf;              /* actual raw response, not synthesized */
    CJBodyUnpack312 *unpack;        /* retained even on an uncommitted tail */
    CJBodySend312 *send;            /* retained across a real inlined child */
    CJBodyCall312 *call;            /* adaptive/post-call/thread child owners */
} CJBodyMachine312;

static uint64_t cjb_send_241(CJBodyMachine312 *m);
static uint64_t cjb_call_240(CJBodyMachine312 *m);

/* This check does not walk current TLS when it no longer names this owner.
 * The saved activation and all borrowed objects must still be retained.
 * Before entry or after finish, compare the original caller links directly.
 * A stale/foreign current frame is never adopted as this activation. */
static int cjb_owner_current(CJBodyMachine312 *m) {
    if (!PyGILState_Check()) return 0;
    CJEvalActivation312 *a = &m->activation;
    if (m->owner_lost || !m->thread || PyThreadState_Get() != m->thread)
        return 0;
    if (a->c_entered || a->py_entered || a->exc_linked || a->stack_live) {
        if (a->tstate != m->thread || a->gen != m->gen || a->frame !=
                (_PyInterpreterFrame *)m->gen->gi_iframe ||
                (a->stack_live && cj312_active_frame != &a->active))
            return 0;
        return cja_links(a);
    }
    return m->thread->cframe == m->caller_cframe &&
        m->caller_cframe->current_frame == m->caller_frame &&
        m->thread->exc_info == m->caller_exc &&
        cj312_active_frame == m->caller_active;
}

static int cjb_observe_owner(CJBodyMachine312 *m) {
    if (!PyGILState_Check()) return 0;
    if (!cjb_owner_current(m)) {
        m->owner_lost = 1;
        return 0;
    }
    CJEvalActivation312 *a = &m->activation;
    m->last_permission = a->permission;
    m->last_links = (uint64_t)a->c_entered | ((uint64_t)a->py_entered << 1) |
                    ((uint64_t)a->exc_linked << 2) | ((uint64_t)a->stack_live << 3);
    if (a->stack_live) {
        m->last_top = a->active.top;
        m->last_pending = a->active.pending_stack_owner != NULL;
    }
    else {
        /* This one scalar remains valid even after ClearExceptCode. Do not
         * inspect cleared locals/f_funcobj/frame_obj during observation. */
        m->last_top = ((_PyInterpreterFrame *)m->gen->gi_iframe)->stacktop;
        m->last_pending = 0;
    }
    return 1;
}

static void cjb_trace(CJBodyMachine312 *m, uint64_t kind, uint64_t result) {
    if (!PyGILState_Check()) return;
    const int current = cjb_observe_owner(m);
    if (m->trace_written >= m->trace_capacity) {
        if (m->trace_dropped != UINT64_MAX) m->trace_dropped++;
        return;
    }
    uint64_t row[CJB_TRACE_WORDS] = {0};
    row[0] = kind; row[1] = result;
    row[2] = cjp_get(m->state, 8); row[3] = cjp_get(m->state, 16);
    row[4] = cjp_get(m->state, 64);
    for (unsigned i = 0; i < 5; i++) row[5+i] = cjp_get(m->state, 72 + 8*i);
    row[10] = (uintptr_t)m->ctx->slot; row[11] = (uintptr_t)m->ctx->raised;
    row[12] = (uintptr_t)m->ctx->external;
    row[13] = m->hia_attempts; row[14] = m->hia_returns;
    row[15] = m->effect_attempts; row[16] = m->effect_returns;
    row[17] = m->issued; row[18] = m->consumed;
    row[19] = m->last_permission; row[20] = m->last_links;
    row[21] = (uint64_t)(int64_t)m->last_top; row[22] = m->last_pending;
    row[23] = (uint64_t)current; row[24] = m->owner_lost;
    row[25] = m->activation_attempts; row[26] = m->activation_returns;
    row[27] = m->finish_attempts; row[28] = m->finish_returns;
    row[29] = m->last_marker;
    row[30] = (uintptr_t)&m->activation.active;
    row[31] = (uintptr_t)cj312_active_frame; /* address only */
    row[32] = m->refusal_reason; row[33] = m->missing_port;
    row[34] = cjp_get(m->state, 112); row[35] = cjp_get(m->state, 416);
    row[36] = m->activation.clear_counter_entered;
    row[37] = m->activation.clear_frame_returned;
    row[38] = (uintptr_t)m->activation.previous_active;
    row[39] = (uintptr_t)m->activation.previous_frame;
    memcpy(m->trace + m->trace_written * CJB_TRACE_BYTES, row, sizeof(row));
    m->trace_written++;
}

/* Full fixed child bytes, before a closed child buffer may be reused.
 * Each row is {kind, chunk_index, total_words, this_words, <=36 raw words}.
 * This is observation only; exhaustion does not interrupt a product leaf.
 */
static void cjb_trace_child(CJBodyMachine312 *m, uint64_t kind,
                              const void *bytes, uint64_t words) {
    const unsigned char *source = bytes;
    for (uint64_t at = 0; at < words; at += CJB_TRACE_WORDS - 4) {
        if (m->trace_written >= m->trace_capacity) {
            if (m->trace_dropped != UINT64_MAX) m->trace_dropped++;
            continue;
        }
        uint64_t row[CJB_TRACE_WORDS] = {0};
        uint64_t count = words - at;
        if (count > CJB_TRACE_WORDS - 4) count = CJB_TRACE_WORDS - 4;
        row[0] = kind; row[1] = at / (CJB_TRACE_WORDS - 4);
        row[2] = words; row[3] = count;
        memcpy(row + 4, source + at*8, count*8);
        memcpy(m->trace + m->trace_written*CJB_TRACE_BYTES, row, sizeof(row));
        m->trace_written++;
    }
}

/* No reference release or link repair on a protocol refusal. In particular,
 * a linked refusal remains an internal C-owner obligation. This include has
 * no exported entry which could reinterpret it as a safe Python return. */
static uint64_t cjb_refuse(CJBodyMachine312 *m, uint64_t reason) {
    /* No-GIL refusal carries no closure observation or return permission. */
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (m->thread && PyThreadState_Get() != m->thread) {
        m->owner_lost = 1;
        m->refusal_reason = reason;
        m->permission = CJB_LINKED_BLOCKED;
        return CJB_LINKED_BLOCKED; /* never steal the other thread's error */
    }
    if (PyErr_Occurred()) {
        if (!m->ctx->external) m->ctx->external = PyErr_GetRaisedException();
        else if (!m->unexpected_error) m->unexpected_error = PyErr_GetRaisedException();
        else {
            /* Do not overwrite either acquired error owner. A pending
             * third error makes this a blocked internal state as well. */
            m->owner_lost = 1;
        }
    }
    m->refusal_reason = reason;
    cjb_observe_owner(m);
    CJEvalActivation312 *a = &m->activation;
    m->permission = (m->owner_lost || a->c_entered || a->py_entered ||
        a->exc_linked || a->stack_live || a->quarantine_failure)
        ? CJB_LINKED_BLOCKED : CJB_REFUSED;
    return m->permission;
}

static int cjb_state_bound(const CJBodyMachine312 *m) {
    return cjp_get(m->state, 0) == CJB_STATE_MAGIC &&
        cjp_get(m->state, 120) == (uintptr_t)m->gen &&
        cjp_get(m->state, 128) == (uintptr_t)m->code &&
        cjp_get(m->state, 136) == (uintptr_t)m->caller_frame &&
        cjp_get(m->state, 160) == m->units &&
        cjp_get(m->state, 368) == (uint64_t)m->activation.throwflag &&
        cjp_get(m->state, 408) == (uint64_t)(m->send_argument == NULL) &&
        cjp_get(m->state, 424) == (m->activation.inlined ? m->activation.inlined->kind : 0) &&
        cjp_get(m->state, 48) == (uintptr_t)m->ctx->raised &&
        cjp_get(m->state, 320) == (uintptr_t)m->ctx->slot;
}

/* Called only by a retaining C owner before it invokes any HIA. No Python
 * allocation, extra object reference or generator resumption occurs here.
 * The complete external packet/code/image admission is an additional gate;
 * these local structural checks are not a replacement for those pins. */
static uint64_t cjb_prepare(CJBodyMachine312 *m, CJContext *ctx,
                             PyGenObject *gen, PyObject *send_argument,
                             uint64_t throwflag, CJHiaEntry entry,
                             const unsigned char *packet, uint64_t packet_bytes,
                             unsigned char *state, unsigned char *trace,
                             uint64_t trace_capacity) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!m || m->magic || m->permission || !ctx || !gen || !entry ||
            !packet || !state || !PyGILState_Check() || PyErr_Occurred() ||
            !cj312_runtime.ready || !cj312_control_runtime.ready ||
            !PyGen_CheckExact(gen) || ctx->magic != CJ_CTX || ctx->profile != 31214 ||
            ctx->slot || ctx->external || throwflag > 1 || !!ctx->raised != !!throwflag ||
            ctx->phase || ctx->list || ctx->saved_size || ctx->saved_allocated ||
            ctx->saved_items || ctx->displaced_size || ctx->displaced_items ||
            ctx->temporary != ctx->temporary_array || ctx->temporary_words != CJ_TEMP_WORDS ||
            packet_bytes < 64 || cjp_get(packet, 0) != CJB_PACKET_MAGIC ||
            cjp_get(packet, 8) != 31214 || cjp_get(packet, 56) != 1 ||
            trace_capacity > UINT64_MAX / CJB_TRACE_BYTES ||
            (!trace_capacity && trace)) return CJ_REFUSAL;
    uint64_t units = cjp_get(packet, 16);
    if (!units || units > (UINT64_MAX - 64) / 64 || packet_bytes != 64 + units*64)
        return CJ_REFUSAL;
    uint64_t addresses[5] = {(uintptr_t)m, (uintptr_t)ctx, (uintptr_t)packet,
                            (uintptr_t)state, (uintptr_t)trace};
    uint64_t sizes[5] = {sizeof(*m), sizeof(*ctx), packet_bytes,
                        CJB_STATE_BYTES, trace_capacity * CJB_TRACE_BYTES};
    for (unsigned i = 0; i < 5; i++) {
        if (!sizes[i]) continue;
        if (!cjp_span(addresses[i], sizes[i])) return CJ_REFUSAL;
        for (unsigned j = 0; j < i; j++)
            if (sizes[j] && !cjp_disjoint(addresses[i], sizes[i], addresses[j], sizes[j]))
                return CJ_REFUSAL;
    }
    for (size_t i = 0; i < sizeof(*m); i++)
        if (((const unsigned char *)m)[i]) return CJ_REFUSAL;
    for (unsigned i = 0; i < 8; i++) if (ctx->cells[i]) return CJ_REFUSAL;
    for (unsigned i = 0; i < CJB_STATE_BYTES; i++) if (state[i]) return CJ_REFUSAL;
    _PyInterpreterFrame *frame = (_PyInterpreterFrame *)gen->gi_iframe;
    PyCodeObject *code = frame->f_code;
    if (!code || (uint64_t)Py_SIZE(code) != units || code->co_nlocalsplus < 0 ||
            code->co_stacksize < 0 || cjp_get(packet, 40) != (uint64_t)code->co_nlocalsplus ||
            cjp_get(packet, 48) != (uint64_t)code->co_stacksize) return CJ_REFUSAL;
    PyThreadState *tstate = PyThreadState_Get();
    if (!tstate || !tstate->cframe || !tstate->exc_info) return CJ_REFUSAL;
    m->magic = CJB_MAGIC; m->permission = CJB_READY;
    m->ctx = ctx; m->gen = gen; m->code = code; m->send_argument = send_argument;
    m->thread = tstate; m->caller_cframe = tstate->cframe;
    m->caller_frame = tstate->cframe->current_frame;
    m->caller_exc = tstate->exc_info; m->caller_active = cj312_active_frame;
    m->entry = entry; m->packet = packet; m->packet_bytes = packet_bytes;
    m->state = state; m->units = units; m->locals = code->co_nlocalsplus;
    m->stacksize = code->co_stacksize; m->trace = trace; m->trace_capacity = trace_capacity;
    /* Save the requested entry mode independently before entry consumes it. */
    m->activation.throwflag = (int)throwflag;
    int64_t lasti = _PyInterpreterFrame_LASTI(frame);
    cjp_put(state, 0, CJB_STATE_MAGIC); cjp_put(state, 48, (uintptr_t)ctx->raised);
    cjp_put(state, 120, (uintptr_t)gen); cjp_put(state, 128, (uintptr_t)code);
    cjp_put(state, 136, (uintptr_t)m->caller_frame);
    cjp_put(state, 144, throwflag ? (uint64_t)lasti : (uint64_t)(lasti + 1));
    cjp_put(state, 152, (uint64_t)lasti); cjp_put(state, 160, units);
    cjp_put(state, 368, throwflag); cjp_put(state, 408, send_argument == NULL);
    return cjb_observe_owner(m) ? 0 : cjb_refuse(m, CJB_BAD_OWNER);
}

/* The child machine must be prepared against the current parent's real
 * frame before a SEND/FOR_ITER owner transfers the argument. This private
 * attachment adds no Python reference and does not start an evaluator. */
static uint64_t cjb_attach_inline(CJBodyMachine312 *child, CJBodyMachine312 *parent,
                                   CJInlineActivation312 *lease,
                                   uint64_t kind, uint64_t following, uint64_t oparg) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!child || !parent || child == parent || !lease ||
            child->magic != CJB_MAGIC || parent->magic != CJB_MAGIC ||
            child->permission != CJB_READY || child->hia_attempts || child->activation_attempts ||
            child->activation.inlined || child->send_argument || child->activation.throwflag ||
            child->ctx == parent->ctx || child->gen == parent->gen ||
            child->thread != parent->thread || !cjb_observe_owner(parent) ||
            child->caller_cframe != cja_current_cframe(&parent->activation) ||
            child->caller_frame != parent->activation.frame ||
            child->caller_active != &parent->activation.active ||
            child->caller_exc != &parent->gen->gi_exc_state)
        return CJ_REFUSAL;
    uint64_t addresses[8] = {(uintptr_t)lease, (uintptr_t)child, (uintptr_t)parent,
        (uintptr_t)child->ctx, (uintptr_t)parent->ctx, (uintptr_t)child->state,
        (uintptr_t)parent->state, (uintptr_t)child->packet};
    uint64_t sizes[8] = {sizeof(*lease), sizeof(*child), sizeof(*parent),
        sizeof(*child->ctx), sizeof(*parent->ctx), CJB_STATE_BYTES,
        CJB_STATE_BYTES, child->packet_bytes};
    for (unsigned i = 0; i < 8; i++) {
        if (!cjp_span(addresses[i], sizes[i])) return CJ_REFUSAL;
        for (unsigned j = 0; j < i; j++)
            if (!cjp_disjoint(addresses[i], sizes[i], addresses[j], sizes[j])) return CJ_REFUSAL;
    }
    uint64_t result = cji_attach(lease, &child->activation, &parent->activation,
                                 child->gen, kind, following, oparg);
    if (result) return result;
    cjp_put(child->state, 424, kind);
    return 0;
}

/* Attach one reusable, owner-retained UNPACK workspace before first entry.
 * Successful child ownership is transferred to the actual frame at COMMIT;
 * only then may its now-owner-free fixed work words be reset. No number of
 * JSON values or UNPACK operations is capped by this reusable workspace.
 */
static uint64_t cjb_attach_unpack(CJBodyMachine312 *m, CJBodyUnpack312 *u,
                                   CJHiaEntry entry, unsigned char *trace,
                                   uint64_t trace_capacity) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!m || m->magic != CJB_MAGIC || m->permission != CJB_READY ||
            m->hia_attempts || m->activation_attempts || m->unpack ||
            !u || !entry || trace_capacity > UINT64_MAX / CJU_TRACE_BYTES ||
            (!trace_capacity && trace) || !cjb_observe_owner(m)) return CJ_REFUSAL;
    uint64_t addresses[7] = {(uintptr_t)m, (uintptr_t)m->ctx, (uintptr_t)m->packet,
        (uintptr_t)m->state, (uintptr_t)m->trace, (uintptr_t)u, (uintptr_t)trace};
    uint64_t sizes[7] = {sizeof(*m), sizeof(*m->ctx), m->packet_bytes, CJB_STATE_BYTES,
        m->trace_capacity*CJB_TRACE_BYTES, sizeof(*u), trace_capacity*CJU_TRACE_BYTES};
    for (unsigned i = 0; i < 7; i++) {
        if (!sizes[i]) continue;
        if (!cjp_span(addresses[i], sizes[i])) return CJ_REFUSAL;
        for (unsigned j = 0; j < i; j++)
            if (sizes[j] && !cjp_disjoint(addresses[i], sizes[i], addresses[j], sizes[j]))
                return CJ_REFUSAL;
    }
    for (size_t i = 0; i < sizeof(*u); i++)
        if (((const unsigned char *)u)[i]) return CJ_REFUSAL;
    u->entry = entry; u->trace = trace; u->trace_capacity = trace_capacity;
    m->unpack = u;
    return 0;
}

static void cjb_reply(CJBodyMachine312 *m, const uint64_t *answer) {
    for (unsigned i = 0; i < 8; i++) cjp_put(m->state, 256 + i*8, answer[i]);
    cjp_put(m->state, 48, (uintptr_t)m->ctx->raised);
    cjp_put(m->state, 320, (uintptr_t)m->ctx->slot);
    if (cjb_observe_owner(m)) cjp_put(m->state, 168, (uint64_t)(int64_t)m->last_top);
}

/* The ledger consumes before a leaf can call foreign code or alter a frame.
 * A failed/partial effect therefore cannot be issued for a second time. */
static uint64_t cjb_consume(CJBodyMachine312 *m, uint64_t operation) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    uint64_t sequence = cjp_get(m->state, 16);
    if (m->permission != CJB_EFFECT_READY || m->issued == UINT64_MAX ||
            m->issued != m->consumed || sequence != m->issued + 1 ||
            cjp_get(m->state, 24) != 1 || cjp_get(m->state, 32) != m->consumed ||
            cjp_get(m->state, 64) != operation || cjp_get(m->state, 112) ||
            !cjb_state_bound(m) || !cjb_observe_owner(m))
        return cjb_refuse(m, CJB_BAD_REPLY);
    if (!cjp_increment(&m->effect_attempts)) return cjb_refuse(m, CJB_COUNTER);
    m->issued = sequence; m->consumed = sequence;
    cjp_put(m->state, 32, sequence); cjp_put(m->state, 40, operation);
    return 0;
}

static uint64_t cjb_complete(CJBodyMachine312 *m, uint64_t result) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    m->last_effect = result;
    if (!cjp_increment(&m->effect_returns)) return cjb_refuse(m, CJB_COUNTER);
    cjb_trace(m, 2, result);
    if (result || PyErr_Occurred() || m->ctx->external || m->owner_lost)
        return cjb_refuse(m, result ? CJB_BAD_LEAF : CJB_BAD_OWNER);
    m->permission = CJB_READY;
    return 0;
}

static uint64_t cjb_enter_243(CJBodyMachine312 *m) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    unsigned char *w = m->state;
    if (cjp_get(w, 8) != 1 || cjp_get(w, 72) != (uintptr_t)m->gen ||
            cjp_get(w, 80) != (uint64_t)m->activation.throwflag ||
            cjp_get(w, 88) != cjp_get(w, 144) || cjp_get(w, 96) != cjp_get(w, 152) ||
            cjp_get(w, 104) || m->activation.permission != CJA_NEW ||
            m->activation_attempts || m->activation_returns)
        return cjb_refuse(m, CJB_BAD_INPUT);
    uint64_t consumed = cjb_consume(m, 243);
    if (consumed) return consumed;
    m->activation_attempts = 1;
    uint64_t result = cja_enter(&m->activation, m->ctx, m->gen,
                                m->send_argument, m->activation.throwflag);
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (PyThreadState_Get() != m->thread) return cjb_refuse(m, CJB_BAD_OWNER);
    m->activation_returns = 1;
    uint64_t answer[8] = {m->activation.permission,
        (uint64_t)(int64_t)m->activation.preflight_send_status,
        (uintptr_t)m->code, m->locals, m->stacksize, 0, 0, 0};
    if (m->activation.permission == CJA_ACTIVE && cjb_observe_owner(m)) {
        answer[5] = (uint64_t)m->activation.active.top;
        answer[6] = (uint64_t)(int64_t)_PyInterpreterFrame_LASTI(m->activation.frame);
    }
    cjb_reply(m, answer);
    return cjb_complete(m, result);
}

static uint64_t cjb_exit_245(CJBodyMachine312 *m) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    unsigned char *w = m->state;
    uint64_t selected = cjp_get(w, 80);
    if (cjp_get(w, 8) != 300 || cjp_get(w, 72) != (uintptr_t)m->gen ||
            selected != cjp_get(w, 400) || selected > CJA_EARLY_ERROR ||
            cjp_get(w, 88) || cjp_get(w, 96) || cjp_get(w, 104) ||
            m->activation_attempts != 1 || m->activation_returns != 1 ||
            m->finish_attempts || m->finish_returns)
        return cjb_refuse(m, CJB_BAD_EXIT);
    uint64_t consumed = cjb_consume(m, 245);
    if (consumed) return consumed;
    m->finish_attempts = 1;
    uint64_t result = cja_finish(&m->activation, m->ctx, selected);
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (PyThreadState_Get() != m->thread) return cjb_refuse(m, CJB_BAD_OWNER);
    m->finish_returns = 1;
    uint64_t links = (uint64_t)m->activation.c_entered |
        ((uint64_t)m->activation.py_entered << 1) |
        ((uint64_t)m->activation.exc_linked << 2) |
        ((uint64_t)m->activation.stack_live << 3);
    uint64_t answer[8] = {m->activation.permission, selected,
        (uint64_t)(int64_t)m->gen->gi_frame_state, (uintptr_t)Py_None, links,
        (uintptr_t)m->ctx->slot, (uintptr_t)m->ctx->raised, 0};
    cjb_reply(m, answer);
    return cjb_complete(m, result);
}

static int cjb_add_count(uint64_t *total, uint64_t value) {
    if (*total > UINT64_MAX - value) return 0;
    *total += value;
    return 1;
}

/* Actual port242 joins the parent one-use permission to the raw UNPACK
 * child's independent one-use permission. Semantic child status1 is a
 * successful protocol reply containing its original raised exception.
 * The parent HIA then enters the same exception-table population; there
 * is no tuple export, extra sequence POP, or host-generated error cleanup.
 */
static uint64_t cjb_unpack_242(CJBodyMachine312 *m) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    unsigned char *w = m->state;
    CJBodyUnpack312 *u = m->unpack;
    if (!u) {
        m->missing_port = 242; m->permission = CJB_PORT_REQUIRED;
        return CJB_PORT_REQUIRED;
    }
    if (cjp_get(w, 8) != 22 || cjp_get(w, 72) != (uintptr_t)m->gen ||
            cjp_get(w, 80) != cjp_get(w, 208) || cjp_get(w, 88) != cjp_get(w, 144) ||
            cjp_get(w, 96) || cjp_get(w, 104) ||
            m->activation.permission != CJA_ACTIVE || m->ctx->slot || m->ctx->raised ||
            m->ctx->external || !cjb_observe_owner(m) ||
            m->activation.active.pending_stack_owner || !u->entry ||
            (u->permission != 0 && u->permission != 2) ||
            u->trace_written > u->trace_capacity || u->completed == UINT64_MAX)
        return cjb_refuse(m, CJB_BAD_INPUT);
    uint64_t pc = cjp_get(w, 144);
    if (pc >= m->units || cjp_get(w, 152) != pc ||
            cjp_get(m->packet, 64 + pc*64) != UNPACK_SEQUENCE ||
            cjp_get(m->packet, 64 + pc*64 + 56) != 1)
        return cjb_refuse(m, CJB_BAD_INPUT);
    if (u->permission == 2) {
        CJUnpackLease312 *old = (CJUnpackLease312 *)u->lease;
        if (u->request[3] != 2 || old->magic != CJU_MAGIC || old->permission != 2 ||
                !old->closed || old->sequence || old->iterator || old->item || old->written ||
                old->owner_lost || old->owner != &m->activation.active)
            return cjb_refuse(m, CJB_BAD_OWNER);
    }
    uint64_t consumed = cjb_consume(m, 242);
    if (consumed) return consumed;
    m->activation.frame->prev_instr = _PyCode_CODE(m->code) + pc;
    /* The previous request/state/lease was recorded in full before this
     * reset, and no owner remains in the three fixed byte spans. */
    memset(u->request, 0, sizeof(u->request));
    memset(u->state, 0, sizeof(u->state));
    memset(u->lease, 0, sizeof(u->lease));
    uint64_t *r = u->request;
    r[0] = CJU_MAGIC; r[1] = 31214; r[2] = 242;
    r[4] = (uintptr_t)m->ctx; r[5] = sizeof(*m->ctx); r[6] = (uintptr_t)u->entry;
    r[7] = (uintptr_t)u->state; r[8] = sizeof(u->state);
    r[9] = (uintptr_t)m->gen; r[10] = (uintptr_t)m->code; r[11] = pc;
    r[12] = cjp_get(w, 208); r[13] = (uintptr_t)u->lease; r[14] = sizeof(u->lease);
    r[16] = u->trace_capacity - u->trace_written;
    r[15] = r[16] ? (uintptr_t)(u->trace + u->trace_written*CJU_TRACE_BYTES) : 0;
    r[17] = CJU_TRACE_BYTES;
    u->permission = 1;
    uint64_t status = hia_cli_json_py312_unpack_run(r, sizeof(u->request));
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (PyThreadState_Get() != m->thread) return cjb_refuse(m, CJB_BAD_OWNER);
    cjb_trace_child(m, 3, u->request, sizeof(u->request)/8);
    cjb_trace_child(m, 4, u->state, sizeof(u->state)/8);
    cjb_trace_child(m, 5, u->lease, sizeof(u->lease)/8);
    uint64_t result = 0;
    if (r[26] > r[16] ||
            !cjb_add_count(&u->trace_written, r[26]) ||
            !cjb_add_count(&u->trace_dropped, r[27]) ||
            !cjb_add_count(&u->native_attempts, r[20]) ||
            !cjb_add_count(&u->native_returns, r[21]) ||
            !cjb_add_count(&u->leaf_attempts, r[22]) ||
            !cjb_add_count(&u->leaf_returns, r[23]) ||
            status > 1 || r[3] != 2 || r[28] != status ||
            m->ctx->slot || m->ctx->external || !!m->ctx->raised != (status == 1) ||
            !cjb_observe_owner(m) || m->activation.active.pending_stack_owner)
        result = CJ_REFUSAL;
    if (!result) { u->permission = 2; u->completed++; }
    else u->permission = 3;
    uint64_t answer[8] = {0};
    cjb_reply(m, answer);
    return cjb_complete(m, result);
}

/* Only HIA-emitted raw body leaves may reach the original leaf switch.
 * FRAME_CLEAR/SUSPEND and the host STACK_CALL/FOR_NEXT alternatives are
 * deliberately absent: the new activation/route ports own those transitions.
 * This is a private-protocol allowlist, not a restricted public value domain. */
static int cjb_raw_operation(uint64_t operation) {
    switch (operation) {
    case CJ_DROP_SLOT: case CJ_PY312_LOAD_GLOBAL: case CJ_PY312_FRAME_INFO:
    case CJ_PY312_FRAME_TRACEBACK: case CJ_PY312_FRAME_LOAD:
    case CJ_PY312_STACK_POP: case CJ_PY312_STACK_PUSH_SLOT:
    case CJ_PY312_STACK_PUSH_NULL: case CJ_PY312_DEREF_LOAD:
    case CJ_PY312_CLEAR_EXC_STATE: case CJ_PY312_STACK_SWAP:
    case CJ_PY312_FRAME_BINDINGS: case CJ_PY312_STACK_COPY:
    case CJ_PY312_FRAME_CONST: case CJ_PY312_FRAME_NAME:
    case CJ_PY312_STACK_TRUTH: case CJ_PY312_STACK_BINARY:
    case CJ_PY312_STACK_GET_ITER: case CJ_PY312_STACK_YIELD_FROM_ITER:
    case CJ_PY312_STACK_CONTAINS: case CJ_PY312_STACK_IS:
    case CJ_PY312_STACK_SET_ITEM: case CJ_PY312_STACK_DEL_ITEM:
    case CJ_PY312_STACK_TUPLE: case CJ_PY312_STACK_ATTR:
    case CJ_PY312_STACK_FORMAT: case CJ_PY312_STACK_STRING:
    case CJ_PY312_TAKE_RAISED: case CJ_PY312_STACK_RAISE:
    case CJ_PY312_STACK_RERAISE: case CJ_PY312_STACK_PUSH_EXC:
    case CJ_PY312_STACK_POP_EXC: case CJ_PY312_STACK_STOPITERATION:
    case CJ_PY312_STACK_END_SEND: case CJ_PY312_STACK_CLEANUP_THROW:
    case CJ_PY312_NEW_LASTI: case CJ_PY312_STACK_STORE_LOCAL:
    case CJ_PY312_FRAME_UNBOUND:
        return 1;
    default:
        return 0;
    }
}

static uint64_t cjb_raw(CJBodyMachine312 *m) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    unsigned char *w = m->state;
    uint64_t operation = cjp_get(w, 64), phase = cjp_get(w, 8);
    const int postlude = phase == 301 || phase == 302;
    if (!cjb_raw_operation(operation) ||
            (postlude ? m->activation.permission != CJA_FINISHED :
                        m->activation.permission != CJA_ACTIVE) ||
            (postlude && !((phase == 301 && operation == CJ_DROP_SLOT) ||
                          (phase == 302 && operation == CJ_PY312_CLEAR_EXC_STATE))))
        return cjb_refuse(m, CJB_BAD_REPLY);
    if (!postlude && (m->activation.active.pending_stack_owner ||
            !cjb_observe_owner(m))) return cjb_refuse(m, CJB_BAD_OWNER);
    CJFrame effect = {0};
    effect.abi = CJ_ABI; effect.context = (uintptr_t)m->ctx; effect.op = operation;
    effect.a = cjp_get(w, 72); effect.b = cjp_get(w, 80);
    effect.c = cjp_get(w, 88); effect.d = cjp_get(w, 96); effect.e = cjp_get(w, 104);
    /* DISPATCH publishes the actual opcode location before its primitives.
     * RERAISE's changed f_lasti is preserved during the unwind phases. */
    uint64_t pc = cjp_get(w, 152);
    const int restored_child_push = operation == CJ_PY312_STACK_PUSH_SLOT &&
        cjp_get(w, 312) == 1 &&
        ((phase == 44 && cjp_get(w, 392) == 1) ||
         (phase == 21 && (cjp_get(w, 200) == SEND || cjp_get(w, 200) == FOR_ITER)));
    if (!postlude && phase < 300) {
        if (pc >= m->units || cjp_get(m->packet, 64 + pc*64 + 56) != 1)
            return cjb_refuse(m, CJB_BAD_INPUT);
    }
    if (restored_child_push) {
        uint64_t resumed = cjp_get(w, 184), restored = cjp_get(w, 288);
        if (!resumed || resumed >= m->units || restored != resumed - 1 ||
                cjp_get(w, 280) != restored ||
                m->activation.frame->prev_instr != _PyCode_CODE(m->code) + restored)
            return cjb_refuse(m, CJB_BAD_INPUT);
    }
    uint64_t consumed = cjb_consume(m, operation);
    if (consumed) return consumed;
    if (!postlude && phase < 300 && !restored_child_push)
        m->activation.frame->prev_instr = _PyCode_CODE(m->code) + pc;
    uint64_t result = hia_cli_json_leaf(&effect);
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (PyThreadState_Get() != m->thread) return cjb_refuse(m, CJB_BAD_OWNER);
    m->last_leaf = effect; m->last_marker = effect.marker;
    if (effect.marker != 2 || effect.captured != (uintptr_t)m->ctx->raised)
        result = CJ_REFUSAL;
    cjb_reply(m, effect.result);
    return cjb_complete(m, result);
}

/* These three exact monitor sites already have admitted original helpers.
 * RESUME, branch/CALL breakers, instrumented opcode variants and SEND/CALL
 * routing are separate unfinished ports. No ignored monitor is called PASS.
 */
static uint64_t cjb_exception_monitor_244(CJBodyMachine312 *m) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    unsigned char *w = m->state;
    uint64_t kind = cjp_get(w, 88), pc = cjp_get(w, 80), phase = cjp_get(w, 8);
    if (cjp_get(w, 72) != (uintptr_t)m->gen || pc >= m->units ||
            cjp_get(w, 96) || cjp_get(w, 104) ||
            m->activation.permission != CJA_ACTIVE ||
            m->activation.active.pending_stack_owner || !cjb_observe_owner(m) ||
            m->ctx->slot || m->ctx->external ||
            !((kind == 4 && phase == 811 && !m->ctx->raised) ||
              (kind == 5 && phase == 813 && m->ctx->raised &&
                  m->activation.active.top == (int)m->locals) ||
              (kind == 6 && phase == 801 && m->ctx->raised)))
        return cjb_refuse(m, CJB_BAD_REPLY);
    _PyInterpreterFrame *frame = m->activation.frame;
    PyObject *handled = NULL;
    if (kind == 4) {
        if (m->activation.active.top <= (int)m->locals) return cjb_refuse(m, CJB_BAD_INPUT);
        handled = frame->localsplus[m->activation.active.top - 1];
        if (!handled || !PyExceptionInstance_Check(handled)) return cjb_refuse(m, CJB_BAD_INPUT);
    }
    uint64_t consumed = cjb_consume(m, 244);
    if (consumed) return consumed;
    PyObject *incoming = m->ctx->raised; m->ctx->raised = NULL;
    PyErr_SetRaisedException(incoming);
    int result = 0;
    if (kind == 4)
        result = cja_monitor_handled(m->thread, frame, _PyCode_CODE(m->code) + pc, handled);
    else if (kind == 5) {
        /* Original no-handler exit publishes the empty stack for this
         * callback. No Python runs between restoring the private sentinel
         * and finish publishing that same top for clear_gen_frame. */
        frame->stacktop = m->activation.active.top;
        cja_monitor_unwind(m->thread, frame, _PyCode_CODE(m->code) + pc);
        if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
        /* Restore only our own still-current published frame. A changed
         * chain is a blocked internal failure, never forcibly unlinked or
         * made to look as if this callback returned through our owner. */
        if (PyThreadState_Get() != m->thread || cj312_active_frame != &m->activation.active ||
                m->thread->cframe != cja_current_cframe(&m->activation) ||
                cja_current_cframe(&m->activation)->current_frame != frame ||
                m->thread->exc_info != &m->gen->gi_exc_state ||
                m->gen->gi_exc_state.previous_item != m->activation.previous_exc ||
                m->gen->gi_frame_state != FRAME_EXECUTING ||
                frame->stacktop != m->activation.active.top)
            m->owner_lost = 1;
        else frame->stacktop = -1;
    }
    else cja_monitor_raise(m->thread, frame, _PyCode_CODE(m->code) + pc);
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (PyThreadState_Get() != m->thread) return cjb_refuse(m, CJB_BAD_OWNER);
    m->ctx->raised = PyErr_GetRaisedException();
    uint64_t answer[8] = {(uint64_t)(int64_t)result, kind, pc, 0, 0, 0, 0, 0};
    cjb_reply(m, answer);
    return cjb_complete(m, 0);
}

/* Dispatch one *already issued* HIA effect. Missing routes retain the active
 * owner and every operand. They do not call legacy STACK_CALL/FOR_NEXT, run
 * a retained JSON body, or report a semantic error for a supported value.
 * A complete executable body request must supply those routes first. */
static uint64_t cjb_dispatch_known(CJBodyMachine312 *m) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!m || m->magic != CJB_MAGIC || m->permission != CJB_EFFECT_READY)
        return CJ_REFUSAL;
    uint64_t operation = cjp_get(m->state, 64);
    if (operation == 240 && cjp_get(m->state, 8) == 43) return cjb_call_240(m);
    if (operation == 241 && cjp_get(m->state, 8) == 41) return cjb_send_241(m);
    if (operation == 242) return cjb_unpack_242(m);
    if (operation == 243) return cjb_enter_243(m);
    if (operation == 245) return cjb_exit_245(m);
    if (operation == 244 && cjp_get(m->state, 88) >= 4 &&
            cjp_get(m->state, 88) <= 6) return cjb_exception_monitor_244(m);
    if (cjb_raw_operation(operation)) return cjb_raw(m);
    m->missing_port = operation;
    m->refusal_reason = CJB_MISSING_PORT;
    m->permission = CJB_PORT_REQUIRED;
    return CJB_PORT_REQUIRED;
}

/* One actual HIA entry. This internal step has no Python wrapper. An outer
 * retaining C owner must keep dispatching, or keep a blocked activation
 * internal; neither EFFECT_READY nor PORT_REQUIRED permits Python return.
 * All terminal predicates are checked again independently of the HIA flag.
 */
static uint64_t cjb_hia_step(CJBodyMachine312 *m) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!m || m->magic != CJB_MAGIC || m->permission != CJB_READY ||
            PyErr_Occurred() ||
            !cjb_state_bound(m) || !cjb_observe_owner(m))
        return m && m->magic == CJB_MAGIC ? cjb_refuse(m, CJB_BAD_INPUT) : CJ_REFUSAL;
    if (!cjp_increment(&m->hia_attempts)) return cjb_refuse(m, CJB_COUNTER);
    /* f0 does not use its output span. A distinct one-byte C object keeps
     * all three ABI spans non-overlapping without a Python allocation. */
    unsigned char output = 0;
    uint32_t status = m->entry(m->packet, m->packet_bytes, &output, 1,
                               m->state, CJB_STATE_BYTES);
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (PyThreadState_Get() != m->thread) return cjb_refuse(m, CJB_BAD_OWNER);
    m->last_native = status;
    if (!cjp_increment(&m->hia_returns)) return cjb_refuse(m, CJB_COUNTER);
    cjb_trace(m, 1, status);
    if (PyErr_Occurred() || m->owner_lost || !cjb_state_bound(m))
        return cjb_refuse(m, CJB_BAD_NATIVE);
    if (status == 2) {
        if (cjp_get(m->state, 112) || cjp_get(m->state, 24) != 1 ||
                m->issued != m->consumed || m->issued == UINT64_MAX ||
                cjp_get(m->state, 16) != m->issued + 1 ||
                cjp_get(m->state, 32) != m->consumed)
            return cjb_refuse(m, CJB_BAD_REPLY);
        m->permission = CJB_EFFECT_READY;
        return CJB_EFFECT_READY;
    }
    if (status != 0 && status != 1 && status != 3)
        return cjb_refuse(m, CJB_BAD_NATIVE);
    CJEvalActivation312 *a = &m->activation;
    uint64_t expected_final = status == 0 ? 1 : status == 1 ? 2 : 4;
    uint64_t expected_pygen = status == 0 ? 0 : status == 1 ? UINT64_MAX : 1;
    if (cjp_get(m->state, 112) != expected_final ||
            cjp_get(m->state, 416) != expected_pygen || cjp_get(m->state, 24) ||
            m->issued != m->consumed || m->effect_attempts != m->effect_returns ||
            m->hia_attempts != m->hia_returns || m->activation_attempts != 1 ||
            m->activation_returns != 1 || m->ctx->external ||
            a->c_entered || a->py_entered || a->exc_linked || a->stack_live ||
            a->quarantine_failure || a->clear_counter_entered ||
            (status == 1 ? m->ctx->slot != NULL : (!m->ctx->slot || m->ctx->raised)) ||
            (a->permission == CJA_PREFLIGHT_TERMINAL
                ? (status == 3 || m->finish_attempts || m->finish_returns ||
                   a->clear_frame_returned)
                : (a->permission != CJA_FINISHED || m->finish_attempts != 1 ||
                   m->finish_returns != 1 ||
                   a->clear_frame_returned != (status != 3))) || !cjb_observe_owner(m))
        return cjb_refuse(m, CJB_BAD_EXIT);
    m->result_status = status; m->pygen_status = expected_pygen;
    m->permission = CJB_DONE;
    return CJB_DONE;
}
#endif
