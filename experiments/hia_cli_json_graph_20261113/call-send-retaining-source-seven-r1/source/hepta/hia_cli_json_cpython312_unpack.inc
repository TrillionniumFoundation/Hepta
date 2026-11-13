/* CPython 3.12.14 raw value-stack leaves for HIA body port 242.
 *
 * HIA owns all semantic routes, cardinality, adaptive cache arithmetic,
 * diagnostics, exact-container copy order and ordinary release order.
 * This C transport executes one requested leaf and then clears PyErr before
 * re-entering HIA. It never calls unpack_iterable, PySequence_Tuple, the old
 * JSON generator or the public tuple-exporting NativeUnpack adapter.
 *
 * The caller must already hold the real executing generator activation.
 * The fixed lease, raw context, generator, HIA image and trace buffers stay
 * strongly retained across the whole call and any protocol quarantine.
 * BEGIN retains the original active stack top until COMMIT. A quarantine
 * retains both committed and uncommitted owners; it does not invent an
 * ordinary error cleanup plan or resume the retained generator body.
 *
 * Reference: PSF-licensed 3.12.14 ceval.c unpack_iterable, generated_cases
 * UNPACK_SEQUENCE variants, ceval_macros and specialize.c. Stats-enabled
 * CPython is a separate, unimplemented runtime profile, not silently used.
 * Source-only successor: no generation, compilation or execution evidence.
 */

#define CJU_MAGIC UINT64_C(0x31334e55494c4348) /* HCLIUN31 */
#define CJU_REQUEST_WORDS 64
#define CJU_LEASE_BYTES 256
#define CJU_TRACE_WORDS 24
#define CJU_TRACE_BYTES 192

#if PY_VERSION_HEX == 0x030c0ef0
#include "opcode.h"
#include "internal/pycore_code.h"
#ifdef Py_STATS
#error UNPACK statistics require separately admitted HIA counter leaves
#endif

_Static_assert(UNPACK_SEQUENCE == 92 && UNPACK_SEQUENCE_LIST == 161 &&
    UNPACK_SEQUENCE_TUPLE == 166 && UNPACK_SEQUENCE_TWO_TUPLE == 167,
    "exact 3.12.14 opcode profile");
_Static_assert(ADAPTIVE_BACKOFF_BITS == 4 && MAX_BACKOFF_VALUE == 12 &&
    ADAPTIVE_COOLDOWN_VALUE == 52 && ADAPTIVE_COOLDOWN_BACKOFF == 0,
    "HIA adaptive constants must retain original runtime values");

typedef struct {
    uint64_t magic, permission;
    PyGenObject *gen;                  /* borrowed, caller strongly retains */
    _PyInterpreterFrame *frame;        /* actual gen->gi_iframe */
    _Py_CODEUNIT *instruction;         /* actual adaptive opcode, not copy */
    PyObject *sequence;                /* original owned stack reference */
    PyObject *iterator;                /* owned result of PyObject_GetIter */
    PyObject *item;                    /* owned PyIter_Next result */
    uint64_t count, written;
    int original_top, base;
    uint64_t kind, size;
    uint64_t started, closed;
    uint64_t item_order;               /* 0 none, 1 generic, 2 exact copy */
    CJActiveFrame312 *owner;           /* original caller-retained identity */
    int observed_top;                 /* last valid owner observation */
    uint64_t observed_pending, owner_lost;
} CJUnpackLease312;
_Static_assert(sizeof(CJUnpackLease312) <= CJU_LEASE_BYTES, "fixed retained lease");

enum {
    CJU_BEGIN=1, CJU_CACHE_SET=2, CJU_GET_ITER=3, CJU_NEXT=4,
    CJU_STORE=5, CJU_DROP_ITEM=6, CJU_DROP_ITER=7, CJU_DROP_SEQ=8,
    CJU_DROP_EXTRA=9, CJU_MATCH_TYPE_ERROR=10, CJU_TYPE_HAS_ITER=11,
    CJU_SEQUENCE_CHECK=12, CJU_FORMAT_NONITER=13, CJU_FORMAT_FEW=14,
    CJU_FORMAT_MANY=15, CJU_FAST_COPY=16, CJU_COMMIT=17
};

/* Never substitute the current TLS owner for the one admitted at entry.
 * The caller retains this owner and the lease across every foreign leaf.
 * A different/absent TLS value is compared as an address only. In that
 * case diagnostic code uses the saved scalar observation and never walks
 * a foreign or stale active-frame chain. */
static int cju_owner_live(CJUnpackLease312 *lease) {
    if (!lease || lease->magic != CJU_MAGIC || !lease->owner ||
            cj312_active_frame != lease->owner || lease->owner_lost ||
            lease->owner->frame != lease->frame || !lease->gen ||
            !lease->frame || !PyThreadState_Get()->cframe)
        return 0;
    return
        cj312_operand_frame((PyObject *)lease->gen) == lease->frame &&
        lease->instruction == lease->frame->prev_instr;
}

static int cju_observe_owner(CJUnpackLease312 *lease) {
    if (!cju_owner_live(lease)) {
        lease->owner_lost = 1; /* sticky mechanical failure, never resumed */
        return 0;
    }
    lease->observed_top = lease->owner->top;
    lease->observed_pending = lease->owner->pending_stack_owner == lease;
    return 1;
}

static int cju_live(CJUnpackLease312 *lease) {
    return cju_owner_live(lease) && lease->permission == 1 &&
        !lease->closed &&
        (lease->started
            ? (lease->owner->pending_stack_owner == lease &&
               lease->owner->pending_stack_base == lease->base &&
               lease->owner->top == lease->original_top)
            : !lease->owner->pending_stack_owner);
}

static int cju_format_equal(const unsigned char *output, const char *text,
                             size_t size) {
    return size <= 128 && memcmp(output + 128, text, size) == 0;
}

/* A leaf captures/restores the raised error without changing handled state.
 * Pointer assignments transfer references; they never manufacture NewRefs
 * around the sequence, iterator or generic values. The only NewRef is the
 * exact-container opcode's original item acquisition. */
static uint64_t cju_leaf(CJContext *ctx, CJUnpackLease312 *lease,
                          const unsigned char *output, uint64_t *value) {
    uint64_t op = cjp_get(output, 16), a = cjp_get(output, 24);
    uint64_t b = cjp_get(output, 32), c = cjp_get(output, 40), d = cjp_get(output, 48);
    if (!cju_live(lease) || PyErr_Occurred() || ctx->external || ctx->slot ||
            op < CJU_BEGIN || op > CJU_COMMIT || cjp_get(output, 56)) return CJ_REFUSAL;
    for (size_t at = 64; at < 128; at += 8)
        if (cjp_get(output, at)) return CJ_REFUSAL;
    if (op < CJU_FORMAT_NONITER || op > CJU_FORMAT_MANY)
        for (size_t at = 128; at < 256; at += 8)
            if (cjp_get(output, at)) return CJ_REFUSAL;
    if (op != CJU_BEGIN && !lease->started) return CJ_REFUSAL;

    /* Validate every ownership move before restoring PyErr. A rejected
     * mechanical packet must not consume a reference or the saved error. */
    switch (op) {
    case CJU_BEGIN:
        if (lease->started || a || b || c || d || ctx->raised) return CJ_REFUSAL;
        break;
    case CJU_CACHE_SET:
        if (!lease->sequence || lease->iterator || lease->item || lease->written ||
                ctx->raised || a > 255 || b > 65535 ||
                (a != 92 && a != 161 && a != 166 && a != 167) ||
                lease->instruction->op.code != c ||
                (( _PyUnpackSequenceCache *)(lease->instruction + 1))->counter != d)
            return CJ_REFUSAL;
        break;
    case CJU_GET_ITER:
        if (!lease->sequence || lease->iterator || lease->item || lease->written ||
                ctx->raised || a || b || c || d) return CJ_REFUSAL;
        break;
    case CJU_NEXT:
        if (!lease->iterator || lease->item || ctx->raised || a || b || c || d)
            return CJ_REFUSAL;
        break;
    case CJU_STORE:
        if (!lease->item || ctx->raised || a != lease->written || a >= lease->count ||
                lease->item_order > 1 || b || c || d) return CJ_REFUSAL;
        break;
    case CJU_DROP_ITEM:
        if (lease->item || !ctx->raised || !lease->written || a + 1 != lease->written ||
                a >= lease->count || lease->item_order != 1 || b || c || d)
            return CJ_REFUSAL;
        break;
    case CJU_DROP_ITER:
        if (!lease->iterator || lease->item || a || b || c || d) return CJ_REFUSAL;
        break;
    case CJU_DROP_SEQ:
        if (!lease->sequence || lease->iterator || lease->item || a || b || c || d)
            return CJ_REFUSAL;
        break;
    case CJU_DROP_EXTRA:
        if (!lease->item || ctx->raised || lease->written != lease->count || a || b || c || d)
            return CJ_REFUSAL;
        break;
    case CJU_MATCH_TYPE_ERROR:
    case CJU_TYPE_HAS_ITER:
    case CJU_SEQUENCE_CHECK:
        if (!lease->sequence || lease->iterator || lease->item || !ctx->raised ||
                lease->written || a || b || c || d) return CJ_REFUSAL;
        break;
    case CJU_FORMAT_NONITER: {
        static const char format[] = "cannot unpack non-iterable %.200s object";
        if (!lease->sequence || !ctx->raised || a || b || c || d ||
                !cju_format_equal(output, format, sizeof(format))) return CJ_REFUSAL;
        break;
    }
    case CJU_FORMAT_FEW: {
        static const char format[] = "not enough values to unpack (expected %d, got %d)";
        if (ctx->raised || lease->item || !lease->iterator || a != lease->count ||
                b != lease->written || b >= a || c || d ||
                !cju_format_equal(output, format, sizeof(format))) return CJ_REFUSAL;
        break;
    }
    case CJU_FORMAT_MANY: {
        static const char format[] = "too many values to unpack (expected %d)";
        if (ctx->raised || lease->item || !lease->iterator || a != lease->count ||
                lease->written != lease->count || b || c || d ||
                !cju_format_equal(output, format, sizeof(format))) return CJ_REFUSAL;
        break;
    }
    case CJU_FAST_COPY:
        if (!lease->sequence || lease->iterator || lease->item || ctx->raised ||
                (a != 1 && a != 2) || a != lease->kind ||
                lease->size != lease->count || c != lease->written ||
                b >= lease->count || b + c + 1 != lease->count ||
                lease->item_order == 1 || d)
            return CJ_REFUSAL;
        break;
    case CJU_COMMIT:
        if (lease->sequence || lease->iterator || lease->item || a > 1 || b || c || d ||
                (!!ctx->raised == !!a) ||
                (a ? lease->written != lease->count : lease->written != 0))
            return CJ_REFUSAL;
        break;
    default:
        return CJ_REFUSAL;
    }

    PyObject *incoming = ctx->raised;
    ctx->raised = NULL;
    PyErr_SetRaisedException(incoming); /* steals exactly once */
    *value = 0;
    switch (op) {
    case CJU_BEGIN: {
        int top = lease->owner->top;
        lease->sequence = lease->frame->localsplus[top - 1];
        lease->original_top = top;
        lease->base = top - 1;
        lease->started = 1;
        /* As in generated_cases.c.h, the evaluator's original stack pointer
         * is unchanged across unpack_iterable and Py_DECREF(seq). The seq
         * local/lease owns the one original reference even when a result
         * overwrites its slot. The frame continues to expose stacktop=-1.
         * The pending-owner guard prevents publishing stale tail slots if
         * a private-protocol refusal interrupts before COMMIT. */
        lease->owner->pending_stack_base = lease->base;
        lease->owner->pending_stack_owner = lease;
        if (PyTuple_CheckExact(lease->sequence)) {
            lease->kind = 1;
            lease->size = (uint64_t)PyTuple_GET_SIZE(lease->sequence);
        }
        else if (PyList_CheckExact(lease->sequence)) {
            lease->kind = 2;
            lease->size = (uint64_t)PyList_GET_SIZE(lease->sequence);
        }
        *value = 1;
        break;
    }
    case CJU_CACHE_SET:
        /* HIA supplies the same opcode/counter update as the original
         * specializer or deferred decrement. No object or policy here. */
        lease->instruction->op.code = (unsigned char)a;
        ((_PyUnpackSequenceCache *)(lease->instruction + 1))->counter = (uint16_t)b;
        break;
    case CJU_GET_ITER:
        lease->iterator = PyObject_GetIter(lease->sequence);
        *value = lease->iterator != NULL;
        break;
    case CJU_NEXT:
        lease->item = PyIter_Next(lease->iterator);
        *value = lease->item != NULL;
        break;
    case CJU_STORE:
        lease->item_order = 1;
        lease->frame->localsplus[lease->base + (int)(lease->count - 1 - a)] = lease->item;
        lease->item = NULL;
        lease->written++;
        break;
    case CJU_DROP_ITEM: {
        /* Generic first item was stored at the highest destination. Thus
         * HIA's descending acquisition index follows original sp++ cleanup.
         * Keep original stale storage bytes; they are no longer owners. */
        PyObject *item = lease->frame->localsplus[lease->base + (int)(lease->count - 1 - a)];
        lease->written--;
        Py_DECREF(item);
        break;
    }
    case CJU_DROP_ITER: {
        PyObject *it = lease->iterator;
        lease->iterator = NULL;
        Py_DECREF(it);
        break;
    }
    case CJU_DROP_SEQ: {
        PyObject *sequence = lease->sequence;
        lease->sequence = NULL;
        Py_DECREF(sequence);
        break;
    }
    case CJU_DROP_EXTRA: {
        PyObject *item = lease->item;
        lease->item = NULL;
        Py_DECREF(item);
        break;
    }
    case CJU_MATCH_TYPE_ERROR:
        *value = PyErr_ExceptionMatches(PyExc_TypeError) != 0;
        break;
    case CJU_TYPE_HAS_ITER:
        *value = Py_TYPE(lease->sequence)->tp_iter != NULL;
        break;
    case CJU_SEQUENCE_CHECK:
        *value = PySequence_Check(lease->sequence) != 0;
        break;
    case CJU_FORMAT_NONITER:
        PyErr_Format(PyExc_TypeError, (const char *)output + 128,
                     Py_TYPE(lease->sequence)->tp_name);
        break;
    case CJU_FORMAT_FEW:
        PyErr_Format(PyExc_ValueError, (const char *)output + 128, (int)a, (int)b);
        break;
    case CJU_FORMAT_MANY:
        PyErr_Format(PyExc_ValueError, (const char *)output + 128, (int)a);
        break;
    case CJU_FAST_COPY:
        lease->item_order = 2;
        lease->frame->localsplus[lease->base + (int)c] = Py_NewRef(
            a == 1 ? PyTuple_GET_ITEM(lease->sequence, (Py_ssize_t)b)
                   : PyList_GET_ITEM(lease->sequence, (Py_ssize_t)b));
        lease->written++;
        break;
    case CJU_COMMIT:
        /* No foreign operation occurs during this transfer. Until here
         * sequence/iterator finalizers saw original_top; only now does the
         * completed opcode publish the successful results or error pop. */
        lease->owner->top = lease->base + (a ? (int)lease->count : 0);
        lease->written = 0; /* success owners now belong to the actual frame */
        lease->owner->pending_stack_owner = NULL;
        lease->owner->pending_stack_base = 0;
        lease->closed = 1;
        lease->permission = 2;
        break;
    }
    ctx->raised = PyErr_GetRaisedException();
    return 0;
}

static void cju_trace(uint64_t *r, uint64_t kind, uint64_t result,
                       const unsigned char *output, CJContext *ctx,
                       CJUnpackLease312 *lease) {
    const int owner_current = cju_observe_owner(lease);
    if (r[26] >= r[16]) {
        if (r[27] != UINT64_MAX) r[27]++;
        return; /* observer capacity never chooses a product branch */
    }
    uint64_t row[CJU_TRACE_WORDS] = {0};
    row[0] = kind; row[1] = result;
    for (unsigned i = 0; i < 7; i++) row[2+i] = cjp_get(output, i * 8);
    row[9] = (uintptr_t)ctx->raised; row[10] = (uintptr_t)lease->sequence;
    row[11] = (uintptr_t)lease->iterator; row[12] = (uintptr_t)lease->item;
    row[13] = lease->written; row[14] = lease->closed;
    row[15] = (uint64_t)lease->observed_top;
    row[16] = r[20]; row[17] = r[21]; row[18] = r[22]; row[19] = r[23];
    row[20] = r[24]; row[21] = r[25];
    row[22] = (uint64_t)lease->original_top;
    /* bit0: last observed pending lease; bit1: observation is current;
     * bit2: owner identity was lost. Width/capacity are unchanged. */
    row[23] = lease->observed_pending | ((uint64_t)owner_current << 1) |
              (lease->owner_lost << 2);
    memcpy((void *)(uintptr_t)(r[15] + r[26] * CJU_TRACE_BYTES), row, sizeof(row));
    r[26]++;
}

static uint64_t cju_refuse(uint64_t *r, CJContext *ctx,
                           CJUnpackLease312 *lease, uint64_t reason) {
    const int owner_current = cju_observe_owner(lease);
    if (PyErr_Occurred()) {
        if (!ctx->external) ctx->external = PyErr_GetRaisedException();
        else r[38] = (uintptr_t)PyErr_GetRaisedException();
    }
    r[3] = 3;
    r[29] = reason;
    r[31] = (uint64_t)lease->observed_top;
    r[32] = (uintptr_t)ctx->raised;
    r[33] = (uintptr_t)lease->sequence;
    r[34] = (uintptr_t)lease->iterator;
    r[35] = (uintptr_t)lease->item;
    r[36] = lease->written;
    r[37] = lease->observed_pending;
    r[39] = (uint64_t)lease->original_top;
    r[40] = (uint64_t)lease->base;
    r[41] = lease->item_order;
    r[42] = (uint64_t)owner_current;
    r[43] = lease->owner_lost;
    r[44] = (uintptr_t)lease->owner;
    r[45] = (uintptr_t)cj312_active_frame; /* address only, no dereference */
    lease->permission = 3;
    return CJ_REFUSAL;
}

/* Entry from the already-active C body driver, not an independent evaluator
 * activation. r[3] is consumed before first HIA entry. r[13] owns a separate
 * retained 256-byte lease so an interrupted primitive cannot lose C locals.
 * Parent port 242 must propagate semantic 1 using ctx->raised, and continue
 * its HIA exception table; it must never issue another POP of the sequence. */
uint64_t hia_cli_json_py312_unpack_run(uint64_t *r, uint64_t bytes) {
    if (!r || bytes != CJU_REQUEST_WORDS * 8 || !PyGILState_Check() || PyErr_Occurred() ||
            r[0] != CJU_MAGIC || r[1] != 31214 || r[2] != 242 || r[3] != 0 ||
            r[5] != sizeof(CJContext) || r[8] != 512 || r[12] > INT_MAX ||
            r[14] != CJU_LEASE_BYTES || r[17] != CJU_TRACE_BYTES ||
            !cjp_span((uintptr_t)r, bytes) ||
            !cjp_span(r[4], r[5]) || !cjp_span(r[7], r[8]) ||
            !cjp_span(r[13], r[14]) || !r[6] || !r[9] || !r[10] ||
            r[16] > UINT64_MAX / CJU_TRACE_BYTES ||
            (r[16] && !cjp_span(r[15], r[16] * CJU_TRACE_BYTES))) return CJ_REFUSAL;
    for (unsigned i = 18; i < 64; i++) if (r[i]) return CJ_REFUSAL;
    uint64_t addresses[5] = {(uintptr_t)r, r[4], r[7], r[13], r[15]};
    uint64_t sizes[5] = {bytes, r[5], r[8], r[14], r[16] * CJU_TRACE_BYTES};
    for (unsigned i = 0; i < 5; i++)
        for (unsigned j = i + 1; j < 5; j++)
            if (sizes[i] && sizes[j] && !cjp_disjoint(addresses[i], sizes[i], addresses[j], sizes[j]))
                return CJ_REFUSAL;
    CJContext *ctx = (CJContext *)(uintptr_t)r[4];
    if (ctx->magic != CJ_CTX || ctx->profile != 31214 || ctx->slot ||
            ctx->raised || ctx->external) return CJ_REFUSAL;
    PyGenObject *gen = (PyGenObject *)(uintptr_t)r[9];
    if (!cj312_active_frame || !PyThreadState_Get()->cframe)
        return CJ_REFUSAL;
    _PyInterpreterFrame *frame = cj312_operand_frame((PyObject *)gen);
    if (!frame || cj312_active_frame->pending_stack_owner ||
            (uintptr_t)frame->f_code != r[10] ||
            r[11] >= (uint64_t)Py_SIZE(frame->f_code) ||
            r[11] + 1 >= (uint64_t)Py_SIZE(frame->f_code) ||
            frame->prev_instr != _PyCode_CODE(frame->f_code) + r[11]) return CJ_REFUSAL;
    int top = *cj312_stack_top(frame);
    int64_t capacity = (int64_t)frame->f_code->co_nlocalsplus + frame->f_code->co_stacksize;
    if (top <= frame->f_code->co_nlocalsplus || !frame->localsplus[top - 1] ||
            r[12] > (uint64_t)(capacity - (top - 1)) ||
            frame->prev_instr->op.arg != (r[12] & 255)) return CJ_REFUSAL;
    unsigned opcode = frame->prev_instr->op.code;
    if (opcode != 92 && opcode != 161 && opcode != 166 && opcode != 167) return CJ_REFUSAL;
    unsigned char *state = (unsigned char *)(uintptr_t)r[7];
    unsigned char *storage = (unsigned char *)(uintptr_t)r[13];
    for (unsigned i = 0; i < 512; i++) if (state[i]) return CJ_REFUSAL;
    for (unsigned i = 0; i < CJU_LEASE_BYTES; i++) if (storage[i]) return CJ_REFUSAL;

    r[3] = 1;
    r[30] = (uint64_t)top;
    CJUnpackLease312 *lease = (CJUnpackLease312 *)storage;
    lease->magic = CJU_MAGIC; lease->permission = 1;
    lease->gen = gen; lease->frame = frame; lease->instruction = frame->prev_instr;
    lease->count = r[12];
    lease->owner = cj312_active_frame;
    lease->original_top = top;
    lease->observed_top = top;
    unsigned char input[128] = {0}, output[256] = {0};
    cjp_put(input, 0, CJU_MAGIC); cjp_put(input, 24, r[12]); cjp_put(input, 32, 31214);
    CJHiaEntry entry = (CJHiaEntry)(uintptr_t)r[6];
    while (1) {
        if (!cjp_increment(&r[20])) return cju_refuse(r, ctx, lease, 1);
        uint32_t status = entry(input, sizeof(input), output, sizeof(output), state, 512);
        if (!cjp_increment(&r[21]) || PyErr_Occurred()) return cju_refuse(r, ctx, lease, 2);
        cju_trace(r, 1, status, output, ctx, lease);
        if (lease->owner_lost) return cju_refuse(r, ctx, lease, 8);
        if (status <= 1) {
            if (!lease->closed || lease->sequence || lease->iterator || lease->item ||
                    lease->written || !!ctx->raised != (status == 1) || ctx->slot || ctx->external ||
                    lease->permission != 2 || lease->owner->pending_stack_owner ||
                    lease->owner->top != lease->base + (status == 0 ? (int)lease->count : 0) ||
                    cjp_get(state, 96) != 1 || r[24] != r[25])
                return cju_refuse(r, ctx, lease, 3);
            r[3] = 2; r[28] = status;
            r[31] = (uint64_t)lease->owner->top;
            r[32] = (uintptr_t)ctx->raised;
            return status;
        }
        if (status != 2 || cjp_get(output, 0) != CJU_MAGIC ||
                cjp_get(output, 8) != r[24] + 1 || r[24] == UINT64_MAX ||
                r[24] != r[25]) return cju_refuse(r, ctx, lease, 4);
        r[24] = cjp_get(output, 8);
        r[25] = r[24]; /* consume before any foreign primitive */
        if (!cjp_increment(&r[22])) return cju_refuse(r, ctx, lease, 5);
        uint64_t value = 0;
        uint64_t result = cju_leaf(ctx, lease, output, &value);
        if (!cjp_increment(&r[23])) return cju_refuse(r, ctx, lease, 6);
        cju_trace(r, 2, result, output, ctx, lease);
        if (lease->owner_lost) return cju_refuse(r, ctx, lease, 8);
        if (result != 0 || PyErr_Occurred()) return cju_refuse(r, ctx, lease, 7);
        memset(input, 0, sizeof(input));
        cjp_put(input, 0, CJU_MAGIC); cjp_put(input, 8, 1);
        cjp_put(input, 16, r[25]); cjp_put(input, 24, cjp_get(output, 16));
        cjp_put(input, 32, 31214); cjp_put(input, 40, ctx->raised != NULL);
        cjp_put(input, 48, value); cjp_put(input, 56, lease->instruction->op.code);
        cjp_put(input, 64, lease->kind); cjp_put(input, 72, lease->size);
        cjp_put(input, 80, ((_PyUnpackSequenceCache *)(lease->instruction + 1))->counter);
    }
}

uint64_t hia_cli_json_py312_unpack_layout(uint64_t *out, uint64_t words) {
    if (!out || words != 8) return CJ_REFUSAL;
    const uint64_t row[8] = {CJU_MAGIC, 31214, CJU_REQUEST_WORDS * 8,
        CJU_LEASE_BYTES, 512, 128, 256, CJU_TRACE_BYTES};
    memcpy(out, row, sizeof(row));
    return 0;
}

/* Concrete body port 242 wiring. It consumes the actual body permission
 * before the child owner, and transfers no object through Python. Parent
 * request words are from the already-admitted body image and code packet.
 * The complete body C dispatcher must select this function for port 242;
 * CALL/SEND and entry/monitoring remain separate unfinished ports.
 *
 * A semantic UNPACK failure returns protocol success here with the original
 * ctx->raised and the actual stack already shrunk by one. The parent HIA
 * continuation selects its existing exception table/traceback path. */
uint64_t hia_cli_json_py312_body_unpack_242(unsigned char *body,
                                           uint64_t body_bytes,
                                           uint64_t *r, uint64_t request_bytes) {
    if (!body || body_bytes != 1024 || !r || request_bytes != 512 ||
            !cjp_span((uintptr_t)body, body_bytes) ||
            !cjp_span((uintptr_t)r, request_bytes) ||
            !cjp_disjoint((uintptr_t)body, body_bytes, (uintptr_t)r, request_bytes) ||
            cjp_get(body, 0) != UINT64_C(0x32594442494c4348) || /* HCLIBDY2 */
            cjp_get(body, 8) != 22 || cjp_get(body, 24) != 1 ||
            cjp_get(body, 64) != 242 || cjp_get(body, 112) != 0 ||
            cjp_get(body, 48) || cjp_get(body, 320) ||
            r[0] != CJU_MAGIC || r[1] != 31214 || r[2] != 242 || r[3] ||
            r[9] != cjp_get(body, 120) || r[10] != cjp_get(body, 128) ||
            r[11] != cjp_get(body, 144) || r[12] != cjp_get(body, 208) ||
            cjp_get(body, 72) != r[9] || cjp_get(body, 80) != r[12] ||
            cjp_get(body, 88) != r[11] || cjp_get(body, 96) || cjp_get(body, 104))
        return CJ_REFUSAL;
    uint64_t sequence = cjp_get(body, 16);
    if (!sequence || cjp_get(body, 32) != sequence - 1) return CJ_REFUSAL;
    /* body cannot alias any writable child or context span. */
    if (!cjp_disjoint((uintptr_t)body, body_bytes, r[4], r[5]) ||
            !cjp_disjoint((uintptr_t)body, body_bytes, r[7], r[8]) ||
            !cjp_disjoint((uintptr_t)body, body_bytes, r[13], r[14]) ||
            (r[16] && (r[16] > UINT64_MAX / CJU_TRACE_BYTES ||
                !cjp_disjoint((uintptr_t)body, body_bytes, r[15], r[16] * CJU_TRACE_BYTES))))
        return CJ_REFUSAL;
    cjp_put(body, 32, sequence);
    cjp_put(body, 40, 242);
    uint64_t status = hia_cli_json_py312_unpack_run(r, request_bytes);
    if (status > 1 || r[3] != 2 || r[28] != status) {
        cjp_put(body, 112, 2); /* permanently refuse body replay */
        return CJ_REFUSAL;
    }
    CJContext *ctx = (CJContext *)(uintptr_t)r[4];
    if (ctx->slot || ctx->external || !!ctx->raised != (status == 1)) {
        cjp_put(body, 112, 2);
        return CJ_REFUSAL;
    }
    cjp_put(body, 48, (uintptr_t)ctx->raised);
    cjp_put(body, 168, r[31]);
    cjp_put(body, 320, 0);
    for (size_t at = 256; at < 320; at += 8) cjp_put(body, at, 0);
    return 0;
}
#else
uint64_t hia_cli_json_py312_unpack_run(uint64_t *r, uint64_t bytes) {
    (void)r; (void)bytes;
    return CJ_REFUSAL;
}
uint64_t hia_cli_json_py312_unpack_layout(uint64_t *out, uint64_t words) {
    (void)out; (void)words;
    return CJ_REFUSAL;
}
uint64_t hia_cli_json_py312_body_unpack_242(unsigned char *body,
                                           uint64_t body_bytes,
                                           uint64_t *r, uint64_t request_bytes) {
    (void)body; (void)body_bytes; (void)r; (void)request_bytes;
    return CJ_REFUSAL;
}
#endif
