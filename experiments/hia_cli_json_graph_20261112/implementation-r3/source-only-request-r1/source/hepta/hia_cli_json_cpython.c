/* Experimental mechanical CPython leaves for HIA JSON graph/sort control.
 *
 * The caller must hold the GIL.  This is not a Python extension entry point,
 * a sorter, a serializer, or an admission substitute for the HIA image.
 * Each invocation performs the single operation named by HIA.  In particular
 * no host loop chooses comparisons, moves runs, traverses a graph, or releases
 * a collection of references.  Restoration and release order are HIA plans.
 *
 * Supported *development ABI profiles*: CPython 3.12.14, 3.14.4, 3.14.10,
 * Linux x86-64, conventional GIL, no Py_TRACE_REFS.  Compilation/header and
 * runtime identities must be pinned independently by the development owner.
 * This source has not been compiled or executed.  Default CLI is unchanged.
 *
 * List-storage mechanisms follow PSF-licensed Objects/listobject.c.  The
 * original source and license are retained in the adjacent source checkpoint.
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#if !defined(__linux__) || !defined(__x86_64__) || defined(Py_GIL_DISABLED) || defined(Py_TRACE_REFS)
#error Unadmitted experimental CPython JSON ABI
#endif
#if PY_VERSION_HEX != 0x030c0ef0 && PY_VERSION_HEX != 0x030e04f0 && PY_VERSION_HEX != 0x030e0af0
#error Bind this shim to one retained exact CPython source/header profile
#endif

#define CJ_ABI UINT64_C(0x31464c4a43414948) /* HIA CJLF1, little endian */
#define CJ_CTX UINT64_C(0x3158544a43414948)
#define CJ_REFUSAL UINT64_C(0xfffffffd)
#define CJ_TEMP_WORDS 256

enum {
    CJ_FACTS=1, CJ_TUPLE_ITEM=2, CJ_RICH_BOOL=3, CJ_RICH_SLOT=4,
    CJ_TRUTH_SLOT=5, CJ_DROP_SLOT=6, CJ_INCREF=7, CJ_DETACH=8,
    CJ_MUTATED=9, CJ_ERROR_TEXT=10, CJ_RESTORE=11, CJ_DROP_DISPLACED=12,
    CJ_FREE_DISPLACED=13, CJ_TEMP_FREE=14, CJ_TEMP_ALLOC=15, CJ_PROFILE=16,
    CJ_IDENTITIES=17, CJ_UNICODE_POINT=18, CJ_SLOT=19, CJ_NO_MEMORY=20,
    CJ_DECREF=21, CJ_GET_ITER=22, CJ_ITER_NEXT=23, CJ_SEQUENCE_FAST=24,
    CJ_MAPPING_ITEMS=25, CJ_RAW_SIZE=26, CJ_RAW_ITEM=27,
    CJ_RECURSION_ENTER=28, CJ_RECURSION_LEAVE=29, CJ_GET_ATTR=30,
    CJ_CALL_ZERO=31, CJ_CALL_ONE=32, CJ_ISINSTANCE=33,
    CJ_OBJECT_TRUTH=34, CJ_ERROR_NOTE=35, CJ_RAW_LONG_DIGIT=36,
    CJ_LONG_POLICY=37, CJ_RAW_UNICODE=38, CJ_FLOAT_BITS=39,
    CJ_REPLACE_ERROR=40, CJ_TAKE_SLOT=41,
    CJ_SAVE_ERROR=42, CJ_RESTORE_ERROR=43, CJ_MOVE_SLOT=44,
    CJ_DROP_CELL=45, CJ_CELL_INFO=46, CJ_FORMAT_OBJECT=47,
    CJ_FORMAT_INDEX=48, CJ_FORMAT_KEY=49, CJ_GET_OPTIONAL_ATTRIBUTE=50,
    CJ_EMPTY_LIST=51, CJ_SET_ATTRIBUTE=52, CJ_LIST_APPEND=53,
    CJ_SET_CONTEXT=54, CJ_RAW_KIND=55, CJ_DICT_NEW=56,
    CJ_POINTER_ID=57, CJ_DICT_CONTAINS=58, CJ_DICT_SET=59,
    CJ_DICT_DELETE=60, CJ_INTERN_NOTES_NAME=61,
    CJ_MOVE_SLOT_TO=62, CJ_INCREF_TO=63, CJ_DROP_FROM=64,
    CJ_TYPE_NAME_ERROR=65, CJ_RECURSION_ENTER_TO=66, CJ_RECURSION_LEAVE_FROM=67
};

typedef struct {
    uint64_t magic, phase, profile;
    PyListObject *list;                 /* borrowed from the graph owner */
    Py_ssize_t saved_size, saved_allocated;
    PyObject **saved_items;
    Py_ssize_t displaced_size;
    PyObject **displaced_items;
    PyObject **temporary;
    Py_ssize_t temporary_words;
    PyObject *slot;                     /* one owned primitive result */
    PyObject *raised;                   /* owned between named leaves */
    PyObject *external;                 /* owned while Python exits except */
    PyObject *cells[8];                 /* individual HIA-named owned cells */
    PyObject *temporary_array[CJ_TEMP_WORDS];
} CJContext;

typedef struct {
    uint64_t abi, op, context, a, b, c, d, e;
    uint64_t raised;                    /* borrowed audit word at marker 1 */
    uint64_t result[8];
    uint64_t captured;                  /* borrowed audit word; ctx owns it */
    uint64_t marker;
    uint64_t reserved[5];
} CJFrame;

_Static_assert(sizeof(void *) == 8 && sizeof(Py_ssize_t) == 8, "64-bit ABI");
_Static_assert(sizeof(CJFrame) == 192, "fixed transaction wire");
_Static_assert(offsetof(PyListObject, ob_item) == 24, "list prefix");
_Static_assert(offsetof(PyListObject, allocated) == 32, "list allocation field");

static uint64_t profile(void) {
#if PY_VERSION_HEX == 0x030c0ef0
    return 31214;
#elif PY_VERSION_HEX == 0x030e04f0
    return 31404;
#else
    return 31410;
#endif
}

/* These metadata helpers never call a user attribute or comparison. */
static void facts(PyObject *object, uint64_t *out) {
    out[0] = (uintptr_t)Py_TYPE(object);
    out[1] = Py_IS_TYPE(object, &PyTuple_Type);
    if (out[1]) {
        out[2] = (uint64_t)PyTuple_GET_SIZE(object);
        out[3] = out[2] ? (uintptr_t)PyTuple_GET_ITEM(object, 0) : 0;
    }
    out[4] = (uintptr_t)Py_TYPE(object)->tp_richcompare;
    if (Py_IS_TYPE(object, &PyUnicode_Type) && PyUnicode_KIND(object) == PyUnicode_1BYTE_KIND) {
        out[5] = 1;
        out[6] = (uint64_t)PyUnicode_GET_LENGTH(object);
        out[7] = (uintptr_t)PyUnicode_1BYTE_DATA(object);
    }
    else if (Py_IS_TYPE(object, &PyLong_Type) && _PyLong_IsCompact((PyLongObject *)object)) {
        out[5] = 2;
        out[6] = (uint64_t)(int64_t)_PyLong_CompactValue((PyLongObject *)object);
    }
    else if (Py_IS_TYPE(object, &PyFloat_Type)) {
        double value = PyFloat_AS_DOUBLE(object);
        out[5] = 3;
        memcpy(&out[6], &value, 8);
    }
}

/* ABI facts are mechanical and do not initialize or acquire any object. */
uint64_t hia_cli_json_leaf_layout(uint64_t *out, uint64_t words) {
    if (out == NULL || words != 8 || !PyGILState_Check()) return CJ_REFUSAL;
    out[0] = CJ_ABI;
    out[1] = sizeof(CJFrame);
    out[2] = sizeof(CJContext);
    out[3] = profile();
    out[4] = PY_VERSION_HEX;
    out[5] = CJ_TEMP_WORDS;
    out[6] = PyLong_SHIFT;
    out[7] = sizeof(digit);
    return 0;
}

uint64_t hia_cli_json_leaf_init(void *storage, uint64_t size) {
    if (storage == NULL || size != sizeof(CJContext) || !PyGILState_Check()) return CJ_REFUSAL;
    CJContext *ctx = (CJContext *)storage;
    memset(ctx, 0, sizeof(*ctx));
    ctx->magic = CJ_CTX;
    ctx->profile = profile();
    ctx->temporary = ctx->temporary_array;
    ctx->temporary_words = CJ_TEMP_WORDS;
    return 0;
}

/* No buffer copies and no hidden extra object references.  The HIA image
 * mutates the actual saved ob_item array while the user-visible list is empty.
 */
uint64_t hia_cli_json_leaf_views(void *storage, uint64_t size, uint64_t *out) {
    if (storage == NULL || size != sizeof(CJContext) || out == NULL || !PyGILState_Check()) return CJ_REFUSAL;
    CJContext *ctx = (CJContext *)storage;
    if (ctx->magic != CJ_CTX) return CJ_REFUSAL;
    out[0] = (uintptr_t)ctx->temporary;
    out[1] = ctx->temporary_words < 0 ? 0 : (uint64_t)ctx->temporary_words * 8;
    out[2] = (uintptr_t)ctx->saved_items;
    out[3] = ctx->saved_size < 0 ? 0 : (uint64_t)ctx->saved_size * 8;
    out[4] = ctx->phase;
    out[5] = (uintptr_t)ctx->slot;
    out[6] = ctx->displaced_size < 0 ? 0 : (uint64_t)ctx->displaced_size;
    out[7] = (uintptr_t)ctx->displaced_items;
    out[8] = (uintptr_t)ctx->raised;
    return 0;
}

/* Acquisition only: no cleanup while the adapter's Python except is active.
 * The next HIA abort entry is driven after that except has restored the
 * caller's handled exception.  Ownership is recorded in C before returning.
 */
uint64_t hia_cli_json_capture_external(void *storage, PyObject *error) {
    if (!storage || !error || !PyGILState_Check()) return CJ_REFUSAL;
    CJContext *ctx = storage;
    if (ctx->magic != CJ_CTX || ctx->external || !PyExceptionInstance_Check(error)) return CJ_REFUSAL;
    ctx->external = Py_NewRef(error);
    return 0;
}

uint64_t hia_cli_json_raise_pending(void *storage) {
    if (!storage || !PyGILState_Check()) return CJ_REFUSAL;
    CJContext *ctx = storage;
    if (ctx->magic != CJ_CTX || !ctx->raised || ctx->slot || ctx->external ||
            ctx->cells[0] || ctx->cells[1] || ctx->cells[2] || ctx->cells[3] ||
            ctx->cells[4] || ctx->cells[5] || ctx->cells[6] || ctx->cells[7] ||
            (ctx->phase != 0 && ctx->phase != 3)) return CJ_REFUSAL;
    PyObject *error = ctx->raised;
    ctx->raised = NULL;
    PyErr_SetRaisedException(error);
    return 0; /* PYFUNCTYPE propagates the actual pending exception object */
}

/* A refusal denotes a broken private ABI, never an ordinary-object fallback.
 * The pending raised exception is installed only around the named leaf.
 * No handled-exception state is changed, and no synthetic raise is used.
 */
uint64_t hia_cli_json_leaf(CJFrame *frame) {
    if (frame == NULL || frame->abi != CJ_ABI || frame->context == 0 || !PyGILState_Check()) return CJ_REFUSAL;
    CJContext *ctx = (CJContext *)(uintptr_t)frame->context;
    if (ctx->magic != CJ_CTX || ctx->profile != profile() || frame->marker != 0) return CJ_REFUSAL;
    if (frame->reserved[0] || frame->reserved[1] || frame->reserved[2] || frame->reserved[3] || frame->reserved[4]) return CJ_REFUSAL;
    if (frame->op < CJ_FACTS || frame->op > CJ_RECURSION_LEAVE_FROM) return CJ_REFUSAL;
    memset(frame->result, 0, sizeof(frame->result));
    PyObject *incoming = ctx->raised;
    ctx->raised = NULL;
    frame->raised = (uintptr_t)incoming;
    frame->marker = 1;
    PyErr_SetRaisedException(incoming); /* steals, including NULL */
    PyObject *a = (PyObject *)(uintptr_t)frame->a;
    PyObject *b = (PyObject *)(uintptr_t)frame->b;
    switch (frame->op) {
    case CJ_FACTS:
        if (!a) goto abi_error;
        facts(a, frame->result);
        break;
    case CJ_TUPLE_ITEM:
        if (!a || !PyTuple_Check(a) || frame->b >= (uint64_t)PyTuple_GET_SIZE(a)) goto abi_error;
        frame->result[0] = (uintptr_t)PyTuple_GET_ITEM(a, (Py_ssize_t)frame->b);
        break;
    case CJ_RICH_BOOL:
        if (!a || !b || frame->c > Py_GE) goto abi_error;
        frame->result[0] = (uint64_t)(int64_t)PyObject_RichCompareBool(a, b, (int)frame->c);
        break;
    case CJ_RICH_SLOT: {
        if (!a || !b || !frame->c || ctx->slot != NULL) goto abi_error;
        /* Repeat the no-callback slot identity check at the actual call.
         * A change means HIA must select the same safe-comparison fallback.
         */
        if ((uintptr_t)Py_TYPE(a)->tp_richcompare != frame->c) {
            frame->result[0] = 4; /* changed slot; no comparison occurred */
            break;
        }
        richcmpfunc function = (richcmpfunc)(uintptr_t)frame->c;
        ctx->slot = function(a, b, Py_LT);
        frame->result[1] = (uintptr_t)ctx->slot;
        frame->result[0] = ctx->slot == NULL ? 5 :
            ctx->slot == Py_NotImplemented ? 0 :
            ctx->slot == Py_False ? 1 : ctx->slot == Py_True ? 2 : 3;
        break;
    }
    case CJ_TRUTH_SLOT:
        if (!ctx->slot) goto abi_error;
        frame->result[0] = (uint64_t)(int64_t)PyObject_IsTrue(ctx->slot);
        break;
    case CJ_DROP_SLOT: {
        if (!ctx->slot) goto abi_error;
        PyObject *value = ctx->slot;
        ctx->slot = NULL; /* consume permission before a possible finalizer */
        Py_DECREF(value);
        break;
    }
    case CJ_INCREF:
        if (!a) goto abi_error;
        Py_INCREF(a);
        frame->result[0] = (uintptr_t)a;
        break;
    case CJ_DETACH:
        if (ctx->phase != 0 || !a || !PyList_Check(a)) goto abi_error;
        ctx->list = (PyListObject *)a;
        ctx->saved_size = PyList_GET_SIZE(a);
        ctx->saved_allocated = ctx->list->allocated;
        ctx->saved_items = ctx->list->ob_item;
        Py_SET_SIZE(ctx->list, 0);
        ctx->list->ob_item = NULL;
        ctx->list->allocated = -1;
        ctx->phase = 1;
        frame->result[0] = (uint64_t)ctx->saved_size;
        frame->result[1] = (uintptr_t)ctx->saved_items;
        break;
    case CJ_MUTATED:
        if (ctx->phase != 1) goto abi_error;
        frame->result[0] = ctx->list->allocated != -1;
        break;
    case CJ_ERROR_TEXT:
        /* HIA supplies the exception object and full NUL-terminated text.
         * They must be pinned or owned by the surrounding graph operation.
         */
        if (!a || !frame->b || frame->c == 0 || ((char *)(uintptr_t)frame->b)[frame->c - 1] != '\0') goto abi_error;
        PyErr_SetString(a, (char *)(uintptr_t)frame->b);
        break;
    case CJ_RESTORE:
        if (ctx->phase != 1) goto abi_error;
        ctx->displaced_items = ctx->list->ob_item;
        ctx->displaced_size = PyList_GET_SIZE(ctx->list);
        Py_SET_SIZE(ctx->list, ctx->saved_size);
        ctx->list->ob_item = ctx->saved_items;
        ctx->list->allocated = ctx->saved_allocated;
        ctx->phase = 2;
        frame->result[0] = (uint64_t)ctx->displaced_size;
        frame->result[1] = (uintptr_t)ctx->displaced_items;
        break;
    case CJ_DROP_DISPLACED: {
        if (ctx->phase != 2 || !ctx->displaced_items || ctx->displaced_size <= 0 ||
                frame->a != (uint64_t)ctx->displaced_size - 1) goto abi_error;
        /* HIA chooses the reverse index.  Consume before entering __del__. */
        PyObject *value = ctx->displaced_items[--ctx->displaced_size];
        ctx->displaced_items[ctx->displaced_size] = NULL;
        Py_XDECREF(value);
        break;
    }
    case CJ_FREE_DISPLACED:
        if (ctx->phase != 2 || (ctx->displaced_items && ctx->displaced_size != 0)) goto abi_error;
        PyMem_Free(ctx->displaced_items);
        ctx->displaced_items = NULL;
        ctx->displaced_size = 0;
        ctx->phase = 3;
        break;
    case CJ_TEMP_FREE:
        if (ctx->temporary != ctx->temporary_array) PyMem_Free(ctx->temporary);
        ctx->temporary = NULL;
        ctx->temporary_words = 0;
        break;
    case CJ_TEMP_ALLOC:
        if (ctx->temporary != NULL || frame->a == 0 || frame->a > (uint64_t)PY_SSIZE_T_MAX / 8) goto abi_error;
        ctx->temporary = PyMem_Malloc((size_t)frame->a * 8);
        if (ctx->temporary) ctx->temporary_words = (Py_ssize_t)frame->a;
        frame->result[0] = (uintptr_t)ctx->temporary;
        break;
    case CJ_PROFILE:
        frame->result[0] = profile();
        frame->result[1] = PY_VERSION_HEX;
        break;
    case CJ_IDENTITIES:
        frame->result[0] = (uintptr_t)&PyTuple_Type;
        frame->result[1] = (uintptr_t)&PyUnicode_Type;
        frame->result[2] = (uintptr_t)&PyLong_Type;
        frame->result[3] = (uintptr_t)&PyFloat_Type;
        frame->result[4] = (uintptr_t)PyExc_ValueError;
        frame->result[5] = (uintptr_t)PyExc_TypeError;
        frame->result[6] = (uintptr_t)Py_None;
        frame->result[7] = (uintptr_t)Py_NotImplemented;
        break;
    case CJ_UNICODE_POINT:
        if (!a || !PyUnicode_Check(a) || frame->b >= (uint64_t)PyUnicode_GET_LENGTH(a)) goto abi_error;
        frame->result[0] = PyUnicode_READ(PyUnicode_KIND(a), PyUnicode_DATA(a), (Py_ssize_t)frame->b);
        break;
    case CJ_SLOT:
        if (!a) goto abi_error;
        frame->result[0] = (uintptr_t)Py_TYPE(a)->tp_richcompare;
        break;
    case CJ_NO_MEMORY:
        PyErr_NoMemory();
        break;
    case CJ_DECREF:
        if (!a) goto abi_error;
        Py_DECREF(a);
        break;
    case CJ_GET_ITER:
        if (!a || ctx->slot) goto abi_error;
        ctx->slot = PyObject_GetIter(a);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_ITER_NEXT:
        if (!a || ctx->slot) goto abi_error;
        ctx->slot = PyIter_Next(a);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_SEQUENCE_FAST:
        if (!a || !frame->b || ctx->slot) goto abi_error;
        ctx->slot = PySequence_Fast(a, (char *)(uintptr_t)frame->b);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_MAPPING_ITEMS:
        if (!a || ctx->slot) goto abi_error;
        ctx->slot = PyMapping_Items(a);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_RAW_SIZE:
        if (!a) goto abi_error;
        if (frame->b == 1 && PyList_Check(a)) frame->result[0] = (uint64_t)PyList_GET_SIZE(a);
        else if (frame->b == 2 && PyTuple_Check(a)) frame->result[0] = (uint64_t)PyTuple_GET_SIZE(a);
        else if (frame->b == 3 && PyDict_Check(a)) frame->result[0] = (uint64_t)PyDict_Size(a);
        else goto abi_error;
        break;
    case CJ_RAW_ITEM:
        if (!a) goto abi_error;
        if (frame->c == 1 && PyList_Check(a) && frame->b < (uint64_t)PyList_GET_SIZE(a)) frame->result[0] = (uintptr_t)PyList_GET_ITEM(a, (Py_ssize_t)frame->b);
        else if (frame->c == 2 && PyTuple_Check(a) && frame->b < (uint64_t)PyTuple_GET_SIZE(a)) frame->result[0] = (uintptr_t)PyTuple_GET_ITEM(a, (Py_ssize_t)frame->b);
        else goto abi_error;
        break;
    case CJ_RECURSION_ENTER:
        if (!frame->a) goto abi_error;
        frame->result[0] = (uint64_t)(int64_t)Py_EnterRecursiveCall((char *)(uintptr_t)frame->a);
        break;
    case CJ_RECURSION_LEAVE:
        Py_LeaveRecursiveCall();
        break;
    case CJ_GET_ATTR:
        if (!a || !b || ctx->slot) goto abi_error;
        ctx->slot = PyObject_GetAttr(a, b);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_CALL_ZERO:
        if (!a || ctx->slot) goto abi_error;
        ctx->slot = PyObject_CallNoArgs(a);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_CALL_ONE:
        if (!a || !b || ctx->slot) goto abi_error;
        ctx->slot = PyObject_CallOneArg(a, b);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_ISINSTANCE:
        if (!a || !b) goto abi_error;
        frame->result[0] = (uint64_t)(int64_t)PyObject_IsInstance(a, b);
        break;
    case CJ_OBJECT_TRUTH:
        if (!a) goto abi_error;
        frame->result[0] = (uint64_t)(int64_t)PyObject_IsTrue(a);
        break;
    case CJ_ERROR_NOTE:
        /* Deliberately not an implementation of _PyErr_FormatNote.  The graph
         * must issue its actual versioned binding/call plan, including repr.
         */
        goto abi_error;
    case CJ_RAW_LONG_DIGIT:
        if (!a || !PyLong_Check(a) || frame->b >= (((PyLongObject *)a)->long_value.lv_tag >> 3)) goto abi_error;
        frame->result[0] = ((PyLongObject *)a)->long_value.ob_digit[frame->b];
        break;
    case CJ_LONG_POLICY:
        if (!a || !PyLong_Check(a)) goto abi_error;
        frame->result[0] = ((PyLongObject *)a)->long_value.lv_tag >> 3;
        frame->result[1] = ((PyLongObject *)a)->long_value.lv_tag & 3;
        frame->result[2] = PyLong_SHIFT;
        /* Runtime digit-limit and _pylong policy are separate observed leaves;
         * no guessed internal interpreter layout is read here.
         */
        break;
    case CJ_RAW_UNICODE:
        if (!a || !PyUnicode_Check(a)) goto abi_error;
        frame->result[0] = PyUnicode_GET_LENGTH(a);
        frame->result[1] = PyUnicode_KIND(a);
        frame->result[2] = (uintptr_t)PyUnicode_DATA(a);
        break;
    case CJ_FLOAT_BITS: {
        if (!a || !PyFloat_Check(a)) goto abi_error;
        double value = PyFloat_AS_DOUBLE(a);
        memcpy(&frame->result[0], &value, 8);
        break;
    }
    case CJ_REPLACE_ERROR:
        /* The adapter has INCREF'd the actual caught external exception and
         * has already left its Python except block before HIA cleanup.
         */
        if (!ctx->external) goto abi_error;
        a = ctx->external;
        ctx->external = NULL;
        PyErr_SetRaisedException(a); /* consumes precisely that owned pointer */
        break;
    case CJ_TAKE_SLOT:
        if (!ctx->slot) goto abi_error;
        frame->result[0] = (uintptr_t)ctx->slot;
        ctx->slot = NULL; /* transfer exactly one owned reference to HIA */
        break;
    case CJ_SAVE_ERROR:
        if (frame->a >= 8 || ctx->cells[frame->a]) goto abi_error;
        ctx->cells[frame->a] = PyErr_GetRaisedException();
        frame->result[0] = (uintptr_t)ctx->cells[frame->a];
        break;
    case CJ_RESTORE_ERROR: {
        if (frame->a >= 8 || !ctx->cells[frame->a] ||
                !PyExceptionInstance_Check(ctx->cells[frame->a])) goto abi_error;
        PyObject *error = ctx->cells[frame->a];
        ctx->cells[frame->a] = NULL;
        PyErr_SetRaisedException(error);
        break;
    }
    case CJ_MOVE_SLOT:
        if (frame->a >= 8 || ctx->cells[frame->a] || !ctx->slot) goto abi_error;
        ctx->cells[frame->a] = ctx->slot;
        ctx->slot = NULL;
        frame->result[0] = (uintptr_t)ctx->cells[frame->a];
        break;
    case CJ_DROP_CELL: {
        if (frame->a >= 8 || !ctx->cells[frame->a]) goto abi_error;
        PyObject *value = ctx->cells[frame->a];
        ctx->cells[frame->a] = NULL;
        Py_DECREF(value);
        break;
    }
    case CJ_CELL_INFO:
        if (frame->a >= 8) goto abi_error;
        frame->result[0] = (uintptr_t)ctx->cells[frame->a];
        frame->result[1] = ctx->cells[frame->a] && PyList_Check(ctx->cells[frame->a]);
        break;
    case CJ_FORMAT_OBJECT:
        if (!frame->a || !b || ctx->slot) goto abi_error;
        ctx->slot = PyUnicode_FromFormat((const char *)(uintptr_t)frame->a, b);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_FORMAT_INDEX:
        if (!frame->a || !b || frame->c > PY_SSIZE_T_MAX || ctx->slot) goto abi_error;
        ctx->slot = PyUnicode_FromFormat((const char *)(uintptr_t)frame->a,
                                        b, (Py_ssize_t)frame->c);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_FORMAT_KEY:
        if (!frame->a || !b || !frame->c || ctx->slot) goto abi_error;
        ctx->slot = PyUnicode_FromFormat((const char *)(uintptr_t)frame->a,
                                        b, (PyObject *)(uintptr_t)frame->c);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_GET_OPTIONAL_ATTRIBUTE:
        if (!a || !b || ctx->slot) goto abi_error;
#if PY_VERSION_HEX >= 0x030d0000
        frame->result[0] = (uint64_t)(int64_t)PyObject_GetOptionalAttr(a, b, &ctx->slot);
        frame->result[1] = (uintptr_t)ctx->slot;
#else
        /* The 3.12 Python encoder does not have the C encoder's error-note
         * step.  Do not substitute a guessed Python getattr transaction. */
        goto abi_error;
#endif
        break;
    case CJ_EMPTY_LIST:
        if (ctx->slot) goto abi_error;
        ctx->slot = PyList_New(0);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_SET_ATTRIBUTE:
        if (!a || !b || !frame->c) goto abi_error;
        frame->result[0] = (uint64_t)(int64_t)PyObject_SetAttr(a, b, (PyObject *)(uintptr_t)frame->c);
        break;
    case CJ_LIST_APPEND:
        if (!a || !PyList_Check(a) || !b) goto abi_error;
        frame->result[0] = (uint64_t)(int64_t)PyList_Append(a, b);
        break;
    case CJ_SET_CONTEXT: {
        if (frame->a >= 8 || frame->b >= 8 || frame->a == frame->b ||
                !ctx->cells[frame->a] || !ctx->cells[frame->b] ||
                !PyExceptionInstance_Check(ctx->cells[frame->a]) ||
                !PyExceptionInstance_Check(ctx->cells[frame->b])) goto abi_error;
        PyObject *previous = ctx->cells[frame->b];
        ctx->cells[frame->b] = NULL; /* consumed before old-context DECREF */
        PyException_SetContext(ctx->cells[frame->a], previous);
        break;
    }
    case CJ_RAW_KIND:
        if (!a) goto abi_error;
        frame->result[0] =
            (PyUnicode_Check(a) ? UINT64_C(1) : 0) |
            (PyLong_Check(a) ? UINT64_C(2) : 0) |
            (PyFloat_Check(a) ? UINT64_C(4) : 0) |
            (PyList_Check(a) ? UINT64_C(8) : 0) |
            (PyTuple_Check(a) ? UINT64_C(16) : 0) |
            (PyDict_Check(a) ? UINT64_C(32) : 0) |
            (a == Py_None ? UINT64_C(64) : 0) |
            (a == Py_True ? UINT64_C(128) : 0) |
            (a == Py_False ? UINT64_C(256) : 0);
        frame->result[1] = (uintptr_t)Py_TYPE(a);
        frame->result[2] = (uintptr_t)Py_TYPE(a)->tp_name;
        break;
    case CJ_DICT_NEW:
        if (ctx->slot) goto abi_error;
        ctx->slot = PyDict_New();
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_POINTER_ID:
        if (!a || ctx->slot) goto abi_error;
        ctx->slot = PyLong_FromVoidPtr(a);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_DICT_CONTAINS:
        if (!a || !PyDict_Check(a) || !b) goto abi_error;
        frame->result[0] = (uint64_t)(int64_t)PyDict_Contains(a, b);
        break;
    case CJ_DICT_SET:
        if (!a || !PyDict_Check(a) || !b || !frame->c) goto abi_error;
        frame->result[0] = (uint64_t)(int64_t)PyDict_SetItem(a, b, (PyObject *)(uintptr_t)frame->c);
        break;
    case CJ_DICT_DELETE:
        if (!a || !PyDict_Check(a) || !b) goto abi_error;
        frame->result[0] = (uint64_t)(int64_t)PyDict_DelItem(a, b);
        break;
    case CJ_INTERN_NOTES_NAME:
        /* Development setup only, before an exception transaction.  The
         * actual graph binding must pin the resulting interned name and
         * prove its identity against the admitted runtime's identifier. */
        if (ctx->slot || PyErr_Occurred()) goto abi_error;
        ctx->slot = PyUnicode_InternFromString("__notes__");
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_MOVE_SLOT_TO: {
        if (!frame->a || !frame->b || !frame->c || (frame->c & (frame->c - 1)) ||
                (frame->a & 7) || (frame->b & 7) || !ctx->slot) goto abi_error;
        uint64_t *destination = (uint64_t *)(uintptr_t)frame->a;
        uint64_t *flags = (uint64_t *)(uintptr_t)frame->b;
        if (*destination || (*flags & frame->c)) goto abi_error;
        *destination = (uintptr_t)ctx->slot;
        *flags |= frame->c;
        ctx->slot = NULL;
        frame->result[0] = *destination;
        break;
    }
    case CJ_INCREF_TO: {
        if (!a || !frame->b || !frame->c || !frame->d || (frame->d & (frame->d - 1)) ||
                (frame->b & 7) || (frame->c & 7)) goto abi_error;
        uint64_t *destination = (uint64_t *)(uintptr_t)frame->b;
        uint64_t *flags = (uint64_t *)(uintptr_t)frame->c;
        if (*destination || (*flags & frame->d)) goto abi_error;
        Py_INCREF(a);
        *destination = (uintptr_t)a;
        *flags |= frame->d;
        frame->result[0] = *destination;
        break;
    }
    case CJ_DROP_FROM: {
        if (!frame->a || !frame->b || !frame->c || (frame->c & (frame->c - 1)) ||
                (frame->a & 7) || (frame->b & 7)) goto abi_error;
        uint64_t *destination = (uint64_t *)(uintptr_t)frame->a;
        uint64_t *flags = (uint64_t *)(uintptr_t)frame->b;
        if (!*destination || !(*flags & frame->c)) goto abi_error;
        PyObject *value = (PyObject *)(uintptr_t)*destination;
        *destination = 0;
        *flags &= ~frame->c;
        Py_DECREF(value);
        break;
    }
    case CJ_TYPE_NAME_ERROR:
        if (!a || !frame->b || !frame->c) goto abi_error;
        /* HIA supplies and validates the fixed original format literal. */
        PyErr_Format(a, (const char *)(uintptr_t)frame->b,
                     Py_TYPE((PyObject *)(uintptr_t)frame->c)->tp_name);
        break;
    case CJ_RECURSION_ENTER_TO: {
        if (!frame->a || !frame->b || (frame->b & 7) || !frame->c ||
                (frame->c & (frame->c - 1))) goto abi_error;
        uint64_t *flags = (uint64_t *)(uintptr_t)frame->b;
        if (*flags & frame->c) goto abi_error;
        int rc = Py_EnterRecursiveCall((const char *)(uintptr_t)frame->a);
        if (rc == 0) *flags |= frame->c;
        frame->result[0] = (uint64_t)(int64_t)rc;
        break;
    }
    case CJ_RECURSION_LEAVE_FROM: {
        if (!frame->a || (frame->a & 7) || !frame->b ||
                (frame->b & (frame->b - 1))) goto abi_error;
        uint64_t *flags = (uint64_t *)(uintptr_t)frame->a;
        if (!(*flags & frame->b)) goto abi_error;
        *flags &= ~frame->b;
        Py_LeaveRecursiveCall();
        break;
    }
    default:
        goto abi_error;
    }
    ctx->raised = PyErr_GetRaisedException();
    frame->captured = (uintptr_t)ctx->raised;
    frame->marker = 2;
    return 0;

abi_error:
    /* Do not fabricate an ordinary JSON error or erase a pending real one. */
    ctx->raised = PyErr_GetRaisedException();
    frame->captured = (uintptr_t)ctx->raised;
    frame->marker = 2;
    return CJ_REFUSAL;
}
