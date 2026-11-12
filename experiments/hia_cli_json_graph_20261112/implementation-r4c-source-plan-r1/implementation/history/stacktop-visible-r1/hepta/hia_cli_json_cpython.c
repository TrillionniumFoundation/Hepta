/* Experimental mechanical CPython leaves for HIA JSON graph/sort control.
 *
 * The caller must hold the GIL.  This is not a Python extension entry point,
 * a sorter, a serializer, or an admission substitute for the HIA image.
 * Each invocation performs the operation named by HIA.  No host loop chooses
 * JSON comparisons, moves sort runs, or traverses the JSON graph.  HIA chooses
 * graph/sort restoration and reference-release plans.  The explicitly named
 * 3.12 CALL/frame leaves retain CPython's runtime argument-binding and frame
 * cleanup loops; those are not claimed as HIA-owned object-runtime semantics.
 *
 * Supported *development ABI profiles*: CPython 3.12.14, 3.14.4, 3.14.10,
 * Linux x86-64, conventional GIL, no Py_TRACE_REFS.  Compilation/header and
 * runtime identities must be pinned independently by the development owner.
 * This source has not been compiled or executed.  Default CLI is unchanged.
 *
 * List-storage mechanisms follow PSF-licensed Objects/listobject.c.  The
 * original source and license are retained in the adjacent source checkpoint.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#define PY_SSIZE_T_CLEAN
#define Py_BUILD_CORE
#include <Python.h>
#include "internal/pycore_interp.h"
#include "internal/pycore_long.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <dlfcn.h>
#if PY_VERSION_HEX == 0x030c0ef0
#include "internal/pycore_frame.h"
#include "internal/pycore_pyerrors.h"
#endif

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
    CJ_TYPE_NAME_ERROR=65, CJ_RECURSION_ENTER_TO=66, CJ_RECURSION_LEAVE_FROM=67,
    CJ_UNICODE_FROM_DATA=68, CJ_LONG_STORAGE=69,
    CJ_LONG_LIMIT=70, CJ_IMPORT_NAME=71, CJ_CALL_NAMED_ONE=72,
    CJ_LONG_LIMIT_ERROR=73, CJ_COPY_CELL_TO_SLOT=74,
    CJ_FRESH_ASCII_FROM_DATA=75, CJ_ESCAPE_TOO_LONG=76,
    CJ_PY312_COMPARE_LOCALS=77, CJ_PY312_TRUTH_CONSUME=78,
    CJ_NEWREF_SLOT=79, CJ_PY312_CALL_LOCAL_ONE=80,
    CJ_PY312_CALL_LOCAL_TWO=81, CJ_PY312_LOAD_GLOBAL=82,
    CJ_NUMBER_ADD=83, CJ_RAISE_SLOT=84, CJ_UNICODE_JOIN=85,
    CJ_PY312_CALL_OWNED=86, CJ_PY312_APPEND_OWNED=87,
    CJ_PY312_LIST_PREALLOCATE=88, CJ_PY312_LIST_TRIM=89,
    CJ_LENGTH_HINT=90, CJ_BOUND_ITER_NEXT=91, CJ_CLEAR_STOP_ITERATION=92,
    CJ_MOVE_CELL_TO_SLOT=93, CJ_PY312_JOIN_LOCAL=94,
    CJ_PY312_FRAME_INFO=95, CJ_PY312_FRAME_CLEAR=96,
    CJ_PY312_FRAME_TRACEBACK=97, CJ_PY312_FRAME_STORE=98,
    CJ_PY312_FRAME_LOAD=99,
    CJ_PY312_STACK_POP=100, CJ_PY312_STACK_PUSH_SLOT=101,
    CJ_PY312_STACK_PUSH_NULL=102, CJ_PY312_STACK_PEEK=103,
    CJ_PY312_DEREF_LOAD=104, CJ_PY312_DEREF_STORE=105,
    CJ_PY312_CLEAR_EXC_STATE=106, CJ_PY312_SUSPEND_AT=107,
    CJ_PY312_STACK_PUSH_REF=108, CJ_PY312_STACK_SWAP=109,
    CJ_PY312_FRAME_POSITION=110, CJ_PY312_FRAME_BINDINGS=111,
    CJ_PY312_STACK_COPY=112
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

#if PY_VERSION_HEX == 0x030c0ef0
/* Exact-runtime private entry points are admitted from the mapped libpython
 * ELF, never inferred from an adjacent Python version.  The binder retains
 * its complete file SHA, symbol spans, load base and live instruction bytes.
 * A second owner can reuse only the identical immutable table. */
typedef struct {
    _PyInterpreterFrame *(*push_frame)(PyThreadState *, size_t);
    void (*pop_frame)(PyThreadState *, _PyInterpreterFrame *);
    void (*clear_frame)(_PyInterpreterFrame *);
    PyObject *(*tuple_from_array_steal)(PyObject *const *, Py_ssize_t);
    PyFrameObject *(*make_frame)(_PyInterpreterFrame *);
    PyObject *(*make_coro)(PyFunctionObject *);
    int (*list_append_take_ref)(PyListObject *, PyObject *);
    int (*list_resize)(PyListObject *, Py_ssize_t);
    int (*check_recursive_py)(PyThreadState *);
    uint64_t admitted[12];
    int ready;
} CJRuntime312;
static CJRuntime312 cj312_runtime;

#include "hia_cli_json_cpython312_call.inc"

/* Consume exactly the original CALL stack references.  In particular, the
 * normal-Python-function path does not call _PyEval_Vector, whose extra
 * INCREFs would retain function/argument temporaries in the caller. */
static PyObject *cj312_call_owned(CJContext *ctx, unsigned callable_cell,
                                 unsigned first_argument, unsigned count) {
    PyObject *storage[10] = {NULL};
    PyObject **args = storage + 2;
    PyObject *callable = ctx->cells[callable_cell];
    ctx->cells[callable_cell] = NULL;
    for (unsigned i = 0; i < count; i++) {
        args[i] = ctx->cells[first_argument + i];
        ctx->cells[first_argument + i] = NULL;
    }
    if (Py_IS_TYPE(callable, &PyMethod_Type)) {
        PyObject *self = ((PyMethodObject *)callable)->im_self;
        PyObject *function = ((PyMethodObject *)callable)->im_func;
        args--;
        args[0] = Py_NewRef(self);
        args[-1] = Py_NewRef(function);
        Py_DECREF(callable);
        callable = function;
        count++;
    }
    PyThreadState *tstate = PyThreadState_Get();
    if (Py_IS_TYPE(callable, &PyFunction_Type) &&
            tstate->interp->eval_frame == NULL &&
            ((PyFunctionObject *)callable)->vectorcall == _PyFunction_Vectorcall) {
        PyFunctionObject *function = (PyFunctionObject *)callable;
        PyCodeObject *code = (PyCodeObject *)function->func_code;
        PyObject *locals = code->co_flags & CO_OPTIMIZED ? NULL :
            Py_NewRef(function->func_globals);
        _PyInterpreterFrame *target = cj312_push_and_init(
            tstate, function, locals, args, count, NULL);
        if (target == NULL) return NULL;
        return _PyEval_EvalFrameDefault(tstate, target, 0);
    }
    PyObject *result = PyObject_Vectorcall(callable, args,
        count | PY_VECTORCALL_ARGUMENTS_OFFSET, NULL);
    Py_DECREF(callable);
    for (unsigned i = 0; i < count; i++) Py_DECREF(args[i]);
    return result;
}
#endif

uint64_t hia_cli_json_bind_runtime_312(const uint64_t *words, uint64_t count) {
#if PY_VERSION_HEX == 0x030c0ef0
    if (!PyGILState_Check() || !words || count != 12 || words[0] != 31214 ||
            words[1] != (uintptr_t)_PyEval_EvalFrameDefault ||
            words[2] != (uintptr_t)_PyFunction_Vectorcall) return CJ_REFUSAL;
    if (cj312_runtime.ready) {
        return memcmp(words, cj312_runtime.admitted, sizeof(cj312_runtime.admitted))
            == 0 ? 0 : CJ_REFUSAL;
    }
    Dl_info reference;
    if (!dladdr((void *)(uintptr_t)words[1], &reference) ||
            !reference.dli_fbase) return CJ_REFUSAL;
    for (unsigned i = 2; i < 12; i++) {
        Dl_info observed;
        if (!words[i] || !dladdr((void *)(uintptr_t)words[i], &observed) ||
                observed.dli_fbase != reference.dli_fbase) return CJ_REFUSAL;
    }
    cj312_runtime.push_frame = (void *)(uintptr_t)words[3];
    cj312_runtime.pop_frame = (void *)(uintptr_t)words[4];
    cj312_runtime.clear_frame = (void *)(uintptr_t)words[5];
    cj312_runtime.tuple_from_array_steal = (void *)(uintptr_t)words[6];
    cj312_runtime.make_frame = (void *)(uintptr_t)words[7];
    cj312_runtime.make_coro = (void *)(uintptr_t)words[8];
    cj312_runtime.list_append_take_ref = (void *)(uintptr_t)words[9];
    cj312_runtime.list_resize = (void *)(uintptr_t)words[10];
    cj312_runtime.check_recursive_py = (void *)(uintptr_t)words[11];
    memcpy(cj312_runtime.admitted, words, sizeof(cj312_runtime.admitted));
    cj312_runtime.ready = 1;
    return 0;
#else
    (void)words;
    (void)count;
    return CJ_REFUSAL;
#endif
}

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
    if (frame->op < CJ_FACTS || frame->op > CJ_PY312_STACK_COPY) return CJ_REFUSAL;
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
        if (ctx->slot) frame->result[1] = (uintptr_t)Py_TYPE(ctx->slot)->tp_iternext;
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
        if (frame->b == 1 && PyList_Check(a)) {
            frame->result[0] = (uint64_t)PyList_GET_SIZE(a);
            frame->result[1] = (uint64_t)((PyListObject *)a)->allocated;
        }
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
    case CJ_UNICODE_FROM_DATA:
        /* HIA has produced UTF-32 words.  This leaf only creates the final
         * CPython Unicode storage; it does not choose escaping or layout. */
        if (!frame->a || frame->b > (uint64_t)PY_SSIZE_T_MAX || ctx->slot) goto abi_error;
        ctx->slot = PyUnicode_FromKindAndData(PyUnicode_4BYTE_KIND,
                                             (void *)(uintptr_t)frame->a,
                                             (Py_ssize_t)frame->b);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_LONG_STORAGE:
        if (!a || !PyLong_Check(a)) goto abi_error;
        frame->result[0] = ((PyLongObject *)a)->long_value.lv_tag >> 3;
        frame->result[1] = ((PyLongObject *)a)->long_value.lv_tag & 3;
        frame->result[2] = PyLong_SHIFT;
        frame->result[3] = (uintptr_t)((PyLongObject *)a)->long_value.ob_digit;
        frame->result[4] = sizeof(digit);
        break;
    case CJ_LONG_LIMIT:
        /* This exact-version development DSO is compiled with the actual
         * target internal headers.  Do not substitute a mutable sys module
         * attribute or a guessed interpreter-structure offset.  HIA chooses
         * whether the early/late original observation is due. */
        frame->result[0] = (uint64_t)PyThreadState_Get()->interp->long_state.max_str_digits;
        frame->result[1] = _PY_LONG_MAX_STR_DIGITS_THRESHOLD;
        frame->result[2] = PyLong_SHIFT;
        /* WITH_PYLONG_MODULE is unconditionally 1 in all three retained
         * exact Objects/longobject.c source profiles. */
        frame->result[3] = 1;
        break;
    case CJ_IMPORT_NAME:
        if (!frame->a || ctx->slot) goto abi_error;
        ctx->slot = PyImport_ImportModule((const char *)(uintptr_t)frame->a);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_CALL_NAMED_ONE:
        if (!a || !frame->b || !frame->c || ctx->slot) goto abi_error;
        ctx->slot = PyObject_CallMethod(a, (const char *)(uintptr_t)frame->b,
                                       "O", (PyObject *)(uintptr_t)frame->c);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_LONG_LIMIT_ERROR:
        if (frame->a == 0 || frame->a > INT_MAX) goto abi_error;
        PyErr_Format(PyExc_ValueError,
            "Exceeds the limit (%d digits) for integer string conversion; "
            "use sys.set_int_max_str_digits() to increase the limit",
            (int)frame->a);
        break;
    case CJ_COPY_CELL_TO_SLOT:
        if (frame->a >= 8 || !ctx->cells[frame->a] || ctx->slot) goto abi_error;
        ctx->slot = Py_NewRef(ctx->cells[frame->a]);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_FRESH_ASCII_FROM_DATA: {
        /* CPython long conversion promises a fresh, non-shared string.
         * PyUnicode_FromKindAndData would cache single Latin-1 characters.
         * HIA has already formatted every code point; this loop only copies
         * its ASCII storage into the one freshly allocated Unicode object. */
        if (!frame->a || frame->b > (uint64_t)PY_SSIZE_T_MAX || ctx->slot) goto abi_error;
        ctx->slot = PyUnicode_New((Py_ssize_t)frame->b, 127);
        if (!ctx->slot) break;
        const Py_UCS4 *source = (const Py_UCS4 *)(uintptr_t)frame->a;
        Py_UCS1 *destination = PyUnicode_1BYTE_DATA(ctx->slot);
        for (uint64_t index = 0; index < frame->b; index++) {
            if (source[index] > 127) goto abi_error;
            destination[index] = (Py_UCS1)source[index];
        }
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    }
    case CJ_ESCAPE_TOO_LONG:
        PyErr_SetString(PyExc_OverflowError, "string is too long to escape");
        break;
    case CJ_PY312_COMPARE_LOCALS:
        /* Coalesced LOAD_FAST left, LOAD_FAST right, COMPARE_OP.  No foreign
         * operation separates the two loads in the retained floatstr body.
         * PyObject_RichCompareBool is deliberately not used: o != o must
         * call a subclass comparison even when both pointers are identical. */
        if (profile() != 31214 || !a || !b || frame->c > Py_GE || ctx->slot) goto abi_error;
        Py_INCREF(a);
        Py_INCREF(b);
        ctx->slot = PyObject_RichCompare(a, b, (int)frame->c);
        Py_DECREF(a);
        Py_DECREF(b);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_PY312_TRUTH_CONSUME: {
        if (profile() != 31214 || !ctx->slot) goto abi_error;
        /* POP_JUMP_IF_* owns the tested value until after its truth call. */
        PyObject *value = ctx->slot;
        ctx->slot = NULL;
        int truth = Py_IsTrue(value) ? 1 : Py_IsFalse(value) ? 0 : PyObject_IsTrue(value);
        Py_DECREF(value);
        frame->result[0] = (uint64_t)(int64_t)truth;
        break;
    }
    case CJ_NEWREF_SLOT:
        if (!a || ctx->slot) goto abi_error;
        ctx->slot = Py_NewRef(a);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_PY312_CALL_LOCAL_ONE:
    case CJ_PY312_CALL_LOCAL_TWO: {
        /* Only a sequence of LOAD_FAST/LOAD_DEREF operands with no intervening
         * foreign observation may use this transaction.  It is NOT the ABI
         * for already-owned temporaries retained across another effect.
         * Exact Python calls transfer their LOAD_FAST references into the
         * callee frame; _PyEval_Vector acquires those same references here.
         * The generic CALL path instead owns callable and args throughout
         * Vectorcall and releases callable then args in ascending order.
         * Bound-method unwrapping follows the original CALL operand shape.
         * Interpreter frame visibility/monitoring and C-recursion equivalence
         * remain explicit unqualified development obligations. */
        if (profile() != 31214 || !a || !b || ctx->slot ||
                (frame->op == CJ_PY312_CALL_LOCAL_TWO && !frame->c)) goto abi_error;
        PyObject *function = a;
        PyObject *storage[4] = {NULL, NULL, NULL, NULL};
        PyObject **arguments = storage + 1;
        size_t count = 0;
        if (Py_IS_TYPE(a, &PyMethod_Type)) {
            function = PyMethod_GET_FUNCTION(a);
            arguments[count++] = PyMethod_GET_SELF(a);
        }
        arguments[count++] = b;
        if (frame->op == CJ_PY312_CALL_LOCAL_TWO)
            arguments[count++] = (PyObject *)(uintptr_t)frame->c;
        int inline_python = PyFunction_Check(function) &&
            PyThreadState_Get()->interp->eval_frame == NULL &&
            ((PyFunctionObject *)function)->vectorcall == _PyFunction_Vectorcall;
        if (!inline_python) {
            Py_INCREF(function);
            for (size_t index = 0; index < count; index++) Py_INCREF(arguments[index]);
        }
        ctx->slot = PyObject_Vectorcall(function, arguments,
                                       count | PY_VECTORCALL_ARGUMENTS_OFFSET, NULL);
        if (!inline_python) {
            Py_DECREF(function);
            for (size_t index = 0; index < count; index++) Py_DECREF(arguments[index]);
        }
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    }
    case CJ_PY312_LOAD_GLOBAL: {
        if (profile() != 31214 || !a || !b || !frame->c || ctx->slot) goto abi_error;
        PyObject *name = (PyObject *)(uintptr_t)frame->c;
        if (!PyUnicode_Check(name)) goto abi_error;
        int missing = 0;
        if (PyDict_CheckExact(a) && PyDict_CheckExact(b)) {
            PyObject *value = PyDict_GetItemWithError(a, name);
            if (!value && !PyErr_Occurred()) value = PyDict_GetItemWithError(b, name);
            if (value) ctx->slot = Py_NewRef(value);
            else missing = !PyErr_Occurred();
        }
        else {
            ctx->slot = PyObject_GetItem(a, name);
            if (!ctx->slot && PyErr_ExceptionMatches(PyExc_KeyError)) {
                PyErr_Clear();
                ctx->slot = PyObject_GetItem(b, name);
                if (!ctx->slot && PyErr_ExceptionMatches(PyExc_KeyError)) missing = 1;
            }
        }
        if (missing) {
            const char *name_utf8 = PyUnicode_AsUTF8(name);
            if (name_utf8) {
                PyErr_Format(PyExc_NameError, "name '%s' is not defined", name_utf8);
                PyObject *error = PyErr_GetRaisedException();
                if (error && PyErr_GivenExceptionMatches(error, PyExc_NameError) &&
                        ((PyNameErrorObject *)error)->name == NULL) {
                    (void)PyObject_SetAttrString(error, "name", name);
                }
                PyErr_SetRaisedException(error);
            }
        }
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    }
    case CJ_NUMBER_ADD:
        if (!a || !b || ctx->slot) goto abi_error;
        ctx->slot = PyNumber_Add(a, b);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_RAISE_SLOT: {
        /* Mechanical raise-value normalization.  HIA has already evaluated
         * the constructor and every argument in versioned source order. */
        if (!ctx->slot) goto abi_error;
        PyObject *exception = ctx->slot;
        PyObject *type = NULL;
        PyObject *value = NULL;
        ctx->slot = NULL;
        if (PyExceptionClass_Check(exception)) {
            type = exception;
            value = PyObject_CallNoArgs(exception);
            if (value && !PyExceptionInstance_Check(value)) {
                PyErr_Format(PyExc_TypeError,
                    "calling %R should have returned an instance of BaseException, not %R",
                    type, Py_TYPE(value));
            }
            else if (value) {
                PyErr_SetObject(type, value);
            }
        }
        else if (PyExceptionInstance_Check(exception)) {
            value = exception;
            type = Py_NewRef(PyExceptionInstance_Class(exception));
            PyErr_SetObject(type, value);
        }
        else {
            Py_DECREF(exception);
            PyErr_SetString(PyExc_TypeError, "exceptions must derive from BaseException");
        }
        Py_XDECREF(value);
        Py_XDECREF(type);
        break;
    }
    case CJ_UNICODE_JOIN:
        if (!a || !b || ctx->slot) goto abi_error;
        ctx->slot = PyUnicode_Join(a, b);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_PY312_CALL_OWNED: {
#if PY_VERSION_HEX == 0x030c0ef0
        if (!cj312_runtime.ready || ctx->slot || frame->raised ||
                frame->a >= 8 || frame->b > 8 || frame->c > 8 - frame->b ||
                frame->d || frame->e || !ctx->cells[frame->a]) goto abi_error;
        if (frame->a >= frame->b && frame->a < frame->b + frame->c)
            goto abi_error;
        for (uint64_t i = 0; i < frame->c; i++) {
            if (!ctx->cells[frame->b + i]) goto abi_error;
        }
        ctx->slot = cj312_call_owned(ctx, (unsigned)frame->a,
            (unsigned)frame->b, (unsigned)frame->c);
        frame->result[0] = (uintptr_t)ctx->slot;
        frame->result[1] = frame->c;
        break;
#else
        goto abi_error;
#endif
    }
    case CJ_PY312_APPEND_OWNED: {
#if PY_VERSION_HEX == 0x030c0ef0
        if (!cj312_runtime.ready || !a || !PyList_CheckExact(a) || !ctx->slot)
            goto abi_error;
        PyListObject *list = (PyListObject *)a;
        Py_ssize_t count = PyList_GET_SIZE(a);
        PyObject *item = ctx->slot;
        ctx->slot = NULL; /* original list_extend takes the iterator's ref */
        int result;
        if (list->allocated > count) {
            PyList_SET_ITEM(list, count, item);
            Py_SET_SIZE(list, count + 1);
            result = 0;
        }
        else result = cj312_runtime.list_append_take_ref(list, item);
        frame->result[0] = (uint64_t)(int64_t)result;
        break;
#else
        goto abi_error;
#endif
    }
    case CJ_PY312_LIST_PREALLOCATE: {
#if PY_VERSION_HEX == 0x030c0ef0
        if (!a || !PyList_CheckExact(a) || PyList_GET_SIZE(a) ||
                ((PyListObject *)a)->ob_item || !frame->b || frame->b > PY_SSIZE_T_MAX)
            goto abi_error;
        /* Original list_preallocate_exact: round to even, not list_resize's
         * growth policy and not a new capacity/JSON input limit. */
        size_t size = (frame->b + 1) & ~(size_t)1;
        PyObject **items = PyMem_New(PyObject *, size);
        if (!items) {
            PyErr_NoMemory();
            frame->result[0] = (uint64_t)(int64_t)-1;
        }
        else {
            ((PyListObject *)a)->ob_item = items;
            ((PyListObject *)a)->allocated = (Py_ssize_t)size;
        }
        break;
#else
        goto abi_error;
#endif
    }
    case CJ_PY312_LIST_TRIM:
#if PY_VERSION_HEX == 0x030c0ef0
        if (!cj312_runtime.ready || !a || !PyList_CheckExact(a) ||
                PyList_GET_SIZE(a) >= ((PyListObject *)a)->allocated) goto abi_error;
        frame->result[0] = (uint64_t)(int64_t)cj312_runtime.list_resize(
            (PyListObject *)a, PyList_GET_SIZE(a));
        break;
#else
        goto abi_error;
#endif
    case CJ_LENGTH_HINT:
        if (!a || frame->b > PY_SSIZE_T_MAX) goto abi_error;
        frame->result[0] = (uint64_t)(int64_t)PyObject_LengthHint(a, (Py_ssize_t)frame->b);
        break;
    case CJ_BOUND_ITER_NEXT: {
        if (!a || !frame->b || ctx->slot) goto abi_error;
        /* list_extend caches this actual tp_iternext before LengthHint.
         * A later type mutation must not silently select another function. */
        iternextfunc next = (iternextfunc)(uintptr_t)frame->b;
        ctx->slot = next(a);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    }
    case CJ_CLEAR_STOP_ITERATION:
        if (!frame->raised || ctx->slot) goto abi_error;
        frame->result[0] = PyErr_ExceptionMatches(PyExc_StopIteration);
        if (frame->result[0]) PyErr_Clear();
        break;
    case CJ_MOVE_CELL_TO_SLOT:
        if (frame->a >= 8 || !ctx->cells[frame->a] || ctx->slot) goto abi_error;
        ctx->slot = ctx->cells[frame->a];
        ctx->cells[frame->a] = NULL;
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    case CJ_PY312_JOIN_LOCAL:
#if PY_VERSION_HEX == 0x030c0ef0
        if (!a || !b || ctx->slot || !PyUnicode_CheckExact(a) || PyUnicode_GET_LENGTH(a))
            goto abi_error;
        /* LOAD_METHOD on the actual empty-str constant has no bound-method
         * allocation. The caller's chunks local remains independently owned;
         * this is the temporary CALL argument reference, not a graph copy. */
        Py_INCREF(b);
        ctx->slot = PyUnicode_Join(a, b);
        Py_DECREF(b);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
#else
        goto abi_error;
#endif
    case CJ_PY312_FRAME_INFO: {
#if PY_VERSION_HEX == 0x030c0ef0
        if (!a || !PyGen_CheckExact(a)) goto abi_error;
        PyGenObject *gen = (PyGenObject *)a;
        if (gen->gi_frame_state >= FRAME_CLEARED) goto abi_error;
        _PyInterpreterFrame *owned = (_PyInterpreterFrame *)gen->gi_iframe;
        frame->result[0] = (uintptr_t)owned->f_code;
        frame->result[1] = (uintptr_t)owned->localsplus;
        frame->result[2] = owned->f_code->co_nlocalsplus;
        frame->result[3] = owned->f_code->co_stacksize;
        frame->result[4] = (uint64_t)(int64_t)owned->stacktop;
        frame->result[5] = (uint64_t)(int64_t)_PyInterpreterFrame_LASTI(owned);
        frame->result[6] = (uint64_t)(int64_t)gen->gi_frame_state;
        frame->result[7] = (uintptr_t)owned->f_funcobj;
        break;
#else
        goto abi_error;
#endif
    }
    case CJ_PY312_FRAME_CLEAR: {
#if PY_VERSION_HEX == 0x030c0ef0
        /* A normal owned return value remains in ctx->slot across frame
         * clearing, exactly as the evaluator retains retval. HIA drops
         * its None only after this leaf and before gi_exc_state. */
        if (!cj312_runtime.ready || !a || !PyGen_CheckExact(a))
            goto abi_error;
        PyGenObject *gen = (PyGenObject *)a;
        if (gen->gi_frame_state >= FRAME_EXECUTING || gen->gi_exc_state.previous_item)
            goto abi_error;
        _PyInterpreterFrame *owned = (_PyInterpreterFrame *)gen->gi_iframe;
        PyThreadState *tstate = PyThreadState_Get();
        if (owned->stacktop != owned->f_code->co_nlocalsplus ||
                tstate->cframe->current_frame == owned ||
                tstate->exc_info == &gen->gi_exc_state) goto abi_error;
        _PyInterpreterFrame *previous = NULL;
        if (b) {
            if (PyGen_CheckExact(b)) {
                if (((PyGenObject *)b)->gi_frame_state >= FRAME_CLEARED) goto abi_error;
                previous = (_PyInterpreterFrame *)((PyGenObject *)b)->gi_iframe;
            }
            else if (PyFrame_Check(b)) previous = ((PyFrameObject *)b)->f_frame;
            else goto abi_error;
            if (previous == owned) goto abi_error;
        }
        owned->previous = previous;
        gen->gi_frame_state = FRAME_CLEARED;
        tstate->c_recursion_remaining--;
        /* The actual runtime performs the forward 3.12 local decrefs, or
         * transfers ALL locals to an externally retained frame/traceback. */
        cj312_runtime.clear_frame(owned);
        tstate->c_recursion_remaining++;
        owned->previous = NULL;
        frame->result[0] = FRAME_CLEARED;
        break;
#else
        goto abi_error;
#endif
    }
    case CJ_PY312_FRAME_TRACEBACK: {
#if PY_VERSION_HEX == 0x030c0ef0
        if (!cj312_runtime.ready || !a || !PyGen_CheckExact(a) || !frame->raised)
            goto abi_error;
        PyGenObject *gen = (PyGenObject *)a;
        if (gen->gi_frame_state >= FRAME_CLEARED) goto abi_error;
        _PyInterpreterFrame *owned = (_PyInterpreterFrame *)gen->gi_iframe;
        if (frame->b >= (uint64_t)Py_SIZE(owned->f_code)) goto abi_error;
        owned->prev_instr = _PyCode_CODE(owned->f_code) + frame->b;
        PyFrameObject *actual = owned->frame_obj;
        if (!actual) actual = cj312_runtime.make_frame(owned);
        if (actual) frame->result[0] = (uint64_t)(int64_t)PyTraceBack_Here(actual);
        else frame->result[0] = (uint64_t)(int64_t)-1;
        break;
#else
        goto abi_error;
#endif
    }
    case CJ_PY312_FRAME_STORE: {
#if PY_VERSION_HEX == 0x030c0ef0
        if (!a || !PyGen_CheckExact(a) || !ctx->slot) goto abi_error;
        PyGenObject *gen = (PyGenObject *)a;
        if (gen->gi_frame_state >= FRAME_CLEARED) goto abi_error;
        _PyInterpreterFrame *owned = (_PyInterpreterFrame *)gen->gi_iframe;
        if (frame->b >= (uint64_t)owned->f_code->co_nlocalsplus) goto abi_error;
        PyObject *old = owned->localsplus[frame->b];
        owned->localsplus[frame->b] = ctx->slot;
        ctx->slot = NULL;
        Py_XDECREF(old); /* STORE_FAST commits the new local before release */
        break;
#else
        goto abi_error;
#endif
    }
    case CJ_PY312_FRAME_LOAD: {
#if PY_VERSION_HEX == 0x030c0ef0
        if (!a || !PyGen_CheckExact(a) || ctx->slot) goto abi_error;
        PyGenObject *gen = (PyGenObject *)a;
        if (gen->gi_frame_state >= FRAME_CLEARED) goto abi_error;
        _PyInterpreterFrame *owned = (_PyInterpreterFrame *)gen->gi_iframe;
        if (frame->b >= (uint64_t)owned->f_code->co_nlocalsplus ||
                !owned->localsplus[frame->b]) goto abi_error;
        ctx->slot = Py_NewRef(owned->localsplus[frame->b]);
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
#else
        goto abi_error;
#endif
    }
    /* Owned-stack leaves never choose a graph branch or a release order.
     * The separately admitted HIA continuation supplies every operation. */
#include "hia_cli_json_cpython312_frame.inc"
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

/* Expose an actual generator frame and its handled-exception stack item for
 * exactly one HIA-selected leaf.  Restore the interpreter links before any
 * ctypes/Python transport code runs.  This is NOT a full evaluator entry:
 * recursion accounting, eval-breaker/monitoring, generator SEND/throw/close,
 * and transport allocation scheduling still require the whole C driver.
 * No pending PyErr crosses the return; the original leaf owns/captures it.
 */
uint64_t hia_cli_json_leaf_in_generator(CJFrame *frame, PyObject *generator,
                                      PyObject *parent, uint64_t instruction) {
#if PY_VERSION_HEX == 0x030c0ef0
    if (!PyGILState_Check() || !cj312_runtime.ready || !frame ||
            !generator || !PyGen_CheckExact(generator) || PyErr_Occurred() ||
            frame->op == CJ_PY312_FRAME_CLEAR ||
            frame->op == CJ_PY312_CLEAR_EXC_STATE ||
            frame->op == CJ_PY312_SUSPEND_AT) return CJ_REFUSAL;
    PyGenObject *gen = (PyGenObject *)generator;
    if ((gen->gi_frame_state != FRAME_CREATED && gen->gi_frame_state != FRAME_SUSPENDED) ||
            gen->gi_exc_state.previous_item) return CJ_REFUSAL;
    _PyInterpreterFrame *owned = (_PyInterpreterFrame *)gen->gi_iframe;
    if (instruction >= (uint64_t)Py_SIZE(owned->f_code) || owned->previous ||
            owned->stacktop < owned->f_code->co_nlocalsplus ||
            owned->stacktop > owned->f_code->co_nlocalsplus + owned->f_code->co_stacksize)
        return CJ_REFUSAL;
    PyThreadState *tstate = PyThreadState_Get();
    _PyInterpreterFrame *parent_frame = tstate->cframe->current_frame;
    if (parent) {
        if (PyGen_CheckExact(parent)) {
            PyGenObject *other = (PyGenObject *)parent;
            if (other == gen || other->gi_frame_state >= FRAME_CLEARED) return CJ_REFUSAL;
            parent_frame = (_PyInterpreterFrame *)other->gi_iframe;
        }
        else if (PyFrame_Check(parent)) parent_frame = ((PyFrameObject *)parent)->f_frame;
        else return CJ_REFUSAL;
    }
    if (parent_frame == owned || tstate->exc_info == &gen->gi_exc_state)
        return CJ_REFUSAL;
    _PyInterpreterFrame *previous_current = tstate->cframe->current_frame;
    _PyErr_StackItem *previous_exc = tstate->exc_info;
    int previous_state = gen->gi_frame_state;
    owned->prev_instr = _PyCode_CODE(owned->f_code) + instruction;
    owned->previous = parent_frame;
    gen->gi_exc_state.previous_item = previous_exc;
    gen->gi_frame_state = FRAME_EXECUTING;
    tstate->exc_info = &gen->gi_exc_state;
    tstate->cframe->current_frame = owned;
    uint64_t result = hia_cli_json_leaf(frame);
    int links_equal = tstate->cframe->current_frame == owned &&
        tstate->exc_info == &gen->gi_exc_state &&
        gen->gi_exc_state.previous_item == previous_exc &&
        gen->gi_frame_state == FRAME_EXECUTING;
    tstate->cframe->current_frame = previous_current;
    tstate->exc_info = previous_exc;
    gen->gi_exc_state.previous_item = NULL;
    gen->gi_frame_state = previous_state;
    owned->previous = NULL;
    return links_equal ? result : CJ_REFUSAL;
#else
    (void)frame; (void)generator; (void)parent; (void)instruction;
    return CJ_REFUSAL;
#endif
}

/* Transfer the error from a completed nested HIA sort without synthesizing a
 * Python raise.  The caller owns both private contexts and holds the GIL.
 * A pre-detach abort may finish with phase 0 and the embedded temporary array;
 * a detached sort must reach phase 3 and release its allocated temporary.
 * Neither path permits a live detached/displaced list or result owner. */
uint64_t hia_cli_json_transfer_closed_error(void *destination, void *source) {
    if (!destination || !source || destination == source ||
            !PyGILState_Check() || PyErr_Occurred()) return CJ_REFUSAL;
    CJContext *dst = destination;
    CJContext *src = source;
    if (dst->magic != CJ_CTX || src->magic != CJ_CTX ||
            dst->profile != profile() || src->profile != profile() ||
            dst->raised || dst->external || dst->slot ||
            dst->phase != 0 || dst->list || dst->saved_items || dst->saved_size ||
            dst->saved_allocated || dst->displaced_items || dst->displaced_size ||
            dst->temporary != dst->temporary_array ||
            dst->temporary_words != CJ_TEMP_WORDS ||
            dst->cells[0] || dst->cells[1] || dst->cells[2] || dst->cells[3] ||
            dst->cells[4] || dst->cells[5] || dst->cells[6] || dst->cells[7] ||
            src->external || src->slot ||
            src->cells[0] || src->cells[1] || src->cells[2] || src->cells[3] ||
            src->cells[4] || src->cells[5] || src->cells[6] || src->cells[7])
        return CJ_REFUSAL;
    if (src->phase == 0) {
        if (src->list || src->saved_items || src->saved_size ||
                src->displaced_items || src->displaced_size ||
                src->temporary != src->temporary_array ||
                src->temporary_words != CJ_TEMP_WORDS)
            return CJ_REFUSAL;
    }
    else if (src->phase == 3) {
        if (src->displaced_items || src->displaced_size ||
                src->temporary || src->temporary_words)
            return CJ_REFUSAL;
    }
    else {
        return CJ_REFUSAL;
    }
    dst->raised = src->raised;
    src->raised = NULL;
    return 0;
}
