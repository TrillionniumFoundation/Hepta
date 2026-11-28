/* HIA-owned cell/frame lifetime and dispatch with closed CPython operations.
 * Exact heap types and GC references are explicit CPython compatibility ABI.
 * Standalone HIA has no CPython dependency; old C is retained as an oracle.
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#if !defined(__linux__) || !defined(__x86_64__)
#error "native cell policy requires Linux x86-64"
#endif

#if PY_VERSION_HEX < 0x030B0000 || PY_VERSION_HEX >= 0x030F0000
#error "cell frame supports CPython 3.11 through 3.14"
#endif
#ifdef Py_GIL_DISABLED
#error "cell frame requires the ordinary GIL build"
#endif

#define CELL_LIMIT 64

typedef struct {
    PyObject *name;
    PyObject *cell;
} CellEntry;

typedef struct {
    PyObject_HEAD
    Py_ssize_t count;
    CellEntry *entries;
    PyObject *empty_reader;
    PyObject *weakrefs;
} CellBindings;

typedef struct {
    PyObject_HEAD
    PyObject *factory;
    PyObject *image;
    PyObject *mode;
    PyObject *cells;
    PyObject *namespace;
    PyObject *builtins;
    PyObject *imports;
    PyObject *weakrefs;
} FrameCallback;

typedef uint64_t (*CellPolicyEntry)(void *, uint64_t, void *, uint64_t, void *, uint64_t);
_Static_assert(sizeof(void *) == 8, "LP64 pointer required");
_Static_assert(sizeof(CellPolicyEntry) == sizeof(void *), "native entry pointer required");
typedef struct {
    PyObject *bindings_type;
    PyObject *callback_type;
    void *policy_mapping;
    size_t policy_size;
    CellPolicyEntry policy;
    uint64_t invocations, native_calls, protocol_failures;
} ModuleState;

#include "carrier_cell_dispatch.inc"

static int
bindings_traverse(CellBindings *self, visitproc visit, void *arg)
{
    Py_VISIT(Py_TYPE(self));
    Py_VISIT(self->empty_reader);
    for (Py_ssize_t i = 0; i < self->count; ++i) {
        Py_VISIT(self->entries[i].name);
        Py_VISIT(self->entries[i].cell);
    }
    return 0;
}

static int
bindings_clear(CellBindings *self)
{
    /* Release ownership only. Never change any real cell's contents. */
    Py_CLEAR(self->empty_reader);
    for (Py_ssize_t i = 0; i < self->count; ++i) {
        Py_CLEAR(self->entries[i].name);
        Py_CLEAR(self->entries[i].cell);
    }
    return 0;
}

static void
bindings_dealloc(CellBindings *self)
{
    PyTypeObject *type = Py_TYPE(self);
    PyObject_GC_UnTrack(self);
    if (self->weakrefs != NULL)
        PyObject_ClearWeakRefs((PyObject *)self);
    bindings_clear(self);
    PyMem_Free(self->entries);
    type->tp_free((PyObject *)self);
    Py_DECREF(type);
}



static PyObject *
bindings_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    return cell_policy_drive(1, type, NULL, args, kwargs);
}

static PyObject *
bindings_getitem(CellBindings *self, PyObject *name)
{
    return cell_policy_drive(2, Py_TYPE(self), (PyObject *)self, name, NULL);
}

static PyObject *
bindings_subset(CellBindings *self, PyObject *names)
{
    return cell_policy_drive(3, Py_TYPE(self), (PyObject *)self, names, NULL);
}

static PyMethodDef bindings_methods[] = {
    {"subset", (PyCFunction)bindings_subset, METH_VARARGS,
     "Keep the actual selected cells, including subsequent rebindings."},
    {NULL, NULL, 0, NULL}
};

static PyType_Slot bindings_slots[] = {
    {Py_tp_new, bindings_new},
    {Py_tp_dealloc, bindings_dealloc},
    {Py_tp_traverse, bindings_traverse},
    {Py_tp_clear, bindings_clear},
    {Py_tp_methods, bindings_methods},
    {Py_mp_subscript, bindings_getitem},
    {0, NULL}
};

static PyType_Spec bindings_spec = {
    .name = "hepta._hia_cell_frame.CellBindings",
    .basicsize = sizeof(CellBindings),
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    .slots = bindings_slots,
};

static int
callback_traverse(FrameCallback *self, visitproc visit, void *arg)
{
    Py_VISIT(Py_TYPE(self));
    Py_VISIT(self->factory);
    Py_VISIT(self->image);
    Py_VISIT(self->mode);
    Py_VISIT(self->cells);
    Py_VISIT(self->namespace);
    Py_VISIT(self->builtins);
    Py_VISIT(self->imports);
    return 0;
}

static int
callback_clear(FrameCallback *self)
{
    Py_CLEAR(self->factory);
    Py_CLEAR(self->image);
    Py_CLEAR(self->mode);
    Py_CLEAR(self->cells);
    Py_CLEAR(self->namespace);
    Py_CLEAR(self->builtins);
    Py_CLEAR(self->imports);
    return 0;
}

static void
callback_dealloc(FrameCallback *self)
{
    PyTypeObject *type = Py_TYPE(self);
    PyObject_GC_UnTrack(self);
    if (self->weakrefs != NULL)
        PyObject_ClearWeakRefs((PyObject *)self);
    callback_clear(self);
    type->tp_free((PyObject *)self);
    Py_DECREF(type);
}

static PyObject *
callback_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    return cell_policy_drive(4, type, NULL, args, kwargs);
}

static PyObject *
callback_call(FrameCallback *self, PyObject *args, PyObject *kwargs)
{
    return cell_policy_drive(5, Py_TYPE(self), (PyObject *)self, args, kwargs);
}

static PyType_Slot callback_slots[] = {
    {Py_tp_new, callback_new},
    {Py_tp_dealloc, callback_dealloc},
    {Py_tp_traverse, callback_traverse},
    {Py_tp_clear, callback_clear},
    {Py_tp_call, callback_call},
    {0, NULL}
};

static PyType_Spec callback_spec = {
    .name = "hepta._hia_cell_frame.FrameCallback",
    .basicsize = sizeof(FrameCallback),
    .flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,
    .slots = callback_slots,
};

static int
module_exec(PyObject *module)
{
    ModuleState *state = (ModuleState *)PyModule_GetState(module);
    if (state == NULL)
        return -1;
    if (cell_policy_map(state) < 0)
        return -1;
    PyObject *bindings = PyType_FromModuleAndSpec(module, &bindings_spec, NULL);
    if (bindings == NULL)
        return -1;
    ((PyTypeObject *)bindings)->tp_weaklistoffset = offsetof(CellBindings, weakrefs);
    state->bindings_type = Py_NewRef(bindings);
    if (PyModule_AddObject(module, "CellBindings", bindings) < 0) {
        Py_DECREF(bindings);
        return -1;
    }
    PyObject *callback = PyType_FromModuleAndSpec(module, &callback_spec, NULL);
    if (callback == NULL)
        return -1;
    ((PyTypeObject *)callback)->tp_weaklistoffset = offsetof(FrameCallback, weakrefs);
    state->callback_type = Py_NewRef(callback);
    if (PyModule_AddObject(module, "FrameCallback", callback) < 0) {
        Py_DECREF(callback);
        return -1;
    }
    return 0;
}

static int
module_traverse(PyObject *module, visitproc visit, void *arg)
{
    ModuleState *state = (ModuleState *)PyModule_GetState(module);
    if (state != NULL) {
        Py_VISIT(state->bindings_type);
        Py_VISIT(state->callback_type);
    }
    return 0;
}

static int
module_clear(PyObject *module)
{
    ModuleState *state = (ModuleState *)PyModule_GetState(module);
    if (state != NULL) {
        Py_CLEAR(state->bindings_type);
        Py_CLEAR(state->callback_type);
    }
    return 0;
}

static void
module_free(void *module)
{
    ModuleState *state = (ModuleState *)PyModule_GetState((PyObject *)module);
    module_clear((PyObject *)module);
    if (state != NULL && state->policy_mapping != NULL) {
        munmap(state->policy_mapping, state->policy_size);
        state->policy_mapping = NULL;
        state->policy = NULL;
    }
}

static PyModuleDef_Slot module_slots[] = {
    {Py_mod_exec, module_exec},
#if PY_VERSION_HEX >= 0x030C0000
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
#endif
    {0, NULL}
};

static struct PyModuleDef module_definition = {
    PyModuleDef_HEAD_INIT,
    .m_name = "_hia_cell_frame",
    .m_doc = "Development mechanical cell owner and private frame call carrier.",
    .m_size = sizeof(ModuleState),
    .m_methods = cell_policy_methods,
    .m_slots = module_slots,
    .m_traverse = module_traverse,
    .m_clear = module_clear,
    .m_free = module_free,
};

PyMODINIT_FUNC
PyInit__hia_cell_frame(void)
{
    return PyModuleDef_Init(&module_definition);
}
