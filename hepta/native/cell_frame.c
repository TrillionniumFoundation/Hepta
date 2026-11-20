/* Mechanical ownership of real Python cells and a private Frame invocation.
 * No graph decision, traversal policy, generator, GC collection or registry.
 * This development carrier does not claim arbitrary function reflection ABI.
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stddef.h>

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

typedef struct {
    PyObject *bindings_type;
    PyObject *callback_type;
} ModuleState;

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

static Py_ssize_t
binding_index(CellBindings *self, PyObject *name)
{
    if (!PyUnicode_CheckExact(name)) {
        PyErr_SetObject(PyExc_KeyError, name);
        return -1;
    }
    for (Py_ssize_t i = 0; i < self->count; ++i) {
        if (self->entries[i].name != NULL &&
                PyUnicode_Compare(self->entries[i].name, name) == 0)
            return i;
        if (PyErr_Occurred())
            return -1;
    }
    PyErr_SetObject(PyExc_KeyError, name);
    return -1;
}

static PyObject *
bindings_new(PyTypeObject *type, PyObject *args, PyObject *kwargs)
{
    PyObject *names, *cells, *empty_reader;
    static char *keywords[] = {"names", "cells", "empty_reader", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OOO:CellBindings", keywords,
                                    &names, &cells, &empty_reader))
        return NULL;
    if (!PyTuple_CheckExact(names) || !PyTuple_CheckExact(cells) ||
            !PyCallable_Check(empty_reader)) {
        PyErr_SetString(PyExc_TypeError, "bindings require exact tuples and an empty-cell reader");
        return NULL;
    }
    Py_ssize_t count = PyTuple_GET_SIZE(names);
    if (count < 1 || count > CELL_LIMIT || PyTuple_GET_SIZE(cells) != count) {
        PyErr_SetString(PyExc_ValueError, "bindings require 1 to 64 matching names and real cells");
        return NULL;
    }
    for (Py_ssize_t i = 0; i < count; ++i) {
        PyObject *name = PyTuple_GET_ITEM(names, i);
        if (!PyUnicode_CheckExact(name) || !PyCell_Check(PyTuple_GET_ITEM(cells, i))) {
            PyErr_SetString(PyExc_TypeError, "bindings require exact string names and actual cells");
            return NULL;
        }
        for (Py_ssize_t j = 0; j < i; ++j) {
            int equal = PyUnicode_Compare(name, PyTuple_GET_ITEM(names, j));
            if (PyErr_Occurred())
                return NULL;
            if (equal == 0) {
                PyErr_SetString(PyExc_ValueError, "binding names must be distinct");
                return NULL;
            }
        }
    }
    CellBindings *self = (CellBindings *)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;
    self->entries = PyMem_Calloc((size_t)count, sizeof(CellEntry));
    if (self->entries == NULL) {
        Py_DECREF(self);
        return PyErr_NoMemory();
    }
    self->count = count;
    self->empty_reader = Py_NewRef(empty_reader);
    for (Py_ssize_t i = 0; i < count; ++i) {
        self->entries[i].name = Py_NewRef(PyTuple_GET_ITEM(names, i));
        self->entries[i].cell = Py_NewRef(PyTuple_GET_ITEM(cells, i));
    }
    return (PyObject *)self;
}

static PyObject *
bindings_getitem(CellBindings *self, PyObject *name)
{
    Py_ssize_t index = binding_index(self, name);
    if (index < 0)
        return NULL;
    PyObject *cell = self->entries[index].cell;
    if (cell == NULL || self->empty_reader == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "cell bindings have been released");
        return NULL;
    }
    PyObject *value = PyCell_GET(cell);
    if (value != NULL)
        return Py_NewRef(value);
    /* CPython's actual LOAD_DEREF supplies the original exception metadata. */
    Py_INCREF(self);
    PyObject *result = PyObject_CallFunctionObjArgs(self->empty_reader,
        self->entries[index].name, cell, NULL);
    Py_DECREF(self);
    return result;
}

static PyObject *
bindings_subset(CellBindings *self, PyObject *names)
{
    Py_ssize_t count = PyTuple_GET_SIZE(names);
    if (count < 1 || count > CELL_LIMIT || self->empty_reader == NULL) {
        PyErr_SetString(PyExc_ValueError, "subset requires 1 to 64 live bindings");
        return NULL;
    }
    PyObject *cells = PyTuple_New(count);
    if (cells == NULL)
        return NULL;
    for (Py_ssize_t i = 0; i < count; ++i) {
        Py_ssize_t index = binding_index(self, PyTuple_GET_ITEM(names, i));
        if (index < 0) {
            Py_DECREF(cells);
            return NULL;
        }
        if (self->entries[index].cell == NULL) {
            Py_DECREF(cells);
            PyErr_SetString(PyExc_RuntimeError, "cell bindings have been released");
            return NULL;
        }
        PyTuple_SET_ITEM(cells, i, Py_NewRef(self->entries[index].cell));
    }
    PyObject *result = PyObject_CallFunctionObjArgs((PyObject *)Py_TYPE(self),
                                                  names, cells, self->empty_reader, NULL);
    Py_DECREF(cells);
    return result;
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
    PyObject *factory, *image, *mode, *cells, *namespace, *builtins, *imports;
    static char *keywords[] = {"factory", "image", "mode", "cells", "namespace",
                               "builtins", "imports", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "OOOOOOO:FrameCallback", keywords,
            &factory, &image, &mode, &cells, &namespace, &builtins, &imports))
        return NULL;
    PyObject *module = PyType_GetModule(type);
    if (module == NULL)
        return NULL;
    ModuleState *state = (ModuleState *)PyModule_GetState(module);
    if (state == NULL || state->bindings_type == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "cell frame module state is unavailable");
        return NULL;
    }
    int admitted = Py_IS_TYPE(cells, (PyTypeObject *)state->bindings_type);
    if (!admitted || !PyCallable_Check(factory) || !PyLong_CheckExact(mode) ||
            !PyDict_CheckExact(namespace) || !PyDict_CheckExact(builtins) ||
            !PyDict_CheckExact(imports)) {
        PyErr_SetString(PyExc_TypeError, "callback requires a frame factory, real cells and actual namespaces");
        return NULL;
    }
    FrameCallback *self = (FrameCallback *)type->tp_alloc(type, 0);
    if (self == NULL)
        return NULL;
    self->factory = Py_NewRef(factory);
    self->image = Py_NewRef(image);
    self->mode = Py_NewRef(mode);
    self->cells = Py_NewRef(cells);
    self->namespace = Py_NewRef(namespace);
    self->builtins = Py_NewRef(builtins);
    self->imports = Py_NewRef(imports);
    return (PyObject *)self;
}

static PyObject *
callback_call(FrameCallback *self, PyObject *args, PyObject *kwargs)
{
    PyObject *name;
    static char *keywords[] = {"name", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O:acyclic", keywords, &name))
        return NULL;
    if (self->factory == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "frame callback has been released");
        return NULL;
    }
    /* Real factory and finish calls can recurse, invoke providers and collect. */
    Py_INCREF(self);
    PyObject *bound = Py_BuildValue("{s:O,s:O}", "name", name, "cells", self->cells);
    PyObject *call_args = NULL, *call_kwargs = NULL, *frame = NULL, *result = NULL;
    if (bound == NULL)
        goto done;
    call_args = PyTuple_Pack(3, self->image, self->mode, bound);
    if (call_args == NULL)
        goto done;
    call_kwargs = Py_BuildValue("{s:O,s:O,s:O}",
        "namespace", self->namespace, "global_builtins", self->builtins,
        "import_capsules", self->imports);
    if (call_kwargs == NULL)
        goto done;
    frame = PyObject_Call(self->factory, call_args, call_kwargs);
    Py_CLEAR(call_args);
    Py_CLEAR(call_kwargs);
    Py_CLEAR(bound);
    if (frame != NULL)
        result = PyObject_CallMethod(frame, "finish", NULL);
done:
    Py_XDECREF(frame);
    Py_XDECREF(call_kwargs);
    Py_XDECREF(call_args);
    Py_XDECREF(bound);
    Py_DECREF(self);
    return result;
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
    module_clear((PyObject *)module);
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
