/* HIA-owned image lifecycle with a closed CPython foreign ABI.
 * Creation, three export acquisitions, reverse unwind and result ownership are
 * decided by the compiled carrier_image_policy.hepta. Heap type/GC plumbing
 * below is an explicit CPython compatibility dependency, never a standalone
 * native Worker dependency. Original C methods remain sealed as the oracle.
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error "The native byte carrier requires Linux x86-64"
#endif
#if PY_VERSION_HEX < 0x030b0000 || PY_VERSION_HEX >= 0x030f0000
#error "The native byte carrier supports CPython 3.11 through 3.14"
#endif
#ifdef Py_GIL_DISABLED
#error "The free-threaded byte carrier is not admitted"
#endif

typedef uint64_t (*Entry)(void *, uint64_t, void *, uint64_t, void *, uint64_t);
_Static_assert(sizeof(void *) == 8, "LP64 pointer required");
_Static_assert(sizeof(Entry) == sizeof(void *), "native entry pointer required");

typedef struct {
    PyObject_HEAD
    unsigned char *data;
    Py_ssize_t size;
    PyObject *weakrefs;
} Buffer;

typedef struct {
    PyObject_HEAD
    void *mapping;
    size_t size;
    Entry entry;
    PyObject *weakrefs;
} Image;

typedef struct {
    PyObject *buffer_type;
    PyObject *image_type;
    void *policy_mapping;
    size_t policy_size;
    Entry policy;
    uint64_t invocations, native_calls, protocol_failures;
} State;

#include "carrier_image_dispatch.inc"

static PyObject *buffer_new(PyTypeObject *type, PyObject *args, PyObject *keywords) {
    return policy_drive(2, type, NULL, args, keywords);
}

static void buffer_dealloc(Buffer *self) {
    PyTypeObject *type = Py_TYPE(self);
    PyObject_GC_UnTrack(self);
    if (self->weakrefs != NULL) PyObject_ClearWeakRefs((PyObject *)self);
    PyMem_Free(self->data);
    type->tp_free((PyObject *)self);
    Py_DECREF(type);
}

static int buffer_traverse(Buffer *self, visitproc visit, void *arg) {
    /* Heap types own their defining module.  A module may in turn own this
     * instance, so this real reference must be visible to cyclic GC. */
    Py_VISIT(Py_TYPE(self));
    return 0;
}

static int buffer_export(Buffer *self, Py_buffer *view, int flags) {
    return PyBuffer_FillInfo(view, (PyObject *)self, self->data, self->size, 0, flags);
}

static Py_ssize_t buffer_length(Buffer *self) { return self->size; }

static PyObject *buffer_raw(Buffer *self, void *unused) {
    return PyBytes_FromStringAndSize((const char *)self->data, self->size);
}

/* Compatibility for independently retained ctypes observers.  The owner is
 * still the actual Buffer argument; this value neither retains an owner nor
 * lets the carrier accept arbitrary integer pointers as native arguments. */
static PyObject *buffer_parameter(Buffer *self, void *unused) {
    return PyLong_FromVoidPtr(self->data);
}

static PyGetSetDef buffer_getsets[] = {
    {"raw", (getter)buffer_raw, NULL, NULL, NULL},
    {"_as_parameter_", (getter)buffer_parameter, NULL, NULL, NULL},
    {NULL, NULL, NULL, NULL, NULL}
};

static PyType_Slot buffer_slots[] = {
    {Py_tp_new, buffer_new}, {Py_tp_dealloc, buffer_dealloc},
    {Py_tp_traverse, buffer_traverse},
    {Py_tp_getset, buffer_getsets}, {Py_bf_getbuffer, buffer_export},
    {Py_sq_length, buffer_length}, {0, NULL}
};

static PyType_Spec buffer_spec = {
    "hepta._hia_native_image.Buffer", sizeof(Buffer), 0,
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC, buffer_slots
};

static PyObject *image_new(PyTypeObject *type, PyObject *args, PyObject *keywords) {
    return policy_drive(3, type, NULL, args, keywords);
}

static void image_dealloc(Image *self) {
    PyTypeObject *type = Py_TYPE(self);
    PyObject_GC_UnTrack(self);
    if (self->weakrefs != NULL) PyObject_ClearWeakRefs((PyObject *)self);
    if (self->mapping != NULL) munmap(self->mapping, self->size);
    type->tp_free((PyObject *)self);
    Py_DECREF(type);
}

static int image_traverse(Image *self, visitproc visit, void *arg) {
    Py_VISIT(Py_TYPE(self));
    return 0;
}

static PyObject *image_call(Image *self, PyObject *args, PyObject *keywords) {
    return policy_drive(1, Py_TYPE(self), self, args, keywords);
}

static PyType_Slot image_slots[] = {
    {Py_tp_new, image_new}, {Py_tp_dealloc, image_dealloc},
    {Py_tp_traverse, image_traverse},
    {Py_tp_call, image_call}, {0, NULL}
};

static PyType_Spec image_spec = {
    "hepta._hia_native_image.Image", sizeof(Image), 0,
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC, image_slots
};

static int module_traverse(PyObject *module, visitproc visit, void *arg) {
    State *state = (State *)PyModule_GetState(module);
    Py_VISIT(state->buffer_type); Py_VISIT(state->image_type);
    return 0;
}

static int module_clear(PyObject *module) {
    State *state = (State *)PyModule_GetState(module);
    Py_CLEAR(state->buffer_type); Py_CLEAR(state->image_type);
    return 0;
}

static int module_exec(PyObject *module) {
    State *state = (State *)PyModule_GetState(module);
    if (policy_image_map(state) < 0) return -1;
    state->buffer_type = PyType_FromModuleAndSpec(module, &buffer_spec, NULL);
    state->image_type = PyType_FromModuleAndSpec(module, &image_spec, NULL);
    if (!state->buffer_type || !state->image_type) return -1;
    ((PyTypeObject *)state->buffer_type)->tp_weaklistoffset = offsetof(Buffer, weakrefs);
    ((PyTypeObject *)state->image_type)->tp_weaklistoffset = offsetof(Image, weakrefs);
    PyType_Modified((PyTypeObject *)state->buffer_type);
    PyType_Modified((PyTypeObject *)state->image_type);
    if (PyModule_AddObjectRef(module, "Buffer", state->buffer_type) < 0 ||
            PyModule_AddObjectRef(module, "Image", state->image_type) < 0 ||
            PyModule_AddStringConstant(module, "ABI", "hepta.native-image.three-writable-buffers.v1") < 0)
        return -1;
    return 0;
}

static void module_free(void *module) {
    State *state = (State *)PyModule_GetState((PyObject *)module);
    if (state != NULL) {
        module_clear((PyObject *)module);
        if (state->policy_mapping != NULL) {
            munmap(state->policy_mapping, state->policy_size);
            state->policy_mapping = NULL;
            state->policy = NULL;
        }
    }
}

static PyModuleDef_Slot module_slots[] = {
    {Py_mod_exec, module_exec},
#if PY_VERSION_HEX >= 0x030c0000
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
#endif
#if PY_VERSION_HEX >= 0x030d0000
    {Py_mod_gil, Py_MOD_GIL_USED},
#endif
    {0, NULL}
};

static struct PyModuleDef definition = {
    PyModuleDef_HEAD_INIT, "_hia_native_image", NULL, sizeof(State),
    image_policy_methods, module_slots, module_traverse, module_clear, module_free
};

PyMODINIT_FUNC PyInit__hia_native_image(void) { return PyModuleDef_Init(&definition); }
