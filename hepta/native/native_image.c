/* Same-process borrowed-byte HIA image carrier.
 *
 * This file owns executable memory, three synchronous writable byte exports,
 * and the six-argument SysV AMD64 call only.  It contains no HIA instruction
 * semantics, protocol decision, effect dispatch, retry, GC collection, Python
 * object registry, or process transport.  Trusted images are not sandboxed.
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
} State;

static PyObject *buffer_new(PyTypeObject *type, PyObject *args, PyObject *keywords) {
    PyObject *initial, *capacity = NULL;
    Py_ssize_t size, count = 0;
    Buffer *self;
    if (keywords != NULL && PyDict_Size(keywords)) {
        PyErr_SetString(PyExc_TypeError, "Buffer accepts positional arguments only");
        return NULL;
    }
    if (!PyArg_UnpackTuple(args, "Buffer", 1, 2, &initial, &capacity)) return NULL;
    if (PyBytes_CheckExact(initial)) {
        count = PyBytes_GET_SIZE(initial);
        if (capacity == NULL) {
            if (count == PY_SSIZE_T_MAX) return PyErr_NoMemory();
            size = count + 1;
        } else {
            if (!PyLong_CheckExact(capacity)) {
                PyErr_SetString(PyExc_TypeError, "Buffer capacity requires an exact integer");
                return NULL;
            }
            size = PyLong_AsSsize_t(capacity);
            if (size == -1 && PyErr_Occurred()) return NULL;
        }
    } else if (PyLong_CheckExact(initial) && capacity == NULL) {
        size = PyLong_AsSsize_t(initial);
        if (size == -1 && PyErr_Occurred()) return NULL;
    } else {
        PyErr_SetString(PyExc_TypeError, "Buffer requires exact bytes or an exact integer capacity");
        return NULL;
    }
    if (size < 0 || count > size) {
        PyErr_SetString(PyExc_ValueError, "Buffer capacity is smaller than its initial bytes");
        return NULL;
    }
    self = (Buffer *)type->tp_alloc(type, 0);
    if (self == NULL) return NULL;
    self->data = PyMem_Calloc((size_t)(size ? size : 1), 1);
    if (self->data == NULL) {
        Py_DECREF(self);
        return PyErr_NoMemory();
    }
    self->size = size;
    if (count) memcpy(self->data, PyBytes_AS_STRING(initial), (size_t)count);
    return (PyObject *)self;
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
    PyObject *raw;
    Image *self;
    if (keywords != NULL && PyDict_Size(keywords)) {
        PyErr_SetString(PyExc_TypeError, "Image accepts one positional byte string");
        return NULL;
    }
    if (!PyArg_UnpackTuple(args, "Image", 1, 1, &raw)) return NULL;
    if (!PyBytes_CheckExact(raw) || PyBytes_GET_SIZE(raw) <= 0 ||
            PyBytes_GET_SIZE(raw) > (1 << 20)) {
        PyErr_SetString(PyExc_ValueError, "Image requires 1 through 1048576 exact bytes");
        return NULL;
    }
    self = (Image *)type->tp_alloc(type, 0);
    if (self == NULL) return NULL;
    self->size = (size_t)PyBytes_GET_SIZE(raw);
    self->mapping = mmap(NULL, self->size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (self->mapping == MAP_FAILED) {
        self->mapping = NULL;
        PyErr_SetFromErrno(PyExc_OSError);
        Py_DECREF(self);
        return NULL;
    }
    memcpy(self->mapping, PyBytes_AS_STRING(raw), self->size);
    if (mprotect(self->mapping, self->size, PROT_READ | PROT_EXEC) != 0) {
        int saved = errno;
        munmap(self->mapping, self->size);
        self->mapping = NULL;
        errno = saved;
        PyErr_SetFromErrno(PyExc_OSError);
        Py_DECREF(self);
        return NULL;
    }
    memcpy(&self->entry, &self->mapping, sizeof(self->entry));
    return (PyObject *)self;
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
    PyObject *objects[6];
    Py_buffer views[3] = {{0}, {0}, {0}};
    uint64_t sizes[3], returned;
    int acquired = 0;
    PyObject *answer;
    /* A C API caller may provide a borrowed receiver.  Keep our own explicit
     * synchronous reference across exporter callbacks and GIL release. */
    Py_INCREF(self);
    if (keywords != NULL && PyDict_Size(keywords)) {
        PyErr_SetString(PyExc_TypeError, "native image entry accepts six positional arguments");
        goto failure;
    }
    if (!PyArg_UnpackTuple(args, "native image entry", 6, 6,
            &objects[0], &objects[1], &objects[2], &objects[3], &objects[4], &objects[5]))
        goto failure;
    for (int i = 0; i < 3; i++) {
        if (!PyLong_CheckExact(objects[2*i + 1])) {
            PyErr_SetString(PyExc_TypeError, "native byte extent requires an exact integer");
            goto failure;
        }
        sizes[i] = PyLong_AsUnsignedLongLong(objects[2*i + 1]);
        if (sizes[i] == UINT64_MAX && PyErr_Occurred()) goto failure;
        if (PyObject_GetBuffer(objects[2*i], &views[i], PyBUF_WRITABLE | PyBUF_C_CONTIGUOUS) < 0)
            goto failure;
        acquired++;
        if (views[i].len < 0 || sizes[i] > (uint64_t)views[i].len) {
            PyErr_SetString(PyExc_ValueError, "native byte extent exceeds its actual export");
            goto failure;
        }
    }
    /* The call owns three buffer exports and its Image receiver.  Resize is
     * prohibited by the exporters until return; no Python object is retained
     * beyond this synchronous call.  Like the previous CFUNCTYPE call, native
     * execution releases the GIL.  Faults keep the existing process semantics. */
    Py_BEGIN_ALLOW_THREADS
    returned = self->entry(views[0].buf, sizes[0], views[1].buf, sizes[1], views[2].buf, sizes[2]);
    Py_END_ALLOW_THREADS
    for (int i = 2; i >= 0; i--) PyBuffer_Release(&views[i]);
    answer = PyLong_FromUnsignedLongLong(returned);
    Py_DECREF(self);
    return answer;
failure:
    while (acquired) PyBuffer_Release(&views[--acquired]);
    Py_DECREF(self);
    return NULL;
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
    NULL, module_slots, module_traverse, module_clear, NULL
};

PyMODINIT_FUNC PyInit__hia_native_image(void) { return PyModuleDef_Init(&definition); }
