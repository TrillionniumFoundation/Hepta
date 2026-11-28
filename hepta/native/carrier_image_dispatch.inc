/* Closed CPython foreign operations for carrier_image_policy.hepta.
 * No request may name a C API, pointer or dynamic symbol.  Only this fixed
 * switch is foreign; HIA owns dispatch order, unwind and terminal decisions.
 */
#include "carrier_image_policy.inc"

typedef struct {
    PyObject *values[6];
    PyObject *initial, *capacity;
    PyObject *result, *answer;
    PyObject *error_type, *error_value, *error_traceback;
    Py_buffer views[3];
    uint64_t sizes[3];
    unsigned int exports;
    int receiver_held;
} CarrierCall;

static int policy_image_map(State *state) {
    state->policy_size = sizeof(hia_carrier_image_policy);
    state->policy_mapping = mmap(NULL, state->policy_size, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (state->policy_mapping == MAP_FAILED) {
        state->policy_mapping = NULL;
        PyErr_SetFromErrno(PyExc_OSError);
        return -1;
    }
    memcpy(state->policy_mapping, hia_carrier_image_policy, state->policy_size);
    if (mprotect(state->policy_mapping, state->policy_size, PROT_READ | PROT_EXEC)) {
        int saved = errno;
        munmap(state->policy_mapping, state->policy_size);
        state->policy_mapping = NULL;
        errno = saved;
        PyErr_SetFromErrno(PyExc_OSError);
        return -1;
    }
    memcpy(&state->policy, &state->policy_mapping, sizeof(state->policy));
    return 0;
}

static void capture_foreign_error(CarrierCall *call) {
    if (!PyErr_Occurred())
        PyErr_SetString(PyExc_RuntimeError, "closed carrier operation did not return an exception");
    if (call->error_type == NULL)
        PyErr_Fetch(&call->error_type, &call->error_value, &call->error_traceback);
    else
        PyErr_Clear();
}

static void fixed_error(uint64_t kind) {
    switch (kind) {
    case 2: PyErr_SetString(PyExc_TypeError, "native byte extent requires an exact integer"); break;
    case 3: PyErr_SetString(PyExc_ValueError, "native byte extent exceeds its actual export"); break;
    case 5: PyErr_SetString(PyExc_TypeError, "Buffer requires exact bytes or an exact integer capacity"); break;
    case 6: PyErr_SetString(PyExc_TypeError, "Buffer capacity requires an exact integer"); break;
    case 7: PyErr_SetString(PyExc_ValueError, "Buffer capacity is smaller than its initial bytes"); break;
    case 8: PyErr_SetString(PyExc_ValueError, "Image requires 1 through 1048576 exact bytes"); break;
    case 9: PyErr_NoMemory(); break;
    default: PyErr_SetString(PyExc_RuntimeError, "unlisted carrier exception primitive"); break;
    }
}

static PyObject *policy_drive(uint64_t mode, PyTypeObject *type, Image *receiver,
                              PyObject *args, PyObject *keywords) {
    PyObject *module = PyType_GetModule(type);
    if (module == NULL) return NULL;
    State *state = (State *)PyModule_GetState(module);
    if (state == NULL || state->policy == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "native carrier policy is unavailable");
        return NULL;
    }
    /* A mechanical executable-loan guard.  HIA separately owns the receiver
     * reference that is observable by exporters and actual Python callbacks. */
    Py_INCREF(module);
    CarrierCall call = {0};
    uint64_t request[8] = {UINT64_C(0x3130504943414948), mode, 0, 0, 0, 0, 0, 0};
    uint64_t response[4] = {0};
    uint64_t workspace[32] = {0};
    PyObject *returned = NULL;
    int terminal = 0, protocol_failure = 0;
    state->invocations++;
    for (int step = 0; step < 64; ++step) {
        state->native_calls++;
        uint64_t status = state->policy(request, sizeof(request), response, sizeof(response),
                                        workspace, sizeof(workspace));
        if (status == 0) {
            terminal = 1;
            if (response[0] != 0 || response[1] > 1 || response[2] || response[3] ||
                    (call.error_type != NULL) != (response[1] == 1)) {
                protocol_failure = 1;
                PyErr_SetString(PyExc_RuntimeError, "native carrier terminal record differs");
                capture_foreign_error(&call);
            } else if (response[1] == 0 && call.error_type == NULL) {
                returned = mode == 1 ? call.answer : call.result;
                if (mode == 1) call.answer = NULL;
                else call.result = NULL;
                if (returned == NULL) {
                    protocol_failure = 1;
                    PyErr_SetString(PyExc_RuntimeError, "native carrier has no terminal object");
                    capture_foreign_error(&call);
                }
            } else if (call.error_type == NULL) {
                protocol_failure = 1;
                PyErr_SetString(PyExc_RuntimeError, "native carrier lost its foreign exception");
                capture_foreign_error(&call);
            }
            break;
        }
        if (status != 1 || response[3]) {
            protocol_failure = 1;
            PyErr_SetString(PyExc_RuntimeError, "native carrier refused its effect acknowledgement");
            capture_foreign_error(&call);
            break;
        }
        uint64_t action = response[0], at = response[1], size = response[2];
        uint64_t value = 0, auxiliary = 0;
        switch (action) {
        case 1:
            if (mode != 1 || receiver == NULL || call.receiver_held) goto invalid_effect;
            Py_INCREF(receiver); call.receiver_held = 1;
            break;
        case 2:
            if (mode != 1) goto invalid_effect;
            if (keywords != NULL && PyDict_Size(keywords)) {
                PyErr_SetString(PyExc_TypeError, "native image entry accepts six positional arguments");
                break;
            }
            (void)PyArg_UnpackTuple(args, "native image entry", 6, 6,
                &call.values[0], &call.values[1], &call.values[2],
                &call.values[3], &call.values[4], &call.values[5]);
            break;
        case 3:
            if (mode != 1 || at >= 3 || call.values[2*at+1] == NULL) goto invalid_effect;
            value = PyLong_CheckExact(call.values[2*at+1]) ? 1 : 0;
            break;
        case 4:
            if (mode != 1 || at >= 3 || call.values[2*at+1] == NULL) goto invalid_effect;
            value = PyLong_AsUnsignedLongLong(call.values[2*at+1]);
            if (!PyErr_Occurred()) call.sizes[at] = value;
            break;
        case 5:
            if (mode != 1 || at >= 3 || call.values[2*at] == NULL ||
                    (call.exports & (1u << at))) goto invalid_effect;
            if (PyObject_GetBuffer(call.values[2*at], &call.views[at],
                                  PyBUF_WRITABLE | PyBUF_C_CONTIGUOUS) == 0) {
                call.exports |= 1u << at;
                value = (uint64_t)call.views[at].len;
            }
            break;
        case 6:
            if (mode != 1 || call.exports != 7 || !call.receiver_held) goto invalid_effect;
            Py_BEGIN_ALLOW_THREADS
            value = receiver->entry(call.views[0].buf, call.sizes[0],
                                    call.views[1].buf, call.sizes[1],
                                    call.views[2].buf, call.sizes[2]);
            Py_END_ALLOW_THREADS
            break;
        case 7:
            if (mode != 1 || at >= 3 || !(call.exports & (1u << at))) goto invalid_effect;
            call.exports &= ~(1u << at);
            PyBuffer_Release(&call.views[at]);
            break;
        case 8:
            if (mode != 1 || call.answer != NULL || call.exports) goto invalid_effect;
            call.answer = PyLong_FromUnsignedLongLong(at);
            break;
        case 9:
            if (mode != 1 || !call.receiver_held || call.exports) goto invalid_effect;
            call.receiver_held = 0;
            Py_DECREF(receiver);
            break;
        case 10:
            fixed_error(at);
            break;
        case 11:
            if (mode != 2) goto invalid_effect;
            if (keywords != NULL && PyDict_Size(keywords)) {
                PyErr_SetString(PyExc_TypeError, "Buffer accepts positional arguments only");
                break;
            }
            if (PyArg_UnpackTuple(args, "Buffer", 1, 2, &call.initial, &call.capacity))
                value = (uint64_t)PyTuple_GET_SIZE(args);
            break;
        case 12:
            if (mode != 2 || call.initial == NULL) goto invalid_effect;
            value = PyBytes_CheckExact(call.initial) ? 1 : (PyLong_CheckExact(call.initial) ? 2 : 0);
            break;
        case 13:
            if (mode != 2 || !PyBytes_CheckExact(call.initial)) goto invalid_effect;
            value = (uint64_t)PyBytes_GET_SIZE(call.initial);
            break;
        case 14:
            if (mode != 2) goto invalid_effect;
            value = call.capacity == NULL ? 0 : (PyLong_CheckExact(call.capacity) ? 1 : 2);
            break;
        case 15: {
            PyObject *selected = at == 0 ? call.initial : call.capacity;
            if (mode != 2 || at > 1 || selected == NULL) goto invalid_effect;
            value = (uint64_t)PyLong_AsSsize_t(selected);
            break;
        }
        case 16: {
            if (mode != 2 || call.result != NULL || at > PY_SSIZE_T_MAX || size > at) goto invalid_effect;
            Buffer *value_buffer = (Buffer *)type->tp_alloc(type, 0);
            call.result = (PyObject *)value_buffer;
            if (value_buffer == NULL) break;
            auxiliary = 1;
            value_buffer->size = (Py_ssize_t)at;
            value_buffer->data = PyMem_Calloc((size_t)(at ? at : 1), 1);
            if (value_buffer->data == NULL) PyErr_NoMemory();
            break;
        }
        case 17: {
            Buffer *value_buffer = (Buffer *)call.result;
            if (mode != 2 || value_buffer == NULL || !PyBytes_CheckExact(call.initial) ||
                    at > (uint64_t)value_buffer->size || at != (uint64_t)PyBytes_GET_SIZE(call.initial))
                goto invalid_effect;
            memcpy(value_buffer->data, PyBytes_AS_STRING(call.initial), (size_t)at);
            break;
        }
        case 18:
            if (mode != 3) goto invalid_effect;
            if (keywords != NULL && PyDict_Size(keywords)) {
                PyErr_SetString(PyExc_TypeError, "Image accepts one positional byte string");
                break;
            }
            (void)PyArg_UnpackTuple(args, "Image", 1, 1, &call.initial);
            break;
        case 19:
            if (mode != 3 || call.initial == NULL) goto invalid_effect;
            value = PyBytes_CheckExact(call.initial) ? 1 : 0;
            auxiliary = value ? (uint64_t)PyBytes_GET_SIZE(call.initial) : 0;
            break;
        case 20: {
            if (mode != 3 || call.result != NULL || at == 0 || at > (1u << 20)) goto invalid_effect;
            Image *value_image = (Image *)type->tp_alloc(type, 0);
            call.result = (PyObject *)value_image;
            if (value_image == NULL) break;
            auxiliary = 1;
            value_image->size = (size_t)at;
            value_image->mapping = mmap(NULL, (size_t)at, PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (value_image->mapping == MAP_FAILED) {
                value_image->mapping = NULL;
                PyErr_SetFromErrno(PyExc_OSError);
            }
            break;
        }
        case 21: {
            Image *value_image = (Image *)call.result;
            if (mode != 3 || value_image == NULL || value_image->mapping == NULL ||
                    !PyBytes_CheckExact(call.initial) || at != value_image->size ||
                    at != (uint64_t)PyBytes_GET_SIZE(call.initial)) goto invalid_effect;
            memcpy(value_image->mapping, PyBytes_AS_STRING(call.initial), (size_t)at);
            break;
        }
        case 22: {
            Image *value_image = (Image *)call.result;
            if (mode != 3 || value_image == NULL || value_image->mapping == NULL ||
                    at != value_image->size) goto invalid_effect;
            if (mprotect(value_image->mapping, value_image->size, PROT_READ | PROT_EXEC))
                PyErr_SetFromErrno(PyExc_OSError);
            else
                memcpy(&value_image->entry, &value_image->mapping, sizeof(value_image->entry));
            break;
        }
        case 23:
            if ((mode != 2 && mode != 3) || call.result == NULL) goto invalid_effect;
            Py_CLEAR(call.result);
            break;
        default:
invalid_effect:
            protocol_failure = 1;
            PyErr_SetString(PyExc_RuntimeError, "native carrier requested an unavailable mechanical operation");
            capture_foreign_error(&call);
            goto end;
        }
        request[2] = workspace[2];
        request[3] = action;
        request[4] = PyErr_Occurred() ? 1 : 0;
        request[5] = value;
        request[6] = auxiliary;
        if (request[4]) capture_foreign_error(&call);
    }
    if (!terminal) {
        protocol_failure = 1;
        if (call.error_type == NULL) {
            PyErr_SetString(PyExc_RuntimeError, "native carrier protocol did not terminate");
            capture_foreign_error(&call);
        }
    }
end:
    if (call.exports || call.receiver_held || call.answer || call.result)
        protocol_failure = 1;
    if (protocol_failure) state->protocol_failures++;
    /* Fail-closed emergency resource release is never an admitted HIA result.
     * Normal success/failure already consumed these in the HIA chosen order. */
    for (int at = 2; at >= 0; --at)
        if (call.exports & (1u << at)) PyBuffer_Release(&call.views[at]);
    if (call.receiver_held) Py_DECREF(receiver);
    Py_XDECREF(call.answer); Py_XDECREF(call.result);
    if (call.error_type != NULL) {
        Py_XDECREF(returned); returned = NULL;
        PyErr_Restore(call.error_type, call.error_value, call.error_traceback);
    }
    Py_DECREF(module);
    return returned;
}


static PyObject *image_policy_observation(PyObject *module, PyObject *unused) {
    (void)unused;
    State *state = (State *)PyModule_GetState(module);
    if (state == NULL) return NULL;
    return Py_BuildValue("{s:K,s:K,s:K}", "invocations", (unsigned long long)state->invocations,
        "native_calls", (unsigned long long)state->native_calls,
        "protocol_failures", (unsigned long long)state->protocol_failures);
}
static PyMethodDef image_policy_methods[] = {
    {"_policy_observation", image_policy_observation, METH_NOARGS, "Read actual policy-call diagnostics."},
    {NULL, NULL, 0, NULL}
};
