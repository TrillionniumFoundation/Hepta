/* Closed CPython foreign operations selected by carrier_cell_policy.hepta.
 * Only fixed object slots and fixed C API calls are admitted; no supplied pointer
 * or symbol is callable. HIA decides loops, ownership, cleanup and completion. */
#include "carrier_cell_policy.inc"

typedef struct {
    PyObject *values[7], *query;
    PyObject *result, *selected, *bound, *arguments, *keywords, *frame, *answer;
    PyObject *error_type, *error_value, *error_traceback;
    int receiver_held;
} CellCall;

static uint64_t cell_owned(const CellCall *call) {
    return (call->result ? 1u : 0u) | (call->selected ? 2u : 0u) |
           (call->bound ? 4u : 0u) | (call->arguments ? 8u : 0u) |
           (call->keywords ? 16u : 0u) | (call->frame ? 32u : 0u) |
           (call->answer ? 64u : 0u) | (call->receiver_held ? 128u : 0u);
}
static void cell_capture_error(CellCall *call) {
    if (!PyErr_Occurred())
        PyErr_SetString(PyExc_RuntimeError, "closed cell operation lost its exception");
    if (call->error_type == NULL)
        PyErr_Fetch(&call->error_type, &call->error_value, &call->error_traceback);
    else
        PyErr_Clear();
}
static int cell_policy_map(ModuleState *state) {
    state->policy_size = sizeof(hia_carrier_cell_policy);
    state->policy_mapping = mmap(NULL, state->policy_size, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (state->policy_mapping == MAP_FAILED) {
        state->policy_mapping = NULL;
        PyErr_SetFromErrno(PyExc_OSError);
        return -1;
    }
    memcpy(state->policy_mapping, hia_carrier_cell_policy, state->policy_size);
    if (mprotect(state->policy_mapping, state->policy_size, PROT_READ | PROT_EXEC)) {
        int saved = errno;
        munmap(state->policy_mapping, state->policy_size);
        state->policy_mapping = NULL; errno = saved;
        PyErr_SetFromErrno(PyExc_OSError);
        return -1;
    }
    memcpy(&state->policy, &state->policy_mapping, sizeof(state->policy));
    return 0;
}
static PyObject **callback_field(FrameCallback *value, uint64_t index) {
    switch (index) {
    case 0: return &value->factory;
    case 1: return &value->image;
    case 2: return &value->mode;
    case 3: return &value->cells;
    case 4: return &value->namespace;
    case 5: return &value->builtins;
    case 6: return &value->imports;
    default: return NULL;
    }
}
static int cell_release(CellCall *call, PyObject *receiver, uint64_t bit) {
    if (!(cell_owned(call) & bit) || bit == 0 || (bit & (bit - 1))) return -1;
    switch (bit) {
    case 1: Py_CLEAR(call->result); break;
    case 2: Py_CLEAR(call->selected); break;
    case 4: Py_CLEAR(call->bound); break;
    case 8: Py_CLEAR(call->arguments); break;
    case 16: Py_CLEAR(call->keywords); break;
    case 32: Py_CLEAR(call->frame); break;
    case 64: Py_CLEAR(call->answer); break;
    case 128:
        call->receiver_held = 0;
        Py_DECREF(receiver);
        break;
    default: return -1;
    }
    return 0;
}
static void cell_fixed_error(CellCall *call, uint64_t kind) {
    switch (kind) {
    case 1: PyErr_SetString(PyExc_TypeError, "bindings require exact tuples and an empty-cell reader"); break;
    case 2: PyErr_SetString(PyExc_ValueError, "bindings require 1 to 64 matching names and real cells"); break;
    case 3: PyErr_SetString(PyExc_TypeError, "bindings require exact string names and actual cells"); break;
    case 4: PyErr_SetString(PyExc_ValueError, "binding names must be distinct"); break;
    case 5:
        if (call->query != NULL) PyErr_SetObject(PyExc_KeyError, call->query);
        else PyErr_SetString(PyExc_RuntimeError, "cell query is unavailable");
        break;
    case 6: PyErr_SetString(PyExc_RuntimeError, "cell bindings have been released"); break;
    case 7: PyErr_SetString(PyExc_ValueError, "subset requires 1 to 64 live bindings"); break;
    case 8: PyErr_SetString(PyExc_TypeError, "callback requires a frame factory, real cells and actual namespaces"); break;
    case 9: PyErr_SetString(PyExc_RuntimeError, "frame callback has been released"); break;
    default: PyErr_SetString(PyExc_RuntimeError, "unlisted cell exception operation"); break;
    }
}
static PyObject *cell_policy_drive(uint64_t mode, PyTypeObject *type, PyObject *receiver,
                                  PyObject *args, PyObject *kwargs) {
    PyObject *module = PyType_GetModule(type);
    if (module == NULL) return NULL;
    ModuleState *state = (ModuleState *)PyModule_GetState(module);
    if (state == NULL || state->policy == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "cell frame module state is unavailable");
        return NULL;
    }
    Py_INCREF(module); /* Mechanical executable loan; never a graph decision. */
    CellCall call = {0};
    uint64_t request[8] = {UINT64_C(0x3130504343414948), mode, 0, 0, 0, 0, 0, 0};
    uint64_t response[4] = {0}, workspace[64] = {0};
    PyObject *returned = NULL;
    CellBindings *bindings = (mode == 2 || mode == 3) ? (CellBindings *)receiver : NULL;
    FrameCallback *callback = mode == 5 ? (FrameCallback *)receiver : NULL;
    int terminal = 0, protocol_failure = 0;
    state->invocations++;
    for (int step = 0; step < 10000; ++step) {
        state->native_calls++;
        uint64_t status = state->policy(request, sizeof(request), response, sizeof(response),
                                        workspace, sizeof(workspace));
        if (status == 0) {
            terminal = 1;
            uint64_t expected = (mode == 1 || mode == 4) ? 1u : 64u;
            if (response[0] || response[1] > 1 || response[3] ||
                    response[2] != (response[1] ? 0u : expected) ||
                    cell_owned(&call) != response[2] ||
                    (call.error_type != NULL) != (response[1] == 1)) {
                protocol_failure = 1;
                PyErr_SetString(PyExc_RuntimeError, "native cell terminal custody differs");
                cell_capture_error(&call);
            } else if (response[1] == 0) {
                if (expected == 1) { returned = call.result; call.result = NULL; }
                else { returned = call.answer; call.answer = NULL; }
            }
            break;
        }
        if (status != 1 || response[3]) {
            protocol_failure = 1;
            PyErr_SetString(PyExc_RuntimeError, "native cell policy refused an acknowledgement");
            cell_capture_error(&call);
            break;
        }
        uint64_t action = response[0], at = response[1], other = response[2], value = 0;
        switch (action) {
        case 1:
            if ((mode != 2 && mode != 5) || receiver == NULL || call.receiver_held) goto invalid;
            Py_INCREF(receiver); call.receiver_held = 1;
            break;
        case 11: {
            static char *names[] = {"names", "cells", "empty_reader", NULL};
            if (mode != 1) goto invalid;
            (void)PyArg_ParseTupleAndKeywords(args, kwargs, "OOO:CellBindings", names,
                &call.values[0], &call.values[1], &call.values[2]);
            break;
        }
        case 12:
            if (mode != 1 || !call.values[0] || !call.values[1] || !call.values[2]) goto invalid;
            value = (PyTuple_CheckExact(call.values[0]) ? 1u : 0u) |
                    (PyTuple_CheckExact(call.values[1]) ? 2u : 0u) |
                    (PyCallable_Check(call.values[2]) ? 4u : 0u);
            break;
        case 13: case 14: {
            PyObject *tuple = call.values[action - 13];
            if (mode != 1 || !tuple || !PyTuple_CheckExact(tuple)) goto invalid;
            value = (uint64_t)PyTuple_GET_SIZE(tuple);
            break;
        }
        case 15:
            if (mode != 1 || !PyTuple_CheckExact(call.values[0]) || !PyTuple_CheckExact(call.values[1]) ||
                    at >= (uint64_t)PyTuple_GET_SIZE(call.values[0]) || at >= (uint64_t)PyTuple_GET_SIZE(call.values[1])) goto invalid;
            value = (PyUnicode_CheckExact(PyTuple_GET_ITEM(call.values[0], (Py_ssize_t)at)) ? 1u : 0u) |
                    (PyCell_Check(PyTuple_GET_ITEM(call.values[1], (Py_ssize_t)at)) ? 2u : 0u);
            break;
        case 16: {
            if (mode != 1 || !PyTuple_CheckExact(call.values[0]) ||
                    at >= (uint64_t)PyTuple_GET_SIZE(call.values[0]) || other >= at) goto invalid;
            PyObject *a = PyTuple_GET_ITEM(call.values[0], (Py_ssize_t)at);
            PyObject *b = PyTuple_GET_ITEM(call.values[0], (Py_ssize_t)other);
            if (!PyUnicode_CheckExact(a) || !PyUnicode_CheckExact(b)) goto invalid;
            value = PyUnicode_Compare(a, b) == 0 ? 1u : 0u;
            break;
        }
        case 17: {
            if (mode != 1 || call.result || at < 1 || at > CELL_LIMIT) goto invalid;
            CellBindings *created = (CellBindings *)type->tp_alloc(type, 0);
            call.result = (PyObject *)created;
            if (created == NULL) break;
            created->entries = PyMem_Calloc((size_t)at, sizeof(CellEntry));
            if (created->entries == NULL) PyErr_NoMemory();
            else created->count = (Py_ssize_t)at;
            break;
        }
        case 18: {
            CellBindings *created = (CellBindings *)call.result;
            if (mode != 1 || !created || created->empty_reader || !call.values[2]) goto invalid;
            created->empty_reader = Py_NewRef(call.values[2]);
            break;
        }
        case 19: {
            CellBindings *created = (CellBindings *)call.result;
            if (mode != 1 || !created || !created->entries || at >= (uint64_t)created->count ||
                    created->entries[at].name || created->entries[at].cell) goto invalid;
            created->entries[at].name = Py_NewRef(PyTuple_GET_ITEM(call.values[0], (Py_ssize_t)at));
            created->entries[at].cell = Py_NewRef(PyTuple_GET_ITEM(call.values[1], (Py_ssize_t)at));
            break;
        }
        case 21:
            if (!bindings || bindings->count < 0 || bindings->count > CELL_LIMIT) goto invalid;
            value = (uint64_t)bindings->count;
            break;
        case 22:
            if (!bindings) goto invalid;
            if (mode == 2) call.query = args;
            else {
                if (!PyTuple_CheckExact(args) || at >= (uint64_t)PyTuple_GET_SIZE(args)) goto invalid;
                call.query = PyTuple_GET_ITEM(args, (Py_ssize_t)at);
            }
            value = PyUnicode_CheckExact(call.query) ? 1u : 0u;
            break;
        case 23:
            if (!bindings || at >= (uint64_t)bindings->count || !call.query ||
                    !PyUnicode_CheckExact(call.query)) goto invalid;
            if (bindings->entries[at].name != NULL)
                value = PyUnicode_Compare(bindings->entries[at].name, call.query) == 0 ? 1u : 0u;
            break;
        case 24:
            if (mode != 2 || !bindings || at >= (uint64_t)bindings->count) goto invalid;
            value = (bindings->entries[at].cell == NULL || bindings->empty_reader == NULL) ? 0u :
                    (PyCell_GET(bindings->entries[at].cell) != NULL ? 1u : 2u);
            break;
        case 25:
            if (mode != 2 || !bindings || at >= (uint64_t)bindings->count || call.answer ||
                    !bindings->entries[at].cell || !PyCell_GET(bindings->entries[at].cell)) goto invalid;
            call.answer = Py_NewRef(PyCell_GET(bindings->entries[at].cell));
            break;
        case 26:
            if (mode != 2 || !bindings || at >= (uint64_t)bindings->count || call.answer ||
                    !call.receiver_held || !bindings->entries[at].cell || !bindings->empty_reader) goto invalid;
            call.answer = PyObject_CallFunctionObjArgs(bindings->empty_reader,
                bindings->entries[at].name, bindings->entries[at].cell, NULL);
            break;
        case 27:
            if (mode != 3 || !PyTuple_CheckExact(args)) goto invalid;
            value = (uint64_t)PyTuple_GET_SIZE(args);
            break;
        case 28:
            if (mode != 3 || !bindings) goto invalid;
            value = bindings->empty_reader != NULL ? 1u : 0u;
            break;
        case 29:
            if (mode != 3 || call.selected || at < 1 || at > CELL_LIMIT) goto invalid;
            call.selected = PyTuple_New((Py_ssize_t)at);
            break;
        case 30:
            if (mode != 3 || !bindings || at >= (uint64_t)bindings->count || !call.selected ||
                    other >= (uint64_t)PyTuple_GET_SIZE(call.selected) || PyTuple_GET_ITEM(call.selected, (Py_ssize_t)other)) goto invalid;
            if (bindings->entries[at].cell == NULL) {
                PyErr_SetString(PyExc_RuntimeError, "cell bindings have been released");
                break;
            }
            PyTuple_SET_ITEM(call.selected, (Py_ssize_t)other, Py_NewRef(bindings->entries[at].cell));
            break;
        case 31: {
            static char *names[] = {"factory","image","mode","cells","namespace","builtins","imports",NULL};
            if (mode != 4) goto invalid;
            (void)PyArg_ParseTupleAndKeywords(args, kwargs, "OOOOOOO:FrameCallback", names,
                &call.values[0], &call.values[1], &call.values[2], &call.values[3],
                &call.values[4], &call.values[5], &call.values[6]);
            break;
        }
        case 32:
            if (mode != 4 || !call.values[0] || !call.values[6]) goto invalid;
            if (state->bindings_type == NULL) {
                PyErr_SetString(PyExc_RuntimeError, "cell frame module state is unavailable");
                break;
            }
            value = (Py_IS_TYPE(call.values[3], (PyTypeObject *)state->bindings_type) ? 1u : 0u) |
                    (PyCallable_Check(call.values[0]) ? 2u : 0u) |
                    (PyLong_CheckExact(call.values[2]) ? 4u : 0u) |
                    (PyDict_CheckExact(call.values[4]) ? 8u : 0u) |
                    (PyDict_CheckExact(call.values[5]) ? 16u : 0u) |
                    (PyDict_CheckExact(call.values[6]) ? 32u : 0u);
            break;
        case 33:
            if (mode != 4 || call.result) goto invalid;
            call.result = (PyObject *)type->tp_alloc(type, 0);
            break;
        case 34: {
            if (mode != 4 || !call.result || at >= 7) goto invalid;
            PyObject **slot = callback_field((FrameCallback *)call.result, at);
            if (!slot || *slot || !call.values[at]) goto invalid;
            *slot = Py_NewRef(call.values[at]);
            break;
        }
        case 35:
            if (mode != 3 || !bindings || !bindings->empty_reader || !call.selected || call.answer) goto invalid;
            call.answer = PyObject_CallFunctionObjArgs((PyObject *)type,
                args, call.selected, bindings->empty_reader, NULL);
            break;
        case 41: {
            static char *names[] = {"name",NULL};
            if (mode != 5) goto invalid;
            (void)PyArg_ParseTupleAndKeywords(args, kwargs, "O:acyclic", names, &call.values[0]);
            break;
        }
        case 42:
            if (mode != 5 || !callback) goto invalid;
            value = callback->factory != NULL ? 1u : 0u;
            break;
        case 43:
            if (mode != 5 || !callback || !call.receiver_held || !call.values[0] || call.bound || !callback->cells) goto invalid;
            call.bound = Py_BuildValue("{s:O,s:O}", "name", call.values[0], "cells", callback->cells);
            break;
        case 44:
            if (mode != 5 || !callback || !call.bound || call.arguments ||
                    !callback->image || !callback->mode) goto invalid;
            call.arguments = PyTuple_Pack(3, callback->image, callback->mode, call.bound);
            break;
        case 45:
            if (mode != 5 || !callback || call.keywords || !callback->namespace ||
                    !callback->builtins || !callback->imports) goto invalid;
            call.keywords = Py_BuildValue("{s:O,s:O,s:O}", "namespace", callback->namespace,
                "global_builtins", callback->builtins, "import_capsules", callback->imports);
            break;
        case 46:
            if (mode != 5 || !callback || !callback->factory || !call.arguments ||
                    !call.keywords || call.frame) goto invalid;
            call.frame = PyObject_Call(callback->factory, call.arguments, call.keywords);
            break;
        case 47:
            if (mode != 5 || !call.frame || call.answer || call.arguments || call.keywords || call.bound) goto invalid;
            call.answer = PyObject_CallMethod(call.frame, "finish", NULL);
            break;
        case 80:
            if (cell_release(&call, receiver, at) < 0) goto invalid;
            break;
        case 90:
            cell_fixed_error(&call, at);
            break;
        default:
invalid:
            protocol_failure = 1;
            PyErr_SetString(PyExc_RuntimeError, "native cell requested an unavailable mechanical operation");
            cell_capture_error(&call);
            goto done;
        }
        request[2] = workspace[2];
        request[3] = action;
        request[4] = PyErr_Occurred() ? 1u : 0u;
        request[5] = value;
        request[6] = cell_owned(&call);
        if (request[4]) cell_capture_error(&call);
    }
    if (!terminal) {
        protocol_failure = 1;
        if (call.error_type == NULL) {
            PyErr_SetString(PyExc_RuntimeError, "native cell protocol did not terminate");
            cell_capture_error(&call);
        }
    }
done:
    if (cell_owned(&call)) {
        /* Emergency cleanup is never an admitted policy result. */
        protocol_failure = 1;
        const uint64_t order[] = {32,16,8,4,2,64,1,128};
        for (size_t i = 0; i < sizeof(order)/sizeof(order[0]); ++i)
            if (cell_owned(&call) & order[i]) (void)cell_release(&call, receiver, order[i]);
    }
    if (protocol_failure) state->protocol_failures++;
    if (call.error_type != NULL) {
        Py_XDECREF(returned); returned = NULL;
        PyErr_Restore(call.error_type, call.error_value, call.error_traceback);
    }
    Py_DECREF(module);
    return returned;
}
static PyObject *cell_policy_observation(PyObject *module, PyObject *unused) {
    (void)unused;
    ModuleState *state = (ModuleState *)PyModule_GetState(module);
    if (state == NULL) return NULL;
    return Py_BuildValue("{s:K,s:K,s:K}", "invocations", (unsigned long long)state->invocations,
        "native_calls", (unsigned long long)state->native_calls,
        "protocol_failures", (unsigned long long)state->protocol_failures);
}
static PyMethodDef cell_policy_methods[] = {
    {"_policy_observation", cell_policy_observation, METH_NOARGS, "Read actual policy-call diagnostics."},
    {NULL, NULL, 0, NULL}
};
