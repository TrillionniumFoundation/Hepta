/* Exact CPython v3.12.14 runtime error helpers. PSF License.
 * Source/whole-body inverse pins: RUNTIME-ERRORS-DERIVATION.json.
 * Only two local function identifiers change. No JSON traversal,
 * message selection, normalization or lifetime body is rewritten.
 * Private development ABI; not compiled or executed.
 */

static int
cj312_do_raise(PyThreadState *tstate, PyObject *exc, PyObject *cause)
{
    PyObject *type = NULL, *value = NULL;

    if (exc == NULL) {
        /* Reraise */
        _PyErr_StackItem *exc_info = _PyErr_GetTopmostException(tstate);
        exc = exc_info->exc_value;
        if (Py_IsNone(exc) || exc == NULL) {
            _PyErr_SetString(tstate, PyExc_RuntimeError,
                             "No active exception to reraise");
            return 0;
        }
        Py_INCREF(exc);
        assert(PyExceptionInstance_Check(exc));
        _PyErr_SetRaisedException(tstate, exc);
        return 1;
    }

    /* We support the following forms of raise:
       raise
       raise <instance>
       raise <type> */

    if (PyExceptionClass_Check(exc)) {
        type = exc;
        value = _PyObject_CallNoArgs(exc);
        if (value == NULL)
            goto raise_error;
        if (!PyExceptionInstance_Check(value)) {
            _PyErr_Format(tstate, PyExc_TypeError,
                          "calling %R should have returned an instance of "
                          "BaseException, not %R",
                          type, Py_TYPE(value));
             goto raise_error;
        }
    }
    else if (PyExceptionInstance_Check(exc)) {
        value = exc;
        type = PyExceptionInstance_Class(exc);
        Py_INCREF(type);
    }
    else {
        /* Not something you can raise.  You get an exception
           anyway, just not what you specified :-) */
        Py_DECREF(exc);
        _PyErr_SetString(tstate, PyExc_TypeError,
                         "exceptions must derive from BaseException");
        goto raise_error;
    }

    assert(type != NULL);
    assert(value != NULL);

    if (cause) {
        PyObject *fixed_cause;
        if (PyExceptionClass_Check(cause)) {
            fixed_cause = _PyObject_CallNoArgs(cause);
            if (fixed_cause == NULL)
                goto raise_error;
            Py_DECREF(cause);
        }
        else if (PyExceptionInstance_Check(cause)) {
            fixed_cause = cause;
        }
        else if (Py_IsNone(cause)) {
            Py_DECREF(cause);
            fixed_cause = NULL;
        }
        else {
            _PyErr_SetString(tstate, PyExc_TypeError,
                             "exception causes must derive from "
                             "BaseException");
            goto raise_error;
        }
        PyException_SetCause(value, fixed_cause);
    }

    _PyErr_SetObject(tstate, type, value);
    /* _PyErr_SetObject incref's its arguments */
    Py_DECREF(value);
    Py_DECREF(type);
    return 0;

raise_error:
    Py_XDECREF(value);
    Py_XDECREF(type);
    Py_XDECREF(cause);
    return 0;
}

static PyObject *
cj312_stopiteration_error(PyThreadState* tstate, PyObject *exc)
{
    _PyInterpreterFrame *frame = tstate->cframe->current_frame;
    assert(frame->owner == FRAME_OWNED_BY_GENERATOR);
    assert(PyExceptionInstance_Check(exc));
    const char *msg = NULL;
    if (PyErr_GivenExceptionMatches(exc, PyExc_StopIteration)) {
        msg = "generator raised StopIteration";
        if (frame->f_code->co_flags & CO_ASYNC_GENERATOR) {
            msg = "async generator raised StopIteration";
        }
        else if (frame->f_code->co_flags & CO_COROUTINE) {
            msg = "coroutine raised StopIteration";
        }
    }
    else if ((frame->f_code->co_flags & CO_ASYNC_GENERATOR) &&
            PyErr_GivenExceptionMatches(exc, PyExc_StopAsyncIteration))
    {
        /* code in `gen` raised a StopAsyncIteration error:
        raise a RuntimeError.
        */
        msg = "async generator raised StopAsyncIteration";
    }
    if (msg != NULL) {
        PyObject *message = _PyUnicode_FromASCII(msg, strlen(msg));
        if (message == NULL) {
            return NULL;
        }
        PyObject *error = PyObject_CallOneArg(PyExc_RuntimeError, message);
        if (error == NULL) {
            Py_DECREF(message);
            return NULL;
        }
        assert(PyExceptionInstance_Check(error));
        PyException_SetCause(error, Py_NewRef(exc));
        // Steal exc reference, rather than Py_NewRef+Py_DECREF
        PyException_SetContext(error, Py_NewRef(exc));
        Py_DECREF(message);
        return error;
    }
    return Py_NewRef(exc);
}
