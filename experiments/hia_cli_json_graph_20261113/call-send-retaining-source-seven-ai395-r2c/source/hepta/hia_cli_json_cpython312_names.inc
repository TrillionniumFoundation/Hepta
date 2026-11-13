/* PSF-licensed CPython v3.12.14 runtime name diagnostics.
 * Only local helper/macro identifiers change; the actual
 * runtime _Py_ID(name) object is retained. Unexecuted. */

#define CJ312_UNBOUNDLOCAL_ERROR_MSG \
    "cannot access local variable '%s' where it is not associated with a value"
#define CJ312_UNBOUNDFREE_ERROR_MSG \
    "cannot access free variable '%s' where it is not associated with a" \
    " value in enclosing scope"

static void
cj312_format_exc_check_arg(PyThreadState *tstate, PyObject *exc,
                     const char *format_str, PyObject *obj)
{
    const char *obj_str;

    if (!obj)
        return;

    obj_str = PyUnicode_AsUTF8(obj);
    if (!obj_str)
        return;

    _PyErr_Format(tstate, exc, format_str, obj_str);

    if (exc == PyExc_NameError) {
        // Include the name in the NameError exceptions to offer suggestions later.
        PyObject *exc = PyErr_GetRaisedException();
        if (PyErr_GivenExceptionMatches(exc, PyExc_NameError)) {
            if (((PyNameErrorObject*)exc)->name == NULL) {
                // We do not care if this fails because we are going to restore the
                // NameError anyway.
                (void)PyObject_SetAttr(exc, &_Py_ID(name), obj);
            }
        }
        PyErr_SetRaisedException(exc);
    }
}

static void
cj312_format_exc_unbound(PyThreadState *tstate, PyCodeObject *co, int oparg)
{
    PyObject *name;
    /* Don't stomp existing exception */
    if (_PyErr_Occurred(tstate))
        return;
    name = PyTuple_GET_ITEM(co->co_localsplusnames, oparg);
    if (oparg < PyCode_GetFirstFree(co)) {
        cj312_format_exc_check_arg(tstate, PyExc_UnboundLocalError,
                             CJ312_UNBOUNDLOCAL_ERROR_MSG, name);
    } else {
        cj312_format_exc_check_arg(tstate, PyExc_NameError,
                             CJ312_UNBOUNDFREE_ERROR_MSG, name);
    }
}
