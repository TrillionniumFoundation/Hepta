/* PSF-licensed CPython v3.12.14 Python/ceval.c monitor helpers.
 * Whole original bodies retained; only prefixed names and one admitted
 * private function pointer are substituted. Not compiled or executed.
 */
static int
cja_do_monitor_exc(PyThreadState *tstate, _PyInterpreterFrame *frame,
               _Py_CODEUNIT *instr, int event)
{
    assert(event < _PY_MONITORING_UNGROUPED_EVENTS);
    PyObject *exc = PyErr_GetRaisedException();
    assert(exc != NULL);
    int err = cj312_control_runtime.instrumentation_arg(tstate, event, frame, instr, exc);
    if (err == 0) {
        PyErr_SetRaisedException(exc);
    }
    else {
        assert(PyErr_Occurred());
        Py_DECREF(exc);
    }
    return err;
}

static inline bool
cja_no_tools_for_global_event(PyThreadState *tstate, int event)
{
    return tstate->interp->monitors.tools[event] == 0;
}

static inline bool
cja_no_tools_for_local_event(PyThreadState *tstate, _PyInterpreterFrame *frame, int event)
{
    assert(event < _PY_MONITORING_LOCAL_EVENTS);
    _PyCoMonitoringData *data = frame->f_code->_co_monitoring;
    if (data) {
        return data->active_monitors.tools[event] == 0;
    }
    else {
        return cja_no_tools_for_global_event(tstate, event);
    }
}

static void
cja_monitor_raise(PyThreadState *tstate, _PyInterpreterFrame *frame,
              _Py_CODEUNIT *instr)
{
    if (cja_no_tools_for_global_event(tstate, PY_MONITORING_EVENT_RAISE)) {
        return;
    }
    cja_do_monitor_exc(tstate, frame, instr, PY_MONITORING_EVENT_RAISE);
}

static void
cja_monitor_reraise(PyThreadState *tstate, _PyInterpreterFrame *frame,
              _Py_CODEUNIT *instr)
{
    if (cja_no_tools_for_global_event(tstate, PY_MONITORING_EVENT_RERAISE)) {
        return;
    }
    cja_do_monitor_exc(tstate, frame, instr, PY_MONITORING_EVENT_RERAISE);
}

static int
cja_monitor_stop_iteration(PyThreadState *tstate, _PyInterpreterFrame *frame,
                       _Py_CODEUNIT *instr)
{
    if (cja_no_tools_for_local_event(tstate, frame, PY_MONITORING_EVENT_STOP_ITERATION)) {
        return 0;
    }
    return cja_do_monitor_exc(tstate, frame, instr, PY_MONITORING_EVENT_STOP_ITERATION);
}

static void
cja_monitor_unwind(PyThreadState *tstate,
               _PyInterpreterFrame *frame,
               _Py_CODEUNIT *instr)
{
    if (cja_no_tools_for_global_event(tstate, PY_MONITORING_EVENT_PY_UNWIND)) {
        return;
    }
    cja_do_monitor_exc(tstate, frame, instr, PY_MONITORING_EVENT_PY_UNWIND);
}


static int
cja_monitor_handled(PyThreadState *tstate,
                _PyInterpreterFrame *frame,
                _Py_CODEUNIT *instr, PyObject *exc)
{
    if (cja_no_tools_for_global_event(tstate, PY_MONITORING_EVENT_EXCEPTION_HANDLED)) {
        return 0;
    }
    return cj312_control_runtime.instrumentation_arg(tstate, PY_MONITORING_EVENT_EXCEPTION_HANDLED, frame, instr, exc);
}

static void
cja_monitor_throw(PyThreadState *tstate,
              _PyInterpreterFrame *frame,
              _Py_CODEUNIT *instr)
{
    if (cja_no_tools_for_global_event(tstate, PY_MONITORING_EVENT_PY_THROW)) {
        return;
    }
    cja_do_monitor_exc(tstate, frame, instr, PY_MONITORING_EVENT_PY_THROW);
}
