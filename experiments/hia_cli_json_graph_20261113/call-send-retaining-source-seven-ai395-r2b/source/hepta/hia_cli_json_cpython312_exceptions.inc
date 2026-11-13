/* Exact-frame exception primitives for the HIA 3.12 continuation.
 * HIA selects the original exception-table target, unwind depth, optional
 * lasti push and traceback-vs-reraise branch.  Each leaf restores/captures
 * only the raised error; the linked generator owns the handled exception.
 * Uncompiled/unexecuted private development source.
 */
#if PY_VERSION_HEX == 0x030c0ef0
    case CJ_PY312_FRAME_UNBOUND: {
        _PyInterpreterFrame *owned = cj312_operand_frame(a);
        if (!owned || ctx->slot || frame->raised || frame->c > 1 ||
                frame->d || frame->e ||
                frame->b >= (uint64_t)owned->f_code->co_nlocalsplus) goto abi_error;
        if (frame->c == 1) {
            cj312_format_exc_unbound(PyThreadState_Get(), owned->f_code, (int)frame->b);
        }
        else {
            cj312_format_exc_check_arg(PyThreadState_Get(), PyExc_UnboundLocalError,
                CJ312_UNBOUNDLOCAL_ERROR_MSG,
                PyTuple_GET_ITEM(owned->f_code->co_localsplusnames, frame->b));
        }
        break;
    }
    case CJ_PY312_TAKE_RAISED: {
        if (!cj312_operand_frame(a) || !frame->raised || ctx->slot ||
                frame->b || frame->c || frame->d || frame->e) goto abi_error;
        ctx->slot = PyErr_GetRaisedException();
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    }
    case CJ_PY312_NEW_LASTI: {
        _PyInterpreterFrame *owned = cj312_operand_frame(a);
        if (!owned || ctx->slot || !frame->raised || frame->b || frame->c ||
                frame->d || frame->e) goto abi_error;
        ctx->slot = PyLong_FromLong(_PyInterpreterFrame_LASTI(owned));
        frame->result[0] = (uintptr_t)ctx->slot;
        break;
    }
    case CJ_PY312_STACK_RAISE: {
        _PyInterpreterFrame *owned = cj312_operand_frame(a);
        if (!owned || ctx->slot || frame->raised || frame->b > 2 ||
                frame->c || frame->d || frame->e) goto abi_error;
        int *top = cj312_stack_top(owned);
        int count = (int)frame->b;
        if (count > *top - owned->f_code->co_nlocalsplus) goto abi_error;
        PyObject **items = owned->localsplus + *top - count;
        for (int i = 0; i < count; i++) if (!items[i]) goto abi_error;
        int reraised = cj312_do_raise(PyThreadState_Get(),
            count ? items[0] : NULL, count == 2 ? items[1] : NULL);
        *top -= count;
        frame->result[0] = reraised;
        frame->result[1] = *top;
        break;
    }
    case CJ_PY312_STACK_RERAISE: {
        _PyInterpreterFrame *owned = cj312_operand_frame(a);
        if (!owned || ctx->slot || frame->raised || frame->b > 2 ||
                frame->c || frame->d || frame->e) goto abi_error;
        int *top = cj312_stack_top(owned);
        if (*top - owned->f_code->co_nlocalsplus <= (int)frame->b) goto abi_error;
        PyObject *error = owned->localsplus[*top - 1];
        if (!error || !PyExceptionInstance_Check(error)) goto abi_error;
        if (frame->b) {
            PyObject *lasti = owned->localsplus[*top - 1 - frame->b];
            if (!lasti || !PyLong_Check(lasti)) {
                PyErr_SetString(PyExc_SystemError, "lasti is not an int");
                frame->result[2] = 1;  /* ordinary error/traceback branch */
                break;
            }
            long location = PyLong_AsLong(lasti);
            if (PyErr_Occurred()) break;
            /* lasti was produced from this original frame's bytecode.
             * Unexpected pointers are a private protocol refusal. */
            if (location < 0 || (uint64_t)location >= (uint64_t)Py_SIZE(owned->f_code))
                goto abi_error;
            owned->prev_instr = _PyCode_CODE(owned->f_code) + location;
        }
        PyErr_SetRaisedException(Py_NewRef(error));
        /* RERAISE retains its original stack references for the exception
         * table's later unwind.  It does not pop/decref the error here. */
        frame->result[0] = (uint64_t)(int64_t)_PyInterpreterFrame_LASTI(owned);
        frame->result[1] = *top;
        break;
    }
    case CJ_PY312_STACK_PUSH_EXC:
    case CJ_PY312_STACK_POP_EXC: {
        _PyInterpreterFrame *owned = cj312_operand_frame(a);
        if (!owned || ctx->slot || frame->raised || frame->b || frame->c ||
                frame->d || frame->e) goto abi_error;
        int *top = cj312_stack_top(owned);
        if (*top <= owned->f_code->co_nlocalsplus) goto abi_error;
        PyObject *value = owned->localsplus[*top - 1];
        _PyErr_StackItem *handled = PyThreadState_Get()->exc_info;
        if (frame->op == CJ_PY312_STACK_PUSH_EXC) {
            if (!value || !PyExceptionInstance_Check(value) ||
                    *top >= owned->f_code->co_nlocalsplus + owned->f_code->co_stacksize)
                goto abi_error;
            PyObject *previous = handled->exc_value ? handled->exc_value : Py_None;
            handled->exc_value = Py_NewRef(value);
            owned->localsplus[*top - 1] = previous;
            owned->localsplus[*top] = value;
            (*top)++;
        }
        else {
            if (!value || (!Py_IsNone(value) && !PyExceptionInstance_Check(value)))
                goto abi_error;
            PyObject *previous = handled->exc_value;
            handled->exc_value = value;
            Py_XDECREF(previous);
            (*top)--;
        }
        frame->result[0] = (uintptr_t)handled->exc_value;
        frame->result[1] = *top;
        break;
    }
    case CJ_PY312_STACK_STOPITERATION: {
        _PyInterpreterFrame *owned = cj312_operand_frame(a);
        if (!owned || ctx->slot || frame->raised || frame->b || frame->c ||
                frame->d || frame->e) goto abi_error;
        int *top = cj312_stack_top(owned);
        if (*top <= owned->f_code->co_nlocalsplus) goto abi_error;
        PyObject *value = owned->localsplus[*top - 1];
        if (!value || !PyExceptionInstance_Check(value)) goto abi_error;
        ctx->slot = cj312_stopiteration_error(PyThreadState_Get(), value);
        Py_DECREF(value);
        (*top)--;
        frame->result[0] = (uintptr_t)ctx->slot;
        frame->result[1] = *top;
        break;
    }
    case CJ_PY312_STACK_END_SEND: {
        _PyInterpreterFrame *owned = cj312_operand_frame(a);
        if (!owned || ctx->slot || frame->raised || frame->b || frame->c ||
                frame->d || frame->e) goto abi_error;
        int *top = cj312_stack_top(owned);
        if (*top - owned->f_code->co_nlocalsplus < 2) goto abi_error;
        PyObject *receiver = owned->localsplus[*top - 2];
        PyObject *value = owned->localsplus[*top - 1];
        if (!receiver || !value) goto abi_error;
        Py_DECREF(receiver);
        (*top)--;
        owned->localsplus[*top - 1] = value;
        frame->result[1] = *top;
        break;
    }
    case CJ_PY312_STACK_CLEANUP_THROW: {
        _PyInterpreterFrame *owned = cj312_operand_frame(a);
        if (!owned || ctx->slot || frame->raised || frame->b || frame->c ||
                frame->d || frame->e) goto abi_error;
        int *top = cj312_stack_top(owned);
        if (*top - owned->f_code->co_nlocalsplus < 3) goto abi_error;
        PyObject **items = owned->localsplus + *top - 3;
        if (!items[0] || !items[1] || !items[2] ||
                !PyExceptionInstance_Check(items[2])) goto abi_error;
        if (PyErr_GivenExceptionMatches(items[2], PyExc_StopIteration)) {
            PyObject *value = Py_NewRef(((PyStopIterationObject *)items[2])->value);
            for (int i = 0; i < 3; i++) Py_DECREF(items[i]);
            *top -= 3;
            owned->localsplus[(*top)++] = Py_None;
            owned->localsplus[(*top)++] = value;
        }
        else {
            PyErr_SetRaisedException(Py_NewRef(items[2]));
            frame->result[2] = 1;  /* exception_unwind, no new traceback */
        }
        frame->result[1] = *top;
        break;
    }
#else
    case CJ_PY312_FRAME_UNBOUND:
    case CJ_PY312_TAKE_RAISED:
    case CJ_PY312_NEW_LASTI:
    case CJ_PY312_STACK_RAISE:
    case CJ_PY312_STACK_RERAISE:
    case CJ_PY312_STACK_PUSH_EXC:
    case CJ_PY312_STACK_POP_EXC:
    case CJ_PY312_STACK_STOPITERATION:
    case CJ_PY312_STACK_END_SEND:
    case CJ_PY312_STACK_CLEANUP_THROW:
        goto abi_error;
#endif
