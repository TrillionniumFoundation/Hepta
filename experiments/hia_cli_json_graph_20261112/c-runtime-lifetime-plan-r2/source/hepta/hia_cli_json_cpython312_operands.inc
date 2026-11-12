/* Actual 3.12.14 operand-stack transactions, selected by HIA.
 *
 * Included inside hia_cli_json_leaf's switch.  These perform one original
 * object-runtime instruction against the actual generator's owned stack.
 * HIA chooses the instruction, branches, known scalar/sort routing, nested
 * generator routing and exception-table unwind.  No retained JSON generator
 * body is evaluated here.  Foreign Python functions still use their actual
 * argument binder/evaluator; its extra C entry, monitoring and eval-breaker
 * scheduling are open until the complete C driver is implemented and tested.
 *
 * Source: PSF-licensed CPython v3.12.14 Python/bytecodes.c and ceval.c.
 * Uncompiled/unexecuted development source; not a public selector.
 */
#if PY_VERSION_HEX == 0x030c0ef0
    case CJ_PY312_STACK_CALL: {
        _PyInterpreterFrame *owned = cj312_operand_frame(a);
        if (!owned || ctx->slot || frame->raised || frame->b > INT_MAX ||
                frame->d || frame->e) goto abi_error;
        int *top = cj312_stack_top(owned);
        int oparg = (int)frame->b;
        if (oparg > *top - owned->f_code->co_nlocalsplus - 2) goto abi_error;
        PyObject *kwnames = (PyObject *)(uintptr_t)frame->c;
        if (kwnames && (!PyTuple_CheckExact(kwnames) ||
                PyTuple_GET_SIZE(kwnames) > oparg)) goto abi_error;
        int keywords = kwnames ? (int)PyTuple_GET_SIZE(kwnames) : 0;
        PyObject **args = owned->localsplus + *top - oparg;
        PyObject *method = args[-2];
        PyObject *callable = args[-1];
        if (!callable) goto abi_error;
        for (int i = 0; i < oparg; i++) if (!args[i]) goto abi_error;
        int total_args = oparg;
        if (method != NULL) {
            callable = method;
            args--;
            total_args++;
        }
        else if (Py_IS_TYPE(callable, &PyMethod_Type)) {
            /* Original CALL rewrites the two real stack cells before
             * releasing the old bound method.  Do not copy its arguments
             * to a tuple/list or introduce another owned callable root. */
            args--;
            total_args++;
            PyObject *self = ((PyMethodObject *)callable)->im_self;
            method = ((PyMethodObject *)callable)->im_func;
            args[0] = Py_NewRef(self);
            args[-1] = Py_NewRef(method);
            Py_DECREF(callable);
            callable = method;
        }
        int positional = total_args - keywords;
        PyThreadState *tstate = PyThreadState_Get();
        if (Py_IS_TYPE(callable, &PyFunction_Type) &&
                tstate->interp->eval_frame == NULL &&
                ((PyFunctionObject *)callable)->vectorcall == _PyFunction_Vectorcall) {
            PyFunctionObject *function = (PyFunctionObject *)callable;
            PyCodeObject *code = (PyCodeObject *)function->func_code;
            PyObject *locals = code->co_flags & CO_OPTIMIZED ? NULL :
                Py_NewRef(function->func_globals);
            _PyInterpreterFrame *target = cj312_push_and_init(
                tstate, function, locals, args, positional, kwnames);
            /* PushAndInit consumes the original function/arguments on both
             * return paths.  Shrink AFTER that call, BEFORE evaluation. */
            *top -= oparg + 2;
            frame->result[2] = 1;
            if (target) ctx->slot = _PyEval_EvalFrameDefault(tstate, target, 0);
        }
        else {
            ctx->slot = PyObject_Vectorcall(callable, args,
                positional | PY_VECTORCALL_ARGUMENTS_OFFSET, kwnames);
            Py_DECREF(callable);
            for (int i = 0; i < total_args; i++) Py_DECREF(args[i]);
            *top -= oparg + 2;
            frame->result[2] = 2;
        }
        frame->result[0] = (uintptr_t)ctx->slot;
        frame->result[1] = *top;
        break;
    }
    case CJ_PY312_FRAME_CONST:
    case CJ_PY312_FRAME_NAME: {
        _PyInterpreterFrame *owned = cj312_operand_frame(a);
        if (!owned || frame->c > 1 || frame->d || frame->e ||
                (frame->op == CJ_PY312_FRAME_NAME && frame->c) ||
                (frame->op == CJ_PY312_FRAME_CONST && ctx->slot)) goto abi_error;
        PyObject *tuple = frame->op == CJ_PY312_FRAME_CONST ?
            owned->f_code->co_consts : owned->f_code->co_names;
        if (frame->b >= (uint64_t)PyTuple_GET_SIZE(tuple)) goto abi_error;
        PyObject *item = PyTuple_GET_ITEM(tuple, (Py_ssize_t)frame->b);
        if (frame->op == CJ_PY312_FRAME_CONST && frame->c == 0)
            ctx->slot = Py_NewRef(item);
        frame->result[0] = (uintptr_t)item;
        break;
    }
    case CJ_PY312_STACK_TRUTH: {
        _PyInterpreterFrame *owned = cj312_operand_frame(a);
        if (!owned || ctx->slot || frame->raised || frame->b > 1 ||
                frame->c || frame->d || frame->e) goto abi_error;
        int *top = cj312_stack_top(owned);
        if (*top <= owned->f_code->co_nlocalsplus) goto abi_error;
        PyObject *value = owned->localsplus[*top - 1];
        if (!value) goto abi_error;
        int result;
        if (frame->b == 1) {
            /* POP_JUMP_*_NONE uses identity, never object truth. */
            result = Py_IsNone(value);
            if (!result) Py_DECREF(value);
        }
        else if (Py_IsTrue(value)) result = 1;
        else if (Py_IsFalse(value)) result = 0;
        else {
            result = PyObject_IsTrue(value);
            Py_DECREF(value);
        }
        (*top)--;
        frame->result[0] = (uint64_t)(int64_t)result;
        frame->result[1] = *top;
        break;
    }
    case CJ_PY312_STACK_BINARY: {
        _PyInterpreterFrame *owned = cj312_operand_frame(a);
        if (!owned || ctx->slot || frame->raised || frame->c || frame->d || frame->e)
            goto abi_error;
        binaryfunc operation;
        /* These are all BINARY_OP indices in the three fixed JSON generator
         * bodies.  Object/subclass protocols remain the actual runtime's. */
        switch (frame->b) {
            case 0: operation = PyNumber_Add; break;
            case 5: operation = PyNumber_Multiply; break;
            case 10: operation = PyNumber_Subtract; break;
            case 13: operation = PyNumber_InPlaceAdd; break;
            case 23: operation = PyNumber_InPlaceSubtract; break;
            default: goto abi_error;
        }
        int *top = cj312_stack_top(owned);
        if (*top - owned->f_code->co_nlocalsplus < 2) goto abi_error;
        PyObject *left = owned->localsplus[*top - 2];
        PyObject *right = owned->localsplus[*top - 1];
        if (!left || !right) goto abi_error;
        ctx->slot = operation(left, right);
        Py_DECREF(left);
        Py_DECREF(right);
        *top -= 2;
        frame->result[0] = (uintptr_t)ctx->slot;
        frame->result[1] = *top;
        break;
    }
    case CJ_PY312_STACK_GET_ITER:
    case CJ_PY312_STACK_YIELD_FROM_ITER: {
        _PyInterpreterFrame *owned = cj312_operand_frame(a);
        if (!owned || ctx->slot || frame->raised || frame->b || frame->c ||
                frame->d || frame->e) goto abi_error;
        int *top = cj312_stack_top(owned);
        if (*top <= owned->f_code->co_nlocalsplus) goto abi_error;
        PyObject *value = owned->localsplus[*top - 1];
        if (!value) goto abi_error;
        if (frame->op == CJ_PY312_STACK_YIELD_FROM_ITER) {
            if (PyCoro_CheckExact(value)) {
                if (!(owned->f_code->co_flags & (CO_COROUTINE | CO_ITERABLE_COROUTINE))) {
                    PyErr_SetString(PyExc_TypeError,
                        "cannot 'yield from' a coroutine object in a non-coroutine generator");
                    frame->result[1] = *top;
                    break;  /* original error retains the stack operand */
                }
                ctx->slot = value;
            }
            else if (PyGen_CheckExact(value)) ctx->slot = value;
            else {
                ctx->slot = PyObject_GetIter(value);
                if (!ctx->slot) {
                    frame->result[1] = *top;
                    break;  /* unlike GET_ITER, no input DECREF on failure */
                }
                Py_DECREF(value);
            }
        }
        else {
            ctx->slot = PyObject_GetIter(value);
            Py_DECREF(value);
        }
        (*top)--;
        frame->result[0] = (uintptr_t)ctx->slot;
        frame->result[1] = *top;
        break;
    }
    case CJ_PY312_STACK_FOR_NEXT: {
        _PyInterpreterFrame *owned = cj312_operand_frame(a);
        if (!owned || ctx->slot || frame->raised || frame->b || frame->c ||
                frame->d || frame->e) goto abi_error;
        int *top = cj312_stack_top(owned);
        if (*top <= owned->f_code->co_nlocalsplus) goto abi_error;
        PyObject *iterator = owned->localsplus[*top - 1];
        if (!iterator || !Py_TYPE(iterator)->tp_iternext) goto abi_error;
        /* FOR_ITER observes the current slot on every iteration.  It is
         * not list_extend's separately implemented cached-next protocol. */
        ctx->slot = Py_TYPE(iterator)->tp_iternext(iterator);
        if (ctx->slot) frame->result[2] = 1;
        else if (PyErr_Occurred() && !PyErr_ExceptionMatches(PyExc_StopIteration))
            frame->result[2] = 2;
        else {
            PyErr_Clear();
            Py_DECREF(iterator);
            (*top)--;
        }
        frame->result[0] = (uintptr_t)ctx->slot;
        frame->result[1] = *top;
        break;
    }
    case CJ_PY312_STACK_CONTAINS:
    case CJ_PY312_STACK_IS: {
        _PyInterpreterFrame *owned = cj312_operand_frame(a);
        if (!owned || ctx->slot || frame->raised || frame->b > 1 ||
                frame->c || frame->d || frame->e) goto abi_error;
        int *top = cj312_stack_top(owned);
        if (*top - owned->f_code->co_nlocalsplus < 2) goto abi_error;
        PyObject *left = owned->localsplus[*top - 2];
        PyObject *right = owned->localsplus[*top - 1];
        if (!left || !right) goto abi_error;
        int result = frame->op == CJ_PY312_STACK_IS ?
            Py_Is(left, right) : PySequence_Contains(right, left);
        Py_DECREF(left);
        Py_DECREF(right);
        *top -= 2;
        if (result >= 0) ctx->slot = Py_NewRef((result ^ (int)frame->b) ? Py_True : Py_False);
        frame->result[0] = (uintptr_t)ctx->slot;
        frame->result[1] = *top;
        break;
    }
    case CJ_PY312_STACK_SET_ITEM:
    case CJ_PY312_STACK_DEL_ITEM: {
        _PyInterpreterFrame *owned = cj312_operand_frame(a);
        if (!owned || ctx->slot || frame->raised || frame->b || frame->c ||
                frame->d || frame->e) goto abi_error;
        int count = frame->op == CJ_PY312_STACK_SET_ITEM ? 3 : 2;
        int *top = cj312_stack_top(owned);
        if (*top - owned->f_code->co_nlocalsplus < count) goto abi_error;
        PyObject **items = owned->localsplus + *top - count;
        for (int i = 0; i < count; i++) if (!items[i]) goto abi_error;
        int result = count == 3 ? PyObject_SetItem(items[1], items[2], items[0]) :
                                 PyObject_DelItem(items[0], items[1]);
        for (int i = 0; i < count; i++) Py_DECREF(items[i]);
        *top -= count;
        frame->result[0] = (uint64_t)(int64_t)result;
        frame->result[1] = *top;
        break;
    }
    case CJ_PY312_STACK_TUPLE: {
        _PyInterpreterFrame *owned = cj312_operand_frame(a);
        if (!owned || ctx->slot || frame->raised || frame->b > INT_MAX ||
                frame->c || frame->d || frame->e) goto abi_error;
        int *top = cj312_stack_top(owned);
        int count = (int)frame->b;
        if (count > *top - owned->f_code->co_nlocalsplus) goto abi_error;
        PyObject **items = owned->localsplus + *top - count;
        for (int i = 0; i < count; i++) if (!items[i]) goto abi_error;
        /* The exact admitted runtime primitive steals every stack item,
         * including its allocation-failure cleanup, without an extra root. */
        ctx->slot = cj312_runtime.tuple_from_array_steal(items, count);
        *top -= count;
        frame->result[0] = (uintptr_t)ctx->slot;
        frame->result[1] = *top;
        break;
    }
    case CJ_PY312_STACK_ATTR: {
        _PyInterpreterFrame *owned = cj312_operand_frame(a);
        if (!owned || ctx->slot || frame->raised || frame->c || frame->d || frame->e)
            goto abi_error;
        int *top = cj312_stack_top(owned);
        if (*top <= owned->f_code->co_nlocalsplus ||
                (frame->b >> 1) >= (uint64_t)PyTuple_GET_SIZE(owned->f_code->co_names) ||
                ((frame->b & 1) && *top >= owned->f_code->co_nlocalsplus + owned->f_code->co_stacksize))
            goto abi_error;
        PyObject *owner = owned->localsplus[*top - 1];
        if (!owner) goto abi_error;
        PyObject *name = PyTuple_GET_ITEM(owned->f_code->co_names, frame->b >> 1);
        PyObject *result = NULL, *method = NULL;
        if (frame->b & 1) {
            if (_PyObject_GetMethod(owner, name, &method)) {
                /* The self reference is moved, not copied or decrefed. */
                result = owner;
            }
            else {
                Py_DECREF(owner);
                result = method;
                method = NULL;
                if (!result) {
                    (*top)--;
                    frame->result[1] = *top;
                    break;
                }
            }
            owned->localsplus[*top - 1] = method;
            owned->localsplus[*top] = result;
            (*top)++;
        }
        else {
            result = PyObject_GetAttr(owner, name);
            Py_DECREF(owner);
            if (!result) (*top)--;
            else owned->localsplus[*top - 1] = result;
        }
        frame->result[0] = (uintptr_t)result;
        frame->result[1] = *top;
        break;
    }
    case CJ_PY312_STACK_FORMAT: {
        _PyInterpreterFrame *owned = cj312_operand_frame(a);
        if (!owned || ctx->slot || frame->raised || frame->b > 7 ||
                frame->c || frame->d || frame->e) goto abi_error;
        int *top = cj312_stack_top(owned);
        int count = (frame->b & 4) ? 2 : 1;
        if (*top - owned->f_code->co_nlocalsplus < count) goto abi_error;
        PyObject *value = owned->localsplus[*top - count];
        PyObject *format = count == 2 ? owned->localsplus[*top - 1] : NULL;
        if (!value || (count == 2 && !format)) goto abi_error;
        unaryfunc convert = NULL;
        switch (frame->b & 3) {
            case 0: break;
            case 1: convert = PyObject_Str; break;
            case 2: convert = PyObject_Repr; break;
            case 3: convert = PyObject_ASCII; break;
        }
        if (convert) {
            PyObject *converted = convert(value);
            Py_DECREF(value);
            if (!converted) {
                Py_XDECREF(format);
                *top -= count;
                frame->result[1] = *top;
                break;
            }
            value = converted;
        }
        ctx->slot = PyObject_Format(value, format);
        Py_DECREF(value);
        Py_XDECREF(format);
        *top -= count;
        frame->result[0] = (uintptr_t)ctx->slot;
        frame->result[1] = *top;
        break;
    }
    case CJ_PY312_STACK_STRING: {
        _PyInterpreterFrame *owned = cj312_operand_frame(a);
        if (!owned || ctx->slot || frame->raised || frame->b > INT_MAX ||
                frame->c || frame->d || frame->e) goto abi_error;
        int *top = cj312_stack_top(owned);
        int count = (int)frame->b;
        if (count > *top - owned->f_code->co_nlocalsplus) goto abi_error;
        PyObject **items = owned->localsplus + *top - count;
        for (int i = 0; i < count; i++) if (!items[i]) goto abi_error;
        ctx->slot = _PyUnicode_JoinArray(&_Py_STR(empty), items, count);
        for (int i = 0; i < count; i++) Py_DECREF(items[i]);
        *top -= count;
        frame->result[0] = (uintptr_t)ctx->slot;
        frame->result[1] = *top;
        break;
    }
    case CJ_PY312_STACK_STORE_LOCAL: {
        _PyInterpreterFrame *owned = cj312_operand_frame(a);
        if (!owned || ctx->slot || frame->raised || frame->c > 1 ||
                frame->d || frame->e ||
                frame->b >= (uint64_t)owned->f_code->co_nlocalsplus) goto abi_error;
        int *top = cj312_stack_top(owned);
        if (*top <= owned->f_code->co_nlocalsplus) goto abi_error;
        PyObject *value = owned->localsplus[*top - 1];
        if (!value) goto abi_error;
        if (frame->c == 0) {
            PyObject *old = owned->localsplus[frame->b];
            owned->localsplus[frame->b] = value;
            Py_XDECREF(old);
        }
        else {
            PyObject *cell = owned->localsplus[frame->b];
            if (!cell || !PyCell_Check(cell)) goto abi_error;
            PyObject *old = PyCell_GET(cell);
            PyCell_SET(cell, value);
            Py_XDECREF(old);
        }
        /* Both original stores publish the new local/cell before releasing
         * its old value, then relinquish the stack reference. */
        (*top)--;
        frame->result[1] = *top;
        break;
    }
#else
    case CJ_PY312_STACK_CALL:
    case CJ_PY312_FRAME_CONST:
    case CJ_PY312_FRAME_NAME:
    case CJ_PY312_STACK_TRUTH:
    case CJ_PY312_STACK_BINARY:
    case CJ_PY312_STACK_GET_ITER:
    case CJ_PY312_STACK_YIELD_FROM_ITER:
    case CJ_PY312_STACK_FOR_NEXT:
    case CJ_PY312_STACK_CONTAINS:
    case CJ_PY312_STACK_IS:
    case CJ_PY312_STACK_SET_ITEM:
    case CJ_PY312_STACK_DEL_ITEM:
    case CJ_PY312_STACK_TUPLE:
    case CJ_PY312_STACK_ATTR:
    case CJ_PY312_STACK_FORMAT:
    case CJ_PY312_STACK_STRING:
    case CJ_PY312_STACK_STORE_LOCAL:
        goto abi_error;
#endif
