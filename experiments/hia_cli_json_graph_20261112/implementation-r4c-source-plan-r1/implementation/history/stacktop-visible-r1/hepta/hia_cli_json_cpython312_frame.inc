/* Mechanical 3.12 frame-slot leaves, included inside the one-leaf switch.
 *
 * A raw frame comes from an already-admitted actual PyGenObject; there is no
 * new generator wrapper, copied Python object graph, or Python handle table.
 * All pointers are borrowed except ctx->slot and live localsplus slots below
 * stacktop. HIA chooses all moves, calls, branches and cleanup order.
 *
 * These leaves do not implement frame activation, SEND, the evaluator loop,
 * pending calls, monitoring, or a generator body dispatcher. Until those
 * mechanisms are supplied, these remain unexecuted private ABI source.
 */
#if PY_VERSION_HEX == 0x030c0ef0
    case CJ_PY312_STACK_POP: {
        if (!a || !PyGen_CheckExact(a) || ctx->slot || frame->b || frame->c ||
                frame->d || frame->e) goto abi_error;
        PyGenObject *gen = (PyGenObject *)a;
        if (gen->gi_frame_state >= FRAME_CLEARED) goto abi_error;
        _PyInterpreterFrame *owned = (_PyInterpreterFrame *)gen->gi_iframe;
        if (owned->stacktop <= owned->f_code->co_nlocalsplus ||
                owned->stacktop > owned->f_code->co_nlocalsplus + owned->f_code->co_stacksize)
            goto abi_error;
        /* Original POP relinquishes the top live reference without a new
         * INCREF. The stale non-live storage above stacktop is not an owner. */
        owned->stacktop--;
        ctx->slot = owned->localsplus[owned->stacktop];
        frame->result[0] = (uintptr_t)ctx->slot;
        frame->result[1] = owned->stacktop;
        frame->result[2] = ctx->slot != NULL;  /* CALL's NULL sentinel is legal */
        break;
    }
    case CJ_PY312_STACK_PUSH_SLOT:
    case CJ_PY312_STACK_PUSH_NULL:
    case CJ_PY312_STACK_PUSH_REF: {
        if (!a || !PyGen_CheckExact(a) || frame->c || frame->d || frame->e)
            goto abi_error;
        if (frame->op == CJ_PY312_STACK_PUSH_SLOT && (!ctx->slot || frame->b))
            goto abi_error;
        if (frame->op == CJ_PY312_STACK_PUSH_NULL && (ctx->slot || frame->b))
            goto abi_error;
        if (frame->op == CJ_PY312_STACK_PUSH_REF && (!b || ctx->slot))
            goto abi_error;
        PyGenObject *gen = (PyGenObject *)a;
        if (gen->gi_frame_state >= FRAME_CLEARED) goto abi_error;
        _PyInterpreterFrame *owned = (_PyInterpreterFrame *)gen->gi_iframe;
        if (owned->stacktop < owned->f_code->co_nlocalsplus ||
                owned->stacktop >= owned->f_code->co_nlocalsplus + owned->f_code->co_stacksize)
            goto abi_error;
        PyObject *item = NULL;
        if (frame->op == CJ_PY312_STACK_PUSH_SLOT) {
            item = ctx->slot;
            ctx->slot = NULL;
        }
        else if (frame->op == CJ_PY312_STACK_PUSH_REF) item = Py_NewRef(b);
        owned->localsplus[owned->stacktop++] = item;
        frame->result[0] = owned->stacktop;
        break;
    }
    case CJ_PY312_STACK_PEEK:
    case CJ_PY312_STACK_COPY: {
        if (!a || !PyGen_CheckExact(a) || frame->c || frame->d || frame->e ||
                (frame->op == CJ_PY312_STACK_COPY && ctx->slot)) goto abi_error;
        PyGenObject *gen = (PyGenObject *)a;
        if (gen->gi_frame_state >= FRAME_CLEARED) goto abi_error;
        _PyInterpreterFrame *owned = (_PyInterpreterFrame *)gen->gi_iframe;
        if (owned->stacktop < owned->f_code->co_nlocalsplus ||
                owned->stacktop > owned->f_code->co_nlocalsplus + owned->f_code->co_stacksize ||
                frame->b >= (uint64_t)(owned->stacktop - owned->f_code->co_nlocalsplus))
            goto abi_error;
        PyObject *item = owned->localsplus[owned->stacktop - 1 - frame->b];
        if (frame->op == CJ_PY312_STACK_COPY) ctx->slot = Py_XNewRef(item);
        frame->result[0] = (uintptr_t)item;
        frame->result[1] = owned->stacktop;
        frame->result[2] = item != NULL;
        break;
    }
    case CJ_PY312_DEREF_LOAD:
    case CJ_PY312_DEREF_STORE: {
        if (!a || !PyGen_CheckExact(a) || frame->c || frame->d || frame->e ||
                ((frame->op == CJ_PY312_DEREF_LOAD) ? ctx->slot != NULL : ctx->slot == NULL))
            goto abi_error;
        PyGenObject *gen = (PyGenObject *)a;
        if (gen->gi_frame_state >= FRAME_CLEARED) goto abi_error;
        _PyInterpreterFrame *owned = (_PyInterpreterFrame *)gen->gi_iframe;
        if (frame->b >= (uint64_t)owned->f_code->co_nlocalsplus) goto abi_error;
        PyObject *cell = owned->localsplus[frame->b];
        if (!cell || !PyCell_Check(cell)) goto abi_error;
        PyObject *item = PyCell_GET(cell);
        if (frame->op == CJ_PY312_DEREF_LOAD) {
            /* The HIA bytecode owner selects the original unbound-name
             * error branch if this returns NULL; this leaf does not guess
             * whether the slot is a local cell or a free variable. */
            ctx->slot = Py_XNewRef(item);
            frame->result[0] = (uintptr_t)ctx->slot;
            frame->result[1] = item != NULL;
        }
        else {
            PyCell_SET(cell, ctx->slot);
            ctx->slot = NULL;
            Py_XDECREF(item);  /* commit the replacement before release */
        }
        break;
    }
    case CJ_PY312_CLEAR_EXC_STATE: {
        if (!a || !PyGen_CheckExact(a) || frame->b || frame->c || frame->d || frame->e)
            goto abi_error;
        PyGenObject *gen = (PyGenObject *)a;
        if (gen->gi_frame_state != FRAME_CLEARED || gen->gi_exc_state.previous_item ||
                PyThreadState_Get()->exc_info == &gen->gi_exc_state) goto abi_error;
        /* gen_send_ex2 clears this cycle AFTER evaluator frame cleanup and
         * after disposing a normal None result for the tp_iternext entry.
         * Separate from frame-clear so HIA preserves that ordering. */
        PyObject *old = gen->gi_exc_state.exc_value;
        gen->gi_exc_state.exc_value = NULL;
        Py_XDECREF(old);
        break;
    }
    case CJ_PY312_SUSPEND_AT:
    case CJ_PY312_FRAME_POSITION: {
        if (!a || !PyGen_CheckExact(a) || frame->c || frame->d || frame->e)
            goto abi_error;
        PyGenObject *gen = (PyGenObject *)a;
        if (gen->gi_frame_state >= FRAME_CLEARED) goto abi_error;
        _PyInterpreterFrame *owned = (_PyInterpreterFrame *)gen->gi_iframe;
        if (frame->b >= (uint64_t)Py_SIZE(owned->f_code)) goto abi_error;
        if (frame->op == CJ_PY312_SUSPEND_AT) {
            if (gen->gi_frame_state >= FRAME_EXECUTING || gen->gi_exc_state.previous_item ||
                    PyThreadState_Get()->exc_info == &gen->gi_exc_state ||
                    PyThreadState_Get()->cframe->current_frame == owned ||
                    owned->stacktop < owned->f_code->co_nlocalsplus ||
                    owned->stacktop > owned->f_code->co_nlocalsplus + owned->f_code->co_stacksize)
                goto abi_error;
            gen->gi_frame_state = FRAME_SUSPENDED;
        }
        owned->prev_instr = _PyCode_CODE(owned->f_code) + frame->b;
        frame->result[0] = (uint64_t)(int64_t)gen->gi_frame_state;
        break;
    }
    case CJ_PY312_STACK_SWAP: {
        if (!a || !PyGen_CheckExact(a) || !frame->b || frame->c || frame->d || frame->e)
            goto abi_error;
        PyGenObject *gen = (PyGenObject *)a;
        if (gen->gi_frame_state >= FRAME_CLEARED) goto abi_error;
        _PyInterpreterFrame *owned = (_PyInterpreterFrame *)gen->gi_iframe;
        if (owned->stacktop < owned->f_code->co_nlocalsplus ||
                owned->stacktop > owned->f_code->co_nlocalsplus + owned->f_code->co_stacksize ||
                frame->b >= (uint64_t)(owned->stacktop - owned->f_code->co_nlocalsplus))
            goto abi_error;
        PyObject **top = &owned->localsplus[owned->stacktop - 1];
        PyObject *item = *top;
        *top = top[-(Py_ssize_t)frame->b];
        top[-(Py_ssize_t)frame->b] = item;
        break;
    }
    case CJ_PY312_FRAME_BINDINGS: {
        if (!a || !PyGen_CheckExact(a) || frame->b || frame->c || frame->d || frame->e)
            goto abi_error;
        PyGenObject *gen = (PyGenObject *)a;
        if (gen->gi_frame_state >= FRAME_CLEARED) goto abi_error;
        _PyInterpreterFrame *owned = (_PyInterpreterFrame *)gen->gi_iframe;
        frame->result[0] = (uintptr_t)owned->f_globals;
        frame->result[1] = (uintptr_t)owned->f_builtins;
        frame->result[2] = (uintptr_t)owned->f_code->co_consts;
        frame->result[3] = (uintptr_t)owned->f_code->co_names;
        frame->result[4] = (uintptr_t)owned->f_code->co_localsplusnames;
        frame->result[5] = (uintptr_t)owned->f_code->co_localspluskinds;
        frame->result[6] = (uintptr_t)gen->gi_exc_state.exc_value;
        frame->result[7] = (uintptr_t)owned->previous;
        break;
    }
#else
    case CJ_PY312_STACK_POP:
    case CJ_PY312_STACK_PUSH_SLOT:
    case CJ_PY312_STACK_PUSH_NULL:
    case CJ_PY312_STACK_PEEK:
    case CJ_PY312_DEREF_LOAD:
    case CJ_PY312_DEREF_STORE:
    case CJ_PY312_CLEAR_EXC_STATE:
    case CJ_PY312_SUSPEND_AT:
    case CJ_PY312_STACK_PUSH_REF:
    case CJ_PY312_STACK_SWAP:
    case CJ_PY312_FRAME_POSITION:
    case CJ_PY312_FRAME_BINDINGS:
    case CJ_PY312_STACK_COPY:
        goto abi_error;
#endif
