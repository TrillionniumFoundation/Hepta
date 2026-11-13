/* One primitive per HIA-selected specialized CALL effect, CPython3.12.14.
 *
 * PRIVATE UNEXECUTED SOURCE. Actual physical stack slots carry the original
 * references. HIA owns guards, default/argument copy iteration, argument
 * and callable release order, partial-error stack and child continuation.
 * There is no generic vectorcall replacement for a specialized family.
 * A failed guard returns the original CALL continuation without rewriting
 * the opcode or adding references. Stats/build/runtime admission remains
 * separate from this new source and from the old finite8+10 result.
 */
#if PY_VERSION_HEX == 0x030c0ef0
#include "internal/pycore_object.h"
#define CJF_MAGIC UINT64_C(0x31304643494c4348) /* HCLICF01 */
enum { CJF_NEW=0, CJF_ACTIVE=1, CJF_DONE=2, CJF_BLOCKED=3 };

typedef struct {
    uint64_t magic, permission;
    CJCallLease312 *call;
    unsigned char *state;              /* common512 prefix + private512 extension */
    uint64_t mode, guards, normalized, guard_facts[8];
    uint64_t frame_allocated, copied_arguments, copied_defaults;
    uint64_t argcount, defcount, minargs;
    uint64_t primitive, primitive_returned, recursive_attempted, recursive_entered;
    uint64_t boxed, append_consumed, self_released, early_error, deoptimized;
    uint64_t failure_reason, in_transaction;
    int64_t scalar;
    PyCFunction cfunc;                 /* original C local, not a Python owner */
} CJFastCall312;

static uint64_t cjf_block(CJFastCall312 *f, uint64_t reason) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    f->permission=CJF_BLOCKED; f->failure_reason=reason;
    return cjc_block(f->call,1000+reason);
}

static int cjf_bound(CJFastCall312 *f) {
    CJCallLease312 *c=f->call; unsigned char *w=f->state;
    return c->fast_mode && cjp_get(w,0)==CJC_MAGIC && cjp_get(w,512)==CJF_MAGIC &&
        cjp_get(w,120)==(uintptr_t)c->gen && cjp_get(w,128)==(uintptr_t)c->frame->f_code &&
        cjp_get(w,136)==(uint64_t)(c->instruction-_PyCode_CODE(c->frame->f_code)) &&
        cjp_get(w,144)==(uint64_t)c->oparg && cjp_get(w,152)==(uintptr_t)c->kwnames &&
        !cjp_get(w,240) && cjp_get(w,248)==f->mode &&
        cjp_get(w,48)==(uintptr_t)c->ctx->raised &&
        cjp_get(w,56)==(uintptr_t)(c->result ? c->result : c->ctx->slot);
}

static uint64_t cjf_prepare(CJFastCall312 *f, CJCallLease312 *c, unsigned char *state) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!f || !c || !state || c->magic!=CJC_MAGIC || !c->fast_mode ||
            c->permission!=CJC_NEW || !cjc_live(c) || c->ctx->raised || c->ctx->slot ||
            c->ctx->external || PyErr_Occurred() || !cjd_fast_opcode(c->fast_mode)) return CJ_REFUSAL;
    for (size_t n=0;n<sizeof(*f);n++) if (((unsigned char *)f)[n]) return CJ_REFUSAL;
    for (unsigned n=512;n<1024;n++) if (state[n]) return CJ_REFUSAL;
    f->magic=CJF_MAGIC; f->call=c; f->state=state; f->mode=c->fast_mode;
    cjp_put(state,248,f->mode); cjp_put(state,512,CJF_MAGIC);
    return 0;
}

/* Facts only. Safe type-dependent field reads do not perform a call or
 * choose deoptimization. The HIA guard compares them in the original
 * branch order. No aggregate boolean replaces the HIA guard algorithm. */
static void cjf_guard_facts(CJFastCall312 *f, uint64_t answer[8]) {
    CJCallLease312 *c=f->call; PyObject *callable=c->callable;
    if (f->mode==CALL_BOUND_METHOD_EXACT_ARGS) {
        answer[0]=c->is_method; answer[1]=Py_IS_TYPE(callable,&PyMethod_Type);
        return;
    }
    if (f->mode==CALL_PY_EXACT_ARGS || f->mode==CALL_PY_WITH_DEFAULTS) {
        answer[0]=c->thread->interp->eval_frame==NULL;
        answer[1]=PyFunction_Check(callable);
        answer[3]=(uint32_t)((_PyCallCache *)(c->instruction+1))->func_version[0] |
                  ((uint32_t)((_PyCallCache *)(c->instruction+1))->func_version[1]<<16);
        answer[5]=c->total_args;
        if (answer[1]) {
            PyFunctionObject *func=(PyFunctionObject *)callable;
            PyCodeObject *code=(PyCodeObject *)func->func_code;
            answer[2]=func->func_version; answer[4]=(uint64_t)code->co_argcount;
            answer[6]=_PyThreadState_HasStackSpace(c->thread,code->co_framesize);
            answer[7]=(f->mode==CALL_PY_WITH_DEFAULTS && func->func_defaults) ?
                       (uint64_t)PyTuple_GET_SIZE(func->func_defaults) : 0;
        }
        return;
    }
    answer[3]=c->total_args; answer[4]=c->is_method;
    switch (f->mode) {
    case CALL_NO_KW_TYPE_1: answer[0]=callable==(PyObject *)&PyType_Type; break;
    case CALL_NO_KW_STR_1: answer[0]=callable==(PyObject *)&PyUnicode_Type; break;
    case CALL_NO_KW_TUPLE_1: answer[0]=callable==(PyObject *)&PyTuple_Type; break;
    case CALL_BUILTIN_CLASS:
        answer[0]=PyType_Check(callable);
        if (answer[0]) answer[6]=((PyTypeObject *)callable)->tp_vectorcall!=NULL;
        break;
    case CALL_NO_KW_BUILTIN_O: case CALL_NO_KW_BUILTIN_FAST:
    case CALL_BUILTIN_FAST_WITH_KEYWORDS:
        answer[0]=PyCFunction_CheckExact(callable);
        if (answer[0]) answer[1]=PyCFunction_GET_FLAGS(callable);
        break;
    case CALL_NO_KW_LEN:
        answer[0]=callable==c->thread->interp->callable_cache.len;
        break;
    case CALL_NO_KW_ISINSTANCE:
        answer[0]=callable==c->thread->interp->callable_cache.isinstance;
        break;
    case CALL_NO_KW_LIST_APPEND:
        answer[0]=c->is_method && callable==c->thread->interp->callable_cache.list_append;
        if (c->total_args) answer[2]=PyList_Check(c->args[0]);
        break;
    case CALL_NO_KW_METHOD_DESCRIPTOR_O: case CALL_NO_KW_METHOD_DESCRIPTOR_NOARGS:
    case CALL_NO_KW_METHOD_DESCRIPTOR_FAST: case CALL_METHOD_DESCRIPTOR_FAST_WITH_KEYWORDS:
        answer[0]=Py_IS_TYPE(callable,&PyMethodDescr_Type);
        if (answer[0]) {
            PyMethodDescrObject *descr=(PyMethodDescrObject *)callable;
            answer[1]=descr->d_method->ml_flags;
            if (c->total_args) answer[2]=Py_IS_TYPE(c->args[0],descr->d_common.d_type);
        }
        break;
    }
}

/* A second, mechanical memory/call-signature check before a selected raw
 * primitive. This does not choose a specialization or repair a failed HIA
 * guard: malformed private requests are refused without making the call.
 * Every inspected value is still rooted by the original operand slots. */
static int cjf_primitive_inputs(CJFastCall312 *f) {
    CJCallLease312 *c=f->call; PyObject *callable=c->callable;
    if (!callable || c->total_args<0 || c->kwcount<0 || c->kwcount>c->total_args ||
            c->args!=c->frame->localsplus+c->arg_base ||
            c->arg_base<0 || c->total_args!=c->original_top-c->arg_base)
        return 0;
    for (int n=0;n<c->total_args;n++) if (!c->args[n]) return 0;
    switch (f->mode) {
    case CALL_NO_KW_TYPE_1: case CALL_NO_KW_STR_1: case CALL_NO_KW_TUPLE_1:
        return !c->kwnames && !c->is_method && c->oparg==1 && c->total_args==1 &&
            callable==(PyObject *)(f->mode==CALL_NO_KW_TYPE_1 ? &PyType_Type :
                f->mode==CALL_NO_KW_STR_1 ? &PyUnicode_Type : &PyTuple_Type);
    case CALL_BUILTIN_CLASS:
        return PyType_Check(callable) && ((PyTypeObject *)callable)->tp_vectorcall!=NULL;
    case CALL_NO_KW_BUILTIN_O: case CALL_NO_KW_BUILTIN_FAST:
    case CALL_BUILTIN_FAST_WITH_KEYWORDS: {
        int flags=f->mode==CALL_NO_KW_BUILTIN_O ? METH_O :
            f->mode==CALL_NO_KW_BUILTIN_FAST ? METH_FASTCALL : METH_FASTCALL|METH_KEYWORDS;
        return PyCFunction_CheckExact(callable) && PyCFunction_GET_FLAGS(callable)==flags &&
            PyCFunction_GET_FUNCTION(callable)!=NULL &&
            (f->mode==CALL_BUILTIN_FAST_WITH_KEYWORDS || !c->kwnames) &&
            (f->mode!=CALL_NO_KW_BUILTIN_O || c->total_args==1);
    }
    case CALL_NO_KW_LEN: case CALL_NO_KW_ISINSTANCE:
        return !c->kwnames && c->total_args==(f->mode==CALL_NO_KW_LEN ? 1 : 2) &&
            callable==(f->mode==CALL_NO_KW_LEN ? c->thread->interp->callable_cache.len :
                c->thread->interp->callable_cache.isinstance);
    case CALL_NO_KW_LIST_APPEND:
        return !c->kwnames && c->is_method && c->oparg==1 && c->total_args==2 &&
            callable==c->thread->interp->callable_cache.list_append &&
            PyList_Check(c->args[0]) && cj312_runtime.list_append_take_ref!=NULL &&
            c->instruction+4<_PyCode_CODE(c->frame->f_code)+Py_SIZE(c->frame->f_code) &&
            (c->instruction+4)->op.code==POP_TOP;
    case CALL_NO_KW_METHOD_DESCRIPTOR_O: case CALL_NO_KW_METHOD_DESCRIPTOR_NOARGS:
    case CALL_NO_KW_METHOD_DESCRIPTOR_FAST: case CALL_METHOD_DESCRIPTOR_FAST_WITH_KEYWORDS: {
        if (!Py_IS_TYPE(callable,&PyMethodDescr_Type) || c->total_args<1 ||
                c->kwcount>c->total_args-1) return 0;
        PyMethodDescrObject *d=(PyMethodDescrObject *)callable;
        int flags=f->mode==CALL_NO_KW_METHOD_DESCRIPTOR_O ? METH_O :
            f->mode==CALL_NO_KW_METHOD_DESCRIPTOR_NOARGS ? METH_NOARGS :
            f->mode==CALL_NO_KW_METHOD_DESCRIPTOR_FAST ? METH_FASTCALL : METH_FASTCALL|METH_KEYWORDS;
        return d->d_method && d->d_method->ml_meth && d->d_method->ml_flags==flags &&
            Py_IS_TYPE(c->args[0],d->d_common.d_type) &&
            (f->mode==CALL_METHOD_DESCRIPTOR_FAST_WITH_KEYWORDS || !c->kwnames) &&
            (f->mode!=CALL_NO_KW_METHOD_DESCRIPTOR_O || c->total_args==2) &&
            (f->mode!=CALL_NO_KW_METHOD_DESCRIPTOR_NOARGS || c->total_args==1);
    }
    default: return 0;
    }
}

static uint64_t cjf_leaf(CJFastCall312 *f) {
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (!f || f->magic!=CJF_MAGIC || !f->call || !f->state) return CJ_REFUSAL;
    CJCallLease312 *c=f->call; unsigned char *w=f->state;
    if (f->permission==CJF_DONE || f->permission==CJF_BLOCKED || !cjc_live(c) ||
            !cjf_bound(f) || c->ctx->slot || c->ctx->external || PyErr_Occurred() ||
            cjp_get(w,24)!=1 || cjp_get(w,112) || c->issued!=c->consumed ||
            c->issued==UINT64_MAX || cjp_get(w,16)!=c->issued+1 || cjp_get(w,32)!=c->consumed)
        return cjf_block(f,1);
    uint64_t op=cjp_get(w,64), a=cjp_get(w,72), b=cjp_get(w,80), phase=cjp_get(w,8);
    if ((op!=CJC_INLINE_CHILD && (op<100 || op>117)) || cjp_get(w,88) ||
            cjp_get(w,96) || cjp_get(w,104) || (op!=105 && b)) return cjf_block(f,2);
    if (op!=100 && !c->begun) return cjf_block(f,3);
    switch (op) {
    case 100:
        if (a || c->begun || c->permission!=CJC_NEW || phase!=100 || c->ctx->raised)
            return cjf_block(f,4);
        break;
    case 101:
        if (a || phase!=101 || c->route || c->ctx->raised || c->result || c->child)
            return cjf_block(f,5);
        break;
    case 102:
        if (a || f->mode!=CALL_BOUND_METHOD_EXACT_ARGS || f->normalized ||
                c->is_method || !Py_IS_TYPE(c->callable,&PyMethod_Type) || c->ctx->raised)
            return cjf_block(f,6);
        break;
    case 103:
        if (!f->guards || f->frame_allocated || c->route || c->ctx->raised || c->result || c->child ||
                (f->mode!=CALL_PY_EXACT_ARGS && f->mode!=CALL_PY_WITH_DEFAULTS) ||
                !PyFunction_Check(c->callable) || a!=f->guard_facts[4] || a>INT_MAX ||
                c->thread->interp->eval_frame || c->kwnames ||
                ((PyFunctionObject *)c->callable)->func_version!=f->guard_facts[3] ||
                ((PyCodeObject *)((PyFunctionObject *)c->callable)->func_code)->co_argcount!=(int)a ||
                c->total_args<0 || (uint64_t)c->total_args>a ||
                (f->mode==CALL_PY_EXACT_ARGS && (uint64_t)c->total_args!=a) ||
                (f->mode==CALL_PY_WITH_DEFAULTS &&
                    (!((PyFunctionObject *)c->callable)->func_defaults ||
                     !PyTuple_CheckExact(((PyFunctionObject *)c->callable)->func_defaults) ||
                     f->guard_facts[7]!=(uint64_t)PyTuple_GET_SIZE(((PyFunctionObject *)c->callable)->func_defaults) ||
                     f->guard_facts[7]>a || (uint64_t)c->total_args<a-f->guard_facts[7])) ||
                !_PyThreadState_HasStackSpace(c->thread,((PyCodeObject *)((PyFunctionObject *)c->callable)->func_code)->co_framesize))
            return cjf_block(f,7);
        break;
    case 104:
        if (!f->frame_allocated || !c->child || a!=f->copied_arguments ||
                a>=(uint64_t)c->total_args || f->copied_defaults || c->ctx->raised || c->stack_committed)
            return cjf_block(f,8);
        break;
    case 105:
        if (!f->frame_allocated || !c->child || f->copied_arguments!=(uint64_t)c->total_args ||
                a!=(uint64_t)c->total_args+f->copied_defaults || a>=f->argcount ||
                a<f->minargs || b!=a-f->minargs || b>=f->defcount || c->ctx->raised || c->stack_committed)
            return cjf_block(f,9);
        break;
    case 106:
        if (a!=(uint64_t)c->base || c->stack_committed ||
                (c->route==1 ? (!c->child || f->copied_arguments!=(uint64_t)c->total_args ||
                    f->copied_defaults!=f->argcount-(uint64_t)c->total_args || c->ctx->raised) :
                    (c->route!=2 || !c->callable_released || c->arguments_released!=(uint64_t)c->total_args)))
            return cjf_block(f,10);
        break;
    case CJC_INLINE_CHILD:
        if (c->route!=1 || !c->fast_frame_ready || !c->stack_committed || !c->child ||
                a!=(uintptr_t)c->child || c->ctx->raised || c->result || phase!=6)
            return cjf_block(f,11);
        c->permission=CJC_INLINE_REQUIRED;
        return CJC_INLINE_REQUIRED; /* no consumption/ACK until actual child owner */
    case 107:
        if (a!=f->mode || !f->guards || f->primitive || c->route || c->ctx->raised ||
                c->result || c->child || !cjf_primitive_inputs(f) ||
                ((f->mode==CALL_NO_KW_BUILTIN_O || f->mode==CALL_NO_KW_METHOD_DESCRIPTOR_O ||
                  f->mode==CALL_NO_KW_METHOD_DESCRIPTOR_NOARGS) && !f->recursive_entered))
            return cjf_block(f,12);
        break;
    case 108:
        if (a || !f->guards || f->recursive_attempted || f->primitive || c->ctx->raised ||
                !cjf_primitive_inputs(f) ||
                (f->mode!=CALL_NO_KW_BUILTIN_O && f->mode!=CALL_NO_KW_METHOD_DESCRIPTOR_O &&
                 f->mode!=CALL_NO_KW_METHOD_DESCRIPTOR_NOARGS)) return cjf_block(f,13);
        break;
    case 109:
        if (a || !f->recursive_entered || !f->primitive_returned) return cjf_block(f,14);
        break;
    case 110:
        if (c->route!=2 || !f->primitive_returned || c->stack_committed ||
                (f->mode==CALL_NO_KW_LIST_APPEND ?
                    (!f->append_consumed || f->scalar<0 || f->self_released || a!=0) :
                    (a!=c->arguments_released || a>=(uint64_t)c->total_args)) ||
                (f->mode==CALL_NO_KW_LEN && !c->callable_released)) return cjf_block(f,15);
        break;
    case 111:
        if (a || c->route!=2 || !f->primitive_returned || c->callable_released || c->stack_committed ||
                (f->mode==CALL_NO_KW_LEN ? c->arguments_released!=0 :
                    c->arguments_released!=(uint64_t)c->total_args)) return cjf_block(f,16);
        break;
    case 112:
        if (a || !f->guards || f->primitive || f->frame_allocated || c->route ||
                c->result || c->child || c->ctx->raised || c->callable_released || c->arguments_released)
            return cjf_block(f,17);
        break;
    case 113:
        if (a || c->route!=2 || !c->stack_committed || c->result_moved || c->child ||
                f->mode==CALL_NO_KW_LIST_APPEND) return cjf_block(f,18);
        break;
    case 114:
        if (!c->ctx->raised || c->result || c->stack_committed || c->callable_released ||
                f->recursive_entered ||
                !((f->recursive_attempted && !f->primitive && !c->arguments_released && a==(uint64_t)c->original_top) ||
                  ((f->mode==CALL_NO_KW_LEN || f->mode==CALL_NO_KW_ISINSTANCE) && f->primitive_returned &&
                    f->scalar<0 && !f->boxed && !c->arguments_released && a==(uint64_t)c->original_top) ||
                  (f->mode==CALL_NO_KW_LIST_APPEND && f->primitive_returned && f->scalar<0 &&
                    f->append_consumed && c->arguments_released==1 && a==(uint64_t)c->original_top-1)))
            return cjf_block(f,19);
        break;
    case 115:
        return cjf_block(f,20); /* unassigned operation, never a generic escape */
    case 116: case 117:
        if (!f->primitive_returned || f->scalar<0 || a!=(uint64_t)f->scalar || f->boxed ||
                c->ctx->raised || c->result ||
                (op==116 ? f->mode!=CALL_NO_KW_LEN : f->mode!=CALL_NO_KW_ISINSTANCE))
            return cjf_block(f,21);
        break;
    }
    if (!cjp_increment(&c->leaf_attempts)) return cjf_block(f,22);
    c->issued=cjp_get(w,16); c->consumed=c->issued;
    cjp_put(w,32,c->consumed); cjp_put(w,40,op);
    uint64_t answer[8]={0}; PyObject *incoming=c->ctx->raised; c->ctx->raised=NULL;
    f->in_transaction=1; PyErr_SetRaisedException(incoming);
    switch (op) {
    case 100:
        c->begun=1; c->permission=CJC_ACTIVE; f->permission=CJF_ACTIVE;
        c->owner->pending_stack_owner=c; c->owner->pending_stack_base=c->base;
        cjc_metadata(c,answer);
        break;
    case 101:
        f->guards++; memset(f->guard_facts,0,sizeof(f->guard_facts));
        cjf_guard_facts(f,answer); memcpy(f->guard_facts,answer,sizeof(f->guard_facts));
        break;
    case 102: {
        PyObject *method=c->callable;
        PyObject *self=((PyMethodObject *)method)->im_self;
        PyObject *function=((PyMethodObject *)method)->im_func;
        c->args--; c->arg_base--; c->total_args++; c->is_method=1;
        c->args[0]=Py_NewRef(self); c->args[-1]=Py_NewRef(function);
        c->callable=function; c->last_released=(uintptr_t)method;
        f->normalized=1; f->mode=CALL_PY_EXACT_ARGS;
        Py_DECREF(method);
        break;
    }
    case 103: {
        PyFunctionObject *function=(PyFunctionObject *)c->callable;
        f->argcount=a; f->defcount=f->guard_facts[7]; f->minargs=a-f->defcount;
        c->route=1; f->frame_allocated=1;
        c->child=_PyFrame_PushUnchecked(c->thread,function,(int)a);
        c->callable=NULL; /* actual child consumes the original callable owner */
        answer[0]=(uintptr_t)c->child; answer[1]=a;
        break;
    }
    case 104:
        c->child->localsplus[a]=c->args[a]; f->copied_arguments++;
        answer[0]=f->copied_arguments;
        break;
    case 105: {
        PyFunctionObject *function=(PyFunctionObject *)c->child->f_funcobj;
        PyObject *value=PyTuple_GET_ITEM(function->func_defaults,(Py_ssize_t)b);
        c->child->localsplus[a]=Py_NewRef(value); f->copied_defaults++;
        answer[0]=f->copied_arguments+f->copied_defaults;
        break;
    }
    case 106:
        c->owner->top=c->base; c->committed_top=c->base;
        c->owner->pending_stack_owner=NULL; c->owner->pending_stack_base=0;
        c->stack_committed=1; c->permission=CJC_COMMITTED;
        if (c->route==1) c->fast_frame_ready=1;
        answer[0]=c->base;
        break;
    case 108: {
        if (f->mode==CALL_NO_KW_BUILTIN_O) f->cfunc=PyCFunction_GET_FUNCTION(c->callable);
        else f->cfunc=((PyMethodDescrObject *)c->callable)->d_method->ml_meth;
        f->recursive_attempted=1;
        int result=_Py_EnterRecursiveCallTstate(c->thread," while calling a Python object");
        f->recursive_entered=result==0; answer[0]=(uint64_t)(int64_t)result;
        break;
    }
    case 109:
        _Py_LeaveRecursiveCallTstate(c->thread); f->recursive_entered=0;
        break;
    case 107:
        c->route=2; f->primitive=1;
        switch (f->mode) {
        case CALL_NO_KW_TYPE_1: c->result=Py_NewRef(Py_TYPE(c->args[0])); break;
        case CALL_NO_KW_STR_1: c->result=PyObject_Str(c->args[0]); break;
        case CALL_NO_KW_TUPLE_1: c->result=PySequence_Tuple(c->args[0]); break;
        case CALL_BUILTIN_CLASS: {
            PyTypeObject *type=(PyTypeObject *)c->callable;
            c->result=type->tp_vectorcall((PyObject *)type,c->args,c->total_args-c->kwcount,c->kwnames);
            break;
        }
        case CALL_NO_KW_BUILTIN_O:
            c->result=_PyCFunction_TrampolineCall(f->cfunc,PyCFunction_GET_SELF(c->callable),c->args[0]);
            break;
        case CALL_NO_KW_BUILTIN_FAST: {
            _PyCFunctionFast function=(_PyCFunctionFast)(void (*)(void))PyCFunction_GET_FUNCTION(c->callable);
            c->result=function(PyCFunction_GET_SELF(c->callable),c->args,c->total_args);
            break;
        }
        case CALL_BUILTIN_FAST_WITH_KEYWORDS: {
            _PyCFunctionFastWithKeywords function=(_PyCFunctionFastWithKeywords)(void (*)(void))PyCFunction_GET_FUNCTION(c->callable);
            c->result=function(PyCFunction_GET_SELF(c->callable),c->args,c->total_args-c->kwcount,c->kwnames);
            break;
        }
        case CALL_NO_KW_LEN:
            f->scalar=PyObject_Length(c->args[0]); answer[0]=(uint64_t)f->scalar;
            break;
        case CALL_NO_KW_ISINSTANCE:
            f->scalar=PyObject_IsInstance(c->args[0],c->args[1]); answer[0]=(uint64_t)f->scalar;
            break;
        case CALL_NO_KW_LIST_APPEND:
            f->append_consumed=1; c->arguments_released=1;
            f->scalar=cj312_runtime.list_append_take_ref((PyListObject *)c->args[0],c->args[1]);
            answer[0]=(uint64_t)f->scalar;
            break;
        case CALL_NO_KW_METHOD_DESCRIPTOR_O:
            c->result=_PyCFunction_TrampolineCall(f->cfunc,c->args[0],c->args[1]);
            break;
        case CALL_NO_KW_METHOD_DESCRIPTOR_NOARGS:
            c->result=_PyCFunction_TrampolineCall(f->cfunc,c->args[0],NULL);
            break;
        case CALL_NO_KW_METHOD_DESCRIPTOR_FAST: {
            _PyCFunctionFast function=(_PyCFunctionFast)(void (*)(void))((PyMethodDescrObject *)c->callable)->d_method->ml_meth;
            c->result=function(c->args[0],c->args+1,c->total_args-1);
            break;
        }
        case CALL_METHOD_DESCRIPTOR_FAST_WITH_KEYWORDS: {
            _PyCFunctionFastWithKeywords function=(_PyCFunctionFastWithKeywords)(void (*)(void))((PyMethodDescrObject *)c->callable)->d_method->ml_meth;
            c->result=function(c->args[0],c->args+1,c->total_args-1-c->kwcount,c->kwnames);
            break;
        }
        }
        f->primitive_returned=1;
        break;
    case 110: {
        PyObject *value=c->args[a]; c->arguments_released++; c->last_released=(uintptr_t)value;
        if (f->mode==CALL_NO_KW_LIST_APPEND) f->self_released=1;
        Py_DECREF(value);
        answer[0]=c->arguments_released;
        break;
    }
    case 111: {
        PyObject *value=c->callable; c->callable=NULL;
        c->callable_released=1; c->last_released=(uintptr_t)value;
        Py_DECREF(value);
        answer[0]=1;
        break;
    }
    case 112:
        c->owner->pending_stack_owner=NULL; c->owner->pending_stack_base=0;
        c->begun=0; c->permission=CJC_DONE; f->deoptimized=1;
        answer[0]=c->original_top;
        break;
    case 113:
        c->ctx->slot=c->result; c->result=NULL;
        c->result_moved=1; c->permission=CJC_DONE;
        break;
    case 114:
        /* Only the original AppendTakeRef failure has consumed an operand.
         * Other early failures keep every operand for normal reverse unwind. */
        c->route=2; c->owner->top=(int)a; c->committed_top=(int)a;
        c->owner->pending_stack_owner=NULL; c->owner->pending_stack_base=0;
        c->stack_committed=1; c->permission=CJC_DONE; f->early_error=1;
        answer[0]=a;
        break;
    case 116:
        f->boxed=1; c->result=PyLong_FromSsize_t((Py_ssize_t)f->scalar);
        break;
    case 117:
        f->boxed=1; c->result=PyBool_FromLong((long)f->scalar);
        break;
    }
    if (!PyGILState_Check()) return CJB_GIL_UNAVAILABLE;
    if (PyThreadState_Get()!=c->thread) return cjf_block(f,23);
    c->ctx->raised=PyErr_GetRaisedException(); f->in_transaction=0;
    if (!cjp_increment(&c->leaf_returns)) return cjf_block(f,24);
    if (!cjc_live(c)) return cjf_block(f,25);
    if (op==102) cjc_metadata(c,answer);
    for (unsigned n=0;n<8;n++) cjp_put(w,256+n*8,answer[n]);
    cjp_put(w,48,(uintptr_t)c->ctx->raised);
    cjp_put(w,56,(uintptr_t)(c->result ? c->result : c->ctx->slot));
    cjp_put(w,248,f->mode);
    return 0;
}
#endif
