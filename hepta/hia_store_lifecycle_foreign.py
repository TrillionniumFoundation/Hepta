"""Fixed CPython CALL/IMPORT/name-error ports, without Store policy.

HIA chooses the operation, operands, order and one-use effect permission.
No Store body or SQLite policy is interpreted or compiled by this bridge.
"""
from __future__ import annotations
import dis
import sys
from types import FunctionType

def _profile():
    if sys.implementation.name != 'cpython' or sys.version_info[:2] not in ((3, 12), (3, 13), (3, 14)):
        raise RuntimeError('store-lifecycle ports require a reviewed CPython ABI')


TABLE_SHA256 = '5402eccb7adea1001ae8ebdadae681fbe215094f4d1541a14c521c13da5227e5'

FUNCTION_LAYOUT = ((1, 'function', 370, 2, 0), (2, 'function', 34, 1, 0))
IMPORT_NAMES = ('admitted_artifact_namespace', 'admitted_execution_budget', 'admitted_request_journal', 'admitted_slot_ledger', 'artifact_namespace_store', 'execution_budget_store', 'request_journal_store', 'slot_ledger_store')
def _import_name_port(template, namespace, module, fromlist, level):
    _profile()
    code = template.__code__
    meaningful = tuple(i for i in dis.get_instructions(code, show_caches=True, adaptive=False)
                       if i.opname != 'CACHE')
    imports = tuple(i for i in meaningful if i.opname == 'IMPORT_NAME')
    if code.co_exceptiontable or len(imports) != 1 or imports[0].argval != module:
        raise RuntimeError('store-lifecycle IMPORT_NAME template differs')
    prefix = tuple(i for i in meaningful if i.offset <= imports[0].offset)
    if (tuple(i.opname for i in prefix) not in (
            ('RESUME', 'LOAD_CONST', 'LOAD_CONST', 'IMPORT_NAME'),
            ('RESUME', 'LOAD_SMALL_INT', 'LOAD_CONST', 'IMPORT_NAME'))
            or prefix[1].argval != level or prefix[2].argval != fromlist):
        raise RuntimeError('store-lifecycle original import operands differ')
    raw = code.co_code[:imports[0].offset + 2] + bytes((dis.opmap['RETURN_VALUE'], 0))
    return FunctionType(code.replace(co_code=raw, co_name='_store_lifecycle_import_name',
                                    co_qualname='_store_lifecycle_import_name'), namespace)

def _from_template(module):
    return module.ARTIFACT_PROFILE

def _import_from_port(name, namespace):
    _profile()
    if name not in IMPORT_NAMES:
        raise RuntimeError('store-lifecycle imported name is outside the fixed inventory')
    # Actual IMPORT_FROM includes CPython's original circular-import fallback
    # and error formatting. A generic getattr would not implement that port.
    # Move the argument onto the interpreter stack before the import. A held
    # ImportError must not retain an extra module parameter in this port's
    # traceback after the HIA controller has retired its module temporary.
    constants = _from_template.__code__.co_consts
    if None not in constants:
        constants += (None,)
    raw = bytes((dis.opmap['RESUME'], 0, dis.opmap['LOAD_FAST'], 0,
                 dis.opmap['LOAD_CONST'], constants.index(None), dis.opmap['STORE_FAST'], 0,
                 dis.opmap['IMPORT_FROM'], 0, dis.opmap['SWAP'], 2,
                 dis.opmap['POP_TOP'], 0, dis.opmap['RETURN_VALUE'], 0))
    code = _from_template.__code__.replace(co_code=raw, co_names=(name,), co_consts=constants,
        co_stacksize=2, co_name='_store_lifecycle_import_from', co_qualname='_store_lifecycle_import_from')
    function = FunctionType(code, namespace)
    if tuple(i.opname for i in dis.get_instructions(function)) != (
            'RESUME', 'LOAD_FAST', 'LOAD_CONST', 'STORE_FAST',
            'IMPORT_FROM', 'SWAP', 'POP_TOP', 'RETURN_VALUE'):
        raise RuntimeError('store-lifecycle IMPORT_FROM primitive differs')
    return function


def _unbound_template():
    value: object
    return value


def _empty_free_template():
    if False:
        value = None
    return lambda: value


_EMPTY_FREE = _empty_free_template()
_UNBOUND_PORTS = {}


def unbound(name, free):
    _profile()
    if type(name) is not str or type(free) is not int or free not in (0, 1):
        raise RuntimeError('store-lifecycle unbound-name representation differs')
    key = (name, free)
    if key not in _UNBOUND_PORTS:
        if free:
            code = _EMPTY_FREE.__code__.replace(co_freevars=(name,))
            function = FunctionType(code, globals(), closure=_EMPTY_FREE.__closure__)
            expected = 'LOAD_DEREF'
        else:
            code = _unbound_template.__code__.replace(co_varnames=(name,))
            function = FunctionType(code, globals())
            expected = 'LOAD_FAST_CHECK'
        instructions = tuple(dis.get_instructions(function, adaptive=False))
        if not any(item.opname == expected and item.argval == name for item in instructions):
            raise RuntimeError('store-lifecycle unbound interpreter opcode differs')
        _UNBOUND_PORTS[key] = function
    return _UNBOUND_PORTS[key]()
def _import_template_0():
    from .hia_artifact_namespace_native import admitted_artifact_namespace, artifact_namespace_store

def _import_template_1():
    from .hia_execution_budget import admitted_execution_budget, execution_budget_store

def _import_template_2():
    from .hia_request_journal_native import admitted_request_journal, request_journal_store

def _import_template_3():
    from .hia_slot_ledger_continuation_native import admitted_slot_ledger, slot_ledger_store

def import_ports(namespace):
    return ({
        ('hia_artifact_namespace_native', ('admitted_artifact_namespace', 'artifact_namespace_store')): _import_name_port(_import_template_0, namespace, 'hia_artifact_namespace_native', ('admitted_artifact_namespace', 'artifact_namespace_store'), 1),
        ('hia_execution_budget', ('admitted_execution_budget', 'execution_budget_store')): _import_name_port(_import_template_1, namespace, 'hia_execution_budget', ('admitted_execution_budget', 'execution_budget_store'), 1),
        ('hia_request_journal_native', ('admitted_request_journal', 'request_journal_store')): _import_name_port(_import_template_2, namespace, 'hia_request_journal_native', ('admitted_request_journal', 'request_journal_store'), 1),
        ('hia_slot_ledger_continuation_native', ('admitted_slot_ledger', 'slot_ledger_store')): _import_name_port(_import_template_3, namespace, 'hia_slot_ledger_continuation_native', ('admitted_slot_ledger', 'slot_ledger_store'), 1),
    }, {name: _import_from_port(name, namespace) for name in IMPORT_NAMES})

def _call_0(frame, slots):
    return frame._move(slots[0])()

def _call_1(frame, slots):
    return frame._move(slots[0])(mode=frame._move(slots[1]), exist_ok=frame._move(slots[2]))

def _call_2(frame, slots):
    return frame._move(slots[0])(mode=frame._move(slots[1]), parents=frame._move(slots[2]), exist_ok=frame._move(slots[3]))

def _call_3(frame, slots):
    return frame._move(slots[0])(namespace_admission=frame._move(slots[1]), request_admission=frame._move(slots[2]))

def _call_4(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]))

def _call_5(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), isolation_level=frame._move(slots[2]), timeout=frame._move(slots[3]), check_same_thread=frame._move(slots[4]))

def _call_6(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]))

def _call_7(frame, slots):
    return frame._move(slots[0])(frame._move(slots[1]), frame._move(slots[2]), shared_lock=frame._move(slots[3]))

CALLS = {
    (0, ()): _call_0,
    (0, ('mode', 'exist_ok')): _call_1,
    (0, ('mode', 'parents', 'exist_ok')): _call_2,
    (0, ('namespace_admission', 'request_admission')): _call_3,
    (1, ()): _call_4,
    (1, ('isolation_level', 'timeout', 'check_same_thread')): _call_5,
    (2, ()): _call_6,
    (2, ('shared_lock',)): _call_7,
}
