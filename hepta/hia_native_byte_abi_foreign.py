"""Fixed CPython import instructions for HIA-owned borrowed-byte imports.

HIA chooses each complete original from-list, field load, assignment, and
module retirement. These ports perform one actual IMPORT_NAME or IMPORT_FROM;
they contain no borrowed-byte validation or code-generation policy.
"""
from __future__ import annotations
import dis
import sys
from types import FunctionType

IMPORT_NAMES = ('IMPORTS', 'MAX_FRAME_BYTES', 'SCALARS', '_ARG_REGS',
                '_LOADER_HOOKS', '_normalize', '_prologue', '_reject')


def _profile():
    if sys.implementation.name != 'cpython' or sys.version_info[:2] not in ((3, 12), (3, 13), (3, 14)):
        raise RuntimeError('byte ABI import ports require a reviewed CPython ABI')


def _import_name_port(template, namespace, module, fromlist, level):
    _profile()
    code = template.__code__
    meaningful = tuple(i for i in dis.get_instructions(code, show_caches=True, adaptive=False)
                       if i.opname != 'CACHE')
    imports = tuple(i for i in meaningful if i.opname == 'IMPORT_NAME')
    if code.co_exceptiontable or len(imports) != 1 or imports[0].argval != module:
        raise RuntimeError('byte ABI IMPORT_NAME template differs')
    prefix = tuple(i for i in meaningful if i.offset <= imports[0].offset)
    if (tuple(i.opname for i in prefix) not in (
            ('RESUME', 'LOAD_CONST', 'LOAD_CONST', 'IMPORT_NAME'),
            ('RESUME', 'LOAD_SMALL_INT', 'LOAD_CONST', 'IMPORT_NAME'))
            or prefix[1].argval != level or prefix[2].argval != fromlist):
        raise RuntimeError('byte ABI original import operands differ')
    raw = code.co_code[:imports[0].offset + 2] + bytes((dis.opmap['RETURN_VALUE'], 0))
    return FunctionType(code.replace(co_code=raw, co_name='_byte_abi_import_name',
                                    co_qualname='_byte_abi_import_name'), namespace)


def _from_template(module):
    return module.MAX_FRAME_BYTES


def _import_from_port(name, namespace):
    _profile()
    if name not in IMPORT_NAMES:
        raise RuntimeError('byte ABI imported name is outside the fixed inventory')
    # The original import keeps its module only on the evaluation stack. Move
    # our argument there before IMPORT_FROM, so a held ImportError traceback
    # cannot retain an extra module local after HIA has retired its temporary.
    constants = _from_template.__code__.co_consts
    if None not in constants:
        constants += (None,)
    raw = bytes((dis.opmap['RESUME'], 0, dis.opmap['LOAD_FAST'], 0,
                 dis.opmap['LOAD_CONST'], constants.index(None), dis.opmap['STORE_FAST'], 0,
                 dis.opmap['IMPORT_FROM'], 0, dis.opmap['SWAP'], 2,
                 dis.opmap['POP_TOP'], 0, dis.opmap['RETURN_VALUE'], 0))
    code = _from_template.__code__.replace(co_code=raw, co_names=(name,), co_consts=constants,
        co_stacksize=2, co_name='_byte_abi_import_from', co_qualname='_byte_abi_import_from')
    function = FunctionType(code, namespace)
    if tuple(i.opname for i in dis.get_instructions(function)) != (
            'RESUME', 'LOAD_FAST', 'LOAD_CONST', 'STORE_FAST',
            'IMPORT_FROM', 'SWAP', 'POP_TOP', 'RETURN_VALUE'):
        raise RuntimeError('byte ABI IMPORT_FROM primitive differs')
    return function


def _import_template_0():
    from .hia_program import SCALARS


def _import_template_1():
    from .hia_program_native import IMPORTS, _LOADER_HOOKS, _reject


def _import_template_2():
    from .hia_program_native import MAX_FRAME_BYTES, _ARG_REGS, _normalize, _prologue, _reject


def import_ports(namespace):
    return ({
        ('hia_program', ('SCALARS',)): _import_name_port(
            _import_template_0, namespace, 'hia_program', ('SCALARS',), 1),
        ('hia_program_native', ('IMPORTS', '_LOADER_HOOKS', '_reject')): _import_name_port(
            _import_template_1, namespace, 'hia_program_native', ('IMPORTS', '_LOADER_HOOKS', '_reject'), 1),
        ('hia_program_native', ('MAX_FRAME_BYTES', '_ARG_REGS', '_normalize', '_prologue', '_reject')): _import_name_port(
            _import_template_2, namespace, 'hia_program_native', ('MAX_FRAME_BYTES', '_ARG_REGS', '_normalize', '_prologue', '_reject'), 1),
    }, {name: _import_from_port(name, namespace) for name in IMPORT_NAMES})
