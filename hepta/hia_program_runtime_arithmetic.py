"""Opt-in arithmetic membership preparation for the unchanged Python VM.

Only metadata actually made by the existing ordinary preparation is eligible.
No old VM source or entry limit changes. The one derived operation differs by
one fixed SetComp -> literal Set AST replacement; all old globals stay live.
The exact v9 source is admitted only by inverse to the complete fixed v8
source; the executed derived body is always the actual current interpreter.
Custom metadata and every failed admission use the original Machine/path.
This is Python execution preparation, not native code or an HIA receipt.
"""
from __future__ import annotations
import ast
from hashlib import sha256
from pathlib import Path
import sys
from types import CodeType, FunctionType, MappingProxyType

from .hia_reference_runtime_sources import PACKAGE_SCALAR_SHA256, RESOURCE_RUNTIME_SHA256S, word_runtime_source
from . import hia_program_runtime as _runtime
from . import hia_program_runtime_prepared as _prepared

_RUNTIME_SHA256 = "ce39be78627f253447f1d4e4b3272ba6689c594c31b22e3be204b1fcfea2ca56"
_V9_RUNTIME_SHA256 = "db118314608168799a0d2c1210cec04ba38981a329e8da6cf4debcd07b267aa0"
_V9_IMPORT = "from .hia_opcodes import ExecutionObservationRejected, WORD_LOADS, WORD_STORES, validate_execution_observation\n"
_ORIGINAL_IMPORT = "from .hia_opcodes import ExecutionObservationRejected, validate_execution_observation\n"
_V9_WORD_BRANCH = """        elif op in WORD_LOADS or op in WORD_STORES:
            owner, index = _underlying(args[0]), args[1]
            if op in WORD_STORES and (not isinstance(args[0], _View) or not args[0].mutable):
                raise HIAProgramRejected("word store through non-mutable view", "E_HIA_RUNTIME_INVARIANT")
            extent = len(owner.data)
            # The complete fixed-width range is checked before any memory
            # access. In particular subtraction cannot underflow and no short
            # store may modify a prefix before trapping.
            if index > extent or 8 > extent - index:
                raise HIAProgramTrap("bounds", "u64 word outside the borrowed buffer")
            if op in WORD_LOADS:
                result = [int.from_bytes(owner.data[index:index + 8], WORD_LOADS[op])]
            else:
                owner.data[index:index + 8] = args[2].to_bytes(8, WORD_STORES[op])
"""

def _retained_runtime_source(raw):
    """Admit the exact original, or invert only the independently pinned v9 delta.

    The inverse is an admission proof, never an executed replacement runtime.
    Derivation below still compiles the actual current complete source, including
    every word operation, and changes only the same arithmetic SetComp.
    """
    if type(raw) is not bytes:
        raise ValueError("runtime source must be exact bytes")
    digest = sha256(raw).hexdigest()
    if digest == _RUNTIME_SHA256:
        return raw
    if digest in RESOURCE_RUNTIME_SHA256S:
        raw = word_runtime_source(raw)
        digest = sha256(raw).hexdigest()
    if digest != _V9_RUNTIME_SHA256:
        raise ValueError("arithmetic preparation runtime exceeds the pinned original/v9 sources")
    incoming, previous, branch = (_V9_IMPORT.encode(), _ORIGINAL_IMPORT.encode(),
                                  _V9_WORD_BRANCH.encode())
    if raw.count(incoming) != 1 or raw.count(branch) != 1:
        raise ValueError("pinned v9 runtime delta is not unique")
    restored = raw.replace(incoming, previous).replace(branch, b"")
    if sha256(restored).hexdigest() != _RUNTIME_SHA256:
        raise ValueError("v9 runtime inverse differs from the complete ce39 original")
    return restored


def _word_order_state(raw):
    if sha256(raw).hexdigest() not in (_V9_RUNTIME_SHA256, *RESOURCE_RUNTIME_SHA256S):
        return ()
    expected = (
        ("WORD_LOADS", (("buffer.load.u64.le", "little"), ("buffer.load.u64.be", "big"))),
        ("WORD_STORES", (("buffer.store.u64.le", "little"), ("buffer.store.u64.be", "big"))),
    )
    rows = []
    for name, items in expected:
        mapping = getattr(_runtime, name, None)
        if type(mapping) is not MappingProxyType or tuple(mapping.items()) != items:
            raise ValueError("live v9 runtime byte-order mapping differs: " + name)
        rows.append((name, mapping, items))
    return tuple(rows)

_PREPARED_SHA256 = '21a5d3f8dd32949448f0d3f05633e11b75abf849ed125414a858aa0f85fd8188'
_ARITHMETIC = ('int.add.checked', 'int.add.wrap', 'int.sub.checked',
               'int.sub.wrap', 'int.mul.checked', 'int.mul.wrap')
_MACHINE = _runtime._Machine
# A live view observes later class writes without creating a proxy per operation.
# Do not copy it or bind the operation descriptor before the fallback decision.
_MACHINE_DICTIONARY = vars(_MACHINE)
_PROGRAM = _prepared._PreparedRuntimeProgram
_OPERATION = vars(_MACHINE)['operation']
_INIT = vars(_MACHINE)['__init__']
_INVOKE = vars(_MACHINE)['invoke']
_HELPER_NAMES = ('prepare_runtime_program', '_ordinary_default_program', '_freeze')
_HELPER_FUNCTIONS = tuple(vars(_prepared)[name] for name in _HELPER_NAMES)
_PROGRAM_NAMES = ('__init__', 'as_dict', '__setattr__', '__delattr__')
_PROGRAM_FUNCTIONS = tuple(vars(_PROGRAM)[name] for name in _PROGRAM_NAMES)
_FUNCTIONS = (_INIT, _INVOKE, _OPERATION) + _HELPER_FUNCTIONS + _PROGRAM_FUNCTIONS
_CODES = tuple(fn.__code__ for fn in _FUNCTIONS)
_DEFAULTS = tuple((fn.__defaults__, fn.__kwdefaults__, fn.__closure__) for fn in _FUNCTIONS)
_CACHE = None


def _derived_current(function, stamp):
    # Capture the actual execution target once and compare it with the immutable
    # creation-time receipt. Source/old-method pins alone do not bind this new
    # FunctionType's mutable code/default attributes.
    return (type(stamp) is tuple and len(stamp) == 7
            and type(stamp[6]) is str and stamp[6] in (_RUNTIME_SHA256, _V9_RUNTIME_SHA256, *RESOURCE_RUNTIME_SHA256S)
            and stamp is _CACHE and function is stamp[0]
            and type(function) is FunctionType
            and function.__code__ is stamp[1]
            and function.__globals__ is stamp[2]
            and function.__defaults__ is stamp[3]
            and function.__kwdefaults__ is stamp[4]
            and function.__closure__ is stamp[5])


def _functions_current():
    if (_runtime._Machine is not _MACHINE
            or _prepared._PreparedRuntimeProgram is not _PROGRAM
            or _prepared.MappingProxyType is not MappingProxyType):
        return False
    if not all(vars(_MACHINE).get(name) is fn for name, fn in zip(('__init__', 'invoke', 'operation'), (_INIT, _INVOKE, _OPERATION))):
        return False
    if not all(vars(_prepared).get(name) is fn for name, fn in zip(_HELPER_NAMES, _HELPER_FUNCTIONS)):
        return False
    if not all(vars(_PROGRAM).get(name) is fn for name, fn in zip(_PROGRAM_NAMES, _PROGRAM_FUNCTIONS)):
        return False
    if any(fn.__globals__ is not _runtime.__dict__ for fn in (_INIT, _INVOKE, _OPERATION)):
        return False
    if any(fn.__globals__ is not _prepared.__dict__ for fn in _HELPER_FUNCTIONS + _PROGRAM_FUNCTIONS):
        return False
    return all(type(fn) is FunctionType and fn.__code__ is code
               and fn.__defaults__ is defaults[0]
               and fn.__kwdefaults__ is defaults[1]
               and fn.__closure__ is defaults[2]
               for fn, code, defaults in zip(_FUNCTIONS, _CODES, _DEFAULTS))


def _same_constant(a, b):
    if type(a) is not type(b):
        return False
    if type(b) is CodeType:
        return _same_code(a, b)
    if type(b) is tuple:
        return len(a) == len(b) and all(_same_constant(x, y) for x, y in zip(a, b))
    if type(b) is slice:
        return (_same_constant(a.start, b.start)
                and _same_constant(a.stop, b.stop)
                and _same_constant(a.step, b.step))
    if type(b) is frozenset:
        return (all(type(x) in (str, int, bytes) for x in a)
                and all(type(x) in (str, int, bytes) for x in b) and a == b)
    if b is None or b is Ellipsis or type(b) in (str, bytes, int, bool, float, complex):
        return a == b
    return False


def _same_code(a, b):
    fields = ('co_argcount', 'co_posonlyargcount', 'co_kwonlyargcount', 'co_nlocals',
              'co_stacksize', 'co_flags', 'co_code', 'co_names', 'co_varnames',
              'co_freevars', 'co_cellvars', 'co_name', 'co_qualname',
              'co_firstlineno', 'co_linetable', 'co_exceptiontable')
    return (type(a) is CodeType and type(b) is CodeType
            and all(getattr(a, name) == getattr(b, name) for name in fields)
            and _same_constant(a.co_consts, b.co_consts))


def _find_code(code, qualified_name):
    found = []
    pending = [code]
    while pending:
        item = pending.pop()
        if item.co_qualname == qualified_name:
            found.append(item)
        pending.extend(value for value in item.co_consts if type(value) is CodeType)
    return found[0] if len(found) == 1 else None


def _derived_operation():
    global _CACHE
    if not _functions_current():
        return None
    runtime_path = Path(_runtime.__file__)
    prepared_path = Path(_prepared.__file__)
    try:
        runtime_raw = runtime_path.read_bytes()
        prepared_raw = prepared_path.read_bytes()
    except OSError:
        return None
    if sha256(prepared_raw).hexdigest() != _PREPARED_SHA256:
        return None
    try:
        _retained_runtime_source(runtime_raw)
        _word_order_state(runtime_raw)
    except ValueError:
        return None
    runtime_digest = sha256(runtime_raw).hexdigest()
    stamp = _CACHE
    if stamp is not None:
        if type(stamp) is not tuple or len(stamp) != 7 or stamp[6] != runtime_digest:
            return None
        function = stamp[0]
        return function if _derived_current(function, stamp) else None
    old = compile(runtime_raw, _OPERATION.__code__.co_filename, 'exec',
                  dont_inherit=True, optimize=sys.flags.optimize)
    helper = compile(prepared_raw, _HELPER_FUNCTIONS[0].__code__.co_filename,
                     'exec', dont_inherit=True, optimize=sys.flags.optimize)
    for fn in (_INIT, _INVOKE, _OPERATION):
        expected = _find_code(old, fn.__qualname__)
        if expected is None or not _same_code(fn.__code__, expected):
            return None
    for fn in _HELPER_FUNCTIONS + _PROGRAM_FUNCTIONS:
        expected = _find_code(helper, fn.__qualname__)
        if expected is None or not _same_code(fn.__code__, expected):
            return None
    tree = ast.parse(runtime_raw)
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef)
               and node.name == '_Machine')
    operation = next(node for node in cls.body if isinstance(node, ast.FunctionDef)
                     and node.name == 'operation')
    before = ast.dump(operation, include_attributes=False)
    target = ast.parse('{f"int.{a}.{m}" for a in ("add", "sub", "mul") for m in ("checked", "wrap")}',
                       mode='eval').body
    matches = [node for node in ast.walk(operation) if isinstance(node, ast.SetComp)
               and ast.dump(node, include_attributes=False) == ast.dump(target, include_attributes=False)]
    if len(matches) != 1:
        return None
    selected = matches[0]
    literal = ast.copy_location(ast.Set(elts=[ast.Constant(x) for x in _ARITHMETIC]), selected)
    replacements = 0
    for parent in ast.walk(operation):
        for field, value in ast.iter_fields(parent):
            if value is selected:
                setattr(parent, field, literal)
                replacements += 1
            elif type(value) is list:
                for index, item in enumerate(value):
                    if item is selected:
                        value[index] = literal
                        replacements += 1
    if replacements != 1:
        return None
    changed = operation
    # Compiling definitions creates code objects only; no module/class body runs.
    # Retain only the mechanically derived operation, not a second VM module.
    fields = dict(name='_Machine', bases=[], keywords=[], body=[changed], decorator_list=[])
    if 'type_params' in ast.ClassDef._fields:
        fields['type_params'] = []
    container = ast.copy_location(ast.ClassDef(**fields), cls)
    futures = [node for node in tree.body if isinstance(node, ast.ImportFrom)
               and node.module == '__future__']
    unit = ast.fix_missing_locations(ast.Module(body=futures + [container], type_ignores=[]))
    transformed = compile(unit, _OPERATION.__code__.co_filename, 'exec',
                          dont_inherit=True, optimize=sys.flags.optimize)
    code = _find_code(transformed, '_Machine.operation')
    if code is None or before == ast.dump(changed, include_attributes=False):
        return None
    if (runtime_path.read_bytes() != runtime_raw or prepared_path.read_bytes() != prepared_raw
            or not _functions_current()):
        return None
    function = FunctionType(code, _OPERATION.__globals__, _OPERATION.__name__,
                            _OPERATION.__defaults__, _OPERATION.__closure__)
    function.__kwdefaults__ = _OPERATION.__kwdefaults__
    _CACHE = (function, function.__code__, function.__globals__,
              function.__defaults__, function.__kwdefaults__, function.__closure__, runtime_digest)
    return function


class _Authority:
    __slots__ = ('program', 'original', 'document', 'canonical', 'structured',
                 'functions', 'instructions', 'operation', 'operation_stamp')

    def __init__(self, program, original, operation):
        self.program, self.original = program, original
        self.document = object.__getattribute__(program, '_document')
        self.canonical = object.__getattribute__(program, '_canonical')
        self.structured = object.__getattribute__(program, '_structured')
        self.functions = ()
        self.instructions = None
        # A privately constructed VerifiedProgram need not be a verifier result.
        # Inspect only exact containers produced by _freeze; malformed/custom
        # metadata keeps the original constructor and operation errors.
        if type(self.document) is not MappingProxyType:
            return
        functions = self.document.get('functions')
        if type(functions) is not tuple:
            return
        self.functions = functions
        entries = {}
        for function in self.functions:
            if type(function) is not MappingProxyType:
                return
            blocks = function.get('blocks')
            if type(blocks) is not tuple:
                return
            for block in blocks:
                if type(block) is not MappingProxyType:
                    return
                instructions = block.get('ops')
                if type(instructions) is not tuple:
                    return
                for instruction in instructions:
                    if (type(instruction) is not MappingProxyType
                            or type(instruction.get('op')) is not str):
                        return
                    entries[id(instruction)] = instruction
        self.instructions = MappingProxyType(entries)
        self.operation = operation
        self.operation_stamp = _CACHE

    def current(self):
        program = self.program
        return (self.instructions is not None
                and _functions_current()
                and _derived_current(self.operation, self.operation_stamp)
                and type(program) is _PROGRAM
                and object.__getattribute__(program, '_program') is self.original
                and object.__getattribute__(program, '_document') is self.document
                and object.__getattribute__(program, '_canonical') is self.canonical
                and object.__getattribute__(program, '_structured') is self.structured
                and _prepared._ordinary_default_program(self.original)
                and object.__getattribute__(self.original, 'canonical_bytes') == self.canonical
                and object.__getattribute__(self.original, 'structured_bytes') == self.structured)

    def matches_functions(self, functions):
        return (type(functions) is dict and len(functions) == len(self.functions)
                and all(a is b for a, b in zip(functions.values(), self.functions)))


class _PreparedMachine(_MACHINE):
    """Fresh original state; only admitted instruction membership is derived."""
    __slots__ = ('_arithmetic_authority', '_arithmetic_active')

    def __init__(self, authority, program, max_steps, max_heap_bytes,
                 allocation_fail_at, max_call_depth):
        self._arithmetic_authority = authority
        self._arithmetic_active = False
        super().__init__(program, max_steps, max_heap_bytes,
                         allocation_fail_at, max_call_depth)
        # No second as_dict/decode call. Check the function objects actually
        # captured by the single original constructor against the held snapshot.
        self._arithmetic_active = (authority.current()
                                   and authority.matches_functions(self.functions))

    def operation(self, instruction, environment, depth):
        authority = self._arithmetic_authority
        # No lookup/hash/equality on a foreign instruction before fallback.
        # Existing instances also observe later base-operation replacement.
        if (self._arithmetic_active
                and _MACHINE_DICTIONARY.get('operation') is _OPERATION
                and _OPERATION.__code__ is _CODES[2]
                and authority.instructions.get(id(instruction)) is instruction):
            target, stamp = authority.operation, authority.operation_stamp
            # Same ordered predicate as _derived_current, inlined only here.
            # Keep the actual target captured above through the final call.
            if (type(stamp) is tuple and len(stamp) == 7
                    and type(stamp[6]) is str and stamp[6] in (_RUNTIME_SHA256, _V9_RUNTIME_SHA256, *RESOURCE_RUNTIME_SHA256S)
                    and stamp is _CACHE and target is stamp[0]
                    and type(target) is FunctionType
                    and target.__code__ is stamp[1]
                    and target.__globals__ is stamp[2]
                    and target.__defaults__ is stamp[3]
                    and target.__kwdefaults__ is stamp[4]
                    and target.__closure__ is stamp[5]):
                return target(self, instruction, environment, depth)
        return super().operation(instruction, environment, depth)


class _Factory:
    __slots__ = ('_authority',)

    def __init__(self, authority):
        self._authority = authority

    def __call__(self, program, max_steps, max_heap_bytes,
                 allocation_fail_at, max_call_depth):
        authority = self._authority
        if program is authority.program and authority.current():
            return _PreparedMachine(authority, program, max_steps, max_heap_bytes,
                                    allocation_fail_at, max_call_depth)
        return _runtime._Machine(program, max_steps, max_heap_bytes,
                                 allocation_fail_at, max_call_depth)


def prepare_arithmetic_runtime(program):
    """Return (program, machine_factory), without executing any VM operation.

    A previously supplied/private prepared wrapper is not admission authority.
    Only a fresh result of the existing ordinary metadata preparation is held
    by this factory. Allocation/compile failures during this new opt-in setup
    are host failures, not logical VM allocation-budget events; no per-allocation
    failure equivalence or timing/GC-history equivalence is claimed.
    """
    if not _functions_current() or not _prepared._ordinary_default_program(program):
        return program, _runtime._Machine
    operation = _derived_operation()
    if operation is None:
        return program, _runtime._Machine
    prepared = _prepared.prepare_runtime_program(program)
    if (prepared is program or type(prepared) is not _PROGRAM
            or not _functions_current()
            or not _prepared._ordinary_default_program(program)):
        return prepared, _runtime._Machine
    authority = _Authority(prepared, program, operation)
    if authority.instructions is None:
        return program, _runtime._Machine
    if not authority.current():
        return prepared, _runtime._Machine
    return prepared, _Factory(authority)
