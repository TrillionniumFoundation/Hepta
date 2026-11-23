"""Explicit native integer factory over the exact original or reviewed v9 interpreter.

This adapter leaves default execute_program, _Machine, Prepared and Arithmetic intact.
Only each selected integer operation body is mechanically replaced. The loop,
all other operations, ticks, resource transitions, validation and report body
are compiled from the admitted original source, not reimplemented here.

This is a partial native execution candidate. Host allocation, Python frame,
GC and arbitrary reflective-history equivalence are not claimed.
"""
from __future__ import annotations

import ast
import copy
from hashlib import sha256
from struct import pack as _ieee_pack
import sys
from types import CodeType, FunctionType, MappingProxyType
import weakref

from .hia_reference_runtime_sources import (PACKAGE_INTEGER_SHA256, PACKAGE_SCALAR_SHA256,
                                            RESOURCE_RUNTIME_SHA256S, word_runtime_source)
from . import hia_program_runtime as original
from . import hia_vm_integer_divrem_protocol as wire
from .hia_native_admission_io import regular_bytes, source_resource_path
from .hia_native_delivery import check_current
from .hia_vm_integer_divrem_native import NativeDivRemBinding, NativeDivRemUnknown, _input_path

RUNTIME_SHA256 = "ce39be78627f253447f1d4e4b3272ba6689c594c31b22e3be204b1fcfea2ca56"
V9_RUNTIME_SHA256 = "db118314608168799a0d2c1210cec04ba38981a329e8da6cf4debcd07b267aa0"
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
    every unselected word operation, then proves all selected-body inverses.
    """
    if type(raw) is not bytes:
        raise ValueError("runtime source must be exact bytes")
    digest = sha256(raw).hexdigest()
    if digest == RUNTIME_SHA256:
        return raw
    if digest in RESOURCE_RUNTIME_SHA256S:
        raw = word_runtime_source(raw)
        digest = sha256(raw).hexdigest()
    if digest != V9_RUNTIME_SHA256:
        raise ValueError("native integer runtime exceeds the pinned original/v9 sources")
    incoming, previous, branch = (_V9_IMPORT.encode(), _ORIGINAL_IMPORT.encode(),
                                  _V9_WORD_BRANCH.encode())
    if raw.count(incoming) != 1 or raw.count(branch) != 1:
        raise ValueError("pinned v9 runtime delta is not unique")
    restored = raw.replace(incoming, previous).replace(branch, b"")
    if sha256(restored).hexdigest() != RUNTIME_SHA256:
        raise ValueError("v9 runtime inverse differs from the complete ce39 original")
    return restored


def _word_order_state(raw):
    if sha256(raw).hexdigest() not in (V9_RUNTIME_SHA256, *RESOURCE_RUNTIME_SHA256S):
        return ()
    expected = (
        ("WORD_LOADS", (("buffer.load.u64.le", "little"), ("buffer.load.u64.be", "big"))),
        ("WORD_STORES", (("buffer.store.u64.le", "little"), ("buffer.store.u64.be", "big"))),
    )
    rows = []
    for name, items in expected:
        mapping = getattr(original, name, None)
        if type(mapping) is not MappingProxyType or tuple(mapping.items()) != items:
            raise ValueError("live v9 runtime byte-order mapping differs: " + name)
        rows.append((name, mapping, items))
    return tuple(rows)


_DIV_TEST = 'op in {"int.div.checked", "int.rem.checked"}'
_DIV_BODY = """a, b = args
_native_status, _native_value = _hia_evaluate(self, op, typ, a, b)
if _native_status == 1:
    raise HIAProgramTrap("division_by_zero", "integer divisor is zero")
if _native_status == 2:
    raise HIAProgramTrap("overflow", "signed minimum divided by minus one")
if _native_status != 0:
    raise HIAProgramRejected("native div/rem status invariant", "E_HIA_RUNTIME_INVARIANT")
result = [_native_value]
"""


_ARITHMETIC_TEST = 'op in {f"int.{a}.{m}" for a in ("add", "sub", "mul") for m in ("checked", "wrap")}'
_ARITHMETIC_BODY = """a, b = args
_native_status, _native_value = _hia_evaluate(self, op, typ, a, b)
if _native_status == 3:
    raise HIAProgramTrap("overflow", f"result is outside {typ}")
if _native_status != 0:
    raise HIAProgramRejected("native arithmetic status invariant", "E_HIA_RUNTIME_INVARIANT")
result = [_native_value]
"""


_SCALAR_REPLACEMENTS = (
    ('op in {"int.shl.checked", "int.shr.checked"}', """a, b = args
_native_status, _native_value = _hia_evaluate(self, op, typ, a, b)
if _native_status == 4:
    raise HIAProgramTrap("overflow", "shift count is outside the word width")
if _native_status != 0:
    raise HIAProgramRejected("native scalar shift status invariant", "E_HIA_RUNTIME_INVARIANT")
result = [_native_value]
"""),
    ('op == "int.neg.checked"', """_native_status, _native_value = _hia_evaluate(self, op, typ, args[0], 0)
if _native_status == 3:
    raise HIAProgramTrap("overflow", f"result is outside {typ}")
if _native_status != 0:
    raise HIAProgramRejected("native scalar negation status invariant", "E_HIA_RUNTIME_INVARIANT")
result = [_native_value]
"""),
    ('op in {"bit.and", "bit.or", "bit.xor"}', """a, b = args
_native_status, _native_value = _hia_evaluate(self, op, typ, a, b)
if _native_status != 0:
    raise HIAProgramRejected("native scalar binary-bit status invariant", "E_HIA_RUNTIME_INVARIANT")
result = [_native_value]
"""),
    ('op == "bit.not"', """_native_status, _native_value = _hia_evaluate(self, op, typ, args[0], 0)
if _native_status != 0:
    raise HIAProgramRejected("native scalar complement status invariant", "E_HIA_RUNTIME_INVARIANT")
result = [_native_value]
"""),
)


def _same_constant(a, b):
    if type(a) is not type(b):
        return False
    if type(b) is CodeType:
        return _same_code(a, b)
    if type(b) is tuple:
        return len(a) == len(b) and all(_same_constant(x, y) for x, y in zip(a, b))
    if type(b) is slice:
        return (_same_constant(a.start, b.start) and _same_constant(a.stop, b.stop)
                and _same_constant(a.step, b.step))
    if type(b) is frozenset:
        return (all(type(x) in (str, int, bytes) for x in a)
                and all(type(x) in (str, int, bytes) for x in b) and a == b)
    if type(b) is float:
        return _ieee_pack(">d", a) == _ieee_pack(">d", b)
    if type(b) is complex:
        return (_ieee_pack(">dd", a.real, a.imag)
                == _ieee_pack(">dd", b.real, b.imag))
    return (b is None or b is Ellipsis or type(b) in
            (str, bytes, int, bool)) and a == b


def _same_code(a, b):
    fields = ("co_argcount", "co_posonlyargcount", "co_kwonlyargcount", "co_nlocals",
              "co_stacksize", "co_flags", "co_code", "co_names", "co_varnames",
              "co_freevars", "co_cellvars", "co_name", "co_qualname",
              "co_firstlineno", "co_linetable", "co_exceptiontable")
    return (type(a) is CodeType and type(b) is CodeType
            and all(getattr(a, name) == getattr(b, name) for name in fields)
            and _same_constant(a.co_consts, b.co_consts))


def _find_code(code, qualified_name):
    pending, found = [code], []
    while pending:
        item = pending.pop()
        if item.co_qualname == qualified_name:
            found.append(item)
        pending.extend(v for v in item.co_consts if type(v) is CodeType)
    if len(found) != 1:
        raise ValueError("original or derived code inventory differs: " + qualified_name)
    return found[0]


def _stamp(fn):
    if type(fn) is not FunctionType:
        raise ValueError("expected an actual Python function")
    keyword = fn.__kwdefaults__
    return (fn, fn.__code__, fn.__globals__, fn.__defaults__, keyword,
            None if keyword is None else tuple(keyword.items()), fn.__closure__,
            None if fn.__closure__ is None else tuple(c.cell_contents for c in fn.__closure__),
            fn.__builtins__)


def _current(stamp):
    fn, code, namespace, defaults, keyword, items, closure, contents, builtins = stamp
    return (type(fn) is FunctionType and fn.__code__ is code and fn.__globals__ is namespace
            and fn.__defaults__ is defaults and fn.__kwdefaults__ is keyword
            and (keyword is None or tuple(keyword) == tuple(k for k, _ in items)
                 and all(keyword[k] is v for k, v in items))
            and fn.__closure__ is closure
            and (closure is None or len(closure) == len(contents)
                 and all(c.cell_contents is v for c, v in zip(closure, contents)))
            and fn.__builtins__ is builtins)


def _cell(value):
    return (lambda: value).__closure__[0]


def _select_integer_dispatch(operation, execute, selected_tests, *, package_default):
    # The explicit standalone integer factory owns its selected operations even
    # when the resource interpreter also has a general native image installed.
    # Leave the general per-operation route available for other opcodes.
    native_guard = ast.parse("self.scalar_reference is not None and scalar_op in NATIVE_SCALAR_OPCODES "
                             "and (typ in WIDTHS or typ == 'bool')", mode="eval").body
    matches = [node for node in ast.walk(operation) if isinstance(node, ast.If)
               and ast.dump(node.test) == ast.dump(native_guard)]
    dispatch = [node for node in ast.walk(execute) if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute) and node.func.attr == "execute"
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "machine"]
    if len(matches) != 1 or len(dispatch) != 1:
        raise ValueError("resource interpreter integer dispatch differs")
    conditions = [ast.parse(source, mode="eval").body for source in selected_tests]
    selected = conditions[0] if len(conditions) == 1 else ast.BoolOp(ast.Or(), conditions)
    matches[0].test.values.append(ast.UnaryOp(ast.Not(), selected))
    if package_default is not None:
        package_guard = ast.parse(package_default, mode="eval").body
        package_matches = [node for node in ast.walk(operation) if isinstance(node, ast.If)
                           and ast.dump(node.test) == ast.dump(package_guard)]
        if len(package_matches) != 1:
            raise ValueError("package integer dispatch differs")
        package_matches[0].test.values.append(ast.UnaryOp(ast.Not(), copy.deepcopy(selected)))
    dispatch[0].func.attr = "invoke"


def _derive(raw, factory, *, integer_arithmetic=False, integer_scalar=False):
    """Compile definitions only; no original module/class body is executed."""
    if type(integer_arithmetic) is not bool:
        raise ValueError("derived integer arithmetic profile must be explicit")
    if type(integer_scalar) is not bool or integer_scalar and not integer_arithmetic:
        raise ValueError("derived scalar profile requires the complete integer arithmetic profile")
    _retained_runtime_source(raw)
    tree = ast.parse(raw)
    machine = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "_Machine")
    operations = [n for n in machine.body if isinstance(n, ast.FunctionDef) and n.name == "operation"]
    invokes = [n for n in machine.body if isinstance(n, ast.FunctionDef) and n.name == "invoke"]
    publics = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "execute_program"]
    if len(operations) != 1 or len(invokes) != 1 or len(publics) != 1:
        raise ValueError("original interpreter definitions differ")
    operation, invoke, execute = copy.deepcopy(operations[0]), copy.deepcopy(invokes[0]), copy.deepcopy(publics[0])
    test = ast.dump(ast.parse(_DIV_TEST, mode="eval").body, include_attributes=False)
    matches = [n for n in ast.walk(operation)
               if isinstance(n, ast.If) and ast.dump(n.test, include_attributes=False) == test]
    if len(matches) != 1:
        raise ValueError("original div/rem branch differs")
    selected = matches[0]
    old_body = selected.body
    selected.body = ast.parse(_DIV_BODY).body
    for statement in selected.body:
        ast.increment_lineno(statement, old_body[0].lineno - 1)
    changed_body = selected.body
    selected.body = old_body
    if ast.dump(operation, include_attributes=False) != ast.dump(operations[0], include_attributes=False):
        raise ValueError("non-div/rem operation changed")
    selected.body = changed_body
    if integer_arithmetic:
        arithmetic_test = ast.dump(ast.parse(_ARITHMETIC_TEST, mode="eval").body,
                                   include_attributes=False)
        arithmetic_matches = [n for n in ast.walk(operation) if isinstance(n, ast.If)
                              and ast.dump(n.test, include_attributes=False) == arithmetic_test]
        if len(arithmetic_matches) != 1:
            raise ValueError("original six-operation arithmetic branch differs")
        arithmetic = arithmetic_matches[0]
        old_arithmetic = arithmetic.body
        arithmetic.body = ast.parse(_ARITHMETIC_BODY).body
        for statement in arithmetic.body:
            ast.increment_lineno(statement, old_arithmetic[0].lineno - 1)
        changed_arithmetic = arithmetic.body
        # Invert both selected bodies, not just the last one. All unrelated
        # operations, original result validation and ticks stay original.
        arithmetic.body, selected.body = old_arithmetic, old_body
        if ast.dump(operation, include_attributes=False) != ast.dump(operations[0], include_attributes=False):
            raise ValueError("nonselected interpreter operation changed")
        arithmetic.body, selected.body = changed_arithmetic, changed_body
    if integer_scalar:
        scalar_bodies = []
        for source_test, source_body in _SCALAR_REPLACEMENTS:
            exact_test = ast.dump(ast.parse(source_test, mode="eval").body,
                                  include_attributes=False)
            scalar_matches = [n for n in ast.walk(operation) if isinstance(n, ast.If)
                              and ast.dump(n.test, include_attributes=False) == exact_test]
            if len(scalar_matches) != 1:
                raise ValueError("original scalar branch differs: " + source_test)
            branch = scalar_matches[0]
            old_scalar = branch.body
            changed_scalar = ast.parse(source_body).body
            for statement in changed_scalar:
                ast.increment_lineno(statement, old_scalar[0].lineno - 1)
            branch.body = changed_scalar
            scalar_bodies.append((branch, old_scalar, changed_scalar))
        # Invert all six selected original bodies together. Ticks, argument
        # fetches, every other opcode and final scalar validation remain exact.
        selected.body, arithmetic.body = old_body, old_arithmetic
        for branch, old_scalar, changed_scalar in scalar_bodies:
            branch.body = old_scalar
        if ast.dump(operation, include_attributes=False) != ast.dump(operations[0], include_attributes=False):
            raise ValueError("nonselected interpreter operation changed in scalar profile")
        selected.body, arithmetic.body = changed_body, changed_arithmetic
        for branch, old_scalar, changed_scalar in scalar_bodies:
            branch.body = changed_scalar
    # Preserve the original method lookup/argument expression, and guard its
    # exact target immediately before every operation. Guarding invoke only
    # at entry would allow a later class replacement to bypass the div/rem
    # body in this already running loop.
    guard = ast.parse("_hia_guard(self)").body[0]
    ast.increment_lineno(guard, invoke.body[0].lineno - 1)
    invoke.body.insert(0, guard)
    operation_sites = []
    for node in ast.walk(invoke):
        for field, items in ast.iter_fields(node):
            if type(items) is not list:
                continue
            for index, statement in enumerate(items):
                if (isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)
                        and isinstance(statement.value.func, ast.Attribute)
                        and isinstance(statement.value.func.value, ast.Name)
                        and statement.value.func.value.id == "self"
                        and statement.value.func.attr == "operation"):
                    operation_sites.append((items, index, statement))
    if len(operation_sites) != 1:
        raise ValueError("original operation dispatch site differs")
    items, index, statement = operation_sites[0]
    operation_guard = ast.parse("_hia_guard(self)").body[0]
    ast.increment_lineno(operation_guard, statement.lineno - 1)
    items.insert(index, operation_guard)
    # Inverse both inserted guards, compare the complete original body, then
    # restore exactly these two nodes. No old tick or statement is deleted.
    items.pop(index)
    invoke.body.pop(0)
    if ast.dump(invoke, include_attributes=False) != ast.dump(invokes[0], include_attributes=False):
        raise ValueError("original invoke body changed")
    invoke.body.insert(0, guard)
    items.insert(index, operation_guard)
    constructors = [n for n in ast.walk(execute)
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_Machine"]
    if len(constructors) != 1:
        raise ValueError("original public machine construction differs")
    constructors[0].func.id = "_hia_factory"
    constructors[0].func.id = "_Machine"
    if ast.dump(execute, include_attributes=False) != ast.dump(publics[0], include_attributes=False):
        raise ValueError("original public body changed")
    constructors[0].func.id = "_hia_factory"
    if sha256(raw).hexdigest() in RESOURCE_RUNTIME_SHA256S:
        tests = [_DIV_TEST]
        if integer_arithmetic:
            tests.append(_ARITHMETIC_TEST)
        if integer_scalar:
            tests.extend(source for source, _body in _SCALAR_REPLACEMENTS)
        package_guard = {
            PACKAGE_INTEGER_SHA256: "self.scalar_reference is None and op in DEFAULT_INTEGER_OPERATIONS and typ in WIDTHS",
            PACKAGE_SCALAR_SHA256: "self.scalar_reference is None and scalar_op in NATIVE_SCALAR_OPCODES",
        }.get(sha256(raw).hexdigest())
        _select_integer_dispatch(operation, execute, tests, package_default=package_guard)
    # The enclosing function creates closure code only. Its body is never run.
    outer = ast.parse("def _bind(_hia_evaluate, _hia_guard, _hia_factory):\n    pass\n").body[0]
    container = ast.parse("class _Machine:\n    pass\n").body[0]
    ast.copy_location(container, machine)
    container.body = [operation, invoke]
    outer.lineno, outer.col_offset = machine.lineno - 1, 0
    outer.end_lineno, outer.end_col_offset = execute.end_lineno, execute.end_col_offset
    outer.body = [container, execute]
    futures = [n for n in tree.body if isinstance(n, ast.ImportFrom) and n.module == "__future__"]
    unit = ast.fix_missing_locations(ast.Module(body=futures + [outer], type_ignores=[]))
    compiled = compile(unit, "<hia-divrem-derived:" + sha256(raw).hexdigest() + ">", "exec",
                       dont_inherit=True, optimize=sys.flags.optimize)
    environment = {"_hia_evaluate": factory.evaluate, "_hia_guard": factory.guard,
                   "_hia_factory": factory}
    cells = {name: _cell(value) for name, value in environment.items()}
    functions = []
    for qualified, base in (
            ("_bind.<locals>._Machine.operation", original._Machine.operation),
            ("_bind.<locals>._Machine.invoke", original._Machine.invoke),
            ("_bind.<locals>.execute_program", original.execute_program)):
        code = _find_code(compiled, qualified)
        if any(name not in cells for name in code.co_freevars):
            raise ValueError("derived code captured an unexpected dependency")
        fn = FunctionType(code, original.__dict__, base.__name__, base.__defaults__,
                          tuple(cells[name] for name in code.co_freevars))
        fn.__kwdefaults__ = None if base.__kwdefaults__ is None else dict(base.__kwdefaults__)
        functions.append(fn)
    return tuple(functions)


class _Factory:
    def __init__(self, binding):
        if type(binding) is not NativeDivRemBinding:
            raise TypeError("native div/rem factory requires the exact admitted binding")
        binding.check()
        self.binding = binding
        self._binding_identity = binding
        self._protocol_identity = binding._protocol
        self.source_path = _input_path("hepta/hia_program_runtime.py")
        raw = regular_bytes(self.source_path, 1 << 20)
        _retained_runtime_source(raw)
        self.word_orders = _word_order_state(raw)
        self.raw = raw
        self.base_type = original._Machine
        self.base_namespace = tuple(vars(self.base_type).items())
        self.base_methods = tuple((name, fn) for name, fn in vars(self.base_type).items()
                                  if type(fn) is FunctionType)
        self.global_functions = tuple((name, fn) for name, fn in original.__dict__.items()
                                      if type(fn) is FunctionType and fn.__globals__ is original.__dict__)
        self.namespace = tuple(original.__dict__.items())
        self.builtins = original._Machine.operation.__builtins__
        if type(self.builtins) is not dict:
            raise ValueError("original interpreter builtin namespace differs")
        self.builtin_items = tuple(self.builtins.items())
        dependencies = (
            ("verify_program", "hepta/hia_program.py"),
            ("integer_range", "hepta/hia_program.py"),
            ("scalar_value_valid", "hepta/hia_program.py"),
            ("fill_bytes", "hepta/hia_bounded_memory.py"),
            ("move_bytes", "hepta/hia_bounded_memory.py"),
            ("supports_feature", "hepta/hia_schema.py"),
            ("validate_execution_observation", "hepta/hia_opcodes.py"))
        if sha256(raw).hexdigest() in RESOURCE_RUNTIME_SHA256S:
            dependencies += (("selected_scalar_reference", "hepta/hia_scalar_reference_native.py"),
                             ("installed_execution_ledger", "hepta/hia_execution_ledger_native.py"))
        self.imported_functions = tuple((name, getattr(original, name), path) for name, path in dependencies)
        self.base_stamps = tuple(_stamp(fn) for _, fn in self.base_methods + self.global_functions)
        self.imported_stamps = tuple(_stamp(fn) for _, fn, _ in self.imported_functions)
        compiled = compile(raw, original.__file__, "exec", dont_inherit=True, optimize=sys.flags.optimize)
        for name, fn in self.base_methods + self.global_functions:
            if not _same_code(fn.__code__, _find_code(compiled, fn.__qualname__)):
                raise ValueError("live original interpreter code differs: " + name)
        dependency_code = {}
        for name, fn, path in self.imported_functions:
            if path not in dependency_code:
                dependency_code[path] = compile(binding.component_inputs[path], fn.__code__.co_filename,
                    "exec", dont_inherit=True, optimize=sys.flags.optimize)
            if not _same_code(fn.__code__, _find_code(dependency_code[path], fn.__qualname__)):
                raise ValueError("live interpreter dependency code differs: " + name)
        self.operation, self.invoke, self.execute = _derive(raw, self,
            integer_arithmetic=(binding._protocol is wire.IntegerArithmeticProtocol
                                or binding._protocol is wire.IntegerScalarProtocol),
            integer_scalar=binding._protocol is wire.IntegerScalarProtocol)
        self.derived_stamps = tuple(_stamp(fn) for fn in (self.operation, self.invoke, self.execute))
        self.machine_type = type("_NativeDivRemMachine", (self.base_type,),
                                 {"__slots__": (), "operation": self.operation,
                                  "invoke": self.invoke, "__module__": __name__})
        self.machine_namespace = tuple(vars(self.machine_type).items())
        self.machines = weakref.WeakKeyDictionary()
        self.check()
        if regular_bytes(self.source_path, 1 << 20) != raw:
            raise ValueError("original interpreter source changed during derivation")

    def check(self):
        self.binding._context()
        if (self.binding is not self._binding_identity
                or self.binding._protocol is not self._protocol_identity
                or original._Machine is not self.base_type
                or any(type(mapping) is not MappingProxyType or tuple(mapping.items()) != items
                       for _name, mapping, items in self.word_orders)
                or any(fn is not stamp[0] for fn, stamp in zip(
                    (self.operation, self.invoke, self.execute), self.derived_stamps))
                or tuple(original.__dict__) != tuple(name for name, _ in self.namespace)
                or any(original.__dict__.get(name) is not value for name, value in self.namespace)
                or tuple(self.builtins) != tuple(name for name, _ in self.builtin_items)
                or any(self.builtins.get(name) is not value for name, value in self.builtin_items)
                or any(getattr(original, name) is not fn for name, fn, _ in self.imported_functions)
                or not all(_current(item) for item in self.imported_stamps)
                or tuple(vars(self.base_type)) != tuple(name for name, _ in self.base_namespace)
                or any(vars(self.base_type).get(name) is not value for name, value in self.base_namespace)
                or any(vars(self.base_type).get(name) is not fn for name, fn in self.base_methods)
                or not all(_current(item) for item in self.base_stamps)
                or not all(_current(item) for item in self.derived_stamps)
                or tuple(vars(self.machine_type)) != tuple(name for name, _ in self.machine_namespace)
                or any(vars(self.machine_type).get(name) is not value
                       for name, value in self.machine_namespace)
                or vars(self.machine_type).get("operation") is not self.operation
                or vars(self.machine_type).get("invoke") is not self.invoke):
            raise NativeDivRemUnknown("native div/rem live code/closure binding changed")
        check_current()

    def __call__(self, program, max_steps, max_heap_bytes, allocation_fail_at, max_call_depth):
        self.check()
        self.binding.check()
        machine = self.machine_type(program, max_steps, max_heap_bytes, allocation_fail_at, max_call_depth)
        self.machines[machine] = machine.functions
        self.check()
        return machine

    def guard(self, machine):
        self.check()
        if (type(machine) is not self.machine_type or machine not in self.machines
                or self.machines[machine] is not machine.functions):
            raise NativeDivRemUnknown("native div/rem machine belongs to another invocation factory")

    def evaluate(self, machine, operation, typ, lhs, rhs):
        self.guard(machine)
        result = self.binding.evaluate(operation, typ, lhs, rhs, vm_owner=machine)
        self.guard(machine)
        return result


class NativeDivRemExecutor:
    """Explicit experimental public-shaped entry; default runtime is unchanged."""
    def __init__(self, manifest_path, expected_manifest_sha256):
        self.binding = NativeDivRemBinding(manifest_path, expected_manifest_sha256)
        self._factory = _Factory(self.binding)
        self._factory_identity = self._factory
        self._binding_identity = self.binding
        self._target = self._factory.execute
        self._stamp = _stamp(self._target)

    def __call__(self, program, function, arguments, *, max_steps=1_000_000,
                 max_heap_bytes=16 * 1024 * 1024, allocation_fail_at=None,
                 max_call_depth=256, bounded_resource_limits=None):
        if self._factory is not self._factory_identity or self.binding is not self._binding_identity:
            raise NativeDivRemUnknown("native div/rem explicit factory identity changed")
        self._factory.check()
        target = self._target
        if target is not self._factory.execute or not _current(self._stamp) or target is not self._stamp[0]:
            raise NativeDivRemUnknown("native div/rem execution target changed")
        return target(program, function, arguments, max_steps=max_steps,
                      max_heap_bytes=max_heap_bytes, allocation_fail_at=allocation_fail_at,
                      max_call_depth=max_call_depth, bounded_resource_limits=bounded_resource_limits)


class NativeIntegerArithmeticExecutor(NativeDivRemExecutor):
    """Explicit eight-op slice: the original two plus checked/wrap add/sub/mul.

    No default runtime or worker-helper selector is changed. The independent
    arithmetic manifest and complete source closure are required.
    """
    def __init__(self, manifest_path, expected_manifest_sha256):
        self.binding = NativeDivRemBinding(manifest_path, expected_manifest_sha256,
                                           _integer_arithmetic=True)
        self._factory = _Factory(self.binding)
        self._factory_identity = self._factory
        self._binding_identity = self.binding
        self._target = self._factory.execute
        self._stamp = _stamp(self._target)


class NativeIntegerScalarExecutor(NativeDivRemExecutor):
    """Explicit fifteen-op integer slice; no default interpreter cutover.

    The original two-operation and eight-operation executor classes above
    retain their closed profile selection. This profile alone adds checked
    shifts/negation and and/or/xor/not; comparisons/casts/select stay hosted.
    """
    def __init__(self, manifest_path, expected_manifest_sha256):
        self.binding = NativeDivRemBinding(manifest_path, expected_manifest_sha256,
                                           _integer_scalar=True)
        self._factory = _Factory(self.binding)
        self._factory_identity = self._factory
        self._binding_identity = self.binding
        self._target = self._factory.execute
        self._stamp = _stamp(self._target)
