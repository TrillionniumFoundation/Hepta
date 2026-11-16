"""Explicit native-div/rem factory over the unchanged original interpreter.

Default execute_program, _Machine, Prepared and Arithmetic source stay intact.
Only the selected operation's div/rem body is mechanically replaced. The loop,
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
from types import CodeType, FunctionType
import weakref

from . import hia_program_runtime as original
from .hia_native_admission_io import regular_bytes, source_resource_path
from .hia_native_delivery import check_current
from .hia_vm_integer_divrem_native import NativeDivRemBinding, NativeDivRemUnknown, _input_path

RUNTIME_SHA256 = "ce39be78627f253447f1d4e4b3272ba6689c594c31b22e3be204b1fcfea2ca56"
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


def _derive(raw, factory):
    """Compile definitions only; no original module/class body is executed."""
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
    compiled = compile(unit, "<hia-divrem-derived:" + RUNTIME_SHA256 + ">", "exec",
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
        self.source_path = _input_path("hepta/hia_program_runtime.py")
        raw = regular_bytes(self.source_path, 1 << 20)
        if sha256(raw).hexdigest() != RUNTIME_SHA256:
            raise ValueError("native div/rem requires the exact retained runtime source")
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
        self.imported_functions = tuple((name, getattr(original, name), path) for name, path in (
            ("verify_program", "hepta/hia_program.py"),
            ("integer_range", "hepta/hia_program.py"),
            ("scalar_value_valid", "hepta/hia_program.py"),
            ("fill_bytes", "hepta/hia_bounded_memory.py"),
            ("move_bytes", "hepta/hia_bounded_memory.py"),
            ("supports_feature", "hepta/hia_schema.py"),
            ("validate_execution_observation", "hepta/hia_opcodes.py")))
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
        self.operation, self.invoke, self.execute = _derive(raw, self)
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
                or original._Machine is not self.base_type
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
