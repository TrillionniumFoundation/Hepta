"""Explicit static opcode metadata for independently initialized VM entries.

This is not a verifier, an execution receipt, or a global cache. The ordinary
runtime module and its operation bodies are unchanged. Only an exact prepared
immutable program may opt in; dynamic bindings retain the original path.
"""
from __future__ import annotations

import ast
import copy
from hashlib import sha256
from pathlib import Path
from types import CodeType, FunctionType, MappingProxyType, MethodType

from . import hia_program_runtime as _runtime
from . import hia_program_runtime_prepared as _metadata

_RUNTIME_SHA256 = "76f184195ffc37dab2e327a2170e0999aa51349b9e1f62475084719d675686f4"
_RUNTIME_PATH = Path(__file__).resolve().with_name("hia_program_runtime.py")
_RUNTIME_BYTES = _RUNTIME_PATH.read_bytes()
_MACHINE = _runtime._Machine
_METHOD_NAMES = ("__init__", "operation", "invoke")
_METHODS = tuple(vars(_MACHINE)[name] for name in _METHOD_NAMES)
_CODES = tuple(method.__code__ for method in _METHODS)
_DEFAULTS = tuple((method.__defaults__, method.__kwdefaults__) for method in _METHODS)
_PREPARED = _metadata._PreparedRuntimeProgram
_AS_DICT = _PREPARED.as_dict
_AS_DICT_CODE = _AS_DICT.__code__
_PROGRAM_GUARD = _metadata._ordinary_default_program
_PROGRAM_GUARD_CODE = _PROGRAM_GUARD.__code__
_LOADS, _STORES = _runtime.WORD_LOADS, _runtime.WORD_STORES
_LOAD_VALUES, _STORE_VALUES = dict(_LOADS), dict(_STORES)


def _code_signature(code):
    return (
        code.co_code,
        tuple(_code_signature(value) if type(value) is CodeType else value
              for value in code.co_consts),
        code.co_names, code.co_varnames, code.co_freevars, code.co_cellvars,
        code.co_argcount, code.co_posonlyargcount, code.co_kwonlyargcount,
        code.co_nlocals, code.co_stacksize, code.co_flags, code.co_exceptiontable,
    )


def _source_methods():
    if (sha256(_RUNTIME_BYTES).hexdigest() != _RUNTIME_SHA256
            or Path(_runtime.__file__).resolve() != _RUNTIME_PATH
            or type(_LOADS) is not MappingProxyType
            or type(_STORES) is not MappingProxyType):
        return None
    tree = ast.parse(_RUNTIME_BYTES)
    classes = [node for node in tree.body
               if isinstance(node, ast.ClassDef) and node.name == "_Machine"]
    if len(classes) != 1:
        return None
    methods = {node.name: node for node in classes[0].body
               if isinstance(node, ast.FunctionDef) and node.name in _METHOD_NAMES}
    module_code = compile(_RUNTIME_BYTES, str(_RUNTIME_PATH), "exec", dont_inherit=True)
    class_code = next(value for value in module_code.co_consts
                      if type(value) is CodeType and value.co_name == "_Machine")
    for name, actual in zip(_METHOD_NAMES, _METHODS):
        if (name not in methods or type(actual) is not FunctionType
                or actual.__globals__ is not _runtime.__dict__
                or actual.__closure__ is not None):
            return None
        expected = next(value for value in class_code.co_consts
                        if type(value) is CodeType and value.co_name == name)
        if _code_signature(actual.__code__) != _code_signature(expected):
            return None
    return methods


_TREES = _source_methods()


def _ordinary_bindings():
    if (_TREES is None or _runtime._Machine is not _MACHINE
            or _PREPARED.as_dict is not _AS_DICT or _AS_DICT.__code__ is not _AS_DICT_CODE
            or _metadata._ordinary_default_program is not _PROGRAM_GUARD
            or _PROGRAM_GUARD.__code__ is not _PROGRAM_GUARD_CODE
            or _runtime.WORD_LOADS is not _LOADS or _runtime.WORD_STORES is not _STORES
            or _LOADS != _LOAD_VALUES or _STORES != _STORE_VALUES):
        return False
    namespace = vars(_MACHINE)
    return all(namespace.get(name) is method and method.__code__ is code
               and (method.__defaults__, method.__kwdefaults__) == defaults
               for name, method, code, defaults in zip(
                   _METHOD_NAMES, _METHODS, _CODES, _DEFAULTS))


def _ordinary_program(program):
    return (type(program) is _PREPARED and _ordinary_bindings()
            and _PROGRAM_GUARD(program._program)
            and _metadata._REFERENCE_CANONICAL_FIELD.__get__(
                program._program, _metadata._PROGRAM_TYPE) == program._canonical
            and _metadata._REFERENCE_STRUCTURED_FIELD.__get__(
                program._program, _metadata._PROGRAM_TYPE) == program._structured)


def _ast_bytes(nodes):
    return ast.dump(ast.Module(body=nodes, type_ignores=[]),
                    include_attributes=False).encode()


def _operation_parts():
    tree = _TREES["operation"]
    candidates = [node for node in tree.body if isinstance(node, ast.If)
                  and ast.unparse(node.test).startswith("self.scalar_reference is not None")]
    if len(candidates) != 1:
        raise ValueError("the fixed operation dispatch relation changed")
    native = candidates[0]
    if len(native.orelse) != 1 or not isinstance(native.orelse[0], ast.If):
        raise ValueError("the fixed package dispatch relation changed")
    package = native.orelse[0]
    if ast.unparse(package.test) != "package_scalar is not None":
        raise ValueError("the fixed package binding changed")
    branches = []
    node = package.orelse[0]
    while isinstance(node, ast.If):
        branches.append((node.test, node.body))
        if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
            node = node.orelse[0]
        else:
            fallback = node.orelse
            break
    position = tree.body.index(native)
    return tree, native, package, tree.body[:position], tree.body[position + 1:], branches, fallback


def _handler(parts, ordinal, branch):
    tree, native, package, prefix, tail, unused, fallback = parts
    function = copy.deepcopy(tree)
    function.name = "_operation_metadata_" + str(ordinal)
    function.args.args[1].arg = "prepared"
    replaced = {"(op, attrs)", "names", "outputs", "typ", "scalar_op"}
    kept = []
    for node in prefix:
        if isinstance(node, ast.Assign) and ast.unparse(node.targets[0]) in replaced:
            continue
        kept.append(copy.deepcopy(node))
    word_branch = next(index for index, (test, body) in enumerate(parts[-2])
                       if ast.unparse(test) == "op in WORD_LOADS or op in WORD_STORES")
    # Earlier fixed opcode tests cannot be affected by either later word map.
    # Preserve the live word binding guard wherever it can affect dispatch.
    word_guard = ("" if ordinal < word_branch else
                  "\n        or WORD_LOADS is not self._dispatch_loads"
                  "\n        or WORD_STORES is not self._dispatch_stores")
    preamble = ast.parse(
        "original, op, attrs, names, outputs, typ, scalar_op = prepared\n"
        "if (self.__class__.operation is not self._dispatch_operation\n"
        "        or self._dispatch_operation.__code__ is not self._dispatch_operation_code\n"
        "        or 'operation' in self.__dict__" + word_guard + "):\n"
        "    return self.operation(original, env, depth)\n"
    ).body
    first, second = copy.deepcopy(native), copy.deepcopy(package)
    second.orelse = copy.deepcopy(branch)
    first.orelse = [second]
    function.body = preamble + kept + [first] + copy.deepcopy(tail)
    relation = {
        "branch": ordinal,
        "body_sha256": sha256(_ast_bytes(branch)).hexdigest(),
        "tail_sha256": sha256(_ast_bytes(tail)).hexdigest(),
    }
    if (_ast_bytes(second.orelse) != _ast_bytes(branch)
            or _ast_bytes(function.body[-len(tail):]) != _ast_bytes(tail)):
        raise ValueError("operation body or result validation was changed")
    local = {}
    module = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    exec(compile(module, "<explicit-prepared-vm-operation>", "exec"),
         _runtime.__dict__, local)
    return local[function.name], MappingProxyType(relation)


class _Invocation(ast.NodeTransformer):
    def __init__(self):
        self.blocks = self.loops = self.calls = 0

    def visit_Assign(self, node):
        if (len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "blocks"):
            if not isinstance(node.value, ast.DictComp):
                raise ValueError("the fixed block lookup changed")
            self.blocks += 1
            node.value = ast.parse("self._dispatch_functions[fn['name']][0]",
                                   mode="eval").body
        return self.generic_visit(node)

    def visit_For(self, node):
        if isinstance(node.target, ast.Name) and node.target.id == "ins":
            if ast.unparse(node.iter) != "block['ops']":
                raise ValueError("the fixed instruction loop changed")
            self.loops += 1
            node.target = ast.parse("handler, ins", mode="eval").body
            node.target.ctx = ast.Store()
            for item in node.target.elts:
                item.ctx = ast.Store()
            node.iter = ast.parse(
                "self._dispatch_functions[fn['name']][1][block['id']]",
                mode="eval").body
        return self.generic_visit(node)

    def visit_Call(self, node):
        if (isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "self" and node.func.attr == "operation"):
            if ast.unparse(node) != "self.operation(ins, env, depth)":
                raise ValueError("the fixed operation invocation changed")
            self.calls += 1
            return ast.parse("handler(self, ins, env, depth)", mode="eval").body
        return self.generic_visit(node)


def _invocation():
    transform = _Invocation()
    function = transform.visit(copy.deepcopy(_TREES["invoke"]))
    if (transform.blocks, transform.loops, transform.calls) != (1, 1, 1):
        raise ValueError("the fixed invocation relation changed")
    function.body = ast.parse(
        "if not self._dispatch_plan._active(self, fn):\n"
        "    return self._dispatch_plan._original_invoke(self, fn, arguments, depth)\n"
    ).body + function.body
    module = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    local = {}
    exec(compile(module, "<explicit-prepared-vm-invocation>", "exec"),
         _runtime.__dict__, local)
    return local["invoke"]


class RuntimeDispatch:
    """One immutable program's metadata; every machine still starts empty."""
    __slots__ = ("program", "document", "canonical", "structured", "functions",
                 "function_objects", "relations", "instruction_count", "_invoke")

    def __setattr__(self, name, value):
        raise AttributeError("runtime dispatch metadata is read-only")

    def __delattr__(self, name):
        raise AttributeError("runtime dispatch metadata is read-only")

    def __init__(self, program):
        document = program.as_dict()
        values = {
            "program": program, "document": document,
            "canonical": program._canonical, "structured": program._structured,
        }
        parts = _operation_parts()
        branches, fallback = parts[-2:]
        handlers, relations, functions, originals = {}, [], {}, {}
        instructions = 0
        for function in document["functions"]:
            blocks = MappingProxyType({block["id"]: block for block in function["blocks"]})
            records = {}
            for block in function["blocks"]:
                prepared = []
                for instruction in block["ops"]:
                    op, attrs = instruction["op"], instruction["attrs"]
                    outputs = instruction["out"]
                    context = dict(_runtime.__dict__, op=op, attrs=attrs)
                    selected = len(branches), fallback
                    for ordinal, (test, body) in enumerate(branches):
                        expression = compile(ast.Expression(copy.deepcopy(test)),
                                             "<static-opcode-metadata>", "eval")
                        if eval(expression, context):
                            selected = ordinal, body
                            break
                    ordinal, body = selected
                    if ordinal not in handlers:
                        handlers[ordinal], relation = _handler(parts, ordinal, body)
                        relations.append(relation)
                    metadata = (instruction, op, attrs, instruction["args"], outputs,
                                outputs[0]["type"] if outputs else None,
                                "cast." + attrs["mode"] if op == "int.cast" else op)
                    prepared.append((handlers[ordinal], metadata))
                    instructions += 1
                records[block["id"]] = tuple(prepared)
            functions[function["name"]] = blocks, MappingProxyType(records)
            originals[function["name"]] = function
        values.update(
            functions=MappingProxyType(functions),
            function_objects=MappingProxyType(originals),
            relations=tuple(relations), instruction_count=instructions,
            _invoke=_invocation(),
        )
        for name, value in values.items():
            object.__setattr__(self, name, value)

    def _valid(self, program):
        return (type(self) is RuntimeDispatch and _ordinary_program(program)
                and program is self.program
                and program._canonical == self.canonical
                and program._structured == self.structured
                and program.as_dict() is self.document)

    def _active(self, machine, function):
        return (type(machine) is _MACHINE and _ordinary_bindings()
                and function is self.function_objects.get(function["name"])
                and "operation" not in vars(machine))

    @staticmethod
    def _original_invoke(machine, function, arguments, depth):
        return _runtime._Machine.invoke(machine, function, arguments, depth)

    def new_machine(self, program, *limits):
        # The full ordinary constructor (including dynamic selected decoding)
        # runs first. Changed bindings keep its actual function objects.
        machine = _runtime._Machine(program, *limits)
        if (not self._valid(program) or type(machine) is not _MACHINE
                or any(machine.functions.get(name) is not function
                       for name, function in self.function_objects.items())):
            return machine
        machine._dispatch_functions = self.functions
        machine._dispatch_plan = self
        machine._dispatch_operation = _METHODS[1]
        machine._dispatch_operation_code = _CODES[1]
        machine._dispatch_loads, machine._dispatch_stores = _LOADS, _STORES
        machine.invoke = MethodType(self._invoke, machine)
        return machine


def prepare_runtime_dispatch(program):
    """Opt in only for exact ordinary immutable prepared program metadata."""
    if not _ordinary_program(program):
        return None
    if _RUNTIME_PATH.read_bytes() != _RUNTIME_BYTES:
        return None
    dispatch = RuntimeDispatch(program)
    if not dispatch._valid(program) or _RUNTIME_PATH.read_bytes() != _RUNTIME_BYTES:
        return None
    return dispatch


def fresh_machine(program, limits, dispatch):
    if type(dispatch) is RuntimeDispatch:
        return dispatch.new_machine(program, *limits)
    return _runtime._Machine(program, *limits)
