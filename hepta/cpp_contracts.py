"""Native-checked, explicitly unsafe C++ interoperation contracts.

This is a bridge generator, not a C++ to safe-Hepta translator. Its routes
have different costs: direct values, checked call-scoped spans, serialized
integer handles, and call-local C++ RAII objects. Foreign retention, global effects and pointer
validity remain stated obligations, never conclusions inferred from a schema.
"""
from __future__ import annotations

from copy import deepcopy
import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile

from .clang_capture import CaptureRejected, CaptureResult, run_bounded
from .c_migrate import MigrationRejected, _IDENT


SCHEMA = "hepta.cpp-contract.v1"
SCHEMA_V2 = "hepta.cpp-contract.v2"
SCHEMA_V3 = "hepta.cpp-contract.v3"
SCHEMA_V4 = "hepta.cpp-contract.v4"
SCHEMA_V5 = "hepta.cpp-contract.v5"
_QUALIFIED = re.compile(r"[A-Za-z_][A-Za-z_0-9]*(?:::[A-Za-z_][A-Za-z_0-9]*)*\Z")
_SCALARS = {
    "i8": ("std::int8_t", "int8_t"), "u8": ("std::uint8_t", "uint8_t"),
    "i16": ("std::int16_t", "int16_t"), "u16": ("std::uint16_t", "uint16_t"),
    "i32": ("std::int32_t", "int32_t"), "u32": ("std::uint32_t", "uint32_t"),
    "i64": ("std::int64_t", "int64_t"), "u64": ("std::uint64_t", "uint64_t"),
    "usize": ("std::size_t", "size_t"), "isize": ("std::intptr_t", "intptr_t"),
    "f32": ("float", "float"), "f64": ("double", "double"),
}
STATUS = {"success": 0, "null_pointer": 1, "stale_handle": 2,
          "cpp_exception": 3, "handle_exhausted": 4, "wrong_thread": 5,
          "reentrancy_rejected": 6, "span_too_large": 7, "misaligned_pointer": 8}


def _reject(message: str, code: str = "E_CPP_CONTRACT") -> None:
    raise MigrationRejected(code, message)


def _fields(obj: object, fields: set[str], context: str) -> dict:
    if not isinstance(obj, dict) or set(obj) != fields:
        _reject(f"{context} requires exactly {sorted(fields)}")
    return obj


def _name(value: object, context: str, *, qualified: bool = False) -> str:
    pattern = _QUALIFIED if qualified else _IDENT
    if not isinstance(value, str) or len(value) > (512 if qualified else 128) or not pattern.fullmatch(value) or "__" in value:
        _reject(f"Invalid {context}")
    return value


def _choice(value: object, choices: set[str], context: str) -> str:
    if not isinstance(value, str) or value not in choices:
        _reject(f"{context} must be one of {sorted(choices)}")
    return value


def _array(value: object, context: str, maximum: int = 32) -> list:
    if not isinstance(value, list) or len(value) > maximum:
        _reject(f"{context} must be a list with at most {maximum} entries")
    return value


def _template_argument(value: object, *, sizes: bool) -> str:
    """Render only checked types or an explicitly bounded size constant.

    A v4 size is a typed value, never a pasted C++ expression. Earlier wire
    schemas retain their type-only interpretation. In particular bool is not
    accepted as an integer, and no negative/floating/string value is coerced.
    """
    if isinstance(value, str):
        return _SCALARS[_choice(value, set(_SCALARS), "concrete scalar template argument")][0]
    if not sizes:
        _reject("Non-type template arguments require the explicit v4 schema")
    item = _fields(value, {"kind", "value"}, "non-type template argument")
    if item["kind"] != "size" or type(item["value"]) is not int or not 0 <= item["value"] <= 65536:
        _reject("Non-type template argument must be an exact size integer in [0, 65536]")
    return "static_cast<std::size_t>(" + str(item["value"]) + ")"


def _validate(contract: object) -> dict:
    if not isinstance(contract, dict):
        _reject("contract must be an object")
    c = _fields(contract, {"schema", "module", "pod_types", "functions", "handles"}
                | ({"scopes"} if contract.get("schema") in (SCHEMA_V3, SCHEMA_V4, SCHEMA_V5) else set())
                | ({"pipelines"} if contract.get("schema") == SCHEMA_V5 else set()), "contract")
    _choice(c["schema"], {SCHEMA, SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5}, "C++ contract schema")
    _name(c["module"], "module name")
    pods = {}
    for pod in _array(c["pod_types"], "pod_types", 16):
        _fields(pod, {"name", "cpp_type", "fields"}, "POD type")
        name = _name(pod["name"], "POD name")
        _name(pod["cpp_type"], "C++ POD type", qualified=True)
        if name in pods or name in _SCALARS or name == "Unit":
            _reject("Duplicate or reserved POD name")
        fields = _array(pod["fields"], "POD fields", 16)
        if not fields:
            _reject("Empty C/C++ structs do not share a supported ABI")
        used = set()
        for f in fields:
            _fields(f, {"name", "type"}, "POD field")
            _name(f["name"], "POD field")
            _choice(f["type"], set(_SCALARS), "POD field type")
            if f["name"] in used:
                _reject("Duplicate POD field")
            used.add(f["name"])
        pods[name] = pod
    types = set(_SCALARS) | set(pods)
    symbols = set()

    def parameters_(params: object, *, constructor: bool = False) -> None:
        used = set()
        # Keep the original schema's reserved names. C++ implementation
        # parameters are separately renamed by position below, so accepted
        # public names cannot capture any generated invocation-scope locals.
        reserved = {"out", "handle"} | ({"entry", "registry", "lock"} if constructor else set())
        for p in _array(params, "parameters", 16):
            if not isinstance(p, dict):
                _reject("Each parameter must be an object")
            mode = _choice(p.get("mode"), {"value", "const_ref", "borrow_const", "borrow_mut"}, "parameter mode")
            reference = mode.startswith("borrow_") or mode == "const_ref"
            _fields(p, {"name", "type", "mode"} | ({"retention"} if reference else set()), "parameter")
            _name(p["name"], "parameter name")
            _choice(p["type"], set(_SCALARS) if mode.startswith("borrow_") else types, "parameter type")
            if reference and p["retention"] != "call_only":
                _reject("Borrowed storage may not be retained; this remains a foreign obligation")
            generated = {p["name"], p["name"] + "_len"} if mode.startswith("borrow_") else {p["name"]}
            if generated & (used | reserved):
                _reject("Duplicate, generated or reserved parameter name")
            used |= generated

    def callable_(fn: dict, *, method: bool = False) -> None:
        expected = {"name", "params", "returns", "exception"}
        expected |= {"cpp_method", "const", "return_mode"} if method else {
            "cpp_name", "template_args", "threading", "reentrancy", "allocation"}
        _fields(fn, expected, "method" if method else "function")
        _name(fn["name"], "exported name")
        _choice(fn["returns"], types | {"Unit"}, "return type")
        _choice(fn["exception"], {"noexcept", "catch_status"}, "exception policy")
        if method:
            _name(fn["cpp_method"], "C++ method")
            if type(fn["const"]) is not bool:
                _reject("Method const must be boolean")
            _choice(fn["return_mode"], {"value", "copy_from_reference"}, "return mode")
            if fn["return_mode"] == "copy_from_reference" and fn["returns"] == "Unit":
                _reject("Void cannot be copied from a reference")
        else:
            _name(fn["cpp_name"], "C++ function", qualified=True)
            for t in _array(fn["template_args"], "template arguments", 4):
                _template_argument(t, sizes=c["schema"] in (SCHEMA_V4, SCHEMA_V5))
            _choice(fn["threading"], {"any_thread", "caller_synchronized"}, "threading")
            _choice(fn["reentrancy"], {"allowed", "caller_prevents"}, "reentrancy")
            _choice(fn["allocation"], {"none_declared", "cpp_internal"}, "allocation")
        parameters_(fn["params"])

    for f in _array(c["functions"], "functions"):
        callable_(f)
        if f["name"] in symbols:
            _reject("Duplicate exported symbol")
        symbols.add(f["name"])
    for h in _array(c["handles"], "handles", 8):
        _fields(h, {"name", "cpp_type", "template_args", "threading", "reentrancy",
                    "allocator", "destruction", "methods"} | ({"constructors"} if c["schema"] in {SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5} else set()), "handle")
        _name(h["name"], "handle name")
        _name(h["cpp_type"], "C++ handle type", qualified=True)
        for t in _array(h["template_args"], "template arguments", 4):
            _template_argument(t, sizes=c["schema"] in (SCHEMA_V4, SCHEMA_V5))
        _choice(h["threading"], {"serialized", "creator_thread"}, "handle threading")
        _choice(h["reentrancy"], {"allow", "reject"}, "handle reentrancy")
        if h["allocator"] != "cpp_shared_owner" or h["destruction"] != "nothrow_defer_inflight":
            _reject("Handles require cpp_shared_owner and nothrow_defer_inflight")
        methods = _array(h["methods"], "methods")
        if not methods:
            _reject("A handle needs at least one method")
        names = {"destroy"}
        if c["schema"] in {SCHEMA_V2, SCHEMA_V3, SCHEMA_V4, SCHEMA_V5}:
            constructors = _array(h["constructors"], "constructors", 8)
            if not constructors:
                _reject("A v2/v3/v4 handle needs at least one explicit constructor contract")
            for constructor in constructors:
                _fields(constructor, {"name", "params", "exception"}, "constructor")
                _name(constructor["name"], "constructor export name")
                _choice(constructor["exception"], {"noexcept", "catch_status"}, "constructor exception policy")
                parameters_(constructor["params"], constructor=True)
                if constructor["name"] in names:
                    _reject("Duplicate or reserved constructor export name")
                names.add(constructor["name"])
        else:
            names.add("new")
        for m in methods:
            callable_(m, method=True)
            if m["name"] in names or m["name"] == "new":
                _reject("Duplicate or reserved handle method name")
            names.add(m["name"])
        exported = {h["name"] + "_" + n for n in names}
        if exported & symbols:
            _reject("Conflicting handle export name")
        symbols |= exported
    handles = {h["name"]: h for h in c["handles"]}
    for scope in _array(c.get("scopes", []), "scopes", 16):
        _fields(scope, {"name", "handle", "constructor", "params", "constructor_args",
                        "calls", "lifetime"}, "scoped operation")
        name = _name(scope["name"], "scoped export name")
        if name in symbols:
            _reject("Conflicting scoped export name")
        symbols.add(name)
        if scope["lifetime"] != "call_scoped_cpp_raii":
            _reject("Scoped operations require call_scoped_cpp_raii")
        handle = _name(scope["handle"], "scoped handle type")
        if handle not in handles:
            _reject("Scoped operation refers to an unknown handle type")
        h = handles[handle]
        parameters_(scope["params"], constructor=True)
        params = {p["name"]: p for p in scope["params"]}
        if {"_hepta_scoped_object", "_hepta_scoped_result"} & set(params):
            _reject("Reserved scoped operation parameter name")
        used = set()

        def arguments_(arguments: object, target: dict) -> None:
            args = _array(arguments, "scoped argument names", 16)
            if len(args) != len(target["params"]):
                _reject("Scoped argument count differs from the selected contract")
            for argument, expected in zip(args, target["params"]):
                _name(argument, "scoped argument")
                if argument not in params:
                    _reject("Scoped argument must name an input parameter")
                actual = params[argument]
                if any(actual.get(k) != expected.get(k) for k in ("type", "mode", "retention")):
                    _reject("Scoped argument type, mode and retention must match exactly")
                used.add(argument)

        constructor_name = _name(scope["constructor"], "scoped constructor name")
        constructors = {ctor["name"]: ctor for ctor in h["constructors"]}
        if constructor_name not in constructors:
            _reject("Scoped operation refers to an unknown constructor")
        arguments_(scope["constructor_args"], constructors[constructor_name])
        calls = _array(scope["calls"], "scoped method calls", 16)
        if not calls:
            _reject("Scoped operation needs at least one method call")
        methods = {m["name"]: m for m in h["methods"]}
        for call in calls:
            _fields(call, {"method", "args"}, "scoped method call")
            method = _name(call["method"], "scoped method name")
            if method not in methods:
                _reject("Scoped operation refers to an unknown method")
            arguments_(call["args"], methods[method])
        if used != set(params):
            _reject("Every scoped input must be used by construction or a method")
    for pipeline in _array(c.get("pipelines", []), "pipelines", 16):
        _fields(pipeline, {"name", "params", "steps", "return", "lifetime"}, "RAII pipeline")
        name = _name(pipeline["name"], "pipeline export name")
        if name in symbols:
            _reject("Conflicting pipeline export name")
        symbols.add(name)
        parameters_(pipeline["params"], constructor=True)
        _pipeline_plan(pipeline, handles)
    if not symbols:
        _reject("Contract must export at least one function or handle")
    return c


def _pipeline_plan(pipeline: dict, handles: dict) -> dict:
    """Resolve a finite typed sequence with copied scalar/POD dataflow only.

    Foreign objects and references never become value bindings. Inputs retain
    their declared categories. A copied method result can feed value/const_ref
    arguments of exactly the same type; no numeric conversions, borrowed spans,
    raw addresses, object moves or escaping references are synthesized.
    """
    if pipeline["lifetime"] != "call_scoped_cpp_raii":
        _reject("RAII pipelines require call_scoped_cpp_raii")
    values = {p["name"]: {"kind": "input", "specification": p} for p in pipeline["params"]}
    objects, used_values, used_objects, steps = {}, set(), set(), []

    def arguments(arguments, target):
        names = _array(arguments, "pipeline arguments", 16)
        if len(names) != len(target["params"]):
            _reject("Pipeline argument count differs from selected contract")
        for name, expected in zip(names, target["params"]):
            _name(name, "pipeline value reference")
            if name not in values:
                _reject("Pipeline arguments must name earlier copied values or inputs")
            binding = values[name]
            if binding["kind"] == "input":
                actual = binding["specification"]
                if any(actual.get(k) != expected.get(k) for k in ("type", "mode", "retention")):
                    _reject("Pipeline input type, mode and retention must match exactly")
            elif (binding["type"] != expected["type"] or expected["mode"] not in {"value", "const_ref"}):
                _reject("Copied pipeline values require identical scalar/POD value or const_ref types")
            used_values.add(name)

    for number, step in enumerate(_array(pipeline["steps"], "pipeline steps", 32)):
        if type(step) is not dict:
            _reject("Each pipeline step must be an object")
        operation = _choice(step.get("op"), {"construct", "call"}, "pipeline operation")
        if operation == "construct":
            _fields(step, {"op", "name", "handle", "constructor", "args"}, "pipeline construction")
            name = _name(step["name"], "pipeline object name")
            handle_name = _name(step["handle"], "pipeline object type")
            if name in values or name in objects or len(objects) >= 8:
                _reject("Pipeline object names must be fresh; at most eight objects are admitted")
            if handle_name not in handles:
                _reject("Unknown pipeline handle type")
            handle = handles[handle_name]
            constructor_name = _name(step["constructor"], "pipeline constructor name")
            constructors = {c["name"]: c for c in handle["constructors"]}
            if constructor_name not in constructors:
                _reject("Unknown pipeline constructor")
            target = constructors[constructor_name]
            arguments(step["args"], target)
            objects[name] = {"handle": handle, "cpp_name": "hepta_pipeline_object" + str(len(objects))}
            steps.append({"step": step, "target": target, "object": objects[name]})
        else:
            _fields(step, {"op", "object", "method", "args", "result"}, "pipeline method call")
            name = _name(step["object"], "pipeline receiver")
            method_name = _name(step["method"], "pipeline method name")
            if name not in objects:
                _reject("Pipeline receiver must name an earlier constructed object")
            obj = objects[name]
            methods = {m["name"]: m for m in obj["handle"]["methods"]}
            if method_name not in methods:
                _reject("Unknown pipeline method")
            target = methods[method_name]
            arguments(step["args"], target)
            used_objects.add(name)
            result = step["result"]
            if result is not None:
                _name(result, "pipeline copied result")
                if result in values or result in objects or target["returns"] == "Unit":
                    _reject("Pipeline result must be a fresh scalar/POD copy of a nonvoid method")
                values[result] = {"kind": "copy", "type": target["returns"],
                                  "cpp_name": "hepta_pipeline_value" + str(number)}
            steps.append({"step": step, "target": target, "object": obj})
    output = pipeline["return"]
    result_type = "Unit"
    if output is not None:
        _name(output, "pipeline returned value")
        if output not in values or values[output]["kind"] != "copy":
            _reject("A pipeline can return only an earlier copied scalar/POD method result")
        result_type = values[output]["type"]
        used_values.add(output)
    if not objects or used_objects != set(objects) or used_values != set(values):
        _reject("Every pipeline object, input and copied value must participate in the sequence")
    return {"steps": steps, "objects": objects, "values": values, "returns": result_type}


def _cpp_type(typ: str, pods: dict, *, abi: bool = False, prefix: str = "") -> str:
    if typ == "Unit":
        return "void"
    if typ in _SCALARS:
        return _SCALARS[typ][0]
    return prefix + typ if abi else pods[typ]["cpp_type"]


def _concrete(name: str, args: list[object]) -> str:
    # The schema gate has already selected the argument grammar. Recheck the
    # actual values here as well so this helper cannot emit arbitrary C++.
    return name + ("<" + ", ".join(_template_argument(t, sizes=True) for t in args) + ">" if args else "")


class _Generator:
    def __init__(self, header: Path, contract: dict):
        self.header, self.c = header, contract
        self.prefix = "hepta_cpp_" + contract["module"] + "_"
        self.pods = {p["name"]: p for p in contract["pod_types"]}
        self.cpp = ["// Generated bridge: foreign code and caller pointers remain unverified.",
                    '#include "bridge.h"', "#include " + json.dumps(str(header), ensure_ascii=False),
                    "#include <cstdint>", "#include <cstddef>", "#include <type_traits>",
                    "#include <span>", "#include <memory>", "#include <mutex>",
                    "#include <thread>", "#include <unordered_map>", "#include <limits>", "#include <utility>", "#include <atomic>"]
        self.h = ["// C ABI declarations. See contract.json for caller obligations.", "#pragma once",
                  "#include <stdint.h>", "#include <stddef.h>", "#ifdef __cplusplus",
                  '#define HEPTA_CPP_NOEXCEPT noexcept', 'extern "C" {', "#else",
                  "#define HEPTA_CPP_NOEXCEPT", "#endif"]
        self.hp = ["module " + contract["module"] + ";",
                   "// All foreign calls remain explicitly unsafe; no C++ safety proof is claimed."]
        self.costs = []
        self.constructor_checks = []
        self.scoped_checks = []
        self.pipeline_checks = []

    def cpp_type(self, typ: str, *, abi: bool = False) -> str:
        return _cpp_type(typ, self.pods, abi=abi, prefix=self.prefix)

    def ctype(self, typ: str) -> str:
        return "void" if typ == "Unit" else _SCALARS[typ][1] if typ in _SCALARS else self.prefix + typ

    def value_in(self, name: str, typ: str) -> str:
        if typ not in self.pods:
            return name
        return self.cpp_type(typ) + "{" + ", ".join(name + "." + f["name"] for f in self.pods[typ]["fields"]) + "}"

    def value_out(self, name: str, typ: str) -> str:
        if typ not in self.pods:
            return name
        return self.cpp_type(typ, abi=True) + "{" + ", ".join(name + "." + f["name"] for f in self.pods[typ]["fields"]) + "}"

    def cpp_arg_type(self, p: dict) -> str:
        typ = self.cpp_type(p["type"])
        if p["mode"] == "const_ref":
            return "const " + typ + "&"
        if p["mode"].startswith("borrow_"):
            return "std::span<" + ("const " if p["mode"] == "borrow_const" else "") + typ + ">"
        return typ

    @staticmethod
    def argument_names(fn: dict) -> dict[str, str]:
        # Public C/Hepta names are documentation, not implementation bindings.
        # A source name such as receiver/result/entry must never resolve to a
        # generated local (which can silently select a C++ conversion overload).
        return {p["name"]: "hepta_arg" + str(i) for i, p in enumerate(fn["params"])}

    def cpp_arg(self, p: dict, names: dict[str, str]) -> str:
        name = names[p["name"]]
        if p["mode"].startswith("borrow_"):
            return self.cpp_arg_type(p) + "(" + name + ", " + name + "_len)"
        # Preserve the category used by the compile-time call-expression check;
        # an lvalue/rvalue overload must not silently replace the declared call.
        return "static_cast<" + self.cpp_arg_type(p) + ">(" + self.value_in(name, p["type"]) + ")"

    def parameters(self, fn: dict, *, handle: bool, checked: bool) -> tuple[list[str], list[str], list[str]]:
        cpp, c, hp = (["std::uint64_t handle"], ["uint64_t handle"], ["handle: u64"]) if handle else ([], [], [])
        names = self.argument_names(fn)
        for p in fn["params"]:
            n, t, mode = p["name"], p["type"], p["mode"]
            implementation_name = names[n]
            if mode.startswith("borrow_"):
                const = "const " if mode == "borrow_const" else ""
                cpp += [const + self.cpp_type(t) + "* " + implementation_name, "std::size_t " + implementation_name + "_len"]
                c += [const + self.ctype(t) + "* " + n, "size_t " + n + "_len"]
                hp += [n + ": raw " + ("const " if const else "mut ") + t, n + "_len: usize"]
            else:
                cpp.append(self.cpp_type(t, abi=True) + " " + implementation_name)
                c.append(self.ctype(t) + " " + n)
                hp.append(n + ": " + t)
        if checked and fn["returns"] != "Unit":
            cpp.append(self.cpp_type(fn["returns"], abi=True) + "* out")
            c.append(self.ctype(fn["returns"]) + "* out")
            hp.append("out: raw mut " + fn["returns"])
        return cpp, c, hp

    def declare(self, name: str, returns: str, cpp: list[str], c: list[str], hp: list[str], effects: set[str]) -> str:
        self.h.append(f"{self.ctype(returns)} {name}({', '.join(c) or 'void'}) HEPTA_CPP_NOEXCEPT;")
        self.hp.append(f'extern "C" fn {name}({", ".join(hp)}) -> {returns} effects {{{", ".join(sorted(effects))}}};')
        return f'extern "C" {self.cpp_type(returns, abi=True)} {name}({", ".join(cpp)}) noexcept {{'

    def checks(self, fn: dict) -> list[str]:
        lines = []
        names = self.argument_names(fn)
        if fn["returns"] != "Unit":
            lines += ["    if (!out) return 1;",
                      f"    if (reinterpret_cast<std::uintptr_t>(out) % alignof({self.cpp_type(fn['returns'], abi=True)})) return 8;"]
        for p in fn["params"]:
            if not p["mode"].startswith("borrow_"):
                continue
            n, typ = names[p["name"]], self.cpp_type(p["type"])
            lines += [f"    if ({n}_len && !{n}) return 1;",
                      f"    if ({n}_len > static_cast<std::size_t>((std::numeric_limits<std::ptrdiff_t>::max)()) / sizeof({typ})) return 7;",
                      f"    if (reinterpret_cast<std::uintptr_t>({n}) % alignof({typ})) return 8;"]
        return lines

    def call_result(self, fn: dict, expression: str, *, checked: bool, indent: str) -> list[str]:
        if fn["returns"] == "Unit":
            return [indent + expression + ";", indent + ("return 0;" if checked else "return;")]
        result = [indent + "auto result = " + expression + ";"]
        out = self.value_out("result", fn["returns"])
        return result + ([indent + "*out = " + out + ";", indent + "return 0;"] if checked else [indent + "return " + out + ";"])

    def pods_(self) -> None:
        for name, p in self.pods.items():
            abi, foreign = self.prefix + name, p["cpp_type"]
            self.h += ["typedef struct " + abi + " {"]
            self.h += ["    " + self.ctype(f["type"]) + " " + f["name"] + ";" for f in p["fields"]]
            self.h += ["} " + abi + ";"]
            self.hp += ["pub repr(C) struct " + name + " {"]
            self.hp += ["    " + f["name"] + ": " + f["type"] + "," for f in p["fields"]]
            self.hp += ["}"]
            self.cpp += [f"static_assert(std::is_aggregate_v<{foreign}> && std::is_trivial_v<{foreign}> && std::is_standard_layout_v<{foreign}>);",
                         f"static_assert(sizeof({foreign}) == sizeof({abi}) && alignof({foreign}) == alignof({abi}));"]
            bindings = ["field" + str(i) for i in range(len(p["fields"]))]
            self.cpp += [f"[[maybe_unused]] static void {abi}_field_count({foreign} value) {{",
                         "    auto [" + ", ".join(bindings) + "] = value;",
                         *["    (void)" + field + ";" for field in bindings], "}"]
            for f in p["fields"]:
                self.cpp += [f"static_assert(std::is_same_v<decltype({foreign}::{f['name']}), {self.cpp_type(f['type'])}>);",
                             f"static_assert(offsetof({foreign}, {f['name']}) == offsetof({abi}, {f['name']}));"]

    def functions_(self) -> None:
        for f in self.c["functions"]:
            name = self.prefix + f["name"]
            borrowed = any(p["mode"].startswith("borrow_") for p in f["params"])
            checked = borrowed or f["exception"] == "catch_status"
            sig = name + "_signature"
            noexcept = " noexcept" if f["exception"] == "noexcept" else ""
            self.cpp += [f"using {sig} = {self.cpp_type(f['returns'])}(*)({', '.join(self.cpp_arg_type(p) for p in f['params'])}){noexcept};",
                         f"static constexpr {sig} {name}_target = static_cast<{sig}>(&{_concrete(f['cpp_name'], f['template_args'])});"]
            params = self.parameters(f, handle=False, checked=checked)
            effects = {"ffi", "unsafe"}
            if f["allocation"] == "cpp_internal":
                effects.add("alloc")
            if checked and f["returns"] != "Unit" or any(p["mode"] == "borrow_mut" for p in f["params"]):
                effects.add("write")
            self.cpp += [self.declare(name, "i32" if checked else f["returns"], *params, effects)]
            if checked:
                self.cpp += self.checks(f) + ["    try {"]
            expr = name + "_target(" + ", ".join(self.cpp_arg(p, self.argument_names(f)) for p in f["params"]) + ")"
            self.cpp += self.call_result(f, expr, checked=checked, indent="        " if checked else "    ")
            if checked:
                self.cpp += ["    } catch (...) { return 3; }"]
            self.cpp += ["}"]
            self.costs.append({"symbol": name, "route": "checked_borrow" if borrowed else "checked_value" if checked else "direct_value",
                               "wrapper_registry_lookups": 0, "wrapper_mutex_acquisitions": 0,
                               "wrapper_heap_allocations": 0, "input_buffer_copy_bytes": 0,
                               "pod_field_conversion": any(p["type"] in self.pods for p in f["params"]) or f["returns"] in self.pods,
                               "exception_boundary": "catch_status" if checked else "native_noexcept_type_checked",
                               "foreign_allocation": f["allocation"], "foreign_allocation_verified": False})

    def handles_(self) -> None:
        if self.c["handles"]:
            self.cpp += ["namespace {", f"std::atomic<std::uint64_t> {self.prefix}next_handle{{1}};",
                         f"std::uint64_t {self.prefix}allocate_handle() noexcept {{",
                         f"    auto current = {self.prefix}next_handle.load(std::memory_order_relaxed);",
                         "    while (current) {",
                         f"        if ({self.prefix}next_handle.compare_exchange_weak(current, current + 1, std::memory_order_relaxed)) return current;",
                         "    }", "    return 0;", "}",
                         f"[[maybe_unused]] const std::shared_ptr<const std::uint8_t>& {self.prefix}thread_token() {{",
                         "    // A retained token distinguishes thread instances even when std::thread::id is reused.",
                         "    static thread_local const auto token = std::make_shared<const std::uint8_t>(0);",
                         "    return token;", "}", "}"]
        for h in self.c["handles"]:
            name, obj = self.prefix + h["name"], _concrete(h["cpp_type"], h["template_args"])
            entry, registry, get = name + "_entry", name + "_registry", name + "_registry_get"
            self.cpp += ["namespace {", f"using {name}_object = {obj};",
                         f"static_assert(std::is_nothrow_destructible_v<{obj}>);",
                         f"struct {entry} {{ std::recursive_mutex mutex; std::shared_ptr<{obj}> object; std::shared_ptr<const std::uint8_t> creator; unsigned active = 0; }};",
                         f"struct {registry} {{ std::mutex mutex; std::unordered_map<std::uint64_t, std::shared_ptr<{entry}>> objects; }};",
                         "// Process-lifetime registry avoids destroying abandoned affine objects on an arbitrary shutdown thread.",
                         f"{registry}& {get}() {{ static auto* r = new {registry}; return *r; }}",
                         f"struct {name}_active {{ {entry}& e; explicit {name}_active({entry}& v): e(v) {{ ++e.active; }} ~{name}_active() {{ --e.active; }} }};", "}"]
            constructors = h.get("constructors", [{"name": "new", "params": [], "exception": "catch_status"}])
            for constructor in constructors:
                symbol = name + "_" + constructor["name"]
                arguments = [self.cpp_arg_type(p) for p in constructor["params"]]
                trait_types = ", ".join([obj, *arguments])
                self.cpp += [f"static_assert(std::is_constructible_v<{trait_types}>);"]
                if constructor["exception"] == "noexcept":
                    self.cpp += [f"static_assert(std::is_nothrow_constructible_v<{trait_types}>);"]
                # Constructor traits check a typed construction expression;
                # C++ has no constructor address to compare as an exact ABI
                # signature. make_shared forwards the same argument categories.
                callable_constructor = {**constructor, "returns": "u64"}
                params = self.parameters(callable_constructor, handle=False, checked=True)
                self.cpp += [self.declare(symbol, "i32", *params, {"ffi", "unsafe", "write", "alloc", "block"})]
                self.cpp += self.checks(callable_constructor)
                self.cpp += ["    try {", f"        auto entry = std::make_shared<{entry}>();",
                             f"        entry->object = std::make_shared<{obj}>({', '.join(self.cpp_arg(p, self.argument_names(constructor)) for p in constructor['params'])});",
                             *([f"        entry->creator = {self.prefix}thread_token();"] if h["threading"] == "creator_thread" else []),
                             f"        auto handle = {self.prefix}allocate_handle();", "        if (!handle) return 4;",
                             f"        auto& registry = {get}();", "        std::lock_guard<std::mutex> lock(registry.mutex);",
                             "        if (!registry.objects.emplace(handle, entry).second) return 4;",
                             "        *out = handle;", "        return 0;", "    } catch (...) { return 3; }", "}"]
                verification = {"symbol": symbol, "cpp_type": obj, "argument_types": arguments,
                                "declared_exception": constructor["exception"],
                                "construction_check": "native_constructibility_with_declared_argument_categories",
                                "exact_constructor_parameter_signature_proved": False,
                                "nothrow_object_construction_checked": constructor["exception"] == "noexcept",
                                "wrapper_allocation_exception_boundary": "catch_status",
                                "borrow_retention_proved": False}
                self.constructor_checks.append(verification)
                self.costs.append({"symbol": symbol, "route": "handle_create",
                                   "allocation": "entry_and_object_shared_owners_plus_registry_node_and_possible_bucket_growth",
                                   "foreign_constructor_allocations": "unverified", "registry_lifetime": "process",
                                   "constructor_exception": constructor["exception"], "exception_boundary": "catch_status",
                                   "wrapper_input_buffer_copy_bytes": 0,
                                   "foreign_input_copy": "constructor_dependent_unverified",
                                   "borrow_retention_proved": False,
                                   "output_write": "only_after_successful_registry_insertion"})
            # Obtain and release the registry mutex before taking the per-object
            # mutex. No generated path holds the registry while running C++ code.
            lookup = [f"        auto& registry = {get}();", f"        std::shared_ptr<{entry}> entry;", "        {",
                      "            std::lock_guard<std::mutex> lock(registry.mutex);",
                      "            auto it = registry.objects.find(handle);", "            if (it == registry.objects.end()) return 2;",
                      "            entry = it->second;", "        }"]
            if h["threading"] == "creator_thread":
                lookup += [f"        if (entry->creator != {self.prefix}thread_token()) return 5;"]
            lookup += ["        std::lock_guard<std::recursive_mutex> lock(entry->mutex);",
                       "        if (!entry->object) return 2;"]
            if h["reentrancy"] == "reject":
                lookup += ["        if (entry->active) return 6;"]
            self.cpp += [self.declare(name + "_destroy", "i32", ["std::uint64_t handle"], ["uint64_t handle"], ["handle: u64"], {"ffi", "unsafe", "write", "alloc", "block"}), "    try {"] + lookup
            self.cpp += ["        {", "            std::lock_guard<std::mutex> registry_lock(registry.mutex);",
                         "            auto it = registry.objects.find(handle);",
                         "            if (it == registry.objects.end() || it->second != entry) return 2;",
                         "            registry.objects.erase(it);", "        }", "        entry->object.reset();",
                         "        return 0;", "    } catch (...) { return 3; }", "}"]
            for m in h["methods"]:
                symbol = name + "_" + m["name"]
                ref = "const " + obj + "&" if m["const"] else obj + "&"
                invocation = "std::declval<" + ref + ">()." + m["cpp_method"] + "(" + ", ".join("std::declval<" + self.cpp_arg_type(p) + ">()" for p in m["params"]) + ")"
                rtype = self.cpp_type(m["returns"])
                if m["return_mode"] == "copy_from_reference":
                    self.cpp += [f'static_assert(std::is_reference_v<decltype({invocation})> && std::is_same_v<std::remove_cvref_t<decltype({invocation})>, {rtype}>, "HEPTA_CPP_METHOD_RESULT:{symbol}");']
                else:
                    self.cpp += [f'static_assert(std::is_same_v<decltype({invocation}), {rtype}>, "HEPTA_CPP_METHOD_RESULT:{symbol}");']
                if m["exception"] == "noexcept":
                    self.cpp += [f"static_assert(noexcept({invocation}));"]
                params = self.parameters(m, handle=True, checked=True)
                effects = {"ffi", "unsafe", "write", "alloc", "block"}
                if m["returns"] != "Unit" or any(p["mode"] == "borrow_mut" for p in m["params"]):
                    effects.add("write")
                self.cpp += [self.declare(symbol, "i32", *params, effects)] + self.checks(m) + ["    try {"] + lookup
                self.cpp += ["        auto object = entry->object;", f"        {name}_active active(*entry);",
                             f"        {ref} receiver = *object;"]
                expr = "receiver." + m["cpp_method"] + "(" + ", ".join(self.cpp_arg(p, self.argument_names(m)) for p in m["params"]) + ")"
                self.cpp += self.call_result(m, expr, checked=True, indent="        ")
                self.cpp += ["    } catch (...) { return 3; }", "}"]
                self.costs.append({"symbol": symbol, "route": "dynamic_handle", "wrapper_registry_lookups": 1,
                                   "wrapper_mutex_acquisitions": 2, "wrapper_heap_allocations": 0,
                                   "accounting_scope": "successful_call_after_registry_initialization",
                                   "lazy_registry_allocation": "possible_on_first_call",
                                   "thread_identity_allocation": "first_use_on_each_thread" if h["threading"] == "creator_thread" else "none",
                                   "wrapper_shared_owner_copies": 2, "input_buffer_copy_bytes": 0,
                                   "foreign_allocation": "method_dependent_unverified",
                                   "exception_boundary": "catch_status", "threading": h["threading"], "reentrancy": h["reentrancy"]})
            self.costs.append({"symbol": name + "_destroy", "route": "handle_destroy", "destruction": h["destruction"],
                               "deallocation": "same_C++_shared_owner_module", "abandoned_handles": "not_automatically_reclaimed"})

    def scopes_(self) -> None:
        """Keep one concrete C++ object inside a single ordinary call lifetime.

        These are generated C++ RAII operations, not Hepta owning values or
        rewritten foreign implementations. Only the already checked scalar/POD
        results cross the ABI; a reference result is copied before destruction.
        """
        handles = {h["name"]: h for h in self.c["handles"]}
        for scope in self.c.get("scopes", []):
            h = handles[scope["handle"]]
            obj = _concrete(h["cpp_type"], h["template_args"])
            constructor = next(ctor for ctor in h["constructors"] if ctor["name"] == scope["constructor"])
            methods = {m["name"]: m for m in h["methods"]}
            last = methods[scope["calls"][-1]["method"]]
            fn = {"params": scope["params"], "returns": last["returns"]}
            name = self.prefix + scope["name"]
            params = self.parameters(fn, handle=False, checked=True)

            def arguments(arguments: list[str], target: dict) -> str:
                return ", ".join(self.cpp_arg({**p, "name": n}, self.argument_names(fn)) for n, p in zip(arguments, target["params"]))

            self.cpp += [self.declare(name, "i32", *params, {"ffi", "unsafe", "write", "alloc", "block"})]
            self.cpp += self.checks(fn) + ["    try {"]
            result_type = self.cpp_type(last["returns"])
            assignment = "auto _hepta_scoped_result = " if last["returns"] != "Unit" else ""
            self.cpp += [f"        {assignment}[&]() -> {result_type} {{",
                         f"            auto _hepta_scoped_object = {obj}({arguments(scope['constructor_args'], constructor)});"]
            for index, call in enumerate(scope["calls"]):
                method = methods[call["method"]]
                receiver_type = ("const " if method["const"] else "") + obj + "&"
                expression = (f"static_cast<{receiver_type}>(_hepta_scoped_object).{method['cpp_method']}"
                              f"({arguments(call['args'], method)})")
                if index == len(scope["calls"]) - 1 and method["returns"] != "Unit":
                    self.cpp += ["            return " + expression + ";"]
                else:
                    self.cpp += ["            (void)" + expression + ";"]
            # Returning from the lambda first materializes the value and then
            # destroys the foreign object. Do not publish *out until both have
            # finished. C++ unwinding handles every ordinary throwing path.
            self.cpp += ["        }();"]
            if last["returns"] != "Unit":
                self.cpp += ["        *out = " + self.value_out("_hepta_scoped_result", last["returns"]) + ";"]
            self.cpp += ["        return 0;", "    } catch (...) { return 3; }", "}"]
            self.scoped_checks.append({
                "symbol": name, "cpp_type": obj, "constructor": constructor["name"],
                "methods": [call["method"] for call in scope["calls"]],
                "lifetime": "one_call_cpp_automatic_object",
                "cleanup": "C++_RAII_on_normal_return_and_caught_C++_exceptions",
                "destructor_nothrow_native_checked": True,
                "result_type": last["returns"],
                "reference_result_copied_before_destructor": last["return_mode"] == "copy_from_reference",
                "output_published_after_destructor": last["returns"] != "Unit",
                "object_handle_exported": False, "foreign_implementation_rewritten": False,
                "foreign_nonretention_proved": False, "whole_library_memory_safety_proved": False,
            })
            self.costs.append({
                "symbol": name, "route": "call_scoped_cpp_raii",
                "wrapper_heap_allocations": 0, "wrapper_registry_lookups": 0,
                "wrapper_mutex_acquisitions": 0, "wrapper_shared_owner_copies": 0,
                "automatic_foreign_objects": 1, "method_invocations": len(scope["calls"]),
                "input_buffer_copy_bytes": 0,
                "pod_field_conversion": any(p["type"] in self.pods for p in scope["params"]) or last["returns"] in self.pods,
                "foreign_allocation": "constructor_and_methods_dependent_unverified",
                "foreign_stack_usage": "sizeof_selected_type_plus_compiler_generated_temporaries",
                "exception_boundary": "catch_status", "accounting_scope": "generated_wrapper_only",
            })

    def render(self) -> tuple[str, str, str]:
        self.pods_()
        self.functions_()
        self.handles_()
        self.scopes_()
        self.pipelines_()
        self.h += ["#ifdef __cplusplus", "}", "#endif", "#undef HEPTA_CPP_NOEXCEPT"]
        return tuple("\n".join(lines) + "\n" for lines in (self.cpp, self.h, self.hp))

    def pipelines_(self) -> None:
        """Compose ordinary C++ automatic lifetimes and copied value edges."""
        handles = {h["name"]: h for h in self.c["handles"]}
        for pipeline in self.c.get("pipelines", []):
            plan = _pipeline_plan(pipeline, handles)
            fn = {"params": pipeline["params"], "returns": plan["returns"]}
            name = self.prefix + pipeline["name"]
            parameters = self.parameters(fn, handle=False, checked=True)
            input_names = self.argument_names(fn)

            def arguments(names, target):
                result = []
                for value, expected in zip(names, target["params"]):
                    binding = plan["values"][value]
                    if binding["kind"] == "input":
                        result.append(self.cpp_arg({**expected, "name": value}, input_names))
                    else:
                        result.append("static_cast<" + self.cpp_arg_type(expected) + ">(" + binding["cpp_name"] + ")")
                return ", ".join(result)

            self.cpp += [self.declare(name, "i32", *parameters, {"ffi", "unsafe", "write", "alloc", "block"})]
            self.cpp += self.checks(fn) + ["    try {"]
            assignment = "auto hepta_pipeline_result = " if plan["returns"] != "Unit" else ""
            self.cpp += ["        " + assignment + "[&]() -> " + self.cpp_type(plan["returns"]) + " {"]
            for row in plan["steps"]:
                step, target, obj = row["step"], row["target"], row["object"]
                handle = obj["handle"]
                typ = _concrete(handle["cpp_type"], handle["template_args"])
                if step["op"] == "construct":
                    self.cpp += ["            auto " + obj["cpp_name"] + " = " + typ + "(" + arguments(step["args"], target) + ");"]
                else:
                    receiver = ("const " if target["const"] else "") + typ + "&"
                    expression = ("static_cast<" + receiver + ">(" + obj["cpp_name"] + ")." + target["cpp_method"]
                                  + "(" + arguments(step["args"], target) + ")")
                    if step["result"] is None:
                        self.cpp += ["            (void)" + expression + ";"]
                    else:
                        binding = plan["values"][step["result"]]
                        # An explicit value type materializes reference returns
                        # before subsequent mutation or destruction of the owner.
                        self.cpp += ["            const " + self.cpp_type(binding["type"]) + " " + binding["cpp_name"] + " = " + expression + ";"]
            if plan["returns"] != "Unit":
                self.cpp += ["            return " + plan["values"][pipeline["return"]]["cpp_name"] + ";"]
            self.cpp += ["        }();"]
            if plan["returns"] != "Unit":
                self.cpp += ["        *out = " + self.value_out("hepta_pipeline_result", plan["returns"]) + ";"]
            self.cpp += ["        return 0;", "    } catch (...) { return 3; }", "}"]
            self.pipeline_checks.append({
                "symbol": name, "objects_in_construction_order": list(plan["objects"]),
                "normal_destruction_order": list(reversed(plan["objects"])),
                "copied_value_edges": sum(b["kind"] == "copy" for b in plan["values"].values()),
                "result_type": plan["returns"], "object_or_reference_escape": False,
                "output_published_after_all_destructors": plan["returns"] != "Unit",
                "cleanup": "completed_objects_reverse_order_on_return_or_C++_unwinding",
                "destructor_nothrow_native_checked": True,
                "foreign_implementation_rewritten": False, "foreign_nonretention_proved": False,
                "whole_library_memory_safety_proved": False,
            })
            self.costs.append({
                "symbol": name, "route": "composed_call_scoped_cpp_raii",
                "automatic_foreign_objects": len(plan["objects"]),
                "method_invocations": sum(row["step"]["op"] == "call" for row in plan["steps"]),
                "wrapper_heap_allocations": 0, "wrapper_registry_lookups": 0,
                "wrapper_mutex_acquisitions": 0, "wrapper_shared_owner_copies": 0,
                "foreign_allocation": "constructors_and_methods_dependent_unverified",
                "exception_boundary": "catch_status", "accounting_scope": "generated_pipeline_wrapper_only",
            })


def _command(argv: list[str], *, timeout: int = 90) -> CaptureResult:
    """Bounded C++ compiler invocation for ABI-contract bridge generation.

    This protects the Agent host from unbounded diagnostic capture. The
    compiler and foreign header are not sandboxed against filesystem effects.
    """
    executable = shutil.which(argv[0]) if argv else None
    def identity():
        try:
            return hashlib.sha256(Path(executable).read_bytes()).hexdigest() if executable else None
        except OSError:
            return None
    before = identity()

    def streams(raw_out, raw_err, stdout, stderr):
        result = {'stdout': stdout, 'stderr': stderr,
                  'raw_streams_available': raw_out is not None and raw_err is not None}
        for name, data in [('stdout', raw_out), ('stderr', raw_err)]:
            result[name + '_raw_base64'] = base64.b64encode(data).decode('ascii') if data is not None else None
            result[name + '_raw_sha256'] = hashlib.sha256(data).hexdigest() if data is not None else None
            result[name + '_raw_bytes'] = len(data) if data is not None else None
        return result

    common = {'argv': list(argv), 'executable_sha256': before,
              'timeout_seconds': timeout, 'stdout_limit': 64000, 'stderr_limit': 256000,
              'text_normalization': 'strict UTF-8 with universal newline normalization'}
    try:
        p = run_bounded(argv, timeout=timeout, stdin_limit=0,
                        stdout_limit=64_000, stderr_limit=256_000)
    except CaptureRejected as exc:
        code = ("E_CPP_CAPTURE" if exc.code in
                {"E_CAPTURE_OUTPUT_SIZE", "E_CAPTURE_ENCODING"} else "E_CPP_ENV")
        rejection = MigrationRejected(code, f"{exc.code}: {exc}")
        captured = exc.capture
        rejection.native_process = {**common, 'status': 'capture_rejected',
            'capture_error': exc.code, 'exit_code': captured.returncode if captured else None,
            'executable_unchanged': before is not None and identity() == before,
            **streams(captured.stdout if captured else None, captured.stderr if captured else None, None, None)}
        raise rejection from exc
    if p.returncode:
        rejection = MigrationRejected('E_CPP_NATIVE', (p.stderr or p.stdout)[-8000:])
        rejection.native_process = {**common, 'status': 'exited', 'exit_code': p.returncode,
            'executable_unchanged': before is not None and identity() == before,
            **streams(p.raw_stdout, p.raw_stderr, p.stdout, p.stderr)}
        raise rejection
    return p


def bridge_cpp_contracts(header: str | Path, contract: dict | str | Path,
                         output_dir: str | Path, *, cxx: str = "c++", rustc: str | None = None,
                         cxx_family: str = "auto") -> dict:
    """Check actual C++ signatures/POD layouts and Rust-lowered declarations.

    An existing output directory is never replaced. Success writes source and
    a contract receipt; it does not link or execute the foreign library. The
    separate native qualification tool performs actual bidirectional execution.
    Validation, rendering, and the receipt share one private contract snapshot.
    """
    src, dest = Path(header).resolve(), Path(output_dir).resolve()
    report = {"schema": "hepta.cpp-bridge-contract-report.v1", "ok": False, "status": "rejected",
              "native_link_qualified": False, "execution": "not_run", "diagnostics": [],
              "paired_toolchain_abi_qualified": False,
              "foreign_library_soundness_proved": False, "borrow_retention_proved": False,
              "foreign_thread_safety_proved": False, "caller_pointer_validity_proved": False}
    phase = 'input_validation'
    generated_failure_inputs = None
    try:
        original_dest = Path(output_dir)
        if original_dest.is_symlink() or dest.exists() or not src.is_file() or src.suffix not in {".h", ".hpp", ".hh"}:
            _reject("Need an existing header and a new, nonsymlink output directory", "E_CPP_PATH")
        raw_contract = contract if isinstance(contract, dict) else json.loads(Path(contract).read_text(encoding="utf-8"))
        # The dict API must not retain caller-owned nested JSON containers:
        # edits during native validation cannot rebind the receipt to a
        # different contract from the one used to render the checked object.
        # Copy before validation and preserve its exact types/schema rules.
        c = _validate(deepcopy(raw_contract))
        report["contract_schema"] = c["schema"]
        header_bytes = src.read_bytes()
        if len(header_bytes) > 256_000:
            _reject("Header exceeds 256 KB", "E_CPP_SIZE")
        generator = _Generator(src, c)
        cpp, ch, hp = generator.render()
        phase = 'compiler_identity'
        from .cpp_host_toolchain import compiler_identity, compile_command, compile_flags
        info = compiler_identity(cxx, _command, family=cxx_family)
        report['compiler'] = info
        with tempfile.TemporaryDirectory(prefix="hepta-cpp-contract-") as td:
            temp = Path(td)
            (temp / "bridge.cpp").write_text(cpp, encoding="utf-8", newline="\n")
            (temp / "bridge.h").write_text(ch, encoding="utf-8", newline="\n")
            flags = compile_flags(info)
            generated_failure_inputs = {'header': str(src),
                'header_sha256': hashlib.sha256(header_bytes).hexdigest(),
                'contract': c,
                'contract_sha256': hashlib.sha256(json.dumps(c, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
                'source_path': str(temp / 'bridge.cpp'), 'object_path': str(temp / 'bridge.o'),
                'dependency_path': str(temp / 'bridge.d'),
                'files': {name: {'text': text, 'sha256': hashlib.sha256(text.encode()).hexdigest(), 'bytes': len(text.encode())}
                          for name, text in [('bridge.cpp', cpp), ('bridge.h', ch), ('bridge.hepta', hp)]}}
            phase = 'cpp_compile'
            _command(compile_command(info, temp / "bridge.cpp", temp / "bridge.o", dependency=temp / "bridge.d"))
            obj = temp / "bridge.o"
            if not obj.is_file() or not obj.stat().st_size:
                _reject("C++ compiler did not produce a nonempty object", "E_CPP_ARTIFACT")
            # Depfiles include user headers, not the complete compiler/sysroot.
            # Record that distinction instead of presenting a header hash as a
            # hermetic dependency lock.
            depfile = (temp / "bridge.d").read_text(encoding="utf-8")
            phase = 'hepta_frontend'
            from .pipeline import analyze
            checked = analyze(hp, str(dest / "bridge.hepta"), rustc=rustc)
            if not checked.report["ok"]:
                report["diagnostics"] = checked.report["diagnostics"]
                report["hepta_validation"] = checked.report
                return report
            if src.read_bytes() != header_bytes:
                _reject("Header changed during native validation", "E_CPP_SOURCE_RACE")
            report.update({"ok": True, "status": "cpp_object_and_hepta_native_checked",
                           "header": str(src), "header_sha256": hashlib.sha256(header_bytes).hexdigest(),
                           "contract_sha256": hashlib.sha256(json.dumps(c, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                           "compiler": info, "cpp_flags": flags,
                           "object_sha256": hashlib.sha256(obj.read_bytes()).hexdigest(), "object_bytes": obj.stat().st_size,
                           "compiler_user_header_dependencies": depfile,
                           "compiler_dependency_format": "msvc_source_dependencies_json" if info["driver"] == "msvc" else "make_user_headers",
                           "transitive_dependency_lock": "not_established_rebuild_from_current_headers_required",
                           "hepta_validation": checked.report, "status_codes": STATUS,
                           "cost_accounting": generator.costs, "constructor_checks": generator.constructor_checks,
                           "scoped_lifetime_checks": generator.scoped_checks,
                           "pipeline_lifetime_checks": generator.pipeline_checks,
                           "template_specializations": [
                               {"kind": kind, "export": item["name"],
                                "cpp": _concrete(item[key], item["template_args"]),
                                "arguments": item["template_args"],
                                "selected_instantiation_native_checked": True,
                                "all_template_instantiations_qualified": False}
                               for kind, items, key in (("function", c["functions"], "cpp_name"),
                                                        ("object", c["handles"], "cpp_type"))
                               for item in items if item["template_args"]],
                           "abi": "selected_C++_compiler_host_C_ABI",
                           "assumptions": ["Foreign code respects declared effects, reentrancy and synchronization requirements.",
                                           "Borrowed pointers name live initialized aligned allocations of the stated extent with valid aliasing.",
                                           "Foreign code does not retain call_only pointers, spans or const references, or create data races through aliases.",
                                           "Output pointers are live writable appropriately aligned nonoverlapping storage.",
                                           "C++ code obeys noexcept; termination, hardware faults and undefined behavior are not catchable exceptions.",
                                           "All handle-owned allocation and release stay in the same C++ module; callers explicitly destroy handles.",
                                           "Scoped operations keep their C++ automatic object inside the call; generated APIs expose no object handle or reference. Foreign nonretention is unproved.",
                                           "Scoped RAII cleanup covers normal return and C++ exception unwinding, not process termination, longjmp, nontermination or foreign undefined behavior.",
                                           "Handles belong to their generating bridge module and type; integers from other loaded modules are not authenticated capabilities.",
                                           "Cancellation and exception status do not roll back foreign side effects or borrowed-buffer writes."]})
        files = {"bridge.cpp": cpp, "bridge.h": ch, "bridge.hepta": hp,
                 "contract.json": json.dumps(c, indent=2, sort_keys=True) + "\n"}
        report["outputs"] = {name: {"path": str(dest / name), "sha256": hashlib.sha256(data.encode()).hexdigest()} for name, data in files.items()}
        phase = 'publication'
        # mkdir(exist_ok=False) is the publication guard. No existing directory
        # is ever removed, and partial output is not advertised as success.
        dest.mkdir(parents=True, exist_ok=False)
        try:
            for name, data in files.items():
                (dest / name).write_text(data, encoding="utf-8", newline="\n")
            (dest / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        except OSError:
            report.update(ok=False, status="publication_failed")
            raise
        return report
    except (MigrationRejected, OSError, ValueError, TypeError) as exc:
        report.update(ok=False, status="rejected")
        report["diagnostics"].append({"code": getattr(exc, "code", "E_CPP_INPUT"), "message": str(exc)})
        report['failure'] = {'phase': phase, 'process': getattr(exc, 'native_process', None)}
        if phase == 'cpp_compile' and generated_failure_inputs is not None:
            report['failure']['generated_inputs'] = generated_failure_inputs
        return report


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("header", type=Path)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cxx", default="c++")
    parser.add_argument("--cxx-family", choices=["auto", "gcc", "clang", "msvc"], default="auto")
    parser.add_argument("--rustc")
    args = parser.parse_args()
    result = bridge_cpp_contracts(args.header, args.contract, args.output_dir, cxx=args.cxx, rustc=args.rustc,
                                  cxx_family=args.cxx_family)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
