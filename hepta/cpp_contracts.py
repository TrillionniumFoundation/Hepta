"""Native-checked, explicitly unsafe C++ interoperation contracts.

This is a bridge generator, not a C++ to safe-Hepta translator. Its three
routes have different costs: direct values, checked call-scoped spans, and
serialized integer handles. Foreign retention, global effects and pointer
validity remain stated obligations, never conclusions inferred from a schema.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from .c_migrate import MigrationRejected, _IDENT


SCHEMA = "hepta.cpp-contract.v1"
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


def _validate(contract: object) -> dict:
    c = _fields(contract, {"schema", "module", "pod_types", "functions", "handles"}, "contract")
    if c["schema"] != SCHEMA:
        _reject("Unsupported C++ contract schema")
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
                _choice(t, set(_SCALARS), "concrete scalar template argument")
            _choice(fn["threading"], {"any_thread", "caller_synchronized"}, "threading")
            _choice(fn["reentrancy"], {"allowed", "caller_prevents"}, "reentrancy")
            _choice(fn["allocation"], {"none_declared", "cpp_internal"}, "allocation")
        used = set()
        for p in _array(fn["params"], "parameters", 16):
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
            if generated & (used | {"out", "handle"}):
                _reject("Duplicate, generated or reserved parameter name")
            used |= generated

    for f in _array(c["functions"], "functions"):
        callable_(f)
        if f["name"] in symbols:
            _reject("Duplicate exported symbol")
        symbols.add(f["name"])
    for h in _array(c["handles"], "handles", 8):
        _fields(h, {"name", "cpp_type", "template_args", "threading", "reentrancy",
                    "allocator", "destruction", "methods"}, "handle")
        _name(h["name"], "handle name")
        _name(h["cpp_type"], "C++ handle type", qualified=True)
        for t in _array(h["template_args"], "template arguments", 4):
            _choice(t, set(_SCALARS), "concrete scalar template argument")
        _choice(h["threading"], {"serialized", "creator_thread"}, "handle threading")
        _choice(h["reentrancy"], {"allow", "reject"}, "handle reentrancy")
        if h["allocator"] != "cpp_shared_owner" or h["destruction"] != "nothrow_defer_inflight":
            _reject("Handles require cpp_shared_owner and nothrow_defer_inflight")
        methods = _array(h["methods"], "methods")
        if not methods:
            _reject("A handle needs at least one method")
        names = {"new", "destroy"}
        for m in methods:
            callable_(m, method=True)
            if m["name"] in names:
                _reject("Duplicate or reserved handle method name")
            names.add(m["name"])
        exported = {h["name"] + "_" + n for n in names}
        if exported & symbols:
            _reject("Conflicting handle export name")
        symbols |= exported
    if not symbols:
        _reject("Contract must export at least one function or handle")
    return c


def _cpp_type(typ: str, pods: dict, *, abi: bool = False, prefix: str = "") -> str:
    if typ == "Unit":
        return "void"
    if typ in _SCALARS:
        return _SCALARS[typ][0]
    return prefix + typ if abi else pods[typ]["cpp_type"]


def _concrete(name: str, args: list[str]) -> str:
    return name + ("<" + ", ".join(_SCALARS[t][0] for t in args) + ">" if args else "")


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

    def cpp_arg(self, p: dict) -> str:
        if p["mode"].startswith("borrow_"):
            return self.cpp_arg_type(p) + "(" + p["name"] + ", " + p["name"] + "_len)"
        # Preserve the category used by the compile-time call-expression check;
        # an lvalue/rvalue overload must not silently replace the declared call.
        return "static_cast<" + self.cpp_arg_type(p) + ">(" + self.value_in(p["name"], p["type"]) + ")"

    def parameters(self, fn: dict, *, handle: bool, checked: bool) -> tuple[list[str], list[str], list[str]]:
        cpp, c, hp = (["std::uint64_t handle"], ["uint64_t handle"], ["handle: u64"]) if handle else ([], [], [])
        for p in fn["params"]:
            n, t, mode = p["name"], p["type"], p["mode"]
            if mode.startswith("borrow_"):
                const = "const " if mode == "borrow_const" else ""
                cpp += [const + self.cpp_type(t) + "* " + n, "std::size_t " + n + "_len"]
                c += [const + self.ctype(t) + "* " + n, "size_t " + n + "_len"]
                hp += [n + ": raw " + ("const " if const else "mut ") + t, n + "_len: usize"]
            else:
                cpp.append(self.cpp_type(t, abi=True) + " " + n)
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
        if fn["returns"] != "Unit":
            lines += ["    if (!out) return 1;",
                      f"    if (reinterpret_cast<std::uintptr_t>(out) % alignof({self.cpp_type(fn['returns'], abi=True)})) return 8;"]
        for p in fn["params"]:
            if not p["mode"].startswith("borrow_"):
                continue
            n, typ = p["name"], self.cpp_type(p["type"])
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
            expr = name + "_target(" + ", ".join(self.cpp_arg(p) for p in f["params"]) + ")"
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
                         f"static_assert(std::is_default_constructible_v<{obj}> && std::is_nothrow_destructible_v<{obj}>);",
                         f"struct {entry} {{ std::recursive_mutex mutex; std::shared_ptr<{obj}> object; std::shared_ptr<const std::uint8_t> creator; unsigned active = 0; }};",
                         f"struct {registry} {{ std::mutex mutex; std::unordered_map<std::uint64_t, std::shared_ptr<{entry}>> objects; }};",
                         "// Process-lifetime registry avoids destroying abandoned affine objects on an arbitrary shutdown thread.",
                         f"{registry}& {get}() {{ static auto* r = new {registry}; return *r; }}",
                         f"struct {name}_active {{ {entry}& e; explicit {name}_active({entry}& v): e(v) {{ ++e.active; }} ~{name}_active() {{ --e.active; }} }};", "}"]
            self.cpp += [self.declare(name + "_new", "i32", ["std::uint64_t* out"], ["uint64_t* out"], ["out: raw mut u64"], {"ffi", "unsafe", "write", "alloc", "block"}),
                         "    if (!out) return 1;", "    if (reinterpret_cast<std::uintptr_t>(out) % alignof(std::uint64_t)) return 8;",
                         "    try {", f"        auto entry = std::make_shared<{entry}>();",
                         f"        entry->object = std::make_shared<{obj}>();",
                         *([f"        entry->creator = {self.prefix}thread_token();"] if h["threading"] == "creator_thread" else []),
                         f"        auto handle = {self.prefix}allocate_handle();", "        if (!handle) return 4;",
                         f"        auto& registry = {get}();", "        std::lock_guard<std::mutex> lock(registry.mutex);",
                         "        if (!registry.objects.emplace(handle, entry).second) return 4;",
                         "        *out = handle;", "        return 0;", "    } catch (...) { return 3; }", "}"]
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
                    self.cpp += [f"static_assert(std::is_reference_v<decltype({invocation})> && std::is_same_v<std::remove_cvref_t<decltype({invocation})>, {rtype}>);"]
                else:
                    self.cpp += [f"static_assert(std::is_same_v<decltype({invocation}), {rtype}>);"]
                if m["exception"] == "noexcept":
                    self.cpp += [f"static_assert(noexcept({invocation}));"]
                params = self.parameters(m, handle=True, checked=True)
                effects = {"ffi", "unsafe", "write", "alloc", "block"}
                if m["returns"] != "Unit" or any(p["mode"] == "borrow_mut" for p in m["params"]):
                    effects.add("write")
                self.cpp += [self.declare(symbol, "i32", *params, effects)] + self.checks(m) + ["    try {"] + lookup
                self.cpp += ["        auto object = entry->object;", f"        {name}_active active(*entry);",
                             f"        {ref} receiver = *object;"]
                expr = "receiver." + m["cpp_method"] + "(" + ", ".join(self.cpp_arg(p) for p in m["params"]) + ")"
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
            self.costs += [{"symbol": name + "_new", "route": "handle_create",
                            "allocation": "entry_and_object_shared_owners_plus_registry_node_and_possible_bucket_growth",
                            "foreign_constructor_allocations": "unverified", "registry_lifetime": "process"},
                           {"symbol": name + "_destroy", "route": "handle_destroy", "destruction": h["destruction"],
                            "deallocation": "same_C++_shared_owner_module", "abandoned_handles": "not_automatically_reclaimed"}]

    def render(self) -> tuple[str, str, str]:
        self.pods_()
        self.functions_()
        self.handles_()
        self.h += ["#ifdef __cplusplus", "}", "#endif", "#undef HEPTA_CPP_NOEXCEPT"]
        return tuple("\n".join(lines) + "\n" for lines in (self.cpp, self.h, self.hp))


def _command(argv: list[str], *, timeout: int = 90) -> subprocess.CompletedProcess:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        _reject(str(exc), "E_CPP_ENV")
    if p.returncode:
        _reject((p.stderr or p.stdout)[-8000:], "E_CPP_NATIVE")
    return p


def bridge_cpp_contracts(header: str | Path, contract: dict | str | Path,
                         output_dir: str | Path, *, cxx: str = "c++", rustc: str | None = None) -> dict:
    """Check actual C++ signatures/POD layouts and Rust-lowered declarations.

    An existing output directory is never replaced. Success writes source and
    a contract receipt; it does not link or execute the foreign library. The
    separate native qualification tool performs actual bidirectional execution.
    """
    src, dest = Path(header).resolve(), Path(output_dir).resolve()
    report = {"schema": "hepta.cpp-bridge-contract-report.v1", "ok": False, "status": "rejected",
              "native_link_qualified": False, "execution": "not_run", "diagnostics": [],
              "paired_toolchain_abi_qualified": False,
              "foreign_library_soundness_proved": False, "borrow_retention_proved": False,
              "foreign_thread_safety_proved": False, "caller_pointer_validity_proved": False}
    try:
        original_dest = Path(output_dir)
        if original_dest.is_symlink() or dest.exists() or not src.is_file() or src.suffix not in {".h", ".hpp", ".hh"}:
            _reject("Need an existing header and a new, nonsymlink output directory", "E_CPP_PATH")
        raw_contract = contract if isinstance(contract, dict) else json.loads(Path(contract).read_text(encoding="utf-8"))
        c = _validate(raw_contract)
        header_bytes = src.read_bytes()
        if len(header_bytes) > 256_000:
            _reject("Header exceeds 256 KB", "E_CPP_SIZE")
        generator = _Generator(src, c)
        cpp, ch, hp = generator.render()
        compiler = shutil.which(cxx)
        if not compiler:
            _reject("C++ compiler is unavailable", "E_CPP_ENV")
        info = {"path": str(Path(compiler).resolve()), "version": _command([compiler, "--version"]).stdout.splitlines()[0],
                "target": _command([compiler, "-dumpmachine"]).stdout.strip(),
                "executable_sha256": hashlib.sha256(Path(compiler).read_bytes()).hexdigest()}
        with tempfile.TemporaryDirectory(prefix="hepta-cpp-contract-") as td:
            temp = Path(td)
            (temp / "bridge.cpp").write_text(cpp, encoding="utf-8")
            (temp / "bridge.h").write_text(ch, encoding="utf-8")
            flags = ["-std=c++20", "-O2", "-fPIC", "-pthread", "-Werror", "-MMD", "-MF", str(temp / "bridge.d")]
            _command([compiler, *flags, "-c", str(temp / "bridge.cpp"), "-o", str(temp / "bridge.o")])
            obj = temp / "bridge.o"
            if not obj.is_file() or not obj.stat().st_size:
                _reject("C++ compiler did not produce a nonempty object", "E_CPP_ARTIFACT")
            # Depfiles include user headers, not the complete compiler/sysroot.
            # Record that distinction instead of presenting a header hash as a
            # hermetic dependency lock.
            depfile = (temp / "bridge.d").read_text(encoding="utf-8")
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
                           "compiler": info, "cpp_flags": ["-std=c++20", "-O2", "-fPIC", "-pthread", "-Werror"],
                           "object_sha256": hashlib.sha256(obj.read_bytes()).hexdigest(), "object_bytes": obj.stat().st_size,
                           "compiler_user_header_dependencies": depfile,
                           "transitive_dependency_lock": "not_established_rebuild_from_current_headers_required",
                           "hepta_validation": checked.report, "status_codes": STATUS,
                           "cost_accounting": generator.costs, "abi": "selected_C++_compiler_host_C_ABI",
                           "assumptions": ["Foreign code respects declared effects, reentrancy and synchronization requirements.",
                                           "Borrowed pointers name live initialized aligned allocations of the stated extent with valid aliasing.",
                                           "Foreign code does not retain call_only pointers, spans or const references, or create data races through aliases.",
                                           "Output pointers are live writable appropriately aligned nonoverlapping storage.",
                                           "C++ code obeys noexcept; termination, hardware faults and undefined behavior are not catchable exceptions.",
                                           "All handle-owned allocation and release stay in the same C++ module; callers explicitly destroy handles.",
                                           "Handles belong to their generating bridge module and type; integers from other loaded modules are not authenticated capabilities.",
                                           "Cancellation and exception status do not roll back foreign side effects or borrowed-buffer writes."]})
        files = {"bridge.cpp": cpp, "bridge.h": ch, "bridge.hepta": hp,
                 "contract.json": json.dumps(c, indent=2, sort_keys=True) + "\n"}
        report["outputs"] = {name: {"path": str(dest / name), "sha256": hashlib.sha256(data.encode()).hexdigest()} for name, data in files.items()}
        # mkdir(exist_ok=False) is the publication guard. No existing directory
        # is ever removed, and partial output is not advertised as success.
        dest.mkdir(parents=True, exist_ok=False)
        try:
            for name, data in files.items():
                (dest / name).write_text(data, encoding="utf-8")
            (dest / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except OSError:
            report.update(ok=False, status="publication_failed")
            raise
        return report
    except (MigrationRejected, OSError, ValueError, TypeError) as exc:
        report.update(ok=False, status="rejected")
        report["diagnostics"].append({"code": getattr(exc, "code", "E_CPP_INPUT"), "message": str(exc)})
        return report


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("header", type=Path)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--cxx", default="c++")
    parser.add_argument("--rustc")
    args = parser.parse_args()
    result = bridge_cpp_contracts(args.header, args.contract, args.output_dir, cxx=args.cxx, rustc=args.rustc)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
