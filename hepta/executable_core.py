"""Executable, source-bound integer/byte-owner core, version 1.

This core has actual value and resource operations consumed by an independent
interpreter and decoded back into the existing native backend's checked AST.
Source replay, round-trip checks and finite differential execution are not a
proof of compiler refinement or whole-language soundness.  The closed profile
deliberately excludes arbitrary AST nodes, FFI, stored loans and concurrency.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile

from .ast import Expr, Function, HeptaError, MatchArm, Param, Pattern, Program, Span, Stmt, Type
from .checker import check
from .parser import parse
from .pipeline import compiler_hash
from .resource_ir import ResourceIRError, verify_resource_ir
from .resource_lowering import lower_resource_ir
from .semantic_ir import lower_checked_program

SCHEMA = "hepta.executable-core.v1"
PROFILE = "checked-integer-buffer-result-structured-v1"
WIDTHS = {**{f"{sign}{bits}": bits for sign in ("i", "u")
             for bits in (8, 16, 32, 64)}, "usize": 64, "isize": 64}
SCALARS = set(WIDTHS) | {"bool", "Unit"}
BUFFER = Type("Buffer", (Type("u8"),))
MAX_SOURCE_BYTES = 1024 * 1024
MAX_CORE_BYTES = 4 * 1024 * 1024
MAX_NODES = 100000
MAX_DEPTH = 96
CLAIMS = {"executable_reference_semantics": True,
          "source_origin_replayed": True,
          "decoded_core_rechecked": True,
          "native_execution_qualified": False,
          "source_to_ir_refinement_proved": False,
          "backend_refinement_proved": False,
          "whole_language_soundness_proved": False,
          "foreign_contracts_proved": False,
          "general_lifetimes_supported": False,
          "concurrency_supported": False}

BINARY = {"+": "int.add.checked", "-": "int.sub.checked",
          "*": "int.mul.checked", "/": "int.div.checked", "%": "int.rem.checked",
          "<<": "int.shl.checked", ">>": "int.shr.checked", "&": "bit.and",
          "|": "bit.or", "^": "bit.xor", "==": "compare.eq", "!=": "compare.ne",
          "<": "compare.lt", "<=": "compare.le", ">": "compare.gt", ">=": "compare.ge",
          "&&": "bool.and.short", "||": "bool.or.short"}
UNARY = {"+": "value.identity", "-": "int.neg.checked", "!": "bit.not",
         "move": "owner.move", "read": "borrow.read", "mut": "borrow.mut"}
BUILTINS = {"buffer": "buffer.new", "try_buffer": "buffer.try_new",
            "drop": "owner.drop", "release": "owner.release", "len": "buffer.length",
            "assert": "guard.assert", "wrapping_add": "int.add.wrap",
            "wrapping_sub": "int.sub.wrap", "wrapping_mul": "int.mul.wrap",
            "min": "int.min", "max": "int.max"}


class ExecutableCoreRejected(ValueError):
    """A controlled profile, identity or resource rejection."""


def reject(message, code="E_CORE_PROFILE"):
    raise ExecutableCoreRejected(f"{code}: {message}")


def _wire(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, RecursionError, UnicodeError) as exc:
        reject("Core is not bounded canonical JSON", "E_CORE_FORMAT")


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _budget(value):
    pending, count = [(value, 0)], 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            reject("Core exceeds structural limits", "E_CORE_LIMIT")
        if type(node) is dict:
            if any(type(k) is not str for k in node):
                reject("Core keys must be strings", "E_CORE_FORMAT")
            pending.extend((child, depth + 1) for child in node.values())
        elif type(node) is list:
            pending.extend((child, depth + 1) for child in node)
        elif type(node) not in (str, int, bool, type(None)):
            reject("Unsupported core wire value", "E_CORE_FORMAT")
    if len(_wire(value)) > MAX_CORE_BYTES:
        reject("Core exceeds byte limit", "E_CORE_LIMIT")


def _span(span):
    return {key: getattr(span, key) for key in ("start", "end", "line", "column", "path")}


def _type(typ):
    if not isinstance(typ, Type) or typ.lifetimes or typ.length is not None:
        reject("Stored lifetimes and array layouts are outside the core")
    if typ.name in SCALARS and not typ.args:
        return {"name": typ.name, "args": []}
    if typ.name in {"Buffer", "slice"} and typ.args == (Type("u8"),):
        return {"name": typ.name, "args": [_type(typ.args[0])]}
    if typ.name == "Result" and len(typ.args) == 2:
        if any(arg.name == "slice" for arg in typ.args):
            reject("Borrowed Result payloads are outside the core")
        return {"name": "Result", "args": [_type(arg) for arg in typ.args]}
    reject("Unsupported core type: " + str(typ))


def _decode_type(value):
    return Type(value["name"], tuple(_decode_type(arg) for arg in value["args"]))


class _Lower:
    def __init__(self, program, checked):
        self.program, self.checked = program, checked
        self.functions = {fn.name: fn for fn in program.functions}
        self.operations = 0

    def expr(self, expr):
        if expr is None:
            return None
        self.operations += 1
        if self.operations > 16384:
            reject("Too many executable operations", "E_CORE_LIMIT")
        typ = self.checked.expr_types.get(id(expr))
        if typ is None:
            reject("Expression lacks a checked source type", "E_CORE_TYPE")
        if expr.type_args:
            # Result constructors carry concrete arguments; generic calls do not.
            if expr.kind != "variant":
                reject("Generic calls are outside executable-core v1")
        out = {"type": _type(typ), "span": _span(expr.span),
               "args": [self.expr(child) for child in expr.children]}
        if expr.kind in {"int", "bool"}:
            out.update(op="const." + expr.kind, value=expr.value)
        elif expr.kind == "name":
            out.update(op="local.get", name=expr.value)
        elif expr.kind == "index":
            out["op"] = "buffer.load"
        elif expr.kind == "binary" and expr.value in BINARY:
            if expr.value in {"<<", ">>"} and self.checked.expr_types[id(expr.children[0])] != self.checked.expr_types[id(expr.children[1])]:
                reject("Core v1 shift operands require the same integer type")
            out["op"] = BINARY[expr.value]
        elif expr.kind == "unary" and expr.value in UNARY:
            out["op"] = UNARY[expr.value]
            if expr.value in {"read", "mut", "move"} and expr.children[0].kind != "name":
                reject("Core ownership/borrow operands must be named locals")
        elif expr.kind == "cast":
            if typ.name not in WIDTHS or self.checked.expr_types[id(expr.children[0])].name not in WIDTHS:
                reject("Core casts require bounded integers")
            out["op"] = "int.cast"
        elif expr.kind == "call":
            if expr.value in BUILTINS:
                out["op"] = BUILTINS[expr.value]
            elif expr.value in self.functions:
                out.update(op="function.call", function=expr.value)
            else:
                reject("Unknown core call: " + str(expr.value))
        elif expr.kind == "variant" and typ.name == "Result":
            out.update(op="result.make", variant=expr.value["variant"],
                       constructor=dict(expr.value),
                       type_args=[_type(arg) for arg in expr.type_args])
        else:
            reject("Unsupported executable expression: " + expr.kind)
        return out

    def body(self, statements):
        out = []
        for stmt in statements:
            d = stmt.data
            op = {"span": _span(stmt.span)}
            if stmt.kind == "let":
                op.update(op="local.bind", name=d["name"], mutable=d["mutable"],
                          annotation=_type(d["type"]) if d.get("type") else None,
                          value=self.expr(d["expr"]))
            elif stmt.kind == "assign":
                if d["target"].kind not in {"name", "index"}:
                    reject("Core assignment requires a local or byte index")
                op.update(op="place.write", target=self.expr(d["target"]), value=self.expr(d["expr"]))
            elif stmt.kind in {"expr", "return"}:
                op.update(op="evaluate" if stmt.kind == "expr" else "return", value=self.expr(d["expr"]))
            elif stmt.kind == "if":
                op.update(op="if", condition=self.expr(d["condition"]),
                          then=self.body(d["then"]), otherwise=self.body(d["else"]))
            elif stmt.kind == "while":
                op.update(op="while", condition=self.expr(d["condition"]), body=self.body(d["body"]))
            elif stmt.kind == "for":
                op.update(op="for", name=d["name"], start=self.expr(d["start"]),
                          end=self.expr(d["end"]), body=self.body(d["body"]))
            elif stmt.kind == "match":
                if self.checked.expr_types[id(d["expr"])].name != "Result":
                    reject("Only Result matching is supported")
                op.update(op="result.match", value=self.expr(d["expr"]), arms=[
                    {"variant": arm.pattern.variant, "bindings": list(arm.pattern.bindings),
                     "pattern_span": _span(arm.pattern.span), "span": _span(arm.span),
                     "body": self.body(arm.body)} for arm in d["arms"]])
            else:
                reject("Unsupported executable statement: " + stmt.kind)
            out.append(op)
        return out

    def lower(self):
        p, checked = self.program, self.checked
        if not checked.ok or checked.assumptions:
            reject("Checked source without foreign assumptions is required", "E_CORE_SOURCE")
        if p.structs or p.enums or p.imports or len(p.functions) > 128:
            reject("Core v1 accepts one module with primitive/Buffer/Result types")
        functions = []
        for fn in p.functions:
            if (fn.extern_c or fn.type_params or fn.lifetime_params or fn.return_mode != "value"
                    or fn.return_origin or fn.return_lifetime or fn.body is None
                    or fn.effects - {"alloc", "block", "panic", "write"}):
                reject("Unsupported function contract: " + fn.name)
            for param in fn.params:
                if param.lifetime or param.mode not in {"value", "take", "read", "mut"}:
                    reject("Unsupported parameter mode")
                if param.mode in {"read", "mut"} and param.type not in {BUFFER, Type("slice", (Type("u8"),))}:
                    reject("Core loans currently cover byte Buffer/slices")
            functions.append({"name": fn.name, "public": fn.public, "export_c": fn.export_c,
                "span": _span(fn.span), "body_span": _span(fn.body_span),
                "params": [{"name": q.name, "mode": q.mode, "type": _type(q.type), "span": _span(q.span)} for q in fn.params],
                "returns": _type(fn.return_type), "declared_effects": sorted(fn.effects),
                "inferred_effects": sorted(checked.effects.get(fn.name, set())),
                "resources": dict(fn.resources), "body": self.body(fn.body)})
        return functions


def _unchecked_lower(program, checked, project_sha256):
    lower = _Lower(program, checked)
    functions = lower.lower()
    semantic = lower_checked_program(program, checked, project_sha256=project_sha256)
    if not semantic["all_expressions_typed"] or semantic["external_obligations"]:
        reject("Unresolved source semantics", "E_CORE_SOURCE")
    try:
        graph = lower_resource_ir(program, checked, project_sha256=project_sha256)
    except ResourceIRError as exc:
        reject(str(exc), "E_CORE_RESOURCE")
    resources = verify_resource_ir(graph)
    if resources.get("ok") is not True or resources.get("external_obligations"):
        reject("Independent resource verification rejected", "E_CORE_RESOURCE")
    out = {"schema": SCHEMA, "profile": PROFILE, "module": program.name, "path": program.path,
        "source_sha256": _sha(program.source.encode()), "project_sha256": project_sha256,
        "compiler_sha256": compiler_hash(), "pointer_width": 64,
        "arithmetic": "checked; explicit wrapping; truncating integer casts; abort-on-guard",
        "functions": functions, "operation_count": lower.operations,
        "semantic_sha256": semantic["sha256"], "resource_ir_sha256": _sha(_wire(graph)),
        "resource_verification_sha256": _sha(_wire(resources)), "claims": dict(CLAIMS)}
    out["sha256"] = _sha(_wire(out))
    _budget(out)
    return out


def _fresh(source, path):
    if type(source) is not str:
        reject("Source text required", "E_CORE_SOURCE")
    try:
        source_bytes = source.encode("utf-8")
    except UnicodeError:
        reject("Source must be valid UTF-8 text", "E_CORE_SOURCE")
    if len(source_bytes) > MAX_SOURCE_BYTES:
        reject("Source exceeds the core input limit", "E_CORE_LIMIT")
    try:
        program = parse(source, path)
        checked = check(program)
    except (HeptaError, RecursionError) as exc:
        reject("Source parsing/checking rejected: " + str(exc), "E_CORE_SOURCE")
    if not checked.ok:
        reject("Source check failed: " + "; ".join(d.code + ": " + d.message for d in checked.diagnostics), "E_CORE_SOURCE")
    return program, checked


def _project_identity(project_sha256):
    if project_sha256 is not None and (type(project_sha256) is not str or len(project_sha256) != 64
            or any(c not in "0123456789abcdef" for c in project_sha256)):
        reject("Invalid project identity", "E_CORE_SOURCE")


def lower_executable_core(program, checked=None, *, project_sha256=None):
    """Encode and replay a single module.  No native qualification is implied."""
    if not isinstance(program, Program):
        reject("Program required", "E_CORE_SOURCE")
    _project_identity(project_sha256)
    checked = checked if checked is not None else check(program)
    core = _unchecked_lower(program, checked, project_sha256)
    decode_executable_core(core, source=program.source, path=program.path,
                           project_sha256=project_sha256)
    return core


def _decode_expr(expr):
    if expr is None:
        return None
    op, value = expr["op"], None
    if op.startswith("const."):
        kind, value = op[6:], expr["value"]
    elif op == "local.get":
        kind, value = "name", expr["name"]
    elif op == "buffer.load":
        kind = "index"
    elif op in BINARY.values():
        kind, value = "binary", next(k for k, v in BINARY.items() if v == op)
    elif op in UNARY.values():
        kind, value = "unary", next(k for k, v in UNARY.items() if v == op)
    elif op == "int.cast":
        kind, value = "cast", _decode_type(expr["type"])
    elif op == "function.call":
        kind, value = "call", expr["function"]
    elif op in BUILTINS.values():
        kind, value = "call", next(k for k, v in BUILTINS.items() if v == op)
    elif op == "result.make":
        kind, value = "variant", dict(expr["constructor"])
    else:
        reject("Unknown executable opcode", "E_CORE_FORMAT")
    return Expr(kind, value, [_decode_expr(a) for a in expr["args"]], Span(**expr["span"]),
                tuple(_decode_type(t) for t in expr.get("type_args", [])))


def _decode_body(ops):
    out = []
    for op in ops:
        kind = op["op"]
        if kind == "local.bind":
            kind, data = "let", {"name": op["name"], "type": _decode_type(op["annotation"]) if op["annotation"] else None,
                                  "mutable": op["mutable"], "expr": _decode_expr(op["value"])}
        elif kind == "place.write":
            kind, data = "assign", {"target": _decode_expr(op["target"]), "expr": _decode_expr(op["value"])}
        elif kind in {"evaluate", "return"}:
            kind, data = "expr" if kind == "evaluate" else "return", {"expr": _decode_expr(op["value"])}
        elif kind == "if":
            data = {"condition": _decode_expr(op["condition"]), "then": _decode_body(op["then"]), "else": _decode_body(op["otherwise"])}
        elif kind == "while":
            data = {"condition": _decode_expr(op["condition"]), "body": _decode_body(op["body"])}
        elif kind == "for":
            data = {"name": op["name"], "start": _decode_expr(op["start"]), "end": _decode_expr(op["end"]), "body": _decode_body(op["body"])}
        elif kind == "result.match":
            kind, data = "match", {"expr": _decode_expr(op["value"]), "arms": [
                MatchArm(Pattern("Result", arm["variant"], list(arm["bindings"]), Span(**arm["pattern_span"])),
                         _decode_body(arm["body"]), Span(**arm["span"])) for arm in op["arms"]]}
        else:
            reject("Unknown executable statement", "E_CORE_FORMAT")
        out.append(Stmt(kind, data, Span(**op["span"])))
    return out


def decode_executable_core(document, *, source, path=None, project_sha256=None):
    """Validate source correspondence, then decode *core operations* for native use."""
    _verify_source_origin(document, source=source, path=path, project_sha256=project_sha256)
    functions = [Function(fn["name"], [Param(q["name"], _decode_type(q["type"]), q["mode"], Span(**q["span"]))
                    for q in fn["params"]], _decode_type(fn["returns"]), set(fn["declared_effects"]),
                    _decode_body(fn["body"]), public=fn["public"], export_c=fn["export_c"],
                    resources=dict(fn["resources"]), span=Span(**fn["span"]), body_span=Span(**fn["body_span"]))
                 for fn in document["functions"]]
    program = Program(document["module"], [], functions, source, document["path"])
    checked = check(program)
    if not checked.ok:
        reject("Decoded core failed type/effect/resource checking", "E_CORE_DECODE")
    replay = _unchecked_lower(program, checked, project_sha256)
    if _wire(replay) != _wire(document):
        reject("Decoded executable operations do not round-trip", "E_CORE_DECODE")
    return program, checked


def _verify_source_origin(document, *, source, path=None, project_sha256=None):
    _project_identity(project_sha256)
    _budget(document)
    if type(document) is not dict or document.get("schema") != SCHEMA or document.get("profile") != PROFILE:
        reject("Unexpected executable-core schema/profile", "E_CORE_FORMAT")
    supplied_path = document.get("path") if path is None else path
    if type(supplied_path) is not str or not supplied_path:
        reject("Exact source path required", "E_CORE_SOURCE")
    program, checked = _fresh(source, supplied_path)
    expected = _unchecked_lower(program, checked, project_sha256)
    if _wire(expected) != _wire(document):
        reject("Core differs from freshly checked source, types, effects or resources", "E_CORE_ORIGIN")
    return expected


def verify_executable_core(document, *, source, path=None, project_sha256=None):
    decode_executable_core(document, source=source, path=path, project_sha256=project_sha256)
    return {"schema": "hepta.executable-core-verification.v1", "ok": True,
            "status": "source_replayed_and_core_rechecked", "core_sha256": document["sha256"],
            "source_sha256": document["source_sha256"], "resource_ir_sha256": document["resource_ir_sha256"],
            "claims": dict(CLAIMS)}


def execute_executable_core(document, function, arguments, *, source, path=None,
                            project_sha256=None, max_steps=1000000, max_heap_bytes=1024 * 1024,
                            allocation_fail_at=None):
    """Run the core itself; host allocator equivalence is not claimed."""
    from .executable_core_runtime import execute_verified_core
    verify_executable_core(document, source=source, path=path, project_sha256=project_sha256)
    return execute_verified_core(document, function, arguments, max_steps=max_steps,
                                 max_heap_bytes=max_heap_bytes, allocation_fail_at=allocation_fail_at)


def build_executable_core_source(source, output, *, rustc=None, clang="clang", kind="shared"):
    """Pinned Rust gate -> source-bound core -> decoded core -> LLVM -> new artifact.

    The LLVM emitter consumes the decoded operations.  It is not called on the
    original input AST.  Every unsupported source is rejected before publication.
    """
    from .pipeline import analyze
    from .llvm_owned_backend import emit_owned_llvm, compile_owned_llvm
    from .artifact_publication import publish_verified, verify_published, withdraw_own_link
    path = Path(source).resolve()
    destination = Path(output).absolute()
    if (kind not in {"shared", "object"} or destination.exists() or destination.is_symlink()
            or not destination.parent.is_dir() or destination == path):
        reject("A new native output is required", "E_CORE_OUTPUT")
    data = path.read_bytes()
    if len(data) > MAX_SOURCE_BYTES:
        reject("Source exceeds byte limit", "E_CORE_LIMIT")
    text = data.decode("utf-8")
    original, original_checked = _fresh(text, str(path))
    core = lower_executable_core(original, original_checked)
    reference = analyze(text, str(path), native=True, rustc=rustc, crate_type="rlib")
    if (reference.report.get("ok") is not True or reference.report.get("assumptions")
            or reference.report.get("checks", {}).get("rust_borrows_types") != "rustc_checked"):
        reject("Fresh pinned Rust native reference validation required", "E_CORE_NATIVE_REFERENCE")
    decoded, checked = decode_executable_core(core, source=text, path=str(path))
    ir = emit_owned_llvm(decoded, checked)
    if path.read_bytes() != data or compiler_hash() != core["compiler_sha256"]:
        reject("Source or compiler changed before native build", "E_CORE_STALE")
    with tempfile.TemporaryDirectory(prefix=".hepta-core-", dir=destination.parent) as temporary:
        stage = Path(temporary) / ("native.so" if kind == "shared" else "native.o")
        native = compile_owned_llvm(ir, program=decoded, checked=checked, output=stage, clang=clang, kind=kind)
        artifact = stage.read_bytes()
        if (native.get("ok") is not True or native.get("artifact_sha256") != _sha(artifact)
                or native.get("llvm_ir_sha256") != ir.sha256 or not artifact):
            reject("Native artifact differs from decoded-core receipt", "E_CORE_ARTIFACT")
        if path.read_bytes() != data or compiler_hash() != core["compiler_sha256"]:
            reject("Source or compiler changed during native build", "E_CORE_STALE")
        publication = publish_verified(stage, destination, artifact)
        try:
            if path.read_bytes() != data or compiler_hash() != core["compiler_sha256"]:
                reject("Source or compiler changed after publication", "E_CORE_STALE")
            verify_published(stage, destination, artifact)
        except Exception:
            withdraw_own_link(stage, destination)
            raise
    return {"schema": "hepta.executable-core-native.v1", "ok": True,
        "status": "native_compiled_not_executed", "output": str(destination), "profile": PROFILE,
        "source": str(path), "kind": kind, "target": native["target"],
        "core_sha256": core["sha256"], "source_sha256": core["source_sha256"],
        "compiler_sha256": core["compiler_sha256"], "llvm_ir_sha256": ir.sha256,
        "artifact_sha256": publication["sha256"], "artifact_bytes": publication["bytes"],
        "reference_validation": reference.report, "native": native,
        "claims": {**CLAIMS, "native_codegen_consumes_decoded_core": True,
                   "native_rust_reference_required": True, "rust_codegen_used": False,
                   "c_codegen_used": False, "fallback_used": False}}
