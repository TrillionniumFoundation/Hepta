"""Fail-closed checked Hepta scalar SSA -> executable standalone HIA Program.

Reuses the sole canonical Hepta HSIR, Resource IR, CFG, scalar SSA, SSA
verifier and HIA Core verifier. This is a finite i32/u32 exported profile,
not a general owned/lifetime translator or formal source refinement proof.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re

from .cfg import lower_hsir_cfg
from .hia_program import VerifiedProgram, verify_program
from .hsir import lower_checked_program
from .native_resource_gate import qualify_native_resource_source
from .ssa import lower_cfg_scalar_ssa
from .ssa_verify import verify_scalar_ssa

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_WORDS = frozenset({"i32", "u32"})
_VALUE_TYPES = _WORDS | {"bool"}
_BINARY = {"+": "int.add.checked", "-": "int.sub.checked",
           "*": "int.mul.checked", "/": "int.div.checked",
           "%": "int.rem.checked", "<<": "int.shl.checked",
           ">>": "int.shr.checked", "&": "bit.and", "|": "bit.or",
           "^": "bit.xor", "==": "compare.eq", "!=": "compare.ne",
           "<": "compare.lt", "<=": "compare.le", ">": "compare.gt",
           ">=": "compare.ge"}
_MAX_BLOCKS = 512
_MAX_VALUES = 8192


class HIAHeptaBridgeRejected(ValueError):
    """Unsupported scalar semantics or inconsistent verified-source SSA."""


def _reject(message):
    raise HIAHeptaBridgeRejected("E_HIA_HEPTA_BRIDGE: " + message)


def _t(value):
    if (type(value) is not dict or set(value) != {"type", "args", "length"}
            or value["args"] != [] or value["length"] is not None
            or type(value["type"]) is not str or value["type"] not in _VALUE_TYPES):
        _reject("only i32/u32 and internal Boolean values are supported")
    return value["type"]


def _refs(expr):
    if type(expr) is not dict or expr.get("node") != "expr":
        _reject("invalid typed expression")
    pending, refs, steps = [expr], set(), 0
    while pending:
        node = pending.pop()
        steps += 1
        if steps > _MAX_VALUES or type(node) is not dict or node.get("node") != "expr":
            _reject("expression exceeds checked scalar budget")
        if node.get("operation") == "name":
            name = node.get("ssa_ref")
            if type(name) is not str:
                _reject("name does not carry a verified SSA reference")
            refs.add(name)
        args = node.get("operands")
        if type(args) is not list or len(args) > 3:
            _reject("unreviewed expression operands")
        pending.extend(args)
    return refs


def _output(definition):
    if type(definition) is not dict or type(definition.get("ssa_name")) is not str:
        _reject("invalid SSA definition")
    return definition["ssa_name"], _t({"type": definition["type"], "args": [], "length": None})


def _analysis(function):
    blocks = function["blocks"]
    if type(blocks) is not list or not 1 <= len(blocks) <= _MAX_BLOCKS:
        _reject("invalid source SSA block count")
    by_id = {b["id"]: b for b in blocks}
    if len(by_id) != len(blocks):
        _reject("duplicate SSA block identity")
    names, defs, uses, outgoing, phi_edges = {}, {}, {}, {}, {}
    entry = function["entry"]
    for block in blocks:
        bid = block["id"]
        initial = function["parameters"] if bid == entry else []
        local = {}
        for definition in initial + [phi["result"] for phi in block["phis"]]:
            name, ty = _output(definition)
            if name in local or name in names:
                _reject("duplicate source SSA definition")
            local[name] = ty
            names[name] = ty
        seen, need = set(local), set()
        for inst in block["instructions"]:
            for name in _refs(inst["ssa_value"]):
                if name not in seen:
                    need.add(name)
            if "definition" in inst:
                name, ty = _output(inst["definition"])
                if name in local or name in names:
                    _reject("duplicate source SSA result")
                local[name] = ty
                names[name] = ty
                seen.add(name)
        term = block["terminator"]
        kind = term["kind"]
        if kind == "goto":
            targets = [term["target"]]
        elif kind == "branch":
            targets = [term["then"], term["else"]]
            for name in _refs(term["condition"]):
                if name not in seen:
                    need.add(name)
        elif kind == "return":
            targets = []
            if term.get("value") is not None:
                for name in _refs(term["value"]):
                    if name not in seen:
                        need.add(name)
        else:
            _reject("range, switch, fallthrough and unchecked exception edges are unsupported")
        if any(t not in by_id for t in targets):
            _reject("SSA has a missing CFG successor")
        defs[bid], uses[bid], outgoing[bid] = set(local), need, targets
        for successor in set(targets):
            for phi in by_id[successor]["phis"]:
                matching = [x["ssa_ref"] for x in phi["incoming"] if x["from"] == bid]
                if len(matching) != 1:
                    _reject("missing or ambiguous edge-specific phi input")
                phi_edges.setdefault((bid, successor), set()).add(matching[0])
    # Validate all SSA references independently of their location. The existing
    # structural SSA verifier checks dominance/edge value legality separately.
    for required in list(uses.values()) + list(phi_edges.values()):
        if not required.issubset(names):
            _reject("SSA reference has no typed definition")
    live = {bid: set() for bid in by_id}
    for _ in range(_MAX_VALUES + 1):
        changed = False
        for bid in reversed([b["id"] for b in blocks]):
            out = set()
            for successor in outgoing[bid]:
                out |= live[successor] | phi_edges.get((bid, successor), set())
            incoming = uses[bid] | (out - defs[bid])
            if incoming != live[bid]:
                live[bid] = incoming
                changed = True
        if not changed:
            break
    else:
        _reject("SSA liveness failed to reach a bounded fixed point")
    if live[entry]:
        _reject("entry must not require undeclared external SSA values")
    return names, live


class _Emit:
    def __init__(self, bid, environment):
        self.bid, self.env, self.ops, self.serial = bid, dict(environment), [], 0

    def instruction(self, opcode, arguments, result_type, attrs=None):
        self.serial += 1
        if self.serial > _MAX_VALUES:
            _reject("excessive HIA instruction expansion")
        name = f"v_{self.bid}_{self.serial}"
        self.ops.append({"op": opcode, "args": list(arguments),
                         "out": [{"name": name, "type": result_type}],
                         "attrs": {} if attrs is None else attrs})
        return name

    def expression(self, expr, depth=0):
        if depth > 48 or type(expr) is not dict or expr.get("node") != "expr":
            _reject("unsupported/deep source expression")
        typ = _t(expr.get("result_type"))
        op = expr.get("operation")
        parts = expr.get("operands")
        if type(parts) is not list:
            _reject("source expression missing operands")
        if op == "name" and not parts:
            ref = expr.get("ssa_ref")
            if ref not in self.env:
                _reject("source value not available in current CFG block")
            return self.env[ref]
        if op in {"int", "bool"} and not parts:
            value = expr.get("value")
            if (op == "int" and (type(value) is not int or typ not in _WORDS)
                    or op == "bool" and (type(value) is not bool or typ != "bool")):
                _reject("invalid typed integer/boolean source constant")
            return self.instruction("const", [], typ, {"value": value})
        if op == "binary" and len(parts) == 2:
            opcode = _BINARY.get(expr.get("value"))
            if opcode is None:
                # && and || are short-circuit operators: eager lowering would
                # incorrectly execute RHS traps. Do not silently translate.
                _reject("binary expression has unqualified lowering (including short-circuit)")
            left = self.expression(parts[0], depth + 1)
            right = self.expression(parts[1], depth + 1)
            return self.instruction(opcode, [left, right], typ)
        if op == "unary" and len(parts) == 1:
            src = _t(parts[0].get("result_type"))
            opcode = ("int.neg.checked" if expr.get("value") == "-" and src in _WORDS
                      else "bool.not" if expr.get("value") == "!" and src == "bool"
                      else "bit.not" if expr.get("value") == "!" and src in _WORDS
                      else None)
            if opcode is None:
                _reject("unqualified source unary operation")
            return self.instruction(opcode, [self.expression(parts[0], depth + 1)], typ)
        if op == "cast" and len(parts) == 1:
            src = _t(parts[0].get("result_type"))
            if src not in _WORDS or typ not in _WORDS:
                _reject("Boolean/float casts are outside the bridge")
            return self.instruction("int.cast", [self.expression(parts[0], depth + 1)],
                                    typ, {"mode": "wrap"})
        _reject("unmapped scalar source expression")


def _function(ssa, original):
    if (ssa["name"] != original["name"] or original.get("direction") != "export"
            or original.get("abi") != "C" or _t(original["return_type"]) not in _WORDS):
        _reject("only source-exported C ABI i32/u32 functions are qualified")
    params = original["param_types"]
    if (len(params) != len(ssa["parameters"]) or len(params) > 16
            or any(p["ownership"] != "value" or _t(p["type"]) not in _WORDS for p in params)):
        _reject("only 0..16 by-value i32/u32 parameters are qualified")
    word = _t(original["return_type"])
    if any(_t(p["type"]) != word for p in params):
        _reject("mixed-sign/width source ABI not qualified in first bridge")
    if set(original["declared_effects"]) - {"panic"} or set(original["inferred_transitive_effects"]) - {"panic"}:
        _reject("unsupported source effects")
    names, live = _analysis(ssa)
    blocks = {b["id"]: b for b in ssa["blocks"]}
    block_params, incoming_order = {}, {}
    for bid, block in blocks.items():
        needed = [] if bid == ssa["entry"] else sorted(live[bid])
        phi = [] if bid == ssa["entry"] else sorted((p["result"]["ssa_name"] for p in block["phis"]))
        ordered = [p["ssa_name"] for p in ssa["parameters"]] if bid == ssa["entry"] else needed + phi
        if len(set(ordered)) != len(ordered):
            _reject("SSA phi and forwarded block argument collide")
        if any(ref not in names for ref in ordered):
            _reject("block arguments are not typed by SSA")
        block_params[bid] = [{"name": f"p_{bid}_{i}", "type": names[ref]}
                             for i, ref in enumerate(ordered)]
        incoming_order[bid] = ordered
    output = []
    for bid, block in blocks.items():
        emit = _Emit(bid, {ref: p["name"] for ref, p in zip(incoming_order[bid], block_params[bid])})
        for instruction in block["instructions"]:
            result = emit.expression(instruction["ssa_value"])
            if "definition" in instruction:
                name, typ = _output(instruction["definition"])
                if _t(instruction["ssa_value"]["result_type"]) != typ:
                    _reject("SSA definition and expression types differ")
                emit.env[name] = result
        def edge(target):
            args = []
            for ref in incoming_order[target]:
                if ref not in emit.env:
                    # A phi argument uses its edge-specific incoming value,
                    # not the target's SSA phi-result name.
                    matched = [x["ssa_ref"] for p in blocks[target]["phis"]
                               if p["result"]["ssa_name"] == ref
                               for x in p["incoming"] if x["from"] == bid]
                    if len(matched) != 1 or matched[0] not in emit.env:
                        _reject("SSA edge lacks a live required value")
                    args.append(emit.env[matched[0]])
                else:
                    # No SSA phi definition at a target is in scope on its
                    # predecessor. Check this even for loop/back edges.
                    if any(p["result"]["ssa_name"] == ref for p in blocks[target]["phis"]):
                        matched = [x["ssa_ref"] for p in blocks[target]["phis"]
                                   if p["result"]["ssa_name"] == ref
                                   for x in p["incoming"] if x["from"] == bid]
                        if len(matched) != 1 or matched[0] not in emit.env:
                            _reject("predecessor cannot provide required phi source")
                        args.append(emit.env[matched[0]])
                    else:
                        args.append(emit.env[ref])
            return {"target": target, "args": args}
        term = block["terminator"]
        if term["kind"] == "goto":
            target = term["target"]
            new_term = {"op": "jump", **edge(target)}
        elif term["kind"] == "branch":
            condition = emit.expression(term["condition"])
            new_term = {"op": "branch", "cond": condition,
                        "then": edge(term["then"]), "else": edge(term["else"])}
        elif term["kind"] == "return":
            if term.get("value") is None:
                _reject("Unit returns are not in the first source bridge")
            result = emit.expression(term["value"])
            new_term = {"op": "ret", "values": [result]}
        else:
            _reject("unsupported source control flow")
        output.append({"id": bid, "params": block_params[bid],
                       "ops": emit.ops, "term": new_term})
    return {"name": ssa["name"], "params": block_params[ssa["entry"]],
            "returns": [word],
            "effects": ["trap"] if "panic" in original["declared_effects"] else [],
            "entry": ssa["entry"], "blocks": output}


@dataclass(frozen=True)
class CheckedScalarHIA:
    program: VerifiedProgram
    source_semantic_sha256: str
    project_sha256: str
    resource_ir_sha256: str
    scalar_ssa_sha256: str
    ssa_verification_sha256: str
    claims: dict


def lower_checked_scalar_hia(program, checked, *, project_sha256: str) -> CheckedScalarHIA:
    """Lower the exact frontend-checked scalar subset into executable HIA Core.

    A supplied digest or externally constructed SSA cannot bypass Hepta's
    canonical source lowering or Resource IR validation. This is a bounded
    translation, not a formal proof of arbitrary source equivalence.
    """
    if (type(project_sha256) is not str or _HASH.fullmatch(project_sha256) is None
            or getattr(checked, "ok", None) is not True):
        _reject("frontend-qualified source and full project identity required")
    try:
        hsir = lower_checked_program(program, checked)
        origin = hsir.as_dict()
        gate = qualify_native_resource_source(
            program, checked, canonical_hsir_sha256=origin["source_semantic_sha256"],
            project_sha256=project_sha256)
        cfg = lower_hsir_cfg(hsir)
        ssa = lower_cfg_scalar_ssa(cfg)
        verification = verify_scalar_ssa(ssa, cfg)
        source_cfg, source_ssa = cfg.as_dict(), ssa.as_dict()
        if (source_cfg.get("source_hsir_sha256") != hsir.sha256
                or source_ssa.get("source_cfg_sha256") != cfg.sha256
                or source_ssa.get("functions") is None
                or len(source_ssa["functions"]) != len(source_cfg["functions"])):
            _reject("canonical CFG/SSA source linkage disagrees")
        lowered = [_function(fn, orig) for fn, orig in zip(
            source_ssa["functions"], source_cfg["functions"])]
        executable = verify_program({"schema": "hepta.hia.program.v1",
                                     "module": "hia_checked_scalar",
                                     "functions": lowered})
        # Rebuild independently from source-owned snapshots; never trust
        # output mutable dictionaries or a self-resealed claimed identity.
        repeated = [_function(fn, orig) for fn, orig in zip(
            ssa.as_dict()["functions"], cfg.as_dict()["functions"])]
        if verify_program({"schema": "hepta.hia.program.v1", "module": "hia_checked_scalar",
                           "functions": repeated}).canonical_bytes != executable.canonical_bytes:
            _reject("HIA output changed during source replay")
        return CheckedScalarHIA(
            program=executable, source_semantic_sha256=origin["source_semantic_sha256"],
            project_sha256=project_sha256, resource_ir_sha256=gate["resource_ir_sha256"],
            scalar_ssa_sha256=ssa.sha256, ssa_verification_sha256=verification.sha256,
            claims={"canonical_checked_source_used": True,
                    "source_bound_resource_ir_checked": True,
                    "independent_scalar_ssa_verified": True,
                    "native_codegen_consumes_hia_core": False,
                    "source_to_core_semantic_refinement_proved": False,
                    "whole_language_soundness_proved": False})
    except HIAHeptaBridgeRejected:
        raise
    except (KeyError, ValueError, TypeError, AttributeError, OverflowError, RecursionError) as exc:
        raise HIAHeptaBridgeRejected(
            "E_HIA_HEPTA_BRIDGE: unsupported or malformed checked scalar source") from exc



@dataclass(frozen=True)
class CheckedOwnedHIA:
    """Source-bound executable owner Core; not a compiler refinement proof."""

    program: VerifiedProgram
    source_semantic_sha256: str
    project_sha256: str
    resource_ir_sha256: str
    claims: dict


def lower_checked_owned_hia(program, checked, *, project_sha256: str) -> CheckedOwnedHIA:
    """Replay the existing typed owner source, abstract Resource IR and HIA Core.

    This is a narrow *adapter*, not another compiler or checker. Resource IR
    abstracts scalar values; native LLVM uses independently verified executable
    HIA bytes, never the non-executable Resource IR as numerical authority.
    """
    from .semantic_ir import lower_checked_program as canonical_checked_source
    from .resource_lowering import lower_resource_ir
    from .resource_ir import verify_resource_ir, _CLAIMS as RESOURCE_CLAIMS
    from .hia_program_source import lower_program
    from .hia_program import SCHEMA

    if (type(project_sha256) is not str or _HASH.fullmatch(project_sha256) is None
            or getattr(checked, "ok", None) is not True):
        _reject("verified frontend and exact owner project identity required")
    try:
        origin = canonical_checked_source(program, checked, project_sha256=project_sha256)
        if (origin.get("schema") != "hepta.hsir.v0"
                or origin.get("profile") != "checked_typed_ast_not_verified_mir"
                or origin.get("project_sha256") != project_sha256
                or origin.get("all_expressions_typed") is not True
                or origin.get("untyped_expressions") != []
                or origin.get("external_obligations") != []
                or origin.get("foreign_assumptions") != []
                or origin.get("volatile_accesses") != []
                or type(origin.get("source_sha256")) is not str
                or _HASH.fullmatch(origin["source_sha256"]) is None):
            _reject("unsafe, foreign, volatile or untyped source is unsupported")
        graph = lower_resource_ir(program, checked, project_sha256=project_sha256)
        if (type(graph) is not dict
                or graph.get("schema") not in {
                    "hepta.resource-ir.v3", "hepta.resource-ir.v4", "hepta.resource-ir.v5"}
                or graph.get("source_sha256") != origin["source_sha256"]
                or graph.get("project_sha256") != project_sha256
                or graph.get("obligations") != {}
                or graph.get("claims") != RESOURCE_CLAIMS
                or any(type(v) is not bool or v is not False
                       for v in graph["claims"].values())):
            _reject("source-bound owner graph has unsupported obligations")
        # Independently recheck a detached wire-equivalent graph: neither the
        # lowering pass nor its earlier check is a trusted proof receipt.
        detached = json.loads(json.dumps(
            graph, sort_keys=True, separators=(",", ":"), allow_nan=False))
        report = verify_resource_ir(detached)
        resource_sha = sha256(json.dumps(
            graph, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()).hexdigest()
        expected = sorted(fn.name for fn in program.functions if not fn.extern_c)
        inventory = report.get("functions") if type(report) is dict else None
        if (type(report) is not dict or report.get("ok") is not True
                or report.get("status") != "resource_cfg_verified"
                or report.get("ir_sha256") != resource_sha
                or report.get("claims") != RESOURCE_CLAIMS
                or report.get("external_obligations") != {}
                or type(inventory) is not list
                or len(inventory) != len(expected)
                or any(type(row) is not dict or type(row.get("function")) is not str
                       for row in inventory)
                or sorted(row["function"] for row in inventory) != expected):
            _reject("owner Resource IR independent graph verification disagrees")
        executable = lower_program(program, checked)
        checked_core = verify_program(executable)
        if (executable.canonical_bytes != checked_core.canonical_bytes
                or checked_core.as_dict().get("schema") != SCHEMA):
            _reject("owner source did not produce a verified executable Core v1")
        # Replay lowering; source identity or a mutable claimed IR hash alone
        # is insufficient to authorize execution or machine-code publication.
        if lower_program(program, checked).canonical_bytes != checked_core.canonical_bytes:
            _reject("owned source replay produced inconsistent executable HIA")
        return CheckedOwnedHIA(
            program=checked_core, source_semantic_sha256=origin["sha256"],
            project_sha256=project_sha256, resource_ir_sha256=resource_sha,
            claims={"checked_source_bound": True,
                    "independent_resource_cfg_verified": True,
                    "independent_executable_owned_core_verified": True,
                    "native_codegen_consumes_hia_core": False,
                    "source_to_core_semantic_refinement_proved": False,
                    "general_memory_provenance_proved": False,
                    "foreign_ownership_contracts_proved": False,
                    "whole_language_soundness_proved": False})
    except HIAHeptaBridgeRejected:
        raise
    except (KeyError, ValueError, TypeError, AttributeError, UnicodeError,
            OverflowError, RecursionError) as exc:
        raise HIAHeptaBridgeRejected(
            "E_HIA_HEPTA_BRIDGE: unsupported/unqualified owner source") from exc


def build_checked_hepta_hia_native(source, output, *, rustc=None, clang="clang",
                                   target="x86_64-unknown-linux-gnu", kind="shared",
                                   locked=False, profile="scalar") -> dict:
    """Build actual verified Core using the existing native HIA LLVM emitter.

    Mandatory *real* pinned Rust validation precedes source-to-HIA conversion;
    the source graph is checked before/after codegen and atomic publication.
    No automatic Rust/C fallback and no proof of compiler refinement.
    """
    from pathlib import Path
    import os
    import tempfile

    from .artifact_publication import (PublicationRejected, publish_verified,
                                       verify_published, withdraw_own_link)
    from .hia_program_llvm import (TARGET, TARGET_AARCH64, _read_artifact,
                                   compile_program_llvm, emit_program_llvm)
    from .pipeline import analyze_project

    report = {"schema": "hepta.build-checked-hia-source.v1", "ok": False,
              "status": "rejected", "source": str(source), "output": str(output),
              "target": target,
              "claims": {"pinned_rust_reference_validated": False,
                         "source_bound_resource_ir_checked": False,
                         "native_codegen_consumed_verified_hia_core": False,
                         "native_executed": False,
                         "source_to_core_refinement_proved": False,
                         "whole_language_soundness_proved": False}}
    try:
        if type(profile) is not str or profile not in {"scalar", "owned"}:
            _reject("unknown checked-source Core profile")
        if profile == "owned":
            report["schema"] = "hepta.build-checked-hia-owned-source.v1"
            report["source_profile"] = "verified-byte-owner-core-v1"
        if target not in {TARGET, TARGET_AARCH64} or (target == TARGET_AARCH64 and kind != "object"):
            _reject("unsupported HIA source target/kind")
        if kind not in {"object", "shared"}:
            _reject("unsupported HIA native artifact kind")
        destination = Path(os.path.abspath(output))
        if (destination.exists() or destination.is_symlink() or not destination.parent.is_dir()
                or destination.parent.resolve() != destination.parent):
            _reject("source-native output must be a new regular file in an existing unaliased directory")
        analyzed = analyze_project(Path(source), backend="rust", rustc=rustc,
                                   native=True, crate_type="rlib", locked=locked)
        report["rust_reference"] = analyzed.report
        if (analyzed.report.get("ok") is not True
                or analyzed.report.get("checks", {}).get("rust_borrows_types") != "rustc_checked"
                or analyzed.program is None or analyzed.checked is None or analyzed.project is None):
            _reject("pinned Rust reference must actually validate checked source")
        project = analyzed.project
        report["claims"]["pinned_rust_reference_validated"] = True
        if destination.resolve(strict=False) in {Path(p).resolve() for p in project.sources}:
            _reject("cannot overwrite any source project input")
        if not project.unchanged():
            _reject("source changed before Core lowering")
        derived = (lower_checked_owned_hia(
            analyzed.program, analyzed.checked, project_sha256=project.identity)
                   if profile == "owned" else lower_checked_scalar_hia(
            analyzed.program, analyzed.checked, project_sha256=project.identity))
        # No other compiler path may produce the native machine code. The
        # canonical HIA Program is reverified again inside emit/compile.
        ir = emit_program_llvm(derived.program, target=target)
        if ir.core_sha256 != derived.program.sha256:
            _reject("native emitter does not consume the qualified HIA program")
        report["identities"] = {
            "project_sha256": project.identity,
            "source_semantic_sha256": derived.source_semantic_sha256,
            "resource_ir_sha256": derived.resource_ir_sha256,
            "hia_program_sha256": derived.program.sha256,
            "llvm_ir_sha256": ir.sha256,
        }
        if profile == "scalar":
            report["identities"]["scalar_ssa_sha256"] = derived.scalar_ssa_sha256
            report["identities"]["ssa_verification_sha256"] = derived.ssa_verification_sha256
        else:
            report["identities"]["executable_owner_core_schema"] = "hepta.hia.program.v1"
            report["identities"]["resource_value_semantics"] = "abstract_not_executable"
        report["claims"]["source_bound_resource_ir_checked"] = True
        if not project.unchanged():
            _reject("source changed before native compilation")
        with tempfile.TemporaryDirectory(prefix=".hia-source-", dir=destination.parent) as folder:
            stage = Path(folder) / ("native.so" if kind == "shared" else "native.o")
            native = compile_program_llvm(ir, program=derived.program, output=stage,
                                          clang=clang, kind=kind)
            payload = _read_artifact(stage)
            if (native.get("status") != "native_compiled_not_executed"
                    or native.get("core_sha256") != derived.program.sha256
                    or native.get("llvm_ir_sha256") != ir.sha256
                    or native.get("target") != target or native.get("kind") != kind
                    or type(native.get("artifact_bytes")) is not int
                    or native["artifact_bytes"] != len(payload)
                    or native.get("artifact_sha256") != sha256(payload).hexdigest()
                    or type(native.get("claims")) is not dict
                    or native["claims"].get("backend_refinement_proved") is not False
                    or native["claims"].get("native_execution_qualified") is not False):
                _reject("staged native bytes/receipt disagree with HIA source")
            if not project.unchanged():
                _reject("source changed during native compilation")
            try:
                published = publish_verified(stage, destination, payload)
                if not project.unchanged():
                    _reject("source changed during artifact publication")
                observed = verify_published(stage, destination, payload)
                if published != observed:
                    _reject("final source artifact identity differs")
            except Exception:
                withdraw_own_link(stage, destination)
                raise
        report["native_backend"] = native
        report["publication"] = published
        report["claims"]["native_codegen_consumed_verified_hia_core"] = True
        report.update(ok=True, status="native_compiled_not_executed")
    except (ValueError, OSError, UnicodeError, RecursionError) as exc:
        report["diagnostics"] = [{"code": str(exc).split(":", 1)[0] if str(exc).startswith("E_")
                                 else "E_HIA_HEPTA_NATIVE", "message": str(exc)}]
    return report


def build_checked_owned_hia_native(source, output, *, rustc=None, clang="clang",
                                   target="x86_64-unknown-linux-gnu", kind="shared",
                                   locked=False) -> dict:
    """Source→verified owned Core→LLVM: no Rust/C output-code fallback."""
    return build_checked_hepta_hia_native(
        source, output, rustc=rustc, clang=clang, target=target, kind=kind,
        locked=locked, profile="owned")
