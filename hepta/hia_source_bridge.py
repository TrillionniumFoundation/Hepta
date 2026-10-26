"""Checked Hepta scalar source -> EXISTING verified HIA Core and native compiler.

No independent SSA-to-HIA translator is maintained here. Only the canonical
Hepta source, existing Resource IR checker, HIA scalar snapshot adapter,
hepta.core.from_scalar_core and the existing HIA native backend are used.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re

from .cfg import lower_hsir_cfg
from .core import from_scalar_core
from .hia_core import seal_hia_scalar_core
from .hia_program import VerifiedProgram, verify_program
# Preserve the genuine analyzer entrypoint during this source module's import.
# Runtime substitution of the builder's public analyzer must not silently
# change the quantitative acceptance reference.
from .hia_static_budget import analyze_static_budget as _replay_static_budget
from .hsir import lower_checked_program
from .native_resource_gate import qualify_native_resource_source
from .ssa import lower_cfg_scalar_ssa
from .ssa_verify import verify_scalar_ssa

_HASH = re.compile(r"[0-9a-f]{64}\Z")


class HIAHeptaBridgeRejected(ValueError):
    """A source/identity/native qualification is outside the reviewed profile."""


def _reject(reason):
    raise HIAHeptaBridgeRejected("E_HIA_HEPTA_BRIDGE: " + reason)


def _validate_static_budget_receipt(program, limits: dict, receipt: dict) -> None:
    """Recheck existing analyzer's complete receipt before native LLVM.

    This is NOT a second numeric resource analyzer: verified immutable Core
    owns the function inventory; the existing static-budget analyzer owns
    actual upper-bound computation. A hash alone does not authorize missing
    functions, false proof types, or fabricated policy limits.
    """
    from .hia_program import verify_program

    checked = verify_program(program)
    if (not isinstance(program, VerifiedProgram)
            or checked.canonical_bytes != program.canonical_bytes):
        _reject("static budget source is not the current verified HIA Core")
    if type(limits) is not dict or not limits or any(
            type(value) is not int or value < 0 for value in limits.values()):
        _reject("static budget receipt requires typed resource policy")
    base_limits = ("max_allocator_interactions", "max_vm_ticks", "max_call_depth")
    allowed = set(base_limits) | {"max_live_heap_bytes"}
    if not set(limits) <= allowed:
        _reject("static budget policy contains unknown fields")
    expected_limits = {name: limits.get(name) for name in base_limits}
    if "max_live_heap_bytes" in limits:
        expected_limits["max_live_heap_bytes"] = limits["max_live_heap_bytes"]
    claims = {
        "finite_acyclic_cfg_and_call_graph_checked": True,
        "allocator_interactions_upper_bounded": True,
        "vm_tick_events_upper_bounded": True,
        "native_cpu_time_or_rss_proved": False,
        "full_source_to_core_refinement_proved": False,
        "whole_language_soundness_proved": False,
    }
    if "max_live_heap_bytes" in limits:
        claims["requested_live_payload_bytes_upper_bounded"] = True
    required_fields = {"schema", "status", "core_sha256", "functions",
                       "limits", "claims", "sha256"}
    if (type(receipt) is not dict or set(receipt) != required_fields
            or receipt.get("schema") != "hepta.hia.static-budget.v1"
            or receipt.get("status") !=
                "finite_structural_upper_bound_not_native_time_proof"
            or receipt.get("core_sha256") != checked.sha256
            or type(receipt.get("claims")) is not dict
            or set(receipt["claims"]) != set(claims)
            or any(receipt["claims"][key] is not val
                   for key, val in claims.items())
            or type(receipt.get("limits")) is not dict):
        _reject("static budget schema, claims or source identity mismatch")
    # JSON scalar types are part of the policy: false is not 0.
    try:
        wire = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"),
                                        allow_nan=False)
        if wire(receipt["limits"]) != wire(expected_limits):
            _reject("static budget policy differs from the explicit request")
        unsealed = {key: value for key, value in receipt.items() if key != "sha256"}
        expected_digest = sha256(wire(unsealed).encode("utf-8")).hexdigest()
        if (type(receipt["sha256"]) is not str
                or receipt["sha256"] != expected_digest):
            _reject("static budget receipt has altered bytes or self-identity")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise HIAHeptaBridgeRejected(
            "E_HIA_HEPTA_BRIDGE: invalid static budget JSON") from exc
    source_functions = checked.as_dict()["functions"]
    names = [f["name"] for f in source_functions]
    rows = receipt.get("functions")
    if (type(rows) is not list or len(rows) != len(names)
            or any(type(row) is not dict or
                   row.get("function") != name
                   for row, name in zip(rows, names))):
        _reject("static budget does not cover every canonical HIA function")
    required_row_keys = {"function", *base_limits}
    if "max_live_heap_bytes" in limits:
        required_row_keys.add("max_live_heap_bytes")
    for row in rows:
        if (set(row) != required_row_keys or
                any(type(row.get(key)) is not int or row[key] < 0
                    for key in required_row_keys - {"function"}) or
                row["max_vm_ticks"] < 1 or row["max_call_depth"] < 1):
            _reject("static budget row has missing/forged quantities")
        for key, upper in limits.items():
            if row[key] > upper:
                _reject("static budget exceeds a requested bound")

    # A well-formed, self-rehashed receipt is not evidence its resource
    # numbers were calculated from the current Core. Recompute from the
    # independently reverified immutable HIA bytes, not from receipt rows.
    # This is a deterministic replay of the ONE established analyzer, not a
    # second numeric authority or proof of the analyzer's soundness.
    try:
        canonical = _replay_static_budget(checked, **limits)
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError) as exc:
        raise HIAHeptaBridgeRejected(
            "E_HIA_HEPTA_BRIDGE: canonical resource replay rejected") from exc
    if canonical != receipt:
        _reject("static budget quantities differ from the canonical Core replay")


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
    """Authenticate old scalar SSA then reuse *the sole* HIA Core converter.

    The existing from_scalar_core replays the exact source identity, rechecks
    the old executable subset and consumes verified SSA/PHIs. A digest alone
    never authenticates untrusted source, and no general ownership proof is
    asserted by this narrow scalar-profile bridge.
    """
    if (type(project_sha256) is not str or _HASH.fullmatch(project_sha256) is None
            or getattr(checked, "ok", None) is not True):
        _reject("frontend checked source and complete project digest required")
    try:
        hsir = lower_checked_program(program, checked)
        origin = hsir.as_dict()
        gate = qualify_native_resource_source(
            program, checked, canonical_hsir_sha256=origin["source_semantic_sha256"],
            project_sha256=project_sha256)
        cfg = lower_hsir_cfg(hsir)
        ssa = lower_cfg_scalar_ssa(cfg)
        verification = verify_scalar_ssa(ssa, cfg)
        # Reuse the canonical v0 HIA scalar packer, then the existing adapter
        # to operational HIA. Neither operation grants source-refinement proof.
        sealed = seal_hia_scalar_core(hsir, cfg, ssa, verification, gate,
                                      project_sha256=project_sha256)
        executable = from_scalar_core(sealed, program=program, checked=checked,
                                      project_sha256=project_sha256,
                                      module="hia_checked_scalar")
        if not isinstance(executable, VerifiedProgram):
            _reject("existing source/Core adapter did not return verified HIA")
        # Same source replay must produce identical immutable executable bytes.
        if executable.canonical_bytes != from_scalar_core(
                sealed, program=program, checked=checked,
                project_sha256=project_sha256, module="hia_checked_scalar").canonical_bytes:
            _reject("source-bound HIA bytes changed during replay")
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
            "E_HIA_HEPTA_BRIDGE: existing canonical source/Core gates rejected") from exc


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
                or type(report.get("claims")) is not dict
                or set(report["claims"]) != set(RESOURCE_CLAIMS)
                or any(report["claims"][key] is not proof
                       for key, proof in RESOURCE_CLAIMS.items())
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
                                   locked=False, profile="scalar",
                                   static_resource_limits=None) -> dict:
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
    from .pipeline import analyze_project, compiler_hash
    from .hia_static_budget import analyze_static_budget

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
        if static_resource_limits is not None:
            if (type(static_resource_limits) is not dict
                    or not static_resource_limits
                    or not set(static_resource_limits) <= {
                        "max_allocator_interactions", "max_vm_ticks", "max_call_depth",
                        "max_live_heap_bytes"}):
                _reject("static resource policy has unknown or missing fields")
            if any(type(v) is not int or v < 0
                   for v in static_resource_limits.values()):
                _reject("static resource policy requires nonnegative integers")
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
        # The pinned Rust qualification binds *the exact Hepta compiler*.
        # Subsequent Core lowering and native publication must not silently
        # use different parser/checker/SSA/source-bridge implementations.
        compiler_identity = analyzed.report.get("compiler_sha256")
        if (type(compiler_identity) is not str
                or _HASH.fullmatch(compiler_identity) is None
                or compiler_hash() != compiler_identity):
            _reject("compiler implementation differs from Rust-qualified source")
        report["claims"]["pinned_rust_reference_validated"] = True
        if destination.resolve(strict=False) in {Path(p).resolve() for p in project.sources}:
            _reject("cannot overwrite any source project input")
        if not project.unchanged():
            _reject("source changed before Core lowering")
        derived = (lower_checked_owned_hia(
            analyzed.program, analyzed.checked, project_sha256=project.identity)
                   if profile == "owned" else lower_checked_scalar_hia(
            analyzed.program, analyzed.checked, project_sha256=project.identity))
        if compiler_hash() != compiler_identity:
            _reject("compiler changed during source-to-Core lowering")
        # Strict optional resource admission belongs *before* LLVM emission.
        # It verifies the existing immutable Core, rejects any recursive/loop
        # CFG rather than inventing a finite bound, and counts every nested
        # call and potential allocator interaction conservatively.
        # Omitted policy leaves the original HIA program profile unchanged.
        if static_resource_limits is not None:
            budget = analyze_static_budget(
                derived.program, **static_resource_limits)
            _validate_static_budget_receipt(
                derived.program, static_resource_limits, budget)
            report["static_resource_budget"] = budget
        # No other compiler path may produce the native machine code. The
        # canonical HIA Program is reverified again inside emit/compile.
        ir = emit_program_llvm(derived.program, target=target)
        if ir.core_sha256 != derived.program.sha256:
            _reject("native emitter does not consume the qualified HIA program")
        report["identities"] = {
            "project_sha256": project.identity,
            "compiler_sha256": compiler_identity,
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
        if compiler_hash() != compiler_identity:
            _reject("compiler changed before native compilation")
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
            if compiler_hash() != compiler_identity:
                _reject("compiler changed during native compilation")
            try:
                published = publish_verified(stage, destination, payload)
                if not project.unchanged():
                    _reject("source changed during artifact publication")
                observed = verify_published(stage, destination, payload)
                if compiler_hash() != compiler_identity:
                    _reject("compiler changed during native publication")
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
                                   locked=False, static_resource_limits=None) -> dict:
    """Source→verified owned Core→LLVM: no Rust/C output-code fallback."""
    return build_checked_hepta_hia_native(
        source, output, rustc=rustc, clang=clang, target=target, kind=kind,
        locked=locked, profile="owned",
        static_resource_limits=static_resource_limits)
