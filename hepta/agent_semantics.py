"""Read-only Agent semantic inspection of one *pinned* v4 workspace version.

A previously native-checked publication is not a soundness theorem or a new
native validation. This entry point intentionally cannot publish or patch.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re

from .checker import check
from .modules import load_project
from .pipeline import compiler_hash
from .semantic_ir import _stable_json, lower_checked_program
from .workspace import WorkspaceError, inspect_workspace

_HASH = re.compile(r"[0-9a-f]{64}\Z")


def inspect_pinned_semantics(store: str | Path, *,
                             expected_version: str | None = None) -> dict:
    """Return canonical checked AST and patch node IDs bound to the SAME pin.

    The v4 reader obtains CURRENT exactly once through inspect_workspace.
    A later commit cannot rebind this report to different source files.
    """
    inspected = inspect_workspace(store)
    if inspected.get("ok") is not True:
        raise WorkspaceError("E_AGENT_PIN", "A verified workspace pin is required")
    snapshot = inspected.get("snapshot")
    if not isinstance(snapshot, dict):
        raise WorkspaceError("E_AGENT_PIN", "Malformed workspace snapshot")
    version = snapshot.get("version")
    if not isinstance(version, str) or not _HASH.fullmatch(version):
        raise WorkspaceError("E_AGENT_PIN", "Invalid published workspace identity")
    if expected_version is not None and expected_version != version:
        raise WorkspaceError("E_STALE_PROJECT", "Expected workspace version does not match published CURRENT")
    meta = snapshot.get("manifest")
    if not isinstance(meta, dict):
        raise WorkspaceError("E_AGENT_PIN", "Missing source-bound validation manifest")
    native = meta.get("validation", {})
    native_checks = native.get("checks") if isinstance(native, dict) else None
    if (meta.get("compiler_sha256") != compiler_hash()
            or not isinstance(native, dict) or native.get("ok") is not True
            or native.get("status") not in {"checked", "checked_with_external_assumptions"}
            or not isinstance(native_checks, dict)
            or native_checks.get("rust_borrows_types") != "rustc_checked"):
        raise WorkspaceError("E_AGENT_VALIDATION", "Published source lacks current-compiler Rust-qualified evidence")
    # Do not load a new mutable editor checkout or follow CURRENT a second time.
    graph = load_project(Path(snapshot["entry"]))
    if not graph.unchanged():
        raise WorkspaceError("E_AGENT_RACE", "Pinned import graph changed during semantic inspection")
    checked = check(graph.program)
    if not checked.ok:
        raise WorkspaceError("E_AGENT_CHECK", "Pinned source no longer passes the current frontend")
    hsir = lower_checked_program(graph.program, checked, project_sha256=version)
    if (hsir.get("schema") != "hepta.hsir.v0"
            or hsir.get("project_sha256") != version
            or hsir.get("all_expressions_typed") is not True
            or hsir.get("untyped_expressions")
            or not isinstance(hsir.get("sha256"), str)
            or not _HASH.fullmatch(hsir["sha256"])):
        raise WorkspaceError("E_AGENT_SEMANTICS", "Canonical HSIR lacks required checked-source identity")
    # Digest must authenticate the full canonical payload, not just be a 64-hex string.
    # Reuse the sole semantic encoder's serializer; do not create a second IR authority.
    claims = hsir.get("claims")
    prototype_claims = {"native_borrow_validation", "translation_correctness_proved",
                        "whole_language_soundness_proved", "foreign_contracts_proved"}
    if (hsir.get("profile") != "checked_typed_ast_not_verified_mir"
            or not isinstance(claims, dict) or set(claims) != prototype_claims
            or any(value is not False for value in claims.values())):
        raise WorkspaceError("E_AGENT_SEMANTICS", "Canonical HSIR profile/claims mismatch")
    try:
        payload = {k: v for k, v in hsir.items() if k != "sha256"}
        observed_digest = sha256(_stable_json(payload)).hexdigest()
    except (TypeError, ValueError) as exc:
        raise WorkspaceError("E_AGENT_SEMANTICS", "Canonical HSIR cannot be serialized") from exc
    if observed_digest != hsir["sha256"]:
        raise WorkspaceError("E_AGENT_SEMANTICS", "Canonical HSIR content checksum mismatch")
    if not graph.unchanged():
        raise WorkspaceError("E_AGENT_RACE", "Pinned import graph changed after semantic inspection")
    # A function's source path inside a v4 store includes versions/<digest>/tree.
    # Normalize against this single immutable pin, not CWD or a mutable checkout,
    # so identities remain comparable across versions and cannot escape the graph.
    snapshot_root = snapshot.get("root")
    validated = meta.get("validated_sources")
    if (not isinstance(snapshot_root, str) or not Path(snapshot_root).is_absolute()
            or not isinstance(validated, list)
            or any(not isinstance(p, str) or not p for p in validated)
            or len(validated) != len(set(validated))):
        raise WorkspaceError("E_AGENT_PATH", "Missing source-bound snapshot root/inventory")
    trusted_root = Path(snapshot_root).resolve()
    trusted_sources = set(validated)

    def source_relative_path(fn: dict) -> str:
        raw = fn.get("path")
        if not isinstance(raw, str) or not raw:
            raise WorkspaceError("E_AGENT_PATH", "Missing canonical function source path")
        source = Path(raw)
        if not source.is_absolute():
            source = trusted_root / source
        try:
            relative = source.resolve().relative_to(trusted_root).as_posix()
        except ValueError as exc:
            raise WorkspaceError("E_AGENT_PATH", "Function source escapes pinned tree") from exc
        if relative not in trusted_sources:
            raise WorkspaceError("E_AGENT_PATH", "Function is not in validated source inventory")
        return relative

    relative_paths = {id(fn): source_relative_path(fn) for fn in hsir["functions"]}
    return {
        "schema": "hepta.agent-semantics.v1",
        "status": "published_native_prevalidated_read_only",
        "ok": True,
        "workspace_version": version,
        "interface_sha256": meta.get("interface_sha256"),
        "compiler_sha256": meta["compiler_sha256"],
        "source_semantic_sha256": hsir["sha256"],
        "source_sha256": hsir["source_sha256"],
        "validated_sources": meta.get("validated_sources"),
        "nodes": inspected.get("nodes"),
        "functions": [{
            "name": fn["name"], "path": fn["path"],
            "source_relative_path": relative_paths[id(fn)],
            "declaration_span": fn["declaration_span"],
            "return_type": fn["returns"], "parameter_modes": [
                {"name": p["name"], "mode": p["mode"], "type": p["type"]} for p in fn["params"]],
            "declared_effects": fn["declared_effects"],
            "inferred_effects": fn["inferred_effects"],
            "resources": fn["resources"],
        } for fn in hsir["functions"]],
        "external_obligations": hsir.get("external_obligations", []),
        "foreign_assumptions": hsir.get("foreign_assumptions", []),
        "claims": {
            "native_validation_occurred_at_publication": True,
            "native_validation_reexecuted_this_query": False,
            "all_foreign_contracts_proved": False,
            "whole_language_soundness_proved": False,
            "functional_equivalence_proved": False,
        },
    }
