"""Compare native-prevalidated pinned Agent contracts without claiming equivalence.

This intentionally consumes hepta.agent_semantics.inspect_pinned_semantics,
not mutable editor files or an alternative semantic encoder. A stable function
signature never proves behavioral equivalence or unchanged function bodies.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path, PurePosixPath
import re
from typing import Any

from .agent_semantics import inspect_pinned_semantics
from .semantic_ir import _stable_json
from .workspace import WorkspaceError

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_TRACKED = ("return_type", "parameter_modes", "declared_effects",
            "inferred_effects", "resources",
            "public", "extern_c", "export_c", "return_mode", "return_origin",
            "return_lifetime", "parameter_lifetimes", "lifetime_params", "type_params", "type_bounds")
_CLAIM_KEYS = frozenset({
    "native_validation_occurred_at_publication",
    "native_validation_reexecuted_this_query",
    "all_foreign_contracts_proved",
    "whole_language_soundness_proved",
    "functional_equivalence_proved",
})


def _same_json_value(left: Any, right: Any) -> bool:
    """Compare complete contracts without Python's bool/int type coercion.

    Python considers False == 0 and True == 1. Native-checked contract
    metadata is serialized as JSON where those types are intentionally
    different, so never use Python collection equality for a semantic diff.
    Reject noncanonical input instead of quietly omitting a reported change.
    """
    try:
        return _stable_json(left) == _stable_json(right)
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise WorkspaceError("E_AGENT_DIFF_CONTRACT",
                             "Noncanonical typed function or foreign contract") from exc


def _inventory(report: dict[str, Any], version: str) -> dict[tuple[str, str], dict]:
    if (not isinstance(report, dict) or report.get("ok") is not True
            or report.get("schema") != "hepta.agent-semantics.v1"
            or report.get("status") != "published_native_prevalidated_read_only"
            or report.get("workspace_version") != version):
        raise WorkspaceError("E_AGENT_DIFF_PIN", "Expected a native-prevalidated pinned semantic report")
    for key in ("compiler_sha256", "source_semantic_sha256", "source_sha256",
                "source_graph_sha256", "interface_sha256"):
        digest = report.get(key)
        if not isinstance(digest, str) or _HASH.fullmatch(digest) is None:
            raise WorkspaceError("E_AGENT_DIFF_ID", "Missing or invalid bound digest: " + key)
    claims = report.get("claims")
    if (not isinstance(claims, dict) or set(claims) != _CLAIM_KEYS
            or claims.get("all_foreign_contracts_proved") is not False
            or claims.get("native_validation_occurred_at_publication") is not True
            or claims.get("native_validation_reexecuted_this_query") is not False
            or claims.get("whole_language_soundness_proved") is not False
            or claims.get("functional_equivalence_proved") is not False):
        raise WorkspaceError("E_AGENT_DIFF_CLAIMS", "Missing or elevated native evidence claims")
    if (not isinstance(report.get("functions"), list)
            or not isinstance(report.get("external_obligations"), list)
            or not isinstance(report.get("foreign_assumptions"), list)
            or not isinstance(report.get("volatile_accesses"), list)
            or not isinstance(report.get("validated_sources"), list)):
        raise WorkspaceError("E_AGENT_DIFF_INVENTORY", "Incomplete semantic inventory")
    keys = {}
    for fn in report["functions"]:
        if not isinstance(fn, dict) or any(k not in fn for k in _TRACKED):
            raise WorkspaceError("E_AGENT_DIFF_FUNCTION", "Malformed function contract")
        # Validate all compared fields even when no before/after delta exists.
        # NaN, Infinity, invalid nested objects and recursive values cannot
        # be silently treated as an unchanged native-checked contract.
        _same_json_value({key: fn[key] for key in _TRACKED}, {})
        path, name = fn.get("path"), fn.get("name")
        if (not isinstance(path, str) or not path or not isinstance(name, str) or not name
                or PurePosixPath(path).is_absolute() or "\\" in path
                or any(part in ("", ".", "..") for part in path.split("/"))
                or path not in report["validated_sources"]):
            raise WorkspaceError("E_AGENT_DIFF_FUNCTION", "Missing or unvalidated relative function origin")
        key = (path, name)
        if key in keys:
            raise WorkspaceError("E_AGENT_DIFF_DUPLICATE", "Duplicate path/function identity")
        keys[key] = fn
    return keys


def compare_pinned_contracts(
    before_store: str | Path,
    after_store: str | Path,
    *,
    expected_before_version: str,
    expected_after_version: str,
) -> dict[str, Any]:
    """Conservatively report machine-readable *contract* changes in two pins.

    Both version hashes are required to avoid drifting silently with CURRENT.
    Reads are independent. Each read validates a single pinned workspace via
    the existing native-evidence and canonical frontend inspection path.
    """
    for version in (expected_before_version, expected_after_version):
        if not isinstance(version, str) or _HASH.fullmatch(version) is None:
            raise WorkspaceError("E_AGENT_DIFF_VERSION", "Both exact version digests are required")
    before = inspect_pinned_semantics(before_store, expected_version=expected_before_version)
    after = inspect_pinned_semantics(after_store, expected_version=expected_after_version)
    old = _inventory(before, expected_before_version)
    new = _inventory(after, expected_after_version)
    if before["compiler_sha256"] != after["compiler_sha256"]:
        raise WorkspaceError("E_AGENT_DIFF_COMPILER", "Snapshots were validated by different compiler identities")

    changes = []
    for path, name in sorted(set(old) | set(new)):
        previous, current = old.get((path, name)), new.get((path, name))
        if previous is None:
            changes.append({"path": path, "name": name, "change": "added", "changed_fields": list(_TRACKED)})
        elif current is None:
            changes.append({"path": path, "name": name, "change": "removed", "changed_fields": list(_TRACKED)})
        else:
            fields = [field for field in _TRACKED
                      if not _same_json_value(previous[field], current[field])]
            if fields:
                changes.append({"path": path, "name": name,
                                "change": "contract_modified", "changed_fields": fields})

    result = {
        "schema": "hepta.agent-contract-diff.v1",
        "status": "read_only_contract_diff_not_equivalence",
        "before_version": expected_before_version,
        "after_version": expected_after_version,
        "compiler_sha256": before["compiler_sha256"],
        "before_semantic_sha256": before["source_semantic_sha256"],
        "after_semantic_sha256": after["source_semantic_sha256"],
        "before_source_sha256": before["source_sha256"],
        "after_source_sha256": after["source_sha256"],
        "before_graph_sha256": before["source_graph_sha256"],
        "after_graph_sha256": after["source_graph_sha256"],
        # An imported module can change while the entry's source SHA stays
        # unchanged. The loader's full source graph + import-edge digest is
        # the only meaningful cross-workspace source-change comparator.
        "source_identity_changed": before["source_graph_sha256"] != after["source_graph_sha256"],
        "entry_source_changed": before["source_sha256"] != after["source_sha256"],
        "before_interface_sha256": before["interface_sha256"],
        "after_interface_sha256": after["interface_sha256"],
        "interface_identity_changed": before["interface_sha256"] != after["interface_sha256"],
        "validated_source_set_changed": not _same_json_value(
            before["validated_sources"], after["validated_sources"]),
        "external_obligations_changed": not _same_json_value(
            before["external_obligations"], after["external_obligations"]),
        "foreign_assumptions_changed": not _same_json_value(
            before["foreign_assumptions"], after["foreign_assumptions"]),
        "volatile_accesses_changed": not _same_json_value(
            before["volatile_accesses"], after["volatile_accesses"]),
        "reported_contract_changes": changes,
        "claims": {
            "both_snapshots_prevalidated_at_publication": True,
            "native_validation_reexecuted_during_comparison": False,
            "function_bodies_compared": False,
            "functional_equivalence_proved": False,
            "whole_language_soundness_proved": False,
            "cross_snapshot_external_obligations_discharged": False,
        },
    }
    result["sha256"] = sha256(_stable_json(result)).hexdigest()
    return result
