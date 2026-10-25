"""Compare native-prevalidated pinned Agent contracts without claiming equivalence.

This intentionally consumes hepta.agent_semantics.inspect_pinned_semantics,
not mutable editor files or an alternative semantic encoder. A stable function
signature never proves behavioral equivalence or unchanged function bodies.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re
from typing import Any

from .agent_semantics import inspect_pinned_semantics
from .semantic_ir import _stable_json
from .workspace import WorkspaceError

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_TRACKED = ("return_type", "parameter_modes", "declared_effects",
            "inferred_effects", "resources")


def _inventory(report: dict[str, Any], version: str) -> dict[tuple[str, str], dict]:
    if (not isinstance(report, dict) or report.get("ok") is not True
            or report.get("schema") != "hepta.agent-semantics.v1"
            or report.get("status") != "published_native_prevalidated_read_only"
            or report.get("workspace_version") != version):
        raise WorkspaceError("E_AGENT_DIFF_PIN", "Expected a native-prevalidated pinned semantic report")
    for key in ("compiler_sha256", "source_semantic_sha256", "interface_sha256"):
        digest = report.get(key)
        if not isinstance(digest, str) or _HASH.fullmatch(digest) is None:
            raise WorkspaceError("E_AGENT_DIFF_ID", "Missing or invalid bound digest: " + key)
    claims = report.get("claims")
    if (not isinstance(claims, dict)
            or claims.get("native_validation_occurred_at_publication") is not True
            or claims.get("native_validation_reexecuted_this_query") is not False
            or claims.get("whole_language_soundness_proved") is not False
            or claims.get("functional_equivalence_proved") is not False):
        raise WorkspaceError("E_AGENT_DIFF_CLAIMS", "Missing or elevated native evidence claims")
    if (not isinstance(report.get("functions"), list)
            or not isinstance(report.get("external_obligations"), list)
            or not isinstance(report.get("foreign_assumptions"), list)
            or not isinstance(report.get("validated_sources"), list)):
        raise WorkspaceError("E_AGENT_DIFF_INVENTORY", "Incomplete semantic inventory")
    source_paths = report["validated_sources"]
    if (any(not isinstance(p, str) or not p or
            Path(p).is_absolute() or Path(p).as_posix() != p or
            any(part in {".", ".."} for part in p.split("/"))
            for p in source_paths)
            or len(source_paths) != len(set(source_paths))):
        raise WorkspaceError("E_AGENT_DIFF_INVENTORY", "Invalid relative source inventory")
    keys = {}
    for fn in report["functions"]:
        if not isinstance(fn, dict) or any(k not in fn for k in _TRACKED):
            raise WorkspaceError("E_AGENT_DIFF_FUNCTION", "Malformed function contract")
        # The original path can be an absolute location inside a versioned tree,
        # so it is deliberately NOT used as a cross-snapshot symbol identity.
        path, name = fn.get("source_relative_path"), fn.get("name")
        if (not isinstance(path, str) or path not in source_paths
                or not isinstance(fn.get("path"), str) or not fn["path"]
                or not isinstance(name, str) or not name):
            raise WorkspaceError("E_AGENT_DIFF_FUNCTION", "Missing pinned relative function origin")
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
            fields = [field for field in _TRACKED if previous[field] != current[field]]
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
        "before_interface_sha256": before["interface_sha256"],
        "after_interface_sha256": after["interface_sha256"],
        "interface_identity_changed": before["interface_sha256"] != after["interface_sha256"],
        "validated_source_set_changed": before["validated_sources"] != after["validated_sources"],
        "external_obligations_changed": before["external_obligations"] != after["external_obligations"],
        "foreign_assumptions_changed": before["foreign_assumptions"] != after["foreign_assumptions"],
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
