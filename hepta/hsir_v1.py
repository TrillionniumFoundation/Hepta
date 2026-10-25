"""Lossless, fail-closed v1 *integration envelope* for two incompatible HSIR v0 wires.

This is a typed-interface inspection and provenance boundary, NOT an independent
compiler IR or a codegen permission. In particular source-bound v0 and frozen
snapshot v0 have the same schema name but different semantics. Keep the entire
producer payload, preserve unresolved FFI assumptions, and disallow cross-wire
reinterpretation of types or expression bodies.

The producer must already have checked its AST. Hashes establish byte identity,
not correctness, signatures, native qualification or source-to-IR refinement.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

SCHEMA = "hepta.hsir.integration.v1"
LEGACY_SCHEMA = "hepta.hsir.v0"
MAX_BYTES = 32_000_000
MAX_DEPTH = 128
MAX_NODES = 200_000
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_MODES = frozenset({"value", "read", "mut", "take"})
_PROOFS = {
    "source_bound_v0": frozenset({"native_borrow_validation", "translation_correctness_proved",
                                   "whole_language_soundness_proved", "foreign_contracts_proved"}),
    "frozen_snapshot_v0": frozenset({"lifetimes_fully_modeled", "pointer_provenance_proved",
                                       "source_semantics_refined", "native_backend_equivalence_proved"}),
}


class HSIRV1Rejected(ValueError):
    """Refuse unknown, weakened, changed, untyped or unverifiable envelopes."""


def _reject(code: str) -> None:
    raise HSIRV1Rejected("E_HSIR_V1_" + code)


def _inspect_tree(root: Any) -> None:
    pending = [(root, 0)]
    nodes = 0
    # There is no type-erasing JSON default serializer. Never silently convert
    # custom AST classes to their str() representation during identity checking.
    while pending:
        obj, depth = pending.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            _reject("LIMIT")
        if isinstance(obj, dict):
            if any(not isinstance(k, str) for k in obj):
                _reject("KEY")
            pending.extend((v, depth + 1) for v in obj.values())
        elif isinstance(obj, list):
            pending.extend((v, depth + 1) for v in obj)
        elif obj is None or isinstance(obj, (str, bool, int, float)):
            if isinstance(obj, str) and len(obj) > MAX_BYTES:
                _reject("LIMIT")
        else:
            _reject("VALUE")


def _canonical(value: dict) -> bytes:
    _inspect_tree(value)
    try:
        result = json.dumps(value, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise HSIRV1Rejected("E_HSIR_V1_JSON") from exc
    if len(result) > MAX_BYTES:
        _reject("LIMIT")
    return result


def _digest(doc: dict) -> str:
    return hashlib.sha256(_canonical(doc)).hexdigest()


def _check_sha(sha: object, code: str = "SHA") -> str:
    if not isinstance(sha, str) or not _SHA.fullmatch(sha):
        _reject(code)
    return sha


def _mode(value: object) -> str:
    if not isinstance(value, str) or value not in _MODES:
        _reject("OWNERSHIP")
    return value


def _effect_set(value: object) -> list[str]:
    if (not isinstance(value, list) or
            any(not isinstance(x, str) or not x for x in value) or
            sorted(set(value)) != value):
        _reject("EFFECTS")
    return list(value)


def _foreign_claims(legacy: dict, profile: str) -> None:
    claims = legacy.get("claims")
    if not isinstance(claims, dict) or not _PROOFS[profile].issubset(claims):
        _reject("PROOF_CLAIMS")
    if any(value is not False for value in claims.values()):
        _reject("PROOF_CLAIMS")


def _producer_profile(doc: dict) -> str:
    if doc.get("schema") != LEGACY_SCHEMA:
        _reject("LEGACY_SCHEMA")
    if doc.get("profile") == "checked_typed_ast_not_verified_mir" and "status" not in doc:
        return "source_bound_v0"
    if doc.get("status") == "checked_frontend_snapshot_not_proved" and "profile" not in doc:
        return "frozen_snapshot_v0"
    _reject("LEGACY_COLLISION")


def _read_type(value: object, *, profile: str) -> dict:
    if profile == "source_bound_v0":
        if not isinstance(value, str) or not value or len(value) > 4096:
            _reject("TYPE")
        # A Rust-like spelling is not equivalent to a verified structural type.
        return {"representation": "producer_display_only", "value": value}
    if not isinstance(value, dict) or not isinstance(value.get("type"), str):
        _reject("TYPE")
    if not value["type"] or not isinstance(value.get("args"), list):
        _reject("TYPE")
    return {"representation": "producer_structural_unverified", "value": value}


def _project_functions(doc: dict, profile: str) -> list[dict]:
    source_funcs = doc.get("functions")
    if not isinstance(source_funcs, list):
        _reject("FUNCTIONS")
    functions = []
    identities = set()
    for fn in source_funcs:
        if not isinstance(fn, dict) or not isinstance(fn.get("name"), str) or not fn["name"]:
            _reject("FUNCTIONS")
        if fn["name"] in identities:
            _reject("DUPLICATE_FUNCTION")
        identities.add(fn["name"])
        fields = fn.get("params") if profile == "source_bound_v0" else fn.get("param_types")
        if not isinstance(fields, list):
            _reject("FUNCTIONS")
        params = []
        for p in fields:
            if not isinstance(p, dict) or not isinstance(p.get("name"), str) or not p["name"]:
                _reject("PARAMETER")
            params.append({"name": p["name"],
                           "ownership": _mode(p.get("mode" if profile == "source_bound_v0" else "ownership")),
                           "type": _read_type(p.get("type"), profile=profile)})
        declared = _effect_set(fn.get("declared_effects"))
        inferred = _effect_set(fn.get("inferred_effects" if profile == "source_bound_v0"
                                           else "inferred_transitive_effects"))
        return_type = _read_type(fn.get("returns" if profile == "source_bound_v0"
                                           else "return_type"), profile=profile)
        if profile == "source_bound_v0":
            if type(fn.get("extern_c")) is not bool or type(fn.get("export_c")) is not bool:
                _reject("ABI")
            if fn["extern_c"] and fn["export_c"]:
                _reject("ABI")
            direction = "extern" if fn["extern_c"] else "export" if fn["export_c"] else "local"
            abi = "C" if direction != "local" else "hepta_unstable"
            return_mode = fn.get("return_mode", "value")
            return_origin = fn.get("return_origin")
        else:
            direction = fn.get("direction")
            abi = fn.get("abi")
            if direction not in ("extern", "export", "local") or abi not in ("C", "hepta_unstable"):
                _reject("ABI")
            if (direction == "local" and abi != "hepta_unstable") or (direction != "local" and abi != "C"):
                _reject("ABI")
            # v0 lacks returned-loan origin and named lifetime fields. Expose
            # them as unknown, not as definitely absent.
            return_mode = "unknown_not_modeled"
            return_origin = "unknown_not_modeled"
        functions.append({"name": fn["name"], "parameters": params, "return_type": return_type,
                          "return_mode": return_mode, "return_origin": return_origin,
                          "declared_effects": declared, "inferred_effects": inferred,
                          "abi": abi, "direction": direction,
                          "resource_contract": fn.get("resources" if profile == "source_bound_v0"
                                                           else "resource_contract"),
                          "semantics_verified": False})
    return functions


def _validate_expression_inventory(doc: dict, profile: str) -> None:
    count = 0
    pending = list(doc.get("functions", []))
    while pending:
        node = pending.pop()
        if isinstance(node, dict):
            if node.get("node") == "expr":
                count += 1
                if profile == "source_bound_v0":
                    if not isinstance(node.get("type"), str) or not node["type"]:
                        _reject("UNTYPED_EXPRESSION")
                elif (not isinstance(node.get("result_type"), dict) or
                      not isinstance(node["result_type"].get("type"), str)):
                    _reject("UNTYPED_EXPRESSION")
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
    if profile == "source_bound_v0":
        if doc.get("all_expressions_typed") is not True or doc.get("untyped_expressions") != []:
            _reject("UNTYPED_EXPRESSION")
    else:
        if type(doc.get("typed_expression_count")) is not int or count != doc["typed_expression_count"]:
            _reject("EXPRESSION_COUNT")


def _validate_legacy(doc: dict, *, expected_source_sha256: str | None,
                     expected_project_sha256: str | None) -> tuple[str, list[dict]]:
    if not isinstance(doc, dict):
        _reject("LEGACY_TYPE")
    profile = _producer_profile(doc)
    digest = _check_sha(doc.get("sha256"), "LEGACY_SHA")
    raw = {key: value for key, value in doc.items() if key != "sha256"}
    if _digest(raw) != digest:
        _reject("LEGACY_HASH_MISMATCH")
    _foreign_claims(doc, profile)
    source_sha = _check_sha(doc.get("source_sha256"), "SOURCE_SHA")
    if expected_source_sha256 is not None and source_sha != _check_sha(expected_source_sha256):
        _reject("SOURCE_IDENTITY")
    if profile == "source_bound_v0":
        project_sha = doc.get("project_sha256")
        if project_sha is not None:
            _check_sha(project_sha, "PROJECT_SHA")
        if expected_project_sha256 is not None and project_sha != _check_sha(expected_project_sha256):
            _reject("PROJECT_IDENTITY")
        if not isinstance(doc.get("external_obligations"), list):
            _reject("EXTERNAL_OBLIGATIONS")
        if "foreign_assumptions" not in doc or "resource_contracts" not in doc:
            _reject("FOREIGN_ASSUMPTIONS")
    else:
        if expected_project_sha256 is not None:
            _reject("PROJECT_UNAVAILABLE")
        if "external_assumptions" not in doc or "resource_contracts" not in doc:
            _reject("FOREIGN_ASSUMPTIONS")
    _validate_expression_inventory(doc, profile)
    return profile, _project_functions(doc, profile)


def integrate_v0(doc: dict, *, expected_source_sha256: str | None = None,
                 expected_project_sha256: str | None = None) -> dict:
    """Create a lossless envelope and inspectable common function signature view.

    This does not grant native validation, ABI compatibility, SSA lowering or
    code generation; the complete legacy payload remains embedded and hash-bound.
    """
    profile, functions = _validate_legacy(doc, expected_source_sha256=expected_source_sha256,
                                          expected_project_sha256=expected_project_sha256)
    legacy = {key: value for key, value in doc.items()}
    result = {
        "schema": SCHEMA,
        "status": "lossless_interface_projection_not_codegen_qualified",
        "producer": {"wire_profile": profile, "legacy_schema": LEGACY_SCHEMA,
                     "legacy_sha256": doc["sha256"],
                     "source_sha256": doc["source_sha256"],
                     "project_sha256": doc.get("project_sha256")},
        "interface_projection": {"functions": functions,
                                 "type_cross_profile_equivalence_proved": False,
                                 "resource_ir_refinement_proved": False},
        "unresolved_external": {"inventory_complete": False,
                                "source_obligations": doc.get("external_obligations") if profile == "source_bound_v0" else None,
                                "foreign_assumptions": doc.get("foreign_assumptions") if profile == "source_bound_v0"
                                                       else doc.get("external_assumptions"),
                                "machine_pointer_provenance_proved": False,
                                "library_implementation_qualified": False},
        "opaque_producer_payload": legacy,
        "claims": {"whole_language_soundness_proved": False,
                   "native_validation_by_this_envelope": False,
                   "safe_codegen_without_consumer_refinement": False,
                   "source_to_ir_refinement_proved": False,
                   "foreign_contracts_proved": False},
    }
    result["sha256"] = _digest(result)
    return result


def verify_v1(doc: dict) -> dict:
    """Regenerate the projected fields from the signed producer; reject edits."""
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        _reject("SCHEMA")
    digest = _check_sha(doc.get("sha256"))
    unsigned = {key: value for key, value in doc.items() if key != "sha256"}
    if _digest(unsigned) != digest:
        _reject("HASH_MISMATCH")
    source = doc.get("opaque_producer_payload")
    if not isinstance(source, dict):
        _reject("PRODUCER")
    expected = integrate_v0(source)
    if doc != expected:
        _reject("RECONSTRUCTION_MISMATCH")
    return {"schema": "hepta.hsir.integration.verify.v1", "ok": True,
            "source_sha256": source["source_sha256"],
            "producer_sha256": source["sha256"], "envelope_sha256": digest,
            "codegen_qualified": False, "whole_language_soundness_proved": False}


def decode_json(raw: bytes) -> dict:
    """Read untrusted serialized HSIR without duplicate-key or NaN ambiguity."""
    if not isinstance(raw, bytes) or len(raw) > MAX_BYTES:
        _reject("INPUT_LIMIT")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                _reject("DUPLICATE_KEY")
            result[key] = value
        return result
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                            parse_constant=lambda _: _reject("NONFINITE"))
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, HSIRV1Rejected):
            raise
        raise HSIRV1Rejected("E_HSIR_V1_JSON") from exc
    if not isinstance(result, dict):
        _reject("INPUT_TYPE")
    _inspect_tree(result)
    return result
