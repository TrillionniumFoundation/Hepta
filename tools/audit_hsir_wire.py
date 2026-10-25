#!/usr/bin/env python3
"""Inspect two checked HSIR v0 exports without trusting an ambiguous schema id.

The two development branches use the same hepta.hsir.v0 schema label with
incompatible wire envelopes. This tool refuses to equate them. It does not
convert programs, certify checks, or grant release/merge authorization.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SCHEMA = "hepta.hsir.v0"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
PROFILES = {
    "source_bound_dict_v0": {
        "discriminator": ("profile", "checked_typed_ast_not_verified_mir"),
        "required": ("module", "source_sha256", "project_sha256", "functions",
                     "external_obligations", "claims", "all_expressions_typed"),
        "denied_claims": ("native_borrow_validation", "translation_correctness_proved",
                          "whole_language_soundness_proved", "foreign_contracts_proved"),
    },
    "frozen_snapshot_v0": {
        "discriminator": ("status", "checked_frontend_snapshot_not_proved"),
        "required": ("program", "source_sha256", "functions", "claims",
                     "external_assumptions", "typed_expression_count"),
        "denied_claims": ("lifetimes_fully_modeled", "pointer_provenance_proved",
                          "source_semantics_refined", "native_backend_equivalence_proved"),
    },
}

class HSIRWireRejected(ValueError):
    pass


def pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise HSIRWireRejected("E_HSIR_DUPLICATE_KEY: " + key)
        result[key] = value
    return result


def load(path: str) -> dict:
    # Bounded reading avoids filling memory from malformed compiler output.
    with open(path, "rb") as stream:
        raw = stream.read(8_000_001)
    if len(raw) > 8_000_000:
        raise HSIRWireRejected("E_HSIR_TOO_LARGE")
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs_unique,
                            parse_constant=lambda x: (_ for _ in ()).throw(
                                HSIRWireRejected("E_HSIR_NONFINITE: " + x)))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise HSIRWireRejected("E_HSIR_JSON") from exc
    if not isinstance(result, dict):
        raise HSIRWireRejected("E_HSIR_NOT_OBJECT")
    return result


def unwrap(record: dict) -> tuple[dict, str]:
    """Separate CLI presentation metadata from the signed HSIR wire payload.

    PR #14 emits an hsir.export.v0 wrapper; PR #36 adds reference_validation
    to a valid HSIRSnapshot.as_dict() *after* computing its digest. Neither
    sidecar is proof of compiler validity and neither enters the payload hash.
    """
    if not isinstance(record, dict):
        raise HSIRWireRejected("E_HSIR_NOT_OBJECT")
    if record.get("schema") == "hepta.hsir.export.v0":
        if (set(record) != {"schema", "ok", "status", "hsir", "validation"}
                or type(record["ok"]) is not bool
                or not isinstance(record["status"], str)
                or not isinstance(record["validation"], dict)
                or not isinstance(record["hsir"], dict)
                or record["hsir"].get("profile") !=
                    "checked_typed_ast_not_verified_mir"):
            raise HSIRWireRejected("E_HSIR_EXPORT_ENVELOPE")
        return record["hsir"], "pr14_export_unbound_validation"
    if record.get("schema") == SCHEMA and "reference_validation" in record:
        if (not isinstance(record["reference_validation"], dict)
                or record.get("status") != "checked_frontend_snapshot_not_proved"):
            raise HSIRWireRejected("E_HSIR_SIDECAR_ENVELOPE")
        return {k: v for k, v in record.items() if k != "reference_validation"}, \
               "pr36_cli_unbound_reference_validation"
    return record, "raw_snapshot"


def fingerprint(record: dict) -> dict:
    record, envelope = unwrap(record)
    if record.get("schema") != SCHEMA:
        raise HSIRWireRejected("E_HSIR_SCHEMA")
    name, profile = None, None
    for candidate, settings in PROFILES.items():
        field, value = settings["discriminator"]
        if record.get(field) == value:
            if name is not None:
                raise HSIRWireRejected("E_HSIR_AMBIGUOUS_PROFILE")
            name, profile = candidate, settings
    if profile is None or ("profile" in record and "status" in record):
        raise HSIRWireRejected("E_HSIR_UNKNOWN_PROFILE")
    if any(key not in record for key in profile["required"]):
        raise HSIRWireRejected("E_HSIR_MISSING_FIELDS")
    if not isinstance(record.get("functions"), list):
        raise HSIRWireRejected("E_HSIR_INVALID_FUNCTIONS")
    if not isinstance(record.get("source_sha256"), str) or not SHA256.fullmatch(record["source_sha256"]):
        raise HSIRWireRejected("E_HSIR_SOURCE_ID")
    if name == "source_bound_dict_v0":
        project = record["project_sha256"]
        if project is not None and (not isinstance(project, str) or not SHA256.fullmatch(project)):
            raise HSIRWireRejected("E_HSIR_PROJECT_ID")
        if type(record["all_expressions_typed"]) is not bool:
            raise HSIRWireRejected("E_HSIR_TYPE_COMPLETENESS")
        if not isinstance(record["external_obligations"], list):
            raise HSIRWireRejected("E_HSIR_OBLIGATIONS")
    else:
        if type(record["typed_expression_count"]) is not int or record["typed_expression_count"] < 0:
            raise HSIRWireRejected("E_HSIR_TYPE_COUNT")
    claims = record.get("claims")
    if not isinstance(claims, dict) or not all(claims.get(k) is False for k in profile["denied_claims"]):
        raise HSIRWireRejected("E_HSIR_UNSUPPORTED_PROOF_CLAIM")
    if any(value is not False for value in claims.values()):
        raise HSIRWireRejected("E_HSIR_UNRECOGNIZED_PROOF_CLAIM")
    supplied = record.get("sha256")
    if not isinstance(supplied, str) or not SHA256.fullmatch(supplied):
        raise HSIRWireRejected("E_HSIR_DIGEST")
    unsigned = {k: v for k, v in record.items() if k != "sha256"}
    try:
        canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise HSIRWireRejected("E_HSIR_NOT_CANONICALIZABLE") from exc
    actual = hashlib.sha256(canonical).hexdigest()
    if supplied != actual:
        raise HSIRWireRejected("E_HSIR_DIGEST_MISMATCH")
    return {"wire_profile": name, "schema": SCHEMA,
            "presentation_envelope": envelope,
            "external_validation_metadata_unbound_to_payload": envelope != "raw_snapshot",
            "source_sha256": record["source_sha256"],
            "project_identity_present": bool(record.get("project_sha256")),
            "sha256": supplied, "checked_native": False,
            "whole_language_soundness_proved": False}


def compare(left: dict, right: dict) -> dict:
    a, b = fingerprint(left), fingerprint(right)
    collision = a["wire_profile"] != b["wire_profile"]
    return {"schema": "hepta.hsir-wire-review.v1", "left": a, "right": b,
            "same_schema_different_wire_format": collision,
            "wire_layout_status": "incompatible_requires_versioned_adapter" if collision
                                  else "same_format_only_not_semantic_equivalence",
            "safe_to_mix_without_adapter": False,
            "automatic_merge_approved": False,
            "whole_project_blockers_closed": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--left", required=True)
    parser.add_argument("--right", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        report = compare(load(args.left), load(args.right))
        with open(args.output, "x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
        print(report["wire_layout_status"])
        return 3 if report["same_schema_different_wire_format"] else 0
    except (HSIRWireRejected, OSError, ValueError, RecursionError) as exc:
        print("E_HSIR_WIRE_AUDIT: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
