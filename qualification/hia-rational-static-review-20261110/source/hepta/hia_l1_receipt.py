"""Strict trust-boundary validation of existing C/C++ L1 migrator receipts.

A frontend migration receipt is metadata, *never* an equivalence proof or an
authorization to execute code. Unknown versions/fields must be reviewed rather
than silently admitted into a source-checked HIA native publication pipeline.
"""
from __future__ import annotations

import re


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_C_FIELDS = frozenset({
    "schema", "ok", "status", "profile", "source", "output", "source_sha256",
    "output_sha256", "source_equivalence_proved", "whole_language_soundness_proved",
    "native_validation", "converted", "rejected", "target_model",
    "preprocessed_sha256", "frontend",
})
_CPP_FIELDS = frozenset({
    "schema", "ok", "status", "tier", "profile", "source", "output",
    "source_sha256", "output_sha256", "converted", "rejected", "target_model",
    "cpp_abi_preserved", "behavioral_equivalence_proved",
    "whole_language_memory_safety_proved", "foreign_cpp_memory_safe",
    "native_validation", "differential_validation",
})
_CPP_PROFILE = "cpp20-noexcept-i32-free-functions-canonical-c-scalar-l1"


class HIAL1ReceiptRejected(ValueError):
    """Unqualified C/C++ migrator receipt; native build must not be invoked."""


def _reject(reason: str) -> None:
    raise HIAL1ReceiptRejected("E_HIA_L1_RECEIPT: " + reason)


def _sha(value: object) -> bool:
    return type(value) is str and _SHA256.fullmatch(value) is not None


def validate_migration_receipt(report: object, *, language: str,
                               source: str, output: str,
                               source_sha256: str, output_sha256: str) -> None:
    """Validate exactly the known successful L1 output schema (returns None).

    Authenticity ultimately depends on independently reading the generated
    source bytes, the live original file and native compiler/toolchain receipts.
    This is a closed shape, safety-claim and origin guard, not attestation.
    """
    if language not in {"c", "cpp"} or type(report) is not dict:
        _reject("unsupported language or non-object migrator response")
    expected = _C_FIELDS if language == "c" else _CPP_FIELDS
    if set(report) != expected:
        _reject("missing or unexpected L1 migrator receipt fields")
    if (report["schema"] != ("hepta.migrate-c.v0" if language == "c" else "hepta.migrate-cpp-l1.v0")
            or report["status"] != "frontend_checked_not_native_qualified"
            or report["ok"] is not True
            or report["native_validation"] != "not_run"
            or type(report["source"]) is not str or report["source"] != source
            or type(report["output"]) is not str or report["output"] != output
            or not _sha(source_sha256) or not _sha(output_sha256)
            or report["source_sha256"] != source_sha256
            or report["output_sha256"] != output_sha256
            or type(report["converted"]) is not list or not report["converted"]
            or type(report["rejected"]) is not list or report["rejected"]
            or type(report["target_model"]) is not dict or not report["target_model"]):
        _reject("invalid success, source identities or qualified declaration inventory")
    seen = set()
    for item in report["converted"]:
        if (type(item) is not dict or type(item.get("name")) is not str
                or not item["name"] or item["name"] in seen):
            _reject("ambiguous or missing converted declaration identity")
        seen.add(item["name"])
    if language == "c":
        if (report["profile"] != "strict_scalar_pilot"
                or report["source_equivalence_proved"] is not False
                or report["whole_language_soundness_proved"] is not False
                or report["frontend"] != "passed"
                or not _sha(report["preprocessed_sha256"])):
            _reject("C translation claims unsupported equivalence or scope")
    else:
        if (report["tier"] != "L1" or report["profile"] != _CPP_PROFILE
                or report["cpp_abi_preserved"] is not False
                or report["behavioral_equivalence_proved"] is not False
                or report["whole_language_memory_safety_proved"] is not False
                or report["foreign_cpp_memory_safe"] is not False
                or report["differential_validation"] != "not_run"):
            _reject("C++ translation claims unsupported ABI, safety or differential qualification")
