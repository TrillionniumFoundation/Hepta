"""Exact native NDU evaluator identity, separate from the historical Rust oracle.

The evaluator owns JSON, numbers, Unicode diagnostics, scalar decisions, digests
and framed transport in HIA.  This adapter only captures the already-qualified
native leaf and hands immutable bytes to the existing sealed process owner.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path

UPSTREAM = "d3c2d760eca5065fc966820379c35c6e8d56e855"
SCHEMA = "hepta.hia.ndu-native-build.v1"
RESPONSE_SCHEMA = "hepta.hia.ndu-native-response.v1"
ENTRY_POINT = "hepta.hia.ndu_evaluator.v1"
REFERENCE_ENTRY_POINT = "codex_hepta_ndu::evaluate_candidates_with_policy"
BINARY_RESOURCE = "_hia_ndu_evaluator.elf"
RECEIPT_RESOURCE = "_hia_ndu_evaluator_build.json"
TEMPLATE = "docs/HIA_NATIVE_NDU_EVALUATOR_BUILD.json"
TEMPLATE_SHA256 = "9d04ec9fab8a0f0ce2d467a951793fc92a890baae8cae985ab9cbfe7476b89a2"
_SELF = Path(__file__).read_bytes()


def _template(read):
    raw = read(TEMPLATE)
    if sha256(raw).hexdigest() != TEMPLATE_SHA256:
        raise ValueError("native NDU build contract differs from its fixed source")
    value = json.loads(raw)
    if value["schema"] != SCHEMA:
        raise ValueError("native NDU build contract has an unknown schema")
    return raw, value


def default_ndu_bridge():
    """Select the two resources beside this actual imported package only."""
    from .hia_ndu_optimizer import _reject

    parent = Path(__file__).resolve().parent
    binary, receipt = parent / BINARY_RESOURCE, parent / RECEIPT_RESOURCE
    present = binary.exists(), receipt.exists()
    if present == (False, False):
        return None
    if present != (True, True):
        _reject("installed HIA NDU image and receipt must both be present")
    return {"binary": str(binary), "build_receipt": str(receipt)}


def admit_ndu_bridge(binary, receipt_raw, receipt):
    """Capture the exact eleven-file native leaf and re-read it before sealing.

    No Rust source or build receipt is admitted here.  The fixed native contract
    retains the independent algorithm reference identity without pretending the
    native binary was built by Cargo.
    """
    from .hia_json_preflight_native import _source_resource_path
    from .hia_ndu_optimizer import _VerifiedBridgeImage, _read_file, _reject

    def read(name):
        return _read_file(_source_resource_path(name), 8 << 20)

    self_path = Path(__file__)
    if _read_file(self_path, 8 << 20) != _SELF:
        _reject("native NDU admission implementation changed after import")
    try:
        template_raw, expected = _template(read)
    except ValueError as error:
        _reject(str(error))
    # Exact JSON bytes also exclude bool/int aliases, extra fields and rewritten
    # historical claims.  This is the declared fixed native receipt format.
    if (type(receipt) is not dict or type(receipt_raw) is not bytes
            or receipt_raw != template_raw or receipt != expected):
        _reject("bridge build receipt has wrong source, scope or build gates: native HIA evaluator required")
    captured = {name: read(name) for name in expected["source_files"]}
    if {name: sha256(raw).hexdigest() for name, raw in captured.items()} != expected["source_files"]:
        _reject("HIA NDU source differs from its exact native build identity")
    data = _read_file(binary, 128 << 20)
    if (len(data) != expected["binary_bytes"]
            or sha256(data).hexdigest() != expected["binary_sha256"]
            or not data.startswith(b"\x7fELF\x02\x01\x01")):
        _reject("bridge executable differs from the recorded native build")
    if (read(TEMPLATE) != template_raw
            or any(read(name) != raw for name, raw in captured.items())
            or _read_file(self_path, 8 << 20) != _SELF):
        _reject("native NDU source changed during identity admission")
    return _VerifiedBridgeImage(Path(binary), data), {
        "upstream_commit": UPSTREAM,
        "binary_sha256": expected["binary_sha256"],
        "build_receipt_sha256": sha256(receipt_raw).hexdigest(),
        "build_inputs_sha256": expected["build_inputs_sha256"],
        "source_attestation": "exact_source_owned_hia_native_evaluator",
        "implementation": "HIA",
        "response_schema": RESPONSE_SCHEMA,
        "entry_point": ENTRY_POINT,
        "reference_entry_point": REFERENCE_ENTRY_POINT,
    }
