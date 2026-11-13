"""Source-bound HIA *scalar* core: one executable SSA consumer, not a new compiler.

This is a deliberately narrow v0 wire envelope around the *existing* canonical
HSIR adapter, checked CFG, scalar SSA and independent Resource IR gate.  The
native pipeline must call qualified_for() with the checked source AST before
using decoded SSA as backend input. A valid digest or valid standalone SSA is
not evidence of source authenticity or a whole-language ownership proof.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re

from .cfg import CFGSnapshot, lower_hsir_cfg
from .hsir import HSIRSnapshot, lower_checked_program
from .native_resource_gate import qualify_native_resource_source
from .ssa import SSASnapshot, lower_cfg_scalar_ssa
from .ssa_verify import verify_scalar_ssa

SCHEMA = "hepta.hia.scalar-core.v0"
STATUS = "source_bound_scalar_ssa_and_resource_gate_not_refinement_proved"
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_MAX_BYTES = 8 * 1024 * 1024
_MAX_NODES = 262144
_CLAIMS = {
    "checked_scalar_cfg_ssa_embedded": True,
    "resource_ir_gate_embedded": True,
    "source_authenticity_proved_by_digest_alone": False,
    "owned_ssa_supported": False,
    "pointer_provenance_proved": False,
    "whole_language_soundness_proved": False,
    "backend_refinement_proved": False,
}
_RESOURCE_CLAIMS = {
    "exact_checked_source_resource_graph_rederived": True,
    "independent_resource_cfg_verified": True,
    "foreign_resource_obligations_absent": True,
    "source_to_resource_ir_refinement_proved": False,
    "native_codegen_consumes_resource_ir": False,
    "whole_language_memory_safety_proved": False,
}
_FIELDS = frozenset({
    "schema", "status", "canonical_hsir_sha256", "scalar_hsir_sha256",
    "source_sha256", "project_sha256", "resource_gate", "cfg_sha256",
    "ssa_sha256", "verification_sha256", "cfg", "ssa", "claims",
})


class HIACoreRejected(ValueError):
    """HIA scalar core was changed, forged, or cannot be source qualified."""


def _reject(reason: str):
    raise HIACoreRejected("E_HIA_CORE: " + reason)


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _reject("duplicate field in HIA core")
        result[key] = value
    return result


def _reject_constant(value):
    _reject("nonfinite JSON constant in HIA core")


def _bounded_json(text: str) -> dict:
    if type(text) is not str or len(text.encode("utf-8")) > _MAX_BYTES:
        _reject("HIA core must be a bounded UTF-8 JSON document")
    try:
        result = json.loads(text, object_pairs_hook=_unique_pairs,
                            parse_constant=_reject_constant)
    except (ValueError, TypeError, RecursionError, OverflowError) as exc:
        raise HIACoreRejected("E_HIA_CORE: invalid or excessively nested JSON") from exc
    if type(result) is not dict:
        _reject("HIA core root must be an object")
    pending = [(result, 0)]
    visited = 0
    while pending:
        node, depth = pending.pop()
        visited += 1
        if visited > _MAX_NODES or depth > 128:
            _reject("HIA core exceeds structural budget")
        if type(node) is dict:
            pending.extend((child, depth + 1) for child in node.values())
        elif type(node) is list:
            pending.extend((child, depth + 1) for child in node)
    try:
        if _canonical(result) != text:
            _reject("HIA core must use canonical encoding")
    except (ValueError, TypeError, RecursionError, OverflowError) as exc:
        raise HIACoreRejected("E_HIA_CORE: malformed canonical payload") from exc
    return result


def _digest(value) -> bool:
    return type(value) is str and _HASH.fullmatch(value) is not None


def _resource_matches(source: dict, project_sha256: str, gate: dict, function_count: int):
    if (type(gate) is not dict or set(gate) != {
            "schema", "status", "canonical_hsir_sha256", "resource_ir_sha256",
            "source_sha256", "project_sha256", "functions_checked", "claims"}
            or gate.get("schema") != "hepta.native.resource-gate.v1"
            or gate.get("status") != "source_bound_resource_cfg_checked_not_refinement_proof"
            or gate.get("canonical_hsir_sha256") != source.get("source_semantic_sha256")
            or gate.get("source_sha256") != source.get("source_sha256")
            or gate.get("project_sha256") != project_sha256
            or not _digest(gate.get("resource_ir_sha256"))
            or type(gate.get("functions_checked")) is not int
            or gate["functions_checked"] != function_count
            or type(gate.get("claims")) is not dict
            or set(gate["claims"]) != set(_RESOURCE_CLAIMS)
            or any(gate["claims"][key] is not val
                   for key, val in _RESOURCE_CLAIMS.items())):
        _reject("source-bound Resource IR gate mismatch or promoted claim")


@dataclass(frozen=True)
class HIAScalarCore:
    canonical_json: str
    sha256: str

    def decode(self) -> tuple[dict, CFGSnapshot, SSASnapshot, object]:
        """Structural check only. Does NOT authenticate against actual source."""
        if not _digest(self.sha256) or type(self.canonical_json) is not str:
            _reject("missing HIA core identity")
        try:
            raw = self.canonical_json.encode("utf-8")
        except UnicodeError as exc:
            raise HIACoreRejected("E_HIA_CORE: invalid UTF-8 core") from exc
        if len(raw) > _MAX_BYTES:
            _reject("HIA core exceeds byte budget")
        if sha256(raw).hexdigest() != self.sha256:
            _reject("HIA core digest differs from bytes")
        data = _bounded_json(self.canonical_json)
        if (set(data) != _FIELDS or data.get("schema") != SCHEMA
                or data.get("status") != STATUS
                or type(data.get("claims")) is not dict
                or set(data["claims"]) != set(_CLAIMS)
                or any(data["claims"][key] is not val for key, val in _CLAIMS.items())
                or any(not _digest(data.get(field)) for field in (
                    "canonical_hsir_sha256", "scalar_hsir_sha256", "source_sha256",
                    "project_sha256", "cfg_sha256", "ssa_sha256", "verification_sha256"))):
            _reject("unknown HIA schema, origin, proof scope or identity")
        if (type(data.get("cfg")) is not dict or type(data.get("ssa")) is not dict):
            _reject("missing typed CFG or SSA payload")
        try:
            cfg_json, ssa_json = _canonical(data["cfg"]), _canonical(data["ssa"])
            cfg = CFGSnapshot("hepta.cfg.v0", cfg_json, sha256(cfg_json.encode()).hexdigest())
            ssa = SSASnapshot("hepta.ssa.scalar.v0", ssa_json, sha256(ssa_json.encode()).hexdigest())
            if (cfg.sha256 != data["cfg_sha256"] or ssa.sha256 != data["ssa_sha256"]
                    or data["cfg"].get("schema") != cfg.schema
                    or data["ssa"].get("schema") != ssa.schema
                    or data["cfg"].get("source_hsir_sha256") != data["scalar_hsir_sha256"]
                    or data["cfg"].get("source_sha256") != data["source_sha256"]):
                _reject("CFG/SSA digest or source origin disagrees")
            verification = verify_scalar_ssa(ssa, cfg)
            if verification.sha256 != data["verification_sha256"]:
                _reject("independent SSA verification digest changed")
            fn = data["cfg"].get("functions")
            if type(fn) is not list:
                _reject("missing function inventory")
            source = {"source_semantic_sha256": data["canonical_hsir_sha256"],
                      "source_sha256": data["source_sha256"]}
            _resource_matches(source, data["project_sha256"],
                              data["resource_gate"], len(fn))
        except HIACoreRejected:
            raise
        except (KeyError, ValueError, TypeError, AttributeError,
                RecursionError, OverflowError) as exc:
            raise HIACoreRejected("E_HIA_CORE: malformed verified SSA graph") from exc
        return data, cfg, ssa, verification

    def qualified_for(self, program, checked, *, project_sha256: str):
        """Replay actual checked source before passing *decoded* SSA to codegen."""
        if not _digest(project_sha256) or getattr(checked, "ok", None) is not True:
            _reject("current checked source and exact project identity required")
        data, cfg, ssa, verification = self.decode()
        try:
            h = lower_checked_program(program, checked)
            source = h.as_dict()
            if (data["scalar_hsir_sha256"] != h.sha256
                    or data["canonical_hsir_sha256"] != source["source_semantic_sha256"]
                    or data["source_sha256"] != source["source_sha256"]
                    or data["project_sha256"] != project_sha256):
                _reject("stale or unrelated checked source/project")
            gate = qualify_native_resource_source(
                program, checked,
                canonical_hsir_sha256=source["source_semantic_sha256"],
                project_sha256=project_sha256)
            if _canonical(data["resource_gate"]) != _canonical(gate):
                _reject("resource gate does not replay from checked source")
            expected_cfg = lower_hsir_cfg(h)
            expected_ssa = lower_cfg_scalar_ssa(expected_cfg)
            expected_verification = verify_scalar_ssa(expected_ssa, expected_cfg)
            if (cfg != expected_cfg or ssa != expected_ssa
                    or verification != expected_verification):
                _reject("HIA executable SSA differs from canonical checked source")
        except HIACoreRejected:
            raise
        except (KeyError, ValueError, TypeError, AttributeError,
                RecursionError, OverflowError) as exc:
            raise HIACoreRejected("E_HIA_CORE: checked-source replay failed") from exc
        return ssa, cfg, verification


def seal_hia_scalar_core(hsir: HSIRSnapshot, cfg: CFGSnapshot,
                         ssa: SSASnapshot, verification,
                         resource_gate: dict, *, project_sha256: str) -> HIAScalarCore:
    """Pack existing verified IRs; no second semantic parser or lowerer."""
    if (not isinstance(hsir, HSIRSnapshot)
            or not isinstance(cfg, CFGSnapshot)
            or not isinstance(ssa, SSASnapshot)
            or not _digest(project_sha256)):
        _reject("expected canonical typed snapshots and project identity")
    try:
        source = hsir.as_dict()
        _resource_matches(source, project_sha256, resource_gate,
                          len(cfg.as_dict().get("functions", [])))
        expected_cfg = lower_hsir_cfg(hsir)
        expected_ssa = lower_cfg_scalar_ssa(expected_cfg)
        expected_verification = verify_scalar_ssa(expected_ssa, expected_cfg)
        if (cfg != expected_cfg or ssa != expected_ssa
                or verification != expected_verification):
            _reject("unrelated CFG/SSA or verification receipt")
        payload = {
            "schema": SCHEMA, "status": STATUS,
            "canonical_hsir_sha256": source["source_semantic_sha256"],
            "scalar_hsir_sha256": hsir.sha256,
            "source_sha256": source["source_sha256"],
            "project_sha256": project_sha256,
            "resource_gate": resource_gate,
            "cfg_sha256": cfg.sha256, "ssa_sha256": ssa.sha256,
            "verification_sha256": verification.sha256,
            "cfg": cfg.as_dict() | {}, "ssa": ssa.as_dict() | {},
            "claims": dict(_CLAIMS),
        }
        # Snapshot.as_dict() adds its own digest, whereas the embedded IR must
        # be exactly the self-contained canonical JSON payload, not a second
        # rehashed format that could differ across consumers.
        payload["cfg"].pop("sha256", None)
        payload["ssa"].pop("sha256", None)
        serialized = _canonical(payload)
        if len(serialized.encode("utf-8")) > _MAX_BYTES:
            _reject("HIA core exceeds 8 MiB wire budget")
        core = HIAScalarCore(serialized, sha256(serialized.encode("utf-8")).hexdigest())
        core.decode()
        return core
    except HIACoreRejected:
        raise
    except (KeyError, ValueError, TypeError, AttributeError,
            RecursionError, OverflowError) as exc:
        raise HIACoreRejected("E_HIA_CORE: cannot seal qualified scalar snapshots") from exc
