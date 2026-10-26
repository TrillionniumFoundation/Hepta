"""Finite Owner acquire/drop emission-site witness for the existing LLVM backend.

The independent Resource IR verifier retains ownership/loan authority.
This consumes its checked graph to require the LLVM emitter to produce the
same *static number of allocation and explicit-drop call sites*. It is not
a dynamic execution count, executable owner SSA, or backend refinement proof.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re

_SCHEMA = "hepta.owned-operation-witness.v1"
_GRAPH_SCHEMA = "hepta.resource-ir.v3"
_CLAIMS = frozenset({
    "source_to_ir_refinement_proved", "native_codegen_uses_this_ir",
    "whole_language_soundness_proved", "external_contracts_proved",
    "termination_proved", "scalar_value_semantics_verified",
})
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_SITES = ("acquire", "drop")
_MAX_FUNCTIONS = 256
_MAX_BLOCKS = 4096
_MAX_OPS = 100000


class OwnedOperationWitnessRejected(ValueError):
    """Source-qualified native emitter and Resource IR disagree."""


def _fail(reason: str):
    raise OwnedOperationWitnessRejected("E_OWNED_OPERATION_WITNESS: " + reason)


def _digest(value) -> bool:
    return type(value) is str and _HASH.fullmatch(value) is not None


@dataclass(frozen=True)
class OwnedOperationWitness:
    """Immutable source/graph identity and per-function source site counts."""

    graph_sha256: str
    source_sha256: str
    project_sha256: str | None
    functions: tuple[tuple[str, int, int], ...]
    schema: str = _SCHEMA

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(name for name, _, _ in self.functions)

    def require_emitted(self, name: str, emitted: dict) -> None:
        """Reject mismatch before any LLVM source or native bytes are returned."""
        if (self.schema != _SCHEMA or not _digest(self.graph_sha256)
                or not _digest(self.source_sha256)
                or self.project_sha256 is not None and not _digest(self.project_sha256)
                or type(name) is not str or _NAME.fullmatch(name) is None
                or type(emitted) is not dict or set(emitted) != set(_SITES)
                or any(type(emitted[op]) is not int or emitted[op] < 0
                       for op in _SITES)):
            _fail("malformed witness or emission observations")
        matched = [item for item in self.functions if item[0] == name]
        if len(matched) != 1:
            _fail("LLVM function is absent or duplicated in verified Resource IR")
        _, allocations, drops = matched[0]
        if (emitted["acquire"], emitted["drop"]) != (allocations, drops):
            _fail(f"{name}: native acquire/drop sites differ from source-bound Resource IR")


def derive_owned_operation_witness(graph: dict, verified: dict) -> OwnedOperationWitness:
    """Bind static resource sites to an already independently verified graph.

    Caller must have just derived graph from checked source. No receipt or hash
    authenticates arbitrary input by itself. The existing verifier, not this
    narrowly scoped site consumer, checks legal moves, drops, borrows and CFG.
    """
    if (type(graph) is not dict or type(verified) is not dict
            or graph.get("schema") != _GRAPH_SCHEMA
            or graph.get("value_semantics") != "copied_values_abstract_not_executable"
            or not _digest(graph.get("source_sha256"))
            or graph.get("project_sha256") is not None
            and not _digest(graph.get("project_sha256"))
            or graph.get("obligations") != {}
            or type(graph.get("claims")) is not dict
            or set(graph["claims"]) != _CLAIMS
            or any(graph["claims"][key] is not False for key in _CLAIMS)):
        _fail("unqualified or unrecognized source Resource IR")
    try:
        encoded = json.dumps(graph, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError, OverflowError) as exc:
        raise OwnedOperationWitnessRejected(
            "E_OWNED_OPERATION_WITNESS: invalid graph bytes") from exc
    graph_sha = sha256(encoded).hexdigest()
    if (len(encoded) > 16 * 1024 * 1024 or verified.get("ok") is not True
            or verified.get("status") != "resource_cfg_verified"
            or verified.get("ir_sha256") != graph_sha
            or verified.get("external_obligations") != {}
            or type(verified.get("claims")) is not dict
            or set(verified["claims"]) != _CLAIMS
            or any(verified["claims"][key] is not False for key in _CLAIMS)):
        _fail("independent Resource IR result/identity or proof claims mismatch")
    functions = graph.get("functions")
    reports = verified.get("functions")
    if (type(functions) is not list or not 1 <= len(functions) <= _MAX_FUNCTIONS
            or type(reports) is not list or len(reports) != len(functions)):
        _fail("missing verified function inventory")
    findings = []
    count = 0
    seen = set()
    for fn, report in zip(functions, reports):
        if (type(fn) is not dict or type(report) is not dict
                or type(fn.get("name")) is not str
                or _NAME.fullmatch(fn["name"]) is None
                or fn["name"] in seen or fn.get("external") is not False
                or report.get("function") != fn["name"]):
            _fail("resource function identity or verification order invalid")
        seen.add(fn["name"])
        blocks = fn.get("blocks")
        if (type(blocks) is not list or not 1 <= len(blocks) <= _MAX_BLOCKS
                or type(report.get("total_blocks")) is not int
                or type(report.get("reachable_blocks")) is not int
                or report["total_blocks"] != len(blocks)
                or report["reachable_blocks"] != len(blocks)):
            _fail("missing or unverified resource CFG blocks")
        sites = {"acquire": 0, "drop": 0}
        for block in blocks:
            if type(block) is not dict or type(block.get("ops")) is not list:
                _fail("malformed resource operation block")
            count += len(block["ops"])
            if count > _MAX_OPS:
                _fail("resource operation witness exceeds finite budget")
            for op in block["ops"]:
                if type(op) is not dict or type(op.get("op")) is not str:
                    _fail("malformed resource operation")
                if op["op"] in sites:
                    sites[op["op"]] += 1
        findings.append((fn["name"], sites["acquire"], sites["drop"]))
    if (type(verified.get("operations_checked")) is not int
            or verified["operations_checked"] != count):
        _fail("operation coverage differs from independent verifier")
    return OwnedOperationWitness(graph_sha, graph["source_sha256"],
                                 graph["project_sha256"], tuple(findings))
