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
_SITES = ("buffer", "try_buffer", "drop")
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
    functions: tuple[tuple[str, int, int, int], ...]
    schema: str = _SCHEMA
    # Only a one-block normal-return CFG has a reviewed lexical site order.
    # None means the multi-block CFG has NOT received an order proof.
    ordered_sites: tuple[tuple[str, tuple[str, ...] | None], ...] = ()

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(name for name, _, _, _ in self.functions)

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
        _, buffers, fallible_buffers, drops = matched[0]
        if (emitted["buffer"], emitted["try_buffer"], emitted["drop"]) != (buffers, fallible_buffers, drops):
            _fail(f"{name}: native acquire/drop sites differ from source-bound Resource IR")

    def require_ordered(self, name: str, sequence: tuple[str, ...]) -> bool:
        """Check emitted lexical order for a *single-block normal-return* CFG.

        False is an explicit unqualified scope, NOT an order verification:
        branches, loops, unwind and exceptional paths need a control-flow-
        sensitive operational IR. require_emitted must also be called on every
        function, including ones with multiple blocks.
        """
        if (self.schema != _SCHEMA or not _digest(self.graph_sha256)
                or not _digest(self.source_sha256)
                or self.project_sha256 is not None and not _digest(self.project_sha256)
                or type(name) is not str or _NAME.fullmatch(name) is None
                or type(sequence) is not tuple or len(sequence) > _MAX_OPS
                or any(type(op) is not str or op not in _SITES for op in sequence)
                or type(self.functions) is not tuple
                or type(self.ordered_sites) is not tuple
                or len(self.functions) != len(self.ordered_sites)
                or any(type(item) is not tuple or len(item) != 4
                       or type(item[0]) is not str for item in self.functions)
                or any(type(item) is not tuple or len(item) != 2
                       or type(item[0]) is not str
                       or item[1] is not None and type(item[1]) is not tuple
                       for item in self.ordered_sites)):
            _fail("malformed ordered owner site observation or witness")
        candidates = [expected for function, expected in self.ordered_sites
                      if function == name]
        if (len(candidates) != 1
                or tuple(function for function, *_ in self.functions)
                != tuple(function for function, _ in self.ordered_sites)):
            _fail("ordered witness lacks exact verified function inventory")
        expected = candidates[0]
        if expected is None:
            return False
        if type(expected) is not tuple or any(type(op) is not str or op not in _SITES for op in expected):
            _fail("invalid verified single-block owner sequence")
        if sequence != expected:
            _fail(f"{name}: native source-site order differs from Resource IR")
        return True


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
    ordered = []
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
        sites = {"buffer": 0, "try_buffer": 0, "drop": 0}
        site_order = []
        for block in blocks:
            if type(block) is not dict or type(block.get("ops")) is not list:
                _fail("malformed resource operation block")
            count += len(block["ops"])
            if count > _MAX_OPS:
                _fail("resource operation witness exceeds finite budget")
            for op in block["ops"]:
                if type(op) is not dict or type(op.get("op")) is not str:
                    _fail("malformed resource operation")
                if op["op"] == "acquire":
                    kind = op.get("kind")
                    if type(kind) is not str or kind not in {"buffer", "try_buffer"}:
                        _fail("unrecognized resource allocation semantics")
                    sites[kind] += 1
                    site_order.append(kind)
                elif op["op"] == "drop":
                    sites["drop"] += 1
                    site_order.append("drop")
        # The verifier has already qualified block reachability and linearity.
        # Only a single entry block with normal return is safely comparable to
        # the emitter's sequential lexical walk. This does not imply dynamic
        # execution counts or order qualification for multi-block functions.
        sole = blocks[0] if len(blocks) == 1 else None
        is_linear = (sole is not None and fn.get("entry") == sole.get("id")
                     and type(sole.get("term")) is dict
                     and sole["term"].get("op") == "return")
        ordered.append((fn["name"], tuple(site_order) if is_linear else None))
        findings.append((fn["name"], sites["buffer"], sites["try_buffer"], sites["drop"]))
    if (type(verified.get("operations_checked")) is not int
            or verified["operations_checked"] != count):
        _fail("operation coverage differs from independent verifier")
    return OwnedOperationWitness(graph_sha, graph["source_sha256"],
                                 graph["project_sha256"], tuple(findings),
                                 ordered_sites=tuple(ordered))
