"""Bind native explicit Drop calls to verified source-derived Resource IR operations.

This is not a second ownership verifier or an executable owner SSA. It consumes
only a graph already checked by hepta.resource_ir.verify_resource_ir and a
matching, independently derived verification receipt. Actual source origin is
established by the caller's existing checked-source replay, never by a hash.

The finite backend contract covers static Drop sites of non-generic functions.
Generic specialization and complete owned operation sequencing remain open.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from hashlib import sha256
import json

from .resource_ir import _CLAIMS as RESOURCE_CLAIMS


class DropSiteRejected(ValueError):
    """A native Drop site is absent from the verified Resource IR inventory."""


def _fail(detail: str) -> None:
    raise DropSiteRejected("E_DROP_SITE: " + detail)


def _canonical(document: dict) -> bytes:
    try:
        return json.dumps(document, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise DropSiteRejected("E_DROP_SITE: invalid resource graph bytes") from exc


@dataclass(frozen=True)
class VerifiedDropSites:
    resource_ir_sha256: str
    # function name -> immutable sorted (owned-type key, static callsite count)
    functions: tuple[tuple[str, tuple[tuple[str, int], ...]], ...]

    def for_function(self, name: str) -> dict[str, int]:
        if type(name) is not str:
            _fail("invalid function name")
        for function, sites in self.functions:
            if function == name:
                return dict(sites)
        _fail("native function missing from verified Resource IR: " + name)


def qualify_drop_sites(graph: dict, verified: dict) -> VerifiedDropSites:
    """Extract *static* explicit Drop callsites from a previously verified CFG.

    This adapter is neither a standalone trust boundary nor a proof that native
    Drop semantics refine the source. The native caller must rederive graph and
    verification from the same checked source AST and match exact digests.
    """
    if type(graph) is not dict or type(verified) is not dict:
        _fail("verified graph and receipt required")
    if set(graph) != {"schema", "source_sha256", "project_sha256", "value_semantics",
                      "types", "functions", "obligations", "claims"}:
        _fail("unrecognized Resource IR envelope")
    digest = sha256(_canonical(graph)).hexdigest()
    if (verified.get("ok") is not True or verified.get("status") != "resource_cfg_verified"
            or verified.get("ir_sha256") != digest
            or verified.get("external_obligations") != {}
            or type(verified.get("claims")) is not dict
            or set(verified["claims"]) != set(RESOURCE_CLAIMS)
            or any(verified["claims"][key] is not val
                   for key, val in RESOURCE_CLAIMS.items())):
        _fail("unqualified Resource IR digest, external assumptions or proof claims")
    if graph.get("obligations") != {} or graph.get("claims") != RESOURCE_CLAIMS or any(
            type(value) is not bool for value in graph["claims"].values()):
        _fail("graph introduces unresolved obligations or false proof claims")
    types, functions, reports = graph.get("types"), graph.get("functions"), verified.get("functions")
    if (type(types) is not dict or type(functions) is not list
            or type(reports) is not list or len(functions) > 512):
        _fail("missing or unbounded type/function inventory")
    compiled = []
    names = set()
    for function in functions:
        if type(function) is not dict or type(function.get("name")) is not str:
            _fail("malformed function entry")
        name = function["name"]
        if name in names:
            _fail("duplicate function name")
        names.add(name)
        if function.get("external") is True:
            continue
        params, locals_, blocks = (function.get(key) for key in ("params", "locals", "blocks"))
        if (type(params) is not list or type(locals_) is not list or type(blocks) is not list
                or len(params) + len(locals_) > 16384 or len(blocks) > 4096):
            _fail("invalid native function resource shape")
        slots: dict[str, str] = {}
        for item in [*params, *locals_]:
            if (type(item) is not dict or type(item.get("id")) is not str
                    or type(item.get("type")) is not str or item["type"] not in types
                    or item["id"] in slots):
                _fail("inconsistent resource slot identity or type")
            slots[item["id"]] = item["type"]
        calls: Counter[str] = Counter()
        for block in blocks:
            if type(block) is not dict or type(block.get("ops")) is not list:
                _fail("invalid resource control-flow block")
            for op in block["ops"]:
                if type(op) is not dict:
                    _fail("malformed resource operation")
                if op.get("op") == "drop":
                    if (set(op) != {"op", "src"} or type(op.get("src")) is not str
                            or op["src"] not in slots):
                        _fail("Drop does not consume a typed verified slot")
                    calls[slots[op["src"]]] += 1
                    if sum(calls.values()) > 16384:
                        _fail("static Drop site budget exceeded")
        compiled.append((name, tuple(sorted(calls.items()))))
    observed = []
    for report in reports:
        if type(report) is not dict or type(report.get("function")) is not str:
            _fail("invalid independently verified function inventory")
        observed.append(report["function"])
    if len(set(observed)) != len(observed) or sorted(observed) != sorted(k for k, _ in compiled):
        _fail("source function inventory differs from Resource IR verification")
    return VerifiedDropSites(digest, tuple(sorted(compiled)))
