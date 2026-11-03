#!/usr/bin/env python3
"""Independent experimental Core checker for deferred, immutable input guards.

This is an executable structural check and a fresh invocation of the existing
reduction proofs, not a whole-language theorem or an admission path. It never
imports the experimental proposer/planner or invokes a compiler. Accepted Core
is related to the existing entry-selected reference by a conditional stuttering
argument; VM steps, quotas, timeouts and native behavior are outside that claim.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from hepta.hia_program import SCALARS, _decode, verify_program
from hepta.hia_optimization import DEFAULT_POLICY, _digest, _policy
from hepta.hia_reduction import (_freeze_pipeline, _verify_frozen,
                                 reduction_checker_identity)

SCHEMA = "hepta.hia.experimental-deferred-guard.v1"
REPORT_SCHEMA = "hepta.hia.experimental-deferred-guard-check.v1"
MAX_SOURCE_BLOCKS = 128


def deferred_guard_checker_identity():
    """Bind this implementation and the complete existing proof/checker closure."""
    digest = sha256(reduction_checker_identity().encode("ascii"))
    source = Path(__file__)
    digest.update(source.name.encode("ascii") + b"\0" + source.read_bytes())
    return digest.hexdigest()


def _require(condition, message):
    if not condition:
        raise ValueError("E_DEFERRED_GUARD: " + message)


def _fields(value, fields, where):
    _require(type(value) is dict and set(value) == set(fields),
             where + ": exact fields required")


def _edges(block):
    term = block["term"]
    if term["op"] == "jump":
        return [("jump", {"target": term["target"], "args": term["args"]})]
    if term["op"] == "branch":
        return [(side, term[side]) for side in ("then", "else")]
    _require(term["op"] in {"ret", "trap"}, "unsupported terminator")
    return []


def _derive_regions(slow, fast, guard):
    """Derive the entire cut set from actual verified block bodies, independently."""
    _require({k: v for k, v in slow.items() if k != "blocks"}
             == {k: v for k, v in fast.items() if k != "blocks"},
             "fast/slow function interfaces differ")
    _require(all(p["type"] in SCALARS for p in slow["params"])
             and all(t in SCALARS for t in slow["returns"]),
             "selected function requires scalar parameters and returns")
    _require(1 <= len(slow["blocks"]) <= MAX_SOURCE_BLOCKS
             and 1 <= len(fast["blocks"]) <= MAX_SOURCE_BLOCKS,
             "first profile supports at most 128 source blocks")
    _require(not any(op["op"] == "call" for fn in (slow, fast)
                     for block in fn["blocks"] for op in block["ops"]),
             "calls and recursion are outside the first profile")
    _fields(guard, {"function", "argument", "maximum"}, "guard")
    _require(guard["function"] == slow["name"]
             and any(p == {"name": guard["argument"], "type": "usize"}
                     for p in slow["params"])
             and type(guard["maximum"]) is int
             and 0 <= guard["maximum"] < 2**64,
             "guard must be original immutable usize input <= constant")
    left = {block["id"]: block for block in slow["blocks"]}
    right = {block["id"]: block for block in fast["blocks"]}
    _require(len(left) == len(slow["blocks"]) and len(right) == len(fast["blocks"])
             and set(left) == set(right), "full duplicate-free source inventory required")
    for name, block in left.items():
        _require(block["params"] == right[name]["params"]
                 and block["term"] == right[name]["term"],
                 "fast/slow ordered block parameters or terminators differ")
        _require(all(edge["target"] in left for _, edge in _edges(block)),
                 "source successor inventory is not closed")
    different = {name for name in left if left[name] != right[name]}
    _require(bool(different), "no actual block differences")
    _require(slow["entry"] not in different, "entry-divergent inputs are unsupported")

    shared, cut, pending = set(), set(), [slow["entry"]]
    while pending:
        name = pending.pop()
        if name in shared:
            continue
        _require(name not in different, "internal shared-region inconsistency")
        shared.add(name)
        for side, edge in _edges(left[name]):
            target = edge["target"]
            if target in different:
                cut.add((name, side, target))
            else:
                pending.append(target)
    _require(bool(cut), "no reachable first-divergence frontier")
    suffix, pending = set(), [edge[2] for edge in cut]
    while pending:
        name = pending.pop()
        if name in suffix:
            continue
        suffix.add(name)
        pending.extend(edge["target"] for _, edge in _edges(left[name]))
    _require(different <= suffix and shared | suffix == set(left),
             "derived regions do not cover all source blocks")
    return left, right, shared, cut, suffix, different


def _layout_map(rows, expected, actual, where):
    _require(type(rows) is list and len(rows) == len(expected), where + ": wrong inventory length")
    result = {}
    for row in rows:
        _fields(row, {"source_block", "candidate_block"}, where)
        source, target = row["source_block"], row["candidate_block"]
        _require(type(source) is str and type(target) is str
                 and source in expected and source not in result and target in actual,
                 where + ": invalid, duplicate or unknown mapping")
        result[source] = target
    _require(set(result) == expected, where + ": incomplete source inventory")
    return result


def _definition_map(source, candidate, *, hidden_snapshot):
    """Reconstruct names from ordered definitions; never consume a claimed map."""
    count = len(source["params"])
    _require(len(candidate["params"]) == count + int(hidden_snapshot),
             "wrong original/snapshot parameter arity")
    if hidden_snapshot:
        _require(candidate["params"][-1]["type"] == "usize", "snapshot must be scalar usize")
    _require(len(source["ops"]) == len(candidate["ops"]), "operation count changed")
    pairs = list(zip(source["params"], candidate["params"][:count]))
    for left, right in zip(source["ops"], candidate["ops"]):
        _require(len(left["out"]) == len(right["out"]), "output definition arity changed")
        pairs.extend(zip(left["out"], right["out"]))
    names, inverse = {}, set()
    for left, right in pairs:
        _require(left["type"] == right["type"] and left["name"] not in names
                 and right["name"] not in inverse, "non-bijective or type-changing alpha map")
        names[left["name"]] = right["name"]
        inverse.add(right["name"])
    if hidden_snapshot:
        _require(candidate["params"][-1]["name"] not in inverse,
                 "snapshot aliases an original definition")
    for left, right in zip(source["ops"], candidate["ops"]):
        expected = {"op": left["op"], "args": [names[a] for a in left["args"]],
                    "out": [{"name": names[o["name"]], "type": o["type"]} for o in left["out"]],
                    "attrs": left["attrs"]}
        _require(right == expected, "actual ordered operation, operand, attribute or effect changed")
    return names


def _check_term(source, candidate, names, route):
    term = source["term"]
    if term["op"] == "ret":
        expected = {"op": "ret", "values": [names[a] for a in term["values"]]}
    elif term["op"] == "trap":
        expected = dict(term)
    elif term["op"] == "jump":
        expected = {"op": "jump", **route("jump", term, names)}
    else:
        expected = {"op": "branch", "cond": names[term["cond"]],
                    **{side: route(side, term[side], names) for side in ("then", "else")}}
    _require(candidate["term"] == expected,
             "actual terminator, target, phi operand order or snapshot propagation changed")


def _check_structure(narrowed, fast, candidate, guarded, layout):
    _fields(layout, {"function", "shared", "fast", "slow", "guards"}, "layout")
    _require(len(guarded["guards"]) == 1, "exactly one guarded function required")
    guard = guarded["guards"][0]
    _require(layout["function"] == guard["function"], "layout selects wrong function")
    slow_data, fast_data, data = narrowed.as_dict(), fast.as_dict(), candidate.as_dict()
    _require({k: v for k, v in data.items() if k != "functions"}
             == {k: v for k, v in slow_data.items() if k != "functions"},
             "module interface changed")
    _require(len(data["functions"]) == len(slow_data["functions"]), "function inventory changed")
    selected = None
    for slow_fn, fast_fn, fn in zip(slow_data["functions"], fast_data["functions"], data["functions"]):
        if slow_fn["name"] != guard["function"]:
            _require(fn == slow_fn == fast_fn, "unselected function changed")
            continue
        _require({k: v for k, v in fn.items() if k not in {"blocks", "entry"}}
                 == {k: v for k, v in slow_fn.items() if k not in {"blocks", "entry"}},
                 "selected function public interface changed")
        selected = (slow_fn, fast_fn, fn)
    _require(selected is not None, "guarded function absent")
    slow_fn, fast_fn, fn = selected
    left, right, shared, cut, suffix, different = _derive_regions(slow_fn, fast_fn, guard)
    blocks = {block["id"]: block for block in fn["blocks"]}
    shared_map = _layout_map(layout["shared"], shared, blocks, "shared")
    fast_map = _layout_map(layout["fast"], suffix, blocks, "fast")
    slow_map = _layout_map(layout["slow"], suffix, blocks, "slow")
    _require(type(layout["guards"]) is list and len(layout["guards"]) == len(cut),
             "guard inventory does not cover the complete cut set")
    guards = {}
    for row in layout["guards"]:
        _fields(row, {"source_block", "edge", "target_block", "candidate_block"}, "frontier guard")
        _require(all(type(value) is str for value in row.values()), "guard layout must contain names")
        key = (row["source_block"], row["edge"], row["target_block"])
        _require(key in cut and key not in guards and row["candidate_block"] in blocks,
                 "unknown or duplicate frontier edge")
        guards[key] = row["candidate_block"]
    inventory = [*shared_map.values(), *fast_map.values(), *slow_map.values(), *guards.values()]
    _require(len(inventory) == len(set(inventory)) and set(inventory) == set(blocks),
             "every actual candidate block must be accounted for exactly once")
    _require(fn["entry"] == shared_map[slow_fn["entry"]], "candidate entry is not original shared entry")

    for name in sorted(shared):
        original, block = left[name], blocks[shared_map[name]]
        entry = name == slow_fn["entry"]
        _require(not entry or block["params"] == slow_fn["params"], "entry input names changed")
        names = _definition_map(original, block, hidden_snapshot=not entry)
        snapshot = guard["argument"] if entry else block["params"][-1]["name"]
        def shared_route(side, edge, alpha):
            target = edge["target"]
            destination = guards[(name, side, target)] if target in different else shared_map[target]
            return {"target": destination, "args": [alpha[a] for a in edge["args"]] + [snapshot]}
        _check_term(original, block, names, shared_route)

    for source_blocks, mapping in ((left, slow_map), (right, fast_map)):
        for name in sorted(suffix):
            original, block = source_blocks[name], blocks[mapping[name]]
            names = _definition_map(original, block, hidden_snapshot=False)
            def selected_route(_side, edge, alpha):
                _require(edge["target"] in mapping, "selected suffix is not successor-closed")
                return {"target": mapping[edge["target"]],
                        "args": [alpha[a] for a in edge["args"]]}
            _check_term(original, block, names, selected_route)

    for (_, _, target), ident in guards.items():
        block, original_params = blocks[ident], left[target]["params"]
        _require(len(block["params"]) == len(original_params) + 1
                 and [p["type"] for p in block["params"]]
                 == [p["type"] for p in original_params] + ["usize"],
                 "frontier guard must preserve ordered target parameters and snapshot")
        _require(len(block["ops"]) == 2, "guard must contain only const and compare.le")
        constant, compare = block["ops"]
        _require(len(constant["out"]) == 1 and len(compare["out"]) == 1,
                 "guard output arity changed")
        limit, condition = constant["out"][0]["name"], compare["out"][0]["name"]
        _require(constant == {"op": "const", "args": [], "out": [{"name": limit, "type": "usize"}],
                              "attrs": {"value": guard["maximum"]}}, "wrong guard constant or unsigned type")
        _require(compare == {"op": "compare.le", "args": [block["params"][-1]["name"], limit],
                             "out": [{"name": condition, "type": "bool"}], "attrs": {}},
                 "guard must compare the immutable snapshot with unsigned <=")
        args = [p["name"] for p in block["params"][:-1]]
        _require(block["term"] == {"op": "branch", "cond": condition,
                 "then": {"target": fast_map[target], "args": args},
                 "else": {"target": slow_map[target], "args": args}},
                 "guard side, target or original parameter routing changed")
    return {"function": slow_fn["name"], "different": sorted(different),
            "shared": sorted(shared), "cut_set": [list(x) for x in sorted(cut)],
            "suffix": sorted(suffix), "source_blocks": len(left), "candidate_blocks": len(blocks),
            "complete_operation_equality_modulo_alpha": True,
            "every_phi_operand_checked": True, "immutable_original_input_snapshot_checked": True,
            "selected_namespaces_successor_closed": True, "core_verifier_rerun": True}


def check_deferred_guard(base, proposal, policy=None):
    """Return checked/rejected/unknown, always DENY_ALL and never native authority.

    A previous report is not an input or proof token. Every call freezes the
    complete bounded proposal, checks actual Core and reruns both scalar and
    inductive reduction proofs. A checked status does not establish VM quota,
    backend, performance or whole-language equivalence.
    """
    started = time.monotonic_ns()
    report = {"schema": REPORT_SCHEMA, "status": "unknown", "authority": "DENY_ALL",
              "native_admission": False, "production_admission": False,
              "performance_qualified": False, "vm_steps_preserved": False,
              "quota_equivalence": False,
              "candidate_guard_placement": "first-divergence frontier after unchanged shared prefix",
              "reduction_proof_scope": "entry-selected reference only; candidate structure checked separately",
              "claims": {"actual_core_structure_checked": False,
                         "fresh_reduction_proofs_checked": False,
                         "whole_language_soundness_proved": False,
                         "backend_refinement_proved": False,
                         "conditional_stuttering_simulation_only": True},
              "limitations": ["experimental executable checker, not a machine-checked language theorem",
                              "entry-divergent and no-difference candidates are unsupported",
                              "one scalar-interface, call-free guarded function; at most 128 source blocks",
                              "instruction counts, VM quotas, fuel and timeouts are not equivalent",
                              "no native compilation, admission or performance qualification"]}
    def finish(status, reason):
        report.update(status=status, reason=reason, elapsed_ns=time.monotonic_ns() - started)
        report["verification_sha256"] = _digest(report)
        return report
    try:
        identity = deferred_guard_checker_identity()
        report["checker_sha256"] = identity
        # Core's exact-built-in, depth/node/byte-bounded decoder creates a
        # detached JSON tree. Never continue reading the caller-owned proposal.
        _require(type(proposal) is dict, "proposal must be a built-in dictionary")
        wire, _ = _decode(proposal)
        _fields(wire, {"schema", "base_sha256", "reduction", "candidate_core", "layout"}, "proposal")
        _require(wire["schema"] == SCHEMA, "unsupported experimental proposal schema")
        original, narrowed, fast, frozen = _freeze_pipeline(base, wire["reduction"])
        _require(wire["base_sha256"] == original.sha256, "experimental proposal source identity mismatch")
        candidate = verify_program(wire["candidate_core"])
        _require(type(wire["candidate_core"]) is dict and wire["candidate_core"] == candidate.as_dict(),
                 "candidate_core must be actual primitive Core, not an elaboration request")
        checked_policy = _policy({**DEFAULT_POLICY, "timeout_ms": 30000} if policy is None else policy)
        report.update(base_sha256=original.sha256, narrowed_sha256=narrowed.sha256,
                      fast_sha256=fast.sha256, candidate_sha256=candidate.sha256,
                      proposal_sha256=_digest(wire), reduction_proposal_sha256=_digest(frozen),
                      policy=checked_policy, policy_sha256=_digest(checked_policy))
        report["structure"] = _check_structure(narrowed, fast, candidate, frozen["guarded"], wire["layout"])
        report["claims"]["actual_core_structure_checked"] = True
        proof, reference = _verify_frozen(original, narrowed, fast, frozen, checked_policy)
        report["reduction_verification"] = proof
        if proof["status"] != "verified":
            return finish("rejected" if proof["status"] == "rejected" else "unknown",
                          "fresh reduction proof did not verify: " + proof["reason"])
        _require(reference is not None and proof["candidate_sha256"] == reference.sha256
                 and proof["base_sha256"] == original.sha256
                 and proof["narrowed_sha256"] == narrowed.sha256
                 and proof["proposal_sha256"] == _digest(frozen),
                 "fresh reduction proof source/reference identity mismatch")
        if deferred_guard_checker_identity() != identity:
            return finish("unknown", "checker implementation changed during verification")
        report["reference_sha256"] = reference.sha256
        report["claims"]["fresh_reduction_proofs_checked"] = True
        return finish("checked", "actual Core frontier, alpha-renaming, every phi edge and immutable snapshot checked; fresh reduction proofs verified")
    except (ValueError, KeyError, TypeError, IndexError, OverflowError, RecursionError) as exc:
        return finish("rejected", str(exc))
    except OSError as exc:
        return finish("unknown", "checker identity/source unavailable: " + str(exc))
    except Exception as exc:
        # Unexpected verifier/solver failures must never escape as a checked
        # receipt or trigger a fallback compiler/admission path.
        return finish("unknown", "experimental check could not complete: " + type(exc).__name__ + ": " + str(exc))
