"""Checked expansion of resolved, single-block leaf calls in resource CFGs.

The proposer substitutes names.  The checker independently normalizes source
call traces and candidate instruction traces and compares every ordered operation
and CFG exit.  Both programs pass the ordinary Core ownership verifier.  This
rule composes through caller loops without unrolling them; it does not prove
arbitrary interprocedural equivalence or backend refinement.  VM fuel, diagnostic
locations, and call-depth budget failures are outside this optimization profile.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import tempfile
import time

from .hia_program import verify_program
from .hia_optimization import OptimizationRejected, _digest, checker_identity

SCHEMA = "hepta.hia.leaf-call-expansion.v1"
VERIFY_SCHEMA = "hepta.hia.leaf-call-expansion-check.v1"
CHAIN_SCHEMA = "hepta.hia.expanded-guarded-proposal.v1"
MAX_SITES = 256
MAX_EXPANDED_OPERATIONS = 16384


def expansion_checker_identity():
    return sha256((checker_identity() + "\0").encode() + Path(__file__).read_bytes()).hexdigest()


def _leaf(function):
    return (len(function["blocks"]) == 1
            and function["blocks"][0]["id"] == function["entry"]
            and function["blocks"][0]["term"]["op"] == "ret"
            and all(op["op"] != "call" for op in function["blocks"][0]["ops"]))


def _rename_term(term, names):
    out = deepcopy(term)
    if out["op"] == "ret":
        out["values"] = [names[x] for x in out["values"]]
    elif out["op"] == "jump":
        out["args"] = [names[x] for x in out["args"]]
    elif out["op"] == "branch":
        out["cond"] = names[out["cond"]]
        for side in ("then", "else"):
            out[side]["args"] = [names[x] for x in out[side]["args"]]
    return out


def propose_leaf_call_expansion(base, *, callees=None):
    """Generate an untrusted expansion; no receipt or safety assertion is issued."""
    original = verify_program(base)
    data = original.as_dict()
    functions = {fn["name"]: fn for fn in data["functions"]}
    eligible = {name for name, fn in functions.items() if _leaf(fn)}
    if callees is not None:
        if type(callees) not in (list, tuple) or not callees or any(type(x) is not str for x in callees):
            raise OptimizationRejected("E_HIA_EXPAND_CALLEES: explicit nonempty names required")
        if len(callees) != len(set(callees)) or not set(callees) <= eligible:
            raise OptimizationRejected("E_HIA_EXPAND_CALLEES: unknown, repeated or non-leaf callee")
        eligible = set(callees)
    result, sites = deepcopy(data), []
    for source_fn, target_fn in zip(data["functions"], result["functions"]):
        used = {p["name"] for block in source_fn["blocks"] for p in block["params"]}
        used.update(p["name"] for block in source_fn["blocks"] for op in block["ops"] for p in op["out"])
        sequence = 0
        def fresh():
            nonlocal sequence
            while True:
                sequence += 1
                name = "inline_" + str(sequence)
                if name not in used:
                    used.add(name)
                    return name
        for source_block, target_block in zip(source_fn["blocks"], target_fn["blocks"]):
            names = {p["name"]: p["name"] for p in source_block["params"]}
            operations = []
            for index, op in enumerate(source_block["ops"]):
                target = op["attrs"].get("function") if op["op"] == "call" else None
                if target not in eligible:
                    item = deepcopy(op)
                    item["args"] = [names[x] for x in op["args"]]
                    operations.append(item)
                    names.update({p["name"]: p["name"] for p in op["out"]})
                    continue
                if len(sites) >= MAX_SITES:
                    raise OptimizationRejected("E_HIA_EXPAND_LIMIT: call-site budget exceeded")
                fn = functions[target]
                frame = {p["name"]: names[x] for p, x in zip(fn["params"], op["args"])}
                for inner in fn["blocks"][0]["ops"]:
                    item = deepcopy(inner)
                    item["args"] = [frame[x] for x in inner["args"]]
                    for output in item["out"]:
                        old = output["name"]
                        output["name"] = fresh()
                        frame[old] = output["name"]
                    operations.append(item)
                values = fn["blocks"][0]["term"]["values"]
                names.update({p["name"]: frame[x] for p, x in zip(op["out"], values)})
                sites.append({"caller": source_fn["name"], "block": source_block["id"],
                              "operation": index, "callee": target})
            target_block["ops"] = operations
            target_block["term"] = _rename_term(source_block["term"], names)
    if not sites:
        raise OptimizationRejected("E_HIA_EXPAND_EMPTY: no admitted leaf call sites")
    checked = verify_program(result)
    return {"schema": SCHEMA, "base_sha256": original.sha256,
            "candidate_core": checked.as_dict(), "sites": sites}


def _trace(block, functions, selected, *, caller):
    """Checker-only SSA trace; independent of the proposer's renaming algorithm."""
    env = {p["name"]: ("argument", index, p["type"])
           for index, p in enumerate(block["params"])}
    trace = []
    def emit(op, frame):
        args = [frame[name] for name in op["args"]]
        index = len(trace)
        trace.append({"op": op["op"], "args": args,
                      "types": [p["type"] for p in op["out"]], "attrs": op["attrs"]})
        for slot, p in enumerate(op["out"]):
            frame[p["name"]] = ("operation", index, slot, p["type"])
        if len(trace) > MAX_EXPANDED_OPERATIONS:
            raise OptimizationRejected("expanded instruction budget exceeded")
    for index, op in enumerate(block["ops"]):
        site = selected.get((caller, block["id"], index))
        if site is None:
            emit(op, env)
            continue
        if op["op"] != "call" or op["attrs"]["function"] != site:
            raise OptimizationRejected("call-site witness does not name the actual call")
        fn = functions[site]
        if not _leaf(fn):
            raise OptimizationRejected("only complete single-block noncalling leaf bodies are supported")
        frame = {p["name"]: env[name] for p, name in zip(fn["params"], op["args"])}
        for inner in fn["blocks"][0]["ops"]:
            emit(inner, frame)
        for output, name in zip(op["out"], fn["blocks"][0]["term"]["values"]):
            env[output["name"]] = frame[name]
    return trace, _rename_term(block["term"], env)


def verify_leaf_call_expansion(base, proposal):
    started = time.monotonic_ns()
    report = {"schema": VERIFY_SCHEMA, "status": "rejected", "target": "x86_64-unknown-linux-gnu",
              "checker_sha256": expansion_checker_identity(), "obligations": [],
              "claims": {"backend_refinement_proved": False, "whole_language_soundness": False,
                         "arbitrary_call_equivalence": False, "vm_budget_failures_preserved": False,
                         "source_language_refinement_proved": False, "performance_qualified": False}}
    try:
        original = verify_program(base)
        if type(proposal) is not dict or set(proposal) != {"schema", "base_sha256", "candidate_core", "sites"}:
            raise OptimizationRejected("exact proposal fields required")
        if proposal["schema"] != SCHEMA or proposal["base_sha256"] != original.sha256:
            raise OptimizationRejected("source identity mismatch")
        candidate = verify_program(proposal["candidate_core"])
        left, right = original.as_dict(), candidate.as_dict()
        report.update(base_sha256=original.sha256, candidate_sha256=candidate.sha256)
        if {k: v for k, v in left.items() if k != "functions"} != {k: v for k, v in right.items() if k != "functions"}:
            raise OptimizationRejected("module interface changed")
        sites = proposal["sites"]
        if type(sites) is not list or not 1 <= len(sites) <= MAX_SITES:
            raise OptimizationRejected("bounded nonempty call-site inventory required")
        selected = {}
        for site in sites:
            if type(site) is not dict or set(site) != {"caller", "block", "operation", "callee"}:
                raise OptimizationRejected("invalid call-site fields")
            if any(type(site[x]) is not str for x in ("caller", "block", "callee")) or type(site["operation"]) is not int or site["operation"] < 0:
                raise OptimizationRejected("invalid call-site identity")
            key = (site["caller"], site["block"], site["operation"])
            if key in selected:
                raise OptimizationRejected("duplicate call-site witness")
            selected[key] = site["callee"]
        functions = {f["name"]: f for f in left["functions"]}
        if len(left["functions"]) != len(right["functions"]):
            raise OptimizationRejected("function inventory changed")
        seen, total = set(), 0
        for lf, rf in zip(left["functions"], right["functions"]):
            if {k: v for k, v in lf.items() if k != "blocks"} != {k: v for k, v in rf.items() if k != "blocks"} or len(lf["blocks"]) != len(rf["blocks"]):
                raise OptimizationRejected("function interface or block inventory changed")
            for lb, rb in zip(lf["blocks"], rf["blocks"]):
                if lb["id"] != rb["id"] or lb["params"] != rb["params"]:
                    raise OptimizationRejected("block interface changed")
                for index in range(len(lb["ops"])):
                    key = (lf["name"], lb["id"], index)
                    if key in selected:
                        seen.add(key)
                expected = _trace(lb, functions, selected, caller=lf["name"])
                actual = _trace(rb, functions, {}, caller=rf["name"])
                total += len(expected[0]) + len(actual[0])
                if total > MAX_EXPANDED_OPERATIONS:
                    raise OptimizationRejected("whole-request instruction budget exceeded")
                if expected != actual:
                    raise OptimizationRejected("ordered operation, operand, trap or CFG exit differs")
                report["obligations"].append({"function": lf["name"], "block": lb["id"],
                                              "expanded_operations": len(expected[0]), "equal": True})
        if seen != set(selected) or original.sha256 == candidate.sha256:
            raise OptimizationRejected("missing witness or unchanged candidate")
        report.update(status="verified", reason="complete alpha-normalized leaf expansion traces agree",
                      call_sites=len(selected), effect_order_preserved=True)
    except (ValueError, KeyError, TypeError, IndexError) as error:
        report["reason"] = str(error)
    report["verification_wall_ns"] = time.monotonic_ns() - started
    report["verification_sha256"] = _digest({k: v for k, v in report.items() if k != "verification_wall_ns"})
    return report


def build_expanded_native(base, proposal, output, *, clang="clang", kind="shared"):
    """Recheck actual Core and bind the resulting native artifact before publication."""
    proof = verify_leaf_call_expansion(base, proposal)
    if proof["status"] != "verified":
        raise OptimizationRejected("E_HIA_EXPAND_NOT_VERIFIED: " + proof["reason"])
    candidate = verify_program(deepcopy(proposal["candidate_core"]))
    return _build_bound(proof, candidate, output, expansion_checker_identity, clang=clang, kind=kind)


def expanded_guarded_checker_identity():
    from .hia_guarded_optimization import guarded_checker_identity
    return sha256((expansion_checker_identity() + "\0" + guarded_checker_identity()).encode()).hexdigest()


def propose_expanded_guarded(base, *, callees=None, maximum=None):
    """Expose a resolved byte producer, then propose a guarded loop reduction."""
    from .hia_guarded_optimization import propose_guarded_reduction
    expansion = propose_leaf_call_expansion(base, callees=callees)
    guarded = propose_guarded_reduction(expansion["candidate_core"], maximum=maximum)
    return {"schema": CHAIN_SCHEMA, "base_sha256": verify_program(base).sha256,
            "expansion": expansion, "guarded": guarded}


def _check_expanded_guarded(base, proposal, policy=None):
    from .hia_guarded_optimization import verify_guarded_optimization, guarded_program
    started = time.monotonic_ns()
    report = {"schema": "hepta.hia.expanded-guarded-check.v1", "status": "rejected",
              "checker_sha256": expanded_guarded_checker_identity(), "stages": [],
              "claims": {"backend_refinement_proved": False, "whole_language_soundness": False,
                         "arbitrary_call_equivalence": False, "vm_budget_failures_preserved": False,
                         "source_language_refinement_proved": False, "performance_qualified": False}}
    candidate = None
    try:
        original = verify_program(base)
        frozen = deepcopy(proposal)
        if (type(frozen) is not dict or set(frozen) != {"schema", "base_sha256", "expansion", "guarded"}
                or frozen["schema"] != CHAIN_SCHEMA or frozen["base_sha256"] != original.sha256):
            raise OptimizationRejected("exact chain fields and original source identity required")
        expansion = verify_leaf_call_expansion(original, frozen["expansion"])
        report["stages"].append(expansion)
        if expansion["status"] != "verified":
            raise OptimizationRejected("call expansion: " + expansion["reason"])
        intermediate = verify_program(frozen["expansion"]["candidate_core"])
        if intermediate.sha256 != expansion["candidate_sha256"]:
            raise OptimizationRejected("expansion intermediate changed")
        guarded = verify_guarded_optimization(intermediate, frozen["guarded"], policy)
        report["stages"].append(guarded)
        if guarded["status"] != "verified":
            report["status"] = guarded["status"]
            raise OptimizationRejected("guarded loop: " + guarded["reason"])
        if guarded["base_sha256"] != intermediate.sha256:
            raise OptimizationRejected("guarded proof names a different intermediate")
        candidate = guarded_program(intermediate, frozen["guarded"], policy)
        if candidate.sha256 != guarded["candidate_sha256"]:
            raise OptimizationRejected("guarded final Core differs from proved Core")
        if expanded_guarded_checker_identity() != report["checker_sha256"]:
            raise OptimizationRejected("chained checker changed during verification")
        report.update(status="verified", reason="resolved leaf expansion and inductive guarded loop proofs compose",
                      base_sha256=original.sha256, intermediate_sha256=intermediate.sha256,
                      candidate_sha256=candidate.sha256, target=guarded["target"],
                      original_fallback_preserved=True, ordered_resource_operations_preserved=True)
    except (ValueError, KeyError, TypeError, IndexError) as error:
        report["reason"] = str(error)
        candidate = None
    report["verification_wall_ns"] = time.monotonic_ns() - started
    report["verification_sha256"] = _digest({k: v for k, v in report.items() if k != "verification_wall_ns"})
    return report, candidate


def verify_expanded_guarded(base, proposal, policy=None):
    return _check_expanded_guarded(base, proposal, policy)[0]


def expanded_guarded_program(base, proposal, policy=None):
    report, candidate = _check_expanded_guarded(base, proposal, policy)
    if report["status"] != "verified":
        raise OptimizationRejected("E_HIA_EXPAND_CHAIN_NOT_VERIFIED: " + report["reason"])
    return candidate


def build_expanded_guarded_native(base, proposal, output, *, policy=None, clang="clang", kind="shared"):
    proof, candidate = _check_expanded_guarded(base, proposal, policy)
    if proof["status"] != "verified":
        raise OptimizationRejected("E_HIA_EXPAND_CHAIN_NOT_VERIFIED: " + proof["reason"])
    return _build_bound(proof, candidate, output, expanded_guarded_checker_identity, clang=clang, kind=kind)


def _build_bound(proof, candidate, output, current_identity, *, clang, kind):
    from .hia_program_llvm import build_program_native, _read_artifact
    from .artifact_publication import publish_verified, verify_published, withdraw_own_link
    if candidate.sha256 != proof["candidate_sha256"]:
        raise OptimizationRejected("candidate changed after verification")
    destination = Path(output).absolute()
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise OptimizationRejected("new output in an existing directory required")
    def recheck():
        if current_identity() != proof["checker_sha256"]:
            raise OptimizationRejected("checker changed during native build")
    with tempfile.TemporaryDirectory(prefix=".hia-expand-", dir=destination.parent) as tmp:
        stage = Path(tmp) / ("expanded.so" if kind == "shared" else "expanded.o")
        native = build_program_native(candidate, stage, clang=clang, kind=kind, target=proof["target"])
        data = _read_artifact(stage)
        if sha256(data).hexdigest() != native["artifact_sha256"]:
            raise OptimizationRejected("native artifact identity changed")
        recheck()
        publish_verified(stage, destination, data)
        try:
            recheck()
            verify_published(stage, destination, data)
        except Exception:
            withdraw_own_link(stage, destination)
            raise
    native["output"] = str(destination)
    return {"schema": "hepta.hia.optimized-native.v1", "status": "verified_core_native_bound",
            "verification": proof, "native": native,
            "binding_sha256": _digest({"base": proof["base_sha256"], "candidate": candidate.sha256,
                "verification": proof["verification_sha256"], "artifact": native["artifact_sha256"],
                "compiler": native["toolchain"]["sha256"], "target": native["target"]}),
            "claims": {"final_artifact_bound": True, "performance_qualified": False,
                       "backend_refinement_proved": False}}
