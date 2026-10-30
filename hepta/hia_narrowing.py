"""Independent proof and artifact admission for modular width narrowing.

The proposer pushes truncation through a bounded unsigned expression. It is
untrusted: the verifier rebuilds the exact edit inventory and invokes the
separate bit-vector scalar/effect/first-trap checker. No compiler flag, cast
annotation, serialized receipt or successful benchmark authorizes deployment.
Guarded reduction can precede narrowing; both proofs then bind the actual
intermediate Core and the final native bytes.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import tempfile
import time

from .hia_program import HIAProgramRejected, WIDTHS, verify_program
from .hia_optimization import (DEFAULT_POLICY, OptimizationRejected, _digest,
                               _policy, _solver_identity, checker_identity,
                               verify_optimization, PURE)

SCHEMA = "hepta.hia.modular-narrowing-proposal.v1"
VERIFY_SCHEMA = "hepta.hia.modular-narrowing-verification.v1"
CHAIN_SCHEMA = "hepta.hia.guarded-narrowing-proposal.v1"
CHAIN_VERIFY_SCHEMA = "hepta.hia.guarded-narrowing-verification.v1"
RULE = "unsigned-modular-truncation.v1"
UNSIGNED = frozenset({"u8", "u16", "u32", "u64", "usize"})
MODULAR = frozenset({"int.add.wrap", "int.sub.wrap", "int.mul.wrap",
                     "bit.and", "bit.or", "bit.xor", "bit.not"})
MAX_REWRITES = 128
MAX_REPLACEMENT_OPERATIONS = 2048
MAX_EXPRESSION_DEPTH = 32


def narrowing_checker_identity():
    digest = sha256(checker_identity().encode())
    digest.update(Path(__file__).read_bytes())
    return digest.hexdigest()


def chain_checker_identity():
    from .hia_guarded_optimization import guarded_checker_identity
    return _digest({"narrowing": narrowing_checker_identity(),
                    "guarded": guarded_checker_identity()})


def _ins(op, args, name, typ, **attrs):
    return {"op": op, "args": args, "out": [{"name": name, "type": typ}], "attrs": attrs}


def propose_modular_narrowing(program):
    """Produce a bounded, optional edit proposal without granting authority.

    Earlier operations, including checked arithmetic and calls, remain in
    place. Only a wrapping unsigned cast is replaced. Clang may subsequently
    eliminate unused, nontrapping wide arithmetic under its trusted semantics.
    The proposer never removes a trap or relies on an input range assertion.
    """
    original = verify_program(program)
    data = original.as_dict()
    used = {p["name"] for fn in data["functions"] for b in fn["blocks"] for p in b["params"]}
    used.update(o["name"] for fn in data["functions"] for b in fn["blocks"]
                for ins in b["ops"] for o in ins["out"])
    rewrites, inserted, serial = [], 0, 0

    def fresh():
        nonlocal serial
        while True:
            serial += 1
            name = "hia_narrow_" + str(serial)
            if name not in used:
                used.add(name)
                return name

    for fn in data["functions"]:
        for block in fn["blocks"]:
            types = {p["name"]: p["type"] for p in block["params"]}
            definitions = {}
            rewritten = []
            for index, ins in enumerate(block["ops"]):
                replacement = None
                if (ins["op"] == "int.cast" and ins["attrs"]["mode"] == "wrap"
                        and ins["out"][0]["type"] in UNSIGNED
                        and types[ins["args"][0]] in UNSIGNED
                        and WIDTHS[ins["out"][0]["type"]] < WIDTHS[types[ins["args"][0]]]):
                    target = ins["out"][0]["type"]
                    width = WIDTHS[target]
                    emitted, memo, changed = [], {}, [0]

                    def narrow(name, depth=0):
                        if name in memo:
                            return memo[name]
                        typ = types[name]
                        source = definitions.get(name)
                        if typ == target:
                            return name
                        if typ not in UNSIGNED:
                            raise ValueError("signed expression outside modular narrowing profile")
                        if depth > MAX_EXPRESSION_DEPTH:
                            raise ValueError("modular expression depth budget exhausted")
                        output = fresh()
                        if source and WIDTHS[typ] >= width and source["op"] in MODULAR:
                            args = [narrow(a, depth + 1) for a in source["args"]]
                            emitted.append(_ins(source["op"], args, output, target))
                            changed[0] += WIDTHS[typ] > width
                        elif source and source["op"] == "const":
                            emitted.append(_ins("const", [], output, target,
                                                value=source["attrs"]["value"] % (1 << width)))
                        elif (source and source["op"] == "int.cast" and source["attrs"]["mode"] == "wrap"
                              and WIDTHS[typ] >= width and types[source["args"][0]] in UNSIGNED
                              and WIDTHS[types[source["args"][0]]] >= width):
                            output = narrow(source["args"][0], depth + 1)
                        else:
                            emitted.append(_ins("int.cast", [name], output, target, mode="wrap"))
                        if len(emitted) > MAX_REPLACEMENT_OPERATIONS:
                            raise ValueError("modular expression operation budget exhausted")
                        memo[name] = output
                        return output

                    try:
                        value = narrow(ins["args"][0])
                        if changed[0]:
                            emitted.append(_ins("int.cast", [value], ins["out"][0]["name"], target, mode="wrap"))
                            if (len(rewrites) >= MAX_REWRITES
                                    or inserted + len(emitted) > MAX_REPLACEMENT_OPERATIONS):
                                raise ValueError("whole modular proposal budget exhausted")
                            replacement = emitted
                            inserted += len(emitted)
                            rewrites.append({"function": fn["name"], "block": block["id"],
                                             "operation": index, "rule": RULE,
                                             "replacement": emitted})
                    except ValueError:
                        # A proposer may abstain on a large or unsupported expression.
                        # It cannot weaken the verifier's finite proof obligations.
                        replacement = None
                rewritten.extend(replacement if replacement is not None else [ins])
                for out in ins["out"]:
                    types[out["name"]] = out["type"]
                    definitions[out["name"]] = ins
            block["ops"] = rewritten
    if not rewrites:
        raise OptimizationRejected("E_HIA_NARROW_NO_CANDIDATE: no supported modular truncation")
    return {"schema": SCHEMA, "base_sha256": original.sha256,
            "candidate_core": verify_program(data).as_dict(), "rewrites": rewrites}


def _freeze(base, proposal):
    original = verify_program(base)
    if (type(proposal) is not dict
            or set(proposal) != {"schema", "base_sha256", "candidate_core", "rewrites"}
            or proposal["schema"] != SCHEMA or proposal["base_sha256"] != original.sha256):
        raise ValueError("exact modular proposal fields and actual base identity required")
    candidate = verify_program(proposal["candidate_core"])
    rows = proposal["rewrites"]
    if type(rows) is not list or not 1 <= len(rows) <= MAX_REWRITES:
        raise ValueError("modular rewrite inventory is outside its bound")
    edits, total = {}, 0
    for row in rows:
        if (type(row) is not dict
                or set(row) != {"function", "block", "operation", "rule", "replacement"}
                or type(row["function"]) is not str or type(row["block"]) is not str
                or type(row["operation"]) is not int or row["operation"] < 0
                or row["rule"] != RULE or type(row["replacement"]) is not list
                or not row["replacement"]):
            raise ValueError("malformed modular rewrite inventory")
        key = row["function"], row["block"], row["operation"]
        if key in edits:
            raise ValueError("duplicate modular rewrite inventory")
        total += len(row["replacement"])
        if total > MAX_REPLACEMENT_OPERATIONS:
            raise ValueError("modular replacement budget exhausted")
        edits[key] = row
    data, actual = original.as_dict(), []
    for fn in data["functions"]:
        for block in fn["blocks"]:
            types = {p["name"]: p["type"] for p in block["params"]}
            ops = []
            for index, ins in enumerate(block["ops"]):
                row = edits.get((fn["name"], block["id"], index))
                if row is not None:
                    if (ins["op"] != "int.cast" or ins["attrs"]["mode"] != "wrap"
                            or ins["out"][0]["type"] not in UNSIGNED
                            or types[ins["args"][0]] not in UNSIGNED
                            or WIDTHS[types[ins["args"][0]]] <= WIDTHS[ins["out"][0]["type"]]):
                        raise ValueError("only unsigned wrapping truncation roots may be replaced")
                    target, replacement = ins["out"][0]["type"], row["replacement"]
                    modular_seen = False
                    replacement_types = dict(types)
                    for emitted in replacement:
                        if (type(emitted) is not dict or set(emitted) != {"op", "args", "out", "attrs"}
                                or emitted["op"] not in MODULAR | {"const", "int.cast"}
                                or type(emitted["out"]) is not list or len(emitted["out"]) != 1
                                or emitted["out"][0].get("type") != target):
                            raise ValueError("replacement must contain only narrow modular scalar operations")
                        if emitted["op"] == "int.cast" and emitted["attrs"] != {"mode": "wrap"}:
                            raise ValueError("replacement casts must wrap")
                        if type(emitted["args"]) is not list or any(
                                type(a) is not str or replacement_types.get(a) not in UNSIGNED
                                for a in emitted["args"]):
                            raise ValueError("replacement operands must be existing unsigned scalars")
                        replacement_types[emitted["out"][0]["name"]] = target
                        modular_seen |= emitted["op"] in MODULAR
                    if not modular_seen or replacement[-1]["out"] != ins["out"]:
                        raise ValueError("replacement must compute the original narrow root output")
                    ops.extend(replacement)
                    actual.append(row)
                else:
                    ops.append(ins)
                types.update((out["name"], out["type"]) for out in ins["out"])
            block["ops"] = ops
    if actual != rows:
        raise ValueError("rewrite inventory is incomplete, out of order, or references absent operations")
    reconstructed = verify_program(data)
    if reconstructed.canonical_bytes != candidate.canonical_bytes:
        raise ValueError("candidate differs from the complete declared modular edits")
    frozen = {"schema": SCHEMA, "base_sha256": original.sha256,
              "candidate_core": candidate.as_dict(), "rewrites": json.loads(json.dumps(actual))}
    return original, candidate, frozen


def _report(schema, identity, policy):
    return {"schema": schema, "status": "unknown", "policy": policy,
            "policy_sha256": _digest(policy),
            "target": policy["target"], "checker_sha256": identity,
            "claims": {"deployment_authority": False, "backend_refinement_proved": False,
                       "whole_language_soundness_proved": False, "performance_qualified": False}}


def _finish(report, started, status, reason):
    report.update(status=status, reason=reason, elapsed_ns=time.monotonic_ns() - started)
    report["verification_sha256"] = _digest(report)
    return report


def verify_modular_narrowing(base, proposal, policy=None):
    started = time.monotonic_ns()
    policy = _policy(policy)
    report = _report(VERIFY_SCHEMA, narrowing_checker_identity(), policy)
    try:
        original, candidate, frozen = _freeze(base, proposal)
    except (HIAProgramRejected, ValueError, KeyError, TypeError, AttributeError) as error:
        return _finish(report, started, "rejected", "modular edit admission failed: " + str(error))
    report.update(base_sha256=original.sha256, candidate_sha256=candidate.sha256,
                  proposal_sha256=_digest(frozen), rewrites=frozen["rewrites"],
                  preconditions=[], structural_preconditions=[
                      "exact inventoried unsigned wrapping truncation roots",
                      "original operations retained except inventoried root casts",
                      "identical signatures, CFG, ordered resource/call operations and first traps"],
                  target_constraints={"triple": policy["target"], "pointer_width": 64,
                                      "foreign_abi": "unchanged scalar C exports"})
    remaining = policy["timeout_ms"] - (time.monotonic_ns() - started) // 1_000_000
    if remaining <= 0:
        return _finish(report, started, "timeout", "narrowing deadline exhausted before independent proof")
    proof = verify_optimization(original, candidate, {**policy, "timeout_ms": remaining})
    report["equivalence"] = proof
    report["resource_delta"] = proof["resource_delta"]
    if "solver" in proof:
        report["solver"] = proof["solver"]
    if proof["status"] != "verified":
        return _finish(report, started, proof["status"], proof["reason"])
    if narrowing_checker_identity() != report["checker_sha256"]:
        return _finish(report, started, "unknown", "narrowing checker changed during proof")
    if time.monotonic_ns() - started >= policy["timeout_ms"] * 1_000_000:
        return _finish(report, started, "timeout", "narrowing deadline exhausted before admission")
    report["claims"].update(core_scalar_effect_equivalence_checked=True,
                            exact_edit_inventory_checked=True, all_declared_scalar_inputs=True)
    return _finish(report, started, "verified", "independent modular scalar/effect/first-trap obligations are UNSAT")


def narrowed_program(base, proposal, policy=None):
    original, candidate, frozen = _freeze(base, proposal)
    proof = verify_modular_narrowing(original, frozen, policy)
    if proof["status"] != "verified":
        raise OptimizationRejected("E_HIA_NARROW_NOT_VERIFIED: " + proof["status"] + ": " + proof["reason"])
    return candidate


def propose_guarded_narrowing(base, maximum=None):
    from .hia_guarded_optimization import propose_guarded_reduction, _freeze as guard_freeze, _compose
    original = verify_program(base)
    guarded = propose_guarded_reduction(original, maximum)
    # Construction and Core admission are not an equivalence proof. The chain
    # verifier discharges both stages before either stage grants publication.
    left, fast, frozen = guard_freeze(original, guarded)
    intermediate = _compose(left, fast, frozen)
    return {"schema": CHAIN_SCHEMA, "base_sha256": original.sha256,
            "guarded": guarded, "narrowing": propose_modular_narrowing(intermediate)}


def _freeze_chain(base, proposal):
    from .hia_guarded_optimization import _freeze as guard_freeze, _compose
    original = verify_program(base)
    if (type(proposal) is not dict
            or set(proposal) != {"schema", "base_sha256", "guarded", "narrowing"}
            or proposal["schema"] != CHAIN_SCHEMA or proposal["base_sha256"] != original.sha256):
        raise ValueError("exact guarded-narrowing proposal and base identity required")
    left, fast, guard = guard_freeze(original, proposal["guarded"])
    intermediate = _compose(left, fast, guard)
    _, candidate, narrow = _freeze(intermediate, proposal["narrowing"])
    return original, intermediate, candidate, {"schema": CHAIN_SCHEMA,
        "base_sha256": original.sha256, "guarded": guard, "narrowing": narrow}


def verify_guarded_narrowing(base, proposal, policy=None):
    from .hia_guarded_optimization import verify_guarded_optimization
    started = time.monotonic_ns()
    policy = _policy({**DEFAULT_POLICY, "timeout_ms": 30000} if policy is None else policy)
    report = _report(CHAIN_VERIFY_SCHEMA, chain_checker_identity(), policy)
    try:
        original, intermediate, candidate, frozen = _freeze_chain(base, proposal)
    except (HIAProgramRejected, ValueError, KeyError, TypeError, AttributeError) as error:
        return _finish(report, started, "rejected", "guarded-narrowing admission failed: " + str(error))
    report.update(base_sha256=original.sha256, intermediate_sha256=intermediate.sha256,
                  candidate_sha256=candidate.sha256, proposal_sha256=_digest(frozen), stages=[])
    operation_count = sum(len(b["ops"]) for f in original.as_dict()["functions"] for b in f["blocks"])
    operation_count += sum(op["op"] in PURE for p in (intermediate, candidate)
                           for f in p.as_dict()["functions"] for b in f["blocks"] for op in b["ops"])
    report["whole_chain_operation_count"] = operation_count
    if operation_count > policy["max_scalar_operations"]:
        return _finish(report, started, "unknown", "whole-chain symbolic operation budget exceeded")
    for stage, before, transform, verify in (
            ("guarded-reduction", original, frozen["guarded"], verify_guarded_optimization),
            ("modular-narrowing", intermediate, frozen["narrowing"], verify_modular_narrowing)):
        remaining = policy["timeout_ms"] - (time.monotonic_ns() - started) // 1_000_000
        if remaining <= 0:
            return _finish(report, started, "timeout", "shared chain deadline exhausted before " + stage)
        used_obligations = sum(len(p["proof"].get("obligations", p["proof"].get("equivalence", {}).get("obligations", [])))
                               for p in report["stages"])
        proof = verify(before, transform, {**policy, "timeout_ms": remaining,
                                          "max_obligations": max(0, policy["max_obligations"] - used_obligations)})
        report["stages"].append({"stage": stage, "proof": proof})
        if proof["status"] != "verified":
            return _finish(report, started, proof["status"], stage + ": " + proof["reason"])
        if "solver" in report and report["solver"] != proof["solver"]:
            return _finish(report, started, "unknown", "SMT identity changed between chain stages")
        report["solver"] = proof["solver"]
    guard, narrow = [s["proof"] for s in report["stages"]]
    if (guard["base_sha256"] != original.sha256 or guard["candidate_sha256"] != intermediate.sha256
            or narrow["base_sha256"] != intermediate.sha256 or narrow["candidate_sha256"] != candidate.sha256):
        return _finish(report, started, "unknown", "proof chain does not bind the actual intermediate and final Core")
    if chain_checker_identity() != report["checker_sha256"]:
        return _finish(report, started, "unknown", "guarded-narrowing checker changed during proof")
    if time.monotonic_ns() - started >= policy["timeout_ms"] * 1_000_000:
        return _finish(report, started, "timeout", "shared chain deadline exhausted before admission")
    report.update(preconditions=guard["preconditions"],
                  target_constraints={"triple": policy["target"], "pointer_width": 64,
                                      "foreign_abi": "unchanged scalar C exports",
                                      "guard_before_effects": True,
                                      "fallback_equivalent_via_modular_proof": True},
                  resource_delta={"peak_live_bytes_change_under_core_model": 0,
                                  "ordered_resource_operations_preserved": True,
                                  "allocation_failure_sequence_preserved_under_core_model": True,
                                  "resource_trace_equivalence_checked": True,
                                  "code_size_and_compile_cost_may_increase": True,
                                  "vm_tick_count_preserved": False})
    report["claims"].update(core_effect_and_resource_equivalence_checked=True,
                            independent_stage_proofs_bound=True, complete_fallback_equivalence_checked=True)
    return _finish(report, started, "verified", "both independent stages bind original, intermediate and final Core")


def guarded_narrowed_program(base, proposal, policy=None):
    original, _, candidate, frozen = _freeze_chain(base, proposal)
    proof = verify_guarded_narrowing(original, frozen, policy)
    if proof["status"] != "verified":
        raise OptimizationRejected("E_HIA_NARROW_NOT_VERIFIED: " + proof["status"] + ": " + proof["reason"])
    return candidate


def _build(program, proof, output, clang, kind, identity):
    from .hia_program_llvm import build_program_native, _read_artifact
    from .artifact_publication import publish_verified, verify_published, withdraw_own_link
    if proof["status"] != "verified" or program.sha256 != proof["candidate_sha256"]:
        raise OptimizationRejected("E_HIA_NARROW_NOT_VERIFIED: final Core is not bound to a verified proof")
    destination = Path(output).absolute()
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise OptimizationRejected("E_HIA_NARROW_OUTPUT: new path in an existing directory required")
    import z3

    def recheck():
        if identity() != proof["checker_sha256"] or _solver_identity(z3) != proof["solver"]:
            raise OptimizationRejected("E_HIA_NARROW_STALE: proof implementation changed during build")

    with tempfile.TemporaryDirectory(prefix=".hia-narrowed-", dir=destination.parent) as tmp:
        stage = Path(tmp) / ("narrowed.so" if kind == "shared" else "narrowed.o")
        native = build_program_native(program, stage, clang=clang, kind=kind, target=proof["target"])
        data = _read_artifact(stage)
        if sha256(data).hexdigest() != native["artifact_sha256"]:
            raise OptimizationRejected("E_HIA_NARROW_ARTIFACT: staged native bytes changed")
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
            "binding_sha256": _digest({"base": proof["base_sha256"], "candidate": program.sha256,
                                        "verification": proof["verification_sha256"],
                                        "artifact": native["artifact_sha256"],
                                        "compiler": native["toolchain"]["sha256"], "target": native["target"]}),
            "claims": {"unverified_candidate_published": False, "final_artifact_bound": True,
                       "performance_qualified": False, "backend_refinement_proved": False}}


def build_narrowed_native(base, proposal, output, *, policy=None, clang="clang", kind="shared"):
    original, candidate, frozen = _freeze(base, proposal)
    proof = verify_modular_narrowing(original, frozen, policy)
    return _build(candidate, proof, output, clang, kind, narrowing_checker_identity)


def build_guarded_narrowed_native(base, proposal, output, *, policy=None, clang="clang", kind="shared"):
    original, _, candidate, frozen = _freeze_chain(base, proposal)
    proof = verify_guarded_narrowing(original, frozen, policy)
    return _build(candidate, proof, output, clang, kind, chain_checker_identity)
