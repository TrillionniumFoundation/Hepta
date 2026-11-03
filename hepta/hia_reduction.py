"""Two independently checked optimizations for owned-byte reductions.

The proposer first narrows modular arithmetic whose result is explicitly
truncated, then proposes the existing guarded checked-reduction transformation.
Neither rule recognition nor a saved receipt grants authority. Admission checks
all scalar/effect/trap boundaries and the complete loop induction again. The
input guard is executed before effects and the original checked reduction is
retained outside its range (after an independently equivalent scalar rewrite).
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import tempfile
import time

from .hia_program import verify_program, WIDTHS
from .hia_optimization import (OptimizationRejected, _digest, _solver_identity,
                               verify_optimization)
from .hia_guarded_optimization import (propose_guarded_reduction,
    verify_guarded_optimization, guarded_checker_identity, _freeze, _compose)


SCHEMA = "hepta.hia.reduction-pipeline-proposal.v1"
VERIFY_SCHEMA = "hepta.hia.reduction-pipeline-verification.v1"
UNSIGNED = frozenset({"u8", "u16", "u32", "u64", "usize"})
MODULAR = frozenset({"int.add.wrap", "int.sub.wrap", "int.mul.wrap",
                     "bit.and", "bit.or", "bit.xor"})
MAX_NEW_OPERATIONS = 4096


def reduction_checker_identity():
    digest = sha256(guarded_checker_identity().encode())
    digest.update(Path(__file__).name.encode() + b"\0" + Path(__file__).read_bytes())
    return digest.hexdigest()


def propose_byte_narrowing(program):
    """Untrusted unsigned modular-expression proposal; no checked op is erased.

    Existing scalar instructions are retained. New nontrapping expressions are
    placed at the original truncation, without moving an effect. This also
    preserves a checked operation used to produce a modular operand: its trap
    cannot disappear merely because the eventual result is one byte wide.
    """
    original = verify_program(program)
    candidate = original.as_dict()
    changes, created = [], 0
    for function in candidate["functions"]:
        used = {p["name"] for p in function["params"]}
        used.update(p["name"] for b in function["blocks"] for p in b["params"])
        used.update(o["name"] for b in function["blocks"] for op in b["ops"] for o in op["out"])
        serial = 0

        def fresh():
            nonlocal serial
            while True:
                serial += 1
                name = "reduce_narrow_" + str(serial)
                if name not in used:
                    used.add(name)
                    return name

        for block in function["blocks"]:
            types = {p["name"]: p["type"] for p in block["params"]}
            producers, revised = {}, []
            for index, operation in enumerate(block["ops"]):
                producer = producers.get(operation["args"][0]) if operation["op"] == "int.cast" else None
                narrow = (operation["op"] == "int.cast" and operation["attrs"]["mode"] == "wrap"
                          and operation["out"][0]["type"] == "u8" and producer is not None
                          and producer["op"] in MODULAR
                          and types[operation["args"][0]] in UNSIGNED
                          and WIDTHS[types[operation["args"][0]]] > 8)
                if narrow:
                    cache = {}

                    def emit(op, args, attrs):
                        nonlocal created
                        created += 1
                        if created > MAX_NEW_OPERATIONS:
                            raise OptimizationRejected("E_HIA_REDUCTION_BUDGET: narrowing proposal operation budget")
                        name = fresh()
                        revised.append({"op": op, "args": args,
                                        "out": [{"name": name, "type": "u8"}], "attrs": attrs})
                        return name

                    def low_byte(name):
                        if types[name] == "u8":
                            return name
                        if name in cache:
                            return cache[name]
                        source = producers.get(name)
                        # The recursive path follows only nontrapping unsigned
                        # arithmetic. All original checked instructions remain.
                        if source is not None and types[name] in UNSIGNED and source["op"] in MODULAR:
                            value = emit(source["op"], [low_byte(a) for a in source["args"]], {})
                        elif (source is not None and source["op"] == "int.cast"
                              and source["attrs"]["mode"] == "wrap"
                              and types[source["args"][0]] in UNSIGNED
                              and WIDTHS[types[source["args"][0]]] >= 8):
                            value = low_byte(source["args"][0])
                        elif source is not None and source["op"] == "const" and types[name] in UNSIGNED:
                            value = emit("const", [], {"value": source["attrs"]["value"] & 255})
                        else:
                            value = emit("int.cast", [name], {"mode": "wrap"})
                        cache[name] = value
                        return value

                    result = low_byte(operation["args"][0])
                    revised.append({**operation, "args": [result]})
                    changes.append({"function": function["name"], "block": block["id"], "operation": index})
                else:
                    revised.append(operation)
                for output in operation["out"]:
                    types[output["name"]] = output["type"]
                    producers[output["name"]] = operation
            block["ops"] = revised
    return verify_program(candidate), {"rule": "unsigned-modular-low-byte.v1",
        "changes": changes, "new_operations": created, "equivalence_authority": False}


def propose_reduction_pipeline(program, maximum=None, *, include_induction=False):
    """Propose the byte pipeline, optionally including same-bound counted steps.

    The general pipeline otherwise leaves the fill and reduction index
    additions checked. Opting in proposes those steps as well; the existing
    independent induction checker must discharge every removed check and the
    complete checked fallback remains available.
    """
    original = verify_program(program)
    narrowed, _ = propose_byte_narrowing(original)
    return {"schema": SCHEMA, "base_sha256": original.sha256,
            "narrowed_core": narrowed.as_dict(),
            "guarded": propose_guarded_reduction(narrowed, maximum=maximum,
                                                   include_induction=include_induction)}


def _freeze_pipeline(base, proposal):
    original = verify_program(base)
    if (type(proposal) is not dict or set(proposal) != {"schema", "base_sha256", "narrowed_core", "guarded"}
            or any(type(k) is not str for k in proposal)
            or type(proposal["schema"]) is not str or proposal["schema"] != SCHEMA
            or type(proposal["base_sha256"]) is not str or proposal["base_sha256"] != original.sha256):
        raise OptimizationRejected("E_HIA_REDUCTION_PROPOSAL: exact source-bound proposal required")
    narrowed = verify_program(proposal["narrowed_core"])
    _, fast, guarded = _freeze(narrowed, proposal["guarded"])
    frozen = {"schema": SCHEMA, "base_sha256": original.sha256,
              "narrowed_core": narrowed.as_dict(), "guarded": guarded}
    return original, narrowed, fast, frozen


def _verify_frozen(original, narrowed, fast, frozen, policy):
    started = time.monotonic_ns()
    report = {"schema": VERIFY_SCHEMA, "status": "unknown",
        "base_sha256": original.sha256, "narrowed_sha256": narrowed.sha256,
        "proposal_sha256": _digest(frozen), "checker_sha256": reduction_checker_identity(),
        "proofs": {}, "claims": {"whole_language_soundness_proved": False,
            "backend_refinement_proved": False, "performance_qualified": False,
            "core_resource_trace_equivalence_checked": False},
        "deadline_scope": "Each of two independent verification stages owns its policy deadline."}

    def finish(status, reason, program=None):
        report.update(status=status, reason=reason, elapsed_ns=time.monotonic_ns()-started)
        report["verification_sha256"] = _digest(report)
        return report, program

    scalar = verify_optimization(original, narrowed, policy)
    report["proofs"]["narrowing"] = scalar
    if scalar["status"] != "verified":
        return finish(scalar["status"], "scalar stage: " + scalar["reason"])
    guarded = verify_guarded_optimization(narrowed, frozen["guarded"], policy)
    report["proofs"]["guarded_reduction"] = guarded
    if guarded["status"] != "verified":
        return finish(guarded["status"], "inductive stage: " + guarded["reason"])
    program = _compose(narrowed, fast, frozen["guarded"])
    if (program.sha256 != guarded["candidate_sha256"] or scalar["solver"] != guarded["solver"]
            or reduction_checker_identity() != report["checker_sha256"]):
        return finish("unknown", "candidate, checker or solver identity changed between proof stages")
    report.update(candidate_sha256=program.sha256, target=guarded["target"], solver=guarded["solver"],
                  input_assumptions=[], executed_guards=frozen["guarded"]["guards"],
                  fallback="independently equivalent narrowed Core with original checked reduction")
    report["claims"].update(core_resource_trace_equivalence_checked=True,
                           checked_reduction_retained_in_fallback=True,
                           byte_narrowing_verified_for_all_scalar_inputs=True)
    return finish("verified", "both scalar equivalence and guarded induction independently checked", program)


def verify_reduction_pipeline(base, proposal, policy=None):
    try:
        return _verify_frozen(*_freeze_pipeline(base, proposal), policy)[0]
    except (ValueError, KeyError, TypeError) as exc:
        return {"schema": VERIFY_SCHEMA, "status": "rejected", "reason": str(exc),
                "claims": {"core_resource_trace_equivalence_checked": False}}


def _admit(base, proposal, policy):
    proof, program = _verify_frozen(*_freeze_pipeline(base, proposal), policy)
    if proof["status"] != "verified":
        raise OptimizationRejected("E_HIA_REDUCTION_NOT_VERIFIED: " + proof["status"] + ": " + proof["reason"])
    return proof, program


def reduction_program(base, proposal, policy=None):
    """Return immutable composed Core only after both independent proofs run."""
    return _admit(base, proposal, policy)[1]


def build_reduction_native(base, proposal, output, *, policy=None, clang="clang", kind="shared"):
    """Bind a fresh two-stage proof to the actual published native bytes."""
    from .hia_program_llvm import build_program_native, _read_artifact
    from .artifact_publication import publish_verified, verify_published, withdraw_own_link
    proof, program = _admit(base, proposal, policy)
    destination = Path(output).absolute()
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise OptimizationRejected("E_HIA_REDUCTION_OUTPUT: new path in an existing directory required")
    import z3

    def recheck():
        if reduction_checker_identity() != proof["checker_sha256"] or _solver_identity(z3) != proof["solver"]:
            raise OptimizationRejected("E_HIA_REDUCTION_STALE: proof implementation changed during build")

    with tempfile.TemporaryDirectory(prefix=".hia-reduction-", dir=destination.parent) as temporary:
        stage = Path(temporary) / ("verified.so" if kind == "shared" else "verified.o")
        native = build_program_native(program, stage, clang=clang, kind=kind, target=proof["target"])
        data = _read_artifact(stage)
        if sha256(data).hexdigest() != native["artifact_sha256"]:
            raise OptimizationRejected("E_HIA_REDUCTION_ARTIFACT: staged native bytes changed")
        recheck()
        publish_verified(stage, destination, data)
        try:
            recheck()
            verify_published(stage, destination, data)
        except Exception:
            withdraw_own_link(stage, destination)
            raise
    native["output"] = str(destination)
    return {"schema": "hepta.hia.reduction-native.v1", "status": "verified_core_native_bound",
        "verification": proof, "native": native,
        "binding_sha256": _digest({"base": proof["base_sha256"], "candidate": program.sha256,
            "verification": proof["verification_sha256"], "artifact": native["artifact_sha256"],
            "compiler": native["toolchain"]["sha256"], "target": proof["target"]}),
        "claims": {"unverified_candidate_published": False, "final_artifact_bound": True,
                   "performance_qualified": False, "backend_refinement_proved": False}}
