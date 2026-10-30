"""Fail-closed, compositional validation of scalar rewrites in HIA resource CFGs.

The admitted transformation preserves the exact CFG, interfaces and ordered
resource/call operations. At every effect barrier an independent bit-vector
encoding proves equal arguments and equal first-trap outcomes for *all* scalar
inputs; scalar outputs of the barrier are shared symbolic values. This permits
loops and resource programs without pretending to solve arbitrary equivalence.
The encoder and Z3 are trusted components, not a proof of the whole compiler.
Serialized receipts are evidence only. Native admission rechecks actual bytes.
"""
from __future__ import annotations

from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import time

from .hia_program import SCALARS, WIDTHS, HIAProgramRejected, verify_program


SCHEMA = "hepta.hia.optimization-verification.v1"
QUALIFIED_CORE_SCHEMAS = frozenset("hepta.hia.program.v" + str(version) for version in range(1, 8))
POLICY_SCHEMA = "hepta.hia.optimization-policy.v1"
TARGETS = frozenset({"x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
                     "riscv64-unknown-linux-gnu"})
PINNED_Z3_VERSION = "4.15.4"
PURE = frozenset({"const", "select", "int.cast", "int.neg.checked", "bit.not",
                  "bit.and", "bit.or", "bit.xor", "bool.not", "bool.and", "bool.or",
                  *[f"compare.{x}" for x in ("eq", "ne", "lt", "le", "gt", "ge")],
                  *[f"int.{x}.{y}" for x in ("add", "sub", "mul") for y in ("wrap", "checked")],
                  *[f"int.{x}.checked" for x in ("div", "rem", "shl", "shr")]})
DEFAULT_POLICY = {"schema": POLICY_SCHEMA, "target": "x86_64-unknown-linux-gnu",
                  "timeout_ms": 5000, "max_scalar_operations": 4096,
                  "max_obligations": 1024, "preconditions": []}


class OptimizationRejected(ValueError):
    pass


def _wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _digest(value):
    return sha256(_wire(value)).hexdigest()


def checker_identity():
    digest = sha256()
    for name in ("hia_optimization.py", "hia_program.py", "hia_opcodes.py", "hia_semantic_kernel.py", "hia_schema.py",
                 "hia_program_composite.py", "hia_json_preflight.py",
                 "hia_program_runtime.py", "hia_bounded_memory.py"):
        digest.update(name.encode() + b"\0" + Path(__file__).with_name(name).read_bytes() + b"\0")
    return digest.hexdigest()


def _solver_identity(z3):
    """Identify the actual ctypes library used by the pinned Python binding.

    This is a narrow qualified binding layout, not a search for any similarly
    named installed library. Unsupported binding layouts cannot grant admission.
    """
    from .hia_program_llvm import _read_artifact
    try:
        function = z3.z3core.Z3_get_version.__defaults__[0].f
        libraries = [v for v in function._objects.values() if hasattr(v, "_name")]
        if len(libraries) != 1:
            raise ValueError("ambiguous loaded SMT library")
        library = Path(libraries[0]._name).resolve(strict=True)
        package = Path(z3.__file__).parent
        bindings = sha256()
        for path in sorted(package.glob("*.py")):
            bindings.update(path.name.encode() + b"\0" + path.read_bytes() + b"\0")
        return {"name": "Z3", "version": z3.get_version_string(),
                "binding_sha256": bindings.hexdigest(), "library_path": str(library),
                "library_sha256": sha256(_read_artifact(library)).hexdigest()}
    except (AttributeError, IndexError, TypeError, OSError, ValueError) as exc:
        raise OptimizationRejected("E_HIA_OPT_SOLVER_IDENTITY: " + str(exc)) from exc


def _policy(value):
    result = dict(DEFAULT_POLICY if value is None else value)
    if set(result) != set(DEFAULT_POLICY) or result["schema"] != POLICY_SCHEMA:
        raise OptimizationRejected("E_HIA_OPT_POLICY: exact policy fields are required")
    if type(result["target"]) is not str or result["target"] not in TARGETS:
        raise OptimizationRejected("E_HIA_OPT_TARGET: unsupported target")
    for key, maximum in (("timeout_ms", 30000), ("max_scalar_operations", 65536),
                         ("max_obligations", 4096)):
        if type(result[key]) is not int or not 0 <= result[key] <= maximum:
            raise OptimizationRejected("E_HIA_OPT_POLICY: invalid " + key)
    if result["preconditions"] != []:
        raise OptimizationRejected("E_HIA_OPT_PRECONDITION: unproved input assumptions are not admitted")
    return result


def _resource_inventory(document):
    return dict(sorted(Counter(op["op"] for fn in document["functions"] for b in fn["blocks"]
                               for op in b["ops"] if op["op"] not in PURE).items()))


def _skeleton(document):
    # Each barrier keeps its complete operands/results/attributes. Numeric
    # values of those operands are proved separately, not inferred from names.
    result = json.loads(json.dumps(document))
    for fn in result["functions"]:
        for b in fn["blocks"]:
            b["ops"] = [op for op in b["ops"] if op["op"] not in PURE]
    return result


def _segments(block):
    segment = []
    for op in block["ops"]:
        if op["op"] in PURE:
            segment.append(op)
        else:
            yield segment, op
            segment = []
    yield segment, None


def _term_names(term):
    if term["op"] == "ret":
        return term["values"]
    if term["op"] == "jump":
        return term["args"]
    if term["op"] == "branch":
        return [term["cond"], *term["then"]["args"], *term["else"]["args"]]
    return []


class _Encoder:
    def __init__(self, z3, inputs, context=None):
        self.z3 = z3
        self.env = dict(inputs)
        self.context = context if context is not None else (
            next(iter(inputs.values()))[0].ctx if inputs else z3.main_ctx())
        self.trap = z3.IntVal(0, ctx=self.context)

    def fail(self, condition, code):
        self.trap = self.z3.If(self.trap == 0, self.z3.If(condition, code, 0), self.trap)

    def integer(self, value, typ):
        return self.z3.BV2Int(value, is_signed=typ.startswith("i"))

    def operation(self, ins):
        z = self.z3
        op, attrs = ins["op"], ins["attrs"]
        args = [self.env[name] for name in ins["args"]]
        values = [pair[0] for pair in args]
        out = ins["out"][0]
        typ = out["type"]
        a = values[0] if values else None
        b = values[1] if len(values) > 1 else None
        if op == "const":
            value = (z.BoolVal(attrs["value"], ctx=self.context) if typ == "bool" else
                     z.BitVecVal(0 if typ == "unit" else attrs["value"], WIDTHS.get(typ, 8), ctx=self.context))
        elif op == "select":
            value = z.If(a, b, values[2])
        elif op == "int.cast":
            old = args[0][1]
            old_width, new_width = WIDTHS[old], WIDTHS[typ]
            if new_width < old_width:
                value = z.Extract(new_width - 1, 0, a)
            else:
                extend = z.SignExt if old.startswith("i") else z.ZeroExt
                value = extend(new_width - old_width, a)
            if attrs["mode"] == "checked":
                self.fail(self.integer(a, old) != self.integer(value, typ), 1)
        elif op in {f"int.{k}.{m}" for k in ("add", "sub", "mul") for m in ("wrap", "checked")}:
            kind = op.split(".")[1]
            arithmetic = lambda x, y: x + y if kind == "add" else x - y if kind == "sub" else x * y
            value = arithmetic(a, b)
            if op.endswith("checked"):
                extend = z.SignExt if typ.startswith("i") else z.ZeroExt
                width = WIDTHS[typ]
                self.fail(arithmetic(extend(width, a), extend(width, b)) != extend(width, value), 1)
        elif op == "int.neg.checked":
            value = -a
            extend = z.SignExt if typ.startswith("i") else z.ZeroExt
            self.fail(-extend(WIDTHS[typ], a) != extend(WIDTHS[typ], value), 1)
        elif op in {"int.div.checked", "int.rem.checked"}:
            self.fail(b == 0, 2)
            if typ.startswith("i"):
                self.fail(z.And(a == -(1 << (WIDTHS[typ] - 1)), b == -1), 1)
                value = a / b if op == "int.div.checked" else z.SRem(a, b)
            else:
                value = z.UDiv(a, b) if op == "int.div.checked" else z.URem(a, b)
        elif op in {"int.shl.checked", "int.shr.checked"}:
            self.fail(z.UGE(b, WIDTHS[typ]), 1)
            value = a << b if op == "int.shl.checked" else (a >> b if typ.startswith("i") else z.LShR(a, b))
        elif op in {"bit.and", "bit.or", "bit.xor"}:
            value = a & b if op == "bit.and" else a | b if op == "bit.or" else a ^ b
        elif op == "bit.not":
            value = ~a
        elif op in {"bool.not", "bool.and", "bool.or"}:
            value = z.Not(a) if op == "bool.not" else z.And(a, b) if op == "bool.and" else z.Or(a, b)
        elif op.startswith("compare."):
            kind = op.split(".")[1]
            operand_type = args[0][1]
            if kind in {"eq", "ne"}:
                value = a == b if kind == "eq" else a != b
            elif operand_type.startswith("i"):
                value = {"lt": lambda: a < b, "le": lambda: a <= b,
                         "gt": lambda: a > b, "ge": lambda: a >= b}[kind]()
            else:
                value = {"lt": z.ULT, "le": z.ULE, "gt": z.UGT, "ge": z.UGE}[kind](a, b)
        else:
            raise OptimizationRejected("E_HIA_OPT_UNSUPPORTED: scalar instruction " + op)
        self.env[out["name"]] = (value, typ)


def _fresh(z3, name, typ, context=None):
    return (z3.Bool(name, ctx=context) if typ == "bool" else z3.BitVecVal(0, 8, ctx=context) if typ == "unit"
            else z3.BitVec(name, WIDTHS[typ], ctx=context), typ)


def verify_optimization(base, candidate, policy=None):
    """Return verified/rejected/unknown/timeout; only verified may be built.

    All modeled inputs are quantified by an UNSAT counterexample query. CFG,
    resource transitions, calls and all exits retain their order. VM ticks and
    solver/CPU costs are not language observables and are reported separately.
    No profile supplied by a producer can turn UNKNOWN into VERIFIED.
    """
    started = time.monotonic_ns()
    policy = _policy(policy)
    report = {"schema": SCHEMA, "status": "unknown", "target": policy["target"],
              "policy": policy, "policy_sha256": _digest(policy), "checker_sha256": checker_identity(),
              "preconditions": [], "obligations": [], "resource_delta": {},
              "structural_preconditions": ["both inputs pass canonical core admission",
                  "identical signatures, CFG edges and ordered resource/call operations",
                  "all scalar inputs in their declared finite widths; no asserted input assumptions"],
              "target_constraints": {"triple": policy["target"], "pointer_width": 64,
                  "foreign_abi": "scalar-only exports", "resources": "preserve exact modeled trace",
                  "optimization_budget": "policy deadline and obligation/operation limits"},
              "claims": {"whole_language_soundness_proved": False, "backend_refinement_proved": False,
                         "native_execution_qualified": False, "arbitrary_rewrites_supported": False,
                         "deployment_authority": False}}

    def finish(status, reason):
        report.update(status=status, reason=reason, elapsed_ns=time.monotonic_ns() - started)
        report["verification_sha256"] = _digest(report)
        return report

    try:
        original, revised = verify_program(base), verify_program(candidate)
    except (HIAProgramRejected, ValueError) as exc:
        return finish("rejected", "Core admission failed: " + str(exc))
    report.update(base_sha256=original.sha256, candidate_sha256=revised.sha256,
                  base_input_sha256=original.input_sha256, candidate_input_sha256=revised.input_sha256)
    left, right = original.as_dict(), revised.as_dict()
    if left["schema"] not in QUALIFIED_CORE_SCHEMAS or right["schema"] not in QUALIFIED_CORE_SCHEMAS:
        return finish("unknown", "Core schema outside qualified primitive v1-v7 optimization profile")
    if _skeleton(left) != _skeleton(right):
        return finish("unknown", "CFG, interface, ordered effects or resource operations differ")
    report["resource_delta"] = {"ordered_resource_operations_preserved": True,
                                "before": _resource_inventory(left), "after": _resource_inventory(right),
                                "allocation_failure_sequence_preserved_under_core_model": False,
                                "vm_tick_count_preserved": False, "native_cost_change_measured": False}
    count = sum(op["op"] in PURE for d in (left, right) for fn in d["functions"]
                for b in fn["blocks"] for op in b["ops"])
    if count > policy["max_scalar_operations"]:
        return finish("unknown", "scalar verification operation budget exceeded")
    if policy["timeout_ms"] == 0:
        return finish("timeout", "verification deadline exhausted before solving")
    try:
        import z3
    except ImportError:
        return finish("unknown", "optional pinned z3-solver is unavailable")
    if z3.get_version_string() != PINNED_Z3_VERSION:
        return finish("unknown", "SMT solver version differs from the qualified profile")
    try:
        report["solver"] = _solver_identity(z3)
    except OptimizationRejected as exc:
        return finish("unknown", str(exc))
    # Z3's default context cannot be concurrently manipulated. Every request
    # owns all its ASTs and solver in a separate context, including constants
    # and empty disjunctions. No process-global solver lock is assumed.
    context = z3.Context()
    deadline = started + policy["timeout_ms"] * 1_000_000
    for fi, (lf, rf) in enumerate(zip(left["functions"], right["functions"])):
        for bi, (lb, rb) in enumerate(zip(lf["blocks"], rf["blocks"])):
            # Separate namespaces prevent an adversarial parameter such as
            # 's0_value' from aliasing a later effect output named 'value'.
            inputs = {p["name"]: _fresh(z3, f"f{fi}.b{bi}.input:{p['name']}", p["type"], context)
                      for p in lb["params"] if p["type"] in SCALARS}
            le, re = _Encoder(z3, inputs, context), _Encoder(z3, inputs, context)
            for si, ((ls, barrier), (rs, _)) in enumerate(zip(_segments(lb), _segments(rb))):
                if len(report["obligations"]) >= policy["max_obligations"]:
                    return finish("unknown", "proof-obligation budget exceeded")
                remaining = (deadline - time.monotonic_ns()) // 1_000_000
                if remaining <= 0:
                    return finish("timeout", "total verification deadline exhausted")
                try:
                    for op in ls:
                        le.operation(op)
                    for op in rs:
                        re.operation(op)
                    observed = barrier["args"] if barrier is not None else _term_names(lb["term"])
                    differences = []
                    for name in observed:
                        if name not in le.env and name not in re.env:
                            continue  # exact resource operands already agree in the skeleton
                        if name not in le.env or name not in re.env or le.env[name][1] != re.env[name][1]:
                            return finish("unknown", "scalar effect operand correspondence is unavailable")
                        differences.append(le.env[name][0] != re.env[name][0])
                    different_values = z3.Or(*differences) if differences else z3.BoolVal(False, ctx=context)
                    mismatch = z3.Or(le.trap != re.trap,
                                     z3.And(le.trap == 0, re.trap == 0, different_values))
                except (KeyError, OptimizationRejected, z3.Z3Exception) as exc:
                    return finish("unknown", "unsupported symbolic correspondence: " + str(exc))
                solver = z3.Solver(ctx=context)
                solver.add(mismatch)
                smt = solver.to_smt2()
                if len(smt.encode()) > 2 * 1024 * 1024:
                    return finish("unknown", "symbolic query byte budget exceeded")
                remaining = (deadline - time.monotonic_ns()) // 1_000_000
                if remaining <= 0:
                    return finish("timeout", "verification deadline exhausted while encoding")
                solver.set(timeout=int(remaining))
                outcome = solver.check()
                obligation = {"function": lf["name"], "block": lb["id"], "segment": si,
                              "observed": observed, "result": str(outcome),
                              "smt2_sha256": sha256(smt.encode()).hexdigest(), "smt2": smt}
                report["obligations"].append(obligation)
                if time.monotonic_ns() >= deadline:
                    return finish("timeout", "total verification deadline exhausted during solving")
                if outcome == z3.sat:
                    obligation["counterexample"] = {str(k): str(solver.model()[k]) for k in solver.model().decls()}
                    return finish("rejected", "a scalar/effect/trap counterexample exists")
                if outcome != z3.unsat:
                    obligation["reason_unknown"] = solver.reason_unknown()
                    return finish("timeout" if "timeout" in solver.reason_unknown() else "unknown",
                                  "solver did not establish equivalence")
                # The barrier itself is identical, receives equal values, and
                # starts from the same memory/resource state. Its successful
                # outputs may be arbitrary but are shared by both executions.
                # If it traps, both executions stop at this same barrier.
                le.trap = re.trap = z3.IntVal(0, ctx=context)
                if barrier is not None:
                    for output in barrier["out"]:
                        if output["type"] in SCALARS:
                            shared = _fresh(z3, f"f{fi}.b{bi}.effect:{si}:{output['name']}", output["type"], context)
                            le.env[output["name"]] = re.env[output["name"]] = shared
    if checker_identity() != report["checker_sha256"]:
        return finish("unknown", "checker source changed during verification")
    try:
        if _solver_identity(z3) != report["solver"]:
            return finish("unknown", "SMT implementation changed during verification")
    except OptimizationRejected as exc:
        return finish("unknown", str(exc))
    if time.monotonic_ns() >= deadline:
        return finish("timeout", "verification deadline exhausted before final admission")
    report["claims"].update(core_scalar_effect_equivalence_checked=True,
                            all_scalar_inputs_in_declared_widths=True,
                            cfg_and_resource_protocol_preserved=True)
    report["resource_delta"].update(allocation_failure_sequence_preserved_under_core_model=True,
                                    resource_trace_equivalence_checked=True,
                                    peak_live_bytes_change_under_core_model=0)
    return finish("verified", "all compositional scalar/effect/trap obligations are UNSAT")


def require_verified(base, candidate, policy=None):
    result = verify_optimization(base, candidate, policy)
    if result["status"] != "verified":
        raise OptimizationRejected("E_HIA_OPT_NOT_VERIFIED: " + result["status"] + ": " + result["reason"])
    return result


def fold_constants(program):
    """An untrusted proposal generator; publication still requires verification.

    Only nontrapping, known-value scalar expressions are replaced. Resource
    operations remain barriers. The independent SMT encoder is not reused.
    """
    from .hia_program_runtime import _Machine, HIAProgramTrap
    checked = verify_program(program)
    data = checked.as_dict()
    replacements = 0
    for fn in data["functions"]:
        for block in fn["blocks"]:
            constants = {}
            evaluator = _Machine(checked, 1000000, 0, None, 64)
            for index, op in enumerate(block["ops"]):
                if op["op"] == "const":
                    constants[op["out"][0]["name"]] = op["attrs"]["value"]
                elif op["op"] in PURE and all(name in constants for name in op["args"]):
                    try:
                        evaluator.operation(op, constants, 0)
                    except HIAProgramTrap:
                        continue
                    value = constants[op["out"][0]["name"]]
                    constants[op["out"][0]["name"]] = value
                    block["ops"][index] = {"op": "const", "args": [], "out": op["out"], "attrs": {"value": value}}
                    replacements += 1
    return verify_program(data), {"rule": "constant-evaluation-proposal.v1", "replacements": replacements,
                                  "equivalence_authority": False}


def build_optimized_native(base, candidate, output, *, policy=None, clang="clang", kind="shared"):
    """Recheck equivalence, then compile and bind the exact final artifact.

    Neither a caller's receipt nor a claimed checksum is accepted as proof.
    Native compiler/loader correctness remains an explicit external assumption.
    """
    from .hia_program_llvm import build_program_native, _read_artifact
    from .artifact_publication import publish_verified, verify_published, withdraw_own_link
    # Freeze both caller-owned inputs before the proof. A concurrent mutation
    # of a producer dict cannot substitute another candidate after verification.
    original, program = verify_program(base), verify_program(candidate)
    verified = require_verified(original, program, policy)
    destination = Path(output).absolute()
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise OptimizationRejected("E_HIA_OPT_OUTPUT: new path in an existing directory required")
    import z3

    def recheck():
        if (checker_identity() != verified["checker_sha256"]
                or _solver_identity(z3) != verified["solver"]):
            raise OptimizationRejected("E_HIA_OPT_STALE: checker or SMT implementation changed during build")

    with tempfile.TemporaryDirectory(prefix=".hia-optimized-", dir=destination.parent) as temporary:
        stage = Path(temporary) / ("verified.so" if kind == "shared" else "verified.o")
        native = build_program_native(program, stage, clang=clang, kind=kind, target=verified["target"])
        data = _read_artifact(stage)
        if sha256(data).hexdigest() != native["artifact_sha256"]:
            raise OptimizationRejected("E_HIA_OPT_ARTIFACT: staged native bytes changed")
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
            "verification": verified, "native": native,
            "binding_sha256": _digest({"base": verified["base_sha256"], "candidate": program.sha256,
                                        "verification": verified["verification_sha256"],
                                        "artifact": native["artifact_sha256"],
                                        "compiler": native["toolchain"]["sha256"], "target": native["target"]}),
            "claims": {"unverified_candidate_published": False, "final_artifact_bound": True,
                       "performance_qualified": False, "backend_refinement_proved": False}}
