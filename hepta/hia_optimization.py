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
from .hia_cnf_native import (
    SAT, UNSAT, WORD_PRODUCT_EXCEEDS, WORD_UNSIGNED_DIV, WORD_UNSIGNED_REM,
    bitblast_clauses, core_circuit, selected_cnf,
)
from .hia_opcodes import RESOURCES, TRAP_CODES
from .hia_scalar_symbolic_native import SymbolicRecipeRejected, selected_scalar_symbolic

SCHEMA = "hepta.hia.optimization-verification.v1"
QUALIFIED_CORE_SCHEMAS = frozenset("hepta.hia.program.v" + str(version) for version in range(1, 8))
NATIVE_CORE_SCHEMA = "hepta.hia.program.v8"
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
    for name in ("hia_optimization.py", "hia_program.py", "hia_capability_flow.py", "hia_opcodes.py", "hia_schema.py",
                 "hia_program_composite.py", "hia_json_preflight.py",
                 "hia_program_runtime.py", "hia_bounded_memory.py"):
        digest.update(name.encode() + b"\0" + Path(__file__).with_name(name).read_bytes() + b"\0")
    native = selected_scalar_symbolic()
    if native is not None:
        digest.update(Path(__file__).with_name("hia_scalar_symbolic_native.py").read_bytes())
        digest.update(bytes.fromhex(native.image_sha256))
    cnf = selected_cnf()
    if cnf is not None:
        digest.update(Path(__file__).with_name("hia_cnf_native.py").read_bytes())
        digest.update(bytes.fromhex(cnf.image_sha256))
    return digest.hexdigest()


def _native_circuit_decision(cnf, circuit, deadline):
    if circuit is None:
        return None
    remaining = (deadline - time.monotonic_ns()) // 1_000_000
    if remaining <= 0:
        return None
    nodes, returns, traps = circuit
    # Carry clauses for checked 64-bit arithmetic require substantially
    # more unit propagation than pure bitwise obligations.
    steps = min(2_000_000, remaining * 1000) if traps is not None else min(200_000, remaining * 100)
    # Nonlinear words benefit from conflict learning, even when only their
    # ordered fault conditions survive projection into the observed circuit.
    nonlinear = any(operation in (WORD_UNSIGNED_DIV, WORD_UNSIGNED_REM, WORD_PRODUCT_EXCEEDS)
                    for operation, *_ in nodes)
    result = cnf.solve_circuit(nodes, returns, steps=steps, traps=traps, learning=nonlinear)
    if result is None or result[0] not in (SAT, UNSAT):
        return None
    verdict, model, steps, variables, clauses, frame = result
    formula = frame[:24] + bytes(8) + frame[32:]
    discharge = {"method": "native_hia_core_circuit", "image_sha256": cnf.image_sha256,
                 "formula_sha256": sha256(formula).hexdigest(), "variables": variables,
                 "clauses": clauses, "steps": steps}
    return verdict, model, discharge, formula


def _native_word_table_decision(cnf, circuit, deadline):
    if circuit is None:
        return None
    remaining_ms = (deadline - time.monotonic_ns()) // 1_000_000
    if remaining_ms <= 0:
        return None
    nodes, observed, traps = circuit
    answer = cnf.search_word_table(nodes, observed, traps=traps, work=remaining_ms * 16_384)
    if answer is None:
        return None
    verdict, model, assignments, query = answer
    discharge = {"method": "native_hia_exhaustive_word_table", "image_sha256": cnf.image_sha256,
                 "formula_sha256": sha256(query).hexdigest(), "assignments_checked": assignments}
    return verdict, model, discharge, query


def _native_solver_identity(cnf):
    return {"name": "HIA", "version": "core-circuit-cnf.v2",
            "binding_sha256": sha256(Path(__file__).with_name("hia_cnf_native.py").read_bytes()).hexdigest(),
            "library_sha256": cnf.image_sha256}


def _native_circuit_witness(before, after, function, model):
    from .hia_program_runtime import HIAProgramTrap, execute_program
    from .hia_scalar_reference_native import selected_scalar_reference

    # HIABVC01 allocates variable 1 to true. The initial input nodes
    # then allocate consecutive, little-endian variable numbers.
    reference = selected_scalar_reference()
    model >>= 1
    arguments, model_values = [], {}
    for parameter in function["params"]:
        typ = parameter["type"]
        width = 1 if typ == "bool" else WIDTHS[typ]
        raw = model & ((1 << width) - 1)
        model >>= width
        if typ == "bool":
            typed = bool(raw)
            model_values[parameter["name"]] = str(typed)
        else:
            typed = raw - (1 << width) if typ.startswith("i") and raw >> (width - 1) else raw
            model_values[parameter["name"]] = str(raw)
        arguments.append(typed)
    name = function["name"]

    def observe(program):
        try:
            return execute_program(program, name, arguments, max_steps=512)["values"], None
        except HIAProgramTrap as error:
            if error.code not in TRAP_CODES:
                raise
            return None, error.code

    previous, revised = observe(before), observe(after)
    if previous == revised:
        return None
    if selected_scalar_reference() is not reference:
        return None
    return model_values, {"function": name, "arguments": arguments, "base_values": previous[0],
                          "candidate_values": revised[0], "base_trap": previous[1], "candidate_trap": revised[1],
                          "scalar_reference_image_sha256": None if reference is None else reference.image_sha256}


def _native_block_circuits(before, after, limit):
    sources = [list(_segments(block)) for block in (before, after)]
    if len(sources[0]) > limit:
        return None
    exits = _term_names(before["term"])
    remaining = set(exits)
    live_after = []
    for left, right in reversed(list(zip(*sources, strict=True))):
        live_after.append(remaining.copy())
        for operations, barrier in (left, right):
            for operation in operations:
                remaining.update(operation["args"])
            if barrier is not None:
                remaining.update(barrier["args"])
    params = before["params"]
    results = []
    for (left, barrier), (right, _), live in zip(*sources, reversed(live_after), strict=True):
        # Core admission and the identical ordered skeleton pair opaque
        # resources by binding, including aliasing and ownership transitions.
        # Only the scalar operands and values need a bit-vector obligation.
        resources = {item["name"] for item in params if item["type"] in RESOURCES}
        scalar_params = [item for item in params if item["name"] not in resources]
        if barrier is None:
            term = before["term"]
            observed = [name for name in exits if name not in resources]
        else:
            known = []
            for operations in (left, right):
                declarations = {item["name"]: item for item in params}
                for operation in operations:
                    declarations.update((item["name"], item) for item in operation["out"])
                known.append(declarations)
            carried = [item for name, item in known[0].items() if name in live and name in known[1]]
            if any(known[1][item["name"]] != item for item in carried):
                return None
            # Before an identical effect, prove equal operands and any
            # scalar live values that the continuation will pair again.
            observed = list(dict.fromkeys(name for name in (
                *barrier["args"], *(item["name"] for item in carried)) if name not in resources))
            term = {"op": "ret", "values": observed}
        circuit = core_circuit({"params": scalar_params, "ops": left, "term": term},
                               {"params": scalar_params, "ops": right, "term": term}, observed)
        if circuit is None:
            return None
        results.append((observed, circuit))
        if barrier is not None:
            params = [*carried, *barrier["out"]]
    return results


def _native_core_obligations(cnf, before, after, left, right, deadline, limit):
    pairs = [(fi, bi, lf, lb, rb)
             for fi, (lf, rf) in enumerate(zip(left["functions"], right["functions"], strict=True))
             for bi, (lb, rb) in enumerate(zip(lf["blocks"], rf["blocks"], strict=True))]
    prepared = []
    for fi, bi, function, lb, rb in pairs:
        segments = _native_block_circuits(lb, rb, limit - len(prepared))
        if segments is None:
            return None
        can_replay = (len(segments) == 1 and len(function["blocks"]) == 1
                      and lb["term"]["op"] in {"ret", "trap"}
                      and all(item["type"] not in RESOURCES for item in function["params"]))
        prepared.extend((fi, bi, function, lb["id"], index, observed, circuit, can_replay)
                        for index, (observed, circuit) in enumerate(segments))
    obligations = []
    for fi, bi, function, block, index, observed, circuit, can_replay in prepared:
        outcome = _native_circuit_decision(cnf, circuit, deadline)
        if outcome is None:
            return None
        verdict, model, evidence, formula = outcome
        obligation = {"function": function["name"], "block": block, "segment": index,
                      "observed": observed, "result": "unsat" if verdict == UNSAT else "sat",
                      "cnf_encoding": "hepta.hia.cnf-sparse-le.v2",
                      "cnf_frame_hex": formula.hex(), "discharge": evidence}
        obligations.append(obligation)
        if verdict == SAT:
            # A model of an arbitrary block input is not proof that the
            # input is reachable, or that the full function disagrees.
            if not can_replay:
                return None
            witness = _native_circuit_witness(before, after, function, model)
            if witness is None:
                return None
            fields, replay = witness
            obligation["counterexample"] = {f"f{fi}.b{bi}.input:{name}": value for name, value in fields.items()}
            obligation["counterexample_replay"] = replay
            break
    return obligations


def _native_unsat(cnf, z3, mismatch, deadline):
    if cnf is None:
        return None
    remaining = (deadline - time.monotonic_ns()) // 1_000_000
    if remaining < 4:
        return None
    formula = bitblast_clauses(z3, mismatch, timeout_ms=min(100, remaining // 4))
    if formula is None:
        return None
    remaining = (deadline - time.monotonic_ns()) // 1_000_000
    if remaining <= 0:
        return None
    variables, clauses = formula
    result, _, steps = cnf.solve_sparse(variables, clauses, steps=min(200_000, remaining * 100))
    if result != UNSAT:
        return None  # The legacy counterexample/model interface remains intact.
    return {"method": "native_hia_cnf", "image_sha256": cnf.image_sha256,
            "formula_sha256": _digest([variables, clauses]), "variables": variables,
            "clauses": len(clauses), "steps": steps}


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
    """Admit an exact, detached policy; never ask caller subclasses to compare.

    Python list/str subclasses can spoof equality to [] or the schema string.
    Merely copying the outer mapping also retains its mutable list. Both are
    inappropriate for a proof receipt that asserts zero preconditions.
    """
    if value is not None and type(value) is not dict:
        raise OptimizationRejected("E_HIA_OPT_POLICY: built-in policy dictionary required")
    source = DEFAULT_POLICY if value is None else value
    try:
        # Capture a finite field snapshot once. Below, all scalar types are
        # exact built-ins, and the only permitted list is reconstructed empty.
        items = tuple(source.items())
    except RuntimeError as exc:
        raise OptimizationRejected("E_HIA_OPT_POLICY: policy changed during capture") from exc
    if (len(items) != len(DEFAULT_POLICY)
            or any(type(key) is not str for key, _ in items)):
        raise OptimizationRejected("E_HIA_OPT_POLICY: exact policy fields are required")
    result = dict(items)
    if (set(result) != set(DEFAULT_POLICY)
            or type(result["schema"]) is not str
            or result["schema"] != POLICY_SCHEMA):
        raise OptimizationRejected("E_HIA_OPT_POLICY: exact policy fields are required")
    if type(result["target"]) is not str or result["target"] not in TARGETS:
        raise OptimizationRejected("E_HIA_OPT_TARGET: unsupported target")
    for key, maximum in (("timeout_ms", 30000), ("max_scalar_operations", 65536),
                         ("max_obligations", 4096)):
        if type(result[key]) is not int or not 0 <= result[key] <= maximum:
            raise OptimizationRejected("E_HIA_OPT_POLICY: invalid " + key)
    if type(result["preconditions"]) is not list or len(result["preconditions"]) != 0:
        raise OptimizationRejected("E_HIA_OPT_PRECONDITION: unproved input assumptions are not admitted")
    return {"schema": POLICY_SCHEMA, "target": result["target"],
            "timeout_ms": result["timeout_ms"],
            "max_scalar_operations": result["max_scalar_operations"],
            "max_obligations": result["max_obligations"],
            "preconditions": []}


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
        self.native_symbolic = selected_scalar_symbolic()

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
        if self.native_symbolic is not None:
            source = args[0][1] if args else typ
            try:
                value, traps = self.native_symbolic.operation(z, self.context, op, attrs, typ, source, values)
            except SymbolicRecipeRejected as error:
                raise OptimizationRejected(str(error)) from error
            for code, condition in traps:
                self.fail(condition, 1 if code == 'overflow' else 2)
        else:
            value = self._reference_operation(z, op, attrs, typ, args, values)
        self.env[out["name"]] = (value, typ)

    def _reference_operation(self, z, op, attrs, typ, args, values):
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
        return value


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

    def verified():
        if time.monotonic_ns() >= deadline:
            return finish("timeout", "verification deadline exhausted before final admission")
        report["claims"].update(core_scalar_effect_equivalence_checked=True,
                                all_scalar_inputs_in_declared_widths=True,
                                cfg_and_resource_protocol_preserved=True)
        report["resource_delta"].update(allocation_failure_sequence_preserved_under_core_model=True,
                                        resource_trace_equivalence_checked=True,
                                        peak_live_bytes_change_under_core_model=0)
        return finish("verified", "all compositional scalar/effect/trap obligations are UNSAT")

    try:
        original, revised = verify_program(base), verify_program(candidate)
    except (HIAProgramRejected, ValueError) as exc:
        return finish("rejected", "Core admission failed: " + str(exc))
    report.update(base_sha256=original.sha256, candidate_sha256=revised.sha256,
                  base_input_sha256=original.input_sha256, candidate_input_sha256=revised.input_sha256)
    left, right = original.as_dict(), revised.as_dict()
    legacy_schema = left["schema"] in QUALIFIED_CORE_SCHEMAS and right["schema"] in QUALIFIED_CORE_SCHEMAS
    native_cnf = selected_cnf()
    if not legacy_schema and not (native_cnf is not None and left["schema"] == right["schema"] == NATIVE_CORE_SCHEMA):
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
    deadline = started + policy["timeout_ms"] * 1_000_000
    if native_cnf is not None:
        obligations = _native_core_obligations(native_cnf, original, revised, left, right,
                                               deadline, policy["max_obligations"])
        if obligations is not None:
            if checker_identity() != report["checker_sha256"]:
                return finish("unknown", "checker source changed during verification")
            report["solver"] = _native_solver_identity(native_cnf)
            report["obligations"] = obligations
            if obligations and obligations[-1]["result"] == "sat":
                if time.monotonic_ns() >= deadline:
                    return finish("timeout", "total verification deadline exhausted during witness replay")
                return finish("rejected", "a scalar/effect/trap counterexample exists")
            return verified()
    if not legacy_schema:
        return finish("unknown", "Core v8 obligations exceeded the installed native scalar circuit profile")
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
                cnf_evidence = None
                if native_cnf is not None and si == 0 and barrier is None:
                    outcome = _native_circuit_decision(native_cnf, core_circuit(lb, rb, observed), deadline)
                    if outcome is not None and outcome[0] == UNSAT:
                        cnf_evidence = outcome[2]
                if cnf_evidence is None:
                    cnf_evidence = _native_unsat(native_cnf, z3, mismatch, deadline)
                remaining = (deadline - time.monotonic_ns()) // 1_000_000
                if remaining <= 0:
                    return finish("timeout", "verification deadline exhausted while solving")
                if cnf_evidence is None:
                    solver.set(timeout=int(remaining))
                    outcome = solver.check()
                else:
                    outcome = z3.unsat
                obligation = {"function": lf["name"], "block": lb["id"], "segment": si,
                              "observed": observed, "result": str(outcome),
                              "smt2_sha256": sha256(smt.encode()).hexdigest(), "smt2": smt}
                if cnf_evidence is not None:
                    obligation["discharge"] = cnf_evidence
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
    return verified()


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
    if verified["solver"]["name"] == "HIA":
        def solver_identity():
            cnf = selected_cnf()
            return None if cnf is None else _native_solver_identity(cnf)
    else:
        import z3

        def solver_identity():
            return _solver_identity(z3)

    def recheck():
        if (checker_identity() != verified["checker_sha256"]
                or solver_identity() != verified["solver"]):
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
