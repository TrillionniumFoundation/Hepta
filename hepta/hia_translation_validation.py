"""Fail-closed, all-input translation validation for a finite scalar HIA profile.

The canonical HIA verifier remains the structural/resource authority.  This
module first re-runs it, then encodes the actual operations of a public scalar
function in Z3.  It asks whether *any* well-typed input changes the return values
or the first specified trap code.  Only UNSAT is a successful equivalence check.

This is an executable SMT encoder, not a machine-checked refinement proof of
the encoder, HIA verifier, LLVM, linker, or native code.  The supported profile
has acyclic CFGs, no calls, memory, FFI, concurrency, or floating point.  A
serialized receipt is evidence, never authority: its consumer must call
``verify_translation_receipt`` or repeat ``validate_translation`` on exact bytes.
"""
from __future__ import annotations

from collections import deque
from hashlib import sha256
import importlib
import json
from pathlib import Path

from .hia_program import (
    HIAProgramRejected, SCALARS, TRAP_CODES, WIDTHS, integer_range, verify_program,
)

SCHEMA = "hepta.hia.translation-validation.v1"
QUALIFIED_CORE_SCHEMAS = frozenset("hepta.hia.program.v" + str(version) for version in range(1, 8))
PROFILE = "hia.scalar-acyclic-bitvector-traps.v1"
MAX_BLOCKS = 128
MAX_OPERATIONS = 2048
MAX_PARAMETERS = 32
MAX_RETURNS = 16
MAX_TIMEOUT_MS = 60_000
_TRAP_TAGS = {code: index + 1 for index, code in enumerate(sorted(TRAP_CODES))}
_OPS = frozenset({
    "const", "int.neg.checked", "int.cast", "select",
    "bit.and", "bit.or", "bit.xor", "bit.not",
    "bool.and", "bool.or", "bool.not",
    "int.div.checked", "int.rem.checked", "int.shl.checked", "int.shr.checked",
} | {f"int.{kind}.{mode}" for kind in ("add", "sub", "mul")
     for mode in ("checked", "wrap")}
  | {f"compare.{kind}" for kind in ("eq", "ne", "lt", "le", "gt", "ge")})


class _OutsideProfile(Exception):
    pass


def _z3_module():
    """Keep the solver optional; absence cannot silently approve a rewrite."""
    return importlib.import_module("z3")


def _implementation_digest():
    return sha256(Path(__file__).read_bytes()).hexdigest()


def _receipt(function, timeout_ms):
    return {
        "schema": SCHEMA, "profile": PROFILE, "status": "unknown",
        "function": function, "scope": "selected_public_scalar_function",
        "before_sha256": None, "after_sha256": None,
        "before_input_sha256": None, "after_input_sha256": None,
        "validator_sha256": _implementation_digest(),
        "structural_verification": {"before": False, "after": False},
        "reason": None, "counterexample": None,
        "solver": {"name": "z3", "version": None, "result": "not_run",
                   "timeout_ms": timeout_ms},
        "claims": {
            "all_input_behavior_equivalence_proved": False,
            "first_trap_code_preserved": False,
            "canonical_core_reverified": False,
            "resource_bounds_proved": False,
            "encoder_refinement_machine_proved": False,
            "whole_language_soundness_proved": False,
            "backend_refinement_proved": False,
            "global_optimality_proved": False,
            "serialized_receipt_authorizes_execution": False,
        },
        "limits": [
            "Only the selected public scalar function is compared; other exports are not proved equivalent.",
            "Acyclic CFGs and the listed scalar operations only; calls, loops and resources return unknown.",
            "Exact return values and the first specified trap code are observable; runtime/host budgets are not.",
            "The Python encoder, canonical verifier and Z3 solver are trusted; encoder refinement is not machine-proved.",
            "No LLVM/native equivalence, resource quota, timing, energy or global-optimality proof is implied.",
            "Receipts must be rebound to exact bytes and the proof recomputed at the point of use.",
        ],
    }


def _signature(fn):
    return ([p["type"] for p in fn["params"]], fn["returns"])


def _profile(fn):
    blocks = {block["id"]: block for block in fn["blocks"]}
    if len(blocks) > MAX_BLOCKS or sum(len(b["ops"]) for b in blocks.values()) > MAX_OPERATIONS:
        raise _OutsideProfile("symbolic_program_budget_exceeded")
    if len(fn["params"]) > MAX_PARAMETERS or len(fn["returns"]) > MAX_RETURNS:
        raise _OutsideProfile("symbolic_signature_budget_exceeded")
    if set(fn["effects"]) - {"trap"}:
        raise _OutsideProfile("resource_effects_outside_scalar_profile")
    declared = [p["type"] for p in fn["params"]] + fn["returns"]
    declared += [p["type"] for b in blocks.values() for p in b["params"]]
    declared += [p["type"] for b in blocks.values() for op in b["ops"] for p in op["out"]]
    if any(typ not in SCALARS for typ in declared):
        raise _OutsideProfile("resource_types_outside_scalar_profile")
    if any(op["op"] not in _OPS for b in blocks.values() for op in b["ops"]):
        raise _OutsideProfile("operation_outside_scalar_profile")
    successors, degree = {}, {ident: 0 for ident in blocks}
    for ident, block in blocks.items():
        term = block["term"]
        edges = ([term] if term["op"] == "jump" else
                 [term["then"], term["else"]] if term["op"] == "branch" else [])
        successors[ident] = [edge["target"] for edge in edges]
        for target in successors[ident]:
            degree[target] += 1
    pending = deque(sorted(ident for ident in blocks if degree[ident] == 0))
    order = []
    while pending:
        ident = pending.popleft()
        order.append(ident)
        for target in successors[ident]:
            degree[target] -= 1
            if degree[target] == 0:
                pending.append(target)
    if len(order) != len(blocks):
        raise _OutsideProfile("cyclic_cfg_outside_profile")
    return blocks, order


class _Encoder:
    def __init__(self, z3):
        self.z = z3
        # Independent proof jobs must not share Z3's process-global context.
        # Z3 AST/context ownership is explicit so parallel compiler workers
        # cannot accidentally mix symbolic inputs or solver state.
        self.context = z3.Context()

    def any(self, expressions):
        expressions = list(expressions)
        return self.z.Or(*expressions) if expressions else self.z.BoolVal(False, self.context)

    def literal(self, value, typ):
        if typ == "unit":
            return None
        if typ == "bool":
            return self.z.BoolVal(value, self.context)
        return self.z.BitVecVal(value, WIDTHS[typ], self.context)

    def zero(self, typ):
        return self.literal(None if typ == "unit" else False if typ == "bool" else 0, typ)

    def input(self, index, typ):
        if typ == "unit":
            return None
        if typ == "bool":
            return self.z.Bool(f"input_{index}", self.context)
        return self.z.BitVec(f"input_{index}", WIDTHS[typ], self.context)

    def choose(self, guard, left, right, typ):
        return None if typ == "unit" else self.z.If(guard, left, right)

    def operation(self, op, env, types):
        """Return a value and ordered (trap-code, condition) pairs.

        Checked arithmetic uses extended bitvectors, never an approximate
        real-valued cost or a sampled input set.  In particular remainder has
        the dividend's sign, and signed MIN/-1 traps for both div and rem.
        """
        z = self.z
        name, attrs = op["op"], op["attrs"]
        args = [env[n] for n in op["args"]]
        typ = op["out"][0]["type"]
        source = types[op["args"][0]] if args else typ
        traps = []
        if name == "const":
            value = self.literal(attrs["value"], typ)
        elif name.startswith("int.") and name.split(".")[1] in {"add", "sub", "mul"}:
            a, b = args
            kind = name.split(".")[1]
            value = a + b if kind == "add" else a - b if kind == "sub" else a * b
            if name.endswith("checked"):
                width = WIDTHS[typ]
                extend = z.SignExt if typ.startswith("i") else z.ZeroExt
                ea, eb = extend(width, a), extend(width, b)
                full = ea + eb if kind == "add" else ea - eb if kind == "sub" else ea * eb
                lo, hi = integer_range(typ)
                ok = z.And(full >= lo, full <= hi) if typ.startswith("i") else z.ULE(full, hi)
                traps.append(("overflow", z.Not(ok)))
        elif name in {"int.div.checked", "int.rem.checked"}:
            a, b = args
            traps.append(("division_by_zero", b == 0))
            if typ.startswith("i"):
                traps.append(("overflow", z.And(a == integer_range(typ)[0], b == -1)))
                value = a / b if name == "int.div.checked" else z.SRem(a, b)
            else:
                value = z.UDiv(a, b) if name == "int.div.checked" else z.URem(a, b)
        elif name in {"int.shl.checked", "int.shr.checked"}:
            a, b = args
            invalid = z.UGE(b, WIDTHS[typ])
            # UGE also rejects negative signed counts, represented by high bits.
            traps.append(("overflow", invalid))
            value = a << b if name == "int.shl.checked" else a >> b if typ.startswith("i") else z.LShR(a, b)
        elif name == "int.neg.checked":
            a = args[0]
            traps.append(("overflow", a == integer_range(typ)[0] if typ.startswith("i") else a != 0))
            value = -a
        elif name in {"bit.and", "bit.or", "bit.xor"}:
            a, b = args
            value = a & b if name == "bit.and" else a | b if name == "bit.or" else a ^ b
        elif name == "bit.not":
            value = ~args[0]
        elif name.startswith("compare."):
            a, b = args
            kind = name.split(".")[1]
            if kind in {"eq", "ne"}:
                value = a == b if kind == "eq" else a != b
            elif source.startswith("i"):
                value = {"lt": lambda: a < b, "le": lambda: a <= b,
                         "gt": lambda: a > b, "ge": lambda: a >= b}[kind]()
            else:
                value = {"lt": z.ULT, "le": z.ULE, "gt": z.UGT, "ge": z.UGE}[kind](a, b)
        elif name == "bool.not":
            value = z.Not(args[0])
        elif name == "bool.and":
            value = z.And(*args)
        elif name == "bool.or":
            value = z.Or(*args)
        elif name == "int.cast":
            a = args[0]
            src_width, dst_width = WIDTHS[source], WIDTHS[typ]
            extend = z.SignExt if source.startswith("i") else z.ZeroExt
            value = (z.Extract(dst_width - 1, 0, a) if dst_width < src_width else
                     extend(dst_width - src_width, a) if dst_width > src_width else a)
            if attrs["mode"] == "checked":
                width = max(src_width, dst_width) + 1
                full = extend(width - src_width, a)
                lo, hi = integer_range(typ)
                traps.append(("overflow", z.Or(full < lo, full > hi)))
        elif name == "select":
            value = self.choose(args[0], args[1], args[2], typ)
        else:
            raise _OutsideProfile("unhandled_scalar_operation")
        return value, traps

    def function(self, fn, inputs, blocks, order):
        z = self.z
        incoming = {ident: [] for ident in blocks}
        incoming[fn["entry"]].append((z.BoolVal(True, self.context), inputs))
        outcomes = []
        for ident in order:
            block = blocks[ident]
            arrivals = incoming[ident]
            guard = self.any(g for g, _ in arrivals)
            types = {p["name"]: p["type"] for p in block["params"]}
            env = {}
            for index, param in enumerate(block["params"]):
                value = self.zero(param["type"])
                if len(arrivals) == 1:
                    # On every execution of this block its only edge guard is
                    # true, so its argument is the phi value. Off that guard,
                    # values are unobservable: traps, outcomes and successor
                    # edges below retain the complete reachability guard.
                    # Scalar BV expressions themselves are total in Z3.
                    value = arrivals[0][1][index]
                else:
                    # Preserve zero-arrival defaults and all guarded merges.
                    for edge_guard, values in arrivals:
                        value = self.choose(edge_guard, values[index], value, param["type"])
                env[param["name"]] = value
            for op in block["ops"]:
                value, traps = self.operation(op, env, types)
                for code, condition in traps:
                    outcomes.append((z.And(guard, condition), _TRAP_TAGS[code], None))
                    guard = z.And(guard, z.Not(condition))
                output = op["out"][0]
                env[output["name"]], types[output["name"]] = value, output["type"]
            term = block["term"]
            if term["op"] == "ret":
                outcomes.append((guard, 0, [env[name] for name in term["values"]]))
            elif term["op"] == "trap":
                outcomes.append((guard, _TRAP_TAGS[term["code"]], None))
            else:
                edges = [(guard, term)] if term["op"] == "jump" else [
                    (z.And(guard, env[term["cond"]]), term["then"]),
                    (z.And(guard, z.Not(env[term["cond"]])), term["else"]),
                ]
                for edge_guard, edge in edges:
                    incoming[edge["target"]].append((edge_guard, [env[n] for n in edge["args"]]))
        tag = z.IntVal(-1, self.context)  # Acyclic verified control flow ends in ret/trap.
        values = [self.zero(typ) for typ in fn["returns"]]
        for guard, code, returned in outcomes:
            tag = z.If(guard, code, tag)
            if returned is not None:
                values = [self.choose(guard, val, old, typ)
                          for val, old, typ in zip(returned, values, fn["returns"])]
        return tag, values

    def concrete(self, model, value, typ):
        if typ == "unit":
            return None
        result = model.eval(value, model_completion=True)
        if typ == "bool":
            return self.z.is_true(result)
        number = result.as_long()
        if typ.startswith("i") and number >= 1 << (WIDTHS[typ] - 1):
            number -= 1 << WIDTHS[typ]
        return number


def _execute_observation(checked, function, arguments):
    from .hia_program_runtime import HIAProgramTrap, execute_program
    try:
        result = execute_program(checked, function, arguments,
                                 max_steps=MAX_OPERATIONS + MAX_BLOCKS + 2)
        return {"status": "returned", "values": result["values"]}
    except HIAProgramTrap as exc:
        return {"status": "trapped", "code": exc.code}


def validate_translation(before, after, *, function=None, timeout_ms=2000):
    """Compare all typed inputs of one function; return a JSON evidence receipt.

    ``proved`` means Z3 found the exact behavioral-difference query UNSAT in the
    declared scalar profile.  ``disproved`` includes a concrete counterexample
    independently replayed by the canonical interpreter.  Invalid programs,
    unsupported constructs, unavailable solver, and solver exhaustion all yield
    ``unknown``.  Missing/changed signatures do not constitute an equivalence
    proof.  If omitted, ``function`` is inferred only for single-function cores.
    """
    result = _receipt(function, timeout_ms)
    if type(timeout_ms) is not int or not 1 <= timeout_ms <= MAX_TIMEOUT_MS:
        result["reason"] = "invalid_solver_timeout"
        return result
    checked = {}
    for label, document in (("before", before), ("after", after)):
        try:
            checked[label] = verify_program(document)
        except HIAProgramRejected as exc:
            result["reason"] = f"invalid_{label}_program"
            result["validation_error"] = {"code": exc.code, "message": str(exc)}
            return result
        result["structural_verification"][label] = True
        result[f"{label}_sha256"] = checked[label].sha256
        result[f"{label}_input_sha256"] = checked[label].input_sha256
    result["claims"]["canonical_core_reverified"] = True
    if any(doc.as_dict()["schema"] not in QUALIFIED_CORE_SCHEMAS for doc in checked.values()):
        result["reason"] = "core_schema_outside_qualified_v1_v7_profile"
        return result
    functions = {label: {fn["name"]: fn for fn in doc.as_dict()["functions"]}
                 for label, doc in checked.items()}
    if function is None and all(len(fns) == 1 for fns in functions.values()):
        function = next(iter(functions["before"]))
    result["function"] = function
    if type(function) is not str or any(function not in fns for fns in functions.values()):
        result["reason"] = "missing_or_ambiguous_function"
        return result
    if any(function not in doc.scalar_entrypoints for doc in checked.values()):
        result["reason"] = "not_a_public_scalar_entrypoint"
        return result
    first, second = functions["before"][function], functions["after"][function]
    if _signature(first) != _signature(second):
        result["reason"] = "signature_mismatch"
        return result
    try:
        graphs = [_profile(fn) for fn in (first, second)]
    except _OutsideProfile as exc:
        result["reason"] = str(exc)
        return result
    try:
        z = _z3_module()
    except (ImportError, OSError):
        result["reason"] = "solver_unavailable"
        return result
    result["solver"]["version"] = z.get_version_string()
    try:
        encoder = _Encoder(z)
        inputs = [encoder.input(i, p["type"]) for i, p in enumerate(first["params"])]
        ltag, lvalues = encoder.function(first, inputs, *graphs[0])
        rtag, rvalues = encoder.function(second, inputs, *graphs[1])
        different_values = [left != right for left, right, typ in
                            zip(lvalues, rvalues, first["returns"]) if typ != "unit"]
        # Do not turn an accidental missing symbolic path into a vacuous
        # equality proof, even when both encodings would miss the same path.
        difference = z.Or(ltag < 0, rtag < 0, ltag != rtag,
                          z.And(ltag == 0, rtag == 0, encoder.any(different_values)))
        solver = z.Solver(ctx=encoder.context)
        solver.set(timeout=timeout_ms)
        solver.add(difference)
        verdict = solver.check()
        result["solver"]["result"] = str(verdict)
        if verdict == z.unsat:
            result["status"] = "proved"
            result["reason"] = "all_input_behavior_difference_unsatisfiable"
            result["claims"]["all_input_behavior_equivalence_proved"] = True
            result["claims"]["first_trap_code_preserved"] = True
        elif verdict == z.sat:
            model = solver.model()
            if model.eval(ltag).as_long() < 0 or model.eval(rtag).as_long() < 0:
                result["reason"] = "incomplete_symbolic_execution"
                return result
            arguments = [encoder.concrete(model, val, p["type"])
                         for val, p in zip(inputs, first["params"])]
            observations = {label: _execute_observation(doc, function, arguments)
                            for label, doc in checked.items()}
            if observations["before"] == observations["after"]:
                result["reason"] = "counterexample_replay_disagrees_with_encoder"
            else:
                result["status"] = "disproved"
                result["reason"] = "behavioral_counterexample_replayed"
                result["counterexample"] = {"arguments": arguments,
                                             "parameter_types": _signature(first)[0],
                                             **observations}
        else:
            result["reason"] = "solver_unknown"
            result["solver"]["reason_unknown"] = solver.reason_unknown()
    except z.Z3Exception as exc:
        result["reason"] = "solver_error"
        result["solver"]["error"] = str(exc)
    return result


def verify_translation_receipt(before, after, receipt, *, function=None, timeout_ms=2000):
    """Rebind and recompute a claimed proof; never execute a receipt's claim.

    Raises ``HIAProgramRejected`` for forged, stale, unsupported, or non-proved
    evidence.  A perfectly fabricated receipt still cannot approve wrong code:
    the all-input query is constructed again from independently verified bytes.
    """
    if type(receipt) is not dict or receipt.get("schema") != SCHEMA or receipt.get("status") != "proved":
        raise HIAProgramRejected("translation receipt does not claim a supported proof",
                                 "E_HIA_TRANSLATION_RECEIPT")
    requested = receipt.get("function") if function is None else function
    fresh = validate_translation(before, after, function=requested, timeout_ms=timeout_ms)
    keys = ("schema", "profile", "function", "scope", "before_sha256", "after_sha256",
            "before_input_sha256", "after_input_sha256", "validator_sha256")
    if any(type(receipt.get(key)) is not str or receipt[key] != fresh[key] for key in keys):
        raise HIAProgramRejected("translation receipt is not bound to the current program/profile",
                                 "E_HIA_TRANSLATION_RECEIPT")
    if fresh["status"] != "proved":
        raise HIAProgramRejected(f"translation proof could not be recomputed: {fresh['reason']}",
                                 "E_HIA_TRANSLATION_UNPROVED")
    return fresh
