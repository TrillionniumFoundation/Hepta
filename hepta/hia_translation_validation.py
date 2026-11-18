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

from .hia_scalar_symbolic_native import (
    MAX_BLOCKS, MAX_OPERATIONS, MAX_PARAMETERS, MAX_RETURNS, SymbolicRecipeRejected,
    selected_scalar_symbolic,
)
from .hia_scalar_proof_contract import (begin_scalar_proof, finish_scalar_proof,
                                        same_scalar_proof_scope)

SCHEMA = "hepta.hia.translation-validation.v1"
QUALIFIED_CORE_SCHEMAS = frozenset("hepta.hia.program.v" + str(version) for version in range(1, 8))
PROFILE = "hia.scalar-acyclic-bitvector-traps.v1"
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
            "The selected encoder, canonical verifier and Z3 solver are trusted; encoder refinement is not machine-proved.",
            "No LLVM/native equivalence, resource quota, timing, energy or global-optimality proof is implied.",
            "Receipts must be rebound to exact bytes and the proof recomputed at the point of use.",
        ],
    }


def _signature(fn):
    return ([p["type"] for p in fn["params"]], fn["returns"])


def _successors(block):
    term = block["term"]
    if term["op"] == "jump":
        return [term["target"]]
    if term["op"] == "branch":
        return [term["then"]["target"], term["else"]["target"]]
    return []


def _declared_types(fn, blocks):
    yield from (p["type"] for p in fn["params"])
    yield from fn["returns"]
    for block in blocks.values():
        yield from (p["type"] for p in block["params"])
        yield from (output["type"] for op in block["ops"] for output in op["out"])


def _profile(fn):
    blocks = {block["id"]: block for block in fn["blocks"]}
    native = selected_scalar_symbolic()
    if native is None:
        return _reference_profile(fn, blocks)
    names = sorted(blocks)
    operations = sum(len(b["ops"]) for b in blocks.values())
    parameters, returns = len(fn["params"]), len(fn["returns"])
    flags = 0
    if (len(blocks) <= MAX_BLOCKS and operations <= MAX_OPERATIONS
            and parameters <= MAX_PARAMETERS and returns <= MAX_RETURNS):
        flags = (bool(set(fn["effects"]) - {"trap"})
                 | (any(typ not in SCALARS for typ in _declared_types(fn, blocks)) << 1)
                 | (any(op["op"] not in _OPS for b in blocks.values() for op in b["ops"]) << 2))
    try:
        order, refusal = native.function_order(
            names, (_successors(blocks[name]) for name in names), operations, parameters, returns, flags)
    except SymbolicRecipeRejected as error:
        raise _OutsideProfile("native_symbolic_profile_unavailable") from error
    if refusal is not None:
        raise _OutsideProfile(refusal)
    return blocks, list(order)


def _reference_profile(fn, blocks):
    if len(blocks) > MAX_BLOCKS or sum(len(b["ops"]) for b in blocks.values()) > MAX_OPERATIONS:
        raise _OutsideProfile("symbolic_program_budget_exceeded")
    if len(fn["params"]) > MAX_PARAMETERS or len(fn["returns"]) > MAX_RETURNS:
        raise _OutsideProfile("symbolic_signature_budget_exceeded")
    if set(fn["effects"]) - {"trap"}:
        raise _OutsideProfile("resource_effects_outside_scalar_profile")
    if any(typ not in SCALARS for typ in _declared_types(fn, blocks)):
        raise _OutsideProfile("resource_types_outside_scalar_profile")
    if any(op["op"] not in _OPS for b in blocks.values() for op in b["ops"]):
        raise _OutsideProfile("operation_outside_scalar_profile")
    successors, degree = {}, {ident: 0 for ident in blocks}
    for ident, block in blocks.items():
        successors[ident] = _successors(block)
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
        self.native_symbolic = selected_scalar_symbolic()

    def any(self, expressions):
        guards = tuple(expressions)
        if self.native_symbolic is not None:
            return self.control("join", guards, edges=len(guards))[0]
        return self._reference_any(guards)

    def _reference_any(self, guards):
        return self.z.Or(*guards) if guards else self.z.BoolVal(False, self.context)

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
        if self.native_symbolic is not None:
            try:
                return self.native_symbolic.operation(z, self.context, name, attrs, typ, source, args,
                                                      translation=True)
            except SymbolicRecipeRejected as error:
                raise z.Z3Exception(str(error)) from error
        return self._reference_operation(z, name, attrs, typ, source, args)

    def _reference_operation(self, z, name, attrs, typ, source, args):
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

    def phi(self, arrivals, index, typ):
        if typ == "unit":
            return None
        if self.native_symbolic is not None:
            guards = tuple(guard for guard, _ in arrivals)
            values = tuple(values[index] for _, values in arrivals)
            return self.control("phi", (*guards, *values, self.zero(typ)), edges=len(guards))[0]
        if len(arrivals) == 1:
            # Off the sole incoming guard this value is never observed.
            return arrivals[0][1][index]
        value = self.zero(typ)
        for guard, values in arrivals:
            value = self.choose(guard, values[index], value, typ)
        return value

    def split(self, guard, condition):
        if self.native_symbolic is None:
            z = self.z
            return z.And(guard, condition), z.And(guard, z.Not(condition))
        return self.control("split", (guard, condition))

    def observe(self, guard, value, previous):
        if self.native_symbolic is None:
            return self.z.If(guard, value, previous)
        return self.control("observe", (guard, value, previous))[0]

    def control(self, kind, operands, *, edges=0):
        try:
            return self.native_symbolic.control(self.z, self.context, kind, operands, edges=edges)
        except SymbolicRecipeRejected as error:
            raise self.z.Z3Exception(str(error)) from error

    def function(self, fn, inputs, blocks, order):
        z = self.z
        incoming = {ident: [] for ident in blocks}
        incoming[fn["entry"]].append((z.BoolVal(True, self.context), inputs))
        outcomes = []
        for ident in order:
            block = blocks[ident]
            arrivals = incoming[ident]
            guard = self.any(guard for guard, _ in arrivals)
            types = {p["name"]: p["type"] for p in block["params"]}
            env = {param["name"]: self.phi(arrivals, index, param["type"])
                   for index, param in enumerate(block["params"])}
            for op in block["ops"]:
                value, traps = self.operation(op, env, types)
                for code, condition in traps:
                    trapped, guard = self.split(guard, condition)
                    outcomes.append((trapped, _TRAP_TAGS[code], None))
                output = op["out"][0]
                env[output["name"]], types[output["name"]] = value, output["type"]
            term = block["term"]
            if term["op"] == "ret":
                outcomes.append((guard, 0, [env[name] for name in term["values"]]))
            elif term["op"] == "trap":
                outcomes.append((guard, _TRAP_TAGS[term["code"]], None))
            else:
                if term["op"] == "jump":
                    edges = ((guard, term),)
                else:
                    yes, no = self.split(guard, env[term["cond"]])
                    edges = ((yes, term["then"]), (no, term["else"]))
                for edge_guard, edge in edges:
                    incoming[edge["target"]].append((edge_guard, [env[n] for n in edge["args"]]))
        tag = z.IntVal(-1, self.context)  # Acyclic verified control flow ends in ret/trap.
        values = [self.zero(typ) for typ in fn["returns"]]
        for guard, code, returned in outcomes:
            tag = self.observe(guard, code, tag)
            if returned is not None:
                values = [None if typ == "unit" else self.observe(guard, val, old)
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


def _partition_entry_equality(z, encoder, inputs, functions, difference):
    """Simplify an exhaustive input partition without assuming the guard.

    A symbolic divisor compared with a literal otherwise makes the solver
    rediscover constant propagation through its division circuit. For any
    input x and literal c, Q is exactly (x=c AND Q[x:=c]) OR
    (x!=c AND Q[(x=c):=false]). Both cases, including every trap and missing
    path tag, remain in the single original-timeout counterexample query.
    This is only a bounded preprocessing hint; no source branch is trusted.
    """
    for fn in functions:
        entry = next(block for block in fn["blocks"] if block["id"] == fn["entry"])
        if entry["term"]["op"] != "branch":
            continue
        params = {p["name"]: (index, p["type"]) for index, p in enumerate(entry["params"])}
        constants = {op["out"][0]["name"]: op for op in entry["ops"] if op["op"] == "const"}
        for op in entry["ops"]:
            if op["op"] != "compare.eq" or op["out"][0]["name"] != entry["term"]["cond"]:
                continue
            for name, constant in (op["args"], op["args"][::-1]):
                if name not in params or constant not in constants:
                    continue
                index, typ = params[name]
                if typ not in WIDTHS:
                    continue
                variable = inputs[index]
                literal = encoder.literal(constants[constant]["attrs"]["value"], typ)
                equal = variable == literal
                hit = z.simplify(z.substitute(difference, (variable, literal)))
                miss = z.simplify(z.substitute(difference,
                    (equal, z.BoolVal(False, encoder.context)),
                    (literal == variable, z.BoolVal(False, encoder.context))))
                return z.Or(z.And(equal, hit), z.And(z.Not(equal), miss)), {
                    "strategy": "exhaustive_entry_input_equality_split",
                    "parameter_index": index, "type": typ,
                    "value": constants[constant]["attrs"]["value"],
                    "input_assumptions": [], "partition_count": 2,
                }
    return difference, {"strategy": "unpartitioned", "input_assumptions": []}


def validate_translation(before, after, *, function=None, timeout_ms=2000):
    """Compare all typed inputs of one function; return a JSON evidence receipt.

    ``proved`` means Z3 found the exact behavioral-difference query UNSAT in the
    declared scalar profile.  ``disproved`` includes a concrete counterexample
    independently replayed by the canonical interpreter.  Invalid programs,
    unsupported constructs, unavailable solver, and solver exhaustion all yield
    ``unknown``.  Missing/changed signatures do not constitute an equivalence
    proof.  If omitted, ``function`` is inferred only for single-function cores.
    """
    scope = begin_scalar_proof("validate_translation")
    result = _receipt(function, timeout_ms)
    if type(timeout_ms) is not int or not 1 <= timeout_ms <= MAX_TIMEOUT_MS:
        result["reason"] = "invalid_solver_timeout"
        return finish_scalar_proof(result, scope)
    checked = {}
    for label, document in (("before", before), ("after", after)):
        try:
            checked[label] = verify_program(document)
        except HIAProgramRejected as exc:
            result["reason"] = f"invalid_{label}_program"
            result["validation_error"] = {"code": exc.code, "message": str(exc)}
            return finish_scalar_proof(result, scope)
        result["structural_verification"][label] = True
        result[f"{label}_sha256"] = checked[label].sha256
        result[f"{label}_input_sha256"] = checked[label].input_sha256
    result["claims"]["canonical_core_reverified"] = True
    if any(doc.as_dict()["schema"] not in QUALIFIED_CORE_SCHEMAS for doc in checked.values()):
        result["reason"] = "core_schema_outside_qualified_v1_v7_profile"
        return finish_scalar_proof(result, scope)
    functions = {label: {fn["name"]: fn for fn in doc.as_dict()["functions"]}
                 for label, doc in checked.items()}
    if function is None and all(len(fns) == 1 for fns in functions.values()):
        function = next(iter(functions["before"]))
    result["function"] = function
    if type(function) is not str or any(function not in fns for fns in functions.values()):
        result["reason"] = "missing_or_ambiguous_function"
        return finish_scalar_proof(result, scope)
    if any(function not in doc.scalar_entrypoints for doc in checked.values()):
        result["reason"] = "not_a_public_scalar_entrypoint"
        return finish_scalar_proof(result, scope)
    first, second = functions["before"][function], functions["after"][function]
    if _signature(first) != _signature(second):
        result["reason"] = "signature_mismatch"
        return finish_scalar_proof(result, scope)
    try:
        graphs = [_profile(fn) for fn in (first, second)]
    except _OutsideProfile as exc:
        result["reason"] = str(exc)
        return finish_scalar_proof(result, scope)
    try:
        z = _z3_module()
    except (ImportError, OSError):
        result["reason"] = "solver_unavailable"
        return finish_scalar_proof(result, scope)
    result["solver"]["version"] = z.get_version_string()
    try:
        from .hia_optimization import _solver_identity
        result["solver"]["identity"] = _solver_identity(z)
    except Exception as exc:
        result.update(reason="solver_identity_unavailable", error_type=type(exc).__name__)
        return finish_scalar_proof(result, scope)
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
        difference, preprocessing = _partition_entry_equality(
            z, encoder, inputs, (second, first), difference)
        result["solver"]["query_preprocessing"] = preprocessing
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
            # A SAT difference can be independent of some input bits (for
            # example an unconditional first trap on only one side). Complete
            # those inputs before reading either symbolic outcome tag, just as
            # concrete() does for the independent interpreter replay below.
            if (model.eval(ltag, model_completion=True).as_long() < 0
                    or model.eval(rtag, model_completion=True).as_long() < 0):
                result["reason"] = "incomplete_symbolic_execution"
                return finish_scalar_proof(result, scope)
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
    return finish_scalar_proof(result, scope)


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
    if not same_scalar_proof_scope(receipt, fresh):
        raise HIAProgramRejected("translation proof scope is missing, stale or altered",
                                 "E_HIA_TRANSLATION_RECEIPT")
    return fresh
