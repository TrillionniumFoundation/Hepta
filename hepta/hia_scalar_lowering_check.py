"""All-input validation of a closed scalar Core-to-LLVM lowering profile.

The reference is the existing audited HIA scalar SMT encoding. The other
side parses the actual emitted internal LLVM function, including its guards,
overflow intrinsics and poison conditions. Unknown syntax, loops, unsupported
types and solver uncertainty cannot pass. This checker has no publication
authority and does not establish LLVM-to-machine-code refinement, C ABI,
resource safety, concurrency or whole-language soundness.
"""
from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import re
import time

from .hia_program import SCALARS, WIDTHS, verify_program
from .hia_program_llvm import emit_program_llvm
from .hia_optimization import PURE, PINNED_Z3_VERSION, _Encoder, _fresh, _solver_identity


SCHEMA = "hepta.hia.scalar-lowering-check.v1"
MAX_OPERATIONS = 128
MAX_LLVM_BYTES = 1_048_576
MAX_LLVM_STEPS = 8192
_NAME = r"%[A-Za-z_][A-Za-z_0-9]*"
_VALUE = rf"(?:{_NAME}|-?\d+|true|false)"


class ScalarLoweringRejected(ValueError):
    pass


def _require(condition, message):
    if not condition:
        raise ScalarLoweringRejected(message)


def _width(token):
    _require(type(token) is str and len(token) <= 2 and token in {"1", "8", "16", "32", "64"},
             "LLVM integer width is outside the selected profile")
    return int(token)


def checker_identity():
    digest = sha256()
    for name in ("hia_scalar_lowering_check.py", "hia_optimization.py", "hia_program.py", "hia_opcodes.py", "hia_semantic_kernel.py",
                 "hia_program_runtime.py", "hia_program_llvm.py", "hia_schema.py"):
        digest.update(name.encode() + b"\0" + Path(__file__).with_name(name).read_bytes() + b"\0")
    return digest.hexdigest()


class _LLVM:
    def __init__(self, z, context, text, fn, inputs, function_index, module, allowed_indices, call_stack=()):
        self.z, self.context = z, context
        self.text, self.module = text, module
        _require(function_index not in call_stack, "recursive LLVM call is outside the selected proof profile")
        self.allowed_indices, self.call_stack = allowed_indices, (*call_stack, function_index)
        self.return_type = fn["returns"][0]
        entry_index = next(index for index, block in enumerate(fn["blocks"]) if block["id"] == fn["entry"])
        self.entry = f"b{entry_index}"
        self.env = {f"%p_{entry_index}_{index}": value for index, (value, _) in enumerate(inputs.values())}
        types = {"bool": "i1", "unit": "i8", "usize": "i64", "isize": "i64"}
        def llvm_type(typ):
            return types.get(typ, "i" + typ[1:])
        parameters = ", ".join(f"{llvm_type(p['type'])} %p_{entry_index}_{index}"
                               for index, p in enumerate(fn["params"]))
        symbol = f"__hia_fn_{function_index}"
        header = f"define internal {llvm_type(self.return_type)} @{symbol}({parameters}) {{"
        definitions = re.findall(rf"(?m)^define [^\n]*@{symbol}\([^\n]*$", text)
        _require(definitions == [header], "selected LLVM function signature is missing or ambiguous")
        body = text.split("\n" + header + "\n", 1)
        _require(len(body) == 2, "selected LLVM definition is not a complete module line")
        body = body[1].split("\n}\n", 1)
        _require(len(body) == 2, "unterminated LLVM function")
        self.blocks = {}
        label = None
        for raw in body[0].splitlines():
            line = raw.strip()
            if not line:
                continue
            if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*:", line):
                label = line[:-1]
                _require(label not in self.blocks, "duplicate LLVM block")
                self.blocks[label] = []
            else:
                _require(label is not None, "LLVM instruction outside a block")
                self.blocks[label].append(line)
        _require(self.entry in self.blocks, "selected LLVM entry block is missing")
        _require(next(iter(self.blocks)) == self.entry, "LLVM entry order differs from selected Core entry")
        definitions = list(self.env)
        for lines in self.blocks.values():
            for line in lines:
                match = re.fullmatch(rf"({_NAME}) = (.+)", line)
                if match:
                    definitions.append(match[1])
        _require(len(definitions) == len(set(definitions)), "duplicate LLVM SSA definition")
        self.aborted = z.BoolVal(False, ctx=context)
        self.poison = z.BoolVal(False, ctx=context)
        self.path = z.BoolVal(True, ctx=context)
        self.steps = 0

    def value(self, token, bits):
        z = self.z
        _require(bits in {1, 8, 16, 32, 64}, "LLVM integer width is outside the selected profile")
        if token.startswith("%"):
            _require(token in self.env, "undefined LLVM value")
            value = self.env[token]
        elif bits == 1 and token in {"true", "false"}:
            value = z.BoolVal(token == "true", ctx=self.context)
        else:
            _require(len(token) <= 21 and re.fullmatch(r"-?\d+", token) is not None,
                     "unsupported LLVM literal")
            literal = int(token)
            _require(-(1 << (bits - 1)) <= literal < (1 << bits),
                     "LLVM literal is outside the selected representable range")
            value = z.BitVecVal(literal, bits, ctx=self.context)
        _require((bits == 1 and z.is_bool(value)) or
                 (bits != 1 and z.is_bv(value) and value.size() == bits),
                 "LLVM value type mismatch")
        return value

    def assigned(self, expression):
        z = self.z
        match = re.fullmatch(r"call i(\d+) @__hia_fn_(\d+)\((.*)\)", expression)
        if match:
            bits, number, arguments = match.groups()
            bits = _width(bits)
            _require(len(number) <= 4 and str(int(number)) == number, "unsupported LLVM call identity")
            number = int(number)
            _require(number in self.allowed_indices, "unaudited internal LLVM call")
            function = self.module["functions"][number]
            pieces = [] if not arguments else arguments.split(", ")
            _require(len(pieces) == len(function["params"]), "LLVM call arity differs")
            incoming = {}
            for param, piece in zip(function["params"], pieces):
                argument = re.fullmatch(rf"i(\d+) ({_VALUE})", piece)
                _require(argument is not None, "unknown LLVM call argument")
                argument_width = _width(argument[1])
                _require(argument_width == WIDTHS.get(param["type"], 1 if param["type"] == "bool" else 8),
                         "LLVM call argument type differs from signature")
                incoming[param["name"]] = (self.value(argument[2], argument_width), param["type"])
            child = _LLVM(z, self.context, self.text, function, incoming, number, self.module,
                          self.allowed_indices, self.call_stack)
            returns, abort, poison = child.execute()
            value, returned = _merge(z, self.context, returns, function["returns"][0])
            _require((bits == 1 and z.is_bool(value)) or
                     (bits != 1 and z.is_bv(value) and value.size() == bits),
                     "LLVM call return type differs")
            self.steps += child.steps
            self.aborted = z.Or(self.aborted, z.And(self.path, abort))
            self.poison = z.Or(self.poison, z.And(self.path, poison))
            self.path = z.And(self.path, returned)
            return value
        match = re.fullmatch(rf"(add|sub|mul|and|or|xor|shl|lshr|ashr|udiv|sdiv|urem|srem) i(\d+) ({_VALUE}), ({_VALUE})", expression)
        if match:
            op, bits, left, right = match.groups()
            bits = _width(bits)
            a, b = self.value(left, bits), self.value(right, bits)
            if bits == 1:
                _require(op in {"and", "or", "xor"}, "unsupported i1 arithmetic")
                return {"and": z.And, "or": z.Or, "xor": z.Xor}[op](a, b)
            if op in {"shl", "lshr", "ashr"}:
                self.poison = z.Or(self.poison, z.And(self.path, z.UGE(b, bits)))
            if op in {"udiv", "sdiv", "urem", "srem"}:
                bad = b == 0
                if op in {"sdiv", "srem"}:
                    bad = z.Or(bad, z.And(a == -(1 << (bits - 1)), b == -1))
                self.poison = z.Or(self.poison, z.And(self.path, bad))
            return {"add": lambda: a + b, "sub": lambda: a - b, "mul": lambda: a * b,
                    "and": lambda: a & b, "or": lambda: a | b, "xor": lambda: a ^ b,
                    "shl": lambda: a << b, "lshr": lambda: z.LShR(a, b), "ashr": lambda: a >> b,
                    "udiv": lambda: z.UDiv(a, b), "sdiv": lambda: a / b,
                    "urem": lambda: z.URem(a, b), "srem": lambda: z.SRem(a, b)}[op]()
        match = re.fullmatch(rf"icmp (eq|ne|slt|sle|sgt|sge|ult|ule|ugt|uge) i(\d+) ({_VALUE}), ({_VALUE})", expression)
        if match:
            op, bits, left, right = match.groups()
            bits = _width(bits)
            a, b = self.value(left, bits), self.value(right, bits)
            _require(bits != 1 or op in {"eq", "ne"}, "unsupported i1 ordering")
            return {"eq": lambda: a == b, "ne": lambda: a != b,
                    "slt": lambda: a < b, "sle": lambda: a <= b,
                    "sgt": lambda: a > b, "sge": lambda: a >= b,
                    "ult": lambda: z.ULT(a, b), "ule": lambda: z.ULE(a, b),
                    "ugt": lambda: z.UGT(a, b), "uge": lambda: z.UGE(a, b)}[op]()
        match = re.fullmatch(rf"(sext|zext|trunc) i(\d+) ({_VALUE}) to i(\d+)", expression)
        if match:
            op, before, token, after = match.groups()
            before, after = _width(before), _width(after)
            a = self.value(token, before)
            _require(before != 1 and after != 1 and
                     (after < before if op == "trunc" else before < after), "invalid LLVM cast")
            return (z.Extract(after - 1, 0, a) if op == "trunc" else
                    (z.SignExt if op == "sext" else z.ZeroExt)(after - before, a))
        match = re.fullmatch(rf"select i1 ({_VALUE}), i(\d+) ({_VALUE}), i(\d+) ({_VALUE})", expression)
        if match:
            condition, bits, yes, other_bits, no = match.groups()
            _require(bits == other_bits, "select type mismatch")
            bits = _width(bits)
            return z.If(self.value(condition, 1), self.value(yes, bits), self.value(no, bits))
        match = re.fullmatch(rf"call \{{ i(\d+), i1 \}} @llvm\.([su])(add|sub|mul)\.with\.overflow\.i(\d+)\(i(\d+) ({_VALUE}), i(\d+) ({_VALUE})\)", expression)
        if match:
            bits, sign, op, intrinsic_bits, left_bits, left, right_bits, right = match.groups()
            _require(bits == intrinsic_bits == left_bits == right_bits, "overflow intrinsic type mismatch")
            bits = _width(bits)
            a, b = self.value(left, bits), self.value(right, bits)
            operation = {"add": lambda x, y: x + y, "sub": lambda x, y: x - y,
                         "mul": lambda x, y: x * y}[op]
            value = operation(a, b)
            extension = z.SignExt if sign == "s" else z.ZeroExt
            wide = operation(extension(bits, a), extension(bits, b))
            return (value, wide != extension(bits, value))
        match = re.fullmatch(rf"extractvalue \{{ i(\d+), i1 \}} ({_NAME}), ([01])", expression)
        if match:
            bits, token, index = match.groups()
            bits = _width(bits)
            pair = self.env.get(token)
            _require(type(pair) is tuple and len(pair) == 2 and
                     z.is_bv(pair[0]) and pair[0].size() == bits and z.is_bool(pair[1]),
                     "overflow pair type mismatch")
            return pair[int(index)]
        raise ScalarLoweringRejected("LLVM expression is outside the audited profile: " + expression)

    def execute(self):
        z = self.z
        graph = {}
        for label, lines in self.blocks.items():
            _require(lines, "empty LLVM block")
            term = lines[-1]
            branch = re.fullmatch(rf"br i1 ({_VALUE}), label %([A-Za-z_0-9]+), label %([A-Za-z_0-9]+)", term)
            jump = re.fullmatch(r"br label %([A-Za-z_0-9]+)", term)
            graph[label] = list(branch.groups()[1:]) if branch else [jump[1]] if jump else []
        _acyclic(graph)
        predecessors = {name: {origin for origin, targets in graph.items() if name in targets} for name in graph}
        pending = [(self.entry, None, dict(self.env), self.path)]
        reached, returns = set(), []
        while pending:
            label, previous, self.env, self.path = pending.pop()
            reached.add(label)
            lines = self.blocks[label]
            seen_non_phi = False
            for index, line in enumerate(lines):
                self.steps += 1
                _require(self.steps <= MAX_LLVM_STEPS, "LLVM instruction/path budget exceeded")
                match = re.fullmatch(rf"({_NAME}) = (.+)", line)
                if match:
                    name, expression = match.groups()
                    _require(name not in self.env and index < len(lines) - 1, "duplicate SSA or missing terminator")
                    phi = re.fullmatch(r"phi i(\d+) (.+)", expression)
                    if phi:
                        _require(not seen_non_phi and previous is not None, "misplaced LLVM PHI")
                        bits, incoming = phi.groups()
                        bits = _width(bits)
                        pieces = re.findall(rf"\[ ({_VALUE}), %([A-Za-z_0-9]+) \]", incoming)
                        _require(", ".join(f"[ {value}, %{origin} ]" for value, origin in pieces) == incoming and
                                 len({origin for _, origin in pieces}) == len(pieces) and
                                 {origin for _, origin in pieces} == predecessors[label], "malformed LLVM PHI")
                        values = [value for value, origin in pieces if origin == previous]
                        _require(len(values) == 1, "LLVM PHI lacks incoming edge")
                        self.env[name] = self.value(values[0], bits)
                    else:
                        seen_non_phi = True
                        self.env[name] = self.assigned(expression)
                    continue
                if line == "call void @abort()":
                    _require(lines[index:] == [line, "unreachable"], "abort must end the selected path")
                    self.aborted = z.Or(self.aborted, self.path)
                    break
                _require(index == len(lines) - 1, "instruction after LLVM terminator")
                branch = re.fullmatch(rf"br i1 ({_VALUE}), label %([A-Za-z_0-9]+), label %([A-Za-z_0-9]+)", line)
                if branch:
                    token, yes, no = branch.groups()
                    condition = self.value(token, 1)
                    pending.append((yes, label, dict(self.env), z.And(self.path, condition)))
                    pending.append((no, label, dict(self.env), z.And(self.path, z.Not(condition))))
                    break
                jump = re.fullmatch(r"br label %([A-Za-z_0-9]+)", line)
                if jump:
                    pending.append((jump[1], label, dict(self.env), self.path))
                    break
                returned = re.fullmatch(rf"ret i(\d+) ({_VALUE})", line)
                if returned:
                    bits, token = returned.groups()
                    returns.append((self.path, self.value(token, _width(bits))))
                    break
                raise ScalarLoweringRejected("LLVM terminator is outside the audited profile: " + line)
        _require(reached == set(self.blocks), "unaccounted LLVM blocks")
        return returns, self.aborted, self.poison


def _acyclic(graph):
    indegree = {name: 0 for name in graph}
    for targets in graph.values():
        for target in set(targets):
            _require(target in graph, "unknown control-flow target")
            indegree[target] += 1
    pending = [name for name, count in indegree.items() if count == 0]
    seen = 0
    while pending:
        name = pending.pop()
        seen += 1
        for target in set(graph[name]):
            indegree[target] -= 1
            if indegree[target] == 0:
                pending.append(target)
    _require(seen == len(graph), "control-flow cycles are outside selected proof profile")


def _merge(z, context, returns, typ):
    value = _fresh(z, "unused", typ, context)[0]
    # A value on a path that did not return is deliberately unconstrained;
    # every consumer carries the explicit returned predicate alongside it.
    for path, result in returns:
        _require(result.sort() == value.sort(), "symbolic return type differs")
        value = z.If(path, result, value)
    returned = z.Or(*[path for path, _ in returns]) if returns else z.BoolVal(False, ctx=context)
    return value, returned


def _reference(z, context, fn, inputs, module):
    blocks = {block["id"]: block for block in fn["blocks"]}
    graph = {}
    for name, block in blocks.items():
        term = block["term"]
        graph[name] = ([term["target"]] if term["op"] == "jump" else
                       [term["then"]["target"], term["else"]["target"]] if term["op"] == "branch" else [])
    _acyclic(graph)
    pending = [(fn["entry"], inputs, z.BoolVal(True, ctx=context))]
    returns, aborted, steps = [], z.BoolVal(False, ctx=context), 0
    while pending:
        name, values, path = pending.pop()
        block = blocks[name]
        encoder = _Encoder(z, values, context)
        for operation in block["ops"]:
            if operation["op"] == "call":
                callee = next(f for f in module["functions"] if f["name"] == operation["attrs"]["function"])
                incoming = {p["name"]: encoder.env[arg]
                            for p, arg in zip(callee["params"], operation["args"])}
                results, abort, child_steps = _reference(z, context, callee, incoming, module)
                value, _returned = _merge(z, context, results, callee["returns"][0])
                steps += child_steps
                encoder.trap = z.If(encoder.trap != 0, encoder.trap, z.If(abort, 1, 0))
                output = operation["out"][0]
                encoder.env[output["name"]] = (value, output["type"])
            else:
                encoder.operation(operation)
        steps += len(block["ops"]) + 1
        _require(steps <= MAX_LLVM_STEPS, "Core path budget exceeded")
        aborted = z.Or(aborted, z.And(path, encoder.trap != 0))
        active = z.And(path, encoder.trap == 0)
        term = block["term"]
        if term["op"] == "ret":
            returns.append((active, encoder.env[term["values"][0]][0]))
        elif term["op"] == "trap":
            aborted = z.Or(aborted, active)
        else:
            edges = [(term, active)] if term["op"] == "jump" else [
                (term["then"], z.And(active, encoder.env[term["cond"]][0])),
                (term["else"], z.And(active, z.Not(encoder.env[term["cond"]][0])))]
            for edge, condition in edges:
                target = blocks[edge["target"]]
                incoming = {p["name"]: encoder.env[arg] for p, arg in zip(target["params"], edge["args"])}
                pending.append((target["id"], incoming, condition))
    return returns, aborted, steps


def verify_scalar_lowering(program, *, function=None, llvm_text=None, timeout_ms=5000):
    """Check one scalar, acyclic, single-result actual emitted body.

    An optional LLVM text enables mutation audits. Reports are observations,
    never an importable admission certificate. The native wrapper/ABI and
    machine code are explicitly outside this selected internal-body theorem.
    """
    _require(type(timeout_ms) is int and 1 <= timeout_ms <= 30000, "invalid solver timeout")
    checked = verify_program(program)
    document = checked.as_dict()
    _require(checked.structured_bytes is None, "selected lowering check requires explicit primitive Core")
    if function is None:
        _require(len(document["functions"]) == 1, "select a function in a multi-function Core")
        function = document["functions"][0]["name"]
    indices = [index for index, fn in enumerate(document["functions"]) if fn["name"] == function]
    _require(type(function) is str and len(indices) == 1, "unknown selected Core function")
    function_index = indices[0]
    fn = document["functions"][function_index]
    functions = {f["name"]: f for f in document["functions"]}
    pending, reachable = [function], set()
    operations, call_graph = [], {}
    while pending:
        name = pending.pop()
        if name in reachable:
            continue
        reachable.add(name)
        _require(len(reachable) <= 16, "selected call graph exceeds function budget")
        current = functions[name]
        _require(len(current["params"]) <= 32 and all(p["type"] in SCALARS - {"unit"} for p in current["params"]) and
                 len(current["returns"]) == 1 and current["returns"][0] in SCALARS and len(current["blocks"]) <= 128 and
                 all(p["type"] in SCALARS for block in current["blocks"] for p in block["params"]),
                 "selected lowering check requires scalar arguments and one result")
        current_ops = [op for block in current["blocks"] for op in block["ops"]]
        operations.extend(current_ops)
        _require(len(operations) <= MAX_OPERATIONS and all(op["op"] in PURE | {"call"} for op in current_ops),
                 "unsupported scalar lowering operation")
        calls = {op["attrs"]["function"] for op in current_ops if op["op"] == "call"}
        call_graph[name] = calls
        pending.extend(calls)
    _acyclic(call_graph)
    emitted = emit_program_llvm(checked)
    text = emitted.text if llvm_text is None else llvm_text
    _require(type(text) is str and len(text) <= MAX_LLVM_BYTES and
             len(text.encode("utf-8")) <= MAX_LLVM_BYTES, "LLVM text budget exceeded")
    # The model treats abort as an external terminating runtime primitive.
    # A custom definition/alias must not inherit that assumption. The actual
    # C runtime and link-time interposition remain outside this internal-body
    # check; a declaration alone is not a native execution guarantee.
    abort_declarations = re.findall(r'(?m)^[ \t]*(?:declare|define)[^\n]*@(?:abort|"abort")\([^\n]*$', text)
    _require(abort_declarations == ["declare void @abort() noreturn"] and
             re.search(r'(?m)^[ \t]*@(?:abort|"abort")[ \t]*=', text) is None and
             re.search(r"(?m)^[ \t]*module[ \t]+asm\b", text) is None,
             "selected lowering check requires the unchanged external abort primitive")
    import z3 as z
    _require(z.get_version_string() == PINNED_Z3_VERSION, "pinned Z3 version required")
    identity, solver_identity = checker_identity(), _solver_identity(z)
    context = z.Context()
    inputs = {p["name"]: _fresh(z, p["name"], p["type"], context) for p in fn["params"]}
    expected, core_abort, _ = _reference(z, context, fn, inputs, document)
    allowed_indices = frozenset(index for index, target in enumerate(document["functions"]) if target["name"] in reachable)
    observed, abort, poison = _LLVM(z, context, text, fn, inputs, function_index, document, allowed_indices).execute()
    disagreements = []
    for core_path, core_value in expected:
        for llvm_path, llvm_value in observed:
            _require(core_value.sort() == llvm_value.sort(), "selected LLVM return type differs")
            disagreements.append(z.And(core_path, llvm_path, core_value != llvm_value))
    core_returned = z.Or(*[path for path, _ in expected]) if expected else z.BoolVal(False, ctx=context)
    llvm_returned = z.Or(*[path for path, _ in observed]) if observed else z.BoolVal(False, ctx=context)
    mismatch = z.Or(poison, abort != core_abort, core_returned != llvm_returned, *disagreements)
    solver = z.Solver(ctx=context)
    solver.set(timeout=timeout_ms)
    solver.add(mismatch)
    query = solver.sexpr()
    _require(len(query.encode()) <= MAX_LLVM_BYTES, "SMT query budget exceeded")
    started = time.monotonic_ns()
    outcome = solver.check()
    wall_ns = time.monotonic_ns() - started
    _require(checker_identity() == identity and _solver_identity(z) == solver_identity,
             "checker or solver changed during validation")
    status = "verified" if outcome == z.unsat else "refuted" if outcome == z.sat else "unknown"
    report = {"schema": SCHEMA, "status": status, "verified": outcome == z.unsat,
              "core_sha256": checked.sha256, "llvm_sha256": sha256(text.encode()).hexdigest(),
              "actual_emitter_output": text == emitted.text, "checker_sha256": identity,
              "solver": solver_identity, "solver_result": str(outcome), "solver_wall_ns": wall_ns,
              "query_sha256": sha256(query.encode()).hexdigest(), "smtlib": query,
              "function": fn["name"], "function_index": function_index, "operations": len(operations),
              "call_closure": sorted(reachable),
              "blocks": len(fn["blocks"]), "core_return_paths": len(expected), "llvm_return_paths": len(observed),
              "claims": {"selected_body_all_input_value_and_abort_equivalence": outcome == z.unsat,
                         "selected_body_poison_unreachable": outcome == z.unsat,
                         "all_programs_of_this_profile_proved": False,
                         "core_encoder_correspondence_proved": False,
                         "llvm_parser_correspondence_proved": False,
                         "native_backend_refinement_proved": False,
                         "c_abi_proved": False, "resource_or_concurrency_safety_proved": False,
                         "whole_language_soundness_proved": False,
                         "publication_authority": False}}
    if outcome == z.sat:
        model = solver.model()
        report["counterexample"] = {name: str(model.eval(value, model_completion=True))
                                    for name, (value, _) in inputs.items()}
    elif outcome != z.unsat:
        report["reason"] = solver.reason_unknown()
    return report
