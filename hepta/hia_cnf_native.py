"""Transport Boolean clauses to the selected bounded HIA solver."""
from __future__ import annotations

import ctypes
from array import array
from dataclasses import dataclass
import os
import struct
from sys import byteorder

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_opcodes import WIDTHS


SOURCE = _source_resource_path('examples/hia_bootstrap/cnf.hepta')
SCHEMA = 'hepta.hia.cnf-native.v1'
SELECTOR = 'HEPTA_HIA_CNF_MANIFEST'
REQUEST = int.from_bytes(b'HIACNF01', 'little')
REPLY = int.from_bytes(b'HIACNR01', 'little')
CLAUSE_LIMIT = 8192
STEP_LIMIT = 10_000_000
WORKSPACE = 1024
SPARSE_REQUEST = int.from_bytes(b'HIACNX02', 'little')
BATCH_REQUEST = int.from_bytes(b'HIACNB03', 'little')
WATCHED_REQUEST = int.from_bytes(b'HIACNW04', 'little')
LEARNING_REQUEST = int.from_bytes(b'HIACNL05', 'little')
RESTART_REQUEST = int.from_bytes(b'HIACNG06', 'little')
SPARSE_REPLY = int.from_bytes(b'HIACNR02', 'little')
SPARSE_VARIABLES = 4096
SPARSE_CLAUSES = 65536
SPARSE_ENTRIES = 1 << 20
SPARSE_WORKSPACE = SPARSE_VARIABLES * 7
WATCH_HEADS = SPARSE_WORKSPACE + 8
WATCH_ROWS = WATCH_HEADS + (2 * SPARSE_VARIABLES + 2) * 8
WATCH_ROW_BYTES = 32
LEARNED_CLAUSES = 4096
LEARNED_ENTRIES = 262144
# Offsets relative to the workspace following the allocated watch rows.
LEARNING_REASONS = 2 * SPARSE_VARIABLES
LEARNING_SEEN = LEARNING_REASONS + 8 * SPARSE_VARIABLES
LEARNING_ORDER = LEARNING_SEEN + 2 * SPARSE_VARIABLES
LEARNING_HEAD = LEARNING_ORDER + 4 * (SPARSE_VARIABLES + 1)
LEARNING_PHASE = LEARNING_HEAD + 4
LEARNING_TEMP = LEARNING_PHASE + SPARSE_VARIABLES
LEARNING_TOKENS = LEARNING_TEMP + 2 * SPARSE_VARIABLES
LEARNING_BYTES = LEARNING_TOKENS + 2 * LEARNED_ENTRIES
CIRCUIT_REQUEST = int.from_bytes(b'HIABVC01', 'little')
GUARDED_CIRCUIT_REQUEST = int.from_bytes(b'HIABVG01', 'little')
CIRCUIT_NODES = 256
CIRCUIT_RETURNS = 16
CIRCUIT_CAPACITY = 192 * 1024
CIRCUIT_GATE_SLOTS = 8192
CIRCUIT_GATES_OFFSET = 32 + CIRCUIT_NODES * 128
CIRCUIT_WORKSPACE = CIRCUIT_GATES_OFFSET + 8 * CIRCUIT_GATE_SLOTS
UNKNOWN, SAT, UNSAT = range(3)
_CORE_WIDTHS = {'bool': 1, **WIDTHS}
_CORE_OPERATIONS = {'const': 2, 'bit.and': 3, 'bool.and': 3, 'bit.or': 4, 'bool.or': 4,
                    'bit.xor': 5, 'bit.not': 6, 'bool.not': 6, 'compare.eq': 7, 'compare.ne': 8,
                    'int.add.wrap': 9, 'int.sub.wrap': 10, 'select': 11,
                    'compare.lt': 12, 'compare.le': 13, 'compare.gt': 14, 'compare.ge': 15,
                    'int.cast': 20, 'int.add.checked': 22, 'int.sub.checked': 23,
                    'int.neg.checked': 23}


class NativeCnf(NativeHiaJsonImage):
    def solve(self, variables, clauses, *, steps):
        if (type(variables) is not int or not 0 <= variables <= 64
                or len(clauses) > CLAUSE_LIMIT or type(steps) is not int or not 0 <= steps <= STEP_LIMIT):
            raise ValueError('formula or work budget exceeds the HIA Boolean profile')
        frame = struct.pack('<4Q', REQUEST, variables, len(clauses), steps)
        frame += b''.join(struct.pack('<2Q', positive, negative) for positive, negative in clauses)
        source = ctypes.create_string_buffer(frame, len(frame))
        reply = ctypes.create_string_buffer(32)
        scratch = ctypes.create_string_buffer(WORKSPACE)
        if self._entry(source, len(frame), reply, len(reply), scratch, len(scratch)) != len(reply):
            raise ValueError('HIA refused the Boolean formula')
        magic, verdict, model, cost = struct.unpack('<4Q', reply.raw)
        if (magic != REPLY or verdict not in (UNKNOWN, SAT, UNSAT)
                or model >= 1 << variables or verdict != SAT and model or cost > steps
                or verdict == UNKNOWN and cost != steps):
            raise RuntimeError('invalid HIA Boolean solver reply')
        return verdict, model, cost

    def solve_sparse(self, variables, clauses, *, steps, batch=False, watched=False, learning=False, restarts=False):
        if (type(variables) is not int or not 0 <= variables <= SPARSE_VARIABLES
                or len(clauses) > SPARSE_CLAUSES or type(steps) is not int or not 0 <= steps <= STEP_LIMIT):
            raise ValueError('formula or work budget exceeds the sparse HIA Boolean profile')
        tokens = array('H')
        for clause in clauses:
            if len(tokens) + len(clause) + 1 > SPARSE_ENTRIES:
                raise ValueError('formula exceeds the sparse HIA Boolean packet')
            if any(type(literal) is not int or not 2 <= literal <= 2 * variables + 1 for literal in clause):
                raise ValueError('invalid sparse HIA Boolean literal')
            tokens.extend(clause)
            tokens.append(0)
        if byteorder != 'little':
            tokens.byteswap()
        magic = _search_mode(batch=batch, watched=watched, learning=learning, restarts=restarts)
        frame = struct.pack('<5Q', magic, variables, len(clauses), steps, len(tokens)) + tokens.tobytes()
        return self._solve_sparse_frame(frame, variables, steps)

    def _solve_sparse_frame(self, frame, variables, steps):
        magic, _, clauses = struct.unpack_from('<3Q', frame)
        if magic in (LEARNING_REQUEST, RESTART_REQUEST):
            extent = WATCH_ROWS + 2 * (clauses + LEARNED_CLAUSES) * WATCH_ROW_BYTES + LEARNING_BYTES
        elif magic == WATCHED_REQUEST:
            extent = WATCH_ROWS + 2 * clauses * WATCH_ROW_BYTES
        else:
            extent = SPARSE_WORKSPACE + (8 if magic == BATCH_REQUEST else 0)
        source = ctypes.create_string_buffer(frame, len(frame))
        reply = ctypes.create_string_buffer(32 + (variables + 7) // 8)
        scratch = ctypes.create_string_buffer(extent)
        size = self._entry(source, len(frame), reply, len(reply), scratch, len(scratch))
        magic, verdict, received, cost = struct.unpack_from('<4Q', reply)
        if (magic != SPARSE_REPLY or received != variables or verdict not in (UNKNOWN, SAT, UNSAT)
                or size != (len(reply) if verdict == SAT else 32) or cost > steps
                or verdict == UNKNOWN and cost != steps):
            raise RuntimeError('invalid sparse HIA Boolean solver reply')
        model = int.from_bytes(reply.raw[32:size], 'little')
        if model >= 1 << variables:
            raise RuntimeError('invalid sparse HIA Boolean solver model')
        return verdict, model, cost

    def solve_circuit(self, nodes, returns, *, steps, traps=None, batch=False, watched=False, learning=False,
                      restarts=False):
        if len(nodes) > CIRCUIT_NODES or len(returns) > CIRCUIT_RETURNS or not 0 <= steps <= STEP_LIMIT:
            return None
        magic = CIRCUIT_REQUEST if traps is None else GUARDED_CIRCUIT_REQUEST
        frame = struct.pack('<4Q', magic, len(nodes), len(returns), steps)
        frame += b''.join(struct.pack('<5Q', *instruction) for instruction in nodes)
        frame += b''.join(struct.pack('<2Q', *pair) for pair in returns)
        if traps is not None:
            frame += struct.pack('<2Q', *traps)
        source = ctypes.create_string_buffer(frame, len(frame))
        output = ctypes.create_string_buffer(CIRCUIT_CAPACITY)
        scratch = ctypes.create_string_buffer(CIRCUIT_WORKSPACE)
        size = self._entry(source, len(frame), output, len(output), scratch, len(scratch))
        if size == 0xfffffffc:
            return None  # No claim with a circuit that exceeds its admitted gate budget.
        if not 40 <= size <= len(output):
            raise ValueError('HIA rejected the circuit representation')
        formula = output.raw[:size]
        magic, variables, clauses, budget, entries = struct.unpack_from('<5Q', formula)
        if (magic != SPARSE_REQUEST or variables > SPARSE_VARIABLES or clauses > SPARSE_CLAUSES
                or steps != budget or entries > SPARSE_ENTRIES or size != 40 + 2 * entries):
            raise RuntimeError('invalid HIA circuit encoding result')
        mode = _search_mode(batch=batch, watched=watched, learning=learning, restarts=restarts)
        if mode != SPARSE_REQUEST:
            formula = struct.pack('<Q', mode) + formula[8:]
        verdict, model, cost = self._solve_sparse_frame(formula, variables, steps)
        return verdict, model, cost, variables, clauses, formula


def _search_mode(*, batch, watched, learning, restarts):
    if restarts:
        return RESTART_REQUEST
    if learning:
        return LEARNING_REQUEST
    if watched:
        return WATCHED_REQUEST
    return BATCH_REQUEST if batch else SPARSE_REQUEST


def selected_cnf():
    manifest = os.environ.get(SELECTOR)
    if manifest is None:
        return None
    if not manifest:
        raise ValueError('HIA Boolean solver selector must not be empty')
    return _installed_json_image(manifest, SOURCE, SCHEMA, NativeCnf)


def core_circuit(before, after, observed):
    """Frame one checked scalar block, including the values on all its exits."""
    if (before['term'] != after['term'] or before['term']['op'] not in {'ret', 'jump', 'branch', 'trap'}
            or before['params'] != after['params']):
        return None
    if len(before['params']) + len(before['ops']) + len(after['ops']) > CIRCUIT_NODES:
        return None
    nodes = []
    parameters = {}
    for parameter in before['params']:
        width = _CORE_WIDTHS.get(parameter['type'])
        if width not in (1, 8, 16, 32, 64):
            return None
        parameters[parameter['name']] = (len(nodes), parameter['type'])
        nodes.append((1, width, 0, 0, 0))
    returned, traps = [], []
    for block in (before, after):
        values = parameters.copy()
        trap = None
        for operation in block['ops']:
            opcode = _CORE_OPERATIONS.get(operation['op'])
            if opcode is None or len(operation['out']) != 1:
                return None
            output, = operation['out']
            width = _CORE_WIDTHS.get(output['type'])
            if width not in (1, 8, 16, 32, 64) or any(arg not in values for arg in operation['args']):
                return None
            args = [values[arg][0] for arg in operation['args']]
            left, right = (args + [0, 0])[:2]
            immediate = 0
            if opcode == 2:
                immediate = int(operation['attrs']['value']) % (1 << width)
            elif opcode == 11:
                immediate = args[2]
            elif 12 <= opcode <= 15:
                opcode += 4 * values[operation['args'][0]][1].startswith('i')
            elif opcode == 20:
                if operation['attrs']['mode'] != 'wrap':
                    return None
                opcode += values[operation['args'][0]][1].startswith('i')
            elif operation['op'] == 'int.neg.checked':
                # Encode negation as checked zero minus the operand. Signed
                # minimum and nonzero unsigned operands share the original
                # subtraction overflow condition.
                left, right = len(nodes), left
                nodes.append((2, width, 0, 0, 0))
            values[output['name']] = (len(nodes), output['type'])
            if opcode < 22:
                nodes.append((opcode, width, left, right, immediate))
                continue
            nodes.append((opcode - 13, width, left, right, 0))
            signed = output['type'].startswith('i')
            if opcode == 23 and nodes[left][0] == 2 and nodes[left][4] == 0:
                # Negation overflows exactly at signed MIN, or for any
                # nonzero unsigned input. Avoid asking the solver to
                # discover this through the unused subtraction result.
                boundary = len(nodes)
                nodes.append((2, width, 0, 0, 1 << (width - 1) if signed else 0))
                nodes.append((7 if signed else 8, 1, right, boundary, 0))
            else:
                nodes.append((opcode + 2 * signed, 1, left, right, 0))
            flag = len(nodes) - 1
            if trap is not None:
                nodes.append((4, 1, trap, flag, 0))
            trap = len(nodes) - 1
        if any(name not in values for name in observed):
            return None
        returned.append([values[name][0] for name in observed])
        traps.append(trap)
    if all(trap is None for trap in traps):
        guards = None
    elif None in traps:
        guards = tuple(len(nodes) if trap is None else trap for trap in traps)
        nodes.append((2, 1, 0, 0, 0))
    else:
        guards = tuple(traps)
    return nodes, list(zip(*returned, strict=True)), guards



@dataclass(frozen=True)
class BitvectorCircuit:
    nodes: tuple
    returns: tuple
    inputs: tuple

    def witness(self, z3, bits, expression):
        model = z3.Model(ctx=expression.ctx)
        # Literal variable one is fixed to true by the native circuit ABI.
        # Input nodes are a contiguous prefix before any derived gate.
        offset = 1
        for term, width in self.inputs:
            value = (bits >> offset) & ((1 << width) - 1)
            offset += width
            translated = (z3.BoolVal(bool(value), ctx=expression.ctx) if z3.is_bool(term)
                          else z3.BitVecVal(value, width, ctx=expression.ctx))
            model.update_value(term, translated)
        return model if z3.is_true(model.eval(expression, model_completion=True)) else None


def _op_frame(z3, term, width, arguments, nodes, references):
    kind = term.decl().kind()
    if z3.is_true(term) or z3.is_false(term):
        return 2, width, 0, 0, int(z3.is_true(term))
    if z3.is_bv_value(term):
        return 2, width, 0, 0, term.as_long()
    source = tuple(references[item.get_id()] for item in arguments)
    if kind == z3.Z3_OP_ITE and len(source) == 3:
        return (11, width, *source)
    if kind == z3.Z3_OP_EXTRACT and len(source) == 1:
        _, low = term.decl().params()
        return 26, width, source[0], 0, low
    if kind in (z3.Z3_OP_SIGN_EXT, z3.Z3_OP_ZERO_EXT) and len(source) == 1:
        return (31 if kind == z3.Z3_OP_SIGN_EXT else 30), width, source[0], 0, 0
    if kind in (z3.Z3_OP_BSHL, z3.Z3_OP_BLSHR) and len(source) == 2:
        if not z3.is_bv_value(arguments[1]):
            return None
        return (28 if kind == z3.Z3_OP_BSHL else 29), width, source[0], 0, arguments[1].as_long()
    if kind in (z3.Z3_OP_NOT, z3.Z3_OP_BNOT) and len(source) == 1:
        return 6, width, source[0], 0, 0
    if kind == z3.Z3_OP_IMPLIES and len(source) == 2:
        negated = len(nodes)
        nodes.append((6, 1, source[0], 0, 0))
        return 4, 1, negated, source[1], 0
    if kind == z3.Z3_OP_BMUL and len(source) == 2:
        # The foreign expression normalizer writes modular negation as a
        # product by all-one bits. The admitted word circuit has subtraction.
        if width == 1:
            return None
        for index, argument in enumerate(arguments):
            if z3.is_bv_value(argument) and argument.as_long() == (1 << width) - 1:
                zero = len(nodes)
                nodes.append((2, width, 0, 0, 0))
                return 10, width, zero, source[1 - index], 0
        return None
    binary = {
        z3.Z3_OP_AND: 3, z3.Z3_OP_BAND: 3,
        z3.Z3_OP_OR: 4, z3.Z3_OP_BOR: 4,
        z3.Z3_OP_XOR: 5, z3.Z3_OP_BXOR: 5,
        z3.Z3_OP_EQ: 7, z3.Z3_OP_DISTINCT: 8, z3.Z3_OP_BADD: 9, z3.Z3_OP_BSUB: 10,
        z3.Z3_OP_ULT: 12, z3.Z3_OP_ULEQ: 13, z3.Z3_OP_UGT: 14, z3.Z3_OP_UGEQ: 15,
        z3.Z3_OP_SLT: 16, z3.Z3_OP_SLEQ: 17, z3.Z3_OP_SGT: 18, z3.Z3_OP_SGEQ: 19,
        z3.Z3_OP_CONCAT: 27,
    }
    op = binary.get(kind)
    if op is None or len(source) < 2 or len(source) > 2 and op not in (3, 4, 5):
        return None
    if width == 1 and op in (9, 10) or 12 <= op <= 19 and nodes[source[0]][1] == 1:
        return None
    left = source[0]
    for right in source[1:-1]:
        nodes.append((op, width, left, right, 0))
        left = len(nodes) - 1
    return op, width, left, source[-1], 0


def bitvector_circuit(z3, expression):
    """Observe a finite typed DAG without asking the foreign library to bit-blast."""
    if not z3.is_bool(expression):
        return None
    ordered, variables, seen = [], [], set()

    def visit(term):
        identity = term.get_id()
        if identity in seen:
            return True
        seen.add(identity)
        if len(seen) >= CIRCUIT_NODES or not z3.is_app(term):
            return False
        width = 1 if z3.is_bool(term) else term.size() if z3.is_bv(term) else 0
        if not 1 <= width <= 64:
            return False
        children = tuple(term.children())
        if not children and term.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            variables.append((term, width))
            return True
        if not all(visit(child) for child in children):
            return False
        ordered.append((term, width, children))
        return True

    if not visit(expression):
        return None
    references = {term.get_id(): index for index, (term, _) in enumerate(variables)}
    nodes = [(1, width, 0, 0, 0) for _, width in variables]
    for term, width, children in ordered:
        record = _op_frame(z3, term, width, children, nodes, references)
        if record is None or len(nodes) >= CIRCUIT_NODES - 1:
            return None
        references[term.get_id()] = len(nodes)
        nodes.append(record)
    result = references[expression.get_id()]
    false = len(nodes)
    nodes.append((2, 1, 0, 0, 0))
    return BitvectorCircuit(tuple(nodes), ((result, false),), tuple(variables))


@dataclass(frozen=True)
class BooleanReduction:
    goal: object
    atoms: tuple
    clauses: tuple

    def witness(self, z3, bits, expression):
        model = z3.Model(ctx=expression.ctx)
        for index, atom in enumerate(self.atoms):
            model.update_value(atom, z3.BoolVal(bool(bits & (1 << index)), ctx=expression.ctx))
        projected = self.goal.convert_model(model)
        # Never report a solver witness unless it satisfies the pre-reduction
        # formula, including the actual caller premises.
        return projected if z3.is_true(projected.eval(expression, model_completion=True)) else None


def bitblast_clauses(z3, expression, *, timeout_ms):
    reduced = bitblast_goal(z3, expression, timeout_ms=timeout_ms)
    return None if reduced is None else (len(reduced.atoms), [list(clause) for clause in reduced.clauses])


def bitblast_goal(z3, expression, *, timeout_ms):
    """Accept only the precise tactic result of one closed Boolean subgoal."""
    context = expression.ctx
    goal = z3.Goal(ctx=context)
    goal.add(expression)
    plan = z3.Then(*(z3.Tactic(name, ctx=context) for name in ('simplify', 'bit-blast', 'tseitin-cnf')))
    try:
        reduced = z3.TryFor(plan, timeout_ms)(goal)
    except z3.Z3Exception:
        return None
    if len(reduced) != 1:
        return None
    goal = reduced[0]
    if goal.precision() != z3.Z3_GOAL_PRECISE or len(goal) > SPARSE_CLAUSES:
        return None
    variables = {}
    atoms = []
    clauses = []
    entries = 0
    for clause in goal:
        tokens = []
        literals = clause.children() if z3.is_or(clause) else (clause,)
        satisfied = False
        for literal in literals:
            negated = z3.is_not(literal)
            atom = literal.arg(0) if negated else literal
            if z3.is_true(atom) or z3.is_false(atom):
                satisfied |= z3.is_true(atom) != negated
                continue
            if not (z3.is_const(atom) and z3.is_bool(atom)
                    and atom.decl().kind() == z3.Z3_OP_UNINTERPRETED):
                return None
            identity = atom.get_id()
            index = variables.get(identity)
            if index is None:
                index = len(atoms)
                variables[identity] = index
                atoms.append(atom)
            if index >= SPARSE_VARIABLES:
                return None
            tokens.append(2 * (index + 1) + int(negated))
        if not satisfied:
            entries += len(tokens) + 1
            if entries > SPARSE_ENTRIES:
                return None
            clauses.append(tuple(tokens))
    return BooleanReduction(goal, tuple(atoms), tuple(clauses))
