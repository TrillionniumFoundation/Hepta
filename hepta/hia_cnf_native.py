"""Transport Boolean clauses to the selected bounded HIA solver."""
from __future__ import annotations

import ctypes
from array import array
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
SPARSE_REPLY = int.from_bytes(b'HIACNR02', 'little')
SPARSE_VARIABLES = 4096
SPARSE_CLAUSES = 65536
SPARSE_ENTRIES = 1 << 20
SPARSE_WORKSPACE = SPARSE_VARIABLES * 7
CIRCUIT_REQUEST = int.from_bytes(b'HIABVC01', 'little')
GUARDED_CIRCUIT_REQUEST = int.from_bytes(b'HIABVG01', 'little')
CIRCUIT_NODES = 128
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
                    'int.cast': 20, 'int.add.checked': 22, 'int.sub.checked': 23}


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

    def solve_sparse(self, variables, clauses, *, steps):
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
        frame = struct.pack('<5Q', SPARSE_REQUEST, variables, len(clauses), steps, len(tokens)) + tokens.tobytes()
        return self._solve_sparse_frame(frame, variables, steps)

    def _solve_sparse_frame(self, frame, variables, steps):
        source = ctypes.create_string_buffer(frame, len(frame))
        reply = ctypes.create_string_buffer(32 + (variables + 7) // 8)
        scratch = ctypes.create_string_buffer(SPARSE_WORKSPACE)
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

    def solve_circuit(self, nodes, returns, *, steps, traps=None):
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
        verdict, model, cost = self._solve_sparse_frame(formula, variables, steps)
        return verdict, model, cost, variables, clauses, formula


def selected_cnf():
    manifest = os.environ.get(SELECTOR)
    if manifest is None:
        return None
    if not manifest:
        raise ValueError('HIA Boolean solver selector must not be empty')
    return _installed_json_image(manifest, SOURCE, SCHEMA, NativeCnf)


def core_circuit(before, after, observed):
    """Frame one checked scalar block, including the values on all its exits."""
    if (before['term'] != after['term'] or before['term']['op'] not in {'ret', 'jump', 'branch'}
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
            values[output['name']] = (len(nodes), output['type'])
            if opcode < 22:
                nodes.append((opcode, width, left, right, immediate))
                continue
            nodes.append((opcode - 13, width, left, right, 0))
            flag = len(nodes)
            nodes.append((opcode + 2 * output['type'].startswith('i'), 1, left, right, 0))
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


def bitblast_clauses(z3, expression, *, timeout_ms):
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
            index = variables.setdefault(atom.get_id(), len(variables))
            if index >= SPARSE_VARIABLES:
                return None
            tokens.append(2 * (index + 1) + int(negated))
        if not satisfied:
            entries += len(tokens) + 1
            if entries > SPARSE_ENTRIES:
                return None
            clauses.append(tokens)
    return len(variables), clauses
