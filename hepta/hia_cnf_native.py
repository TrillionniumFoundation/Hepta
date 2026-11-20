"""Transport Boolean clauses to the selected bounded HIA solver."""
from __future__ import annotations

import ctypes
from array import array
from dataclasses import dataclass
from itertools import groupby
import os
import struct
from sys import byteorder

from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path
from .hia_opcodes import TRAP_CODES, WIDTHS


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
WORD_WITNESS_REQUEST = int.from_bytes(b'HIABVW01', 'little')
WORD_TABLE_REQUEST = int.from_bytes(b'HIABVT01', 'little')
WORD_TABLE_INPUT_BITS = 16
WORD_TABLE_WORK_LIMIT = 32 * 1024 * 1024
GRAPH_PROJECTION_REQUEST = int.from_bytes(b'HIABVP01', 'little')
CALL_PROJECTION_REQUEST = int.from_bytes(b'HIABVP02', 'little')
SCALAR_SUMMARY = int.from_bytes(b'HIABVS01', 'little')
TUPLE_SUMMARY = int.from_bytes(b'HIABVS02', 'little')
FEEDBACK_REQUEST = int.from_bytes(b'HIABVF01', 'little')
FEEDBACK_REPLY = int.from_bytes(b'HIABFR01', 'little')
FEEDBACK_BLOCK_LIMIT = 128
FEEDBACK_OP_LIMIT = 2048
FEEDBACK_LAYER_LIMIT = 32
FEEDBACK_WORKSPACE = 12288
CIRCUIT_NODES = 256
CIRCUIT_RETURNS = 16
CIRCUIT_CAPACITY = 192 * 1024
CIRCUIT_GATE_SLOTS = 8192
CIRCUIT_GATES_OFFSET = 32 + CIRCUIT_NODES * 128
CIRCUIT_DIVISION_TEMP = CIRCUIT_GATES_OFFSET + 8 * CIRCUIT_GATE_SLOTS
CIRCUIT_SIGNED_MAGNITUDES = CIRCUIT_DIVISION_TEMP + 256
CIRCUIT_WORKSPACE = CIRCUIT_SIGNED_MAGNITUDES + 256
SUMMARIZED_CALL_INPUTS = 32
PROJECTION_OUTPUT = 56 + 40 * CIRCUIT_NODES + 16 * CIRCUIT_RETURNS + 8 * SUMMARIZED_CALL_INPUTS
PROJECTION_WORKSPACE = 294912
PROJECTION_INPUT_LIMIT = 131072
UNKNOWN, SAT, UNSAT = range(3)
WRAPPING_PRODUCT = 32
WORD_UNSIGNED_DIV, WORD_UNSIGNED_REM = 33, 34
WORD_PRODUCT_EXCEEDS = 35
WORD_VARIABLE_SHL, WORD_VARIABLE_SHR = 36, 37
WORD_ARITHMETIC_SHR, WORD_SIGNED_DIV, WORD_SIGNED_REM = 38, 39, 40
PROJECT_CHECKED_SHL, PROJECT_CHECKED_SHR = 34, 35
PROJECT_CHECKED_DIV, PROJECT_CHECKED_REM = 36, 37
PROJECT_CHECKED_CAST = 38
PROJECT_CHECKED_MUL = 39
PROJECT_DIRECT_CALL = 40
PROJECT_CALL_RESULT = 41
PROJECT_UNIT_TYPE = 65
_CORE_WIDTHS = {'bool': 1, **WIDTHS}
_CORE_TRAP_TAGS = {code: index for index, code in enumerate(sorted(TRAP_CODES), 1)}
_CORE_OPERATIONS = {'const': 2, 'bit.and': 3, 'bool.and': 3, 'bit.or': 4, 'bool.or': 4,
                    'bit.xor': 5, 'bit.not': 6, 'bool.not': 6, 'compare.eq': 7, 'compare.ne': 8,
                    'int.add.wrap': 9, 'int.sub.wrap': 10, 'select': 11,
                    'compare.lt': 12, 'compare.le': 13, 'compare.gt': 14, 'compare.ge': 15,
                    'int.cast': 20, 'int.add.checked': 22, 'int.sub.checked': 23,
                    'int.neg.checked': 23, 'int.mul.wrap': WRAPPING_PRODUCT}
_GRAPH_OPERATIONS = {**_CORE_OPERATIONS, 'int.neg.checked': 33,
                     'int.shl.checked': PROJECT_CHECKED_SHL, 'int.shr.checked': PROJECT_CHECKED_SHR,
                     'int.div.checked': PROJECT_CHECKED_DIV, 'int.rem.checked': PROJECT_CHECKED_REM,
                     'int.mul.checked': PROJECT_CHECKED_MUL}


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
        if verdict == SAT:
            words = []
            for node, (operation, width, _, _, _) in enumerate(nodes):
                if operation == 1:
                    tokens = struct.unpack_from(f'<{width}H', scratch, 32 + 128 * node)
                    if any(token < 4 or token & 1 or token >> 1 > variables for token in tokens):
                        raise RuntimeError('invalid HIA circuit input projection')
                    words.append(sum(((model >> ((token >> 1) - 1)) & 1) << bit
                                     for bit, token in enumerate(tokens)))
            if not self.check_word_witness(nodes, returns, words, traps=traps):
                raise RuntimeError('native HIA SAT model did not satisfy the original word circuit')
        return verdict, model, cost, variables, clauses, formula

    def check_word_witness(self, nodes, returns, words, *, traps=None):
        """Check a candidate mismatch directly on words, without encoding CNF."""
        if len(nodes) > CIRCUIT_NODES or len(returns) > CIRCUIT_RETURNS or len(words) > len(nodes):
            raise ValueError('outside HIA word-witness profile')
        raw = bytearray(struct.pack('<4Q', WORD_WITNESS_REQUEST, len(nodes), len(returns), int(traps is not None)))
        for instruction in nodes:
            raw.extend(struct.pack('<5Q', *instruction))
        for pair in returns:
            raw.extend(struct.pack('<2Q', *pair))
        if traps is not None:
            raw.extend(struct.pack('<2Q', *traps))
        raw.extend(struct.pack(f'<{len(words)}Q', *words))
        source = ctypes.create_string_buffer(bytes(raw), len(raw))
        scratch = ctypes.create_string_buffer(max(8, len(nodes) * 8))
        output = ctypes.create_string_buffer(32)
        status = self._entry(source, len(raw), output, len(output), scratch, len(scratch))
        if status not in (0, 1):
            raise ValueError('HIA rejected the concrete word witness')
        return bool(status)

    def search_word_table(self, nodes, returns, *, traps=None, work):
        """Independently enumerate a small complete input domain in HIA."""
        bits = sum(width for operation, width, *_ in nodes if operation == 1)
        if bits > WORD_TABLE_INPUT_BITS:
            return None
        frame = struct.pack('<4Q', WORD_TABLE_REQUEST, len(nodes), len(returns), int(traps is not None))
        frame += b''.join(struct.pack('<5Q', *instruction) for instruction in nodes)
        frame += b''.join(struct.pack('<2Q', *pair) for pair in returns)
        if traps is not None:
            frame += struct.pack('<2Q', *traps)
        frame += struct.pack('<Q', min(work, WORD_TABLE_WORK_LIMIT))
        source = ctypes.create_string_buffer(frame, len(frame))
        output = ctypes.create_string_buffer(32)
        scratch = ctypes.create_string_buffer(max(8, len(nodes) * 8))
        size = self._entry(source, len(frame), output, len(output), scratch, len(scratch))
        if size == 0xfffffffc:
            return None
        if size != len(output):
            raise RuntimeError('invalid HIA word table reply extent')
        magic, verdict, assignment, checked = struct.unpack('<4Q', output.raw)
        if (magic != WORD_TABLE_REQUEST or verdict not in (SAT, UNSAT)
                or verdict == SAT and (assignment >= 1 << bits or checked != assignment + 1)
                or verdict == UNSAT and (assignment != 0 or checked != 1 << bits)):
            raise RuntimeError('invalid HIA word table reply')
        # The circuit's defined model format reserves bit zero for true.
        return verdict, (assignment << 1) | 1, checked, frame[:-8]

    def _run_projection(self, frame):
        if frame is None or len(frame) > PROJECTION_INPUT_LIMIT:
            return None
        source = ctypes.create_string_buffer(frame, len(frame))
        reply = ctypes.create_string_buffer(PROJECTION_OUTPUT)
        scratch = ctypes.create_string_buffer(PROJECTION_WORKSPACE)
        size = self._entry(source, len(frame), reply, len(reply), scratch, len(scratch))
        if size == 0xfffffffc:
            return None
        if not 32 <= size <= len(reply):
            raise RuntimeError('invalid HIA scalar projection extent')
        return reply.raw[:size]

    def project_scalar_graphs(self, functions, graphs, *, totality, summaries=None, bound_marker=False):
        reply = self._run_projection(_graph_packet(functions, graphs, totality=totality, summaries=summaries,
                                                   bound_marker=bound_marker))
        if reply is None:
            return None
        magic, nodes, pairs, reserved = struct.unpack_from('<4Q', reply)
        if (magic != CIRCUIT_REQUEST or reserved or nodes > CIRCUIT_NODES or pairs > CIRCUIT_RETURNS
                or len(reply) != 32 + 40 * nodes + 16 * pairs):
            raise RuntimeError('invalid HIA scalar circuit projection')
        split = 32 + 40 * nodes
        instructions = tuple(struct.iter_unpack('<5Q', reply[32:split]))
        observed = tuple(struct.iter_unpack('<2Q', reply[split:]))
        return instructions, observed, None

    def project_scalar_calls(self, name, closures, *, totality, expansion_limit):
        roots, graphs, bindings, expansions = [], [], [], []
        for functions, closure in closures:
            compiled, costs = {}, {}
            for callee, graph in closure.items():
                function = functions[callee]
                costs[callee] = 1 + sum(
                    costs[op['attrs']['function']] for block in function['blocks'] for op in block['ops']
                    if op['op'] == 'call')
                if costs[callee] > expansion_limit:
                    return None
                if callee == name:
                    roots.append(function)
                    graphs.append(graph)
                    bindings.append(compiled)
                    expansions.append(costs[callee])
                    break
                raw = self._run_projection(_graph_packet(
                    (function,), (graph,), totality=False, summaries=(compiled,), summarize=True))
                if raw is None:
                    return None
                if struct.unpack_from('<Q', raw)[0] not in (SCALAR_SUMMARY, TUPLE_SUMMARY):
                    raise RuntimeError('invalid HIA scalar callee summary')
                compiled[callee] = raw
        circuit = self.project_scalar_graphs(roots, graphs, totality=totality, summaries=bindings)
        return None if circuit is None else (circuit, expansions)

    def plan_feedback(self, blocks, edges, entry, maximum, *, block_budget, operation_budget):
        """Return the ordered bounded graph states, not a proof that its limit holds."""
        names = sorted(blocks)
        ids = {name: index for index, name in enumerate(names)}
        frame = struct.pack('<6Q', FEEDBACK_REQUEST, len(names), ids[entry], maximum,
                            block_budget, operation_budget)
        for name in names:
            targets = [ids[target] for target in edges[name]]
            targets.extend([FEEDBACK_BLOCK_LIMIT] * (2 - len(targets)))
            frame += struct.pack('<3Q', *targets, len(blocks[name]['ops']))
        source = ctypes.create_string_buffer(frame, len(frame))
        reply = ctypes.create_string_buffer(40 + 16 * FEEDBACK_BLOCK_LIMIT)
        scratch = ctypes.create_string_buffer(FEEDBACK_WORKSPACE)
        size = self._entry(source, len(frame), reply, len(reply), scratch, len(scratch))
        if not 40 <= size <= len(reply):
            raise ValueError('HIA refused the bounded feedback graph')
        magic, status, start, end, count = struct.unpack_from('<5Q', reply)
        if magic != FEEDBACK_REPLY or status > 3 or size != 40 + 16 * count:
            raise RuntimeError('invalid HIA bounded feedback plan')
        if status:
            if start or end or count:
                raise RuntimeError('invalid HIA bounded feedback refusal')
            return status, None, []
        if (start >= len(names) or end >= len(names) or names[end] not in edges[names[start]]
                or not 0 < count < block_budget):
            raise RuntimeError('invalid HIA bounded feedback plan dimensions')
        states = []
        for node, layer in struct.iter_unpack('<2Q', reply.raw[40:size]):
            if node >= len(names) or layer > maximum:
                raise RuntimeError('invalid HIA bounded feedback state')
            states.append((names[node], layer))
        if states[0] != (entry, 0) or len(set(states)) != count:
            raise RuntimeError('invalid HIA bounded feedback state order')
        return status, (names[start], names[end]), states


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


def _word_type(name):
    if name == 'unit':
        return PROJECT_UNIT_TYPE
    return _CORE_WIDTHS.get(name, 0) | (128 if name.startswith('i') else 0)


def _graph_packet(functions, graphs, *, totality, summaries=None, summarize=False, bound_marker=False):
    """Marshal verified SSA slots without constructing formulas.

    The type table precedes sized functions, each carrying topologically
    ordered blocks. A block has a fixed terminal header, parameter types,
    fixed-width instruction rows, and the local slots of its outgoing values.
    """
    parameters = functions[0]['params']
    returns = functions[0]['returns']
    if (summarize and len(returns) > CIRCUIT_RETURNS
            or not (totality or summarize) and len(returns) + 2 > CIRCUIT_RETURNS):
        return None
    magic = GRAPH_PROJECTION_REQUEST if summaries is None else CALL_PROJECTION_REQUEST
    mode = 4 if bound_marker else 3 if summarize else 1 if totality else 2
    buffer = bytearray(struct.pack('<4Q', magic, mode,
                                   len(parameters), len(returns)))
    if summaries is not None:
        buffer.extend(bytes(8))
    calls = []
    types = [*(_word_type(item['type']) for item in parameters), *map(_word_type, returns)]
    buffer.extend(struct.pack(f'<{len(types)}Q', *types))
    bindings = [None] * len(functions) if summaries is None else summaries
    for function, (blocks, order), available in zip(functions, graphs, bindings, strict=True):
        start = len(buffer)
        indexes = {name: index for index, name in enumerate(order)}
        buffer.extend(struct.pack('<3Q', 0, len(order), indexes[function['entry']]))
        for name in order:
            block = blocks[name]
            operation_rows = sum(max(1, len(op['out'])) for op in block['ops'])
            bound = len(block['params']) + operation_rows
            if bound > CIRCUIT_NODES:
                return None
            term = block['term']
            kind = {'ret': 1, 'trap': 2, 'jump': 3, 'branch': 4}[term['op']]
            layout = len(buffer)
            buffer.extend(bytes(64))
            slots = {item['name']: index for index, item in enumerate(block['params'])}
            buffer.extend(b''.join(struct.pack('<Q', _word_type(item['type'])) for item in block['params']))
            for op in block['ops']:
                operands = [slots[argument] for argument in op['args']]
                outputs = op['out']
                for result in outputs:
                    slots[result['name']] = len(slots)
                if op['op'] == 'call' and available is not None:
                    summary = available[op['attrs']['function']]
                    calls.append((len(buffer), operands, summary))
                    count = len(outputs) if len(outputs) != 1 else 0  # v1 scalar summary uses a zero count.
                    first_type = _word_type(outputs[0]['type']) if outputs else 0
                    buffer.extend(struct.pack('<6Q', PROJECT_DIRECT_CALL, first_type,
                                              0, 0, 0, count))
                    for result in outputs[1:]:
                        buffer.extend(struct.pack('<6Q', PROJECT_CALL_RESULT, _word_type(result['type']),
                                                  0, 0, 0, 0))
                    continue
                result, = outputs
                role = _GRAPH_OPERATIONS.get(op['op'], 0)
                if op['op'] == 'int.cast' and op['attrs']['mode'] == 'checked':
                    role = PROJECT_CHECKED_CAST
                operands.extend([0] * (3 - len(operands)))
                literal = op['attrs'].get('value', 0)
                buffer.extend(struct.pack('<6Q', role, _word_type(result['type']),
                                          *operands, int(literal or 0) & ((1 << 64) - 1)))
            edges = ((term['then'], term['else']) if kind == 4 else (term,) if kind == 3 else ())
            control = (slots[term['cond']] if kind == 4
                       else _CORE_TRAP_TAGS[term['code']] if kind == 2 else 0)
            row = [len(block['params']), operation_rows, kind, control, 0, 0, 0, 0]
            if kind == 1:
                row[5] = len(term['values'])
                for value in term['values']:
                    buffer.extend(struct.pack('<Q', slots[value]))
            for edge, offset in zip(edges, (4, 6)):
                row[offset:offset + 2] = [indexes[edge['target']], len(edge['args'])]
                for argument in edge['args']:
                    buffer.extend(struct.pack('<Q', slots[argument]))
            struct.pack_into('<8Q', buffer, layout, *row)
            if len(buffer) > PROJECTION_INPUT_LIMIT:
                return None
        struct.pack_into('<Q', buffer, start, len(buffer) - start)
    if summaries is not None:
        struct.pack_into('<Q', buffer, 32, len(buffer))
        addresses = {}
        for row, operands, summary in calls:
            if summary not in addresses:
                addresses[summary] = len(buffer)
                buffer.extend(summary)
            arguments = len(buffer)
            buffer.extend(struct.pack(f'<{len(operands)}Q', *operands))
            struct.pack_into('<3Q', buffer, row + 16, addresses[summary], arguments, len(operands))
    return bytes(buffer)


def core_circuit(before, after, observed):
    """Frame one checked scalar block, including the values on all its exits."""
    if (before['term'] != after['term'] or before['term']['op'] not in {'ret', 'jump', 'branch', 'trap'}
            or before['params'] != after['params']):
        return None
    if len(before['params']) + len(before['ops']) + len(after['ops']) > CIRCUIT_NODES:
        return None
    inputs = _scalar_inputs(before['params'])
    if inputs is None:
        return None
    nodes, parameters = inputs
    returned, traps = [], []
    for block in (before, after):
        values = parameters.copy()
        trap, supported = _scalar_block(nodes, values, block['ops'])
        if not supported:
            return None
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


def _scalar_inputs(declarations):
    nodes = []
    parameters = {}
    for parameter in declarations:
        width = _CORE_WIDTHS.get(parameter['type'])
        if width not in (1, 8, 16, 32, 64):
            return None
        parameters[parameter['name']] = (len(nodes), parameter['type'])
        nodes.append((1, width, 0, 0, 0))
    return nodes, parameters


def _scalar_block(nodes, values, operations):
    if len(nodes) + len(operations) > CIRCUIT_NODES:
        return None, False
    trap = None
    for operation in operations:
        opcode = _CORE_OPERATIONS.get(operation['op'])
        if opcode is None or len(operation['out']) != 1:
            return None, False
        output, = operation['out']
        width = _CORE_WIDTHS.get(output['type'])
        if width not in (1, 8, 16, 32, 64) or any(arg not in values for arg in operation['args']):
            return None, False
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
                return None, False
            opcode += values[operation['args'][0]][1].startswith('i')
        elif operation['op'] == 'int.neg.checked':
            # Encode negation as checked zero minus the operand. Signed
            # minimum and nonzero unsigned operands share the original
            # subtraction overflow condition.
            left, right = len(nodes), left
            nodes.append((2, width, 0, 0, 0))
        values[output['name']] = (len(nodes), output['type'])
        if opcode < 22 or opcode == WRAPPING_PRODUCT:
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
    return trap, True


def scalar_model_arguments(model, parameters):
    """Project the initial contiguous input words of a checked HIA circuit model."""
    model >>= 1  # Variable one is the fixed true literal, not an input.
    for parameter in parameters:
        typ = parameter['type']
        if typ == 'unit':
            # Its fixed node allocates no witness bit.
            yield None
            continue
        width = _CORE_WIDTHS[typ]
        raw = model & ((1 << width) - 1)
        model >>= width
        if typ == 'bool':
            yield bool(raw)
        elif typ.startswith('i') and raw >> (width - 1):
            yield raw - (1 << width)
        else:
            yield raw


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


def _concat_frame(source, width, nodes):
    if len(source) < 2:
        return None
    # Simplified sign extensions often arrive as a single large CONCAT with
    # the same one-bit operand repeated. Keep those runs as one native node.
    if nodes[source[0]][1] == 1 and all(index == source[0] for index in source):
        return 31, width, source[0], 0, 0
    portions = []
    for index, run in groupby(source):
        repeat = sum(1 for _ in run)
        if repeat > 1 and nodes[index][1] == 1:
            nodes.append((31, repeat, index, 0, 0))
            portions.append(len(nodes) - 1)
        else:
            portions.extend([index] * repeat)
    left = portions[0]
    extent = nodes[left][1]
    for right in portions[1:-1]:
        extent += nodes[right][1]
        nodes.append((27, extent, left, right, 0))
        left = len(nodes) - 1
    return 27, width, left, portions[-1], 0


def _op_frame(z3, term, width, arguments, nodes, references):
    kind = term.decl().kind()
    if z3.is_true(term) or z3.is_false(term):
        return 2, width, 0, 0, int(z3.is_true(term))
    if z3.is_bv_value(term):
        return 2, width, 0, 0, term.as_long()
    source = tuple(references[item.get_id()] for item in arguments)
    if kind == z3.Z3_OP_CONCAT:
        return _concat_frame(source, width, nodes)
    if kind == z3.Z3_OP_ITE and len(source) == 3:
        return (11, width, *source)
    if kind == z3.Z3_OP_EXTRACT and len(source) == 1:
        _, low = term.decl().params()
        return 26, width, source[0], 0, low
    if kind in (z3.Z3_OP_SIGN_EXT, z3.Z3_OP_ZERO_EXT) and len(source) == 1:
        return (31 if kind == z3.Z3_OP_SIGN_EXT else 30), width, source[0], 0, 0
    if kind in (z3.Z3_OP_BSHL, z3.Z3_OP_BLSHR) and len(source) == 2:
        if z3.is_bv_value(arguments[1]):
            return (28 if kind == z3.Z3_OP_BSHL else 29), width, source[0], 0, arguments[1].as_long()
        operation = WORD_VARIABLE_SHL if kind == z3.Z3_OP_BSHL else WORD_VARIABLE_SHR
        return operation, width, source[0], source[1], 0
    if kind == z3.Z3_OP_BASHR and len(source) == 2:
        return WORD_ARITHMETIC_SHR, width, source[0], source[1], 0
    # The pinned Z3 API specifies the same semantics for its simplified _I
    # forms. The native word operators implement SMT's total zero case.
    if width > 1 and len(source) == 2:
        if kind in (z3.Z3_OP_BUDIV, z3.Z3_OP_BUDIV_I):
            return WORD_UNSIGNED_DIV, width, source[0], source[1], 0
        if kind in (z3.Z3_OP_BUREM, z3.Z3_OP_BUREM_I):
            return WORD_UNSIGNED_REM, width, source[0], source[1], 0
        if kind in (z3.Z3_OP_BSDIV, z3.Z3_OP_BSDIV_I):
            return WORD_SIGNED_DIV, width, source[0], source[1], 0
        if kind in (z3.Z3_OP_BSREM, z3.Z3_OP_BSREM_I):
            return WORD_SIGNED_REM, width, source[0], source[1], 0
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
        return WRAPPING_PRODUCT, width, source[0], source[1], 0
    binary = {
        z3.Z3_OP_AND: 3, z3.Z3_OP_BAND: 3,
        z3.Z3_OP_OR: 4, z3.Z3_OP_BOR: 4,
        z3.Z3_OP_XOR: 5, z3.Z3_OP_BXOR: 5,
        z3.Z3_OP_EQ: 7, z3.Z3_OP_DISTINCT: 8, z3.Z3_OP_BADD: 9, z3.Z3_OP_BSUB: 10,
        z3.Z3_OP_ULT: 12, z3.Z3_OP_ULEQ: 13, z3.Z3_OP_UGT: 14, z3.Z3_OP_UGEQ: 15,
        z3.Z3_OP_SLT: 16, z3.Z3_OP_SLEQ: 17, z3.Z3_OP_SGT: 18, z3.Z3_OP_SGEQ: 19,
    }
    op = binary.get(kind)
    if op is None or len(source) < 2 or len(source) > 2 and op not in (3, 4, 5, 9):
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


from .hia_loaded_source import register_loaded_module as _register_loaded_source
_register_loaded_source(__name__)
