"""Static authoring of resumable HIA sort control; no host execution fallback.

This generator compiles a small, explicitly constrained control-flow notation
to Core blocks. Every algorithm local lives in the HIA workspace. Calls use
workspace continuations; only declared effect() nodes yield to the foreign
observer. The generated owner, not this authoring module, runs in production.
"""
from __future__ import annotations
import ast
from dataclasses import dataclass

FRAME_POINTER = 3264
FRAME_BYTES = 16384
LOCAL_LIMIT = 4096
PHASE_OFFSET = 8
PHASE_BASE = 1000
PHASE_STRIDE = 1000


@dataclass
class Routine:
    name: str
    node: ast.FunctionDef
    parameters: list[str]
    slots: dict[str, int]
    result: int
    continuation: int
    phase_base: int
    nodes: dict
    entry: int
    resumes: set


class Graph:
    def __init__(self, node, async_names):
        self.node = node
        self.async_names = async_names
        self.nodes = {}
        self.resumes = set()
        self.serial = 0

    def add(self, operations, terminal):
        number = self.serial
        self.serial += 1
        self.nodes[number] = {'operations': operations, 'terminal': terminal}
        return number

    def sequence(self, body, following, break_target=None, continue_target=None):
        current = following
        for statement in reversed(body):
            if isinstance(statement, ast.Return):
                current = self.add([], {'kind': 'return', 'value': statement.value})
            elif isinstance(statement, ast.Break):
                if break_target is None:
                    raise ValueError('sort break outside loop')
                current = break_target
            elif isinstance(statement, ast.Continue):
                if continue_target is None:
                    raise ValueError('sort continue outside loop')
                current = continue_target
            elif isinstance(statement, ast.If):
                yes = self.sequence(statement.body, current, break_target, continue_target)
                no = self.sequence(statement.orelse, current, break_target, continue_target)
                current = self.add([], {'kind': 'branch', 'condition': statement.test,
                                        'yes': yes, 'no': no})
            elif isinstance(statement, ast.While):
                if statement.orelse:
                    raise ValueError('sort while-else is not an authoring form')
                condition = self.add([], {})
                body_entry = self.sequence(statement.body, condition, current, condition)
                self.nodes[condition]['terminal'] = {
                    'kind': 'branch', 'condition': statement.test,
                    'yes': body_entry, 'no': current}
                current = condition
            elif isinstance(statement, (ast.Assign, ast.Expr)):
                expression = statement.value
                name = (expression.func.id if isinstance(expression, ast.Call)
                        and isinstance(expression.func, ast.Name) else None)
                if name == 'abort':
                    if not isinstance(statement, ast.Expr) or len(expression.args) != 1:
                        raise ValueError('invalid explicit sort abort')
                    current = self.add([], {'kind': 'abort', 'value': expression.args[0]})
                elif name == 'effect':
                    if not isinstance(statement, ast.Expr) or len(expression.args) != 5:
                        raise ValueError('sort effect requires five explicit words')
                    self.resumes.add(current)
                    current = self.add([], {'kind': 'effect', 'args': expression.args,
                                            'resume': current})
                elif name in self.async_names:
                    if (not isinstance(statement, ast.Assign) or len(statement.targets) != 1
                            or not isinstance(statement.targets[0], ast.Name)
                            or expression.keywords):
                        raise ValueError('sort continuation call requires one result local')
                    resume = self.add([('result', statement.targets[0].id, name)],
                                      {'kind': 'jump', 'target': current})
                    self.resumes.add(resume)
                    current = self.add([], {'kind': 'call', 'callee': name,
                                            'args': expression.args, 'resume': resume})
                else:
                    if isinstance(statement, ast.Assign):
                        if len(statement.targets) != 1 or not isinstance(statement.targets[0], ast.Name):
                            raise ValueError('sort locals require a single named target')
                    current = self.add([statement], {'kind': 'jump', 'target': current})
            else:
                raise ValueError('unsupported sort authoring node: ' + ast.dump(statement))
        return current

    @staticmethod
    def targets(terminal):
        kind = terminal['kind']
        if kind == 'jump':
            return (terminal['target'],)
        if kind == 'branch':
            return (terminal['yes'], terminal['no'])
        if kind in ('effect', 'call'):
            return (terminal['resume'],)
        return ()

    def finish(self):
        missing_return = self.add([], {'kind': 'abort', 'value': ast.Constant(4294967293)})
        entry = self.sequence(self.node.body, missing_return)
        keep = set()
        pending = [entry]
        while pending:
            number = pending.pop()
            if number in keep:
                continue
            keep.add(number)
            pending.extend(self.targets(self.nodes[number]['terminal']))
        self.nodes = {key: row for key, row in self.nodes.items() if key in keep}
        self.resumes &= keep
        # Coalesce only single-predecessor ordinary jumps. No effects, branches,
        # comparisons, stores or continuation order are removed or reordered.
        while True:
            incoming = {number: 0 for number in self.nodes}
            incoming[entry] += 1
            for number in self.resumes:
                incoming[number] += 1
            for row in self.nodes.values():
                for target in self.targets(row['terminal']):
                    incoming[target] += 1
            changed = False
            for number, row in tuple(self.nodes.items()):
                terminal = row['terminal']
                if terminal['kind'] != 'jump':
                    continue
                target = terminal['target']
                if target == number or incoming[target] != 1:
                    continue
                next_row = self.nodes[target]
                row['operations'].extend(next_row['operations'])
                row['terminal'] = next_row['terminal']
                del self.nodes[target]
                changed = True
                break
            if not changed:
                return entry, self.nodes, self.resumes


def routines(source):
    nodes = ast.parse(source).body
    if not nodes or any(not isinstance(node, ast.FunctionDef) for node in nodes):
        raise ValueError('only sort function definitions may enter authoring')
    async_names = {node.name for node in nodes}
    if len(async_names) != len(nodes):
        raise ValueError('duplicate sort function')
    cursor = 0
    result = []
    for index, node in enumerate(nodes):
        if (node.decorator_list or node.args.defaults or node.args.kw_defaults
                or node.args.vararg or node.args.kwarg or node.args.kwonlyargs
                or node.args.posonlyargs):
            raise ValueError('unsupported sort signature')
        parameters = [argument.arg for argument in node.args.args]
        locals_ = set(parameters)
        locals_.update(item.id for item in ast.walk(node)
                       if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Store))
        if 's' in locals_ or 'w' in locals_:
            raise ValueError('sort workspace names are reserved')
        result_slot, return_slot = cursor, cursor + 8
        cursor += 16
        slots = {}
        for name in parameters + sorted(locals_ - set(parameters)):
            slots[name] = cursor
            cursor += 8
        graph = Graph(node, async_names)
        entry, blocks, resumes = graph.finish()
        if graph.serial >= PHASE_STRIDE:
            raise ValueError('sort phase range exceeds its fixed interval')
        result.append(Routine(node.name, node, parameters, slots, result_slot, return_slot,
            PHASE_BASE + index * PHASE_STRIDE, blocks, entry, resumes))
    if cursor > LOCAL_LIMIT:
        raise ValueError('sort local frame exceeds its unchanged fixed reservation')
    by_name = {item.name: item for item in result}
    edges = {item.name: {node['terminal']['callee'] for node in item.nodes.values()
             if node['terminal']['kind'] == 'call'} for item in result}
    visiting, visited = set(), set()
    def visit(name):
        if name in visiting:
            raise ValueError('recursive sort continuations are forbidden')
        if name in visited:
            return
        visiting.add(name)
        for child in edges[name]:
            visit(child)
        visiting.remove(name)
        visited.add(name)
    for name in edges:
        visit(name)
    return result, cursor


def signature_node(name):
    return ast.parse('def ' + name + '(s:readbuf, w:mutbuf) -> u64:\n    return 0\n').body[0]


def frame_address(offset):
    return ast.BinOp(
        ast.Call(ast.Name('get', ast.Load()),
                 [ast.Name('w', ast.Load()), ast.Constant(FRAME_POINTER)], []),
        ast.Add(), ast.Constant(offset))


class LocalReads(ast.NodeTransformer):
    def __init__(self, slots):
        self.slots = slots

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load) and node.id in self.slots:
            return ast.copy_location(ast.Call(ast.Name('get', ast.Load()),
                [ast.Name('w', ast.Load()), frame_address(self.slots[node.id])], []), node)
        return node


def emit_routine(routine, all_routines, names, signatures, builder_class):
    by_name = {item.name: item for item in all_routines}
    builder = builder_class(signature_node(routine.name), names, signatures)
    initial = dict(builder.env)
    blocks = {}
    for number in sorted(routine.nodes):
        blocks[number] = builder.fresh(initial)
    def scalar(value):
        if value[1] == 'bool':
            return builder.op('select', [value, builder.c(1), builder.c(0)], 'u64')
        return builder.cast(value, 'u64')
    def read_slot(offset):
        return builder.expr(ast.Call(ast.Name('get', ast.Load()),
            [ast.Name('w', ast.Load()), frame_address(offset)], []))
    def write_slot(offset, value):
        builder.op('call', [builder.env['w'], builder.expr(frame_address(offset)), scalar(value)],
                   'u64', function=names['put'])
    def write_phase(value):
        builder.op('call', [builder.env['w'], builder.c(PHASE_OFFSET), scalar(value)],
                   'u64', function=names['put'])
    def expression(node):
        # Copy the input AST: one routine's lowering cannot change the frozen
        # algorithm source or another use of the same expression.
        import copy
        return builder.expr(LocalReads(routine.slots).visit(copy.deepcopy(node)))
    def return_status(value):
        builder.block['term'] = {'op': 'ret', 'values': [scalar(value)[0]]}
    def edge(number):
        return {'target': blocks[number][0]['id'],
                'args': [builder.env['s'][0], builder.env['w'][0]]}
    # Only actual resume points need a phase dispatch. Pure control flow remains
    # ordinary Core edges and never returns to Python or to the dispatcher.
    entries = sorted({routine.entry, *routine.resumes})
    for number in entries:
        pc = builder.expr(ast.Call(ast.Name('get', ast.Load()),
            [ast.Name('w', ast.Load()), ast.Constant(PHASE_OFFSET)], []))
        condition = builder.op('compare.eq', [pc, builder.c(routine.phase_base + number)], 'bool')
        next_block, next_env = builder.fresh(initial)
        builder.block['term'] = {'op': 'branch', 'cond': condition[0],
            'then': edge(number),
            'else': {'target': next_block['id'],
                     'args': [builder.env['s'][0], builder.env['w'][0]]}}
        builder.block, builder.env = next_block, next_env
    return_status(builder.c(4294967293))
    for number in sorted(routine.nodes):
        builder.block, builder.env = blocks[number]
        row = routine.nodes[number]
        for operation in row['operations']:
            if isinstance(operation, tuple):
                _, target, callee = operation
                write_slot(routine.slots[target], read_slot(by_name[callee].result))
            elif isinstance(operation, ast.Assign):
                write_slot(routine.slots[operation.targets[0].id], expression(operation.value))
            elif isinstance(operation, ast.Expr):
                expression(operation.value)
            else:
                raise ValueError('invalid lowered sort operation')
        terminal = row['terminal']
        kind = terminal['kind']
        if kind == 'jump':
            builder.block['term'] = {'op': 'jump', **edge(terminal['target'])}
        elif kind == 'branch':
            condition = expression(terminal['condition'])
            if condition[1] != 'bool':
                condition = builder.op('compare.ne', [condition, builder.c(0)], 'bool')
            builder.block['term'] = {'op': 'branch', 'cond': condition[0],
                'then': edge(terminal['yes']), 'else': edge(terminal['no'])}
        elif kind == 'call':
            callee = by_name[terminal['callee']]
            arguments = [expression(arg) for arg in terminal['args']]
            if len(arguments) != len(callee.parameters):
                raise ValueError('sort continuation arity differs')
            for parameter, argument in zip(callee.parameters, arguments, strict=True):
                write_slot(callee.slots[parameter], argument)
            write_slot(callee.continuation, builder.c(routine.phase_base + terminal['resume']))
            write_phase(builder.c(callee.phase_base + callee.entry))
            return_status(builder.c(4))
        elif kind == 'effect':
            arguments = [expression(arg) for arg in terminal['args']]
            status = builder.op('call', [builder.env['w'], *map(scalar, arguments),
                builder.c(routine.phase_base + terminal['resume'])], 'u64', function=names['request'])
            return_status(status)
        elif kind == 'return':
            write_slot(routine.result, expression(terminal['value']))
            write_phase(read_slot(routine.continuation))
            return_status(builder.c(4))
        elif kind == 'abort':
            return_status(expression(terminal['value']))
        else:
            raise ValueError('invalid sort terminal')
    return {'name': names[routine.name], 'params': [builder.param(p) for p in builder.params],
        'returns': ['u64'], 'effects': ['read', 'write', 'trap'], 'entry': 'b0',
        'blocks': builder.blocks}
