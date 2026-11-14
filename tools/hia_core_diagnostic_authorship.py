"""Attach complete original diagnostics to the native whole-Core policy.

This is authoring code only.  The generated HIA owns all diagnostic decisions,
text constants, formatting, and copied identifiers.  Neither the native bridge
nor the image consults Python policy or message templates at execution time.
Every replacement is exact and count-checked so changes to the underlying
policy cannot silently lose a refusal's diagnostic.
"""
import ast
from textwrap import dedent

from hepta.hia_core_diagnostic_protocol import (
    TABLE_CAPACITY, MESSAGE_SLACK, TRAILER_BYTES, DIAGNOSTIC_MAGIC,
)


class DiagnosticAuthor:
    def __init__(self):
        self.data = bytearray()
        self.records = {}

    def literal(self, text):
        raw = text.encode('utf-8')
        record = len(raw).to_bytes(8, 'little') + raw
        return self.record(record)

    def record(self, raw):
        if raw not in self.records:
            self.records[raw] = len(self.data)
            self.data.extend(raw)
        return self.records[raw]

    def fixed(self, code, message):
        return f'diagnostic_fixed(o, {code}, {self.literal(message)})'

    def context(self, code, context, suffix):
        return f'diagnostic_context(o, {code}, {context}, {self.literal(suffix)})'

    def named(self, code, prefix, node, suffix=''):
        return (f'diagnostic_named(w, o, {code}, {self.literal(prefix)}, '
                f'{node}, {self.literal(suffix)})')

    @staticmethod
    def edit(source, before, after, count=1):
        before = dedent(before).strip('\n')
        after = dedent(after).strip('\n')
        actual = source.count(before)
        if actual != count:
            raise AssertionError(f'diagnostic anchor count {actual} != {count}: {before!r}')
        return source.replace(before, after)

    @staticmethod
    def functions(source):
        return {node.name: ast.unparse(node) for node in ast.parse(source).body}

    @staticmethod
    def source(functions):
        return '\n\n'.join(functions.values()) + '\n'

    def refusals(self, source, entries, *, body=False):
        """Replace every direct policy refusal in lexical order, checking codes."""
        nodes = ast.parse(source)
        sites = []
        for node in ast.walk(nodes):
            if body:
                if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                        and node.func.id == 'put' and len(node.args) == 3
                        and ast.unparse(node.args[0]) == 'o'
                        and ast.unparse(node.args[1]) == '0'
                        and isinstance(node.args[2], ast.Name)
                        and node.args[2].id.isupper()):
                    sites.append(node)
            elif (isinstance(node, ast.Return) and isinstance(node.value, ast.Name)
                  and node.value.id.isupper()):
                sites.append(node)
        sites.sort(key=lambda node: (node.lineno, node.col_offset))
        if len(sites) != len(entries):
            raise AssertionError((nodes.body[0].name, len(sites), len(entries)))
        replacements = {}
        for site, (code, expression) in zip(sites, entries):
            original = site.args[2].id if body else site.value.id
            if original != code:
                raise AssertionError((nodes.body[0].name, original, code))
            replacement = ast.parse(expression, mode='eval').body
            replacements[id(site)] = replacement if body else ast.Return(value=replacement)

        class Replace(ast.NodeTransformer):
            def visit(self, node):
                if id(node) in replacements:
                    return replacements[id(node)]
                return super().visit(node)

        return ast.unparse(ast.fix_missing_locations(Replace().visit(nodes)))

    def fixed_refusals(self, source, entries, *, body=False):
        return self.refusals(source, [(code, self.fixed(code, message))
                                     for code, message in entries], body=body)

    def function_source(self, source):
        fs = self.functions(source)
        # Context is an image-owned literal offset, never submitted text.
        fs['parameters'] = self.edit(fs['parameters'],
            'namespace: u64)', 'namespace: u64, context: u64)')
        fs['names'] = self.edit(fs['names'],
            'w: mutbuf, array: u64)', 'w: mutbuf, o: mutbuf, array: u64, context: u64)')
        for name in ('edge', 'terminator'):
            fs[name] = self.edit(fs[name], 'w: mutbuf, node: u64)',
                                 'w: mutbuf, o: mutbuf, node: u64)')
        root = fs['function_shape']
        root = self.edit(root, 'if identifier(w, name) == 0 or runtime_name(w, name) != 0:\n        return NAME',
            'if identifier(w, name) == 0:\n        return NAME\n    if runtime_name(w, name) != 0:\n        return NAME')
        for call, context in (
            ('parameters(w, o, params, 1)', 'function parameters'),
            ('parameters(w, o, field(w, block, K_params), fresh(o))', 'block parameters'),
            ('parameters(w, o, field(w, ins, K_out), fresh(o))', 'instruction outputs')):
            root = self.edit(root, call, call[:-1] + f', {self.literal(context)})')
        root = self.edit(root, 'names(w, field(w, ins, K_args))',
                         f'names(w, o, field(w, ins, K_args), {self.literal("instruction arguments")})')
        root = self.edit(root, 'terminator(w, field(w, block, K_term))',
                         'terminator(w, o, field(w, block, K_term))')
        root_entries = [
            ('FORMAT', self.context('FORMAT', str(self.literal('function')),
                                   ': expected exactly blocks, effects, entry, name, params, returns')),
            ('NAME', self.fixed('NAME', 'function: invalid/reserved ASCII identifier')),
            ('NAME', self.fixed('NAME', 'function collides with native runtime symbol')),
            ('TYPE', self.fixed('TYPE', 'returns must be a list')),
            ('TYPE', self.fixed('TYPE', 'type is outside the closed primitive profile')),
            ('LOAN', self.fixed('LOAN', 'call loans require the v8 parameter-return contract')),
            ('LOAN', self.fixed('LOAN', 'return_loans must match the return arity')),
            ('LOAN', self.fixed('LOAN', 'nonloan result requires a null return_loans entry')),
            *[('LOAN', self.fixed('LOAN', 'borrowed result must name an input loan with sufficient permission'))] * 3,
            ('EFFECT', self.fixed('EFFECT', 'unknown/duplicate function effect')),
            ('EFFECT', self.fixed('EFFECT', 'unknown/duplicate function effect')),
            ('NAME', self.fixed('NAME', 'entry: invalid/reserved ASCII identifier')),
            ('CFG', self.fixed('CFG', 'invalid block inventory')),
            ('FORMAT', self.fixed('FORMAT', 'block: expected exactly id, ops, params, term')),
            ('NAME', self.fixed('NAME', 'block id: invalid/reserved ASCII identifier')),
            ('CFG', self.fixed('CFG', 'duplicate block')),
            ('FORMAT', self.fixed('FORMAT', 'block operations must be a list')),
            ('FORMAT', self.fixed('FORMAT', 'instruction: expected exactly args, attrs, op, out')),
            ('FORMAT', self.fixed('FORMAT', 'opcode must be text')),
            ('FORMAT', self.fixed('FORMAT', 'instruction attributes must be an object')),
            *[('CFG', self.fixed('CFG', 'entry parameters must equal the function signature'))] * 2,
            ('CFG', self.fixed('CFG', 'unreachable blocks are not admitted')),
            ('TYPE', self.fixed('TYPE', 'recursive chain types require HIA program v7')),
        ]
        with_origins = self.literal('function: expected exactly blocks, effects, entry, name, params, return_loans, returns')
        without_origins = self.literal('function: expected exactly blocks, effects, entry, name, params, returns')
        root_entries[0] = ('FORMAT', f'diagnostic_fixed(o, FORMAT, choose((fields & K_return_loans) != 0, {with_origins}, {without_origins}))')
        fs['function_shape'] = self.refusals(root, root_entries)
        fs['parameters'] = self.refusals(fs['parameters'], [
            ('FORMAT', self.context('FORMAT', 'context', ': expected parameter list')),
            ('FORMAT', self.context('FORMAT', 'context', ': expected exactly name, type')),
            ('NAME', self.context('NAME', 'context', ': invalid/reserved ASCII identifier')),
            ('TYPE', self.fixed('TYPE', 'type is outside the closed primitive profile')),
            ('SSA', f'diagnostic_parameter(w, o, context, name)'),
        ])
        fs['definitions'] = self.refusals(fs['definitions'], [
            ('SSA', self.named('SSA', 'SSA value ', 'field(w, item, K_name)', ' is defined more than once'))])
        fs['names'] = self.refusals(fs['names'], [
            ('FORMAT', self.context('FORMAT', 'context', ': expected value list')),
            ('NAME', self.context('NAME', 'context', ': invalid/reserved ASCII identifier'))])
        edge = self.edit(fs['edge'], 'names(w, field(w, node, K_args))',
                         f'names(w, o, field(w, node, K_args), {self.literal("edge arguments")})')
        fs['edge'] = self.fixed_refusals(edge, [
            ('FORMAT', 'CFG edge: expected exactly args, target'),
            ('NAME', 'edge target: invalid/reserved ASCII identifier')])
        term = self.edit(fs['terminator'], 'op = field(w, node, K_op)',
                         'op = field(w, node, K_op)\n    if kind(w, op) != 4:\n        return CFG')
        for field, context in (('K_values', 'return values'), ('K_args', 'edge arguments')):
            term = self.edit(term, f'names(w, field(w, node, {field}))',
                             f'names(w, o, field(w, node, {field}), {self.literal(context)})')
        term = self.edit(term, 'edge(w, field(w, node, K_then))', 'edge(w, o, field(w, node, K_then))')
        term = self.edit(term, 'edge(w, field(w, node, K_else))', 'edge(w, o, field(w, node, K_else))')
        fs['terminator'] = self.fixed_refusals(term, [
            ('CFG', 'missing terminator'), ('CFG', 'missing terminator'),
            ('FORMAT', 'ret: expected exactly op, values'),
            ('FORMAT', 'jump: expected exactly args, op, target'),
            ('NAME', 'edge target: invalid/reserved ASCII identifier'),
            ('FORMAT', 'branch: expected exactly cond, else, op, then'),
            ('NAME', 'branch condition: invalid/reserved ASCII identifier'),
            ('FORMAT', 'trap: expected exactly code, op'),
            ('CFG', 'unknown trap code'), ('CFG', 'unknown terminator')])
        connect = self.edit(fs['connect'], 'if target == NONE or target == entry:\n        return CFG',
            'if target == NONE:\n        return CFG\n    if target == entry:\n        return CFG')
        fs['connect'] = self.fixed_refusals(connect, [
            ('CFG', 'jump to missing block'),
            ('CFG', 'entry cannot have incoming CFG edges; use a loop header'),
            ('CFG', 'edge arity differs from block parameters')])
        return self.source(fs)

    def program_source(self, source):
        fs = self.functions(source)
        program = self.edit(fs['program_shape'], 'names(w, exports)',
                            f'names(w, o, exports, {self.literal("explicit scalar exports")})')
        program = self.fixed_refusals(program, [
            ('FORMAT', 'program: expected exactly functions, module, schema'),
            ('SCHEMA_ERROR', 'unsupported program schema'),
            ('NAME', 'module: invalid/reserved ASCII identifier'),
            ('FORMAT', 'invalid function inventory'), ('NAME', 'duplicate function'),
            ('NAME', 'duplicate explicit scalar export'),
            ('CALL_ERROR', 'explicit export names a missing function'),
            ('EXPORT_TYPE', 'public exports cannot carry resource descriptors'),
            ('EXPORT_TYPE', 'public exports cannot carry resource descriptors')])
        basic = self.fixed('FORMAT', 'program: expected exactly functions, module, schema')
        replacement = (f'diagnostic_fixed(o, FORMAT, choose(exports != NONE, '
                       f'{self.literal("program: expected exactly exports, functions, module, schema")}, '
                       f'{self.literal("program: expected exactly functions, module, schema")}))')
        fs['program_shape'] = self.edit(program, basic, replacement)
        return self.source(fs)

    def body_source(self, source):
        fs = self.functions(source)
        root = fs['core_admission']
        root = self.edit(root, 'status = widen(program_shape(s, o, w))',
            'if diagnostic_initialize(s, o) == 0:\n        return ABI\n    status = widen(program_shape(s, o, w))')
        root = self.edit(root, 'return status', 'return diagnostic_status(o, status)')
        root = self.edit(root, 'return get(o, 0)', 'return diagnostic_status(o, get(o, 0))')
        fs['core_admission'] = root
        fs['value'] = self.refusals(fs['value'], [
            ('SSA', 'diagnostic_nonlocal(w, o, name)'),
            ('SSA', 'diagnostic_nonlocal(w, o, name)'),
            ('RESOURCE', self.named('RESOURCE', 'use of consumed resource ', 'name')),
        ], body=True)
        for name, entries in {
            'owner_free': [('TYPE', 'operation requires an owner'), ('LOAN', 'owner moved/dropped/returned while borrowed')],
            'access': [('TYPE', 'memory access requires appropriate view'), ('LOAN', 'parent view is suspended until child loans end')],
            'borrow': [('LOAN', 'invalid borrow permission'), ('LOAN', 'invalid loan parent graph'),
                       ('LOAN', 'invalid loan parent graph'), ('LOAN', 'conflicting live borrow')],
            'callee': [('NAME', 'callee: invalid/reserved ASCII identifier'), ('CALL', 'unknown callee')],
            'finish_return': [('TYPE', 'return type/arity mismatch'), ('TYPE', 'return type/arity mismatch'),
                              ('LOAN', 'same loan capability returned twice'),
                              ('RETURN_LOAN', 'returned loan must be its declared parameter or a direct child'),
                              ('RETURN_LOAN', 'returned loan must be its declared parameter or a direct child'),
                              ('RESOURCE', 'same owner returned twice'), ('RESOURCE', 'return leaves live owner/local loan')],
            'function_body': [('CFG', 'not all blocks were checked')],
        }.items():
            fs[name] = self.fixed_refusals(fs[name], entries, body=True)
        guards = self.edit(fs['guards'],
            'if cap(o, name, 32) != 0 or children(o, name) != 0:\n                put(o, 0, LOAN)',
            'if cap(o, name, 32) != 0:\n                put(o, 0, LOAN)\n            else:\n                if children(o, name) != 0:\n                    put(o, 0, LOAN)')
        fs['guards'] = self.refusals(guards, [
            ('LOAN', self.fixed('LOAN', "callee cannot end its caller's loan")),
            ('LOAN', self.fixed('LOAN', 'end child loans before their parent')),
            ('LOAN', self.named('LOAN', '', 'field(w, ins, K_op)', ' may not alias one owner')),
        ], body=True)
        calls = self.refusals(fs['call_instruction'], [
            ('CALL', self.fixed('CALL', 'call arity mismatch')),
            ('CALL', self.fixed('CALL', 'call argument type mismatch')),
            ('RESOURCE', self.fixed('RESOURCE', 'owner supplied twice to call')),
            ('LOAN', self.fixed('LOAN', 'aliased exclusive call arguments')),
            ('TYPE', 'diagnostic_call_returns(w, o, ins, returns)'),
            ('TYPE', 'diagnostic_call_returns(w, o, ins, returns)'),
        ], body=True)
        fs['call_instruction'] = calls
        fs['finish'] = self.refusals(fs['finish'], [
            ('CFG', self.fixed('CFG', 'branch condition is not bool')),
            ('EFFECT', 'diagnostic_effects(o, get(o, 72) & (15 ^ mask))'),
        ], body=True)
        local = self.refusals(fs['local_types'], [
            ('OPCODE', 'diagnostic_opcode(w, o, ins, OPCODE, info, 0)'),
            ('FORMAT', 'diagnostic_opcode(w, o, ins, FORMAT, info, 8)'),
            ('FORMAT', 'diagnostic_opcode(w, o, ins, FORMAT, info, 8)'),
            ('TYPE', self.named('TYPE', '', 'field(w, ins, K_op)', ': wrong operand count')),
            ('TYPE', self.named('TYPE', '', 'field(w, ins, K_op)', ': wrong output count')),
            ('TYPE', 'diagnostic_opcode(w, o, ins, TYPE, info, 24)'),
            ('TYPE', self.fixed('TYPE', 'constant must be an exactly typed scalar')),
            ('TYPE', self.fixed('TYPE', 'unsupported integer cast')),
        ], body=True)
        local = self.edit(local, 'put(o, 0, choose(a & 281474976710656 != 0, LOAN, TYPE))',
            'diagnostic_opcode(w, o, ins, choose(a & 281474976710656 != 0, LOAN, TYPE), info, 16)')
        fs['local_types'] = local
        transfer = fs['transfer']
        # Finish the complete renamed capability graph before comparing any
        # incoming predecessor, matching rename_capabilities then exact join.
        insertion = '''
    i = 0
    while i < count(w, args):
        name = definition(w, o, item(w, args, i))
        if value_type(w, name) > 12:
            root = cap(o, name, 16)
            parent = cap(o, name, 24)
            if get(o, rec(o, root) + 80) != stamp:
                put(o, 0, LOAN)
                return last
            if parent != NONE:
                if get(o, rec(o, parent) + 80) != stamp:
                    put(o, 0, LOAN)
                    return last
        i = i + 1
'''
        old = '''
    i = 0
    while i < count(w, args):
        name = definition(w, o, item(w, args, i))
        if value_type(w, name) > 12:
            root = cap(o, name, 16)
            parent = cap(o, name, 24)
'''
        # ast.unparse has already normalized the exact indentation.
        anchor = dedent(old).strip('\n')
        indented_anchor = '\n'.join('    ' + line if line else line for line in anchor.splitlines())
        insert = dedent(insertion).strip('\n')
        insert = '\n'.join('    ' + line if line else line for line in insert.splitlines())
        if transfer.count(indented_anchor) != 1:
            raise AssertionError('native transfer loop anchor changed')
        transfer = transfer.replace(indented_anchor, insert + '\n' + indented_anchor)
        # The first pass owns the two closure refusals.  The second pass reads
        # only proven remappings and cannot change the diagnostic ordering.
        closure = '            if get(o, rec(o, root) + 80) != stamp:\n                put(o, 0, LOAN)\n                return last\n'
        parent_closure = '                if get(o, rec(o, parent) + 80) != stamp:\n                    put(o, 0, LOAN)\n                    return last\n'
        if transfer.count(closure) != 2 or transfer.count(parent_closure) != 2:
            raise AssertionError('native transfer closure anchors changed')
        at = transfer.rfind(closure)
        transfer = transfer[:at] + transfer[at:].replace(closure, '', 1)
        at = transfer.rfind(parent_closure)
        transfer = transfer[:at] + transfer[at:].replace(parent_closure, '', 1)
        fs['transfer'] = self.fixed_refusals(transfer, [
            ('CFG', 'edge values do not match block parameter types'),
            ('RESOURCE', 'linear capability duplicated across an edge'),
            ('RESOURCE', 'edge drops a live owner or local loan'),
            ('LOAN', 'loan must travel with its owner/parent capability'),
            ('LOAN', 'loan must travel with its owner/parent capability'),
            ('LOAN', 'predecessors disagree on loan origins/permissions'),
        ], body=True)
        return self.source(fs)

    def opcode_info(self, spec):
        messages = [f' requires HIA program v{spec.since}',
                    f': expected exactly {", ".join(spec.attributes)} attributes',
                    f': operand types must match {spec.operands}',
                    f': output types must match {spec.results}']
        return self.record(b''.join(self.literal(text).to_bytes(8, 'little') for text in messages))

    def unknown_opcode(self):
        return self.named('OPCODE', 'unsupported opcode ', 'op')

    def helpers(self):
        source = f'''
def diagnostic_initialize(s:readbuf, o:mutbuf) -> u64:
    if length(s) > 8388608:
        return 0
    nodes = ((length(s) + 1) >> 1) + 1
    if nodes > 262144:
        nodes = 262144
    if length(o) < {TABLE_CAPACITY + MESSAGE_SLACK + TRAILER_BYTES} + length(s) + nodes:
        return 0
    trailer = length(o) - {TRAILER_BYTES}
    table = trailer - {TABLE_CAPACITY + MESSAGE_SLACK} - length(s) - nodes
    slots = 2
    while slots < nodes * 4:
        slots = slots * 2
    if table < 128 + slots * 24 + 4096 * 40 + nodes * 120:
        return 0
    put(o, trailer, table)
    put(o, trailer + 8, table + {TABLE_CAPACITY})
    put(o, trailer + 16, 0)
    put(o, trailer + 24, length(s) + nodes + {MESSAGE_SLACK})
    put(o, trailer + 32, 0)
    put(o, trailer + 40, 0)
    put(o, trailer + 48, 0)
    put(o, trailer + 56, 0)
    return 1

def diagnostic_begin(o:mutbuf, code:u64) -> u64:
    trailer = length(o) - {TRAILER_BYTES}
    diagnostic_table(o, get(o, trailer))
    put(o, 0, code)
    put(o, trailer + 16, 0)
    put(o, trailer + 32, code)
    put(o, trailer + 40, {DIAGNOSTIC_MAGIC})
    return 0

def diagnostic_literal(o:mutbuf, offset:u64) -> u64:
    trailer = length(o) - {TRAILER_BYTES}
    at = get(o, trailer) + offset
    size = get(o, at)
    used = get(o, trailer + 16)
    if size > get(o, trailer + 24) - used:
        put(o, trailer + 48, 1)
        return 0
    destination = get(o, trailer + 8) + used
    i = 0
    while i < size:
        store(o, destination + i, byte(o, at + 8 + i))
        i = i + 1
    put(o, trailer + 16, used + size)
    return 0

def diagnostic_node(w:mutbuf, o:mutbuf, node:u64) -> u64:
    trailer = length(o) - {TRAILER_BYTES}
    size = count(w, node)
    used = get(o, trailer + 16)
    if size > get(o, trailer + 24) - used:
        put(o, trailer + 48, 1)
        return 0
    at = get(w, 64 + node * 56 + 24)
    destination = get(o, trailer + 8) + used
    i = 0
    while i < size:
        store(o, destination + i, byte(w, at + i))
        i = i + 1
    put(o, trailer + 16, used + size)
    return 0

def diagnostic_fixed(o:mutbuf, code:u64, text:u64) -> u64:
    diagnostic_begin(o, code)
    diagnostic_literal(o, text)
    return code

def diagnostic_context(o:mutbuf, code:u64, context:u64, suffix:u64) -> u64:
    diagnostic_begin(o, code)
    diagnostic_literal(o, context)
    diagnostic_literal(o, suffix)
    return code

def diagnostic_named(w:mutbuf, o:mutbuf, code:u64, prefix:u64, node:u64, suffix:u64) -> u64:
    diagnostic_begin(o, code)
    diagnostic_literal(o, prefix)
    diagnostic_node(w, o, node)
    diagnostic_literal(o, suffix)
    return code

def diagnostic_parameter(w:mutbuf, o:mutbuf, context:u64, node:u64) -> u64:
    diagnostic_context(o, SSA, context, {self.literal(': duplicate parameter ')})
    diagnostic_node(w, o, node)
    return SSA

def diagnostic_nonlocal(w:mutbuf, o:mutbuf, node:u64) -> u64:
    diagnostic_begin(o, SSA)
    diagnostic_node(w, o, field(w, get(o, 80), K_name))
    diagnostic_literal(o, {self.literal('/')})
    diagnostic_node(w, o, field(w, get(o, 56) - 1, K_id))
    diagnostic_literal(o, {self.literal(': undefined/nonlocal value ')})
    diagnostic_node(w, o, node)
    return SSA

def diagnostic_opcode(w:mutbuf, o:mutbuf, ins:u64, code:u64, info:u64, offset:u64) -> u64:
    diagnostic_begin(o, code)
    diagnostic_node(w, o, field(w, ins, K_op))
    diagnostic_literal(o, get(o, get(o, length(o) - {TRAILER_BYTES}) + info + offset))
    return code

def diagnostic_call_returns(w:mutbuf, o:mutbuf, ins:u64, returns:u64) -> u64:
    diagnostic_begin(o, TYPE)
    diagnostic_node(w, o, field(w, ins, K_op))
    diagnostic_literal(o, {self.literal(': output types must be [')})
    node = child(w, returns)
    first = 1
    while node != NONE:
        if first == 0:
            diagnostic_literal(o, {self.literal(', ')})
        diagnostic_literal(o, {self.literal(chr(39))})
        diagnostic_node(w, o, node)
        diagnostic_literal(o, {self.literal(chr(39))})
        first = 0
        node = next_node(w, node)
    diagnostic_literal(o, {self.literal(']')})
    return TYPE

def diagnostic_effects(o:mutbuf, missing:u64) -> u64:
    diagnostic_fixed(o, EFFECT, {self.literal('missing effects [')})
    first = 1
    if (missing & 1) != 0:
        diagnostic_literal(o, {self.literal("'alloc'")})
        first = 0
    if (missing & 2) != 0:
        if first == 0:
            diagnostic_literal(o, {self.literal(', ')})
        diagnostic_literal(o, {self.literal("'read'")})
        first = 0
    if (missing & 8) != 0:
        if first == 0:
            diagnostic_literal(o, {self.literal(', ')})
        diagnostic_literal(o, {self.literal("'trap'")})
        first = 0
    if (missing & 4) != 0:
        if first == 0:
            diagnostic_literal(o, {self.literal(', ')})
        diagnostic_literal(o, {self.literal("'write'")})
    diagnostic_literal(o, {self.literal(']')})
    return EFFECT

def diagnostic_status(o:mutbuf, status:u64) -> u64:
    trailer = length(o) - {TRAILER_BYTES}
    if get(o, trailer + 40) != {DIAGNOSTIC_MAGIC}:
        if status == 4294967295:
            diagnostic_fixed(o, status, {self.literal('invalid/deep UTF-8 JSON')})
        else:
            if status == 4294967294:
                diagnostic_fixed(o, status, {self.literal('program exceeds structural budget before JSON allocation')})
            else:
                if status == 4294967292:
                    diagnostic_fixed(o, status, {self.literal('duplicate JSON object field')})
                else:
                    return ABI
    if get(o, trailer + 48) != 0 or get(o, trailer + 32) != status:
        return ABI
    return status
'''
        if len(self.data) > TABLE_CAPACITY:
            raise ValueError(f'diagnostic table {len(self.data)} exceeds reserved {TABLE_CAPACITY}')
        raw = bytes(self.data)
        raw += bytes((-len(raw)) % 64)
        source += '\ndef diagnostic_table(o:mutbuf, base:u64) -> u64:\n'
        # Bound each function's SSA inventory below the unchanged compiler's
        # v2047 ceiling, including constants and write arguments.
        chunks = [raw[at:at + 2048] for at in range(0, len(raw), 2048)]
        for index in range(len(chunks)):
            source += f'    diagnostic_table_{index}(o, base)\n'
        source += '    return 0\n'
        for index, chunk in enumerate(chunks):
            source += f'\ndef diagnostic_table_{index}(o:mutbuf, base:u64) -> u64:\n'
            for offset in range(0, len(chunk), 64):
                words = [int.from_bytes(chunk[offset + lane:offset + lane + 8], 'little')
                         for lane in range(0, 64, 8)]
                source += (f'    diagnostic_words(o, base + {index * 2048 + offset}, '
                           + ', '.join(map(str, words)) + ')\n')
            source += '    return 0\n'
        source += '\ndef diagnostic_words(o:mutbuf, base:u64, a:u64, b:u64, c:u64, d:u64, e:u64, f:u64, g:u64, h:u64) -> u64:\n'
        for offset, name in zip(range(0, 64, 8), 'abcdefgh'):
            source += f'    put(o, base + {offset}, {name})\n'
        source += '    return 0\n'
        return source
