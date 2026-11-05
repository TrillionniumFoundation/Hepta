"""Unchecked compositional transport source proposals with independent data binding.

No Lean invocation or acceptance is performed here. The verifier parses emitted
Lean data expressions independently of the source emitter, then reconstructs the
whole original Raw value and byte stream. Unsupported expressions fail closed.
"""
from dataclasses import dataclass
from hashlib import sha256
from itertools import repeat
from operator import is_
import json
import re

from tools import check_core_syntax_lean as old

LEAF_BYTES = 256
MAX_SOURCE_BYTES = old.MAX_PROOF_BYTES
NS = 'HiaCoreSyntaxSlice'
HELPER = NS + '.Structured.'
require = old.require


def digest(data):
    return sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('ascii')


@dataclass(frozen=True)
class StructuredInput:
    source: str
    expected_theorems: frozenset
    manifest_json: str

    @property
    def manifest(self):
        return json.loads(self.manifest_json)

    @property
    def manifest_sha256(self):
        return digest(self.manifest_json.encode())


def _scan(data):
    """Read positions directly from the canonical stream, not Raw serialization."""
    def value(pos):
        start = pos
        ch = data[pos]
        children, keys, key_spans = [], [], []
        if ch == 34:
            end = data.index(b'"', pos + 1) + 1
            val = data[pos + 1:end - 1].decode('ascii')
            kind = 'str'
        elif ch in (91, 123):
            kind = 'arr' if ch == 91 else 'obj'
            close = 93 if ch == 91 else 125
            pos += 1
            while data[pos] != close:
                if kind == 'obj':
                    ks = pos
                    key, pos = value(pos)
                    require(key['kind'] == 'str' and data[pos] == 58, 'object key envelope')
                    keys.append(key['value'])
                    pos += 1
                    key_spans.append((ks, pos))
                child, pos = value(pos)
                children.append(child)
                if data[pos] == close:
                    break
                require(data[pos] == 44, 'structural comma')
                pos += 1
            end = pos + 1
            val = [c['value'] for c in children] if kind == 'arr' else dict(zip(keys, (c['value'] for c in children)))
        else:
            end = pos
            while end < len(data) and 48 <= data[end] <= 57:
                end += 1
            require(end > pos, 'unsupported stream token')
            val = int(data[pos:end])
            kind = 'num'
        return {'start': start, 'end': end, 'kind': kind, 'value': val,
                'children': children, 'keys': keys, 'key_spans': key_spans}, end
    root, end = value(0)
    require(end == len(data), 'trailing stream data')
    return root


def _ledger(root, data):
    nodes = []
    def visit(node, fuel, depth):
        require(fuel > 0 and depth > 0, 'insufficient structural fuel/depth')
        ident = len(nodes)
        leaf = node['end'] - node['start'] <= LEAF_BYTES
        require(leaf or node['kind'] in ('arr', 'obj'), 'oversized indivisible scalar leaf')
        delimiter = data[node['end']] if node['kind'] == 'num' and node['end'] < len(data) else None
        if node['kind'] == 'num':
            require(delimiter in (44, 93, 125), 'numeric leaf requires structural delimiter')
        row = {'id': ident, 'start': node['start'], 'end': node['end'],
               'fuel': fuel, 'depth': depth, 'leaf': leaf, 'kind': node['kind'],
               'children': [], 'delimiter': delimiter}
        nodes.append(row)
        node['id'], node['fuel'], node['depth'], node['leaf'] = ident, fuel, depth, leaf
        if not leaf:
            require(bool(node['children']), 'nonleaf container must have children')
            for i, child in enumerate(node['children']):
                row['children'].append(visit(child, fuel - 2 - i, depth - 1))
        return ident
    visit(root, old.MAX_NODES, old.MAX_DEPTH)
    return nodes


def _list_ledger(root):
    rows = []
    def walk(node):
        if node['leaf']:
            return
        for i, child in enumerate(node['children']):
            rows.append({'parent': node['id'], 'index': i, 'child': child['id'],
                         'fuel': node['fuel'] - 1 - i, 'depth': node['depth'] - 1,
                         'kind': node['kind'], 'close': 125 if node['kind'] == 'obj' else 93,
                         'start': node['key_spans'][i][0] if node['kind'] == 'obj' else child['start'],
                         'value_start': child['start'], 'end': node['end'] - 1})
            walk(child)
    walk(root)
    return rows


def _segments(root, data):
    spans = []
    def walk(node):
        if node['leaf']:
            spans.append((node['start'], node['end']))
            return
        spans.append((node['start'], node['start'] + 1))
        for i, child in enumerate(node['children']):
            if node['kind'] == 'obj':
                spans.append(node['key_spans'][i])
            walk(child)
            if i + 1 < len(node['children']):
                spans.append((child['end'], child['end'] + 1))
        spans.append((node['end'] - 1, node['end']))
    walk(root)
    require(spans[0][0] == 0 and spans[-1][1] == len(data) and
            all(a < b for a, b in spans) and
            all(spans[i][1] == spans[i + 1][0] for i in range(len(spans) - 1)),
            'gap-free ordered segment partition')
    return spans


# This parser accepts only the emitted data-expression language. It neither
# invokes the emitter nor treats a manifest's claimed flattened value as true.
_TOKEN = re.compile(r'\s*(::|\+\+|\.[a-z]+|[A-Za-z][A-Za-z0-9_]*|[0-9]+|[\[\](),])')


@dataclass(frozen=True)
class _Raw:
    kind: str
    value: object


def _parse_expression(text, env):
    tokens, pos = [], 0
    while pos < len(text):
        match = _TOKEN.match(text, pos)
        require(match is not None, 'unsupported emitted data syntax')
        tokens.append(match.group(1))
        pos = match.end()
    index = 0
    def take(wanted=None):
        nonlocal index
        require(index < len(tokens), 'incomplete emitted expression')
        token = tokens[index]
        index += 1
        require(wanted is None or wanted == token, 'unexpected emitted token')
        return token
    def atom():
        token = take()
        if token == '(':
            first = expr()
            if index < len(tokens) and tokens[index] == ',':
                take(',')
                first = (first, expr())
            take(')')
            return first
        if token == '[':
            items = []
            if index < len(tokens) and tokens[index] != ']':
                items.append(expr())
                while index < len(tokens) and tokens[index] == ',':
                    take(',')
                    items.append(expr())
            take(']')
            return items
        if token.startswith('.'):
            require(token in ('.str', '.num', '.arr', '.obj'), 'unknown Raw constructor')
            return _Raw(token[1:], atom())
        if token.isdigit():
            return int(token)
        require(token in env, 'missing/forward data alias: ' + token)
        return env[token]
    def expr():
        left = atom()
        if index < len(tokens) and tokens[index] in ('::', '++'):
            op = take()
            right = expr()
            require(type(right) is list, 'list operator right type')
            if op == '::':
                return [left] + right
            require(type(left) is list, 'append left type')
            return left + right
        return left
    result = expr()
    require(index == len(tokens), 'unconsumed emitted expression')
    return result


def _raw_value(raw):
    require(isinstance(raw, _Raw), 'expected Raw expression')
    if raw.kind == 'num':
        require(type(raw.value) is int and 0 <= raw.value <= old.MAX_INTEGER, 'Raw numeric domain')
        return raw.value
    if raw.kind == 'str':
        require(type(raw.value) is list and all(type(n) is int and 32 <= n <= 126 and n not in (34, 92) for n in raw.value), 'Raw string domain')
        return bytes(raw.value).decode('ascii')
    require(type(raw.value) is list, 'Raw container domain')
    if raw.kind == 'arr':
        return [_raw_value(v) for v in raw.value]
    require(all(type(p) is tuple and len(p) == 2 for p in raw.value), 'Raw object pair domain')
    keys = [_raw_value(_Raw('str', p[0])) for p in raw.value]
    require(keys == sorted(set(keys)), 'Raw object keys duplicate or unordered')
    return {k: _raw_value(p[1]) for k, p in zip(keys, raw.value)}


def _byte_alias_bytes(value):
    """Read every actual value using exact builtin integer identity.

    C-level iteration preserves the old type/range domain without invoking
    metaclass equality, integer subclasses or user __index__ conversions.
    The caller retains the separate original expanded-length bound.
    """
    require(type(value) is list and
            all(map(is_, map(type, value), repeat(int))), 'byte alias range')
    try:
        return bytes(value)
    except (ValueError, OverflowError):
        require(False, 'byte alias range')


def verify_structured_source(source, manifest, expected_tree, expected_bytes):
    """Independently parse and flatten emitted aliases; fail closed on drift."""
    require(type(source) is str and type(manifest) is dict, 'structured source/manifest types')
    require(len(source.encode()) <= MAX_SOURCE_BYTES, 'structured source byte cap')
    require(type(expected_bytes) is bytes and old.strict_canonical(expected_bytes) == expected_tree,
            'independent original tree/bytes binding')
    require(manifest['schema'] == 'hepta.hia.structured-transport-input.v1', 'structured manifest schema')
    require(manifest['source_sha256'] == digest(source.encode()), 'structured source digest')
    require(all(type(manifest[name]) is int for name in
                ('canonical_bytes','leaf_byte_limit','transport_fuel','transport_depth')),
            'structured numeric metadata must be exact integers')
    require(manifest['canonical_sha256'] == digest(expected_bytes) and
            manifest['canonical_bytes'] == len(expected_bytes) and
            manifest['tree_sha256'] == digest(canonical(expected_tree)), 'original full-input identity')
    require(manifest['leaf_byte_limit'] == LEAF_BYTES and
            manifest['transport_fuel'] == old.MAX_NODES and manifest['transport_depth'] == old.MAX_DEPTH,
            'unchanged structured resource limits')
    ns = manifest['namespace']
    require(re.fullmatch(r'HiaCoreSyntaxSlice(?:\.[A-Za-z][A-Za-z0-9_]*)*', ns) is not None,
            'structured namespace')
    require(source.startswith('namespace ' + ns + '\n') and source.endswith('end ' + ns + '\n'),
            'exact namespace wrapper')
    require(not re.search(r'(?m)^\s*(import|namespace|end|axiom|opaque|unsafe|set_option|initialize|run_cmd|run_elab)\b',
                          source.split('\n', 1)[1].rsplit('end ' + ns, 1)[0]) and
            not re.search(r'\b(sorry|native_decide)\b', source), 'unsupported structured source command')
    env, definitions, expressions = {}, [], {}
    for match in re.finditer(r'(?m)^def ([A-Za-z][A-Za-z0-9_]*) : (.+?) := (.+)$', source):
        name, ty, rhs = match.groups()
        require(name not in env, 'duplicate data alias')
        require(ty in ('Raw', 'List Nat', 'List Raw', 'List (List Nat × Raw)'), 'unsupported data alias type')
        val = _parse_expression(rhs, env)
        if ty == 'Raw':
            _raw_value(val)
        elif ty == 'List Nat':
            _byte_alias_bytes(val)
            require(len(val) <= old.MAX_BYTES, 'byte alias length')
        elif ty == 'List Raw':
            require(type(val) is list, 'Raw list alias type')
            for v in val:
                _raw_value(v)
        else:
            _raw_value(_Raw('obj', val))
        env[name] = val
        expressions[name] = rhs
        definitions.append({'name': name, 'type': ty, 'rhs_sha256': digest(rhs.encode())})
    require(definitions == manifest['definitions'], 'exact emitted definition manifest')
    require(_raw_value(env[manifest['raw_name']]) == expected_tree, 'full emitted Raw differs')
    require(bytes(env[manifest['bytes_name']]) == expected_bytes, 'full emitted bytes differ')
    segments = manifest['segments']
    cursor = 0
    for entry in segments:
        start, end, name = entry['start'], entry['end'], entry['name']
        require(type(start) is int and type(end) is int, 'segment offsets must be exact integers')
        require(start == cursor and start < end <= len(expected_bytes), 'segment partition gap/order/overlap')
        require(type(env[name]) is list and bytes(env[name]) == expected_bytes[start:end], 'independently sourced segment differs')
        require(entry['sha256'] == digest(expected_bytes[start:end]), 'segment identity')
        cursor = end
    require(cursor == len(expected_bytes), 'complete segment coverage')
    root = _scan(expected_bytes)
    ledger = _ledger(root, expected_bytes)
    require(canonical(manifest['nodes']) == canonical(ledger), 'exact recursive fuel/depth/leaf/delimiter ledger')
    list_ledger = _list_ledger(root)
    require(canonical(manifest['list_steps']) == canonical(list_ledger), 'exact recursive list-step ledger')
    def check_node_aliases(node):
        ident = node['id']
        require(_raw_value(env[f'{manifest["stem"]}_r{ident}']) == node['value'],
                'exact complete subtree alias binding')
        require(bytes(env[f'{manifest["stem"]}_b{ident}']) == expected_bytes[node['start']:node['end']],
                'exact subtree byte interval binding')
        if not node['leaf']:
            for child in node['children']:
                check_node_aliases(child)
    check_node_aliases(root)
    spans = _segments(root, expected_bytes)
    require([(x['start'], x['end']) for x in segments] == spans, 'maximal complete leaf/key/punctuation partition')
    require(len(manifest['tails']) == len(segments) + 1, 'all segment suffix aliases')
    for index, name in enumerate(manifest['tails']):
        start = segments[index]['start'] if index < len(segments) else len(expected_bytes)
        require(bytes(env[name]) == expected_bytes[start:], 'exact segment suffix binding')
        rhs = segments[index]['name'] + ' ++ ' + manifest['tails'][index + 1] if index < len(segments) else '[]'
        require(expressions[name] == rhs, 'exact named suffix recurrence')
    # Preserve each root proposition, not only the printed declaration name.
    stem, cert = manifest['stem'], manifest['cert']
    require(all(re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', x) for x in (stem, cert)),
            'structured stem/certificate identifiers')
    require(manifest['raw_name'] == stem + 'Raw' and manifest['bytes_name'] == stem + 'Bytes',
            'original root declaration names')
    roots = {
        cert + '_bounds': f': withinBounds {stem}Raw = true',
        cert + '_serialized': f': serializeRaw transportFuel transportDepth {stem}Raw = some {stem}Bytes',
        cert + '_parsed': f': parseRaw transportFuel transportDepth {stem}Bytes = some ({stem}Raw, [])',
        cert + '_length': f': {stem}Bytes.length ≤ transportByteLimit',
        cert + '_byte_range': f': {stem}Bytes.all (fun byte => decide (byte ≤ 255)) = true',
        cert + '_transport': f': checkedEncode {stem}Raw = some {stem}Bytes',
    }
    for name, statement in roots.items():
        require(source.count('theorem ' + name + ' ' + statement + ' := ') == 1,
                'unchanged complete root theorem: ' + name)
    # Check the leaf/container equation schemas against the independently rebuilt
    # recursive ledger. In particular no numeric arbitrary-tail claim is allowed.
    for node in ledger:
        i, f, d = node['id'], node['fuel'], node['depth']
        r, b = f'{stem}_r{i}', f'{stem}_b{i}'
        serial = f'theorem {cert}_s{i} : serializeRaw {f} {d} {r} = some {b} := '
        residual = f'({node["delimiter"]} :: tail)' if node['kind'] == 'num' else 'tail'
        result_tail = f'{node["delimiter"]} :: tail' if node['kind'] == 'num' else 'tail'
        parsed = f'theorem {cert}_p{i} (tail : List Nat) : parseRaw {f} {d} ({b} ++ {residual}) = some ({r}, {result_tail}) := '
        require(source.count(serial) == 1 and source.count(parsed) == 1,
                'exact local fuel/depth and symbolic delimiter equation')
    for step in list_ledger:
        parent, i, f, d = step['parent'], step['index'], step['fuel'], step['depth']
        xs, bs = f'{stem}_l{parent}_{i}', f'{stem}_v{parent}_{i}'
        sf = 'serializeFields' if step['kind'] == 'obj' else 'serializeItems'
        pf = 'parseFields' if step['kind'] == 'obj' else 'parseItems'
        serial = f'theorem {cert}_sl{parent}_{i} : {sf} {f} {d} {xs} = some {bs} := '
        parsed = f'theorem {cert}_pl{parent}_{i} (tail : List Nat) : {pf} {f} {d} ({bs} ++ ({step["close"]} :: tail)) = some ({xs}, tail) := '
        require(source.count(serial) == 1 and source.count(parsed) == 1,
                'exact list-step fuel/depth/closing-delimiter equation')
    expected_names = set(roots)
    for node in ledger:
        expected_names.update((f'{cert}_s{node["id"]}', f'{cert}_p{node["id"]}'))
        if not node['leaf'] and node['kind'] == 'obj':
            expected_names.add(f'{cert}_o{node["id"]}')
    for step in list_ledger:
        suffix = f'{step["parent"]}_{step["index"]}'
        expected_names.update((cert + '_sl' + suffix, cert + '_pl' + suffix))
        if step['kind'] == 'obj':
            expected_names.update((cert + '_kd' + suffix, cert + '_kp' + suffix))
    names = re.findall(r'(?m)^theorem ([A-Za-z][A-Za-z0-9_]*)\b', source)
    require(set(names) == expected_names, 'independently derived complete theorem inventory')
    require(len(names) == len(set(names)) and
            sorted(ns + '.' + n for n in names) == manifest['expected_theorems'], 'complete named theorem inventory')
    require(len(definitions) == source.count('\ndef '), 'unsupported multiline data declaration')
    require(all(line.startswith(('def ', 'theorem ', '  simpa only ['))
                for line in source.splitlines()[1:-1]), 'unexpected generated command or proof form')
    return {'canonical_sha256': digest(expected_bytes), 'leaf_count': sum(n['leaf'] for n in ledger),
            'container_count': sum(not n['leaf'] for n in ledger), 'segment_count': len(segments),
            'theorem_count': len(names), 'source_bytes': len(source.encode())}


def build_structured_input(key, tree, canonical_bytes, namespace, stem, cert):
    require(type(tree) is dict and old.strict_canonical(canonical_bytes) == tree, 'complete canonical Core object required')
    require(re.fullmatch(r'HiaCoreSyntaxSlice(?:\.[A-Za-z][A-Za-z0-9_]*)*', namespace) is not None,
            'full structured namespace')
    require(all(type(x) is str and re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*', x) for x in (key, stem, cert)),
            'structured identifiers')
    root = _scan(canonical_bytes)
    nodes = _ledger(root, canonical_bytes)
    spans = _segments(root, canonical_bytes)
    lines, definitions, names = ['namespace ' + namespace + '\n'], [], []
    segments, lookup = [], {}
    def define(name, ty, rhs):
        lines.append(f'def {name} : {ty} := {rhs}\n')
        definitions.append({'name': name, 'type': ty, 'rhs_sha256': digest(rhs.encode())})
        return name
    def theorem(name, statement, proof):
        lines.append(f'theorem {name} {statement} := {proof}\n')
        names.append(namespace + '.' + name)
        return name
    def simp_using(unfold, term):
        # Only local aliases and append equations; never the transport evaluator
        # or an opaque residual tail. Do not use unrestricted simp here.
        rules = list(dict.fromkeys(unfold)) + ['List.append_assoc', 'List.cons_append', 'List.nil_append', 'List.append_nil']
        return 'by\n  simpa only [' + ', '.join(rules) + '] using (' + term + ')'
    for index, (start, end) in enumerate(spans):
        name = define(f'{stem}_g{index}', 'List Nat', old.render_bytes(canonical_bytes[start:end]))
        segments.append({'name': name, 'start': start, 'end': end, 'sha256': digest(canonical_bytes[start:end])})
        lookup[(start, end)] = name
    tails = [f'{stem}_t{i}' for i in range(len(spans) + 1)]
    define(tails[-1], 'List Nat', '[]')
    for i in range(len(spans) - 1, -1, -1):
        define(tails[i], 'List Nat', segments[i]['name'] + ' ++ ' + tails[i + 1])

    def emit(node):
        ident, fuel, depth = node['id'], node['fuel'], node['depth']
        r, b = f'{stem}_r{ident}', f'{stem}_b{ident}'
        ser, par = f'{cert}_s{ident}', f'{cert}_p{ident}'
        node.update(r=r, b=b, ser=ser, par=par)
        if node['leaf']:
            g = lookup[(node['start'], node['end'])]
            define(r, 'Raw', old.render_raw(node['value']))
            define(b, 'List Nat', g)
            theorem(ser, f': serializeRaw {fuel} {depth} {r} = some {b}', 'by decide +kernel')
            if node['kind'] == 'num':
                delim = canonical_bytes[node['end']]
                statement = f'(tail : List Nat) : parseRaw {fuel} {depth} ({b} ++ ({delim} :: tail)) = some ({r}, {delim} :: tail)'
            else:
                statement = f'(tail : List Nat) : parseRaw {fuel} {depth} ({b} ++ tail) = some ({r}, tail)'
            theorem(par, statement, 'by rfl')
            return
        children = node['children']
        for child in children:
            emit(child)
        obj = node['kind'] == 'obj'
        close = 125 if obj else 93
        opening = lookup[(node['start'], node['start'] + 1)]
        closing = lookup[(node['end'] - 1, node['end'])]
        xs, bs, ss, ps, keys, packets, kd, kp = [], [], [], [], [], [], [], []
        for i, child in enumerate(children):
            xs.append(f'{stem}_l{ident}_{i}')
            bs.append(f'{stem}_v{ident}_{i}')
            ss.append(f'{cert}_sl{ident}_{i}')
            ps.append(f'{cert}_pl{ident}_{i}')
            if obj:
                k = define(f'{stem}_k{ident}_{i}', 'List Nat', old.render_bytes(node['keys'][i].encode('ascii')))
                keys.append(k)
                packets.append(lookup[node['key_spans'][i]])
                kd.append(theorem(f'{cert}_kd{ident}_{i}', f': stringBytes {k} = true', 'by decide +kernel'))
                kp.append(theorem(f'{cert}_kp{ident}_{i}',
                    f'(tail : List Nat) : parseStringTail ({k} ++ (34 :: 58 :: tail)) [] = some ({k}, 58 :: tail)', 'by rfl'))
        for i in range(len(children) - 1, -1, -1):
            child = children[i]
            last = i == len(children) - 1
            f, d = fuel - 2 - i, depth - 1
            item = '(' + keys[i] + ', ' + child['r'] + ')' if obj else child['r']
            list_rhs = '[' + item + ']' if last else item + ' :: ' + xs[i + 1]
            define(xs[i], 'List (List Nat × Raw)' if obj else 'List Raw', list_rhs)
            value_b = packets[i] + ' ++ ' + child['b'] if obj else child['b']
            byte_rhs = value_b if last else '(' + value_b + ') ++ (44 :: ' + bs[i + 1] + ')'
            define(bs[i], 'List Nat', byte_rhs)
            local = [xs[i], bs[i]] + ([keys[i], packets[i]] if obj else [])
            if not last:
                local += [xs[i + 1]]
            if obj:
                if last:
                    term = f'{HELPER}serialize_fields_single {f} {d} {keys[i]} {child["r"]} {child["b"]} {kd[i]} {child["ser"]}'
                else:
                    nxt = children[i + 1]
                    rest = '[]' if i + 2 == len(children) else xs[i + 2]
                    term = f'{HELPER}serialize_fields_cons {f} {d} {keys[i]} {child["r"]} ({keys[i+1]}, {nxt["r"]}) {rest} {child["b"]} {bs[i+1]} {kd[i]} {child["ser"]} {ss[i+1]}'
            elif last:
                term = f'{HELPER}serialize_items_single {f} {d} {child["r"]} {child["b"]} {child["ser"]}'
            else:
                nxt = children[i + 1]
                rest = '[]' if i + 2 == len(children) else xs[i + 2]
                term = f'{HELPER}serialize_items_cons {f} {d} {child["r"]} {nxt["r"]} {rest} {child["b"]} {bs[i+1]} {child["ser"]} {ss[i+1]}'
            function = 'serializeFields' if obj else 'serializeItems'
            theorem(ss[i], f': {function} {f+1} {d} {xs[i]} = some {bs[i]}', simp_using(local, term))
            middle = f'({bs[i+1]} ++ ({close} :: tail))' if not last else 'tail'
            residual = f'({close} :: tail)' if last else f'(44 :: {middle})'
            value_input = f'({child["b"]} ++ {residual})'
            child_arg = middle if child['kind'] == 'num' else residual
            child_proof = f'({child["par"]} {child_arg})'
            if obj:
                key_input = f'({keys[i]} ++ (34 :: 58 :: {value_input}))'
                key_proof = f'({kp[i]} {value_input})'
                if last:
                    term = f'{HELPER}parse_fields_last {f} {d} {key_input} {keys[i]} {value_input} tail {child["r"]} {key_proof} {child_proof}'
                else:
                    term = f'{HELPER}parse_fields_cons {f} {d} {key_input} {keys[i]} {value_input} {middle} tail {child["r"]} {xs[i+1]} {key_proof} {child_proof} ({ps[i+1]} tail)'
                function = 'parseFields'
            elif last:
                term = f'{HELPER}parse_items_last {f} {d} {value_input} tail {child["r"]} {child_proof}'
                function = 'parseItems'
            else:
                term = f'{HELPER}parse_items_cons {f} {d} {value_input} {middle} tail {child["r"]} {xs[i+1]} {child_proof} ({ps[i+1]} tail)'
                function = 'parseItems'
            theorem(ps[i], f'(tail : List Nat) : {function} {f+1} {d} ({bs[i]} ++ ({close} :: tail)) = some ({xs[i]}, tail)', simp_using(local, term))
        define(r, 'Raw', '(.obj ' + xs[0] + ')' if obj else '(.arr ' + xs[0] + ')')
        define(b, 'List Nat', opening + ' ++ (' + bs[0] + ' ++ ' + closing + ')')
        local = [r, b, opening, closing]
        if obj:
            ordered = theorem(f'{cert}_o{ident}', f': orderedFields {xs[0]} = true', 'by decide +kernel')
            term = f'{HELPER}serialize_object {fuel-1} {depth-1} {xs[0]} {bs[0]} {ordered} {ss[0]}'
        else:
            term = f'{HELPER}serialize_array {fuel-1} {depth-1} {xs[0]} {bs[0]} {ss[0]}'
        theorem(ser, f': serializeRaw {fuel} {depth} {r} = some {b}', simp_using(local, term))
        if obj:
            first = children[0]
            residual = f'({close} :: tail)' if len(children) == 1 else f'(44 :: ({bs[1]} ++ ({close} :: tail)))'
            vi = f'({first["b"]} ++ {residual})'
            ki = f'({keys[0]} ++ (34 :: 58 :: {vi}))'
            bridge_rules = [bs[0], keys[0], packets[0], 'List.append_assoc', 'List.cons_append', 'List.nil_append', 'List.append_nil']
            bridge = '(by simpa only [' + ', '.join(bridge_rules) + f'] using ({ps[0]} tail))'
            term = f'{HELPER}parse_object {fuel-1} {depth-1} {ki} tail {xs[0]} {ordered} {bridge}'
            local += [bs[0], keys[0], packets[0]]
        else:
            inp = f'({bs[0]} ++ (93 :: tail))'
            term = f'{HELPER}parse_array {fuel-1} {depth-1} {inp} tail {xs[0]} (by intro h; cases h) ({ps[0]} tail)'
        theorem(par, f'(tail : List Nat) : parseRaw {fuel} {depth} ({b} ++ tail) = some ({r}, tail)', simp_using(local, term))
    emit(root)
    define(stem + 'Raw', 'Raw', root['r'])
    define(stem + 'Bytes', 'List Nat', root['b'])
    theorem(cert + '_bounds', f': withinBounds {stem}Raw = true', 'by decide +kernel')
    theorem(cert + '_serialized', f': serializeRaw transportFuel transportDepth {stem}Raw = some {stem}Bytes', f'by exact {root["ser"]}')
    theorem(cert + '_parsed', f': parseRaw transportFuel transportDepth {stem}Bytes = some ({stem}Raw, [])',
            simp_using([], root['par'] + ' []'))
    theorem(cert + '_length', f': {stem}Bytes.length ≤ transportByteLimit', 'by decide +kernel')
    theorem(cert + '_byte_range', f': {stem}Bytes.all (fun byte => decide (byte ≤ 255)) = true', 'by decide +kernel')
    theorem(cert + '_transport', f': checkedEncode {stem}Raw = some {stem}Bytes',
            f'checkedEncode_of_parts {stem}Raw {stem}Bytes {cert}_bounds {cert}_serialized {cert}_parsed {cert}_length {cert}_byte_range')
    lines.append('end ' + namespace + '\n')
    source = ''.join(lines)
    require(len(source.encode()) <= MAX_SOURCE_BYTES, 'structured source byte cap')
    manifest = {'schema': 'hepta.hia.structured-transport-input.v1', 'key': key,
                'namespace': namespace, 'stem': stem, 'cert': cert,
                'canonical_sha256': digest(canonical_bytes), 'canonical_bytes': len(canonical_bytes),
                'tree_sha256': digest(canonical(tree)), 'leaf_byte_limit': LEAF_BYTES,
                'transport_fuel': old.MAX_NODES, 'transport_depth': old.MAX_DEPTH,
                'raw_name': stem + 'Raw', 'bytes_name': stem + 'Bytes',
                'segments': segments, 'tails': tails, 'nodes': nodes, 'list_steps': _list_ledger(root),
                'definitions': definitions, 'expected_theorems': sorted(names),
                'source_sha256': digest(source.encode())}
    verify_structured_source(source, manifest, tree, canonical_bytes)
    return StructuredInput(source, frozenset(names), json.dumps(manifest, sort_keys=True, separators=(',', ':')))
