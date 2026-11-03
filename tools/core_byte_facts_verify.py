"""Independent source-insertion checker, not Lean elaboration or acceptance.

This module deliberately imports neither the proposal emitter nor its rendering
helpers. The original preparation must already have passed the exact11 oracle,
and the caller must have checked the reversible edit ledger first.
"""
from hashlib import sha256
import json
import re

from tools.core_byte_facts_dag import analyze
from tools.core_syntax_partition_sources import ROOT_OWNERS

_HELPER_NS = 'HiaCoreSyntaxSlice.ByteFactsResearch'
_PREDICATE = _HELPER_NS + '.facts'
_HELPERS = frozenset(_HELPER_NS + '.' + x for x in ('nil', 'cons', 'append'))
_HELPER_HASH = '58b2081fe8736aa150f597ba02f51a241bfc8206c6c310004b8d7664383fe026'
_FRAME = re.compile(r'theorem ([A-Za-z][A-Za-z0-9_]*) : '
                    + re.escape(_PREDICATE)
                    + r' ([A-Za-z][A-Za-z0-9_]*) (0|[1-9][0-9]*) := (by(?: decide \+kernel)?)\n')


def _check(ok, reason):
    if not ok:
        raise ValueError('independent byte-fact insertion: ' + reason)


def _hash(raw):
    return sha256(raw).hexdigest()


def _json_hash(value):
    return _hash(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode())


def _scope_at(raw, offset):
    """Check the actual original namespace at a byte boundary, not ledger claims."""
    scope = None
    for line in raw[:offset].decode().splitlines():
        if line.startswith('namespace '):
            _check(scope is None, 'nested original namespace')
            scope = line[len('namespace '):]
        elif line.startswith('end '):
            _check(line[len('end '):] == scope, 'original namespace close')
            scope = None
    return scope


def _tree_terms(root, earlier):
    """Bottom-up certificate checking terms, independently from the emitter.

    Each result binds a list expression, its evaluated length, and its unique
    allowed evidence. Explicit references use only earlier original DAG rows.
    """
    work, values = [(root, False)], {}
    while work:
        node, ready = work.pop()
        tag = node[0]
        children = node[1:3] if tag == 'append' else (node[2],) if tag == 'cons' else ()
        if children and not ready:
            work.append((node, True))
            work.extend((child, False) for child in reversed(children))
            continue
        if tag == 'literal':
            expression = '[' + ', '.join(str(b) for b in node[1]) + ']'
            size = len(node[1])
            evidence = f'(by decide +kernel : {_PREDICATE} {expression} {size})'
        elif tag == 'ref':
            _check(node[1] in earlier, 'unknown or forward child fact')
            size, evidence = earlier[node[1]]
            expression = node[1]
        elif tag == 'cons':
            tail, length, proof = values[id(node[2])]
            expression = f'({node[1]} :: {tail})'
            size = length + 1
            evidence = f'({_HELPER_NS}.cons {node[1]} {tail} {length} (by decide +kernel) {proof})'
        elif tag == 'append':
            left, n, lp = values[id(node[1])]
            right, m, rp = values[id(node[2])]
            expression = f'({left} ++ {right})'
            size = n + m
            evidence = f'({_HELPER_NS}.append {left} {right} {n} {m} {lp} {rp})'
        else:
            raise ValueError('unsupported independently parsed byte AST')
        values[id(node)] = (expression, size, evidence)
    return values[id(root)]


def _check_fact_block(block, plan, stem):
    pos, known, names = 0, {}, []
    for ordinal, row in enumerate(plan['rows']):
        frame = _FRAME.match(block, pos)
        _check(frame is not None, 'fact declaration frame or count')
        name, reference, numeral, mode = frame.groups()
        expected_name = f'{stem}_bf{ordinal:04d}'
        _check(name == expected_name and reference == row['name'], 'fact name, order or original target')
        _, length, proof = _tree_terms(row['ast'], known)
        _check(length == row['length'] == int(numeral), 'fact length proposal')
        pos = frame.end()
        if row['ast'][0] == 'literal':
            _check(mode == 'by decide +kernel', 'literal proof schema')
        else:
            _check(mode == 'by', 'nonliteral proof schema')
            end = block.find('\n', pos)
            _check(end >= pos, 'missing proof continuation')
            expected = f"  simpa only [{row['name']}] using {proof}"
            _check(block[pos:end] == expected, 'explicit child evidence or immediate-only proof template')
            pos = end + 1
        known[row['name']] = (length, name)
        names.append(plan['namespace'] + '.' + name)
    _check(pos == len(block), 'extra fact declarations, commands or proof text')
    _check(plan['root'] == stem + 'Bytes' and plan['root'] in known, 'actual Bytes root')
    return frozenset(names), known[plan['root']]


def validate_insertions(prepared, proposal):
    """Validate every added byte independently, after exact inverse validation."""
    old_stages = {s.name: s for s in prepared['stages']}
    new_stages = {s.name: s for s in proposal.stages}
    manifest = proposal.manifest
    ledger = manifest['edits']
    _check(set(old_stages) == set(new_stages) == set(ledger), 'complete stage inventory')
    expected_edits = {name: [] for name in old_stages}
    added = {name: set() for name in old_stages}
    summaries = {}

    def interval(stage, kind, anchor, namespace, start, end):
        matches = [e for e in ledger[stage] if e['kind'] == kind and e['anchor'] == anchor]
        _check(len(matches) == 1, 'missing or duplicate edit anchor')
        edit = matches[0]
        _check(edit['namespace'] == namespace and edit['original_start'] == start
               and edit['original_end'] == end, 'edit placement, namespace or extent')
        expected_edits[stage].append(edit)
        return new_stages[stage].source.encode()[edit['transformed_start']:edit['transformed_end']]

    syntax = old_stages['SyntaxData'].source.encode()
    _check(_scope_at(syntax, len(syntax)) is None, 'helper placement outside original namespaces')
    helper_block = interval('SyntaxData', 'helpers', 'fixed_helpers', _HELPER_NS, len(syntax), len(syntax))
    helper_prints = ''.join('#print axioms ' + name + '\n' for name in sorted(_HELPERS)).encode()
    _check(helper_block.endswith(helper_prints), 'exact helper print inventory')
    _check(_hash(helper_block[:-len(helper_prints)]) == _HELPER_HASH, 'fixed predicate and helper contracts/proofs')
    added['SyntaxData'].update(_HELPERS)
    _check(set(prepared['structured_certificates']) == set(ROOT_OWNERS), 'five original complete inputs')
    original_names = set().union(*(s.expected_theorems for s in old_stages.values()))
    total_roots = 0
    for key, item in prepared['structured_certificates'].items():
        meta = item['manifest']
        namespace, stem, cert = (meta[k] for k in ('namespace', 'stem', 'cert'))
        plan = analyze(item['source'], namespace, stem, prepared['binding_inputs'][key]['bytes'])
        _check(len(plan['rows']) == 595 and sum(r['ast'][0] == 'literal' for r in plan['rows']) == 281,
               'fixed reachable DAG inventory')
        owner = ROOT_OWNERS[key]
        raw = old_stages[owner].source.encode()
        targets = ((cert + '_length', stem + 'Bytes.length ≤ transportByteLimit'),
                   (cert + '_byte_range', stem + 'Bytes.all (fun byte => decide (byte ≤ 255)) = true'))
        positions = []
        for name, target in targets:
            prefix = f'theorem {name} : {target} := '.encode()
            complete = prefix + b'by decide +kernel\n'
            _check(raw.count(complete) == 1, 'unchanged unique original root target')
            start = raw.index(complete)
            _check(start == 0 or raw[start-1:start] == b'\n', 'root declaration boundary')
            _check(_scope_at(raw, start) == namespace, 'actual root namespace')
            positions.append((start, start + len(prefix), start + len(complete) - 1))
        block_bytes = interval(owner, 'facts', namespace + '.' + targets[0][0], namespace,
                               positions[0][0], positions[0][0])
        names, (length, root_fact) = _check_fact_block(block_bytes.decode(), plan, stem)
        _check(len(names) == 595 and not names.intersection(original_names), 'auxiliary inventory collision')
        original_declared = set(re.findall(r'^(?:def|theorem) ([A-Za-z][A-Za-z0-9_]*)\b', item['source'], re.M))
        _check(not {n.rsplit('.', 1)[1] for n in names}.intersection(original_declared), 'original data name collision')
        proofs = (f'by\n  rw [({root_fact}).1]\n  decide +kernel', f'by exact ({root_fact}).2')
        for (name, _), (_, start, end), proof in zip(targets, positions, proofs):
            actual = interval(owner, 'root_proof', namespace + '.' + name, namespace, start, end)
            _check(actual.decode() == proof, 'root proof must project actual Bytes fact')
            total_roots += 1
        _check(_scope_at(raw, len(raw)) is None, 'added prints outside original namespaces')
        prints = interval(owner, 'prints', 'auxiliary_inventory', namespace, len(raw), len(raw))
        _check(prints.decode() == ''.join('#print axioms ' + n + '\n' for n in sorted(names)),
               'auxiliary prints exactly once in fixed order')
        added[owner].update(names)
        summaries[key] = dict(namespace=namespace, stem=stem, owner=owner, root=plan['root'],
            fact_count=595, graph_sha256=plan['graph_digest'], input_source_sha256=plan['source_sha256'],
            bytes_sha256=_hash(prepared['binding_inputs'][key]['bytes']), bytes_length=length,
            auxiliary_source_sha256=_hash(block_bytes), auxiliary_inventory_sha256=_json_hash(sorted(names)))
    _check(total_roots == 10, 'exact ten root replacements')
    _check(manifest['inputs'] == summaries, 'independently reconstructed input summaries')
    _check(manifest['helper_sha256'] == _HELPER_HASH and manifest['helper_definition'] == _PREDICATE
           and manifest['helper_theorems'] == sorted(_HELPERS), 'helper manifest inventory')
    _check(manifest['auxiliary_theorem_count'] == 2975, 'total auxiliary count')
    for name, old in old_stages.items():
        _check(sorted(expected_edits[name], key=lambda e: (e['original_start'], e['original_end']))
               == ledger[name], 'extra, omitted or reordered insertion')
        new = new_stages[name]
        _check(new.expected_theorems == old.expected_theorems | frozenset(added[name]),
               'exact old plus independent auxiliary inventory')
        actual_prints = re.findall(r'^#print axioms ([A-Za-z][A-Za-z0-9_.]*)$', new.source, re.M)
        for target in added[name]:
            _check(actual_prints.count(target) == 1, 'added axiom print multiplicity')
    return dict(auxiliary_theorem_count=2975, helper_theorem_count=3, root_proof_count=10)
