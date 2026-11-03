"""Isolated Core syntax transport research; no admission or runtime refinement.

Python proposes inert data. Only a future successful locked kernel check of the
independent syntax relation can establish the deliberately narrow connection.
"""
import json
import re
from pathlib import Path

from tools.check_guarded_slice_lean import require

MAX_BYTES = 32768
MAX_NODES = 4096
MAX_DEPTH = 32
MAX_PROOF_BYTES = 2 * 1024 * 1024
MAX_INTEGER = 2**64 - 1


def _string(value):
    require(type(value) is str and len(value) <= MAX_BYTES and all(32 <= ord(c) <= 126 and c not in '\\"' for c in value),
            'unsupported restricted string')
    return value


def _validate(value):
    # Iterative before recursive generation; reject bool even though it is int's subclass.
    pending = [(value, 1)]
    nodes = 0
    string_bytes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        require(nodes <= MAX_NODES and depth <= MAX_DEPTH, 'transport structural budget')
        if type(item) is dict:
            require(nodes + len(pending) + len(item) <= MAX_NODES, 'transport node budget')
            for key in item:
                _string(key)
                string_bytes += len(key)
                require(string_bytes <= MAX_BYTES, 'transport string budget')
            keys = list(item)
            require(keys == sorted(keys), 'noncanonical object order')
            for key, child in item.items():
                pending.append((child, depth + 1))
        elif type(item) is list:
            require(nodes + len(pending) + len(item) <= MAX_NODES, 'transport node budget')
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            require(len(item) <= MAX_BYTES, 'transport string budget')
            _string(item)
            string_bytes += len(item)
            require(string_bytes <= MAX_BYTES, 'transport string budget')
        else:
            require(type(item) is int and 0 <= item <= MAX_INTEGER, 'unsupported restricted integer/value')
    return value


def strict_canonical(raw):
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, 'canonical input byte budget/type')
    # Scan depth before json.loads can recurse or allocate a deeply nested graph.
    quoted = False
    depth = 0
    for byte in raw:
        require(32 <= byte <= 126, 'unsupported canonical input byte')
        if byte == 92:
            raise ValueError('escaped strings unsupported')
        if byte == 34:
            quoted = not quoted
        elif not quoted:
            if byte in (91, 123):
                depth += 1
                require(depth <= MAX_DEPTH, 'transport depth budget')
            elif byte in (93, 125):
                depth -= 1
                require(depth >= 0, 'unbalanced input')
    require(not quoted and depth == 0, 'unbalanced input')

    def pairs(rows):
        keys = [k for k, _ in rows]
        require(len(keys) == len(set(keys)), 'duplicate object keys')
        require(keys == sorted(keys), 'noncanonical object order')
        return dict(rows)

    def integer(token):
        require(re.fullmatch(r'0|[1-9][0-9]*', token) is not None and len(token) <= 20,
                'noncanonical integer')
        n = int(token)
        require(n <= MAX_INTEGER, 'integer range')
        return n

    def refused(_):
        raise ValueError('noninteger JSON number')

    value = json.loads(raw, object_pairs_hook=pairs, parse_int=integer,
                       parse_float=refused, parse_constant=refused)
    _validate(value)
    require(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                       allow_nan=False).encode('ascii') == raw, 'noncanonical byte spelling')
    return value


def render_bytes(sequence):
    require(type(sequence) in (list, tuple, bytes) and len(sequence) <= MAX_BYTES,
            'byte literal budget/type')
    require(all(type(n) is int and 0 <= n < 256 for n in sequence), 'byte numeral range/type')
    return '[' + ','.join(str(n) for n in sequence) + ']'


def checked_source(parts):
    chunks = []
    total = 0
    for part in parts:
        require(type(part) is str, 'proof text type')
        # Bound before appending/concatenating; UTF-8 expansion included.
        require(total + len(part) <= MAX_PROOF_BYTES, 'proof text byte budget')
        size = len(part.encode('utf-8'))
        total += size
        require(total <= MAX_PROOF_BYTES, 'proof text byte budget')
        chunks.append(part)
    return ''.join(chunks)


def render_raw(value):
    _validate(value)
    require(len(json.dumps(value, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=False, allow_nan=False).encode('ascii')) <= MAX_BYTES,
            'canonical render byte budget')
    # This producer is intentionally not the kernel extractor. Canonical byte
    # equality must independently check its output, including ALL unused fields.
    def parts(item):
        if type(item) is str:
            yield '(.str ' + render_bytes([ord(c) for c in item]) + ')'
        elif type(item) is int:
            yield '(.num ' + str(item) + ')'
        elif type(item) is list:
            yield '(.arr ['
            for i, child in enumerate(item):
                if i:
                    yield ','
                yield from parts(child)
            yield '])'
        else:
            yield '(.obj ['
            for i, (key, child) in enumerate(item.items()):
                if i:
                    yield ','
                yield '(' + render_bytes([ord(c) for c in key]) + ','
                yield from parts(child)
                yield ')'
            yield '])'
    return checked_source(parts(value))


def fixed_input():
    """Rebuild one real candidate; no selected fields copied into raw transport."""
    from hepta.hia_program import verify_program
    from hepta.hia_program_source import lower_source
    from hepta.hia_reduction import propose_reduction_pipeline
    from tools.experimental_deferred_guard_proposer import propose_deferred_guard
    from tools.check_dynamic_unsigned_step import extract_step_slices
    root = Path(__file__).resolve().parents[1]
    base = lower_source((root / 'benchmarks/hia_reduction_release/linear.hepta').read_text())
    core = verify_program(propose_deferred_guard(base,
                propose_reduction_pipeline(base, include_induction=True))['candidate_core'])
    original = core.canonical_bytes
    tree = strict_canonical(original)
    hints = extract_step_slices(core)
    require(hints['status'] == 'extracted' and len(hints['slices']) == 4, 'fixed slice inventory')
    hint = hints['slices'][0]
    # Source identity is independent of how either proposed Lean structure prints.
    return {'bytes': original, 'tree': tree, 'core_sha256': core.sha256,
            'hint': {k: hint[k] for k in ('function', 'header', 'target',
                       'compare_ordinal', 'step_ordinal', 'body_index', 'body_extent')}}


def render_hint(tree, locator):
    functions = tree['functions']
    function_indices = [n for n, f in enumerate(functions) if f['name'] == locator['function']]
    require(len(function_indices) == 1, 'ambiguous function locator')
    fi = function_indices[0]
    blocks = functions[fi]['blocks']
    positions = {}
    for field in ('header', 'target'):
        matches = [n for n, b in enumerate(blocks) if b['id'] == locator[field]]
        require(len(matches) == 1, 'ambiguous block locator')
        positions[field] = matches[0]
    require(type(locator['compare_ordinal']) is int and locator['compare_ordinal'] == 0,
            'only sole header compare supported')
    ordinal = locator['step_ordinal']
    require(type(ordinal) is int and 0 <= ordinal < 2048, 'add ordinal bound')
    names = []
    for key in ('body_index', 'body_extent'):
        names.append(render_bytes([ord(c) for c in _string(locator[key])]))
    return ('{ functionIndex := ' + str(fi) + ', headerIndex := ' + str(positions['header']) +
            ', targetIndex := ' + str(positions['target']) + ', addOrdinal := ' + str(ordinal) +
            ', bodyIndex := ' + names[0] + ', bodyExtent := ' + names[1] + ' }')


ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / 'experiments/hia_initialization_frontiers_20261103/CoreSyntaxSlice.lean'
NAMESPACE = 'HiaCoreSyntaxSlice'
MODEL_THEOREMS = {'checkedEncode_roundtrip', 'checkedEncode_determinate',
                  'extract_sound', 'extracted_successor'}
MAX_TOTAL_PROOF_BYTES = 8 * 1024 * 1024


def source_identity():
    from tools import check_guarded_slice_lean as previous
    from hashlib import sha256
    result = previous.source_identity()
    for path in (Path(__file__), MODEL,
                 ROOT / '.github/workflows/hia-core-syntax-kernel-research.yml'):
        result[str(path.relative_to(ROOT))] = sha256(path.read_bytes()).hexdigest()
    return result


def _model():
    text = MODEL.read_text()
    require(not re.search(r'(?m)^\s*(import|axiom|unsafe|opaque|constant|initialize|builtin_initialize|run_elab|run_cmd|elab|macro|syntax|set_option)\b|\b(sorry|native_decide)\b', text),
            'unsupported model command or placeholder')
    names = set(re.findall(r'(?m)^theorem (\w+)', text))
    require(MODEL_THEOREMS <= names, 'missing model theorem')
    return text


def _definitions(tree, raw, hint):
    literal = render_bytes(raw)
    # Check the exact emitted numeral payload independently of the tree producer.
    require(re.fullmatch(r'\[(?:[0-9]+(?:,[0-9]+)*)?\]', literal) is not None,
            'nonliteral byte payload')
    numbers = [] if literal == '[]' else [int(n) for n in literal[1:-1].split(',')]
    require(all(0 <= n < 256 for n in numbers) and bytes(numbers) == raw,
            'emitted exact byte literal differs')
    return checked_source(('\nnamespace HiaCoreSyntaxSlice\n',
        'def linearRaw : Raw := ' + render_raw(tree) + '\n',
        'def linearBytes : List Nat := ' + literal + '\n',
        'def linearHint : Hint := ' + render_hint(tree, hint) + '\n'))


def build_inputs():
    """One real slice first; neither Python extraction nor mock checks prove it."""
    from copy import deepcopy
    from hepta.hia_program import verify_program
    from tools import check_guarded_slice_lean as previous
    from hashlib import sha256
    baseline = previous.build_inputs()
    fixed = fixed_input()
    model = _model()
    defs = _definitions(fixed['tree'], fixed['bytes'], fixed['hint'])
    proofs = '''theorem linear_transport : checkedEncode linearRaw = some linearBytes := by decide
 theorem linear_extraction : extract linearRaw linearHint = some HiaGuardedUsizeSlice.linear_0 := by decide
 theorem linear_relation : SliceSyntaxRelation linearRaw linearHint HiaGuardedUsizeSlice.linear_0 :=
   extract_sound linearRaw linearHint HiaGuardedUsizeSlice.linear_0 linear_extraction
'''.replace('\n theorem', '\ntheorem')
    parallel = deepcopy(fixed['tree'])
    fn = next(f for f in parallel['functions'] if f['name'] == fixed['hint']['function'])
    blocks = {b['id']:b for b in fn['blocks']}
    header, body = blocks[fixed['hint']['header']], blocks[fixed['hint']['target']]
    # Keep the original else target reachable; only vary its same-typed operands.
    else_target = header['term']['else']['target']
    header['term']['else'] = deepcopy(header['term']['then'])
    header['term']['else']['target'] = else_target
    names = [p['name'] for p in body['params']]
    i, n = names.index(fixed['hint']['body_index']), names.index(fixed['hint']['body_extent'])
    args = header['term']['else']['args']
    args[i], args[n] = args[n], args[i]
    parallel_bytes = verify_program(parallel).canonical_bytes
    parallel_tree = strict_canonical(parallel_bytes)
    parallel_defs = _definitions(parallel_tree, parallel_bytes, fixed['hint']).replace('linearRaw','parallelRaw').replace('linearBytes','parallelBytes').replace('linearHint','parallelHint')
    parallel_proofs = '''theorem parallel_transport : checkedEncode parallelRaw = some parallelBytes := by decide
 theorem parallel_extraction : extract parallelRaw parallelHint = some HiaGuardedUsizeSlice.linear_0 := by decide
'''.replace('\n theorem','\ntheorem')
    new_names = MODEL_THEOREMS | {'linear_transport', 'linear_extraction', 'linear_relation',
                                 'parallel_transport', 'parallel_extraction'}
    printed = ''.join('#print axioms '+NAMESPACE+'.'+name+'\n' for name in sorted(new_names))
    positive = checked_source((baseline['positive'], model, defs, proofs,
                               'end HiaCoreSyntaxSlice\n', parallel_defs, parallel_proofs, 'end HiaCoreSyntaxSlice\n', printed))
    # Negative declarations do not print failed-theorem placeholders as axioms.
    common = re.sub(r'(?m)^#print axioms .*\n', '', baseline['positive'] + model)
    negatives = {}
    proof_bytes = len(positive.encode())
    require(proof_bytes <= MAX_TOTAL_PROOF_BYTES, 'total proof input budget')

    def negative(name, definitions, proposition, kind):
        nonlocal proof_bytes
        start = checked_source((common, definitions))
        line = start.count('\n') + 1
        source = checked_source((start, 'theorem intended_negative : '+proposition+' := by decide\n',
                                 'end HiaCoreSyntaxSlice\n'))
        proof_bytes += len(source.encode())
        require(proof_bytes <= MAX_TOTAL_PROOF_BYTES, 'total proof input budget')
        negatives[name] = {'source': source, 'failure_lines': [line, line], 'kind': kind}

    changed = bytearray(fixed['bytes'])
    changed[-1] = 93 if changed[-1] != 93 else 125
    negative('changed_exact_byte', _definitions(fixed['tree'], bytes(changed), fixed['hint']),
             'checkedEncode linearRaw = some linearBytes', 'transport_equality')
    negative('stale_descriptor', defs,
             'extract linearRaw linearHint = some { HiaGuardedUsizeSlice.linear_0 with literalValue := 2 }',
             'descriptor_claim')
    for name, raw_literal, byte_literal in (
            ('duplicate_keys', '(.obj [([97],.num 0),([97],.num 1)])', '[123,34,97,34,58,48,44,34,97,34,58,49,125]'),
            ('unordered_keys', '(.obj [([98],.num 0),([97],.num 1)])', '[123,34,98,34,58,48,44,34,97,34,58,49,125]'),
            ('byte_modulo_alias', '(.str [256])', '[34,0,34]')):
        negative(name, '\nnamespace HiaCoreSyntaxSlice\n',
                 'checkedEncode '+raw_literal+' = some '+byte_literal, 'transport_policy')
    for kind in ('wrong_phi', 'literal_two', 'wrong_condition'):
        mutant = deepcopy(fixed['tree'])
        fn = next(f for f in mutant['functions'] if f['name'] == fixed['hint']['function'])
        blocks = {b['id']: b for b in fn['blocks']}
        header, body = blocks[fixed['hint']['header']], blocks[fixed['hint']['target']]
        if kind == 'wrong_phi':
            slot = [p['name'] for p in body['params']].index(fixed['hint']['body_index'])
            header['term']['then']['args'][slot] = header['ops'][0]['args'][1]
        elif kind == 'literal_two':
            rhs = body['ops'][fixed['hint']['step_ordinal']]['args'][1]
            next(op for op in body['ops'] if any(o['name'] == rhs for o in op['out']))['attrs']['value'] = 2
        else:
            condition = header['term']['cond']
            header['ops'].append({'op':'bool.not', 'args':[condition], 'attrs':{},
                                 'out':[{'name':'syntax_wrong_condition','type':'bool'}]})
            header['term']['cond'] = 'syntax_wrong_condition'
        checked = verify_program(mutant)
        raw = checked.canonical_bytes
        negative(kind, _definitions(strict_canonical(raw), raw, fixed['hint']) +
                 'theorem mutated_transport : checkedEncode linearRaw = some linearBytes := by decide\n',
                 'extract linearRaw linearHint = some HiaGuardedUsizeSlice.linear_0',
                 'reverified_core_syntax')
    negative('leading_zero', '\nnamespace HiaCoreSyntaxSlice\n',
             'decode [48,49] = some (.num 1)', 'transport_parser_policy')
    selector = 'let edge := field (field header "term") "then" -- MUTATION_SITE_SELECT_THEN'
    require(common.count(selector) == 1, 'selector mutation site changed')
    changed_common = common.replace(selector, selector.replace('"then"','"else"'))
    start = checked_source((changed_common, parallel_defs))
    line = start.count('\n') + 1
    semantic_source = checked_source((start, 'theorem intended_negative : extract parallelRaw parallelHint = some HiaGuardedUsizeSlice.linear_0 := by decide\nend HiaCoreSyntaxSlice\n'))
    require(proof_bytes + len(semantic_source.encode()) <= MAX_TOTAL_PROOF_BYTES, 'total proof input budget')
    negatives['wrong_arm_implementation'] = {
        'source':semantic_source,
        'failure_lines':[line,line], 'kind':'reconstruction_implementation'}
    total = len(positive.encode()) + sum(len(n['source'].encode()) for n in negatives.values())
    require(total <= MAX_TOTAL_PROOF_BYTES, 'total proof input budget')
    require(len(negatives) == 10, 'negative inventory changed')
    return {'positive': positive, 'negatives': negatives, 'canonical_bytes': fixed['bytes'],
            'expected_theorems': baseline['expected_theorems'] | {NAMESPACE+'.'+n for n in new_names},
            'manifest': {'core_sha256': fixed['core_sha256'], 'canonical_bytes':len(fixed['bytes']),
                         'hint':fixed['hint'], 'rendered_hint':render_hint(fixed['tree'], fixed['hint']),
                         'baseline_manifest_sha256':sha256(json.dumps(baseline['manifests'],sort_keys=True).encode()).hexdigest(),
                         'scope':'one actual linear slice; syntax only',
                         'proof_input_bytes':total}}


def decide_negative_rejected(result, path, lines):
    """Only a complete intended-line proof of false qualifies, not any error.

    All new negative declarations use by decide. Syntax/import/timeout errors,
    even on the intended line or mixed with an expected error, are failures.
    """
    if type(result.get('returncode')) is not int or result['returncode'] != 1:
        return False
    log = result.get('stdout', '') + result.get('stderr', '')
    match = re.fullmatch(re.escape(str(path)) +
        r":(\d+):\d+: error: tactic 'decide' proved that the proposition\n(.+)\nis false\s*",
        log, re.S)
    return bool(match and lines[0] <= int(match.group(1)) <= lines[1]
                and match.group(2).strip() and 'error:' not in match.group(2)
                and 'sorryAx' not in log)


def qualify(lean, output_directory):
    import time
    from hashlib import sha256
    from tools.check_guarded_slice_lean import theorem_inventory
    from tools.qualify_hia_selected_formal import _run_lean, _support_identity
    from tools.extract_initialization_obligations import OBLIGATIONS
    from tools.check_initialization_frontiers import DENY
    digest = lambda data: sha256(data).hexdigest()
    executable = Path(lean).resolve(strict=True)
    lock = json.loads((ROOT / 'formal/toolchain-lock.json').read_text())
    require(digest(executable.read_bytes()) == lock['lean_binary_sha256'], 'pinned Lean binary required')
    identity = source_identity()
    support = _support_identity(executable)
    prepared = build_inputs()
    require(source_identity() == identity, 'sources changed during preparation')
    # Independent reread of the fixed canonical bytes, not rendered tree output.
    require(fixed_input()['bytes'] == prepared['canonical_bytes'], 'Core bytes changed')
    output = Path(output_directory).resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema':'hepta.hia.core-syntax-slice-kernel.v1', 'status':'running',
        'kernel_core_syntax_connection_checked':False, 'actual_core_bridge_proved':False,
        'python_exporter_refinement_proved':False, 'body_prefix_refinement_proved':False,
        'all_edge_transfer_proved':False, 'source_sha256':identity,
        'lean_binary_sha256':lock['lean_binary_sha256'], 'support_sha256':support,
        'negative_controls':[], 'manifest':prepared['manifest'],
        'obligations':[{'id':n,'status':'unproved'} for n, _ in OBLIGATIONS], **DENY}
    started = time.monotonic()
    try:
        path = output / 'positive.lean'
        path.write_text(prepared['positive'])
        result = _run_lean(executable, path)
        report['positive'] = {'source_sha256':digest(prepared['positive'].encode()), **result}
        require(result['returncode'] == 0, 'positive kernel check failed')
        report['theorems'] = theorem_inventory(result['stdout']+result['stderr'], prepared['expected_theorems'])
        for name, mutation in prepared['negatives'].items():
            require(time.monotonic()-started < 540, 'total proof execution bound')
            path = output / (name+'.lean')
            path.write_text(mutation['source'])
            result = _run_lean(executable, path)
            accepted = decide_negative_rejected(result,path,mutation['failure_lines'])
            report['negative_controls'].append({'name':name, 'kind':mutation['kind'],
                'source_sha256':digest(mutation['source'].encode()),
                'failure_lines':mutation['failure_lines'], 'expected_rejection':accepted, **result})
            require(accepted, 'intended negative obligation not rejected: '+name)
        require(source_identity() == identity and digest(executable.read_bytes()) == lock['lean_binary_sha256']
                and _support_identity(executable) == support, 'source or checker changed')
        require(fixed_input()['bytes'] == prepared['canonical_bytes'], 'Core bytes changed')
        report.update(status='passed',kernel_core_syntax_connection_checked=True)
    except Exception as error:
        report.update(status='failed',error_type=type(error).__name__,error=str(error))
    finally:
        report['wall_seconds'] = time.monotonic()-started
        (output/'RESULT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    return report


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lean', required=True, type=Path)
    parser.add_argument('--output-directory', required=True, type=Path)
    args = parser.parse_args()
    result = qualify(args.lean,args.output_directory)
    print(json.dumps(result,sort_keys=True))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
