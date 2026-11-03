"""Pinned-kernel research checker for exported partial scalar slices.

No runtime/exporter refinement, production admission, native work or uploads.
Proof source is unchecked until the actual pinned Lean process accepts it.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import re
import time

from hepta.hia_program import verify_program
from tools.check_dynamic_unsigned_step import extract_step_slices
from tools.extract_initialization_obligations import OBLIGATIONS
from tools.check_initialization_frontiers import DENY
from tools.qualify_hia_selected_formal import _run_lean, _support_identity
from tools.qualify_hia_initialization_prefix import THEOREMS as PREFIX_THEOREMS

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / 'experiments/hia_initialization_frontiers_20261103/GuardedUsizeSlice.lean'
PREFIX = ROOT / 'formal/HiaInitializationPrefix.lean'
NAMESPACE = 'HiaGuardedUsizeSlice'
MODEL_THEOREMS = {'readUsize_bounded', 'readUsize_phi', 'guard_values', 'checked_add_in_range',
                  'wrapping_add_in_range', 'guarded_successors', 'selected_successor',
                  'false_guard_no_step', 'invalid_no_step'}
MAXIMUM = 2**64 - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return sha256(data).hexdigest()


def source_identity():
    paths = [Path(__file__), MODEL, PREFIX, ROOT / 'formal/toolchain-lock.json',
             ROOT / 'formal/proof-dependencies.txt', ROOT / 'tools/bootstrap_verification.py',
             ROOT / '.github/workflows/hia-guarded-slice-kernel-research.yml', *sorted((ROOT / 'hepta').glob('*.py')),
             ROOT / 'tools/check_dynamic_unsigned_step.py',
             ROOT / 'tools/extract_initialization_obligations.py',
             ROOT / 'tools/check_initialization_frontiers.py',
             ROOT / 'tools/experimental_deferred_guard_proposer.py',
             ROOT / 'tools/research_deferred_guard_model.py',
             ROOT / 'tools/qualify_hia_selected_formal.py', ROOT / 'tools/evidence_checks.py',
             ROOT / 'tools/qualify_hia_initialization_prefix.py',
             ROOT / 'benchmarks/hia_reduction_release/linear.hepta',
             ROOT / 'benchmarks/hia_reduction_release/affine.hepta']
    return {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in paths}


def export_descriptor(program, hint):
    """Reconstruct from actual Core; hint identifies slots, never supplies facts.

    Unsupported concrete opcodes are encoded as other for kernel rejection.
    A projection ignores intervening body semantics, explicitly not proving it.
    """
    checked = verify_program(program)
    function = next(f for f in checked.as_dict()['functions'] if f['name'] == hint['function'])
    blocks = {b['id']: b for b in function['blocks']}
    header = blocks[hint['header']]
    compare = header['ops'][hint['compare_ordinal']]
    term = header['term']
    require(term['op'] == 'branch' and term['then']['target'] == hint['target'], 'branch locator mismatch')
    body = blocks[hint['target']]
    step = body['ops'][hint['step_ordinal']]
    require(len(compare['args']) == 2 and len(compare['out']) == 1 and len(step['args']) == 2 and len(step['out']) == 1,
            'unsupported operation arity')
    values = [p for p in header['params']] + [out for op in header['ops'] for out in op['out']]
    positions = {p['name']: n for n, p in enumerate(values)}
    require(len(positions) == len(values) and len(values) <= 4096, 'source binder inventory')
    types = {p['name']: p['type'] for p in values}
    params = [p['name'] for p in body['params']]
    require(hint['body_index'] in params and hint['body_extent'] in params, 'target slot absent')
    definitions = {out['name']: (n, op, out) for n, op in enumerate(body['ops']) for out in op['out']}
    literal_ordinal, literal, out = definitions[step['args'][1]]
    require(literal['op'] == 'const' and type(literal['attrs']['value']) is int and literal['attrs']['value'] >= 0,
            'RHS must be an actual nonnegative literal for this projection')
    tag = lambda t: 'usize' if t == 'usize' else 'other'
    d = {'sourceIndex': positions[compare['args'][0]], 'sourceExtent': positions[compare['args'][1]],
         'compareOutput': positions[compare['out'][0]['name']], 'branchCondition': positions[term['cond']],
         'indexType': tag(types[compare['args'][0]]), 'extentType': tag(types[compare['args'][1]]),
         'compareOp': {'compare.lt': 'lt', 'compare.le': 'le'}.get(compare['op'], 'other'),
         'selectedArm': 'thenArm', 'incoming': [positions[a] for a in term['then']['args']],
         'indexSlot': params.index(hint['body_index']), 'extentSlot': params.index(hint['body_extent']),
         'addIndexSlot': params.index(step['args'][0]) if step['args'][0] in params else len(params),
         'addOp': {'int.add.checked': 'checked', 'int.add.wrap': 'wrapping'}.get(step['op'], 'other'),
         'addType': tag(step['out'][0]['type']), 'literalType': tag(out['type']),
         'literalValue': literal['attrs']['value'], 'literalOrdinal': literal_ordinal,
         'addOrdinal': hint['step_ordinal']}
    return {'descriptor': d, 'core_sha256': checked.sha256,
            'manifest': {'function': deepcopy(function), 'locator': deepcopy(hint),
                         'source_slots': deepcopy(values), 'projection_only': True}}


def render_descriptor(name, d):
    require(re.fullmatch(r'[a-z][a-z0-9_]*', name), 'bad declaration name')
    fields = []
    for key, value in d.items():
        if type(value) is int:
            require(value >= 0, 'negative descriptor Nat')
            text = str(value)
        elif isinstance(value, list):
            require(all(type(x) is int and x >= 0 for x in value), 'bad incoming list')
            text = '[' + ', '.join(map(str, value)) + ']'
        else:
            require(value in {'usize','other','lt','le','thenArm','elseArm','checked','wrapping'}, 'bad enum')
            text = '.' + value
        fields.append(f'  {key} := {text}')
    return f'def {name} : Descriptor := {{\n' + ',\n'.join(fields) + '\n}\n'


def base_source():
    source, prefix = MODEL.read_text(), PREFIX.read_text()
    require(not re.search(r'(?m)^\s*(import|axiom|unsafe|opaque|constant|initialize|builtin_initialize|run_elab|run_cmd|elab|macro|syntax|set_option)\b|\b(sorry|native_decide)\b', source),
            'unreviewed model declaration or placeholder')
    require(set(re.findall(r'(?m)^theorem (\w+)', source)) == MODEL_THEOREMS, 'model theorem inventory')
    return prefix + '\n' + source + '\n'


def positive_declarations(name, d):
    text = render_descriptor(name, d)
    text += f'theorem {name}_valid : Valid {name} := by decide\n'
    names = [name + '_valid']
    for suffix, index, extent in [('small', 0, 1), ('upper', MAXIMUM-1, MAXIMUM)]:
        env = f'{name}_{suffix}_env'
        text += (f'def {env} : Env := fun slot =>\n'
                 f'  if slot = {d["sourceIndex"]} then some (.usize {index})\n'
                 f'  else if slot = {d["sourceExtent"]} then some (.usize {extent}) else none\n')
        theorem = f'{name}_{suffix}'
        text += (f'theorem {theorem} : evalGuard {MAXIMUM} {name} {env} = some true ∧\n'
                 f'    evalStep .checked {MAXIMUM} {name} {env} = some {index+1} ∧\n'
                 f'    evalStep .wrapping {MAXIMUM} {name} {env} = some {index+1} := by decide\n')
        names.append(theorem)
    text += ''.join(f'#print axioms {n}\n' for n in names)
    return text, names


def build_inputs():
    from hepta.hia_program_source import lower_source
    from hepta.hia_reduction import propose_reduction_pipeline
    from tools.experimental_deferred_guard_proposer import propose_deferred_guard
    source = base_source()
    manifests, declarations, generated = [], [], []
    first = None
    for workload in ('linear', 'affine'):
        base = lower_source((ROOT / 'benchmarks/hia_reduction_release' / (workload+'.hepta')).read_text())
        core = propose_deferred_guard(base, propose_reduction_pipeline(base, include_induction=True))['candidate_core']
        slices = extract_step_slices(core)
        require(slices['status'] == 'extracted' and len(slices['slices']) == 4, 'actual slice inventory differs')
        for number, hint in enumerate(slices['slices']):
            exported = export_descriptor(core, hint)
            text, names = positive_declarations(f'{workload}_{number}', exported['descriptor'])
            declarations.append(text)
            generated.extend(names)
            manifests.append(exported)
            if first is None:
                first = (core, hint)
    # Positive real-Core permutation: target parameter and ALL ingress argument
    # positions change together. The scalar projection must remain simultaneous.
    crossed, cross_hint = deepcopy(first[0]), first[1]
    cross_fn = next(f for f in crossed['functions'] if f['name'] == cross_hint['function'])
    cross_body = next(b for b in cross_fn['blocks'] if b['id'] == cross_hint['target'])
    names = [p['name'] for p in cross_body['params']]
    left, right = names.index(cross_hint['body_index']), names.index(cross_hint['body_extent'])
    cross_body['params'][left], cross_body['params'][right] = cross_body['params'][right], cross_body['params'][left]
    for block in cross_fn['blocks']:
        term = block['term']
        edges = [term] if term['op']=='jump' else [term['then'],term['else']] if term['op']=='branch' else []
        for edge in edges:
            if edge['target'] == cross_hint['target']:
                edge['args'][left], edge['args'][right] = edge['args'][right], edge['args'][left]
    exported = export_descriptor(crossed, cross_hint)
    text, names = positive_declarations('crossed_0', exported['descriptor'])
    declarations.append(text)
    generated.extend(names)
    manifests.append(exported)
    for suffix, value in [('missing','none'), ('opaque','some .opaque'),
                          ('oversized',f'some (.usize {MAXIMUM+1})'), ('false_guard','some (.usize 0)')]:
        name = 'no_step_' + suffix
        declarations.append(f'theorem {name} : evalSelectedStep {MAXIMUM} linear_0 (fun _ => {value}) = none := by decide\n#print axioms {name}\n')
        generated.append(name)
    positive = source + '\nnamespace HiaGuardedUsizeSlice\n' + '\n'.join(declarations) + '\nend HiaGuardedUsizeSlice\n'
    expected = {'HiaInitializationPrefix.'+n for n in PREFIX_THEOREMS} | {NAMESPACE+'.'+n for n in MODEL_THEOREMS | set(generated)}
    # Failed Lean declarations may acquire internal sorry placeholders while
    # reporting an intended proof error. Only the SUCCESSFUL positive input
    # prints/verifies axioms; negatives contain no axiom-print commands.
    negative_base = re.sub(r'(?m)^#print axioms .*\n', '', source)
    negatives = {}
    core, hint = first
    # Preserve target slots/specification while mutating actual well-typed Core.
    for kind in ('non_strict_guard', 'wrong_phi', 'literal_two', 'wrong_condition'):
        mutant = deepcopy(core)
        function = next(f for f in mutant['functions'] if f['name'] == hint['function'])
        blocks = {b['id']: b for b in function['blocks']}
        header, body = blocks[hint['header']], blocks[hint['target']]
        if kind == 'non_strict_guard':
            header['ops'][0]['op'] = 'compare.le'
        elif kind == 'wrong_phi':
            index_slot = [p['name'] for p in body['params']].index(hint['body_index'])
            header['term']['then']['args'][index_slot] = header['ops'][0]['args'][1]
        elif kind == 'literal_two':
            rhs = body['ops'][hint['step_ordinal']]['args'][1]
            next(op for op in body['ops'] if any(o['name']==rhs for o in op['out']))['attrs']['value'] = 2
        else:
            cond = header['term']['cond']
            header['ops'].append({'op':'bool.not','args':[cond], 'out':[{'name':'research_wrong_condition','type':'bool'}], 'attrs':{}})
            header['term']['cond'] = 'research_wrong_condition'
        exported = export_descriptor(mutant, hint)
        declaration = render_descriptor('negative_slice', exported['descriptor'])
        start = negative_base + '\nnamespace HiaGuardedUsizeSlice\n' + declaration
        bad = 'theorem negative_valid : Valid negative_slice := by decide\n'
        line = start.count('\n') + 1
        negatives[kind] = {'source': start + bad + 'end HiaGuardedUsizeSlice\n',
                           'failure_lines': [line, line], 'manifest': exported, 'kind': 'actual_core_validation'}
    # Explicit descriptor-policy negatives; not represented as mutated Core.
    for kind, field, value in [('false_arm','selectedArm','elseArm'),
                               ('non_usize_type','indexType','other'),
                               ('missing_phi','incoming',[])]:
        descriptor = deepcopy(manifests[0]['descriptor'])
        descriptor[field] = value
        start = negative_base + '\nnamespace HiaGuardedUsizeSlice\n' + render_descriptor('negative_slice', descriptor)
        line = start.count('\n') + 1
        negatives[kind] = {'source':start + 'theorem negative_valid : Valid negative_slice := by decide\nend HiaGuardedUsizeSlice\n',
                           'failure_lines':[line,line], 'kind':'descriptor_policy_mutation'}
    mutations = [
        ('wrong_phi_semantics', 'd.incoming[slot]? with -- MUTATION_SITE_PHI_LOOKUP',
         'd.incoming[slot + 1]? with -- MUTATION_SITE_PHI_LOOKUP', 'readUsize_phi'),
        ('wrong_add_semantics', 'index + literal -- MUTATION_SITE_ADD_LITERAL',
         'index + (literal + 1) -- MUTATION_SITE_ADD_LITERAL', 'checked_add_in_range'),
        ('skipped_guard_semantics', 'if evalGuard maximum d env = some true then -- MUTATION_SITE_STEP_GUARD',
         'if True then -- MUTATION_SITE_STEP_GUARD', 'false_guard_no_step')]
    for name, old, new, theorem in mutations:
        require(negative_base.count(old) == 1, 'semantic mutation point differs')
        changed = negative_base.replace(old, new)
        lines = changed.splitlines()
        start = next(i+1 for i, row in enumerate(lines) if row.startswith('theorem '+theorem+' '))
        end = next((i for i in range(start, len(lines)) if lines[i].startswith('theorem ') or lines[i].startswith('#print')),len(lines))
        negatives[name] = {'source': changed, 'failure_lines': [start,end], 'kind':'evaluator_semantic_mutation'}
    return {'positive': positive, 'expected_theorems': expected, 'manifests': manifests, 'negatives': negatives}


def theorem_inventory(log, expected):
    rows = re.findall(r"^'([^']+)' depends on axioms: \[([^\]]*)\]$", log, re.M)
    rows += [(n, '') for n in re.findall(r"^'([^']+)' does not depend on any axioms$", log, re.M)]
    require(len(rows) == len(expected) and {n for n, _ in rows} == expected, 'theorem inventory differs')
    result = {n: [a.strip() for a in text.split(',') if a.strip()] for n, text in rows}
    require('error:' not in log and 'sorryAx' not in log and
            all(set(xs) <= {'propext','Classical.choice','Quot.sound'} for xs in result.values()),
            'unexpected theorem axiom or error')
    return result


def negative_rejected(result, path, lines):
    log = result['stdout'] + result['stderr']
    locations = re.findall(re.escape(str(path)) + r':(\d+):\d+: error:', log)
    return (result['returncode'] == 1 and 'sorryAx' not in log and
            any(lines[0] <= int(line) <= lines[1] for line in locations))


def qualify(lean, output_directory):
    executable = Path(lean).resolve(strict=True)
    lock = json.loads((ROOT / 'formal/toolchain-lock.json').read_text())
    require(digest(executable.read_bytes()) == lock['lean_binary_sha256'], 'pinned Lean binary required')
    identity = source_identity()
    support = _support_identity(executable)
    prepared = build_inputs()
    require(source_identity() == identity, 'sources changed during preparation')
    output = Path(output_directory).resolve()
    output.mkdir(parents=True, exist_ok=False)
    report = {'schema':'hepta.hia.projected-guarded-step-kernel.v1', 'status':'running',
        'kernel_projected_scalar_theorem_checked': False, 'actual_core_bridge_proved': False,
        'python_exporter_refinement_proved': False, 'body_prefix_refinement_proved': False,
        'all_edge_transfer_proved': False, 'source_sha256': identity,
        'lean_binary_sha256': lock['lean_binary_sha256'], 'support_sha256': support,
        'negative_controls': [], 'obligations': [{'id': n, 'status':'unproved'} for n, _ in OBLIGATIONS], **DENY}
    (output/'manifest.json').write_text(json.dumps(prepared['manifests'],indent=2,sort_keys=True)+'\n')
    report['manifest_sha256'] = digest((output/'manifest.json').read_bytes())
    started = time.monotonic()
    try:
        positive_path = output/'positive.lean'
        positive_path.write_text(prepared['positive'])
        positive = _run_lean(executable, positive_path)
        (output/'positive.stdout').write_text(positive['stdout'])
        (output/'positive.stderr').write_text(positive['stderr'])
        report['positive'] = {'source_sha256':digest(prepared['positive'].encode()), **positive}
        require(positive['returncode'] == 0, 'positive kernel check failed')
        report['theorems'] = theorem_inventory(positive['stdout']+positive['stderr'], prepared['expected_theorems'])
        for name, mutation in prepared['negatives'].items():
            require(time.monotonic()-started < 540, 'total proof execution bound')
            path = output/(name+'.lean')
            path.write_text(mutation['source'])
            result = _run_lean(executable, path)
            (output/(name+'.stdout')).write_text(result['stdout'])
            (output/(name+'.stderr')).write_text(result['stderr'])
            require(negative_rejected(result,path,mutation['failure_lines']), 'intended negative obligation not rejected: '+name)
            report['negative_controls'].append({'name':name,'kind':mutation['kind'],
                'source_sha256':digest(mutation['source'].encode()),'failure_lines':mutation['failure_lines'], **result})
        require(source_identity()==identity and digest(executable.read_bytes())==lock['lean_binary_sha256']
                and _support_identity(executable)==support, 'proof source or tool support changed')
        report.update(status='passed', kernel_projected_scalar_theorem_checked=True)
    except Exception as error:
        report.update(status='failed', error_type=type(error).__name__, error=str(error))
    finally:
        report['wall_seconds'] = time.monotonic()-started
        (output/'RESULT.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    return report


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lean', required=True, type=Path)
    parser.add_argument('--output-directory', required=True, type=Path)
    args = parser.parse_args()
    result = qualify(args.lean,args.output_directory)
    # All material is generated fixture/proof information, not user inputs.
    print(json.dumps(result,sort_keys=True))
    return 0 if result['status']=='passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
