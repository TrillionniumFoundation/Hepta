"""Read all fixed inputs and the source delta; do not run new admission code."""
from __future__ import annotations
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
OLD = Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r3-20261112-e26e')
sys.path.insert(0, str(ROOT / 'control'))
from common import require, read_file, save
from support import frozen, read_policy
from original_current_compiler import current_compiler


def main():
    started = time.monotonic_ns()
    checks = []
    def check(name, value):
        checks.append({'name': name, 'ok': bool(value)})
        require(value, name)
    req_raw = (ROOT / 'REQUEST.json').read_bytes()
    req = json.loads(req_raw)
    policy, policy_pin = read_policy(ROOT / 'POLICY.json', req['policy_sha256'])
    old = json.loads((OLD / 'POLICY.json').read_bytes())
    pre = json.loads((ROOT / 'PREEXEC.json').read_bytes())
    counter = json.loads((ROOT / 'SOURCE-CONTROL-REQUEST.json').read_bytes())
    correction = json.loads((ROOT / 'CORRECTION.json').read_bytes())
    check('fresh finite actual is absent', not os.path.lexists(policy['operation_root']))
    check('fresh pure-source counterexample output is absent', not os.path.lexists(counter['output']))
    check('command and cwd bind this exact request', pre['command'] == [policy['python']['path'],
          '-I', '-S', '-B', str(ROOT / 'control/launch.py'), '--request', str(ROOT / 'REQUEST.json'),
          '--sha256', hashlib.sha256(req_raw).hexdigest()] and pre['cwd'] == str(ROOT))
    inverse_req = dict(req)
    old_req = json.loads((OLD / 'REQUEST.json').read_bytes())
    for key in ('operation_key', 'operation_root', 'policy_sha256'):
        inverse_req[key] = old_req[key]
    check('entire request inverse is original', inverse_req == old_req)
    for row in old['control_files']:
        check('whole original control unchanged: ' + row['path'],
              (ROOT / row['path']).read_bytes() == (OLD / row['path']).read_bytes())
    check('original 15 controls plus exact four new authoring/source-control inputs',
          policy['control_files'][:15] == old['control_files']
          and [x['path'] for x in policy['control_files'][15:]] ==
          ['build_runtime_mapping_revision.py', 'source_controls.py', 'freeze_revision_r4.py', 'SOURCE-CONTROL-REQUEST.json'])
    targets = {'hepta/hia_cli_json_runtime312.py', 'hepta/hia_cli_json_runtime312_control.py'}
    changed = [r['path'] for r in old['source_files'] if
               (OLD / 'source' / r['path']).read_bytes() != (ROOT / 'source' / r['path']).read_bytes()]
    check('only two Python runtime admission modules changed', set(changed) == targets and len(changed) == 2)
    check('complete source count and all physical modes preserved', len(policy['source_files']) == 182
          and all(a['path'] == b['path'] and a['mode'] == b['mode']
                  for a, b in zip(old['source_files'], policy['source_files'])))
    asts = {}
    for label, base in (('old', OLD), ('new', ROOT)):
        for target in targets:
            asts[label, target] = ast.parse((base / 'source' / target).read_bytes())
    base_target = 'hepta/hia_cli_json_runtime312.py'
    for name in ('identity', 'read_runtime'):
        nodes = [next(n for n in asts[label, base_target].body if isinstance(n, ast.FunctionDef)
                      and n.name == name) for label in ('old', 'new')]
        check('original physical reader function unchanged: ' + name,
              ast.dump(nodes[0], include_attributes=False) == ast.dump(nodes[1], include_attributes=False))
    def names(tree, key):
        node = next(n for n in tree.body if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == key for t in n.targets))
        return ast.literal_eval(node.value)
    for target, constant, count in ((base_target, 'SYMBOLS', 11),
            ('hepta/hia_cli_json_runtime312_control.py', 'CONTROL_SYMBOLS', 5)):
        before = names(asts['old', target], constant)
        after = names(asts['new', target], constant)
        check('exact original symbol population/order: ' + constant, before == after and len(after) == count)
    extra_ast = asts['new', 'hepta/hia_cli_json_runtime312_control.py']
    wrapper = next(n for n in extra_ast.body if isinstance(n, ast.FunctionDef) and n.name == 'control_symbol_table')
    check('additional table delegates the same strict parser with its exact names',
          len(wrapper.body) == 1 and isinstance(wrapper.body[0], ast.Return)
          and ast.unparse(wrapper.body[0].value) == '_symbol_records(raw, CONTROL_SYMBOLS)[0]')
    inverse = copy.deepcopy(policy)
    for key in ('operation_key', 'operation_root', 'c_command', 'source_files', 'control_files'):
        inverse[key] = old[key]
    check('entire policy inverse only names and explicit two-source/four-control pins', inverse == old)
    check('original 8+10 IDs and 48+11 expected counts unchanged',
          policy['runtime_ids'] == old['runtime_ids'] and len(policy['runtime_ids']) == 8
          and policy['lifetime_ids'] == old['lifetime_ids'] and len(policy['lifetime_ids']) == 10
          and policy['expected_total_HIA_returns'] == 48
          and policy['expected_total_C_pump_calls_including_refusals'] == 11)
    check('all original durations and capacities unchanged', policy['qualification_seconds'] == 180
          and policy['cleanup_seconds'] == 3 and policy['child_seconds'] == 5
          and policy['c_compiler_limits'] == old['c_compiler_limits']
          and policy['compiler_limits'] == {'wall_seconds': 20, 'cpu_seconds': 10, 'output_capacity': 1048576})
    check('all four HIA assets unchanged', all((ROOT / row['path']).read_bytes() == (OLD / row['path']).read_bytes()
                                              for row in old['asset_files']))
    check('original 17 and 46 populations remain outside request',
          policy['preserved_original17_and46'] == old['preserved_original17_and46'])
    source_tree = ast.parse((ROOT / 'source_controls.py').read_bytes())
    check('28 separate frozen counterexamples have exact unique IDs',
          list(names(source_tree, 'IDS')) == counter['expected_ids']
          and len(counter['expected_ids']) == len(set(counter['expected_ids'])) == 28
          and counter['new_source_control_wall_seconds'] == 20
          and counter['root_review_required_before_execution'] is True)
    for row in counter['inputs']:
        raw = Path(row['path']).read_bytes()
        check('exact source counterexample input: ' + row['path'], len(raw) == row['bytes']
              and hashlib.sha256(raw).hexdigest() == row['sha256']
              and hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest() == row['git_blob'])
    glibc = ROOT / 'reference/glibc-2.41'
    check('official dladdr mapping base differs from relocation coordinate definition',
          b'info->dli_fbase = (void *) match->l_map_start;' in (glibc / 'elf/dl-addr.c').read_bytes()
          and b'l_map_start\n       need not be the same as l_addr.' in (glibc / 'include/link.h').read_bytes())
    check('official executable and DYN map-start derivations retained',
          b'(ph->p_vaddr & ~(GLRO(dl_pagesize) - 1))' in (glibc / 'elf/rtld.c').read_bytes()
          and b'l->l_addr = l->l_map_start - c->mapstart;' in (glibc / 'elf/dl-map-segments.h').read_bytes())
    static = json.loads((ROOT / 'reference/independent-runtime-ELF/STATIC-ELF-REPORT.r2.json').read_bytes())
    check('independent complete actual ELF report preserved', static == json.loads(Path(
        '/workspace/scratch/e26ed3e2edcf/native-cli-r3-failure-custody-r1/runtime-ELF-static/STATIC-ELF-REPORT.r2.json').read_bytes()))
    check('original HOLD is explicit and not promoted', correction['actual_original'] == {
          'C_compile': 'PASS', 'runtime_loaded': 2, 'runtime_executed': 1,
          'runtime_error': 'ValueError: runtime ELF profile differs',
          'HIA_compile': False, 'lifetime_executed': 0, 'HIA_returns': 0, 'C_pumps': 0})
    observation = frozen(policy)
    observation_pin = save(ROOT / 'proof/FROZEN-INPUTS.READBACK.json', observation)
    old_observation = json.loads((OLD / 'proof/FROZEN-INPUTS.READBACK.json').read_bytes())
    check('all 182 source and 4555 system files actually reread', observation['source_files'] == 182
          and len(observation['system']['files']) == 4555)
    check('whole original system physical namespace and identities unchanged',
          observation['system']['files'] == old_observation['system']['files']
          and observation['system']['namespace'] == old_observation['system']['namespace'])
    compiler = current_compiler(Path(policy['compiler_origin_root']), policy, read_file)
    compiler_pin = save(ROOT / 'proof/CURRENT-COMPILER.READBACK.json', compiler)
    check('complete 62 current-v89 compiler originals independently reread',
          len(compiler['originals']) == 62 and compiler['compiler_from_current_v89_cold'] is True)
    check('not a new current-v92 or fresh-cold claim', policy['fresh_cold'] is False
          and policy['current_v92_matching_claimed'] is False
          and policy['activation_CALL_SEND_UNPACK_monitoring_closed'] is False)
    check('request and policy unchanged after readback', (ROOT / 'REQUEST.json').read_bytes() == req_raw
          and read_file(ROOT / 'POLICY.json', 2 << 20)[1] == policy_pin)
    check('both new execution outputs remain absent', not os.path.lexists(policy['operation_root'])
          and not os.path.lexists(counter['output']))
    parsed = []
    for name in ('build_runtime_mapping_revision.py', 'source_controls.py', 'freeze_revision_r4.py',
                 'proof/audit_frozen_request.py'):
        raw = (ROOT / name).read_bytes()
        ast.parse(raw, filename=name)
        parsed.append({'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    result = {'schema': 'hia.cli-json.runtime-layout-request-readonly-audit.v1',
              'status': 'READONLY_REQUEST_AND_INPUTS_PASS', 'checks': checks, 'check_count': len(checks),
              'elapsed_ns': time.monotonic_ns() - started, 'input_observation': observation_pin,
              'current_compiler_original_provenance': compiler_pin,
              'authoring_and_reader_AST_only': parsed,
              'new28_source_counterexamples_executed': False, 'C_frontend_HIA_or_native_executed': False,
              'runtime_load_or_symbol_binding_executed': False, 'original8_10_17_46_executed': False,
              'old_HOLD_preserved': True, 'new_actual_absent': True}
    save(ROOT / 'proof/READONLY-REQUEST-AUDIT.json', result)
    print(json.dumps({'status': result['status'], 'checks': len(checks),
                      'elapsed_ns': result['elapsed_ns'], 'source': 182, 'system': 4555,
                      'compiler_originals': 62, 'source_counterexamples_or_native_executed': False}))


if __name__ == '__main__':
    main()
