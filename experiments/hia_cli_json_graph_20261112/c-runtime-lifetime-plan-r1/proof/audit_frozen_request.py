"""Read-only source/request integrity checks, not a product execution."""
from __future__ import annotations
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'control'))
from common import require, read_file, pin, save
from support import frozen, read_policy
from original_current_compiler import current_compiler


def main():
    started = time.monotonic_ns()
    preexec = json.loads((ROOT / 'PREEXEC.json').read_bytes())
    request = json.loads((ROOT / 'REQUEST.json').read_bytes())
    policy, policy_pin = read_policy(ROOT / 'POLICY.json', request['policy_sha256'])
    report = {'schema': 'hia.cli-json.C-finite-static-request-readback.v1', 'status': 'HOLD',
              'checks': [], 'product_imports': False, 'C_frontend_executed': False,
              'HIA_compiler_executed': False, 'runtime_symbols_admitted': False,
              'finite_cases_executed': False, 'original17_executed': False, 'original46_executed': False}
    def check(value, name):
        report['checks'].append({'name': name, 'ok': bool(value)})
        require(value, name)
    check(not os.path.lexists(policy['operation_root']), 'unique actual output does not exist')
    check(preexec['command'] == [policy['python']['path'], '-I', '-S', '-B', str(ROOT / 'control/launch.py'),
        '--request', str(ROOT / 'REQUEST.json'), '--sha256', sha256((ROOT / 'REQUEST.json').read_bytes()).hexdigest()],
        'exact isolated one-shot command and raw request seal')
    check(preexec['cwd'] == str(ROOT) and request['qualification_seconds'] == 180
          and request['cleanup_seconds'] == 3, 'actual absolute cwd and unchanged outer limits')
    contract_ast = ast.parse((ROOT / 'control/case_contract.py').read_bytes())
    literals = {node.targets[0].id: ast.literal_eval(node.value) for node in contract_ast.body if isinstance(node, ast.Assign)}
    check(len(literals['RUNTIME_IDS']) == len(set(literals['RUNTIME_IDS'])) == 8
          and len(literals['LIFETIME_IDS']) == len(set(literals['LIFETIME_IDS'])) == 10,
          'exact distinct 8 runtime and 10 lifetime cases')
    check(sum(literals['EXPECTED_HIA_RETURNS']) == 48
          and sum(literals['EXPECTED_C_PUMP_CALLS']) == 11,
          '48 HIA returns and 11 actual pump calls are explicit unexecuted expectations')
    old = Path('/tmp/hia-cli-json-source-r4c-request-r1-20261112-e26e')
    before = json.loads((old / 'control/CONFIG.json').read_bytes())['source_pins']
    now = {row['path']: row for row in policy['source_files']}
    changed = [name for name in before if before[name]['sha256'] != now[name]['sha256']]
    added = sorted(set(now) - set(before))
    check(len(before) == 177 and len(now) == 182 and changed == ['hepta/hia_cli_json_cpython.c']
          and added == sorted(['hepta/hia_cli_json_cpython312_activation.inc',
              'hepta/hia_cli_json_cpython312_monitor.inc', 'hepta/hia_cli_json_cpython312_pump.inc',
              'hepta/hia_cli_json_py312_pump_native.py', 'hepta/hia_cli_json_runtime312_control.py']),
          '177 original source files with one composed C replacement and five explicit additions')
    check((ROOT / 'assets/py312_lifetime.hiaasm').read_bytes() == (old / 'actual/py312_lifetime.hiaasm').read_bytes(),
          'exact 26967-byte actually source-qualified HIA is consumed without regeneration')
    check(policy['preserved_original17_and46'] == json.loads((old / 'PREEXEC.json').read_bytes())['preserved_not_run'],
          'all original 17 CLI and 46 trace IDs retained without execution')
    base = Path('/tmp/hia-core-integer-native-current-v89-r2-20261112-e26e')
    original = (base / 'control/admission.py').read_bytes()
    check((ROOT / 'control/original_current_compiler.py').read_bytes()
          == original[:original.index(b'\ndef compile_checked(')] + b'\n',
          'only unchanged existing current compiler read-only verifier prefix is reused')
    check((ROOT / 'control/common.py').read_bytes() == (base / 'control/common.py').read_bytes()
          and sha256((ROOT / 'control/process_owner_impl.py').read_bytes()).hexdigest()
          == '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2',
          'original physical reader and 180/3 process owner bytes unchanged')
    observation = frozen(policy)
    report['input_observation'] = save(ROOT / 'proof/FROZEN-INPUTS.READBACK.json', observation)
    check(observation['source_files'] == 182 and len(observation['system']['files']) == 4555,
          'all isolated source and all 4555 actual system inputs fully read and joined')
    provenance = current_compiler(base, policy, read_file)
    report['compiler_original_provenance'] = save(ROOT / 'proof/CURRENT-COMPILER.READBACK.json', provenance)
    check(len(provenance['originals']) == 62 and provenance['compiler_from_current_v89_cold'] is True,
          'all 62 actual current-v89 originals and original six-generation chain checked without compiling')
    check(read_file(ROOT / 'POLICY.json', 2 << 20)[1] == policy_pin,
          'complete request policy bytes and physical identity preserved')
    report.update(status='STATIC_REQUEST_AND_ACTUAL_INPUT_READBACK_PASS',
                  source_files=182, system_files=4555, current_compiler_originals=62,
                  source_changes=changed, source_additions=added,
                  elapsed_ns=time.monotonic_ns() - started)
    save(ROOT / 'proof/READONLY-REQUEST-AUDIT.json', report)
    print(json.dumps({'status': report['status'], 'checks': len(report['checks']),
                      'elapsed_ns': report['elapsed_ns'], 'product_executed': False}))


if __name__ == '__main__':
    main()
