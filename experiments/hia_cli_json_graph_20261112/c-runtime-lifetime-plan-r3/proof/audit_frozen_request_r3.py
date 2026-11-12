"""Readonly exact successor audit, including all frozen input bytes; no product."""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
OLD = Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r2b-20261112-e26e')
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

    pre = json.loads((ROOT / 'PREEXEC.json').read_bytes())
    req = json.loads((ROOT / 'REQUEST.json').read_bytes())
    policy, policy_pin = read_policy(ROOT / 'POLICY.json', req['policy_sha256'])
    old = json.loads((OLD / 'POLICY.json').read_bytes())
    check('new actual absent before readonly audit', not os.path.lexists(policy['operation_root']))
    check('exact new command/cwd/request seal', pre['command'] == [policy['python']['path'], '-I', '-S', '-B',
        str(ROOT / 'control/launch.py'), '--request', str(ROOT / 'REQUEST.json'), '--sha256',
        hashlib.sha256((ROOT / 'REQUEST.json').read_bytes()).hexdigest()] and pre['cwd'] == str(ROOT))
    for row in old['control_files']:
        check('old bound control whole bytes unchanged: ' + row['path'],
              (ROOT / row['path']).read_bytes() == (OLD / row['path']).read_bytes())
    check('one additional authoring input with old fourteen untouched',
          policy['control_files'][:-1] == old['control_files']
          and policy['control_files'][-1]['path'] == 'freeze_revision_r3.py'
          and len(policy['control_files']) == 15)
    changed = [row['path'] for row in old['source_files']
               if (OLD / 'source' / row['path']).read_bytes() != (ROOT / 'source' / row['path']).read_bytes()]
    target = 'hepta/hia_cli_json_cpython312_errors.inc'
    check('exact one source delta and 181 unchanged sources', changed == [target]
          and len(policy['source_files']) == len(old['source_files']) == 182)
    before = (OLD / 'source' / target).read_bytes()
    after = (ROOT / 'source' / target).read_bytes()
    official = (ROOT / 'reference/official-errors.c').read_bytes()
    function = (ROOT / 'reference/official-raised-function.c.txt').read_bytes()
    local = (ROOT / 'reference/local-raised-function.c.txt').read_bytes()
    note = (b'/* Exact CPython v3.12.14 Python/errors.c body; local linkage only.\n'
            b' * Preserve the explicit state, stolen reference, and store-before-DECREF.\n'
            b' */\n')
    check('full official CPython v3.12.14 errors.c pin', len(official) == 55402
          and hashlib.sha256(official).hexdigest() == 'd38cf667e13fb9f298a278759daf6117167f45a08d2c5bae7f279d9ba86a2454')
    check('helper complete exact official body with local name and linkage only',
          official.count(function) == 1 and local == function.replace(
              b'void\n_PyErr_SetRaisedException(', b'static void\ncj312_set_raised_exception(', 1)
          and after.count(local) == 1)
    old_call = b'        _PyErr_SetRaisedException(tstate, exc);'
    new_call = b'        cj312_set_raised_exception(tstate, exc);'
    check('one call renamed and entire old include restored by exact inverse',
          before.count(old_call) == after.count(new_call) == 1
          and after.replace(new_call, old_call, 1).replace(note + local + b'\n', b'', 1) == before)
    check('explicit state and ordered ref transfer source operations',
          local == b'static void\ncj312_set_raised_exception(PyThreadState *tstate, PyObject *exc)\n{\n'
          b'    PyObject *old_exc = tstate->current_exception;\n'
          b'    tstate->current_exception = exc;\n'
          b'    Py_XDECREF(old_exc);\n}\n')
    check('prior TLS fix and original statistics preserved exactly',
          after.count(b'_PyObject_CallNoArgsTstate(_PyThreadState_GetCurrent(),') == 2
          and after.count(b'EVAL_CALL_STAT_INC_IF_FUNCTION(EVAL_CALL_API,') == 2
          and b'_PyObject_CallNoArgs(' not in after)
    check('removed unavailable external call with no injected fake symbol',
          b'_PyErr_SetRaisedException(' not in after and b'#define _PyErr_SetRaisedException' not in after)
    inverse_policy = json.loads(json.dumps(policy))
    inverse_policy['source_files'] = old['source_files']
    inverse_policy['control_files'] = inverse_policy['control_files'][:-1]
    inverse_policy['operation_key'] = old['operation_key']
    inverse_policy['operation_root'] = old['operation_root']
    inverse_policy['c_command'] = [v.replace(str(ROOT), str(OLD)).replace(
        policy['operation_root'], old['operation_root']) for v in policy['c_command']]
    check('whole policy inverse only exact source/new authoring/namespace delta', inverse_policy == old)
    old_req = json.loads((OLD / 'REQUEST.json').read_bytes())
    inverse_req = dict(req)
    for key in ('operation_key', 'operation_root', 'policy_sha256'):
        inverse_req[key] = old_req[key]
    check('whole request inverse', inverse_req == old_req)
    check('all original 8 runtime and 10 lifetime IDs and 48/11 expected observations',
          policy['runtime_ids'] == old['runtime_ids'] and len(policy['runtime_ids']) == 8
          and policy['lifetime_ids'] == old['lifetime_ids'] and len(policy['lifetime_ids']) == 10
          and policy['expected_lifetime_HIA_returns'] == old['expected_lifetime_HIA_returns']
          and policy['expected_C_pump_calls_including_refusals'] == old['expected_C_pump_calls_including_refusals']
          and policy['expected_total_HIA_returns'] == 48
          and policy['expected_total_C_pump_calls_including_refusals'] == 11)
    check('original 17 CLI and 46 trace IDs retained outside this finite request',
          policy['preserved_original17_and46'] == old['preserved_original17_and46'])
    check('original budgets and compiler capacities unchanged',
          policy['qualification_seconds'] == 180 and policy['cleanup_seconds'] == 3
          and policy['child_seconds'] == 5
          and policy['compiler_limits'] == {'wall_seconds': 20, 'cpu_seconds': 10, 'output_capacity': 1 << 20}
          and policy['c_compiler_limits'] == old['c_compiler_limits'])
    check('all four HIA assets whole-byte unchanged', all(
          (ROOT / r['path']).read_bytes() == (OLD / r['path']).read_bytes() for r in old['asset_files']))
    closure = json.loads((ROOT / 'reference/R2B-DYNAMIC-CLOSURE.original.json').read_bytes())
    check('all 119 original strong imports examined and exactly one missing',
          closure['strong_undefined_count'] == 119 and closure['compatible_strong_count'] == 118
          and closure['unresolved'] == ['_PyErr_SetRaisedException'])
    observation = frozen(policy)
    observation_pin = save(ROOT / 'proof/FROZEN-INPUTS.READBACK.json', observation)
    old_observation = json.loads((OLD / 'proof/FROZEN-INPUTS.READBACK.json').read_bytes())
    check('all 182 isolated sources and 4555 pinned system files actually reread',
          observation['source_files'] == 182 and len(observation['system']['files']) == 4555)
    check('actual complete system identity and namespace unchanged from frozen r2b',
          observation['system']['files'] == old_observation['system']['files']
          and observation['system']['namespace'] == old_observation['system']['namespace']
          and all(observation['system']['manifest'][key] == old_observation['system']['manifest'][key]
                  for key in ('sha256', 'size', 'mode')))
    compiler = current_compiler(Path(policy['compiler_origin_root']), policy, read_file)
    compiler_pin = save(ROOT / 'proof/CURRENT-COMPILER.READBACK.json', compiler)
    check('all original current-v89 62 compiler files reread and bound',
          len(compiler['originals']) == 62 and compiler['compiler_from_current_v89_cold'] is True)
    check('no fresh cold or newer source matching claim', policy['fresh_cold'] is False
          and policy['current_v92_matching_claimed'] is False
          and policy['activation_CALL_SEND_UNPACK_monitoring_closed'] is False)
    check('policy unchanged after entire readonly audit', read_file(ROOT / 'POLICY.json', 2 << 20)[1] == policy_pin)
    check('new actual remains absent', not os.path.lexists(policy['operation_root']))
    parsed = []
    for name in ('freeze_revision_r3.py', 'proof/audit_frozen_request_r3.py'):
        raw = (ROOT / name).read_bytes()
        ast.parse(raw, filename=name)
        parsed.append({'path': name, 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()})
    result = {'schema': 'hia.cli-json.local-raised-helper-request-readonly-audit.v1',
        'status': 'READONLY_REQUEST_AND_INPUTS_PASS', 'checks': checks, 'check_count': len(checks),
        'input_observation': observation_pin, 'compiler_original_provenance': compiler_pin,
        'new_authoring_and_reader_AST_only': parsed, 'elapsed_ns': time.monotonic_ns() - started,
        'source_generation': False, 'C_frontend_executed': False, 'HIA_compiler_executed': False,
        'runtime_load_or_symbol_binding_executed': False, 'finite_case_bodies_executed': False,
        'original17_executed': False, 'original46_executed': False, 'old_HOLD_preserved': True,
        'new_actual_absent': True}
    save(ROOT / 'proof/READONLY-REQUEST-AUDIT.json', result)
    print(json.dumps({'status': result['status'], 'checks': len(checks),
        'elapsed_ns': result['elapsed_ns'], 'source_files': 182, 'system_files': 4555,
        'compiler_originals': 62, 'new_native_executed': False}))


if __name__ == '__main__':
    main()
