"""Root read-only admission of the one-helper finite CLI successor."""
import ast
import copy
import json
import os
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, '/workspace/scratch/e26ed3e2edcf/root')
from audit_cli_r2b_actual_publication import read, pin, js, save

ROOT = Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r3-20261112-e26e')
OLD = Path('/tmp/hia-cli-json-c-runtime-lifetime-plan-r2b-20261112-e26e')
OUT = Path('/workspace/scratch/e26ed3e2edcf/root/cli-c-runtime-lifetime-review-r3')


def main():
    git = js(OUT / 'GIT-READBACK.json')
    assert git['status'] == 'FULL_TREE_AND_ALL23_NEW_RAW_BLOBS_PASS'
    assert (git['all_leaves'], git['old_leaves'], git['new_leaves']) == (6393, 6167, 226)
    assert git['commit'] == '7e2d37f425987c827a09f5cd0207595fd86e2e56'
    published = []
    for row in git['additions']:
        actual = pin(ROOT / row['path'])
        assert all(actual[k] == row[k] for k in ('bytes', 'git_blob', 'sha256'))
        assert ('100755' if actual['mode'] & 0o111 else '100644') == row['git_mode']
        published.append(actual)
    assert len(published) == 226
    request, old_request = js(ROOT / 'REQUEST.json'), js(OLD / 'REQUEST.json')
    policy, previous = js(ROOT / 'POLICY.json'), js(OLD / 'POLICY.json')
    assert pin(ROOT / 'REQUEST.json')['sha256'] == '29e590a10fe3d32ef911aa19db6b73eb3cc2a0681d004c45b3bd653fb12d4849'
    assert pin(ROOT / 'POLICY.json')['sha256'] == request['policy_sha256'] == '3c9057cc8b1ed7722beb6a7f9cdca01571459290b66b0334263f0eeb908d00b7'
    assert not os.path.lexists(request['operation_root'])
    changed_keys = {k for k in set(policy) | set(previous) if policy.get(k) != previous.get(k)}
    assert changed_keys == {'operation_root', 'operation_key', 'c_command', 'source_files', 'control_files'}
    assert policy['operation_root'] == '/tmp/hia-cli-json-c-runtime-lifetime-actual-r3-20261112-e26e'
    assert policy['operation_key'] == 'hia-cli-json-c-runtime-lifetime-local312-r3'
    assert [x.replace(str(ROOT), str(OLD)).replace(policy['operation_root'], previous['operation_root'])
            for x in policy['c_command']] == previous['c_command']
    changed_request = {k for k in set(request) | set(old_request) if request.get(k) != old_request.get(k)}
    assert changed_request == {'operation_root', 'operation_key', 'policy_sha256'}
    for key in ('operation_root', 'operation_key'):
        assert request[key] == policy[key]
    assert (request['qualification_seconds'], request['cleanup_seconds'], request['runtime_case_count'],
            request['lifetime_case_count'], request['expected_HIA_returns'],
            request['expected_C_pump_calls_including_refusals']) == (180, 3, 8, 10, 48, 11)
    new_sources = {r['path']: r for r in policy['source_files']}
    old_sources = {r['path']: r for r in previous['source_files']}
    assert set(new_sources) == set(old_sources) and len(new_sources) == 182
    changed = [name for name in new_sources if new_sources[name] != old_sources[name]]
    assert changed == ['hepta/hia_cli_json_cpython312_errors.inc']
    for name in new_sources:
        if name not in changed:
            assert read(ROOT / 'source' / name) == read(OLD / 'source' / name)
    assert sum(r['bytes'] for r in policy['source_files']) == 2804757
    new_controls = {r['path']: r for r in policy['control_files']}
    old_controls = {r['path']: r for r in previous['control_files']}
    assert len(old_controls) == 14 and set(new_controls) - set(old_controls) == {'freeze_revision_r3.py'}
    assert set(old_controls) <= set(new_controls)
    for name, row in old_controls.items():
        assert new_controls[name] == row and read(ROOT / name) == read(OLD / name)
    for row in policy['asset_files']:
        assert read(ROOT / row['path']) == read(OLD / row['path'])
    assert len(policy['asset_files']) == 4
    for name in ('freeze_revision_r3.py', 'proof/audit_frozen_request_r3.py'):
        ast.parse(read(ROOT / name), filename=name)
    source = read(ROOT / 'source' / changed[0])
    official_function = read(ROOT / 'reference/official-raised-function.c.txt')
    local_function = read(ROOT / 'reference/local-raised-function.c.txt')
    official_full = read(ROOT / 'reference/official-errors.c')
    assert official_function in official_full
    assert pin(ROOT / 'reference/official-errors.c')['sha256'] == 'd38cf667e13fb9f298a278759daf6117167f45a08d2c5bae7f279d9ba86a2454'
    assert local_function == official_function.replace(b'void\n_PyErr_SetRaisedException', b'static void\ncj312_set_raised_exception', 1)
    comment = b'\n/* Exact CPython v3.12.14 Python/errors.c body; local linkage only.\n * Preserve the explicit state, stolen reference, and store-before-DECREF.\n */\n'
    insertion = comment + local_function
    assert source.count(insertion) == 1
    inverse = source.replace(insertion, b'', 1).replace(b'        cj312_set_raised_exception(tstate, exc);',
                                                       b'        _PyErr_SetRaisedException(tstate, exc);', 1)
    assert inverse == read(OLD / 'source' / changed[0])
    assert source.count(b'cj312_set_raised_exception(') == 2
    assert source.count(b'_PyThreadState_GetCurrent()') == source.count(b'EVAL_CALL_STAT_INC_IF_FUNCTION') == 2
    assert b'        Py_INCREF(exc);\n        assert(PyExceptionInstance_Check(exc));\n        cj312_set_raised_exception(tstate, exc);' in source
    assert b'    PyObject *old_exc = tstate->current_exception;\n    tstate->current_exception = exc;\n    Py_XDECREF(old_exc);' in local_function
    assert b'_PyErr_SetRaisedException(' not in source
    previous_closure = js(Path('/workspace/scratch/e26ed3e2edcf/root/cli-c-runtime-lifetime-actual-r2b-git-review/ROOT-READBACK.json'))
    assert previous_closure['symbols']['strong_undefined'] == 119 and previous_closure['symbols']['compatible'] == 118
    assert previous_closure['symbols']['unresolved'] == ['_PyErr_SetRaisedException']
    replacement = js(ROOT / 'proof/REPLACEMENT-SYMBOL-PLAN.json')
    assert replacement['new_helper_Py_XDECREF_uses_already_existing_import']['required']['name'] == '_Py_Dealloc'
    assert replacement['new_helper_Py_XDECREF_uses_already_existing_import']['resolved_by_declared_scope'] is True
    assert policy['compiler_limits'] == {'wall_seconds': 20, 'cpu_seconds': 10, 'output_capacity': 1048576}
    assert policy['c_compiler_limits'] == previous['c_compiler_limits'] and policy['child_seconds'] == 5
    assert (len(policy['runtime_ids']), len(policy['lifetime_ids']), sum(policy['expected_lifetime_HIA_returns']),
            sum(policy['expected_C_pump_calls_including_refusals'])) == (8, 10, 48, 11)
    assert (len(policy['preserved_original17_and46']['original_cli_ids']),
            len(policy['preserved_original17_and46']['trace_plan_ids'])) == (17, 46)
    assert policy['fresh_cold'] is False and policy['current_v92_matching_claimed'] is False
    assert policy['activation_CALL_SEND_UNPACK_monitoring_closed'] is False
    # The previously reviewed unchanged helper reads inputs; no compiler, case,
    # loader, subprocess, or owner is invoked in this root review.
    sys.path.insert(0, str(ROOT / 'control'))
    from support import frozen
    snapshot = frozen(policy)
    old_snapshot = js(Path('/workspace/scratch/e26ed3e2edcf/root/cli-c-runtime-lifetime-review-r2b/FROZEN-INPUTS.original.json'))
    assert snapshot['source_files'] == 182 and len(snapshot['system']['files']) == 4555
    assert snapshot['system']['files'] == old_snapshot['system']['files']
    assert snapshot['system']['namespace'] == old_snapshot['system']['namespace']
    assert policy['external_files'] == previous['external_files'] and len(policy['external_files']) == 72
    assert not os.path.lexists(request['operation_root'])
    save(OUT / 'FROZEN-INPUTS.original.json', snapshot)
    result = {'schema': 'hia.root.cli-raised-helper-r3-input-review.v1',
              'status': 'ROOT_STATIC_AND_COMPLETE_INPUT_READBACK_PASS', 'canonical': git['commit'],
              'tree': git['tree'], 'all226_published_files_freshly_matched': published,
              'all23_new_unique_raw_blobs_full_read': True, 'request': pin(ROOT / 'REQUEST.json'),
              'policy': pin(ROOT / 'POLICY.json'), 'git_readback': pin(OUT / 'GIT-READBACK.json'),
              'original_r2b_full119_independent_ELF_audit': pin(Path('/workspace/scratch/e26ed3e2edcf/root/cli-c-runtime-lifetime-actual-r2b-git-review/ROOT-READBACK.json')),
              'source_changed_files': changed, 'unchanged_source_files': 181,
              'whole_include_inverse_exact': True, 'official_three_statement_body_exact': True,
              'stolen_reference_and_explicit_state_and_store_before_decref_preserved': True,
              'old_control_inputs_unchanged': 14, 'runtime_controls_unchanged': 11, 'HIA_assets_unchanged': 4,
              'system_files_freshly_read': 4555, 'all_old_system_identities_namespaces_bytes_equal': True,
              'external_original_compiler_and_other_inputs_freshly_read': 72,
              'frozen_inputs': pin(OUT / 'FROZEN-INPUTS.original.json'),
              'expected_runtime': 8, 'expected_lifetime': 10, 'expected_HIA_returns': 48, 'expected_C_pumps': 11,
              'expected_not_actual': True, 'outer_limits': [180, 3], 'inner_seconds': [20, 5, 20, 5],
              'new_actual_absent': True, 'new_C_or_HIA_compile_or_runtime_execution': False,
              'limitations': ['v89 development compiler only; no current v92 or fresh cold claim.',
                              'Full CLI17, trace46 and evaluator CALL/SEND/UNPACK remain open.',
                              'Original r1 and r2b HOLDs remain unchanged.']}
    save(OUT / 'ROOT-REVIEW.json', result)
    print(json.dumps({'status': result['status'], 'readback': pin(OUT / 'ROOT-REVIEW.json'),
                      'source_files': 182, 'system_files': 4555, 'expected': [8, 10, 48, 11]}))


if __name__ == '__main__':
    main()
