"""Record already-frozen finite controls; never import or execute the product."""
from pathlib import Path
import hashlib
import json
import os
import stat

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'experiments/hia_cli_json_graph_20261112/c-runtime-lifetime-plan-r1'


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':')) + '\n').encode()


def record(path):
    info = path.lstat()
    assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    data = path.read_bytes()
    data.decode('utf-8')
    return {'path': path.relative_to(ROOT).as_posix(), 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest(),
            'git_mode': '100644', 'physical_mode': stat.S_IMODE(info.st_mode)}


def create(name, value):
    path = ROOT / name
    data = encoded(value)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(data)
        while view:
            count = os.write(descriptor, view)
            assert count > 0
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    assert path.read_bytes() == data
    return record(path)


def main():
    policy = json.loads((ROOT / 'POLICY.json').read_bytes())
    preexec = json.loads((ROOT / 'PREEXEC.json').read_bytes())
    audit = json.loads((ROOT / 'proof/READONLY-REQUEST-AUDIT.json').read_bytes())
    assert not os.path.lexists(policy['operation_root'])
    assert preexec['status'] == 'FROZEN_NOT_EXECUTED'
    assert audit['status'] == 'STATIC_REQUEST_AND_ACTUAL_INPUT_READBACK_PASS'
    paths = [p for p in sorted(ROOT.rglob('*')) if p.is_file()
             and p.relative_to(ROOT).parts[0] != 'publication'
             and p.name not in ('MANIFEST.json', 'HANDOFF.json')]
    rows = [record(path) for path in paths]
    manifest = create('MANIFEST.json', {
        'schema': 'hia.cli-json.C-runtime-lifetime-frozen-files.v1',
        'status': 'FROZEN_NOT_EXECUTED', 'prefix': PREFIX,
        'parent_commit': '5f30676148b332fd8c1f01324a145e041e4582c0',
        'parent_tree': 'cf9dc2f2a2e70dda23bf9869db95fe04e812a8ac',
        'files': rows, 'file_count': len(rows), 'bytes': sum(r['bytes'] for r in rows),
        'physical_modes_are_recorded_separately_from_git_regular_modes': True,
        'external_tool_and_compiler_bytes_are_pinned_not_duplicated': True,
        'not_self_recursive': ['MANIFEST.json', 'HANDOFF.json'],
        'publication_ACKs_and_readbacks_are_external_receipts': True,
    })
    root_pins = {name: record(ROOT / name) for name in (
        'POLICY.json', 'REQUEST.json', 'PREEXEC.json', 'SYSTEM-INPUTS.json',
        'proof/AST-ONLY.json', 'proof/READONLY-REQUEST-AUDIT.json',
        'proof/FROZEN-INPUTS.READBACK.json', 'proof/CURRENT-COMPILER.READBACK.json')}
    handoff = {
        'schema': 'hia.cli-json.C-runtime-lifetime-plan-handoff.v1',
        'status': 'FROZEN_NOT_EXECUTED_REQUIRES_ROOT_REVIEW',
        'git_prefix': PREFIX, 'local_root': str(ROOT), 'manifest': manifest,
        'parent_commit': '5f30676148b332fd8c1f01324a145e041e4582c0',
        'parent_tree': 'cf9dc2f2a2e70dda23bf9869db95fe04e812a8ac',
        'source_actual_basis': {
            'canonical': '5f30676148b332fd8c1f01324a145e041e4582c0',
            'actual_source_components': 2,
            'lifetime_HIA_bytes': 26967,
            'lifetime_HIA_sha256': '43b7d82d0dd14cc44e70168127801046d17112c4e0338b453c251e575a791ec4',
            'unchanged_actual_HIA_consumed_without_regeneration': True,
            'source_snapshot': '177 prior source files; one composed C replacement and five additions',
            'source_files': preexec['source_files'], 'source_bytes': preexec['source_bytes'],
        },
        'fixed_inputs': root_pins,
        'command': preexec['command'], 'cwd': preexec['cwd'],
        'environment': preexec['environment'], 'unique_output': policy['operation_root'],
        'python': policy['python'],
        'system_inputs': {
            'files': preexec['system_files'], 'bytes': preexec['system_bytes'],
            'GCC': policy['c_toolchain']['gcc'], 'include_search': policy['c_toolchain']['include_search'],
            'closure': 'Actual compiler programs, headers, CPython executable/stdlib, declared ELF dependencies, and namespace/link identities',
            'provisioned_uid_exception': 'Only exact physical rows including bytes, mode, UID/GID and link count; no blanket system-owner relaxation',
            'mapped_python_is_executable_not_separate_libpython': True,
            'root_or_kernel_lock_claimed': False,
        },
        'existing_compiler': {
            'canonical': policy['compiler_capsule_commit'],
            'original_count': preexec['current_compiler_original_files'],
            'other_bound_inputs': preexec['current_compiler_other_inputs'],
            'artifact': policy['current_compiler_capsule']['artifact'],
            'B3': policy['compiler'],
            'scope': 'Read-only reuse of actual v89 B3 for this finite development experiment',
            'new_fresh_B0_B1_B2': False, 'current_v92_matching': False,
        },
        'outer_owner': {
            'implementation_sha256': '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2',
            'entry': 'unchanged process_owner_impl.run_owned',
            'qualification_seconds': 180, 'cleanup_seconds': 3,
            'd0b_guardian_file': 'Frozen historical input only; not called by this launch',
            'worker_actual_input_reread_inside_outer': True,
            'launcher_independent_rechecks_after_outer': True,
        },
        'stages': [
            {'name': 'c-compile', 'wall_seconds': 20, 'cleanup_seconds': 3,
             'cpu_seconds': 10, 'per_file_output_capacity': 1048576,
             'kind': 'one newly declared finite GCC frontend invocation'},
            {'name': 'runtime', 'wall_seconds': 5, 'cleanup_seconds': 3, 'cases': 8,
             'scope': 'actual DSO and 11 base plus 5 control symbols; pinned mapped executable'},
            {'name': 'hia-compile', 'wall_seconds': 20, 'cleanup_seconds': 3,
             'original_child_wall_seconds': 20, 'cpu_seconds': 10,
             'full_output_capacity': 1048576, 'scope': 'one original compile_stage call for lifetime HIA'},
            {'name': 'lifetime', 'wall_seconds': 5, 'cleanup_seconds': 3, 'cases': 10,
             'scope': 'finite real generator/ref/error lifecycle leaves and C pump; no body evaluator activation'},
        ],
        'finite_expected_populations': {
            'runtime_ids': policy['runtime_ids'], 'lifetime_ids': policy['lifetime_ids'],
            'expected_HIA_returns_per_lifetime_case': policy['expected_lifetime_HIA_returns'],
            'expected_C_pump_calls_per_lifetime_case': policy['expected_C_pump_calls_including_refusals'],
            'expected_HIA_returns': 48, 'expected_C_pump_calls': 11,
            'all_expected_counts_unexecuted': True, 'actual_counts_known': False,
            'raw_leaf_only_cases_have_zero_HIA_entries': True,
            'trace_overflow_is_explicit_negative_control_not_JSON_domain_limit': True,
        },
        'preserved_original17_and46': policy['preserved_original17_and46'],
        'failure_and_custody': {
            'first_HOLD_stops_subsequent_stage': True,
            'no_retries_or_new_key': True,
            'actual_bound_ECHILD_required_before_reading_child_outputs': True,
            'nonzero_closed_run_preserves_actual_original_inventory_before_success_checks': True,
            'unknown_closure_keeps_metadata_and_HOLD_without_live_child_reads': True,
            'actual_raw_outputs_are_not_reconstructed': True,
            'closed_inventory_budget_bytes': 67108864,
            'typed_specials_are_metadata_only': True,
        },
        'actual_checks_completed': {
            'Python_AST_files': preexec['source_and_control_AST_parses_only'],
            'readonly_request_checks': len(audit['checks']),
            'all_182_source_and_4555_system_files_actual_full_hash': True,
            'complete_old_62_compiler_originals_and_six_generation_chain': True,
        },
        'not_executed': {
            'C_frontend': True, 'HIA_compiler': True, 'private_symbol_admission': True,
            'runtime_8': True, 'lifetime_10': True, 'original_CLI_17': True,
            'original_trace_46': True, 'any_native_entry': True,
        },
        'remaining_scope': preexec['unexecuted_scopes'],
        'remaining_concrete_gap': 'Actual finite C compilation, mapped-symbol admission and 8+10 execution require the root-reviewed unique invocation; no result is predicted',
        'full_activation_OPEN': 'r4e CALL/SEND/UNPACK, evaluator frame semantics, hooks and monitoring remain unqualified and are not executed by these cases',
        'default_selection_changed': False,
        'old_unknown_TimSort_or_h_requests_touched': False,
        'frozen_history': 'history/authoring-freeze-r1 preserves the earlier unexecuted local request and verifier before strengthening readonly joins',
    }
    handoff_pin = create('HANDOFF.json', handoff)
    print(json.dumps({'manifest': manifest, 'handoff': handoff_pin,
                      'total_Git_leaves_to_add': len(rows) + 2,
                      'status': handoff['status']}))


if __name__ == '__main__':
    main()
