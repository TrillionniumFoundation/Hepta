"""Freeze new-host source4 inputs without importing or generating project code."""
from __future__ import annotations
import ast
import json
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
import source_common as common

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'source'

def main():
    os.umask(0o077)
    names = ('SOURCE4-REQUEST.json', 'SOURCE4-LAUNCH.json', 'SOURCE4-PREEXEC.json',
             'DEVELOPMENT-NATIVE-NEXT.json')
    common.require(all(not (ROOT / name).exists() for name in names), 'new freeze outputs required')
    materialization_raw, materialization_pin = common.read_regular(ROOT / 'SOURCE-MATERIALIZATION.json')
    materialization = common.decode(materialization_raw)
    common.require(materialization_pin['sha256'] == 'a2b5f97daa344b8c773377b597c75a26f5e997eb23bda72345c9eb6280fe0ece'
                   and materialization['changed'] == ['tools/generate_hia_core_lowering.py'],
                   'materialization scope differs')
    common.require(materialization['base_commit'] == 'fbbac0417195122a3261a1bfc708e997a8cd69e5'
                   and materialization['base_tree'] == '64a6acbf342bf646759e7994f90d658d5711ccfc',
                   'restored baseline differs')
    source_test = SOURCE / 'tests/test_hia_core_lowering_native.py'
    tree = ast.parse(common.read_regular(source_test)[0])
    cls = next(node for node in tree.body if isinstance(node, ast.ClassDef)
               and node.name == 'CoreLoweringSourceTests')
    ids = ['tests.test_hia_core_lowering_native.CoreLoweringSourceTests.' + n.name
           for n in sorted((n for n in cls.body if isinstance(n, ast.FunctionDef)
                            and n.name.startswith('test_')), key=lambda n: n.name)]
    expected = [
        'tests.test_hia_core_lowering_native.CoreLoweringSourceTests.test_complete_original_Function_and_five_helpers_are_independent',
        'tests.test_hia_core_lowering_native.CoreLoweringSourceTests.test_current_32_sources_keep_original_Core_caps_and_literal_VM',
        'tests.test_hia_core_lowering_native.CoreLoweringSourceTests.test_unqualified_cold_refuses_before_output_creation',
        'tests.test_hia_core_lowering_native.CoreLoweringSourceTests.test_unselected_constructor_subclass_and_early_target_errors_stay_original']
    common.require(ids == expected, 'original source4 methods differ')
    abi_raw, abi_pin = common.read_regular(SOURCE / 'hepta/hia_core_lowering_abi.json')
    abi = common.decode(abi_raw)
    common.require(abi['schema'] == 'hepta.hia.core-lowering-abi.v2'
                   and abi['units'] == ['core_lowering_' + format(i, '03d') for i in range(38)],
                   'original 39-source ABI differs')
    assemblies = ['examples/hia_bootstrap/' + name + '.hiaasm'
                  for name in ('core_lowering_pool', *abi['units'])]
    runtime_path = Path(sys.executable).resolve(strict=True)
    runtime = common.read_regular(runtime_path)[1]
    common.require(str(runtime_path) == '/usr/bin/python3.14'
                   and runtime['sha256'] == '52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41'
                   and tuple(sys.version_info[:3]) == (3, 14, 4), 'new-host runtime differs')
    owner_pin = common.read_regular(SOURCE / 'tools/hia_selfhost_process_owner.py')[1]
    common.require(owner_pin['sha256'] == '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2',
                   'original owner changed')
    inputs = [ROOT / name for name in ('source_common.py', 'source_worker.py', 'source_launch.py',
                                       'freeze_source_request.py', 'SOURCE-MATERIALIZATION.json')]
    inputs.extend(sorted((ROOT / 'canonical').rglob('*')))
    inputs.extend([ROOT / 'references/generate_hia_core_lowering.before.py',
                   SOURCE / 'tools/hia_selfhost_process_owner.py'])
    input_pins = [common.read_regular(p)[1] for p in inputs if p.is_file()]
    output = ROOT / 'source4-actual-r1'
    common.require(not output.exists(), 'fresh source4 actual root required')
    environment = {'PATH': '', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                   'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1',
                   'PYTHONHASHSEED': '0', 'TMPDIR': str(output / 'scratch')}
    request_path = ROOT / 'SOURCE4-REQUEST.json'
    request = {'schema': common.SCHEMA,
        'operation': 'pc-forwarding-source4-ai395-r1-20261113-e26e',
        'host': 'ai395', 'scope': 'NEW_HOST_SOURCE_GENERATION_AND_FOUR_ORIGINAL_SOURCE_CORE_VM_METHODS_ONLY',
        'baseline_commit': materialization['base_commit'], 'baseline_tree': materialization['base_tree'],
        'static_draft_commit': '43b4c3777c33d30930aba5e3b758d9cbcc9efad8',
        'static_draft_ref_state': 'CREATE_422_GET404_NO_RETRY_COMMIT_AND_ALL_BLOBS_READABLE',
        'runtime': runtime, 'runtime_version': sys.version,
        'inputs': input_pins, 'materialization': materialization_pin,
        'source_root': str(SOURCE), 'source_file_count': materialization['file_count'],
        'source_bytes_before': materialization['source_bytes'],
        'output_root': str(output), 'qualification_seconds': 180, 'cleanup_seconds': 3,
        'minimum_free_bytes': 512 * 1024 * 1024, 'minimum_free_inodes': 4096,
        'environment': environment, 'owner_implementation': owner_pin,
        'expected_ids': expected, 'expected_method_count': 4,
        'generated_assembly': assemblies, 'generated_count': 39,
        'generated_write_paths': sorted([*assemblies, 'hepta/hia_core_lowering_abi.json']),
        'unchanged_generated_paths': ['hepta/hia_core_lowering_abi.json', assemblies[0]],
        'expected_changed_assembly': sorted(assemblies[1:]),
        'original_nine_caps': {'source_bytes': 1048576, 'source_lines': 16384,
            'functions': 128, 'blocks': 1536, 'operations_plus_terminators': 8192,
            'blocks_per_function': 256, 'parameters_per_function': 16,
            'arguments_per_operation': 16, 'ssa_definitions_per_function': 2048},
        'guards': {'audit_hook_before_project_import': True,
            'forbid_product_native_image_loading': True, 'forbid_mmap': True,
            'forbid_new_dlopen': True, 'forbid_network': True,
            'forbid_subprocess': True,
            'standard_ctypes_memory_copy_for_original_Core_VM_fixture_allowed': True},
        'original116_or18_or_cold_or_installed_qualification_claimed': False,
        'original_ci_timeout_and_old_R4_UNKNOWN_preserved': True,
        'worker_command_template': [str(runtime_path), '-I', '-S', '-B',
            str(ROOT / 'source_worker.py'), '--request', str(request_path), '--sha256', '<REQUEST-SHA256>']}
    # The owner command is assembled from a frozen literal template plus the
    # caller-supplied request hash after verifying those same request bytes.
    request['worker_command'] = None
    raw = common.wire(request)
    request_pin = common.save(request_path, raw)
    launch = {'schema': 'hia.frozen.single-launch.v1', 'host': 'ai395',
        'argv': [str(runtime_path), '-I', '-S', '-B', str(ROOT / 'source_launch.py'),
                 '--request', str(request_path), '--sha256', request_pin['sha256']],
        'cwd': str(ROOT), 'env': environment, 'request_sha256': request_pin['sha256'],
        'status': 'UNEXECUTED_REQUIRES_ROOT_REVIEW_AND_ONE_INVOCATION',
        'source_worker_budget_seconds': 180, 'cleanup_seconds': 3}
    launch_pin = common.save_json(ROOT / 'SOURCE4-LAUNCH.json', launch)
    preexec = {'schema': 'hia.pc-forwarding.source4-preexecution.v1', 'status': 'FROZEN_UNEXECUTED',
        'request': request_pin, 'launch': launch_pin,
        'original_four_test_body_modified': False,
        'source_changes_before_generation': materialization['changed'],
        'source_snapshot_count': materialization['file_count'],
        'source_snapshot_bytes': materialization['source_bytes'],
        'native_stage_not_authorized_by_this_request': True}
    common.save_json(ROOT / 'SOURCE4-PREEXEC.json', preexec)
    native = {'schema': 'hia.pc-forwarding.development-next-stage.v1',
        'status': 'DESIGN_ONLY_NO_EXECUTABLE_LAUNCH',
        'depends_on': ['This exact source4 PASS and all original generated source bytes',
                       'Root full seven-file B3 archival receipt recovery and independent admission'],
        'compiler_scope': 'HISTORICAL_V87_DEVELOPMENT_ONLY_NOT_CURRENT_MATCHING_COLD',
        'compiler_sha256': '9de8606c153e50f2e742a18d4eb9f3b7c210b404f005346e95b550648d8f2892',
        'compiler_plan_commit': 'df7cc43d9b225108924aef972b10f67a5a0dfb29',
        'compile_units': 39, 'per_compile_wall_seconds': 20, 'per_compile_cpu_seconds': 10,
        'per_compile_output_bytes': 1048576, 'per_compile_full_six_originals_required': True,
        'prepare_owner_seconds': 180, 'prepare_cleanup_seconds': 3,
        'later_full_caller_groups': [15, 51, 50], 'later_full_caller_total': 116,
        'later_full_caller_owner_seconds': 180, 'later_full_caller_cleanup_seconds': 3,
        'independent_reemission_preserved': True, 'full_source_image_ABI_identity_preserved': True,
        'new_host_speed_is_not_original_CI_closure': True,
        'current_matching_cold_and_standard_CI_require_new_actual_evidence': True,
        'no_native_or_compile_execution_authorized': True}
    common.save_json(ROOT / 'DEVELOPMENT-NATIVE-NEXT.json', native)
    print(json.dumps({'request': request_pin, 'launch': launch_pin, 'expected_ids': expected,
                      'status': 'FROZEN_UNEXECUTED'}, sort_keys=True))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
