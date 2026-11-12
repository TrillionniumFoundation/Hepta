import json
from hashlib import sha1, sha256
from pathlib import Path

ROOT = Path(__file__).absolute().parent.parent

def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()

def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob_sha1': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}

old = json.loads((ROOT / 'originals/control-manifest.json').read_bytes())
controls = json.loads((ROOT / 'control/control-manifest.json').read_bytes())
unchanged_names = ['source_common.py', 'source-manifest.json', 'populations.json', 'guardian.py',
    'process_owner_impl.py', 'reject_cases.py', 'lifetime_cases.py', 'permission_cases.py',
    'filesystem_cases.py', 'original_eight.py', 'caller_observer.py', 'read_bounded.original.py']
unchanged = []
for name in unchanged_names:
    actual = pin((ROOT / 'control' / name).read_bytes())
    if name in old['files']:
        assert actual == old['files'][name], name
    elif name == 'guardian.py':
        assert actual['sha256'] == 'd0b56d24905895ad59120f401d006badfdb1df5b3e0ab17a80e8414da78a1023'
    else:
        raise AssertionError('missing old immutable input binding: ' + name)
    unchanged.append({'path': name, **actual})

design = {
    'schema': 'hepta.hia.bounded-read-actions-design.v1',
    'status': 'STATIC_UNEXECUTED_ACTIONS_CANDIDATE',
    'revision': 2,
    'unexecuted_A1_retained': '5473f1eb2c541184828f6e885af4bc8807e01a39',
    'unexecuted_B1_retained': '86ac6c56f0ea7747d63016a07959a0658d04f529',
    'original_native_control_checkpoint': '66a3cd673ee93ecfd37ebee4eecfe7cd166b39d2',
    'original_native_control_tree': '7e073c72a0a5c3d2a5d5af13ff1bc68f8391727a',
    'source': {'commit': '0e36619bc65ada7072c1e8a1f1454728036fee4e',
        'tree': '1d95802c453a006f077eb8735a6939b1957d500b', 'regular_leaves': 4025,
        'physical_leaves_after_generation': 4026,
        'sole_added_path': 'examples/hia_bootstrap/bounded_read.hiaasm',
        'candidate_global_contract_and_coverage_updated': False},
    'execution': {'dispatch_not_authorized_by_checkpoint': True, 'workflow_triggered': False,
        'outer_original_guardian_seconds': 180, 'cleanup_seconds': 3,
        'fresh_current_source_B0_B1_B2_inside_same_outer': True,
        'original_compile_wall_seconds': 20, 'original_compile_CPU_seconds': 10,
        'original_compile_address_space_bytes': 256 << 20, 'original_stack_bytes': 8 << 20,
        'original_output_and_workspace_bytes_each': 1 << 20,
        'preparer_inner_seconds': 60, 'finite_inner_seconds_each': 30,
        'original_eight_inner_seconds': 180, 'original_CLI_seconds_each': 20,
        'expected_HIA_functions': 14, 'finite_case_denominators': [12, 24, 10, 9],
        'original_methods': 8, 'original_CLI_children': 7,
        'normal_path_expected_native_attempts': 12, 'normal_path_expected_native_returns': 11},
    'compiler_binding': ['full actual detached commit/tree/parent and 4025 leaf bytes/modes',
        'actual original B0 receipt and loaded seed modules; explicit host seed only',
        'B1 request uses exact current B0; B2 uses actual B1; B1/B2 complete raw bytes must equal',
        'component request uses actual B2 and freshly generated assembly',
        'each unchanged child request/receipt/full output/image independently reread',
        'B0 original artifact_sha256/artifact_bytes/output identify actual B0.so',
        'all three child image/source/output hashes bind loaded image, actual input and complete output',
        'each actual child stdout JSON exactly equals receipt minus the original seven plus three producer fields',
        'original source, qualifier, child, B0/B1/B2/component images and linker stable across execution',
        'source-only rendered Core roundtrip and original caps; no B3 or cold claim'],
    'independent_acceptance': ['original outer natural lifecycle and current operation-bound ECHILD',
        'all six actual inner requests/receipts/returned projections and six raw files per process',
        'all 55 case raw originals plus fixed loaded/executed IDs and zero five anomalies',
        'all original eight IDs, parent record and seven distinct CLI start/completion pairs',
        'retained policy code-object and alias observers in actual parent and unchanged CLI children',
        'complete current source physical snapshots, Git identity, compiled image and control bytes'],
    'custody': {'ordinary_outputs': 'closed-current-ECHILD typed tar with full bytes and exact modes/uid/gid',
        'FIFO_and_symlinks': 'typed metadata only; not opened/followed; tar is not extracted',
        'other_specials': 'lstat identity in manifest only; no node or data access',
        'full_original_inventory_regular_bytes_limit': 128 << 20,
        'typed_archive_readback_bytes_limit': 160 << 20, 'member_limit': 4096,
        'full_ordinary_outputs_uploaded_even_when_product_HOLD': True,
        'unclosed_process': 'HOLD; only fixed safe setup/context/request metadata, no live child originals',
        'upload_root': 'public ordinary outputs plus six fixed host stage logs; never fixture tree'},
    'small_channel': {'fixed_targets': 133, 'previous_targets': 130, 'added_actual_sources': [
        'build/bounded-read.hiaasm', 'build/entry-abi.json', 'build/manifest.json'],
        'raw_bytes_limit': 512 << 10, 'stdout_bytes_limit': 1 << 20, 'complete_index_limit': 64 << 10,
        'source_and_ABI_priority_before_total_reports': True, 'whole_file_only_no_truncation': True,
        'each_fixed_target_has_SHA_or_explicit_missing_refused_omitted_unclosed_status': True,
        'complete_artifact_transport_claimed': False,
        'END_after_all_prebudgeted_file_frames_only': True},
    'scope': {'native_or_product_execution_performed_before_this_checkpoint': False,
        'original_or_new_product_tests_run_locally': False, 'finite_cases_are_not_universal_equivalence': True,
        'foreign_finalizer_and_exception_traces_pending_actual_execution': True,
        'cyclic_GC_and_all_async_interleavings_not_qualified': True,
        'no_installed_or_full_delivery_qualification': True,
        'paths_are_observations_not_locks_spanning_process_execution': True},
    'local_evidence': {'AST': 'evidence/AST-PARSE-ACTIONS.json',
        'five_actual_small_filesystem_transport_controls': 'evidence/custody-controls-r1-report.json',
        'ten_actual_synthetic_original_vs_strengthened_receipt_controls': 'evidence/receipt-joins-r2/report.json',
        'transport_controls_are_not_product_tests_or_real_guardian_execution': True},
    'original_control_bytes_retained': unchanged,
    'runtime_switch': {'precommit_V8_Actions_draft_was_lost': True,
        'canonical_original_66a3_retained': True, 'lost_draft_claimed_byte_identical': False,
        'interrupted_mutation_or_product_dispatch': False,
        'new_Actions_text_is_explicit_reconstruction_then_local_AST_parse': True}}
(ROOT / 'control/DESIGN.json').write_bytes(wire(design))
print(json.dumps({'unchanged_files': len(unchanged), 'design': pin((ROOT / 'control/DESIGN.json').read_bytes())}))
