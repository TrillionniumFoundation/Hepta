#!/usr/bin/env python3
"""Package the completed P3 records. This script does not run any qualifier."""
import base64
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

ROOT = Path('/workspace/scratch/f0c12f106c89')
OUT = ROOT / 'p3-integrated-50c4067-evidence'
REPO = ROOT / 'hepta-integration'
HEAD = '50c4067399989e7194028576c38c0e783b78cf06'
LAUNCHES = ROOT / 'p3-integrated-50c4067-launches'
BASELINE = ROOT / 'p3-integrated-50c4067-musl125'
MAINTENANCE = ROOT / 'p3-integrated-50c4067-maintenance126'
CPP = ROOT / 'p3-integrated-50c4067-cpp-upgrade'
HISTORICAL = REPO / 'evidence/hia_musl_strncmp_20261030'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def load(path):
    return json.loads(path.read_text())

def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')

def identity(path):
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': sha(data)}

def git(*args):
    return subprocess.check_output(['git', '-C', str(REPO), *args]).decode().strip()

def main():
    assert git('rev-parse', 'HEAD') == HEAD
    assert git('status', '--porcelain') == ''
    plan = load(LAUNCHES / 'PLAN.json')
    assert plan['source_head'] == HEAD
    launches = [load(LAUNCHES / f'{i:02d}-{stage}-attempt-001/launch.json')
                for i, stage in enumerate(('musl125', 'musl126', 'cpp'), 1)]
    for launch in launches:
        assert launch['status'] == 'completed'
        assert launch['inputs_before'] == launch['inputs_after'] == plan['frozen_inputs']
    c_reports = [load(BASELINE / 'qualification.json'), load(MAINTENANCE / 'successor/qualification.json')]
    update = load(MAINTENANCE / 'update.json')
    cpp_report = load(CPP / 'report.json')
    versions, terminations = {}, []
    for version in cpp_report['versions']:
        faults = version['allocation_failures']
        recovered = [f for f in faults if f['status'] == 'caught_and_recovered']
        terminated = [f for f in faults if f['status'] == 'foreign_noexcept_termination']
        for fault in terminated:
            process = fault['process']
            terminations.append({'version': version['version'], 'site': fault['site'],
                                 'exit_code': process['exit_code'], 'seconds': process['seconds'],
                                 'stderr': process['stderr'], 'stderr_sha256': process['stderr_sha256'],
                                 'recovery_qualified': fault['recovery_qualified']})
        versions[version['version']] = {
            'ordinary_cases': len(version['execution']['cases']),
            'actual_calibrated_allocation_sites': version['calibration']['observation']['allocation_sites'],
            'caught_and_recovered': len(recovered),
            'foreign_noexcept_termination': len(terminated),
            'all_allocation_failure_paths_recovered': version['all_allocation_failure_paths_recovered'],
            'pointer_guards': version['execution']['pointer_guards'],
            'ordinary_live_delta': version['execution']['ordinary_live_delta'],
            'c_export_symbols': version['c_symbols'],
            'cost': version['cost'],
            'explicit_process_ledger_entries': len(version['processes']),
        }
    summary = {
        'schema': 'hepta.p3-integrated-evidence-summary.v1',
        'source_head': HEAD, 'source_tree': plan['frozen_inputs']['tree'],
        'source_status_before_and_after': '',
        'same_matrix': True, 'new_holdout': False,
        'scope': 'fresh same-matrix regression of merged front/backend; C finite standalone rewrite and a distinct C++ retaining bridge upgrade',
        'historical_results_relabelled': False,
        'plan': identity(LAUNCHES / 'PLAN.json'), 'launcher': identity(LAUNCHES / 'launch.py'),
        'c': {
            'component': 'complete generic musl strncmp.c; two initialized read-slice contracts plus one authored finite scalar client',
            'upstream_versions': ['1.2.5', '1.2.6'],
            'original_function_bytes': 220,
            'original_function_sha256': c_reports[0]['upstream']['files'][0]['sha256'],
            'unchanged_upstream_bodies_per_version': 1,
            'manual_migrated_body_edits': 0,
            'domain': 'unsigned-char C11, Linux x86_64 LP64; two initialized slices each at least n bytes; scalar client limits n to 8',
            'input_cases_per_version': 386, 'allocation_refusal_values': [0, 1, 2],
            'versions': {r['upstream']['version']: {
                'completed_cases': r['completed_cases'],
                'native_observations': r['native_observations'],
                'vm_observations': r['vm_observations'],
                'whole_qualification_wall_ns': r['whole_qualification_wall_ns'],
                'capture_lowering_verification_wall_ns': r['migration']['wall_ns'],
                'direct_llvm_native_build_wall_ns': r['native_build_wall_ns'],
                'claims': r['claims'],
            } for r in c_reports},
            'core_sha256_both_versions': c_reports[0]['migration']['program_sha256'],
            'native_route': 'captured C AST to HIA Core to direct LLVM object, linked only with the observer for the HIA target',
            'original_c_linked_into_hia_target': False, 'rust_codegen_used': False,
            'fallback_used': False,
            'observed_final_native_live_allocations': 0,
            'observed_final_vm_live_owners_bytes_and_local_loans': 0,
            'maintenance_conditions': update['accepted_conditions'],
            'maintenance_source_delta': update['source_delta'],
            'maintenance_wall_ns_excluding_historical_acquisition': update['maintenance_wall_ns_excluding_acquisition'],
            'changed_body_auto_adaptation_qualified': False,
            'foreign_pointer_abi_qualified': False,
            'arbitrary_c_cpp_supported': False,
            'all_input_semantics_or_backend_proved': False,
        },
        'cpp': {
            'library': 'nlohmann/json', 'from': '3.11.3', 'to': '3.12.0',
            'route': 'retained C++ library and adapter, generated C++/C ABI bridge, native Hepta caller through Rust backend',
            'foreign_library_rewritten': False, 'foreign_memory_safety_proved': False,
            'versions': versions,
            'foreign_noexcept_terminations': len(terminations),
            'all_allocation_failure_paths_recovered': all(v['all_allocation_failure_paths_recovered'] for v in versions.values()),
            'unrecovered_termination_records': terminations,
            'termination_cost_is_already_included_in_qualifier_cost': True,
            'upgrade': cpp_report['upgrade'],
            'negative_controls': {
                'incompatible_signature_rejected': cpp_report['negative_controls']['incompatible_signature']['report']['ok'] is False,
                'incompatible_signature_output_published': cpp_report['negative_controls']['incompatible_signature']['output_published'],
                'wrong_compiled_bridge_exit_code': cpp_report['negative_controls']['wrong_implementation']['execution_process']['exit_code'],
                'wrong_compiled_bridge_stderr': cpp_report['negative_controls']['wrong_implementation']['execution_process']['stderr'],
            },
            'ordinary_cases_are_rows_in_one_cases_process_per_version': True,
            'explicit_process_ledger_entries': sum(len(v['processes']) for v in cpp_report['versions']) + len(cpp_report['processes']) + len(cpp_report['negative_controls']['processes']),
            'explicit_process_ledger_is_complete_os_process_count': False,
            'claims': cpp_report['claims'],
        },
        'launches': [{key: launch[key] for key in ('stage', 'status', 'returncode', 'timeout_seconds',
                     'process_launched', 'qualifier_process_wall_ns', 'outer_wall_ns', 'error', 'postflight_error',
                     'timed_out', 'signals_sent')} for launch in launches],
        'all_three_outer_wall_ns': sum(launch['outer_wall_ns'] for launch in launches),
        'nested_costs_are_not_additional_to_outer_cost': True,
        'fresh_failed_outer_attempts': sum(launch['status'] != 'completed' for launch in launches),
        'new_upstream_download_requests': 0,
        'historical_acquisition_wall_ns': update['acquisition']['wall_ns'],
        'historical_acquisition_cost_counted_again': False,
        'complete_development_effort': None, 'complete_development_effort_status': 'unknown',
        'human_effort': None, 'human_effort_status': 'unknown',
        'actual_ai_model_runs': 0, 'runtime_performance_advantage_measured': False,
        'complete_system_or_dynamic_loader_attestation': False,
        'general_migration_success_claimed': False,
        'historical_source_commits': {
            'baseline': '46534e04ec874bd5681b9f38914e210c2ef813be',
            'maintenance': 'f82d016e08431bf9c16d12a613bfab6151103d8a',
            'evidence': '712e926cbfa4fc7c14a9d2ee7be321b6f1a0961a',
        },
        'historical_records': plan['frozen_inputs']['historical_evidence_unchanged'],
        'historical_failed_attempts_and_measured_costs': 'unaltered original six-file package retained under historical/, including its full prior execution archive; they are not current-source runs',
        'verification_scope': 'offline retained byte identity and finite receipt consistency, without executing artifacts, authenticating a remote signer, or proving all-input semantics',
        'original_execution_directories_preserved': True,
    }
    write(OUT / 'SUMMARY.json', summary)

    roots = {str(LAUNCHES): 'launches', str(BASELINE): 'baseline', str(MAINTENANCE): 'maintenance',
             str(CPP): 'cpp-upgrade', str(REPO): 'source/' + HEAD}
    files = {}
    def add(path, name):
        assert path.is_file() and not path.is_symlink(), str(path)
        assert name not in files
        files[name] = path
    def tree(path, prefix):
        for child in sorted(path.rglob('*')):
            if child.is_file():
                add(child, prefix + '/' + child.relative_to(path).as_posix())
    for path, prefix in ((LAUNCHES, 'launches'), (BASELINE, 'baseline'), (MAINTENANCE, 'maintenance'),
                         (CPP, 'cpp-upgrade'), (ROOT / 'p3-upstream-acquisition', 'acquisition')):
        tree(path, prefix)
    for relative, expected in plan['frozen_inputs']['source_bindings'].items():
        path = REPO / relative
        data = path.read_bytes()
        assert len(data) == expected['bytes'] and sha(data) == expected['sha256']
        add(path, 'source/' + HEAD + '/' + relative)
    for name, expected in plan['frozen_inputs']['historical_evidence_unchanged'].items():
        path = HISTORICAL / name
        assert sha(path.read_bytes()) == expected['sha256']
        add(path, 'historical/' + name)
    add(ROOT / 'musl-1.2.5.tar.gz', 'archives/musl-1.2.5.tar.gz')
    environment = Path(plan['environment_source']['path'])
    assert sha(environment.read_bytes()) == plan['environment_source']['sha256']
    add(environment, 'environment/environment.json')
    archive_path = OUT / 'executions.tar.xz'
    inventory = []
    with tarfile.open(archive_path, 'w:xz', format=tarfile.PAX_FORMAT, preset=6) as archive:
        for name, path in sorted(files.items()):
            data = path.read_bytes()
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
            entry.mtime = 0
            archive.addfile(entry, io.BytesIO(data))
            inventory.append({'path': name, 'bytes': len(data), 'sha256': sha(data), 'origin': str(path)})
    with archive_path.open('rb') as source, (OUT / 'executions.tar.xz.base64').open('wb') as destination:
        base64.encode(source, destination)
    (OUT / 'cpp-report.json').write_bytes((CPP / 'report.json').read_bytes())
    (OUT / 'maintenance-report.json').write_bytes((MAINTENANCE / 'update.json').read_bytes())
    manifest = {
        'schema': 'hepta.p3-integrated-evidence-manifest.v1', 'source_head': HEAD,
        'same_matrix': True, 'new_holdout': False,
        'archive_bytes': archive_path.stat().st_size,
        'archive_sha256': sha(archive_path.read_bytes()),
        'encoded_archive': identity(OUT / 'executions.tar.xz.base64'),
        'uncompressed_member_bytes': sum(row['bytes'] for row in inventory),
        'members': inventory, 'roots': roots, 'cpp_original_root': str(CPP),
        'summary_sha256': sha((OUT / 'SUMMARY.json').read_bytes()),
        'verifier': identity(OUT / 'verify_archive.py'),
        'packaging_script': identity(Path(__file__).resolve()),
        'visible_copies': [identity(OUT / 'cpp-report.json'), identity(OUT / 'maintenance-report.json')],
        'source_binding_count': len(plan['frozen_inputs']['source_bindings']),
        'source_snapshot_is_whole_repository': False,
        'tool_binaries_or_complete_host_dependencies_included': False,
        'tool_identity_records': 'launches/PLAN.json and per-stage launch records and qualification raw ledgers',
        'integrity_is_not_signature_authentication': True,
        'original_execution_directories_preserved': True,
    }
    write(OUT / 'MANIFEST.json', manifest)
    assert git('rev-parse', 'HEAD') == HEAD
    assert git('status', '--porcelain') == ''
    print(json.dumps({key: manifest[key] for key in ('source_head', 'archive_bytes', 'archive_sha256', 'uncompressed_member_bytes', 'source_binding_count')} | {'members': len(inventory)}, indent=2))

if __name__ == '__main__':
    main()
