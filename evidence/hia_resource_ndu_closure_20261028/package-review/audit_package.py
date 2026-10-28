#!/usr/bin/env python3
"""Read-only payload audit of the original gzip evidence package.

The seven package inputs were snapshotted before the concurrent lossless xz
repack. No test, benchmark or archived executable is run by this audit.
"""
from collections import Counter, defaultdict
from datetime import datetime, timezone
from hashlib import sha1, sha256
import gzip
import json
import lzma
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile

BASE = Path('/workspace/scratch/bf7d454bbc83')
ROOT = BASE / 'hepta-next-evidence'
PACKAGE = BASE / 'hia-next-package-original-gzip-audit-inputs'
REPORT = BASE / 'hia-next-final-package-audit.json'
SOURCE = '389f33b0dccec3fcbb0e2205b3cb1f07bd3ff9c4'
TREE = '0f6bff924e6926eb7e4031828426c960c129465b'
NDU_SOURCE = '01310b2e6c1676e73cd0f338fcf0b8bf072d3fe4'


def sha(path):
    result = sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            result.update(chunk)
    return result.hexdigest()


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('Duplicate JSON key: ' + key)
        result[key] = value
    return result


def decode(data):
    return json.loads(data, object_pairs_hook=pairs)


def load(name):
    return decode((PACKAGE / name).read_bytes())


def safe_path(name):
    path = PurePosixPath(name)
    return (type(name) is str and bool(name) and '\x00' not in name and '\\' not in name
            and not re.match(r'^[A-Za-z]:', name) and not path.is_absolute()
            and all(part not in {'', '.', '..'} for part in name.split('/'))
            and path.as_posix() == name)


def main():
    checks, findings = {}, []

    def check(label, condition, details=None):
        checks[label] = bool(condition)
        if not condition:
            findings.append({'check': label, 'details': details})

    manifest, acceptance = load('raw-evidence-manifest.json'), load('acceptance.json')
    full, component, qualification = load('full-audit.json'), load('component-audit.json'), load('qualification.json')
    before = {path.name: sha(path) for path in PACKAGE.iterdir() if path.is_file()}
    expected_archive = manifest['archive']
    archive = PACKAGE / expected_archive['name']
    check('original_gzip_archive_identity', expected_archive['name'] == 'raw-evidence.tar.gz'
          and sha(archive) == expected_archive['sha256'] == '9361a22cc2d55e38fb951d3c7329386876f84aeece872ac69f4f5535e0683570'
          and archive.stat().st_size == expected_archive['bytes'] == 37836096
          and (archive.stat().st_mode & 0o7777) == expected_archive['mode'])
    checksum_rows = {}
    for line in (PACKAGE / 'SHA256SUMS').read_text().splitlines():
        value, name = line.split('  ', 1)
        check('checksum_row_' + name, safe_path(name) and name not in checksum_rows
              and re.fullmatch(r'[0-9a-f]{64}', value) is not None and sha(PACKAGE / name) == value)
        checksum_rows[name] = value
    check('six_payload_checksum_rows', set(checksum_rows) == {
        'acceptance.json', 'component-audit.json', 'full-audit.json', 'qualification.json',
        'raw-evidence-manifest.json', 'raw-evidence.tar.gz'})

    members, cached, native, origins = {}, {}, {}, defaultdict(list)
    duplicates, unsafe, irregular, mismatches = [], [], [], []
    total = 0
    bundle_data = None
    with tarfile.open(archive, mode='r:gz') as tar:
        for member in tar:
            name = member.name
            if name in members:
                duplicates.append(name)
            if not safe_path(name):
                unsafe.append(name)
            if not member.isfile() or member.linkname or member.mode & 0o7000 or member.mode & 0o002:
                irregular.append({'name': name, 'type': repr(member.type), 'mode': member.mode})
            if not member.isfile():
                continue
            h = sha256()
            size, prefix, retained = 0, b'', []
            keep = (name.endswith('.json') and member.size < 12 * 1024 * 1024) or name == 'source/development-source.bundle'
            stream = tar.extractfile(member)
            for chunk in iter(lambda: stream.read(1 << 20), b''):
                if not prefix:
                    prefix = chunk[:64]
                h.update(chunk)
                size += len(chunk)
                if keep:
                    retained.append(chunk)
            actual = {'sha256': h.hexdigest(), 'bytes': size, 'mode': member.mode}
            expected = manifest['files'].get(name)
            if expected is None or actual != {key: expected[key] for key in actual} or size != member.size:
                mismatches.append(name)
            members[name] = actual
            if expected is not None:
                origins[expected['origin']].append(name)
            total += size
            if keep:
                data = b''.join(retained)
                if name.endswith('.json'):
                    cached[name] = decode(data)
                else:
                    bundle_data = data
            if prefix.startswith(b'\x7fELF'):
                endian = 'little' if prefix[5] == 1 else 'big'
                kind = int.from_bytes(prefix[16:18], endian)
                native[name] = dict(actual, format='ELF', elf_type=kind,
                                    machine=int.from_bytes(prefix[18:20], endian))
            elif prefix.startswith(b'MZ'):
                native[name] = dict(actual, format='PE')
            elif prefix.startswith(b'\0asm'):
                native[name] = dict(actual, format='WASM')
            elif prefix[:4] in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe'):
                native[name] = dict(actual, format='MachO')
    check('all_archive_names_safe', not unsafe, unsafe)
    check('archive_member_names_unique', not duplicates, duplicates)
    check('all_members_regular_with_safe_modes', not irregular, irregular)
    check('every_member_size_mode_and_sha256_matches_manifest', not mismatches, mismatches)
    check('manifest_is_exact_full_member_denominator', set(members) == set(manifest['files'])
          and len(members) == manifest['members'] == 932)
    check('uncompressed_payload_bytes_match', total == manifest['uncompressed_bytes'] == 251608427)

    check('top_level_source_identity', manifest['source_commit'] == acceptance['source_commit'] == SOURCE
          and manifest['source_tree'] == acceptance['source_tree'] == TREE)
    check('qualification_frozen_source_before_after', qualification['source_before'] == qualification['source_after']
          and qualification['source_before']['head'] == SOURCE and qualification['source_before']['tree'] == TREE
          and not qualification['source_before']['status'] and qualification['source_unchanged'] is True)
    check('full_audit_frozen_source_identity', full['source_head'] == SOURCE and full['source_tree'] == TREE
          and full['ok'] is True and full['audit_integrity_ok'] is True and full['qualification_passed'] is True)
    check('component_audit_frozen_source_identity', component['ok'] is True and not component['failures']
          and component['source']['head'] == SOURCE and component['source']['tree'] == TREE
          and component['source']['clean'] is True)
    check('acceptance_nested_audits_are_exact', acceptance['independent_audit']['component_audit'] == component
          and acceptance['independent_audit']['full'] == {'ok': full['ok'],
              'checks': sum(value is True for value in full['checks'].values()),
              'acceptance_checks': sum(value is True for value in full['acceptance_checks'].values())})
    check('archived_top_level_report_matches', cached['same-source/full-qualification/qualification.json'] == qualification)
    check('archived_full_audit_matches', cached['audits/full/audit.json'] == full)
    archived_component = [value for name, value in cached.items()
                          if name.startswith('audits/components-and-hosts/') and value == component]
    check('archived_component_audit_matches', len(archived_component) == 1)

    by_gate = {row['name']: row for row in qualification['gates']}
    check('six_expected_gates_pass', len(qualification['gates']) == len(by_gate) == 6 and
          set(by_gate) == {'actual_tools_and_linux_seals', 'ranking_bridge_identity', 'recursive_bridge_identity',
                           'rust_resource_crate', 'full_regression', 'merge_and_profile_coverage'}
          and all(row['passed'] is True for row in by_gate.values()))
    python = by_gate['full_regression']
    raw = python['execution']['stderr']
    footer = re.findall(r'^Ran (\d+) tests? in ([0-9.]+)s$', raw, re.M)
    method_records = re.findall(r'^test\w+ \(((?:tests\.)?test_[^\s)]+)\)', raw, re.M)
    check('python_raw_counts_and_success', len(footer) == 1 and int(footer[0][0]) == 2785
          and len(method_records) == len(set(method_records)) == 2785
          and python['tests_run'] == full['full_python_tests'] == acceptance['full_qualification']['python_tests'] == 2785
          and python['execution']['returncode'] == 0 and re.search(r'\nOK\s*\Z', raw) is not None
          and all(python[key] == 0 for key in ('failures', 'errors', 'skipped')))
    rust = by_gate['rust_resource_crate']
    summaries = re.findall(r'^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;',
                           rust['execution']['stdout'], re.M)
    check('rust_raw_counts_and_success', len(summaries) == 10
          and sum(int(row[1]) for row in summaries) == 57
          and all(row[0] == 'ok' and all(int(x) == 0 for x in row[2:]) for row in summaries)
          and rust['execution']['returncode'] == 0
          and rust['tests_run'] == full['rust_tests'] == acceptance['full_qualification']['rust_tests'] == 57)
    check('tracked_and_external_denominators', len(qualification['source_before']['files']) == full['tracked_files'] == 3540
          and len(qualification['external_inventory_before']) == full['external_inventory_files'] == 244
          and qualification['external_inventory_before'] == qualification['external_inventory_after']
          and qualification['external_inputs_unchanged'] is True)
    check('scalar_state_count_comes_from_full_run', acceptance['scalar_state']['tests_in_full_regression'] == 16
          and full['coverage_module_test_counts']['native_runtime_lifecycles']['test_hia_scalar_state'] == 16)
    check('six_stage_and_general_claims_remain_open', all(acceptance[key] is False for key in (
        'six_stages_closed', 'whole_language_soundness_proved', 'global_optimality_established',
        'universal_rust_performance_advantage', 'general_live_owner_loan_stack_migration',
        'primitive_cross_call_loan_returns_supported')) and qualification['six_stages_closed'] is False
        and qualification['global_optimality_established'] is False
        and acceptance['scalar_state']['automatic_profitability_established'] is False)

    origin_mismatches = []
    for directory, files in component['evidence_manifest'].items():
        for relative, expected in files.items():
            origin = str(Path(directory) / relative)
            names = origins.get(origin, [])
            if not names or any(members[name]['sha256'] != expected['sha256'] or
                                members[name]['bytes'] != expected['bytes'] for name in names):
                origin_mismatches.append(origin)
    check('all_component_audited_evidence_files_are_archived', not origin_mismatches, origin_mismatches)
    vm = component['sections']['owned_memory']['actual_rust_binary']
    check('actual_owned_memory_native_vm_retained', 'native/rust-owned-memory-vm' in native
          and members['native/rust-owned-memory-vm']['sha256'] == vm['sha256']
          and members['native/rust-owned-memory-vm']['bytes'] == vm['bytes'])
    musl = cached['same-source/components/musl/qualification.json']
    check('musl_counts_match_exact_component_report', musl['ok'] is True
          and all(acceptance['musl'][key] == musl[key] for key in acceptance['musl']))
    native_bindings = []
    for row in musl['configurations']:
        label = row['optimization'][1:]
        artifact = row['migration']['artifacts']['libtranslated.so']
        name = 'same-source/components/musl/' + label + '/translated/libtranslated.so'
        check('musl_' + label + '_native_target_hash', name in native
              and members[name]['sha256'] == artifact['sha256'] and members[name]['bytes'] == artifact['bytes'])
        native_bindings.append(name)
    for title, row in (('owner', musl['caller_resources']), ('wrong_control', musl['wrong_implementation'])):
        build = row['native_build']
        names = origins.get(build['artifact'], [])
        check('musl_' + title + '_actual_binary_hash', bool(names) and all(name in native
              and members[name]['sha256'] == build['artifact_sha256'] and members[name]['bytes'] == build['artifact_bytes']
              for name in names))
        native_bindings.extend(names)

    ndu_root = ROOT / 'evidence/hia-specialization-01310b2'
    ndu = decode((ndu_root / 'native/RESULT.json').read_bytes())
    provenance = decode((ndu_root / 'PROVENANCE.json').read_bytes())
    check('ndu_013_is_not_relabelled_389', acceptance['ndu_frozen_experiment']['source_commit'] == ndu['source_commit'] == provenance['source_commit'] == NDU_SOURCE
          and NDU_SOURCE != SOURCE and acceptance['ndu_frozen_experiment']['actual_workload_profitability_established'] is False
          and acceptance['ndu_frozen_experiment']['incremental_value_established'] is False
          and acceptance['ndu_frozen_experiment']['publications'] == 0
          and acceptance['ndu_frozen_experiment']['episodes'] == 36)
    check('separate_ndu_result_matches_prior_provenance', sha(ndu_root / 'native/RESULT.json') == provenance['native_report_sha256'])
    for identifier, build in ndu['native_builds'].items():
        name = 'native/specialization/' + identifier + '.so'
        check('ndu_' + identifier + '_binary_matches_013_receipt', name in native
              and members[name]['sha256'] == build['artifact_sha256']
              and members[name]['bytes'] == build['artifact_bytes'])
        native_bindings.append(name)
    receipt = cached['native/specialization/ndu-build-inputs/build-receipt.json']
    bridge_hashes = [value for key, value in receipt.items() if key in {'binary_sha256', 'artifact_sha256'}]
    check('ndu_native_bridge_retained_with_receipt_hash', 'native/specialization/hia-ndu-bridge' in native
          and members['native/specialization/hia-ndu-bridge']['sha256'] in bridge_hashes)

    hosts = component['sections']['seven_native_hosts']
    check('seven_host_binary_scope_not_overclaimed', hosts['native_binaries_downloaded'] is False
          and hosts['independent_musl_cross_platform_execution'] is False
          and hosts['source_head'] == SOURCE and hosts['jobs'] == 7)
    bundle_checks = {}
    if bundle_data is not None:
        with tempfile.TemporaryDirectory(prefix='hia-package-bundle-audit-', dir=BASE) as directory:
            bundle = Path(directory) / 'development.bundle'
            bundle.write_bytes(bundle_data)
            for action in ('verify', 'list-heads'):
                process = subprocess.run(['git', 'bundle', action, str(bundle)], cwd=ROOT,
                                         text=True, capture_output=True)
                bundle_checks[action] = {'returncode': process.returncode,
                                          'stdout': process.stdout, 'stderr': process.stderr}
        check('development_git_bundle_verifies', bundle_checks['verify']['returncode'] == 0
              and bundle_checks['list-heads']['returncode'] == 0
              and manifest['development_source_bundle_requires'] == '817713b163b6812a6516179951412b4a6c93ae2b')
    else:
        check('development_git_bundle_verifies', False, 'missing bundle')

    def git(*args):
        return subprocess.check_output(['git', *args], cwd=ROOT).decode().splitlines()
    committed = git('diff', '--name-only', SOURCE, 'HEAD')
    tracked_changed = git('diff', '--name-only', SOURCE)
    untracked = git('ls-files', '--others', '--exclude-standard')
    check('repository_changes_are_evidence_only', all(name.startswith('evidence/') for name in
          set(committed + tracked_changed + untracked)))
    after = {path.name: sha(path) for path in PACKAGE.iterdir() if path.is_file()}
    check('original_audit_inputs_unchanged', before == after)

    # The xz file is a publication-container replacement. Recompute both full
    # decompressed TAR byte streams independently, including headers/padding;
    # equal streams bind all earlier per-member checks to the new container.
    final = ROOT / 'evidence/hia_resource_ndu_closure_20261028'
    final_manifest = decode((final / 'raw-evidence-manifest.json').read_bytes())
    final_acceptance = decode((final / 'acceptance.json').read_bytes())
    repack = decode((final / 'archive-repack.json').read_bytes())
    new_archive = final / 'raw-evidence.tar.xz'

    def stream_identity(opener, path):
        result, size = sha256(), 0
        with opener(path, 'rb') as stream:
            for chunk in iter(lambda: stream.read(1 << 20), b''):
                result.update(chunk)
                size += len(chunk)
        return {'sha256': result.hexdigest(), 'bytes': size}

    tar_gzip = stream_identity(gzip.open, archive)
    tar_xz = stream_identity(lzma.open, new_archive)
    check('xz_decompressed_tar_stream_is_identical_to_audited_gzip', tar_gzip == tar_xz
          and tar_xz == {'sha256': repack['tar_sha256'], 'bytes': repack['uncompressed_tar_bytes']}
          and tar_xz['sha256'] == '7055292623a01c91d1c7f70d399f693a2c0c2e5368ea26f999b0d07ad4da36c0')
    check('published_xz_file_matches_repack_receipt', sha(new_archive) == repack['output_sha256']
          == 'b9b271fa70326a95607c150cdd916942a412c5d3b6a7e56f1ea2d36f8240ee4e'
          and new_archive.stat().st_size == repack['output_bytes'] == 14182632
          and repack['input_sha256'] == expected_archive['sha256'])
    new_identity = {'name': 'raw-evidence.tar.xz', 'sha256': sha(new_archive),
                    'bytes': new_archive.stat().st_size, 'mode': new_archive.stat().st_mode & 0o7777}
    check('final_container_metadata_binds_actual_xz', final_manifest['archive'] == new_identity
          and final_acceptance['evidence_archive'] == new_identity
          and final_manifest['initial_assembly_archive'] == final_acceptance['initial_assembly_archive'] == expected_archive)
    stripped_manifest = {k: v for k, v in final_manifest.items()
                         if k not in {'archive_transport_repack', 'initial_assembly_archive', 'publication_parts'}}
    stripped_acceptance = {k: v for k, v in final_acceptance.items()
                           if k not in {'archive_transport_repack', 'initial_assembly_archive', 'publication_parts'}}
    stripped_manifest['archive'] = manifest['archive']
    stripped_acceptance['evidence_archive'] = acceptance['evidence_archive']
    check('repack_changes_only_declared_transport_fields', stripped_manifest == manifest
          and stripped_acceptance == acceptance
          and final_manifest['archive_transport_repack'] == final_acceptance['archive_transport_repack']
          and final_manifest['archive_transport_repack']['member_data_changed'] is False)
    check('original_gzip_metadata_retained_verbatim', sha(final / 'assembly-gzip/raw-evidence-manifest.json') == before['raw-evidence-manifest.json']
          and sha(final / 'assembly-gzip/acceptance.json') == before['acceptance.json'])
    check('qualification_and_audits_unchanged_by_transport', all(sha(final / name) == before[name]
          for name in ('qualification.json', 'full-audit.json', 'component-audit.json')))
    readme = (final / 'README.md').read_text()
    check('readme_uses_distinct_source_and_test_denominators', SOURCE in readme and TREE in readme
          and NDU_SOURCE in readme and '2,785' in readme and '57 tests' in readme
          and '67,558' in readme and '135,116' in readme and '810,696' in readme
          and '六个研发阶段尚未全部关闭' in readme)
    check('readme_retains_native_and_economic_scope_boundaries',
          '没有包含远程目标对象／可执行文件本体' in readme
          and '新增迁移实测只覆盖 Linux x86-64' in readme
          and '36/36 保留基线，0 次发布' in readme
          and '不能将新版结果覆写为同一次实验' in readme
          and '原始字节、摘要和拒绝记录经过独立核对' in readme)
    result = {'schema': 'hepta.hia.final-package-audit.v1', 'ok': all(checks.values()),
              'checked_at_utc': datetime.now(timezone.utc).isoformat(), 'checks': checks,
              'findings': findings, 'source_commit': SOURCE, 'source_tree': TREE,
              'container_audited': expected_archive, 'manifest_sha256': before['raw-evidence-manifest.json'],
              'published_container_independently_checked': new_identity,
              'decompressed_tar_stream_identity': tar_xz,
              'published_manifest_sha256': sha(final / 'raw-evidence-manifest.json'),
              'published_acceptance_sha256': sha(final / 'acceptance.json'),
              'repack_receipt_sha256': sha(final / 'archive-repack.json'),
              'readme_scope_review_sha256': sha(final / 'README.md'),
              'archive_member_count': len(members), 'uncompressed_member_bytes': total,
              'member_mode_counts': dict(Counter(oct(row['mode']) for row in members.values())),
              'native_artifacts': native, 'native_artifact_count': len(native),
              'native_elf_executable_or_shared_count': sum(row.get('elf_type') in {2, 3} for row in native.values()),
              'native_receipt_bindings_checked': native_bindings,
              'native_scope': {'local_and_selected_verified_CI_binaries': 'retained and rehashed',
                               'seven_native_host_matrix_binaries': 'not downloaded; reported actual process evidence only'},
              'full_python_methods': 2785, 'rust_tests': 57, 'full_gates': 6,
              'ndu_experiment_source_commit': NDU_SOURCE, 'ndu_experiment_relabelled_as_full_source': False,
              'six_stages_closed': False, 'source_bundle': bundle_checks,
              'repository_diff': {'committed_changed_files': len(committed),
                                  'all_tracked_changed_files': len(tracked_changed),
                                  'untracked_files': len(untracked), 'non_evidence_files': [name for name in
                                      set(committed + tracked_changed + untracked) if not name.startswith('evidence/')]},
              'input_snapshot': str(PACKAGE), 'input_sha256': before,
              'tests_or_benchmarks_executed_by_this_audit': False,
              'qualification_processes_reexecuted': False,
              'auditor_sha256': sha(Path(__file__)),
              'audit_development_record': {
                  'first_attempt': str(BASE / 'hia-next-final-package-audit-first-attempt.json'),
                  'issue': 'Auditor initially compared aggregate acceptance audit counts to dictionaries; corrected to rederived true-check counts 43 and 6. No package artifact changed for this correction.'},
              'publication_checksum_finalization_pending': True,
              'limits': ['Top-level final SHA256SUMS is intentionally pending root finalization after adding this audit and script; original six-file gzip checksum set was verified',
                         'Archive hashes establish retained artifact identity, not a new native execution or semantic proof']}
    REPORT.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({key: result[key] for key in ('ok', 'archive_member_count', 'uncompressed_member_bytes',
        'native_artifact_count', 'native_elf_executable_or_shared_count', 'findings')}, indent=2))
    return 0 if result['ok'] else 1


def finalize_parts():
    """Validate newly added transport parts without repeating the member audit."""
    prior = BASE / 'hia-next-final-package-audit-transport-transition.json'
    result = decode(prior.read_bytes())
    if set(row['check'] for row in result['findings']) != {'repack_changes_only_declared_transport_fields'}:
        raise ValueError('Unexpected prior member-audit failure; cannot finalize transport')
    if not all(passed for name, passed in result['checks'].items()
               if name != 'repack_changes_only_declared_transport_fields'):
        raise ValueError('Earlier member/native/stream audit was incomplete')
    final = ROOT / 'evidence/hia_resource_ndu_closure_20261028'
    manifest = decode((final / 'raw-evidence-manifest.json').read_bytes())
    acceptance = decode((final / 'acceptance.json').read_bytes())
    original_manifest = load('raw-evidence-manifest.json')
    original_acceptance = load('acceptance.json')
    checks = result['checks']
    findings = []

    def check(name, condition, details=None):
        checks[name] = bool(condition)
        if not condition:
            findings.append({'check': name, 'details': details})

    before = {name: sha(final / name) for name in ('raw-evidence-manifest.json', 'acceptance.json',
        'archive-repack.json', 'assemble_archive.py', 'README.md', 'qualification.json', 'full-audit.json', 'component-audit.json')}
    spec = manifest['publication_parts']
    check('published_parts_metadata_consistent', spec == acceptance['publication_parts']
          and [row['name'] for row in spec['ordered']] == ['raw-evidence.tar.xz.part01', 'raw-evidence.tar.xz.part02'])
    whole, count = sha256(), 0
    rows = []
    for row in spec['ordered']:
        name = row['name']
        if not safe_path(name) or '/' in name:
            raise ValueError('Unsafe published part path')
        content = (final / name).read_bytes()
        actual = {'name': name, 'bytes': len(content), 'sha256': sha256(content).hexdigest(),
                  'git_blob': sha1(b'blob ' + str(len(content)).encode() + b'\0' + content).hexdigest()}
        check('published_part_identity_' + name, actual == row)
        whole.update(content)
        count += len(content)
        rows.append(actual)
    logical = manifest['archive']
    check('parts_concatenate_to_exact_audited_xz', count == logical['bytes'] == spec['concatenation_bytes'] == 14182632
          and whole.hexdigest() == logical['sha256'] == spec['concatenation_sha256']
          == result['published_container_independently_checked']['sha256']
          == 'b9b271fa70326a95607c150cdd916942a412c5d3b6a7e56f1ea2d36f8240ee4e')
    check('parts_match_retained_complete_xz', sha(BASE / 'hia-next-raw-evidence.tar.xz') == whole.hexdigest())
    excluded = {'archive_transport_repack', 'initial_assembly_archive', 'publication_parts'}
    stripped_manifest = {key: value for key, value in manifest.items() if key not in excluded}
    stripped_acceptance = {key: value for key, value in acceptance.items() if key not in excluded}
    stripped_manifest['archive'] = original_manifest['archive']
    stripped_acceptance['evidence_archive'] = original_acceptance['evidence_archive']
    check('repack_changes_only_declared_transport_fields', stripped_manifest == original_manifest
          and stripped_acceptance == original_acceptance
          and manifest['initial_assembly_archive'] == acceptance['initial_assembly_archive'] == original_manifest['archive']
          and manifest['archive_transport_repack'] == acceptance['archive_transport_repack'])
    check('final_reports_remain_original_qualified_bytes', all(sha(final / name) == result['input_sha256'][name]
          for name in ('qualification.json', 'full-audit.json', 'component-audit.json')))
    check('original_gzip_metadata_still_retained', sha(final / 'assembly-gzip/raw-evidence-manifest.json') == result['input_sha256']['raw-evidence-manifest.json']
          and sha(final / 'assembly-gzip/acceptance.json') == result['input_sha256']['acceptance.json'])
    with tempfile.TemporaryDirectory(prefix='hia-archive-reassembly-audit-', dir=BASE) as directory:
        work = Path(directory)
        for name in ('raw-evidence-manifest.json', 'assemble_archive.py', *(row['name'] for row in rows)):
            (work / name).write_bytes((final / name).read_bytes())
        process = subprocess.run([sys.executable, str(work / 'assemble_archive.py')], cwd=work,
                                 text=True, capture_output=True)
        reassembly = {'returncode': process.returncode, 'stdout': process.stdout, 'stderr': process.stderr,
                      'executed_only_in_temporary_copy': True}
        check('published_reassembly_utility_restores_audited_container', process.returncode == 0
              and sha(work / logical['name']) == whole.hexdigest()
              and (work / logical['name']).stat().st_size == count)
    readme = (final / 'README.md').read_text()
    check('readme_has_actual_part_reassembly_instructions', all(value in readme for value in
          ('assemble_archive.py', 'raw-evidence.tar.xz.part01', 'raw-evidence.tar.xz.part02')))
    check('readme_final_scope_preserved', SOURCE in readme and NDU_SOURCE in readme and TREE in readme
          and '六个研发阶段尚未全部关闭' in readme
          and '没有包含远程目标对象／可执行文件本体' in readme
          and '新增迁移实测只覆盖 Linux x86-64' in readme)
    after = {name: sha(final / name) for name in before}
    check('final_metadata_unchanged_during_parts_audit', before == after)
    result.update(ok=all(checks.values()), findings=findings, checked_at_utc=datetime.now(timezone.utc).isoformat(),
                  publication_parts=rows,
                  prior_tar_member_and_stream_audit={'path': str(prior), 'sha256': sha(prior),
                      'new_part_metadata_arrived_during_that_audit': True,
                      'all_932_member_and_complete_gzip_xz_stream_checks_passed': True},
                  published_manifest_sha256=sha(final / 'raw-evidence-manifest.json'),
                  published_acceptance_sha256=sha(final / 'acceptance.json'),
                  readme_scope_review_sha256=sha(final / 'README.md'),
                  reassembly_utility=reassembly, reassembly_script_sha256=sha(final / 'assemble_archive.py'),
                  auditor_sha256=sha(Path(__file__)),
                  original_member_audit_reexecuted_for_transport_parts=False,
                  remote_upload_requeried_by_this_audit=False,
                  part_git_blob_identities_recomputed_locally=True)
    REPORT.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'ok': result['ok'], 'findings': findings, 'parts': rows,
                      'concatenation_sha256': whole.hexdigest(), 'concatenation_bytes': count,
                      'archive_members_reused_from_prior_audit': result['archive_member_count']}, indent=2))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(finalize_parts() if sys.argv[1:] == ['--finalize-parts'] else main())
