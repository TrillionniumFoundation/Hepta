"""Read-only audit of a fixed original CI ZIP; this does not rerun qualification."""
from __future__ import annotations
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import time
import traceback
import zipfile

BASE = Path('/tmp/hia-e26e-d2-ci-independent-review-r1')
OUT = BASE / 'audit-r1'
ARTIFACT = Path('/tmp/hia-e26e-d2-ci-artifact-13860171868.zip')
SOURCE_ZIP = Path('/workspace/scratch/hia-machine-encoder-native-20261111/source/experiments/hia_v66_integration_20261111/source-controls-r3/executed-source.zip')
PACKAGE_MANIFEST = Path('/workspace/scratch/hia-machine-encoder-native-20261111/source/experiments/hia_v66_desktop_development_20261111/source-package-r2/canonical-e09-development-package.json')
ARTIFACT_SHA = '63f7ddd6c0857956e10cb03823836bb284eb2142bd269a98d124c4b5bf086a56'
SOURCE_ZIP_SHA = '862c1cae8df60172296def6531dbfc28e10d30eb679f2a8bcab752cc038a59b8'
PACKAGE_MANIFEST_SHA = '7a45af0a08d837c3ecba97cd47b54e1a3eb8838c838d03a14a82d58df3e799af'
HEAD = 'd2c22d0c4caea145295a8213c6c718eb55546ec9'
TREE = '082ab925e16a1c89e2ada2ba9b6662e73dd60e00'
B3_SHA = '0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def git_blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()

def snapshot(path):
    s = path.lstat()
    assert stat.S_ISREG(s.st_mode) and not path.is_symlink()
    return (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)

def save(path, data):
    if not isinstance(data, bytes):
        data = (json.dumps(data, sort_keys=True, indent=2) + '\n').encode()
    with path.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    assert path.read_bytes() == data
    return {'path': str(path.relative_to(BASE)), 'bytes': len(data), 'sha256': sha(data), 'git_blob_sha1': git_blob(data)}

def file_sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()

def canonical_json_sha(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())

def main():
    started = time.monotonic_ns()
    OUT.mkdir(mode=0o700)
    report = {'schema': 'hia.ci-original-evidence-independent-audit.v1',
              'status': 'AUDIT_HOLD', 'original_workflow_status': 'FAILURE',
              'run_id': 43024566228, 'artifact_id': 13860171868,
              'head': HEAD, 'tree': TREE, 'whole_native_delivery_qualified': False,
              'product_tests_rerun': False, 'original_artifact_modified': False}
    try:
        before = {str(p): snapshot(p) for p in (ARTIFACT, SOURCE_ZIP, PACKAGE_MANIFEST)}
        assert ARTIFACT.stat().st_size == 111981819 and file_sha(ARTIFACT) == ARTIFACT_SHA
        assert SOURCE_ZIP.stat().st_size == 5809373 and file_sha(SOURCE_ZIP) == SOURCE_ZIP_SHA
        manifest_raw = PACKAGE_MANIFEST.read_bytes()
        assert sha(manifest_raw) == PACKAGE_MANIFEST_SHA
        package = json.loads(manifest_raw)
        assert package['canonical_commit'] == 'e09c6faf5507fc4e38d8b7c36ba2650a1c0a10d6'
        package_files = {r['path']: r for r in package['files']}
        canonical_commit = json.loads((BASE / 'canonical-d2-commit.json').read_bytes())
        canonical_tree = json.loads((BASE / 'canonical-d2-tree.json').read_bytes())
        assert canonical_commit['sha'] == HEAD and canonical_commit['tree']['sha'] == TREE
        assert canonical_tree['sha'] == TREE and canonical_tree['truncated'] is False
        git_files = {r['path']: r for r in canonical_tree['tree'] if r['type'] == 'blob'}
        with zipfile.ZipFile(ARTIFACT) as archive, zipfile.ZipFile(SOURCE_ZIP) as source:
            infos = archive.infolist()
            assert len(infos) == 5306 and len({i.filename for i in infos}) == len(infos)
            assert sum(i.file_size for i in infos) == 544910309
            outer = []
            for info in infos:
                name = PurePosixPath(info.filename)
                assert not name.is_absolute() and '..' not in name.parts and '\\' not in info.filename
                digest = hashlib.sha256()
                total = 0
                with archive.open(info) as stream:
                    while chunk := stream.read(1024 * 1024):
                        total += len(chunk)
                        digest.update(chunk)
                assert total == info.file_size
                outer.append({'path': info.filename, 'bytes': total, 'crc32': f'{info.CRC:08x}',
                              'sha256': digest.hexdigest(), 'mode': oct((info.external_attr >> 16) & 0o7777)})
            by_name = {r['path']: r for r in outer}
            outer_receipt = save(OUT / 'all-outer-members.json', {'crc_verified_by_full_read': True, 'files': outer})
            print(json.dumps({'stage': 'OUTER_CRC_AND_SHA_COMPLETE', 'members': len(outer)}), flush=True)
            cold_raw = archive.read('hia-cold.json')
            cold = json.loads(cold_raw)
            assert cold['status'] == 'COLD_SELFHOST_REPLAY_PASS' and len(cold['checks']) == 11
            assert all(v is True for v in cold['checks'].values())
            assert cold['qualification_wall_limit_seconds'] == 180 and cold['cleanup_wall_limit_seconds'] == 3
            assert cold['returncode'] == 0 and cold['wall_elapsed_ns'] == 139322747176
            assert cold['generation_sha256'] == [B3_SHA] * 3
            closure = cold['source_manifest']
            assert len(closure) == 662
            qualification_raw = archive.read('hia-cold.cold/qualification.json')
            assert sha(qualification_raw) == cold['nested_report_sha256']
            qualification = json.loads(qualification_raw)
            assert qualification['status'] == 'SELF_HOSTED_FIXED_CORE_PASS'
            assert len(qualification['checks']) == 5051 and all(v is True for v in qualification['checks'].values())
            assert qualification['source_manifest'] == closure
            owner_raw = archive.read('hia-cold.cold/process-owner.json')
            owner = json.loads(owner_raw)
            assert sha(owner_raw) == cold['process_owner']['receipt_sha256']
            assert owner['status'] == 'OWNED_PROCESS_COMPLETED' and owner['returncode'] == 0
            assert owner['qualification_seconds'] == 180 and owner['timed_out'] is False
            assert owner['event_overflow'] is False and owner['interrupted_signals'] == []
            assert owner['cleanup']['complete'] is True and owner['cleanup']['observed_echild'] is True
            assert owner['cleanup']['leader_reaped'] is True and owner['cleanup']['errors'] == []
            assert owner['cleanup']['remaining_direct_children'] == []
            assert not any(e['kind'] == 'owned_child_sigkill' for e in owner['events'])
            source_rows, differences = [], []
            assert len(source.infolist()) == 663 and len(set(source.namelist())) == 663
            assert set(source.namelist()) == set(closure) | {'experiments/hia_v66_integration_20261111/run-source-controls-r3.py'}
            assert source.testzip() is None
            for path, expected_sha in sorted(closure.items()):
                raw = source.read(path)
                assert sha(raw) == expected_sha and archive.read('hia-cold.cold/source/' + path) == raw
                git = git_files[path]
                mode = (source.getinfo(path).external_attr >> 16) & 0o777
                assert git_blob(raw) == git['sha'] and len(raw) == git['size']
                assert mode == (int(git['mode'], 8) & 0o777)
                row = {'path': path, 'bytes': len(raw), 'sha256': expected_sha, 'git_blob_sha1': git['sha'],
                       'canonical_git_mode': git['mode'], 'source_zip_mode': oct(mode),
                       'cold_export_mode': oct((archive.getinfo('hia-cold.cold/source/' + path).external_attr >> 16) & 0o777)}
                source_rows.append(row)
                if package_files[path]['sha256'] != expected_sha:
                    differences.append({'path': path, 'e09_sha256': package_files[path]['sha256'], 'd2_sha256': expected_sha,
                                        'e09_git_blob': package_files[path]['git_blob_sha1'], 'd2_git_blob': git['sha']})
            assert {r['path'] for r in differences} == {'docs/HIA_SELFHOST_CORE_SUPPORT.json', 'docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json'}
            source_receipt = save(OUT / 'all-source-bindings.json', {'canonical_commit': HEAD, 'canonical_tree': TREE,
                'source_manifest_canonical_sha256': canonical_json_sha(closure), 'members': source_rows, 'differences_from_e09': differences})
            helper = source.read('tools/hia_evidence_archive.py')
            assert sha(helper) == closure['tools/hia_evidence_archive.py']
            namespace = {'__name__': 'hia_original_archive_verifier'}
            exec(compile(helper, 'canonical-d2/tools/hia_evidence_archive.py', 'exec'), namespace)
            verify_archive = namespace['verify_archive']
            inner_names = sorted(n for n in by_name if n.startswith('hia-cold.cold/qualification.evidence/phase-runs/') and n.endswith('.zip'))
            assert len(inner_names) == 38
            phases = []
            total_inner_files = total_inner_bytes = 0
            for index, name in enumerate(inner_names):
                packed = archive.read(name)
                inner = verify_archive(io.BytesIO(packed))
                assert inner['schema'] == 'hepta.hia.lossless-evidence-archive.v1' and inner['native_or_correctness_authority'] is False
                phase = PurePosixPath(name).stem
                process_name = 'hia-cold.cold/qualification.evidence/phase-' + phase + '.process.json'
                phase_name = 'hia-cold.cold/qualification.evidence/phase-' + phase + '.json'
                proc = json.loads(archive.read(process_name))
                phase_raw = archive.read(phase_name)
                phase_report = json.loads(phase_raw)
                retained = proc['raw_artifacts']
                assert proc['returncode'] == 0 and phase_report['status'] == 'PASS'
                assert all(v is True for v in phase_report['checks'].values())
                assert proc['report_sha256'] == sha(phase_raw)
                assert retained['archive_sha256'] == sha(packed) and retained['packed_bytes'] == len(packed)
                assert retained['files'] == len(inner['files']) and retained['unpacked_bytes'] == inner['unpacked_bytes']
                assert retained['manifest_sha256'] == canonical_json_sha(inner)
                assert retained['every_original_byte_verified_before_retirement'] is True
                assert phase_report['source_manifest_sha256'] == canonical_json_sha(closure)
                total_inner_files += len(inner['files'])
                total_inner_bytes += inner['unpacked_bytes']
                phases.append({'phase': phase, 'archive': name, 'archive_bytes': len(packed), 'archive_sha256': sha(packed),
                    'manifest_sha256': canonical_json_sha(inner), 'members': len(inner['files']), 'decoded_bytes': inner['unpacked_bytes'],
                    'every_member_sha256_and_mode_verified': True, 'process_sha256': by_name[process_name]['sha256'],
                    'phase_report_sha256': sha(phase_raw), 'phase_checks': len(phase_report['checks']), 'phase_status': phase_report['status']})
                print(json.dumps({'stage': 'INNER_ARCHIVE_VERIFIED', 'completed': index + 1, 'phase': phase}), flush=True)
            phases_receipt = save(OUT / 'all-phase-archives.json', {'verifier_source_sha256': sha(helper), 'archives': phases,
                'archive_count': 38, 'member_count': total_inner_files, 'decoded_bytes': total_inner_bytes})
            b3 = archive.read('hia-cold.cold/qualification.evidence/B3.image.bin')
            assert len(b3) == 668608 and sha(b3) == B3_SHA
            manifests, builds = [], []
            for name in sorted(by_name):
                if not name.endswith('/manifest.json') or '/source/' in name or '/pinned-inputs/' in name:
                    continue
                m = json.loads(archive.read(name))
                if not all(k in m for k in ('compiler_sha256', 'image_path', 'image_sha256', 'source_sha256')):
                    continue
                assert m['compiler_sha256'] == B3_SHA, name
                relative = PurePosixPath(m['image_path'])
                assert not relative.is_absolute() and '..' not in relative.parts
                image_name = str(PurePosixPath(name).parent / relative)
                image = archive.read(image_name)
                assert sha(image) == m['image_sha256'], name
                source_paths = sorted(p for p, d in closure.items() if d == m['source_sha256'])
                assert source_paths, name
                manifests.append({'manifest': name, 'manifest_sha256': by_name[name]['sha256'], 'source_paths': source_paths,
                    'source_sha256': m['source_sha256'], 'compiler_sha256': B3_SHA, 'image': image_name,
                    'image_bytes': len(image), 'image_sha256': sha(image)})
            for directory, case in [('hia-machine-plan-callers-evidence/build', 'machine-plan'), ('hia-json-wire-callers-evidence/wire', 'json-wire')]:
                build_raw = archive.read(directory + '/build.json')
                build = json.loads(build_raw)
                m = json.loads(archive.read(directory + '/manifest.json'))
                receipt = json.loads(archive.read(directory + '/' + case + '.receipt.json'))
                request = json.loads(archive.read(directory + '/' + case + '.request.json'))
                input_raw = archive.read(directory + '/' + case + '.input.bin')
                output_raw = archive.read(directory + '/' + case + '.output.bin')
                image = archive.read(directory + '/' + m['image_path'])
                assert build['cold_report_sha256'] == sha(cold_raw) and build['source_manifest'] == closure
                assert build['manifest'] == m and build['native_compile_receipt'] == receipt
                assert request['image'] == '/home/runner/work/_temp/hia-cold.cold/qualification.evidence/B3.image.bin'
                assert request['image_sha256'] == receipt['image_sha256'] == receipt['artifact_sha256'] == B3_SHA
                assert request['source_sha256'] == receipt['input_sha256'] == receipt['source_sha256'] == sha(input_raw) == m['source_sha256']
                assert receipt['status'] == 'returned' and receipt['abi_status'] == 0 and receipt['forbidden_compiler_modules_loaded'] == []
                assert receipt['produced_bytes'] == receipt['result_u64'] == len(image)
                assert receipt['produced_sha256'] == sha(image) == m['image_sha256']
                assert receipt['output_sha256'] == sha(output_raw)
                builds.append({'directory': directory, 'build_sha256': sha(build_raw), 'cold_report_sha256': sha(cold_raw),
                    'source_manifest_exact_match': True, 'request_names_actual_cold_b3': True,
                    'actual_input_output_receipt_image_verified': True, 'manifest': m})
            builds_receipt = save(OUT / 'native-build-bindings.json', {'actual_cold_b3_bytes': len(b3), 'actual_cold_b3_sha256': sha(b3),
                'native_manifests': manifests, 'strict_retained_caller_builds': builds})
            native = json.loads(archive.read('hia-native-components.json'))
            plan = json.loads(archive.read('hia-machine-plan-callers.json'))
            wire = json.loads(archive.read('hia-json-wire-callers.json'))
            journal = json.loads(archive.read('hia-journal-callers.json'))
            assert native['status'] == 'PASS' and native['tests_run'] == 67
            assert native['loaded_test_ids'] == native['executed_test_ids'] and len(native['loaded_test_ids']) == 67
            assert all(not v for v in native['anomalies'].values())
            assert plan['status'] == 'PASS' and plan['tests_run'] == plan['tests_loaded'] == 44
            assert plan['loaded_test_ids'] == plan['executed_test_ids']
            for report_ in (plan, wire, journal):
                assert not report_['errors'] and not report_['skipped'] and not report_['expected_failures'] and not report_['unexpected_successes']
            assert wire['status'] == 'FAIL_OR_INCOMPLETE' and wire['tests_run'] == wire['tests_loaded'] == wire['tests_chosen'] == 89
            assert wire['loaded_test_ids'] == wire['chosen_test_ids'] == wire['executed_test_ids']
            assert len(wire['failures']) == 1 and not wire['explicit_development_exclusions']
            assert wire['failures'][0]['test'] == 'tests.test_hia_agent_native_tools.NativeLifecycleTests.test_native_timeout_is_incomplete_terminated_and_not_adoptable'
            assert '7.074126838999746 not less than 5' in wire['failures'][0]['trace']
            assert wire['all_eleven_agent_tools_entered_selected_wire'] is True and len(wire['agent_tools_with_native_wire']) == 11
            assert wire['ordinary_wire_calls'] == 77319 and wire['actual_native_step_returns']['1'] == 17221711
            assert journal['status'] == 'PASS' and journal['tests_run'] == journal['tests_loaded'] == journal['tests_chosen'] == 94
            assert journal['loaded_test_ids'] == journal['chosen_test_ids'] == journal['executed_test_ids'] and not journal['failures']
            originals = []
            for name in ['hia-cold.json', 'hia-native-components.json', 'hia-machine-plan-callers.json', 'hia-json-wire-callers.json', 'hia-journal-callers.json', 'hia-language.assertions.json']:
                originals.append(save(OUT / name, archive.read(name)))
            report.update(status='ORIGINAL_EVIDENCE_INTEGRITY_VERIFIED',
                original_artifact={'path': str(ARTIFACT), 'bytes': ARTIFACT.stat().st_size, 'sha256': ARTIFACT_SHA,
                    'members': 5306, 'decoded_bytes': 544910309, 'all_member_crc_verified': True, 'member_sha_inventory': outer_receipt},
                source_binding={'members': 662, 'all_bytes_size_git_blob_and_mode_match_d2_tree': True,
                    'cold_export_matches_executed_source_zip': True, 'source_zip_sha256': SOURCE_ZIP_SHA,
                    'differences_from_e09': differences, 'evidence': source_receipt},
                phase_archives={'count': 38, 'all_crc_sha256_modes_and_retention_receipts_match': True,
                    'decoded_members': total_inner_files, 'decoded_bytes': total_inner_bytes, 'evidence': phases_receipt},
                cold={'status': cold['status'], 'wall_elapsed_ns': cold['wall_elapsed_ns'], 'limit_seconds': 180,
                    'checks_passed': 11, 'nested_checks_passed': 5051, 'nested_report_sha256': sha(qualification_raw),
                    'cold_report_sha256': sha(cold_raw), 'natural_owner_cleanup': True, 'source_manifest_canonical_sha256': canonical_json_sha(closure)},
                native_build_binding=builds_receipt,
                reported_results={'native_component_tests': 67, 'machine_plan_callers': 44, 'journal_callers': 94,
                    'ordinary_wire_tests_run': 89, 'ordinary_wire_status': wire['status'], 'ordinary_wire_failures': wire['failures'],
                    'ordinary_wire_calls': wire['ordinary_wire_calls'], 'ordinary_wire_status1_returns': wire['actual_native_step_returns']['1'],
                    'all_11_tools_entered': True, 'python': wire['python']},
                compact_original_reports=originals)
        assert before == {str(p): snapshot(p) for p in (ARTIFACT, SOURCE_ZIP, PACKAGE_MANIFEST)}
        report['input_file_identities_unchanged'] = True
        report['audit_elapsed_ns'] = time.monotonic_ns() - started
        save(OUT / 'AUDIT.json', report)
        print(json.dumps({'status': report['status'], 'original_workflow_status': report['original_workflow_status'],
            'outer_members': 5306, 'inner_archives': 38, 'inner_members': total_inner_files,
            'inner_decoded_bytes': total_inner_bytes, 'native_manifests': len(manifests), 'elapsed_ns': report['audit_elapsed_ns']}), flush=True)
    except BaseException as exc:
        report.update(error_type=type(exc).__name__, error=str(exc), traceback=traceback.format_exc(), elapsed_ns=time.monotonic_ns()-started)
        save(OUT / 'AUDIT-HOLD.json', report)
        raise

if __name__ == '__main__':
    main()
