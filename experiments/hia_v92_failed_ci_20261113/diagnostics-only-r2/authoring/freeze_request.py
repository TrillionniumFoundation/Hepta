"""Freeze source-only validation and new remote diagnostic custody requests.

This utility reads source/runtime bytes, writes metadata, and never imports a
test, starts an owner, contacts GitHub, or opens an artifact.
"""
from hashlib import sha256, sha1
from pathlib import Path
import ast
import json
import os
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'experiments/hia_v92_failed_ci_20261113/diagnostics-only-r2'
PARENT = '2924975f3849ea86a5294fa2d6c5fb7cde723567'


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def pin(path, *, role):
    path = Path(path)
    st = path.lstat()
    raw = path.read_bytes()
    assert path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode)
    assert identity(st) == identity(path.lstat()) and len(raw) == st.st_size
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'identity': identity(st), 'role': role}


def save(name, value):
    raw = wire(value)
    path = ROOT / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'wb') as output:
        os.fchmod(output.fileno(), 0o400)
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    assert path.read_bytes() == raw
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'git_blob': sha1(b'blob ' + str(len(raw)).encode() + bytes([0]) + raw).hexdigest()}


def main():
    source_inputs = sorted(path for folder in ('candidate', 'reference', 'controls')
                           for path in (ROOT / folder).rglob('*') if path.is_file())
    source_inputs += [ROOT / 'SOURCE-DELTA.patch', ROOT / 'SOURCE-PINS.json', ROOT / 'MECHANICAL-PROJECTION.json']
    parsed = []
    for path in source_inputs:
        assert not path.is_symlink()
        if path.suffix == '.py':
            ast.parse(path.read_bytes(), filename=str(path))
            parsed.append(str(path.relative_to(ROOT)))
        os.chmod(path, 0o400)
    tree = ast.parse((ROOT / 'controls/check_diagnostics.py').read_bytes())
    methods = [n.name for c in tree.body if isinstance(c, ast.ClassDef)
               and c.name == 'DiagnosticCustodySourceIOTests'
               for n in c.body if isinstance(n, ast.FunctionDef) and n.name.startswith('test_')]
    expected = ['DiagnosticCustodySourceIOTests.' + name for name in methods]
    literal_names = next(ast.literal_eval(n.value.generators[0].iter) for n in tree.body
                         if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'EXPECTED_IDS' for t in n.targets))
    assert methods == list(literal_names) and len(methods) == len(set(methods)) == 12
    output = Path('/home/agent/hia-v92-diagnostics-only-source12-r2-output-20261113-e26e')
    assert not os.path.lexists(output)
    runtime = Path(sys.executable).resolve(strict=True)
    inputs = [pin(path, role='frozen_source_or_reference') for path in source_inputs]
    inputs.append(pin(runtime, role='exact_runtime'))
    request = {
        'schema': 'hia.v92.diagnostic-relocation.source12-request.v1',
        'status': 'FROZEN_SOURCE_IO_REQUEST_UNEXECUTED',
        'runtime': {'executable': str(runtime), 'version': sys.version, 'version_info': list(sys.version_info)},
        'output_root': str(output), 'qualification_seconds': 20, 'cleanup_seconds': 3,
        'minimum_free_bytes': 128 << 20, 'minimum_free_inodes': 4096,
        'maximum_output_bytes': 64 << 20, 'maximum_output_files_and_directories': 4096,
        'tests_path': str(ROOT / 'controls/check_diagnostics.py'),
        'worker_path': str(ROOT / 'controls/source_worker.py'),
        'owner_path': str(ROOT / 'candidate/process_owner_impl.py'),
        'expected_ids': expected, 'inputs': inputs,
        'environment': {'PATH': '', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
                        'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONUNBUFFERED': '1', 'PYTHONHASHSEED': '0'},
        'network_and_process_effects_in_source_child': 'FORBIDDEN_BY_AUDIT_AND_POPEN_POISON',
        'real_project_or_product_code_imported': False,
        'real_artifact_or_provider_reference_opened': False,
        'synthetic_fixture': {'selected_originals': 460, 'selected_bytes': 3012789,
            'metadata_files': 3, 'missing_expected_originals': 5,
            'not_the_historical_ZIP': True, 'nonselected_bodies_also_read': True},
        'historical_R4_owner_status': 'UNKNOWN_NOT_RECLASSIFIED',
        'root_authorization_required_before_owner_execution': True,
    }
    source_pin = save('CONTROL-REQUEST.json', request)
    launch = {'schema': 'hia.v92.diagnostic-source12.launch.v1', 'status': 'UNEXECUTED',
              'command': [str(runtime), '-I', '-S', '-B', str(ROOT / 'controls/source_launch.py'),
                          '--request', source_pin['path'], '--request-sha256', source_pin['sha256']],
              'cwd': str(ROOT), 'environment': request['environment'],
              'request': source_pin, 'output_root': str(output),
              'network': False, 'product': False, 'automatic_retry': False}
    launch_pin = save('CONTROL-LAUNCH.json', launch)
    policy_raw = (ROOT / 'candidate/policy.json').read_bytes()
    policy = json.loads(policy_raw)
    remote = {
        'schema': 'hia.v92.failed-ci.diagnostics-only-request.v2',
        'status': 'FROZEN_SOURCE_REVIEW_REQUIRED_NOT_TRIGGERED', 'repository': policy['repository'],
        'control_prefix': PREFIX, 'publication_parent': PARENT,
        'trigger_branch': policy['trigger_branch'], 'event': 'create', 'attempt': 1,
        'original_artifact': policy['artifact'], 'original_source': policy['source'],
        'policy': {'bytes': len(policy_raw), 'sha256': sha256(policy_raw).hexdigest()},
        'control_files': policy['control_files'], 'expected_diagnostics': policy['expected_diagnostics'],
        'limits_unchanged_from_original_recovery': policy['limits'],
        'diagnostic_limits_unchanged': policy['diagnostics'],
        'single_original_storage_GET': 1, 'official_API_GETs': 2,
        'storage_GET_redirects': 0, 'retries': 0,
        'configured_proxy_and_CA_environment_preserved': True,
        'token_or_signed_URL_in_public_evidence': False,
        'whole_original_ZIP_body_CRC_SHA_read': True,
        'original_ZIP_preserved_privately': True,
        'partial_original_ZIP_bytes_preserved_privately_on_failure': True,
        'original_ZIP_copy_uploaded': False, 'partition_files_created': 0,
        'public_artifacts': [{'name': 'hia-v92-step42-diagnostics-only-r2-RUN_ID-1',
            'root': policy['public_root_name'] + '/small', 'maximum_bytes': 224 << 20,
            'originals': 'all 460 selected bodies plus the original 3 metadata files',
            'control_originals': 11, 'derived_control_receipts': ['SMALL-READBACK.json', 'FINAL.json'],
            'partial_capture_must_remain_HOLD': True}],
        'owner': {'guardian_sha256': policy['control_files']['guardian.py']['sha256'],
                  'implementation_sha256': policy['control_files']['process_owner_impl.py']['sha256'],
                  'wall_seconds': 900, 'cleanup_seconds': 3, 'worker_transfer_seconds': 720},
        'workflow_step_timeouts_minutes': {'prepare': 5, 'owned_collection': 16, 'closed_finalization': 5},
        'finalization_is_separate_post_ECHILD_custody_not_a_900_second_product_qualification': True,
        'original_remote_recovery': {'run': 43338002642, 'status': 'HOLD',
            'cause': 'diagnostics/463 fixed files were passed to a parts-only relocation helper',
            'actual_canonical': 'b32b3e5ff65e8161cd705c3e90724559c7aa04a8'},
        'old_local_R4': {'request_commit': '0b5bf069d8a1c6509cf1421897553bbf99efce72',
                         'owner_status': 'UNKNOWN', 'replayed': False, 'resolved_by_this_request': False},
        'source_controls': {'request': source_pin, 'launch': launch_pin, 'count': 12,
            'status': 'UNEXECUTED', 'actual_required_before_remote_trigger': True,
            'not_inherited_from_old_20_or_8_controls': True},
        'no_product_CI_native_or_supplier_execution': True,
        'Root_sole_remote_trigger': True,
    }
    remote_pin = save('REQUEST.json', remote)
    preexec = {'schema': 'hia.v92.diagnostics-only.preexecution.v2',
               'status': 'AST_AND_SOURCE_PROJECTION_ONLY', 'source_tests_executed': 0,
               'network_requests': 0, 'owner_started': False, 'remote_triggered': False,
               'old_R4_status': 'UNKNOWN', 'parsed_files': parsed, 'expected_ids': expected,
               'source_request': source_pin, 'source_launch': launch_pin, 'remote_request': remote_pin,
               'frozen_sources': len(source_inputs),
               'original_4_file_fullbyte_preservation': ['diagnostics.py', 'guardian.py',
                                                      'original_receiver.py', 'process_owner_impl.py'],
               'mechanical_proof': pin(ROOT / 'MECHANICAL-PROJECTION.json', role='static_proof')}
    save('PREEXEC.json', preexec)
    print(json.dumps({'source_request': source_pin, 'source_launch': launch_pin,
                      'remote_request': remote_pin, 'inputs': len(inputs), 'expected': len(expected),
                      'source_controls_executed': 0, 'product_executed': False}))


if __name__ == '__main__':
    main()
