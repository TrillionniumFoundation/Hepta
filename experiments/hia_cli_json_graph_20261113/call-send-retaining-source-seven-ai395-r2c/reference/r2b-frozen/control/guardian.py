"""External Linux guardian for a pinned qualification workflow.

Reuses the frozen lifecycle implementation's supervise() function directly,
with a distinct schema and an external controller deadline. Its run_owned()
entry and its fixed 180-second cold-qualification gate are never changed or
called here. This controller is hosted evidence machinery, not HIA runtime.

The subreaper owns the initial preparation child and adopted descendants across
exec and setsid. SIGINT, SIGTERM, ordinary owner exceptions and the controller
deadline lead to bounded kill/reap cleanup and HOLD. Hard SIGKILL of this
guardian, host loss, hostile process namespaces and privileged interference
remain outside that cleanup claim.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import importlib.util
import json
import math
import os
from pathlib import Path
import stat
import sys
import time

SCHEMA = 'hepta.hia.external-qualification-guardian.v1'
MAX_CONTROLLER_SECONDS = 10800
EXPECTED_IMPL_SHA256 = '36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def private_directory(path):
    item = Path(path).lstat()
    require(stat.S_ISDIR(item.st_mode) and item.st_uid == os.geteuid()
            and stat.S_IMODE(item.st_mode) == 0o700,
            'guardian requires its existing private directory')


def load_owner(path):
    require(digest(path) == EXPECTED_IMPL_SHA256, 'frozen lifecycle implementation changed')
    spec = importlib.util.spec_from_file_location('external_guardian_lifecycle', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Only this disposable imported module has the external receipt schema.
    # The original file, its constants, and all cold subprocesses are untouched.
    module.SCHEMA = SCHEMA + '.lifecycle'
    return module


def verify_qualification(config):
    expected = config.get('expected_qualification')
    if expected is None:
        return None
    path = Path(expected['path'])
    raw = path.read_bytes()
    value = json.loads(raw)
    require(value.get('schema') == 'hepta.hia.native-rewrite-qualification.v5'
            and value.get('status') == 'FULL_RETAINED_PASS'
            and value.get('cold_qualified') is True
            and value.get('source_preserved') is True
            and value.get('harness_preserved') is True
            and value.get('full_retained_regression_requested') is True
            and value.get('full_retained_regression_executed') is True
            and value.get('full_retained_regression_qualified') is True,
            'unchanged v5 runner did not qualify the complete retained suite')
    source = value.get('source_identity', {})
    require(source.get('head') == expected['head'] and source.get('tree') == expected['tree']
            and source.get('raw_git_tree_blobs_and_modes_checked') is True,
            'qualified complete Git identity differs from the published pin')
    cold = value.get('cold_source_manifest', {})
    require(len(cold) == expected['cold_source_count']
            and cold.get('docs/HIA_SELFHOST_CORE_SUPPORT.json') == expected['contract_sha256'],
            'qualified cold closure differs from the frozen contract')
    full = value.get('full_retained_regression', {})
    require(full.get('passed') is True and full.get('completed') is True
            and full.get('discovery') is True
            and type(full.get('tests_run')) is int and full['tests_run'] > 0,
            'complete retained discovery outcome is missing')
    return {'path': str(path), 'sha256': sha256(raw).hexdigest(),
            'head': source['head'], 'tree': source['tree'],
            'tests_run': full['tests_run'], 'status': value['status']}


def execute(config, control, implementation):
    """Must run in a fresh single-threaded process; never in the test caller."""
    private_directory(control)
    seconds = config['controller_seconds']
    require(type(seconds) in (int, float) and math.isfinite(seconds)
            and 0 < seconds <= MAX_CONTROLLER_SECONDS and int(seconds * 1e9) > 0,
            'external controller deadline is outside its bound')
    command = config['command']
    require(type(command) is list and command
            and all(type(item) is str and item and '\0' not in item for item in command),
            'explicit shell-free command is required')
    cwd = Path(config['cwd'])
    require(cwd.is_absolute() and cwd.is_dir(), 'absolute existing child cwd is required')
    identities = config['source_identities']
    require(type(identities) is dict and identities
            and identities.get(str(Path(implementation).resolve())) == EXPECTED_IMPL_SHA256
            and identities.get(str(Path(__file__).resolve())) == digest(__file__),
            'guardian and frozen lifecycle identities must be present')
    for path, expected in identities.items():
        require(Path(path).is_absolute() and digest(path) == expected,
                'guardian input differs before launch: ' + path)
    owner = load_owner(implementation)
    stdout = control / 'child.stdout.log'
    stderr = control / 'child.stderr.log'
    receipt = control / 'guardian.json'
    require(not any(os.path.lexists(path) for path in (stdout, stderr, receipt)),
            'create-only guardian evidence already exists; reconcile the original job')
    owner.create(stdout, b'')
    owner.create(stderr, b'')
    environment = dict(os.environ)
    environment.update(PYTHONDONTWRITEBYTECODE='1', PYTHONUNBUFFERED='1')
    started = time.monotonic_ns()
    request = {'command': command, 'cwd': str(cwd), 'env': environment,
               'stdout_path': str(stdout), 'stderr_path': str(stderr),
               'parent_pid': os.getppid(), 'started_ns': started,
               'deadline_ns': started + int(seconds * 1e9),
               'qualification_seconds': seconds,
               'cleanup_seconds': owner.CLEANUP_SECONDS}
    print(json.dumps({'stage': 'external_guardian_starting', 'supervisor_pid': os.getpid(),
                      'controller_seconds': seconds, 'child_stdout': str(stdout),
                      'receipt': str(receipt)}), flush=True)
    # The implementation installs SIGTERM/SIGINT handlers before configuring
    # subreaping, catches BaseException, and always executes identity-bound
    # adopted-child cleanup followed by kernel waitid ECHILD.
    lifecycle = owner.supervise(request)
    # A current-bound, fully closed owner is the sole authority for reading
    # child bodies or source-after bytes. A failed qualification may still
    # have proven cleanup; an unknown cleanup never permits these reads.
    cleanup = lifecycle.get('cleanup') if type(lifecycle) is dict else None
    body_reads_permitted = (
        type(lifecycle) is dict and type(cleanup) is dict
        and lifecycle.get('schema') == SCHEMA + '.lifecycle'
        and lifecycle.get('supervisor_pid') == os.getpid()
        and lifecycle.get('parent_pid') == request['parent_pid']
        and lifecycle.get('qualification_seconds') == request['qualification_seconds']
        and lifecycle.get('cleanup_seconds') == request['cleanup_seconds']
        and lifecycle.get('subreaper_enabled') is True
        and cleanup.get('complete') is True
        and cleanup.get('observed_echild') is True
        and cleanup.get('leader_reaped') is True
        and cleanup.get('remaining_direct_children') == []
        and cleanup.get('errors') == []
        and cleanup.get('deadline_exceeded') is False)
    result = {'schema': SCHEMA, 'status': 'HOLD', 'command': command, 'cwd': str(cwd),
              'external_controller_seconds': seconds,
              'cold_180_second_gate_modified': False,
              'lifecycle_implementation_sha256': EXPECTED_IMPL_SHA256,
              'lifecycle_entry': 'supervise; distinct external schema and deadline',
              'lifecycle': lifecycle,
              'source_identities_before': identities,
              'source_identities_after': None, 'input_identity_preserved': False,
              'post_owner_body_reads': {
                  'permitted': body_reads_permitted,
                  'source_after': 'UNREAD',
                  'child_logs': 'UNREAD',
                  'reason': ('BOUND_OWNER_CLOSED' if body_reads_permitted
                             else 'UNREAD_UNCONFIRMED_OWNER')},
              'qualification': None,
              'hard_sigkill_or_host_loss_cleanup_claimed': False,
              'hostile_process_namespaces_or_privileged_interference_covered': False,
              'whole_native_delivery_qualified': False}
    try:
        require(body_reads_permitted,
                'current-bound owner closure unconfirmed; child bodies and source-after remain UNREAD')
        after = {path: digest(path) for path in identities}
        result['post_owner_body_reads']['source_after'] = 'READ_COMPLETE'
        result['source_identities_after'] = after
        result['input_identity_preserved'] = after == identities
        require(result['input_identity_preserved'], 'guardian inputs changed during execution')
        require(lifecycle.get('status') == 'OWNED_PROCESS_COMPLETED'
                and lifecycle.get('returncode') == 0
                and lifecycle.get('exit_observed_before_deadline') is True
                and lifecycle.get('timed_out') is False
                and not lifecycle.get('interrupted_signals')
                and not lifecycle.get('owner_error')
                and lifecycle.get('cleanup', {}).get('complete') is True
                and lifecycle['cleanup'].get('observed_echild') is True
                and lifecycle['cleanup'].get('leader_reaped') is True,
                'external owned workflow was interrupted, failed, timed out, or not fully reaped')
        result['qualification'] = verify_qualification(config)
        result['status'] = ('GUARDIAN_FULL_RETAINED_PASS' if result['qualification'] is not None
                            else 'EXTERNAL_OWNED_PROCESS_COMPLETED')
    except BaseException as error:
        result['classification_error'] = type(error).__name__ + ': ' + str(error)[:512]
    if body_reads_permitted:
        try:
            result['logs'] = {str(path): digest(path) for path in (stdout, stderr)}
            result['post_owner_body_reads']['child_logs'] = 'READ_COMPLETE'
        except BaseException as error:
            result['status'] = 'HOLD'
            result['logs'] = {'status': 'CLOSED_OWNER_LOG_READ_FAILED',
                              'paths': [str(stdout), str(stderr)]}
            result['post_owner_body_reads']['child_logs'] = 'READ_FAILED'
            result['log_read_error'] = type(error).__name__ + ': ' + str(error)[:512]
    else:
        # Fixed path names are metadata only. Do not open, stat, enumerate,
        # or hash either child output when descendant closure is unknown.
        result['logs'] = {'status': 'UNREAD_UNCONFIRMED_OWNER',
                          'paths': [str(stdout), str(stderr)]}
    owner.create(receipt, owner.wire(result))
    print(json.dumps({'stage': 'external_guardian_finished', 'status': result['status'],
                      'lifecycle_status': lifecycle.get('status'),
                      'cleanup_complete': lifecycle.get('cleanup', {}).get('complete'),
                      'observed_echild': lifecycle.get('cleanup', {}).get('observed_echild'),
                      'receipt': str(receipt)}), flush=True)
    return 0 if result['status'] in ('EXTERNAL_OWNED_PROCESS_COMPLETED',
                                    'GUARDIAN_FULL_RETAINED_PASS') else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--config-sha256', required=True)
    parser.add_argument('--implementation', type=Path, required=True)
    args = parser.parse_args()
    raw = args.config.read_bytes()
    require(len(raw) <= 262144 and sha256(raw).hexdigest() == args.config_sha256,
            'external guardian request identity differs')
    config = json.loads(raw)
    require(config.get('schema') == 'hia-external-guardian-request.v1',
            'unexpected external guardian request schema')
    return execute(config, args.config.parent, args.implementation)


if __name__ == '__main__':
    raise SystemExit(main())
