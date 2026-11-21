"""Assemble a relocatable, explicitly selected HIA worker release.

The selected process still uses the installed Python custody/service bridge.
Only the program images and policy manifests are deployed by this command.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import errno
from functools import partial
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import struct
from tempfile import TemporaryDirectory

from hepta import hia_native_helpers as authority
from hepta.hia_json_preflight_native import _source_resource_path
from hepta.hia_worker_scheduling_bundle import FAMILIES
from tools.bind_hia_worker_store import bind_worker_store
from tools.build_hia_agent_binary64 import build as build_binary64
from tools.build_hia_agent_binary64_format import build as build_binary64_format
from tools.build_hia_cost_ledger import build as build_cost_ledger
from tools.build_hia_agent_data_json import build as build_agent_data_json
from tools.build_hia_direct_call import build as build_direct_call
from tools.build_hia_evaluation import build as build_evaluation
from tools.build_hia_agent_read_page import build as build_agent_stdio
from tools.build_hia_json_preflight import build_batch as build_helper_batch
from tools.build_hia_native_build_admission import build as build_build_admission
from tools.build_hia_native_continuation import build as build_scheduler
from tools.build_hia_release_install import build as build_installer
from tools.build_hia_scalar_reference_cli import build as build_reference_executable
from tools.build_hia_owned_reference_cli import build as build_owned_reference_executable
from tools.build_hia_sha256 import build as build_sha256
from tools.build_hia_service_context import build as build_service_context
from tools.build_hia_slot_ledger import build as build_slot_ledger
from tools.build_hia_worker_report import bind_worker_bundle, build as build_report
from tools.build_hia_worker_scheduling_bundle import bind_scheduling_bundle


INSTALLED_HELPERS = (
    'agent-schema', 'agent-response-schema', 'agent-verify-response-schema',
    'agent-discovery', 'agent-inspection', 'agent-identity', 'elf-shared-linker', 'scalar-reference',
)
ADDITIONAL_HELPERS = (
    'worker-request', 'agent-journal', 'execution-budget', 'candidate-budget',
    'agent-read-page', 'slot-ledger', 'execution-ledger', 'scalar-symbolic',
    'sha256-stream', 'cnf',
    'agent-data-json', 'agent-binary64', 'agent-binary64-format',
    'agent-describe-answer', 'agent-payload-schema', 'agent-plan-schema', 'machine-plan',
    'safe-core-x64-decode', 'safe-core-elf-inventory', 'elf-verified-linker', 'service-context', 'cost-ledger', 'evaluation',
    'native-build-admission', 'agent-store-transport',
)
HELPER_BUILDERS = {
    'slot-ledger': build_slot_ledger,
    'sha256-stream': partial(build_sha256, candidate='sha256_stream'),
    'agent-data-json': build_agent_data_json,
    'agent-binary64': build_binary64,
    'agent-binary64-format': build_binary64_format,
    'service-context': build_service_context,
    'cost-ledger': build_cost_ledger,
    'evaluation': build_evaluation,
    'native-build-admission': build_build_admission,
}


CONTROLLER_MANIFEST = 'hia-controller.json'
CONTROLLER_JOB_RECEIPT = 'hia-job-receipt'
CONTROLLER_FILES = (
    'HIA_AGENT_NATIVE_TOOL_CATALOG.json', 'hia-worker-prepare',
    'hia-agent-mcp-request', 'hia-agent-mcp-reply', 'hia-agent-mcp-terminal',
    'hia-agent-mcp-negotiation', 'hia-agent-mcp-catalog', 'hia-agent-mcp-uri',
    'hia-agent-mcp-input-schema', 'hia-agent-mcp-response-schema', 'hia-agent-mcp-proof-schema',
)


def _copy_runtime_file(source, destination):
    # The build tree may contain source, proof logs and tool intermediates.
    # Only the explicitly referenced immutable runtime files are reproduced.
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with destination.open('xb') as output:
        output.write(source.read_bytes())
    destination.chmod(0o400)
    return destination


def _copy_image_manifest(source, destination):
    image = json.loads(source.read_bytes())['image_path']
    if Path(image).name != image:
        raise ValueError('a release image manifest must name one adjacent image')
    _copy_runtime_file(source.parent / image, destination.parent / image)
    return _copy_runtime_file(source, destination)


def _copy_report(source, destination):
    for name in ('policy', 'wire'):
        child = name + '/manifest.json'
        _copy_image_manifest(source.parent / child, destination / child)
    return _copy_runtime_file(source, destination / 'manifest.json')


def _copy_scheduler(source, destination):
    policy = source.parent / 'policy/manifest.json'
    for name in json.loads(policy.read_bytes())['unit_manifests']:
        child = 'policy/' + name + '/manifest.json'
        _copy_image_manifest(source.parent / child, destination / child)
    _copy_runtime_file(policy, destination / 'policy/manifest.json')
    return _copy_image_manifest(source, destination / 'inprocess-manifest.json')


def _worker_prepare_has_terminal_witness(prepare):
    # v1/v2 deployments are admitted only to their old roles. Recognize the
    # complete v3 protocol by an exact acceptance and a tamper refusal.
    identity = b'controller-package-probe'
    nonce = b'0123456789abcdef' * 2
    raw = b'{"exit_code":0}'
    header = struct.Struct('<8s11Q')
    for decision, digest in ((0, sha256(raw).hexdigest().encode('ascii')), (3, b'0' * 64)):
        fields = (identity, identity, identity, nonce, nonce, nonce, digest, raw)
        frame = header.pack(b'HIAJWC01', 1, 1, 1, *map(len, fields)) + b''.join(fields)
        result = subprocess.run([prepare], input=frame, env={'PATH': ''}, capture_output=True, timeout=5)
        if decision == 0 and (result.returncode, result.stdout, result.stderr) == (2, b'', b''):
            return False
        expected = struct.pack('<8sQ', b'HIAJWR01', decision)
        if (result.returncode, result.stdout, result.stderr) != (0, expected, b''):
            raise ValueError('installed HIA worker preparation has an invalid terminal witness protocol')
    return True


def _worker_prepare_has_live_owner_binding(prepare):
    job = b'controller-owner-probe'
    fields = (job,) + (b'',) * 12
    frame = struct.pack('<8s17Q', b'HIAJOQ01', 0, 1, 0, 1, *map(len, fields)) + job
    result = subprocess.run([prepare], input=frame, env={'PATH': ''}, capture_output=True, timeout=5)
    observed = result.returncode, result.stdout, result.stderr
    if observed == (2, b'', b''):
        return False
    if observed != (0, struct.pack('<8s3Q', b'HIAJOR01', 0, 0, 2), b''):
        raise ValueError('installed HIA worker preparation has an invalid live owner binding protocol')
    return True


def _worker_prepare_has_witness_publisher(prepare):
    job, nonce, raw = b'controller-publisher-probe', b'0' * 32, b'{}\n'
    frame = struct.pack('<8sQ32s', b'HIAJWE01', len(job), nonce) + job + raw
    result = subprocess.run([prepare], input=frame, env={'PATH': ''}, capture_output=True, timeout=5)
    observed = result.returncode, result.stdout, result.stderr
    if observed == (2, b'', b''):
        return False
    body = {'exit_sha256': sha256(raw).hexdigest(), 'job_id': job.decode('ascii'),
            'launch_nonce': nonce.decode('ascii'), 'terminal_publication_protocol': 1}
    expected = (json.dumps(body, sort_keys=True) + '\n').encode('ascii')
    if observed != (0, expected, b''):
        raise ValueError('installed HIA worker preparation has an invalid terminal witness writer')
    return True


@contextmanager
def _sealed_frame(frame):
    import fcntl

    with os.fdopen(os.memfd_create('hia-worker-probe', os.MFD_ALLOW_SEALING), 'w+b') as source:
        source.write(frame)
        source.flush()
        fcntl.fcntl(source, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK |
                    fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE)
        source.seek(0)
        yield source


def _run_job_writer(writer, frame, directory):
    output = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with _sealed_frame(frame) as source:
            return subprocess.run([writer], stdin=source, stdout=output, stderr=subprocess.PIPE,
                                  env={'PATH': ''}, timeout=5)
    finally:
        os.close(output)


def _verify_terminal_publisher(writer, scratch):
    name, raw = b'exit.witness', b'{}\n'
    frame = struct.pack('<8s3Q', b'HIAJRQ02', len(raw), os.getpid(), len(name)) + name + raw
    with TemporaryDirectory(prefix='terminal-writer-', dir=scratch) as directory:
        result = _run_job_writer(writer, frame, directory)
        if (result.returncode != 0 or result.stderr != struct.pack('<8sQq', b'HIAJRW01', 6, 0)
                or (Path(directory) / 'exit.witness.json').read_bytes() != raw):
            raise ValueError('installed HIA terminal publisher did not preserve the complete witness bytes')


def _job_writer_has_owner_publication(writer, scratch):
    raw = b'{"supervisor_pid": 17}'
    frame = struct.pack('<8s3Q', b'HIAJRO01', len(raw), os.getpid(), 0) + raw
    with TemporaryDirectory(prefix='owner-writer-', dir=scratch) as directory:
        result = _run_job_writer(writer, frame, directory)
        flags = result.returncode, result.stderr
        records = {path.name: path.read_bytes() for path in Path(directory).iterdir()}
        if flags == (65, b'') and not records:
            return False
        if flags != (0, struct.pack('<8sQq', b'HIAJRW01', 6, 0)) or records != {
                'owner-intent.json': raw, 'started.json': raw}:
            raise ValueError('installed HIA owner publisher did not preserve both bound receipts')
        return True


def _job_writer_has_cancellation(writer, scratch):
    name, nonce, now = b'controller-cancel-probe', b'0' * 32, 17
    absent_fd = 2147483647
    frame = struct.pack('<8s5Q32s', b'HIAJRC01', os.getpid(), absent_fd, now, len(name), 0, nonce) + name
    with TemporaryDirectory(prefix='cancel-writer-', dir=scratch) as directory:
        result = _run_job_writer(writer, frame, directory)
        observed = result.returncode, result.stderr
        records = {path.name: path.read_bytes() for path in Path(directory).iterdir()}
        if observed == (65, b'') and not records:
            return False
        expected = (json.dumps({'at_unix_ms': now, 'job_id': name.decode('ascii'),
                                'launch_nonce': nonce.decode('ascii')}, sort_keys=True) + '\n').encode('ascii')
        if (observed != (0, struct.pack('<8sQq', b'HIAJRW01', 7, -errno.EBADF))
                or records != {'cancel-request.json': expected}):
            raise ValueError('installed HIA cancellation writer did not preserve the durable intent and signal boundary')
        return True


def _job_writer_has_group_authority(writer, scratch):
    frame = struct.pack('<8s4Q', b'HIASGQ01', os.getpid(), 0, 0, 0)
    with TemporaryDirectory(prefix='group-signal-writer-', dir=scratch) as directory:
        result = _run_job_writer(writer, frame, directory)
        observed = result.returncode, result.stderr
        if list(Path(directory).iterdir()):
            raise ValueError('HIA group authority probe created unexpected durable state')
        if observed == (65, b''):
            return False
        if observed != (0, struct.pack('<8sQq', b'HIAJRW01', 0, 0)):
            raise ValueError('installed HIA job writer has an invalid group authority protocol')
        return True


def _worker_prepare_has_supervisor_outcome(prepare):
    frame = struct.pack('<8s6Q', b'HIAJSQ01', 15, 3, 3, 0, 0, 3)
    expected = struct.pack('<8s2q3Q', b'HIAJSO01', -15, 125, 125, 0, 0)
    result = subprocess.run([prepare], input=frame, env={'PATH': ''}, capture_output=True, timeout=5)
    observed = result.returncode, result.stdout, result.stderr
    if observed == (2, b'', b''):
        return False
    if observed != (0, expected, b''):
        raise ValueError('installed HIA worker preparation has an invalid raw supervisor outcome protocol')
    return True


def _job_writer_has_child_publication(writer, scratch):
    name, raw = b'child', b'{"identity": null, "pid": 17}\n'
    probe = struct.pack('<8s3Q', b'HIAJCH01', 3, os.getpid(), 0) + b'{}\n'
    frame = struct.pack('<8s3Q', b'HIAJCH01', len(raw), os.getpid(), len(name)) + name + raw
    with TemporaryDirectory(prefix='child-writer-', dir=scratch) as directory:
        result = _run_job_writer(writer, probe, directory)
        observed = result.returncode, result.stderr
        if list(Path(directory).iterdir()):
            raise ValueError('HIA child publication probe created unexpected durable state')
        if observed == (65, b''):
            return False
        if observed != (0, struct.pack('<8sQq', b'HIAJRW01', 0, 0)):
            raise ValueError('installed HIA job writer has an invalid child publication protocol')
        result = _run_job_writer(writer, frame, directory)
        records = {path.name: path.read_bytes() for path in Path(directory).iterdir()}
        if ((result.returncode, result.stderr) != (0, struct.pack('<8sQq', b'HIAJRW01', 6, 0))
                or records != {'child.json': raw}):
            raise ValueError('installed HIA job writer changed the original child receipt')
        return True


def _job_writer_has_original_wait(writer):
    raw = writer.read_bytes()
    entry, end = b'HIAWABI1', b'HIAWEND1'
    occurrences = raw.count(entry), raw.count(end)
    if occurrences == (0, 0):
        return False
    if occurrences != (1, 1) or not 32 <= raw.index(end) - raw.index(entry) - len(entry) <= 256:
        raise ValueError('installed HIA job writer has an invalid original-child wait entry')
    return True


def _job_writer_has_output_capture(writer):
    raw = writer.read_bytes()
    begin, end, policy = b'HIAKABI1', b'HIAKEND1', b'HIAJPOL1'
    occurrences = tuple(raw.count(marker) for marker in (begin, end, policy))
    if occurrences == (0, 0, 0):
        return False
    if occurrences != (1, 1, 1):
        raise ValueError('installed HIA job writer has an invalid output capture entry')
    first, last, linked = (raw.index(marker) for marker in (begin, end, policy))
    if (not 32 <= last - first - len(begin) <= 256 or linked != last + len(end)
            or not 32 <= len(raw) - linked - len(policy) <= 1 << 20):
        raise ValueError('installed HIA job writer has an invalid output capture extent')
    return True


def _job_writer_has_spawn_plan(writer):
    raw = writer.read_bytes()
    marker = b'HIASPAWN'
    count = raw.count(marker)
    if not count:
        return False
    if count != 1 or b'HIAWEND1' + marker + b'HIAKABI1' not in raw:
        raise ValueError('installed HIA job writer has an invalid workload spawn entry')
    return True


def _worker_prepare_has_workdir_authority(prepare):
    root = b'/workdir/probe'
    for path, allowed in ((root + b'/nested', True), (root + b'-sibling', False)):
        frame = (struct.pack('<8s4Q', b'HIAJCQ01', len(path), 1, 0, 0) + path +
                 struct.pack('<Q', len(root)) + root)
        result = subprocess.run([prepare], input=frame, env={'PATH': ''}, capture_output=True, timeout=5)
        observed = result.returncode, result.stdout, result.stderr
        if allowed and observed == (2, b'', b''):
            return False
        if observed != (0, struct.pack('<8sQ', b'HIAJCO01', allowed), b''):
            raise ValueError('installed HIA workdir authority does not preserve the workspace boundary')
    return True


def _worker_prepare_has_cancel_authority(prepare):
    job = b'cancel-probe'
    nonce = b'0123456789abcdef' * 2
    kind = b'proc_start_ticks'
    identity = b'boot:123'
    for phase, uid, sample, decision in ((0, 0, b'', 1), (1, 1000, identity, 4),
                                         (1, 1001, identity, 2), (1, 1000, b'boot:124', 2)):
        fields = (job, job, job, nonce, nonce, kind, identity, nonce, kind if phase else b'', sample)
        frame = (struct.pack('<8s16Q', b'HIAJCX01', phase, 1000, 1000, 42, uid, 1,
                             *map(len, fields)) + b''.join(fields))
        result = subprocess.run([prepare], input=frame, env={'PATH': ''}, capture_output=True, timeout=5)
        observed = result.returncode, result.stdout, result.stderr
        if phase == 0 and observed == (2, b'', b''):
            return False
        if observed != (0, struct.pack('<8sQ', b'HIAJCY01', decision), b''):
            raise ValueError('installed HIA cancellation authority does not preserve frozen process identity')
    return True


def _worker_prepare_has_supervision_loop(prepare):
    # Timeout arms TERM, an existing drain keeps its budget, and the last
    # reader's expiry permits one group KILL before final completion.
    for index, (stage, facts, decision) in enumerate(((0, 8, 9), (0, 21, 2),
                                                      (1, 11, 2), (2, 104, 7), (2, 5, 4))):
        frame = struct.pack('<8s2Q', b'HIAJLQ01', stage, facts)
        result = subprocess.run([prepare], input=frame, env={'PATH': ''}, capture_output=True, timeout=5)
        observed = result.returncode, result.stdout, result.stderr
        if index == 0 and observed == (2, b'', b''):
            return False
        if observed != (0, struct.pack('<8sQ', b'HIAJLO01', decision), b''):
            raise ValueError('installed HIA supervision loop changed the original timeout or drain boundary')
    return True


def _request_classifier_has_resource_uri(classifier):
    uri = rb'"hia:\/\/artifact\/controller-\u0072ead"'
    request_id = rb'"session\u0031"'
    params = b'{"uri":' + uri + b'}'
    frame = b'{"jsonrpc":"2.0","method":"resources/read","id":' + request_id + b',"params":' + params + b'}'
    with _sealed_frame(frame) as source:
        run = subprocess.run([classifier], stdin=source, capture_output=True, timeout=5, env={'PATH': ''})
    if run.returncode or run.stderr or len(run.stdout) != 96:
        raise ValueError('invalid installed HIA MCP resource request probe')
    fields = struct.unpack('<Q8s10Q', run.stdout)
    if fields[:4] != (88, b'HIAMCP01', 8, 4) or fields[8] or fields[11]:
        raise ValueError('installed HIA MCP request classifier cannot identify the resource route')
    for start, size, expected in ((fields[4], fields[5], request_id), (fields[6], fields[7], params)):
        if frame[start:start + size] != expected:
            raise ValueError('installed HIA MCP request classifier changed the request identity')
    if fields[9:11] == (0, 0):
        return False
    if frame[fields[9]:fields[9] + fields[10]] != uri:
        raise ValueError('installed HIA MCP request classifier changed the resource URI')
    return True


def _install_controller(output, scratch, release, installer):
    # The earlier verified packages without a complete controller keep their
    # original Worker-only contract. Never create a partially bound controller.
    files = [release / name for name in CONTROLLER_FILES]
    builder = release / 'hia-directory-package-build'
    if not all(path.is_file() for path in (*files, builder)):
        return
    receipt_writer = release / CONTROLLER_JOB_RECEIPT
    terminal_receipt = release / 'hia-agent-job-terminal-receipt'
    schema = 'hepta.hia.mcp.controller.v1'
    if receipt_writer.is_file():
        files.append(receipt_writer)
        if _worker_prepare_has_terminal_witness(release / 'hia-worker-prepare'):
            schema = 'hepta.hia.mcp.controller.v3'
        else:
            schema = 'hepta.hia.mcp.controller.v2'
    if terminal_receipt.is_file():
        if schema != 'hepta.hia.mcp.controller.v3':
            raise ValueError('native terminal receipt requires the pinned witness controller')
        files.append(terminal_receipt)
        schema = 'hepta.hia.mcp.controller.v4'
        if _worker_prepare_has_live_owner_binding(release / 'hia-worker-prepare'):
            schema = 'hepta.hia.mcp.controller.v5'
            if _worker_prepare_has_witness_publisher(release / 'hia-worker-prepare'):
                _verify_terminal_publisher(receipt_writer, scratch)
                schema = 'hepta.hia.mcp.controller.v6'
                if _worker_prepare_has_supervisor_outcome(release / 'hia-worker-prepare'):
                    schema = 'hepta.hia.mcp.controller.v7'
                    if _job_writer_has_owner_publication(receipt_writer, scratch):
                        schema = 'hepta.hia.mcp.controller.v8'
                        if _worker_prepare_has_workdir_authority(release / 'hia-worker-prepare'):
                            schema = 'hepta.hia.mcp.controller.v9'
    if schema == 'hepta.hia.mcp.controller.v9':
        if _worker_prepare_has_cancel_authority(release / 'hia-worker-prepare'):
            schema = 'hepta.hia.mcp.controller.v10'
    if schema == 'hepta.hia.mcp.controller.v10':
        if _worker_prepare_has_supervision_loop(release / 'hia-worker-prepare'):
            schema = 'hepta.hia.mcp.controller.v11'
    if schema == 'hepta.hia.mcp.controller.v11' and _job_writer_has_cancellation(receipt_writer, scratch):
        schema = 'hepta.hia.mcp.controller.v12'
    if schema == 'hepta.hia.mcp.controller.v12' and _request_classifier_has_resource_uri(release / 'hia-agent-mcp-request'):
        schema = 'hepta.hia.mcp.controller.v13'
    if schema == 'hepta.hia.mcp.controller.v13' and _job_writer_has_group_authority(receipt_writer, scratch):
        schema = 'hepta.hia.mcp.controller.v14'
    if schema == 'hepta.hia.mcp.controller.v14' and _job_writer_has_child_publication(receipt_writer, scratch):
        schema = 'hepta.hia.mcp.controller.v15'
    if schema == 'hepta.hia.mcp.controller.v15' and _job_writer_has_original_wait(receipt_writer):
        schema = 'hepta.hia.mcp.controller.v16'
    if schema == 'hepta.hia.mcp.controller.v16' and _job_writer_has_output_capture(receipt_writer):
        schema = 'hepta.hia.mcp.controller.v17'
    if schema == 'hepta.hia.mcp.controller.v17' and _job_writer_has_spawn_plan(receipt_writer):
        schema = 'hepta.hia.mcp.controller.v18'
    stage = scratch / 'controller-stage'
    stage.mkdir(mode=0o700)
    pins = {}
    for source in files:
        dest = _copy_runtime_file(source, stage / source.name)
        if source.name.startswith('hia-'):
            dest.chmod(0o500)
        pins[source.name] = sha256(dest.read_bytes()).hexdigest()
    manifest = stage / CONTROLLER_MANIFEST
    with manifest.open('x') as stream:
        json.dump({'schema':schema, 'files':pins}, stream,
                  sort_keys=True, separators=(',', ':'))
        stream.write('\n')
    manifest.chmod(0o400)
    environment = {'PATH': ''}
    package = subprocess.run([builder, stage], env=environment, check=True,
                             capture_output=True, timeout=60)
    digest = package.stderr.decode('ascii').strip()
    if not authority._digest(digest):
        raise ValueError('HIA controller packer did not publish an exact package digest')
    depot = output / 'controller'
    depot.mkdir(mode=0o700)
    for action in ('install', 'verify'):
        result = subprocess.run([installer, action, depot, digest], input=package.stdout,
                                env=environment, check=True, capture_output=True, timeout=60)
        receipt = json.loads(result.stdout)
        if receipt['sha256'] != digest or receipt['files'] != len(files) + 1:
            raise ValueError('HIA controller package receipt differs from its fixed role inventory')
    if (depot / digest / CONTROLLER_MANIFEST).read_bytes() != manifest.read_bytes():
        raise ValueError('installed HIA controller manifest differs from its verified role pins')


def build(output, compiler, cold_report, package, package_sha256):
    if not authority._digest(package_sha256):
        raise ValueError('an exact Store release SHA-256 is required')
    output = Path(output).absolute()
    output.mkdir(mode=0o700)
    depot = output / 'store'
    depot.mkdir(mode=0o700)
    release = depot / package_sha256
    with TemporaryDirectory(prefix='hia-worker-release-tools-', dir=output.parent) as temp:
        scratch = Path(temp)
        installer = build_installer(scratch / 'installer', compiler, cold_report)
        for action in ('install', 'verify'):
            with Path(package).open('rb') as source:
                subprocess.run([installer, action, depot, package_sha256], stdin=source,
                               env={'PATH': ''}, check=True, capture_output=True, timeout=60)
        contract = 'HIA_SELFHOST_CORE_SUPPORT.json'
        if (release / contract).read_bytes() != _source_resource_path('docs/' + contract).read_bytes():
            raise ValueError('Store release source contract differs from the worker build')
        _install_controller(output, scratch, release, installer)
        batched = build_helper_batch(scratch / 'generic-helpers', compiler, cold_report,
                                     candidates=tuple(candidate for candidate in ADDITIONAL_HELPERS
                                                      if candidate not in HELPER_BUILDERS))
        helpers = []
        for candidate in (*INSTALLED_HELPERS, *ADDITIONAL_HELPERS):
            if candidate in INSTALLED_HELPERS:
                manifest = release / (candidate + '-manifest.json')
            else:
                builder = HELPER_BUILDERS.get(candidate)
                source = (batched[candidate] if builder is None
                          else builder(scratch / candidate, compiler, cold_report))
                manifest = _copy_image_manifest(source, output / candidate / 'manifest.json')
            selector = 'HEPTA_HIA_' + candidate.replace('-', '_').upper() + '_MANIFEST'
            helpers.append({'selector': selector, 'manifest_path': manifest.relative_to(output).as_posix(),
                            'manifest_sha256': sha256(manifest.read_bytes()).hexdigest()})
        base = output / 'helpers.json'
        base.write_bytes((json.dumps({'schema': authority.SCHEMA, 'target': authority.TARGET,
            'abi': authority.ABI, 'helpers': helpers}, indent=2, sort_keys=True) + '\n').encode())
        base.chmod(0o400)
        report = _copy_report(build_report(scratch / 'report', compiler, cold_report), output / 'report')
        wrapped, _ = bind_worker_bundle(output / 'report.json', base, report, portable=True)
        schedulers = {}
        for kind in FAMILIES:
            source = build_scheduler(scratch / kind, compiler, cold_report, kind=kind, in_process=True)
            schedulers[kind] = _copy_scheduler(source, output / kind)
        scheduled, _ = bind_scheduling_bundle(output / 'schedulers.json', wrapped, schedulers, portable=True)
        reference = _copy_runtime_file(
            build_reference_executable(scratch / 'reference-cli', compiler, cold_report),
            output / 'reference' / 'hia-reference-wire')
        reference.chmod(0o500)
        owned_reference = _copy_runtime_file(
            build_owned_reference_executable(scratch / 'owned-reference-cli', compiler, cold_report),
            output / 'reference' / 'hia-owned-reference-wire')
        owned_reference.chmod(0o500)
        direct_call = _copy_runtime_file(
            build_direct_call(scratch / 'direct-call', compiler, cold_report),
            output / 'reference' / 'hia-direct-call')
        direct_call.chmod(0o500)
        read_page = _copy_runtime_file(
            build_agent_stdio(scratch / 'read-page', compiler, cold_report,
                              output / 'agent-read-page' / 'manifest.json'),
            output / 'agent-read-page' / 'hia-agent-read-page')
        read_page.chmod(0o500)
        journal = _copy_runtime_file(
            build_agent_stdio(scratch / 'journal-stdio', compiler, cold_report,
                              output / 'agent-journal' / 'manifest.json', kind='journal'),
            output / 'agent-journal' / 'hia-agent-journal')
        journal.chmod(0o500)
        profile = output / 'worker.json'
        pin = bind_worker_store(profile, scheduled, release, candidate_import=True, portable=True,
                                reference_executable=reference, owned_reference_executable=owned_reference,
                                direct_call_executable=direct_call, direct_call_protocol=5,
                                read_page_executable=read_page, initialize_fresh=True,
                                journal_executable=journal)
    profile.chmod(0o400)
    with authority.native_helpers_scope(str(profile), pin) as binding:
        binding.check()
    return profile, pin


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report', 'package'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--package-sha256', required=True)
    args = parser.parse_args()
    profile, pin = build(args.output, args.compiler, args.cold_report, args.package, args.package_sha256)
    result = {'native_helpers_manifest': str(profile), 'native_helpers_sha256': pin,
              'package_sha256': args.package_sha256, 'production_activated': False}
    controller = list(profile.parent.glob('controller/*/' + CONTROLLER_MANIFEST))
    if controller:
        manifest, = controller
        result.update(hia_controller_manifest=str(manifest),
                      hia_controller_sha256=sha256(manifest.read_bytes()).hexdigest())
    print(json.dumps(result))


if __name__ == '__main__':
    main()
