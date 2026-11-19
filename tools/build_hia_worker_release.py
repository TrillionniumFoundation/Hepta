"""Assemble a relocatable, explicitly selected HIA worker release.

The selected process still uses the installed Python custody/service bridge.
Only the program images and policy manifests are deployed by this command.
"""

from __future__ import annotations

import argparse
from functools import partial
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from hepta import hia_native_helpers as authority
from hepta.hia_json_preflight_native import _source_resource_path
from hepta.hia_worker_scheduling_bundle import FAMILIES
from tools.bind_hia_worker_store import bind_worker_store
from tools.build_hia_agent_binary64 import build as build_binary64
from tools.build_hia_agent_binary64_format import build as build_binary64_format
from tools.build_hia_agent_data_json import build as build_agent_data_json
from tools.build_hia_direct_call import build as build_direct_call
from tools.build_hia_agent_read_page import build as build_read_page
from tools.build_hia_json_preflight import build as build_helper
from tools.build_hia_native_continuation import build as build_scheduler
from tools.build_hia_release_install import build as build_installer
from tools.build_hia_scalar_reference_cli import build as build_reference_executable
from tools.build_hia_owned_reference_cli import build as build_owned_reference_executable
from tools.build_hia_sha256 import build as build_sha256
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
)
HELPER_BUILDERS = {
    'slot-ledger': build_slot_ledger,
    'sha256-stream': partial(build_sha256, candidate='sha256_stream'),
    'agent-data-json': build_agent_data_json,
    'agent-binary64': build_binary64,
    'agent-binary64-format': build_binary64_format,
}


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
        helpers = []
        for candidate in (*INSTALLED_HELPERS, *ADDITIONAL_HELPERS):
            if candidate in INSTALLED_HELPERS:
                manifest = release / (candidate + '-manifest.json')
            else:
                staging = scratch / candidate
                builder = HELPER_BUILDERS.get(candidate)
                if builder is None:
                    builder = partial(build_helper, candidate=candidate)
                source = builder(staging, compiler, cold_report)
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
            build_read_page(scratch / 'read-page', compiler, cold_report,
                            output / 'agent-read-page' / 'manifest.json'),
            output / 'agent-read-page' / 'hia-agent-read-page')
        read_page.chmod(0o500)
        profile = output / 'worker.json'
        pin = bind_worker_store(profile, scheduled, release, candidate_import=True, portable=True,
                                reference_executable=reference, owned_reference_executable=owned_reference,
                                direct_call_executable=direct_call, direct_call_protocol=3,
                                read_page_executable=read_page)
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
    print(json.dumps({'native_helpers_manifest': str(profile), 'native_helpers_sha256': pin,
                      'package_sha256': args.package_sha256, 'production_activated': False}))


if __name__ == '__main__':
    main()
