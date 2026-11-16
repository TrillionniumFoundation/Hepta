"""Test-only construction and custody; the formal artifact builder stays cold-only."""
from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_ARTIFACT_DELIVERY_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_ARTIFACT_DELIVERY_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_ARTIFACT_DELIVERY_EVIDENCE'
OWNERS = ('store_artifact_profile', 'service_context', 'store_lifecycle', 'agent_journal')
INPUTS = ('hepta/artifact_publication_native.py', 'hepta/hia_artifact_delivery.py',
    'hepta/hia_artifact_delivery_protocol.py', 'hepta/hia_artifact_delivery_worker.py',
    'hepta/hia_native_delivery.py', 'hepta/hia_native_helpers.py', 'hepta/hia_agent_store.py',
    'hepta/hia_store_lifecycle_native.py', 'hepta/hia_store_lifecycle_selection.py',
    'hepta/hia_store_artifact_profile_native.py', 'tools/build_hia_artifact_publication.py',
    'tools/generate_hia_artifact_publication.py', 'tools/hia_artifact_publication_syscalls.S',
    'examples/hia_bootstrap/artifact_publication_policy.hepta',
    'examples/hia_bootstrap/artifact_publication_packer.hepta',
    'tests/test_hia_artifact_delivery.py', 'tests/hia_artifact_delivery_fixture.py',
    'tests/hia_artifact_delivery_cases.py', 'tests/hia_artifact_delivery_installed.py',
    'tests/hia_artifact_delivery_oracle.py',
    'tests/hia_artifact_delivery_operation_oracle.py',
    'tests/fixtures/hia_artifact_delivery_operation_cases.json',
    'tests/fixtures/hia_artifact_delivery_operation_expected.json',
    'tools/qualify_hia_artifact_delivery_callers.py',
    'tests/fixtures/hia_artifact_delivery_callers_5bf69586.json',
    'tests/fixtures/hia_artifact_delivery_original_5da589f0.json',
    'tests/fixtures/hia_artifact_delivery_bridge_5da589f0.py.txt',
    'tests/fixtures/hia_artifact_delivery_syscalls_5da589f0.S.txt',
    'tests/fixtures/hia_artifact_delivery_generator_5da589f0.py.txt',
    'tests/fixtures/hia_artifact_delivery_bridge_cases.json',
    'tests/fixtures/hia_artifact_delivery_bridge_expected.json',
    'tests/fixtures/hia_artifact_delivery_terminal_cases.json',
    'tests/hia_store_delivery_successor.py',
    'tests/fixtures/store_delivery_successor_provenance.json',
    'docs/HIA_ARTIFACT_DELIVERY.md')


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(',', ':')).encode()


def clean_environment():
    return {key: value for key, value in os.environ.items()
            if key not in ('PYTHONPATH', 'PYTHONHOME') and not key.startswith('HEPTA_HIA_')}


def source_pins():
    from tools.hia_selfhost_contract import file_digests
    return {**file_digests(), **{name: sha256((ROOT / name).read_bytes()).hexdigest()
                               for name in INPUTS}}


def prepare(root, compiler, cold):
    from tools.qualify_hia_selfhost import compile_stage, invoke
    from tools.build_hia_source_build import _check_pack_output
    from tools.build_hia_artifact_publication import build, current_sources, PROFILE, SOURCES, OPERATIONS
    from tools.generate_hia_artifact_publication import MAGIC
    from hepta.hia_artifact_delivery_protocol import control_descriptor, private_executable
    root, compiler = Path(root), Path(compiler)
    before, compiler_raw = source_pins(), compiler.read_bytes()
    built = root / 'artifact'
    if cold is not None:
        app = build(built, compiler, Path(cold))
    else:
        built.mkdir(mode=0o700)
        images, receipts = {}, {}
        for label, name in zip(('policy', 'packer', 'sha256'), SOURCES[:3], strict=True):
            images[label], receipts[label] = compile_stage(built, label, compiler, (ROOT / name).read_bytes())
        policy, digest = images['policy'].read_bytes(), images['sha256'].read_bytes()
        frame = struct.pack('<3Q', MAGIC, len(policy), len(digest)) + policy + digest
        result, output = invoke(built, 'publication-pack', images['packer'], frame)
        public = _check_pack_output(result, output, artifact=images['packer'].read_bytes(), source=frame)
        control_descriptor(public)
        app = built / 'hia-artifact'
        app.write_bytes(public)
        app.chmod(0o700)
        record = {'schema': 'hepta.hia.artifact-publication-build.v1',
            'status': 'NATIVE_ARTIFACT_PUBLICATION_BUILT', 'profile': PROFILE,
            'source_manifest': current_sources(),
            'source_sha256': {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES},
            'executable_path': app.name, 'executable_sha256': sha256(public).hexdigest(),
            'public_executable_sha256': sha256(public).hexdigest(),
            'private_executable_sha256': sha256(private_executable(public)).hexdigest(),
            'compiler_sha256': sha256(compiler_raw).hexdigest(), 'operations': OPERATIONS,
            'compile_receipts': receipts, 'native_packer_receipt': result,
            'scope': 'DEVELOPMENT_COMPONENT', 'matching_current_source_cold_qualified': False}
        (built / 'build.json').write_bytes(encoded(record) + b'\n')
    manifests = {'artifact': str((built / 'build.json').resolve())}
    private = built / 'hia-artifact-private'
    private.write_bytes(private_executable(app.read_bytes()))
    private.chmod(0o700)
    for name in OWNERS:
        output = root / ('build-' + name)
        if name != 'agent_journal':
            manifest = importlib.import_module('tools.build_hia_' + name).build(
                output, compiler, cold, development=cold is None)
        elif cold is not None:
            from tools.build_hia_json_preflight import build as journal_build
            manifest = journal_build(output, compiler, Path(cold), candidate='agent-journal')
        else:
            from hepta import hia_agent_journal_native as journal
            output.mkdir(mode=0o700)
            image, receipt = compile_stage(output, 'agent-journal', compiler, journal.SOURCE.read_bytes())
            manifest = output / 'manifest.json'
            manifest.write_bytes(encoded({'schema': journal.SCHEMA,
                'source_sha256': sha256(journal.SOURCE.read_bytes()).hexdigest(),
                'image_path': image.name, 'image_sha256': sha256(image.read_bytes()).hexdigest(),
                'compiler_sha256': sha256(compiler_raw).hexdigest()}) + b'\n')
            (output / 'development-build.json').write_bytes(encoded({
                'scope': 'DEVELOPMENT_COMPONENT', 'native_compile_receipt': receipt,
                'matching_current_source_cold_qualified': False}) + b'\n')
        manifests[name] = str(manifest.resolve())
    if compiler.read_bytes() != compiler_raw or source_pins() != before:
        raise AssertionError('artifact delivery component inputs changed during construction')
    (root / 'manifests.json').write_bytes(encoded(manifests) + b'\n')
    return manifests
