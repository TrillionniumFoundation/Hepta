"""Build the checked native patch-result frame producer from a matching cold run.

The host binds source/compiler identities and owns build files. HIA computes
the candidate and complete diagnostics and admits both original and candidate.
Runtime output is an opaque, bounded HIAPAR01 frame with no hosted JSON work.
"""
import argparse
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import struct

from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.generate_hia_core_patch_result_cli import MAGIC, BUNDLE_LIMIT
from tools.hia_selfhost_contract import CONTRACT_PATH, PROFILE, validate_contract
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'examples/hia_bootstrap/core_patch.hepta'
ADMISSION = ROOT / 'examples/hia_bootstrap/core_admission.hepta'
PACKER = ROOT / 'examples/hia_bootstrap/core_patch_result_cli_packer.hepta'
SCHEMA = 'hepta.hia.core-patch-result-cli-build.v1'
REQUIRED_CHECKS = {'export_manifest_matches_qualification', 'isolated_python_without_site',
    'nested_full_qualification_pass', 'nested_process_exit_zero', 'no_ancestor_git_identity',
    'no_bytecode_cache_created', 'no_inherited_home_or_python_cache', 'no_inherited_seed_or_successor_images',
    'origin_hashes_preserved', 'owned_process_tree_cleanup_confirmed', 'source_export_hashes_preserved'}


def current_sources():
    contract = validate_contract()
    return {**contract['source_identity']['files'],
            CONTRACT_PATH: sha256((ROOT / CONTRACT_PATH).read_bytes()).hexdigest()}


def build(output, compiler, cold_report):
    paths = (compiler, cold_report, SOURCE, ADMISSION, PACKER)
    pins = {path: path.read_bytes() for path in paths}
    cold = json.loads(pins[cold_report])
    if (type(cold) is not dict or cold.get('schema') != 'hepta.hia.selfhost-cold-replay.v1'
            or cold.get('profile') != PROFILE or cold.get('status') != 'COLD_SELFHOST_REPLAY_PASS'
            or type(cold.get('returncode')) is not int or cold['returncode'] != 0
            or type(cold.get('checks')) is not dict
            or set(cold['checks']) != REQUIRED_CHECKS
            or any(value is not True for value in cold['checks'].values())
            or cold.get('generation_sha256') != [sha256(pins[compiler]).hexdigest()] * 3):
        raise ValueError('completed matching-source native cold qualification required for Core patch-result CLI')
    sources = current_sources()
    if (cold.get('source_manifest') != sources
            or any(str(path.relative_to(ROOT)) not in sources for path in (SOURCE, ADMISSION, PACKER))):
        raise ValueError('completed matching-source native cold qualification required for Core patch-result CLI')
    output.mkdir(mode=0o700)
    images = {}; receipts = {}
    for name, source in (('patch', SOURCE), ('admission', ADMISSION), ('packer', PACKER)):
        image, receipt = compile_stage(output, 'core-patch-result-' + name, compiler, pins[source])
        raw = image.read_bytes()
        if not 0 < len(raw) <= 1 << 20:
            raise ValueError('native Core patch-result component exceeds unchanged 1-MiB image profile')
        images[name] = (image, raw); receipts[name] = receipt
    frame = struct.pack('<3Q', MAGIC, len(images['patch'][1]), len(images['admission'][1]))
    frame += images['patch'][1] + images['admission'][1]
    native = NativeHiaJsonImage(images['packer'][1], sha256(images['packer'][1]).hexdigest())
    request = ctypes.create_string_buffer(frame, len(frame))
    arena = ctypes.create_string_buffer(BUNDLE_LIMIT); scratch = ctypes.create_string_buffer(1)
    size = native._entry(request, len(frame), arena, BUNDLE_LIMIT, scratch, 0)
    if not 0 < size <= BUNDLE_LIMIT:
        raise ValueError('native Core patch-result packer refused the bound images')
    raw = ctypes.string_at(arena, size); inspection = inspect_executable(raw)
    if (any(path.read_bytes() != before for path, before in pins.items())
            or current_sources() != sources
            or any(path.read_bytes() != before for path, before in images.values())):
        raise ValueError('native Core patch-result build inputs changed')
    manifests = {}
    for name, source, schema, filename in (
        ('patch', SOURCE, 'hepta.hia.core-patch-native.v1', 'manifest.json'),
        ('admission', ADMISSION, 'hepta.hia.core-admission-native.v1', 'admission-manifest.json')):
        path, data = images[name]
        value = {'schema': schema, 'source_sha256': sha256(pins[source]).hexdigest(),
                 'image_path': path.name, 'image_sha256': sha256(data).hexdigest(),
                 'compiler_sha256': sha256(pins[compiler]).hexdigest()}
        with (output / filename).open('x') as stream:
            json.dump(value, stream, indent=2, sort_keys=True); stream.write('\n')
        manifests[filename] = value
    executable = output / 'hia-patch-result'
    with executable.open('xb') as stream: stream.write(raw)
    executable.chmod(0o700)
    record = {'schema': SCHEMA, 'status': 'NATIVE_CORE_PATCH_RESULT_CLI_BUILT', 'profile': PROFILE,
        'source_manifest': sources, 'executable_path': executable.name,
        'executable_sha256': sha256(raw).hexdigest(), 'executable': inspection,
        'source_sha256': {str(path.relative_to(ROOT)): sha256(pins[path]).hexdigest()
                          for path in (SOURCE, ADMISSION, PACKER)},
        'cold_report_sha256': sha256(pins[cold_report]).hexdigest(),
        'image_sha256': {name: sha256(data).hexdigest() for name, (_, data) in images.items()},
        'native_compile_receipts': receipts, 'frame_sha256': sha256(frame).hexdigest(),
        'manifests': manifests, 'arguments': ['v1', 'v2'],
        'input': '[raw primitive Core, snapshot-bound patch] JSON array',
        'output': {'magic_ascii': 'HIAPAR01', 'header': ['magic_u64_le', 'candidate_bytes_u64_le',
                   'diagnostic_bytes_u64_le', 'reserved_zero_u64_le'],
                   'payloads': ['canonical candidate Core JSON', 'canonical complete patch-result JSON']},
        'output_after_full_base_and_candidate_admission': True,
        'runtime_foreign_payload_parser_or_interpreter': False,
        'host_authoring_build_and_filesystem_custody': True,
        'durable_Agent_publication_implemented': False, 'default_changed': False,
        'whole_native_delivery_qualified': False}
    with (output / 'build.json').open('x') as stream:
        json.dump(record, stream, indent=2, sort_keys=True); stream.write('\n')
    return executable


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for key in ('output', 'compiler', 'cold-report'): p.add_argument('--' + key, type=Path, required=True)
    a = p.parse_args()
    print(build(a.output.resolve(), a.compiler.resolve(), a.cold_report.resolve()))
