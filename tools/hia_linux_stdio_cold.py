"""Strict cold/input/receipt custody for the explicit Linux stdio profile.

These are hosted build and qualification checks, not a new HIA runtime policy.
Every public admission freshly reads the complete current source contract and
the original cold authority. Serialized fixture records never grant authority.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

CAPACITY = 1048576
COMPILER_SOURCE = 'examples/hia_bootstrap/selfhost_linux_stdio.hepta'
PACKER_SOURCE = 'examples/hia_bootstrap/linux_stdio_entry_packer.hepta'
ORDINARY_SOURCE = 'examples/hia_bootstrap/selfhost.hepta'
CASE_NAMES = ('bounded-copy', 'zero-transfer', 'read-ebadf-exact',
              'write-ebadf-exact', 'out-of-bounds')
CASE_SOURCES = tuple('tests/fixtures/hia_linux_stdio_' + name + '.hepta'
                     for name in CASE_NAMES)
CHILD_FIELDS = frozenset({
    'abi_status', 'core_u32', 'forbidden_compiler_modules_loaded', 'image_sha256',
    'limits', 'loader_operations', 'native_elapsed_ns', 'output_sha256',
    'output_unchanged', 'result_u64', 'return_encoding', 'source_sha256',
    'source_unchanged', 'status', 'workspace_header',
})
RECEIPT_HOST_FIELDS = frozenset({
    'artifact_sha256', 'case', 'format', 'input_bytes', 'input_sha256',
    'produced_bytes', 'produced_image', 'produced_sha256', 'runner_sha256',
    'wall_elapsed_ns',
})
REQUIRED_SOURCES = (
    COMPILER_SOURCE, PACKER_SOURCE, ORDINARY_SOURCE,
    'hepta/hia_linux_stdio.py', 'hepta/hia_program.py',
    'hepta/hia_agent_assembly.py', 'hepta/hia_program_runtime.py',
    'hepta/hia_opcodes.py', 'hepta/hia_agent_contract.py',
    'tools/build_hia_linux_stdio_program.py', 'tools/build_hia_linux_stdio_cold.py',
    'tools/hia_linux_stdio_cold.py', 'tools/qualify_hia_linux_stdio.py',
    'tools/generate_hia_selfhost_linux_stdio.py', 'tools/generate_hia_linux_stdio_entry.py',
    'tools/generate_hia_selfhost.py', 'tools/hia_selfhost_effects.py',
    'tools/hia_selfhost_contract.py', 'tools/hia_selfhost_limits.py',
    'tools/qualify_hia_selfhost.py', 'tools/hia_selfhost_child.py',
    'tools/build_hia_json_preflight.py', 'tools/hia_selfhost_process_owner.py',
    'tests/test_hia_linux_stdio.py', 'tests/test_hia_linux_stdio_cold.py',
    'tests/hia_linux_stdio_cases.py',
    'tests/fixtures/hia_linux_stdio_public_native_r2.py.txt',
    'tests/test_hia_program.py', 'tests/test_hia_agent_assembly.py',
    'docs/HIA_LINUX_STDIO_PROFILE.md', 'docs/HIA_LINUX_STDIO_COLD.md', 'setup.py', 'MANIFEST.in',
    *CASE_SOURCES,
)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(raw):
    return sha256(raw).hexdigest()


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    def constant(value):
        raise ValueError('nonfinite JSON value: ' + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def wire(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def publish(path, value):
    with Path(path).open('xb') as stream:
        stream.write(wire(value))


def pin(path):
    path = Path(path).absolute()
    observed = path.lstat()
    require(stat.S_ISREG(observed.st_mode), 'regular captured input required: ' + str(path))
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': digest(raw),
            'mode': stat.S_IMODE(observed.st_mode)}


def check_bindings(bindings):
    require(type(bindings) is list and bindings, 'nonempty exact input bindings required')
    names = []
    for row in bindings:
        require(type(row) is dict and set(row) == {'path', 'bytes', 'sha256', 'mode'},
                'unknown input binding')
        require(type(row['path']) is str and Path(row['path']).is_absolute()
                and type(row['bytes']) is int and type(row['mode']) is int,
                'exact absolute input identity required')
        require(pin(row['path']) == row, 'captured input changed: ' + row['path'])
        names.append(row['path'])
    require(len(names) == len(set(names)), 'duplicate input bindings')


def admit_required_sources(sources, *, root=ROOT, names=REQUIRED_SOURCES):
    require(type(sources) is dict, 'complete matching-cold source map required')
    require(type(names) is tuple and len(names) == len(set(names)), 'exact unique required source names')
    for name in names:
        require(name in sources, 'Linux stdio input missing from cold source map: ' + name)
        require(sources[name] == digest((Path(root) / name).read_bytes()),
                'Linux stdio input differs from cold source map: ' + name)


def outer_shape(outer):
    require(type(outer) is dict
            and outer.get('schema') == 'hepta.hia.selfhost-cold-replay.v1'
            and outer.get('status') == 'COLD_SELFHOST_REPLAY_PASS'
            and type(outer.get('returncode')) is int and outer['returncode'] == 0,
            'completed matching-current-source cold replay required')
    require(type(outer.get('qualification_wall_limit_seconds')) is int
            and outer['qualification_wall_limit_seconds'] == 180
            and type(outer.get('cleanup_wall_limit_seconds')) is int
            and outer['cleanup_wall_limit_seconds'] == 3,
            'original cold limits must remain 180+3')
    owner = outer.get('process_owner')
    require(type(owner) is dict and owner.get('schema') == 'hepta.hia.selfhost-process-owner.v1'
            and owner.get('status') == 'OWNED_PROCESS_COMPLETED'
            and type(owner.get('returncode')) is int and owner['returncode'] == 0
            and type(owner.get('qualification_seconds')) is int and owner['qualification_seconds'] == 180
            and type(owner.get('cleanup_seconds')) is int and owner['cleanup_seconds'] == 3
            and owner.get('timed_out') is False
            and owner.get('exit_observed_before_deadline') is True
            and type(owner.get('cleanup')) is dict and owner['cleanup'].get('complete') is True,
            'actual cold terminal and process cleanup required')
    require(type(outer.get('nested_report')) is str and outer['nested_report']
            and type(outer.get('nested_report_sha256')) is str,
            'actual nested cold qualification is required')


def admit_cold(cold_report, *, compiler=None):
    """Admit original cold authority, all actual B images and current sources."""
    from tools.build_hia_json_preflight import admit_cold_build
    path = Path(cold_report).resolve(strict=True)
    raw = path.read_bytes()
    outer = decode(raw)
    outer_shape(outer)
    nested_path = Path(outer['nested_report']).resolve(strict=True)
    nested_raw = nested_path.read_bytes()
    require(digest(nested_raw) == outer['nested_report_sha256'], 'nested cold report changed')
    nested = decode(nested_raw)
    require(type(nested) is dict
            and nested.get('schema') == 'hepta.hia.selfhost-qualification.v6'
            and nested.get('status') == 'SELF_HOSTED_FIXED_CORE_PASS'
            and type(nested.get('checks')) is dict and nested['checks']
            and all(value is True for value in nested['checks'].values()),
            'nested complete original qualification required')
    rows = nested.get('generations')
    require(type(rows) is list and len(rows) == 3
            and all(type(row) is dict for row in rows), 'three actual cold generations required')
    paths = [Path(row['produced_image']).resolve(strict=True) for row in rows]
    images = [p.read_bytes() for p in paths]
    hashes = [digest(image) for image in images]
    require(all(0 < len(image) <= CAPACITY for image in images)
            and [row.get('produced_sha256') for row in rows] == hashes
            == outer.get('generation_sha256') and len(set(hashes)) == 1
            and all(type(row.get('produced_bytes')) is int
                    and row['produced_bytes'] == len(image) for row, image in zip(rows, images)),
            'cold fixed-point images or sizes differ')
    if compiler is not None:
        chosen = Path(compiler).resolve(strict=True)
        require(chosen.read_bytes() == images[-1], 'chosen compiler is not the actual cold B3')
    else:
        chosen = paths[-1]
    sources = admit_cold_build(images[-1], raw)
    require(nested.get('source_manifest') == sources
            and nested.get('profile') == outer.get('profile'),
            'nested and current source/profile identity differ')
    admit_required_sources(sources)
    bound = list(dict.fromkeys((path, nested_path, *paths, chosen)))
    result = {'schema': 'hepta.hia.linux-stdio-cold-inputs.v1',
        'cold_report': str(path), 'cold_report_sha256': digest(raw),
        'nested_report': str(nested_path), 'nested_report_sha256': digest(nested_raw),
        'compiler': str(chosen), 'compiler_sha256': hashes[-1],
        'actual_generations': [str(p) for p in paths],
        'source_manifest': sources, 'cold_profile': outer['profile'],
        'input_bindings': [pin(p) for p in bound]}
    guard_authority(result)
    return result


def guard_authority(authority):
    from tools.build_hia_json_preflight import current_sources
    check_bindings(authority['input_bindings'])
    require(current_sources() == authority['source_manifest'], 'full matching-cold source map changed')
    admit_required_sources(authority['source_manifest'])


def re_admit_authority(authority):
    require(type(authority) is dict, 'fresh original cold admission required')
    fresh = admit_cold(authority['cold_report'], compiler=authority['compiler'])
    require(fresh == authority, 'serialized fixture differs from freshly admitted cold authority')
    return fresh


def child_receipt(child, receipt):
    """Bind every original child field; this shape check grants no authority."""
    require(type(child) is dict and set(child) == CHILD_FIELDS
            and type(receipt) is dict and set(receipt) == CHILD_FIELDS | RECEIPT_HOST_FIELDS
            and all(wire(receipt[key]) == wire(child[key]) for key in CHILD_FIELDS),
            'actual child stdout differs from full receipt')


def observation(directory, label, provider, payload, *, extension='.image.bin'):
    """Re-read the exact original request, child stdout, receipt and full output."""
    from tools.qualify_hia_selfhost import CHILD, _compile_observation_size
    folder, provider = Path(directory), Path(provider)
    request_path = folder / (label + '.request.json')
    receipt_path = folder / (label + '.receipt.json')
    source_path = folder / (label + '.input.bin')
    output_path = folder / (label + '.output.bin')
    produced_path = folder / (label + extension)
    request = decode(request_path.read_bytes())
    receipt = decode(receipt_path.read_bytes())
    child = decode((folder / (label + '.stdout.log')).read_bytes())
    output = output_path.read_bytes()
    provider_raw = provider.read_bytes()
    require(type(payload) is bytes and 0 < len(provider_raw) <= CAPACITY,
            'exact bounded provider and payload bytes required')
    expected = {'capacity': CAPACITY, 'format': 'flat-x86-64',
        'image': str(provider.resolve()), 'image_sha256': digest(provider_raw),
        'output': str(output_path.resolve()), 'source': str(source_path.resolve()),
        'source_sha256': digest(payload), 'workspace_fill': 0, 'workspace_size': CAPACITY}
    require(type(request) is dict and wire(request) == wire(expected)
            and all(type(request[key]) is int for key in ('capacity', 'workspace_fill', 'workspace_size'))
            and source_path.read_bytes() == payload,
            'native request differs from captured inputs: ' + label)
    child_receipt(child, receipt)
    require((folder / (label + '.stderr.log')).read_bytes() == b'',
            'native child emitted unexpected stderr: ' + label)
    size = _compile_observation_size(receipt, output, image_format='flat-x86-64',
        compiler_sha256=digest(provider_raw), source_sha256=digest(payload), input_bytes=len(payload))
    require(size is not None and receipt.get('case') == label
            and receipt.get('runner_sha256') == digest(CHILD.read_bytes()),
            'actual compile receipt differs from inputs: ' + label)
    limits = receipt.get('limits')
    require(limits == {'address_bytes': 268435456, 'core_dumpable': False,
        'cpu_seconds': 10, 'output_capacity': CAPACITY,
        'stack_bytes': 8388608, 'workspace_bytes': CAPACITY}
        and limits['core_dumpable'] is False
        and all(type(limits[key]) is int for key in limits if key != 'core_dumpable'),
        'original native limits changed: ' + label)
    produced = output[:size]
    require(receipt.get('produced_image') == str(produced_path)
            and type(receipt.get('produced_bytes')) is int and receipt['produced_bytes'] == size
            and receipt.get('produced_sha256') == digest(produced)
            and produced_path.read_bytes() == produced,
            'published compiled bytes differ from complete actual output: ' + label)
    return produced_path, produced, receipt


def capture(path, raw):
    require(type(raw) is bytes, 'immutable capture required')
    with Path(path).open('xb') as stream:
        stream.write(raw)
    Path(path).chmod(0o400)
    require(Path(path).read_bytes() == raw, 'captured input readback differs')


def compile_bound(folder, label, provider, payload, authority, *, extension='.image.bin'):
    from tools.qualify_hia_selfhost import compile_stage
    guard_authority(authority)
    before = Path(provider).read_bytes()
    path, returned = compile_stage(Path(folder), label, Path(provider), payload,
                                   output_extension=extension)
    actual_path, produced, observed = observation(folder, label, provider, payload, extension=extension)
    require(path == actual_path and returned == observed and Path(provider).read_bytes() == before,
            'actual compiler stage or provider changed: ' + label)
    guard_authority(authority)
    return path, produced, observed
