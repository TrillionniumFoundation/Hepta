"""Fresh current-source cold custody for the explicit Linux process profile.

This hosted qualifier checks original cold authority and actual bounded child
receipts. It grants no authority to a development digest, startup snapshot, or
serialized fixture. The underlying stdio checks and their full source domain
remain required; process inputs add to that domain.
"""
from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools import hia_linux_stdio_cold as _stdio
from hepta.hia_linux_process import PROFILE

CAPACITY = _stdio.CAPACITY
COMPILER_SOURCE = 'examples/hia_bootstrap/selfhost_linux_process.hepta'
PACKER_SOURCE = 'examples/hia_bootstrap/linux_process_entry_packer.hepta'
ORDINARY_SOURCE = _stdio.ORDINARY_SOURCE
AUTHORITY_SCHEMA = 'hepta.hia.linux-process-cold-inputs.v1'
RETAINED_INPUTS = 'tests/fixtures/hia_linux_process_retained_controls.json'
RETAINED_INPUTS_SHA256 = '7a308746f98a62627ac1449d9391ad72ab3c17dd9b70c089bf8ca874731e66ba'
PROCESS_SOURCES = (
    COMPILER_SOURCE, PACKER_SOURCE, 'hepta/hia_linux_process.py',
    'tools/generate_hia_selfhost_linux_process.py',
    'tools/generate_hia_linux_process_entry.py',
    'tools/build_hia_linux_process_program.py',
    'tools/hia_linux_process_cold.py', 'tools/build_hia_linux_process_cold.py',
    'tools/qualify_hia_linux_process.py', 'tests/test_hia_linux_process.py',
    'tests/hia_linux_process_programs.py', 'tests/hia_linux_process_cases.py',
    'tests/hia_linux_process_cold_cases.py',
    'tests/hia_linux_process_buffer_observer.py',
    'tests/hia_linux_process_buffer_child.py',
    'tests/hia_linux_process_startup_fault_observer.py',
    'tests/test_hia_linux_process_cold.py', RETAINED_INPUTS,
    'docs/HIA_LINUX_PROCESS_COLD.md',
)
REQUIRED_SOURCES = tuple(dict.fromkeys((*_stdio.REQUIRED_SOURCES, *PROCESS_SOURCES)))
require = _stdio.require
digest = _stdio.digest
decode = _stdio.decode
wire = _stdio.wire
publish = _stdio.publish
pin = _stdio.pin
check_bindings = _stdio.check_bindings
outer_shape = _stdio.outer_shape
child_receipt = _stdio.child_receipt
observation = _stdio.observation
capture = _stdio.capture


def retained_inputs():
    raw = (ROOT / RETAINED_INPUTS).read_bytes()
    require(digest(raw) == RETAINED_INPUTS_SHA256, 'complete retained process inputs changed')
    value = decode(raw)
    require(value.get('schema') == 'hepta.hia.linux-process-retained-controls.v1'
            and value.get('native_or_cold_qualification') is False,
            'retained observations are inputs, not current-cold authority')
    return value


def admit_required_sources(sources, *, root=ROOT, names=REQUIRED_SOURCES):
    _stdio.admit_required_sources(sources, root=root, names=names)


def admit_cold(cold_report, *, compiler=None):
    authority = _stdio.admit_cold(cold_report, compiler=compiler)
    admit_required_sources(authority['source_manifest'])
    authority = {**authority, 'schema': AUTHORITY_SCHEMA, 'physical_profile': PROFILE}
    guard_authority(authority)
    return authority


def guard_authority(authority):
    require(type(authority) is dict and authority.get('schema') == AUTHORITY_SCHEMA
            and authority.get('physical_profile') == PROFILE,
            'explicit process current-cold authority required')
    _stdio.guard_authority(authority)
    admit_required_sources(authority['source_manifest'])


def re_admit_authority(authority):
    require(type(authority) is dict and authority.get('schema') == AUTHORITY_SCHEMA
            and authority.get('physical_profile') == PROFILE,
            'fresh original process cold admission required')
    fresh = admit_cold(authority['cold_report'], compiler=authority['compiler'])
    require(fresh == authority, 'serialized process fixture differs from fresh cold authority')
    return fresh


def compile_bound(folder, label, provider, payload, authority, *, extension='.image.bin'):
    from tools.qualify_hia_selfhost import compile_stage
    guard_authority(authority)
    before = Path(provider).read_bytes()
    path, returned = compile_stage(Path(folder), label, Path(provider), payload,
                                   output_extension=extension)
    actual_path, produced, observed = observation(folder, label, provider, payload, extension=extension)
    require(path == actual_path and returned == observed and Path(provider).read_bytes() == before,
            'actual process compiler stage or provider changed: ' + label)
    guard_authority(authority)
    return path, produced, observed


def probe_observation(directory, label, provider, payload):
    """Read a rejecting or successful original compiler probe without a build claim."""
    from tools.qualify_hia_selfhost import CHILD
    folder, provider = Path(directory), Path(provider)
    source_path = folder / (label + '.input.bin')
    output_path = folder / (label + '.output.bin')
    request = decode((folder / (label + '.request.json')).read_bytes())
    receipt = decode((folder / (label + '.receipt.json')).read_bytes())
    child = decode((folder / (label + '.stdout.log')).read_bytes())
    provider_raw = provider.read_bytes()
    output = output_path.read_bytes()
    expected = {'capacity': CAPACITY, 'format': 'flat-x86-64',
        'image': str(provider.resolve()), 'image_sha256': digest(provider_raw),
        'output': str(output_path.resolve()), 'source': str(source_path.resolve()),
        'source_sha256': digest(payload), 'workspace_fill': 0, 'workspace_size': CAPACITY}
    host_fields = _stdio.RECEIPT_HOST_FIELDS - {'produced_bytes', 'produced_image', 'produced_sha256'}
    require(type(request) is dict and wire(request) == wire(expected)
            and all(type(request[key]) is int for key in ('capacity', 'workspace_fill', 'workspace_size'))
            and type(payload) is bytes and source_path.read_bytes() == payload,
            'probe request differs from the actual captured input: ' + label)
    require(type(child) is dict and set(child) == _stdio.CHILD_FIELDS
            and type(receipt) is dict and set(receipt) == _stdio.CHILD_FIELDS | host_fields
            and all(wire(child[key]) == wire(receipt[key]) for key in child),
            'actual child stdout differs from full probe receipt: ' + label)
    require((folder / (label + '.stderr.log')).read_bytes() == b''
            and receipt.get('case') == label and receipt.get('status') == 'returned'
            and type(receipt.get('abi_status')) is int and receipt['abi_status'] == 0
            and type(receipt.get('core_u32')) is int and 0 <= receipt['core_u32'] <= 0xffffffff
            and type(receipt.get('result_u64')) is int and receipt['result_u64'] == receipt['core_u32']
            and receipt.get('return_encoding') == 'zero-extended-u32'
            and receipt.get('forbidden_compiler_modules_loaded') == []
            and receipt.get('format') == 'flat-x86-64'
            and receipt.get('artifact_sha256') == receipt.get('image_sha256') == digest(provider_raw)
            and receipt.get('source_sha256') == receipt.get('input_sha256') == digest(payload)
            and type(receipt.get('input_bytes')) is int and receipt['input_bytes'] == len(payload)
            and receipt.get('source_unchanged') is True
            and receipt.get('runner_sha256') == digest(CHILD.read_bytes())
            and len(output) == CAPACITY and receipt.get('output_sha256') == digest(output),
            'actual probe outcome/provider/source differs: ' + label)
    limits = receipt.get('limits')
    require(limits == {'address_bytes': 268435456, 'core_dumpable': False,
        'cpu_seconds': 10, 'output_capacity': CAPACITY, 'stack_bytes': 8388608,
        'workspace_bytes': CAPACITY} and limits['core_dumpable'] is False
        and all(type(value) is int for key,value in limits.items() if key != 'core_dumpable'),
        'original probe resource limits changed: ' + label)
    return receipt, output
