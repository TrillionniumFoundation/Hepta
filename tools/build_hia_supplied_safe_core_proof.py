"""Build a self-contained HIA verifier of supplied scalar Core and paired ELF bytes."""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import struct

from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.build_hia_core_admission_cli import build as build_core
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_safe_core_binder import build as build_stage
from tools.generate_hia_native_filter import elf_header, read_adapter_binding, verify_adapter
from tools.generate_hia_supplied_safe_core_proof import SOURCE_PATH
from tools.generate_hia_supplied_safe_core_proof_packer import ADAPTER, MAGIC, PACKER, PACK_LIMIT, ROLE_TABLE
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable

ROOT = Path(__file__).resolve().parents[1]
HASH_SOURCE = 'examples/hia_bootstrap/sha256.hepta'


def digest(raw):
    return sha256(raw).hexdigest()


def package(packer_bytes, binding, images):
    if len(images) != 7 or any(not 0 < len(image) <= 1 << 20 for image in images):
        raise ValueError('supplied Safe Core executable stage extent differs')
    frame = struct.pack('<8Q', MAGIC, *map(len, images)) + b''.join(images)
    if len(frame) > 64 + PACK_LIMIT:
        raise ValueError('supplied Safe Core executable exceeds its packing bound')
    source = ctypes.create_string_buffer(frame, len(frame))
    output = ctypes.create_string_buffer(PACK_LIMIT)
    packer = NativeHiaJsonImage(packer_bytes, digest(packer_bytes))
    size = packer._entry(source, len(source), output, len(output), None, 0)
    if not len(elf_header()) < size <= len(output) or source.raw != frame or any(output.raw[size:]):
        raise ValueError('native supplied-proof packer refused or changed private bytes')
    binary = output.raw[:size]
    check_placement(binary, binding, images)
    return binary


def check_placement(binary, binding, images):
    adapter_digest, stub_size, (policy, hasher, table) = binding
    header = len(elf_header())
    table_at = header + table
    if table + ROLE_TABLE > stub_size:
        raise ValueError('supplied Safe Core executable table lies outside its syscall adapter')
    body = bytearray()
    starts = []
    for image in images:
        body.extend(bytes(-(stub_size + len(body)) % 8))
        starts.append(len(body))
        body.extend(image)
    for i, (offset, image) in enumerate(zip(starts[2:], images[2:], strict=True)):
        got = struct.unpack_from('<2Q', binary, table_at + 16 * i)
        if got != (stub_size + offset - table, len(image)):
            raise ValueError('HIA packer changed an embedded proof component boundary')
    masked = bytearray(binary)
    masked[table_at:table_at + ROLE_TABLE] = bytes(ROLE_TABLE)
    verify_adapter(masked, body, (adapter_digest, stub_size, (policy, hasher)), entries=starts[:2])


def build(output, compiler, cold_report):
    compiler_bytes, report_bytes = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_bytes, report_bytes)
    source_files = (SOURCE_PATH, HASH_SOURCE, ADAPTER, PACKER,
                    'tools/build_hia_supplied_safe_core_proof.py', 'tools/generate_hia_supplied_safe_core_proof.py',
                    'tools/generate_hia_supplied_safe_core_proof_packer.py')
    sources = {name: (ROOT / name).read_bytes() for name in source_files}
    if any(admitted.get(name) != digest(raw) for name, raw in sources.items()):
        raise ValueError('supplied Safe Core program differs from admitted cold source')
    binding = read_adapter_binding(sources[PACKER], sources[ADAPTER], calls=3)
    output.mkdir(mode=0o700)
    compiled = {}
    receipts = {}
    for label, name in (('policy', SOURCE_PATH), ('hasher', HASH_SOURCE), ('packer', PACKER)):
        path, receipt = compile_stage(output, label, compiler, sources[name])
        raw = path.read_bytes()
        if digest(raw) != receipt['produced_sha256']:
            raise ValueError('supplied Safe Core input differs from its native build receipt')
        compiled[label] = path, raw
        receipts[label] = receipt

    products = {'subject': build_core(output / 'subject', compiler, cold_report, proof_subject=True)}
    for label, options in (('binder', {}), ('machine', {'observe_machine': True}),
                           ('observations', {'join_observations': True}), ('obligation', {'prove_obligation': True})):
        products[label] = build_stage(output / label, compiler, cold_report, **options)
    retained = {}
    for label, path in products.items():
        raw = path.read_bytes()
        report_path = path.parent / 'build.json'
        proof = json.loads(report_path.read_bytes())
        expected = proof['executable_sha256'] if label == 'subject' else proof['native_executable_sha256']
        if digest(raw) != expected:
            raise ValueError('supplied Safe Core component differs from its native build receipt')
        retained[label] = path, raw
    binary = package(compiled['packer'][1], binding, (
        compiled['policy'][1], compiled['hasher'][1], *(raw for _, raw in retained.values()),
    ))
    inspection = inspect_executable(binary)
    if (current_sources() != admitted or compiler.read_bytes() != compiler_bytes
            or cold_report.read_bytes() != report_bytes
            or any(path.read_bytes() != raw for path, raw in (*compiled.values(), *retained.values()))):
        raise ValueError('supplied Safe Core build input changed before publication')
    target = output / 'hia-safe-core-prove'
    with target.open('xb') as stream:
        stream.write(binary)
    target.chmod(0o500)
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.supplied-safe-core-proof-build.v1',
        'compiler_sha256': digest(compiler_bytes),
        'cold_report_sha256': digest(report_bytes),
        'images': {label: digest(raw) for label, (_, raw) in retained.items()},
        'compile_receipts': receipts,
        'executable': inspection,
        'executable_sha256': digest(binary),
    }, indent=2, sort_keys=True) + '\n')
    return target


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))
