"""Pack a HIA Agent Linux/x86-64 descriptor carrier.

The carrier is fixed platform code, not a compiler or an alternate read policy.
The normal build compiles the checked-in HIA packer and needs no C toolchain,
assembler, oracle, runtime interpreter, or mutable link inputs.
"""
from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.build_hia_json_preflight import ROOT, admit_cold_build, current_sources
from tools.generate_hia_agent_discovery import ENTRY as DISCOVERY_POLICY, pack_seed, seed_source
from tools.generate_hia_agent_stdio import document, writes
from tools.generate_hia_core_json_cli import source_program
from tools.generate_hia_mcp_stdio_packer import elf_prefix
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable

SOURCE = 'examples/hia_bootstrap/agent_read_carrier_packer.hepta'
MAGIC = b'HIARCK01'
CODE_DIGEST = 'ae0d86e08bf8a687b85e6532cd9bb4e9fa65ac68a6e61e1c3fe5e8aaefa9ee34'
CODE_SIZE = 15800
HEADER_SIZE = 176
# Offsets in the audited ISA profile. Each group owns only delivery mechanics.
CARRIER_SECTIONS = (
    ('entry_and_abi', 0, 468),
    ('bounded_io', 468, 1426),
    ('closeout_and_buffers', 1426, 2595),
    ('sealed_launch', 2595, 3704),
    ('store_startup_and_transport', 3704, 5015),
    ('journal_receipt_routing', 5015, 6065),
    ('sealed_worker_and_read_relay', 6065, CODE_SIZE),
)


@dataclass(frozen=True)
class CarrierImage:
    source: str
    magic: bytes
    digest: str
    size: int
    sections: tuple
    compressed: bool = False
    tail_source: str = ''


CARRIERS = {
    'read': CarrierImage(SOURCE, MAGIC, CODE_DIGEST, CODE_SIZE, CARRIER_SECTIONS),
    'discovery': CarrierImage(
        'examples/hia_bootstrap/agent_discovery_carrier_packer.hepta', b'HIADCK01',
        '59aa176802d4cf359999f30af16ca5d381a722edc8a25c8edf73d64c4e165458', 8672,
        (('process_descriptors', 0, 2079), ('sealed_child_delivery', 2079, 3414),
         ('publication_and_store_transport', 3414, 4156), ('discovery_relay', 4156, 8672))),
    'input': CarrierImage(
        'examples/hia_bootstrap/agent_input_carrier_packer.hepta', b'HIAICK01',
        '822069b4538ff3a9c646f595737c4db62c505cc55cd0491db60b502e7765c583', 7984,
        (('descriptor_io', 0, 1923), ('sealed_process_and_publisher', 1923, 3027),
         ('typed_store_transport', 3027, 3758), ('input_relay', 3758, 7984))),
    'discovery-bootstrap': CarrierImage(
        'examples/hia_bootstrap/agent_discovery_bootstrap_carrier_packer.hepta', b'HIADBK01',
        '2d64152b9ea70a8fe0927567f76c96659cae027455cca7c3741e13412b33e7ea', 9590,
        (('entry_and_directory_custody', 0, 1657), ('bounded_children_and_io', 1657, 3643),
         ('document_render_and_retention', 3643, 4595),
         ('bootstrap_loop_and_closeout', 4595, 9590))),
    'artifact-worker': CarrierImage(
        'examples/hia_bootstrap/agent_artifact_worker_carrier_packer.hepta', b'HIAAWK01',
        '1c126bdcdb58d798294f759a60a906c8d038378b092b677066b7076cf0376563', 18592,
        (('descriptor_io_and_child_ownership', 0, 3762),
         ('store_and_journal_frames', 3762, 6669),
         ('immutable_input_and_worker_relay', 6669, 18592))),
    'context-worker': CarrierImage(
        'examples/hia_bootstrap/agent_context_worker_carrier_packer.hepta', b'HIACTK01',
        '4462cca8fdaf7ccfeece9179e3991929960792bfd78100aedefc5ad82cebed41', 27928,
        (('platform_io_and_custody', 0, 3572), ('sealed_children_and_store', 3572, 6564),
         ('receipt_and_artifact_transfer', 6564, 9590), ('context_effect_delivery', 9590, 27928)),
        compressed=True),
    'inspection-worker': CarrierImage(
        'examples/hia_bootstrap/agent_inspection_worker_carrier_packer.hepta', b'HIAIWK01',
        'c716eb86454b4093e98d4e922543646535eb6043b7a8113b6950a49bc8f51d3b', 51568,
        (('program_descriptor_effect_relay', 0, 51568),), compressed=True,
        tail_source='examples/hia_bootstrap/agent_inspection_worker_carrier_tail.hepta'),
    'rollback-worker': CarrierImage(
        'examples/hia_bootstrap/agent_rollback_worker_carrier_packer.hepta', b'HIARWK01',
        'd31772123d69363f27680a569fe0c6f38faeaaa893c7266dd1479195c3ac9f50', 49072,
        (('conditional_store_descriptor_relay', 0, 49072),), compressed=True,
        tail_source='examples/hia_bootstrap/agent_rollback_worker_carrier_tail.hepta'),
    'describe-worker': CarrierImage(
        'examples/hia_bootstrap/agent_describe_worker_carrier_packer.hepta', b'HIADWK01',
        'd3b3b68645a247e27e7081e475e38e0333186bd0983199bbe2a123fa3454fec1', 11258,
        (('worker_entry_and_custody', 0, 1200), ('worker_descriptor_transfer', 1200, 3333),
         ('worker_journal_relay', 3333, 4217), ('describe_effect_relay', 4217, 9513),
         ('isolated_worker_main', 9513, 11258))),
}


def author(platform_code, *, kind='read'):
    """Render the canonical HIA source from separately reviewed ISA bytes."""
    carrier = CARRIERS[kind]
    if len(platform_code) != carrier.size or sha256(platform_code).hexdigest() != carrier.digest:
        raise ValueError('unrecognized Agent carrier ISA profile')
    prefix = elf_prefix(platform_code)
    size = len(prefix)
    if carrier.tail_source:
        return compressed_carrier(prefix[:carrier_split(carrier)], carrier,
                                  tail_size=len(prefix) - carrier_split(carrier))
    if carrier.compressed:
        return compressed_carrier(prefix, carrier)
    source = f"""def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 8 or read_word(s, 0) != {int.from_bytes(carrier.magic, 'little')}:
        return 4294967295
    if length(o) < {size}:
        return 4294967294
    elf_header(o)
"""
    sections = {'elf_header': (0, HEADER_SIZE)}
    for name, start, end in carrier.sections:
        for begin in range(start, end, 512):
            chunk = f'{name}_{begin}'
            sections[chunk] = (HEADER_SIZE + begin, HEADER_SIZE + min(end, begin + 512))
            source += f'    {chunk}(o)\n'
    source += f"""    put_word(o, 96, {size})
    put_word(o, 104, {size})
    return {size}
"""
    for label, (begin, end) in sections.items():
        source += f'\ndef {label}(o:mutbuf) -> u64:\n'
        source += writes(prefix[begin:end], offset=begin)
        source += '    return 0\n'
    helpers = source_program()
    source += helpers[helpers.index('\ndef read_word('):helpers.index('\ndef put_four(')]
    return render_assembly(document(source, Path(carrier.source).stem))


def carrier_split(carrier):
    return (carrier.size + HEADER_SIZE) // 2


def author_tail(platform_code, carrier):
    return compressed_carrier(elf_prefix(platform_code)[carrier_split(carrier):],
                              carrier, component=True)


def compressed_carrier(payload, carrier, *, tail_size=0, component=False):
    packed = pack_seed(payload, history=128)
    extent = len(payload)
    total = extent + tail_size
    workspace = extent + len(packed)
    finish = ''
    if not component:
        if tail_size:
            finish = f"""    while index < {total}:
        store(o, index, byte(s, 8 + index - {extent}))
        index = index + 1
"""
        finish += f'    put_word(o, 96, {total})\n    put_word(o, 104, {total})\n'
    source = f"""def pack(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != {8 + tail_size} or read_word(s, 0) != {int.from_bytes(carrier.magic, 'little')}:
        return 4294967295
    if length(o) < {total} or length(w) < {workspace}:
        return 4294967294
    seed(w)
    if unpack_table(w) == 0:
        return 4294967295
    index = 0
    while index < {extent}:
        store(o, index, byte(w, index))
        index = index + 1
{finish}    return {total}
"""
    unpack = DISCOVERY_POLICY[DISCOVERY_POLICY.index('\ndef unpack_table('):
                              DISCOVERY_POLICY.index('\ndef same_backend(')]
    source += unpack.replace('PACK_START', str(extent)).replace('PACK_END', str(workspace))
    source += seed_source(packed, offset=extent)
    words = source_program()
    source += words[words.index('\ndef read_word('):words.index('\ndef put_four(')]
    name = carrier.tail_source if component else carrier.source
    return render_assembly(document(source, Path(name).stem))


def build(output, compiler, cold_report, *, kind='read'):
    """Use the cold compiler to pack the exact admitted native carrier ELF."""
    if kind == 'read':
        from tools.build_hia_worker_read_release import build as build_read_flow
        return build_read_flow(output, compiler, cold_report)
    if kind == 'describe-worker':
        from tools.build_hia_worker_flow import build as build_describe_flow
        return build_describe_flow(output, compiler, cold_report)
    carrier = CARRIERS[kind]
    source_path = ROOT / carrier.source
    report, seed, source = cold_report.read_bytes(), compiler.read_bytes(), source_path.read_bytes()
    admitted = admit_cold_build(seed, report)
    if admitted[carrier.source] != sha256(source).hexdigest():
        raise ValueError('Agent carrier must use the cold-admitted HIA source')
    output.mkdir(mode=0o700)
    packer, receipt = compile_stage(output, kind + '-carrier-packer', compiler, source)
    packed_program = packer.read_bytes()
    program = NativeHiaJsonImage(packed_program, receipt['produced_sha256'])
    size = HEADER_SIZE + carrier.size
    frame = carrier.magic
    component_receipt = {}
    if carrier.tail_source:
        tail_path = ROOT / carrier.tail_source
        tail_source = tail_path.read_bytes()
        if admitted[carrier.tail_source] != sha256(tail_source).hexdigest():
            raise ValueError('Agent carrier tail must use the cold-admitted HIA source')
        tail_packer, tail_receipt = compile_stage(output, kind + '-carrier-tail', compiler, tail_source)
        tail_image = tail_packer.read_bytes()
        tail = NativeHiaJsonImage(tail_image, tail_receipt['produced_sha256'])
        tail_request = ctypes.create_string_buffer(carrier.magic)
        tail_result = ctypes.create_string_buffer(size - carrier_split(carrier))
        tail_workspace = ctypes.create_string_buffer(2 * len(tail_result))
        tail_count = tail._entry(tail_request, len(carrier.magic), tail_result, len(tail_result),
                                 tail_workspace, len(tail_workspace))
        if tail_count != len(tail_result) or tail_request.raw != carrier.magic + b'\0':
            raise ValueError('Agent carrier tail packer refused its exact component extent')
        frame += tail_result.raw
        component_receipt['tail_compilation'] = tail_receipt
    request = ctypes.create_string_buffer(frame)
    result = ctypes.create_string_buffer(size)
    workspace = ctypes.create_string_buffer(2 * size) if carrier.compressed else None
    count = program._entry(request, len(frame), result, size, workspace,
                           len(workspace) if workspace is not None else 0)
    executable = result.raw
    if (count != size or request.raw != frame + b'\0'
            or sha256(executable[HEADER_SIZE:]).hexdigest() != carrier.digest):
        raise ValueError('Agent carrier packer did not produce the admitted platform image')
    expected_header = bytearray(elf_prefix(b''))
    for offset in (96, 104):
        expected_header[offset:offset + 8] = size.to_bytes(8, 'little')
    if (executable[:HEADER_SIZE] != expected_header
            or author(executable[HEADER_SIZE:], kind=kind).encode() != source):
        raise ValueError('Agent carrier platform header or source is noncanonical')
    if carrier.tail_source and (
            author_tail(executable[HEADER_SIZE:], carrier).encode() != tail_source
            or tail_path.read_bytes() != tail_source or tail_packer.read_bytes() != tail_image):
        raise ValueError('Agent carrier tail source or image changed before publication')
    elf = inspect_executable(executable)
    if (current_sources() != admitted or source_path.read_bytes() != source
            or compiler.read_bytes() != seed or cold_report.read_bytes() != report
            or packer.read_bytes() != packed_program):
        raise ValueError('Agent carrier inputs changed before publication')
    target = output / ('hia-agent-' + kind + '-carrier')
    with target.open('xb') as stream:
        stream.write(executable)
    target.chmod(0o500)
    with (output / 'build.json').open('x') as stream:
        json.dump({
            'schema': 'hepta.hia.agent-' + kind + '-carrier-stdio-build.v1',
            'source_sha256': admitted[carrier.source], 'platform_sha256': carrier.digest,
            'executable_sha256': sha256(executable).hexdigest(),
            'packer_compilation': receipt, 'elf': elf, **component_receipt,
        }, stream, indent=2)
        stream.write('\n')
    return target


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--kind', choices=CARRIERS, default='read')
    args = parser.parse_args()
    print(build(args.output, args.compiler, args.cold_report, kind=args.kind))
