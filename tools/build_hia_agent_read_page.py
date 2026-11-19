"""Build sealed HIA page, journal and MCP wire executables."""
from __future__ import annotations

import argparse
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import struct

from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_sqlite_pager import EMBED_SOURCE, assemble, build_embedder, embed, link
from tools.generate_hia_mcp_stdio_packer import MAGIC as MCP_PACK_MAGIC, MODES as MCP_MODES
from tools.generate_hia_mcp_stdio_packer import DESCRIPTORS, template
from tools.generate_hia_mcp_stdio_packer import SOURCE as MCP_PACKER
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable

ROOT = Path(__file__).resolve().parents[1]
LINKER = 'examples/hia_bootstrap/elf_static_linker.hepta'
DRIVER = 'tools/build_hia_agent_read_page.py'
VARIANTS = {
    'read-page': ('agent_read_page', 'hepta.hia.agent-read-page-native.v1'),
    'journal': ('agent_journal', 'hepta.hia.agent-journal-native.v2'),
    'mcp-request': ('mcp_request_route', 'hepta.hia.mcp-request-native.v1'),
    'mcp-reply': ('mcp_reply_wire', 'hepta.hia.mcp-reply-native.v1'),
    'mcp-negotiation': ('mcp_negotiation', 'hepta.hia.mcp-negotiation-native.v1'),
    'mcp-catalog': ('mcp_catalog_wire', 'hepta.hia.mcp-catalog-native.v1'),
    'mcp-uri': ('mcp_resource_uri', 'hepta.hia.mcp-uri-native.v1'),
}
MCP_PACK_CAPACITY = (1 << 20) + 4096


def pack_mcp(output, compiler, sources, mode, image, pins):
    packer, compiled = compile_stage(output, 'mcp-packer', compiler, sources[MCP_PACKER])
    pins[packer] = packer.read_bytes()
    program = NativeHiaJsonImage(pins[packer], compiled['produced_sha256'])
    request = struct.pack('<2Q', MCP_PACK_MAGIC, mode) + image
    input_bytes = ctypes.create_string_buffer(request)
    result = ctypes.create_string_buffer(MCP_PACK_CAPACITY)
    count = program._entry(input_bytes, len(request), result, len(result), None, 0)

    prefix, call = template(DESCRIPTORS[mode])
    expected_size = len(prefix) + len(image)
    if (count != expected_size or input_bytes.raw != request + b'\0'
            or any(result.raw[count:])):
        raise ValueError('native HIA MCP packer refused or changed private bytes')
    expected = bytearray(prefix)
    struct.pack_into('<2Q', expected, 96, count, count)
    struct.pack_into('<i', expected, call, len(prefix) - call - 4)
    executable = result.raw[:count]
    if executable[:len(prefix)] != expected or not executable.endswith(image):
        raise ValueError('packed MCP adapter or kernel differs from the admitted bytes')
    return executable, {'elf': inspect_executable(executable), 'mode': mode,
                        'packer_compilation': compiled, 'input_sha256': sha256(request).hexdigest()}


def build(output, compiler, cold_report, manifest, *, kind='read-page'):
    symbol, schema = VARIANTS[kind]
    label = 'agent-' + kind
    source = 'examples/hia_bootstrap/' + symbol + '.hepta'
    mode = MCP_MODES.get(kind)
    adapter = 'tools/hia_' + symbol + '_stdio.S'
    assembly_inputs = (LINKER, EMBED_SOURCE, adapter) if mode is None else (MCP_PACKER,)
    pins = {path: path.read_bytes() for path in (compiler, cold_report, manifest)}
    sources = {name: (ROOT / name).read_bytes() for name in (source, DRIVER, *assembly_inputs)}
    source_digests = {name: sha256(raw).hexdigest() for name, raw in sources.items()}
    admitted = admit_cold_build(pins[compiler], pins[cold_report])
    if any(admitted.get(name) != digest for name, digest in source_digests.items()):
        raise ValueError(label + ' build needs matching cold sources')
    record = json.loads(pins[manifest])
    if (record.get('schema') != schema
            or record.get('compiler_sha256') != sha256(pins[compiler]).hexdigest()
            or record.get('source_sha256') != source_digests[source]
            or Path(record['image_path']).name != record['image_path']):
        raise ValueError(label + ' image manifest does not match this cold build')
    image_path = manifest.parent / record['image_path']
    image = pins[image_path] = image_path.read_bytes()
    if not 0 < len(image) <= 1 << 20 or sha256(image).hexdigest() != record['image_sha256']:
        raise ValueError(label + ' image does not match its manifest')
    output.mkdir(mode=0o700)
    build_receipt = {}
    if mode is None:
        linker_path, linker_receipt = compile_stage(output, 'linker', compiler, sources[LINKER])
        linker = pins[linker_path] = linker_path.read_bytes()
        if sha256(linker).hexdigest() != linker_receipt['produced_sha256']:
            raise ValueError(label + ' linker changed')
        embedder = build_embedder(output, compiler, sources[EMBED_SOURCE])
        objects = (assemble(output, adapter, sources[adapter]),
                   embed(output, symbol, kind, image, embedder))
        executable, receipt = link(output, linker, image, objects, wire_magic=b'HIALNK01')
        build_receipt['linking'] = receipt
    else:
        executable, receipt = pack_mcp(output, compiler, sources, mode, image, pins)
        build_receipt['native_packing'] = receipt
    if (current_sources() != admitted or any(path.read_bytes() != raw for path, raw in pins.items())
            or any((ROOT / name).read_bytes() != raw for name, raw in sources.items())):
        raise ValueError(label + ' inputs changed before publishing')
    target = output / ('hia-' + label)
    with target.open('xb') as stream:
        stream.write(executable)
    target.chmod(0o500)
    with (output / 'build.json').open('x') as stream:
        json.dump({'schema': 'hepta.hia.' + label + '-stdio-build.v1',
                   'source_sha256': source_digests, 'binding': record,
                   'executable_sha256': sha256(executable).hexdigest(), **build_receipt}, stream, indent=2)
        stream.write('\n')
    return target


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report', 'manifest'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--kind', choices=VARIANTS, default='read-page')
    args = parser.parse_args()
    print(build(args.output, args.compiler, args.cold_report, args.manifest, kind=args.kind))
