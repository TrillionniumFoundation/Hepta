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
from tools.generate_hia_agent_journal_transport import SOURCE as JOURNAL_TRANSPORT
from tools.generate_hia_journal_stdio_packer import (
    MAGIC as JOURNAL_PACK_MAGIC, SOURCE as JOURNAL_PACKER, template as journal_template,
)
from tools.generate_hia_mcp_stdio_packer import MAGIC as STDIO_PACK_MAGIC, MODES as STDIO_MODES
from tools.generate_hia_mcp_stdio_packer import template
from tools.generate_hia_mcp_stdio_packer import SOURCE as STDIO_PACKER
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable

ROOT = Path(__file__).resolve().parents[1]
DRIVER = 'tools/build_hia_agent_read_page.py'
VARIANTS = {
    'read-page': ('agent_read_page', 'hepta.hia.agent-read-page-native.v1'),
    'store-unique': ('agent_store_transport', 'hepta.hia.agent-store-transport-native.v1'),
    'store-ready': ('agent_store_transport', 'hepta.hia.agent-store-transport-native.v1'),
    'read-request': ('agent_read_request', 'hepta.hia.agent-read-request-native.v1'),
    'read-effect': ('agent_read_request', 'hepta.hia.agent-read-request-native.v1'),
    'journal': ('agent_journal', 'hepta.hia.agent-journal-native.v2'),
    'journal-cost': ('agent_journal_transport', 'hepta.hia.journal-cost-native.v1'),
    'journal-read-workflow': ('agent_journal_transport', 'hepta.hia.journal-cost-native.v1'),
    'worker-arguments': ('worker_request', 'hepta.hia.worker-request-native.v1'),
    'worker-canonical': ('worker_request', 'hepta.hia.worker-request-native.v1'),
    'describe-request': ('worker_describe_request', 'hepta.hia.worker-describe-request-native.v1'),
    'artifact-request': ('worker_artifact_request', 'hepta.hia.worker-artifact-request-native.v1'),
    'journal-records': ('worker_journal_records', 'hepta.hia.journal-records-native.v1'),
    'journal-observation': ('worker_journal_observation', 'hepta.hia.journal-observation-native.v1'),
    'artifact-authority': ('worker_artifact_authority', 'hepta.hia.artifact-authority-native.v1'),
    'artifact-diagnostic': ('worker_artifact_diagnostic', 'hepta.hia.artifact-diagnostic-native.v1'),
    'context-store': ('worker_context_store', 'hepta.hia.context-store-native.v1'),
    'context-record': ('worker_context_record', 'hepta.hia.context-record-native.v1'),
    'context-request': ('worker_context_request', 'hepta.hia.context-request-native.v1'),
    'inspection-request': ('worker_inspection_request', 'hepta.hia.inspection-request-native.v1'),
    'inspection-effect': ('worker_inspection_effect', 'hepta.hia.inspection-effect-native.v1'),
    'inspection-lowering-elf': ('inspection_lowering_elf', 'hepta.hia.inspection-lowering-elf-native.v1'),
    'inspection-lowering-frames': ('inspection_lowering_frames', 'hepta.hia.inspection-lowering-frames-native.v1'),
    'context-workload': ('worker_context_workload', 'hepta.hia.context-workload-native.v1'),
    'context-cost': ('worker_context_cost', 'hepta.hia.context-cost-native.v1'),
    'context-cost-diagnostic': ('worker_context_cost_diagnostic', 'hepta.hia.context-cost-diagnostic-native.v1'),
    'context-effect': ('worker_context_effect', 'hepta.hia.context-effect-native.v1'),
    'context-diagnostic': ('worker_context_diagnostic', 'hepta.hia.context-diagnostic-native.v1'),
    'context-journal': ('worker_context_journal', 'hepta.hia.context-journal-native.v1'),
    'context-journal-records': ('worker_context_journal_records', 'hepta.hia.context-journal-records-native.v1'),
    'context-journal-observation': ('worker_context_journal_observation', 'hepta.hia.context-journal-observation-native.v1'),
    'context-payload': ('agent_payload_schema', 'hepta.hia.agent-payload-schema-native.v1'),
    'inspection-wire': ('agent_inspection', 'hepta.hia.agent-inspection-native.v1'),
    'artifact-journal': ('worker_artifact_journal', 'hepta.hia.artifact-journal-native.v1'),
    'discovery': ('agent_discovery', 'hepta.hia.agent-discovery-native.v1'),
    'describe-answer': ('agent_describe_answer', 'hepta.hia.agent-describe-answer-native.v1'),
    'discovery-artifact': ('discovery_artifact', 'hepta.hia.discovery-artifact-native.v1'),
    'discovery-effect': ('discovery_effect', 'hepta.hia.discovery-effect-native.v1'),
    'describe-bind': ('describe_bind', 'hepta.hia.describe-bind-native.v1'),
    'discovery-bootstrap-assemble': ('discovery_bootstrap_assemble', 'hepta.hia.discovery-bootstrap-assemble-native.v1'),
    'discovery-bootstrap-plan': ('discovery_bootstrap_plan', 'hepta.hia.discovery-bootstrap-plan-native.v1'),
    'mcp-request': ('mcp_request_route', 'hepta.hia.mcp-request-native.v1'),
    'mcp-reply': ('mcp_reply_wire', 'hepta.hia.mcp-reply-native.v1'),
    'job-terminal-receipt': ('job_terminal_receipt', 'hepta.hia.job-terminal-receipt-native.v1'),
    'mcp-terminal': ('mcp_terminal_admission', 'hepta.hia.mcp-terminal-native.v1'),
    'mcp-negotiation': ('mcp_negotiation', 'hepta.hia.mcp-negotiation-native.v1'),
    'mcp-connection': ('mcp_connection', 'hepta.hia.mcp-connection-native.v1'),
    'mcp-catalog': ('mcp_catalog_wire', 'hepta.hia.mcp-catalog-native.v1'),
    'mcp-uri': ('mcp_resource_uri', 'hepta.hia.mcp-uri-native.v1'),
    'mcp-input-schema': ('agent_schema', 'hepta.hia.agent-schema-native.v1'),
    'mcp-response-schema': ('agent_response_schema', 'hepta.hia.agent-response-schema-native.v1'),
    'mcp-proof-schema': ('agent_verify_response_schema', 'hepta.hia.agent-verify-response-schema-native.v1'),
}
IMAGE_LIMIT = 1 << 20


def pack_elf(output, compiler, source, request, prefix, relocations, images, pins):
    packer, compiled = compile_stage(output, 'stdio-packer', compiler, source)
    pins[packer] = packer.read_bytes()
    program = NativeHiaJsonImage(pins[packer], compiled['produced_sha256'])
    input_bytes = ctypes.create_string_buffer(request)
    result = ctypes.create_string_buffer(len(images) * IMAGE_LIMIT + 4096)
    count = program._entry(input_bytes, len(request), result, len(result), None, 0)

    raw_images = b''.join(images)
    expected_size = len(prefix) + len(raw_images)
    if (count != expected_size or input_bytes.raw != request + b'\0'
            or any(result.raw[count:])):
        raise ValueError('native HIA stdio packer refused or changed private bytes')
    expected = bytearray(prefix)
    struct.pack_into('<2Q', expected, 96, count, count)
    for address, image_offset in relocations:
        struct.pack_into('<i', expected, address, len(prefix) + image_offset - address - 4)
    executable = result.raw[:count]
    if executable[:len(prefix)] != expected or executable[len(prefix):] != raw_images:
        raise ValueError('packed stdio adapter or kernel differs from the admitted bytes')
    return executable, {'elf': inspect_executable(executable),
                        'packer_compilation': compiled, 'input_sha256': sha256(request).hexdigest()}


def pack_stdio(output, compiler, sources, mode, image, pins):
    prefix, call = template(mode)
    request = struct.pack('<2Q', STDIO_PACK_MAGIC, mode) + image
    executable, receipt = pack_elf(output, compiler, sources[STDIO_PACKER], request, prefix,
                                   ((call, 0),), (image,), pins)
    return executable, {**receipt, 'mode': mode}


def build(output, compiler, cold_report, manifest, *, kind='read-page'):
    symbol, schema = VARIANTS[kind]
    label = 'agent-' + kind
    source = 'examples/hia_bootstrap/' + symbol + '.hepta'
    mode = STDIO_MODES.get(kind)
    pack_inputs = (JOURNAL_TRANSPORT, JOURNAL_PACKER) if kind == 'journal' else (STDIO_PACKER,)
    pins = {path: path.read_bytes() for path in (compiler, cold_report, manifest)}
    sources = {name: (ROOT / name).read_bytes() for name in (source, DRIVER, *pack_inputs)}
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
    if not 0 < len(image) <= IMAGE_LIMIT or sha256(image).hexdigest() != record['image_sha256']:
        raise ValueError(label + ' image does not match its manifest')
    output.mkdir(mode=0o700)
    build_receipt = {}
    if mode is None:
        transport_path, transport_receipt = compile_stage(
            output, 'journal-wire', compiler, sources[JOURNAL_TRANSPORT])
        transport = pins[transport_path] = transport_path.read_bytes()
        if sha256(transport).hexdigest() != transport_receipt['produced_sha256']:
            raise ValueError(label + ' transport differs from its compilation receipt')
        prefix, (primary, codec) = journal_template()
        request = struct.pack('<3Q', JOURNAL_PACK_MAGIC, len(image), len(transport)) + image + transport
        executable, receipt = pack_elf(
            output, compiler, sources[JOURNAL_PACKER], request, prefix,
            ((primary, 0), (codec, len(image))), (image, transport), pins)
        build_receipt['journal_wire_compilation'] = transport_receipt
    else:
        executable, receipt = pack_stdio(output, compiler, sources, mode, image, pins)
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
