"""Cold-build native Core query, edit, impact and publication executables."""

import argparse
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import re
import struct

from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.build_hia_agent_batch_commit import ELF_HEADER_SIZE
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_nominal_constructor import (
    ADAPTER as NOMINAL_ADAPTER, COMPONENTS as NOMINAL_COMPONENTS,
    NOMINAL_IMAGE_LABELS, ORDINARY_CLI_IMAGE_CAPACITY,
    build as build_nominal_constructor,
)
from tools.build_hia_sqlite_pager import EMBED_SOURCE, embed, link, load_static_object, verify_executable
from tools.generate_hia_core_edit_packer import MAGIC
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = 'examples/hia_bootstrap/'
EDIT = BOOTSTRAP + 'core_edit/'
CLI = BOOTSTRAP + 'core_cli/'
CORE_ADMISSION = BOOTSTRAP + 'core_admission.hepta'
PACKER = EDIT + 'packer.hepta'
STATIC_ADAPTERS = (EDIT + 'adapter_templates_a.hepta', EDIT + 'adapter_templates_b.hepta')
ADAPTER_RECORD = struct.Struct('<32s32s32sQQ')
NOMINAL_ADAPTER_GROUPS = tuple(EDIT + f'nominal_adapters_{group}.hepta' for group in 'abcde')
NOMINAL_CONSTRUCTOR_GROUP = EDIT + 'nominal_constructor_adapter.hepta'
CAPACITY = 4 * (1 << 20) + 4096
DISPATCH = CLI + 'dispatch.hepta'
DISPATCH_ARCHIVE = '<public-dispatch-images>'
ARGUMENT_PARSER = CLI + 'arguments.hepta'
ARGUMENT_FORMATTER = BOOTSTRAP + 'cli_format.hepta'
ARGUMENT_PAYLOAD = CLI + 'argument_payload.hepta'
ARGUMENT_ARCHIVE = '<public-argument-images>'
RELEASE_DEFLATE = CLI + 'release_deflate.hepta'
EXEC_LAUNCHER = 'tools/hia_core_edit_packed_exec.S'
EDIT_ENVELOPE = 'tools/hia_core_edit_nominal_envelope.S'
EDIT_RESPONSE = 'tools/hia_core_edit_response.S'
BATCH_CAPTURE = 'tools/hia_core_edit_batch_capture.S'
EXEC_ARCHIVE_MAGIC = b'HIAECP01'
EXEC_CHUNK = 1 << 19
DISPATCH_ROLES = frozenset((
    'hia-apply-edit', 'hia-apply-edit-batch', 'hia-build-object', 'hia-capabilities',
    'hia-catalog', 'hia-impact-core-json', 'hia-import-assembly', 'hia-nominal-constructor',
    'hia-patch-core-json', 'hia-prepare-edit-batch', 'hia-prepare-edit-query',
    'hia-publish-batch', 'hia-publish-batch-query', 'hia-publish-edit', 'hia-publish-patch',
    'hia-publish-query',
))
DISPATCH_PIN_SLOTS = (65728, 65744, 65752, 65760, 65768)
DISPATCH_WORD = re.compile(
    rb'  (v\d+):u64 = const\(\) \{"value":(\d+)\}\n'
    rb'  (v\d+):u64 = const\(\) \{"value":(\d+)\}\n'
    rb'  v\d+:u64 = call\(v\d+,\1,\3\) \{"function":"f43"\}')
ASSEMBLY_PRESENTATION = '<assembly-presenters>'
ASSEMBLY_PRESENTERS = tuple(CLI + name + '.hepta' for name in (
    'assembly_diagnostic_report', 'assembly_pretty', 'assembly_driver'))
ASSEMBLY_PUBLICATION = tuple(EDIT + name + '.hepta' for name in (
    'publication_frontend', 'publication_import', 'publication_policy'))
NOMINAL_BUILD_IMAGES = {
    'types': 'types_image', 'admit': 'function_admit',
    'records': 'function_records', 'terms': 'function_terms',
    'advanced': 'function_advanced', 'function-render': 'function_render',
    'helpers': 'function_helper', 'outer-owner': 'outer_owner',
    'outer-render': 'outer_render', 'public-canonical': 'public_canonical',
    'public-presentation': 'public_presentation',
}
NOMINAL_BUILD_SOURCES = {
    key: NOMINAL_COMPONENTS[key]
    for key in (*NOMINAL_BUILD_IMAGES, 'owner', 'render', 'nominal-json', 'linker')
}
OBJECT_BUILD_IMAGES = {
    CORE_ADMISSION: 'build_core',
    EDIT + 'publication_frontend.hepta': 'build_frontend',
    CLI + 'build_codegen.hepta': 'build_codegen',
    CLI + 'build_backend.hepta': 'build_backend',
}
EDIT_QUERY_IMAGES = {
    BOOTSTRAP + 'core_patch.hepta': 'edit_base_extract',
    CORE_ADMISSION: 'edit_base_admission',
    EDIT + 'nominal_base_span.hepta': 'edit_base_span',
    EDIT + 'query.hepta': 'edit_query',
    BOOTSTRAP + 'agent_slice.hepta': 'edit_slice',
}
PUBLISHED_EDIT_QUERY_IMAGES = {
    CORE_ADMISSION: 'edit_base_admission',
    EDIT + 'patch_word_io.hepta': 'edit_base_extract',
    EDIT + 'nominal_base_span.hepta': 'edit_base_span',
    EDIT + 'query.hepta': 'edit_query',
    EDIT + 'publication_json_view.hepta': 'edit_publication',
}
BATCH_QUERY_IMAGES = {
    CORE_ADMISSION: 'edit_base_admission',
    EDIT + 'patch_word_io.hepta': 'edit_base_extract',
    EDIT + 'nominal_base_span.hepta': 'edit_base_span',
    EDIT + 'batch_query.hepta': 'edit_batch_query',
}
BATCH_QUERY_STDOUT_IMAGES = {**BATCH_QUERY_IMAGES, BOOTSTRAP + 'agent_slice.hepta': 'edit_slice'}
BATCH_QUERY_PUBLISH_IMAGES = {**BATCH_QUERY_IMAGES, EDIT + 'publication_json_view.hepta': 'edit_publication'}

EDIT_APPLY_INPUT_IMAGES = {
    CORE_ADMISSION: 'edit_base_admission',
    EDIT + 'patch_word_io.hepta': 'edit_base_extract',
    EDIT + 'nominal_base_span.hepta': 'edit_base_span',
}
EDIT_APPLY_IMAGES = {
    **EDIT_APPLY_INPUT_IMAGES,
    EDIT + 'apply.hepta': 'edit_apply_owner',
    BOOTSTRAP + 'agent_slice.hepta': 'edit_slice',
}
PUBLISHED_EDIT_APPLY_IMAGES = {
    **EDIT_APPLY_INPUT_IMAGES,
    EDIT + 'publication_single_edit.hepta': 'edit_apply_owner',
    EDIT + 'publication_edit_policy.hepta': 'edit_publication',
}

BATCH_APPLY_INPUT_IMAGES = {
    EDIT + 'batch_capture.hepta': 'edit_batch_capture',
    EDIT + 'nominal_base_span.hepta': 'edit_base_span',
    EDIT + 'batch_apply.hepta': 'edit_batch_apply',
}
BATCH_APPLY_IMAGES = {
    CORE_ADMISSION: 'edit_base_admission',
    EDIT + 'batch_normalize.hepta': 'edit_batch_front',
    **BATCH_APPLY_INPUT_IMAGES,
    BOOTSTRAP + 'agent_slice.hepta': 'edit_slice',
}
PUBLISHED_BATCH_APPLY_IMAGES = {
    EDIT + 'batch_capture.hepta': 'edit_batch_capture',
    CORE_ADMISSION: 'edit_base_admission',
    EDIT + 'publication_batch_receipt.hepta': 'edit_batch_front',
    **BATCH_APPLY_INPUT_IMAGES,
    EDIT + 'publication_batch_policy.hepta': 'edit_publication',
}

PATCH_INPUT_IMAGES = {
    CORE_ADMISSION: 'edit_base_admission',
    EDIT + 'nominal_base_span.hepta': 'edit_base_span',
}
PATCH_IMAGES = {
    **PATCH_INPUT_IMAGES,
    EDIT + 'impact_patch.hepta': 'edit_patch',
    CLI + 'patch.hepta': 'edit_patch_receipt',
    EDIT + 'publication_pretty.hepta': 'edit_pretty',
}
PUBLISHED_PATCH_IMAGES = {
    **PATCH_INPUT_IMAGES,
    EDIT + 'publication_patch_policy.hepta': 'edit_patch',
    EDIT + 'publication_patch.hepta': 'edit_patch_receipt',
    EDIT + 'publication_pretty.hepta': 'edit_pretty',
}
IMPACT_IMAGES = {
    **PATCH_INPUT_IMAGES,
    EDIT + 'impact_patch.hepta': 'edit_patch',
    EDIT + 'impact.hepta': 'edit_impact',
    EDIT + 'impact_json_io.hepta': 'edit_pretty',
}
NOMINAL_CLI_IMAGES = {
    'build_object': OBJECT_BUILD_IMAGES,
    'query': EDIT_QUERY_IMAGES,
    'publish_query': PUBLISHED_EDIT_QUERY_IMAGES,
    'patch_core_json': PATCH_IMAGES,
    'publish_patch': PUBLISHED_PATCH_IMAGES,
    'impact': IMPACT_IMAGES,
    'batch_query': BATCH_QUERY_STDOUT_IMAGES,
    'publish_batch_query': BATCH_QUERY_PUBLISH_IMAGES,
    'apply': EDIT_APPLY_IMAGES,
    'publish_edit': PUBLISHED_EDIT_APPLY_IMAGES,
    'batch_apply': BATCH_APPLY_IMAGES,
    'publish_batch': PUBLISHED_BATCH_APPLY_IMAGES,
}
EDIT_ENVELOPE_ROLES = ('query', 'publish_query', 'patch_core_json', 'publish_patch', 'impact',
                       'batch_query', 'publish_batch_query', 'apply', 'publish_edit',
                       'batch_apply', 'publish_batch')

# Each entry lists the flat payloads in placement order, then the adapter
# relocation sites belonging to each. Several stages use the same image entry.
PROGRAMS = {
    'dispatch': ('hia', (
        (DISPATCH_ARCHIVE, ('dispatch_archive', 'query_syntax_archive')),
        (CLI + 'selfhost_entry.hepta', ('selfhost_call',)),
        (ARGUMENT_PAYLOAD, ('argument_unpack', 'argument_frame', 'argument_encode', 'argument_command')),
        (ARGUMENT_ARCHIVE, ('argument_images',)),
    )),
    'selfhost_component': ('hia-selfhost-component', (
        (CLI + 'selfhost_controller.hepta', ('dispatch_call',)),
        (CLI + 'selfhost_selection.hepta', ('capsule_call',)),
        (CLI + 'selfhost_semantics.hepta', ('full_Core_call',)),
        (CLI + 'selfhost_wire.hepta', ('emergency_call', 'canonical_wire_call', 'policy_call')),
    )),
    'normalize_core': ('hia-normalize-core', (
        (CORE_ADMISSION, ('core_call',)),
        (BOOTSTRAP + 'json_canonical.hepta', ('canonical_call',)),
        (CLI + 'normalize_pretty.hepta', ('pretty_call',)),
    )),
    'verify_core_json': ('hia-verify-core-json', (
        (CORE_ADMISSION, ('core_call',)),
        (BOOTSTRAP + 'json_canonical.hepta', ('canonical_call',)),
        (CLI + 'verify.hepta', ('report_call',)),
        (CLI + 'verify_pretty.hepta', ('pretty_call',)),
    )),
    'inspect_core_json': ('hia-inspect-core-json', (
        (CORE_ADMISSION, ('core_call',)),
        (BOOTSTRAP + 'json_canonical.hepta', ('canonical_call',)),
        (CLI + 'inspect.hepta', ('report_call',)),
        (EDIT + 'publication_pretty.hepta', ('pretty_call',)),
    )),
    'patch_core_json': ('hia-patch-core-json', tuple((path, ()) for path in PATCH_IMAGES)),
    'catalog': ('hia-catalog', (
        (BOOTSTRAP + 'cli_discovery_json.hepta', ('catalog_call',)),
    )),
    'import_assembly': ('hia-import-assembly', (
        (CLI + 'assembly_syntax_diagnostics.hepta', ('syntax_call',)),
        (CORE_ADMISSION, ('core_call',)),
        (BOOTSTRAP + 'json_canonical.hepta', ('canonical_call',)),
        (ASSEMBLY_PRESENTATION, ('presentation_images',)),
    )),
    'render_assembly': ('hia-render-assembly', (
        (CORE_ADMISSION, ('original_core', 'roundtrip_core')),
        (BOOTSTRAP + 'json_canonical.hepta', ('original_canonical', 'roundtrip_canonical')),
        (CLI + 'assembly_render.hepta', ('render', 'finish')),
        (CLI + 'assembly_syntax.hepta', ('syntax',)),
    )),
    'capabilities': ('hia-capabilities', (
        (CLI + 'capabilities.hepta', ('capabilities_call',)),
    )),
    'emit_object': ('hia-emit-object', (
        (CORE_ADMISSION, ('core',)),
        (EDIT + 'publication_frontend.hepta', ('frame', 'exports', 'expectations')),
        (CLI + 'build_codegen.hepta', ('codegen',)),
        (CLI + 'build_backend.hepta', ('byte_address',)),
    )),
    'build_object': ('hia-build-object', tuple((path, ()) for path in OBJECT_BUILD_IMAGES)),
    'publish_program': ('hia-publish-program', (
        (CORE_ADMISSION, ('core_address',)),
        (EDIT + 'publication_frontend.hepta', ('front_address',)),
        (EDIT + 'publication_program.hepta', ('owner_address',)),
        (EDIT + 'publication_policy.hepta', ('publication_address',)),
    )),
    'publish_assembly': ('hia-publish-assembly', (
        (CORE_ADMISSION, ('core_address',)),
        (EDIT + 'publication_frontend.hepta', ('front_address',)),
        (EDIT + 'publication_render.hepta', ('owner_address',)),
        (EDIT + 'publication_assembly.hepta', ('publication_address',)),
    )),
    'publish_patch': ('hia-publish-patch', tuple((path, ()) for path in PUBLISHED_PATCH_IMAGES)),
    'publish_edit': ('hia-publish-edit', tuple((path, ()) for path in PUBLISHED_EDIT_APPLY_IMAGES)),
    'publish_query': ('hia-publish-query', tuple((path, ()) for path in PUBLISHED_EDIT_QUERY_IMAGES)),
    'publish_batch_query': ('hia-publish-batch-query', tuple((path, ()) for path in BATCH_QUERY_PUBLISH_IMAGES)),
    'publish_batch': ('hia-publish-batch', tuple((path, ()) for path in PUBLISHED_BATCH_APPLY_IMAGES)),
    'impact': ('hia-impact-core-json', tuple((path, ()) for path in IMPACT_IMAGES)),
    'query': ('hia-prepare-edit-query', tuple((path, ()) for path in EDIT_QUERY_IMAGES)),
    'batch_query': ('hia-prepare-edit-batch', tuple((path, ()) for path in BATCH_QUERY_STDOUT_IMAGES)),
    'apply': ('hia-apply-edit', tuple((path, ()) for path in EDIT_APPLY_IMAGES)),
    'batch_apply': ('hia-apply-edit-batch', tuple((path, ()) for path in BATCH_APPLY_IMAGES)),
}

STATIC_RELOCATIONS = {
    EXEC_LAUNCHER: (('decompress', 0), ('archive', 1)),
    **{
        'tools/hia_core_edit_' + kind + '.S': tuple(
            (call, index) for index, (_path, calls) in enumerate(roles) for call in calls)
        for kind, (_name, roles) in PROGRAMS.items() if kind not in NOMINAL_CLI_IMAGES
    },
}
STATIC_ADAPTER_ROLES = {
    name: (STATIC_ADAPTERS[role % len(STATIC_ADAPTERS)], role)
    for role, name in enumerate(STATIC_RELOCATIONS)
}
NOMINAL_ADAPTER_ROLES = {
    name: (NOMINAL_ADAPTER_GROUPS[role % len(NOMINAL_ADAPTER_GROUPS)], role)
    for role, name in enumerate((*(f'tools/hia_core_edit_{kind}.S' for kind in NOMINAL_CLI_IMAGES),
                                 EDIT_ENVELOPE, EDIT_RESPONSE, BATCH_CAPTURE))
}
NOMINAL_ADAPTER_ROLES[NOMINAL_ADAPTER] = (NOMINAL_CONSTRUCTOR_GROUP, len(NOMINAL_ADAPTER_ROLES))


def digest(raw):
    return sha256(raw).hexdigest()


class ReleaseCompressor:
    """Transport build bytes through the admitted HIA encoder and decoder."""

    def __init__(self, encoder, decoder):
        self.encoder = encoder
        self.decoder = decoder
        self.encoder_workspace = ctypes.create_string_buffer(393216)
        self.decoder_workspace = ctypes.create_string_buffer(4096)

    def compress(self, raw, capacity):
        source = ctypes.create_string_buffer(raw, len(raw))
        packed = ctypes.create_string_buffer(capacity)
        size = self.encoder._entry(source, len(raw), packed, capacity,
                                   self.encoder_workspace, len(self.encoder_workspace))
        if not 0 < size <= capacity or source.raw != raw or any(packed.raw[size:]):
            raise ValueError('HIA release encoder refused or changed private bytes')
        encoded = packed.raw[:size]
        decoded = ctypes.create_string_buffer(len(raw))
        restored = self.decoder._entry(packed, size, decoded, len(raw),
                                       self.decoder_workspace, len(self.decoder_workspace))
        if restored != len(raw) or decoded.raw != raw or packed.raw[:size] != encoded:
            raise ValueError('HIA release encoder failed the native round trip')
        return encoded


def argument_images(control, formatter, compressor):
    raw = control + formatter
    if not control or not formatter or len(raw) > 1048576:
        raise ValueError('native CLI argument images exceed the decoded extent')
    compressed = compressor.compress(raw, 1048576 - 24)
    return struct.pack('<3Q', len(compressed), len(raw), len(control)) + compressed


def pack(packer, stub, holes, images):
    lengths = list(map(len, images))
    frame = struct.pack('<8Q', MAGIC, len(stub), len(holes), len(lengths),
                        *lengths, *([0] * (4 - len(lengths))))
    frame += b''.join(struct.pack('<2Q', offset, index) for offset, index in holes)
    frame += stub + b''.join(images)
    source = ctypes.create_string_buffer(frame)
    output = ctypes.create_string_buffer(CAPACITY)
    size = packer._entry(source, len(frame), output, len(output), None, 0)
    if (type(size) is not int or not ELF_HEADER_SIZE < size <= len(output)
            or source.raw != frame + b'\0' or any(output.raw[size:])):
        raise ValueError('native Core edit packer refused or changed private bytes')
    binary = output.raw[:size]
    expected = bytearray(stub)
    for index, image in enumerate(images):
        expected.extend(bytes(-len(expected) % 8))
        for hole, target in holes:
            if target == index:
                struct.pack_into('<i', expected, hole, len(expected) - hole - 4)
        expected.extend(image)
    if binary[ELF_HEADER_SIZE:] != expected:
        raise ValueError('native Core edit packer changed the admitted adapter or image placement')
    return binary, inspect_executable(binary)


def link_nominal_cli(folder, adapter, images, roles, embedder, adapters, *, edit_envelope=False,
                     edit_response=False, batch_capture=False):
    objects = [adapters[adapter], adapters[NOMINAL_ADAPTER]]
    if edit_envelope:
        objects.append(adapters[EDIT_ENVELOPE])
    if edit_response:
        objects.append(adapters[EDIT_RESPONSE])
    if batch_capture:
        objects.append(adapters[BATCH_CAPTURE])
    payloads = {label: images[NOMINAL_BUILD_SOURCES[key]]
                for key, label in {**NOMINAL_IMAGE_LABELS, **NOMINAL_BUILD_IMAGES}.items()}
    payloads.update({label: images[path] for path, label in roles.items()})
    objects.extend(embed(folder, label, label, raw, embedder) for label, raw in payloads.items())
    reference = next(iter(roles))
    binary, receipt = link(folder, images[NOMINAL_BUILD_SOURCES['linker']], images[reference], objects,
                           wire_magic=b'HIALNK01', executable_limit=ORDINARY_CLI_IMAGE_CAPACITY)
    for raw in payloads.values():
        verify_executable(binary, raw)
    writable_offset = struct.unpack_from('<Q', binary, 128)[0]
    if any(memoryview(binary)[writable_offset:]):
        raise ValueError('linked nominal CLI must have an initially zero writable segment')
    return binary, {'link_receipt': receipt, 'adapter_object_sha256': digest(objects[0])}


def load_static_adapter(templates, name, source):
    group, role = STATIC_ADAPTER_ROLES[name]
    relocations = STATIC_RELOCATIONS[name]
    packet = struct.pack('<Q', role)
    request = ctypes.create_string_buffer(packet, len(packet))
    result = ctypes.create_string_buffer(ADAPTER_RECORD.size + 8 * 32 + 8016)
    n = templates[group]._entry(request, len(request), result, len(result), None, 0)
    if not ADAPTER_RECORD.size < n <= len(result) or request.raw != packet or any(result.raw[n:]):
        raise ValueError('native Core adapter template refused or changed the transport')
    source_sha, stub_sha, object_sha, size, count = ADAPTER_RECORD.unpack_from(result)
    start = ADAPTER_RECORD.size + 8 * count
    if (source_sha != sha256(source).digest() or not 5 <= size <= 8016
            or count != len(relocations) or n != start + size):
        raise ValueError('native Core adapter template differs from the admitted source')
    stub = result.raw[start:n]
    offsets = struct.unpack_from(f'<{count}Q', result, ADAPTER_RECORD.size)
    if sha256(stub).digest() != stub_sha or len(set(offsets)) != count:
        raise ValueError('native Core adapter template bytes or relocations changed')
    holes = sorted((offset, target) for offset, (_call, target) in zip(offsets, relocations, strict=True))
    return stub, holes, object_sha.hex()


def pack_executable(packer, launcher, inflater, executable, compressor):
    if not 0 < len(executable) <= ORDINARY_CLI_IMAGE_CAPACITY:
        raise ValueError('packed CLI executable exceeds the admitted extent')
    parts = [struct.pack('<8sQ', EXEC_ARCHIVE_MAGIC, len(executable))]
    for start in range(0, len(executable), EXEC_CHUNK):
        block = executable[start:start + EXEC_CHUNK]
        encoded = compressor.compress(block, 1 << 20)
        parts.extend((struct.pack('<2Q', len(encoded), len(block)), encoded))
    stub, holes, adapter_hash = launcher
    binary, details = pack(packer, stub, holes, [inflater, b''.join(parts)])
    if binary.count(EXEC_ARCHIVE_MAGIC) != 1:
        raise ValueError('packed CLI executable has ambiguous framing')
    return binary, {'elf': details, 'launcher_object_sha256': adapter_hash,
                    'implementation_sha256': digest(executable), 'implementation_bytes': len(executable)}


def bind_dispatch_roles(template, executables):
    """Fill only the release identity words in the admitted HIA dispatcher."""
    if executables.keys() != DISPATCH_ROLES:
        raise ValueError('incomplete native HIA dispatcher release roles')
    blocks = re.split(rb'(?=^block |^fn |^end$)', template, flags=re.M)
    observed = set()
    for index, block in enumerate(blocks):
        words = list(DISPATCH_WORD.finditer(block))
        if not any(int(word[2]) == DISPATCH_PIN_SLOTS[0] for word in words):
            continue
        slots = {int(word[2]): word for word in words}
        required = {*DISPATCH_PIN_SLOTS, 65736, 65776, 8192, 8200}
        if (len(slots) != len(words) or not required <= slots.keys()
                or any(int(slots[slot][4]) != 0 for slot in DISPATCH_PIN_SLOTS)):
            raise ValueError('malformed native HIA dispatcher pin template')
        name_words = (int(slots[slot][4]) if slot in slots else 0 for slot in (8192, 8200, 8208))
        name = struct.pack('<3Q', *name_words).rstrip(b'\0').decode('ascii')
        if name in observed or name not in executables or len(name) != int(slots[65736][4]):
            raise ValueError('unexpected or duplicate native HIA dispatcher release role: ' + name)
        observed.add(name)
        executable = executables[name]
        if not executable.startswith(b'\x7fELF') or len(executable) > ORDINARY_CLI_IMAGE_CAPACITY:
            raise ValueError('native HIA dispatcher role has an invalid executable extent: ' + name)
        values = (len(executable), *struct.unpack('<4Q', sha256(executable).digest()))
        replacements = [(slots[slot].span(4), value) for slot, value in zip(DISPATCH_PIN_SLOTS, values, strict=True)]
        for (start, end), value in sorted(replacements, reverse=True):
            block = block[:start] + str(value).encode('ascii') + block[end:]
        blocks[index] = block
    if observed != DISPATCH_ROLES:
        raise ValueError('missing native HIA dispatcher pin templates')
    return b''.join(blocks)


def build(output, compiler, cold_report, *, release_only=False):
    compiler_raw, report_raw = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_raw, report_raw)
    # The stdin-to-object development probe is not a public dispatcher role.
    # Public object builds use the checked, atomic build_object publisher.
    programs = {key: value for key, value in PROGRAMS.items()
                if not release_only or key != 'emit_object'}
    adapters = {kind: 'tools/hia_core_edit_' + kind + '.S' for kind in programs}
    assembly_images = (*ASSEMBLY_PRESENTERS, *ASSEMBLY_PUBLICATION)
    adapter_groups = (*STATIC_ADAPTERS, *NOMINAL_ADAPTER_GROUPS, NOMINAL_CONSTRUCTOR_GROUP)
    source_files = {PACKER, *adapter_groups, DISPATCH, ARGUMENT_PARSER, ARGUMENT_FORMATTER,
                    RELEASE_DEFLATE, EMBED_SOURCE,
                    *assembly_images, *adapters.values(),
                    NOMINAL_ADAPTER, EXEC_LAUNCHER, EDIT_ENVELOPE, EDIT_RESPONSE, BATCH_CAPTURE, *NOMINAL_BUILD_SOURCES.values(),
                    *(path for _name, roles in programs.values() for path, _calls in roles
                      if path not in (DISPATCH_ARCHIVE, ARGUMENT_ARCHIVE, ASSEMBLY_PRESENTATION))}
    sources = {path: (ROOT / path).read_bytes() for path in sorted(source_files)}
    if any(admitted.get(path) != digest(raw) for path, raw in sources.items()):
        raise ValueError('native Core edit source differs from admitted cold source')
    output.mkdir(mode=0o700)
    images, receipts = {}, {}
    for path, raw in sources.items():
        if path.endswith('.json'):
            images[path] = raw
        if not path.endswith('.hepta') or path == DISPATCH:
            continue
        image, receipt = compile_stage(output, Path(path).stem, compiler, raw)
        images[path] = image.read_bytes()
        receipts[path] = receipt
    compressor = ReleaseCompressor(*(
        NativeHiaJsonImage(images[path], receipts[path]['produced_sha256'])
        for path in (RELEASE_DEFLATE, ARGUMENT_PAYLOAD)))
    images[ARGUMENT_ARCHIVE] = argument_images(
        images[ARGUMENT_PARSER], images[ARGUMENT_FORMATTER], compressor)
    payloads = [images[path] for path in assembly_images]
    position = 8 * len(payloads)
    offsets = []
    for payload in payloads:
        offsets.append(struct.pack('<Q', position))
        position += len(payload)
    images[ASSEMBLY_PRESENTATION] = b''.join((*offsets, *payloads))
    packer = NativeHiaJsonImage(images[PACKER], receipts[PACKER]['produced_sha256'])
    embedder = NativeHiaJsonImage(images[EMBED_SOURCE], receipts[EMBED_SOURCE]['produced_sha256'])
    templates = {path: NativeHiaJsonImage(images[path], receipts[path]['produced_sha256'])
                 for path in adapter_groups}
    nominal_objects = {name: load_static_object(templates[group], role, sources[name])
                       for name, (group, role) in NOMINAL_ADAPTER_ROLES.items()}
    launcher = load_static_adapter(templates, EXEC_LAUNCHER, sources[EXEC_LAUNCHER])
    products = {}
    for kind, (name, roles) in programs.items():
        if kind == 'dispatch':
            continue
        adapter = adapters[kind]
        folder = output / kind
        folder.mkdir(mode=0o700)
        if kind in NOMINAL_CLI_IMAGES:
            executable, details = link_nominal_cli(
                folder, adapter, images, NOMINAL_CLI_IMAGES[kind], embedder, nominal_objects,
                edit_envelope=kind in EDIT_ENVELOPE_ROLES,
                edit_response=kind in ('apply', 'publish_edit'), batch_capture=kind in ('batch_apply', 'publish_batch'))
            binary, packed = pack_executable(packer, launcher,
                                             images[ARGUMENT_PAYLOAD], executable, compressor)
            products[name] = (binary, {**details, **packed})
            continue
        stub, holes, adapter_hash = load_static_adapter(templates, adapter, sources[adapter])
        binary, details = pack(packer, stub, holes, [images[path] for path, _calls in roles])
        products[name] = (binary, {'elf': details, 'adapter_object_sha256': adapter_hash})
    constructor = build_nominal_constructor(output / 'nominal-constructor', compiler, cold_report)
    bound_roles = {name: products[name][0] for name in DISPATCH_ROLES if name != constructor.name}
    bound_roles[constructor.name] = constructor.read_bytes()
    bound_dispatch = bind_dispatch_roles(sources[DISPATCH], bound_roles)
    image, receipts[DISPATCH] = compile_stage(output, Path(DISPATCH).stem, compiler, bound_dispatch)
    dispatch_image = images[DISPATCH] = image.read_bytes()
    query_image = images[NOMINAL_BUILD_SOURCES['public-presentation']]
    images[DISPATCH_ARCHIVE] = struct.pack('<2Q', 16, 16 + len(dispatch_image)) + dispatch_image + query_image
    name, roles = programs['dispatch']
    adapter = adapters['dispatch']
    stub, holes, adapter_hash = load_static_adapter(templates, adapter, sources[adapter])
    binary, details = pack(packer, stub, holes, [images[path] for path, _calls in roles])
    products[name] = (binary, {'elf': details, 'adapter_object_sha256': adapter_hash,
                              'role_sha256': {role: digest(raw) for role, raw in bound_roles.items()}})
    if (current_sources() != admitted or compiler.read_bytes() != compiler_raw
            or cold_report.read_bytes() != report_raw
            or constructor.read_bytes() != bound_roles[constructor.name]
            or any((ROOT / path).read_bytes() != raw for path, raw in sources.items())
            or any(digest(images[path]) != receipt['produced_sha256']
                   or Path(receipt['produced_image']).read_bytes() != images[path]
                   for path, receipt in receipts.items())):
        raise ValueError('native Core edit build inputs changed before publication')
    for name, (binary, _details) in products.items():
        executable = output / name
        with executable.open('xb') as stream:
            stream.write(binary)
        executable.chmod(0o500)
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.core-edit-build.v1',
        'compiler_sha256': digest(compiler_raw), 'cold_report_sha256': digest(report_raw),
        'native_nominal_adapter_object_sha256': {name: digest(raw) for name, raw in nominal_objects.items()},
        'source_sha256': {path: digest(raw) for path, raw in sources.items()},
        'compile_receipts': receipts, 'executables': {name: details for name, (_, details) in products.items()},
    }, indent=2, sort_keys=True) + '\n')
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--release-only', action='store_true',
                        help='omit the standalone development emission probe')
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve(),
                release_only=args.release_only))


if __name__ == '__main__':
    main()
