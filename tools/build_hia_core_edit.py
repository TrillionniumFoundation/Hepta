"""Cold-build native Core query, edit, impact and publication executables."""

import argparse
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import struct
import zlib

from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.build_hia_agent_batch_commit import ELF_HEADER_SIZE, assemble_adapter
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_nominal_constructor import (
    ADAPTER as NOMINAL_ADAPTER, COMPONENTS as NOMINAL_COMPONENTS,
    ORDINARY_CLI_IMAGE_CAPACITY,
)
from tools.build_hia_sqlite_migrate import embed
from tools.build_hia_sqlite_pager import assemble, link, verify_executable
from tools.generate_hia_core_edit_packer import MAGIC
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = 'examples/hia_bootstrap/'
EDIT = BOOTSTRAP + 'core_edit/'
CLI = BOOTSTRAP + 'core_cli/'
PACKER = EDIT + 'packer.hepta'
CAPACITY = 4 * (1 << 20) + 4096
DISPATCH = CLI + 'dispatch.hepta'
DISPATCH_ARCHIVE = '<public-dispatch-images>'
ARGUMENT_PARSER = CLI + 'arguments.hepta'
ARGUMENT_FORMATTER = BOOTSTRAP + 'cli_format.hepta'
ARGUMENT_PAYLOAD = CLI + 'argument_payload.hepta'
ARGUMENT_ARCHIVE = '<public-argument-images>'
EXEC_LAUNCHER = 'tools/hia_core_edit_packed_exec.S'
EDIT_ENVELOPE = 'tools/hia_core_edit_nominal_envelope.S'
EXEC_ARCHIVE_MAGIC = b'HIAECP01'
EXEC_CHUNK = 1 << 19
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
    EDIT + 'admission_word_io.hepta': 'build_core',
    EDIT + 'publication_frontend.hepta': 'build_frontend',
    CLI + 'build_codegen.hepta': 'build_codegen',
    CLI + 'build_backend.hepta': 'build_backend',
}
EDIT_QUERY_IMAGES = {
    BOOTSTRAP + 'core_patch.hepta': 'edit_base_extract',
    BOOTSTRAP + 'core_admission.hepta': 'edit_base_admission',
    EDIT + 'nominal_base_span.hepta': 'edit_base_span',
    EDIT + 'query.hepta': 'edit_query',
    BOOTSTRAP + 'agent_slice.hepta': 'edit_slice',
}
PUBLISHED_EDIT_QUERY_IMAGES = {
    EDIT + 'admission_word_io.hepta': 'edit_base_admission',
    EDIT + 'patch_word_io.hepta': 'edit_base_extract',
    EDIT + 'nominal_base_span.hepta': 'edit_base_span',
    EDIT + 'query.hepta': 'edit_query',
    EDIT + 'publication_json_view.hepta': 'edit_publication',
}
BATCH_QUERY_IMAGES = {
    EDIT + 'admission_word_io.hepta': 'edit_base_admission',
    EDIT + 'patch_word_io.hepta': 'edit_base_extract',
    EDIT + 'nominal_base_span.hepta': 'edit_base_span',
    EDIT + 'batch_query.hepta': 'edit_batch_query',
}
BATCH_QUERY_STDOUT_IMAGES = {**BATCH_QUERY_IMAGES, BOOTSTRAP + 'agent_slice.hepta': 'edit_slice'}
BATCH_QUERY_PUBLISH_IMAGES = {**BATCH_QUERY_IMAGES, EDIT + 'publication_json_view.hepta': 'edit_publication'}

EDIT_APPLY_INPUT_IMAGES = {
    EDIT + 'admission_word_io.hepta': 'edit_base_admission',
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
    EDIT + 'nominal_base_span.hepta': 'edit_base_span',
    EDIT + 'batch_apply.hepta': 'edit_batch_apply',
}
BATCH_APPLY_IMAGES = {
    EDIT + 'admission_word_io.hepta': 'edit_base_admission',
    EDIT + 'batch_normalize.hepta': 'edit_batch_front',
    **BATCH_APPLY_INPUT_IMAGES,
    BOOTSTRAP + 'agent_slice.hepta': 'edit_slice',
}
PUBLISHED_BATCH_APPLY_IMAGES = {
    EDIT + 'publication_batch_admission.hepta': 'edit_base_admission',
    EDIT + 'publication_batch_receipt.hepta': 'edit_batch_front',
    **BATCH_APPLY_INPUT_IMAGES,
    EDIT + 'publication_batch_policy.hepta': 'edit_publication',
}

PATCH_INPUT_IMAGES = {
    EDIT + 'admission_word_io.hepta': 'edit_base_admission',
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
        (BOOTSTRAP + 'core_admission.hepta', ('core_call',)),
        (BOOTSTRAP + 'json_canonical.hepta', ('canonical_call',)),
        (CLI + 'normalize_pretty.hepta', ('pretty_call',)),
    )),
    'verify_core_json': ('hia-verify-core-json', (
        (BOOTSTRAP + 'core_admission.hepta', ('core_call',)),
        (BOOTSTRAP + 'json_canonical.hepta', ('canonical_call',)),
        (CLI + 'verify.hepta', ('report_call',)),
        (CLI + 'verify_pretty.hepta', ('pretty_call',)),
    )),
    'inspect_core_json': ('hia-inspect-core-json', (
        (BOOTSTRAP + 'core_admission.hepta', ('core_call',)),
        (BOOTSTRAP + 'json_canonical.hepta', ('canonical_call',)),
        (CLI + 'inspect.hepta', ('report_call',)),
        (EDIT + 'publication_pretty.hepta', ('pretty_call',)),
    )),
    'patch_core_json': ('hia-patch-core-json', tuple((path, ()) for path in PATCH_IMAGES)),
    'catalog': ('hia-catalog', (
        (BOOTSTRAP + 'json_canonical.hepta', ('canonical_call',)),
        (CLI + 'catalog.hepta', ('catalog_call',)),
        (CLI + 'verify_pretty.hepta', ('pretty_call',)),
        (CLI + 'catalog_registry.json', ('data_lea',)),
    )),
    'import_assembly': ('hia-import-assembly', (
        (CLI + 'assembly_syntax_diagnostics.hepta', ('syntax_call',)),
        (CLI + 'assembly_core_diagnostics.hepta', ('core_call',)),
        (BOOTSTRAP + 'json_canonical.hepta', ('canonical_call',)),
        (ASSEMBLY_PRESENTATION, ('presentation_images',)),
    )),
    'render_assembly': ('hia-render-assembly', (
        (BOOTSTRAP + 'core_admission.hepta', ('original_core', 'roundtrip_core')),
        (BOOTSTRAP + 'json_canonical.hepta', ('original_canonical', 'roundtrip_canonical')),
        (CLI + 'assembly_render.hepta', ('render', 'finish')),
        (CLI + 'assembly_syntax.hepta', ('syntax',)),
    )),
    'capabilities': ('hia-capabilities', (
        (CLI + 'capabilities.hepta', ('capabilities_call',)),
    )),
    'emit_object': ('hia-emit-object', (
        (EDIT + 'admission_word_io.hepta', ('core',)),
        (EDIT + 'publication_frontend.hepta', ('frame', 'exports', 'expectations')),
        (CLI + 'build_codegen.hepta', ('codegen',)),
        (CLI + 'build_backend.hepta', ('byte_address',)),
    )),
    'build_object': ('hia-build-object', tuple((path, ()) for path in OBJECT_BUILD_IMAGES)),
    'publish_program': ('hia-publish-program', (
        (EDIT + 'admission_word_io.hepta', ('core_address',)),
        (EDIT + 'publication_frontend.hepta', ('front_address',)),
        (EDIT + 'publication_program.hepta', ('owner_address',)),
        (EDIT + 'publication_policy.hepta', ('publication_address',)),
    )),
    'publish_assembly': ('hia-publish-assembly', (
        (EDIT + 'admission_word_io.hepta', ('core_address',)),
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


def digest(raw):
    return sha256(raw).hexdigest()


def argument_images(control, formatter):
    raw = control + formatter
    if not control or not formatter or len(raw) > 1048576:
        raise ValueError('native CLI argument images exceed the decoded extent')
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15, 6)
    compressed = compressor.compress(raw) + compressor.flush()
    if len(compressed) + 24 > 1048576 or zlib.decompress(compressed, -15) != raw:
        raise ValueError('native CLI argument images failed packing')
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


def link_nominal_cli(folder, adapter, sources, images, roles, *, edit_envelope=False):
    for key in ('owner', 'render', 'nominal-json'):
        (folder / (key + '.image.bin')).write_bytes(images[NOMINAL_BUILD_SOURCES[key]])
    objects = [assemble(folder, adapter, sources[adapter]), assemble(
        folder, NOMINAL_ADAPTER, b'.set HIA_NOMINAL_BUILD,1\n' + sources[NOMINAL_ADAPTER])]
    if edit_envelope:
        objects.append(assemble(folder, EDIT_ENVELOPE, sources[EDIT_ENVELOPE]))
    payloads = {label: images[NOMINAL_BUILD_SOURCES[key]]
                for key, label in NOMINAL_BUILD_IMAGES.items()}
    payloads.update({label: images[path] for path, label in roles.items()})
    objects.extend(embed(folder, label, label, raw) for label, raw in payloads.items())
    reference = next(iter(roles))
    binary, receipt = link(folder, images[NOMINAL_BUILD_SOURCES['linker']], images[reference], objects,
                           wire_magic=b'HIALNK01', executable_limit=ORDINARY_CLI_IMAGE_CAPACITY)
    for raw in (*payloads.values(), *(images[NOMINAL_BUILD_SOURCES[key]]
                                      for key in ('owner', 'render', 'nominal-json'))):
        verify_executable(binary, raw)
    writable_offset = struct.unpack_from('<Q', binary, 128)[0]
    if any(memoryview(binary)[writable_offset:]):
        raise ValueError('linked nominal CLI must have an initially zero writable segment')
    return binary, {'link_receipt': receipt, 'adapter_object_sha256': digest(objects[0])}


def pack_executable(folder, packer, launcher, inflater, executable):
    if not 0 < len(executable) <= ORDINARY_CLI_IMAGE_CAPACITY:
        raise ValueError('packed CLI executable exceeds the admitted extent')
    parts = [struct.pack('<8sQ', EXEC_ARCHIVE_MAGIC, len(executable))]
    for start in range(0, len(executable), EXEC_CHUNK):
        block = executable[start:start + EXEC_CHUNK]
        compressor = zlib.compressobj(9, zlib.DEFLATED, -15, 6)
        encoded = compressor.compress(block) + compressor.flush()
        if not 0 < len(encoded) <= (1 << 20) or zlib.decompress(encoded, -15) != block:
            raise ValueError('CLI executable failed lossless packing')
        parts.extend((struct.pack('<2Q', len(encoded), len(block)), encoded))
    stub, symbols, adapter_hash = assemble_adapter(folder, EXEC_LAUNCHER, launcher)
    holes = sorted((symbols[name + '_hole'], index)
                   for index, name in enumerate(('decompress', 'archive')))
    binary, details = pack(packer, stub, holes, [inflater, b''.join(parts)])
    if binary.count(EXEC_ARCHIVE_MAGIC) != 1:
        raise ValueError('packed CLI executable has ambiguous framing')
    return binary, {'elf': details, 'launcher_object_sha256': adapter_hash,
                    'implementation_sha256': digest(executable), 'implementation_bytes': len(executable)}


def build(output, compiler, cold_report, *, release_only=False):
    compiler_raw, report_raw = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_raw, report_raw)
    # The stdin-to-object development probe is not a public dispatcher role.
    # Public object builds use the checked, atomic build_object publisher.
    programs = {key: value for key, value in PROGRAMS.items()
                if not release_only or key != 'emit_object'}
    adapters = {kind: 'tools/hia_core_edit_' + kind + '.S' for kind in programs}
    assembly_images = (*ASSEMBLY_PRESENTERS, *ASSEMBLY_PUBLICATION)
    source_files = {PACKER, DISPATCH, ARGUMENT_PARSER, ARGUMENT_FORMATTER, *assembly_images, *adapters.values(),
                    NOMINAL_ADAPTER, EXEC_LAUNCHER, EDIT_ENVELOPE, *NOMINAL_BUILD_SOURCES.values(),
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
        if not path.endswith('.hepta'):
            continue
        image, receipt = compile_stage(output, Path(path).stem, compiler, raw)
        images[path] = image.read_bytes()
        receipts[path] = receipt
    images[ARGUMENT_ARCHIVE] = argument_images(images[ARGUMENT_PARSER], images[ARGUMENT_FORMATTER])
    dispatch_image = images[DISPATCH]
    query_image = images[NOMINAL_BUILD_SOURCES['public-presentation']]
    images[DISPATCH_ARCHIVE] = struct.pack('<2Q', 16, 16 + len(dispatch_image)) + dispatch_image + query_image
    payloads = [images[path] for path in assembly_images]
    position = 8 * len(payloads)
    offsets = []
    for payload in payloads:
        offsets.append(struct.pack('<Q', position))
        position += len(payload)
    images[ASSEMBLY_PRESENTATION] = b''.join((*offsets, *payloads))
    packer = NativeHiaJsonImage(images[PACKER], receipts[PACKER]['produced_sha256'])
    products = {}
    for kind, (name, roles) in programs.items():
        adapter = adapters[kind]
        folder = output / kind
        folder.mkdir(mode=0o700)
        if kind in NOMINAL_CLI_IMAGES:
            executable, details = link_nominal_cli(
                folder, adapter, sources, images, NOMINAL_CLI_IMAGES[kind],
                edit_envelope=kind in EDIT_ENVELOPE_ROLES)
            binary, packed = pack_executable(folder, packer, sources[EXEC_LAUNCHER],
                                             images[ARGUMENT_PAYLOAD], executable)
            products[name] = (binary, {**details, **packed})
            continue
        stub, symbols, adapter_hash = assemble_adapter(folder, adapter, sources[adapter])
        holes = sorted((symbols[call + '_hole'], index)
                       for index, (_path, calls) in enumerate(roles) for call in calls)
        binary, details = pack(packer, stub, holes, [images[path] for path, _calls in roles])
        products[name] = (binary, {'elf': details, 'adapter_object_sha256': adapter_hash})
    if (current_sources() != admitted or compiler.read_bytes() != compiler_raw
            or cold_report.read_bytes() != report_raw
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
