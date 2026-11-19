"""Cold-build the native primitive Core query, edit, impact and publication executables."""

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
from tools.generate_hia_core_edit_packer import MAGIC
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = 'examples/hia_bootstrap/'
EDIT = BOOTSTRAP + 'core_edit/'
CLI = BOOTSTRAP + 'core_cli/'
PACKER = EDIT + 'packer.hepta'
CAPACITY = 4 * (1 << 20) + 4096
ARGUMENT_PARSER = CLI + 'arguments.hepta'
ARGUMENT_FORMATTER = BOOTSTRAP + 'cli_format.hepta'
ARGUMENT_ARCHIVE = '<public-argument-images>'
ASSEMBLY_PRESENTATION = '<assembly-presenters>'
ASSEMBLY_PRESENTERS = tuple(CLI + name + '.hepta' for name in (
    'assembly_diagnostic_report', 'assembly_pretty', 'assembly_driver'))
ASSEMBLY_PUBLICATION = tuple(EDIT + name + '.hepta' for name in (
    'publication_frontend', 'publication_import', 'publication_policy'))

# Each entry lists the flat payloads in placement order, then the adapter
# relocation sites belonging to each. Several stages use the same image entry.
PROGRAMS = {
    'dispatch': ('hia', (
        (CLI + 'dispatch.hepta', ('dispatch_call',)),
        (CLI + 'selfhost_entry.hepta', ('selfhost_call',)),
        (CLI + 'argument_payload.hepta', ('argument_unpack', 'argument_frame', 'argument_encode',
                                         'argument_command')),
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
    'patch_core_json': ('hia-patch-core-json', (
        (EDIT + 'impact_patch.hepta', ('extract_call', 'result_call', 'patch_diagnostic')),
        (EDIT + 'admission_word_io.hepta', ('base_admission_call', 'candidate_admission_call')),
        (CLI + 'patch.hepta', ('compose_call',)),
        (EDIT + 'publication_pretty.hepta', ('pretty_call',)),
    )),
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
    'build_object': ('hia-build-object', (
        (EDIT + 'admission_word_io.hepta', ('core',)),
        (EDIT + 'publication_frontend.hepta', ('path', 'source_admit', 'frame', 'exports', 'expectations', 'facts', 'canonical', 'hash_direct')),
        (CLI + 'build_codegen.hepta', ('codegen', 'report')),
        (CLI + 'build_backend.hepta', ('byte_address',)),
    )),
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
    'publish_patch': ('hia-publish-patch', (
        (EDIT + 'admission_word_io.hepta', ('core_address',)),
        (EDIT + 'publication_patch_policy.hepta', ('front_address', 'patch_diagnostic')),
        (EDIT + 'publication_patch.hepta', ('owner_address',)),
        (EDIT + 'publication_pretty.hepta', ('publication_address',)),
    )),
    'publish_edit': ('hia-publish-edit', (
        (EDIT + 'admission_word_io.hepta', ('core_address',)),
        (EDIT + 'patch_word_io.hepta', ('front_address',)),
        (EDIT + 'publication_single_edit.hepta', ('owner_address',)),
        (EDIT + 'publication_edit_policy.hepta', ('publication_address',)),
    )),
    'publish_query': ('hia-publish-query', (
        (EDIT + 'admission_word_io.hepta', ('core_address',)),
        (EDIT + 'patch_word_io.hepta', ('front_address',)),
        (EDIT + 'query.hepta', ('owner_address',)),
        (EDIT + 'publication_json_view.hepta', ('publication_address',)),
    )),
    'publish_batch_query': ('hia-publish-batch-query', (
        (EDIT + 'admission_word_io.hepta', ('core_address',)),
        (EDIT + 'patch_word_io.hepta', ('front_address',)),
        (EDIT + 'batch_query.hepta', ('owner_address',)),
        (EDIT + 'publication_json_view.hepta', ('publication_address',)),
    )),
    'publish_batch': ('hia-publish-batch', (
        (EDIT + 'publication_batch_admission.hepta', ('core_address',)),
        (EDIT + 'publication_batch_receipt.hepta', ('front_address',)),
        (EDIT + 'batch_apply.hepta', ('owner_address',)),
        (EDIT + 'publication_batch_policy.hepta', ('publication_address',)),
    )),
    'impact': ('hia-impact-core-json', (
        (EDIT + 'impact_patch.hepta', ('extract', 'result', 'patch_diagnostic')),
        (EDIT + 'admission_word_io.hepta', ('base_admission', 'candidate_admission')),
        (EDIT + 'impact.hepta', ('compose', 'impact')),
        (EDIT + 'impact_json_io.hepta', ('canonical', 'pretty')),
    )),
    'query': ('hia-prepare-edit-query', (
        (BOOTSTRAP + 'core_patch.hepta', ('extract',)),
        (BOOTSTRAP + 'core_admission.hepta', ('core',)),
        (EDIT + 'query.hepta', ('decode', 'facts', 'query', 'pretty')),
        (BOOTSTRAP + 'agent_slice.hepta', ('slice',)),
    )),
    'batch_query': ('hia-prepare-edit-batch', (
        (EDIT + 'patch_word_io.hepta', ('extract',)),
        (EDIT + 'admission_word_io.hepta', ('core',)),
        (EDIT + 'batch_query.hepta', ('decode', 'initialize', 'facts', 'query', 'append', 'pretty')),
        (BOOTSTRAP + 'agent_slice.hepta', ('slice',)),
    )),
    'apply': ('hia-apply-edit', (
        (EDIT + 'patch_word_io.hepta', ('extract', 'patch')),
        (EDIT + 'admission_word_io.hepta', ('core', 'candidate_core')),
        (EDIT + 'apply.hepta', ('decode', 'facts', 'query', 'replay', 'raw_response',
                               'response_decode', 'response_validate', 'build_pair', 'compose', 'pretty')),
        (BOOTSTRAP + 'agent_slice.hepta', ('slice',)),
    )),
    'batch_apply': ('hia-apply-edit-batch', (
        (EDIT + 'batch_normalize.hepta', ('extract', 'normalize_prepare', 'normalize_finish',
                                         'replay', 'raw_response', 'response_validate', 'pair',
                                         'patch', 'compose')),
        (EDIT + 'admission_word_io.hepta', ('core', 'candidate_core')),
        (EDIT + 'batch_apply.hepta', ('decode', 'query_decode', 'normalized_decode', 'initialize',
                                     'facts', 'query', 'append', 'hash', 'response_decode', 'pretty')),
        (BOOTSTRAP + 'agent_slice.hepta', ('slice',)),
    )),
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


def build(output, compiler, cold_report, *, release_only=False):
    compiler_raw, report_raw = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_raw, report_raw)
    # The stdin-to-object development probe is not a public dispatcher role.
    # Public object builds use the checked, atomic build_object publisher.
    programs = {key: value for key, value in PROGRAMS.items()
                if not release_only or key != 'emit_object'}
    adapters = {kind: 'tools/hia_core_edit_' + kind + '.S' for kind in programs}
    assembly_images = (*ASSEMBLY_PRESENTERS, *ASSEMBLY_PUBLICATION)
    source_files = {PACKER, ARGUMENT_PARSER, ARGUMENT_FORMATTER, *assembly_images, *adapters.values(),
                    *(path for _name, roles in programs.values() for path, _calls in roles
                      if path not in (ARGUMENT_ARCHIVE, ASSEMBLY_PRESENTATION))}
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
