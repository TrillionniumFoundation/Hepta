"""Cold-build the native primitive Core query, edit, impact and publication executables."""

import argparse
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import struct

from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.build_hia_agent_batch_commit import ELF_HEADER_SIZE, assemble_adapter
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.generate_hia_core_edit_packer import MAGIC
from tools.qualify_hia_selfhost import compile_stage
from tools.qualify_hia_selfhost_cli import inspect_executable

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = 'examples/hia_bootstrap/'
EDIT = BOOTSTRAP + 'core_edit/'
PACKER = EDIT + 'packer.hepta'
CAPACITY = 4 * (1 << 20) + 4096

# Each entry lists the four flat images in placement order, then the adapter
# relocation sites belonging to each. Several stages use the same image entry.
PROGRAMS = {
    'publish_program': ('hia-publish-program', (
        (EDIT + 'admission_word_io.hepta', ('core_address',)),
        (EDIT + 'publication_frontend.hepta', ('front_address',)),
        (EDIT + 'publication_program.hepta', ('owner_address',)),
        (EDIT + 'publication_policy.hepta', ('publication_address',)),
    )),
    'publish_import': ('hia-publish-import', (
        (EDIT + 'admission_word_io.hepta', ('core_address',)),
        (EDIT + 'publication_frontend.hepta', ('front_address',)),
        (EDIT + 'publication_import.hepta', ('owner_address',)),
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
        (EDIT + 'publication_patch_policy.hepta', ('front_address',)),
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
        (EDIT + 'impact_patch.hepta', ('extract', 'result')),
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


def pack(packer, stub, holes, images):
    frame = struct.pack('<7Q', MAGIC, len(stub), len(holes), *map(len, images))
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


def build(output, compiler, cold_report):
    compiler_raw, report_raw = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_raw, report_raw)
    adapters = {kind: 'tools/hia_core_edit_' + kind + '.S' for kind in PROGRAMS}
    source_files = {PACKER, *adapters.values(),
                    *(path for _name, roles in PROGRAMS.values() for path, _calls in roles)}
    sources = {path: (ROOT / path).read_bytes() for path in sorted(source_files)}
    if any(admitted.get(path) != digest(raw) for path, raw in sources.items()):
        raise ValueError('native Core edit source differs from admitted cold source')
    output.mkdir(mode=0o700)
    images, receipts = {}, {}
    for path, raw in sources.items():
        if not path.endswith('.hepta'):
            continue
        image, receipt = compile_stage(output, Path(path).stem, compiler, raw)
        images[path] = image.read_bytes()
        receipts[path] = receipt
    packer = NativeHiaJsonImage(images[PACKER], receipts[PACKER]['produced_sha256'])
    products = {}
    for kind, (name, roles) in PROGRAMS.items():
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
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))


if __name__ == '__main__':
    main()
