"""Build the native nominal constructor and type session from one cold source tree."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_nominal_json import admit_compile_receipt
from tools.build_hia_sqlite_pager import (
    EMBED_SOURCE, ROOT, build_embedder, digest, embed, link, load_static_object, verify_executable, write_new,
)
from tools.generate_hia_elf_linker import OUTPUT_LIMIT
from tools.qualify_hia_selfhost import compile_stage


ADAPTER = 'tools/hia_nominal_constructor.S'
PUBLICATION_ADAPTER = 'tools/hia_core_edit_publish_program.S'
ASSEMBLY_ADAPTER = 'tools/hia_core_edit_publish_assembly.S'
DRIVER = 'tools/build_hia_nominal_constructor.py'
TRANSPORT_TEMPLATES = {
    'constructor': 'examples/hia_bootstrap/nominal_constructor_transport_adapters.hepta',
    'constructor-tail': 'examples/hia_bootstrap/nominal_constructor_transport_tail.hepta',
    'publication': 'examples/hia_bootstrap/nominal_constructor_publication_adapters.hepta',
}
TRANSPORT_ROLES = (ADAPTER, PUBLICATION_ADAPTER, ASSEMBLY_ADAPTER)
NOMINAL_IMAGE_LABELS = {'owner': 'core_nominal_owner', 'render': 'core_nominal_render',
                        'nominal-json': 'core_nominal_codec'}
# The packed launcher inflates the private static ELF in 512 KiB blocks.
ORDINARY_CLI_IMAGE_CAPACITY = OUTPUT_LIMIT
COMPONENTS = {
    'nominal-json': 'examples/hia_bootstrap/nominal_json.hepta',
    'owner': 'examples/hia_bootstrap/composite_constructor_owner.hepta',
    'render': 'examples/hia_bootstrap/composite_constructor_render.hepta',
    'types': 'examples/hia_bootstrap/composite_types.hepta',
    'admit': 'examples/hia_bootstrap/composite_function_admit.hepta',
    'records': 'examples/hia_bootstrap/composite_function_records.hepta',
    'terms': 'examples/hia_bootstrap/composite_function_terms.hepta',
    'advanced': 'examples/hia_bootstrap/composite_function_advanced.hepta',
    'function-render': 'examples/hia_bootstrap/composite_function_render.hepta',
    'helpers': 'examples/hia_bootstrap/task_helpers.hepta',
    'outer-owner': 'examples/hia_bootstrap/composite_outer_owner.hepta',
    'outer-render': 'examples/hia_bootstrap/composite_outer_render.hepta',
    'public-core': 'examples/hia_bootstrap/core_admission.hepta',
    'public-canonical': 'examples/hia_bootstrap/json_canonical.hepta',
    'public-presentation': 'examples/hia_bootstrap/core_nominal_report_json.hepta',
    'publish-frontend': 'examples/hia_bootstrap/core_edit/publication_frontend.hepta',
    'publish-program': 'examples/hia_bootstrap/core_edit/publication_program.hepta',
    'publish-policy': 'examples/hia_bootstrap/core_edit/publication_policy.hepta',
    'assembly-roundtrip': 'examples/hia_bootstrap/core_edit/publication_render.hepta',
    'assembly-publication': 'examples/hia_bootstrap/core_edit/publication_assembly.hepta',
    'linker': 'examples/hia_bootstrap/elf_static_linker.hepta',
}


def build(output: Path, compiler: Path, cold: Path) -> Path:
    compiler_body, cold_body = compiler.read_bytes(), cold.read_bytes()
    admitted = admit_cold_build(compiler_body, cold_body)
    inputs = {name: (ROOT / name).read_bytes()
              for name in (*COMPONENTS.values(), EMBED_SOURCE, *TRANSPORT_TEMPLATES.values(), *TRANSPORT_ROLES, DRIVER)}
    if any(admitted.get(name) != digest(raw) for name, raw in inputs.items()):
        raise ValueError('constructor source differs from admitted cold build')

    output.mkdir(mode=0o700)
    images, checks = {}, {}
    for label, filename in COMPONENTS.items():
        path, receipt = compile_stage(output, label, compiler, inputs[filename])
        body = path.read_bytes()
        admit_compile_receipt(receipt, compiler_bytes=compiler_body,
                              source_bytes=inputs[filename], image_bytes=body)
        images[label], checks[path] = body, body
    templates = {name: build_embedder(output, compiler, inputs[path], label=f'{name}-adapters')
                 for name, path in TRANSPORT_TEMPLATES.items()}
    objects = [load_static_object(templates['constructor'], 0, inputs[ADAPTER],
                                  continuations=(templates['constructor-tail'],))]
    objects.extend(load_static_object(templates['publication'], role, inputs[adapter])
                   for role, adapter in enumerate(TRANSPORT_ROLES[1:], 1))
    embedder = build_embedder(output, compiler, inputs[EMBED_SOURCE])
    embedded = {**NOMINAL_IMAGE_LABELS, 'types': 'types_image', 'admit': 'function_admit',
                'records': 'function_records', 'terms': 'function_terms',
                'advanced': 'function_advanced', 'function-render': 'function_render',
                'helpers': 'function_helper', 'outer-owner': 'outer_owner',
                'outer-render': 'outer_render', 'public-core': 'public_core',
                'public-canonical': 'public_canonical', 'public-presentation': 'public_presentation',
                'publish-frontend': 'publish_frontend', 'publish-program': 'publish_program',
                'publish-policy': 'publish_policy',
                'assembly-roundtrip': 'assembly_roundtrip',
                'assembly-publication': 'assembly_publication'}
    for role, label in embedded.items():
        stem = 'constructor-' + role
        objects.append(embed(output, label, stem, images[role], embedder))
        checks[output / (stem + '.embedded.elf')] = images[role]
    binary, link_receipt = link(output, images['linker'], images['owner'], objects,
                                wire_magic=b'HIALNK01', executable_limit=ORDINARY_CLI_IMAGE_CAPACITY)
    for label in embedded:
        verify_executable(binary, images[label])
    if (current_sources() != admitted or compiler.read_bytes() != compiler_body
            or cold.read_bytes() != cold_body
            or any((ROOT / path).read_bytes() != raw for path, raw in inputs.items())
            or any(path.read_bytes() != raw for path, raw in checks.items())):
        raise ValueError('constructor inputs or images changed during build')

    executable = output / 'hia-nominal-constructor'
    with executable.open('xb') as stream:
        stream.write(binary)
        os.fchmod(stream.fileno(), 0o500)
    report = {'schema': 'hepta.hia.nominal-constructor-build.v1',
              'executable_sha256': digest(binary), 'executable_bytes': len(binary),
              'compiler_sha256': digest(compiler_body), 'cold_report_sha256': digest(cold_body),
              'source_sha256': {name: digest(raw) for name, raw in inputs.items()},
              'image_sha256': {name: digest(raw) for name, raw in images.items()},
              'link_receipt': link_receipt, 'whole_nominal_elaboration': False}
    write_new(output / 'build.json', (json.dumps(report, indent=2, sort_keys=True) + '\n').encode())
    return executable


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))


if __name__ == '__main__':
    main()
