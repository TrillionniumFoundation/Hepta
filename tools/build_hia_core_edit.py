"""Cold-build native Core query, edit, impact and publication executables."""

import argparse
from hashlib import sha256
import json
from pathlib import Path
import struct

from tools.build_hia_agent_batch_commit import ELF_HEADER_SIZE
from tools import build_hia_core_edit_link as core_link, build_hia_core_static as core_static
from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.build_hia_nominal_constructor import (
    ADAPTER as NOMINAL_ADAPTER, COMPONENTS as NOMINAL_COMPONENTS,
    NOMINAL_IMAGE_LABELS, ORDINARY_CLI_IMAGE_CAPACITY,
)
from tools.qualify_hia_selfhost_cli import inspect_executable

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = 'examples/hia_bootstrap/'
EDIT = BOOTSTRAP + 'core_edit/'
CLI = BOOTSTRAP + 'core_cli/'
CORE_ADMISSION = BOOTSTRAP + 'core_admission.hepta'
SELFHOST_CORE_ARCHIVE = '<selfhost-core-images>'
SELFHOST_CORE_SOURCES = (
    CORE_ADMISSION,
    CLI + 'selfhost_semantics.hepta',
    BOOTSTRAP + 'core_nominal_report_json.hepta',
)
SELFHOST_ENTRY = CLI + 'selfhost_entry.hepta'
PACKER = EDIT + 'packer.hepta'
STATIC_ADAPTERS = (EDIT + 'adapter_templates_a.hepta', EDIT + 'adapter_templates_b.hepta')
ADAPTER_RECORD = struct.Struct('<32s32s32sQQ')
NOMINAL_ADAPTER_GROUPS = tuple(EDIT + f'nominal_adapters_{group}.hepta' for group in 'abcde')
NOMINAL_CONSTRUCTOR_GROUP = EDIT + 'nominal_constructor_adapter.hepta'
NOMINAL_BUILD_GROUP = EDIT + 'nominal_build_adapter.hepta'
NOMINAL_TEMPLATE_GROUPS = (*NOMINAL_ADAPTER_GROUPS, NOMINAL_CONSTRUCTOR_GROUP, NOMINAL_BUILD_GROUP)
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
# Shared adapters issue syntax and refusal-presentation operations as well as
# canonical-input hashes. Keep the complete owner in this common linker slot.
NOMINAL_BUILD_SOURCES = {
    key: NOMINAL_COMPONENTS[key]
    for key in (*NOMINAL_BUILD_IMAGES, 'owner', 'render', 'nominal-json', 'linker')
}
NOMINAL_BUILD_PRESENTATION = BOOTSTRAP + 'core_nominal_build_hash.hepta'
REGISTER_RELAY = 'tools/hia_core_edit_register_relay.inc'
REGISTER_RELAY_INCLUDE = b'.include "hia_core_edit_register_relay.inc"\n'
REGISTER_IMAGES = {
    BOOTSTRAP + 'sha256.hepta': 'register_hash',
    BOOTSTRAP + 'worker_register_schedule.hepta': 'register_schedule',
    BOOTSTRAP + 'worker_register_layout.hepta': 'register_layout',
}
PACKED_BUILD_IMAGES = {
    BOOTSTRAP + 'verified_simd_core.hepta': 'build_simd_subject',
    BOOTSTRAP + 'verified_simd_sse2_object.hepta': 'build_simd_object',
    BOOTSTRAP + 'verified_scalar_subject.hepta': 'build_scalar_subject',
    BOOTSTRAP + 'verified_scalar_object.hepta': 'build_scalar_object',
}
OBJECT_BUILD_IMAGES = {
    CORE_ADMISSION: 'build_core',
    **PACKED_BUILD_IMAGES,
    CLI + 'release_fixed_inflate.hepta': 'build_release_inflate',
    EDIT + 'publication_frontend.hepta': 'build_frontend',
    CLI + 'build_codegen.hepta': 'build_codegen',
    CLI + 'build_backend.hepta': 'build_backend',
    BOOTSTRAP + 'elf_shared_linker.hepta': 'build_shared_linker',
    BOOTSTRAP + 'elf_verified_linker.hepta': 'build_verified_linker',
    BOOTSTRAP + 'safe_core_elf_inventory.hepta': 'build_shared_inventory',
    BOOTSTRAP + 'sha256_stream.hepta': 'build_shared_hash',
    CLI + 'shared_build_report.hepta': 'build_shared_report',
    **{path: 'build_' + label for path, label in REGISTER_IMAGES.items()},
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
def nominal_cli_payloads(kind):
    # The private object builder calls canonical hashing and driver refusals.
    # Editing also calls syntax presentation and keeps the complete public owner.
    selected = NOMINAL_BUILD_SOURCES
    if kind == 'build_object':
        selected = {**selected, 'public-presentation': NOMINAL_BUILD_PRESENTATION}
    common = {selected[key]: label
              for key, label in {**NOMINAL_IMAGE_LABELS, **NOMINAL_BUILD_IMAGES}.items()}
    return {**common, **NOMINAL_CLI_IMAGES[kind]}


EDIT_ENVELOPE_ROLES = ('query', 'publish_query', 'patch_core_json', 'publish_patch', 'impact',
                       'batch_query', 'publish_batch_query', 'apply', 'publish_edit',
                       'batch_apply', 'publish_batch')

# Each entry lists the flat payloads in placement order, then the adapter
# relocation sites belonging to each. Several stages use the same image entry.
PROGRAMS = {
    'dispatch': ('hia', (
        (DISPATCH_ARCHIVE, ('dispatch_archive', 'query_syntax_archive')),
        (SELFHOST_ENTRY, ('selfhost_call',)),
        (ARGUMENT_PAYLOAD, ('argument_unpack', 'argument_frame', 'argument_encode', 'argument_command')),
        (ARGUMENT_ARCHIVE, ('argument_images',)),
    )),
    'selfhost_component': ('hia-selfhost-component', (
        (CLI + 'selfhost_controller.hepta', ('dispatch_call',)),
        (CLI + 'selfhost_selection.hepta', ('capsule_call',)),
        (SELFHOST_CORE_ARCHIVE, ('current_Core_archive', 'selected_Core_archive', 'Core_diagnostic_archive')),
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
        (BOOTSTRAP + 'borrowed_export_wire.hepta', ('borrowed_export',)),
        (BOOTSTRAP + 'borrowed_wrapper.hepta', ('borrowed_wrapper',)),
        *((path, (label,)) for path, label in REGISTER_IMAGES.items()),
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
_BUILD_ADAPTER = 'tools/hia_core_edit_build_object.S'
NOMINAL_ADAPTER_ROLES[_BUILD_ADAPTER] = (NOMINAL_BUILD_GROUP, NOMINAL_ADAPTER_ROLES[_BUILD_ADAPTER][1])


def digest(raw):
    return sha256(raw).hexdigest()


def expand_register_relay(source, relay):
    return source.replace(REGISTER_RELAY_INCLUDE, relay)


def check_placement(binary, stub, holes, images):
    expected = bytearray(stub)
    for index, image in enumerate(images):
        expected.extend(bytes(-len(expected) % 8))
        for hole, target in holes:
            if target == index:
                struct.pack_into('<i', expected, hole, len(expected) - hole - 4)
        expected.extend(image)
    if binary[ELF_HEADER_SIZE:] != expected:
        raise ValueError('native Core edit packer changed the admitted adapter or image placement')
    return inspect_executable(binary)


def build(output, compiler, cold_report, *, release_only=False, native_tools=None, constructor=None,
          prover_bytes=None, wheel_layout=False, retain_compiled_image=None):
    compiler_raw, report_raw = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_raw, report_raw)
    # The stdin-to-object development probe is not a public dispatcher role.
    # Public object builds use the checked, atomic build_object publisher.
    programs = {key: value for key, value in PROGRAMS.items()
                if not release_only or key != 'emit_object'}
    adapters = {kind: 'tools/hia_core_edit_' + kind + '.S' for kind in programs}
    assembly_images = (*ASSEMBLY_PRESENTERS, *ASSEMBLY_PUBLICATION)
    source_files = {PACKER, *STATIC_ADAPTERS, *NOMINAL_TEMPLATE_GROUPS, DISPATCH, ARGUMENT_PARSER, ARGUMENT_FORMATTER,
                    RELEASE_DEFLATE, BOOTSTRAP + core_link.POLICY, BOOTSTRAP + core_link.PACKED_POLICY,
                    *assembly_images, *SELFHOST_CORE_SOURCES, *adapters.values(),
                    NOMINAL_ADAPTER, EXEC_LAUNCHER, EDIT_ENVELOPE, EDIT_RESPONSE, BATCH_CAPTURE,
                    REGISTER_RELAY, *(path for kind in NOMINAL_CLI_IMAGES for path in nominal_cli_payloads(kind)),
                    *(path for _name, roles in programs.values() for path, _calls in roles
                      if path not in (DISPATCH_ARCHIVE, ARGUMENT_ARCHIVE, ASSEMBLY_PRESENTATION,
                                      SELFHOST_CORE_ARCHIVE))}
    sources = {path: (ROOT / path).read_bytes() for path in sorted(source_files)}
    if any(admitted.get(path) != digest(raw) for path, raw in sources.items()):
        raise ValueError('native Core edit source differs from admitted cold source')
    output.mkdir(mode=0o700)
    if native_tools is None:
        native_tools = core_static.cold_tools(output, compiler, cold_report, admitted)
    seed, compile_sources, call = native_tools
    compiler_sha256 = digest(compiler_raw)
    receipts = {}

    def compile_with_receipts(named):
        wire, images, originals = compile_sources(named)
        for name, relative in named.items():
            path = BOOTSTRAP + relative
            source_sha256 = digest(originals[name])
            if source_sha256 != admitted.get(path):
                raise ValueError('Core compilation consumed a source outside cold admission: ' + path)
            record = {'source_sha256': source_sha256, 'compiler_sha256': compiler_sha256,
                      'produced_sha256': digest(images[name]), 'produced_bytes': len(images[name])}
            if receipts.setdefault(path, record) != record:
                raise ValueError('Core source produced inconsistent native images: ' + path)
            if retain_compiled_image is not None:
                retain_compiled_image(path, images[name])
        return wire, images, originals

    native_tools = seed, compile_with_receipts, call
    if prover_bytes is None:
        prover_bytes = core_static.source_prover(output / 'supplied-proof', native_tools, admitted)
    if type(prover_bytes) is not bytes or not 176 <= len(prover_bytes) <= ORDINARY_CLI_IMAGE_CAPACITY:
        raise ValueError('Core requires the captured Safe Core verifier')
    if constructor is None:
        constructor = core_static.source_constructor(output / 'nominal-constructor', native_tools, admitted)
    if constructor.name != 'hia-nominal-constructor':
        raise ValueError('unexpected nominal constructor supplied to the Core build')

    compressor = core_static.ReleaseCodec(native_tools)
    products = core_static.build_products(native_tools, admitted, compressor=compressor, release_only=release_only)
    implementations = core_link.build_implementations(native_tools, admitted, prover=prover_bytes, codec=compressor)
    adapter_sha256 = {}
    for kind, (implementation, details) in implementations.items():
        name = programs[kind][0]
        prover = prover_bytes if kind == 'build_object' else None
        binary, packed = core_static.pack_implementation(native_tools, admitted, compressor, implementation, prover=prover)
        if digest(implementation) != packed['implementation_sha256']:
            raise ValueError('Core implementation differs from its packaged executable: ' + name)
        products[name] = binary, {**details, **packed}
        adapter_sha256.update(details['adapter_sha256'])
        if kind == 'build_object':
            if digest(prover_bytes) != packed['attached_prover_sha256']:
                raise ValueError('Core build attached a different Safe Core verifier')
            products['hia-worker-scalar-implementation'] = implementation, {**details, 'sha256': digest(implementation)}
    bound_roles = {name: products[name][0] for name in DISPATCH_ROLES if name != constructor.name}
    bound_roles[constructor.name] = constructor.read_bytes()
    pin_owner = core_static.policy_builder(native_tools, 'source_core_pin.hepta', 'source_build_packer.hepta')
    overrides = {
        DISPATCH: core_static.bound_source(native_tools, pin_owner, 1, sources[DISPATCH], bound_roles),
        SELFHOST_ENTRY: core_static.bound_source(native_tools, pin_owner, 2, sources[SELFHOST_ENTRY], {
            'hia-selfhost-component': products['hia-selfhost-component'][0],
        }),
    }
    if wheel_layout:
        # pip's scripts directory can be shared read-only with other users.
        # The HIA layout owner authenticates each original stat predicate before
        # admitting conventional root/user-owned modes. Member byte pins still bind the launch.
        layout = core_static.policy_builder(native_tools, 'source_wheel_layout.hepta', 'source_build_packer.hepta')
        for mode, path in enumerate((DISPATCH, SELFHOST_ENTRY), 1):
            packet = struct.pack('<8sQ', b'HIAWPER1', mode) + overrides[path]
            overrides[path] = call(layout, 'build', packet)
    dispatch = core_static.build_products(native_tools, admitted, overrides=overrides, compressor=compressor)
    name = programs['dispatch'][0]
    binary, details = dispatch[name]
    details['role_sha256'] = {role: digest(raw) for role, raw in bound_roles.items()}
    products[name] = binary, details
    if (current_sources() != admitted or compiler.read_bytes() != compiler_raw
            or cold_report.read_bytes() != report_raw
            or constructor.read_bytes() != bound_roles[constructor.name]
            or any((ROOT / path).read_bytes() != raw for path, raw in sources.items())):
        raise ValueError('native Core edit build inputs changed before publication')
    expected = {name for name, _ in programs.values()} | {'hia-worker-scalar-implementation'}
    if set(products) != expected:
        raise ValueError('Core build did not produce exactly its declared executable set')
    for name, (binary, _details) in products.items():
        executable = output / name
        with executable.open('xb') as stream:
            stream.write(binary)
        executable.chmod(0o500)
    (output / 'build.json').write_text(json.dumps({
        'schema': 'hepta.hia.core-edit-build.v1',
        'compiler_sha256': digest(compiler_raw), 'cold_report_sha256': digest(report_raw),
        'native_nominal_adapter_object_sha256': adapter_sha256,
        'supplied_proof_sha256': digest(prover_bytes),
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
