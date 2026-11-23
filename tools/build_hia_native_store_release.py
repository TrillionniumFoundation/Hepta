"""Build and verify a flat native Store release from a matching HIA cold qualification."""
from __future__ import annotations

import argparse
import gzip
import io
from contextlib import ExitStack
from hashlib import sha256
from importlib import import_module
import json
import os
import stat
import struct
from pathlib import Path
import tarfile
from tempfile import NamedTemporaryFile, TemporaryDirectory

from tools.build_hia_core_edit import PROGRAMS as CORE_EDIT_PROGRAMS
from tools.build_hia_source_build import _compiled_sources, _run_captured, _source_bundle
from tools.build_hia_json_preflight import CANDIDATES, ROOT, _image_manifest, admit_cold_build, current_sources
from tools.build_hia_sqlite_components import PROJECTION, UNITS
from tools.build_hia_worker_release import AGENT_STDIO_ROLES, INSTALLED_HELPERS


# These are release entry points. Other stdio variants have independent build contracts.
STDIO_ROLES = tuple(sorted(AGENT_STDIO_ROLES.keys() - {
    'borrowed-wrapper', 'context-cost-diagnostic', 'worker-describe-reactor',
}))
FLOW_ROLES = ('describe', 'input', 'artifact', 'discovery', 'context', 'inspection',
              'candidate', 'rollback', 'emit', 'adopt', 'verify', 'discovery-bootstrap',
              'evaluate-replay', 'evaluate-intake', 'evaluate-claim', 'evaluate-run-input', 'evaluate-run', 'evaluate-proof', 'evaluate-document', 'evaluate-closeout', 'evaluate-unkeyed')
LAUNCHERS = ('read', 'context-control', 'native', 'readonly', 'evaluate-replay', 'evaluate-intake', 'evaluate-full')
RESOURCES = ('examples/hia_bootstrap/selfhost.hepta', 'examples/hia_bootstrap/source_build_packer.hepta',
             'examples/hia_bootstrap/source_filter_member.hepta',
             'examples/hia_bootstrap/source_build_policy.hepta', 'examples/hia_bootstrap/core_json_cli_packer.hepta',
             'examples/hia_bootstrap/core_json_frontend.hepta', 'docs/HIA_SELFHOST_CORE_SUPPORT.json',
             'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json')


def _compile(work, component, compiler, cold_report, *args, label=None, **options):
    builder = import_module('tools.build_hia_' + component).build
    directory = work / (label or component)
    return builder(directory, compiler, cold_report, *args, **options)


def _stage_component_outputs(work, compiler, cold_report, publish):
    with TemporaryDirectory(prefix='source-build-', dir=work) as tmp:
        publish(_compile(Path(tmp), 'source_build', compiler, cold_report))


def _stage_agent_store(work, seed, compile_sources, call, compiler, admitted, publish):
    """Compile the Store's word-filtered units, bundle its modules and bind the transaction root."""
    from tools.build_hia_agent_batch_commit import verify_placement
    from tools.build_hia_agent_store import ADAPTER, PLAN, PROGRAMS, ROOT_INSTRUCTIONS
    from tools.generate_hia_native_filter import read_adapter_binding

    plan_bytes = (ROOT / PLAN).read_bytes()
    if sha256(plan_bytes).hexdigest() != admitted.get(PLAN):
        raise ValueError('native Store plan differs from its cold admission')
    plan = json.loads(plan_bytes)
    groups = plan['modules']
    if (plan['schema'] != 'hepta.hia.agent-store-build-plan.v1'
            or [group['role'] for group in groups] != list(range(4))):
        raise ValueError('invalid native Store module plan')

    def owner(name):
        kit, images, sources = compile_sources({
            'source_build_policy.hepta': 'source_agent_store.hepta',
            'selfhost.hepta': 'selfhost.hepta',
            'source_build_packer.hepta': 'agent_store/' + name,
        })
        if images['selfhost.hepta'] != compiler:
            raise ValueError('native Store requires the admitted cold compiler')
        alias = 'source_build_packer.hepta'
        return call(seed, 'pack', kit), images[alias], sources[alias]

    def build(program, tag, role, parts):
        sizes = struct.pack('<' + 'Q' * len(parts), *map(len, parts))
        header = struct.pack('<8s3Q', tag, role, len(plan_bytes), len(parts))
        return call(program, 'build', header + sizes + plan_bytes + b''.join(parts))

    word_filter, _, _ = owner('word_filter.hepta')
    bundle, bundle_image, _ = owner('bundle_packer.hepta')
    root, _, root_packer_source = owner(plan['units']['packer']['source'])
    if sha256(bundle_image).hexdigest() != plan['bundle_packer_sha256']:
        raise ValueError('native Store bundle packer differs from its plan')
    adapter = (ROOT / ADAPTER).read_bytes()
    if sha256(adapter).hexdigest() != admitted.get(ADAPTER):
        raise ValueError('native Store adapter differs from its cold admission')
    binding = read_adapter_binding(root_packer_source, adapter, calls=len(ROOT_INSTRUCTIONS))

    units = {name: spec for name, spec in plan['units'].items() if 'id' in spec}
    if sorted(spec['id'] for spec in units.values()) != list(range(25)):
        raise ValueError('invalid native Store word-filter unit identities')
    paths = {spec['source']: (PROGRAMS + spec['source']).removeprefix('examples/hia_bootstrap/')
             for spec in units.values()}
    _, flats, _ = compile_sources(paths)
    images = {}
    for name, spec in units.items():
        images[name] = build(word_filter, b'HIAAWFL1', spec['id'], [flats[spec['source']]])
    modules = [build(bundle, b'HIAAWBN1', group['role'], [images[name] for name in group['units']])
               for group in groups]
    manifest = build(bundle, b'HIAAWMF1', 0, modules)
    parts = {'loader': images['loader'], 'owner': images['owner'], 'manifest': manifest, 'json': images['JSON_hub']}
    executable = build(root, b'HIAAWR01', 0, list(parts.values()))
    verify_placement(executable, binding, parts, instructions=tuple(ROOT_INSTRUCTIONS[name] for name in parts))
    if (ROOT / PLAN).read_bytes() != plan_bytes or (ROOT / ADAPTER).read_bytes() != adapter:
        raise ValueError('a Store build input changed before publication')
    for group, module in zip(groups, modules, strict=True):
        path = work / f"module-{group['role']}.bin"
        path.write_bytes(module)
        publish(path, expected=group['sha256'])
    path = work / 'hia-agent-store'
    path.write_bytes(executable)
    publish(path, expected=plan['expected_root_sha256'])


def _stage_sqlite_migrations(work, compile_sources, admitted, publish, tools, linked, dependencies, compiler, report):
    """Use native source objects and hash-bound child executables for both migration programs."""
    from tools.build_hia_sqlite_migrate import ADAPTER as MIGRATE_ADAPTER, COMPONENTS, COORDINATOR, read_component
    from tools.build_hia_sqlite_migration_publish import (
        ADAPTER as PUBLISH_ADAPTER, MIGRATION_TEMPLATES, UNITS as PUBLISH_UNITS, read_dependency,
    )
    from tools.build_hia_sqlite_pager import EMBED_SOURCE, STATIC_LINKER, verify_executable

    adapter, embed, link = tools
    (components, selected), (pager, pager_record) = linked
    compiler_pin, report_pin = sha256(compiler).hexdigest(), sha256(report).hexdigest()
    identity = {'compiler_sha256': compiler_pin, 'cold_report_sha256': report_pin}
    pager_receipt = {'schema': 'hepta.hia.sqlite-pager-build.v1', **identity, **pager_record}
    (pager / 'build.json').write_text(json.dumps(pager_receipt, sort_keys=True, indent=2) + '\n')
    receipt = {'schema': 'hepta.hia.sqlite-component-process-build.v1', **identity,
               'source_sha256': selected['source_sha256'], 'executable_manifest': {PROJECTION: selected}}
    (components / 'build.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')

    publication = (PUBLISH_UNITS['sqlite-migration-publish'], PUBLISH_UNITS['sqlite-agent-artifact-catalog'])
    names = {Path(path).name: Path(path).name for path in (*publication, COORDINATOR)}
    _, images, sources = compile_sources(names)
    owner_path = 'examples/hia_bootstrap/source_sqlite_unit.hepta'
    common = (MIGRATION_TEMPLATES, EMBED_SOURCE, STATIC_LINKER, owner_path)
    folders = {'pager': pager, 'staging': components, 'initializer': dependencies['initialize']}
    checks = []
    for name, template_role, adapter_path, source_roles, section, magic in (
            ('hia-sqlite-migration-publish', 0, PUBLISH_ADAPTER, tuple(enumerate(publication, 36)), 17, b'HIAMGPL1'),
            ('hia-sqlite-migrate', 1, MIGRATE_ADAPTER, ((38, COORDINATOR),), 20, b'HIAMGCL1')):
        objects = [adapter(MIGRATION_TEMPLATES, template_role, adapter_path)]
        embedded = []
        for role, path in source_roles:
            alias = Path(path).name
            objects.append(embed(b'HIAMGIS1', role, sources[alias]))
            embedded.append(images[alias])

        children = []
        if template_role == 0:
            for folder, program, schema in (
                    (dependencies['artifact'], 'hia-artifact', 'hepta.hia.artifact-publication-build.v1'),
                    (dependencies['batch'], 'hia-agent-batch-commit', 'hepta.hia.agent-batch-commit-build.v1')):
                raw, executable, receipt = read_dependency(folder, program, schema, compiler_pin, report_pin, admitted)
                children.append(raw)
                checks.extend((executable, receipt))
        else:
            for label, program, schema in COMPONENTS:
                raw, captured = read_component(folders[label], label, program, schema, compiler_pin, report_pin, admitted)
                children.append(raw)
                checks.extend(captured)
        for ordinal, raw in enumerate(children, section):
            objects.append(embed(b'HIAMGEL1', ordinal, raw, sha256(raw).digest()))
        executable = link(magic, objects)
        for raw in (*embedded, *children):
            verify_executable(executable, raw)
        if any(path.read_bytes() != raw for path, raw in checks):
            raise ValueError('a sealed SQLite migration dependency changed before publication')
        digest = sha256(executable).hexdigest()
        if template_role == 0:
            consumed = (*common, adapter_path, *publication)
            source_pins = {path: admitted[path] for path in consumed}
            folder = _migration_dependency(work, name, 'hepta.hia.sqlite-migration-publish-build.v1', executable,
                                           {'sha256': digest}, source_pins, compiler, report)
            folders['publisher'] = folder
            path = folder / name
        else:
            path = work / name
            path.write_bytes(executable)
        publish(path, expected=digest)


def _stage_helper_images(work, seed, compile_sources, call, compiler, publish):
    """Rebuild the eight flat images and let HIA attest each source/compiler/image tuple."""
    kit, kit_images, kit_sources = compile_sources({
        'source_build_policy.hepta': 'source_helper_manifest.hepta',
        'selfhost.hepta': 'selfhost.hepta',
        'source_build_packer.hepta': 'source_build_packer.hepta',
    })
    if kit_images['selfhost.hepta'] != compiler:
        raise ValueError('flat helper compiler differs from the admitted cold compiler')
    author = call(seed, 'pack', kit)
    selfhost = kit_sources['selfhost.hepta']
    names = [CANDIDATES[kind][0] + '.hepta' for kind in INSTALLED_HELPERS]
    _, images, sources = compile_sources({name: name for name in names})
    compiler_sha = sha256(compiler).hexdigest()

    for role, (kind, name) in enumerate(zip(INSTALLED_HELPERS, names, strict=True), 1):
        source, image = sources[name], images[name]
        frame = struct.pack('<8s5Q', b'HIAHLM01', role, len(source), len(image), len(selfhost), len(compiler))
        raw = call(author, 'build', frame + source + image + selfhost + compiler)
        protocol = CANDIDATES[kind][1]
        image_name = protocol + '.image.bin'
        expected = _image_manifest(kind, protocol, source, image, image_name, compiler_sha)
        if json.loads(raw) != expected:
            raise ValueError('native flat helper manifest differs from the admitted inputs: ' + kind)
        manifest_path = work / (kind + '-manifest.json')
        manifest_path.write_bytes(raw)
        publish(manifest_path)
        image_path = work / image_name
        image_path.write_bytes(image)
        publish(image_path, expected=expected['image_sha256'])


def _stage_safe_proof(work, seed, compile_sources, call, admitted, publish):
    """Recompile and authenticate the five nested proof programs before publishing their verifier."""
    from tools.build_hia_agent_batch_commit import verify_placement
    from tools.build_hia_safe_core_binder import PARTS, MACHINE_PARTS, OBSERVATION_PARTS, OBLIGATION_PARTS
    from tools.build_hia_supplied_safe_core_proof import HASH_SOURCE, check_placement
    from tools.generate_hia_core_admission_cli import STATE_BYTES, ARENA_BYTES
    from tools.generate_hia_native_filter import elf_header, read_adapter_binding, template, verify_adapter
    from tools.generate_hia_safe_core_binder_packer import ADAPTER, CALLS, PACKER, PROOF_PACKER, adapter_source
    from tools.generate_hia_supplied_safe_core_proof import SOURCE_PATH
    from tools.generate_hia_supplied_safe_core_proof_packer import ADAPTER as FINAL_ADAPTER, PACKER as FINAL_PACKER

    def adapter(name):
        data = (ROOT / name).read_bytes()
        if sha256(data).hexdigest() != admitted.get(name):
            raise ValueError('nested proof adapter differs from cold admission: ' + name)
        return data

    builds = release_sources(seed, compile_sources, call)

    def record(source, image, *, embedded=False):
        header = struct.pack('<QQ', len(source), len(image))
        return header + source if embedded else header + source + image

    def request(role, rows):
        return struct.pack('<8sQ', b'HIASPR01', role) + b''.join(rows)

    subject = ('core_admission.hepta', 'core_proof_subject.hepta')
    recipes = [subject, *(tuple(Path(path).name for path in parts.values())
                          for parts in (PARTS, MACHINE_PARTS, OBSERVATION_PARTS, OBLIGATION_PARTS))]
    packers = ('core_proof_subject_cli_packer.hepta', *(Path(PACKER).name for _ in range(3)), Path(PROOF_PACKER).name)
    outer = (Path(SOURCE_PATH).name, Path(HASH_SOURCE).name)
    final_packer = Path(FINAL_PACKER).name
    names = {*packers, *outer, final_packer, *(name for group in recipes for name in group)}
    _, images, sources = compile_sources({name: name for name in sorted(names)})
    controllers = {name: builds.kit('source_safe_proof.hepta', name)
                   for name in dict.fromkeys((*packers, 'native_filter_packer.hepta'))}
    final_rows = [record(sources[name], images[name]) for name in outer]
    children = []
    for role, (names, packer) in enumerate(zip(recipes, packers, strict=True), 1):
        rows = [record(sources[name], images[name]) for name in names]
        child = call(controllers[packer], 'build', request(role, rows))
        if role == 1:
            prefix, absolute = template(output_bytes=STATE_BYTES, workspace_bytes=ARENA_BYTES, formatter=True)
            header = len(elf_header())
            binding = (sha256(prefix[header:]).digest(), len(prefix) - header, tuple(h - header for h in absolute))
            verify_adapter(child, b''.join(images[n] for n in names), binding, entries=(0, len(images[names[0]])))
        else:
            binding = read_adapter_binding(sources[packer], adapter_source(adapter(ADAPTER), proof=role == 5), calls=len(CALLS))
            verify_placement(child, binding, {n: images[n] for n in names})
        children.append(child)
        final_rows.append(struct.pack('<Q', len(child)) + child)
        final_rows.extend(record(sources[name], images[name], embedded=True) for name in names)

    # The outer frame exceeds the source seed's three-image packing buffer. The HIA
    # controller publishes it through its ordinary stdout arena after verifying every child.
    filter_owner = controllers['native_filter_packer.hepta']
    runner = call(filter_owner, 'build', request(7, [record(sources[final_packer], images[final_packer])]))
    frame = call(filter_owner, 'build', request(6, final_rows))
    product = call(runner, None, frame)
    binding = read_adapter_binding(sources[final_packer], adapter(FINAL_ADAPTER), calls=3)
    check_placement(product, binding, [*(images[name] for name in outer), *children])
    path = work / 'hia-safe-core-prove'
    path.write_bytes(product)
    publish(path, expected=sha256(product).hexdigest())


def source_owned_reference(seed, compile_sources, call, compiler, admitted):
    """Link a native compiler that reports the private executor entry for this source."""
    from tools.generate_hia_native_filter import elf_header, read_adapter_binding, verify_adapter
    from tools.generate_hia_owned_reference import ADAPTER_PATH, PACKER_PATH, SOURCE_PATH

    policy = 'source_owned_reference.hepta'
    kit, kit_images, _ = compile_sources({
        'source_build_policy.hepta': policy, 'selfhost.hepta': 'selfhost.hepta',
        'source_build_packer.hepta': 'source_build_packer.hepta',
    })
    if kit_images['selfhost.hepta'] != compiler:
        raise ValueError('owned reference requires the admitted cold compiler')
    composer = call(seed, 'pack', kit)
    packer = Path(PACKER_PATH).name
    owned = Path(SOURCE_PATH).name
    components = (policy, 'selfhost.hepta', 'owned_reference_entry_wrapper.hepta',
                  'owned_reference_entry_stub.hepta', packer)
    _, images, sources = compile_sources({name: name for name in (*components, owned)})
    pieces = [piece for name in components for piece in (sources[name], images[name])]
    frame = struct.pack('<8s10Q', b'HIAOCM01', *map(len, pieces)) + b''.join(pieces)
    assembler = call(composer, 'build', frame)
    source = sources[owned]
    product = call(assembler, 'build', struct.pack('<8sQ', b'HIAORUN1', len(source)) + source)

    adapter = (ROOT / ADAPTER_PATH).read_bytes()
    if sha256(adapter).hexdigest() != admitted.get(ADAPTER_PATH):
        raise ValueError('owned reference adapter differs from cold admission')
    binding = read_adapter_binding(sources[packer], adapter, calls=2)
    _, adapter_size, (_, hole) = binding
    header = len(elf_header())
    if len(product) != header + adapter_size + len(images[owned]):
        raise ValueError('owned reference length differs from its admitted components')
    entry = hole + 4 + struct.unpack_from('<i', product, header + hole)[0] - adapter_size
    if entry < 0 or images[owned][entry:entry + 4] != bytes.fromhex('554889e5'):
        raise ValueError('owned reference private entry lacks the compiled function prologue')
    verify_adapter(product, images[owned], binding, entries=(0, entry))
    return product


def _stage_owned_reference(work, seed, compile_sources, call, compiler, admitted, publish):
    product = source_owned_reference(seed, compile_sources, call, compiler, admitted)
    path = work / 'hia-owned-reference-wire'
    path.write_bytes(product)
    publish(path, expected=sha256(product).hexdigest())


def _stage_read_carrier(work, seed, compile_sources, call, admitted, publish):
    """Build each Read flow and bind the four position-independent entries in HIA."""
    from tools.build_hia_agent_batch_commit import verify_placement
    from tools.build_hia_worker_flow import _adapter_binding
    from tools.generate_hia_native_filter import elf_header, read_adapter_binding, verify_adapter
    from tools.generate_hia_worker_flow_packer import FLOW, PEERS, PEER_KINDS, PORTS, PROGRAMS
    from tools.generate_hia_worker_read_release import ADAPTER, ENTRIES, SOURCE

    def cold_source(name):
        raw = (ROOT / name).read_bytes()
        if sha256(raw).hexdigest() != admitted.get(name):
            raise ValueError('native Read carrier dependency differs from cold admission: ' + name)
        return raw

    builds = release_sources(seed, compile_sources, call)

    def builder(packer):
        return builds.kit('source_read_carrier.hepta', Path(packer).name)

    source_names = [Path(PROGRAMS[role][0]).name for role in ENTRIES]
    _, images, sources = compile_sources({name: name for name in source_names})
    entries = []
    bodies = {}
    flow = {name: cold_source(name) for name in (FLOW, PORTS)}
    for ordinal, (role, name) in enumerate(zip(ENTRIES, source_names, strict=True), 1):
        _, packer = PROGRAMS[role]
        source = sources[name]
        request = struct.pack('<8sQQ', b'HIARDIN1', ordinal, len(source)) + source
        elf = call(builder(packer), 'build', request)
        dependencies = {**flow, packer: cold_source(packer)}
        if role in PEER_KINDS:
            dependencies[PEERS] = cold_source(PEERS)
        binding = _adapter_binding(dependencies, role, packer)
        verify_adapter(elf, images[name], binding, entries=(0,))
        entries.extend((source, elf))
        bodies[role] = elf[len(elf_header()):]

    request = struct.pack('<8s8Q', b'HIARDLK1', *map(len, entries)) + b''.join(entries)
    carrier = call(builder(SOURCE), 'build', request)
    binding = read_adapter_binding(cold_source(SOURCE), cold_source(ADAPTER), calls=len(ENTRIES))
    verify_placement(carrier, binding, bodies, instructions=(b'\xe9',) * len(ENTRIES))
    path = work / 'hia-agent-read-carrier'
    path.write_bytes(carrier)
    publish(path, expected=sha256(carrier).hexdigest())


def _sqlite_build_tools(seed, linker, compile_sources, call, admitted):
    """Bind source admission, object generation and sealed native linking to one build."""
    from functools import cache

    builds = release_sources(seed, compile_sources, call)

    @cache
    def owner(application):
        return builds.kit('source_sqlite_unit.hepta', application)

    def adapter(template, ordinal, name, *, continuation=None):
        source = (ROOT / name).read_bytes()
        if sha256(source).hexdigest() != admitted.get(name):
            raise ValueError('SQLite adapter source differs from cold admission: ' + name)
        if continuation is not None:
            if ordinal != 0:
                raise ValueError('the split nominal constructor adapter uses role zero')
            fragments = []
            for part, path in enumerate((template, continuation)):
                request = struct.pack('<8sQQ', b'HIACTPT1', part, len(source)) + source
                fragments.append(call(owner(Path(path).name), 'build', request))
            first, tail = fragments
            packet = struct.pack('<8s3Q', b'HIACTAD1', len(source), len(first), len(tail))
            return call(embedder, 'build', packet + source + first + tail)
        frame = struct.pack('<8sQQ', b'HIASQAD1', ordinal, len(source)) + source
        return call(owner(Path(template).name), 'build', frame)

    embedder = owner('elf_embed_image.hepta')

    def embed(kind, ordinal, data, pin=b''):
        request = struct.pack('<8sQQ', kind, ordinal, len(data)) + pin + data
        return call(embedder, 'build', request)

    def link(kind, inputs):
        request = struct.pack('<8s' + str(len(inputs)) + 'Q', kind, *map(len, inputs)) + b''.join(inputs)
        return call(linker, None, call(embedder, 'build', request))

    return adapter, embed, link


def _stage_nominal_constructor(work, compile_sources, publish, tools):
    """Compile the twenty public constructor components and link their named HIA objects."""
    from tools.build_hia_nominal_constructor import COMPONENTS, CONSTRUCTOR_IMAGES, TRANSPORT_ROLES, TRANSPORT_TEMPLATES
    from tools.build_hia_sqlite_pager import verify_executable

    adapter, embed, link = tools
    transport = adapter(TRANSPORT_TEMPLATES['constructor'], 0, TRANSPORT_ROLES[0],
                        continuation=TRANSPORT_TEMPLATES['constructor-tail'])
    objects = [transport]
    for ordinal, name in enumerate(TRANSPORT_ROLES[1:], 1):
        objects.append(adapter(TRANSPORT_TEMPLATES['publication'], ordinal, name))
    paths = {Path(COMPONENTS[role]).name: COMPONENTS[role].removeprefix('examples/hia_bootstrap/')
             for role in CONSTRUCTOR_IMAGES}
    _, images, sources = compile_sources(paths)
    for ordinal, role in enumerate(CONSTRUCTOR_IMAGES, 39):
        alias = Path(COMPONENTS[role]).name
        objects.append(embed(b'HIACTIM1', ordinal, sources[alias]))
    executable = link(b'HIACTLK1', objects)
    for image in images.values():
        verify_executable(executable, image)
    path = work / 'hia-nominal-constructor'
    path.write_bytes(executable)
    publish(path, expected=sha256(executable).hexdigest())
    return path


def _stage_sqlite_units(work, compile_sources, admitted, publish, tools):
    """Build the installed SQLite units through sealed HIA source, embedding and linking stages."""
    from tools.build_hia_agent_artifact_capture import UNIT as CAPTURE_UNIT
    from tools.build_hia_nominal_json import SOURCE_NAME as NOMINAL_SOURCE, STDIO, STDIO_TEMPLATE
    from tools.build_hia_sqlite_components import (
        CAPTURE_ADAPTERS, COMPONENT_TEMPLATES, INPUT, PROJECTION_ADAPTER, PROJECTION_ROLES, START,
    )
    from tools.build_hia_sqlite_pager import ADAPTERS, EMBED_SOURCE, PAGER, STATIC_LINKER, STREAM, TEMPLATES, verify_executable

    adapter, embed_bytes, link = tools
    objects = [adapter(COMPONENT_TEMPLATES, ordinal, name)
               for ordinal, name in enumerate((START, INPUT, *CAPTURE_ADAPTERS, PROJECTION_ADAPTER))]
    nominal_adapter = adapter(STDIO_TEMPLATE, 0, STDIO)
    pager_adapters = [adapter(TEMPLATES, i, path) for i, path in enumerate(ADAPTERS)]
    recipes = [(unit, b'HIASQUN1', ordinal, objects[:2]) for ordinal, unit in enumerate(UNITS, 1)]
    recipes.append((CAPTURE_UNIT, b'HIASQCP1', 32, objects[2:4]))
    recipes.append(('nominal-packet', b'HIANMPK1', 33, [nominal_adapter]))
    projection_units = (PROJECTION, *PROJECTION_ROLES)
    source_names = {unit: unit.replace('-', '_') + '.hepta'
                    for unit in (*[row[0] for row in recipes], *projection_units)}
    source_names['nominal-packet'] = Path(NOMINAL_SOURCE).name
    source_names.update({'pager': Path(PAGER).name, 'stream': Path(STREAM).name})
    _, images, sources = compile_sources({name: name for name in source_names.values()})

    def embed(unit, kind, ordinal):
        source = sources[source_names[unit]]
        return embed_bytes(kind, ordinal, source)

    for unit, kind, ordinal, adapter_objects in recipes:
        link_kind = b'HIANMLK1' if unit == 'nominal-packet' else b'HIASQLK1'
        executable = link(link_kind, (*adapter_objects, embed(unit, kind, ordinal)))
        verify_executable(executable, images[source_names[unit]])
        path = work / ('hia-' + unit)
        path.write_bytes(executable)
        publish(path, expected=sha256(executable).hexdigest())

    projection_inputs = [objects[4]]
    for ordinal, unit in enumerate(projection_units, 1):
        projection_inputs.append(embed(unit, b'HIASQPR1', ordinal))
    executable = link(b'HIASQPL1', projection_inputs)
    for unit in projection_units:
        verify_executable(executable, images[source_names[unit]])
    staging = work / 'native-sqlite-staging'
    staging.mkdir(mode=0o700)
    path = staging / ('hia-' + PROJECTION)
    path.write_bytes(executable)
    digest = sha256(executable).hexdigest()
    publish(path, expected=digest)
    projection_sources = [STATIC_LINKER, EMBED_SOURCE, COMPONENT_TEMPLATES, PROJECTION_ADAPTER,
                          *('examples/hia_bootstrap/' + source_names[unit] for unit in projection_units)]
    record = {'name': path.name, 'sha256': digest, 'bytes': len(executable),
              'source_sha256': {name: admitted[name] for name in projection_sources},
              'image_sha256': {unit: sha256(images[source_names[unit]]).hexdigest() for unit in projection_units}}
    pager_inputs = (*pager_adapters, embed('pager', b'HIAPGIM1', 34), embed('stream', b'HIAPGIM1', 35))
    pager = link(b'HIAPGLK3', pager_inputs)
    for name in ('pager', 'stream'):
        verify_executable(pager, images[source_names[name]])
    pager_directory = work / 'native-sqlite-pager'
    pager_directory.mkdir(mode=0o700)
    executable = pager_directory / 'hia-sqlite-pager'
    executable.write_bytes(pager)
    pager_digest = sha256(pager).hexdigest()
    publish(executable, expected=pager_digest)
    consumed = (PAGER, STREAM, TEMPLATES, STATIC_LINKER, EMBED_SOURCE, *ADAPTERS,
                'examples/hia_bootstrap/source_sqlite_unit.hepta')
    pager_record = {'executable_sha256': pager_digest, 'source_sha256': {path: admitted[path] for path in consumed}}
    return (staging, record), (pager_directory, pager_record)


def _stage_agent_stdio(work, seed, catalog_program, compile_sources, call, compiler_bytes, publish):
    """Publish the original Agent stdio ELF with catalog recipes constructed by HIA."""
    core = ('agent_stdio_dispatch.hepta', 'core_json_frontend.hepta', 'selfhost.hepta')
    _, images, sources = compile_sources({name: name for name in core})
    if images['selfhost.hepta'] != compiler_bytes:
        raise ValueError('Agent stdio selfhost differs from the cold compiler')
    builds = release_sources(seed, compile_sources, call)
    author = builds.kit('source_agent_stdio.hepta', 'agent_stdio_packer.hepta')
    # Nine ordered catalogs belong to the published Agent stdio v2 protocol.
    catalogs = [call(catalog_program, ('--schema', f'hepta.hia.program.v{version}'), b'')
                for version in range(1, 10)]
    parts = [*(sources[name] for name in core), *(images[name] for name in core), *catalogs]
    request = struct.pack('<8s15Q', b'HIAAGS01', *map(len, parts)) + b''.join(parts)
    executable = call(author, 'build', request)
    path = work / 'hia-native'
    path.write_bytes(executable)
    publish(path, expected=sha256(executable).hexdigest())


def _bind_transaction_program(work, kind, variant, source_map, images, program, admitted, compiler, report):
    from tools.build_hia_agent_batch_commit import verify_placement
    from tools.generate_hia_native_filter import read_adapter_binding
    from tools.qualify_hia_selfhost_cli import inspect_executable

    name, _tag, packer, adapter, calls = variant
    packer_source = (ROOT / packer).read_bytes()
    adapter_source = (ROOT / adapter).read_bytes()
    if (sha256(packer_source).hexdigest() != admitted.get(packer) or
            sha256(adapter_source).hexdigest() != admitted.get(adapter)):
        raise ValueError('transaction adapter source differs from the cold admission: ' + name)
    binding = read_adapter_binding(packer_source, adapter_source, calls=len(calls))
    parts = {label: images[alias] for label, alias in zip(calls, source_map, strict=True)}
    verify_placement(program, binding, parts)
    if kind == 'sealed':
        return None
    # The migration publisher consumes the batch writer. Its coordinator opens
    # the initializer independently and validates its executable and cold pins.
    sources = (packer, adapter, *('examples/hia_bootstrap/' + value for value in source_map.values()))
    schema = ('hepta.hia.agent-store-init-build.v1' if kind == 'initialize'
              else 'hepta.hia.agent-batch-commit-build.v1')
    return _migration_dependency(work, name, schema, program, inspect_executable(program),
                                 {path: admitted[path] for path in sources}, compiler, report)


def _migration_dependency(work, name, schema, program, inspection, sources, compiler, report):
    folder = work / ('migration-dependency-' + name)
    folder.mkdir(mode=0o700)
    (folder / name).write_bytes(program)
    receipt = {'schema': schema, 'executable_path': name, 'executable_sha256': sha256(program).hexdigest(),
               'executable': inspection, 'source_sha256': sources,
               'compiler_sha256': sha256(compiler).hexdigest(), 'cold_report_sha256': sha256(report).hexdigest()}
    (folder / 'build.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    return folder


def _bind_artifact_publisher(work, program, admitted, compiler, report):
    from hepta.hia_artifact_delivery_protocol import control_descriptor, private_executable, public_executable
    from tools.build_hia_artifact_publication import SOURCES

    sources = {}
    for name in SOURCES:
        digest = sha256((ROOT / name).read_bytes()).hexdigest()
        if digest != admitted.get(name):
            raise ValueError('artifact publisher source differs from its cold admission: ' + name)
        sources[name] = digest
    descriptor = control_descriptor(program)
    private = private_executable(program)
    if public_executable(private) != program:
        raise ValueError('artifact delivery descriptor does not restore the public publisher')
    inspection = {'sha256': sha256(program).hexdigest(), 'public_entry': descriptor.public_entry,
                  'private_entry': descriptor.private_entry, 'private_sha256': sha256(private).hexdigest()}
    return _migration_dependency(work, 'hia-artifact', 'hepta.hia.artifact-publication-build.v1',
                                 program, inspection, sources, compiler, report)


def _source_directory_recipe():
    from tools.build_hia_release_install import DIRECTORY_SOURCES

    policy, packer, hasher = (Path(path).name for path in DIRECTORY_SOURCES[:3])
    name = 'hia-directory-package-build'
    return name, packer, {name + '.hepta': policy, hasher: hasher}


def _decode_member_plan(raw):
    if len(raw) < 16 or raw[:8] != b'HIARLST1':
        raise ValueError('invalid native release recipe header')
    count = int.from_bytes(raw[8:16], 'little')
    if not 1 <= count <= 256:
        raise ValueError('invalid native release recipe count')
    at = 16
    members = []
    for _ in range(count):
        if at >= len(raw):
            raise ValueError('truncated native release recipe')
        width = raw[at]
        at += 1
        if width < 2 or width > 34 or width % 2:
            raise ValueError('invalid native release recipe field count')
        fields = []
        for _ in range(width):
            if at >= len(raw) or not 0 < raw[at] <= len(raw) - at - 1:
                raise ValueError('truncated native release recipe field')
            end = at + 1 + raw[at]
            fields.append(raw[at + 1:end].decode('ascii'))
            at = end
        members.append((fields[0], fields[1], dict(zip(fields[2::2], fields[3::2], strict=True))))
    if at != len(raw):
        raise ValueError('trailing native release recipe bytes')
    return members


def _release_packer_schedule(wire, call_planner):
    """Read the HIA planner's first-use recipe slot for each packer."""
    recipes = _decode_member_plan(wire)
    count = len(recipes)
    raw = call_planner(wire)
    if (len(raw) != 16 + count * 8 or
            raw[:16] != struct.pack('<8sQ', b'HIARUSE1', count)):
        raise ValueError('native packer schedule extent differs')
    owners = struct.unpack_from(f'<{count}Q', raw, 16)
    for i, owner in enumerate(owners):
        if owner > i or owners[owner] != owner or recipes[owner][1] != recipes[i][1]:
            raise ValueError('native packer schedule references a different recipe')
    return list(zip(recipes, owners, strict=True))


def _named_source_request(sources, *, tag=b'HIANAM01'):
    frame = bytearray(struct.pack('<8sQ', tag, len(sources)))
    for name, raw in sources.items():
        encoded = name.encode('ascii')
        frame.extend(struct.pack('<2Q', len(encoded), len(raw)))
        frame.extend(encoded)
        frame.extend(raw)
    return bytes(frame)


def _kit_sources(policy, packer):
    return {'source_build_policy.hepta': policy, 'selfhost.hepta': 'selfhost.hepta',
            'source_build_packer.hepta': packer}


class NativeReleaseSources:
    """Share one HIA kit composer with every consumer of the captured source compiler."""

    def __init__(self, seed, compile_sources, capture_sources, call):
        self.compile_sources = compile_sources
        self.capture_sources = capture_sources
        self.call = call
        group, _, _ = compile_sources(_kit_sources('source_release_kit.hepta', 'source_build_packer.hepta'))
        self.composer = call(seed, 'pack', group)

    def __call__(self, named):
        return self.compile_sources(named)

    def kit_from_sources(self, sources):
        return self.call(self.composer, 'build', _named_source_request(sources, tag=b'HIAKIT01'))

    def kit(self, policy, packer):
        return self.kit_from_sources(self.capture_sources(_kit_sources(policy, packer)))


def release_sources(seed, compile_sources, call):
    if isinstance(compile_sources, NativeReleaseSources):
        return compile_sources
    # Independent callers supply their own admission callback. Its third result
    # is the exact source snapshot authenticated by that caller.
    return NativeReleaseSources(seed, compile_sources, lambda named: compile_sources(named)[2], call)


def _member_with_object(frame):
    """Split the verified ELF and the object copied from the embedded compiler workspace."""
    if len(frame) < 24:
        raise ValueError('truncated compiled member frame')
    elf_size, image_size, magic = struct.unpack_from('<QQ8s', frame, len(frame) - 24)
    if (magic != b'HIAOBJ01' or not frame.startswith(b'\x7fELF') or elf_size < 4
            or not 0 < image_size <= 1 << 20 or elf_size + image_size != len(frame) - 24):
        raise ValueError('invalid compiled member frame')
    return frame[:elf_size], frame[elf_size:-24]


def _member_with_objects(frame, sources):
    """Recover the ELF and source-order objects retained by a group member builder."""
    count = len(sources)
    footer_bytes = (count + 3) * 8
    if not 2 <= count <= 4 or len(frame) < footer_bytes:
        raise ValueError('truncated member object group')
    footer = len(frame) - footer_bytes
    elf_size, *sizes, declared, magic = struct.unpack_from(f'<Q{count}QQ8s', frame, footer)
    if (magic != b'HIAOBJS1' or declared != count or not frame.startswith(b'\x7fELF') or elf_size < 4
            or any(not 0 < size <= 1 << 20 for size in sizes) or elf_size + sum(sizes) != footer):
        raise ValueError('invalid member object group')
    offset = elf_size
    images = {}
    for name, size in zip(sources, sizes, strict=True):
        images[name] = frame[offset:offset + size]
        offset += size
    return frame[:elf_size], images


def _native_member_batches(products, plan):
    """Materialize the HIA planner's ordered Store batches from captured bytes."""
    items = list(products.items())
    frame = bytearray(struct.pack('<8sQ', b'HIABAT01', len(items)))
    for name, raw in items:
        frame.extend(struct.pack('<3Q', len(name.encode('ascii')), len(raw),
                                 int.from_bytes(raw[:4], 'little')))
    result = plan(bytes(frame))
    expected = struct.pack('<8sQ', b'HIABGR01', len(items))
    if len(result) != 16 + len(items) * 24 or result[:16] != expected:
        raise ValueError('native Store layout response extent differs')
    seen = set()
    groups = []
    for index, group, mode in struct.iter_unpack('<3Q', result[16:]):
        if index >= len(items) or index in seen or mode not in (0o400, 0o500):
            raise ValueError('native Store member index or mode differs')
        if group == len(groups):
            groups.append((mode, {}))
        if group != len(groups) - 1 or groups[group][0] != mode:
            raise ValueError('native Store batch sequence differs')
        seen.add(index)
        name, raw = items[index]
        groups[group][1][name] = raw
    return (iter([batch for mode, batch in groups if mode == 0o400]),
            iter([batch for mode, batch in groups if mode == 0o500]))


def _install_captured_packet(work, installer, depot, packet, digest, count):
    receipt = {'sha256': digest, 'files': count, 'bytes': len(packet)}
    for action in ('install', 'verify'):
        checked = _run_captured(installer, (action, depot, digest), packet, work)
        checked.check_returncode()
        result = json.loads(checked.stdout)
        if checked.stderr or any(result.get(k) != v for k, v in receipt.items()):
            raise ValueError('captured Store package differs from its installation receipt')
    return depot / digest


def _stage_captured_members(work, stage, members, products, capture_packet, plan):
    """Use the native installer for data and code and publish their verified inodes."""
    if members.keys() & products.keys():
        raise ValueError('duplicate captured Store member')
    publisher, installer = products['hia-artifact'], products['hia-release']
    identities = {name: sha256(raw).hexdigest() for name, raw in products.items()}
    data_batches, code_batches = _native_member_batches(products, plan)
    # The native plan places empty data in the first batch. Those files stay
    # in the installed base, since the artifact publisher links nonempty bytes.

    def install(batch, tag, depot):
        packet, digest = capture_packet(batch, tag=tag)
        installed = _install_captured_packet(work, installer, depot, packet, digest, len(batch))
        # The private build can change directory entries without chmod on member inodes.
        os.chmod(installed, 0o700)
        return installed

    base = next(data_batches, None)
    if base is not None:
        if any(stage.iterdir()):
            raise FileExistsError('captured Store staging directory already contains entries')
        stage = install(base, b'HIADATA1', stage)
        for name, raw in base.items():
            file = stage / name
            if stat.S_IMODE(file.lstat().st_mode) != 0o400 or file.read_bytes() != raw:
                raise ValueError('native Store data differs from its capture: ' + name)

    directory = os.open(stage, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW)
    try:
        with TemporaryDirectory(prefix='compiled-members-', dir=work) as depot:
            depot = Path(depot)
            linked = []
            def invoke(action, source, target, expected):
                return _run_captured(publisher, (action, source, target), expected, work, pass_fds=(directory,))
            try:
                for tag, batches, mode in ((b'HIADATA1', data_batches, 0o400), (b'HIAELF01', code_batches, 0o500)):
                    for batch in batches:
                        installed = install(batch, tag, depot)
                        for name, raw in batch.items():
                            source = installed / name
                            target = Path(f'/proc/self/fd/{directory}') / name
                            if stat.S_IMODE(source.lstat().st_mode) != mode:
                                raise ValueError('captured Store member has an invalid native mode: ' + name)
                            # An interrupted publisher can already have linked its inode.
                            linked.append((source, target))
                            publication = invoke('publish', source, target, raw)
                            if publication.returncode == 14:
                                linked.pop()
                                raise FileExistsError('captured Store member already exists: ' + name)
                            publication.check_returncode()
                            expected = {'bytes': len(raw), 'sha256': identities[name]}
                            if (publication.stderr or json.loads(publication.stdout) != expected
                                    or not os.path.samestat(source.lstat(), target.lstat())):
                                raise ValueError('captured Store member differs from its native publication: ' + name)
                if not os.path.samestat(stage.lstat(), os.fstat(directory)):
                    raise ValueError('captured Store staging directory changed')
            except BaseException:
                for source, target in reversed(linked):
                    try:
                        same = os.path.samestat(source.lstat(), target.lstat())
                    except FileNotFoundError:
                        same = False
                    if same:
                        invoke('withdraw', source, target, b'').check_returncode()
                raise
        members.update(identities)
        return stage
    finally:
        os.close(directory)


def _stage_source_members(work, stage, admitted, members, publish, *, compiler_bytes, report_bytes, core_inputs,
                          captured_members=None):
    """Compile and pack release members with the captured native seed and HIA policy."""
    products = {} if captured_members is None else captured_members

    def captured(role):
        if role in products:
            return products[role]
        return _capture_release_tool(stage, role, members)

    seed = captured('hia-source-build')
    pack_directory = None
    bootstrap_packets = []
    builders = {}
    compiler_packer = None

    # These products bind their non-relocated syscall adapter and image entry
    # separately as part of the original build contract.
    from tools.build_hia_agent_batch_commit import VARIANTS as transaction_variants
    transaction_members = {values[0]: (kind, values) for kind, values in transaction_variants.items()}
    migration_dependencies = {}
    from tools.build_hia_direct_call import ROLES as direct_roles
    from tools.generate_hia_native_filter import REFERENCE_CLI_ADAPTER, read_adapter_binding, verify_adapter
    adapter_files = {'hia-' + role: info[2] for role, info in direct_roles.items()}
    adapter_files['hia-reference-wire'] = REFERENCE_CLI_ADAPTER

    def call(program, operation, wire):
        result = _run_captured(program, operation, wire, work)
        if result.returncode or result.stderr or not result.stdout:
            raise ValueError(f'native release member {operation} failed ({result.returncode})')
        return result.stdout

    def verify_bootstrap_packets(installer):
        for count, wire in bootstrap_packets:
            with TemporaryDirectory(prefix='member-sources-', dir=work) as depot:
                digest = sha256(wire).hexdigest()
                installed = _install_captured_packet(work, installer, Path(depot), wire, digest, count)
                packed = _run_captured(pack_directory, installed, b'', work)
                if (packed.returncode or packed.stdout != wire
                        or packed.stderr != (digest + '\n').encode('ascii')):
                    raise ValueError('source-built directory packer differs from its bootstrap packet')

    def capture_sources(named):
        pinned = {}
        for name, source in named.items():
            relative = 'examples/hia_bootstrap/' + source
            data = (ROOT / relative).read_bytes()
            if admitted.get(relative) != sha256(data).hexdigest():
                raise ValueError('release member source differs from cold admission: ' + relative)
            pinned[name] = data
        return pinned

    policy_sources = capture_sources({
        'selfhost.hepta': 'selfhost.hepta',
        'source_build_packer.hepta': 'source_build_packer.hepta',
        'source_build_policy.hepta': 'source_named_packet.hepta',
    })
    bootstrap = _source_bundle(policy_sources.values(), names=policy_sources)
    compiled = call(seed, 'build', bootstrap)
    _compiled_sources(compiled, policy_sources)
    named_packer = call(seed, 'pack', compiled)

    def capture_packet(pinned, *, tag=b'HIANAM01'):
        wire = call(named_packer, 'build', _named_source_request(pinned, tag=tag))
        digest = call(named_packer, 'pack', wire)
        if digest != sha256(wire).digest():
            raise ValueError('native source packet digest differs from its bytes')
        return wire, digest.hex()

    if capture_packet(policy_sources)[0] != bootstrap:
        raise ValueError('native source packager differs from its bootstrap packet')
    bootstrap_packets.append((len(policy_sources), bootstrap))

    def compile_sources(named):
        pinned = capture_sources(named)
        if pack_directory is None:
            wire, _ = capture_packet(pinned)
            bootstrap_packets.append((len(pinned), wire))
            compiled = call(seed, 'build', wire)
        else:
            compiled = call(seed, 'sources', _named_source_request(pinned))
        return compiled, _compiled_sources(compiled, pinned), pinned

    # Bootstrap once. The kit composer binds all three freshly compiled objects
    # and the complete executable template before returning a private builder.
    builds = NativeReleaseSources(seed, compile_sources, capture_sources, call)

    def planned_members():
        directory = _source_directory_recipe()
        yield directory, 0
        # Its successor is built with the admitted seed and the new directory packer.
        planner = builds.kit('source_release_member_plan.hepta', 'source_build_packer.hepta')
        relative = 'examples/hia_bootstrap/release_member_sources.tsv'
        source = (ROOT / relative).read_bytes()
        if sha256(source).hexdigest() != admitted.get(relative):
            raise ValueError('release recipe table differs from cold admission')
        schedule = _release_packer_schedule(call(planner, 'build', source),
                                            lambda wire: call(planner, 'build', wire))
        if schedule[0] != (directory, 0):
            raise ValueError('native release plan differs from its directory bootstrap')
        yield from schedule[1:]

    for index, ((name, packer, sources), owner) in enumerate(planned_members()):
        if pack_directory is None and name != 'hia-directory-package-build':
            raise ValueError('the first native release member must bootstrap its directory packer')
        if owner == index:
            kit_sources = capture_sources(_kit_sources('source_filter_member.hepta', packer))
            if pack_directory is None:
                bootstrap_packets.append((len(kit_sources), capture_packet(kit_sources)[0]))
            builders[owner] = builds.kit_from_sources(kit_sources)
            if packer == 'core_json_cli_packer.hepta':
                compiler_packer = call(seed, 'compile', kit_sources['source_build_packer.hepta'])
        attach_image = len(sources) == 1 and (name in adapter_files or name in transaction_members)
        if name == 'hia-worker-port':
            group, images = b'HIAWPRT1', {}
        elif len(sources) == 1:
            # Bound tools return their independently compiled object for the adapter placement check.
            tag = b'HIAIMG01' if attach_image else b'HIASRC01'
            group, images = _named_source_request(capture_sources(sources), tag=tag), {}
        else:
            group, images = _named_source_request(capture_sources(sources), tag=b'HIAMUL01'), {}
        product = call(builders[owner], 'build', group)
        if attach_image:
            alias, = sources
            product, images[alias] = _member_with_object(product)
        elif len(sources) > 1:
            product, images = _member_with_objects(product, sources)
        if name == 'hia-artifact':
            migration_dependencies['artifact'] = _bind_artifact_publisher(
                work, product, admitted, compiler_bytes, report_bytes)
        if name in transaction_members:
            kind, variant = transaction_members[name]
            folder = _bind_transaction_program(work, kind, variant, sources, images, product,
                                               admitted, compiler_bytes, report_bytes)
            if folder is not None:
                migration_dependencies[kind] = folder
        if name in adapter_files:
            adapter_file = adapter_files[name]
            packer_file = 'examples/hia_bootstrap/' + packer
            adapter_source = (ROOT / adapter_file).read_bytes()
            packer_source = (ROOT / packer_file).read_bytes()
            if (sha256(adapter_source).hexdigest() != admitted.get(adapter_file) or
                    sha256(packer_source).hexdigest() != admitted.get(packer_file)):
                raise ValueError('release tool adapter differs from the cold source: ' + name)
            binding = read_adapter_binding(packer_source, adapter_source, calls=1)
            verify_adapter(product, images[name + '.hepta'], binding, entries=(0,))
        if not product.startswith(b'\x7fELF'):
            raise ValueError('native source member returned an invalid release program: ' + name)
        if name in members or name in products:
            raise ValueError('duplicate compiled Store member: ' + name)
        products[name] = product
        if name == 'hia-directory-package-build':
            pack_directory = captured(name)
        if name == 'hia-release':
            verify_bootstrap_packets(product)
            bootstrap_packets.clear()
        if 'selfhost.hepta' in images and images['selfhost.hepta'] != compiler_bytes:
            raise ValueError('source-built selfhost differs from the admitted cold compiler')
        if name == 'hia-core-json':
            # The manifest owner independently recompiles the three sources, repacks the
            # exact selected ELF and hashes all nine raw inputs before its first write.
            author = builds.kit('source_compiler_manifest.hepta', 'core_json_cli_packer.hepta')
            parts = (report_bytes, compiler_bytes, captured(name), images[name + '.hepta'],
                     compiler_packer, captured('HIA_SELFHOST_CORE_SUPPORT.json'),
                     captured('core_json_cli_packer.hepta'), captured('core_json_frontend.hepta'),
                     captured('selfhost.hepta'))
            packet = struct.pack('<8s9Q', b'HIACMF01', *map(len, parts)) + b''.join(parts)
            manifest = call(author, 'build', packet)
            if 'compiler-manifest.json' in products or 'compiler-manifest.json' in members:
                raise ValueError('duplicate compiled Store member: compiler-manifest.json')
            products['compiler-manifest.json'] = manifest

    if bootstrap_packets:
        raise ValueError('release member plan did not verify its bootstrap packets')
    sqlite_tools = _sqlite_build_tools(seed, captured('hia-elf-link'), builds, call, admitted)
    _stage_safe_proof(work, seed, builds, call, admitted, publish)
    constructor = _stage_nominal_constructor(work, compile_sources, publish, sqlite_tools)
    with TemporaryDirectory(prefix='core-edit-', dir=work) as tmp:
        output = _compile(Path(tmp), 'core_edit', *core_inputs, native_tools=(seed, builds, call),
                          constructor=constructor, prover_bytes=captured('hia-safe-core-prove'))
        for name, _ in CORE_EDIT_PROGRAMS.values():
            publish(output / name)
        publish(output / 'hia-worker-scalar-implementation')

    _stage_helper_images(work, seed, compile_sources, call, compiler_bytes, publish)
    _stage_agent_store(work, seed, compile_sources, call, compiler_bytes, admitted, publish)
    _stage_agent_stdio(work, seed, captured('hia-catalog'), builds, call, compiler_bytes, publish)
    _stage_read_carrier(work, seed, builds, call, admitted, publish)
    _stage_owned_reference(work, seed, compile_sources, call, compiler_bytes, admitted, publish)
    linked = _stage_sqlite_units(work, compile_sources, admitted, publish, sqlite_tools)
    _stage_sqlite_migrations(work, compile_sources, admitted, publish, sqlite_tools, linked,
                             migration_dependencies, compiler_bytes, report_bytes)
    return _stage_captured_members(work, stage, members, products, capture_packet,
                                   lambda wire: call(named_packer, 'build', wire))


def _capture_release_tool(stage, name, members):
    descriptor = os.open(stage / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as source:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError('native release tool is not an ordinary file: ' + name)
        image = source.read()
    if sha256(image).hexdigest() != members[name]:
        raise ValueError('native release tool differs from its staged identity: ' + name)
    return image


def _source_inventory_packet(package, members):
    """Frame the captured package and independent digests for HIA release attestation.

    Each row has a one-byte name length, ASCII name and 32-byte SHA-256, in the
    directory packer's lexical order. The footer locates the original package.
    """
    inventory = bytearray()
    for name, digest in sorted(members.items()):
        encoded = name.encode('ascii')
        raw_digest = bytes.fromhex(digest)
        if not 1 <= len(encoded) <= 127 or len(raw_digest) != 32 or raw_digest.hex() != digest:
            raise ValueError('invalid source Store member identity: ' + name)
        inventory.append(len(encoded))
        inventory.extend(encoded)
        inventory.extend(raw_digest)
    return b''.join((package, inventory, struct.pack('<Q8s', len(package), b'HIAATT01')))


def _pack_and_verify(work, stage, members):
    package = work / 'store.hiapack'
    packer = _capture_release_tool(stage, 'hia-directory-package-build', members)
    installer = _capture_release_tool(stage, 'hia-release', members)
    with package.open('x+b') as stream:
        packed = _run_captured(packer, stage, b'', work, stdout=stream)
        os.fchmod(stream.fileno(), 0o400)
        identity = os.fstat(stream.fileno())
        stream.seek(0)
        expected = stream.read()
    if (packed.returncode or len(packed.stderr) != 65 or packed.stderr[-1:] != b'\n'
            or any(value not in b'0123456789abcdef' for value in packed.stderr[:-1])):
        raise ValueError('native directory packager failed to issue its package digest')
    digest = packed.stderr[:-1].decode('ascii')
    depot = work / 'verified'
    depot.mkdir(mode=0o700)
    for action in ('install', 'attest'):
        payload = expected if action == 'install' else _source_inventory_packet(expected, members)
        checked = _run_captured(installer, (action, depot, digest), payload, work)
        checked.check_returncode()
        receipt = {'schema': 'hepta.hia.release-install.v1', 'sha256': digest, 'bytes': len(expected),
                   'files': len(members), 'published': action == 'install'}
        if action == 'attest':
            receipt['source_attested'] = True
        if checked.stderr or json.loads(checked.stdout) != receipt:
            raise ValueError('native Store installation receipt differs from its built inventory')
    publisher = _capture_release_tool(stage, 'hia-artifact', members)
    return package, expected, digest, publisher, identity


def _publish_verified_package(package, output, expected, digest, publisher, original):
    """Publish the exact native installer input and verify the resulting hard link."""
    target = output / package.name
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    with ExitStack() as opened:
        authority = Path(opened.enter_context(TemporaryDirectory(dir=package.parent))) / package.name
        reference = _run_captured(publisher, ('publish', package, authority), expected, package.parent)
        reference.check_returncode()
        receipt = {'sha256': digest, 'bytes': len(expected)}
        if (reference.stderr or json.loads(reference.stdout) != receipt
                or not os.path.samestat(original, authority.lstat())
                or stat.S_IMODE(authority.lstat().st_mode) != 0o400):
            raise ValueError('package differs from its verified inode, bytes or mode')
        parent = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        opened.callback(os.close, parent)
        try:
            directory = os.open(output.name, directory_flags, dir_fd=parent)
            created = False
        except FileNotFoundError:
            os.mkdir(output.name, 0o700, dir_fd=parent)
            directory = os.open(output.name, directory_flags, dir_fd=parent)
            created = True
        opened.callback(os.close, directory)
        identity = os.fstat(directory)

        def named_directory():
            try:
                return os.path.samestat(identity, output.lstat())
            except FileNotFoundError:
                return False

        destination = f'/proc/self/fd/{directory}/{package.name}'

        def invoke(action, payload):
            return _run_captured(publisher, (action, authority, destination), payload,
                                 package.parent, pass_fds=(directory,))

        linked = False
        try:
            if os.listdir(directory) or not named_directory():
                raise FileExistsError('release output changed during the build: ' + str(output))
            for operation in ('publish', 'verify'):
                if not os.path.samestat(original, package.lstat()):
                    raise ValueError('verified package inode changed during publication')
                if operation == 'publish':
                    linked = True
                result = invoke(operation, expected)
                if operation == 'publish':
                    # A signal or an I/O failure may follow a completed hard link.
                    # Only a kernel no-replace refusal proves that this call did not link.
                    linked = result.returncode != 14
                    if result.returncode == 14 and os.path.lexists(destination):
                        raise FileExistsError('native Store publication refused an existing target')
                result.check_returncode()
                if result.stderr or json.loads(result.stdout) != receipt:
                    raise ValueError('native package publication receipt differs from the verified release')
            if not os.path.samestat(original, package.lstat()):
                raise ValueError('verified package inode changed after publication')
            if not named_directory() or os.listdir(directory) != [package.name]:
                raise FileExistsError('release output changed during publication: ' + str(output))
        except BaseException:
            if linked:
                withdrawn = invoke('withdraw', b'')
                withdrawn.check_returncode()
            if created and named_directory() and not os.listdir(directory):
                os.rmdir(output.name, dir_fd=parent)
            raise
    return target


def build(output, compiler, cold_report):
    """Publish one verified package. All compiler receipts and component scratch are private."""
    output = Path(output).absolute()
    compiler, cold_report = Path(compiler).resolve(), Path(cold_report).resolve()
    if output.is_symlink() or (output.exists() and (not output.is_dir() or any(output.iterdir()))):
        raise FileExistsError('expected a new or empty release output directory: ' + str(output))
    compiler_bytes, report_bytes = compiler.read_bytes(), cold_report.read_bytes()
    admitted = admit_cold_build(compiler_bytes, report_bytes)
    with TemporaryDirectory(prefix='hia-native-store-release-', dir=output.parent) as tmp:
        work = Path(tmp)
        stage = work / 'stage'
        stage.mkdir(mode=0o700)
        members = {}
        captures = {}

        def publish(path, name=None, *, expected=None):
            name = path.name if name is None else name
            if Path(name).name != name or name in captures or path.is_symlink() or not path.is_file():
                raise ValueError('invalid or duplicate Store release member: ' + name)
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, 'rb') as stream:
                if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                    raise ValueError('invalid Store release member: ' + name)
                raw = stream.read()
            if expected is not None and sha256(raw).hexdigest() != expected:
                raise ValueError('Store release member differs from its declared source: ' + name)
            captures[name] = raw

        for name in RESOURCES:
            publish(ROOT / name, expected=admitted[name])
        _stage_component_outputs(work, compiler, cold_report, publish)
        stage = _stage_source_members(work, stage, admitted, members, publish,
                                      compiler_bytes=compiler_bytes, report_bytes=report_bytes,
                                      core_inputs=(compiler, cold_report), captured_members=captures)
        package, expected, digest, publisher, identity = _pack_and_verify(work, stage, members)
        if current_sources() != admitted or compiler.read_bytes() != compiler_bytes or cold_report.read_bytes() != report_bytes:
            raise ValueError('native Store cold inputs changed before publication')
        return _publish_verified_package(package, output, expected, digest, publisher, identity)


def _read_regular_cold_source(relative):
    """Pin cold source descriptors and reject links/devices before reading any bytes.

    The checked-in inventory is not permission to traverse a symlink, including
    a parent directory symlink, or to block indefinitely on a FIFO.
    """
    opened = []
    try:
        directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened.append(directory)
        for component in relative.parts[:-1]:
            directory = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=directory)
            opened.append(directory)
        file = os.open(relative.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                       dir_fd=directory)
        opened.append(file)
        if not stat.S_ISREG(os.fstat(file).st_mode):
            raise ValueError('cold source is not a regular file: ' + str(relative))
        with os.fdopen(os.dup(file), 'rb') as stream:
            return stream.read()
    except OSError as error:
        raise ValueError('cold source is a symlink or not a regular file: ' + str(relative)) from error
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)


def write_source_archive(output):
    """Archive precisely the files exported by the cold replay, including its support contract."""
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError(output)
    sources = current_sources()
    with NamedTemporaryFile(dir=output.parent, prefix='.hia-native-source-') as temporary:
        with gzip.GzipFile(fileobj=temporary, filename='', mode='wb', mtime=0, compresslevel=6) as compressed:
            with tarfile.open(fileobj=compressed, mode='w|', format=tarfile.PAX_FORMAT) as archive:
                for name, expected in sorted(sources.items()):
                    path = Path(name)
                    if path.is_absolute() or path.as_posix() != name or '..' in path.parts:
                        raise ValueError('invalid cold source path: ' + name)
                    data = _read_regular_cold_source(path)
                    if sha256(data).hexdigest() != expected:
                        raise ValueError('cold source changed during export: ' + name)
                    entry = tarfile.TarInfo('hia-core-source/' + name)
                    entry.mode = 0o644
                    entry.size = len(data)
                    archive.addfile(entry, io.BytesIO(data))
        temporary.flush()
        if current_sources() != sources:
            raise ValueError('cold source inventory changed before publication')
        os.fchmod(temporary.fileno(), 0o400)
        os.link(temporary.name, output)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='From an extracted hia-core-source directory:\n'
               '  python -m tools.replay_hia_selfhost_cold --output ../cold.json\n'
               '  python -m tools.build_hia_native_store_release --output ../release '
               '--compiler ../cold.cold/qualification.evidence/B3.image.bin --cold-report ../cold.json')
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--output', type=Path, help='new or empty directory for the native store.hiapack')
    action.add_argument('--source-archive', type=Path, help='new .tar.gz path for all source inputs to cold replay')
    parser.add_argument('--compiler', type=Path, help='B3 compiler image from the matching cold replay')
    parser.add_argument('--cold-report', type=Path, help='matching source-qualified cold replay JSON')
    args = parser.parse_args()
    if args.source_archive is not None:
        if args.compiler is not None or args.cold_report is not None:
            parser.error('--source-archive takes only the complete checked-in sources')
        print(write_source_archive(args.source_archive))
    else:
        if args.compiler is None or args.cold_report is None:
            parser.error('--output requires --compiler and --cold-report')
        print(build(args.output, args.compiler, args.cold_report))


if __name__ == '__main__':
    main()
