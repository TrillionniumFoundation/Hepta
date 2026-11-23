"""Build and verify a flat native Store release from a matching HIA cold qualification."""
from __future__ import annotations

import argparse
import gzip
import io
from hashlib import file_digest, sha256
from importlib import import_module
import json
import os
import stat
import struct
from pathlib import Path
import subprocess
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
    def component(name, *args, **options):
        with TemporaryDirectory(prefix=name + '-', dir=work) as tmp:
            result = _compile(Path(tmp), name, compiler, cold_report, *args, **options)
            publish(result)

    with TemporaryDirectory(prefix='core-edit-', dir=work) as tmp:
        output = _compile(Path(tmp), 'core_edit', compiler, cold_report)
        for name, _ in CORE_EDIT_PROGRAMS.values():
            publish(output / name)
        publish(output / 'hia-worker-scalar-implementation')

    for name in ('source_build',
                 'supplied_safe_core_proof',
                 'owned_reference_cli', 'nominal_constructor'):
        component(name)

    with TemporaryDirectory(prefix='standalone-', dir=work) as tmp:
        directory = Path(tmp)
        owner = _compile(directory, 'agent_store', compiler, cold_report)
        publish(owner)
        metadata = json.loads((owner.parent / 'build.json').read_bytes())
        for name, digest in metadata['module_sha256'].items():
            publish(owner.parent / metadata['module_root'] / name, expected=digest)


def _stage_sqlite(work, compiler, cold_report, publish, linked_components):
    def component(name, *args, **options):
        path = _compile(work, name, compiler, cold_report, *args, **options)
        publish(path)
        return path.parent

    ((components, selected), (pager, pager_record)), dependencies = linked_components
    cold_identity = {'compiler_sha256': sha256(compiler.read_bytes()).hexdigest(),
                     'cold_report_sha256': sha256(cold_report.read_bytes()).hexdigest()}
    pager_receipt = {'schema': 'hepta.hia.sqlite-pager-build.v1', **cold_identity, **pager_record}
    (pager / 'build.json').write_text(json.dumps(pager_receipt, sort_keys=True, indent=2) + '\n')
    # The migration coordinator independently checks its staged input against the
    # cold report, the actual executable and each consumed source identity.
    receipt = {'schema': 'hepta.hia.sqlite-component-process-build.v1',
               **cold_identity, 'source_sha256': selected['source_sha256'], 'executable_manifest': {PROJECTION: selected}}
    (components / 'build.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    publisher = component('sqlite_migration_publish', dependencies['artifact'], dependencies['batch'])
    component('sqlite_migrate', {'pager': pager, 'staging': components, 'initializer': dependencies['initialize'],
                                 'publisher': publisher})


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

    def builder(packer):
        kit, _, _ = compile_sources({
            'source_build_policy.hepta': 'source_read_carrier.hepta',
            'selfhost.hepta': 'selfhost.hepta', 'source_build_packer.hepta': Path(packer).name,
        })
        return call(seed, 'pack', kit)

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


def _stage_sqlite_units(work, seed, linker, compile_sources, call, admitted, publish):
    """Build the installed SQLite units through sealed HIA source, embedding and linking stages."""
    from tools.build_hia_agent_artifact_capture import UNIT as CAPTURE_UNIT
    from tools.build_hia_nominal_json import SOURCE_NAME as NOMINAL_SOURCE, STDIO, STDIO_TEMPLATE
    from tools.build_hia_sqlite_components import (
        CAPTURE_ADAPTERS, COMPONENT_TEMPLATES, INPUT, PROJECTION_ADAPTER, PROJECTION_ROLES, START,
    )
    from tools.build_hia_sqlite_pager import ADAPTERS, EMBED_SOURCE, PAGER, STATIC_LINKER, STREAM, TEMPLATES, verify_executable

    def owner(application):
        kit, _, _ = compile_sources({
            'source_build_policy.hepta': 'source_sqlite_unit.hepta',
            'selfhost.hepta': 'selfhost.hepta',
            'source_build_packer.hepta': application,
        })
        return call(seed, 'pack', kit)

    adapters = owner('sqlite_component_adapters.hepta')
    embedder = owner('elf_embed_image.hepta')
    def adapter_object(program, ordinal, name):
        source = (ROOT / name).read_bytes()
        if sha256(source).hexdigest() != admitted.get(name):
            raise ValueError('SQLite adapter source differs from cold admission: ' + name)
        frame = struct.pack('<8sQQ', b'HIASQAD1', ordinal, len(source)) + source
        return call(program, 'build', frame)

    objects = [adapter_object(adapters, ordinal, name)
               for ordinal, name in enumerate((START, INPUT, *CAPTURE_ADAPTERS, PROJECTION_ADAPTER))]
    nominal_adapter = adapter_object(owner(Path(STDIO_TEMPLATE).name), 0, STDIO)
    pager_template = owner(Path(TEMPLATES).name)
    pager_adapters = [adapter_object(pager_template, i, path) for i, path in enumerate(ADAPTERS)]
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
        request = struct.pack('<8sQQ', kind, ordinal, len(source)) + source
        return call(embedder, 'build', request)

    def link(kind, inputs):
        request = struct.pack('<8s' + str(len(inputs)) + 'Q', kind, *map(len, inputs)) + b''.join(inputs)
        return call(linker, None, call(embedder, 'build', request))

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
    kit, _, _ = compile_sources({
        'source_build_policy.hepta': 'source_agent_stdio.hepta',
        'selfhost.hepta': 'selfhost.hepta',
        'source_build_packer.hepta': 'agent_stdio_packer.hepta',
    })
    author = call(seed, 'pack', kit)
    # Nine ordered catalogs belong to the published Agent stdio v2 protocol.
    catalogs = [call(catalog_program, ('--schema', f'hepta.hia.program.v{version}'), b'')
                for version in range(1, 10)]
    parts = [*(sources[name] for name in core), *(images[name] for name in core), *catalogs]
    request = struct.pack('<8s15Q', b'HIAAGS01', *map(len, parts)) + b''.join(parts)
    executable = call(author, 'build', request)
    path = work / 'hia-native'
    path.write_bytes(executable)
    publish(path, expected=sha256(executable).hexdigest())


def _source_worker_recipes():
    from tools.build_hia_read_launcher import LAUNCHERS as READ_PROGRAMS
    from tools.generate_hia_readonly_worker_capsule import FULL_SOURCE, INTAKE_SOURCE, NATIVE_SOURCE, REPLAY_SOURCE
    from tools.generate_hia_worker_flow_packer import PROGRAMS, SECTIONS

    authorities = {'native': NATIVE_SOURCE, 'evaluate-intake': INTAKE_SOURCE,
                   'evaluate-replay': REPLAY_SOURCE, 'evaluate-full': FULL_SOURCE}
    for kind in FLOW_ROLES:
        suffix = '' if kind in ('input', 'discovery', 'discovery-bootstrap') else '-worker'
        name = f'hia-agent-{kind}{suffix}-carrier'
        primary, packer = PROGRAMS[kind]
        sources = {name + '.hepta': Path(primary).name}
        for part in SECTIONS.get(kind, ()):
            sources[Path(part).name] = Path(part).name
        yield name, Path(packer).name, sources

    for kind in LAUNCHERS:
        name = f'hia-agent-{kind}-launcher'
        if kind in authorities:
            primary, packer = PROGRAMS[kind + '-launcher']
            authority = Path(authorities[kind]).name
            sources = {name + '.hepta': Path(primary).name, authority: authority}
        else:
            launcher = READ_PROGRAMS[kind]
            packer = launcher.source
            sources = {name + '.hepta': Path(launcher.authority).name}
        yield name, Path(packer).name, sources


def _source_tool_recipes():
    from tools.build_hia_direct_call import ROLES
    from tools.build_hia_elf_linker import LINKERS
    from tools.build_hia_json_preflight import CANDIDATES
    from tools.generate_hia_native_filter import REFERENCE_CLI_PACKER

    for application, name in (('worker-prepare', 'hia-worker-prepare'), ('cnf', 'hia-proof-cnf')):
        yield name, 'native_filter_packer.hepta', {name + '.hepta': CANDIDATES[application][0] + '.hepta'}
    for application, packer, _magic, name, _inputs in LINKERS.values():
        yield name, CANDIDATES[packer][0] + '.hepta', {name + '.hepta': CANDIDATES[application][0] + '.hepta'}
    for role, (source, packer, _adapter, _magic, _label) in ROLES.items():
        name = 'hia-' + role
        yield name, Path(packer).name, {name + '.hepta': Path(source).name}
    yield 'hia-reference-wire', Path(REFERENCE_CLI_PACKER).name, {'hia-reference-wire.hepta': 'scalar_reference.hepta'}


def _source_transaction_recipes():
    from tools.build_hia_agent_batch_commit import PARTS, VARIANTS

    for name, _tag, packer, _adapter, roles in VARIANTS.values():
        sources = {}
        for index, label in enumerate(roles):
            source = PARTS[label].removeprefix('examples/hia_bootstrap/')
            alias = name + '.hepta' if index == 0 else Path(source).name
            sources[alias] = source
        yield name, packer.removeprefix('examples/hia_bootstrap/'), sources


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


def _source_request_recipes():
    stdio = 'mcp_stdio_packer.hepta'
    for suffix in ('admit', 'terminal', 'data', 'response', 'journal-call'):
        name = 'hia-worker-' + suffix
        packer = 'worker_request_filter_packer.hepta' if suffix == 'admit' else stdio
        yield name, packer, {name + '.hepta': 'worker_request.hepta'}
    # Its entire body belongs to the stdio packer's fixed sealed-port mode.
    yield 'hia-worker-port', stdio, {}


def _source_release_recipes():
    from tools.build_hia_core_admission_cli import MODES
    from tools.build_hia_release_install import SOURCES as installer
    from tools.build_hia_release_selection import SOURCES as selector

    def recipe(name, packer, components):
        main, *companions = (Path(source).name for source in components)
        inputs = {name + '.hepta': main, **{source: source for source in companions}}
        return name, Path(packer).name, inputs

    from tools.build_hia_artifact_publication import SOURCES as publisher
    yield recipe('hia-artifact', publisher[1], (publisher[0], publisher[2]))
    yield recipe('hia-release', installer[1], (installer[0], installer[2]))
    yield recipe('hia-core-json', 'core_json_cli_packer.hepta', ('core_json_frontend.hepta', 'selfhost.hepta'))
    yield recipe('hia-workspace-compile', 'core_workspace_pipeline_packer.hepta',
                 ('core_workspace_json.hepta', 'core_admission.hepta', 'core_json_frontend.hepta',
                  'selfhost.hepta'))
    yield recipe('hia-select', selector[3], selector[:3])
    yield recipe('hia-patch-result', 'core_patch_result_cli_packer.hepta', ('core_patch.hepta', 'core_admission.hepta'))
    for mode, name in (('suite', 'hia-core'), ('totality', 'hia-totality-core'), ('proof-wire', 'hia-core-proof-wire')):
        _magic, packer, components = MODES[mode]
        inputs = list(components)
        inputs.insert(1 if mode == 'suite' else 0, 'core_admission.hepta')
        yield recipe(name, packer, inputs)


def _source_directory_recipe():
    from tools.build_hia_release_install import DIRECTORY_SOURCES

    policy, packer, hasher = (Path(path).name for path in DIRECTORY_SOURCES[:3])
    name = 'hia-directory-package-build'
    return name, packer, {name + '.hepta': policy, hasher: hasher}


def _source_member_recipes():
    """Map published names to checked-in HIA inputs. Framing and modes belong to HIA."""
    # The qualified source seed is sufficient to bootstrap the directory packer.
    yield _source_directory_recipe()
    for role in STDIO_ROLES:
        name = 'hia-agent-' + role
        sources = {name + '.hepta': AGENT_STDIO_ROLES[role][0] + '.hepta'}
        if role == 'journal':
            sources['agent_journal_transport.hepta'] = 'agent_journal_transport.hepta'
            yield name, 'agent_journal_stdio_packer.hepta', sources
        else:
            yield name, 'mcp_stdio_packer.hepta', sources

    for role in ('budget-observation', 'budget-store', 'cost-ledger', 'cost-ledger-flow',
                 'measurements', 'native-report', 'paired-batch', 'publication', 'reference-batch',
                 'reference-report', 'report-flow', 'run-plan', 'settlement'):
        stem = 'evaluate_' + role.replace('-', '_')
        sources = {stem + '.hepta': stem + '.hepta'}
        if role in ('cost-ledger', 'run-plan'):
            sources['worker_request.hepta'] = 'worker_request.hepta'
        yield 'hia-evaluate-' + role, stem + '_packer.hepta', sources
    for name, stem, packer in (
            ('hia-evaluate-projector', 'evaluate_reference_wire', 'evaluate_reference_wire_filter_packer'),
            ('hia-execution-budget-session', 'execution_budget', 'execution_budget_session_packer'),
            ('hia-safe-core-loader', 'safe_core_elf_inventory', 'safe_core_loader_filter_packer')):
        yield name, packer + '.hepta', {stem + '.hepta': stem + '.hepta'}

    yield from _source_worker_recipes()
    yield from _source_tool_recipes()
    yield from _source_request_recipes()
    yield from _source_transaction_recipes()
    yield from _source_release_recipes()


def _stage_source_members(work, stage, admitted, members, publish, *, compiler_bytes, report_bytes):
    """Compile and pack release members with the captured native seed and HIA policy."""
    def captured(role):
        data = (stage / role).read_bytes()
        if sha256(data).hexdigest() != members[role]:
            raise ValueError('native release tool differs from its staged identity: ' + role)
        return data

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

    def native_directory_packet(program, pinned):
        with TemporaryDirectory(prefix='member-sources-', dir=work) as staging:
            directory = Path(staging)
            for name, data in pinned.items():
                with (directory / name).open('xb') as stream:
                    stream.write(data)
                    os.fchmod(stream.fileno(), 0o400)
            packed = _run_captured(program, directory, b'', work)
            if packed.returncode or packed.stderr != (sha256(packed.stdout).hexdigest() + '\n').encode():
                raise ValueError('native source directory receipt differs from its bytes')
            return packed.stdout

    def compile_sources(named):
        pinned = {}
        for name, source in sorted(named.items()):
            relative = 'examples/hia_bootstrap/' + source
            data = (ROOT / relative).read_bytes()
            if admitted.get(relative) != sha256(data).hexdigest():
                raise ValueError('release member source differs from cold admission: ' + relative)
            pinned[name] = data
        if pack_directory is None:
            # Before the directory packer exists only a source byte transport is
            # needed. Its two packets must subsequently match the HIA program.
            wire = _source_bundle(pinned.values(), names=pinned)
            bootstrap_packets.append((pinned, wire))
        else:
            wire = native_directory_packet(pack_directory, pinned)
        compiled = call(seed, 'build', wire)
        return compiled, _compiled_sources(compiled, pinned), pinned

    for name, packer, sources in _source_member_recipes():
        if pack_directory is None and name != 'hia-directory-package-build':
            raise ValueError('the first native release member must bootstrap its directory packer')
        if packer not in builders:
            kit, kit_images, _ = compile_sources({'source_build_policy.hepta': 'source_filter_member.hepta',
                                      'selfhost.hepta': 'selfhost.hepta', 'source_build_packer.hepta': packer})
            builders[packer] = call(seed, 'pack', kit)
            if packer == 'core_json_cli_packer.hepta':
                compiler_packer = kit_images['source_build_packer.hepta']
        if name == 'hia-worker-port':
            group, images = b'HIAWPRT1', {}
        else:
            group, images, _ = compile_sources(sources)
        product = call(builders[packer], 'build', group)
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
        with NamedTemporaryFile(dir=work, prefix='native-member-') as stream:
            stream.write(product)
            stream.flush()
            publish(Path(stream.name), name, expected=sha256(product).hexdigest())
        if name == 'hia-directory-package-build':
            pack_directory = captured(name)
            for pinned, wire in bootstrap_packets:
                if native_directory_packet(pack_directory, pinned) != wire:
                    raise ValueError('source-built directory packer differs from its bootstrap packet')
            bootstrap_packets.clear()
        if 'selfhost.hepta' in images and images['selfhost.hepta'] != compiler_bytes:
            raise ValueError('source-built selfhost differs from the admitted cold compiler')
        if name == 'hia-core-json':
            # The manifest owner independently recompiles the three sources, repacks the
            # exact selected ELF and hashes all nine raw inputs before its first write.
            author_sources = {
                'source_build_policy.hepta': 'source_compiler_manifest.hepta',
                'selfhost.hepta': 'selfhost.hepta',
                'source_build_packer.hepta': 'core_json_cli_packer.hepta',
            }
            author = call(seed, 'pack', compile_sources(author_sources)[0])
            parts = (report_bytes, compiler_bytes, captured(name), images[name + '.hepta'],
                     compiler_packer, captured('HIA_SELFHOST_CORE_SUPPORT.json'),
                     captured('core_json_cli_packer.hepta'), captured('core_json_frontend.hepta'),
                     captured('selfhost.hepta'))
            packet = struct.pack('<8s9Q', b'HIACMF01', *map(len, parts)) + b''.join(parts)
            manifest = call(author, 'build', packet)
            path = work / 'compiler-manifest.json'
            path.write_bytes(manifest)
            publish(path)

    _stage_helper_images(work, seed, compile_sources, call, compiler_bytes, publish)
    _stage_agent_stdio(work, seed, captured('hia-catalog'), compile_sources, call, compiler_bytes, publish)
    _stage_read_carrier(work, seed, compile_sources, call, admitted, publish)
    linked = _stage_sqlite_units(work, seed, captured('hia-elf-link'), compile_sources, call, admitted, publish)
    return linked, migration_dependencies


def _pack_and_verify(work, stage, members):
    package = work / 'store.hiapack'
    with package.open('xb') as result:
        pack = subprocess.run([stage / 'hia-directory-package-build', stage], stdout=result, stderr=subprocess.PIPE,
                              env={'PATH': ''}, check=True, timeout=180)
    with package.open('rb') as stream:
        digest = file_digest(stream, 'sha256').hexdigest()
    if pack.stderr != (digest + '\n').encode():
        raise ValueError('native directory package digest differs from its output')
    depot = work / 'verified'
    depot.mkdir(mode=0o700)
    for action in ('install', 'verify'):
        with package.open('rb') as stream:
            checked = subprocess.run([stage / 'hia-release', action, depot, digest], stdin=stream,
                                     capture_output=True, env={'PATH': ''}, check=True, timeout=180)
        receipt = json.loads(checked.stdout)
        if checked.stderr or receipt['sha256'] != digest or receipt['files'] != len(members):
            raise ValueError('native Store installation receipt differs from its built inventory')
    installed = depot / digest
    actual = {path.name: sha256(path.read_bytes()).hexdigest() for path in installed.iterdir()}
    if actual != members:
        raise ValueError('installed native Store files differ from their source-built members')
    return package


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

        def publish(path, name=None, *, expected=None):
            name = path.name if name is None else name
            if Path(name).name != name or name in members or path.is_symlink() or not path.is_file():
                raise ValueError('invalid or duplicate Store release member: ' + name)
            raw = path.read_bytes()
            digest = sha256(raw).hexdigest()
            if expected is not None and digest != expected:
                raise ValueError('Store release member differs from its declared source: ' + name)
            target = stage / name
            with target.open('xb') as stream:
                stream.write(raw)
                os.fchmod(stream.fileno(), 0o500 if raw.startswith(b'\x7fELF') else 0o400)
            members[name] = digest

        for name in RESOURCES:
            publish(ROOT / name, expected=admitted[name])
        _stage_component_outputs(work, compiler, cold_report, publish)
        linked_components = _stage_source_members(work, stage, admitted, members, publish,
                                           compiler_bytes=compiler_bytes, report_bytes=report_bytes)
        _stage_sqlite(work, compiler, cold_report, publish, linked_components)
        package = _pack_and_verify(work, stage, members)
        if current_sources() != admitted or compiler.read_bytes() != compiler_bytes or cold_report.read_bytes() != report_bytes:
            raise ValueError('native Store cold inputs changed before publication')
        created = not output.exists()
        if created:
            output.mkdir(mode=0o700)
        elif output.is_symlink() or any(output.iterdir()):
            raise FileExistsError('release output changed during the build')
        target = output / package.name
        try:
            package.chmod(0o400)
            os.link(package, target)
        except BaseException:
            if created:
                output.rmdir()
            raise
    return target


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
