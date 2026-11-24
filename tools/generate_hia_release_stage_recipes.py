"""Author native HIASTD01 release recipes from the retained source declarations.

This development generator is not an executable release coordinator. The checked
binary recipes are data interpreted by the HIA release owner; no Python process
participates when they are consumed. Their inputs are source-pinned captures and
this invocation's already checked, sealed product registry.
"""
from __future__ import annotations
import json
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parents[1]
PROGRAMS = 'examples/hia_bootstrap/'
U64_MAX = (1 << 64) - 1
RECIPE_NAMES = ('release_stage_constructor.hiastd', 'release_stage_additional.hiastd',
                'release_stage_controller.hiastd')


def stage_rows():
    lines = (ROOT / PROGRAMS / 'release_stage_sources.tsv').read_text('ascii').splitlines()
    return [row.split('\t') for row in lines[1:]]


def outputs(stage):
    return [row[2] for row in stage_rows() if row[:2] == ['output', str(stage)]]


def program(path):
    text = str(path)
    return text if text.startswith(PROGRAMS) else PROGRAMS + text


def capture_payload(named):
    data = bytearray(struct.pack('<Q', len(named)))
    for alias, path in named.items():
        alias, path = alias.encode('ascii'), path.encode('ascii')
        data += struct.pack('<2Q', len(alias), len(path)) + alias + path
    return bytes(data)


def instructions(values):
    return b''.join(struct.pack('<Q', len(value)) + value for value in values)


class Recipe:
    def __init__(self):
        self.nodes = []
        self.next_handle = 1
        self.imports = {}
        self.kits = {}
        self.published = []

    def node(self, operation, args=(), payload=b''):
        identity = 0
        if operation not in (7, 8, 9, 10):
            identity = self.next_handle
            self.next_handle += 1
            assert identity <= 2048
        self.nodes.append((operation, identity, tuple(args), bytes(payload)))
        return identity

    def binary(self):
        out = bytearray(struct.pack('<8s2Q', b'HIASTD01', len(self.nodes), len(self.published)))
        for operation, identity, args, payload in self.nodes:
            out += struct.pack('<4Q', operation, identity, len(args), len(payload))
            out += struct.pack('<' + 'Q' * len(args), *args) + payload
        return bytes(out)

    def capture(self, named, tag=b'HIANAM01'):
        return self.node(1, (int.from_bytes(tag, 'little'),), capture_payload(named))

    def pick(self, handle, ordinal, image=False):
        return self.node(4, (handle, ordinal, int(image)))

    def source(self, path):
        path = str(path)
        captured = self.capture({Path(path).name: path}, b'HIARAW01')
        return self.pick(captured, 0)

    def compile(self, named):
        captured = self.capture({alias: program(path) for alias, path in named.items()})
        compiled = self.node(2, (captured,))
        sources = {alias: self.pick(captured, i) for i, alias in enumerate(named)}
        images = {alias: self.pick(compiled, i, True) for i, alias in enumerate(named)}
        return sources, images

    def import_product(self, name):
        if name not in self.imports:
            self.imports[name] = self.node(11, payload=name.encode('ascii'))
        return self.imports[name]

    def kit(self, policy, application):
        key = (policy, application)
        if key not in self.kits:
            named = {'source_build_policy.hepta': program(policy),
                     'selfhost.hepta': program('selfhost.hepta'),
                     'source_build_packer.hepta': program(application)}
            captured = self.capture(named, b'HIAKOBJ1')
            executable = self.node(3, (captured,))
            sources = {alias: self.pick(captured, i) for i, alias in enumerate(named)}
            images = {alias: self.pick(executable, i, True) for i, alias in enumerate(named)}
            self.node(8, (images['selfhost.hepta'], self.import_product('selfhost.image.bin')))
            self.kits[key] = executable, sources, images
        return self.kits[key]

    def literal(self, data):
        return self.node(12, payload=data)

    def frame(self, stage, operation, ordinal, parts, *, auxiliary=0):
        return self.node(5, (stage, operation, ordinal, auxiliary, *parts))

    def run(self, executable, wire, operation=3):
        return self.node(6, (executable, operation, wire))

    def frame_run(self, executable, stage, operation, ordinal, parts):
        return self.run(executable, self.frame(stage, operation, ordinal, parts))

    def publish(self, name, value, expected=None):
        expected_ref = self.literal(bytes.fromhex(expected)) if expected else 0
        self.node(7, (value, expected_ref), name.encode('ascii'))
        self.published.append(name)

    def check_image(self, executable, image):
        self.node(10, (1, 0, executable, image))

    def check_adapter(self, executable, image, packer, adapter):
        self.node(10, (2, 1, executable, image, packer, adapter,
                       self.literal(struct.pack('<Q', 0)), self.literal(instructions((b'\xe8',)))))

    def check_placement(self, executable, packer, adapter, parts, opcodes=None):
        opcodes = (b'\xe8',) * len(parts) if opcodes is None else tuple(opcodes)
        self.node(10, (3, len(parts), executable, packer, adapter,
                       self.literal(instructions(opcodes)), *parts))

    def sqlite_kit(self, application):
        return self.kit('source_sqlite_unit.hepta', Path(application).name)[0]

    def adapter(self, stage, template, ordinal, source):
        return self.frame_run(self.sqlite_kit(template), stage, 3 if stage == 2 else 1,
                              ordinal, [self.source(source)])

    def embed(self, stage, operation, ordinal, parts):
        return self.frame_run(self.sqlite_kit('elf_embed_image.hepta'), stage, operation, ordinal, parts)

    def link(self, stage, operation, objects):
        packed = self.embed(stage, operation, 0, objects)
        return self.run(self.import_product('hia-elf-link'), packed, 0)


def constructor(recipe):
    from tools.build_hia_nominal_constructor import (
        COMPONENTS, CONSTRUCTOR_IMAGES, TRANSPORT_ROLES, TRANSPORT_TEMPLATES)
    source = recipe.source(TRANSPORT_ROLES[0])
    parts = [recipe.frame_run(recipe.sqlite_kit(TRANSPORT_TEMPLATES[name]), 2, 1, ordinal, [source])
             for ordinal, name in enumerate(('constructor', 'constructor-tail'))]
    objects = [recipe.embed(2, 2, 0, [source, *parts])]
    objects.extend(recipe.adapter(2, TRANSPORT_TEMPLATES['publication'], ordinal, path)
                   for ordinal, path in enumerate(TRANSPORT_ROLES[1:], 1))
    names = {Path(COMPONENTS[role]).name: COMPONENTS[role] for role in CONSTRUCTOR_IMAGES}
    sources, images = recipe.compile(names)
    for ordinal, role in enumerate(CONSTRUCTOR_IMAGES, 39):
        objects.append(recipe.embed(2, 4, ordinal, [sources[Path(COMPONENTS[role]).name]]))
    executable = recipe.link(2, 5, objects)
    for image in images.values():
        recipe.check_image(executable, image)
    recipe.publish(outputs(2)[0], executable)


def helpers(recipe):
    from tools.build_hia_worker_release import INSTALLED_HELPERS
    from tools.build_hia_json_preflight import CANDIDATES
    author, kit_sources, _ = recipe.kit('source_helper_manifest.hepta', 'source_build_packer.hepta')
    names = [CANDIDATES[kind][0] + '.hepta' for kind in INSTALLED_HELPERS]
    sources, images = recipe.compile({name: name for name in names})
    compiler = recipe.import_product('selfhost.image.bin')
    for role, (kind, name) in enumerate(zip(INSTALLED_HELPERS, names, strict=True), 1):
        image, source = images[name], sources[name]
        manifest = recipe.frame_run(author, 4, 1, role,
                                    [source, image, kit_sources['selfhost.hepta'], compiler])
        recipe.node(10, (5, role, manifest, source, image, compiler))
        recipe.publish(kind + '-manifest.json', manifest)
        recipe.publish(CANDIDATES[kind][1] + '.image.bin', image)


def store(recipe):
    from tools.build_hia_agent_store import ADAPTER, PLAN, PROGRAMS as STORE_PROGRAMS, ROOT_INSTRUCTIONS
    plan = json.loads((ROOT / PLAN).read_bytes())
    assert plan['schema'] == 'hepta.hia.agent-store-build-plan.v1'
    assert [item['role'] for item in plan['modules']] == list(range(4))
    plan_source = recipe.source(PLAN)
    word_filter, _, _ = recipe.kit('source_agent_store.hepta', 'agent_store/word_filter.hepta')
    bundle, _, bundle_images = recipe.kit('source_agent_store.hepta', 'agent_store/bundle_packer.hepta')
    root, root_sources, _ = recipe.kit('source_agent_store.hepta', 'agent_store/' + plan['units']['packer']['source'])
    recipe.node(9, (bundle_images['source_build_packer.hepta'],), bytes.fromhex(plan['bundle_packer_sha256']))
    adapter = recipe.source(ADAPTER)
    units = {name: spec for name, spec in plan['units'].items() if 'id' in spec}
    assert sorted(spec['id'] for spec in units.values()) == list(range(25))
    _, flats = recipe.compile({spec['source']: STORE_PROGRAMS + spec['source'] for spec in units.values()})
    images = {name: recipe.frame_run(word_filter, 5, 1, spec['id'], [plan_source, flats[spec['source']]])
              for name, spec in units.items()}
    modules = [recipe.frame_run(bundle, 5, 2, group['role'],
                                [plan_source, *(images[name] for name in group['units'])])
               for group in plan['modules']]
    manifest = recipe.frame_run(bundle, 5, 3, 0, [plan_source, *modules])
    parts = {'loader': images['loader'], 'owner': images['owner'],
             'manifest': manifest, 'json': images['JSON_hub']}
    executable = recipe.frame_run(root, 5, 4, 0, [plan_source, *parts.values()])
    recipe.check_placement(executable, root_sources['source_build_packer.hepta'], adapter,
                           list(parts.values()), [ROOT_INSTRUCTIONS[name] for name in parts])
    recipe.node(8, (plan_source, recipe.source(PLAN)))
    recipe.node(8, (adapter, recipe.source(ADAPTER)))
    for group, module in zip(plan['modules'], modules, strict=True):
        recipe.publish(f"module-{group['role']}.bin", module, group['sha256'])
    recipe.publish(outputs(5)[-1], executable, plan['expected_root_sha256'])


def stdio(recipe):
    names = ('agent_stdio_dispatch.hepta', 'core_json_frontend.hepta', 'selfhost.hepta')
    sources, images = recipe.compile({name: name for name in names})
    recipe.node(8, (images['selfhost.hepta'], recipe.import_product('selfhost.image.bin')))
    author, _, _ = recipe.kit('source_agent_stdio.hepta', 'agent_stdio_packer.hepta')
    catalog = recipe.import_product('hia-catalog')
    catalogs = [recipe.node(14, (catalog, version)) for version in range(1, 10)]
    executable = recipe.frame_run(author, 6, 1, 0,
                                  [*(sources[name] for name in names),
                                   *(images[name] for name in names), *catalogs])
    recipe.publish(outputs(6)[0], executable)


def read_adapters():
    from tools.generate_hia_worker_flow_packer import FLOW, PORTS, PEERS, PEER_KINDS, adapter_source
    from tools.generate_hia_worker_read_release import ENTRIES
    flow, ports, peers = ((ROOT / path).read_bytes() for path in (FLOW, PORTS, PEERS))
    return {PROGRAMS + 'release_stage_read_adapters/' + role + '.S':
            adapter_source(flow, ports, kind=role, peers=peers if role in PEER_KINDS else b'')
            for role in ENTRIES}


def read_carrier(recipe):
    from tools.generate_hia_worker_flow_packer import PROGRAMS as FLOWS
    from tools.generate_hia_worker_read_release import ADAPTER, ENTRIES, SOURCE
    names = [Path(FLOWS[role][0]).name for role in ENTRIES]
    sources, images = recipe.compile({name: name for name in names})
    parts, bodies = [], []
    for ordinal, (role, name) in enumerate(zip(ENTRIES, names, strict=True), 1):
        _, packer = FLOWS[role]
        owner, kit_sources, _ = recipe.kit('source_read_carrier.hepta', Path(packer).name)
        executable = recipe.frame_run(owner, 7, 1, ordinal, [sources[name]])
        adapter = recipe.source(PROGRAMS + 'release_stage_read_adapters/' + role + '.S')
        recipe.check_adapter(executable, images[name], kit_sources['source_build_packer.hepta'], adapter)
        parts.extend((sources[name], executable))
        bodies.append(recipe.node(15, (executable, 176, U64_MAX)))
    owner, kit_sources, _ = recipe.kit('source_read_carrier.hepta', Path(SOURCE).name)
    carrier = recipe.frame_run(owner, 7, 2, 0, parts)
    recipe.check_placement(carrier, kit_sources['source_build_packer.hepta'],
                           recipe.source(ADAPTER), bodies, (b'\xe9',) * len(ENTRIES))
    recipe.publish(outputs(7)[0], carrier)


def owned_reference(recipe):
    from tools.generate_hia_owned_reference import ADAPTER_PATH, PACKER_PATH, SOURCE_PATH
    policy = 'source_owned_reference.hepta'
    composer, _, _ = recipe.kit(policy, 'source_build_packer.hepta')
    packer, owned = Path(PACKER_PATH).name, Path(SOURCE_PATH).name
    components = (policy, 'selfhost.hepta', 'owned_reference_entry_wrapper.hepta',
                  'owned_reference_entry_stub.hepta', packer)
    sources, images = recipe.compile({name: name for name in (*components, owned)})
    parts = [part for name in components for part in (sources[name], images[name])]
    assembler = recipe.frame_run(composer, 8, 1, 0, parts)
    product = recipe.frame_run(assembler, 8, 2, 0, [sources[owned]])
    recipe.node(10, (4, 2, product, images[owned], sources[packer], recipe.source(ADAPTER_PATH)))
    recipe.publish(outputs(8)[0], product)


def sqlite_units(recipe):
    from tools.build_hia_agent_artifact_capture import UNIT as CAPTURE_UNIT
    from tools.build_hia_nominal_json import SOURCE_NAME as NOMINAL_SOURCE, STDIO, STDIO_TEMPLATE
    from tools.build_hia_sqlite_components import (
        CAPTURE_ADAPTERS, COMPONENT_TEMPLATES, INPUT, PROJECTION,
        PROJECTION_ADAPTER, PROJECTION_ROLES, START, UNITS)
    from tools.build_hia_sqlite_pager import ADAPTERS, PAGER, STREAM, TEMPLATES
    objects = [recipe.adapter(9, COMPONENT_TEMPLATES, ordinal, path)
               for ordinal, path in enumerate((START, INPUT, *CAPTURE_ADAPTERS, PROJECTION_ADAPTER))]
    nominal_adapter = recipe.adapter(9, STDIO_TEMPLATE, 0, STDIO)
    pager_adapters = [recipe.adapter(9, TEMPLATES, ordinal, path)
                      for ordinal, path in enumerate(ADAPTERS)]
    units = [(unit, 2, ordinal, objects[:2]) for ordinal, unit in enumerate(UNITS, 1)]
    units.extend(((CAPTURE_UNIT, 3, 32, objects[2:4]),
                  ('nominal-packet', 4, 33, [nominal_adapter])))
    projection = (PROJECTION, *PROJECTION_ROLES)
    names = {unit: unit.replace('-', '_') + '.hepta' for unit in (*[row[0] for row in units], *projection)}
    names['nominal-packet'] = Path(NOMINAL_SOURCE).name
    names.update(pager=Path(PAGER).name, stream=Path(STREAM).name)
    sources, images = recipe.compile({name: name for name in names.values()})
    for unit, operation, ordinal, adapters in units:
        embedded = recipe.embed(9, operation, ordinal, [sources[names[unit]]])
        executable = recipe.link(9, 8 if unit == 'nominal-packet' else 7, [*adapters, embedded])
        recipe.check_image(executable, images[names[unit]])
        recipe.publish('hia-' + unit, executable)
    inputs = [objects[4], *(recipe.embed(9, 5, ordinal, [sources[names[unit]]])
                            for ordinal, unit in enumerate(projection, 1))]
    executable = recipe.link(9, 9, inputs)
    for unit in projection:
        recipe.check_image(executable, images[names[unit]])
    recipe.publish('hia-' + PROJECTION, executable)
    inputs = [*pager_adapters, recipe.embed(9, 6, 34, [sources[names['pager']]]),
              recipe.embed(9, 6, 35, [sources[names['stream']]])]
    executable = recipe.link(9, 10, inputs)
    for unit in ('pager', 'stream'):
        recipe.check_image(executable, images[names[unit]])
    recipe.publish(outputs(9)[-1], executable)


def migrations(recipe):
    from tools.build_hia_sqlite_migrate import ADAPTER as MIGRATE_ADAPTER, COMPONENTS, COORDINATOR
    from tools.build_hia_sqlite_migration_publish import (
        ADAPTER as PUBLISH_ADAPTER, MIGRATION_TEMPLATES, UNITS as PUBLISH_UNITS)
    publication = (PUBLISH_UNITS['sqlite-migration-publish'], PUBLISH_UNITS['sqlite-agent-artifact-catalog'])
    sources, images = recipe.compile({Path(path).name: Path(path).name for path in (*publication, COORDINATOR)})
    external = [row[3] for row in stage_rows() if row[:3] == ['need', '10', '0']]
    publisher_children = external[2:4]
    assert len(publisher_children) == 2
    artifact = recipe.import_product(publisher_children[0])
    recipe.node(10, (6, 0, artifact))
    for name, role, adapter, source_roles, section, link_op in (
        (outputs(10)[0], 0, PUBLISH_ADAPTER, tuple(enumerate(publication, 36)), 17, 4),
        (outputs(10)[1], 1, MIGRATE_ADAPTER, ((38, COORDINATOR),), 20, 5),
    ):
        objects = [recipe.adapter(10, MIGRATION_TEMPLATES, role, adapter)]
        embedded = []
        for ordinal, path in source_roles:
            alias = Path(path).name
            objects.append(recipe.embed(10, 2, ordinal, [sources[alias]]))
            embedded.append(images[alias])
        names = publisher_children if role == 0 else [program for _, program, _ in COMPONENTS]
        children = [recipe.import_product(child) for child in names]
        for ordinal, child in enumerate(children, section):
            pin = recipe.node(13, (child,))
            objects.append(recipe.embed(10, 3, ordinal, [child, pin]))
        executable = recipe.link(10, link_op, objects)
        for raw in (*embedded, *children):
            recipe.check_image(executable, raw)
        recipe.publish(name, executable)


def ndu_scalar(recipe):
    """Source-compile the NDU policy and its exact bound process adapter."""
    sources, images = recipe.compile({name: name for name in
        ('ndu_scalar.hepta', 'ndu_scalar_packer.hepta')})
    host = recipe.kit('source_mcp_filter.hepta', 'mcp_build_filter_packer.hepta')[0]
    source, image = sources['ndu_scalar_packer.hepta'], images['ndu_scalar_packer.hepta']
    frame = recipe.node(16, (recipe.literal(b'HIAMCF01'),
        recipe.node(17, (source,)), recipe.node(17, (image,)), source, image))
    packer = recipe.run(host, frame)
    from tools.generate_hia_mcp_release import check_packer_host
    check_packer_host(recipe, packer, image)
    application = images['ndu_scalar.hepta']
    packet = recipe.node(16, (recipe.literal(b'HIANDU01'),
        recipe.node(17, (application,)), application))
    executable = recipe.run(packer, packet, operation=0)
    recipe.check_adapter(executable, application, source,
        recipe.source('tools/hia_ndu_scalar_syscalls.S'))
    recipe.publish('hia-ndu-scalar', executable)


def source_contract(recipe):
    """Deliver the native source-inventory contract owner through the same DAG."""
    from tools.generate_hia_mcp_release import check_packer_host, check_sequential_layout
    from tools.generate_hia_native_filter import template
    sources, images = recipe.compile({name: name for name in
        ('source_contract_generate.hepta', 'native_filter_packer.hepta')})
    host = recipe.kit('source_mcp_filter.hepta', 'mcp_build_filter_packer.hepta')[0]
    source, image = sources['native_filter_packer.hepta'], images['native_filter_packer.hepta']
    frame = recipe.node(16, (recipe.literal(b'HIAMCF01'),
        recipe.node(17, (source,)), recipe.node(17, (image,)), source, image))
    packer = recipe.run(host, frame)
    check_packer_host(recipe, packer, image)
    application = images['source_contract_generate.hepta']
    packet = recipe.node(16, (recipe.literal(b'HIAFLT01'),
        recipe.node(17, (application,)), application))
    executable = recipe.run(packer, packet, operation=0)
    prefix, holes = template()
    if len(holes) != 1:
        raise ValueError('source contract filter has an unexpected call layout')
    check_sequential_layout(recipe, executable, prefix,
                            {'image': holes[0]}, {'image': application})
    recipe.publish('hia-source-contract', executable)

def recipes():
    first, rest, controller = Recipe(), Recipe(), Recipe()
    constructor(first)
    for stage in (helpers, store, stdio, read_carrier, owned_reference, sqlite_units, migrations):
        stage(rest)
    # The owner releases a DAG's owned transient descriptors at its boundary.
    # Keep the final six products in their own graph so complete delivery fits
    # the ordinary 1024-descriptor limit while retaining published products.
    from tools.generate_hia_mcp_release import append_recipe
    append_recipe(controller)
    ndu_scalar(controller)
    from tools.generate_hia_system_jobctl_release import append_recipe as system_jobctl_recipe
    system_jobctl_recipe(controller)
    source_contract(controller)
    assert first.published == outputs(2)
    assert rest.published + controller.published == [
        name for stage in range(4, 11) for name in outputs(stage)]
    assert len(first.published) + len(rest.published) + len(controller.published) == 46
    return {RECIPE_NAMES[0]: first, RECIPE_NAMES[1]: rest,
            RECIPE_NAMES[2]: controller}


def main():
    for relative, data in read_adapters().items():
        path = ROOT / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        print(relative, len(data))
    for name, recipe in recipes().items():
        raw = recipe.binary()
        (ROOT / PROGRAMS / name).write_bytes(raw)
        print(name, 'nodes', len(recipe.nodes), 'publishes', len(recipe.published), 'bytes', len(raw))


if __name__ == '__main__':
    main()
