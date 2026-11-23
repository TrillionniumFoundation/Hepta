"""Build the fixed Core applications with the admitted HIA compiler, adapters and ELF packer."""

from hashlib import sha256
from pathlib import Path
import struct

from tools.build_hia_source_build import _build_captured, _compiled_sources, _run_captured, _source_bundle

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = 'examples/hia_bootstrap/'
POLICY = 'source_core_application.hepta'
KINDS = ('catalog', 'capabilities', 'normalize_core', 'verify_core_json', 'inspect_core_json',
         'render_assembly', 'publish_program', 'publish_assembly', 'import_assembly')


def cold_tools(directory, compiler, cold_report, admitted):
    """Bootstrap the native seed when this builder is invoked independently."""
    _, seed = _build_captured(directory / 'core-source-seed', compiler, cold_report)

    def call(program, operation, wire):
        result = _run_captured(program, operation, wire, directory)
        if result.returncode or result.stderr or not result.stdout:
            raise ValueError(f'native Core application {operation} failed ({result.returncode})')
        return result.stdout

    def compile_sources(named):
        pinned = {}
        for name, relative in sorted(named.items()):
            path = BOOTSTRAP + relative
            source = (ROOT / path).read_bytes()
            if sha256(source).hexdigest() != admitted.get(path):
                raise ValueError('Core application source differs from cold admission: ' + path)
            pinned[name] = source
        wire = _source_bundle(pinned.values(), names=pinned)
        result = call(seed, 'build', wire)
        return result, _compiled_sources(result, pinned), pinned

    return seed, compile_sources, call


def source_paths(kind, roles):
    from tools.build_hia_core_edit import ASSEMBLY_PRESENTERS, ASSEMBLY_PUBLICATION
    if kind == 'import_assembly':
        return (*(path for path, _ in roles[:3]), *ASSEMBLY_PRESENTERS, *ASSEMBLY_PUBLICATION)
    return tuple(path for path, _ in roles)


def indexed_images(images):
    offset = 8 * len(images)
    offsets = []
    for image in images:
        offsets.append(offset)
        offset += len(image)
    return struct.pack(f'<{len(offsets)}Q', *offsets) + b''.join(images)


def build_products(tools, admitted):
    """The host transports sources and checks the physical output; HIA owns row selection,
    recompilation, relocation binding, aligned layout and publication.
    """
    from tools.build_hia_core_edit import (
        ADAPTER_RECORD, PACKER, PROGRAMS, STATIC_ADAPTER_ROLES, STATIC_RELOCATIONS, check_placement,
    )
    seed, compile_sources, call = tools
    builders = {}

    def builder(leaf):
        if leaf not in builders:
            kit, _, _ = compile_sources({
                'source_build_policy.hepta': POLICY, 'selfhost.hepta': 'selfhost.hepta',
                'source_build_packer.hepta': leaf.removeprefix(BOOTSTRAP),
            })
            builders[leaf] = call(seed, 'pack', kit)
        return builders[leaf]

    paths = {path for kind in KINDS for path in source_paths(kind, PROGRAMS[kind][1])}
    named = {Path(path).name: path.removeprefix(BOOTSTRAP) for path in paths}
    if len(named) != len(paths):
        raise ValueError('Core application source names collide')
    _, images, sources = compile_sources(named)
    packer = builder(PACKER)
    products = {}
    for ordinal, kind in enumerate(KINDS, 1):
        name, roles = PROGRAMS[kind]
        adapter_name = 'tools/hia_core_edit_' + kind + '.S'
        adapter = (ROOT / adapter_name).read_bytes()
        if sha256(adapter).hexdigest() != admitted.get(adapter_name):
            raise ValueError('Core mechanical adapter differs from cold admission: ' + adapter_name)
        group, _ = STATIC_ADAPTER_ROLES[adapter_name]
        row = call(builder(group), 'build', struct.pack('<8sQ', b'HIACST01', ordinal))
        source_sha, stub_sha, object_sha, size, count = ADAPTER_RECORD.unpack_from(row)
        relocs = STATIC_RELOCATIONS[adapter_name]
        stub_at = ADAPTER_RECORD.size + 8 * len(relocs)
        stub = row[stub_at:]
        if (count != len(relocs) or len(stub) != size or not 5 <= size <= 8016
                or sha256(adapter).digest() != source_sha or sha256(stub).digest() != stub_sha):
            raise ValueError('native Core adapter record differs from source: ' + kind)
        offsets = struct.unpack_from(f'<{count}Q', row, ADAPTER_RECORD.size)
        holes = [(offset, target) for offset, (_, target) in zip(offsets, relocs, strict=True)]
        inputs = [Path(path).name for path in source_paths(kind, roles)]
        pairs = [(sources[key], images[key]) for key in inputs]
        header = struct.pack('<8s3Q', b'HIACSA01', ordinal, len(adapter), len(row))
        lengths = b''.join(struct.pack('<2Q', len(source), len(image)) for source, image in pairs)
        wire = header + lengths + adapter + row + b''.join(data for pair in pairs for data in pair)
        binary = call(packer, 'build', wire)
        sections = [image for _, image in pairs]
        if kind == 'import_assembly':
            sections = [*sections[:3], indexed_images(sections[3:])]
        elf = check_placement(binary, stub, holes, sections)
        products[name] = (binary, {
            'elf': elf, 'adapter_object_sha256': object_sha.hex(),
            'native_source_sha256': {key: sha256(sources[key]).hexdigest() for key in inputs},
            'native_image_sha256': {key: sha256(images[key]).hexdigest() for key in inputs},
        })
    return products
