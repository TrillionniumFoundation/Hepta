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


def policy_builder(tools, policy, leaf):
    seed, compile_sources, call = tools
    kit, _, _ = compile_sources({
        'source_build_policy.hepta': policy, 'selfhost.hepta': 'selfhost.hepta',
        'source_build_packer.hepta': leaf.removeprefix(BOOTSTRAP),
    })
    return call(seed, 'pack', kit)


class ReleaseCodec:
    """Run the existing HIA encoder and decoder with their exact bounded ABI views."""

    def __init__(self, tools):
        _, compile_sources, self.call = tools
        self.builder = policy_builder(tools, 'source_core_codec.hepta', 'core_edit/source_codec_packer.hepta')
        self.inputs = ('release_deflate.hepta', 'argument_payload.hepta')
        _, self.images, self.sources = compile_sources({n: 'core_cli/' + n for n in self.inputs})
        self.executables = {}

    def executable(self, mode, capacity):
        key = (mode, capacity)
        if key not in self.executables:
            name = self.inputs[mode - 1]
            source, image = self.sources[name], self.images[name]
            wire = struct.pack('<8s4Q', b'HIACCO01', mode, capacity, len(source), len(image))
            self.executables[key] = self.call(self.builder, 'build', wire + source + image)
        return self.executables[key]

    def compress(self, raw, capacity):
        encoded = self.call(self.executable(1, capacity), None, raw)
        if not 0 < len(encoded) <= capacity:
            raise ValueError('native Core release compressor exceeded its output view')
        decoded = self.call(self.executable(2, len(raw)), None, encoded)
        if decoded != raw:
            raise ValueError('native Core release codec failed its exact-byte round trip')
        return encoded


def bound_source(tools, builder, mode, template, executables):
    _, _, call = tools
    entries = [(name.encode('ascii'), raw) for name, raw in sorted(executables.items())]
    header = struct.pack('<8s2Q', b'HIACPIN1', mode, len(template))
    lengths = b''.join(struct.pack('<2Q', len(name), len(data)) for name, data in entries)
    return call(builder, 'build', header + lengths + template + b''.join(name + data for name, data in entries))


def source_paths(kind, roles):
    from tools.build_hia_core_edit import ASSEMBLY_PRESENTERS, ASSEMBLY_PUBLICATION
    if kind == 'dispatch':
        from tools import build_hia_core_edit as core
        return (core.DISPATCH, core.NOMINAL_BUILD_SOURCES['public-presentation'], core.SELFHOST_ENTRY,
                core.ARGUMENT_PAYLOAD, core.ARGUMENT_PARSER, core.ARGUMENT_FORMATTER)
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


def build_products(tools, admitted, *, overrides=None, compressor=None):
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
            builders[leaf] = policy_builder(tools, POLICY, leaf)
        return builders[leaf]

    selected = ('dispatch',) if overrides is not None else KINDS
    overrides = {} if overrides is None else overrides
    paths = {path for kind in selected for path in source_paths(kind, PROGRAMS[kind][1])}
    named = {Path(path).name: path.removeprefix(BOOTSTRAP) for path in paths}
    if len(named) != len(paths):
        raise ValueError('Core application source names collide')
    _, images, sources = compile_sources({key: value for key, value in named.items()
                                         if BOOTSTRAP + value not in overrides})
    for path, source in overrides.items():
        key = Path(path).name
        sources[key] = source
        images[key] = call(seed, 'compile', source)
    packer = builder(PACKER)
    products = {}
    for kind in selected:
        ordinal = (*KINDS, 'dispatch').index(kind) + 1
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
        sections = [image for _, image in pairs]
        if kind == 'dispatch':
            control, formatter = sections[4:]
            raw = control + formatter
            encoded = compressor.compress(raw, (1 << 20) - 24)
            wire += encoded
            arguments = struct.pack('<3Q', len(encoded), len(raw), len(control)) + encoded
            sections = [indexed_images(sections[:2]), *sections[2:4], arguments]
        binary = call(packer, 'build', wire)
        if kind == 'import_assembly':
            sections = [*sections[:3], indexed_images(sections[3:])]
        elf = check_placement(binary, stub, holes, sections)
        products[name] = (binary, {
            'elf': elf, 'adapter_object_sha256': object_sha.hex(),
            'native_source_sha256': {key: sha256(sources[key]).hexdigest() for key in inputs},
            'native_image_sha256': {key: sha256(images[key]).hexdigest() for key in inputs},
        })
    return products
