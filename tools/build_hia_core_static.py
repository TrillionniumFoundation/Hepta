"""Build the fixed Core applications with the admitted HIA compiler, adapters and ELF packer."""

from hashlib import sha256
from pathlib import Path
import struct

from tools.build_hia_source_build import _build_captured, _compiled_sources, _named_source_request, _run_captured

ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP = 'examples/hia_bootstrap/'
POLICY = 'source_core_application.hepta'
ROLE_ORDER = ('catalog', 'capabilities', 'normalize_core', 'verify_core_json', 'inspect_core_json',
              'render_assembly', 'publish_program', 'publish_assembly', 'import_assembly', 'dispatch',
              'selfhost_component', 'emit_object', 'packed_exec')
KINDS = tuple(kind for kind in ROLE_ORDER if kind not in ('dispatch', 'packed_exec'))


def cold_tools(directory, compiler, cold_report, admitted):
    """Bootstrap the native seed when this builder is invoked independently."""
    _, seed = _build_captured(directory / 'core-source-seed', compiler, cold_report)

    def call(program, operation, wire):
        result = _run_captured(program, operation, wire, directory)
        if result.returncode or result.stderr or not result.stdout:
            raise ValueError(f'native Core application {operation} failed ({result.returncode})')
        return result.stdout

    from tools.build_hia_native_store_release import NativeReleaseSources

    def capture_sources(named):
        pinned = {}
        for name, relative in sorted(named.items()):
            path = BOOTSTRAP + relative
            source = (ROOT / path).read_bytes()
            if sha256(source).hexdigest() != admitted.get(path):
                raise ValueError('Core application source differs from cold admission: ' + path)
            pinned[name] = source
        return pinned

    def compile_sources(named):
        pinned = capture_sources(named)
        result = call(seed, 'sources', _named_source_request(pinned))
        return result, _compiled_sources(result, pinned), pinned

    return seed, NativeReleaseSources(seed, compile_sources, capture_sources, call), call


def source_prover(directory, tools, admitted):
    """Build the same verified proof executable for a standalone Core source build."""
    from tools.build_hia_native_store_release import _stage_safe_proof

    seed, compile_sources, call = tools
    directory.mkdir(mode=0o700)
    emitted = []

    def capture(path, *, expected):
        raw = path.read_bytes()
        if path.name != 'hia-safe-core-prove' or sha256(raw).hexdigest() != expected:
            raise ValueError('native Core verifier changed before capture')
        emitted.append(raw)

    _stage_safe_proof(directory, seed, compile_sources, call, admitted, capture)
    prover, = emitted
    return prover


def source_constructor(directory, tools, admitted):
    """Use the release constructor's source and object pipeline for standalone builds."""
    from tools.build_hia_core_edit_link import source_linker
    from tools.build_hia_native_store_release import _sqlite_build_tools, _stage_nominal_constructor

    seed, compile_sources, call = tools
    directory.mkdir(mode=0o700)
    sqlite_tools = _sqlite_build_tools(seed, source_linker(tools), compile_sources, call, admitted)

    def capture(path, *, expected):
        if path.name != 'hia-nominal-constructor' or sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('native Core constructor changed before capture')

    return _stage_nominal_constructor(directory, compile_sources, capture, sqlite_tools)


def policy_builder(tools, policy, leaf):
    from tools.build_hia_native_store_release import release_sources

    return release_sources(*tools).kit(policy, leaf.removeprefix(BOOTSTRAP))


class ReleaseCodec:
    """Run the existing HIA encoder and decoder with their exact bounded ABI views."""

    def __init__(self, tools):
        self.tools = tools
        _, compile_sources, self.call = tools
        self.builder = policy_builder(tools, 'source_core_codec.hepta', 'core_edit/source_codec_packer.hepta')
        self.inputs = ('release_deflate.hepta', 'argument_payload.hepta', 'packer.hepta')
        _, self.images, self.sources = compile_sources({self.inputs[0]: 'core_cli/' + self.inputs[0],
                                                       self.inputs[1]: 'core_cli/' + self.inputs[1],
                                                       self.inputs[2]: 'core_edit/' + self.inputs[2]})
        self.owners = {}
        self.executables = {}

    def owner(self, leaf):
        if leaf not in self.owners:
            self.owners[leaf] = policy_builder(self.tools, POLICY, leaf)
        return self.owners[leaf]

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
        return (core.DISPATCH, core.NOMINAL_COMPONENTS['public-presentation'], core.SELFHOST_ENTRY,
                core.ARGUMENT_PAYLOAD, core.ARGUMENT_PARSER, core.ARGUMENT_FORMATTER)
    if kind == 'import_assembly':
        return (*(path for path, _ in roles[:3]), *ASSEMBLY_PRESENTERS, *ASSEMBLY_PUBLICATION)
    if kind == 'selfhost_component':
        from tools.build_hia_core_edit import SELFHOST_CORE_SOURCES
        return (roles[0][0], roles[1][0], *SELFHOST_CORE_SOURCES, roles[3][0])
    return tuple(path for path, _ in roles)


def indexed_images(images):
    offset = 8 * len(images)
    offsets = []
    for image in images:
        offsets.append(offset)
        offset += len(image)
    return struct.pack(f'<{len(offsets)}Q', *offsets) + b''.join(images)


def product(tools, admitted, codec, kind, inputs, sources, images, suffix, sections):
    """Independently inspect the source-bound HIA row and the final ELF placement."""
    from tools.build_hia_core_edit import (
        ADAPTER_RECORD, CAPACITY, PACKER, REGISTER_RELAY, STATIC_ADAPTER_ROLES, STATIC_RELOCATIONS,
        check_placement,
    )
    _, _, call = tools
    ordinal = ROLE_ORDER.index(kind) + 1
    adapter_name = 'tools/hia_core_edit_' + kind + '.S'

    def physical(path):
        raw = (ROOT / path).read_bytes()
        if sha256(raw).hexdigest() != admitted.get(path):
            raise ValueError('Core mechanical adapter differs from cold admission: ' + path)
        return raw

    adapter = physical(adapter_name)
    packer = codec.owner(PACKER)
    if kind == 'emit_object':
        relay = physical(REGISTER_RELAY)
        request = struct.pack('<8s3Q', b'HIACINC1', ordinal, len(adapter), len(relay))
        adapter = call(packer, 'build', request + adapter + relay)
    group, _ = STATIC_ADAPTER_ROLES[adapter_name]
    row = call(codec.owner(group), 'build', struct.pack('<8sQ', b'HIACST01', ordinal))
    source_sha, stub_sha, object_sha, size, count = ADAPTER_RECORD.unpack_from(row)
    relocs = STATIC_RELOCATIONS[adapter_name]
    stub_at = ADAPTER_RECORD.size + 8 * len(relocs)
    stub = row[stub_at:]
    if (count != len(relocs) or len(stub) != size or not 5 <= size <= 8016
            or sha256(adapter).digest() != source_sha or sha256(stub).digest() != stub_sha):
        raise ValueError('native Core adapter record differs from source: ' + kind)
    offsets = struct.unpack_from(f'<{count}Q', row, ADAPTER_RECORD.size)
    holes = [(offset, target) for offset, (_, target) in zip(offsets, relocs, strict=True)]
    pairs = [(sources[key], images[key]) for key in inputs]
    header = struct.pack('<8s3Q', b'HIACSA01', ordinal, len(adapter), len(row))
    lengths = b''.join(struct.pack('<2Q', len(source), len(image)) for source, image in pairs)
    wire = header + lengths + adapter + row + b''.join(data for pair in pairs for data in pair) + suffix
    output = call(packer, 'build', wire)
    if kind in ('selfhost_component', 'emit_object', 'packed_exec'):
        # These frames can exceed the three-image scratch area of the source seed.
        # The original HIA Core packer runs in a sealed process with the full four-MiB view.
        output = call(codec.executable(3, CAPACITY), None, output)
    elf = check_placement(output, stub, holes, sections)
    return output, {
        'elf': elf, 'adapter_object_sha256': object_sha.hex(),
        'native_source_sha256': {key: sha256(sources[key]).hexdigest() for key in inputs},
        'native_image_sha256': {key: sha256(images[key]).hexdigest() for key in inputs},
    }


def pack_implementation(tools, admitted, codec, executable, *, prover=None):
    """HIA re-inflates every block against its physical ELF before emitting the launcher frame."""
    from tools.build_hia_core_edit import EXEC_ARCHIVE_MAGIC, EXEC_CHUNK, ORDINARY_CLI_IMAGE_CAPACITY

    members = (executable,) if prover is None else (executable, prover)
    encoded = [struct.pack('<Q', len(members))]
    sections = [codec.images['argument_payload.hepta']]
    for raw in members:
        if not 176 <= len(raw) <= ORDINARY_CLI_IMAGE_CAPACITY:
            raise ValueError('Core compressed implementation exceeds the release extent')
        encoded.extend((struct.pack('<Q', len(raw)), raw))
        archive = [struct.pack('<8sQ', EXEC_ARCHIVE_MAGIC, len(raw))]
        for at in range(0, len(raw), EXEC_CHUNK):
            block = raw[at:at + EXEC_CHUNK]
            packed = codec.compress(block, 1 << 20)
            encoded.extend((struct.pack('<Q', len(packed)), packed))
            archive.extend((struct.pack('<2Q', len(packed), len(block)), packed))
        sections.append(b''.join(archive))
    binary, receipt = product(tools, admitted, codec, 'packed_exec', ('argument_payload.hepta',),
                              codec.sources, codec.images, b''.join(encoded), sections)
    if binary.count(EXEC_ARCHIVE_MAGIC) != len(members):
        raise ValueError('packed Core executable contains ambiguous framing')
    details = {'implementation_sha256': sha256(executable).hexdigest(), 'implementation_bytes': len(executable),
               'elf': receipt['elf'], 'launcher_object_sha256': receipt['adapter_object_sha256']}
    if prover is not None:
        details['attached_prover_sha256'] = sha256(prover).hexdigest()
    return binary, details


def build_products(tools, admitted, *, overrides=None, compressor=None, release_only=False):
    """Recompile and link uncompressed and composite Core applications with the sealed HIA owners."""
    from tools.build_hia_core_edit import PROGRAMS

    seed, compile_sources, call = tools
    codec = ReleaseCodec(tools) if compressor is None else compressor
    selected = ('dispatch',) if overrides is not None else tuple(
        kind for kind in KINDS if kind != 'emit_object' or not release_only)
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

    products = {}
    for kind in selected:
        name, roles = PROGRAMS[kind]
        inputs = [Path(path).name for path in source_paths(kind, roles)]
        sections = [images[key] for key in inputs]
        suffix = b''
        if kind == 'dispatch':
            control, formatter = sections[4:]
            raw = control + formatter
            suffix = codec.compress(raw, (1 << 20) - 24)
            arguments = struct.pack('<3Q', len(suffix), len(raw), len(control)) + suffix
            sections = [indexed_images(sections[:2]), *sections[2:4], arguments]
        elif kind == 'import_assembly':
            sections = [*sections[:3], indexed_images(sections[3:])]
        elif kind == 'selfhost_component':
            sections = [*sections[:2], indexed_images(sections[2:5]), sections[5]]
        binary, details = product(tools, admitted, codec, kind, inputs, sources, images, suffix, sections)
        if kind == 'selfhost_component':
            binary, wrapper = pack_implementation(tools, admitted, codec, binary)
            details.update(wrapper)
        products[name] = binary, details
    return products
