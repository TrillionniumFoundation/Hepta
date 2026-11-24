"""Build the inner nominal Core CLI programs with sealed HIA source and link stages."""

from hashlib import sha256
import struct

from tools.build_hia_core_static import policy_builder
from tools.build_hia_json_preflight import CANDIDATES, ROOT
from tools.build_hia_sqlite_pager import verify_executable


BOOTSTRAP = 'examples/hia_bootstrap/'
POLICY = 'source_core_edit_link.hepta'
PACKED_POLICY = 'source_core_packed_assets.hepta'


def source_linker(native_tools):
    from tools.build_hia_elf_linker import LINKERS

    _, compile_sources, call = native_tools
    application, packer, _, name, _ = LINKERS['static']
    owner = policy_builder(native_tools, 'source_filter_member.hepta', CANDIDATES[packer][0] + '.hepta')
    packet, _, _ = compile_sources({name + '.hepta': CANDIDATES[application][0] + '.hepta'})
    return call(owner, 'build', packet)


def build_implementations(native_tools, admitted, prover=None, *, codec=None):
    """Return each role's actual linked executable and object/link identity."""
    from tools import build_hia_core_edit as core

    _, compile_sources, call = native_tools
    linker = source_linker(native_tools)
    kinds = [kind for kind in core.NOMINAL_CLI_IMAGES if kind != 'build_object']
    if prover is not None:
        kinds.append('build_object')
    payloads_by_kind = {kind: core.nominal_cli_payloads(kind) for kind in kinds}
    files = sorted(set().union(*(payloads_by_kind[kind] for kind in kinds)))
    sources, images = {}, {}
    for offset in range(0, len(files), 12):
        chunk = files[offset:offset + 12]
        # Derived aliases keep distinct source paths separate in each flat native directory.
        named = {f'unit-{i}.hepta': path.removeprefix(BOOTSTRAP) for i, path in enumerate(chunk)}
        _, compiled, originals = compile_sources(named)
        for i, path in enumerate(chunk):
            alias = f'unit-{i}.hepta'
            sources[path], images[path] = originals[alias], compiled[alias]

    templates, objects = {}, {}
    for path, (template, role) in core.NOMINAL_ADAPTER_ROLES.items():
        if role == 0 and prover is None:
            continue
        source = (ROOT / path).read_bytes()
        if sha256(source).hexdigest() != admitted.get(path):
            raise ValueError('nominal Core adapter differs from cold admission: ' + path)
        if template not in templates:
            templates[template] = policy_builder(native_tools, POLICY, template)
        if role == 0:
            relay = (ROOT / core.REGISTER_RELAY).read_bytes()
            if sha256(relay).hexdigest() != admitted.get(core.REGISTER_RELAY):
                raise ValueError('Core register relay differs from cold admission')
            frame = struct.pack('<8s3Q', b'HIACERL1', role, len(source), len(relay)) + source + relay
        else:
            frame = struct.pack('<8sQQ', b'HIACEAD1', role, len(source)) + source
        objects[path] = call(templates[template], 'build', frame)

    products = {}
    for kind in kinds:
        path = f'tools/hia_core_edit_{kind}.S'
        template, role = core.NOMINAL_ADAPTER_ROLES[path]
        adapters = [path, core.NOMINAL_ADAPTER]
        if kind in core.EDIT_ENVELOPE_ROLES:
            adapters.append(core.EDIT_ENVELOPE)
        if kind in ('apply', 'publish_edit'):
            adapters.append(core.EDIT_RESPONSE)
        if kind in ('batch_apply', 'publish_batch'):
            adapters.append(core.BATCH_CAPTURE)
        payloads = payloads_by_kind[kind]
        parts = [*(objects[path] for path in adapters), *(sources[path] for path in payloads)]
        if kind == 'build_object':
            parts.append(prover)
        header = struct.pack('<8sQQ', b'HIACELK1', role, len(parts))
        request = header + struct.pack('<' + 'Q' * len(parts), *map(len, parts)) + b''.join(parts)
        wire = call(templates[template], 'build', request)
        packed = {}
        if kind == 'build_object':
            from tools.build_hia_core_static import ReleaseCodec

            if codec is None:
                codec = ReleaseCodec(native_tools)
            for source in core.PACKED_BUILD_IMAGES:
                raw = images[source]
                compressed = codec.compress(raw, 1 << 20)
                packed[source] = struct.pack('<QQ32s', len(raw), len(compressed), sha256(raw).digest()) + compressed
            owner = policy_builder(native_tools, PACKED_POLICY, core.PACKER)
            frame = struct.pack('<8sQ', b'HIACPA01', len(wire)) + wire + b''.join(packed.values())
            wire = call(owner, 'build', frame)
        executable = call(linker, None, wire)
        for source in payloads:
            verify_executable(executable, packed.get(source, images[source]))
        if kind == 'build_object':
            for label in ('build_shared_linker', 'build_verified_linker'):
                path = next(path for path, image_label in payloads.items() if image_label == label)
                verify_executable(executable, sha256(images[path]).digest())
            verify_executable(executable, struct.pack('<Q', len(prover)) + sha256(prover).digest())
        writable = struct.unpack_from('<Q', executable, 128)[0]
        if any(memoryview(executable)[writable:]):
            raise ValueError('a linked nominal Core CLI contains nonzero writable data: ' + kind)
        products[kind] = (executable, {
            'adapter_object_sha256': sha256(objects[adapters[0]]).hexdigest(),
            'adapter_sha256': {adapter: sha256(objects[adapter]).hexdigest() for adapter in adapters},
            'link_receipt': {'status': len(executable), 'input_sha256': sha256(wire).hexdigest()},
        })
    return products
