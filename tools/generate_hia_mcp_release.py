"""Author the HIA compiler-bound MCP packer host and ordinary release DAG.

The Python module is development authoring. HIASTD01 executes source capture,
compilation, byte comparison, packet framing, hashing and packing natively.
"""
from __future__ import annotations
from pathlib import Path
import struct

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_native_filter import document as filter_document, template
from tools.generate_hia_source_build import POLICY as SOURCE_POLICY

ROOT = Path(__file__).resolve().parents[1]
PROGRAMS = 'examples/hia_bootstrap/'
POLICY_PATH = PROGRAMS + 'source_mcp_filter.hepta'
FILTER_PATH = PROGRAMS + 'mcp_build_filter_packer.hepta'
FILTER_CAPACITY = 64 << 20
FILTER_WORK = 1 << 20
PRODUCTS = ('hia-mcp-request-audit', 'hia-mcp-job-bridge', 'hia-mcp-service')


def specifications():
    from tools import generate_hia_mcp_request_audit as audit
    from tools import generate_hia_mcp_job_bridge as bridge
    from tools import generate_hia_mcp_service as service
    return (
        ('audit', 'mcp_request_audit', audit.ROLES, {}, b'HIARAU01'),
        ('bridge', 'mcp_job_bridge', bridge.ROLES, bridge.COMPANIONS, b'HIAJBP01'),
        ('service', 'mcp_service', service.ROLES, service.COMPANIONS, b'HIAMSP03'),
    )


def component_paths():
    paths = {}
    for label, stem, roles, companions, _ in specifications():
        for role in roles:
            if label == 'service' and role in ('bridge', 'audit'):
                continue
            paths[label, role] = companions.get(role, PROGRAMS + stem + '_' + role + '.hepta')
        paths[label, 'packer'] = PROGRAMS + stem + '_packer.hepta'
    return paths


def source_paths():
    return tuple(sorted(set(component_paths().values()) | {
        POLICY_PATH, FILTER_PATH, PROGRAMS + 'selfhost.hepta',
        PROGRAMS + 'source_build_packer.hepta',
        'tools/hia_source_build_syscalls.S',
        'tools/hia_mcp_service_syscalls.S',
        'tools/hia_mcp_job_bridge_syscalls.S',
        'tools/hia_mcp_request_audit_syscalls.S',
        'tools/generate_hia_mcp_release.py',
    }))


def policy_source():
    prefix, _ = template(wire_bytes=FILTER_CAPACITY, output_bytes=FILTER_CAPACITY,
                         workspace_bytes=FILTER_WORK)
    code = '''def policy(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 1114112:
        return 16
    phase = get(w, 0)
    state = get(w, 16)
    if phase == 0:
        if state != 0 or length(s) != 21 or uint(s, 0, 8) != 1 or uint(s, 8, 8) != 5 or uint(s, 16, 5) != BUILD_WORD:
            return 16
        put(w, 16, 1)
        return 0
    if phase == 1:
        if state != 1 or length(s) < 26 or uint(s, 0, 8) != WIRE_MAGIC:
            return 16
        source = uint(s, 8, 8)
        image = uint(s, 16, 8)
        if source == 0 or image == 0 or source > 1048576 or image > 1048576 or length(s) != 24 + source + image:
            return 16
        put(w, 40, length(s))
        put(w, 56, 24)
        put(w, 64, source)
        put(w, 96, image)
        put(w, 16, 2)
        return 0
    if length(s) != get(w, 40):
        return 16
    if phase == 2:
        if state == 2:
            return 1
        if state == 3:
            return 2
        return 16
    if phase == 3:
        if state != 2 or get(w, 72) != get(w, 96):
            return 18
        index = 0
        while index < get(w, 96):
            if byte(s, 24 + get(w, 64) + index) != byte(w, 65536 + index):
                return 19
            index = index + 1
        put(w, 16, 3)
        return 0
    if phase == 4:
        if state != 3 or 16 + get(w, 96) > length(o):
            return 16
        write(o, 0, FILTER_MAGIC, 8)
        write(o, 8, get(w, 96), 8)
        copy_bytes(s, o, 24 + get(w, 64), 16, get(w, 96))
        put(w, 80, 16 + get(w, 96))
        put(w, 16, 4)
        return 0
    if phase == 5:
        expected = PREFIX_BYTES + get(w, 96)
        if state != 4 or get(w, 72) != expected or expected > 1048576 or expected > length(o):
            return 18
        put(w, 88, expected)
        put(w, 16, 5)
        return 0
    return 16
'''
    values = {'BUILD_WORD': int.from_bytes(b'build', 'little'),
              'WIRE_MAGIC': int.from_bytes(b'HIAMCF01', 'little'),
              'FILTER_MAGIC': int.from_bytes(b'HIAFLT01', 'little'),
              'PREFIX_BYTES': len(prefix)}
    for key, value in values.items():
        code = code.replace(key, str(value))
    return code + SOURCE_POLICY[SOURCE_POLICY.index('\ndef copy_bytes('):]


def check_sequential_layout(recipe, executable, prefix, holes, parts, extra_patches=None):
    """Check every ELF byte against admitted components and the adapter template.

    All arithmetic is performed by existing native DAG extent/slice operations.
    These adapters concatenate exact parts without alignment padding; repeated
    common images inside embedded executables retain their distinct positions.
    """
    if not parts or set(holes) != set(parts):
        raise ValueError('exact sequential layout requires every declared role')
    prefix = bytes(prefix)
    prefix_view = recipe.literal(prefix)
    whole_unpatched = recipe.node(16, (prefix_view, *parts.values()))
    size = recipe.node(17, (whole_unpatched,))
    patches = {96: (8, size), 104: (8, size)}
    previous = []
    for role, part in parts.items():
        hole = holes[role]
        if not isinstance(hole, int) or not 176 <= hole <= len(prefix) - 4:
            raise ValueError('relocation is outside the mechanical adapter')
        # A slice beginning just after the relocation operand has exactly the
        # forward distance to this component's first byte.
        target = recipe.node(16, (prefix_view, *previous))
        distance = recipe.node(17, (recipe.node(15, (target, hole + 4, (1 << 64) - 1)),))
        displacement = recipe.node(15, (distance, 0, 4))
        if hole in patches:
            raise ValueError('duplicate relocation')
        patches[hole] = (4, displacement)
        previous.append(part)
    for offset, patch in (extra_patches or {}).items():
        if offset in patches:
            raise ValueError('overlapping adapter patch')
        width, value = patch
        if width not in (4, 8, 32):
            raise ValueError('invalid adapter patch width')
        recipe.node(8, (recipe.node(17, (value,)), recipe.literal(struct.pack('<Q', width))))
        patches[offset] = patch
    cursor, pieces = 0, []
    for offset, (width, value) in sorted(patches.items()):
        if width not in (4, 8, 32) or offset < cursor or offset + width > len(prefix):
            raise ValueError('invalid exact adapter patch extent')
        if offset > cursor:
            pieces.append(recipe.literal(prefix[cursor:offset]))
        pieces.append(value)
        cursor = offset + width
    if cursor < len(prefix):
        pieces.append(recipe.literal(prefix[cursor:]))
    expected = recipe.node(16, (*pieces, *parts.values()))
    recipe.node(8, (executable, expected))
    return expected


def check_packer_host(recipe, executable, image):
    prefix, holes = template(wire_bytes=FILTER_CAPACITY,
        output_bytes=FILTER_CAPACITY, workspace_bytes=FILTER_WORK)
    if len(holes) != 1:
        raise ValueError('unexpected generic packer host continuation layout')
    return check_sequential_layout(recipe, executable, prefix,
                                   {'image': holes[0]}, {'image': image})


def append_recipe(recipe):
    """Append source-complete MCP products to an ordinary native recipe."""
    paths = component_paths()
    named = {Path(path).name: path for path in sorted(set(paths.values()))}
    sources, images = recipe.compile(named)
    host = recipe.kit(Path(POLICY_PATH).name, Path(FILTER_PATH).name)[0]

    def concat(*parts):
        return recipe.node(16, parts)

    def extent(part):
        return recipe.node(17, (part,))

    built = {}
    for label, stem, roles, companions, magic in specifications():
        name = Path(paths[label, 'packer']).name
        source, image = sources[name], images[name]
        frame = concat(recipe.literal(b'HIAMCF01'), extent(source), extent(image), source, image)
        packer = recipe.run(host, frame)
        check_packer_host(recipe, packer, image)
        parts = [built[role] if label == 'service' and role in ('bridge', 'audit')
                 else images[Path(paths[label, role]).name] for role in roles]
        pins = [recipe.node(13, (built[role],)) for role in ('bridge', 'audit')] if label == 'service' else []
        wire = concat(recipe.literal(magic), *(extent(part) for part in parts), *pins, *parts)
        product = recipe.run(packer, wire, operation=0)
        from tools import generate_hia_mcp_request_audit as audit
        from tools import generate_hia_mcp_job_bridge as bridge
        from tools import generate_hia_mcp_service as service
        prefix, holes = {'audit': audit, 'bridge': bridge, 'service': service}[label].template()
        role_parts = dict(zip(roles, parts, strict=True))
        extra = {}
        if label == 'service':
            for role in ('bridge', 'audit'):
                extra[holes[role + '_size']] = (4, recipe.node(15, (extent(role_parts[role]), 0, 4)))
                extra[holes[role + '_pin']] = (32, recipe.node(13, (role_parts[role],)))
        check_sequential_layout(recipe, product, prefix,
                                {role: holes[role] for role in roles}, role_parts, extra)
        built[label] = product
        recipe.publish(PRODUCTS[len(built) - 1], product)
    return built


def main():
    policy = render_assembly(document(policy_source(), 'source_mcp_filter'))
    filter_source = render_assembly(filter_document(wire_bytes=FILTER_CAPACITY,
        output_bytes=FILTER_CAPACITY, workspace_bytes=FILTER_WORK, module='mcp_build_filter_packer'))
    for path, text in ((POLICY_PATH, policy), (FILTER_PATH, filter_source)):
        (ROOT / path).write_text(text)
        print(path, len(text.encode()))


if __name__ == '__main__':
    main()
