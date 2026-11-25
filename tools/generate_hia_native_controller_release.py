"""Author the final native controller release DAG and its independent byte checks.

This development author is removed from the production source set. The retained
HIA assembly and HIASTD01 declarations execute all capture, compilation, hashing,
packing, identity checks and publication through the native release owner.
"""
from __future__ import annotations

from pathlib import Path
import json
import struct

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_mcp_service import document
from tools import generate_hia_mcp_service as service
from tools import generate_hia_mcp_http as http
from tools import generate_hia_mcp_job_bridge as bridge
from tools import generate_hia_mcp_request_audit as audit
from tools import generate_hia_system_jobctl_packer as jobctl
from tools import generate_hia_native_filter as filters
from tools.generate_hia_release_core_recipe import CoreRecipe

ROOT = Path(__file__).resolve().parents[1]
BOOT = 'examples/hia_bootstrap/'
FILTER_POLICY = 'source_native_filter_pack.hepta'
WIDE_FILTER = 'native_controller_filter_packer.hepta'
DELIVERY = 'native_controller_delivery.hepta'
RECIPE = 'release_stage_controller.hiastd'
FILTER_WIRE = b'HIANPF01'
DELIVERY_WIRE = b'HIANCD01'
DELIVERY_OK = b'HIAOKD01'


def specifications():
    rows = []
    for mode, name, magic, roles, parts, packer, adapter, template, cap in (
        (1, 'hia-mcp-job-bridge', bridge.PACKER_MAGIC, bridge.ROLES,
         {r: bridge.COMPANIONS.get(r, BOOT + 'mcp_job_bridge_' + r + '.hepta') for r in bridge.ROLES},
         'mcp_job_bridge_packer.hepta', 'tools/hia_mcp_job_bridge_syscalls.S', bridge.template, 16777216),
        (2, 'hia-mcp-request-audit', b'HIARAU01', audit.ROLES,
         {r: BOOT + 'mcp_request_audit_' + r + '.hepta' for r in audit.ROLES},
         'mcp_request_audit_packer.hepta', 'tools/hia_mcp_request_audit_syscalls.S', audit.template, 16777216),
        (3, 'hia-system-jobctl', jobctl.MAGIC, tuple(r for r, _ in jobctl.MODULES),
         {r: BOOT + stem + '.hepta' for r, stem in jobctl.MODULES},
         'system_jobctl_packer.hepta', 'tools/hia_system_jobctl_syscalls.S', jobctl.template, 4194304),
        (4, 'hia-mcp-service', b'HIAMSP03', service.ROLES,
         {r: service.COMPANIONS.get(r, BOOT + 'mcp_service_' + r + '.hepta')
          for r in service.ROLES if r not in ('bridge', 'audit')},
         'mcp_service_packer.hepta', 'tools/hia_mcp_service_syscalls.S', service.template, 67108864),
        (5, 'hia-mcp-http', b'HIAMHP01', http.ROLES,
         {r: http.COMPANIONS.get(r, http.source_path(r))
          for r in http.ROLES if r not in ('bridge', 'audit')},
         'mcp_http_packer.hepta', 'tools/hia_mcp_http_syscalls.S', http.template, 67108864),
    ):
        prefix, holes = template()
        rows.append(dict(mode=mode, name=name, magic=magic, roles=tuple(roles), parts=parts,
                         packer=BOOT + packer, adapter=adapter, prefix=prefix, holes=holes, cap=cap))
    return rows


HELPERS = '''
def uint(s:readbuf, at:u64, n:u64) -> u64:
    i = 0
    result = 0
    while i < n:
        result = result | (byte(s, at + i) << (i * 8))
        i = i + 1
    return result

def get(w:mutbuf, at:u64) -> u64:
    i = 0
    result = 0
    while i < 8:
        result = result | (byte(w, at + i) << (i * 8))
        i = i + 1
    return result

def write(w:mutbuf, at:u64, value:u64, n:u64) -> u64:
    i = 0
    while i < n:
        store(w, at + i, (value >> (i * 8)) & 255)
        i = i + 1
    return 0

def copy(s:readbuf, o:mutbuf, start:u64, target:u64, n:u64) -> u64:
    i = 0
    while i < n:
        store(o, target + i, byte(s, start + i))
        i = i + 1
    return 0

def same(s:readbuf, w:mutbuf, start:u64, target:u64, n:u64) -> bool:
    i = 0
    while i < n:
        if byte(s, start + i) != byte(w, target + i):
            return False
        i = i + 1
    return True
'''


def constant_functions(prefixes, offset=256):
    dispatch = 'def prefix(w:mutbuf, mode:u64) -> u64:\n'
    helpers = ''
    for mode, raw in prefixes.items():
        dispatch += f'    if mode == {mode}:\n'
        for bank, start in enumerate(range(0, len(raw), 512)):
            name = f'prefix_{mode}_{bank}'
            dispatch += f'        {name}(w)\n'
            helpers += f'\ndef {name}(w:mutbuf) -> u64:\n'
            for at in range(start, min(start + 512, len(raw)), 8):
                part = raw[at:at + 8]
                helpers += f'    write(w, {offset + at}, {int.from_bytes(part, "little")}, {len(part)})\n'
            helpers += '    return 0\n'
        dispatch += f'        return {len(raw)}\n'
    return dispatch + '    return 0\n' + helpers


def filter_policy():
    prefixes, holes = {}, {}
    for mode, wire, output in ((1, 8388608, 8388608), (2, 67108864, 67108864)):
        prefixes[mode], sites = filters.template(wire_bytes=wire, output_bytes=output, workspace_bytes=16777216)
        assert len(sites) == 1
        holes[mode] = sites[0]
    assert len(prefixes[1]) == len(prefixes[2])
    width = len(prefixes[1])
    source = f'''def build(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 4096:
        return 17
    phase = get(w, 0)
    state = get(w, 16)
    if phase == 0 and state == 0:
        if length(s) != 21 or uint(s, 0, 8) != 1 or uint(s, 8, 8) != 5 or uint(s, 16, 5) != 431315580258:
            return 16
        write(w, 16, 1, 8)
        return 0
    if phase == 1 and state == 1:
        if length(s) < 25 or length(s) > 1048576 or uint(s, 0, 8) != {int.from_bytes(FILTER_WIRE, 'little')}:
            return 16
        mode = uint(s, 8, 8)
        size = uint(s, 16, 8)
        if (mode != 1 and mode != 2) or size == 0 or size != length(s) - 24 or size + {width} > 1048576:
            return 16
        write(w, 24, mode, 8)
        write(w, 32, size, 8)
        write(w, 40, length(s), 8)
        write(w, 16, 2, 8)
        return 0
    if length(s) != get(w, 40):
        return 16
    if phase == 2 and state == 2:
        write(w, 16, 4, 8)
        return 2
    if phase == 4 and state == 4:
        if length(o) < get(w, 32) + 16:
            return 17
        write(o, 0, {filters.MAGIC}, 8)
        write(o, 8, get(w, 32), 8)
        copy(s, o, 24, 16, get(w, 32))
        write(w, 80, get(w, 32) + 16, 8)
        write(w, 16, 5, 8)
        return 0
    if phase == 5 and state == 5:
        size = get(w, 72)
        if size != {width} + get(w, 32) or size > length(o):
            return 18
        prefix(w, get(w, 24))
        write(w, 352, size, 8)
        write(w, 360, size, 8)
        site = choose(get(w, 24) == 1, {holes[1]}, {holes[2]})
        write(w, 256 + site, {width} - site - 4, 4)
        i = 0
        while i < {width}:
            if byte(o, i) != byte(w, 256 + i):
                return 18
            i = i + 1
        i = 0
        while i < get(w, 32):
            if byte(o, {width} + i) != byte(s, 24 + i):
                return 19
            i = i + 1
        write(w, 88, size, 8)
        write(w, 16, 6, 8)
        return 0
    return 16
'''
    return source + constant_functions(prefixes) + HELPERS


def delivery_source(specs):
    source = f'''def check(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(w) < 65536 or length(o) < 8:
        return 4294967294
    if length(s) < 33 or length(s) > 67108864 or uint(s, 0, 8) != {int.from_bytes(DELIVERY_WIRE, 'little')}:
        return 4294967295
    mode = uint(s, 8, 8)
    wire = uint(s, 16, 8)
    elf = uint(s, 24, 8)
    if wire > length(s) - 32 or elf != length(s) - 32 - wire:
        return 4294967295
    head = header(mode)
    count = roles(mode)
    ceiling = limit(mode)
    if head == 0 or wire < head or elf > ceiling or uint(s, 32, 8) != magic(mode):
        return 4294967295
    base = prefix(w, mode)
    if base == 0 or elf < base:
        return 4294967295
    index = 0
    total = 0
    while index < count:
        size = uint(s, 40 + index * 8, 8)
        maximum = 1048576
        if mode == 4 and index >= {len(service.ROLES) - 2}:
            maximum = 16777216
        if mode == 5 and index >= {len(http.ROLES) - 2}:
            maximum = 16777216
        if size == 0 or size > maximum or size > ceiling - total:
            return 4294967295
        hole = call_hole(mode, index)
        if hole == 0 or hole + 4 > base:
            return 4294967295
        write(w, 256 + hole, base + total - hole - 4, 4)
        total = total + size
        index = index + 1
    if total != wire - head or elf != base + total:
        return 4294967295
    write(w, 352, elf, 8)
    write(w, 360, elf, 8)
    if mode == 4 or mode == 5:
        embedded_fields(mode, s, w)
    if same(s, w, 32 + wire, 256, base) == False:
        return 4294967295
    index = 0
    while index < total:
        if byte(s, 32 + head + index) != byte(s, 32 + wire + base + index):
            return 4294967295
        index = index + 1
    write(o, 0, {int.from_bytes(DELIVERY_OK, 'little')}, 8)
    return 8
'''
    for name, getter in (
        ('header', lambda r: 8 + len(r['roles']) * 8 + (64 if r['mode'] in (4, 5) else 0)),
        ('roles', lambda r: len(r['roles'])),
        ('magic', lambda r: int.from_bytes(r['magic'], 'little')),
        ('limit', lambda r: r['cap']),
    ):
        source += f'\ndef {name}(mode:u64) -> u64:\n'
        for r in specs:
            source += f'    if mode == {r["mode"]}:\n        return {getter(r)}\n'
        source += '    return 0\n'
    source += '\ndef call_hole(mode:u64, index:u64) -> u64:\n'
    for r in specs:
        source += f'    if mode == {r["mode"]}:\n        return holes_{r["mode"]}(index)\n'
    source += '    return 0\n'
    for r in specs:
        source += f'\ndef holes_{r["mode"]}(index:u64) -> u64:\n'
        for i, role in enumerate(r['roles']):
            source += f'    if index == {i}:\n        return {r["holes"][role]}\n'
        source += '    return 0\n'
    source += '\ndef embedded_fields(mode:u64, s:readbuf, w:mutbuf) -> u64:\n'
    for r in specs:
        if r['mode'] in (4, 5):
            source += f'    if mode == {r["mode"]}:\n        return embedded_fields_{r["mode"]}(s, w)\n'
    source += '    return 0\n'
    for r in specs:
        if r['mode'] not in (4, 5):
            continue
        count = len(r['roles'])
        source += f'\ndef embedded_fields_{r["mode"]}(s:readbuf, w:mutbuf) -> u64:\n'
        for role, index, at in (('bridge', count - 2, 8 + count * 8), ('audit', count - 1, 40 + count * 8)):
            source += f'    write(w, {256 + r["holes"][role + "_size"]}, uint(s, {40 + index * 8}, 8), 4)\n'
            source += f'    copy(s, w, {32 + at}, {256 + r["holes"][role + "_pin"]}, 32)\n'
        source += '    return 0\n'
    return source + constant_functions({r['mode']: r['prefix'] for r in specs}) + HELPERS


class ControllerRecipe(CoreRecipe):
    def compile_exact(self, paths):
        self.compile_paths(paths)
        names = sorted(set(paths))
        for at in range(0, len(names), 12):
            named = {f'unit-{i}.hepta': path for i, path in enumerate(names[at:at + 12])}
            sources, images = self.compile(named)
            for alias, path in named.items():
                self.node(8, (self.source_views[path], sources[alias]))
                self.node(8, (self.compiled[path], images[alias]))

    def checked_kit(self, application):
        executable, sources, images = self.kit(FILTER_POLICY, application)
        for alias, path in (('source_build_policy.hepta', BOOT + FILTER_POLICY),
                            ('source_build_packer.hepta', BOOT + application)):
            self.node(8, (sources[alias], self.source_views[path]))
            self.node(8, (images[alias], self.compiled[path]))
        return executable

    def native_filter(self, image, *, wide):
        builder = self.wide_builder if wide else self.small_builder
        wire = self.concat(self.literal(FILTER_WIRE + struct.pack('<Q', 2 if wide else 1)), self.length(image), image)
        executable = self.run(builder, wire)
        # HIASTC01 kind 1 is the retained three-segment SQLite pager check.
        # Native filters have a closed two-segment template. Construct its
        # complete expected bytes with native DAG operations instead of
        # widening that older verifier or executing a candidate to trust it.
        ceiling = 67108864 if wide else 8388608
        prefix, sites = filters.template(wire_bytes=ceiling, output_bytes=ceiling,
                                         workspace_bytes=16777216)
        assert len(sites) == 1 and prefix[96:112] == bytes(16)
        prefix = bytearray(prefix)
        site = sites[0]
        assert 112 <= site < len(prefix) - 4 and prefix[site - 1] == 0xe8
        struct.pack_into('<I', prefix, site, len(prefix) - site - 4)
        extent = self.length(executable)
        expected = self.concat(self.literal(prefix[:96]), extent, extent,
                               self.literal(prefix[112:]), image)
        self.node(8, (expected, executable))
        return executable

    def verify_delivery(self, mode, wire, executable):
        request = self.concat(self.literal(DELIVERY_WIRE + struct.pack('<Q', mode)),
                              self.length(wire), self.length(executable), wire, executable)
        result = self.run(self.delivery, request, 0)
        self.node(8, (result, self.literal(DELIVERY_OK)))


def build_recipe(specs):
    r = ControllerRecipe()
    paths = {BOOT + FILTER_POLICY, BOOT + WIDE_FILTER, BOOT + DELIVERY,
             BOOT + 'native_filter_packer.hepta', BOOT + 'source_contract_generate.hepta'}
    paths.update(row['packer'] for row in specs)
    paths.update(path for row in specs for path in row['parts'].values())
    r.compile_exact(paths)
    r.wide_builder = r.checked_kit(WIDE_FILTER)
    r.small_builder = r.checked_kit('native_filter_packer.hepta')
    r.delivery = r.native_filter(r.compiled[BOOT + DELIVERY], wide=True)
    products = {}
    for row in specs:
        packer = r.native_filter(r.compiled[row['packer']], wide=True)
        parts = []
        for role in row['roles']:
            if row['mode'] in (4, 5) and role in ('bridge', 'audit'):
                parts.append(products['hia-mcp-job-bridge' if role == 'bridge' else 'hia-mcp-request-audit'])
            else:
                parts.append(r.compiled[row['parts'][role]])
        pins = [r.digest(parts[-2]), r.digest(parts[-1])] if row['mode'] in (4, 5) else []
        wire = r.concat(r.literal(row['magic']), *(r.length(part) for part in parts), *pins, *parts)
        executable = r.run(packer, wire, 0)
        r.verify_delivery(row['mode'], wire, executable)
        r.publish(row['name'], executable)
        products[row['name']] = executable
    contract = r.native_filter(r.compiled[BOOT + 'source_contract_generate.hepta'], wide=False)
    r.publish('hia-source-contract', contract)
    assert len(r.nodes) <= 8192 and r.next_handle <= 2049 and len(r.binary()) <= 1048576
    return r, sorted(paths)


def main():
    specs = specifications()
    sources = {
        FILTER_POLICY: filter_policy(),
        WIDE_FILTER: filters.source_program(wire_bytes=67108864, output_bytes=67108864,
                                            workspace_bytes=16777216, pack_limit=1048576),
        DELIVERY: delivery_source(specs),
    }
    counts = {}
    for name, source in sources.items():
        doc = document(source, Path(name).stem)
        counts[name] = dict(functions=len(doc['functions']), blocks=sum(len(f['blocks']) for f in doc['functions']),
                            operations=sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']))
        (ROOT / BOOT / name).write_text(render_assembly(doc))
    recipe, paths = build_recipe(specs)
    (ROOT / BOOT / RECIPE).write_bytes(recipe.binary())
    table = ROOT / BOOT / 'release_stage_sources.tsv'
    lines = table.read_text().splitlines()
    assert lines, 'empty native stage inventory'
    header = lines[0].split('\t')
    assert len(header) == 3 and header[0] == 'stage' and 10 <= int(header[1]) <= 16, header
    # The first line is the aggregate count, not stage 11's data. Preserve
    # it and the first stage's source-builder requirement on every replay.
    later = [line for line in lines[1:] if int(line.split('\t')[1]) > 11]
    lines = [lines[0]] + [line for line in lines[1:] if int(line.split('\t')[1]) < 11]
    old_outputs = sum(line.startswith('output\t') for line in lines + later)
    lines[0] = '\t'.join((header[0], str(max(11, int(header[1]))), str(old_outputs + len(recipe.published))))
    lines += ['stage\t11\tnative-controllers', 'need\t11\t0\thia-source-build',
              'need\t11\t0\tselfhost.image.bin']
    lines += ['compile\t11\tcontrollers\t' + Path(path).name + '\t' + path.removeprefix(BOOT) for path in paths]
    lines += ['kit\t11\t' + FILTER_POLICY + '\t' + name for name in (WIDE_FILTER, 'native_filter_packer.hepta')]
    lines += ['resource\t11\t' + row['adapter'] for row in specs]
    lines += ['output\t11\t' + name for name in recipe.published]
    for row in specs:
        lines += [f'framing\t11\t{row["mode"]}\t{row["magic"].decode()}\tindependent-prefix-and-all-source-images']
    lines += later
    table.write_text('\n'.join(lines) + '\n')
    # The legacy cold proof also authenticates this new production graph. Its
    # optional reference-only driver remains separate from the native runtime.
    from tools.hia_selfhost_contract import SOURCE_FILES
    required = set(paths) | {BOOT + RECIPE, 'tools/generate_hia_native_controller_release.py'}
    required.update(row['adapter'] for row in specs)
    missing = sorted(required - set(SOURCE_FILES))
    if missing:
        contract = ROOT / 'tools/hia_selfhost_contract.py'
        text = contract.read_text()
        marker = 'SOURCE_FILES = (\n'
        assert text.count(marker) == 1
        text = text.replace(marker, marker + ''.join(f'    {path!r},\n' for path in missing))
        contract.write_text(text)
    print(json.dumps({'sources': counts, 'nodes': len(recipe.nodes), 'handles': recipe.next_handle - 1,
                      'recipe_bytes': len(recipe.binary()), 'compile_sources': len(paths),
                      'products': recipe.published}, indent=2))


if __name__ == '__main__':
    main()
