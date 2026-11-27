"""Observe the exact release compiler, Unicode table and intact replay phases.

This independent component observer retains the original 1 MiB compiler ABI.
The process-owner adapter supplies the existing complete 384 MiB private state;
raw flat ABI calls with overlapping or undersized owner state are not a public
process interface. The original adapter and compiler are not modified here.
"""
from __future__ import annotations
import argparse
import ast
import ctypes
import gzip
from hashlib import sha256
import json
import mmap
from pathlib import Path
import re
import struct
import subprocess

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools import generate_hia_mcp_history_diagnostic as diagnostic
from tools import generate_hia_mcp_http_events as events
from tools.generate_hia_mcp_http_common import C
from tools.generate_hia_mcp_http_metadata_stream import events_source
from tools.generate_hia_mcp_service import document
from tools.generate_hia_mcp_service_dispatch import source as dispatch_source
from tools.generate_hia_mcp_service_owner_common import C as OWNER_C
from tools.generate_hia_source_build import template
from tools.qualify_hia_mcp_request_history_seed import HistorySeeds

ROOT = Path(diagnostic.__file__).resolve().parents[1]
EVIDENCE = ROOT/'docs/evidence/http-b3-capacity-20261127-2807'
COMPILER = '494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af'
BACKEND = 'acb6478d1a466d17210611c5fcbbd5aeec3109b0813e917f0bb5c8419f3c33a9'
NONE = (1 << 64)-1
PHASES = (200, 201, 202, 203, 204, 210, 211, 220, 221, 222, 224, 225, 226, 227)


def unpack_named(raw):
    assert raw[:8] == b'HIANAM01'
    count = struct.unpack_from('<Q', raw, 8)[0]
    at, result = 16, {}
    for _ in range(count):
        name_size, size = struct.unpack_from('<QQ', raw, at)
        at += 16
        name = raw[at:at+name_size].decode()
        at += name_size
        assert name not in result
        result[name] = raw[at:at+size]
        at += size
    assert at == len(raw)
    return result


def closure(source, entry):
    tree = ast.parse(source)
    nodes = {node.name: node for node in tree.body}
    needed, pending = set(), [entry]
    while pending:
        for call in ast.walk(ast.parse(pending.pop())):
            if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                    and call.func.id in nodes and call.func.id not in needed):
                needed.add(call.func.id)
                pending.append(ast.get_source_segment(source, nodes[call.func.id]))
    return entry+'\n'+'\n'.join(ast.get_source_segment(source, node)
                               for node in tree.body if node.name in needed)


def prove_replay_ast():
    original = ast.parse(events_source(events.SOURCE))
    split = ast.parse(events.split_replay_phases(events_source(events.SOURCE)))
    helper = split.body.pop(1)
    assert helper.name == 'event_replay'
    assert [(a.arg, a.annotation.id) for a in helper.args.args] == [
        ('o', 'mutbuf'), ('w', 'mutbuf'), ('phase', 'u64'), ('result', 'u64')]
    assert ast.dump(helper.body[-1]) == ast.dump(ast.parse('return 0').body[0])
    expected_branch = ast.parse('if phase >= 200 and phase <= 227:\n    return event_replay(o,w,phase,result)').body[0]
    positions = [i for i, node in enumerate(split.body[0].body)
                 if ast.dump(node) == ast.dump(expected_branch)]
    assert len(positions) == 1
    index = positions[0]
    split.body[0].body[index:index+1] = helper.body[:-1]
    assert ast.dump(split) == ast.dump(original)
    observed = tuple(node.test.comparators[0].value for node in helper.body[:-1])
    assert observed == PHASES
    return {'phases': list(PHASES), 'complete_original_ast_restored': True,
            'phase_and_result_reads_unchanged': True, 'exclusive_formals': ['o', 'w']}


def qualify(bootstrap, output):
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {'schema': 'hepta.hia.http-b3-native-capacity-controls.v1', 'passed': False,
              'compiler_bytes_limit': 1 << 20, 'state_bytes': OWNER_C['STATE_BYTES'],
              'whole_cold_qualified': False, 'whole_runtime_qualified': False,
              'public_owner_state_precondition': 'fixed full-size, disjoint adapter buffers',
              'sources': {}, 'checks': [],
              'observer': {'path': str(Path(__file__).resolve()),
                           'sha256': sha256(Path(__file__).read_bytes()).hexdigest()}}
    seeds = None
    try:
        for name in ('tools/generate_hia_mcp_history_diagnostic.py',
                     'tools/generate_hia_mcp_http_events.py',
                     'tools/hia_mcp_http_syscalls.S', 'tools/hia_mcp_service_syscalls.S',
                     'tools/hia_request_history_debug_ranges.json'):
            report['sources'][name] = sha256((ROOT/name).read_bytes()).hexdigest()
        compiler = gzip.decompress((EVIDENCE/'original-source-build.elf.gz').read_bytes())
        assert sha256(compiler).hexdigest() == COMPILER
        executable = output/'original-source-build'
        executable.write_bytes(compiler)
        executable.chmod(0o500)
        _, holes = template()
        targets = {name: at+4+struct.unpack_from('<i', compiler, at)[0]
                   for name, at in holes.items()}
        backend = compiler[targets['compiler_hole']:targets['packer_hole']]
        assert len(backend) == 641344 and sha256(backend).hexdigest() == BACKEND
        native = NativeHiaJsonImage(backend, BACKEND)
        report.update(compiler_sha256=COMPILER, backend_sha256=BACKEND)
        report['replay_ast'] = prove_replay_ast()

        def compiled(name, raw):
            (output/(name+'.hepta')).write_bytes(raw)
            result = subprocess.run([str(executable), 'compile'], input=raw,
                                    capture_output=True, timeout=10)
            assert result.returncode == 0, (name, result.returncode, result.stderr)
            assert 0 < len(result.stdout) <= 1 << 20
            (output/(name+'.flat')).write_bytes(result.stdout)
            return result.stdout

        # Compile precisely the sources already carried by this checkpoint.
        construction = json.loads((EVIDENCE/'report.json').read_bytes())
        images = {}
        for name, expected in construction['parts'].items():
            raw = (ROOT/'examples/hia_bootstrap'/(name+'.hepta')).read_bytes()
            assert sha256(raw).hexdigest() == expected['source_sha256']
            flat = compiled(name, raw)
            assert sha256(flat).hexdigest() == expected['flat_sha256']
            images[name] = flat
        report['checks'].append({'case': 'all-three-exact-source-build-images', 'passed': True})

        # The inserted call still rejects aliasing exclusive formals in B3.
        raw = (ROOT/'examples/hia_bootstrap/mcp_http_events.hepta').read_text()
        pattern = re.compile(r'(?m)^(.*?call\()([^\n)]*)(\)\s+\{function: "f1"\}.*)$')
        matches = list(pattern.finditer(raw))
        assert len(matches) == 1
        match = matches[0]
        args = match[2].split(',')
        assert len(args) == 4 and args[0].strip() != args[1].strip()
        args[0] = args[1]
        malformed = (raw[:match.start()]+match[1]+','.join(args)+match[3]+raw[match.end():]).encode()
        (output/'exclusive-alias-rejected.hepta').write_bytes(malformed)
        s = ctypes.create_string_buffer(malformed)
        o = ctypes.create_string_buffer(b'\xa5'*(1 << 20), 1 << 20)
        w = ctypes.create_string_buffer(1 << 20)
        status = native._entry(s, len(malformed), o, len(o), w, len(w))
        assert status == 4294967295 and o.raw == b'\xa5'*(1 << 20)
        report['checks'].append({'case': 'exclusive-replay-alias-rejected', 'passed': True,
                                 'status': status, 'native_reason': struct.unpack_from('<Q', w, 40)[0]})
        status = native._entry(s, len(malformed), o, len(o), w, (1 << 20)-1)
        assert status == 4294967294 and o.raw == b'\xa5'*(1 << 20)
        report['checks'].append({'case': 'original-compiler-workspace-bound', 'passed': True,
                                 'status': status, 'output_unchanged': True})

        # The native initializer must recreate all original words, including
        # the wide terminal interval, without touching either adjacent guard.
        table = json.loads(diagnostic.RANGES.read_bytes())['ranges']
        expected_table = b''.join(struct.pack('<Q', low | (high << 21)) for low, high in table)
        size, at = len(expected_table), OWNER_C['SCRATCH']
        assert len(table) == 909 and size == 7272
        harness = f'''def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w) < {at + size} or length(o) < {size}:
        return 4294967295
    if length(s) == 0:
        history_debug_init(w)
        index = 0
        while index < {size}:
            store(o,index,byte(w,{at}+index))
            index = index+1
        return {size}
    if length(s) != 8:
        return 4294967295
    point = 0
    index = 0
    while index < 8:
        point = point | (byte(s,index) << (index*8))
        index = index+1
    return choose(history_debug_escape(w,point),1,0)
'''
        source = render_assembly(document(closure(dispatch_source(), harness), 'diagnostic_table_control')).encode()
        flat = compiled('diagnostic-table-control', source)
        image = NativeHiaJsonImage(flat, sha256(flat).hexdigest())
        arena = mmap.mmap(-1, at+size+16)
        state = (ctypes.c_ubyte * len(arena)).from_buffer(arena)
        arena[at-16:at+size+16] = b'\xa5'*(size+32)
        output_table = ctypes.create_string_buffer(size)
        empty = ctypes.create_string_buffer(1)
        status = image._entry(empty, 0, output_table, size, state, len(arena))
        assert status == size and output_table.raw == expected_table
        assert arena[at:at+size] == expected_table
        assert arena[at-16:at] == b'\xa5'*16 and arena[at+size:at+size+16] == b'\xa5'*16
        (output/'unicode-table.bin').write_bytes(output_table.raw)
        points = {0, 0x10ffff, 0x110000, 0xd800, 0xdfff, NONE}
        for low, high in table:
            points.update(p for p in (low-1, low, low+1, high-1, high, high+1) if p >= 0)
        observations = []
        for point in sorted(points):
            s = ctypes.create_string_buffer(struct.pack('<Q', point), 8)
            status = image._entry(s, 8, output_table, size, state, len(arena))
            expected = int(any(low <= point <= high for low, high in table))
            assert status == expected, (point, status, expected)
            observations.append({'point': point, 'expected': expected, 'actual': status})
        assert arena[at:at+size] == expected_table
        raw_observations = b''.join((json.dumps(row, separators=(',', ':'))+'\n').encode() for row in observations)
        (output/'unicode-boundaries.jsonl.gz').write_bytes(gzip.compress(raw_observations, mtime=0))
        report['unicode'] = {'table_bytes': size, 'table_sha256': sha256(expected_table).hexdigest(),
                             'boundaries': len(observations), 'raw_sha256': sha256(raw_observations).hexdigest(),
                             'surrounding_sentinels_unchanged': True}
        del state
        arena.close()

        # Original seed-produced code is the oracle for every moved phase.
        original = unpack_named(gzip.decompress((EVIDENCE/'original-sources-21.stdin.gz').read_bytes()))['unit-2.hepta']
        assert sha256(original).hexdigest() == 'b162f8c86369c36bb86135694be9f6e00306006e3cb616fb9d7fc66ff00bbbd6'
        seeds = HistorySeeds(ROOT, bootstrap, output/'original-seeds')
        old_flat = seeds.compile(original, 'div-word')
        (output/'original-events.flat').write_bytes(old_flat)
        old_image = NativeHiaJsonImage(old_flat, sha256(old_flat).hexdigest())
        new_image = NativeHiaJsonImage(images['mcp_http_events'], sha256(images['mcp_http_events']).hexdigest())
        state_bytes = OWNER_C['STATE_BYTES']
        maps = [mmap.mmap(-1, state_bytes) for _ in range(2)]
        buffers = [(ctypes.c_ubyte * state_bytes).from_buffer(m) for m in maps]
        plans = [ctypes.create_string_buffer(128) for _ in range(2)]
        compare = ctypes.CDLL(None).memcmp
        compare.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
        compare.restype = ctypes.c_int
        phase_observations = []
        regions = [(0, 65536), (C['H_RECORD'], 1024), (C['H_SESSION'], 1024),
                   (C['H_TASKS'], 8192), (C['H_IO'], 131072),
                   (OWNER_C['SESSION_OUT'], 4096), (OWNER_C['PURE_INPUT'], 4096)]
        for phase in (*PHASES, 199, 205, 223, 228, 300, 400, 403):
            for result in (0, 1, 3, 64, NONE-3, NONE):
                setup = {0: phase, 8: result, C['H_CURRENT']: 1, C['H_S_CURRENT']: 7,
                         C['H_NOW']: 100, C['CR_STATUS']: 1, C['CR_FD']: 20,
                         C['CR_SESSION']: 7, C['CR_STREAM_ID']: NONE, C['CR_FLAGS']: 256,
                         C['CR_REPLY_FD']: 30, C['CR_TASK_GENERATION']: 9,
                         C['SR_CACHE_FD']: 44, C['SR_CACHE_N']: 67, C['SR_GET_CONN']: NONE,
                         C['H_E_STREAM']: 9, C['H_E_PLAIN_N']: 3, C['H_E_GENERATION']: 9,
                         C['H_IO']: int.from_bytes(b'HIAHEV01', 'little'),
                         C['H_IO']+8: 9, C['H_IO']+24: 3}
                for arena, plan in zip(maps, plans, strict=True):
                    for start, count in regions:
                        arena[start:start+count] = bytes(count)
                    for offset, value in setup.items():
                        struct.pack_into('<Q', arena, offset, value)
                    ctypes.memset(plan, 0xa5, 128)
                statuses = [image._entry(empty, 0, plan, 128, state, state_bytes)
                            for image, plan, state in zip((old_image, new_image), plans, buffers, strict=True)]
                assert statuses[0] == statuses[1] and plans[0].raw == plans[1].raw, (phase, result, statuses)
                assert compare(buffers[0], buffers[1], state_bytes) == 0, (phase, result, 'private state differs')
                phase_observations.append({'phase': phase, 'syscall_result': result, 'status': statuses[0],
                                           'plan_hex': plans[0].raw.hex(), 'full_private_state_equal': True})
        phase_raw = b''.join((json.dumps(row, separators=(',', ':'))+'\n').encode() for row in phase_observations)
        (output/'replay-phases.jsonl.gz').write_bytes(gzip.compress(phase_raw, mtime=0))
        report['replay'] = {'cases': len(phase_observations), 'compared_state_bytes_per_case': state_bytes,
                            'original_image_sha256': sha256(old_flat).hexdigest(),
                            'new_image_sha256': sha256(images['mcp_http_events']).hexdigest(),
                            'raw_sha256': sha256(phase_raw).hexdigest(),
                            'setup_reset_regions': regions, 'result_words': [0, 1, 3, 64, NONE-3, NONE]}
        del buffers
        for arena in maps:
            arena.close()
        report['passed'] = True
        return report
    finally:
        if seeds is not None:
            seeds.save()
        (output/'qualification.json').write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('bootstrap', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(qualify(args.bootstrap.resolve(), args.output.resolve())))


if __name__ == '__main__':
    main()
