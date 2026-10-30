#!/usr/bin/env python3
"""Bounded stdlib-only CRC evidence reader. No extraction/import/native execution."""
from __future__ import annotations
import argparse
import base64
from hashlib import sha1, sha256, shake_256
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import tarfile
import time

HEAD = '953fa62dee5aa563551d57b1374ab95b6d548b45'
PROTOCOL_SHA = 'd7fa8f5e580803d4a27b56d66f53b3fb04443527329f01c3a80cb54eb571e99d'
OLD_PROTOCOL_SHA = '19b46aafdccf573cecd19311e7f2767026274bc180b002a4cb119d0a05716038'
FORMAL_SHA = 'fd2ce8e0adbefe160c01ba2fbb79492cf98bbd6b4905f6ab2c9e76bb0e69bbd4'
OUTER_SHA = '7735a856e4c76de25d34da0350db5adb614d9d116e6554f8e661d352d57957a8'
FAILED_SHA = 'de898aa09deb8afe6453af63666740c98af551a0acdcfc33a8bcd23213d22715'
LEGACY_SHA = '88bc95a8466adbb3f83ba46f536248b2637226711382e362a963180877500700'
TIMED_SHA = 'c1c9d095fe5dc1ab61c5946c30c2ab6222f6d6e93d41834e2c887ec6d7cde1e9'
PROFILE = 'hepta.hia.finite-u32-timed-xor-fold-context.v1'
LEGACY_PROFILE = 'hepta.hia.finite-u32-fold-context.v1'
LABELS = ['baseline', 'ieee_guard', 'castagnoli_guard', 'linear_ieee', 'linear_castagnoli', 'linear_dual']
STATIC = {'coalesced_baseline': 'baseline', 'coalesced_ieee_only': 'ieee_guard',
    'coalesced_castagnoli_only': 'castagnoli_guard', 'coalesced_linear_ieee_only': 'linear_ieee',
    'coalesced_linear_castagnoli_only': 'linear_castagnoli', 'coalesced_linear_dual': 'linear_dual'}
ARMS = ['fresh_child_baseline', *STATIC, 'coalesced_poly_dispatch']
POLYS = [0xEDB88320, 0x82F63B78]
IMPLEMENTATION = ['hia_finite_context.py', 'hia_guarded_batch.py', 'hia_program.py', 'hia_program_llvm.py',
    'hia_program_runtime.py', 'hia_translation_validation.py', 'hia_scalar_lowering_check.py',
    'hia_native_differential.py', 'hia_adaptive.py', 'clang_capture.py', 'elf_shared_abi.py']
MAX_ARCHIVE, MAX_MANIFEST, MAX_TAR = 64 << 20, 8 << 20, 128 << 20
MAX_MEMBER, MAX_MEMBERS, MAX_XZ_MEMORY = 8 << 20, 4096, 64 << 20


def need(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, minimum=0):
    return type(value) is int and value >= minimum


def regular_bytes(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= limit, 'bounded regular input required')
        with os.fdopen(fd, 'rb', closefd=False) as f:
            raw = f.read(limit + 1)
        need(len(raw) == info.st_size and len(raw) <= limit, 'input changed size or exceeded bound')
        return raw
    finally:
        os.close(fd)


def pairs(values):
    out = {}
    for key, value in values:
        need(key not in out, 'duplicate JSON key')
        out[key] = value
    return out


def loads(raw):
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON number')))


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')


def digest(raw):
    return sha256(raw).hexdigest()


def git_id(kind, raw):
    return sha1(kind.encode() + b' ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()


def name_ok(name):
    path = PurePosixPath(name)
    return (type(name) is str and name == path.as_posix() and not path.is_absolute()
            and '..' not in path.parts and '.' not in path.parts and name != '.')


def read_archive(archive, manifest_raw):
    manifest = loads(manifest_raw)
    need(manifest['schema'] == 'hepta.hia.crc-linear.evidence-manifest.v1', 'manifest schema')
    need(manifest['frozen_source_head'] == HEAD, 'wrong frozen head')
    inventory = manifest['members']
    need(type(inventory) is dict and len(inventory) <= MAX_MEMBERS, 'manifest member bound')
    need(len(inventory) == manifest['member_count'], 'manifest member denominator')
    need(all(name_ok(name) and integer(row['bytes']) and row['bytes'] <= MAX_MEMBER
             and re.fullmatch('[0-9a-f]{64}', row['sha256']) for name, row in inventory.items()), 'invalid manifest member')
    dec = lzma.LZMADecompressor(memlimit=MAX_XZ_MEMORY)
    expanded = dec.decompress(archive, max_length=MAX_TAR + 1)
    need(len(expanded) <= MAX_TAR and dec.eof and not dec.unused_data, 'XZ output/trailing bound')
    members = {}
    with tarfile.open(fileobj=io.BytesIO(expanded), mode='r:') as tar:
        for item in tar:
            need(len(members) < MAX_MEMBERS and item.isreg() and not item.linkname and not item.pax_headers
                 and name_ok(item.name) and item.name not in members, 'archive type/name/duplicate/member bound')
            need(item.name in inventory and item.size == inventory[item.name]['bytes']
                 and 0 <= item.size <= MAX_MEMBER, 'archive size/inventory mismatch')
            stream = tar.extractfile(item)
            need(stream is not None, 'missing regular member stream')
            raw = stream.read(MAX_MEMBER + 1)
            need(len(raw) == item.size and digest(raw) == inventory[item.name]['sha256'], 'member identity mismatch')
            members[item.name] = raw
        need(not any(expanded[tar.offset:]), 'nonzero data after final tar member')
    need(set(members) == set(inventory), 'missing or extra members')
    need(sum(map(len, members.values())) == manifest['payload_bytes'], 'expanded payload denominator')
    need(all(value is False for value in manifest['claims'].values()), 'unjustified archive claim')
    return manifest, members, len(expanded)


def parse_tree(raw):
    offset, entries = 0, {}
    while offset < len(raw):
        space = raw.find(b' ', offset)
        end = raw.find(b'\0', space + 1)
        need(offset < space < end and end + 21 <= len(raw), 'truncated Git tree')
        mode, name = raw[offset:space].decode('ascii'), raw[space + 1:end].decode('utf-8')
        need(name and '/' not in name and name not in ('.', '..') and name not in entries, 'invalid Git tree entry')
        entries[name] = mode, raw[end + 1:end + 21].hex()
        offset = end + 21
    return entries


def source_check(manifest, members):
    trees = {}
    for name, raw in members.items():
        if name.startswith('git/trees/'):
            oid = name.removeprefix('git/trees/').removesuffix('.raw')
            need(git_id('tree', raw) == oid, 'Git tree payload hash')
            trees[oid] = parse_tree(raw)
    count = 0
    for stage, source in manifest['sources'].items():
        head = source['head']
        raw = members['git/commits/' + head + '.raw']
        need(git_id('commit', raw) == head and raw.splitlines()[0] == ('tree ' + source['tree']).encode(), 'commit/root tree identity')
        report = loads(members[source['report']])
        need(report['source_before'] == report['source_after'] and report['tools_before'] == report['tools_after'], 'source/tool drift')
        need(report['source_before']['head'] == head and report['source_before']['tree'] == source['tree']
             and report['source_before']['files'] == source['files'], 'source report binding')
        for path, expected in source['files'].items():
            need(name_ok(path), 'source path')
            components, tree = PurePosixPath(path).parts, source['tree']
            for part in components[:-1]:
                mode, tree = trees[tree][part]
                need(mode in ('40000', '040000'), 'source ancestor is not a Git tree')
            mode, oid = trees[tree][components[-1]]
            raw = members['source/' + head + '/' + path]
            need(mode in ('100644', '100755') and git_id('blob', raw) == oid and digest(raw) == expected, 'source blob identity')
            count += 1
    return {'snapshots': len(manifest['sources']), 'source_bindings': count, 'Git_trees': len(trees)}


def crc(state, polynomial):
    need(integer(state) and state < 1 << 32 and integer(polynomial) and polynomial < 1 << 32, 'CRC u32 arguments')
    for _ in range(8):
        if state & 1:
            state = (state >> 1) ^ polynomial
        else:
            state >>= 1
    return state


def fold(request):
    need(request['mode'] in ('xor_fold', 'timed_xor_fold'), 'unsupported audited fold mode')
    state, checksum = request['seed'], 0
    need(integer(state) and state < 1 << 32, 'fold seed')
    for byte in request['values']:
        need(integer(byte) and byte <= 255, 'fold byte')
        state = crc(state ^ byte, request['parameter'])
        checksum = (checksum * 1099511628211 + state) & ((1 << 64) - 1)
    return ['returned', state, checksum]


def original_controls(report, prefix, members):
    d = report['original_c_differential']
    expected_cases = [[state, byte, polynomial] for state in (0, 0x81234567, 0xFFFFFFFF)
                      for byte in (0, 1, 127, 255) for polynomial in (*POLYS, 0, 0x12345678)]
    need(d['cases'] == expected_cases and d['cases_executed'] == 48 and d['ok'] is True, 'original C case inventory')
    values = [crc(state ^ byte, poly) for state, byte, poly in expected_cases]
    need(d['expected'] == values and d['native'] == values and d['vm'] == values, 'original C/VM/math relation')
    commands = report['original_c_commands']
    need(len(commands) == 2 and all(row['returncode'] == 0 and row['stderr'] == '' and integer(row['wall_ns'], 1) for row in commands), 'original C raw commands')
    need(commands[1]['stdout'] == ''.join(str(value) + '\n' for value in values), 'original native stdout mismatch')
    need(members[prefix + '/original-c/cases.stdin.txt'] == ''.join(' '.join(map(str, case)) + '\n' for case in expected_cases).encode(), 'original native stdin mismatch')
    executable = members[prefix + '/original-c/original-crc']
    need(digest(executable) == d['executable']['sha256'] and len(executable) == d['executable']['bytes'], 'original native executable identity')
    return 48


def elf_symbol(image):
    need(len(image) >= 64 and image[:6] == b'\x7fELF\x02\x01', 'ELF64 little-endian image required')
    need(struct.unpack_from('<H', image, 18)[0] == 62, 'ELF x86-64 machine required')
    offset = struct.unpack_from('<Q', image, 40)[0]
    size, number = struct.unpack_from('<HH', image, 58)
    need(size == 64 and 0 < number <= 4096 and offset + size * number <= len(image), 'ELF section table bound')
    sections = [struct.unpack_from('<IIQQQQIIQQ', image, offset + index * size) for index in range(number)]
    found = []
    for section in sections:
        if section[1] != 11:
            continue
        need(section[6] < number and section[9] == 24 and section[5] % 24 == 0, 'ELF dynamic symbol table')
        strings = sections[section[6]]
        need(strings[4] + strings[5] <= len(image) and section[4] + section[5] <= len(image), 'ELF symbol/string bounds')
        names = image[strings[4]:strings[4] + strings[5]]
        for index in range(section[5] // 24):
            name, info, _other, shndx, value, count = struct.unpack_from('<IBBHQQ', image, section[4] + index * 24)
            need(name < len(names), 'ELF symbol name bound')
            end = names.find(b'\0', name)
            need(end >= 0, 'ELF symbol terminator')
            if names[name:end] != b'calculate':
                continue
            need(info & 15 == 2 and 0 < shndx < number and count > 0, 'calculate function definition')
            body = sections[shndx]
            begin = body[4] + value - body[3]
            need(body[3] <= value and begin >= body[4] and begin + count <= body[4] + body[5]
                 and begin + count <= len(image), 'ELF function bytes bound')
            found.append(image[begin:begin + count])
    need(len(found) == 1, 'unique dynamic calculate symbol required')
    return found[0]


def bank_check(report, prefix, head, members, failed=False):
    bank, baseline = report['bank'], report['bank']['baseline_sha256']
    need(bank['labels'] == LABELS and set(bank['candidates']) == set(LABELS), 'complete six candidate pool')
    need(bank['serialized_receipts_authorize_execution'] is False and bank['machine_code_semantics_proved'] is False
         and bank['global_optimality_proved'] is False and bank['economic_benefit_proved'] is False, 'bank claim boundary')
    need(digest(wire(loads(members[prefix + '/baseline.hia.json']))) == baseline, 'baseline Core identity')
    bridge = report['source_bridge']
    need(bridge['status'] == 'proved' and bridge['max_backedges'] == 8 and bridge['kernel_sha256'] == baseline,
         'original captured Core bridge')
    need(bridge['before_sha256'] == digest(members[prefix + '/captured.hia.json']), 'captured Core bytes')
    need(bridge['claims']['first_trap_code_preserved'] is True
         and bridge['claims']['frontend_refinement_proved'] is False, 'bridge scope')
    # The corpus identity below is independently pinned; the aggregate native
    # receipt has no per-case native stdout and is not presented as raw replay.
    corpus_sha = '3114c2498703609b92ceea20ded16bf2112aafa3134e2f10f7bdfa84bd9f3a89'
    native_count = 0
    artifacts = {}
    for label in LABELS:
        row = bank['candidates'][label]
        raw_core = members[prefix + '/' + label + '.hia.json']
        core = loads(raw_core)
        operations = sum(len(block['ops']) for fn in core['functions'] for block in fn['blocks'])
        if failed and label == 'linear_dual':
            need(operations == 148 and 'native_differential' not in row and 'compilation' not in row,
                 'initial 148-op failure must remain unexecuted')
            continue
        need(row['status'] == 'proved_compiled_and_finitely_compared' and row['core_sha256'] == digest(wire(core)), 'candidate Core/preparation status')
        need(operations <= 128 and integer(row['preparation_wall_ns'], 1), 'unchanged selected LLVM op bound/preparation cost')
        translation, lowering, compilation, native = (row[k] for k in ('translation', 'lowering', 'compilation', 'native_differential'))
        need(translation['status'] == 'proved' and translation['before_sha256'] == baseline
             and translation['after_sha256'] == row['core_sha256']
             and translation['claims']['first_trap_code_preserved'] is True, 'candidate first-trap TV binding')
        llvm = members[prefix + '/bank/' + label + '.ll']
        need(lowering['status'] == 'verified' and lowering['verified'] is True
             and lowering['core_sha256'] == row['core_sha256'] and lowering['llvm_sha256'] == digest(llvm)
             and digest(lowering['smtlib'].encode()) == lowering['query_sha256'], 'LLVM checker receipt identity')
        image = members[prefix + '/bank/' + label + '.so']
        need(compilation['ok'] is True and compilation['artifact_sha256'] == digest(image)
             and compilation['artifact_bytes'] == len(image) and compilation['llvm_ir_sha256'] == digest(llvm), 'compiled artifact identity')
        code = elf_symbol(image)
        need(code.hex() == row['code']['hex'] and digest(code) == row['code']['sha256']
             and len(code) == row['code']['bytes'], 'actual ELF exported body differs')
        need(native['status'] == 'finite_native_observations_match_oracle_not_proved'
             and native['cases_executed'] == 64 and native['cases_sha256'] == corpus_sha
             and native['artifact_sha256'] == digest(image)
             and native['executable_hia_program_sha256'] == row['core_sha256'], 'native preparation aggregate receipt')
        native_count += 64
        artifacts[label] = digest(image)
    if failed:
        need(bank['status'] == 'preparation-failed' and bank['release']['complete'] is True
             and native_count == 320, 'failed preparation cost/count/release')
        return native_count
    need(native_count == 384 and bank['status'] == 'prepared' and report['release']['complete'] is True, 'complete native bank/release')
    driver = bank['driver']
    need(driver['returncode'] == 0 and driver['stderr'] == '' and digest(members[prefix + '/bank/context_driver']) == driver['sha256']
         and digest(members[prefix + '/bank/context_driver.c']) == driver['source_sha256'], 'driver actual bytes/command')
    implementation = digest(wire({name: digest(members['source/' + head + '/hepta/' + name]) for name in IMPLEMENTATION}))
    expected_bank = {'profile': bank['profile'], 'root': baseline, 'images': [[label, artifacts[label]] for label in LABELS],
                     'driver': driver['sha256'], 'implementation': implementation, 'oracle_reference_reuse': True}
    need(digest(wire(expected_bank)) == bank['bank_sha256'], 'bank authority namespace identity')
    return native_count


def native_context(plan, native, bank, mode):
    requests = plan['requests']
    need(1 <= len(requests) <= 256 and sum(len(x['values']) for x in requests) <= 65536, 'native request bounds')
    profile = PROFILE if mode == 3 else LEGACY_PROFILE
    images = sorted({LABELS.index(r['candidate']) for r in requests})
    normalized = [[r['id'], images.index(LABELS.index(r['candidate'])), mode, r['seed'], r['parameter'], r['values']] for r in requests]
    expected = [fold(request) for request in requests]
    need(plan['expected'] == expected, 'plan independent CRC/checksum differs')
    if 'images' in plan:
        need(plan['images'] == images, 'plan selected image inventory')
    trace = digest(wire({'profile': profile, 'bank': bank['bank_sha256'], 'images': images,
                         'requests': normalized, 'expected': expected}))
    need(plan['trace_sha256'] == trace and native['trace_sha256'] == trace and native['bank_sha256'] == bank['bank_sha256'], 'trace exact binding')
    need(native['profile'] == profile and native['status'] == 'completed' and native['returncode'] == 0
         and native['owned_child_cleanup'] == 'confirmed_by_bounded_capture'
         and native['replay_permitted'] is False and native['prefix']['complete'] is True, 'native terminal status')
    raw = base64.b64decode(native['raw_stdout_base64'], validate=True)
    need(len(raw) <= 128 << 10 and base64.b64decode(native['raw_stderr_base64'], validate=True) == b'', 'native raw output bounds/stderr')
    rows = [loads(line) for line in raw.splitlines()]
    need(raw == b''.join(wire(row) + b'\n' for row in rows) and rows == native['prefix']['events'], 'canonical raw native event sequence')
    wanted = [{'as_bytes': 268435456, 'core_bytes': 0, 'cpu_seconds': 3, 'fsize_bytes': 131072, 'kind': 'limits', 'trace': trace}]
    for image in range(len(images)):
        wanted += [{'image': image, 'kind': event, 'trace': trace} for event in ('opened', 'ready')]
    completed, timers = [], []
    for seq, (request, normal, outcome) in enumerate(zip(requests, normalized, expected)):
        wanted.append({'candidate': normal[1], 'id': request['id'], 'kind': 'start', 'seq': seq, 'trace': trace})
        row = {'calls': len(request['values']), 'candidate': normal[1], 'checksum': outcome[2], 'id': request['id'],
               'kind': 'result', 'mode': mode, 'parameter': request['parameter'], 'seed': request['seed'],
               'seq': seq, 'state': outcome[1], 'trace': trace}
        if mode == 3:
            timer = rows[len(wanted)].get('kernel_ns')
            need(integer(timer, 1), 'unknown/nonpositive fold-loop timer')
            row['kernel_ns'] = timer
            timers.append(timer)
        wanted.append(row)
        completed.append(row)
    for image in reversed(range(len(images))):
        wanted.append({'image': image, 'kind': 'closed', 'ok': True, 'trace': trace})
    wanted.append({'acquired': len(images), 'closed': len(images), 'kind': 'finish', 'ok': True, 'trace': trace})
    need(rows == wanted and completed == native['prefix']['completed_requests'], 'raw native limits/load/start/result/close sequence')
    need(integer(native['outer_wall_ns'], 1) and sum(timers) <= native['outer_wall_ns'], 'nested timer boundary')
    inventory = [{'slot': slot, 'bank_index': index, 'candidate': LABELS[index],
                  'artifact_sha256': bank['candidates'][LABELS[index]]['compilation']['artifact_sha256']}
                 for slot, index in enumerate(images)]
    need(native['planned_load_inventory'] == inventory and native['loaded_inventory'] == inventory
         and native['ready_inventory'] == inventory, 'actual image identities/load inventory')
    return {'requests': len(requests), 'calls': sum(len(r['values']) for r in requests),
            'kernel_ns': sum(timers), 'outer_wall_ns': native['outer_wall_ns'],
            'labels': {r['candidate'] for r in requests}}


def ledger_check(report, formal=False):
    ledger = report['ledger']
    need(type(ledger) is list and 0 < len(ledger) <= 128, 'bounded timing ledger')
    labels = [row['label'] for row in ledger]
    need(len(labels) == len(set(labels)), 'duplicate cost label')
    for row in ledger:
        need(row['status'] in ('completed', 'failed') and integer(row['wall_ns'])
             and integer(row['parent_cpu_ns']) and integer(row['child_cpu_ns']), 'unfinished/unknown cost row')
    if formal:
        required = {'source.before', 'tools.before', 'source.capture-and-bridge', 'proposal.generate', 'bank.prepare',
            'code.inspect', 'data.prepare', 'reference.prime', 'bank.close', 'source.after', 'tools.after', 'protocol.after', 'analysis'}
        need(set(labels) == required | {f'sample.{index:03d}' for index in range(96)} and len(ledger) == 109
             and all(row['status'] == 'completed' for row in ledger), 'formal complete cost-label inventory')
        closed = [row for row in ledger if row['label'] != 'analysis']
        need(digest(wire(closed)) == report['closed_pre_analysis_ledger_sha256'], 'closed pre-analysis ledger snapshot')


def stage_qualifications(manifest, members):
    result, controls, preparation, requests, calls = {}, 0, 0, 0, 0
    pins = {'failed': FAILED_SHA, 'legacy': LEGACY_SHA, 'timed': TIMED_SHA}
    for stage, pin in pins.items():
        source = manifest['sources'][stage]
        raw = members[source['report']]
        need(digest(raw) == pin, 'historical qualification changed')
        report = loads(raw)
        prefix = source['report'].rsplit('/', 1)[0]
        controls += original_controls(report, prefix, members)
        preparation += bank_check(report, prefix, source['head'], members, failed=(stage == 'failed'))
        ledger_check(report)
        need(integer(report['wall_ns'], 1), 'qualification complete wall cost')
        if stage == 'failed':
            need(report['qualified'] is False and report['status'] == 'failed' and report['errors']
                 and any(row['type'] == 'ScalarLoweringRejected' for row in report['errors'])
                 and prefix + '/NATIVE.json' not in members, 'real failed initial qualification relabelled')
        else:
            need(report['qualified'] is True and report['status'] == 'completed' and report['errors'] == [], 'qualification completion')
            plan = loads(members[prefix + '/PLAN.json'])
            native = loads(members[prefix + '/NATIVE.json'])
            need(report['native'] == native and len(plan['requests']) == 18, 'qualification raw/report identity')
            mode = 1 if stage == 'legacy' else 3
            expected_plan = [{'id': index * 3 + p, 'candidate': label,
                'mode': 'xor_fold' if mode == 1 else 'timed_xor_fold', 'parameter': poly,
                'seed': 0xFFFFFFFF, 'values': list(b'123456789')} for index, label in enumerate(LABELS)
                for p, poly in enumerate((*POLYS, 0x12345678))]
            need(plan['requests'] == expected_plan, 'qualification all candidate/poly/fallback calls')
            observed = native_context(plan, native, report['bank'], mode)
            need(observed['requests'] == 18 and observed['calls'] == 162, 'qualification native denominator')
            requests += observed['requests']; calls += observed['calls']
        result[stage] = {'qualified': report['qualified'], 'wall_ns': report['wall_ns'], 'result_sha256': pin}
    return {'stages': result, 'original_C_controls': controls, 'aggregate_preparation_cases': preparation,
            'raw_native_requests_recomputed': requests, 'raw_native_calls_recomputed': calls}


def expected_schedule(protocol):
    rows = []
    for phase in ('training', 'validation'):
        for trial in range(2):
            workloads = protocol['workloads'][trial % 3:] + protocol['workloads'][:trial % 3]
            for workload in workloads:
                start = (trial + protocol['workloads'].index(workload)) % 8
                arms = ARMS[start:] + ARMS[:start]
                if trial % 2:
                    arms = list(reversed(arms))
                rows.extend((phase, trial, workload, arm) for arm in arms)
    return rows


def formal_check(manifest, members):
    prefix = 'raw/formal/run'
    need(digest(members[prefix + '/RESULT.json']) == FORMAL_SHA
         and digest(members['raw/formal/OUTER_ECONOMICS.json']) == OUTER_SHA, 'formal immutable results')
    report = loads(members[prefix + '/RESULT.json'])
    outer = loads(members['raw/formal/OUTER_ECONOMICS.json'])
    execution = loads(members['raw/formal/EXECUTION.json'])
    p = loads(members[prefix + '/FROZEN_PROTOCOL.json'])
    need(digest(members[prefix + '/FROZEN_PROTOCOL.json']) == PROTOCOL_SHA
         and report['protocol_sha256'] == PROTOCOL_SHA and report['protocol'] == p == report['protocol_after'], 'frozen protocol binding')
    need(p['arms'] == ARMS and p['static_targets'] == STATIC and p['labels'] == LABELS
         and p['execution_profile']['profile'] == PROFILE and p['max_study_wall_ns'] == 300000000000,
         'full strong fixed pool/profile/budget')
    need(report['qualified'] is True and report['status'] == 'completed' and report['errors'] == []
         and report['release']['complete'] is True and outer['audit_passed'] is True
         and outer['original_inner_result_rewritten'] is False, 'formal execution/outer audit incomplete')
    need(execution['returncode'] == 0 and execution['timeout'] is False
         and execution['source_before'] == execution['source_after']
         and execution['source_before']['head'] == HEAD and execution['source_before']['status'] == '', 'outer source/process identity')
    need(execution['protocol_sha256'] == PROTOCOL_SHA and execution['one_attempt_no_retry'] is True
         and execution['performance_timing_qualified'] is False, 'outer protocol/claim')
    need(outer['execution_receipt_sha256'] == digest(members['raw/formal/EXECUTION.json'])
         and outer['result_sha256'] == FORMAL_SHA, 'outer receipt exact bindings')
    ledger_check(report, formal=True)
    controls = original_controls(report, prefix, members)
    preparation = bank_check(report, prefix, HEAD, members)
    need(report['bank']['profile'] == PROFILE and report['bank']['timed_xor_fold']['enabled'] is True, 'timed explicit admission')
    need(len(report['reference_priming']) == 4 and all(row['wire_mode'] == 3
         and row['cancellation']['execution_attempted'] is False for row in report['reference_priming']), 'same timed oracle priming/no native warmup')
    before, after = report['reference_state_after_priming'], report['reference_state_before_close']
    need(before['entries'] == before['misses'] == after['entries'] == after['misses'] == 64
         and before['capacity_bypasses'] == after['capacity_bypasses'] == 0
         and before['failed_computations'] == after['failed_computations'] == 0, 'shared bounded reference rule')
    data = {}
    chunks = []
    for phase in ('training', 'validation'):
        spec = p['data'][phase]
        value = shake_256(p['data']['domain'].encode('ascii') + b'\0' + phase.encode() + b'\0'
                          + spec['seed'].to_bytes(8, 'big')).digest(spec['bytes'])
        need(len(value) == 4096 and members[prefix + '/' + phase + '.bin'] == value, 'frozen SHAKE input stream')
        data[phase] = value
        chunks += [value[index:index + 256] for index in range(0, len(value), 256)]
    need(len(set(chunks)) == 32 and all(any(block) for block in chunks), 'input block diversity')
    schedule = expected_schedule(p)
    need(len(report['samples']) == len(schedule) == 96, 'formal observation denominator')
    totals = {'requests': 0, 'calls': 0, 'contexts': 0, 'kernel_ns': 0}
    for index, (sample, key) in enumerate(zip(report['samples'], schedule)):
        need(tuple(sample[field] for field in ('phase', 'trial', 'workload', 'arm')) == key
             and sample['status'] == 'completed' and not sample.get('unknown_native_measurements')
             and not sample.get('native_persistence_errors'), 'sample order/status/unknown cost')
        root = prefix + f'/samples/{index:03d}'
        need(loads(members[root + '/OBSERVATION.json']) == sample, 'raw observation/result mismatch')
        phase, trial, workload, arm = key
        plan = []
        for seq in range(16):
            poly = POLYS[0 if workload == 'ieee' else 1 if workload == 'castagnoli' else seq % 2]
            label = ('baseline' if arm == 'fresh_child_baseline' else STATIC[arm] if arm in STATIC
                     else 'linear_ieee' if poly == POLYS[0] else 'linear_castagnoli')
            plan.append({'id': seq, 'candidate': label, 'mode': 'timed_xor_fold', 'parameter': poly,
                         'seed': 0xFFFFFFFF, 'values': list(data[phase][seq * 256:(seq + 1) * 256])})
        need(loads(members[root + '/PLAN.json']) == plan, 'public arm input/candidate plan')
        groups = [[request] for request in plan] if arm == 'fresh_child_baseline' else [plan]
        need(len(sample['contexts']) == len(groups), 'context arm denominator')
        acquired = {'requests': 0, 'calls': 0, 'kernel_ns': 0, 'outer_wall_ns': 0}
        labels = set()
        for context, (refs, requests) in enumerate(zip(sample['contexts'], groups)):
            need(refs == {'native': f'{context:02d}.native.json', 'plan': f'{context:02d}.plan.json'}, 'context raw refs')
            plan_record = loads(members[root + '/' + refs['plan']])
            need(plan_record['requests'] == requests, 'per-context request binding')
            native = loads(members[root + '/' + refs['native']])
            observed = native_context(plan_record, native, report['bank'], 3)
            for field in acquired:
                acquired[field] += observed[field]
            labels.update(observed['labels'])
        need(acquired['requests'] == sample['completed_requests'] == 16 and acquired['calls'] == sample['calls'] == 4096
             and acquired['kernel_ns'] == sample['kernel_ns'] and acquired['outer_wall_ns'] == sample['native_outer_wall_ns']
             and sorted(labels) == sample['loaded_candidates'], 'raw/sample work and cost sums')
        need(integer(sample['arm_host_wall_ns'], 1) and sample['arm_host_wall_ns'] >= sample['native_outer_wall_ns'] >= sample['kernel_ns'], 'nested complete timing')
        totals['requests'] += acquired['requests']; totals['calls'] += acquired['calls']
        totals['kernel_ns'] += acquired['kernel_ns']; totals['contexts'] += len(groups)
    need((totals['requests'], totals['calls'], totals['contexts']) == (1536, 393216, 276), 'whole actual work denominator')
    need(report['actual_counts'] == {'original_C_reference_cases': controls, 'native_preparation_differential_cases': preparation,
        'delivered_requests': 1536, 'delivered_kernel_calls': 393216, 'native_contexts': 276, 'ndu_decisions': 0}, 'formal reported count mismatch')
    cost = economics(report, outer['outer_economics'], execution['outer_wall_ns'], p)
    return {'observations': 96, 'actual_requests_recomputed': 1536, 'actual_calls_recomputed': 393216,
            'actual_contexts_recomputed': 276, 'all_raw_fold_loop_ns': totals['kernel_ns'],
            'original_C_controls': controls, 'aggregate_preparation_cases': preparation, 'NDU_decisions': 0, **cost}


def economics(report, outer, whole, p):
    samples = report['samples']
    total = sum(row['arm_host_wall_ns'] for row in samples)
    need(integer(whole, 1) and total <= whole <= 300000000000, 'actual outer wall budget')
    prep = {name: report['bank']['candidates'][name]['preparation_wall_ns'] for name in LABELS}
    extra = sum(prep[name] for name in LABELS[3:])
    need(outer['delivered_host_sum_ns'] == total and outer['charged_whole_wall_ns'] == whole
         and outer['shared_non_delivery_charge_ns'] == whole - total
         and outer['image_preparation_ns'] == prep and outer['additional_three_image_preparation_component_ns'] == extra,
         'whole non-overlapping cost arithmetic')
    exports = {name: report['bank']['candidates'][name]['code']['sha256'] for name in LABELS}
    differs = all(exports[name] not in {exports[old] for old in LABELS[:3]} for name in LABELS[3:])
    need(outer['new_exports_differ_from_every_legacy'] == differs, 'actual new code identity distinction')
    need(len(outer['groups']) == 6, 'six economic groups required')
    contrasts, dispatches = [], []
    for group, key in zip(outer['groups'], [(phase, work) for phase in ('training', 'validation') for work in p['workloads']]):
        need((group['phase'], group['workload']) == key, 'economic group order')
        subset = [row for row in samples if (row['phase'], row['workload']) == key]
        env = {arm: {metric: {'min': min(row[metric] for row in subset if row['arm'] == arm),
            'max': max(row[metric] for row in subset if row['arm'] == arm)}
            for metric in ('kernel_ns', 'native_outer_wall_ns', 'arm_host_wall_ns')} for arm in ARMS}
        need(group['envelopes'] == env, 'all raw repeats, no exclusions')
        old_kernel = min(env[arm]['kernel_ns']['min'] for arm in list(STATIC)[:3])
        old_host = min(env[arm]['arm_host_wall_ns']['min'] for arm in list(STATIC)[:3])
        strong_host = min(env[arm]['arm_host_wall_ns']['min'] for arm in STATIC)
        dispatch = strong_host - env['coalesced_poly_dispatch']['arm_host_wall_ns']['max']
        need(group['dispatch_host_increment_over_all_six_fixed_ns'] == dispatch
             and group['cold_dispatch_net_over_all_six_fixed_ns'] == dispatch - (whole - total), 'strong fixed dispatch charge')
        need(group['batching_host_increment_ns'] == env['fresh_child_baseline']['arm_host_wall_ns']['min']
             - env['coalesced_baseline']['arm_host_wall_ns']['max'], 'shared batching control')
        dispatches.append(dispatch)
        for arm, name in list(STATIC.items())[3:]:
            value = group['new_candidate_contrasts'][name]
            saving = old_kernel - env[arm]['kernel_ns']['max']
            host = old_host - env[arm]['arm_host_wall_ns']['max']
            need(value['kernel_saving_vs_fastest_legacy_ns'] == saving
                 and value['kernel_saving_ns_per_call'] == saving / 4096
                 and value['full_host_saving_vs_fastest_legacy_ns'] == host
                 and value['cold_candidate_net_vs_fastest_legacy_ns'] == host - (whole - total), 'candidate full negative/positive contrast')
            need(value['image_preparation_delta_over_each_legacy_ns'] == {old: prep[name] - prep[old] for old in LABELS[:3]}, 'per-image observed preparation delta')
            for field, charge in (('conditional_break_even_calls_full_charge', whole - total),
                                  ('conditional_break_even_calls_additional_three_image_component', extra)):
                need(value[field] == ((charge * 4096 + saving - 1) // saving if saving > 0 else None), 'conditional break-even arithmetic')
            contrasts.append(host)
    need(len(contrasts) == 18 and len(dispatches) == 6 and all(value < 0 for value in contrasts + dispatches), 'all retained 18+6 host negatives')
    need(outer['complete_cost_cold_gate_passed'] is False and outer['inner_cold_gate_passed'] is False
         and outer['NDU_incremental_value_established'] is False and outer['break_even_is_observed_profit'] is False
         and outer['production_demand_established'] is False and outer['envelopes_are_statistical_confidence_intervals'] is False,
         'economic claim boundary')
    # Inner and actual outer costs are nested. Recheck the independent charge
    # revision without adding either interval twice.
    inner = report['economics']
    need(inner['charged_whole_wall_ns'] == report['wall_through_first_result_write_ns']
         and report['wall_ns'] <= report['wall_through_first_result_write_ns'] <= whole
         and inner['shared_non_delivery_charge_ns'] == inner['charged_whole_wall_ns'] - total
         and inner['complete_cost_cold_gate_passed'] is False, 'inner/final-write cost boundary')
    need(inner['image_preparation_ns'] == prep and inner['delivered_host_sum_ns'] == total, 'inner common accounting')
    for old, new in zip(inner['groups'], outer['groups']):
        need(old['envelopes'] == new['envelopes'], 'inner observations changed by outer charge')
        need(old['cold_dispatch_net_over_all_six_fixed_ns'] == old['dispatch_host_increment_over_all_six_fixed_ns']
             - inner['shared_non_delivery_charge_ns'], 'inner dispatch charge')
    return {'outer_wall_ns': whole, 'arm_host_sum_ns': total, 'shared_non_delivery_ns': whole - total,
            'negative_candidate_host_contrasts': len(contrasts), 'negative_dispatch_host_contrasts': len(dispatches),
            'complete_cost_cold_gate_passed': False, 'future_profit_or_NDU_value_established': False}


def historical_development(members):
    root = 'raw/development/'
    need(loads(members[root + '04-shared-body-tests.json'])['returncode'] != 0
         and loads(members[root + '05-shared-body-tests.json'])['returncode'] != 0, 'developer failures were omitted/relabelled')
    need(loads(members[root + '03-native-qualification.json'])['returncode'] != 0
         and loads(members[root + '07-native-qualification.json'])['returncode'] == 0
         and loads(members[root + '12-timed-native-qualification.json'])['returncode'] == 0, 'qualification outer status history')
    final_tests = members[root + '11-timed-fold-final-tests.stderr'].decode()
    need(re.search(r'Ran 90 tests in [0-9.]+s\n\nOK\n', final_tests)
         and '... skipped' not in final_tests and loads(members[root + '11-timed-fold-final-tests.json'])['returncode'] == 0,
         'actual focused ninety/no-skip footer')
    failed_plan = loads(members[root + 'FINAL_PLAN_3533b95c.json'])
    supersession = loads(members[root + 'PRE_EXECUTION_CONTRACT_REPAIR_1873755.json'])
    need(failed_plan['economic_execution_started'] is False and supersession['economic_execution_started'] is False
         and supersession['old_intended_output_exists'] is False, 'pre-execution timer defect falsely became a run')
    old = members['source/' + HEAD + '/experiments/hia_crc_linear_20261030/PRE_TIMING_PROTOCOL.json']
    need(digest(old) == OLD_PROTOCOL_SHA, 'old protocol bytes lost')
    receipts = [loads(raw) for name, raw in members.items()
                if re.fullmatch(r'raw/development/[0-9]{2}[^/]+\.json', name) and not name.endswith('.plan.json')]
    costs = []
    for receipt in receipts:
        cost = receipt.get('wall_ns', receipt.get('outer_launcher_wall_ns'))
        need(integer(cost, 1), 'developer execution cost unknown/missing')
        costs.append(cost)
    return {'retained_development_execution_receipts': len(costs),
            'sum_outer_development_receipt_wall_ns': sum(costs),
            'scope': 'Includes the formal launcher once; nested stage/inner receipts must not be added again. Human and all historical acquisition costs unknown.',
            'original_3533_economic_executions': 0, 'old_initial_candidate_failure_preserved': True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--archive-sha256', required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    start = time.monotonic_ns()
    result = {'schema': 'hepta.hia.crc-linear.offline-verification.v1', 'passed': False,
              'native_model_or_payload_execution': False, 'extraction_performed': False,
              'proof_solver_reexecuted': False, 'source': HEAD}
    try:
        archive = regular_bytes(args.archive, MAX_ARCHIVE)
        manifest_raw = regular_bytes(args.manifest, MAX_MANIFEST)
        need(digest(archive) == args.archive_sha256 and digest(manifest_raw) == args.manifest_sha256,
             'external archive/manifest SHA does not match the same bounded bytes')
        result.update(archive_sha256=digest(archive), manifest_sha256=digest(manifest_raw), archive_bytes=len(archive))
        manifest, members, expanded = read_archive(archive, manifest_raw)
        result.update(member_count=len(members), payload_bytes=sum(map(len, members.values())), expanded_tar_bytes=expanded)
        result['sources'] = source_check(manifest, members)
        result['qualification_history'] = stage_qualifications(manifest, members)
        result['formal'] = formal_check(manifest, members)
        result['development'] = historical_development(members)
        result['passed'] = True
    except BaseException as error:
        result['error'] = {'type': type(error).__name__, 'message': str(error)}
    result['wall_ns'] = time.monotonic_ns() - start
    with args.output.open('x') as target:
        json.dump(result, target, sort_keys=True, indent=2, allow_nan=False)
        target.write('\n')
    print(json.dumps(result, sort_keys=True))
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
