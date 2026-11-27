"""Native differential controls for the private journal pre-encode index.

The historical and candidate HIA drivers execute the same finite plans. Their
entire physical journals and receipts must agree byte for byte. Separate
callback controls execute the real candidate HIA policy and its real native
SHA companion against stale/colliding indexes and corrupted physical bytes.
No execution result is cached and no full-cold qualification is claimed.
"""
from pathlib import Path
from hashlib import sha256
import argparse, ctypes, fcntl, json, os, random, struct, subprocess, time

from tools.generate_hia_cold_qualification_plan import Plan
from tools.qualify_hia_cold_qualification_codec_lz import decode
from hepta.hia_json_preflight_native import NativeHiaJsonImage

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--original-build-report', type=Path, required=True)
parser.add_argument('--candidate-build-report', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
BASE = args.original_build_report.resolve().parent
NEW = args.candidate_build_report.resolve().parent
OUT = args.output.resolve()
OUT.mkdir(mode=0o700, parents=True, exist_ok=False)
old_build = json.loads(args.original_build_report.read_bytes())
new_build = json.loads(args.candidate_build_report.read_bytes())
assert old_build['passed'] and new_build['passed']
assert not old_build['target_or_successor_compiler_used'] and not new_build['target_or_successor_compiler_used']
roots = {row['name']: row for row in old_build['initial_roots']}
candidate_roots = {row['name']: row for row in new_build['initial_roots']}
for table in (roots, candidate_roots):
    for row in table.values():
        raw = Path(row['path']).read_bytes()
        assert len(raw) == row['bytes'] and sha256(raw).hexdigest() == row['sha256']
old = Path(roots['hia-cold-qualification-driver']['path'])
new = Path(candidate_roots['hia-cold-qualification-driver']['path'])
assert sha256(old.read_bytes()).hexdigest() == '7ba244d01989b94b9368cdde3fdb5712dfdcc4c0f3f44d8e86a98fbe11e09e48'
assert old_build['sources']['examples/hia_bootstrap/cold_qualification_driver.hepta']['sha256'] == '87e56dfdafd59964959e354d1cc3e4a141fa91ac4c09903781c34e7f920248a9'
current = Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/cold_qualification_driver.hepta'
assert sha256(current.read_bytes()).hexdigest() == new_build['sources'][str(current.relative_to(current.parents[2]))]['sha256']
MASK = (1 << 64) - 1
PRIME = 1099511628211
GUARD = bytes.fromhex('91d34a68') * 8


def fingerprint(raw):
    value = 14695981039346656037
    at = 0
    while len(raw) - at >= 8:
        word, = struct.unpack_from('<Q', raw, at)
        value = ((value ^ word) * PRIME) & MASK
        at += 8
    for value_byte in raw[at:]:
        value = ((value ^ value_byte) * PRIME) & MASK
    return value


def collide(raw):
    assert len(raw) >= 16 and len(raw) % 8 == 0
    changed = bytearray(raw)
    changed[0] ^= 1
    state = fingerprint(changed[:-8])
    final = (fingerprint(raw) * pow(PRIME, -1, 1 << 64)) & MASK
    struct.pack_into('<Q', changed, len(changed)-8, state ^ final)
    assert bytes(changed) != raw and fingerprint(changed) == fingerprint(raw)
    return bytes(changed)


def uncompressed(raw):
    return b'HIAQAZ02' + struct.pack('<3Q', len(raw), len(raw), 0) + raw


def memfd(name, raw):
    fd = os.memfd_create(name, os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    os.write(fd, raw)
    os.lseek(fd, 0, 0)
    fcntl.fcntl(fd, 1033, 15)
    return fd


def run(name, executable, plan, sample):
    folder = OUT/name
    folder.mkdir(mode=0o700)
    fds = []
    try:
        directory = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
        fds.append(directory)
        imports = []
        for alias, raw in [('fast', Path(roots['hia-independent-subprocess']['path']).read_bytes()),
                           ('cold', Path(roots['hia-cold-process-owner']['path']).read_bytes()), ('sample', sample)]:
            fd = memfd(alias, raw)
            fds.append(fd)
            imports.append((alias, fd, raw))
        plan_raw = plan.pack()
        plan_fd = memfd('plan', plan_raw)
        fds.append(plan_fd)
        journal = folder/'evidence.hiaqj'
        journal_fd = os.open(journal, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        fds.append(journal_fd)
        words = [int.from_bytes(b'HIAQDR01', 'little'), os.getpid(), time.monotonic_ns()+180_000_000_000,
                 directory, imports[0][1], imports[1][1], plan_fd, journal_fd, len(imports), len(plan_raw), len(plan.nodes)]
        request = struct.pack('<11Q', *words) + sha256(plan_raw).digest() + bytes(8)
        for alias, fd, raw in imports:
            request += struct.pack('<4Q', fd, len(raw), len(alias), 0) + sha256(raw).digest() + alias.encode().ljust(128,b'\0')
        request_fd = memfd('request', request)
        fds.append(request_fd)
        began = time.monotonic_ns()
        child = subprocess.run([str(executable)], stdin=request_fd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               pass_fds=fds, timeout=183, env={'PATH':'', 'LANG':'C', 'LC_ALL':'C'})
        elapsed = time.monotonic_ns()-began
        (folder/'stdout.bin').write_bytes(child.stdout)
        (folder/'stderr.bin').write_bytes(child.stderr)
        actual = journal.read_bytes()
        row = dict(name=name, executable_sha256=sha256(executable.read_bytes()).hexdigest(),
                   nodes=len(plan.nodes), plan_sha256=sha256(plan_raw).hexdigest(), sample_sha256=sha256(sample).hexdigest(),
                   sample_bytes=len(sample), elapsed_ns=elapsed, status=child.returncode,
                   journal_bytes=len(actual), journal_sha256=sha256(actual).hexdigest(),
                   receipt_sha256=sha256(child.stdout).hexdigest())
        print(json.dumps(row), flush=True)
        assert child.returncode == 0 and not child.stderr and len(child.stdout)==64
        assert child.stdout[:8] == b'HIAQOK01' and child.stdout[32:] == sha256(actual).digest()
        return row
    finally:
        for fd in reversed(fds):
            os.close(fd)


def native_policy_controls():
    derivation = new_build['current_root_derivations']['hia-cold-qualification-driver']
    native = {}
    for name, path, pin in [('policy', NEW/'products/cold_qualification_driver-bulk.flat', derivation['policy']),
                            ('sha', NEW/'products/tmp-cold-sha256-flat', derivation['sha256_flat'])]:
        raw = path.read_bytes()
        assert len(raw) == pin['bytes'] and sha256(raw).hexdigest() == pin['sha256']
        native[name] = NativeHiaJsonImage(raw, pin['sha256'])
    rows = []
    raw = random.Random(177).randbytes(64)
    encoded = uncompressed(raw)
    for name in ('valid', 'short-read', 'read-eintr', 'raw-fingerprint-collision',
                 'raw-slot-miss', 'encoded-slot-eviction', 'physical-byte-corruption',
                 'physical-fingerprint-collision', 'physical-short-eof', 'physical-read-error',
                 'stored-digest-corruption', 'raw-offset-outside-journal', 'raw-length-overflow'):
        source_bytes = bytearray(320)
        struct.pack_into('<Q', source_bytes, 56, 9)
        source = ctypes.create_string_buffer(GUARD + source_bytes + GUARD)
        output = ctypes.create_string_buffer(GUARD + bytes(128) + GUARD)
        work = ctypes.create_string_buffer(GUARD + bytes(4194304) + GUARD)
        address = ctypes.addressof(work) + 32
        def put(at, value):
            ctypes.memmove(address + at, struct.pack('<Q', value), 8)
        def get(at):
            return struct.unpack('<Q', ctypes.string_at(address + at, 8))[0]
        def store(at, data):
            ctypes.memmove(address + at, bytes(data), len(data))
        actual_raw = collide(raw) if name == 'raw-fingerprint-collision' else raw
        physical = bytearray(encoded)
        put(0, 1101)
        put(1500128, len(encoded))
        put(1500288, len(raw))
        store(700000, actual_raw)
        raw_fingerprint = fingerprint(raw)
        slot = 3932160 + (raw_fingerprint & 4095) * 64
        for at, value in [(0, raw_fingerprint), (8, 1), (16, len(raw)), (24, len(encoded))]:
            put(slot + at, value)
        store(slot + 32, sha256(encoded).digest())
        encoded_fingerprint = fingerprint(encoded)
        old_slot = 3342336 + (encoded_fingerprint & 8191) * 64
        for at, value in [(0, encoded_fingerprint), (8, 1), (16, len(encoded))]:
            put(old_slot + at, value)
        store(old_slot + 24, sha256(encoded).digest())
        if name == 'raw-slot-miss':
            put(slot, raw_fingerprint ^ 8192)
        elif name == 'encoded-slot-eviction':
            put(old_slot, encoded_fingerprint ^ 16384)
        elif name == 'physical-byte-corruption':
            physical[44] ^= 1
        elif name == 'physical-fingerprint-collision':
            # Keep a valid raw chunk header while changing a payload word and
            # compensating the last word to retain the exact encoded FNV.
            physical[40] ^= 1
            value = fingerprint(physical[:-8]) ^ ((encoded_fingerprint * pow(PRIME, -1, 1 << 64)) & MASK)
            struct.pack_into('<Q', physical, len(physical)-8, value)
            assert fingerprint(physical) == encoded_fingerprint and physical != encoded
        elif name == 'stored-digest-corruption':
            store(slot + 32, bytes(32))
            store(old_slot + 24, bytes(32))
        elif name == 'raw-offset-outside-journal':
            put(slot + 8, len(encoded) + 1)
        elif name == 'raw-length-overflow':
            put(slot + 24, MASK)
        if name == 'physical-short-eof':
            physical = physical[:-1]
        reads = 0
        sha_calls = 0
        for step in range(200):
            action = native['policy']._entry(ctypes.byref(source, 32), 320,
                         ctypes.byref(output, 32), 128, address, 4194304)
            commands = struct.unpack('<16Q', output.raw[32:160])
            if action == 4:
                continue
            if action == 3:
                sha_calls += 1
                assert 1 <= commands[0] <= 65537
                result = native['sha']._entry(address+65536, commands[0], address+4096, 32, address+4160, 1184)
                put(8, result)
                continue
            assert action == 1
            operation, fd, buffer, count, offset = commands[:5]
            if operation == 60:
                outcome = dict(exit_code=fd)
                break
            assert fd == 9 and commands[7] == 12
            if operation == 17:
                reads += 1
                if name == 'read-eintr' and reads == 1:
                    put(8, MASK-3)
                    continue
                if name == 'physical-read-error':
                    put(8, MASK-4)
                    continue
                data = bytes(physical[offset:offset+count])
                if name == 'short-read':
                    data = data[:7]
                store(buffer, data)
                put(8, len(data))
                continue
            assert operation == 18 and offset == len(encoded)
            written = ctypes.string_at(address+buffer, count)
            if written[:8] == b'HIAQAZ03':
                assert written == b'HIAQAZ03' + struct.pack('<4Q', len(actual_raw), 8, 3, 0)
                outcome = dict(backref=True)
            else:
                assert decode(written) == actual_raw
                outcome = dict(backref=False)
            break
        else:
            raise AssertionError('native callback protocol did not terminate: ' + name)
        assert source.raw[:-1] == GUARD + source_bytes + GUARD
        assert work.raw[:32] == GUARD and work.raw[32+4194304:-1] == GUARD
        assert output.raw[:32] == GUARD and output.raw[160:-1] == GUARD
        assert ctypes.string_at(address+700000, len(actual_raw)) == actual_raw
        if name.startswith('physical-') or name == 'stored-digest-corruption':
            assert outcome == dict(exit_code=74), (name, outcome)
        elif name in ('raw-fingerprint-collision', 'encoded-slot-eviction'):
            assert outcome == dict(backref=False), (name, outcome)
        else:
            assert outcome == dict(backref=True), (name, outcome)
        rows.append(dict(name=name, reads=reads, native_sha_calls=sha_calls, **outcome))
    return rows


report = dict(schema='hepta.hia.cold-journal-preencode-qualification.v1',
              scope=__doc__, passed=False, whole_cold_qualified=False, groups=[],
              original_build_report_sha256=sha256(args.original_build_report.read_bytes()).hexdigest(),
              candidate_build_report_sha256=sha256(args.candidate_build_report.read_bytes()).hexdigest())
rng = random.Random(20261127)
policy = (BASE/'products/cold_qualification_driver-bulk.flat').read_bytes()
samples = [('zero', bytes(65536)), ('random', rng.randbytes(65536)), ('code', policy[:65536]),
           ('observed-shape', policy + bytes(1048576))]
try:
    report['native_callback_controls'] = native_policy_controls()
    print('NATIVE_CALLBACK_CONTROLS_PASS', len(report['native_callback_controls']), flush=True)
    for group, sample in samples:
        plan = Plan()
        original = plan.imported('sample')
        for i in range(128):
            h = plan.slice(original)
            plan.drop(h)
        plan.drop(original)
        pair = [run(group+'-'+tag, executable, plan, sample) for tag, executable in [('old',old),('new',new)]]
        assert pair[0]['journal_sha256'] == pair[1]['journal_sha256'], group
        report['groups'].append(dict(group=group, rows=pair, speedup=pair[0]['elapsed_ns']/pair[1]['elapsed_ns']))
    for group in ('raw-fingerprint-collision', 'raw-slot-collision', 'encoded-slot-collision', 'boundaries'):
        if group == 'boundaries':
            sample = rng.randbytes(65536)
            slices = [(0, n) for n in (0,1,7,8,15,31,32,63,64,65,127,128,16383,16384,16385,65504)]
        else:
            first = rng.randbytes(64)
            if group == 'raw-fingerprint-collision':
                second = collide(first)
            else:
                mask = 4095 if group == 'raw-slot-collision' else 8191
                key = fingerprint(first if mask == 4095 else uncompressed(first)) & mask
                for _ in range(200000):
                    second = rng.randbytes(64)
                    if (fingerprint(second if mask == 4095 else uncompressed(second)) & mask) == key:
                        if mask == 4095 or (fingerprint(second) & 4095) != (fingerprint(first) & 4095):
                            break
                else:
                    raise AssertionError('could not construct finite collision control')
            sample = first + second
            slices = [(0,64),(64,64),(0,64),(64,64),(0,64)] * 8
        plan = Plan()
        original = plan.imported('sample')
        for offset, size in slices:
            h = plan.slice(original, offset, size)
            plan.drop(h)
        plan.drop(original)
        pair = [run(group+'-'+tag, executable, plan, sample) for tag, executable in [('old',old),('new',new)]]
        assert pair[0]['journal_sha256'] == pair[1]['journal_sha256'], group
        report['groups'].append(dict(group=group, rows=pair))
    report['passed'] = True
finally:
    (OUT/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
