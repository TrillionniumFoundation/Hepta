"""Exercise the native release owner kit boundary with real captured kit frames.

External component fixture only. The original HIA owner/DAG/SHA machine images
select every operation. This interpreter implements only their bounded buffer
selectors and a small Linux memfd syscall set; it never executes a candidate
kit or substitutes Python for the native admission/hash comparisons.
"""
from pathlib import Path
from hashlib import sha256
import argparse, ctypes, fcntl, json, mmap, os, struct, sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))
from tools.generate_hia_release_owner import template
from tools.generate_hia_native_controller_release import ControllerRecipe
from tools.generate_hia_generation_lease_native_release import pin_kit_body

def pin(raw):
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}

class NativeBoundary:
    def __init__(self, owner):
        prefix, holes = template()
        names = ('policy_hole', 'stage_hole', 'sha_hole')
        starts = [holes[n] + 4 + struct.unpack_from('<i', owner, holes[n])[0] for n in names]
        if starts != sorted(starts) or starts[0] != len(prefix):
            raise ValueError('owner machine-image extents differ')
        self.parts = [owner[a:b] for a, b in zip(starts, starts[1:] + [len(owner)])]
        self.maps, self.functions = [], []
        signature = ctypes.CFUNCTYPE(ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint64,
            ctypes.c_void_p, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_uint64)
        for raw in self.parts:
            mapping = mmap.mmap(-1, len(raw), prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
            mapping.write(raw)
            address = ctypes.addressof(ctypes.c_char.from_buffer(mapping))
            self.maps.append(mapping)
            self.functions.append(signature(address))
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.syscall.restype = ctypes.c_long
        self.active = set()

    def seal(self, raw):
        fd = os.memfd_create('native-kit-boundary-input', os.MFD_ALLOW_SEALING)
        self.active.add(fd)
        written = os.write(fd, raw)
        if written != len(raw):
            raise OSError('short fixture input capture')
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, 15)
        return fd

    def close_fds(self):
        for fd in self.active:
            try:
                os.close(fd)
            except OSError:
                pass
        self.active.clear()

    def case(self, frame, expected):
        self.close_fds()
        state = bytearray(4194304)
        plan = bytearray(128)
        source = ctypes.create_string_buffer(bytes(305), 305)
        state_array = (ctypes.c_ubyte * len(state)).from_buffer(state)
        plan_array = (ctypes.c_ubyte * len(plan)).from_buffer(plan)
        sp, wp, op = (ctypes.addressof(x) for x in (source, state_array, plan_array))
        def get(at):
            return struct.unpack_from('<Q', state, at)[0]
        def put(at, value):
            struct.pack_into('<Q', state, at, value & ((1 << 64) - 1))
        def invoke(which=0):
            return self.functions[which](sp, 305, op, 128, wp, len(state))
        # The actual native entry initializes its constants before rejecting the
        # intentionally empty request. No requested exit is executed here.
        assert invoke() == 1 and struct.unpack_from('<2Q', plan) == (60, 65)
        fd = self.seal(frame)
        for at, value in {0: 5200, 8: 0, 144: fd, 152: len(frame),
                          1500056: 1, 1500144: 3, 1500152: 0, 1500160: 0,
                          1500088: 2097152, 1500040: 0}.items():
            put(at, value)
        calls, stage = [], 'kit-frame'
        while len(calls) < 30000:
            previous = get(0)
            if stage == 'kit-frame' and previous == 5003:
                row = 1048576 + 64
                if get(row) != fd or get(row + 16) != len(frame) or get(row + 24) != 3:
                    raise AssertionError('native kit admission did not retain its exact frame')
                recipe = ControllerRecipe()
                recipe.nodes.clear()
                recipe.next_handle = 2
                # Handle 1 is the original HIA-admitted frame and its native
                # body extent. The tested author emits the actual guard graph.
                pin_kit_body(recipe, 1, expected)
                graph = recipe.binary()
                assert len(graph) <= 1048576
                state[2097152:2097152 + len(graph)] = graph
                graph_fd = self.seal(graph)
                put(1500000, graph_fd)
                put(1500008, len(graph))
                put(0, 5002)
                put(8, 0)
                stage = 'body-identity'
                continue
            if stage == 'body-identity' and previous == 5003 and get(1500040) == get(1500016):
                return {'accepted': True, 'stage': stage, 'calls': len(calls),
                        'body_bytes': get(1048576 + 64 + 48),
                        'body_nodes': get(1500016)}
            action = invoke()
            if action == 5:
                action = invoke(1)
            calls.append([previous, action])
            if action == 4:
                continue
            if action == 3:
                count = struct.unpack_from('<Q', plan)[0]
                if not 1 <= count <= 65537:
                    raise AssertionError('native SHA transport extent')
                result = self.functions[2](wp + 65536, count, wp + 4096, 32, wp + 4160, 1184)
                put(8, result)
                continue
            if action != 1:
                raise AssertionError(('unexpected mechanical action', action))
            words = list(struct.unpack('<16Q', plan))
            number, arguments, mask = words[0], words[1:7], words[7]
            if number == 60:
                return {'accepted': False, 'stage': stage, 'calls': len(calls),
                        'phase': previous, 'exit_code': arguments[0]}
            if number not in (1, 3, 5, 8, 17, 18, 72, 91, 319):
                raise AssertionError(('non-memfd syscall refused by fixture', number))
            for i in range(6):
                selector = mask & 3
                mask >>= 2
                if selector:
                    base, bound = ((sp, 305), (op, 128), (wp, len(state)))[selector - 1]
                    if arguments[i] >= bound:
                        raise AssertionError('native pointer selector out of fixture extent')
                    arguments[i] += base
            if mask:
                raise AssertionError('native pointer mask overflow')
            ctypes.set_errno(0)
            result = self.libc.syscall(ctypes.c_long(number),
                *(ctypes.c_ulonglong(value) for value in arguments))
            if result == -1:
                result = -ctypes.get_errno()
            if number == 319 and result >= 0:
                self.active.add(result)
            elif number == 3 and result == 0:
                self.active.discard(arguments[0])
            put(8, result)
        raise AssertionError('native component did not terminate within fixture steps')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('owner', 'small_frame', 'wide_frame', 'receipt', 'output'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    owner = args.owner.read_bytes()
    receipt_raw = args.receipt.read_bytes()
    receipt = json.loads(receipt_raw)
    native = NativeBoundary(owner)
    report = {'schema': 'hepta.hia.release-kit-extent-controls.v1',
              'scope': 'native component boundary; not full release/cold qualification',
              'owner': pin(owner), 'receipt': pin(receipt_raw),
              'native_parts': [pin(raw) for raw in native.parts],
              'fixture_source': pin(Path(__file__).read_bytes()),
              'cases': [], 'passed': False}
    try:
        for kind, path in [('small', args.small_frame), ('wide', args.wide_frame)]:
            raw = path.read_bytes()
            expected = receipt['kits'][kind]
            changed_body = bytearray(raw)
            changed_body[180] ^= 1  # A body byte outside all retained call-site boundaries.
            changed_magic = raw[:-1] + bytes([raw[-1] ^ 1])
            changed_extent = bytearray(raw)
            struct.pack_into('<Q', changed_extent, len(raw) - 64, len(raw) - 65)
            cases = [('actual-frame', raw, expected, True),
                     ('wrong-body-identity', bytes(changed_body), expected, False),
                     ('wrong-expected-body-extent', raw, {**expected, 'bytes': expected['bytes'] + 1}, False),
                     ('wrong-footer-magic', changed_magic, expected, False),
                     ('wrong-footer-body-extent', bytes(changed_extent), expected, False),
                     ('truncated-frame', raw[:-1], expected, False),
                     ('appended-frame-byte', raw + b'x', expected, False)]
            for name, frame, record, accept in cases:
                actual = native.case(frame, record)
                row = {'profile': kind, 'case': name, 'frame': pin(frame),
                       'expected_body': record, 'expected_accept': accept, **actual}
                row['passed'] = actual['accepted'] is accept and (accept or actual.get('exit_code') == 65)
                report['cases'].append(row)
                print(json.dumps(row), flush=True)
                if not row['passed']:
                    raise AssertionError(row)
        report['passed'] = True
    finally:
        native.close_fds()
        for mapping in native.maps:
            mapping.close()
        (args.output / 'report.json').write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report

if __name__ == '__main__':
    main()
