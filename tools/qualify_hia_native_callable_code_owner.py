"""Native code-owner qualification; complete Value callable semantics are separate.

Every executable tested here is compiled inside the native owner by its fixed
selfhost role. Python supplies wires and independent observations only. Faults
are real kernel errors at the owner's exact fixed syscall instruction.
"""
from pathlib import Path
import argparse
import concurrent.futures
import ctypes as C
import errno
import fcntl
import hashlib
import json
import os
import platform
import queue
import select
import struct
import subprocess
import threading
import time

from tools.qualify_hia_multiversion_components import Image, get
from tools.qualify_hia_result_value_cleanup import Filter, Program, Notification, Response, LIBC
from tools.generate_hia_native_callable_common import source, document, render_assembly
from tools import generate_hia_native_callable_code_packer as pack

ZERO = (0, 0, 0)
MASK = (1 << 64) - 1


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def wire(op, cap=ZERO, tail=b'', feedback=0):
    return struct.pack('<8s15Q', b'HIACODQ1', op, 0, *cap, 0, 0, 0, 0, 0, 0,
                       len(tail), feedback, 0, 0) + tail


def policy(name, body):
    return render_assembly(document(source('callback', body), name)).encode()


ARITHMETIC = policy('native_dynamic_arithmetic', '''def callback(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=16 or length(o)<128:
        return 2
    put(o,0,NC_BODY_REPLY)
    put(o,8,0)
    put(o,48,(readword(s,0)+readword(s,8))*7)
    return 0
''')

SUSPEND = policy('native_dynamic_continuation', '''def callback(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(s)!=16 or length(o)<NC_LIMIT or length(w)<64:
        return 2
    phase=get(w,0)
    if phase==0:
        put(w,0,1)
        put(w,8,readword(s,0))
        put(o,0,NC_BODY_VALUE)
        put(o,8,128)
        zero(o,128,128)
        put(o,128,MAGIC)
        put(o,136,3)
        return 1
    if phase!=1:
        return 2
    put(w,0,2)
    put(o,0,NC_BODY_REPLY)
    put(o,8,0)
    put(o,48,(get(w,8)+readword(s,8))*7)
    put(o,56,get(o,112))
    return 0
''')


class Owner:
    def __init__(self, path, initialize=True):
        self.image = Image(path)
        self.context = C.create_string_buffer(256)
        self.rows = []
        prefix = self.image.raw[:len(pack.BRIDGE)]
        assert prefix.count(b'\x0f\x05') == 1
        self.syscall_ip = self.image.address + prefix.index(b'\x0f\x05') + 2
        if initialize:
            self.call(0)

    def invoke(self, raw, output=None, context=None):
        source_buffer = C.create_string_buffer(raw)
        result = output or C.create_string_buffer(b'\xa5' * (8192 + 64))
        ctx = self.context if context is None else context
        rc = self.image.entry(source_buffer, len(raw), result, 8192, ctx, 256)
        assert source_buffer.raw == raw + b'\0'
        assert result.raw[8192:] == b'\xa5' * 64 + b'\0'
        return rc, result.raw[:8192]

    def call(self, op, cap=ZERO, tail=b'', feedback=0, want=0):
        rc, raw = self.invoke(wire(op, cap, tail, feedback))
        assert rc == 0 and raw[:8] == b'HIACODR1', (op, rc, raw[:128].hex())
        result = dict(op=op, status=get(raw, 8), kind=get(raw, 16),
                      cap=struct.unpack_from('<3Q', raw, 24), pending=get(raw, 80),
                      known=get(raw, 88), consumed=get(raw, 96),
                      cleanup=get(raw, 112), state=get(raw, 120), raw=raw)
        assert result['known'] == 1 and result['pending'] in (0, 1) and result['consumed'] in (0, 1)
        if want is not None:
            assert result['status'] == want, {k: v for k, v in result.items() if k != 'raw'}
        self.rows.append({k: v for k, v in result.items() if k != 'raw'})
        return result

    def create(self, data=ARITHMETIC):
        row = self.call(1, tail=data)
        assert row['kind'] == 1 and row['consumed'] == 1 and all(row['cap'])
        return row['cap']

    def empty(self):
        raw = self.call(7)['raw']
        assert tuple(get(raw, at) for at in (48, 56, 64, 80)) == (0, 0, 0, 0), raw[:128].hex()

    def finish(self):
        self.empty()
        row = self.call(6)
        assert row['state'] == 3 and not row['pending']
        assert get(self.context, 16) == get(self.context, 32) == get(self.context, 40) == get(self.context, 48) == 0
        self.call(6)
        return dict(registry_empty=True, actual_metadata_mapping_retired=True)


def mapped(address, extent, permissions):
    cursor = address
    end = address + extent
    for line in Path('/proc/self/maps').read_text().splitlines():
        span, modes, *_ = line.split()
        left, right = (int(x, 16) for x in span.split('-'))
        if left <= cursor < right:
            assert modes == permissions, (line, permissions)
            cursor = min(right, end)
            if cursor == end:
                return True
    raise AssertionError(('native mapping was not fully present', address, extent, permissions))


def native_compile(compiler, data):
    raw = compiler.read_bytes()
    assert pin(raw) == dict(bytes=813129, sha256='494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af')
    fd = os.memfd_create('hia-callable-original-oracle', os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    try:
        at = 0
        while at < len(raw):
            n = os.write(fd, raw[at:])
            assert n > 0
            at += n
        os.fchmod(fd, 0o500)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, 15)
        assert fcntl.fcntl(fd, fcntl.F_GET_SEALS) == 15
        result = subprocess.run(['/proc/self/fd/' + str(fd), 'compile'], input=data,
                                capture_output=True, pass_fds=(fd,), env={'PATH': ''}, timeout=120)
        assert result.returncode == 0 and not result.stderr
        return result.stdout
    finally:
        os.close(fd)


def listener(ip, numbers):
    checks = [(8, ip & 0xffffffff), (12, ip >> 32)]
    count = 2 * len(checks) + 1 + len(numbers) + 2
    instructions = []
    for at, value in checks:
        instructions.append(Filter(0x20, 0, 0, at))
        index = len(instructions)
        instructions.append(Filter(0x15, 0, count - index - 2, value))
    instructions.append(Filter(0x20, 0, 0, 0))
    for number in numbers:
        index = len(instructions)
        instructions.append(Filter(0x15, count - index - 3, 0, number))
    instructions.extend((Filter(0x06, 0, 0, 0x7fff0000), Filter(0x06, 0, 0, 0x7fc00000)))
    # Nonmatching IPs must jump to ALLOW, and matching syscall tests to NOTIFY.
    instructions[1].jf = count - 4
    instructions[3].jf = count - 6
    for i in range(5, 5 + len(numbers)):
        instructions[i].jt = count - i - 2
    native = (Filter * len(instructions))(*instructions)
    program = Program(len(instructions), native)
    if LIBC.prctl(38, 1, 0, 0, 0):
        raise OSError(C.get_errno(), 'private no_new_privs')
    fd = LIBC.syscall(317, 1, 8, C.byref(program))
    if fd < 0:
        raise OSError(C.get_errno(), 'private seccomp notification listener')
    return int(fd)


def deny_native(ip, number, error):
    checks = ((8, ip & 0xffffffff), (12, ip >> 32), (0, number))
    count = 2 * len(checks) + 2
    items = []
    for at, value in checks:
        items.append(Filter(0x20, 0, 0, at))
        index = len(items)
        items.append(Filter(0x15, 0, count - index - 2, value))
    items.extend((Filter(0x06, 0, 0, 0x50000 | error), Filter(0x06, 0, 0, 0x7fff0000)))
    native = (Filter * len(items))(*items)
    program = Program(len(items), native)
    if LIBC.prctl(38, 1, 0, 0, 0):
        raise OSError(C.get_errno(), 'private no_new_privs')
    if LIBC.syscall(317, 1, 0, C.byref(program)) != 0:
        raise OSError(C.get_errno(), 'private syscall errno filter')


def fault(owner, raw, numbers, phases, error, target):
    output = C.create_string_buffer(b'\xa5' * (8192 + 64))
    ready = queue.Queue()
    result = queue.Queue()
    notices = []
    def run():
        try:
            ready.put(listener(owner.syscall_ip, numbers))
            result.put(owner.invoke(raw, output))
        except BaseException as problem:
            ready.put(problem)
            result.put(problem)
    thread = threading.Thread(target=run)
    thread.start()
    fd = ready.get(timeout=30)
    if isinstance(fd, BaseException):
        raise fd
    try:
        until = time.monotonic() + 120
        while thread.is_alive():
            assert time.monotonic() < until, 'native fault gate exceeded 120 seconds'
            readable, _, _ = select.select([fd], [], [], 0.2)
            if not readable:
                continue
            notice = Notification()
            if LIBC.ioctl(fd, 0xc0502100, C.byref(notice)) < 0:
                if C.get_errno() in (errno.EINTR, errno.ENOENT):
                    continue
                raise OSError(C.get_errno(), 'SECCOMP_IOCTL_NOTIF_RECV')
            phase = get(output, 128)
            assert notice.data.ip == owner.syscall_ip and notice.data.nr in numbers
            denied = phase in phases
            row = dict(nr=notice.data.nr, phase=phase, args=list(notice.data.args),
                       errno=error if denied else 0, ip=notice.data.ip, tid=notice.pid)
            notices.append(row)
            target.write_text(json.dumps(notices, indent=2) + '\n')
            reply = Response(notice.id, 0, -error if denied else 0, 0 if denied else 1)
            assert LIBC.ioctl(fd, 0xc0182101, C.byref(reply)) == 0, C.get_errno()
        thread.join(1)
    finally:
        os.close(fd)
        thread.join(10)
    assert not thread.is_alive()
    pair = result.get_nowait()
    if isinstance(pair, BaseException):
        raise pair
    rc, reply = pair
    assert rc == 0 and reply[:8] in (b'HIACODR1', b'HIAVRFR1')
    target.with_suffix('.reply.bin').write_bytes(reply)
    target.with_suffix('.reply.json').write_text(json.dumps(list(struct.unpack_from('<16Q', reply)), indent=2) + '\n')
    assert any(row['errno'] == error for row in notices), notices
    return reply, notices


def construction_case(path, compiler):
    owner = Owner(path)
    code = owner.create()
    captured = owner.call(8, code)['raw']
    code_address, code_extent, code_bytes = (get(captured, at) for at in (288, 296, 304))
    source_address, source_extent, source_bytes = (get(captured, at) for at in (312, 320, 328))
    expected = native_compile(compiler, ARITHMETIC)
    assert code_bytes == len(expected) and C.string_at(code_address, code_bytes) == expected
    assert source_bytes == len(ARITHMETIC) and C.string_at(source_address, source_bytes) == ARITHMETIC
    mapped(code_address, code_extent, 'r-xp')
    mapped(source_address, source_extent, 'r--p')
    alias = owner.call(2, code)['cap']
    assert alias != code
    vectors = [(0, 0), (7, 19), (MASK, 1), (MASK, MASK), (1 << 63, (1 << 63) - 1)]
    for left, right in vectors:
        row = owner.call(4, code, struct.pack('<2Q', left, right))
        assert row['kind'] == 2 and row['consumed'] == 1 and all(row['cap'])
        body = row['raw'][4096:4224]
        assert body[:8] == b'HIACBR01' and get(body, 48) == ((left + right) * 7) & MASK
        owner.call(9, row['cap'], want=6)
        owner.call(3, row['cap'])
    owner.call(3, code)
    last = owner.call(4, alias, struct.pack('<2Q', 2, 5))
    frame = last['cap']
    closed = owner.call(3, alias)
    assert closed['consumed'] == 1 and closed['pending'] == 1
    mapped(code_address, code_extent, 'r-xp')
    owner.call(3, frame)
    return dict(case='actual-source-compile-rx-execution-and-code-lifetime',
                independent_original_compiler_bytes_equal=True, readonly_source_and_rx_code=True,
                independent_random_clone_tokens=True, vectors=len(vectors) + 1,
                continuation_owns_code_after_last_code_cap=True, **owner.finish())


def continuation_case(path):
    owner = Owner(path)
    code = owner.create(SUSPEND)
    original = struct.pack('<2Q', 11, 17)
    first = owner.call(4, code, original)
    raw = first['raw']
    assert get(raw, 48) == 1 and get(raw, 64) == 128 and get(raw, 104) == 524288
    request = C.string_at(get(raw, 56), get(raw, 64))
    assert request[:8] == b'HIABVQ01' and get(request, 8) == 3
    frame = first['cap']
    snapshot = owner.call(8, frame)['raw']
    mapped(get(snapshot, 288), 1048576, 'r--p')
    mapped(get(snapshot, 288) + 1048576, 2097152, 'rw-p')
    owner.call(3, code)
    resumed = owner.call(9, frame, feedback=7)
    assert resumed['cap'] == ZERO and get(resumed['raw'], 48) == 0
    body = resumed['raw'][4096:4224]
    assert body[:8] == b'HIACBR01' and get(body, 48) == 196 and get(body, 56) == 7
    owner.call(9, frame, want=6)
    owner.call(3, frame)
    return dict(case='native-suspended-code-state-and-immutable-input', native_yield_and_resume=True,
                original_input_survives_code_cap_drop=True, no_host_callback=True, **owner.finish())


def controls_case(path):
    owner = Owner(path)
    code = owner.create()
    for bad in (ZERO, (1, 1, 1), (code[0], code[1] ^ 1, code[2]), (code[0], code[1], code[2] ^ 1)):
        for op in (2, 3, 4, 8, 9):
            row = owner.call(op, bad, want=1)
            assert not row['consumed'] and row['cap'] == ZERO
    rejected = []
    for label, data in (
        ('wrong-entry-signature', ARITHMETIC.replace(b'v2:mutbuf) -> (u32)', b'v2:readbuf) -> (u32)', 1)),
        ('wrong-entry-effect', ARITHMETIC.replace(b'effects(read,write,trap)', b'effects(read,write)', 1)),
        ('wrong-entry-name', ARITHMETIC.replace(b'fn f0(', b'fn f9(', 1)),
        ('valid-prefix-invalid-source', ARITHMETIC + b'not_hia\n'),
        ('different-program-version', ARITHMETIC.replace(b'program.v9', b'program.v8', 1))):
        row = owner.call(1, tail=data, want=3)
        assert row['cap'] == ZERO and not row['consumed'] and not row['pending']
        rejected.append(label)
    malformed = []
    for at in (16, 48, 56, 64, 72, 80, 88, 104, 112, 120):
        data = bytearray(wire(7))
        struct.pack_into('<Q', data, at, 1)
        malformed.append(bytes(data))
    malformed.extend((wire(7)[:-1], wire(7) + b'\0', wire(12)))
    for raw in malformed:
        before = owner.context.raw
        rc, result = owner.invoke(raw)
        assert rc == 0xfffffffd and result[:128] == b'\xa5' * 128 and owner.context.raw == before
    duplicate = C.create_string_buffer(owner.context.raw, 256)
    rc, result = owner.invoke(wire(7), context=duplicate)
    assert rc == 0 and get(result, 8) == 6 and duplicate.raw == owner.context.raw
    owner.call(3, code)
    again = owner.call(3, code, want=1)
    assert not again['consumed']
    return dict(case='source-signature-capability-process-and-wire-guards',
                malformed=len(malformed), invalid_cap_operations=20, rejected_sources=rejected,
                copied_context_refused=True, no_duplicate_consumption=True, **owner.finish())


def growth_case(path, target):
    owner = Owner(path)
    code = owner.create()
    aliases = [owner.call(2, code)['cap'] for _ in range(600)]
    assert get(owner.context, 40) > 65536
    for cap in aliases:
        owner.call(3, cap)
    # Saturation is driven by real cap allocation, never a written free-list.
    thread_result = queue.Queue()
    def fill():
        caps = []
        try:
            deny_native(owner.syscall_ip, 25, errno.ENOMEM)
            extent = get(owner.context, 40)
            for _ in range(65536):
                row = owner.call(2, code, want=None)
                if row['status']:
                    assert row['status'] == 5 and not row['consumed'] and row['cap'] == ZERO
                    break
                caps.append(row['cap'])
            else:
                raise AssertionError('code metadata did not reach actual refused mremap')
            assert get(owner.context, 40) == extent
            thread_result.put((caps, dict(real_caps=len(caps), extent=extent)))
        except BaseException as error:
            thread_result.put((caps, error))
    thread = threading.Thread(target=fill)
    thread.start()
    thread.join(120)
    assert not thread.is_alive()
    caps, facts = thread_result.get_nowait()
    for cap in caps:
        owner.call(3, cap)
    if isinstance(facts, BaseException):
        raise facts
    owner.call(3, code)
    return dict(case='native-metadata-growth-and-refused-growth', successful_aliases=600,
                actual_mremap_errno=errno.ENOMEM, **facts, **owner.finish())


def concurrent_case(path):
    owner = Owner(path)
    code = owner.create()
    gate = threading.Barrier(8)
    def run(index):
        gate.wait(timeout=30)
        for n in range(24):
            left, right = index * 37 + n, (1 << 63) + 7 * n
            row = owner.call(4, code, struct.pack('<2Q', left, right))
            assert get(row['raw'], 4144) == ((left + right) * 7) & MASK
            owner.call(3, row['cap'])
        return 24
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        counts = list(pool.map(run, range(8)))
    owner.call(3, code)
    return dict(case='concurrent-native-code-invocations', threads=8, invocations=sum(counts), **owner.finish())


def fault_cases(path, target):
    rows = []
    for label, numbers, phases, error in (
        ('source-mmap', (9,), (31,), errno.ENOMEM),
        ('compiler-work-mmap', (9,), (35,), errno.ENOMEM),
        ('code-mmap', (9,), (37,), errno.ENOMEM),
        ('source-readonly-protection', (10,), (34,), errno.EACCES),
        ('code-executable-protection', (10,), (52,), errno.EACCES),
        ('random-code-token', (318,), (60,), errno.EIO),
        ('compile-work-retirement', (11,), (53, 201), errno.EIO),
    ):
        owner = Owner(path)
        reply, notices = fault(owner, wire(1, tail=ARITHMETIC), numbers, phases, error, target / (label + '.json'))
        assert get(reply, 8) in (5, 11) and struct.unpack_from('<3Q', reply, 24) == ZERO
        assert get(reply, 88) == 1 and get(reply, 96) == 0
        pending = get(reply, 80)
        if label == 'compile-work-retirement':
            assert pending == 1
        owner.call(5)
        rows.append(dict(case=label, kernel_errno=error, notices=notices,
                         orphan_retained_until_actual_retry=bool(pending), **owner.finish()))
    for label, operation in (('code-drop-retirement', 3), ('arena-close-retirement', 6)):
        owner = Owner(path)
        code = owner.create()
        if operation == 6:
            owner.call(3, code)
        request = wire(operation, code if operation == 3 else ZERO)
        reply, notices = fault(owner, request, (11,), (201, 231), errno.EIO, target / (label + '.json'))
        assert (get(reply, 8), get(reply, 80), get(reply, 88), get(reply, 96)) == (11, 1, 1, int(operation == 3))
        if operation == 3:
            stale = owner.call(3, code, want=1)
            assert stale['consumed'] == 0
            owner.call(5)
            ending = owner.finish()
        else:
            row = owner.call(5)
            assert row['state'] == 3 and get(owner.context, 16) == get(owner.context, 40) == 0
            ending = dict(registry_empty=True, actual_metadata_mapping_retired=True)
        rows.append(dict(case=label, exact_consumed_pending_retained=True, notices=notices, **ending))
    for label, numbers, phases in (
        ('continuation-mapping', (9,), (41,)),
        ('continuation-readonly-input', (10,), (44,)),
        ('continuation-token', (318,), (60,)),
    ):
        owner = Owner(path)
        code = owner.create()
        reply, notices = fault(owner, wire(4, code, struct.pack('<2Q', 4, 6)), numbers, phases,
                               errno.ENOMEM, target / (label + '.json'))
        assert get(reply, 8) in (5, 11) and get(reply, 96) == 0
        assert struct.unpack_from('<3Q', reply, 24) == ZERO
        recovered = owner.call(4, code, struct.pack('<2Q', 4, 6))
        assert get(recovered['raw'], 4144) == 70
        owner.call(3, recovered['cap'])
        owner.call(3, code)
        rows.append(dict(case=label, actual_parent_code_pin_released_on_failure=True,
                         notices=notices, **owner.finish()))
    return rows


def fence_case(path):
    owner = Owner(path)
    code = owner.create()
    owner.call(10, want=6)
    assert get(owner.context, 24) == 0
    frame = owner.call(4, code, struct.pack('<2Q', 1, 1))['cap']
    owner.call(3, code)
    owner.call(10, want=6)
    owner.call(3, frame)
    owner.empty()
    owner.call(10)
    assert get(owner.context, 24) == 4
    owner.call(1, tail=ARITHMETIC, want=6)
    owner.call(2, code, want=6)
    owner.call(4, code, b'', want=6)
    owner.call(11)
    code = owner.create()
    owner.call(3, code)
    owner.call(10)
    row = owner.call(6)
    assert row['state'] == 3
    owner.call(6)
    return dict(case='actual-empty-provider-fence-rollback-and-close',
                live_code_and_continuation_refuse_fence=True,
                new_work_blocked_while_fenced=True, rollback_restores_actual_compilation=True,
                final_mapping_retired=True)


def fork_case(path):
    owner = Owner(path)
    code = owner.create()
    before = owner.context.raw
    reader, writer = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(reader)
        try:
            for op in (2, 3, 4, 8, 9):
                row = owner.call(op, code, want=6)
                assert not row['consumed'] and owner.context.raw == before
            os.write(writer, b'PASS')
            os._exit(0)
        except BaseException:
            os._exit(1)
    os.close(writer)
    reply = os.read(reader, 4)
    os.close(reader)
    _, status = os.waitpid(pid, 0)
    assert status == 0 and reply == b'PASS' and owner.context.raw == before
    owner.call(3, code)
    return dict(case='actual-process-identity-binding', fork_refused_without_consumption=True, **owner.finish())


def final_request(owner, operation, kind, cap):
    nonce = get(owner.context, 128)
    assert nonce
    return struct.pack('<8s15Q', b'HIAVRFQ1', operation, nonce, kind, *cap, *([0] * 9))


def final_call(owner, operation, kind, cap, want=(0, 1, 1, 0)):
    raw = final_request(owner, operation, kind, cap)
    source_buffer = C.create_string_buffer(raw)
    output = C.create_string_buffer(b'\xa5' * (128 + 64))
    rc = owner.image.entry(source_buffer, len(raw), output, 128, owner.context, 256)
    assert source_buffer.raw == raw + b'\0' and output.raw[128:] == b'\xa5' * 64 + b'\0'
    reply = output.raw[:128]
    assert rc == 0 and reply[:8] == b'HIAVRFR1', (rc, reply.hex())
    actual = tuple(get(reply, at) for at in (8, 16, 24, 32))
    assert actual == want, (actual, want, reply.hex())
    return reply


def finalizer_case(path):
    owner = Owner(path)
    nonce = get(owner.context, 128)
    assert nonce and get(owner.call(0)['raw'], 48) == nonce
    for kind in (3, 4, 5):
        code = owner.create()
        alias = owner.call(2, code)['cap']
        final_call(owner, 0, kind, code)
        final_call(owner, 0, kind, code, (1, 1, 0, 0))
        final_call(owner, 0, kind, alias)
        final_call(owner, 1, kind, alias)
    code = owner.create()
    frame = owner.call(4, code, struct.pack('<2Q', 1, 1))['cap']
    final_call(owner, 0, 3, frame, (2, 1, 0, 0))
    valid = final_request(owner, 0, 3, code)
    for at, value in ((8, 2), (16, nonce ^ 1), (24, 2), (24, 6), (56, 1), (120, 1)):
        invalid = bytearray(valid)
        struct.pack_into('<Q', invalid, at, value)
        source_buffer = C.create_string_buffer(bytes(invalid))
        output = C.create_string_buffer(b'\xa5' * (128 + 64))
        before = owner.context.raw
        rc = owner.image.entry(source_buffer, 128, output, 128, owner.context, 256)
        assert rc == 0xfffffffd and output.raw == b'\xa5' * 192 + b'\0'
        assert source_buffer.raw == bytes(invalid) + b'\0' and owner.context.raw == before
    final_call(owner, 0, 3, code, (0, 1, 1, 1))
    owner.call(3, frame)
    final_call(owner, 1, 3, code)
    return dict(case='fixed-native-resource-finalizer-transport',
                actual_random_provider_nonce=True, exact_128_byte_response=True,
                kinds=[3, 4, 5], malformed_private_wires=6,
                continuation_rejected_as_code=True,
                code_consumption_and_active_continuation_pending_separate=True,
                **owner.finish())


def extra_fault_cases(path, target):
    rows = []
    for label, numbers, phases, error, status in (
        ('initial-provider-nonce', (318,), (12,), errno.EIO, 11),
        ('initial-metadata-map', (9,), (3,), errno.ENOMEM, 5),
    ):
        owner = Owner(path, initialize=False)
        reply, notices = fault(owner, wire(0), numbers, phases, error, target / (label + '.json'))
        assert (get(reply, 8), get(reply, 80), get(reply, 88), get(reply, 96)) == (status, 0, 1, 0)
        assert owner.context.raw == b'\0' * 256
        recovered = owner.call(0)
        assert get(recovered['raw'], 48) == get(owner.context, 128) != 0
        rows.append(dict(case=label, actual_failure_fully_releases_initialization_claim=True,
                         actual_retry_generates_provider_nonce=True, notices=notices, **owner.finish()))
    for kind in (3, 4, 5):
        owner = Owner(path)
        code = owner.create()
        label = 'fixed-finalizer-retirement-kind-' + str(kind)
        reply, notices = fault(owner, final_request(owner, 0, kind, code), (11,), (201,),
                               errno.EIO, target / (label + '.json'))
        assert reply[:8] == b'HIAVRFR1'
        assert tuple(get(reply, at) for at in (8, 16, 24, 32)) == (11, 1, 1, 1)
        final_call(owner, 1, kind, code)
        rows.append(dict(case=label, actual_consumed_pending_preserved=True,
                         fixed_retry_actually_unmaps_code_and_source=True,
                         notices=notices, **owner.finish()))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert platform.python_version() == '3.14.4'
    args.output.mkdir(parents=True, exist_ok=False)
    build = json.loads((args.image.parent / 'build.json').read_bytes())
    assert pin(args.image.read_bytes()) == {k: build['products'][args.image.name][k] for k in ('bytes', 'sha256')}
    rows = []
    for name, function in (
        ('construction', lambda: construction_case(args.image, args.compiler)),
        ('continuation', lambda: continuation_case(args.image)),
        ('controls', lambda: controls_case(args.image)),
        ('growth', lambda: growth_case(args.image, args.output)),
        ('concurrent', lambda: concurrent_case(args.image)),
        ('fence', lambda: fence_case(args.image)),
        ('fork', lambda: fork_case(args.image)),
        ('fixed-finalizer', lambda: finalizer_case(args.image)),
    ):
        row = function()
        rows.append(row)
        (args.output / (name + '.json')).write_text(json.dumps(row, indent=2) + '\n')
        (args.output / 'progress.json').write_text(json.dumps(rows, indent=2) + '\n')
        print('NATIVE_CODE_CASE', name, flush=True)
    fault_rows = fault_cases(args.image, args.output)
    rows.extend(fault_rows)
    rows.extend(extra_fault_cases(args.image, args.output))
    report = dict(schema='hia.native-callable-code-owner.qualification.v1', passed=True,
                  image=pin(args.image.read_bytes()), oracle=platform.python_version(),
                  code_owner_qualified=True, cases=rows, groups=len(rows),
                  source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  native_callable_and_boundmethod_qualified=False,
                  fixed_finalizer_transport_qualified=True,
                  fixed_resource_finalizer_integration_qualified=False,
                  whole_public_runtime_qualified=False)
    (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(passed=True, groups=len(rows), code_owner_qualified=True)), flush=True)


if __name__ == '__main__':
    main()
