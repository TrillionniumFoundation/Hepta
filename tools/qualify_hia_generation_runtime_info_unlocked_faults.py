"""Q14 Info publication followed by the original refused cache allocation.

Derived only for the actual 1031-byte Value bridge and Q14 request magic.
The original fault trigger, assertions and actual allocation budget are retained.

The notifier pauses the fixed Value syscall before cache import, after Info60
has published its main capability. A second actual consumer fills the same
arena through context-token operations. Only the kernel supplies ENOMEM;
no arena word, lock, result, or product function pointer is changed.
"""
from pathlib import Path
import argparse
import ctypes as C
import errno
import hashlib
import json
import mmap
import os
import platform
import queue
import select
import struct
import threading
import time

from tools import qualify_hia_generation_info_owner as prior
from tools.qualify_hia_generation_lease_owner_resources import setup, capture, finish, pin, clean_row
from tools.qualify_hia_result_value_cleanup import Filter, Program, Notification, Response, LIBC

q = prior.q
ZERO = (0, 0, 0)


def private_listener(ip):
    items = (
        Filter(0x20, 0, 0, 8),
        Filter(0x15, 0, 7, ip & 0xffffffff),
        Filter(0x20, 0, 0, 12),
        Filter(0x15, 0, 5, ip >> 32),
        Filter(0x20, 0, 0, 0),
        Filter(0x15, 2, 0, 39),
        Filter(0x15, 1, 0, 25),
        Filter(0x06, 0, 0, 0x7fff0000),
        Filter(0x06, 0, 0, 0x7fc00000),
        Filter(0x06, 0, 0, 0x7fff0000),
    )
    native = (Filter * len(items))(*items)
    program = Program(len(items), native)
    if LIBC.prctl(38, 1, 0, 0, 0):
        raise OSError(C.get_errno(), 'private no_new_privs')
    fd = LIBC.syscall(317, 1, 8, C.byref(program))
    if fd < 0:
        raise OSError(C.get_errno(), 'private seccomp NEW_LISTENER')
    return int(fd)


class SharedConsumer:
    """Invoke only the exact Value entry/context captured by native owner init."""
    def __init__(self, owner, raw):
        self.context = (C.c_char * 256).from_buffer(owner.context, 512)
        entry = q.get(owner.context, 40)
        assert entry and q.get(owner.context, 48) == C.addressof(self.context)
        assert q.get(owner.context, 56) == 256
        assert C.string_at(entry, len(raw)) == raw
        assert raw[:1031].count(b'\x0f\x05') == 1
        self.syscall_ip = entry + raw[:1031].index(b'\x0f\x05') + 2
        signature = C.CFUNCTYPE(C.c_uint32, C.c_void_p, C.c_uint64,
                               C.c_void_p, C.c_uint64, C.c_void_p, C.c_uint64)
        self.entry = signature(entry)

    def call(self, raw):
        source = C.create_string_buffer(raw)
        output = C.create_string_buffer(b'\xa5' * (16384 + 64))
        rc = self.entry(source, len(raw), output, 16384, self.context, 256)
        assert source.raw == raw + b'\0' and output.raw[16384:] == b'\xa5' * 64 + b'\0'
        return rc, output.raw[:16384]


def token_release(consumer, cap):
    raw = bytearray(q.value_wire(30, a=cap))
    raw[:8] = b'HIABVQ02'
    rc, reply = consumer.call(bytes(raw))
    assert rc == 0 and reply[:8] == b'HIABVR02'
    assert tuple(q.get(reply, at) for at in (8, 80, 88, 96)) == (0, 0, 1, 1), reply[:128].hex()


def fill_actual_arena(consumer):
    result = queue.Queue()
    def denied():
        tokens = []
        try:
            q.deny_syscall(25, errno.ENOMEM)
            extent = q.get(consumer.context, 40)
            for _ in range(65536):
                rc, reply = consumer.call(q.value_wire(21))
                assert rc == 0 and reply[:8] == b'HIABVR01'
                status = q.get(reply, 8)
                if status:
                    assert status == 5 and q.get(reply, 24) == 0, reply[:128].hex()
                    break
                tokens.append(struct.unpack_from('<3Q', reply, 24))
            else:
                raise AssertionError('native context tokens did not reach refused arena growth')
            assert len(tokens) >= 8 and q.get(consumer.context, 40) == extent
            for _ in range(4):
                token_release(consumer, tokens.pop())
            result.put((tokens, dict(extent=extent, retained_context_tokens=len(tokens),
                                    actual_mremap_errno=errno.ENOMEM)))
        except BaseException as error:
            result.put((tokens, error))
    thread = threading.Thread(target=denied)
    thread.start()
    thread.join(120)
    assert not thread.is_alive(), 'native token saturation exceeded 120 seconds'
    tokens, facts = result.get_nowait()
    if isinstance(facts, BaseException):
        raise facts
    return tokens, facts


def case(owner_path, value_path, files, parent, progress):
    owner, carrier, values = setup(owner_path)
    before = set(os.listdir('/proc/self/fd'))
    runtime_raw = prior.make_runtime(carrier, files, parent)
    lease_raw = q.old.lease(carrier, runtime_raw)
    runtime = capture(owner, values, 1, runtime_raw)
    lease = capture(owner, values, 2, lease_raw, runtime)
    expected, captured, capture_pin = prior.captured_metadata(carrier, lease_raw)
    count = q.get(values.raw(47), 48)
    consumer = SharedConsumer(owner, value_path.read_bytes())
    handoff = queue.Queue()
    outcome = queue.Queue()
    notices = []
    tokens = []
    listener = None
    published = ZERO
    fill_facts = None
    raw = q.envelope(8, prior.request(lease))
    source = C.create_string_buffer(raw)
    with mmap.mmap(-1, q.OUT) as output:
        def execute():
            try:
                fd = private_listener(consumer.syscall_ip)
                handoff.put(fd)
                rc = owner.entry(source, len(raw), q.address(output), q.OUT,
                                 owner.context, q.CONTEXT_BYTES)
                assert rc == 0 and output[:8] == b'HIAGLOR1'
                assert source.raw == raw + b'\0'
                header = bytes(output[:128])
                kind = q.get(header, 16)
                at = q.get(header, 24)
                assert kind == 4 and at == q.CHILD
                result = dict(op=8, status=q.get(header, 8), kind=kind,
                              child_rc=q.get(header, 40), state=q.get(header, 48),
                              active=q.get(header, 56), cleanup_status=q.get(header, 72),
                              cleanup_caps=[struct.unpack_from('<3Q', header, 80 + i * 24)
                                            for i in range(q.get(header, 64))],
                              result=bytes(output[at:at + 16384]))
                outcome.put(result)
            except BaseException as error:
                handoff.put(error)
                outcome.put(error)
        thread = threading.Thread(target=execute)
        thread.start()
        try:
            listener = handoff.get(timeout=30)
            if isinstance(listener, BaseException):
                raise listener
            deadline = time.monotonic() + 120
            while thread.is_alive():
                assert time.monotonic() < deadline, 'native Info fault gate exceeded 120 seconds'
                readable, _, _ = select.select([listener], [], [], 0.2)
                if not readable:
                    continue
                notice = Notification()
                if LIBC.ioctl(listener, 0xc0502100, C.byref(notice)) < 0:
                    if C.get_errno() in (errno.EINTR, errno.ENOENT):
                        continue
                    raise OSError(C.get_errno(), 'SECCOMP_IOCTL_NOTIF_RECV')
                assert notice.data.ip == consumer.syscall_ip and notice.data.nr in (25, 39)
                phase = q.get(output, 256)
                cache_request = bytes(output[32768:32776]) == b'HIABVQ14' and q.get(output, 32776) == 66
                if notice.data.nr == 39 and phase == 75 and cache_request and fill_facts is None:
                    saved = bytes(output[2048:2176])
                    assert saved[:8] == b'HIABVR01' and q.get(saved, 8) == 0
                    assert q.get(saved, 16) == 12 and q.get(output, 1160) == 1
                    published = struct.unpack_from('<3Q', saved, 24)
                    assert all(published)
                    tokens, fill_facts = fill_actual_arena(consumer)
                deny = notice.data.nr == 25 and fill_facts is not None
                event = dict(tid=notice.pid, nr=notice.data.nr, ip=notice.data.ip,
                             phase=phase, cache_import=cache_request,
                             kernel_errno=errno.ENOMEM if deny else 0)
                notices.append(event)
                progress.write_text(json.dumps(dict(notifications=notices,
                                    published_main_cap=published, fill=fill_facts), indent=2) + '\n')
                response = Response(notice.id, 0, -errno.ENOMEM if deny else 0, 0 if deny else 1)
                assert LIBC.ioctl(listener, 0xc0182101, C.byref(response)) == 0, C.get_errno()
            thread.join(1)
        finally:
            if isinstance(listener, int):
                os.close(listener)
            thread.join(10)
        assert not thread.is_alive()
        result = outcome.get_nowait()
        if isinstance(result, BaseException):
            raise result
    assert fill_facts and any(row['kernel_errno'] == errno.ENOMEM for row in notices)
    for token in tokens:
        token_release(consumer, token)
    assert result['status'] != 0 and result['child_rc'] == 0 and result['cleanup_status'] != 0, clean_row(result)
    assert not result['cleanup_caps'], clean_row(result)
    reply = result['result']
    assert reply[:8] == b'HIABVR01' and q.get(reply, 8) == 0 and q.get(reply, 16) == 12
    assert struct.unpack_from('<3Q', reply, 24) == published
    delivered = values.keep(reply)
    assert q.get(values.raw(47), 48) == count + 1, 'lost or hidden native capability'
    recovered = prior.info_call(owner, values, lease)
    assert values.same(delivered, recovered)
    comparison = prior.compare_record(values, delivered, expected, captured)
    carrier.q(3, lease_raw)
    carrier.q(3, runtime_raw)
    prior.drop_all(values)
    return dict(case='published-main-info-survives-later-cache-enomem',
                captured_blob=capture_pin, notifications=notices,
                same_fixed_value_entry_and_arena=True,
                kernel_failure_after_successful_info60=True,
                fill=fill_facts, published_main_cap=published, failed_capture=clean_row(result),
                recovered_same_actual_info_object=True, returned_cap_explicitly_consumed=True,
                **comparison, **finish(owner, carrier, values, parent, before))


def main():
    parser = argparse.ArgumentParser()
    for name in ('owner', 'value', 'normalizer', 'proof', 'builder', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    assert platform.python_version() == '3.14.4'
    args.output.mkdir(parents=True, exist_ok=False)
    build = json.loads((args.owner.parent / 'build.json').read_bytes())
    assert pin(args.owner.read_bytes()) == build['build']['products']['hia-generation-lease-owner.so']
    assert pin(args.value.read_bytes()) == build['build']['products']['hia-generation-lease-values.core.bin']
    parent = args.output / 'runtime'
    parent.mkdir(mode=0o700)
    files = []
    try:
        for name in ('normalizer', 'proof', 'builder'):
            data = getattr(args, name).read_bytes()
            files.append((q.old.sealed(data), data))
        row = case(args.owner, args.value, files, parent, args.output / 'notifications.json')
        report = dict(schema='hia.native-info-owner.post-publication-allocation.v1',
                      passed=True, owner=pin(args.owner.read_bytes()), value=pin(args.value.read_bytes()),
                      oracle=platform.python_version(), case=row,
                      source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      allocator_published_cap_custody_qualified=True,
                      whole_public_runtime_qualified=False)
        (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(dict(passed=True, notifications=len(row['notifications']),
                              allocator_published_cap_custody_qualified=True)), flush=True)
    finally:
        for fd, _ in files:
            os.close(fd)


if __name__ == '__main__':
    main()
