"""Managed04 physical exit observation; thread-window fixtures are external.

This preserves the historical df6 pthread-window and join-error oracle while
using the self-bound managed04 protocol. Queue/Future/ref kernels are native.
Business callbacks and the unused/deferred-drain acknowledgement are fixtures;
this focused gate does not qualify the full managed business or public owner.
"""
from pathlib import Path
import argparse, ctypes as C, hashlib, json, os, struct, subprocess, sys, threading, time
from tools.qualify_hia_multiversion_background_queue import Queue, Owner, get

CALL = C.CFUNCTYPE(C.c_uint64, C.c_void_p, C.c_uint64, C.c_void_p,
                  C.c_uint64, C.c_void_p, C.c_uint64)

# The exact original df6 scheduling/fault injector is inserted below.
INJECTOR = '\n#define _GNU_SOURCE\n#include <pthread.h>\n#include <dlfcn.h>\n#include <stdint.h>\n#include <stdlib.h>\n#include <stdatomic.h>\n#include <unistd.h>\nstatic uintptr_t lo,hi;\nstatic _Atomic int gate,waiting,join_error;\nstatic _Atomic unsigned long joins;\nstruct launch {void *(*fn)(void *);void *arg;};\nvoid bg_alive_arm(uintptr_t a,uintptr_t b,int hold) {lo=a;hi=b;atomic_store(&gate,hold);atomic_store(&waiting,0);atomic_store(&joins,0);atomic_store(&join_error,0);}\nvoid bg_alive_release(void) {atomic_store(&gate,0);}\nvoid bg_alive_join_error(int e) {atomic_store(&join_error,e);}\nunsigned long bg_alive_read(unsigned long op) {return op?atomic_load(&joins):(unsigned long)atomic_load(&waiting);}\nstatic void *launch(void *p) {\n struct launch v=*(struct launch *)p;free(p);void *r=v.fn(v.arg);\n atomic_store(&waiting,1);while(atomic_load(&gate))usleep(100);return r;\n}\nint pthread_create(pthread_t *t,const pthread_attr_t *a,void *(*f)(void *),void *p) {\n int (*real)(pthread_t *,const pthread_attr_t *,void *(*)(void *),void *)=dlsym(RTLD_NEXT,"pthread_create");\n uintptr_t pc=(uintptr_t)__builtin_return_address(0);\n if(pc<lo || pc>=hi)return real(t,a,f,p);\n struct launch *v=malloc(sizeof *v);if(!v)return 12;v->fn=f;v->arg=p;\n int rc=real(t,a,launch,v);if(rc)free(v);return rc;\n}\nint pthread_join(pthread_t t,void **v) {\n uintptr_t pc=(uintptr_t)__builtin_return_address(0);\n if(pc>=lo && pc<hi){atomic_fetch_add(&joins,1);int e=atomic_exchange(&join_error,0);if(e)return e;}\n int (*real)(pthread_t,void **)=dlsym(RTLD_NEXT,"pthread_join");return real(t,v);\n}\n'


def put(buf, at, *words):
    struct.pack_into('<' + 'Q' * len(words), buf, at, *words)


class ManagedWorker:
    def __init__(self, image, queue, handler):
        self.q = queue
        self.lib = C.CDLL(str(image))
        self.f = self.lib.hia_background_worker_managed
        self.f.argtypes = [C.c_void_p, C.c_uint64] * 3
        self.f.restype = C.c_uint32
        self.w = C.create_string_buffer(512)
        self.value_context = C.create_string_buffer(256)
        self.errors, self.calls, self.drain_calls = [], 0, 0
        self.lock = threading.Lock()

        @CALL
        def callback(s, n, o, on, ctx, cn):
            try:
                assert n == 128 and on == 128
                assert ctx == C.addressof(queue.w) and cn == len(queue.w)
                raw = C.string_at(s, n)
                assert raw[:8] == b'HIABGWQ4'
                assert get(raw, 96) == 0 and get(raw, 104) == 1
                status = handler(self, raw)
                reply = bytearray(128)
                reply[:8] = b'HIABGWR3'
                put(reply, 8, status)
                put(reply, 56, 1)
                C.memmove(o, bytes(reply), 128)
                return 0x1234567800000000
            except BaseException as error:
                self.errors.append(repr(error))
                return 65

        @CALL
        def drain(s, n, o, on, ctx, cn):
            try:
                assert n == 128 and on == 8192 and cn == 256
                assert ctx == C.addressof(self.value_context)
                raw = C.string_at(s, n)
                assert raw[:8] == b'HIABVQ05' and get(raw, 8) == 56
                assert not any(raw[16:])
                reply = bytearray(128)
                reply[:8] = b'HIABVR01'
                C.memmove(o, bytes(reply), 128)
                self.drain_calls += 1
                return 0
            except BaseException as error:
                self.errors.append(repr(error))
                return 65

        self.callback, self.drain = callback, drain
        self.run(0, {16: C.cast(queue.f, C.c_void_p).value,
                     24: C.addressof(queue.w), 32: len(queue.w),
                     40: C.cast(callback, C.c_void_p).value,
                     48: C.addressof(queue.w), 56: len(queue.w),
                     64: C.cast(drain, C.c_void_p).value,
                     72: C.addressof(self.value_context), 80: 256})
        assert get(self.w, 112) == get(self.w, 120) == 1
        assert get(self.w, 160) == C.addressof(self.w)
        assert get(self.w, 168) == C.cast(self.f, C.c_void_p).value

    @staticmethod
    def packet(op, fields=None):
        raw = bytearray(128)
        raw[:8] = b'HIABGW04'
        put(raw, 8, op)
        for at, value in (fields or {}).items():
            put(raw, at, value)
        return bytes(raw)

    def run(self, op, fields=None, want=0, wire=None, context=None):
        raw = self.packet(op, fields) if wire is None else wire
        s = C.create_string_buffer(raw)
        o = C.create_string_buffer(8192)
        C.memset(o, 0xa5, len(o))
        ctx = self.w if context is None else context
        rc = self.f(s, len(raw), o, 8192, ctx, 512)
        with self.lock:
            self.calls += 1
        assert s.raw == raw + b'\0'
        if want >= 0xfffffff0:
            assert rc == want and o.raw[:128] == b'\xa5' * 128, (op, rc, want)
        else:
            assert rc == 0 and o.raw[:8] == b'HIABGWO2', (op, rc, o.raw[:128].hex())
            assert get(o, 8) == want, (op, get(o, 8), want, o.raw[:128].hex())
        return o.raw

    def settle(self, raw):
        a, b, c = struct.unpack_from('<3Q', raw, 16)
        return self.q.run(3, {16: get(raw, 56), 24: a, 32: b, 40: c})


def child(a):
    values = Owner(a.values)
    future = C.CDLL(str(a.future))
    hooks = C.CDLL(None)
    arm = hooks.bg_alive_arm
    arm.argtypes = [C.c_uint64, C.c_uint64, C.c_int]
    read = hooks.bg_alive_read
    read.argtypes = [C.c_uint64]
    read.restype = C.c_uint64
    release = hooks.bg_alive_release
    seterr = hooks.bg_alive_join_error
    seterr.argtypes = [C.c_int]
    rows, workers = [], []

    def query(worker, want=0):
        return worker.run(3, want=want)

    def make(handler=None, hold=1):
        queue = Queue(a.queue, values, future)
        worker = ManagedWorker(a.image, queue, handler or (lambda w, r: 0))
        workers.append(worker)
        maps = [line.split()[0].split('-') for line in Path('/proc/self/maps').read_text().splitlines()
                if str(a.image) in line]
        assert maps
        arm(min(int(x, 16) for x, y in maps), max(int(y, 16) for x, y in maps), hold)
        return queue, worker

    def wait(fn):
        until = time.monotonic() + 8
        while not fn():
            assert time.monotonic() < until, 'actual thread gate timeout'
            time.sleep(.0005)

    def done(queue, worker):
        worker.run(5)
        queue.destroy()
        assert get(values.w.raw, 16) == 0 and not worker.errors, worker.errors

    def row(name, detail):
        rows.append({'name': name, 'passed': True, 'detail': detail})

    queue, worker = make()
    assert get(query(worker), 24) == 0
    queue.run(4)
    worker.run(1)
    wait(lambda: read(0) == 1)
    # Inspect only the announced state before starting the active observers.
    assert get(worker.w, 24) == 3 and read(1) == 0
    replies, errors = [], []

    def call(op):
        try:
            replies.append(query(worker) if op == 3 else worker.run(2))
        except BaseException as error:
            errors.append(repr(error))

    threads = [threading.Thread(target=call, args=(3 if i < 12 else 2,)) for i in range(18)]
    for thread in threads:
        thread.start()
    wait(lambda: read(1) == 1)
    time.sleep(.03)
    assert not replies and not errors
    release()
    for thread in threads:
        thread.join(8)
        assert not thread.is_alive()
    assert len(replies) == 18 and all(get(r, 24) == 4 for r in replies)
    assert read(1) == 1 and not errors
    for _ in range(10):
        assert get(query(worker), 24) == 4
    assert read(1) == 1 and worker.drain_calls == 0
    done(queue, worker)
    row('announced-exit-waits-for-real-thread-return-once',
        {'observers': 12, 'joiners': 6, 'actual_join_calls': 1, 'announced_state': 3})

    entered, proceed, own = threading.Event(), threading.Event(), []

    def handler(worker, raw):
        own.append(get(query(worker), 24))
        entered.set()
        assert proceed.wait(8)
        owned = worker.settle(raw)
        job['future'].complete(7)
        queue.release_refs(owned)
        return 0

    queue, worker = make(handler, hold=0)
    job = queue.job(7)
    queue.admit(job)
    worker.run(1)
    assert entered.wait(5)
    queue.run(4)
    result = []
    joiner = threading.Thread(target=lambda: result.append(worker.run(2)))
    joiner.start()
    wait(lambda: read(1) == 1)
    start = time.monotonic()
    observed = query(worker)
    elapsed = time.monotonic() - start
    assert get(observed, 24) == 2 and elapsed < 1 and not result and own == [2]
    proceed.set()
    joiner.join(8)
    assert not joiner.is_alive() and get(result[0], 24) == 4 and read(1) == 1
    assert job['future'].result() == 7
    job['future'].destroy()
    assert worker.drain_calls == 1
    done(queue, worker)
    row('live-thread-query-does-not-wait-for-another-joiner',
        {'native_self_query': 2, 'external_query': 2, 'join_calls': 1, 'fixture_deferred_drain_calls': 1})

    for errno in (3, 22, 35):
        queue, worker = make(hold=0)
        queue.run(4)
        worker.run(1)
        wait(lambda: read(0) == 1)
        seterr(errno)
        observed = query(worker, want=6)
        assert get(observed, 16) == errno and get(observed, 24) == 3
        assert get(observed, 48) == 0 and read(1) == 1
        assert get(query(worker), 24) == 4 and read(1) == 2
        assert get(query(worker), 24) == 4 and read(1) == 2
        done(queue, worker)
    row('announced-exit-join-errors-retain-same-owner-for-retry', {'errnos': [3, 22, 35], 'joins_each': 2})

    queue, worker = make(hold=0)
    controls = 0
    for magic in (b'HIABGW01', b'HIABGW02', b'HIABGW03', b'HIABGW05'):
        before = worker.w.raw
        worker.run(3, wire=magic + worker.packet(3)[8:], want=0xfffffffd)
        assert worker.w.raw == before
        controls += 1
    for op in (6, 7, (1 << 64) - 1):
        before = worker.w.raw
        worker.run(op, want=0xfffffffd)
        assert worker.w.raw == before
        controls += 1
    for at in range(16, 128, 8):
        before = worker.w.raw
        worker.run(3, {at: 1}, want=0xfffffffd)
        assert worker.w.raw == before
        controls += 1
    for raw in (b'HIABGW04', worker.packet(3)[:127], worker.packet(3) + b'x'):
        before = worker.w.raw
        worker.run(3, wire=raw, want=0xfffffffd)
        assert worker.w.raw == before
        controls += 1
    clone = C.create_string_buffer(worker.w.raw, 512)
    worker.run(3, context=clone, want=65)
    for marker in (0, 2):
        put(clone, 120, marker)
        worker.run(3, context=clone, want=65)
    assert read(1) == 0
    queue.run(4)
    worker.run(1)
    wait(lambda: read(0) == 1)
    pid = os.fork()
    if pid == 0:
        try:
            query(worker, want=65)
            os._exit(0)
        except BaseException:
            os._exit(71)
    _, status = os.waitpid(pid, 0)
    assert status == 0 and read(1) == 0
    assert get(query(worker), 24) == 4
    done(queue, worker)
    row('managed-profile-domain-copy-marker-and-fork-isolation',
        {'private_guards': controls, 'copied_context_rejected': True, 'downgrade_and_invalid_marker_rejected': True, 'fork_without_join': True})
    values.run(9)
    print(json.dumps({'passed': len(rows), 'failed': 0, 'cases': rows,
                      'actual_worker_calls': sum(w.calls for w in workers),
                      'all_threads_reaped': True}), flush=True)


def main():
    parser = argparse.ArgumentParser()
    for name in ('image', 'queue', 'values', 'future', 'directory'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--child', action='store_true')
    args = parser.parse_args()
    if args.child:
        return child(args)
    args.directory.mkdir(parents=True, exist_ok=False)
    source = args.directory / 'thread-exit-window.c'
    source.write_text(INJECTOR)
    hook = args.directory / 'thread-exit-window.so'
    subprocess.run(['cc', '-shared', '-fPIC', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-o', str(hook), str(source), '-ldl'], check=True, capture_output=True)
    result = subprocess.run([sys.executable, '-u', '-m', 'tools.qualify_hia_background_worker_managed_alive', *sys.argv[1:], '--child'],
                            env={**os.environ, 'LD_PRELOAD': str(hook)}, capture_output=True, timeout=60)
    (args.directory / 'child.stdout').write_bytes(result.stdout)
    (args.directory / 'child.stderr').write_bytes(result.stderr)
    assert result.returncode == 0 and not result.stderr, (result.returncode, result.stdout, result.stderr)
    report = json.loads(result.stdout)
    report.update(schema='hia.background-managed-worker-exit-observation.v1',
                  whole_background_qualified=False, managed_business_qualified=False,
                  public_snapshot_entry_qualified=False,
                  image_sha256=hashlib.sha256(args.image.read_bytes()).hexdigest(),
                  external_thread_window_only=True,
                  business_and_deferred_drain_are_fixtures=True,
                  historical_oracle_revision='df6b1ef2302630f743fae6315e7d603df417fab2',
                  child_timeout_seconds=60,
                  injector_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest())
    (args.directory / 'qualification.json').write_text(json.dumps(report, indent=2) + '\n')
    print('MANAGED_WORKER_ALIVE_PASS', report['passed'], report['actual_worker_calls'], flush=True)


if __name__ == '__main__':
    main()
