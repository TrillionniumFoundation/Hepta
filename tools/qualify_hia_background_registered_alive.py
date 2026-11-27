"""Observe managed worker completion through the real registered snapshot.

The existing registered-method suite runs unchanged. The additional window
uses the historical pthread scheduling injector; all object registration,
Value ownership, queue shutdown, snapshot policy, and joins remain native.
"""
from pathlib import Path
import argparse, ctypes as C, hashlib, json, os, struct, subprocess, sys, threading, time, traceback
from tools import qualify_hia_background_native_methods as methods
from tools import qualify_hia_background_native_objects as objects
from tools import qualify_hia_background_native_context as context
from tools import qualify_hia_generation_lease_owner as q
from tools.qualify_hia_background_public_constructor import make
from tools.qualify_hia_background_worker_managed_alive import INJECTOR

get, cap, put = context.get, context.cap, context.put


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def save(path, report):
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')


def paths(a):
    # These change only external fixture locators. Every file is pinned in the
    # build/transfer receipts; no product dispatch or assertion is replaced.
    context.E = methods.E = objects.E = a.evidence_root


def window(a):
    paths(a)
    hooks = C.CDLL(None)
    hooks.bg_alive_arm.argtypes = [C.c_uint64, C.c_uint64, C.c_int]
    hooks.bg_alive_read.argtypes = [C.c_uint64]
    hooks.bg_alive_read.restype = C.c_uint64
    release = hooks.bg_alive_release
    f = context.Fixture(a)
    f.init()
    owner, v = f.f.bound.owner, f.f.v
    carrier, files = q.Carrier(owner), []
    for name in ('normalizer-84619bd.bin', 'proof-3fc158.bin', 'builder-539ce9.bin'):
        raw = (a.evidence_root / 'shared-custody' / name).read_bytes()
        files.append((q.old.sealed(raw), raw))
    parent = a.output / 'native-runtime'
    parent.mkdir()
    runtime = q.old.create(carrier, files, parent)
    cloned = carrier.q(2, runtime)
    assert cloned['row']['kind'] == 1
    captured = v.raw(48, arg0=1, tail=struct.pack('<3Q', *cloned['cap']))
    assert tuple(get(captured, at) for at in (80, 88, 96)) == (0, 1, 1)
    retained_runtime = v.keep(captured)
    baseline = q.old.scalar_program(None)
    bridge = {'binary': str(a.evidence_root / 'shared-custody/builder-539ce9.bin'),
              'build_receipt': str(context.B / 'docs/HIA_NATIVE_VALUE_RESOURCE_QUALIFICATION.json')}
    inputs = [retained_runtime, make(v, baseline), make(v, 'calculate'), make(v, bridge),
              (0, 0, 0), (0, 0, 0), (0, 0, 0)]
    native = objects.Objects(a.objects, f)
    public = methods.Methods(native)
    value_baseline, fd_baseline = get(v.raw(47), 48), context.open_fds()
    reply = native.call(0, caps=inputs)
    owned, record = cap(reply, 24), None
    record = native.record(owned)
    assert get(record, 56) == 511
    assert get(record, 8704 + 24) == 0 and get(record, 8704 + 120) == 1
    assert get(record, 8704 + 160) == C.addressof(record) + 8704
    worker_entry = f.images['worker'][1]
    assert get(record, 8704 + 168) == C.cast(worker_entry, C.c_void_p).value
    ranges = [line.split()[0].split('-') for line in Path('/proc/self/maps').read_text().splitlines()
              if str(a.worker) in line]
    assert ranges
    hooks.bg_alive_arm(min(int(lo, 16) for lo, hi in ranges),
                       max(int(hi, 16) for lo, hi in ranges), 1)
    threads, replies, errors = [], [], []

    def wait_for(predicate):
        deadline = time.monotonic() + 8
        while not predicate():
            assert time.monotonic() < deadline, 'actual registered worker window timeout'
            time.sleep(.0005)

    def observe():
        try:
            replies.append(public.call(4, owned))
        except BaseException as error:
            errors.append(repr(error))

    try:
        public.call(3, owned)
        initial = public.snapshot(owned, v)
        assert initial['worker_alive'] is True and initial['closed'] is False
        no_wait = make(v, False)
        started = time.monotonic()
        public.call(5, owned, args=(no_wait, (0, 0, 0)))
        nonwaiting_seconds = time.monotonic() - started
        assert nonwaiting_seconds < 1, 'shutdown(wait=False) waited for physical exit'
        v.drop(no_wait)
        wait_for(lambda: hooks.bg_alive_read(0) == 1)
        assert get(record, 8704 + 24) == 3 and hooks.bg_alive_read(1) == 0
        threads = [threading.Thread(target=observe) for _ in range(8)]
        for thread in threads:
            thread.start()
        wait_for(lambda: hooks.bg_alive_read(1) == 1 or replies or errors)
        assert hooks.bg_alive_read(1) == 1 and not replies and not errors, 'registered snapshot skipped physical pthread join'
        time.sleep(.03)
        assert not replies and not errors, 'registered snapshot reported before physical pthread exit'
        release()
        for thread in threads:
            thread.join(8)
            assert not thread.is_alive()
        assert len(replies) == 8 and not errors
        assert hooks.bg_alive_read(1) == 1 and get(record, 8704 + 24) == 4
        returned = [v.keep(reply, 32) for reply in replies]
        assert len(set(returned)) == 8
        snapshots = [v.python_value(value) for value in returned]
        assert all(row['worker_alive'] is False and row['closed'] is True for row in snapshots)
        for value in returned:
            v.drop(value)
        for _ in range(4):
            assert public.snapshot(owned, v)['worker_alive'] is False
        public.call(5, owned)
        assert hooks.bg_alive_read(1) == 1
        assert get(record, 72) == get(f.ctx, 184) == 0
        end = native.call(2, owned)
        assert get(end, 88) == 1 and get(f.ctx, 184) == get(f.ctx, 192) == 0
        assert get(v.raw(47), 48) == value_baseline and context.open_fds() == fd_baseline
        assert get(f.control(1), 24) == 2 and get(f.control(3), 24) == 3
        carrier.q(3, runtime)
        for fd, _ in files:
            os.close(fd)
        f.finish()
        assert not list(parent.iterdir())
        return {'schema': 'hia.BG.registered-managed-alive.window.v1', 'passed': True,
                'whole_background_closed': False, 'host_product_callbacks': False,
                'native_registered_object': True, 'native_public_methods_entry': True,
                'native_managed_snapshot': True, 'actual_physical_thread_window': True,
                'snapshots': len(snapshots), 'distinct_owned_values': len(returned),
                'actual_join_calls': 1, 'shutdown_wait_false_seconds': nonwaiting_seconds,
                'method_calls': public.calls, 'object_calls': native.calls,
                'dependencies': f.pins, 'worker': pin(a.worker.read_bytes()),
                'all_native_resources_retired': True}
    finally:
        release()
        for thread in threads:
            thread.join(8)


def main():
    parser = argparse.ArgumentParser()
    for name in ('owner', 'context', 'dependencies', 'ledger', 'jobs', 'core', 'consumers',
                 'snapshot', 'nested', 'constructor', 'pure', 'objects', 'worker',
                 'rank', 'evidence-root', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--child', action='store_true')
    parser.add_argument('--original-only', action='store_true')
    a = parser.parse_args()
    a.output.mkdir(parents=True, exist_ok=a.child)
    if a.child or a.original_only:
        report = {'passed': False, 'whole_background_closed': False}
        try:
            paths(a)
            report = methods.qualify(a) if a.original_only else window(a)
        except BaseException as error:
            report.update(error=repr(error), traceback=traceback.format_exc())
            raise
        finally:
            save(a.output / 'report.json', report)
        print('REGISTERED_MANAGED_ALIVE_PASS', 'original' if a.original_only else 'window', flush=True)
        return
    source = a.output / 'inject.c'
    source.write_text(INJECTOR)
    assert pin(source.read_bytes())['sha256'] == '03ec76da303915a0978f19e82ef7ba2865eb2476300536b24465ffa53cae50e2'
    library = a.output / 'inject.so'
    build = subprocess.run(['cc', '-O2', '-shared', '-fPIC', '-pthread', str(source), '-ldl', '-o', str(library)],
                           capture_output=True, timeout=30)
    (a.output / 'inject.stdout').write_bytes(build.stdout)
    (a.output / 'inject.stderr').write_bytes(build.stderr)
    assert build.returncode == 0 and not build.stderr
    env = dict(os.environ, LD_PRELOAD=str(library))
    try:
        result = subprocess.run([sys.executable, '-m', __package__ + '.qualify_hia_background_registered_alive',
                                 *sys.argv[1:], '--child'], capture_output=True, env=env, timeout=60)
    except subprocess.TimeoutExpired as error:
        (a.output / 'child.stdout').write_bytes(error.stdout or b'')
        (a.output / 'child.stderr').write_bytes(error.stderr or b'')
        save(a.output / 'timeout.json', {'passed': False, 'seconds': 60, 'whole_background_closed': False})
        raise
    (a.output / 'child.stdout').write_bytes(result.stdout)
    (a.output / 'child.stderr').write_bytes(result.stderr)
    assert result.returncode == 0, (result.returncode, result.stderr.decode(errors='replace'))
    report = json.loads((a.output / 'report.json').read_text())
    assert report['passed'] and report['actual_join_calls'] == 1 and report['snapshots'] == 8
    print('REGISTERED_MANAGED_ALIVE_PASS window', flush=True)


if __name__ == '__main__':
    main()
