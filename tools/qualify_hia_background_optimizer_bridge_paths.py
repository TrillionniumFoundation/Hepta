"""Integrate the live bridge loop with real filesystem operations.

The author mode executes actual x86 mechanical capsules and actual Linux
syscalls, with explicitly development-only Python execution of exact HIA
author functions. It never constitutes native HIA qualification. The private
leaf currently returns resolved strings; the public PosixPath factory is an
independent required integration and is not claimed by this qualifier.
"""
from __future__ import annotations
import argparse
import ast
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import tempfile
import traceback

from tools.qualify_hia_native_path_value import Pipeline, Flat, SIG, ptr, view, caps
from tools.qualify_hia_result_value_dict_iterator import put, word, wire, ZERO
from tools import generate_hia_background_optimizer_bridge_paths as owner
from tools import generate_hia_background_optimizer_bridge_paths_packer as packer
from tools import generate_hia_native_path_resolve as resolver
from tools import generate_hia_native_path_resolve_packer as resolver_packer
from tools import generate_hia_native_path_string_codec as codec
from tools import generate_hia_ndu_rank_native_owner_error as errors

MASK = (1 << 64) - 1
ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_SHA = 'd5a3c81eb0d7907fe872565b6ca6605708f8a6f13fd5a8d55788a9a13a095f7b'
_original = (ROOT / 'hepta/hia_background_optimizer.py').read_bytes()
assert hashlib.sha256(_original).hexdigest() == ORIGINAL_SHA
_class = next(n for n in ast.parse(_original).body if isinstance(n, ast.ClassDef) and n.name == 'BackgroundOptimizer')
_constructor = next(n for n in _class.body if isinstance(n, ast.FunctionDef) and n.name == '__init__')
_bridge_expression = next(n.value for n in _constructor.body if isinstance(n, ast.Assign)
                          and isinstance(n.targets[0], ast.Attribute) and n.targets[0].attr == '_bridge')
_bridge_code = compile(ast.Expression(_bridge_expression), '<original-BackgroundOptimizer-bridge-expression>', 'eval')


class Word(int):
    """The author interpreter's word-load has HIA unsigned subtraction."""
    def __rsub__(self, value):
        return Word((value - int(self)) & MASK)


def loaded(data, at):
    return Word(word(data, at))


def namespace(source):
    ns = dict(length=len, byte=lambda b, at: b[at], word_load=loaded,
              word_store=put, store=lambda b, at, value: b.__setitem__(at, value & 255),
              choose=lambda condition, yes, no: yes if condition else no)
    exec(compile('from __future__ import annotations\n' + source,
                 '<exact-HIA-author-development-only>', 'exec'), ns)
    return ns


def trampoline(function):
    return b'\x48\xb8' + struct.pack('<Q', ptr(function)) + b'\xff\xe0'


def object_text(raw):
    assert raw[:7] == b'\x7fELF\x02\x01\x01'
    sh = word(raw, 40)
    at, size = struct.unpack_from('<2Q', raw, sh + 64 + 24)
    assert at == 64 and at + size <= len(raw)
    return raw[at:at + size]


class Bridge:
    def __init__(self, images=None):
        self.native = images is not None
        self.path = Pipeline(images['path_value'] if images else None,
                             images['value'] if images else None)
        self.values = self.path.values
        self.failures = []
        self.calls = 0
        self.resolutions = 0
        self.transitions = 0
        self.unmap_faults = 0
        self.syscall_faults = []
        self.interrupted_writes = 0
        self.short_writes = 0
        self.value_faults = []
        self.drop_faults = []
        self.root_drop_calls = []
        self.w = C.create_string_buffer(262144)
        if images:
            self.image = Flat(Path(images['bridge']).read_bytes())
            self.resolve_image = Flat(Path(images['resolve']).read_bytes())
            self.codec_image = Flat(Path(images['codec']).read_bytes())
            self.error_image = Flat(Path(images['error']).read_bytes())
            codec_entry, error_entry = ptr(self.codec_image.f), ptr(self.error_image.f)
        else:
            self.owner_ns = namespace(owner.source_program())
            self.resolve_ns = namespace(resolver.program())
            self.codec_ns = namespace(codec.source_program())
            self.error_ns = namespace(errors.program())
            self.owner_function = SIG(self.owner_call)
            self.resolve_function = SIG(self.resolve_call)
            self.codec_function = SIG(self.codec_call)
            self.error_function = SIG(self.error_call)
            self.image = Flat(object_text(packer.reference_object([trampoline(self.owner_function)])))
            self.resolve_image = Flat(object_text(resolver_packer.reference_object([trampoline(self.resolve_function)])))
            codec_entry, error_entry = ptr(self.codec_function), ptr(self.error_function)
        for at, value in ((0, int.from_bytes(b'HIABBPC1', 'little')),
                          (8, ptr(self.path.value_func)), (16, C.addressof(self.path.context)),
                          (24, 256), (32, ptr(self.path.image.f)), (40, ptr(self.resolve_image.f)),
                          (48, error_entry), (56, os.getpid()), (72, codec_entry)):
            put(self.w, at, value)

    def owner_call(self, s, sn, o, on, w, wn):
        try:
            self.transitions += 1
            ov, wv = view(o, on), view(w, wn)
            action = self.owner_ns['bridge_paths'](view(s, sn), ov, wv)
            phase = word(ov, owner.C['PHASE'])
            if action == 1 and self.syscall_faults and phase == self.syscall_faults[0]:
                self.syscall_faults.pop(0)
                put(ov, owner.C['FEEDBACK'], MASK - 11)
                return 10
            if action == 1 and word(ov, 0) in (1, 18):
                if self.interrupted_writes:
                    self.interrupted_writes -= 1
                    put(ov, owner.C['FEEDBACK'], MASK - 3)
                    return 10
                if self.short_writes:
                    self.short_writes -= 1
                    put(ov, 32, min(3, word(ov, 32)))
            if action == 1 and word(ov, 0) == 11 and self.unmap_faults:
                self.unmap_faults -= 1
                put(ov, owner.C['FEEDBACK'], MASK - 4)
                return 10
            if action == 9 and phase == 61:
                self.resolutions += 1
            if action == 9 and phase in (501, 502):
                op = word(ov, owner.C['RQ'] + 8)
                self.root_drop_calls.append((op, caps(ov, owner.C['RQ'] + 24)))
                if self.drop_faults and op == self.drop_faults[0].get('op', 29):
                    fault = self.drop_faults.pop(0)
                    assert op == fault.get('op', 29)
                    if fault.get('consume'):
                        request = bytes(ov[owner.C['RQ']:owner.C['RQ'] + 128])
                        rc, actual = self.path.engine.call(request, 32768)
                        assert rc == 0 and word(actual, 96) == 1
                    reply = bytearray(128)
                    reply[:8] = b'HIABVR02'
                    for at, value in ((8, fault.get('status', 11)), (80, fault.get('pending', 0)),
                                      (88, fault.get('known', 1)), (96, int(fault.get('consume', False)))):
                        put(reply, at, value)
                    if 'malformed' in fault:
                        put(reply, fault['malformed'], 1)
                    ov[owner.C['RP']:owner.C['RP'] + 128] = reply
                    put(ov, owner.C['FEEDBACK'], 0)
                    return 10
            if action == 9 and self.value_faults and phase == self.value_faults[0]:
                self.value_faults.pop(0)
                reply = bytearray(128)
                reply[:8] = b'HIABVR01'
                put(reply, 8, 5)
                ov[owner.C['RP']:owner.C['RP'] + 128] = reply
                put(ov, owner.C['FEEDBACK'], 0)
                return 10
            return action
        except BaseException:
            self.failures.append(traceback.format_exc())
            return 0xfffffffd

    def resolve_call(self, s, sn, o, on, w, wn):
        try:
            return self.resolve_ns['resolve'](view(s, sn), view(o, on), view(w, wn))
        except BaseException:
            self.failures.append(traceback.format_exc())
            return 0xfffffffd

    def codec_call(self, s, sn, o, on, w, wn):
        try:
            return self.codec_ns['path_string_codec'](view(s, sn), view(o, on), view(w, wn))
        except BaseException:
            self.failures.append(traceback.format_exc())
            return 0xfffffffd

    def error_call(self, s, sn, o, on, w, wn):
        try:
            return self.error_ns['render'](view(s, sn), view(o, on), view(w, wn))
        except BaseException:
            self.failures.append(traceback.format_exc())
            return 0xfffffffd

    def call(self, dictionary=ZERO, op=0):
        self.calls += 1
        raw = bytearray(128)
        raw[:8] = b'HIABBPQ1'
        put(raw, 8, op)
        struct.pack_into('<3Q', raw, 16, *dictionary)
        sb = C.create_string_buffer(bytes(raw))
        out = C.create_string_buffer(b'\xa5' * (262144 + 32))
        before = self.w.raw[:64] + self.w.raw[72:128]
        rc = self.image.f(sb, 128, out, 262144, self.w, 262144)
        assert not self.failures and not self.path.failures, self.failures + self.path.failures
        assert rc == 0, (rc, word(out, 256), out.raw[:128].hex())
        assert out.raw[:8] == b'HIABBPR1'
        assert out.raw[262144:] == b'\xa5' * 32 + b'\0'
        assert sb.raw == bytes(raw) + b'\0'
        assert self.w.raw[:64] + self.w.raw[72:128] == before
        reply = out.raw[:128]
        assert reply[112:] == bytes(16)
        return reply

    def decode(self, reply):
        status = word(reply, 8)
        if status == 0:
            assert word(reply, 104) == 1
            cap = caps(reply, 16)
            self.path.adopt(cap)
            iterator = self.values.iterator(cap, 1)
            result = {}
            while True:
                row = self.values.next(iterator, 1)
                if row == ('end',):
                    break
                assert row[0] == 'value', row
                key, value = row[1]
                result[key] = value
            self.values.drop(iterator)
            self.values.drop(cap)
            return ('ok', result)
        if status == 1:
            cap = caps(reply, 40)
            self.path.adopt(cap)
            data = json.loads(self.path.read(cap))
            self.values.drop(cap)
            return ('error', data['type'], data['message'])
        if status == 2:
            cap = caps(reply, 64)
            self.path.adopt(cap)
            return ('exception', cap)
        return ('status', status, word(reply, 88), word(reply, 96))

    def finish(self):
        assert word(self.w, 64) == 0
        assert word(self.w, owner.C['CONVERTER_WORK'] + 128) == 0
        self.path.finish()


def original(dictionary):
    try:
        actual = eval(_bridge_code, {'Path': Path}, {'bridge': dictionary})
        return ('ok', {key: str(value) for key, value in actual.items()})
    except BaseException as exc:
        return ('error', type(exc).__name__, str(exc))


def dictionary_with_caps(client, items):
    values = client.values
    dictionary = values.keep(values.raw(4))
    for key, value in items:
        k = values.scalar(key)
        values.raw(10, a=dictionary, b=k, c=value)
        values.drop(k)
    return dictionary


def compare(client, items):
    caps_to_drop = [(key, client.values.scalar(value)) for key, value in items]
    dictionary = dictionary_with_caps(client, caps_to_drop)
    expected = original(dict(items))
    actual = client.decode(client.call(dictionary))
    assert actual == expected, (items, actual, expected)
    client.values.drop(dictionary)
    for _, value in caps_to_drop:
        client.values.drop(value)
    return dict(name='original-live-dictionary-path-expression', count=len(items), outcome=actual[0])


def mutations(images):
    rows = []
    for mutation in ('replace-next', 'grow', 'shrink', 'delete-current-add', 'delete-next-add', 'clear'):
        client = Bridge(images)
        v = client.values
        output = v.scalar('目录/source')
        next_value = v.scalar('.')
        actual_dictionary = [None]
        py_dictionary = {}
        calls = [0, 0]

        def change_python(self):
            calls[0] += 1
            if mutation == 'replace-next':
                py_dictionary['build_receipt'] = 'link/source'
            elif mutation == 'grow':
                py_dictionary['third'] = '.'
            elif mutation == 'shrink':
                del py_dictionary['build_receipt']
            elif mutation == 'delete-current-add':
                del py_dictionary['binary']
                py_dictionary['third'] = '.'
            elif mutation == 'delete-next-add':
                del py_dictionary['build_receipt']
                py_dictionary['third'] = '.'
            else:
                py_dictionary.clear()
            return '目录/source'

        def change_actual():
            calls[1] += 1
            d = actual_dictionary[0]
            if mutation == 'replace-next':
                v.set(d, 'build_receipt', 'link/source')
            elif mutation == 'grow':
                v.set(d, 'third', '.')
            elif mutation == 'shrink':
                v.delete(d, 'build_receipt')
            elif mutation == 'delete-current-add':
                v.delete(d, 'binary')
                v.set(d, 'third', '.')
            elif mutation == 'delete-next-add':
                v.delete(d, 'build_receipt')
                v.set(d, 'third', '.')
            else:
                v.delete(d, 'binary')
                v.delete(d, 'build_receipt')
            return 0, output

        obj = client.path.native_object('ChangesDictionary', change_actual)
        d = dictionary_with_caps(client, [('binary', obj), ('build_receipt', next_value)])
        actual_dictionary[0] = d
        py_dictionary.update(binary=type('ChangesDictionary', (), {'__fspath__': change_python})(), build_receipt='.')
        expected = original(py_dictionary)
        observed = client.decode(client.call(d))
        assert expected == observed and calls == [1, 1], (mutation, expected, observed, calls)
        client.finish()
        rows.append(dict(name='method-mutates-live-input-dictionary', mutation=mutation, method_calls=1, outcome=observed[0]))
    return rows


def aliases_and_exceptions(images):
    rows = []
    client = Bridge(images)
    v = client.values
    result = v.scalar('link/source')
    obj = client.path.native_object('ActualPathLike', lambda: (0, result))
    other = v.scalar('.')
    d = dictionary_with_caps(client, [('binary', obj), ('build_receipt', other)])
    py = type('ActualPathLike', (), {'__fspath__': lambda self: 'link/source'})()
    assert client.decode(client.call(d)) == original(dict(binary=py, build_receipt='.'))
    assert client.path.callback_calls == 1
    client.finish()
    rows.append(dict(name='actual-captured-method-result', passed=True))
    for base in ('link/source', b'link/source'):
        client = Bridge(images)
        v = client.values
        result = v.scalar(None)
        obj = client.path.native_object('OverridesFspath', lambda: (0, result), base)
        d = dictionary_with_caps(client, [('binary', obj)])
        py = type('OverridesFspath', (type(base),), {'__fspath__': lambda self: None})(base)
        assert client.decode(client.call(d)) == original(dict(binary=py))
        assert client.path.callback_calls == 0
        client.finish()
        rows.append(dict(name='native-base-subclass-method-bypass', base=type(base).__name__, passed=True))
    for exception in (TypeError('actual'), ValueError('actual'), KeyboardInterrupt('actual')):
        client = Bridge(images)
        v = client.values
        captured = client.path.native_object(type(exception).__name__)
        family = 1 if isinstance(exception, TypeError) else 2
        obj = client.path.native_object('Raises', lambda: (family, captured))
        d = dictionary_with_caps(client, [('binary', obj)])
        observed = client.decode(client.call(d))
        if family == 1:
            def raise_original(self):
                raise exception
            py = type('Raises', (), {'__fspath__': raise_original})()
            assert observed == original(dict(binary=py)), observed
        else:
            assert observed[0] == 'exception', observed
            assert word(v.raw(8, a=observed[1], b=captured), 48) == 1
        assert client.path.callback_calls == 1
        client.finish()
        rows.append(dict(name='captured-raised-object-preserves-identity-or-original-Path-TypeError', exception=type(exception).__name__, passed=True))
    return rows


def fault_cases():
    rows = []
    for fault in ('root-unmap', 'converter-drop', 'converter-unmap', 'value-pending'):
        client = Bridge()
        v = client.values
        result = v.scalar('link/source')
        obj = client.path.native_object('Retry', lambda: (0, result))
        d = dictionary_with_caps(client, [('binary', obj)])
        if fault == 'root-unmap':
            client.unmap_faults = 1
        elif fault == 'converter-drop':
            client.path.drop_faults = [dict(status=11, consumed=0)]
        elif fault == 'converter-unmap':
            client.path.munmap_faults = 1
        else:
            client.drop_faults = [dict(status=11, consume=True, pending=1),
                                  dict(op=31, status=0, consume=False, pending=0)]
        before = len(os.listdir('/proc/self/fd'))
        reply = client.call(d)
        assert (word(reply, 8), word(reply, 88), client.path.callback_calls) == (9, 1, 1), (fault, reply.hex())
        first_calls = list(client.root_drop_calls)
        reply = client.call(op=1)
        actual, expected = client.decode(reply), original(dict(binary='link/source'))
        assert actual == expected, (fault, actual, expected, reply.hex())
        assert client.path.callback_calls == 1
        if fault == 'value-pending':
            first_cap = first_calls[0][1]
            assert sum(cap == first_cap for op, cap in client.root_drop_calls if op == 29) == 1
            assert any(op == 31 for op, _ in client.root_drop_calls)
        assert len(os.listdir('/proc/self/fd')) == before
        client.finish()
        rows.append(dict(name='owned-cleanup-resume-without-method-replay', fault=fault, passed=True))
    for next_phase in (41, 49, 63, 71, 80):
        client = Bridge()
        v = client.values
        value = v.scalar('link/source')
        d = dictionary_with_caps(client, [('binary', value)])
        client.syscall_faults = [next_phase]
        before = len(os.listdir('/proc/self/fd'))
        reply = client.call(d)
        assert (word(reply, 8), word(reply, 88)) == (5, 0), (next_phase, reply.hex())
        assert client.syscall_faults == [] and len(os.listdir('/proc/self/fd')) == before
        client.finish()
        rows.append(dict(name='resource-allocation-refusal-closes-real-predecessors', next_phase=next_phase, passed=True))
    for next_phase in (2, 3, 81, 111):
        client = Bridge()
        v = client.values
        value = v.scalar('link/source')
        d = dictionary_with_caps(client, [('binary', value)])
        client.value_faults = [next_phase]
        before = len(os.listdir('/proc/self/fd'))
        reply = client.call(d)
        assert (word(reply, 8), word(reply, 88)) == (5, 0), (next_phase, reply.hex())
        assert client.value_faults == [] and len(os.listdir('/proc/self/fd')) == before
        client.finish()
        rows.append(dict(name='value-allocation-refusal-releases-real-earlier-references', next_phase=next_phase, passed=True))
    client = Bridge()
    client.short_writes, client.interrupted_writes = 100, 3
    rows.append(compare(client, [('binary', 'link/source'), ('build_receipt', '目录/source')]))
    client.finish()
    rows[-1]['name'] = 'actual-partial-transfers-and-pre-effect-EINTR'
    return rows


def cleanup_protocol_cases():
    ns, c = namespace(owner.source_program()), owner.C
    rows = []
    for status in (0, 1, 6, 11, 999):
        for known in (0, 1):
            for consumed in (0, 1):
                for pending in (0, 1):
                    out, work = bytearray(262144), bytearray(262144)
                    put(out, c['PHASE'], 501)
                    struct.pack_into('<3Q', out, c['ROOTCAP'], 123, 456, 789)
                    for at, value in ((0, c['VR2']), (8, status), (80, pending), (88, known), (96, consumed)):
                        put(out, c['RP'] + at, value)
                    ns['bridge_paths'](bytes(128), out, work)
                    valid = (known == 1 and status in (0, 1, 6, 11)
                             and (consumed == 0 or status in (0, 11))
                             and (status != 1 or pending == 0)
                             and (status != 0 or consumed == 1 and pending == 0))
                    assert (word(out, c['ROOTCAP']) == 0) == (valid and consumed == 1)
                    if status == 0 and known == consumed == 1 and pending == 0:
                        assert word(out, c['PHASE']) == 500 and word(out, c['CLEAN']) == 1
                    else:
                        expected = 1 if valid and consumed == pending else 2
                        assert word(work, 64) == expected, (status, known, consumed, pending)
                        if valid and pending:
                            assert word(out, c['V_PENDING']) == 1
                            saved = 128 + c['V_PENDING'] - 256
                            assert word(work, saved) == 1
                    rows.append(dict(name='explicit-consumption-reply-domain', status=status, known=known,
                                     consumed=consumed, pending=pending, passed=True))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--author', action='store_true')
    for name in ('bridge', 'value', 'path-value', 'resolve', 'codec', 'error'):
        parser.add_argument('--' + name + '-image')
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    images = {key: getattr(args, key + '_image') for key in ('bridge', 'value', 'path_value', 'resolve', 'codec', 'error')}
    assert args.author != any(images.values())
    assert args.author or all(images.values())
    if args.author:
        images = None
    groups = []
    temp_root = Path(os.environ.get('TMPDIR', Path.cwd() / 'tmp'))
    temp_root.mkdir(exist_ok=True, parents=True)
    previous = Path.cwd()
    with tempfile.TemporaryDirectory(prefix='bridge-paths-', dir=temp_root) as temporary:
        os.chdir(temporary)
        Path('目录').mkdir()
        Path('目录/source').write_text('actual filesystem fixture')
        Path('link').symlink_to('目录', target_is_directory=True)
        os.mkdir(b'invalid-\xff')
        client = Bridge(images)
        initial_descriptors = len(os.listdir('/proc/self/fd'))
        for items in ([], [('binary', '')], [('binary', '.'), ('build_receipt', 'link/source')],
                      [('binary', 'missing/a/../b'), ('build_receipt', '../child')],
                      [('binary', os.fsdecode(b'invalid-\xff')), ('build_receipt', '/tmp')],
                      [('binary', 'quotation"\\\n\t'), ('build_receipt', '目录/source')],
                      [('binary', None), ('build_receipt', '.')],
                      [('binary', b'not-a-str'), ('build_receipt', '.')],
                      [('binary', 1), ('build_receipt', '.')],
                      [('binary', str(Path.cwd() / '\ud800')), ('build_receipt', '.')]):
            groups.append(compare(client, items))
        assert len(os.listdir('/proc/self/fd')) == initial_descriptors
        client.finish()
        groups.extend(mutations(images))
        groups.extend(aliases_and_exceptions(images))
        if args.author:
            groups.extend(fault_cases())
            groups.extend(cleanup_protocol_cases())
        os.chdir(previous)
    report = dict(schema='hepta.hia.background-bridge-paths.qualification.v1',
                  scope='actual-native-components' if images else 'actual-mechanical-capsules-filesystem-with-development-authors',
                  native_hia_executed=bool(images), whole_native_runtime_qualified=False,
                  public_path_factory_integrated=False, python=platform.python_version(),
                  original_source_sha256=ORIGINAL_SHA,
                  passed=len(groups), groups=groups)
    paths = ('tools/generate_hia_background_optimizer_bridge_paths.py',
             'examples/hia_bootstrap/background_optimizer_bridge_paths.hepta',
             'tools/hia_background_optimizer_bridge_paths_bridge.S',
             'tools/generate_hia_background_optimizer_bridge_paths_packer.py',
             'examples/hia_bootstrap/background_optimizer_bridge_paths_packer.hepta',
             'tools/generate_hia_native_path_string_codec.py',
             'examples/hia_bootstrap/native_path_string_codec.hepta',
             'tools/generate_hia_native_path_value.py',
             'examples/hia_bootstrap/native_path_value.hepta',
             'tools/generate_hia_native_path_resolve.py',
             'tools/qualify_hia_background_optimizer_bridge_paths.py')
    report['source_pins'] = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('scope', 'native_hia_executed', 'passed')}), flush=True)


if __name__ == '__main__':
    main()
