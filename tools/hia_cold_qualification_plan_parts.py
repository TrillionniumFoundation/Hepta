"""Development composition of source-bound native qualification plans.

This file never executes a fixture or supplies a runtime oracle.  The serialized
plan invokes only independently constructed HIA tools and current native images.
"""
import struct

from tools.generate_hia_cold_qualification_plan import U64


def call(p, tool, request, *, label, argv=('child',), seconds=20):
    run = p.run(tool, request, argv=argv, seconds=seconds, label=label)
    receipt = p.resultpart(run, 0)
    p.word(receipt, 8, 0, label=label + ':exit-zero')
    result = p.resultpart(run, 1)
    stderr = p.resultpart(run, 2)
    empty = p.literal(b'')
    p.compare(stderr, empty, label=label + ':stderr-empty')
    p.drop(receipt, run, stderr, empty)
    return result


def check_flat(p, tool, observation, source, *, mode=0, cap=1 << 20,
               work=1 << 20, initial=b'', expected=b'', core=0, code=0,
               words=(), label='compile-check', initial_handle=None,
               expected_handle=None, cap_word=None, snapshot_handle=None,
               core_word=None):
    created = []
    def literal(raw):
        handle = p.literal(raw)
        created.append(handle)
        return handle
    ini = literal(initial) if initial_handle is None else initial_handle
    exp = literal(expected) if expected_handle is None else expected_handle
    start = literal((b'HIAQFV01' if snapshot_handle is None else b'HIAQLV01') + struct.pack('<Q', mode))
    source_n = p.length(source)
    cap_h = literal(struct.pack('<Q', cap)) if cap_word is None else cap_word
    middle = literal(struct.pack('<2Q', work, 0))
    ini_n, exp_n = p.length(ini), p.length(exp)
    if core_word is None:
        controls = literal(struct.pack('<3Q', core & U64, code & U64, len(words)))
    else:
        other_controls = literal(struct.pack('<2Q', code & U64, len(words)))
        controls = p.concat(core_word, other_controls)
        created.append(controls)
    snap_n = literal(bytes(8)) if snapshot_handle is None else p.length(snapshot_handle)
    result_n = p.length(observation)
    tail = literal(bytes(24))
    head = p.concat(start, source_n, cap_h, middle, ini_n, exp_n, controls, snap_n, result_n, tail)
    worddata = literal(b''.join(struct.pack('<3Q', *row) for row in words))
    snapshot = [] if snapshot_handle is None else [snapshot_handle]
    wire = p.concat(head, source, ini, exp, worddata, *snapshot, observation,
                    label=label + ':complete-observation')
    output = call(p, tool, wire, label=label)
    p.drop(*created, source_n, ini_n, exp_n, result_n, head, wire)
    if snapshot_handle is not None:
        p.drop(snap_n)
    return output


def observe(p, observer, image, source, *, cap=1 << 20, work=1 << 20,
            fill=0, shared=0, label, cap_word=None):
    start = p.literal(b'HIAOBS02')
    image_n, source_n = p.length(image), p.length(source)
    cap_h = p.literal(struct.pack('<Q', cap)) if cap_word is None else cap_word
    sizes = p.literal(struct.pack('<2Q', work, fill))
    outputfd = p.fdword(shared) if shared else p.literal(struct.pack('<Q', U64))
    wire = p.concat(start, image_n, source_n, cap_h, sizes, outputfd, image, source,
                    label=label + ':actual-flat-call-frame')
    observed = p.run(observer, wire, shared=shared, label=label)
    p.drop(start, image_n, source_n, sizes, outputfd, wire)
    if cap_word is None:
        p.drop(cap_h)
    return observed


def assert_gate(p, gate, *, label):
    expected = p.literal(b'HIAQOK01')
    p.compare(gate, expected, label=label)
    p.drop(gate, expected)


def build(p, observer, validator, compiler, source, *, label, **kwargs):
    run = observe(p, observer, compiler, source, label=label, **kwargs)
    checks = {key: value for key, value in kwargs.items() if key != 'fill' and key != 'shared'}
    image = check_flat(p, validator, run, source, label=label + ':compile-check', **checks)
    p.drop(run)
    return image


def utility(p, tool, mode, data=None, *, arg=0, arg_word=None, module=None, fill=165, label='byte-utility'):
    start = p.literal(b'HIAQUT01' + struct.pack('<Q', mode))
    extra = []
    if module is not None:
        name = p.literal(module)
        extra.append(name)
        arg = len(module)
    scalar = p.literal(struct.pack('<Q', arg)) if arg_word is None else arg_word
    size = p.length(data) if data is not None else p.literal(struct.pack('<Q', fill))
    pieces = [start, scalar, size, *extra]
    if data is not None:
        pieces.append(data)
    request = p.concat(*pieces)
    result = call(p, tool, request, label=label)
    p.drop(start, size, request, *extra)
    if arg_word is None:
        p.drop(scalar)
    return result


def observe_linked(p,observer,image,source,*,label,cap=1<<20,work=1<<20,
                   fill=0,shared=0,cap_word=None,zero_base=None,util=None):
    created=[]
    start=p.literal(b'HIAOBS03');image_n=p.length(image);source_n=p.length(source)
    cap_h=p.literal(struct.pack('<Q',cap)) if cap_word is None else cap_word
    sizes=p.literal(struct.pack('<2Q',work,fill))
    if cap_word is None and zero_base is not None:
        initial=p.slice(zero_base,0,cap+8)
    else:
        zero=p.literal(bytes(cap)) if cap_word is None else utility(p,util,0,arg_word=cap_word,fill=0,label=label+':snapshot-preimage')
        eight=p.literal(bytes(8));initial=p.concat(eight,zero);created.extend([eight,zero])
    snapshot=p.snapshot(initial)
    snapfd=p.fdword(snapshot);snaplow=p.slice(snapfd,0,4)
    outfd=p.fdword(shared) if shared else p.literal(struct.pack('<Q',U64))
    outlow=p.slice(outfd,0,4);descriptors=p.concat(outlow,snaplow)
    wire=p.concat(start,image_n,source_n,cap_h,sizes,descriptors,image,source,
                  label=label+':actual-linked-call-frame')
    observed=p.run(observer,wire,shared=shared,passed=(snapshot,),label=label)
    captured=p.slice(snapshot)
    p.drop(start,image_n,source_n,sizes,initial,snapshot,snapfd,snaplow,outfd,outlow,descriptors,wire,*created)
    if cap_word is None:
        p.drop(cap_h)
    return observed,captured


def cli(p, check, image, data, *, label, code=0, expected_handle=None,
        expected=None, argv=('child',), passed=()):
    run = p.run(image, data, seconds=15, owned=True, argv=argv,
                passed=passed, label=label + ':actual-kernel-exec')
    empty = p.literal(b'')
    if expected_handle is not None or expected is not None:
        gate = check_flat(p, check, run, empty, mode=4, cap=0, work=0,
                          expected=b'' if expected is None else expected,
                          expected_handle=expected_handle, code=code,
                          label=label + ':exact-CLI-observation')
        assert_gate(p, gate, label=label)
        p.drop(run, empty)
        return None
    result = check_flat(p, check, run, empty, mode=3, cap=0, work=0,
                        code=code, label=label + ':complete-CLI-stdout')
    p.drop(run, empty)
    return result
