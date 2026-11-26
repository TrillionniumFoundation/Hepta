"""Actual native GenerationInfo capture and lifetime through the sole lease owner.

The only product entry is the fixed enclosing owner. The development oracle
reads independently captured carrier metadata and original Python dataclasses;
it never writes a Value node, identity nonce, callback, or allocator result.
"""
from pathlib import Path
import argparse
import concurrent.futures
import ctypes as C
import hashlib
import json
import mmap
import os
import platform
import queue
import struct
import threading

from hepta.hia_multiversion import GenerationInfo, ScalarABI
from tools import qualify_hia_generation_lease_owner as q
from tools.qualify_hia_generation_lease_owner_resources import setup, capture, finish, pin, clean_row
from tools.qualify_hia_future_value_kinds import identity
from tools.qualify_hia_result_value_records import equivalent

ZERO = (0, 0, 0)
FIELDS = tuple(GenerationInfo.__dataclass_fields__)


def request(lease):
    return b'HIAGLIQ1' + struct.pack('<3Q', *lease)


def info_call(owner, values, lease):
    row = owner.call(8, request(lease))
    assert row['status'] == 0 and row['kind'] == 4 and row['child_rc'] == 0, clean_row(row)
    assert row['cleanup_status'] == 0 and not row['cleanup_caps'], clean_row(row)
    reply = row['result']
    assert reply[:8] == b'HIABVR01' and q.get(reply, 8) == 0 and q.get(reply, 16) == 12, reply[:128].hex()
    return values.keep(reply)


def captured_metadata(carrier, raw_lease):
    result = carrier.q(4, raw_lease, q.old.public_request(6), child=0)
    pointer, length, raw = q.old.detached(result)
    try:
        assert raw[:8] == b'HIAMVIR2'
        assert q.get(raw, 8) == q.get(raw, 16) == 0 and q.get(raw, 24) == length - 32
        data = json.loads(raw[32:])
        assert tuple(data) == FIELDS
        signatures = tuple(ScalarABI(row['function'], tuple(row['parameters']), row['result'])
                           for row in data['abi'])
        fields = dict(data)
        fields['abi'] = signatures
        fields['loaded_mapping'] = json.dumps(data['loaded_mapping'], sort_keys=True,
                                             separators=(',', ':')).encode()
        expected = GenerationInfo(**fields)
        return expected, data, pin(raw)
    finally:
        q.old.free(pointer)


def read_record(values, record):
    fields = []
    for index in range(len(FIELDS)):
        field = values.field(record, index)
        try:
            if index == 5:
                signatures = []
                members = values.copy_caps(field)
                try:
                    for member in members:
                        slots = [values.field(member, i) for i in range(3)]
                        try:
                            signatures.append(ScalarABI(*(values.python_value(slot) for slot in slots)))
                        finally:
                            for slot in slots:
                                values.drop(slot)
                finally:
                    for member in members:
                        values.drop(member)
                fields.append(tuple(signatures))
            else:
                fields.append(values.python_value(field))
        finally:
            values.drop(field)
    return GenerationInfo(*fields)


def compare_record(values, record, expected, captured):
    cls = values.builtin(30)
    actual_type = values.keep(values.raw(36, a=record))
    try:
        assert values.isinst(record, cls) and values.same(actual_type, cls)
    finally:
        values.drop(actual_type)
        values.drop(cls)
    actual = read_record(values, record)
    for name in FIELDS:
        left, right = getattr(actual, name), getattr(expected, name)
        assert equivalent(left, right), (name, left, right)
        assert type(left) is type(right), (name, type(left), type(right))
    assert all(type(row) is ScalarABI and type(row.parameters) is tuple for row in actual.abi)
    assert actual.loaded_mapping == json.dumps(captured['loaded_mapping'], sort_keys=True,
                                              separators=(',', ':')).encode()
    snapshot = values.keep(values.raw(44, a=record))
    try:
        assert equivalent(values.python_value(snapshot), expected.as_dict())
    finally:
        values.drop(snapshot)
    return dict(fields=len(FIELDS), actual_canonical_record=True,
                signatures=len(actual.abi), loaded_mapping_bytes=len(actual.loaded_mapping),
                original_as_dict_equal=True)


def drop_all(values):
    for cap in list(values.held):
        values.drop(cap)


def make_runtime(carrier, files, parent, program=None):
    if program is None:
        return q.old.create(carrier, files, parent)
    return carrier.q(1, payload=q.old.public_request(0, files=files, parent=os.fsencode(parent),
                     raw=q.old.rawdoc(program)), child=0)['cap']


def actual_close_and_survival(path, files, parent):
    owner, carrier, values = setup(path)
    before = set(os.listdir('/proc/self/fd'))
    raw_runtime = make_runtime(carrier, files, parent)
    raw_first = q.old.lease(carrier, raw_runtime)
    raw_second = q.old.lease(carrier, raw_runtime)
    runtime = capture(owner, values, 1, raw_runtime)
    first = capture(owner, values, 2, raw_first, runtime)
    second = capture(owner, values, 2, raw_second, runtime)
    expected, captured, blob = captured_metadata(carrier, raw_first)
    original = info_call(owner, values, first)
    repeated = info_call(owner, values, first)
    across = info_call(owner, values, second)
    assert values.same(original, repeated) and values.same(original, across)
    comparison = compare_record(values, original, expected, captured)
    carrier.q(4, raw_first, q.old.public_request(5), child=0)
    carrier.q(4, raw_second, q.old.public_request(5), child=0)
    closed_first = info_call(owner, values, first)
    closed_second = info_call(owner, values, second)
    assert values.same(original, closed_first) and values.same(original, closed_second)
    # The detached as_dict graph and individual ABI members remain independent
    # owners after every native runtime and lease reference has been released.
    detached = values.keep(values.raw(44, a=original))
    abi = values.field(original, 5)
    member = values.copy_caps(abi)[0]
    parameter = values.field(member, 1)
    for raw in (raw_first, raw_second, raw_runtime):
        carrier.q(3, raw)
    for cap in (first, second, runtime, repeated, across, closed_first, closed_second):
        values.drop(cap)
    assert read_record(values, original) == expected
    values.drop(original)
    assert equivalent(values.python_value(detached), expected.as_dict())
    assert values.python_value(parameter) == expected.abi[0].parameters
    values.drop(abi)
    assert values.python_value(parameter) == expected.abi[0].parameters
    values.drop(member)
    assert values.python_value(parameter) == expected.abi[0].parameters
    values.drop(parameter)
    values.drop(detached)
    return dict(case='actual-info-closed-lease-and-independent-survival',
                captured_blob=blob, repeated_and_same_generation_identity=True,
                closed_lease_property_access=True, independent_info_and_abi_lifetime=True,
                **comparison, **finish(owner, carrier, values, parent, before))


def generation_abi_identity(path, files, parent):
    owner, carrier, values = setup(path)
    before = set(os.listdir('/proc/self/fd'))
    raw_runtime = make_runtime(carrier, files, parent)
    raw_first = q.old.lease(carrier, raw_runtime)
    runtime = capture(owner, values, 1, raw_runtime)
    first = capture(owner, values, 2, raw_first, runtime)
    old_info = info_call(owner, values, first)
    old_abi = values.field(old_info, 5)
    old_members = values.copy_caps(old_abi)
    published = carrier.q(4, raw_runtime, q.old.public_request(
        1, raw=q.old.rawdoc(q.old.scalar_program('int.add.wrap', 0))), child=0)
    publication = q.old.release_detached(published)
    assert publication[:8] == b'HIAMVIR2'
    raw_second = q.old.lease(carrier, raw_runtime)
    second = capture(owner, values, 2, raw_second, runtime)
    new_info = info_call(owner, values, second)
    expected, captured, _ = captured_metadata(carrier, raw_second)
    compare_record(values, new_info, expected, captured)
    assert expected.generation == 1 and not expected.baseline
    assert not values.same(old_info, new_info)
    new_abi = values.field(new_info, 5)
    new_members = values.copy_caps(new_abi)
    assert values.same(old_abi, new_abi) and len(old_members) == len(new_members)
    assert all(values.same(a, b) for a, b in zip(old_members, new_members))
    old_params = values.field(old_members[0], 1)
    new_params = values.field(new_members[0], 1)
    assert values.same(old_params, new_params)
    for raw in (raw_first, raw_second, raw_runtime):
        carrier.q(3, raw)
    drop_all(values)
    return dict(case='same-runtime-shared-abi-across-actual-publication',
                different_generation_records=True, shared_abi_tuple=True,
                shared_scalar_abi_members=True, shared_parameter_tuple=True,
                **finish(owner, carrier, values, parent, before))


def different_runtime_identity(path, files, parent):
    owner, carrier, values = setup(path)
    before = set(os.listdir('/proc/self/fd'))
    records = []
    raw_caps = []
    for label in ('one', 'two'):
        child = parent / label
        child.mkdir()
        raw_runtime = make_runtime(carrier, files, child)
        raw_lease = q.old.lease(carrier, raw_runtime)
        runtime = capture(owner, values, 1, raw_runtime)
        lease = capture(owner, values, 2, raw_lease, runtime)
        info = info_call(owner, values, lease)
        records.append((info, values.field(info, 5), read_record(values, info)))
        raw_caps.extend((raw_lease, raw_runtime))
    a, b = records
    assert a[2].generation == b[2].generation == 0
    assert a[2].program_sha256 == b[2].program_sha256 and a[2].abi == b[2].abi
    assert not values.same(a[0], b[0]) and not values.same(a[1], b[1])
    am = values.copy_caps(a[1])
    bm = values.copy_caps(b[1])
    assert all(not values.same(x, y) for x, y in zip(am, bm))
    for raw in raw_caps:
        carrier.q(3, raw)
    drop_all(values)
    for child in parent.iterdir():
        assert not list(child.iterdir())
        child.rmdir()
    return dict(case='real-runtime-identity-not-equal-field-interning',
                equal_abi_values=True, independent_info_abi_and_members=True,
                **finish(owner, carrier, values, parent, before))


def generation_strong_identity(path, files, parent):
    owner, carrier, values = setup(path)
    before = set(os.listdir('/proc/self/fd'))
    raw_runtime = make_runtime(carrier, files, parent)
    raw_lease = q.old.lease(carrier, raw_runtime)
    runtime = capture(owner, values, 1, raw_runtime)
    lease = capture(owner, values, 2, raw_lease, runtime)
    first = info_call(owner, values, lease)
    first_id = identity(values, first)
    first_abi = values.field(first, 5)
    abi_id = identity(values, first_abi)
    values.drop(first_abi)
    values.drop(first)
    # No user Info/ABI capability exists. The actual generation and runtime
    # still own these objects, just as the original Python owners do.
    churn = [values.scalar('hold-new-object-' + str(i)) for i in range(128)]
    assert all(identity(values, cap) != first_id for cap in churn), 'live generation Info storage was reused'
    second = info_call(owner, values, lease)
    assert identity(values, second) == first_id, 'lease lost its actual strong GenerationInfo owner'
    values.drop(second)
    carrier.q(3, raw_lease)
    values.drop(lease)
    churn.extend(values.scalar('hold-after-lease-' + str(i)) for i in range(128))
    assert all(identity(values, cap) != first_id for cap in churn), 'selected generation Info storage was reused'
    raw_new = q.old.lease(carrier, raw_runtime)
    new_lease = capture(owner, values, 2, raw_new, runtime)
    third = info_call(owner, values, new_lease)
    assert identity(values, third) == first_id, 'live selected generation did not retain its Info object'
    third_abi = values.field(third, 5)
    assert identity(values, third_abi) == abi_id, 'runtime did not retain its immutable ABI tuple'
    carrier.q(3, raw_new)
    carrier.q(3, raw_runtime)
    drop_all(values)
    return dict(case='actual-generation-and-runtime-own-info-without-user-caps',
                lease_info_strong_identity=True, selected_generation_info_strong_identity=True,
                runtime_abi_strong_identity=True,
                **finish(owner, carrier, values, parent, before))


def concurrent_identity(path, files, parent):
    owner, carrier, values = setup(path)
    before = set(os.listdir('/proc/self/fd'))
    raw_runtime = make_runtime(carrier, files, parent)
    raw_lease = q.old.lease(carrier, raw_runtime)
    runtime = capture(owner, values, 1, raw_runtime)
    lease = capture(owner, values, 2, raw_lease, runtime)
    gate = threading.Barrier(8)
    def call(_):
        gate.wait(timeout=30)
        return owner.call(8, request(lease))
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        replies = list(pool.map(call, range(8)))
    infos = []
    for row in replies:
        assert row['status'] == row['child_rc'] == row['cleanup_status'] == 0 and not row['cleanup_caps'], clean_row(row)
        assert row['kind'] == 4 and row['result'][:8] == b'HIABVR01' and q.get(row['result'], 8) == 0
        infos.append(values.keep(row['result']))
    assert all(values.same(infos[0], cap) for cap in infos[1:])
    carrier.q(3, raw_lease)
    carrier.q(3, raw_runtime)
    drop_all(values)
    return dict(case='concurrent-first-info-capture-single-object', threads=8,
                all_returned_caps_own_same_object=True,
                **finish(owner, carrier, values, parent, before))


def allocator_failure(path, files, parent):
    owner, carrier, values = setup(path)
    before = set(os.listdir('/proc/self/fd'))
    raw_runtime = make_runtime(carrier, files, parent)
    raw_lease = q.old.lease(carrier, raw_runtime)
    runtime = capture(owner, values, 1, raw_runtime)
    lease = capture(owner, values, 2, raw_lease, runtime)
    original_lease = identity(values, lease)
    result = queue.Queue()
    def denied_growth():
        tokens = []
        try:
            q.deny_syscall(25, 12)
            initial_extent = q.get(owner.context, 552)
            for _ in range(65536):
                rc, reply = values.engine.call(q.value_wire(21))
                assert rc == 0 and reply[:8] == b'HIABVR01'
                status = q.get(reply, 8)
                if status:
                    assert status == 5 and not q.get(reply, 24), reply[:128].hex()
                    break
                tokens.append(struct.unpack_from('<3Q', reply, 24))
            else:
                raise AssertionError('actual arena failed to reach a refused mremap')
            assert len(tokens) >= 8 and q.get(owner.context, 552) == initial_extent
            # Make room for the owner's short-lived argument retain and random
            # workspace, while keeping the actual larger import allocation full.
            for _ in range(4):
                values.raw(22, a=tokens.pop())
            count = q.get(values.raw(47), 48)
            row = owner.call(8, request(lease))
            assert row['status'] != 0 or q.get(row['result'], 8) != 0, clean_row(row)
            if row['kind'] == 4 and row['result'][:8] == b'HIABVR01':
                assert not q.get(row['result'], 24), 'failed Info capture published an unowned cap'
            assert row['cleanup_status'] == 0 and not row['cleanup_caps'], clean_row(row)
            assert q.get(values.raw(47), 48) == count
            assert q.get(owner.context, 552) == initial_extent
            result.put((tokens, dict(kernel_mremap_errno=12, arena_extent=initial_extent,
                                    retained_context_tokens=len(tokens),
                                    failed_capture=clean_row(row),
                                    no_partial_cap_or_argument_retain_leak=True)))
        except BaseException as error:
            result.put((tokens, error))
    thread = threading.Thread(target=denied_growth)
    thread.start()
    thread.join(120)
    assert not thread.is_alive(), 'native allocator gate exceeded its fixed 120-second bound'
    tokens, outcome = result.get_nowait()
    for token in tokens:
        values.raw(22, a=token)
    if isinstance(outcome, BaseException):
        raise outcome
    assert identity(values, lease) == original_lease
    recovered = info_call(owner, values, lease)
    expected, captured, _ = captured_metadata(carrier, raw_lease)
    compare_record(values, recovered, expected, captured)
    carrier.q(3, raw_lease)
    carrier.q(3, raw_runtime)
    drop_all(values)
    return dict(case='actual-arena-enomem-preserves-info-custody-and-recovers',
                recovered_after_rejecting_thread_exit=True, **outcome,
                **finish(owner, carrier, values, parent, before))


def guards(path, files, parent):
    owner, carrier, values = setup(path)
    before = set(os.listdir('/proc/self/fd'))
    raw_runtime = make_runtime(carrier, files, parent)
    raw_lease = q.old.lease(carrier, raw_runtime)
    runtime = capture(owner, values, 1, raw_runtime)
    lease = capture(owner, values, 2, raw_lease, runtime)
    none = values.scalar(None)
    count = q.get(values.raw(47), 48)
    for bad in (ZERO, (1, 1, 1), raw_lease, raw_runtime, runtime, none,
                (lease[0], lease[1] ^ 1, lease[2]), (lease[0], lease[1], lease[2] ^ 1)):
        row = owner.call(8, request(bad))
        assert row['status'] == 1 and not row['cleanup_caps'], clean_row(row)
        assert q.get(values.raw(47), 48) == count
    malformed = [request(lease)[:-1], request(lease) + b'\0',
                 b'BADMAGIC' + request(lease)[8:]]
    with mmap.mmap(-1, q.OUT) as output:
        for payload in malformed:
            raw = q.envelope(8, payload)
            source = C.create_string_buffer(raw)
            output[:128] = b'\xa5' * 128
            context = bytes(owner.context)
            rc = owner.entry(source, len(raw), q.address(output), q.OUT,
                             owner.context, q.CONTEXT_BYTES)
            assert rc == q.BAD and output[:128] == b'\xa5' * 128
            assert bytes(owner.context) == context and source.raw == raw + b'\0'
    carrier.q(3, raw_lease)
    carrier.q(3, raw_runtime)
    drop_all(values)
    return dict(case='info-real-lease-authority-and-no-write-wire-guards',
                invalid_caps=8, malformed_frames=len(malformed),
                **finish(owner, carrier, values, parent, before))


CASES = (
    ('closed-survival', actual_close_and_survival),
    ('generation-abi', generation_abi_identity),
    ('different-runtime', different_runtime_identity),
    ('concurrent', concurrent_identity),
    ('allocator', allocator_failure),
    ('guards', guards),
    ('strong-generation-identity', generation_strong_identity),
)


def main():
    parser = argparse.ArgumentParser()
    for name in ('owner', 'value', 'normalizer', 'proof', 'builder', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--cases', nargs='+', choices=[name for name, _ in CASES],
                        help='Diagnostic selection; a subset never grants complete Info qualification.')
    args = parser.parse_args()
    assert platform.python_version() == '3.14.4'
    args.output.mkdir(parents=True, exist_ok=False)
    build = json.loads((args.owner.parent / 'build.json').read_bytes())
    assert pin(args.owner.read_bytes()) == build['build']['products']['hia-generation-lease-owner.so']
    assert pin(args.value.read_bytes()) == build['build']['products']['hia-generation-lease-values.core.bin']
    selected = set(args.cases or [name for name, _ in CASES])
    files = []
    rows = []
    for name in ('normalizer', 'proof', 'builder'):
        raw = getattr(args, name).read_bytes()
        files.append((q.old.sealed(raw), raw))
    try:
        for name, function in CASES:
            if name not in selected:
                continue
            parent = args.output / name
            parent.mkdir(mode=0o700)
            row = function(args.owner, files, parent)
            rows.append(row)
            (args.output / (name + '.json')).write_text(json.dumps(row, indent=2) + '\n')
            (args.output / 'progress.json').write_text(json.dumps(rows, indent=2) + '\n')
            print('OWNER_INFO_CASE', name, flush=True)
        complete = selected == {name for name, _ in CASES}
        report = dict(schema='hepta.hia.generation-info-owner.qualification.v1',
                      passed=True, selected_cases=sorted(selected), complete_case_set=complete,
                      generation_info_owner_qualified=complete,
                      same_generation_info_and_runtime_abi_identity_qualified=complete,
                      owner=pin(args.owner.read_bytes()), value=pin(args.value.read_bytes()),
                      original_oracle='hepta.hia_multiversion.GenerationInfo/ScalarABI',
                      oracle=platform.python_version(), cases=rows,
                      source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      whole_public_runtime_qualified=False)
        (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(dict(passed=True, cases=len(rows),
                              generation_info_owner_qualified=complete)), flush=True)
    finally:
        for fd, _ in files:
            os.close(fd)


if __name__ == '__main__':
    main()
