"""Native VerifiedProgram records preserve the original non-authoritative constructor."""
from pathlib import Path
import argparse
import ctypes as C
import dataclasses
import hashlib
import json
import platform
import struct

from hepta.hia_program import VerifiedProgram
from tools.qualify_hia_result_value_resources import Values as PriorValues, NativeEngine, frame, word, ZERO
from tools.qualify_hia_result_value_records import equivalent


class Values(PriorValues):
    def raw(self, op, *, want=0, on=16384, **kw):
        if op != 67:
            return super().raw(op, want=want, on=on, **kw)
        wire = bytearray(frame(op, **kw))
        wire[:8] = b'HIABVQ05'
        rc, out = self.engine.call(bytes(wire), on=on)
        assert rc == 0 and out[:8] == b'HIABVR01', (op, rc, out[:128].hex())
        assert word(out, 8) == want, (op, word(out, 8), want, out[:128].hex())
        return out

    def program(self, canonical, structured=ZERO, cls=ZERO):
        return self.keep(self.raw(67, a=canonical, b=structured, c=cls))


def make_value(values, source):
    if type(source) is list:
        items = [make_value(values, item) for item in source]
        cap = values.lst(items)
        for item in items:
            values.drop(item)
        return cap
    if type(source) is tuple:
        items = [make_value(values, item) for item in source]
        cap = values.tuple(items)
        for item in items:
            values.drop(item)
        return cap
    if type(source) is dict:
        return values.dictionary(list(source.items()))
    return values.scalar(source)


def objects(values):
    arena = word(values.engine.context.raw, 16)
    assert arena
    return word(C.string_at(arena + 104, 8), 0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert platform.python_version() == '3.14.4'
    assert tuple(VerifiedProgram.__dataclass_fields__) == ('canonical_bytes', 'structured_bytes')
    assert VerifiedProgram.__dataclass_params__.frozen
    args.output.mkdir(parents=True, exist_ok=False)
    values = Values(NativeEngine(args.image))
    rows = []
    canonical_type = values.builtin(36)
    name = values.keep(values.raw(38, a=canonical_type))
    assert values.python(name) == VerifiedProgram.__name__
    values.drop(name)
    same_name = values.cls('VerifiedProgram', [])
    fake = values.instance(same_name)
    assert not values.isinst(fake, canonical_type)
    for cap in (same_name, fake):
        values.drop(cap)
    rows.append(dict(case='real-class-and-same-name-impostor', class_id=36))

    inputs = (b'', b'{}', b'\xff\x00', b'{"not":"a verified program"}',
              None, False, 10**160, -0.0, 'not bytes', [1, 'x'], {'x': 1}, (1, 'x'))
    for index, item in enumerate(inputs):
        left = make_value(values, item)
        # Omitted and explicit structured values both preserve the original
        # dataclass constructor; annotations alone do not validate arguments.
        for omitted in (True, False):
            structured = ZERO if omitted else values.scalar(b'{"separate":"input"}')
            original = VerifiedProgram(item) if omitted else VerifiedProgram(item, b'{"separate":"input"}')
            record = values.program(left, structured)
            assert word(values.raw(7, a=record), 16) == 12
            actual_type = values.keep(values.raw(36, a=record))
            assert values.same(actual_type, canonical_type) and values.isinst(record, canonical_type)
            fields = [values.field(record, i) for i in range(2)]
            assert values.same(fields[0], left)
            assert equivalent(values.python_value(fields[0]), original.canonical_bytes)
            assert equivalent(values.python_value(fields[1]), original.structured_bytes)
            if not omitted:
                assert values.same(fields[1], structured)
            values.raw(43, a=record, arg0=2, want=4)
            for cap in [record, actual_type, *fields]:
                values.drop(cap)
            if structured != ZERO:
                values.drop(structured)
        values.drop(left)
        rows.append(dict(case='constructor-keeps-real-fields-without-granting-authority',
                         index=index, original_type=type(item).__name__, default_and_explicit=True))

    subclass = values.cls('ProgramSubclass', [canonical_type])
    original_subclass = type('ProgramSubclass', (VerifiedProgram,), {})
    canonical = values.scalar(b'{}')
    record = values.program(canonical, cls=subclass)
    actual_type = values.keep(values.raw(36, a=record))
    assert values.same(actual_type, subclass)
    assert values.isinst(record, canonical_type) and values.isinst(record, subclass)
    assert isinstance(original_subclass(b'{}'), VerifiedProgram)
    values.drop(subclass)
    values.drop(actual_type)
    values.drop(canonical)
    field = values.field(record, 0)
    assert values.python(field) == b'{}'
    values.drop(field)
    values.drop(record)
    rows.append(dict(case='real-record-subclass-retains-actual-class-and-fields'))

    live_list = values.lst([])
    record = values.program(live_list)
    extra = values.scalar(91)
    values.raw(16, a=live_list, b=extra)
    field = values.field(record, 0)
    assert values.same(field, live_list) and values.python_value(field) == [91]
    values.drop(live_list)
    values.drop(extra)
    values.drop(record)
    assert values.python_value(field) == [91]
    values.drop(field)
    rows.append(dict(case='frozen-record-shares-arbitrary-mutable-field-and-keeps-it-alive'))

    canonical = values.scalar(b'{}')
    unrelated = values.cls('VerifiedProgram', [])
    before = word(values.raw(47), 48)
    for kwargs, want in ((dict(a=(1, 1, 1)), 1),
                         (dict(a=canonical, b=(1, 1, 1)), 1),
                         (dict(a=canonical, c=(1, 1, 1)), 1),
                         (dict(a=canonical, c=canonical), 2),
                         (dict(a=canonical, c=unrelated), 2)):
        values.raw(67, want=want, **kwargs)
        assert word(values.raw(47), 48) == before
    for cap in (canonical, unrelated, canonical_type):
        values.drop(cap)
    assert not values.held
    baseline = objects(values)
    child = values.lst([])
    cyclic = values.program(child)
    values.raw(16, a=child, b=cyclic)
    values.drop(child)
    values.drop(cyclic)
    assert word(values.raw(47), 48) == 0 and objects(values) == baseline
    rows.append(dict(case='invalid-cap-and-real-class-controls-and-record-cycle-collection',
                     invalid_cap_or_class_controls=5, actual_native_object_count_restored=True))

    valid = bytearray(frame(67))
    valid[:8] = b'HIABVQ05'
    malformed = []
    for magic in (b'HIABVQ01', b'HIABVQ02', b'HIABVQ03', b'HIABVQ04'):
        wire = bytearray(valid)
        wire[:8] = magic
        malformed.append(bytes(wire))
    for offset in (16, 96, 104, 112, 120):
        wire = bytearray(valid)
        struct.pack_into('<Q', wire, offset, 1)
        malformed.append(bytes(wire))
    malformed.extend((bytes(valid[:-1]), bytes(valid) + b'\0'))
    context = values.engine.context.raw
    for wire in malformed:
        rc, _ = values.engine.call(wire)
        assert rc == 0xfffffffd and values.engine.context.raw == context
    rows.append(dict(case='new-request-domain-preserves-original-protocols',
                     controls=len(malformed)))
    values.finish()
    report = dict(schema='hia.native-verified-program-record.qualification.v1',
                  passed=True, verified_program_record_qualified=True,
                  original_oracle='hepta.hia_program.VerifiedProgram',
                  original_fields=tuple(VerifiedProgram.__dataclass_fields__),
                  constructor_does_not_validate_annotations=True,
                  actual_native_image=True, image_sha256=hashlib.sha256(args.image.read_bytes()).hexdigest(),
                  oracle=platform.python_version(), groups=rows,
                  program_verification_authority_qualified=False,
                  verified_program_methods_qualified=False,
                  whole_public_runtime_qualified=False)
    (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(passed=True, groups=len(rows),
                          verified_program_record_qualified=True)), flush=True)


if __name__ == '__main__':
    main()
