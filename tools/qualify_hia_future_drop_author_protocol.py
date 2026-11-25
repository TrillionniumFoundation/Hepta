"""Offline transition probes, explicitly not native or full-VM qualification.

The independent wire matrices below compare original/candidate admission and
old replies, then check the new consumption record. Actual effects are never
implemented here; only pure author transitions are evaluated.
"""
from pathlib import Path
from hashlib import sha256
import argparse
import importlib.util
import json
import struct
import sys

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--source-root", type=Path, default=HERE)
parser.add_argument("--baseline-root", type=Path, default=HERE / "baseline")
parser.add_argument("--dependency-root", type=Path, default=HERE.parent / "root_native_recovery")
parser.add_argument("--output", type=Path, default=HERE)
args = parser.parse_args()
sys.path.insert(0, str(args.dependency_root))
baseline_authors = args.baseline_root / "tools"
if not baseline_authors.is_dir():
    baseline_authors = args.baseline_root
args.output.mkdir(parents=True, exist_ok=True)
NONE = (1 << 64) - 1
BAD = (1 << 32) - 3
cases = []

def put(buf, offset, value):
    struct.pack_into("<Q", buf, offset, value)

def get(buf, offset):
    return struct.unpack_from("<Q", buf, offset)[0]

def owner(directory, stem):
    directory_root = baseline_authors if directory == "baseline" else args.source_root / "tools"
    path = directory_root / ("generate_hia_" + stem + ".py")
    spec = importlib.util.spec_from_file_location(directory + stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    env = {"readbuf": bytearray, "mutbuf": bytearray, "u64": int, "u32": int,
           "length": len, "byte": lambda b, i: b[i],
           "store": lambda b, i, v: b.__setitem__(i, v), "word_load": get}
    exec(compile(mod.source_program(), str(path) + ":SOURCE", "exec"), env)
    return mod.C, env

def frame(n, magic, op):
    data = bytearray(n)
    data[:8] = magic
    put(data, 8, op)
    if n == 128 and op in (11, 15, 16):
        put(data, 80, 1)
    if n == 128 and op == 12:
        put(data, 48, 17)
    if n == 192 and op in (12, 22, 23):
        put(data, 96, 1)
    if n == 192 and op == 13:
        put(data, 88, 17)
    return data

def record(name, count):
    cases.append({"case": name, "checks": count, "passed": True})

for label, stem, n, outn, magics in (
    ("cell", "multiversion_background_future_cell", 128, 16384,
     (b"HIABFQ01", b"HIABFQ02", b"HIABFQ03")),
    ("public", "background_optimizer_future_public_owner", 192, 65536,
     (b"HIABFP01", b"HIABFP02")),
):
    bc, before = owner("baseline", stem)
    nc, after = owner("tools", stem)
    count = 0
    for magic in magics:
        for op in [*range(34), NONE]:
            original = frame(n, magic, op)
            for offset in [None, *range(16, n, 8)]:
                data = bytearray(original)
                if offset is not None:
                    put(data, offset, 1)
                a = bytearray(b"\xa5" * outn)
                b = bytearray(a)
                aw = bytearray(b"\x97" * 256)
                bw = bytearray(aw)
                ar = before["begin"](data, a, aw)
                br = after["begin"](data, b, bw)
                assert (ar, a, aw) == (br, b, bw), (label, magic, op, offset)
                count += 1
    record(label + "-old-profile-admission-byte-exact", count)
    count = 0
    for op in range(20 if n == 128 else 26):
        for status in range(12):
            a = bytearray((i * 7 + 3) & 255 for i in range(outn))
            put(a, bc["OP"], op)
            b = bytearray(a)
            if n == 128:
                ar = before["finish"](a, bytearray(256), status)
                br = after["finish"](b, bytearray(256), status)
                extent = 160 if op >= 15 else 128
            else:
                for kind in (0, 1, 2, 3, 4, 5, 6, 7, 100, 103, 107, 200):
                    aa, bb = bytearray(a), bytearray(b)
                    ar = before["finish"](aa, status, kind)
                    br = after["finish"](bb, status, kind)
                    assert (ar, aa[:128]) == (br, bb[:128]), (label, op, status, kind)
                    count += 1
                continue
            assert (ar, a[:extent]) == (br, b[:extent]), (label, op, status)
            count += 1
    record(label + "-old-header-byte-exact", count)

cc, cell = owner("tools", "multiversion_background_future_cell")
pc, public = owner("tools", "background_optimizer_future_public_owner")
count = 0
for op in (20, 21):
    for offset in [None, *range(16, 128, 8)]:
        data = frame(128, b"HIABFQ04", op)
        if offset is not None:
            put(data, offset, 1)
        out = bytearray(b"\xa5" * 16384)
        status = cell["begin"](data, out, bytearray(256))
        permitted = offset is None or (op == 20 and offset in (24, 32, 40))
        assert (status == 1) is permitted, (op, offset, status)
        if not permitted:
            assert status == BAD and out == b"\xa5" * 16384
        count += 1
for op in [*range(20), *range(22, 35), NONE]:
    assert cell["begin"](frame(128, b"HIABFQ04", op), bytearray(16384), bytearray(256)) == BAD
    count += 1
record("cell-new-exact-domain", count)

# No deallocation effect is executed: verify only that the pure continuation
# publishes the bit after, never before, the deallocation-return phase.
data = frame(128, b"HIABFQ04", 20)
out = bytearray(16384)
put(out, cc["OP"], 20)
put(out, cc["CAP"], 0x1234)
assert cell["release"](data, out, bytearray(256), 404) == 7
assert get(out, cc["DROP_CONSUMED"]) == 0 and get(out, cc["PHASE"]) == 405
assert cell["release"](data, out, bytearray(256), 405) == 8
assert get(out, cc["DROP_CONSUMED"]) == 1
cell["finish"](out, bytearray(256), 9)
assert out[:8] == b"HIABFR02" and get(out, 128) == 1
record("cell-consumption-published-at-deallocation-return", 3)

for pending in (0, 1):
    data = frame(128, b"HIABFQ04", 21)
    out, work = bytearray(16384), bytearray(256)
    put(out, cc["OP"], 21)
    put(out, cc["HELD"], 1)
    put(work, 40, 0x8000 if pending else 0)
    assert cell["locks"](data, out, work, 20) == 10
    assert get(out, cc["RETIRING_PENDING"]) == pending
    assert get(out, cc["RETIRING_KNOWN"]) == 1
    cell["finish"](out, work, 0)
    assert tuple(get(out, at) for at in (128, 136, 144, 152)) == (0, pending, 1, 0)
record("cell-retirement-query-serializes-locked-observation", 2)

count = 0
for status, consumed, failed in ((0, 1, 0), (1, 0, 0), (5, 0, 0), (6, 0, 0), (9, 0, 0), (9, 1, 1)):
    out = bytearray(65536)
    put(out, pc["OP"], 26)
    out[pc["FP"]:pc["FP"] + 8] = b"HIABFR02"
    put(out, pc["FP"] + 8, status)
    put(out, pc["FP"] + 120, failed)
    put(out, pc["FP"] + 128, consumed)
    assert public["drop_record"](out) == 10
    assert get(out, pc["DROP_KNOWN"]) == 1 and get(out, pc["DROP_CONSUMED"]) == consumed
    public["finish"](out, get(out, pc["ERROR"]), get(out, pc["RKIND"]))
    assert out[:8] == b"HIABFRP2" and (get(out, 96), get(out, 104)) == (consumed, 1)
    assert out[72:96] == bytes(24)
    assert (get(out, 8), get(out, 16)) == ((0, 0) if status == 0 else ((3, 107) if status == 1 else (1, 107)))
    count += 1
for offset, value in ((8, 2), (128, 0), (128, 2), (120, 2), (16, 1), (136, 1), (144, 1), (152, 1)):
    out = bytearray(65536)
    put(out, pc["OP"], 26)
    out[pc["FP"]:pc["FP"] + 8] = b"HIABFR02"
    put(out, pc["FP"] + 128, 1)
    put(out, pc["FP"] + offset, value)
    public["drop_record"](out)
    assert get(out, pc["DROP_KNOWN"]) == 0
    count += 1
record("public-strict-consumption-record-and-typed-error", count)

count = 0
for op in [*range(35), NONE]:
    for offset in [None, *range(16, 192, 8)]:
        data = frame(192, b"HIABFP03", op)
        # Optional fields set for older operations are not part of profile 03.
        data[16:] = bytes(176)
        if offset is not None:
            put(data, offset, 1)
        out = bytearray(b"\xa5" * 65536)
        status = public["begin"](data, out, bytearray(256))
        permitted = 26 <= op <= 29 and (
            offset is None or
            (op in (26, 27) and offset in range(16, 57, 8)) or
            (op == 28 and offset in (16, 24, 32)))
        assert (status == 1) is permitted, (op, offset, status)
        if not permitted:
            assert status == BAD and out == b"\xa5" * 65536
        count += 1
record("public-profile03-exact-26-through29-reserved-domain", count)

def value_reply(c, out, status, known, consumed, pending, poison=None):
    at = c["VP"]
    out[at:at+128] = bytes(128)
    out[at:at+8] = b"HIABVR02"
    for off, value in ((8, status), (80, pending), (88, known), (96, consumed)):
        put(out, at + off, value)
    if poison is not None:
        put(out, at + poison, 1)

count = 0
for c, implementation, size in ((cc, cell, 16384), (pc, public, 65536)):
    for op in (29, 30, 31):
        for status in (0, 1, 6, 11, 14, 2**63, NONE):
            for known in range(3):
                for consumed in range(3):
                    for pending in range(3):
                        out = bytearray(size)
                        value_reply(c, out, status, known, consumed, pending)
                        accepted = implementation["value_drop_record"](out, op)
                        expected = (known == 1 and consumed <= 1 and pending <= 1
                                    and status in (0, 1, 6, 11)
                                    and (consumed != 1 or status in (0, 11)))
                        if op == 31:
                            expected &= (status in (0, 6, 11) and consumed == 0
                                         and (status != 0 or pending == 0))
                        elif status == 0:
                            expected &= consumed == 1 and pending == 0
                        assert accepted == expected, (op, status, known, consumed, pending)
                        if accepted:
                            assert tuple(get(out, c[k]) for k in (
                                "VD_STATUS", "VD_CONSUMED", "VD_PENDING")) == (status, consumed, pending)
                        count += 1
    for offset in [*range(16, 80, 8), 104, 112, 120]:
        out = bytearray(size)
        value_reply(c, out, 0, 1, 1, 0, offset)
        assert not implementation["value_drop_record"](out, 30)
        count += 1
record("value02-completion-exact-status-domain-and-consumption-invariants", count)

# These probes inspect the policies' requested effects; they do not implement
# allocation, mutexes, memory writes or callee execution.
out, work = bytearray(65536), bytearray(256)
put(out, pc["OP"], 27)
put(out, pc["F"], 0x90000)
put(out, pc["LEASE"], 0xA0000)
assert public["release_lease"](bytearray(192), out, work, 182) == 7
assert get(out, pc["PHASE"]) == 183 and get(out, pc["DROP_CONSUMED"]) == 0
assert public["release_lease"](bytearray(192), out, work, 183) == 8
assert get(out, pc["DROP_CONSUMED"]) == 1 and get(out, pc["PHASE"]) == 184
put(out, pc["TEMP"], 0)  # actual list-head read result for the last lease
assert public["release_lease"](bytearray(192), out, work, 184) == 8
assert (get(out, 24), get(out, pc["TEMP"]), get(out, pc["RETIRE_OWNED"])) == (0x90000 + 128, 2, 1)
record("factory-drop-consumption-commit-precedes-registry-retirement-claim", 3)

count = 0
for state, fenced in ((0, 0), (1, 0), (1, 1), (2, 0), (2, 1), (3, 0)):
    out = bytearray(65536)
    put(out, pc["OP"], 28)
    put(out, pc["F"], 0x90000)
    put(out, pc["HEADER"] + 128, state)
    put(out, pc["HEADER"] + 144, fenced)
    action = public["factory_retry"](out, work)
    if state == 1 and not fenced:
        assert action == 8 and get(out, 24) == 0x90000 + 128
        assert get(out, pc["TEMP"]) == 2 and get(out, pc["RETIRE_OWNED"]) == 1
    else:
        assert action == 10 and get(out, pc["RETIRE_OWNED"]) == 0
        assert get(out, pc["DROP_KNOWN"]) == int(state in (1, 2))
    count += 1
out = bytearray(65536)
put(out, pc["F"], 0x90000)
put(out, pc["HEADER"] + 128, 2)
assert public["retire"](bytearray(192), out, work, 601) == 10
assert get(out, pc["PHASE"]) == 690  # no cell/value effect by a non-owner
count += 1
record("factory-retirement-claim-and-other-thread-does-not-retire", count)

count = 0
for op, field in ((27, 1), (28, 0)):
    out = bytearray(65536)
    put(out, pc["OP"], op)
    put(out, pc["DROP_CONSUMED"], field)
    put(out, pc["DROP_KNOWN"], 1)
    put(out, pc["DROP_PENDING"], 1)
    for i, word in enumerate((0x90000, 42, 93)):
        put(out, pc["FACTORY_ID"] + 8*i, word)
    public["finish"](out, 1, 107)
    assert out[:8] == b"HIABFRP2"
    assert tuple(get(out, at) for at in (24, 32, 40, 96, 104, 112)) == (0x90000, 42, 93, field, 1, 1)
    assert out[48:96] == bytes(48)
    count += 1
record("factory-reply-transfers-retirement-identity-never-consumed-lease", count)

count = 0
for attempt in (30, 31):
    states = [(0, 1, 1, 0), (11, 1, 1, 1), (11, 1, 1, 0),
              (11, 1, 0, 0), (6, 1, 0, 1), (NONE, 0, 0, 0)] if attempt == 30 else [
              (0, 1, 0, 0), (11, 1, 0, 1), (11, 1, 0, 0), (NONE, 0, 0, 0)]
    for status, known, consumed, pending in states:
        out, work = bytearray(65536), bytearray(256)
        token = struct.pack("<QQQ", 0x8765, 0xA1, 0xB2)
        work[128:152] = token if attempt == 30 else bytes(24)
        put(work, 24, 0 if attempt == 30 else 2)
        put(out, pc["OP"], 29)
        put(out, pc["VALUE_ATTEMPT"], attempt)
        value_reply(pc, out, status, known, consumed, pending)
        assert public["global_close"](out, work, 21) == 10
        if known == 0:
            assert get(work, 24) == 3 and get(out, pc["DROP_KNOWN"]) == 0
            if attempt == 30:
                assert work[128:152] == token
        else:
            assert get(out, pc["DROP_KNOWN"]) == 1
            if attempt == 30 and consumed:
                assert work[128:152] == bytes(24)
            elif attempt == 30:
                assert work[128:152] == token
            if status == 0:
                assert get(work, 24) == 1 and get(out, pc["DROP_PENDING"]) == 0
            elif attempt == 31:
                assert get(work, 24) == 2 and get(out, pc["DROP_PENDING"]) == 1
            elif consumed:
                assert get(work, 24) == (2 if pending else 3)
        count += 1
for state, expected_op in ((0, 30), (2, 31)):
    out, work = bytearray(65536), bytearray(256)
    put(work, 24, state)
    assert public["global_close"](out, work, 20) == 9
    assert out[pc["RQ"]:pc["RQ"]+8] == b"HIABVQ02"
    assert get(out, pc["RQ"] + 8) == expected_op
    assert get(out, pc["DROP_KNOWN"]) == 0
    count += 1
record("global-token-consumption-pending-retry-and-unknown-quarantine", count)

count = 0
for c, implementation, size, phase, name in (
    (cc, cell, 16384, 624, "cell-box"),
    (cc, cell, 16384, 631, "cell-token"),
    (pc, public, 65536, 605, "factory-token")):
    for status in (6, 11):
        for reported_pending in (0, 1):
            out, work = bytearray(size), bytearray(256)
            value_reply(c, out, status, 1, 0, reported_pending)
            if name == "factory-token":
                put(out, c["VALUE_ATTEMPT"], 31)
                action = implementation["retire_value"](out, work, phase)
                assert action == 10 and get(out, c["PHASE"]) == 690
            else:
                action = implementation["retire_values"](out, work, phase)
                assert action == 2 and get(out, c["AFTER"]) == 680
            # None of these failure continuations requests a store that clears
            # the object's pending mapping or consumes another original cap.
            count += 1
record("pending31-nonzero-never-clears-prior-actual-mapping-record", count)

count = 0
for status, pending in ((1, 0), (6, 0), (999, 0), (0, 1)):
    for role in ("global", "factory", "cell-token"):
        c = cc if role == "cell-token" else pc
        out = bytearray(16384 if role == "cell-token" else 65536)
        work = bytearray(256)
        value_reply(c, out, status, 1, 1, pending)
        if role == "global":
            token = struct.pack("<QQQ", 0x22200, 8, 9)
            work[128:152] = token
            put(out, c["VALUE_ATTEMPT"], 30)
            assert public["global_close"](out, work, 21) == 10
            assert work[128:152] == token and get(work, 24) == 3
            assert get(out, c["DROP_KNOWN"]) == 0
        elif role == "factory":
            put(out, c["F"], 0x90000)
            put(out, c["VALUE_ATTEMPT"], 30)
            assert public["retire_value"](out, work, 605) == 8
            # First requested write only fences the actual record. It never
            # clears F+72, whose consumption was not validly attested.
            assert get(out, 24) == 0x90000 + 144
        else:
            put(out, c["OBJ"], 0xA0000)
            assert cell["retire_values"](out, work, 622) == 8
            assert get(out, 24) == 0xA0000 + 184
        count += 1
record("malformed-consumption-record-preserves-original-owned-slot", count)

report = {"schema": "hepta.hia.future-drop-author-protocol-probes.v1",
          "passed": True, "checks": sum(x["checks"] for x in cases), "cases": cases,
          "execution_kind": "Python evaluation of pure author transitions; effects not executed",
          "native_execution_qualification_pass": False,
          "whole_native_runtime_closed": False}
(args.output / "author-protocol-probes.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
