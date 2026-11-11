"""New actual-image private record protocol controls; not namespace effects."""
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import resource
import struct
import sys
import time
import traceback
resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
from records_harness_recovered_r2 import Actual, BAD, M, capture, forbid_retained, observed_value

OUT = Path(sys.argv[1])
SELF = Path(__file__).resolve()
test_before = SELF.read_bytes()
actual = Actual(OUT)
(OUT / "test-source-before.json").write_text(json.dumps(dict(path=str(SELF), sha256=sha256(test_before).hexdigest(), bytes=len(test_before)), sort_keys=True) + "\n")
rows = []
start = time.monotonic_ns()
summary = dict(status="INCOMPLETE", scope="PRIVATE_RECORD_FRAME_PROTOCOL_NOT_ARBITRARY_SOURCE_AUTHENTICATION_OR_NAMESPACE",
               cpu_limit_seconds=90, address_space_bytes=1 << 30)
source = capture(["request", {"result": [1, 2]}], lease=881)
command = actual.command(source, 0)

def word(raw, at):
    return struct.unpack_from("<Q", raw, at)[0]

def change(raw, at, value):
    raw = bytearray(raw)
    struct.pack_into("<Q", raw, at, value)
    return bytes(raw)

def invoke(s, c, state, label):
    work = actual.buffer(len(state), state)
    with ExitStack() as stack:
        forbid_retained(stack)
        ret, _, after, _ = actual.call("records", s, c, work, len(state), label)
    return ret, after

def row(label, **extra):
    item = dict(case=label, status="PASS", **extra)
    rows.append(item)
    with (OUT / "cases.jsonl").open("a") as f:
        f.write(json.dumps(item, sort_keys=True) + "\n")

def bad(label, s, c, state=None, reason=None):
    state = bytes(1024) if state is None else state
    ret, after = invoke(s, c, state, label)
    assert ret == BAD, (label, ret, struct.unpack_from("<16Q", after, 256))
    assert word(after, 8) == 3, (label, "full workspace refusal not poisoned")
    if reason is not None:
        assert word(after, 192) == reason, (label, word(after, 192), reason)
    again, final = invoke(source, command, after, label + "/after-poison")
    assert again == BAD and final == after, (label, "poison did more work")
    row(label, expected="permanent-refusal", reason=word(after, 192),
        source=actual.save(s), command=actual.save(c), before=actual.save(state), after=actual.save(after))

def event(state):
    return struct.unpack_from("<16Q", state, 256)

def finish(s, c, state, label):
    calls = 0
    while True:
        ret, state = invoke(s, c, state, label + "/" + str(calls))
        calls += 1
        assert ret == 384
        e = event(state)
        if e[1] == 1:
            assert e[5] > len(state)
            state = state + bytes(e[5] - len(state))
            continue
        assert e[1] in (0, 3), e
        return state, e, calls

try:
    for length in (0, 1, 63, 64, 95, 97, 128):
        bad("command-length-" + str(length), source, (command + bytes(128))[:length], reason=1)
    for at, values in ((0, (0, M(b"BADMAGIC"))), (8, (0,)), (16, (0,)), (24, (2, (1 << 64) - 1))):
        for value in values:
            bad("command-field-%s-%s" % (at, value), source, change(command, at, value), reason=1)
    for at in range(48, 96, 8):
        bad("command-reserved-" + str(at), source, change(command, at, 1), reason=3)
    for at in (32, 40):
        for value in (0, word(source, 16) + 1, (1 << 64) - 1):
            bad("command-root-%s-%s" % (at, value), source, change(command, at, value), reason=4)
    for at in (0, 7, 15, 31, 255, 511, 768, 1023):
        state = bytearray(1024)
        state[at] = 17
        bad("initial-nonzero-workspace-" + str(at), source, command, bytes(state), reason=7 if 8 <= at < 16 else 5)
    for at, value in ((0, 0), (8, 0), (16, 0), (48, len(source) + 1), (56, 1)):
        bad("source-graph-header-" + str(at), change(source, at, value), command, reason=2)
    bad("source-graph-truncated", source[:-1], command, reason=2)
    bad("source-graph-trailing", source + b"x", command, reason=2)

    ret, grow = invoke(source, command, bytes(1024), "initial-grow")
    assert ret == 384 and event(grow)[1] == 1 and event(grow)[5] > 1024
    row("initial-grow", needed=event(grow)[5], before=actual.save(grow))
    for at in range(0, 96, 8):
        bad("grow-command-drift-" + str(at), source, change(command, at, word(command, at) ^ 1), grow, reason=10)
    bad("grow-command-short", source, command[:-1], grow, reason=9)
    bad("grow-source-length-drift", source + b"x", command, grow, reason=7)
    for at in range(0, 64, 8):
        bad("grow-source-header-drift-" + str(at), change(source, at, word(source, at) ^ 1), command, grow, reason=8)
    terminal, final_event, calls = finish(source, command, grow, "finish-original")
    assert observed_value(terminal[final_event[6]:final_event[6] + final_event[7]])["status"] == "completed"
    ret, repeated = invoke(source, command, terminal, "completed-reuse")
    assert ret == BAD and repeated == terminal
    row("completed-reuse-refused", calls=calls)

    pending_source = capture(["request", {"message": "reject", "type": "ValueError", "pending_slot_snapshot": False}], lease=883)
    pending_command = actual.command(pending_source, 1)
    ret, waiting = invoke(pending_source, pending_command, bytes(1024), "pending-publish")
    assert ret == 384 and event(waiting)[1] == 2
    seq = event(waiting)[4]
    publication = capture({"id": "snapshot", "kind": "slot-snapshot", "sha256": "a" * 64}, lease=884)
    ack = struct.pack("<8Q", M(b"HIASRR01"), 981, 1, seq, 0, len(publication), 0, 0) + publication
    bad("publisher-replay-original-command", pending_source, pending_command, waiting, reason=11)
    for length in (0, 63, 64, 127, 191):
        bad("publisher-short-ack-" + str(length), pending_source, ack[:length], waiting, reason=11)
    for at, value in ((0, 0), (8, 982), (16, 2)):
        bad("publisher-identity-" + str(at), pending_source, change(ack, at, value), waiting, reason=11)
    for at, value in ((24, seq + 1), (32, 2), (40, len(publication) + 1), (48, 1), (56, 1)):
        bad("publisher-correlation-" + str(at), pending_source, change(ack, at, value), waiting, reason=12)
    for at, value in ((64, 0), (72, 0), (112, len(publication) + 1), (120, 1)):
        bad("publisher-graph-header-" + str(at), pending_source, change(ack, at, value), waiting, reason=13)
    ret, ack_grow = invoke(pending_source, ack, waiting, "publisher-accepted-grow")
    assert ret == 384 and event(ack_grow)[1] == 1 and word(ack_grow, 240) == 3
    for at in range(0, 128, 8):
        bad("publisher-held-ack-drift-" + str(at), pending_source, change(ack, at, word(ack, at) ^ 1), ack_grow, reason=16)
    bad("publisher-held-ack-size", pending_source, ack + b"x", ack_grow, reason=15)
    terminal, e, calls = finish(pending_source, ack, ack_grow, "publisher-exact-retry")
    got = observed_value(terminal[e[6]:e[6] + e[7]])
    assert got["error"]["details_artifact"] == {"id": "snapshot", "kind": "slot-snapshot", "sha256": "a" * 64}
    assert e[13] == 884 and e[1] == 0
    row("publisher-exact-retry-no-republish", calls=calls, consumed_publisher_lease=e[13])
    failed_ack = change(ack, 32, 1)
    terminal, e, calls = finish(pending_source, failed_ack, waiting, "publisher-failed-observation")
    assert e[1] == 3 and observed_value(terminal[e[6]:e[6] + e[7]]) == {"id": "snapshot", "kind": "slot-snapshot", "sha256": "a" * 64}
    row("publisher-failure-propagated-not-rejected-record", calls=calls)

    # Deliberate invalid borrowed extents cannot always poison unreachable bytes.
    for size in (0, 1, 8, 255, 1023):
        ret, short = invoke(source, command, bytes(size), "short-workspace-" + str(size))
        assert ret == BAD and short == bytes(size)
        row("short-workspace-" + str(size), scope="driver-must-discard-lease-no-native-poison-claim")
    overflow = change(grow, 32, (1 << 64) - 1)
    ret, poisoned = invoke(source, command, overflow, "event-sequence-overflow")
    assert ret == BAD and word(poisoned, 8) == 3
    ret, repeated = invoke(source, command, poisoned, "event-sequence-after-poison")
    assert ret == BAD and repeated == poisoned
    row("event-sequence-overflow-poisoned", stale_event_not_consumed=True)

    # The ABI binds a private issuer lease, not arbitrary same-shape replacement.
    altered = bytearray(source)
    original = b"result"
    pos = source.find(original)
    assert pos >= 64
    altered[pos:pos + len(original)] = b"RESULT"
    assert bytes(altered[:64]) == source[:64]
    terminal, e, calls = finish(bytes(altered), command, grow, "private-same-shape-replacement")
    got = observed_value(terminal[e[6]:e[6] + e[7]])
    assert "RESULT" in got["result"]
    row("private-same-header-replacement-is-not-authentication", accepted_private_control=True,
        requirement="fixed-executor-retains-original-immutable-source-lease", calls=calls)
    summary.update(status="PASS", cases=len(rows), entries=actual.entries)
except BaseException as exc:
    summary.update(status="FAIL", cases=len(rows), entries=actual.entries, error_class=type(exc).__name__, error=str(exc))
    traceback.print_exc()
    raise
finally:
    summary["wall_ns"] = time.monotonic_ns() - start
    summary["test_source_unchanged"] = SELF.read_bytes() == test_before
    actual.close()
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True), flush=True)
    assert summary["test_source_unchanged"]
