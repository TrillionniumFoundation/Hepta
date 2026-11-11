"""Full-byte CoreVM replay for NEW FS-r4 including actual F_GETLK trace records.

Actual primitive replies are observations, not synthetic success or a replacement
for filesystem/locking assertions. This file is new and has not run.
"""
from __future__ import annotations
import gzip, hashlib, json, struct
from collections import Counter
from pathlib import Path
from hepta.hia_program_runtime import _Machine, _Owner, _View

TRACE_MAGIC = int.from_bytes(b"HIANFT03", "little")
MAGIC = int.from_bytes(b"HIANFR03", "little")
BAD = 0xfffffffd
SYSCALLS = {1:257, 2:17, 3:18, 4:5, 5:77, 6:74, 7:264, 8:3, 9:263,
            10:258, 11:73, 12:228, 13:35, 14:318, 15:5, 16:107, 17:72,
            18:262, 19:267, 20:79, 21:91, 22:268, 23:72}

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def replay(program, directory, *, fatal_code=0):
    # This describes expected mechanical trace records, not OS process success.
    # External SIGKILL/death observations are recorded separately by the harness.
    directory = Path(directory)
    trace = (directory / "trace.bin").read_bytes()
    requests = json.loads((directory / "requests.json").read_bytes())
    originals = [(directory / "requests" / str(row["index"]) / "input.bin").read_bytes()
                 for row in requests]
    offset = 0
    def take(size):
        nonlocal offset
        assert 0 <= size <= len(trace) - offset, ("truncated trace", offset, size, len(trace))
        raw = trace[offset:offset + size]; offset += size
        return raw
    previous = None
    waiting = None
    ack = None
    consumed_requests = 0
    serial = 0
    counts = Counter()
    primitive_events = []
    grows = 0
    fatals = []
    entry = program.as_dict()["functions"][0]
    ledger_path = directory / "vm-replay.jsonl.gz"
    with gzip.open(ledger_path, "wt", encoding="utf-8") as ledger:
        while offset < len(trace):
            header_offset = offset
            h = struct.unpack("<8Q", take(64))
            assert h[0] == TRACE_MAGIC
            kind = h[1]
            if kind == 1:
                assert waiting is None
                serial += 1
                assert h[2] == serial and h[6:] == (0, 0)
                source, output, workspace = take(h[3]), take(h[4]), take(h[5])
                if previous is None:
                    assert serial == 1 and output == bytes(256) and workspace == bytes(512)
                    assert ack is None
                else:
                    old_source, old_output, old_workspace, old_code = previous
                    if old_code == 2:
                        grows += 1
                        assert ack is None and source == old_source
                        old_header = struct.unpack_from("<32Q", old_output)
                        assert len(workspace) == max(len(old_workspace), old_header[17])
                        assert len(output) == max(len(old_output), old_header[18])
                        assert workspace == old_workspace + bytes(len(workspace) - len(old_workspace))
                        assert output == old_output + bytes(len(output) - len(old_output))
                    else:
                        assert workspace == old_workspace and output == old_output
                    if old_code == 1:
                        assert ack is not None and source == ack
                        ack = None
                    elif old_code != 2:
                        assert old_code in (0, BAD) and ack is None
                if previous is None or previous[3] in (0, BAD):
                    assert consumed_requests < len(originals)
                    assert source == originals[consumed_requests]
                    consumed_requests += 1
                waiting = (source, output, workspace)
            elif kind == 2:
                assert waiting is not None and h[2] == serial and h[7] == 0
                source, before_output, before_workspace = waiting
                assert h[3:6] == (len(source), len(before_output), len(before_workspace))
                actual_output, actual_workspace = take(h[4]), take(h[5])
                owners = [_Owner(-1, bytearray(source)), _Owner(-2, bytearray(before_output)),
                          _Owner(-3, bytearray(before_workspace))]
                machine = _Machine(program, 4000000, 16 << 20, None, 64)
                returned = machine.invoke(entry, [_View(owners[0], False),
                    _View(owners[1], True), _View(owners[2], True)])[0]
                expected_output, expected_workspace = bytes(owners[1].data), bytes(owners[2].data)
                row = dict(serial=serial, trace_header_offset=header_offset,
                    input_hex=source.hex(), pre_output_hex=before_output.hex(),
                    pre_workspace_hex=before_workspace.hex(),
                    actual_return=h[6], expected_return=returned,
                    actual_output_hex=actual_output.hex(), expected_output_hex=expected_output.hex(),
                    actual_workspace_hex=actual_workspace.hex(), expected_workspace_hex=expected_workspace.hex(),
                    input_unchanged=bytes(owners[0].data) == source)
                ledger.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
                ledger.flush()
                assert row["input_unchanged"]
                assert returned == h[6] and expected_output == actual_output
                assert expected_workspace == actual_workspace
                assert struct.unpack_from("<Q", actual_output, 8)[0] == h[6]
                previous = (source, actual_output, actual_workspace, h[6])
                waiting = None
            elif kind == 3:
                assert waiting is None and previous is not None and previous[3] == 1
                assert ack is None and h[2] == serial
                event = struct.unpack_from("<32Q", previous[1])
                op = event[6]
                assert op in SYSCALLS and h[4] == SYSCALLS[op]
                assert (h[5], h[7]) == (op, event[5])
                ack = take(h[3])
                a = struct.unpack_from("<32Q", ack)
                assert a[0] == MAGIC and a[1] == 3
                assert a[2:7] == event[2:7]
                assert a[7] == h[6] and a[12] == len(ack) - 256 and a[13] == event[14]
                assert not any(a[8:12]) and not any(a[14:])
                counts[op] += 1
                primitive_events.append(dict(operation=op, syscall_number=h[4], sequence=h[7],
                    raw_return=h[6], ack_bytes=len(ack), ack_sha256=sha(ack)))
            elif kind == 4:
                assert h[2] == serial and h[3:6] == (0, 0, 0) and h[7] == 0
                assert fatal_code != 0 and h[6] == fatal_code
                fatals.append(dict(offset=header_offset, code=h[6], entry_serial=serial))
                assert offset == len(trace)
            else:
                raise AssertionError(("unknown trace kind", kind))
    assert waiting is None and ack is None
    assert serial > 0
    assert consumed_requests == len(originals)
    if fatal_code == 0:
        assert not fatals and previous is not None and previous[3] in (0, BAD)
    else:
        assert len(fatals) == 1
    result = dict(status="PASS", scope="EXACT_NATIVE_ENTRY_COREVM_REPLAY",
        native_entries=serial, vm_entries=serial, actual_primitive_acks=sum(counts.values()),
        primitive_operation_counts={str(k):v for k,v in sorted(counts.items())},
        primitive_events=primitive_events,
        growth_continuations=grows, requests=consumed_requests, fatal_records=fatals,
        trace_bytes=len(trace), trace_sha256=sha(trace),
        ledger_bytes=ledger_path.stat().st_size, ledger_sha256=sha(ledger_path.read_bytes()),
        all_return_output_workspace_bytes_equal=True, no_field_masks=True,
        actual_syscall_payloads_are_observed_not_synthetic=True)
    (directory / "vm-replay.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    return result
