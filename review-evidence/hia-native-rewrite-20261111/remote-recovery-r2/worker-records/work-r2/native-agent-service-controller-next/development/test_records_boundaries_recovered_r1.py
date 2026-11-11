"""New full-size and late-wire controls for the native record component."""
from hashlib import sha256
import json
from pathlib import Path
import resource
import sys
import time
import traceback
resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))
resource.setrlimit(resource.RLIMIT_CPU, (90, 90))
from records_harness_recovered_r2 import Actual, capture, observed_value
from hepta.hia_agent_contract import VERSION
from hepta.hia_agent_store import wire

OUT = Path(sys.argv[1])
MODE = sys.argv[2]
SELF = Path(__file__).resolve()
before = SELF.read_bytes()
actual = Actual(OUT)
rows = []
start = time.monotonic_ns()
summary = dict(status="INCOMPLETE", mode=MODE, cpu_limit_seconds=90, address_space_bytes=1 << 30,
               scope="RECORD_COMPONENT_AND_ORIGINAL_LATE_WIRE_GATE_NOT_COMPLETE_SERVICE_OR_NAMESPACE")
(OUT / "test-source-before.json").write_text(json.dumps(dict(path=str(SELF), bytes=len(before), sha256=sha256(before).hexdigest()), sort_keys=True) + "\n")

def check(label, payload, *, cycle=False, wanted_bytes=None):
    expected = dict(contract_version=VERSION, request_id="r", status="completed", result=payload)
    try:
        expected_wire = dict(wire=wire(expected))
    except Exception as exc:
        expected_wire = dict(error=str(exc), error_class=type(exc).__name__)
    source = capture(["r", payload], lease=991)
    result = actual.run(source, 0, exact_growth=True, label=label)
    got = observed_value(result["graph"])
    assert list(got) == list(expected)
    if cycle:
        assert got["result"][0] is got["result"]
    elif not isinstance(payload, float):
        assert got == expected
    observed = actual.serialize(result["graph"], label=label + "/wire")
    assert observed.get("wire") == expected_wire.get("wire") and observed.get("error") == expected_wire.get("error"), (label, observed.get("error"), expected_wire.get("error"))
    if wanted_bytes is not None:
        assert len(expected_wire["wire"]) == wanted_bytes
    row = dict(case=label, status="PASS", native_record_completed=True, source=actual.save(source),
               graph=result["result"], grows=result["grows"], event=result["event"],
               late_wire_accepted="wire" in observed,
               expected_wire=actual.save(expected_wire["wire"]) if "wire" in expected_wire else expected_wire,
               actual_wire=actual.save(observed["wire"]) if "wire" in observed else observed)
    rows.append(row)
    with (OUT / "cases.jsonl").open("a") as f:
        f.write(json.dumps(row, sort_keys=True) + "\n")
    print(json.dumps(dict(case=label, status="PASS", late_wire_accepted=row["late_wire_accepted"]), sort_keys=True), flush=True)

try:
    if MODE == "small":
        for label, value in (("tuple", (1, "x", None)), ("bytes", b"raw"), ("infinity", float("inf")),
                             ("minus-infinity", float("-inf")), ("nan", float("nan")),
                             ("integer-map-key", {3: "value"}), ("mixed-map-keys", {"a": 1, 2: "value"})):
            check(label, value)
        cycle = []
        cycle.append(cycle)
        check("cycle-kept-until-wire", cycle, cycle=True)
    elif MODE in ("exact", "plusone"):
        empty = dict(contract_version=VERSION, request_id="r", status="completed", result="")
        overhead = len(wire(empty))
        size = (8 << 20) - overhead + (MODE == "plusone")
        assert size > 0
        check("late-wire-8MiB" + ("+1" if MODE == "plusone" else ""),
              "a" * size, wanted_bytes=(8 << 20) if MODE == "exact" else None)
        assert rows[-1]["late_wire_accepted"] == (MODE == "exact")
        summary.update(payload_bytes=size, envelope_bytes=overhead, original_wire_limit=8 << 20)
    else:
        raise AssertionError(("unknown test mode", MODE))
    summary.update(status="PASS", cases=len(rows), entries=actual.entries)
except BaseException as exc:
    summary.update(status="FAIL", cases=len(rows), entries=actual.entries, error_class=type(exc).__name__, error=str(exc))
    traceback.print_exc()
    raise
finally:
    summary["wall_ns"] = time.monotonic_ns() - start
    summary["test_source_unchanged"] = SELF.read_bytes() == before
    actual.close()
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True), flush=True)
    assert summary["test_source_unchanged"]
