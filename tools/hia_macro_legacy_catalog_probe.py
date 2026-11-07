"""Separate zero-generation default-stdio diagnostic for the observed Codex 0.133.

This does not change the production provider transport or replace an earlier
failed observation. It reuses its ownership/cleanup checks and deliberately
keeps a failed cleanup failed, even if catalog bytes have already arrived.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys

SOURCE = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(SOURCE))
sys.dont_write_bytecode = True

from tools.hia_agent_codex_transport import canonical, identity, run_owned, save
from tools.qualify_hia_agent_preflight import initialization_wire, process_ok, startup_response
from tools.qualify_hia_agent_provider import (MAX_LINE, MAX_STREAM, MAX_CATALOG_WARNINGS,
    catalog_response, catalog_warning, event_lines)

EXPECTED_ENTRYPOINT_SHA = "aa3c64b122c9d06bf48eaf988f5970aa69556d69506c3118cf07d10b2401b48a"


def worker(codex, logs, sent_path):
    # Codex 0.133 rejects --stdio. Its default stdio form is a separate
    # registered diagnostic; this is never a retry of the old request.
    child = subprocess.Popen([codex, "-c", "log_dir=" + json.dumps(logs), "app-server"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr.buffer)
    with Path(sent_path).open("xb") as sent:
        def send(raw):
            child.stdin.write(raw)
            child.stdin.flush()
            sent.write(raw)
            sent.flush()
        def receive():
            raw = child.stdout.readline(MAX_LINE + 1)
            if not raw or len(raw) > MAX_LINE or not raw.endswith(b"\n"):
                raise ValueError("incomplete or oversized catalog response")
            sys.stdout.buffer.write(raw)
            sys.stdout.buffer.flush()
            return raw
        initialize, initialized = initialization_wire().splitlines(keepends=True)
        send(initialize)
        startup_response(receive())
        send(initialized)
        send(canonical({"id": 2, "method": "model/list", "params": {}}) + b"\n")
        for _ in range(MAX_CATALOG_WARNINGS + 1):
            _, incoming = event_lines(receive())
            event = incoming[0]
            if type(event.get("id")) is int and event["id"] == 2:
                break
            catalog_warning(event)
        else:
            raise ValueError("catalog notification budget exhausted")
        child.stdin.close()
        while True:
            raw = child.stdout.read(65536)
            if not raw:
                break
            sys.stdout.buffer.write(raw)
            sys.stdout.buffer.flush()
    return child.wait(timeout=5)


def main():
    if len(sys.argv) == 7 and sys.argv[2] == "_worker":
        return worker(sys.argv[3], sys.argv[4], sys.argv[5])
    if len(sys.argv) != 5 or sys.argv[2] != "catalog":
        raise ValueError("expected SOURCE catalog ABSOLUTE_CODEX FRESH_OUTPUT")
    codex, output = Path(sys.argv[3]), Path(sys.argv[4])
    if not codex.is_absolute() or not output.is_absolute():
        raise ValueError("absolute paths required")
    output.mkdir(mode=0o700, exist_ok=False)
    tool = identity(codex)
    if tool["sha256"] != EXPECTED_ENTRYPOINT_SHA:
        raise ValueError("this diagnostic is pinned to the observed legacy entrypoint")
    adapter = identity(Path(__file__))
    manifest_path = SOURCE.parent / "source-manifest.json"
    source_manifest = json.loads(manifest_path.read_bytes())
    for name, expected in source_manifest["files"].items():
        raw = (SOURCE / name).read_bytes()
        if len(raw) != expected["bytes"] or sha256(raw).hexdigest() != expected["sha256"]:
            raise ValueError("original diagnostic dependency changed")
    report = {"schema": "hepta.hia.macro-provider-legacy-catalog.v1", "status": "blocked",
        "source_commit": source_manifest["commit"], "source_manifest": identity(manifest_path),
        "adapter": adapter, "cli_entrypoint": tool,
        "transport_form": "codex app-server; default stdio; no --stdio option",
        "coding_task_requests": 0, "model_generation_requests": 0,
        "prior_negative_results_replaced": False, "provider_entitlement_attested": False}
    save(output / "REGISTRATION.json", report)
    process = run_owned([sys.executable, "-B", str(Path(__file__).resolve()), str(SOURCE), "_worker",
        str(codex), str(output / "logs"), str(output / "wire.sent.raw"), "v1"],
        output, output / "process", wall_seconds=60)
    report["process"] = process
    raw = (output / "process/stdout.raw").read_bytes()
    try:
        if len(raw) > MAX_STREAM:
            raise ValueError("catalog stream byte limit")
        # Separately report parseable metadata; it never overrides transport
        # admission or asserts that a model would accept an actual turn.
        report["observed_catalog_metadata"] = catalog_response(raw)
    except (ValueError, TypeError, KeyError, RecursionError) as error:
        report["metadata_error"] = {"type": type(error).__name__, "message": str(error)}
    report["cli_entrypoint_after"] = identity(codex)
    report["adapter_after"] = identity(Path(__file__))
    if (process_ok(process) and "observed_catalog_metadata" in report
            and report["cli_entrypoint_after"] == tool and report["adapter_after"] == adapter):
        report["status"] = "catalog_observed"
    else:
        report["reason"] = "transport_cleanup_or_metadata_not_admitted"
    if (output / "wire.sent.raw").exists():
        report["original_outbound_wire"] = identity(output / "wire.sent.raw")
    save(output / "RESULT.json", report)
    print(json.dumps({key: report.get(key) for key in ("status", "reason", "model_generation_requests")}, sort_keys=True))
    return 0 if report["status"] == "catalog_observed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
