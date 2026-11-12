"""Fresh-process, source-bound independent Core references, all before B0.

Only the fixed oracle inventory is admitted. Native compiler generations remain
sequential. Each worker fully verifies its ordinary Core VM inputs; no verified
program cache, changed deadline, native-child reuse or reference substitution.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
from tools.hia_selfhost_contract import CONTRACT_PATH, file_digests, validate_contract

BUILDERS = {
    "exports": ("tools.qualify_hia_selfhost_exports", "independent_reference"),
    "names": ("tools.hia_selfhost_names", "independent_reference"),
    "cli": ("tools.qualify_hia_selfhost_cli", "independent_reference"),
    "explicit-traps": ("tools.hia_selfhost_traps", "independent_reference"),
    "resource": ("tools.hia_selfhost_resources", "independent_resource_reference"),
    "bulk": ("tools.hia_selfhost_bulk", "independent_bulk_reference"),
    "loan": ("tools.hia_selfhost_loans", "independent_loan_reference"),
    "cfg": ("tools.hia_selfhost_cfg_worklist", "independent_reference"),
    "capacity": ("tools.hia_selfhost_capacity", "independent_capacity_reference"),
    "tail": ("tools.hia_selfhost_tailcalls", "independent_tail_reference"),
    "select": ("tools.hia_selfhost_select", "independent_select_reference"),
    "effects": ("tools.hia_selfhost_effects", "independent_reference"),
    "multi": ("tools.hia_selfhost_multi_results", "independent_reference"),
    "keyword": ("tools.hia_selfhost_keywords", "independent_reference"),
    "signed": ("tools.hia_selfhost_signed_cases", "independent_reference"),
    "scalar-casts": ("tools.hia_selfhost_scalar_casts", "independent_reference"),
    "core": ("tools.qualify_hia_selfhost", "independent_call_reference"),
}
SCHEMA = "hepta.hia.selfhost-independent-reference-process.v1"


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def snapshot():
    return {**file_digests(), CONTRACT_PATH: sha256((ROOT / CONTRACT_PATH).read_bytes()).hexdigest()}


def validate_envelope(report, family, identity):
    if (type(report) is not dict or report.get("schema") != SCHEMA
            or report.get("family") != family or report.get("before_B0") is not True
            or report.get("source_manifest_sha256") != identity
            or type(report.get("worker_pid")) is not int or report["worker_pid"] <= 0
            or type(report.get("reference")) is not dict
            or report.get("reference_sha256") != digest(report["reference"])):
        raise ValueError("independent reference identity or payload mismatch")
    return report["reference"]


def produce(family):
    if family not in BUILDERS:
        raise ValueError("unknown independent reference family")
    validate_contract()
    identity = digest(snapshot())
    started = time.monotonic_ns()
    module, symbol = BUILDERS[family]
    builder = getattr(importlib.import_module(module), symbol)
    reference = (builder((ROOT / "examples/hia_bootstrap/bytesum.hiaasm").read_bytes())
                 if family == "core" else builder())
    validate_contract()
    if digest(snapshot()) != identity:
        raise ValueError("independent reference source changed during execution")
    return {"schema": SCHEMA, "family": family, "before_B0": True,
            "source_manifest_sha256": identity, "reference_sha256": digest(reference),
            "reference": reference, "worker_pid": os.getpid(),
            "wall_elapsed_ns": time.monotonic_ns() - started}


def _run(directory, family, identity):
    stem = directory / ("reference-" + family)
    output = stem.with_suffix(".worker.json")
    command = [sys.executable, "-I", "-S", "-B", str(Path(__file__).resolve()),
               "--family", family, "--output", str(output.resolve())]
    started = time.monotonic_ns()
    with stem.with_suffix(".stdout.log").open("xb") as out, stem.with_suffix(".stderr.log").open("xb") as err:
        with subprocess.Popen(command, cwd=directory, stdout=out, stderr=err) as child:
            returncode = child.wait()
            pid = child.pid
    receipt = {"family": family, "command": command, "worker_pid": pid,
               "returncode": returncode, "started_monotonic_ns": started,
               "completed_monotonic_ns": time.monotonic_ns()}
    if returncode:
        raise AssertionError({"independent_reference_process_failed": receipt})
    raw = output.read_bytes()
    report = json.loads(raw)
    result = validate_envelope(report, family, identity)
    if report["worker_pid"] != pid:
        raise ValueError("independent reference PID does not match fresh child")
    receipt.update({"report_sha256": sha256(raw).hexdigest(),
                    "reference_sha256": report["reference_sha256"],
                    "source_manifest_sha256": identity})
    return family, result, receipt


def build_references(directory, manifest, filenames, workers):
    if type(workers) is not int or workers != 2:
        raise ValueError("reference scheduling uses the existing two-worker budget")
    if set(filenames) != set(BUILDERS) - {"core"}:
        raise ValueError("independent reference inventory mismatch")
    identity = digest(manifest)
    # Start expensive families first. A thread only owns a fresh subprocess;
    # VM globals and verified values are never shared between workers.
    # Retained remote artifact 13762513077 identifies names as the longest
    # fresh oracle, followed by signed/casts. Schedule long work first while
    # retaining every fresh worker, every VM check, and exactly two slots.
    priority = ("names", "signed", "scalar-casts", "keyword", "exports", "capacity")
    order = (*priority, *[f for f in BUILDERS if f not in priority])
    with ThreadPoolExecutor(max_workers=workers) as pool:
        scheduled = [pool.submit(_run, directory, family, identity) for family in order]
        observations = [future.result() for future in scheduled]
    references = {family: result for family, result, receipt in observations}
    if digest(snapshot()) != identity:
        raise ValueError("reference source manifest changed before B0")
    for family, filename in {**filenames, "core": "independent-core-reference.json"}.items():
        with (directory / filename).open("x") as stream:
            json.dump(references[family], stream, sort_keys=True, indent=2)
            stream.write("\n")
    return references, [receipt for family, result, receipt in observations]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family", choices=tuple(BUILDERS), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = produce(args.family)
    with args.output.open("x") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")


if __name__ == "__main__":
    main()
