"""Independent raw/RECORD/v5/worker/SQL readback; imports no product code."""
from __future__ import annotations
import argparse
import ast
import base64
import csv
from hashlib import sha256
import io
import json
from pathlib import Path, PurePosixPath
import sys
import zipfile
ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))
from tests.hia_slot_operations_qualification_support import (
    canonical, regular_bytes, unique_pairs, write_json)
from tools.read_hia_slot_mechanical_observations import mechanical_counters


def need(value, message):
    if not value:
        raise ValueError(message)


def integer(value, expected=None):
    need(type(value) is int and (expected is None or value == expected), "integer identity differs")


def same(left, right):
    need(canonical(left) == canonical(right), "type/value identity differs")


def digest(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


class Captures:
    def __init__(self):
        self.files = {}

    def raw(self, path, expected=None):
        path = Path(path).resolve(strict=True)
        raw = regular_bytes(path)
        if path in self.files:
            need(raw == self.files[path], "already captured evidence changed")
        else:
            self.files[path] = raw
        if expected is not None:
            same(digest(raw), expected)
        return raw

    def json(self, path, expected=None):
        return json.loads(self.raw(path, expected), object_pairs_hook=unique_pairs,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))

    def stable(self):
        for path, raw in self.files.items():
            need(regular_bytes(path) == raw, "readback input changed: " + str(path))

    def pins(self):
        return {str(path): digest(raw) for path, raw in self.files.items()}


def owned(captured, directory, embedded, seconds, code=0):
    directory = Path(directory)
    command = captured.json(directory / "command.json")
    result = captured.json(directory / "result.json")
    same(result, embedded)
    same(result["command"], command)
    integer(command["timeout_seconds"], seconds)
    integer(command["cleanup_seconds"], 5)
    need(command["new_session"] is True, "child process did not own a session")
    integer(command["pid"])
    integer(command["pgid"], command["pid"])
    integer(command["parent_pid"])
    integer(result["pid"], command["pid"])
    integer(result["exit_code"], code)
    need(result["timed_out"] is False and result["interruption"] is None,
         "child did not naturally finish")
    effective = command["effective_timeout_seconds"]
    need(type(effective) in (int, float) and 0 < effective <= seconds, "actual timeout differs")
    cleanup = result["owned_cleanup"]
    need(cleanup["reaped"] is True and cleanup["after"] == [] and cleanup["signals"] == [],
         "child group did not naturally finish/reap")
    stdout = captured.raw(directory / "stdout.log", result["stdout"])
    stderr = captured.raw(directory / "stderr.log", result["stderr"])
    return command, stdout, stderr


def tag(stderr, prefix):
    found = [json.loads(line[len(prefix):], object_pairs_hook=unique_pairs)
             for line in stderr.splitlines() if line.startswith(prefix)]
    need(len(found) == 1, "exact original tagged raw observation absent")
    return found[0]


def capture_capsule(captured, path, expected, installed):
    raw = captured.raw(path, expected)
    value = json.loads(raw, object_pairs_hook=unique_pairs)
    need(set(value) == {"schema", "target", "abi", "helpers_bundle",
                        "helpers_bundle_sha256", "bridges"}, "v5 closed schema differs")
    need(value["schema"] == "hepta.hia.native-helpers.v5"
         and value["target"] == "linux-x86_64-lp64"
         and value["abi"] == "hia-worker-mechanical-bridges-v1",
         "v5 ABI/target differs")
    bridge, = value["bridges"]
    need(set(bridge) == {"name", "abi", "package_path", "profile", "build_receipt",
                         "binary", "sources"} and bridge["name"] == "slot-mechanical",
         "named mechanical record differs")
    package = Path(installed) / "hepta"
    need(bridge["package_path"] == str(package), "exact installed package path differs")
    receipt = bridge["build_receipt"]
    need(receipt["path"] == str(package / "_slot_mechanical_build.json"), "receipt path differs")
    record = captured.json(receipt["path"], {k: receipt[k] for k in ("bytes", "sha256")})
    need(set(record) == {"schema", "abi", "profile", "binary", "sources",
                         "compiler_commands", "compiler_executables", "build_scope",
                         "product_qualification_claimed"}, "closed build receipt differs")
    need(record["schema"] == "hepta.slot.mechanical.build.v2"
         and record["build_scope"] == "CPYTHON_MECHANICAL_EXTENSION_ONLY"
         and record["product_qualification_claimed"] is False, "receipt is not explicit build-only")
    same(record["profile"], bridge["profile"])
    need(record["abi"] == bridge["abi"] == "hepta.slot.mechanical.cpython-gil-linux.v1",
         "mechanical ABI differs")
    binary = bridge["binary"]
    need(binary["path"] == str(package / binary["name"]), "exact executable path differs")
    same(record["binary"], {k: binary[k] for k in ("name", "bytes", "sha256")})
    captured.raw(binary["path"], {k: binary[k] for k in ("bytes", "sha256")})
    loader_source = captured.raw(package / "hia_slot_mechanical.py")
    declarations = [node for node in ast.parse(loader_source).body
                    if isinstance(node, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == "SOURCES" for t in node.targets)]
    need(len(declarations) == 1, "exact mechanical source closure declaration absent")
    source_names = ast.literal_eval(declarations[0].value)
    need(type(source_names) is tuple and len(source_names) == len(set(source_names)) == 11,
         "complete eleven-source closure differs")
    need(set(record["sources"]) == set(bridge["sources"]) == set(source_names),
         "compile-source closure differs")
    for name, pin in bridge["sources"].items():
        need(name.startswith("hepta/") and ".." not in PurePosixPath(name).parts,
             "unsafe named compile source")
        need(pin["path"] == str(package / name.removeprefix("hepta/")), "compile source path differs")
        same(record["sources"][name], {k: pin[k] for k in ("bytes", "sha256")})
        captured.raw(pin["path"], record["sources"][name])
    base_raw = captured.raw(value["helpers_bundle"])
    need(sha256(base_raw).hexdigest() == value["helpers_bundle_sha256"], "base v1 raw digest differs")
    base = json.loads(base_raw, object_pairs_hook=unique_pairs)
    need(base["schema"] == "hepta.hia.native-helpers.v1", "original base v1 was silently upgraded")
    need([row["selector"] for row in base["helpers"]] ==
         ["HEPTA_HIA_SLOT_LEDGER_MANIFEST", "HEPTA_HIA_SLOT_OPERATIONS_MANIFEST"],
         "installed fixture exact selected owners differ")
    for row in base["helpers"]:
        raw = captured.raw(row["manifest_path"])
        need(sha256(raw).hexdigest() == row["manifest_sha256"], "actual HIA manifest differs")
        manifest = json.loads(raw, object_pairs_hook=unique_pairs)
        image = Path(manifest["image_path"])
        if not image.is_absolute():
            image = Path(row["manifest_path"]).parent / image
        need(sha256(captured.raw(image)).hexdigest() == manifest["image_sha256"],
             "actual selected HIA executable differs")
    return value, bridge


def mechanical_evidence(value, command, bridge, loaded):
    need(value["schema"] == "hepta.slot.mechanical.worker-custody.v1"
         and value["loaded"] is loaded, "actual mechanical load observation differs")
    same(value["argv"], command["argv"][3:])
    integer(value["pid"], command["pid"])
    integer(value["pgid"], command["pid"])
    integer(value["ppid"], command["parent_pid"])
    if loaded:
        same(value["actual_binary"], {k: bridge["binary"][k] for k in ("bytes", "sha256")})
        same(value["receipt"], {k: bridge["build_receipt"][k] for k in ("bytes", "sha256")})
        need(value["abi"] == bridge["abi"] and value["actual_live_exports_unchanged"] is True,
             "loaded C binding differs")
        integer(value["modes"], 15)
        integer(value["ports"], 136)
        integer(value["seals"], 15)
        integer(value["required_seals"], 15)
        mechanical_counters(value["execution_counters"], command["pid"])
        need(sum(value["execution_counters"]["raw_frame_calls"]) == 0,
             "installed public worker used a raw Frame C shortcut")
        need(type(value["module_file"]) is str and value["module_file"].startswith("/proc/self/fd/")
             and value["module_file"].removeprefix("/proc/self/fd/").isdecimal(),
             "loaded executable is not the pinned sealed descriptor")


def verify(evidence, product_root, freeze, freeze_sha256, captured):
    report_path = evidence / "report.json"
    report = captured.json(report_path)
    started = captured.json(evidence / "started.json")
    need(report["schema"] == started["schema"] == "hepta.slot.mechanical.installed-driver.v1",
         "installed driver schema differs")
    need(report["status"] == "PASS" and report["failure"] is None and report["source_stable"] is True,
         "installed producer did not completely succeed")
    for key, value in started.items():
        same(report[key], value)
    need(report["whole_native_stack_qualified"] is False
         and report["new_v5_scope_not_old_Native6_qualification"] is True
         and report["original_scope_replaced"] is False, "scope declaration differs")
    freeze_raw = captured.raw(freeze)
    need(sha256(freeze_raw).hexdigest() == freeze_sha256, "external product freeze differs")
    fixed = json.loads(freeze_raw, object_pairs_hook=unique_pairs)
    need(fixed["schema"] == "hepta.slot-operations.qualification-source-freeze.v1", "source schema differs")
    same(fixed["files"], report["source_before"])
    same(report["product_freeze"], digest(freeze_raw))
    for relative, expected in fixed["files"].items():
        need(not PurePosixPath(relative).is_absolute() and ".." not in PurePosixPath(relative).parts,
             "unsafe product input")
        captured.raw(product_root / relative, expected)
    labels = ["wheel", "install", "ordinary-installed-identity", "installed-scenarios"]
    need([row["label"] for row in report["commands"]] == labels, "complete outer commands differ")
    outer = {}
    for row in report["commands"]:
        label = row["label"]
        outer[label] = owned(captured, evidence / label, row["result"],
                             1800 if label == "installed-scenarios" else 60)
    details = report["details"]
    wheel = details["wheel"]
    wheel_raw = captured.raw(wheel["path"], {k: wheel[k] for k in ("bytes", "sha256")})
    installed = Path(details["installed"]).resolve(strict=True)
    need(installed == evidence / "installed", "actual installed target differs")
    files = {}
    with zipfile.ZipFile(io.BytesIO(wheel_raw)) as archive:
        names = archive.namelist()
        need(len(names) == len(set(names)) and all(
             not PurePosixPath(name).is_absolute() and ".." not in PurePosixPath(name).parts
             for name in names), "unsafe/repeated wheel entry")
        record_name, = [name for name in names if name.endswith(".dist-info/RECORD")]
        need(record_name == details["wheel_record"], "wheel RECORD identity differs")
        rows = list(csv.reader(io.StringIO(archive.read(record_name).decode("utf-8"))))
        need(len(rows) == len({row[0] for row in rows}), "duplicate RECORD row")
        need(set(names) == {row[0] for row in rows}, "wheel entry outside RECORD")
        for name, recorded, length in rows:
            raw = archive.read(name)
            if name == record_name:
                need(recorded == length == "", "RECORD self row differs")
            else:
                want = "sha256=" + base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b"=").decode()
                need(recorded == want and length == str(len(raw)), "wheel RECORD bytes differ")
                need(captured.raw(installed / name) == raw, "installed bytes differ from actual wheel")
                files[name] = digest(raw)
    same(files, details["wheel_files"])
    captured.raw(installed / record_name, details["installed_record"])
    identity = json.loads(outer["ordinary-installed-identity"][1], object_pairs_hook=unique_pairs)
    same(identity, report["source_identity"])
    same(identity, details["ordinary_installed_identity"])
    need(set(identity) == {"worker_sha256", "backend_sha256", "catalog_sha256"},
         "unselected source/wheel identity schema changed")
    admin = details["administrator"]
    capsule, bridge = capture_capsule(captured, admin["path"],
        {k: admin[k] for k in ("bytes", "sha256")}, installed)
    need(admin["authority"] == "OPERATOR_MUST_PIN_THIS_DIGEST"
         and admin["product_qualification_claimed"] is False, "fixture administrator pin differs")
    rawpin = details["probe_report"]
    probe_path = Path(rawpin["path"])
    need(probe_path == evidence / "installed-probe/report.json", "actual probe report path differs")
    probe = captured.json(probe_path, {k: rawpin[k] for k in ("bytes", "sha256")})
    need(probe["schema"] == "hepta.slot.mechanical.installed-worker.v1" and probe["status"] == "PASS",
         "installed original-worker scenario incomplete")
    same(probe["capsule"], {k: admin[k] for k in ("path", "bytes", "sha256")})
    need(probe["installed"] == str(installed)
         and probe["actual_installed_same_capsule_setup"] is True
         and probe["actual_original_worker"] is True
         and probe["all_fifteen_methods_in_worker_observed"] is False
         and probe["original_Native6_replaced"] is False
         and probe["whole_native_stack_qualified"] is False, "installed scope declaration differs")
    selected_identity = {**identity, "native_helpers_sha256": admin["sha256"]}
    same(probe["identities"], selected_identity)
    worker_labels = ["installation-manifest", "normal", "replay", "lost-SQL-ACK",
                     "unknown-replay", "source-plus-LF", "extra-module"]
    need([row["label"] for row in probe["commands"]] == worker_labels,
         "complete original worker/extra-source scenarios differ")
    rows = {}
    for row in probe["commands"]:
        label = row["label"]
        code = 1 if label == "lost-SQL-ACK" else 2 if label in worker_labels[-2:] else 0
        command, stdout, stderr = owned(captured, probe_path.parent / label, row["result"], 60, code)
        argv = command["argv"]
        need(argv[1:3] == ["-I", "-B"]
             and Path(argv[3]).resolve() == product_root / "tests/hia_slot_mechanical_worker_probe.py",
             "actual worker probe source differs")
        def argument(flag):
            need(argv.count(flag) == 1 and argv.index(flag) + 1 < len(argv), "worker flag missing/repeated")
            return argv[argv.index(flag) + 1]
        need(argument("--installed") == str(installed)
             and argument("--native-helpers-manifest") == admin["path"]
             and argument("--expected-native-helpers-sha256") == admin["sha256"],
             "actual v5 worker flags differ")
        if label == "installation-manifest":
            need(argv[-1] == "--installation-manifest", "identity child is not the original worker flag")
            same(json.loads(stdout), selected_identity)
        else:
            for field in ("worker", "backend", "catalog"):
                need(argument("--expected-" + field + "-sha256") == identity[field + "_sha256"],
                     "worker lacks actual source/backend/catalog identity")
            need("--request-json-stdin" in argv, "actual worker request transport differs")
        counts = tag(stderr, b"SLOT_OPERATIONS_INSTALLED=")
        mechanical = tag(stderr, b"SLOT_MECHANICAL_WORKER=")
        mechanical_evidence(mechanical, command, bridge, label != "source-plus-LF")
        need(counts["retained_calls"] == [], "selected worker called retained Slot method")
        if label in ("installation-manifest", "source-plus-LF", "extra-module"):
            need(sum(counts["startup"].values()) == sum(counts["request"].values()) == 0
                 and counts["unknown_records"] == 0, "pre-request boundary executed effects")
        rows[label] = (stdout, counts, mechanical)
    observations = probe["observations"]
    same(probe["identity_child"], {"counts": rows["installation-manifest"][1],
                                  "mechanical": rows["installation-manifest"][2]})
    for label in ("normal", "lost-SQL-ACK"):
        counters = rows[label][2]["execution_counters"]
        need(sum(counters["public_calls"]) > 0 and sum(counters["initialized"]) > 0,
             "installed request never actually entered C and its HIA owner")
    normal, replay = observations["normal"], observations["replay"]
    for label, value in (("normal", normal), ("replay", replay),
                         ("lost-SQL-ACK", observations["lost_SQL_ACK"]),
                         ("unknown-replay", observations["unknown_replay"])):
        same(value["counts"], rows[label][1])
        same(value["mechanical"], rows[label][2])
        if "response" in value:
            same(value["response"], json.loads(rows[label][0]))
    need(normal["response"]["response"]["status"] == "rejected"
         and normal["after"]["request"]["state"] == "completed"
         and normal["counts"]["unknown_records"] == 0
         and sum(normal["counts"]["request"].values()) > 0
         and normal["counts"]["request_modes"].get("4", 0) > 0
         and normal["counts"]["request_modes"].get("2", 0) > 0
         and normal["counts"]["decision_request"] > 0, "original normal selected behavior differs")
    for name in ("slots", "versions", "leases"):
        same(normal["before"][name], normal["after"][name])
    same(replay["response"]["response"], normal["response"]["response"])
    need(sum(replay["counts"]["request"].values()) == 0, "healthy replay repeated selected effects")
    lost, unknown = observations["lost_SQL_ACK"], observations["unknown_replay"]
    need(rows["lost-SQL-ACK"][0] == b"" and lost["counts"]["lost_ack_injected"] is True
         and lost["counts"]["unknown_records"] > 0
         and lost["counts"]["unknown_resource_observations"] > 0
         and lost["counts"]["close_calls"] == 0
         and lost["after"]["request"]["state"] == "running"
         and lost["after"]["request"]["response"] is None, "real SQL loss custody differs")
    for name in ("slots", "versions", "leases", "costs"):
        same(lost["before"][name], lost["after"][name])
    need(unknown["response"]["response"]["status"] == "rejected"
         and unknown["response"]["response"]["error"]["code"] == "E_HIA_REQUEST_UNKNOWN"
         and sum(unknown["counts"]["request"].values()) == 0, "unknown replay ran effects")
    same(unknown["after"]["request"], lost["after"]["request"])
    integer(unknown["after"]["costs"], lost["after"]["costs"] + 1)
    drift = observations["source_drift"]
    need(drift["source_restored"] is True and drift["extra_module_removed"] is True
         and [row["label"] for row in drift["rows"]] == worker_labels[-2:],
         "source drift restoration is incomplete")
    raw = captured.raw(drift["source_before"]["path"],
                       {k: drift["source_before"][k] for k in ("bytes", "sha256")})
    for row in drift["rows"]:
        label = row["label"]
        same(row["counts"], rows[label][1])
        same(row["mechanical"], rows[label][2])
        need(rows[label][0] == b"" and row["state_unchanged"] is True, "refusal produced a response/effect")
        mutation = row["mutation"]
        if label == "source-plus-LF":
            same({k: mutation[k] for k in ("bytes", "sha256")}, digest(raw + b"\n"))
        else:
            same({k: mutation[k] for k in ("bytes", "sha256")},
                 digest(b"# installed inventory drift control\n"))
            need(not Path(mutation["path"]).exists(), "extra installed module was not removed")
    return {"scope": "SEPARATE_V5_INSTALLED_CONTROL", "workers": len(worker_labels),
            "source_wheel_identity_equal": True, "admin_bundle": admin,
            "original_Native6_replaced": False, "whole_native_stack_qualified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("evidence", "product-root", "product-freeze", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--product-freeze-sha256", required=True)
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    captured = Captures()
    try:
        detail = verify(args.evidence.resolve(strict=True), args.product_root.resolve(strict=True),
                        args.product_freeze, args.product_freeze_sha256, captured)
        captured.stable()
        result = {"status": "PASS", "detail": detail, "failure": None}
    except Exception as error:
        result = {"status": "HOLD", "detail": None,
                  "failure": {"type": type(error).__name__, "message": str(error)}}
    result.update({"schema": "hepta.slot.mechanical.installed-readback.v1",
                   "actual_inputs": captured.pins(), "product_imported": False})
    # Pins are from the same bytes that were parsed; never refresh them to bless
    # a changed report/ledger. Even a refusal reports its originally seen bytes.
    write_json(args.output / "READBACK.json", result)
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
