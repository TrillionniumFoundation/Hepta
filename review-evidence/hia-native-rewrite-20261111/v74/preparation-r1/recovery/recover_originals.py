"""Recover immutable HIA evidence and check the exact ac3 resource-binding repair.

This runner does not qualify cold, native, installed-wheel or whole delivery.
The recovered aa801 failure remains a failure; no original operation is replayed.
"""
from __future__ import annotations
import argparse, ast, base64, io, json, os, pathlib, re, subprocess, sys, tarfile, time, zlib
from hashlib import sha256

PIN = "ac3fb576419d9ec36841822b4be0fca420268f1b"
TREE = "8231abac1bb2f30d7a8da8eb08a79ce92c50eb25"
COLD_SHA = "86858e1d6069389d0bf43561dc9ffb0e37d4fde705e29c894801fde99f1dd78b"
ARCHIVE_SHA = "76187ecb326927f232aa4af5f437cc8c140306bdd029f3722cae9ac35a667c09"
MANIFEST_SHA = "a5e3bdda3170af914f30337d7ac664058a42860912e4a404d8c487be1dd73a58"
R1_SHA = "55097a1db37eb9c2771e6988c6299ac90b87a02b437f1c48527e9e64ee408298"
p = argparse.ArgumentParser()
p.add_argument("--source", type=pathlib.Path, required=True)
p.add_argument("--artifact", type=pathlib.Path, required=True)
p.add_argument("--capsule", type=pathlib.Path, required=True)
p.add_argument("--output", type=pathlib.Path, required=True)
a = p.parse_args()
# Keep argument identities explicit; the output is the only newly owned directory.
root = a.source.resolve(strict=True)
artifact = a.artifact.resolve(strict=True)
capsule = a.capsule.resolve(strict=True)
out = a.output.resolve()
if out == root or out.is_relative_to(root) or out == artifact or out.is_relative_to(artifact):
    raise ValueError("recovery output must be separate from retained inputs")
out.mkdir(parents=True, exist_ok=False)
started = time.monotonic_ns()
failures = []
report = {
    "schema": "hia.v73.original-evidence-recovery-and-source-controls.v1",
    "source_pin": PIN, "source_tree": TREE,
    "scope": "original evidence recovery, source-dependency scan and four resource-binding source controls only",
    "original_operations_replayed": False, "current_cold_qualified": False,
    "full_qualified": False, "whole_closed": False, "legacy_deleted": False,
    "interpreter": {"version": sys.version, "executable": sys.executable,
                    "bytes_sha256": sha256(pathlib.Path(sys.executable).resolve().read_bytes()).hexdigest()},
}
transport_paths = []

def save_bytes(name, raw, *, transport=False):
    dest = out / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open("xb") as f:
        f.write(raw)
    record = {"path": name, "bytes": len(raw), "sha256": sha256(raw).hexdigest()}
    if transport:
        transport_paths.append(name)
    return record

def save_json(name, value, *, transport=False):
    return save_bytes(name, (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(), transport=transport)

def git(*args):
    return subprocess.check_output(["git", *args], cwd=root)

def source_state():
    state = {
        "head": git("rev-parse", "HEAD").decode().strip(),
        "tree": git("rev-parse", "HEAD^{tree}").decode().strip(),
        "status": git("status", "--porcelain=v1", "--untracked-files=all").decode(),
        "files": {},
    }
    for value in git("ls-files", "-z").split(b"\0"):
        if value:
            path = os.fsdecode(value)
            raw = (root / path).read_bytes()
            state["files"][path] = {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}
    if state["head"] != PIN or state["tree"] != TREE or state["status"] or len(state["files"]) != 3067:
        raise ValueError("complete clean pinned source identity differs")
    return state

def attempt(label, fn):
    try:
        return fn()
    except Exception as error:
        failures.append({"step": label, "error": repr(error)})
        return None

held_before = {
    "runner": sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
    "capsule": sha256(capsule.read_bytes()).hexdigest(),
}
before = attempt("complete-source-before", source_state)
if before:
    report["source_before"] = save_json("source-before.json", before)
    def scan():
        rows = []
        pattern = re.compile(r"skipUnless|skipIf|SkipTest|skipTest|HEPTA_RUN_|shutil\.which|which\(|HEPTA_[A-Z0-9_]*(?:BRIDGE|IDENTITY|PROVER|QEMU|LEAN)")
        for path in sorted((root / "tests").rglob("*.py")):
            raw = path.read_bytes()
            text = raw.decode("utf-8")
            ast.parse(text, filename=str(path))
            lines = text.splitlines()
            hits = []
            for index, line in enumerate(lines):
                if pattern.search(line):
                    first, last = max(0, index - 3), min(len(lines), index + 4)
                    hits.append({"line": index + 1, "context_start": first + 1,
                                 "context": lines[first:last]})
            if hits:
                rows.append({"path": path.relative_to(root).as_posix(), "sha256": sha256(raw).hexdigest(), "matches": hits})
        return save_json("test-dependency-and-skip-contexts.json", {"source_pin": PIN, "files": rows}, transport=True)
    report["dependency_scan"] = attempt("complete-tests-static-scan", scan)

    def source_checks():
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        contract = subprocess.run([sys.executable, "-B", "tools/generate_hia_selfhost_contract.py", "--check"],
                                  cwd=root, env=env, capture_output=True, timeout=60)
        save_bytes("support-check.stdout", contract.stdout, transport=True)
        save_bytes("support-check.stderr", contract.stderr, transport=True)
        if contract.returncode:
            raise AssertionError("actual support-contract --check failed")
        suite_code = (
            "import json,sys,unittest\n"
            "suite=unittest.defaultTestLoader.loadTestsFromName('tests.test_hia_agent_installed_resources.AgentInstalledResourceSourceTests')\n"
            "r=unittest.TextTestRunner(verbosity=2).run(suite)\n"
            "v=dict(tests_run=r.testsRun,successful=r.wasSuccessful(),errors=[(t.id(),s) for t,s in r.errors],"
            "failures=[(t.id(),s) for t,s in r.failures],skipped=[(t.id(),s) for t,s in r.skipped],"
            "expected_failures=[(t.id(),s) for t,s in r.expectedFailures],unexpected_successes=[t.id() for t in r.unexpectedSuccesses])\n"
            "print(json.dumps(v,sort_keys=True))\n"
            "sys.exit(0 if r.wasSuccessful() and r.testsRun==4 and not (r.skipped or r.expectedFailures or r.unexpectedSuccesses) else 1)\n"
        )
        controls = subprocess.run([sys.executable, "-B", "-c", suite_code],
                                  cwd=root, env=env, capture_output=True, timeout=180)
        save_bytes("resource-controls.stdout", controls.stdout, transport=True)
        save_bytes("resource-controls.stderr", controls.stderr, transport=True)
        value = json.loads(controls.stdout)
        if controls.returncode or value.get("tests_run") != 4 or value.get("successful") is not True:
            raise AssertionError("four resource-binding source controls failed")
        if any(value.get(key) != [] for key in ("errors", "failures", "skipped", "expected_failures", "unexpected_successes")):
            raise AssertionError("resource-binding controls were not complete successes")
        return {"support_check_returncode": contract.returncode, "controls": value,
                "installed_wheel_executed": False}
    report["source_checks"] = attempt("actual-support-and-resource-controls", source_checks)

def recover_cold():
    cold_path = artifact / "hia-cold.json"
    raw = cold_path.read_bytes()
    if len(raw) != 99205 or sha256(raw).hexdigest() != COLD_SHA:
        raise ValueError("original aa801 cold bytes differ from the previously downloaded artifact")
    cold = json.loads(raw)
    original = {}
    for name in ("hia-cold.json", "hia-cold.cold/process-owner.json", "hia-cold.cold/stderr.log", "hia-cold.cold/stdout.log"):
        path = artifact / name
        if not path.is_file():
            raise ValueError("required original artifact file absent: " + name)
        original[name] = save_bytes("original-aa801/" + name, path.read_bytes(), transport=True)
    inventory, phases, images = [], [], []
    for path in sorted(artifact.rglob("*")):
        if path.is_symlink():
            raise ValueError("unexpected symlink in original artifact")
        if not path.is_file():
            continue
        value = path.read_bytes()
        name = path.relative_to(artifact).as_posix()
        row = {"path": name, "bytes": len(value), "sha256": sha256(value).hexdigest()}
        inventory.append(row)
        if path.name.startswith("phase-") and path.suffix == ".json" and not path.name.endswith((".request.json", ".process.json")):
            record = json.loads(value)
            phases.append({**row, "keys": sorted(record),
                           "scalars": {k: v for k, v in record.items() if v is None or type(v) in (str, int, float, bool)}})
        if re.search(r"(?:^|/)[BM][123](?:[^/]*)(?:\.bin|\.so|\.o)$", name):
            images.append(row)
    if len(inventory) != 6072:
        raise ValueError("original artifact file inventory count differs")
    manifest = save_json("original-aa801-artifact-file-manifest.json", {"files": inventory})
    summary = {key: cold.get(key) for key in ("status", "returncode", "wall_elapsed_ns",
                "qualification_wall_limit_seconds", "cleanup_wall_limit_seconds",
                "generation_sha256", "modified_generation_sha256", "nested_report", "checks")}
    return {"run_id": 43136468788, "artifact_id": 13908947654,
            "original_files": original, "inventory": manifest, "summary": summary,
            "completed_phase_reports": phases, "actual_generation_files": images,
            "original_status_reclassified": False}
report["original_aa801"] = attempt("recover-original-aa801-cold", recover_cold)

def recover_archive():
    wrapper = json.loads(capsule.read_bytes())
    archive = base64.b64decode(wrapper["content_base64"], validate=True)
    if len(archive) != 309024 or sha256(archive).hexdigest() != ARCHIVE_SHA:
        raise ValueError("source-admission original archive identity differs")
    rows, manifests, fixtures = [], [], []
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:xz") as tar:
        members = tar.getmembers()
        if len(members) != 143 or len({m.name for m in members}) != 143:
            raise ValueError("source-admission original member count/names differ")
        for member in members:
            name = pathlib.PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts or not (member.isfile() or member.isdir()):
                raise ValueError("unsafe or unexpected original archive member")
            row = {"path": member.name, "bytes": member.size, "mode": member.mode,
                   "type": "file" if member.isfile() else "directory"}
            if member.isfile():
                raw = tar.extractfile(member).read()
                if len(raw) != member.size:
                    raise ValueError("short archive member")
                row["sha256"] = sha256(raw).hexdigest()
                if row["sha256"] == MANIFEST_SHA:
                    record = save_bytes("source-admission-original-MANIFEST.json", raw, transport=True)
                    manifests.append({"member": member.name, **record})
                if row["sha256"] == R1_SHA:
                    fixtures.append({"member": member.name, "bytes": len(raw), "sha256": row["sha256"]})
            rows.append(row)
    if len(manifests) != 1 or not fixtures:
        raise ValueError("original manifest or independent r1 fixture absent")
    record = {"status": "EXACT_ORIGINAL_ARCHIVE_MEMBERS_READ_AND_MANIFEST_CAPTURED",
              "archive_bytes": len(archive), "archive_sha256": sha256(archive).hexdigest(),
              "members": rows, "original_manifest": manifests[0], "r1_fixture_members": fixtures,
              "manifest_entries_compared": False,
              "note": "Every actual member is read and hashed. The exact original manifest is preserved for schema-aware comparison; no unperformed entry comparison is claimed."}
    return save_json("source-admission-original-archive-member-readback.json", record, transport=True)
report["source_admission_archive"] = attempt("read-original-source-admission-archive", recover_archive)
after = attempt("complete-source-after", source_state)
report["source_unchanged"] = before is not None and after == before
if not report["source_unchanged"]:
    failures.append({"step": "source-preservation", "error": "complete source state changed or unavailable"})
held_after = {
    "runner": sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
    "capsule": sha256(capsule.read_bytes()).hexdigest(),
}
report["held_inputs_unchanged"] = held_after == held_before
report["held_inputs"] = held_before
if held_after != held_before:
    failures.append({"step": "held-input-preservation", "error": "runner or capsule changed"})
report["wall_elapsed_ns"] = time.monotonic_ns() - started
report["failures"] = failures
report["status"] = "RECOVERY_AND_SOURCE_CHECKS_PASS" if not failures else "RECOVERY_OR_SOURCE_CHECKS_FAILED"
save_json("RESULT.json", report, transport=True)
packet = {"schema": "hia.v73.original-evidence-transport.v1", "files": []}
for name in transport_paths:
    raw = (out / name).read_bytes()
    packet["files"].append({"path": name, "bytes": len(raw), "sha256": sha256(raw).hexdigest(),
                            "content_base64": base64.b64encode(raw).decode("ascii")})
raw = (json.dumps(packet, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
compressed = zlib.compress(raw, 9)
header = {"schema": packet["schema"], "bytes": len(raw), "sha256": sha256(raw).hexdigest(),
          "compressed_bytes": len(compressed), "compressed_sha256": sha256(compressed).hexdigest(),
          "chunks": (len(compressed) + 17999) // 18000}
print("HIA_V73_RECOVERY_BEGIN " + json.dumps(header, sort_keys=True), flush=True)
for index, offset in enumerate(range(0, len(compressed), 18000)):
    chunk = compressed[offset:offset + 18000]
    print("HIA_V73_RECOVERY_CHUNK " + json.dumps({"index": index, "bytes": len(chunk),
          "sha256": sha256(chunk).hexdigest(), "base64": base64.b64encode(chunk).decode("ascii")}, sort_keys=True), flush=True)
print("HIA_V73_RECOVERY_END " + json.dumps(header, sort_keys=True), flush=True)
print(json.dumps({"status": report["status"], "source_unchanged": report["source_unchanged"],
                  "source_checks": report.get("source_checks"), "failure_count": len(failures),
                  "whole_closed": False}, sort_keys=True), flush=True)
raise SystemExit(1 if failures else 0)
