#!/usr/bin/env python3
"""Exact-candidate source generation and development controls; no cold/full claim."""
from __future__ import annotations
import argparse
import base64
from datetime import datetime, timezone
import gzip
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import time
import traceback
import zlib

MANIFEST = json.loads(r'''{
  "schema": "hepta.hia.v71.source-generation-candidate.v1",
  "candidate_branch": "codex/hia-heap-source-v71-20261112-dda7",
  "candidate_commit": "8b9fbcbeb943447bdbd4e534f081f92e5f1ad8b2",
  "candidate_tree": "1766691461d2ba7fef644e2b4e436566016f2226",
  "parent_commit": "67382498b9d60bfecf3696d8c2cb632d8f20281b",
  "parent_tree": "4412879c31f0a9fe489a76f123b919936f8bed67",
  "candidate_file_count": 3025,
  "explicit_support_files": 640,
  "dynamic_hepta_files": 181,
  "total_support_files": 821,
  "source_paths": [
    {
      "path": "MANIFEST.in",
      "bytes": 3798,
      "sha256": "3cdf39606053c5d1f07b47e02c0299279d9fac5fc916cbe8a8d1118fe325166a",
      "git_blob": "9927fc655b300e52643ca241e63a754d77a9681c",
      "mode": "100644"
    },
    {
      "path": "docs/HIA_HEAP_BOUND_NATIVE.md",
      "bytes": 12880,
      "sha256": "560753504617acab7f69e5b185ba928b42f7eb5baec9247425a36912ac3a2196",
      "git_blob": "82c21699c1dd7cc1a34887a14751ed3a728cf966",
      "mode": "100644"
    },
    {
      "path": "examples/hia_bootstrap/heap_bound.hiaasm",
      "bytes": 340198,
      "sha256": "36f7dac31a8b0e19e2e7782a4c4a5699f00025ef05c2b49cc1d19076f809c8db",
      "git_blob": "9431a5701b3426796b30cd721f730c180e2ee341",
      "mode": "100644"
    },
    {
      "path": "examples/hia_bootstrap/heap_live_engine.hiaasm",
      "bytes": 388398,
      "sha256": "c837a1559c1552d7ce1d911712d255b33f53eea07218fb8d420ce19c6ff08b4c",
      "git_blob": "bac5cbbf645792dafaa5b70459a52fbb5fcde3e6",
      "mode": "100644"
    },
    {
      "path": "examples/hia_bootstrap/heap_payload.hiaasm",
      "bytes": 261516,
      "sha256": "17f3f7591ae0b539f29002dd2288c7cb536971fab7b1a5f9b09d30c461b7b535",
      "git_blob": "4540103817fac8c1ab20bd3de88bd5b2d3449012",
      "mode": "100644"
    },
    {
      "path": "hepta/hia_agent_contract.py",
      "bytes": 19628,
      "sha256": "ead782c0b21928b5bb6b0379806937a4e090ff0075f1b5053756208c0f44e139",
      "git_blob": "5f4e3eaf534132f9c9e6ec421d6ec86a1fac2463",
      "mode": "100644"
    },
    {
      "path": "hepta/hia_checker_identity.py",
      "bytes": 9862,
      "sha256": "dd73718e87236b93fd4752ff29b36e87457162c171f61786c952d577d8b8b168",
      "git_blob": "a325b846dc414085ad141f8935efad93e84e2b07",
      "mode": "100644"
    },
    {
      "path": "hepta/hia_heap_bound.py",
      "bytes": 87165,
      "sha256": "c51ad178d08612852c0a5c58edb73d15297c48eb8bfdfd796dbe8214969978b8",
      "git_blob": "66a03aa025a9c9c180f42f6af5544f2e6b0c4430",
      "mode": "100644"
    },
    {
      "path": "hepta/hia_heap_bound_native.py",
      "bytes": 31210,
      "sha256": "19bb4194dd9791b68e11b792fc2f873cf2a68193ac6d1e6a6a3c553a688c8669",
      "git_blob": "3f7f5af9b95b717580032e265f42d3c3e72110ac",
      "mode": "100644"
    },
    {
      "path": "hepta/hia_heap_live_native.py",
      "bytes": 619,
      "sha256": "128477cda6e2f81b01b8544051d47410dae1ceddfb1e4a8820dff58c2217d3ef",
      "git_blob": "7994994c7c28f67067d662edad758875284adb34",
      "mode": "100644"
    },
    {
      "path": "hepta/hia_heap_payload_native.py",
      "bytes": 645,
      "sha256": "fa68f72e2354fde079d526f51ea001c73627d0fc5f6a8764e771c862fd53f86a",
      "git_blob": "284dd3476087264c3f0c7fdc1d466b3fe371c165",
      "mode": "100644"
    },
    {
      "path": "hepta/hia_native_helpers.py",
      "bytes": 11688,
      "sha256": "3052338ec45bbe6a80991cc3325d58f4c2e1197757dede7ff939fcf6ac171c19",
      "git_blob": "61196a4ce4fd6ee5dee8aabf5139540abaf7b627",
      "mode": "100644"
    },
    {
      "path": "hepta/hia_static_budget_native.py",
      "bytes": 16397,
      "sha256": "0ffab003672a5ee5c7095dc4c1306e7c86136064a6c11be3f7f386f02eb9afd7",
      "git_blob": "3c4e52295e74a61fce37fbbb2ca1a25b44691364",
      "mode": "100644"
    },
    {
      "path": "tests/hia_heap_native_fixture.py",
      "bytes": 6274,
      "sha256": "05a8e7af6d7967e2a64160331d5fb650bae8a13a0d4a5ed8e566ba3d2702d9ea",
      "git_blob": "ea957bb377cbc920b1f8e44751f0fa2c271b8f92",
      "mode": "100644"
    },
    {
      "path": "tests/hia_heap_public_controls.py",
      "bytes": 30563,
      "sha256": "281febae26968487fb6142d6292f48d1496a588503e77811f3d9350ef667d2b4",
      "git_blob": "fad4de31ae902ece34bf0067f7fdf270f2a70b0e",
      "mode": "100644"
    },
    {
      "path": "tests/test_hia_borrowed_extent_heap.py",
      "bytes": 33440,
      "sha256": "29cb3313a02f87656fd582979f6b766dd3776b762f9fc0b8a86c8d6c2d94b5de",
      "git_blob": "18441e75f4f4229c2dc07587fdd5de0410f29057",
      "mode": "100644"
    },
    {
      "path": "tests/test_hia_finite_v8_heap.py",
      "bytes": 27937,
      "sha256": "bdce6033ba3a51315c0118bc3e99d5c63a6cccd96fe242f4e51106dee583c47e",
      "git_blob": "025171007b4356576a95234769c5b34051ad9e8c",
      "mode": "100644"
    },
    {
      "path": "tests/test_hia_heap_bound_integration.py",
      "bytes": 15553,
      "sha256": "2f139808b15bc8adb7aa0a6e755a11b5eaa07934c8c0082ea00a5e36b7423be5",
      "git_blob": "e482021ccebc09e20aaa5e6b9d87d9c8f533dcde",
      "mode": "100644"
    },
    {
      "path": "tests/test_hia_heap_bound_native.py",
      "bytes": 31873,
      "sha256": "d3c4409c95781183e20c738069147b30df26df8a54a90246767056d89ad58c79",
      "git_blob": "729a03f4e19fa72bb612ea85a3416715b4d3b785",
      "mode": "100644"
    },
    {
      "path": "tests/test_hia_heap_live_engine_native.py",
      "bytes": 44444,
      "sha256": "6fde4c8984000a41383884dbad628d77a6cdbd7071e1b2b13f7881f535de922e",
      "git_blob": "277d8a2b22fb1073bd60b878b82863f1cab544df",
      "mode": "100644"
    },
    {
      "path": "tests/test_hia_partial_finite_bounds.py",
      "bytes": 23286,
      "sha256": "1efe720bea5bc3a5f3ccb44ece16e43aea25e09869cde17a8c3107068db9ada6",
      "git_blob": "d4deb6233ef6db02a4e8c853211e9d9ec1b0f93b",
      "mode": "100644"
    },
    {
      "path": "tools/build_hia_json_preflight.py",
      "bytes": 10334,
      "sha256": "cbd46e55f76f4dcfbe7ae3a73a5e0582f49c08d634b3664018f2a78d5a03afaf",
      "git_blob": "63bff7606afe7dd2c74c2ed0c44b10d0f84c13f7",
      "mode": "100644"
    },
    {
      "path": "tools/generate_hia_heap_bound.py",
      "bytes": 44836,
      "sha256": "9592f33b77a2860b919b23f1ee99fcb0ae58fa3ff0f2c6cd0b297f78f8b7cdb6",
      "git_blob": "92b95990d34233689602eff6fe666617853ac955",
      "mode": "100644"
    },
    {
      "path": "tools/hia_heap_live_engine.py",
      "bytes": 32315,
      "sha256": "db1d88a5b7f1540734e3b7e15d35252c102fff227b7cd23841e8fe9fb08e822c",
      "git_blob": "573ed239ba574e130cfbe3f4adbc50d730048e36",
      "mode": "100644"
    },
    {
      "path": "tools/hia_heap_live_state.py",
      "bytes": 8473,
      "sha256": "c9d3b7b6ea638337c350b3d617ac046c18a36368f076d06683358cfd60c48f9b",
      "git_blob": "5773b3edeefe8623d3fa068b429999166280feee",
      "mode": "100644"
    },
    {
      "path": "tools/hia_heap_live_transfers.py",
      "bytes": 5435,
      "sha256": "54f52d52849928374c3d2997e42b7cb345bab23455cf0f76d3302495e33c5919",
      "git_blob": "4283edfb150046b767b5894bf1fea4971d4be39b",
      "mode": "100644"
    },
    {
      "path": "tools/hia_heap_payload.py",
      "bytes": 37447,
      "sha256": "058129d3046163e24e300030020f9aa4c816879ead061cd7fff0ef1fec67be4c",
      "git_blob": "987454c8894748261b414de108562f759d4bdbdd",
      "mode": "100644"
    },
    {
      "path": "tools/hia_heap_scoped_cycle.py",
      "bytes": 10729,
      "sha256": "15a69848de1e7a6cd5c76b8c87236829637db06aefa06846924fd70fda2aa8a2",
      "git_blob": "cd34c15182357883de5d3177ea80d64154031ce5",
      "mode": "100644"
    },
    {
      "path": "tools/hia_native_heap_intervals.py",
      "bytes": 22158,
      "sha256": "8b030598323cb63b6b51face9c7e6e3672cc1cc98836385c13d2d149156b1e38",
      "git_blob": "703ad1bd824d8a8354771fdca8f157d6a688788c",
      "mode": "100644"
    },
    {
      "path": "tests/test_hia_static_budget_native.py",
      "bytes": 35229,
      "sha256": "9e5dc0d7f48fe331d76842edbc064a8cdbdfad0ab198925d5a41357eb24d6cdd",
      "git_blob": "9ccc6ad8c267219de1a8eca5ab1f24830c861ba5",
      "mode": "100644"
    },
    {
      "path": "tools/hia_selfhost_contract.py",
      "bytes": 128714,
      "sha256": "c5397a49e0587c8f5c6c2d6004e5dee1b178d1912135b52500e14352f2c46029",
      "git_blob": "dcfd69e5b7b17ff415e83b26db03b89750af8b68",
      "mode": "100644"
    },
    {
      "path": ".github/workflows/hia-core.yml",
      "bytes": 30862,
      "sha256": "9d1fe480849a3ef136c67ac3dc59c0242df20b8ebf1ce761450d055da7778c5e",
      "git_blob": "8b6653a66e867e1b61cc8537497e499553e381fa",
      "mode": "100644"
    },
    {
      "path": "tools/generate_hia_heap_kernels.py",
      "bytes": 1038,
      "sha256": "12e7503713f5dd0851f32553bf2dacb1a45aae450ec30a188ea577d0fd1e75e9",
      "git_blob": "3b6476bd30d32b04679cad569c349c0ca4decdf7",
      "mode": "100644"
    }
  ],
  "generators": {
    "support": [
      "python",
      "-B",
      "tools/generate_hia_selfhost_contract.py"
    ],
    "language_inventory": [
      "python",
      "-B",
      "tests/test_hia_selfhost_language_coverage.py",
      "--generate-inventory"
    ],
    "native_inventory": [
      "python",
      "-B",
      "tools/audit_hia_native_rewrite.py",
      "--output",
      "docs/HIA_NATIVE_REWRITE_INVENTORY.json"
    ]
  },
  "scope": "UNQUALIFIED_ISOLATED_SOURCE_CANDIDATE_REQUIRING_ACTUAL_GENERATED_RECORDS",
  "primary_pr_source_unchanged": "67382498b9d60bfecf3696d8c2cb632d8f20281b",
  "whole_native": false,
  "default_native": false,
  "live_migration": false,
  "legacy_deletion": false
}
''')
PHASE = "SOURCE_GENERATION_AND_DEVELOPMENT_CONTROLS"
SCHEMA = "hepta.hia.source-integration-v71.v1"
GENERATED = (
    "docs/HIA_SELFHOST_CORE_SUPPORT.json",
    "docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json",
    "docs/HIA_NATIVE_REWRITE_INVENTORY.json",
)
HEAP_ASSETS = (
    "examples/hia_bootstrap/heap_bound.hiaasm",
    "examples/hia_bootstrap/heap_live_engine.hiaasm",
    "examples/hia_bootstrap/heap_payload.hiaasm",
)
PACKAGES = {
    "setuptools": "78.1.1", "wheel": "0.46.3",
    "z3-solver": "4.15.4.0", "jsonschema": "4.26.0",
}
CLASSES = (
    "tests.test_hia_integrated_workflow.CoreWorkflowContractTests",
    "tests.test_hia_heap_bound_native.HeapBoundSourceTests",
    "tests.test_hia_heap_bound_native.HeapBoundAdapterTests",
    "tests.test_hia_heap_live_engine_native.HeapLiveEngineSourceTests",
)
CLAIMS = {
    "current_source_cold_qualified": False,
    "native_machine_controls_executed_by_this_driver": False,
    "whole_product_qualified": False, "default_native_enabled": False,
    "live_migration_performed": False, "legacy_deletion_authorized": False,
    "historical_passes_transferred": False,
}
# Unmodified test bodies and original internal limits. Only observation is added.
CONTROL_CHILD = r"""
import json
from pathlib import Path
import sys
import traceback
import unittest
source, target = Path(sys.argv[1]).resolve(strict=True), Path(sys.argv[2])
names = json.loads(sys.argv[3])
sys.path.insert(0, str(source))
record = {"schema": "hepta.hia.source-controls.v1", "status": "LOADING",
          "classes": names, "events": [], "loaded_ids": []}
def save():
    raw = (json.dumps(record, sort_keys=True, indent=2) + "\n").encode()
    tmp = target.with_suffix(".json.tmp")
    tmp.write_bytes(raw)
    tmp.replace(target)
def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item
class RecordingResult(unittest.TextTestResult):
    def startTest(self, test):
        record["events"].append({"event": "start", "test": test.id()})
        save()
        super().startTest(test)
    def addSuccess(self, test):
        record["events"].append({"event": "success", "test": test.id()})
        super().addSuccess(test)
    def addFailure(self, test, err):
        record["events"].append({"event": "failure", "test": test.id(),
                                "traceback": self._exc_info_to_string(err, test)})
        super().addFailure(test, err)
    def addError(self, test, err):
        record["events"].append({"event": "error", "test": test.id(),
                                "traceback": self._exc_info_to_string(err, test)})
        super().addError(test, err)
    def addSkip(self, test, reason):
        record["events"].append({"event": "skip", "test": test.id(), "reason": reason})
        super().addSkip(test, reason)
    def addExpectedFailure(self, test, err):
        record["events"].append({"event": "expected_failure", "test": test.id(),
                                "traceback": self._exc_info_to_string(err, test)})
        super().addExpectedFailure(test, err)
    def addUnexpectedSuccess(self, test):
        record["events"].append({"event": "unexpected_success", "test": test.id()})
        super().addUnexpectedSuccess(test)
    def addSubTest(self, test, subtest, err):
        if err is not None:
            record["events"].append({"event": "subtest_failure", "test": test.id(),
                                    "subtest": str(subtest),
                                    "traceback": self._exc_info_to_string(err, test)})
        super().addSubTest(test, subtest, err)
    def stopTest(self, test):
        super().stopTest(test)
        save()
save()
exit_code = 1
try:
    suite = unittest.defaultTestLoader.loadTestsFromNames(names)
    ids = [test.id() for test in flatten(suite)]
    counts = {name: sum(test.startswith(name + ".") for test in ids) for name in names}
    record.update(loaded_ids=ids, loaded_count=len(ids), counts_by_class=counts,
                  loader_errors=list(unittest.defaultTestLoader.errors))
    if record["loader_errors"] or len(ids) != len(set(ids)):
        raise RuntimeError("source-control loading failed or duplicated a test")
    if list(counts.values()) != [6, 5, 5, 4] or len(ids) != 20:
        raise RuntimeError("exact candidate source-control inventory changed")
    record["status"] = "RUNNING"
    save()
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordingResult).run(suite)
    success = (result.wasSuccessful() and result.testsRun == len(ids)
               and not result.skipped and not result.expectedFailures
               and not result.unexpectedSuccesses)
    record.update(status="PASS" if success else "FAIL", tests_run=result.testsRun,
                  failures=len(result.failures), errors=len(result.errors),
                  skips=len(result.skipped), expected_failures=len(result.expectedFailures),
                  unexpected_successes=len(result.unexpectedSuccesses))
    exit_code = 0 if success else 1
except BaseException:
    record["status"] = "FAIL"
    record["exception"] = traceback.format_exc()
    traceback.print_exc()
finally:
    save()
print(json.dumps({k: v for k, v in record.items()
                  if k not in ("events", "loaded_ids", "exception")}, sort_keys=True))
raise SystemExit(exit_code)
"""
REPORT, REPORT_PATH = {}, None
SOURCE = OUT = ENV = HEAD_ROWS = BEFORE = None

def now():
    return datetime.now(timezone.utc).isoformat()

def sha256(raw):
    return hashlib.sha256(raw).hexdigest()

def git_blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()

def byte_record(raw, content=True):
    result = {"bytes": len(raw), "sha256": sha256(raw)}
    if content:
        result["base64"] = base64.b64encode(raw).decode("ascii")
    return result

def require(value, message):
    if not value:
        raise RuntimeError(message)

def checkpoint():
    if REPORT_PATH is not None:
        raw = (json.dumps(REPORT, sort_keys=True, indent=2) + "\n").encode("utf-8")
        tmp = REPORT_PATH.with_suffix(".json.tmp")
        tmp.write_bytes(raw)
        tmp.replace(REPORT_PATH)

def run(name, argv):
    serial = len(REPORT["commands"]) + 1
    stdout, stderr = [OUT / f"{serial:03d}-{name}.{stream}" for stream in ("stdout", "stderr")]
    row = {"name": name, "argv": list(argv), "cwd": str(SOURCE),
           "started_utc": now(), "status": "RUNNING", "timeout_override": None}
    REPORT["commands"].append(row)
    checkpoint()
    start = time.monotonic()
    try:
        with stdout.open("wb") as so, stderr.open("wb") as se:
            done = subprocess.run(argv, cwd=SOURCE, env=ENV, stdout=so, stderr=se, check=False)
        row.update(returncode=done.returncode, status="PASS" if done.returncode == 0 else "FAIL")
    except BaseException:
        row.update(status="LAUNCH_OR_WAIT_ERROR", exception=traceback.format_exc())
        raise
    finally:
        row.update(finished_utc=now(), elapsed_seconds=time.monotonic() - start,
                   stdout=byte_record(stdout.read_bytes() if stdout.exists() else b""),
                   stderr=byte_record(stderr.read_bytes() if stderr.exists() else b""))
        checkpoint()
    require(done.returncode == 0, f"{name} returned {done.returncode}")
    return stdout.read_bytes()

def git(name, *args):
    return run("git-" + name, ["git", "-C", str(SOURCE), *args])

def parse_tree(raw):
    result = {}
    for entry in raw.split(b"\0"):
        if not entry:
            continue
        head, path_raw = entry.split(b"\t", 1)
        mode, kind, blob = head.decode("ascii").split()
        path = path_raw.decode("utf-8")
        pure = PurePosixPath(path)
        require(not pure.is_absolute() and ".." not in pure.parts and
                str(pure) == path and path not in result, "unsafe/duplicate Git path")
        require(kind == "blob" and mode in {"100644", "100755", "120000"},
                "unsupported Git entry: " + path)
        result[path] = {"git_mode": mode, "git_blob": blob}
    return result

def path_bytes(path, git_mode):
    target = SOURCE.joinpath(*PurePosixPath(path).parts)
    for parent in target.parents:
        if parent == SOURCE:
            break
        require(not parent.is_symlink(), "symlink ancestor: " + path)
    info = target.lstat()
    if git_mode == "120000":
        require(stat.S_ISLNK(info.st_mode), "Git symlink kind changed: " + path)
        raw = os.fsencode(os.readlink(target))
    else:
        require(stat.S_ISREG(info.st_mode), "not a regular file: " + path)
        require(bool(info.st_mode & 0o111) == (git_mode == "100755"),
                "executable mode changed: " + path)
        raw = target.read_bytes()
    return raw, stat.S_IMODE(info.st_mode)

def source_map(rows, require_head=False):
    result = {}
    for path, expected in sorted(rows.items()):
        raw, mode = path_bytes(path, expected["git_mode"])
        blob = git_blob(raw)
        if require_head:
            require(blob == expected["git_blob"], "worktree differs from HEAD: " + path)
        result[path] = {**byte_record(raw, False), "git_mode": expected["git_mode"],
                        "head_git_blob": expected["git_blob"], "actual_git_blob": blob,
                        "observed_posix_mode": mode}
    return result

def changed(before, after):
    return sorted(p for p in set(before) | set(after) if before.get(p) != after.get(p))

def require_no_untracked(label):
    other = git(label + "-untracked", "ls-files", "--others", "--exclude-standard", "-z")
    ignored = git(label + "-ignored", "ls-files", "--others", "--ignored", "--exclude-standard", "-z")
    require(not other and not ignored, "unexpected untracked or ignored files in source")

def context(label):
    return {
        "git_head": git(label + "-head", "rev-parse", "HEAD").decode().strip(),
        "git_head_tree": git(label + "-tree", "rev-parse", "HEAD^{tree}").decode().strip(),
        "index_vs_head_changed_paths": git(
            label + "-index", "diff", "--cached", "--name-only").decode().splitlines(),
        "worktree_vs_index_changed_paths": git(
            label + "-worktree", "diff", "--name-only").decode().splitlines(),
    }

def observe(label, allowed):
    current = source_map(HEAD_ROWS)
    differences = changed(BEFORE, current)
    row = {"label": label, "changed_from_initial": differences,
           "source_map_sha256": sha256(json.dumps(current, sort_keys=True).encode())}
    REPORT.setdefault("source_observations", []).append(row)
    if not set(differences).issubset(set(allowed)):
        row["source_map"] = current
    checkpoint()
    require(set(differences).issubset(set(allowed)), "unexpected source changes at " + label)
    frozen = {row["path"]: row for row in MANIFEST["source_paths"]}
    for path in HEAP_ASSETS:
        require((current[path]["sha256"], current[path]["bytes"]) ==
                (frozen[path]["sha256"], frozen[path]["bytes"]),
                "frozen HIA asset changed at " + label + ": " + path)
    return current

def generator_script():
    lines = (SOURCE / ".github/workflows/hia-core.yml").read_text(encoding="utf-8").splitlines()
    starts = [i for i, line in enumerate(lines)
              if line == "      - name: Regenerate actual HIA sources"]
    require(len(starts) == 1, "actual generator step missing or duplicated")
    start = starts[0]
    end = next((i for i in range(start + 1, len(lines))
                if lines[i].startswith("      - ")), len(lines))
    step = lines[start:end]
    begin = step.index("        run: |") + 1
    end = next((i for i in range(begin, len(step))
                if step[i] and not step[i].startswith("          ")), len(step))
    script = "\n".join(line[10:] for line in step[begin:end]) + "\n"
    require(script.startswith("set -eu\n") and "git diff --exit-code\n" in script,
            "original generator failure boundary changed")
    return script

def perform(args):
    global SOURCE, ENV, HEAD_ROWS, BEFORE
    SOURCE = Path(args.source).resolve(strict=True)
    require(SOURCE.is_dir(), "source is not a directory")
    require(args.expected_commit == MANIFEST["candidate_commit"], "candidate parameter mismatch")
    require(args.expected_tree == MANIFEST["candidate_tree"], "tree parameter mismatch")
    removed = sorted(key for key in os.environ if key.startswith("HEPTA_"))
    ENV = {key: value for key, value in os.environ.items() if not key.startswith("HEPTA_")}
    for key in ("PYTHONPATH", "PYTHONHOME"):
        if key in ENV:
            removed.append(key)
            del ENV[key]
    ENV.update(PYTHONDONTWRITEBYTECODE="1", GIT_TERMINAL_PROMPT="0")
    REPORT.update(removed_environment_names=removed, candidate_manifest=MANIFEST,
                  candidate_parameters={"commit": args.expected_commit, "tree": args.expected_tree},
                  paths={"source": str(SOURCE), "output": str(OUT)})
    require(git("format", "rev-parse", "--show-object-format").decode().strip() == "sha1",
            "unexpected Git object format")
    initial = context("initial")
    REPORT["initial_git_context"] = initial
    require(initial["git_head"] == args.expected_commit and
            initial["git_head_tree"] == args.expected_tree, "candidate HEAD/tree mismatch")
    require(not initial["index_vs_head_changed_paths"] and
            not initial["worktree_vs_index_changed_paths"], "candidate checkout not clean")
    parents = git("parents", "show", "-s", "--format=%P", "HEAD").decode().strip().split()
    require(parents == [MANIFEST["parent_commit"]], "candidate parent mismatch")
    base_tree = git("base-tree", "rev-parse", MANIFEST["parent_commit"] + "^{tree}").decode().strip()
    require(base_tree == MANIFEST["parent_tree"], "candidate base tree mismatch")
    require_no_untracked("initial")
    HEAD_ROWS = parse_tree(git("all-paths", "ls-tree", "-r", "-z", "HEAD"))
    require(len(HEAD_ROWS) == MANIFEST["candidate_file_count"], "candidate file count mismatch")
    BEFORE = source_map(HEAD_ROWS, require_head=True)
    REPORT["source_before"] = BEFORE
    paths = git("candidate-delta", "diff", "--name-only", "--no-renames", "-z",
                MANIFEST["parent_commit"], "HEAD")
    paths = sorted(p.decode("utf-8") for p in paths.split(b"\0") if p)
    expected = sorted(row["path"] for row in MANIFEST["source_paths"])
    require(paths == expected and len(paths) == 33, "candidate delta differs from frozen 33 paths")
    for row in MANIFEST["source_paths"]:
        got = BEFORE[row["path"]]
        require((got["bytes"], got["sha256"], got["actual_git_blob"], got["git_mode"]) ==
                (row["bytes"], row["sha256"], row["git_blob"], row["mode"]),
                "candidate manifest mismatch: " + row["path"])
    checkpoint()
    # Preserve the actual immutable Git source before any generator runs. The
    # full archive is an artifact, never embedded into the numbered report logs.
    archive_path = OUT / "candidate-source.tar"
    compressed_path = OUT / "candidate-source.tar.gz"
    git("archive-candidate-source", "archive", "--format=tar",
        "--output=" + str(archive_path), "HEAD")
    with archive_path.open("rb") as source_archive, compressed_path.open("wb") as target_archive:
        with gzip.GzipFile(filename="", mode="wb", fileobj=target_archive, mtime=0) as zipped:
            shutil.copyfileobj(source_archive, zipped)
    def file_identity(path):
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1048576), b""):
                digest.update(block)
        return {"bytes": path.stat().st_size, "sha256": digest.hexdigest()}
    REPORT["candidate_source_archive"] = {
        "source": "actual git archive HEAD before source generation",
        "candidate_commit": args.expected_commit, "candidate_tree": args.expected_tree,
        "git_file_count": len(HEAD_ROWS), "archive": file_identity(archive_path),
        "artifact_name": compressed_path.name, "gzip": file_identity(compressed_path),
        "full_source_embedded_in_report": False,
    }
    checkpoint()
    require(sys.version_info[:3] == (3, 14, 4), "Python must be exactly 3.14.4")
    if args.install_dependencies:
        run("install-pinned-source-dependencies", [
            sys.executable, "-m", "pip", "install",
            *[name + "==" + version for name, version in PACKAGES.items()]])
    actual = {name: importlib.metadata.version(name) for name in PACKAGES}
    REPORT["runtime"] = {"python": sys.version, "executable": sys.executable,
                         "packages": actual, "required_packages": PACKAGES}
    require(actual == PACKAGES, "source dependency pin mismatch")
    script = generator_script()
    REPORT["actual_generator_shell"] = byte_record(script.encode("utf-8"))
    checkpoint()
    run("actual-hia-core-generator-loop", ["bash", "--noprofile", "--norc", "-c", script])
    observe("after-actual-generator-loop", ())
    require_no_untracked("after-generators")
    # Coverage depends on semantic support, excluding source_identity. The full
    # support contract in turn hashes COVERAGE_PATH, so generate coverage first.
    run("generate-language-inventory", [
        sys.executable, "-B", "tests/test_hia_selfhost_language_coverage.py", "--generate-inventory"])
    observe("after-language-generation", (GENERATED[1],))
    run("validate-language-inventory", [
        sys.executable, "-B", "-c",
        "import json; from tests.test_hia_selfhost_language_coverage import validate_inventory; "
        "v=validate_inventory(); print(json.dumps({'status':'PASS',"
        "'semantic_support_sha256':v['source']['semantic_support_sha256']},sort_keys=True))"])
    run("generate-support-contract", [
        sys.executable, "-B", "tools/generate_hia_selfhost_contract.py"])
    observe("after-support-generation", GENERATED[:2])
    run("check-support-contract", [
        sys.executable, "-B", "tools/generate_hia_selfhost_contract.py", "--check"])
    support = json.loads((SOURCE / GENERATED[0]).read_bytes())
    REPORT["generated_support_file_count"] = len(support["source_identity"]["files"])
    require(REPORT["generated_support_file_count"] == MANIFEST["total_support_files"],
            "generated support closure file count differs from frozen candidate")
    git("stage-first-two-generated-records", "add", "--", *GENERATED[:2])
    generation_context = context("native-inventory-generation")
    REPORT["native_inventory_generation_git_context"] = generation_context
    require(not generation_context["worktree_vs_index_changed_paths"],
            "unstaged source before native inventory generation")
    checkpoint()
    run("generate-native-rewrite-inventory", [
        sys.executable, "-B", "tools/audit_hia_native_rewrite.py", "--output", GENERATED[2]])
    inventory = json.loads((SOURCE / GENERATED[2]).read_bytes())
    for key, value in generation_context.items():
        require(inventory.get(key) == value, "native inventory Git metadata differs: " + key)
    require(inventory["claims"] == {
        "whole_native_delivery_qualified": False, "old_stack_can_be_removed": False,
        "historical_tests_relabelled": False,
    }, "native inventory promoted qualification")
    REPORT["native_inventory_metadata_verified"] = generation_context
    observe("after-native-inventory-generation", GENERATED)
    git("stage-native-generated-record", "add", "--", GENERATED[2])
    child_result = OUT / "source-controls.json"
    REPORT["source_control_child"] = byte_record(CONTROL_CHILD.encode())
    checkpoint()
    try:
        run("original-workflow-and-new-source-adapter-controls", [
            sys.executable, "-I", "-B", "-c", CONTROL_CHILD, str(SOURCE),
            str(child_result), json.dumps(CLASSES)])
    finally:
        if child_result.exists():
            raw = child_result.read_bytes()
            REPORT["source_controls_raw"] = byte_record(raw)
            REPORT["source_controls"] = json.loads(raw)
            checkpoint()
    final = observe("after-original-source-controls", GENERATED)
    require_no_untracked("final")
    final_context = context("final")
    REPORT["final_git_context"] = final_context
    require(final_context["git_head"] == args.expected_commit and
            final_context["git_head_tree"] == args.expected_tree, "HEAD/tree changed")
    require(not final_context["worktree_vs_index_changed_paths"],
            "controls changed staged source records")
    require(set(final_context["index_vs_head_changed_paths"]) == set(changed(BEFORE, final)),
            "staged delta and actual final bytes differ")
    REPORT["source_after"] = final
    REPORT["status"] = "PASS"

def collect_final():
    if SOURCE is None or HEAD_ROWS is None:
        return
    try:
        final = source_map(HEAD_ROWS)
        REPORT["source_after"] = final
        if BEFORE is not None:
            differences = changed(BEFORE, final)
            REPORT["all_changed_paths"] = differences
            unexpected = sorted(set(differences) - set(GENERATED))
            REPORT["unexpected_changed_paths"] = unexpected
            if unexpected:
                REPORT["status"] = "FAIL"
            records = []
            for path in GENERATED:
                if path in differences:
                    raw, mode = path_bytes(path, HEAD_ROWS[path]["git_mode"])
                    records.append({"path": path, "before": BEFORE[path], "after": final[path],
                                    "content": byte_record(raw), "observed_posix_mode": mode})
            REPORT["changed_generated_records"] = records
    except BaseException:
        REPORT["final_observation_exception"] = traceback.format_exc()
        REPORT["status"] = "FAIL"

def export_report(path):
    if not path.is_file():
        fallback = {
            "schema": SCHEMA, "phase": PHASE, "status": "NOT_STARTED_OR_NO_REPORT",
            "created_utc": now(), "claims": CLAIMS, "expected_candidate": MANIFEST,
            "workflow_step_outcomes": {key: os.environ.get(key) for key in (
                "HIA_HARNESS_CHECKOUT_OUTCOME", "HIA_SOURCE_CHECKOUT_OUTCOME",
                "HIA_PYTHON_SETUP_OUTCOME", "HIA_DRIVER_OUTCOME")},
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes((json.dumps(fallback, sort_keys=True, indent=2) + "\n").encode())
    raw = path.read_bytes()
    packed = zlib.compress(raw, level=9)
    encoded = base64.b64encode(packed).decode("ascii")
    chunks = [encoded[i:i + 8192] for i in range(0, len(encoded), 8192)]
    identity = {
        "protocol": "HIA_SOURCE_V71_ZLIB_BASE64",
        "raw_bytes": len(raw), "raw_sha256": sha256(raw),
        "compressed_bytes": len(packed), "compressed_sha256": sha256(packed),
        "base64_chars": len(encoded), "chunk_count": len(chunks),
    }
    messages = [{"record": "begin", **identity}]
    for index, payload in enumerate(chunks):
        messages.append({"record": "chunk", "protocol": identity["protocol"],
                         "index": index, "chunk_count": len(chunks),
                         "data_sha256": sha256(payload.encode("ascii")), "data": payload})
    messages.append({"record": "end", **identity})
    lines = []
    for message in messages:
        line = json.dumps(message, sort_keys=True, separators=(",", ":"))
        require(len(line.encode("utf-8")) <= 12000, "export chunk exceeds 12KB")
        lines.append(line)
        print(line, flush=True)
    (path.parent / "EXPORT.json").write_text(
        json.dumps(identity, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    (path.parent / "REPORT.json.zlib").write_bytes(packed)
    (path.parent / "LOG_CHUNKS.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")

def main():
    global REPORT, REPORT_PATH, OUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--install-dependencies", action="store_true")
    parser.add_argument("--export-only", action="store_true")
    args = parser.parse_args()
    OUT = Path(args.output).resolve()
    source = Path(args.source).resolve()
    require(not OUT.is_relative_to(source), "evidence directory is inside source")
    OUT.mkdir(parents=True, exist_ok=True)
    REPORT_PATH = OUT / "REPORT.json"
    if args.export_only:
        export_report(REPORT_PATH)
        return 0
    require(not REPORT_PATH.exists(), "refusing to overwrite an earlier run report")
    REPORT = {
        "schema": SCHEMA, "phase": PHASE, "status": "RUNNING",
        "started_utc": now(), "claims": CLAIMS, "commands": [],
        "driver": {"path": str(Path(__file__).resolve()),
                   **byte_record(Path(__file__).read_bytes(), False)},
        "github": {key: os.environ.get(key) for key in (
            "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_REF", "GITHUB_RUN_ID",
            "GITHUB_RUN_ATTEMPT", "GITHUB_WORKFLOW", "RUNNER_OS", "RUNNER_ARCH")},
    }
    checkpoint()
    try:
        perform(args)
    except BaseException:
        REPORT["status"] = "FAIL"
        REPORT["exception"] = traceback.format_exc()
        traceback.print_exc()
    finally:
        collect_final()
        REPORT["finished_utc"] = now()
        checkpoint()
    print(json.dumps({"phase": PHASE, "status": REPORT["status"],
                      "report": str(REPORT_PATH),
                      "changed_generated_paths": [
                          row["path"] for row in REPORT.get("changed_generated_records", [])],
                      "current_source_cold_qualified": False}, sort_keys=True))
    return 0 if REPORT["status"] == "PASS" else 1

if __name__ == "__main__":
    raise SystemExit(main())
