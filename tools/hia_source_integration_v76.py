#!/usr/bin/env python3
"""Build a reviewable source tree from exact 5f7 plus a finite pinned overlay.

This stage performs source generation and source/ordinary-reference controls.
It does not create a source commit, run cold replay, or grant native/default/
migration/deletion qualification. Every original failure remains an outcome.
"""
from __future__ import annotations

import argparse
import ast
import base64
from datetime import datetime, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import sys
import time
import traceback
import zipfile
import zlib

import workflow_process

BASE_COMMIT = "5f7f95367e8e395863801487e969d286b9091110"
BASE_TREE = "4f4e58e06a6e03adcd6548bd8ea4ef591c20359f"
PROTECTED_SOURCE_PATHS = frozenset(("tools/check_hia_core_only.py",))
BASE_FILE_COUNT = 3120
SCHEMA = "hepta.hia.source-generation-v76.v1"
OVERLAY_SCHEMA = "hepta.hia.source-overlay.v1"
STEP_SECONDS = 1800
SUPERVISOR_SHA256 = "f3ebc453de2d2c9ecd3825547e301c122b6c7fa05af1aacd9103b8a67893ee80"
PACKAGES = {
    "setuptools": "78.1.1", "wheel": "0.46.3",
    "z3-solver": "4.15.4.0", "jsonschema": "4.26.0",
}
GENERATED_HIA = (
    "examples/hia_bootstrap/cli_control.hiaasm",
    "examples/hia_bootstrap/cli_format.hiaasm",
    "examples/hia_bootstrap/machine_encoding.hiaasm",
    "examples/hia_bootstrap/machine_state.hiaasm",
    "examples/hia_bootstrap/machine_instructions.hiaasm",
    "examples/hia_bootstrap/machine_elf.hiaasm",
    "examples/hia_bootstrap/machine_plan.hiaasm",
    "examples/hia_bootstrap/service_context.hiaasm",
    "examples/hia_bootstrap/heap_live_engine.hiaasm",
)
GENERATED_DOCS = (
    "docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json",
    "docs/HIA_SELFHOST_CORE_SUPPORT.json",
    "docs/HIA_NATIVE_REWRITE_INVENTORY.json",
)
MAX_GENERATED_PATHS = frozenset((*GENERATED_HIA, *GENERATED_DOCS))
EXTRA_GENERATORS = ("cli_control", "cli_format", "machine_encoding", "machine_state", "machine_instructions",
                    "machine_elf", "machine_plan", "service_context")
MANDATORY_CONTROLS = (
    "tests.test_hia_machine_elf_native.MachineElfSourceTests",
    "tests.test_hia_machine_plan_native.MachinePlanSourceTests",
    "tests.test_hia_service_context_native.ServiceContextSourceTests",
    "tests.test_hia_service_context_builder.ServiceContextAdapterTests",
    "tests.test_hia_macro_campaign.JournalTests",
    "tests.test_hia_macro_campaign.NativeObservationTests",
    "tests.test_hia_macro_campaign.WorkerSourceInventoryTests",
    "tests.test_hia_cli_native.CliSourceTests",
    "tests.test_hia_cli_continuation_native.CliContinuationSourceTests",
    "tests.test_hia_machine_encoding_native.MachineEncodingSourceTests",
    "tests.test_hia_machine_state_native.MachineStateSourceTests",
    "tests.test_hia_machine_instructions_native.MachineInstructionsSourceTests",
    "tests.test_hia_machine_code_composition.MachineCodeCompositionSourceTests",
    "tests.test_hia_source_build.SourceBuilderSourceTests",
    "tests.test_hia_program_selfhost.SelfhostBuildSourceTests",
    "tests.test_hia_source_release_integration.SourceReleaseIntegrationSourceTests",
    "tests.test_hia_source_release_integration.PublicationUnionCustodyTests",
    "tests.test_hia_source_admission_native.SourceAdmissionSourceTests",
    "tests.test_hia_artifact_publication_route.PublicationSealedDescriptorTests",
    "tests.test_hia_release_selection_review.ReleaseSelectionReviewPolicyTests",
    "tests.test_hia_agent_installed_resources.AgentInstalledResourceSourceTests",
    "tests.test_hia_selfhost_contract.SelfhostContractTests",
    'tests.test_hia_service_context_qualifier.ServiceContextQualifierSourceTests',
)
EXTRA_CONTROL_MAX = frozenset((*MANDATORY_CONTROLS,
    "tests.test_hia_integrated_workflow.CoreWorkflowContractTests",
    "tests.test_hia_program_normalization_native.ProgramNormalizationSourceTests",
    "tests.test_hia_program_normalization_native.ProgramNormalizationAdapterTests",
    "tests.test_hia_core_json_bytes_native.CoreJSONBytesSourceTests",
    "tests.test_hia_nominal_json_native.NominalJSONSourceTests",
    "tests.test_hia_cpython_note_packer_native.CPythonNotePackerSourceTests",
    "tests.test_hia_selfhost_linked_observer.LinkedObserverSourceTests",
    "tests.test_hia_candidate_evidence",
    "tests.test_hia_candidate_preflight",
))
CLAIMS = {
    "source_generation_only": True,
    "source_and_ordinary_reference_controls_only": True,
    "fixed_machine_custody_fixtures_may_execute": True,
    "component_native_test_classes_executed": False,
    "current_source_cold_qualified": False,
    "full_retained_suite_executed": False,
    "whole_native_delivery_qualified": False,
    "native_default_enabled": False,
    "live_migration_performed": False,
    "legacy_deletion_authorized_by_qualification": False,
    "historical_results_transferred": False,
    "source_commit_created": False,
}
CONTROL_CHILD = r"""
import json
from pathlib import Path
import sys
import traceback
import unittest

source, target = Path(sys.argv[1]).resolve(strict=True), Path(sys.argv[2])
names = json.loads(sys.argv[3])
sys.path.insert(0, str(source))
record = {"schema": "hepta.hia.source-control-observations.v76",
          "status": "LOADING", "selectors": names, "events": [], "loaded_ids": []}
def save():
    raw = (json.dumps(record, sort_keys=True, indent=2) + "\n").encode()
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_bytes(raw)
    temporary.replace(target)
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
    loader = unittest.defaultTestLoader
    selected = [(name, loader.loadTestsFromName(name)) for name in names]
    suite = unittest.TestSuite([part for _, part in selected])
    by_selector = {name: [test.id() for test in flatten(part)] for name, part in selected}
    ids = [test.id() for test in flatten(suite)]
    counts = {name: len(by_selector[name]) for name in names}
    duplicated = sorted({name for name in ids if ids.count(name) > 1})
    record.update(loaded_ids=ids, loaded_count=len(ids), counts_by_selector=counts,
                  ids_by_selector=by_selector, loader_errors=list(loader.errors),
                  duplicated_test_ids=duplicated)
    loading_ok = (not loader.errors and bool(ids) and not duplicated
                  and all(number > 0 for number in counts.values()))
    record["status"] = "RUNNING"
    save()
    result = unittest.TextTestRunner(verbosity=2, resultclass=RecordingResult).run(suite)
    success = (loading_ok and result.wasSuccessful() and result.testsRun == len(ids)
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
print(json.dumps({key: value for key, value in record.items()
                  if key not in ("events", "loaded_ids", "exception")}, sort_keys=True), flush=True)
raise SystemExit(exit_code)
"""

REPORT = {}
SOURCE = OUT = ENV = REPORT_PATH = None
BASE_ROWS = BEFORE = OVERLAY = OVERLAY_RAW = None
PRE_STAGE = None
GENERATOR_BASELINE = None
SOURCE_BEFORE_CONTENT = {}


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def strict_pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate JSON key: " + name)
        result[name] = value
    return result


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def save_json(path, value):
    raw = json_bytes(value)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(raw)
    temporary.replace(path)
    return identity(raw)


def identity(raw):
    return {"bytes": len(raw), "sha256": digest(raw), "blob": blob(raw)}


def file_identity(path):
    return identity(path.read_bytes())


def checkpoint():
    if REPORT_PATH is not None:
        save_json(REPORT_PATH, REPORT)


def live(value):
    print(json.dumps(value, ensure_ascii=True, sort_keys=True), flush=True)


def run(name, argv, *, check=True, cwd=None):
    """Every child uses the unchanged owned process supervisor and 1800 seconds."""
    serial = len(REPORT["commands"]) + 1
    stem = f"{serial:03d}-{name}"
    stdout = OUT / (stem + ".stdout")
    stderr = OUT / (stem + ".stderr")
    receipt = OUT / (stem + ".owner.json")
    argv = [os.fspath(value) for value in argv]
    directory = SOURCE if cwd is None else Path(cwd)
    row = {"serial": serial, "name": name, "argv": argv, "cwd": str(directory),
           "started_utc": now(), "status": "RUNNING", "wall_limit_seconds": STEP_SECONDS}
    REPORT["commands"].append(row)
    checkpoint()
    live({"step": name, "serial": serial, "status": "RUNNING",
          "wall_limit_seconds": STEP_SECONDS})
    started = time.monotonic()
    try:
        owner = workflow_process.run_workflow_step(
            argv, cwd=directory, env=ENV, stdout_path=stdout, stderr_path=stderr,
            receipt_path=receipt, seconds=STEP_SECONDS)
        row["owner"] = owner
        row["returncode"] = owner.get("returncode")
        row["timed_out"] = owner.get("timed_out")
        row["passed"] = (owner.get("status") == "WORKFLOW_STEP_COMPLETED"
                         and type(owner.get("returncode")) is int
                         and owner["returncode"] == 0
                         and owner.get("timed_out") is False
                         and owner.get("cleanup", {}).get("complete") is True)
        row["status"] = "PASS" if row["passed"] else "FAIL"
    except BaseException:
        row.update(status="LAUNCH_OR_WAIT_ERROR", passed=False,
                   exception=traceback.format_exc())
        raise
    finally:
        row.update(finished_utc=now(), elapsed_seconds=time.monotonic() - started)
        for key, path in (("stdout", stdout), ("stderr", stderr), ("receipt", receipt)):
            row[key] = ({"path": path.name, **file_identity(path)} if path.is_file()
                        else {"path": path.name, "missing": True})
        checkpoint()
        live({key: row.get(key) for key in
              ("serial", "name", "status", "returncode", "timed_out",
               "elapsed_seconds", "stdout", "stderr", "receipt")})
    if check:
        require(row["passed"], "command failed: " + name)
    return row, stdout.read_bytes() if stdout.is_file() else b""


def git(name, *args, check=True):
    return run("git-" + name, ["git", "--no-replace-objects", "-C", str(SOURCE),
        "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", *args], check=check)


def git_bytes(name, *args):
    return git(name, *args)[1]


def safe_path(path):
    require(type(path) is str and bool(path) and "\0" not in path and "\\" not in path,
            "invalid source path")
    pure = PurePosixPath(path)
    require(not pure.is_absolute() and str(pure) == path
            and ".." not in pure.parts and "." not in pure.parts
            and ".git" not in pure.parts, "unsafe source path: " + path)
    return pure


def parse_tree(raw):
    result = {}
    for item in raw.split(b"\0"):
        if not item:
            continue
        header, path_raw = item.split(b"\t", 1)
        mode, kind, sha = header.decode("ascii").split()
        path = path_raw.decode("utf-8", "strict")
        safe_path(path)
        require(path not in result and kind == "blob"
                and mode in ("100644", "100755", "120000")
                and re.fullmatch("[0-9a-f]{40}", sha), "unsupported/duplicate Git entry")
        result[path] = {"mode": mode, "blob": sha}
    return result


def actual_paths():
    result = []
    for directory, dirs, names in os.walk(SOURCE, followlinks=False):
        here = Path(directory)
        if here == SOURCE:
            dirs[:] = [name for name in dirs if name != ".git"]
        for name in list(dirs):
            path = here / name
            if path.is_symlink():
                result.append(path.relative_to(SOURCE).as_posix())
                dirs.remove(name)
        result.extend((here / name).relative_to(SOURCE).as_posix() for name in names)
    return sorted(result)


def read_path(path):
    pure = safe_path(path)
    target = SOURCE.joinpath(*pure.parts)
    for ancestor in target.parents:
        if ancestor == SOURCE:
            break
        require(not ancestor.is_symlink(), "symlink ancestor: " + path)
    info = target.lstat()
    if stat.S_ISLNK(info.st_mode):
        raw, mode = os.fsencode(os.readlink(target)), "120000"
    else:
        require(stat.S_ISREG(info.st_mode), "nonregular source object: " + path)
        raw = target.read_bytes()
        mode = "100755" if info.st_mode & stat.S_IXUSR else "100644"
    return raw, mode, stat.S_IMODE(info.st_mode)


def snapshot():
    result = {}
    for path in actual_paths():
        raw, mode, posix = read_path(path)
        result[path] = {**identity(raw), "mode": mode, "observed_posix_mode": posix}
    return result


def semantic_record(row):
    return None if row is None else (row["bytes"], row["sha256"], row["blob"], row["mode"])


def changes(before, after):
    return sorted(path for path in set(before) | set(after)
                  if semantic_record(before.get(path)) != semantic_record(after.get(path)))


def observe(label, baseline, allowed, *, require_all=None):
    current = snapshot()
    changed_paths = changes(baseline, current)
    missing = sorted(set(BEFORE) - set(current))
    unexpected = sorted(set(changed_paths) - set(allowed))
    invalid_generated_modes = {
        path: current[path]["mode"] for path in MAX_GENERATED_PATHS if path in current
        and current[path]["mode"] != BEFORE.get(path, {"mode": "100644"})["mode"]
    }
    generated_symlinks = sorted(path for path in MAX_GENERATED_PATHS
                                if path in current and current[path]["mode"] == "120000")
    protected_changes = sorted(path for path in PROTECTED_SOURCE_PATHS
                               if semantic_record(current.get(path)) != semantic_record(BEFORE.get(path)))
    row = {"label": label, "changed_paths": changed_paths,
           "unexpected_paths": unexpected, "missing_original_paths": missing,
           "snapshot": label + ".source.json",
           "invalid_generated_modes": invalid_generated_modes,
           "generated_symlinks": generated_symlinks,
           "protected_changes": protected_changes}
    save_json(OUT / row["snapshot"], current)
    REPORT.setdefault("source_observations", []).append(row)
    checkpoint()
    require(not missing, "an original source input disappeared at " + label)
    require(not unexpected, "unexpected source delta at " + label + ": " + repr(unexpected))
    require(not invalid_generated_modes and not generated_symlinks,
            "generated output changed Git mode or became a symlink at " + label)
    require(not protected_changes, "unchanged Core-only checker changed at " + label)
    if require_all is not None:
        require(set(current) == set(require_all), "source path set differs at " + label)
    return current


def context(label):
    return {
        "git_head": git_bytes(label + "-head", "rev-parse", "HEAD").decode().strip(),
        "git_head_tree": git_bytes(label + "-head-tree", "rev-parse", "HEAD^{tree}").decode().strip(),
        "index_vs_head_changed_paths": git_bytes(
            label + "-index", "diff", "--cached", "--name-only", "--no-renames").decode().splitlines(),
        "worktree_vs_index_changed_paths": git_bytes(
            label + "-worktree", "diff", "--name-only", "--no-renames").decode().splitlines(),
    }


def parse_generator_step(text):
    lines = text.splitlines()
    marker = "      - name: Regenerate actual HIA sources"
    require(lines.count(marker) == 1, "expected one actual source-generator step")
    start = lines.index(marker)
    end = next((i for i in range(start + 1, len(lines))
                if lines[i].startswith("      - ")), len(lines))
    section = lines[start:end]
    require(section.count("        run: |") == 1, "literal generator shell required")
    begin = section.index("        run: |") + 1
    body = section[begin:]
    require(all(not line or line.startswith("          ") for line in body),
            "unexpected generator-step fields")
    script = "\n".join(line[10:] if line else "" for line in body).rstrip() + "\n"
    match = re.fullmatch(
        r'set -eu\nfor component in ([a-z0-9_ ]+); do\n'
        r'  python -B -m "tools\.generate_hia_\$component"\n'
        r'done\ngit diff --exit-code\n', script)
    require(match is not None, "actual generator shell shape changed; inspect before adapting")
    names = match.group(1).split()
    require(names and len(names) == len(set(names)), "empty or duplicate generator inventory")
    return names, script


def workflow_source_names(text):
    marker = "      - name: Core source and independent reference controls\n"
    require(text.count(marker) == 1, "expected one exact workflow source-control step")
    section = re.split(r"(?m)^      - ", text.split(marker, 1)[1], maxsplit=1)[0]
    blocks = re.findall(r"          names = \((.*?)\n          \)", section, re.S)
    require(len(blocks) == 1, "expected one complete literal source tuple")
    values = ast.literal_eval("(" + blocks[0] + ")")
    require(type(values) is tuple and bool(values)
            and len(set(values)) == len(values)
            and all(type(value) is str and re.fullmatch(r"tests\.[A-Za-z0-9_.]+", value)
                    for value in values), "invalid original source-control tuple")
    return list(values)


def preserve_subsequence(original, current, label):
    require(len(set(current)) == len(current), "duplicate " + label)
    require([value for value in current if value in set(original)] == original,
            "original order or member changed: " + label)


def append_uncovered(names, item):
    if any(item == name or item.startswith(name + ".") for name in names):
        return
    require(not any(name.startswith(item + ".") for name in names),
            "new module selector would duplicate an existing class: " + item)
    names.append(item)


def source_controls(base_workflow, current_workflow, extra):
    original = workflow_source_names(base_workflow)
    current = workflow_source_names(current_workflow)
    preserve_subsequence(original, current, "source selectors")
    additions = [name for name in current if name not in original]
    require(set(additions).issubset(EXTRA_CONTROL_MAX),
            "unapproved new workflow source selector")
    names = list(current)
    for item in (*MANDATORY_CONTROLS, *extra):
        require(item in EXTRA_CONTROL_MAX or item in original,
                "unapproved extra source control: " + item)
        append_uncovered(names, item)
    for required in MANDATORY_CONTROLS:
        require(any(required == item or required.startswith(item + ".") for item in names),
                "mandatory source class not covered")
    require("tests.test_hia_source_admission_native.IndependentVMTests" not in names,
            "native-dependent IndependentVMTests cannot run in this source stage")
    return {"original_names": original, "workflow_names": current, "executed_selectors": names,
            "original_order_preserved": True, "new_workflow_selectors": additions,
            "extra_selectors": [name for name in names if name not in current]}


def decode_overlay(raw, args):
    require(digest(raw) == args.overlay_sha256, "overlay SHA256 differs from pinned input")
    value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=strict_pairs)
    allowed = {"schema", "base_commit", "base_tree", "files",
               "expected_generated_paths", "extra_controls"}
    require(type(value) is dict and set(value).issubset(allowed)
            and {"schema", "base_commit", "base_tree", "files"}.issubset(value),
            "invalid overlay object")
    require(value["schema"] == OVERLAY_SCHEMA
            and value["base_commit"] == args.expected_commit == BASE_COMMIT
            and value["base_tree"] == args.expected_tree, "overlay base identity differs")
    require(type(value["files"]) is list and bool(value["files"]), "finite nonempty file overlay required")
    seen = set()
    for row in value["files"]:
        require(type(row) is dict and set(row) ==
                {"path", "mode", "bytes", "sha256", "blob", "content"}, "invalid overlay file fields")
        path = row["path"]
        safe_path(path)
        require(path not in PROTECTED_SOURCE_PATHS, "overlay may not alter the original Core-only checker")
        require(path not in seen, "duplicate overlay file: " + path)
        seen.add(path)
        require(row["mode"] in ("100644", "100755")
                and type(row["content"]) is str
                and type(row["bytes"]) is int and row["bytes"] >= 0
                and type(row["sha256"]) is str and re.fullmatch("[0-9a-f]{64}", row["sha256"])
                and type(row["blob"]) is str and re.fullmatch("[0-9a-f]{40}", row["blob"]),
                "invalid overlay content/mode/identity: " + path)
        content = row["content"].encode("utf-8", "strict")
        require(identity(content) == {key: row[key] for key in ("bytes", "sha256", "blob")},
                "overlay bytes disagree with recorded identity: " + path)
        require(not path.endswith(".hepta"), "physical .hepta input violates unchanged Core-only policy")
    generated = value.get("expected_generated_paths", list((*GENERATED_HIA, *GENERATED_DOCS)))
    require(type(generated) is list and len(generated) == len(set(generated))
            and all(type(path) is str for path in generated)
            and set(generated) == MAX_GENERATED_PATHS,
            "generation whitelist differs; inspect and revise driver for a new explicit output")
    extra = value.get("extra_controls", [])
    require(type(extra) is list and len(extra) == len(set(extra))
            and all(type(name) is str and name in EXTRA_CONTROL_MAX for name in extra),
            "extra controls must be an explicit approved source-only list")
    value["expected_generated_paths"] = generated
    value["extra_controls"] = extra
    return value


def apply_overlay():
    for row in OVERLAY["files"]:
        path = row["path"]
        if path in BEFORE:
            require(BEFORE[path]["mode"] != "120000", "cannot replace a tracked symlink")
        target = SOURCE.joinpath(*safe_path(path).parts)
        for ancestor in target.parents:
            if ancestor == SOURCE:
                break
            require(not ancestor.is_symlink(), "overlay has symlink ancestor")
        target.parent.mkdir(parents=True, exist_ok=True)
        require(not target.is_symlink(), "overlay target is a symlink")
        target.write_bytes(row["content"].encode("utf-8", "strict"))
        target.chmod(0o755 if row["mode"] == "100755" else 0o644)
    paths = {row["path"] for row in OVERLAY["files"]}
    current = observe("after-overlay", BEFORE, paths,
                      require_all=set(BEFORE) | paths)
    for row in OVERLAY["files"]:
        require(semantic_record(current[row["path"]]) ==
                (row["bytes"], row["sha256"], row["blob"], row["mode"]),
                "overlay readback differs: " + row["path"])
    return current


def stage_known(label, allowed):
    """Stage only finite authorized paths in this exclusive checkout."""
    current = snapshot()
    delta = changes(BEFORE, current)
    require(set(BEFORE).issubset(current), "source deletion is not authorized")
    require(set(delta).issubset(set(allowed)), "refusing to stage an unexpected path")
    if delta:
        git(label + "-add", "add", "-f", "--", *delta)
    staged = {}
    for item in git_bytes(label + "-index-map", "ls-files", "--stage", "-z").split(b"\0"):
        if not item:
            continue
        header, path_raw = item.split(b"\t", 1)
        mode, sha, stage = header.decode("ascii").split()
        path = path_raw.decode("utf-8", "strict")
        safe_path(path)
        require(stage == "0" and mode in ("100644", "100755", "120000")
                and re.fullmatch("[0-9a-f]{40}", sha) and path not in staged,
                "nonzero/duplicate or malformed index stage")
        staged[path] = {"mode": mode, "blob": sha}
    require(set(staged) == set(current), "index/source path set differs")
    for path, row in staged.items():
        require((row["mode"], row["blob"]) == (current[path]["mode"], current[path]["blob"]),
                "index/source identity differs: " + path)
    require(not git_bytes(label + "-unstaged", "diff", "--name-only", "-z"),
            "unstaged source after exact staging")
    return current


def environment():
    discarded = {}
    env = dict(os.environ)
    for key in sorted(list(env)):
        if key.startswith("HEPTA_") or key in {
                "PYTHONPATH", "PYTHONHOME", "GIT_INDEX_FILE",
                "GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR",
                "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES"}:
            discarded[key] = {"bytes": len(env[key].encode()),
                              "sha256": digest(env[key].encode())}
            del env[key]
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1",
               GIT_TERMINAL_PROMPT="0")
    return env, discarded


def prerequisite_state():
    distribution_rows = {}
    for name, expected in PACKAGES.items():
        distribution = importlib.metadata.distribution(name)
        require(distribution.version == expected, "prerequisite version differs: " + name)
        records = {}
        require(distribution.files is not None, "prerequisite file inventory missing: " + name)
        for entry in sorted(distribution.files, key=str):
            path = Path(distribution.locate_file(entry))
            require(path.is_file(), "prerequisite file missing: " + str(path))
            records[str(entry)] = {"path": str(path.resolve()),
                                  **file_identity(path)}
        distribution_rows[name] = {"version": distribution.version, "files": records}
    programs = {}
    for name in ("python", "as", "objcopy", "ld", "cc", "git", "bash"):
        selected = shutil.which(name, path=ENV.get("PATH"))
        require(selected is not None, "required source tool unavailable: " + name)
        path = Path(selected).resolve(strict=True)
        programs[name] = {"path": str(path), **file_identity(path)}
    require(Path(programs["python"]["path"]) == Path(sys.executable).resolve(),
            "generator shell python differs from the admitted interpreter")
    return {"python": sys.version, "executable": str(Path(sys.executable).resolve()),
            "platform": platform.platform(), "machine": platform.machine(),
            "packages": distribution_rows, "programs": programs}


def check_harness_inputs():
    paths = {
        "driver": Path(__file__).resolve(),
        "workflow_process": Path(workflow_process.__file__).resolve(),
        "workflow": Path(__file__).resolve().parents[1] / ".github" / "workflows" / "hia-source-generation-v76.yml",
        "overlay": Path(REPORT["overlay_input"]["path"]),
    }
    require(paths["workflow_process"] == paths["driver"].with_name("workflow_process.py"),
            "workflow supervisor is not adjacent to this driver")
    require(digest(paths["workflow_process"].read_bytes()) == SUPERVISOR_SHA256,
            "original process supervisor bytes changed")
    return {name: {"path": str(path), **file_identity(path)}
            for name, path in paths.items()}


def support_snapshot():
    value = json.loads((SOURCE / GENERATED_DOCS[1]).read_bytes(),
                       object_pairs_hook=strict_pairs)
    files = value["source_identity"]["files"]
    require(type(files) is dict and bool(files), "support source closure missing")
    for name, expected in files.items():
        safe_path(name)
        require(type(expected) is str and re.fullmatch("[0-9a-f]{64}", expected),
                "invalid support source digest")
        raw, _, _ = read_path(name)
        require(digest(raw) == expected, "generated support closure is stale: " + name)
    return {"path": GENERATED_DOCS[1], **file_identity(SOURCE / GENERATED_DOCS[1]),
            "source_file_count": len(files), "files": files,
            "profile": value.get("profile")}


def perform(args):
    global SOURCE, ENV, BASE_ROWS, BEFORE, OVERLAY, OVERLAY_RAW, GENERATOR_BASELINE, PRE_STAGE
    SOURCE = Path(args.source).resolve(strict=True)
    require(SOURCE.is_dir(), "product source is not a directory")
    require(args.expected_commit == BASE_COMMIT, "v76 requires exact 5f7 base")
    require(args.expected_tree == BASE_TREE, "v76 requires the exact 5f7 tree")
    require((SOURCE / ".git").is_dir() and not (SOURCE / ".git").is_symlink(),
            "an exclusive complete checkout with its own .git directory is required")
    ENV, discarded = environment()
    REPORT["removed_environment"] = discarded
    REPORT["source_parameters"] = {"source": str(SOURCE), "base_commit": args.expected_commit,
                                   "base_tree": args.expected_tree,
                                   "expected_base_file_count": BASE_FILE_COUNT}
    require(git_bytes("object-format", "rev-parse", "--show-object-format").decode().strip() == "sha1",
            "unsupported Git object format")
    top = Path(git_bytes("toplevel", "rev-parse", "--show-toplevel").decode().strip()).resolve()
    common_raw = git_bytes("common-dir", "rev-parse", "--git-common-dir").decode().strip()
    common = (SOURCE / common_raw).resolve() if not Path(common_raw).is_absolute() else Path(common_raw).resolve()
    require(top == SOURCE and common == (SOURCE / ".git").resolve(),
            "source checkout borrows another worktree's Git metadata")
    initial = context("initial")
    REPORT["initial_git_context"] = initial
    require(initial["git_head"] == args.expected_commit
            and initial["git_head_tree"] == args.expected_tree,
            "source HEAD/tree differs from exact base")
    require(not initial["index_vs_head_changed_paths"]
            and not initial["worktree_vs_index_changed_paths"], "initial source is dirty")
    tree_raw = git_bytes("base-tree", "ls-tree", "-r", "-z", "HEAD")
    (OUT / "base-ls-tree.raw").write_bytes(tree_raw)
    BASE_ROWS = parse_tree(tree_raw)
    require(len(BASE_ROWS) == BASE_FILE_COUNT, "base tracked inventory is not complete")
    BEFORE = snapshot()
    require(set(BEFORE) == set(BASE_ROWS), "base has missing, untracked or ignored source files")
    for path, row in BASE_ROWS.items():
        require((BEFORE[path]["mode"], BEFORE[path]["blob"]) == (row["mode"], row["blob"]),
                "base worktree does not contain exact Git bytes: " + path)
    save_json(OUT / "source-before.json", BEFORE)
    REPORT["source_before"] = {"path": "source-before.json", "files": len(BEFORE),
                               **file_identity(OUT / "source-before.json")}
    base_workflow = (SOURCE / ".github/workflows/hia-core.yml").read_text(encoding="utf-8")
    (OUT / "workflow-base.yml").write_text(base_workflow, encoding="utf-8")
    original_generators, original_shell = parse_generator_step(base_workflow)
    original_names = workflow_source_names(base_workflow)
    REPORT["base_workflow"] = {"path": "workflow-base.yml",
                              **file_identity(OUT / "workflow-base.yml"),
                              "generators": original_generators,
                              "source_selectors": original_names}
    OVERLAY_RAW = Path(args.overlay).resolve(strict=True).read_bytes()
    OVERLAY = decode_overlay(OVERLAY_RAW, args)
    (OUT / "overlay-input.json").write_bytes(OVERLAY_RAW)
    REPORT["overlay_input"] = {"path": str(Path(args.overlay).resolve()),
                              "saved_path": "overlay-input.json",
                              **identity(OVERLAY_RAW),
                              "file_count": len(OVERLAY["files"]),
                              "files": [{key: value for key, value in row.items() if key != "content"}
                                        for row in OVERLAY["files"]],
                              "expected_generated_paths": OVERLAY["expected_generated_paths"],
                              "extra_controls": OVERLAY["extra_controls"]}
    REPORT["harness_before"] = check_harness_inputs()
    for name, row in REPORT["harness_before"].items():
        if name != "overlay":
            suffix = ".yml" if name == "workflow" else ".py"
            (OUT / ("harness-" + name + suffix)).write_bytes(Path(row["path"]).read_bytes())
    touched = {row["path"] for row in OVERLAY["files"]} | MAX_GENERATED_PATHS
    for path in sorted(touched & set(BEFORE)):
        raw, mode, posix = read_path(path)
        saved = OUT / "original-inputs" / path
        saved.parent.mkdir(parents=True, exist_ok=True)
        saved.write_bytes(raw)
        SOURCE_BEFORE_CONTENT[path] = {"mode": mode, "observed_posix_mode": posix,
                                      "saved_path": saved.relative_to(OUT).as_posix(),
                                      **identity(raw)}
    REPORT["retained_original_inputs"] = SOURCE_BEFORE_CONTENT
    checkpoint()
    require(sys.version_info[:3] == (3, 14, 4), "source harness Python must be exactly 3.14.4")
    require(sys.platform == "linux" and platform.machine() == "x86_64",
            "original source/ordinary-kernel controls require Linux x86-64")
    if args.install_dependencies:
        run("install-pinned-source-dependencies", [
            sys.executable, "-I", "-m", "pip", "install", "--isolated",
            *[name + "==" + version for name, version in PACKAGES.items()]])
    prerequisites = prerequisite_state()
    save_json(OUT / "prerequisites-before.json", prerequisites)
    REPORT["prerequisites_before"] = {
        "path": "prerequisites-before.json", **file_identity(OUT / "prerequisites-before.json")}
    post_overlay = apply_overlay()
    GENERATOR_BASELINE = post_overlay
    current_workflow = (SOURCE / ".github/workflows/hia-core.yml").read_text(encoding="utf-8")
    generators, current_shell = parse_generator_step(current_workflow)
    preserve_subsequence(original_generators, generators, "generator inventory")
    require(set(generators) - set(original_generators) <= set(EXTRA_GENERATORS),
            "unexpected new workflow generator")
    for component in EXTRA_GENERATORS:
        if component not in generators:
            generators.append(component)
    controls = source_controls(base_workflow, current_workflow, OVERLAY["extra_controls"])
    REPORT["generator_inventory"] = {
        "original": original_generators, "actual_workflow": parse_generator_step(current_workflow)[0],
        "construction_order": generators, "original_order_preserved": True,
        "extra_modules": list(EXTRA_GENERATORS),
        "ordinary_command_wall_limit_seconds": STEP_SECONDS,
        "construction_pass": "each original module in original order, then missing approved extra modules",
        "reproduction_pass": "exact source-owned shell including original git diff; missing extras checked separately",
    }
    REPORT["source_control_inventory"] = controls
    (OUT / "workflow-after-overlay.yml").write_text(current_workflow, encoding="utf-8")
    (OUT / "generator-original-shell.sh").write_text(original_shell, encoding="utf-8")
    (OUT / "generator-current-shell.sh").write_text(current_shell, encoding="utf-8")
    checkpoint()
    # Never generate over a source tree already violating the unchanged core boundary.
    run("original-core-only-before-generation",
        [sys.executable, "-B", "tools/check_hia_core_only.py"])
    observe("after-pre-generation-core-only", post_overlay, ())
    failed_generators = []
    for index, component in enumerate(generators):
        row, _ = run(f"generate-{index + 1:02d}-{component}",
                     [sys.executable, "-B", "-m", "tools.generate_hia_" + component], check=False)
        if not row["passed"]:
            failed_generators.append(component)
        observe(f"after-generator-{index + 1:02d}-{component}",
                post_overlay, GENERATED_HIA)
    REPORT["failed_generators"] = failed_generators
    checkpoint()
    require(not failed_generators, "one or more actual HIA generators failed")
    for path in GENERATED_HIA:
        require((SOURCE / path).is_file(), "required generated HIA source missing: " + path)
    # Semantic coverage excludes source_identity; support hashes the coverage file.
    run("generate-language-inventory", [sys.executable, "-B",
        "tests/test_hia_selfhost_language_coverage.py", "--generate-inventory"])
    observe("after-language-generation", post_overlay, (*GENERATED_HIA, GENERATED_DOCS[0]))
    run("validate-language-inventory", [sys.executable, "-B", "-c",
        "import json; from tests.test_hia_selfhost_language_coverage import validate_inventory; "
        "v=validate_inventory(); print(json.dumps({'status':'PASS',"
        "'semantic_support_sha256':v['source']['semantic_support_sha256']},sort_keys=True))"])
    run("generate-support-contract", [sys.executable, "-B", "tools/generate_hia_selfhost_contract.py"])
    observe("after-support-generation", post_overlay, (*GENERATED_HIA, *GENERATED_DOCS[:2]))
    run("check-support-contract", [sys.executable, "-B",
        "tools/generate_hia_selfhost_contract.py", "--check"])
    REPORT["generated_support"] = support_snapshot()
    allowed = {row["path"] for row in OVERLAY["files"]} | MAX_GENERATED_PATHS
    stage_known("pre-inventory", allowed)
    inventory_context = context("native-inventory-generation")
    require(inventory_context["git_head"] == args.expected_commit
            and inventory_context["git_head_tree"] == args.expected_tree,
            "source base identity changed before inventory")
    require(not inventory_context["worktree_vs_index_changed_paths"],
            "unstaged source before inventory")
    REPORT["native_inventory_generation_context"] = inventory_context
    checkpoint()
    run("generate-native-rewrite-inventory", [sys.executable, "-B",
        "tools/audit_hia_native_rewrite.py", "--output", GENERATED_DOCS[2]])
    inventory = json.loads((SOURCE / GENERATED_DOCS[2]).read_bytes(),
                           object_pairs_hook=strict_pairs)
    for key, value in inventory_context.items():
        require(inventory.get(key) == value, "inventory did not record actual Git context: " + key)
    require(inventory.get("claims") == {
        "whole_native_delivery_qualified": False, "old_stack_can_be_removed": False,
        "historical_tests_relabelled": False}, "inventory promoted an unsupported claim")
    observe("after-native-inventory", post_overlay, MAX_GENERATED_PATHS)
    PRE_STAGE = stage_known("final-generated-source", allowed)
    save_json(OUT / "source-frozen-for-controls.json", PRE_STAGE)
    REPORT["frozen_source_before_controls"] = {
        "path": "source-frozen-for-controls.json",
        **file_identity(OUT / "source-frozen-for-controls.json")}
    # The original script now runs without removing or weakening its git-diff gate.
    reproduction, _ = run("original-generator-script-and-git-diff-reproduction",
                          ["bash", "--noprofile", "--norc", "-c", current_shell], check=False)
    observe("after-original-generator-reproduction", PRE_STAGE, ())
    final_workflow_generators = parse_generator_step(current_workflow)[0]
    reproduction_failures = [] if reproduction["passed"] else ["original-generator-script"]
    for component in EXTRA_GENERATORS:
        if component not in final_workflow_generators:
            row, _ = run("reproduce-extra-" + component,
                         [sys.executable, "-B", "-m", "tools.generate_hia_" + component], check=False)
            if not row["passed"]:
                reproduction_failures.append(component)
            observe("after-extra-reproduction-" + component, PRE_STAGE, ())
    git("reproduction-diff", "diff", "--exit-code")
    checks = [
        ("original-core-only-final", [sys.executable, "-B", "tools/check_hia_core_only.py"]),
        ("original-support-check-final",
         [sys.executable, "-B", "tools/generate_hia_selfhost_contract.py", "--check"]),
        ("original-coverage-validation-final", [sys.executable, "-B", "-c",
         "from tests.test_hia_selfhost_language_coverage import validate_inventory; "
         "validate_inventory(); print('PASS')"]),
        ("original-diff-check", ["git", "--no-replace-objects", "-C", str(SOURCE),
                                 "diff", "--cached", "--check"]),
    ]
    failed_checks = list(reproduction_failures)
    for name, command in checks:
        row, _ = run(name, command, check=False)
        if not row["passed"]:
            failed_checks.append(name)
        observe("after-" + name, PRE_STAGE, ())
    child_result = OUT / "source-controls.json"
    (OUT / "source-controls-child.py").write_text(CONTROL_CHILD, encoding="utf-8")
    row, _ = run("complete-original-and-additional-source-controls", [
        sys.executable, "-I", "-B", "-c", CONTROL_CHILD, str(SOURCE),
        str(child_result), json.dumps(controls["executed_selectors"])], check=False)
    if not row["passed"]:
        failed_checks.append("source-controls-process")
    if child_result.is_file():
        value = json.loads(child_result.read_bytes(), object_pairs_hook=strict_pairs)
        REPORT["source_controls"] = {"path": child_result.name,
                                     **file_identity(child_result), "summary": value}
        passed = (value.get("status") == "PASS"
                  and type(value.get("tests_run")) is int and value["tests_run"] > 0
                  and value.get("tests_run") == value.get("loaded_count")
                  and all(type(value.get(key)) is int and value[key] == 0 for key in
                          ("failures", "errors", "skips", "expected_failures", "unexpected_successes")))
        if not passed:
            failed_checks.append("source-controls-outcome")
    else:
        failed_checks.append("source-controls-report-missing")
    observe("after-all-source-controls", PRE_STAGE, ())
    REPORT["failed_checks"] = failed_checks
    REPORT["harness_after"] = check_harness_inputs()
    require(REPORT["harness_after"] == REPORT["harness_before"], "harness/overlay bytes changed")
    after_prerequisites = prerequisite_state()
    save_json(OUT / "prerequisites-after.json", after_prerequisites)
    REPORT["prerequisites_after"] = {
        "path": "prerequisites-after.json", **file_identity(OUT / "prerequisites-after.json")}
    require(after_prerequisites == prerequisites, "prerequisite bytes changed during source controls")
    REPORT["status"] = "PASS" if not failed_checks else "FAIL"
    finalize_source_packet(args, allowed)
    checkpoint()
    require(not failed_checks, "original/new source checks failed")


def finalize_source_packet(args, allowed):
    final = stage_known("handoff", allowed)
    final_context = context("final")
    require(final_context["git_head"] == args.expected_commit
            and final_context["git_head_tree"] == args.expected_tree,
            "authentic base HEAD/tree changed")
    require(not final_context["worktree_vs_index_changed_paths"], "final source is unstaged")
    differences = changes(BEFORE, final)
    require(set(final_context["index_vs_head_changed_paths"]) == set(differences),
            "actual source delta and staged delta differ")
    write_tree = git_bytes("actual-write-tree", "write-tree").decode().strip()
    require(re.fullmatch("[0-9a-f]{40}", write_tree) is not None, "invalid actual write-tree")
    tree_rows = parse_tree(git_bytes("actual-write-tree-entries", "ls-tree", "-r", "-z", write_tree))
    require(set(tree_rows) == set(final), "write-tree source inventory differs")
    for path, row in tree_rows.items():
        require((row["mode"], row["blob"]) == (final[path]["mode"], final[path]["blob"]),
                "write-tree does not contain actual final bytes: " + path)
    entries = []
    for path in differences:
        raw, mode, posix = read_path(path)
        entry = {"path": path, "status": "modified" if path in BEFORE else "added",
                 "mode": mode, **identity(raw), "observed_posix_mode": posix,
                 "before": BEFORE.get(path)}
        try:
            content = raw.decode("utf-8", "strict")
        except UnicodeError:
            entry["encoding"] = "base64"
            entry["base64"] = base64.b64encode(raw).decode("ascii")
        else:
            require(content.encode("utf-8") == raw, "changed source UTF-8 roundtrip differs")
            entry["encoding"] = "utf-8"
            entry["content"] = content
        entries.append(entry)
    save_json(OUT / "source-after.json", final)
    packet = {
        "schema": "hepta.hia.source-generation-packet.v76",
        "status": "SOURCE_GENERATED_AND_CONTROLS_PASS" if REPORT["status"] == "PASS"
                  else "SOURCE_GENERATED_WITH_FAILED_CONTROLS_NOT_QUALIFIED",
        "base_commit": args.expected_commit, "base_tree": args.expected_tree,
        "authentic_head": final_context["git_head"],
        "authentic_head_tree": final_context["git_head_tree"],
        "future_source_commit": None, "actual_write_tree": write_tree,
        "source_commit_created": False,
        "overlay": REPORT["overlay_input"],
        "base_files": BEFORE, "base_file_count": len(BEFORE),
        "final_files": final, "final_file_count": len(final),
        "changed_paths": differences, "files": entries, "deleted_paths": [],
        "generated_hia": {path: final[path] for path in GENERATED_HIA},
        "generated_records": {path: final[path] for path in GENERATED_DOCS},
        "source_control_inventory": REPORT["source_control_inventory"],
        "source_controls": REPORT.get("source_controls"),
        "native_inventory_generation_context": REPORT["native_inventory_generation_context"],
        "final_git_context": final_context,
        "claims": CLAIMS,
    }
    save_json(OUT / "SOURCE-PACKET.json", packet)
    REPORT["source_packet"] = {"path": "SOURCE-PACKET.json", **file_identity(OUT / "SOURCE-PACKET.json"),
                              "actual_write_tree": write_tree,
                              "changed_paths": differences, "base_files": len(BEFORE),
                              "final_files": len(final)}
    REPORT["final_git_context"] = final_context
    REPORT["source_after"] = {"path": "source-after.json", **file_identity(OUT / "source-after.json")}
    checkpoint()


def collect_failure():
    if SOURCE is None or BEFORE is None:
        return
    try:
        final = snapshot()
        differences = changes(BEFORE, final)
        allowed = ({row["path"] for row in OVERLAY["files"]} | MAX_GENERATED_PATHS
                   if OVERLAY is not None else set())
        partial = {"schema": "hepta.hia.source-generation-partial.v76",
                   "status": "FAILURE_OBSERVATION_NOT_A_SOURCE_HANDOFF",
                   "source_before": BEFORE, "source_after": final,
                   "changed_paths": differences,
                   "missing_original_paths": sorted(set(BEFORE) - set(final)),
                   "unexpected_changed_paths": sorted(set(differences) - allowed),
                   "future_source_commit": None, "claims": CLAIMS}
        rows = []
        for path in differences:
            if path in final:
                raw, mode, posix = read_path(path)
                rows.append({"path": path, "mode": mode, "observed_posix_mode": posix,
                             **identity(raw), "base64": base64.b64encode(raw).decode("ascii")})
            else:
                rows.append({"path": path, "status": "missing", "before": BEFORE[path]})
        partial["changed_bytes"] = rows
        save_json(OUT / "PARTIAL-FAILURE-SOURCE.json", partial)
        REPORT["partial_failure_source"] = {
            "path": "PARTIAL-FAILURE-SOURCE.json",
            **file_identity(OUT / "PARTIAL-FAILURE-SOURCE.json")}
    except BaseException:
        REPORT["final_observation_exception"] = traceback.format_exc()


def export_payload(path, label):
    raw = path.read_bytes()
    packed = zlib.compress(raw, level=9)
    encoded = base64.b64encode(packed).decode("ascii")
    chunks = [encoded[index:index + 16384] for index in range(0, len(encoded), 16384)]
    metadata = {
        "protocol": "HIA_SOURCE_V75_ZLIB_BASE64", "payload": label,
        "raw_bytes": len(raw), "raw_sha256": digest(raw),
        "compressed_bytes": len(packed), "compressed_sha256": digest(packed),
        "base64_chars": len(encoded), "chunk_count": len(chunks),
    }
    messages = [{"record": "begin", **metadata}]
    for index, data in enumerate(chunks):
        messages.append({"record": "chunk", "protocol": metadata["protocol"],
                         "payload": label, "index": index, "chunk_count": len(chunks),
                         "data_bytes": len(data), "data_sha256": digest(data.encode("ascii")),
                         "data": data})
    messages.append({"record": "end", **metadata})
    lines = []
    for message in messages:
        line = json.dumps(message, sort_keys=True, separators=(",", ":"))
        require(len(line.encode("utf-8")) <= 18000, "export chunk exceeds 18000 bytes")
        lines.append(line)
        print(line, flush=True)
    packed_path = path.with_name(path.name + ".zlib")
    packed_path.write_bytes(packed)
    path.with_name(path.name + ".chunks.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    save_json(path.with_name(path.name + ".export.json"), metadata)
    return metadata


def evidence_zip():
    archive = OUT / "EVIDENCE.zip"
    require(not archive.exists(), "refusing to overwrite original evidence archive")
    rows = {}
    for path in sorted(OUT.rglob("*")):
        if path.is_dir():
            continue
        require(path.is_file() and not path.is_symlink(), "nonregular evidence input")
        relative = path.relative_to(OUT).as_posix()
        require(relative not in {"EVIDENCE-MANIFEST.json", "EVIDENCE-ZIP-RECEIPT.json"},
                "unexpected earlier evidence seal")
        rows[relative] = {**file_identity(path),
                          "posix_mode": stat.S_IMODE(path.stat().st_mode)}
    manifest = {"schema": "hepta.hia.source-evidence-manifest.v76", "files": rows,
                "file_count": len(rows), "claims": CLAIMS}
    manifest_path = OUT / "EVIDENCE-MANIFEST.json"
    save_json(manifest_path, manifest)
    all_paths = [OUT / name for name in sorted(rows)] + [manifest_path]
    with zipfile.ZipFile(archive, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zipped:
        for path in all_paths:
            zipped.write(path, path.relative_to(OUT).as_posix())
    with zipfile.ZipFile(archive) as zipped:
        require(zipped.testzip() is None, "raw evidence ZIP CRC failed")
        require(set(zipped.namelist()) == {path.relative_to(OUT).as_posix() for path in all_paths},
                "raw evidence ZIP member inventory differs")
        for path in all_paths:
            name = path.relative_to(OUT).as_posix()
            item = zipped.getinfo(name)
            raw = zipped.read(name)
            require(identity(raw) == file_identity(path)
                    and stat.S_IMODE(item.external_attr >> 16) == stat.S_IMODE(path.stat().st_mode),
                    "raw evidence ZIP byte/mode mismatch: " + name)
    receipt = {"schema": "hepta.hia.source-evidence-zip.v76", "path": archive.name,
               **file_identity(archive), "member_count": len(all_paths),
               "manifest": file_identity(manifest_path), "all_member_bytes_modes_crc_verified": True,
               "claims": CLAIMS}
    save_json(OUT / "EVIDENCE-ZIP-RECEIPT.json", receipt)
    live({"evidence_zip": receipt})


def export_only(args):
    path = OUT / "REPORT.json"
    if not path.is_file():
        fallback = {
            "schema": SCHEMA, "status": "NOT_STARTED_OR_NO_REPORT",
            "created_utc": now(), "claims": CLAIMS,
            "expected_base_commit": args.expected_commit, "expected_base_tree": args.expected_tree,
            "expected_overlay_sha256": args.overlay_sha256,
            "github": {key: os.environ.get(key) for key in
                       ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA")},
            "workflow_step_outcomes": {key: os.environ.get(key) for key in
                ("HIA_HARNESS_CHECKOUT_OUTCOME", "HIA_SOURCE_CHECKOUT_OUTCOME",
                 "HIA_PYTHON_SETUP_OUTCOME", "HIA_DRIVER_OUTCOME")},
        }
        save_json(path, fallback)
    report = json.loads(path.read_bytes(), object_pairs_hook=strict_pairs)
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        require(report.get("github", {}).get(key) == os.environ.get(key),
                "refusing to relabel a report from another workflow attempt")
    for filename in ("REPORT.json", "SOURCE-PACKET.json", "PARTIAL-FAILURE-SOURCE.json"):
        target = OUT / filename
        if target.is_file():
            export_payload(target, filename)
    evidence_zip()


def main():
    global OUT, REPORT_PATH, REPORT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--overlay", required=True)
    parser.add_argument("--overlay-sha256", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--install-dependencies", action="store_true")
    parser.add_argument("--export-only", action="store_true")
    args = parser.parse_args()
    source = Path(args.source).resolve()
    OUT = Path(args.output).resolve()
    require(not OUT.is_relative_to(source) and not source.is_relative_to(OUT),
            "source/evidence directories overlap")
    require(not OUT.is_relative_to(Path(__file__).resolve().parent),
            "evidence must be outside the immutable harness input directory")
    require(re.fullmatch("[0-9a-f]{64}", args.overlay_sha256) is not None,
            "overlay SHA256 must be explicitly pinned")
    if args.export_only:
        OUT.mkdir(mode=0o700, parents=True, exist_ok=True)
        export_only(args)
        return 0
    OUT.mkdir(mode=0o700, parents=True, exist_ok=False)
    REPORT_PATH = OUT / "REPORT.json"
    REPORT = {
        "schema": SCHEMA, "status": "RUNNING", "started_utc": now(),
        "claims": CLAIMS, "commands": [],
        "driver": {"path": str(Path(__file__).resolve()),
                   **file_identity(Path(__file__).resolve())},
        "github": {key: os.environ.get(key) for key in
            ("GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_REF", "GITHUB_RUN_ID",
             "GITHUB_RUN_ATTEMPT", "GITHUB_WORKFLOW", "RUNNER_OS", "RUNNER_ARCH")},
    }
    checkpoint()
    try:
        perform(args)
    except BaseException:
        REPORT["status"] = "FAIL"
        REPORT["exception"] = traceback.format_exc()
        traceback.print_exc()
        collect_failure()
    finally:
        REPORT["finished_utc"] = now()
        checkpoint()
    live({"stage": "source-generation", "status": REPORT["status"],
          "report": str(REPORT_PATH), "source_packet": REPORT.get("source_packet"),
          "current_source_cold_qualified": False,
          "future_source_commit": None})
    return 0 if REPORT["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
