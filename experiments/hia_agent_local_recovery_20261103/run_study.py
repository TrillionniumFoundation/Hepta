#!/usr/bin/env python3
"""A new owner-evidence registry for the unchanged three-arm v4 protocol.

Original sources, registration and results remain unchanged. Inference and
scoring reuse v4 with newly frozen source/tool/model identities.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True
if __name__ == "__main__":
    # Unit controls import this same adapter; avoid a second module instance
    # capturing an already-installed validation hook.
    sys.modules["experiments.hia_agent_local_recovery_20261103.run_study"] = sys.modules[__name__]

from experiments.hia_agent_assembly_v4_20261030 import controls, evaluator, fixtures
from experiments.hia_agent_assembly_v4_20261030 import run_study as inherited
from experiments.hia_agent_assembly_v4_20261030 import tokenizer_check
from tools.hia_agent_codex_transport import strict_json
from tools.provider_adapter.llama_cpp_engine import file_identity

HERE = Path(__file__).resolve().parent
PARENT = ROOT / "experiments/hia_agent_assembly_v4_20261030"
CAMPAIGN = "local-recovery-20261103"
_VALIDATE = inherited.validate_registration


def owner_path(value):
    path = Path(value)
    if not path.is_absolute() or path.resolve().is_relative_to(ROOT):
        raise ValueError("owner evidence must be absolute and outside source")
    return path.resolve()


def check_protocol(actual, expected):
    if actual != expected:
        raise ValueError("recovery must preserve the exact v4 protocol bytes")


def source_bindings():
    paths = set((ROOT / "hepta").glob("*.py"))
    paths.update(PARENT.glob("*.py")); paths.update(HERE.glob("*.py"))
    paths.update((HERE / "PROTOCOL.json", PARENT / "PROTOCOL.json"))
    for module in tuple(sys.modules.values()):
        name = getattr(module, "__file__", None)
        if name:
            path = Path(name).resolve()
            if path.is_relative_to(ROOT) and path.suffix == ".py":
                paths.add(path)
    return {str(path.relative_to(ROOT)): file_identity(path)["sha256"] for path in sorted(paths)}


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def require_committed_sources():
    for name, expected in source_bindings().items():
        raw = subprocess.check_output(["git", "show", "HEAD:" + name], cwd=ROOT)
        if hashlib.sha256(raw).hexdigest() != expected:
            raise ValueError("uncommitted study source: " + name)


def activate(registry):
    folder = owner_path(registry)
    check_protocol((HERE / "PROTOCOL.json").read_bytes(), (PARENT / "PROTOCOL.json").read_bytes())
    check_protocol((folder / "PROTOCOL.json").read_bytes(), (HERE / "PROTOCOL.json").read_bytes())
    inherited.HERE = folder
    inherited.SCHEMA = "hepta.agent.assembly-maintenance-upgrade.v4.recovery-20261103"
    inherited.source_bindings = source_bindings
    inherited.validate_registration = validate_registration
    return folder


def validate_registration():
    value = _VALIDATE()
    if (value.get("campaign") != CAMPAIGN
            or value.get("source_commit") != git("rev-parse", "HEAD")
            or value.get("source_tree") != git("rev-parse", "HEAD^{tree}")
            or value.get("inherited_protocol_sha256") != file_identity(PARENT / "PROTOCOL.json")["sha256"]):
        raise ValueError("recovery source commit/tree or parent protocol changed")
    return value


def test_ids(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from test_ids(item)
        else:
            yield item.id()


def prepare(registry, output, binary, qwen, granite, clang, rustc):
    folder, artifacts = owner_path(registry), owner_path(output)
    folder.mkdir(parents=True, exist_ok=False); artifacts.mkdir(parents=True, exist_ok=False)
    (folder / "PROTOCOL.json").write_bytes((HERE / "PROTOCOL.json").read_bytes())
    activate(folder); require_committed_sources()
    started = time.monotonic_ns(); log = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromNames([
        "experiments.hia_agent_assembly_v4_20261030.test_protocol",
        "experiments.hia_agent_local_recovery_20261103.test_recovery"])
    ids = list(test_ids(suite))
    with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
        result = unittest.TextTestRunner(stream=log, verbosity=2).run(suite)
    (artifacts / "unit-controls.log").write_text(log.getvalue())
    # Absolute keys bind the actual executed sources despite the owner registry.
    units = {"tests_run": result.testsRun, "test_ids": ids,
             "failures": len(result.failures), "errors": len(result.errors),
             "skipped": len(result.skipped), "passed": result.wasSuccessful() and not result.skipped,
             "source_sha256": {str(p): file_identity(p)["sha256"]
                 for p in sorted({*PARENT.glob("*.py"), *HERE.glob("*.py")})},
             "model_requests": 0, "fixture_outputs_are_model_results": False}
    evaluator.save(folder / "UNIT_CONTROLS.json", units)
    if not units["passed"]:
        raise ValueError("orchestration controls failed; no tokenizer/inference startup")
    reference = evaluator.reference_controls(fixtures.make_fixtures(), artifacts / "reference", clang, rustc)
    evaluator.save(folder / "DEVELOPMENT_CONTROLS.json", reference)
    hostile = controls.run(artifacts / "hostile", clang, rustc)
    evaluator.save(folder / "HOSTILE_CONTROLS.json", hostile)
    if reference["count"] != 36 or reference["passed"] != 36 or hostile["count"] != 9 or hostile["passed"] != 9:
        raise ValueError("native controls failed; no tokenizer/inference startup")
    capacity = tokenizer_check.run(artifacts / "tokenizer", binary, qwen, granite)
    evaluator.save(folder / "TOKENIZER_CAPACITY.json", capacity)
    value = {"campaign": CAMPAIGN, "source_commit": git("rev-parse", "HEAD"),
             "source_tree": git("rev-parse", "HEAD^{tree}"), "sources": source_bindings(),
             "model_requests": capacity["model_requests"], "passed": capacity["passed"],
             "wall_ns": time.monotonic_ns() - started,
             "unit_controls": file_identity(folder / "UNIT_CONTROLS.json"),
             "reference_controls": file_identity(folder / "DEVELOPMENT_CONTROLS.json"),
             "hostile_controls": file_identity(folder / "HOSTILE_CONTROLS.json"),
             "tokenizer_capacity": file_identity(folder / "TOKENIZER_CAPACITY.json")}
    evaluator.save(folder / "PREPARATION.json", value)
    return value


def freeze(registry):
    folder = activate(registry)
    if (folder / "REGISTRATION.json").exists():
        raise ValueError("registration already exists; never replace a cohort")
    preparation = strict_json((folder / "PREPARATION.json").read_bytes())
    if (preparation.get("passed") is not True or preparation.get("model_requests") != 0
            or preparation.get("source_commit") != git("rev-parse", "HEAD")
            or not inherited.check_bindings(preparation["sources"])):
        raise ValueError("current exact-source no-generation preparation required")
    require_committed_sources()
    value = inherited.register()
    value.update(campaign=CAMPAIGN, source_commit=git("rev-parse", "HEAD"),
                 source_tree=git("rev-parse", "HEAD^{tree}"),
                 inherited_protocol_sha256=file_identity(PARENT / "PROTOCOL.json")["sha256"],
                 preparation=file_identity(folder / "PREPARATION.json"),
                 original_campaigns_replaced=False, frontier_model_cohort_completed=False)
    evaluator.save(folder / "REGISTRATION.json", value)
    return validate_registration()


def check_review(review, registration, registration_sha256):
    if (review.get("decision") != "allow_generation"
            or review.get("registration_sha256") != registration_sha256
            or review.get("source_commit") != registration["source_commit"]
            or review.get("protocol_sha256") != registration["protocol_sha256"]
            or type(review.get("model_task_requests_by_reviewer")) is not int
            or review["model_task_requests_by_reviewer"] != 0):
        raise ValueError("independent review of the exact recovery registration required")


def run(registry, review, expected_head, **kwargs):
    folder = activate(registry); value = validate_registration()
    if expected_head != value["source_commit"]:
        raise ValueError("expected source head differs from exact recovery registration")
    check_review(strict_json(Path(review).read_bytes()), value,
                 file_identity(folder / "REGISTRATION.json")["sha256"])
    owner_path(kwargs["output"])
    # v4 refuses an existing family directory and enforces the registered
    # family/cell order, budgets, process ownership and scoring gates.
    return inherited.run(**kwargs)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--registry", required=True)
    commands = parser.add_subparsers(dest="action", required=True)
    p = commands.add_parser("prepare")
    for name in ("output", "binary", "qwen", "granite", "clang", "rustc"):
        p.add_argument("--" + name, required=True)
    commands.add_parser("freeze"); commands.add_parser("validate")
    p = commands.add_parser("run")
    for name in ("output", "model-id", "model-path", "binary", "clang", "rustc", "review", "expected-head"):
        p.add_argument("--" + name, required=True)
    p = commands.add_parser("summarize"); p.add_argument("--output", required=True)
    args = vars(parser.parse_args(argv)); action = args.pop("action")
    if action in {"prepare", "freeze", "run"}:
        result = {"prepare": prepare, "freeze": freeze, "run": run}[action](**args)
    else:
        activate(args.pop("registry"))
        result = validate_registration() if action == "validate" else inherited.summarize(**args)
    print(json.dumps({"action": action, "status": result.get("status", "completed"),
                      "passed": result.get("passed"),
                      "model_requests": result.get("new_requests", result.get("model_requests"))}))
    return 1 if result.get("status") == "incomplete" or result.get("passed") is False else 0


if __name__ == "__main__":
    raise SystemExit(main())
