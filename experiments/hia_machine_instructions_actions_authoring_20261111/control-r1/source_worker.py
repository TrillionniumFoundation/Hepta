"""Execute only frozen instruction source authoring under the unchanged 180s owner."""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
from author_common import (BASE_COMMIT, BASE_TREE, GOOD_AUTHOR_STATUS, atomic_report,
    base_entries, below, blob, check_unchanged_outside, create, digest, git,
    index_snapshot, load_policy, read_regular, require, save_new)
import subprocess

root = Path(sys.argv[1]).resolve(strict=True)
source = Path(sys.argv[2]).resolve(strict=True)
control = Path(__file__).resolve().parent
policy = load_policy(control)
started = time.monotonic()
report = {
    "schema": "hia.machine-instructions.complete-actions-authoring.v1",
    "status": "STARTED", "scope": "ISOLATED_SOURCE_AUTHORING_ONLY",
    "frozen_prototype_commit": policy["prototype_commit"], "commands": [],
    "native_compilation_executed": False, "product_tests_executed": False,
    "matching_current_cold": False, "whole_native_delivery": False,
    "python": sys.version, "executable": sys.executable,
    "base_product_commit": BASE_COMMIT, "base_product_tree": BASE_TREE,
}

def run(label, arguments):
    at = time.monotonic()
    out = root / "commands" / (label + ".stdout")
    err = root / "commands" / (label + ".stderr")
    create(out, b"")
    create(err, b"")
    item = {"label": label, "argv": arguments, "cwd": str(source), "returncode": None}
    try:
        with out.open("ab", buffering=0) as stdout, err.open("ab", buffering=0) as stderr:
            result = subprocess.run(arguments, cwd=source, stdin=subprocess.DEVNULL,
                                    stdout=stdout, stderr=stderr, timeout=120, close_fds=True)
        item["returncode"] = result.returncode
        require(result.returncode == 0, label + " returned " + str(result.returncode))
    except BaseException:
        item["exception"] = traceback.format_exc()
        raise
    finally:
        item["seconds"] = time.monotonic() - at
        for key, path in (("stdout", out), ("stderr", err)):
            raw, _ = read_regular(path)
            item[key] = {"path": path.relative_to(root).as_posix(), "bytes": len(raw), "sha256": digest(raw)}
        report["commands"].append(item)
        atomic_report(root / "worker-report.json", report)

def document_caps(document,raw):
    functions=[]
    for function in document['functions']:
        definitions=list(function['params'])
        for block in function['blocks']:
            definitions+=block['params']
            for operation in block['ops']:
                definitions+=operation['out']
            if len(block['params'])>16:raise ValueError('original block parameter limit')
            term=block['term']
            edges=[term] if term['op']=='jump' else [term['then'],term['else']] if term['op']=='branch' else []
            if any(len(edge['args'])>16 for edge in edges):raise ValueError('original edge parameter limit')
        row={'name':function['name'],'parameters':len(function['params']),
             'blocks':len(function['blocks']),'operations':sum(len(b['ops']) for b in function['blocks']),
             'unique_ssa_names':len({v['name'] for v in definitions}),
             'largest_numeric_suffix_observed_only':max(int(v['name'][1:]) for v in definitions)}
        if row['parameters']>16 or row['blocks']>256 or row['unique_ssa_names']>2048:
            raise ValueError('original per-function caps exceeded '+str(row))
        functions.append(row)
    totals={'source_bytes':len(raw),'source_lines':len(raw.splitlines()),'functions':len(functions),
            'blocks':sum(f['blocks'] for f in functions),'operations':sum(f['operations'] for f in functions)}
    for key,limit in [('source_bytes',1048576),('source_lines',16384),('functions',128),('blocks',1536),('operations',8192)]:
        if totals[key]>limit:raise ValueError('original '+key+' limit exceeded')
    return {'totals':totals,'per_function':functions}

baseline = None
try:
    require(tuple(sys.version_info[:3]) == (3, 14, 4), "authoring interpreter is not fixed Python 3.14.4")
    base = base_entries(source)
    require(git(source, "write-tree").decode().strip() == BASE_TREE, "initial index differs")
    baseline = index_snapshot(source)
    require(len(baseline) == 3933, "complete initial source count differs")
    require([{k: r[k] for k in ("path", "mode", "git_blob")} for r in baseline] == base,
            "full baseline source bytes/modes differ")
    save_new(root / "base-source-leaves.json", baseline)
    parsed = []
    for item in policy["files"]:
        raw, _ = read_regular(control / item["control_path"])
        require(len(raw) == item["bytes"] and blob(raw) == item["sha"]
                and digest(raw) == item["sha256"], "frozen input differs: " + item["path"])
        target = below(source, item["path"])
        if target.exists():
            read_regular(target)
            descriptor = os.open(target, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            target.chmod(0o644)
        else:
            create(target, raw, 0o644)
        if item["path"].endswith(".py"):
            ast.parse(raw.decode("utf-8"), filename=item["path"])
            parsed.append(item["path"])
    report["parsed_python_files"] = parsed
    run("generate-instructions", [sys.executable, "-B", "-m", "tools.generate_hia_machine_instructions"])
    sys.path.insert(0, str(source))
    from tools.generate_hia_machine_instructions import document, MODES
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    generated = source / "examples/hia_bootstrap/machine_instructions.hiaasm"
    raw, _ = read_regular(generated)
    doc = document()
    require(render_assembly(doc).encode() == raw and assemble_program(raw).as_dict() == doc,
            "complete generated source/Core roundtrip differs")
    require(len(MODES) == 41, "instruction mode denominator differs")
    report["source_caps"] = document_caps(doc, raw)
    report["instruction_modes"] = list(MODES)
    report["complete_core_roundtrip"] = True
    report["generated_source"] = {"path": generated.relative_to(source).as_posix(),
                                 "bytes": len(raw), "git_blob": blob(raw), "sha256": digest(raw)}
    run("generate-coverage", [sys.executable, "-B", "tests/test_hia_selfhost_language_coverage.py", "--generate-inventory"])
    run("generate-contract", [sys.executable, "-B", "-m", "tools.generate_hia_selfhost_contract"])
    run("check-contract", [sys.executable, "-B", "-m", "tools.generate_hia_selfhost_contract", "--check"])
    run("check-source-scope", [sys.executable, "-B", "tools/check_hia_core_only.py"])
    candidate_paths = sorted(policy["candidate_paths"])
    run("stage-candidate", ["/usr/bin/git", "add", "--", *candidate_paths])
    tree = git(source, "write-tree").decode().strip()
    changed = git(source, "diff", "--name-only", BASE_TREE, tree, "--").decode().splitlines()
    require(changed == candidate_paths, "candidate real index tree delta differs: " + repr(changed))
    leaves = index_snapshot(source)
    require(len(leaves) == 3941, "candidate source leaf count differs")
    check_unchanged_outside(base, leaves, set(candidate_paths))
    save_new(root / "candidate-source-leaves.json", leaves)
    report["candidate_index_tree"] = tree
    report["candidate_changed_paths"] = changed
    report["candidate_source_leaves"] = len(leaves)
    report["source_identity_binding"] = {
        "actual_HEAD": git(source, "rev-parse", "HEAD").decode().strip(),
        "base_product_commit": BASE_COMMIT, "base_product_index_tree": BASE_TREE,
        "actual_materialized_index_tree": tree,
        "not_claimed_checked_out_canonical_candidate_commit": True,
    }
    from tools.hia_selfhost_contract import file_digests, CONTRACT_PATH
    pins = file_digests(source)
    pins[CONTRACT_PATH] = digest((source / CONTRACT_PATH).read_bytes())
    save_new(root / "candidate-source-pins.json", pins)
    report["candidate_source_pins"] = len(pins)
    report["status"] = GOOD_AUTHOR_STATUS
except BaseException:
    report["status"] = "HOLD"
    report["exception"] = traceback.format_exc()
finally:
    try:
        report["base_head_after"] = git(source, "rev-parse", "HEAD").decode().strip()
        require(report["base_head_after"] == BASE_COMMIT, "base HEAD changed")
        for item in policy["files"]:
            raw, _ = read_regular(control / item["control_path"])
            require(blob(raw) == item["sha"] and digest(raw) == item["sha256"],
                    "frozen input changed during authoring")
        report["frozen_inputs_preserved"] = True
    except BaseException:
        report["status"] = "HOLD"
        report["final_identity_error"] = traceback.format_exc()
    report["seconds"] = time.monotonic() - started
    atomic_report(root / "worker-report.json", report)
    print(json.dumps({k: report.get(k) for k in (
        "schema", "status", "scope", "seconds", "candidate_index_tree",
        "candidate_source_leaves", "candidate_source_pins", "source_caps", "exception")},
        sort_keys=True), flush=True)
raise SystemExit(0 if report["status"] == GOOD_AUTHOR_STATUS else 1)
