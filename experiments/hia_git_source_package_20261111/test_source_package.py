#!/usr/bin/env python3
"""Actual Git custody controls; no HIA build/qualification is executed."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import traceback


HERE = Path(__file__).resolve().parent
TOOL = "experiments/hia_git_source_package_20261111/source_package.py"
HELPER = "tools/hia_core_source_identity.py"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")) + "\n").encode()


def command(argv, root, input=None, success=True):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("GIT_") and key not in {"PYTHONPATH", "PYTHONHOME"}}
    env.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1", "PYTHONDONTWRITEBYTECODE": "1",
                "GIT_AUTHOR_NAME": "HIA Source Custody Controls",
                "GIT_AUTHOR_EMAIL": "source-custody@example.invalid",
                "GIT_COMMITTER_NAME": "HIA Source Custody Controls",
                "GIT_COMMITTER_EMAIL": "source-custody@example.invalid",
                "GIT_AUTHOR_DATE": "2026-11-11T00:00:00Z",
                "GIT_COMMITTER_DATE": "2026-11-11T00:00:00Z"})
    result = subprocess.run(argv, cwd=root, env=env, input=input,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if success:
        require(result.returncode == 0, (argv, result.returncode,
                                         result.stderr.decode("utf-8", "backslashreplace")))
    return result


def git(root, *args, input=None):
    return command(["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
                    *map(str, args)], root, input=input).stdout


def fixture(root, helper):
    origin = root / "origin"
    origin.mkdir()
    git(origin, "init", "--quiet", "--object-format=sha1", "--template=", "--initial-branch=main")
    (origin / TOOL).parent.mkdir(parents=True)
    (origin / HELPER).parent.mkdir(parents=True)
    shutil.copyfile(HERE / "source_package.py", origin / TOOL)
    shutil.copyfile(helper, origin / HELPER)
    (origin / "nested").mkdir()
    (origin / "nested" / "雪 space\ttab\nnewline.bin").write_bytes(bytes(range(256)))
    (origin / "binary-over-one-MiB.dat").write_bytes(
        hashlib.shake_256(b"hia-exact-git-package-controls").digest(2 * 1024 * 1024 + 7))
    (origin / "empty.bin").write_bytes(b"")
    (origin / "run.sh").write_bytes(b"#!/bin/sh\nprintf 'fixture\\n'\n")
    (origin / "run.sh").chmod(0o755)
    (origin / ".gitignore").write_bytes(b"ignored.marker\n")
    git(origin, "add", "--all")
    git(origin, "commit", "--quiet", "-m", "real synthetic root")
    first = git(origin, "rev-parse", "HEAD").decode().strip()
    (origin / "left.txt").write_bytes(b"left parent\n")
    git(origin, "add", "left.txt")
    git(origin, "commit", "--quiet", "-m", "real first parent")
    left = git(origin, "rev-parse", "HEAD").decode().strip()
    tree = git(origin, "rev-parse", "HEAD^{tree}").decode().strip()
    right = git(origin, "commit-tree", tree, "-p", first,
                input=b"real distinct second parent\n").decode().strip()
    empty = git(origin, "mktree", input=b"").decode().strip()
    listing = git(origin, "ls-tree", "-z", tree)
    merged_tree = git(origin, "mktree", "-z", input=listing
                      + ("040000 tree " + empty + "\tempty-subtree\0").encode()).decode().strip()
    head = git(origin, "commit-tree", merged_tree, "-p", left, "-p", right,
               input=b"real merge with empty subtree\n").decode().strip()
    git(origin, "update-ref", "refs/heads/main", head)
    git(origin, "reset", "--hard", head)
    source = root / "depth-one-source"
    cloned = command(["git", "-c", "core.hooksPath=/dev/null", "clone", "--depth=1",
                      "--no-tags", "--no-hardlinks", origin.as_uri(), str(source)], root)
    (root / "clone.stdout").write_bytes(cloned.stdout)
    (root / "clone.stderr").write_bytes(cloned.stderr)
    require((source / ".git" / "shallow").read_text() == head + "\n", "real depth-one boundary")
    return source, head, merged_tree, [left, right], empty


def refresh_manifest(package, manifest):
    raw = encoded(manifest)
    (package / "manifest.json").write_bytes(raw)
    report = json.loads((package / "export-report.json").read_bytes())
    report["manifest_sha256"] = sha(raw)
    (package / "export-report.json").write_bytes(encoded(report))
    return sha(raw)


def replace_pack(source, package, manifest, objects):
    result = command(["git", "--no-replace-objects", "pack-objects", "--stdout",
                      "--no-reuse-delta", "--window=10", "--depth=50", "--threads=1"],
                     source, input=("\n".join(sorted(objects)) + "\n").encode())
    (package / "source.pack").write_bytes(result.stdout)
    manifest["pack"]["size"] = len(result.stdout)
    manifest["pack"]["sha256"] = sha(result.stdout)


def run(root, helper):
    started = time.monotonic()
    root.mkdir(mode=0o700, exist_ok=False)
    report = {"schema": "hepta.hia.git-source-package-controls.v1", "status": "HOLD",
              "qualification_executed": False, "controls": [],
              "python": sys.version, "executable": sys.executable,
              "git_version": git(root, "--version").decode().strip(),
              "helper_sha256": sha(helper.read_bytes()),
              "tool_sha256": sha((HERE / "source_package.py").read_bytes())}

    def passed(name, **facts):
        report["controls"].append({"id": name, "status": "PASS", **facts})

    try:
        source, head, tree, parents, empty_tree = fixture(root, helper)
        report.update({"commit": head, "tree": tree, "real_parents": parents})
        package = root / "package"
        exported = command([sys.executable, "-I", "-S", "-B", str(source / TOOL), "export",
                            "--source-root", str(source), "--output-dir", str(package),
                            "--expected-commit", head], root)
        (root / "export.stdout").write_bytes(exported.stdout)
        (root / "export.stderr").write_bytes(exported.stderr)
        original_manifest = json.loads((package / "manifest.json").read_bytes())
        manifest_sha = sha((package / "manifest.json").read_bytes())
        require(original_manifest["commit"]["parents"] == parents, "raw parents retained")
        require(any(x["oid"] == empty_tree and x["type"] == "tree"
                    for x in original_manifest["objects"]), "empty tree retained")
        passed("actual-depth-one-export", counts=original_manifest["counts"],
               manifest_sha256=manifest_sha)

        def materialize(name, candidate, pin, expected=None, destination=None):
            destination = destination or root / (name + "-source")
            result = command([sys.executable, "-I", "-S", "-B", str(candidate / "source-package.py"),
                              "materialize", "--package", str(candidate),
                              "--destination", str(destination), "--expected-commit", head,
                              "--reproduction-destination", str(root / (name + "-clone")),
                              "--expected-tree", tree, "--manifest-sha256", pin,
                              "--report", str(root / (name + ".json"))], root, success=False)
            (root / (name + ".stdout")).write_bytes(result.stdout)
            (root / (name + ".stderr")).write_bytes(result.stderr)
            receipt = json.loads((root / (name + ".json")).read_bytes())
            if expected is None:
                require(result.returncode == 0 and receipt["status"] == "PASS", result.stderr.decode())
            else:
                require(result.returncode != 0 and receipt["status"] == "HOLD", "bad package accepted")
                require(expected in receipt["exception"]["message"], receipt["exception"])
            return destination, receipt

        destination, receipt = materialize("roundtrip", package, manifest_sha)
        require(git(destination, "cat-file", "commit", head) == git(source, "cat-file", "commit", head),
                "original commit bytes changed")
        require(git(destination, "rev-list", "--count", "HEAD").strip() == b"1", "shallow traversal")
        require(git(destination, "rev-parse", "HEAD").decode().strip() == head, "same HEAD")
        require(git(destination, "rev-parse", "HEAD^{tree}").decode().strip() == tree, "same tree")
        for parent in parents:
            probe = command(["git", "cat-file", "-e", parent], destination, success=False)
            require(probe.returncode != 0, "parent history unexpectedly included")
        passed("independent-standalone-reconstruction", counts=receipt["counts"],
               fsck_full_strict=receipt["fsck_full_strict"],
               original_source_state_matches_export=receipt["original_source_state_matches_export"],
               raw_original_commit_bytes_equal=True, ancestor_history_absent=True)
        require(receipt["clone_reproduction"]["status"] == "PASS"
                and receipt["clone_reproduction"]["original_source_state_after"]
                == receipt["original_source_state_after"], "real clone reconstruction differs")
        passed("actual-git-clone-reproduction", object_storage_hardlinks=0,
               same_original_source_state=True)

        def candidate(name):
            copied = root / (name + "-package")
            shutil.copytree(package, copied)
            return copied, json.loads((copied / "manifest.json").read_bytes())

        materialize("wrong-external-manifest-pin", package, "0" * 64,
                    "manifest does not match external SHA256")
        passed("wrong-external-manifest-pin")
        copied, manifest = candidate("altered-shallow-boundary")
        manifest["shallow"]["exported_boundary"] = []
        materialize("altered-shallow-boundary", copied, refresh_manifest(copied, manifest),
                    "undeclared or altered shallow boundary")
        passed("altered-shallow-boundary")
        copied, manifest = candidate("omitted-large-blob")
        omitted = next(x["oid"] for x in manifest["leaves"] if x["path"] == "binary-over-one-MiB.dat")
        replace_pack(source, copied, manifest, [x["oid"] for x in manifest["objects"] if x["oid"] != omitted])
        materialize("omitted-large-blob", copied, refresh_manifest(copied, manifest), "index-pack rejected")
        passed("omitted-large-blob")
        copied, manifest = candidate("omitted-empty-tree")
        replace_pack(source, copied, manifest,
                     [x["oid"] for x in manifest["objects"] if x["oid"] != empty_tree])
        materialize("omitted-empty-tree", copied, refresh_manifest(copied, manifest), "git fsck --full --strict")
        passed("omitted-empty-tree")
        copied, manifest = candidate("extra-unreachable-object")
        extra = git(source, "hash-object", "-w", "--stdin", input=b"not part of selected tree\n").decode().strip()
        replace_pack(source, copied, manifest, [x["oid"] for x in manifest["objects"]] + [extra])
        materialize("extra-unreachable-object", copied, refresh_manifest(copied, manifest),
                    "not exactly commit/tree/blob closure")
        passed("extra-unreachable-object")
        copied, manifest = candidate("changed-leaf-mode")
        next(x for x in manifest["entries"] if x["path"] == "run.sh")["mode"] = "100644"
        materialize("changed-leaf-mode", copied, refresh_manifest(copied, manifest), "raw tree inventory mismatch")
        passed("changed-leaf-mode")
        copied, manifest = candidate("truncated-pack")
        raw = (copied / "source.pack").read_bytes()[:-9]
        (copied / "source.pack").write_bytes(raw)
        manifest["pack"].update({"size": len(raw), "sha256": sha(raw)})
        materialize("truncated-pack", copied, refresh_manifest(copied, manifest), "index-pack rejected")
        passed("truncated-pack")
        occupied = root / "existing-destination"
        occupied.mkdir()
        sentinel = occupied / "preserve.bin"
        sentinel.write_bytes(b"unchanged\x00\xff")
        materialize("existing-destination", package, manifest_sha, "File exists", destination=occupied)
        require(sentinel.read_bytes() == b"unchanged\x00\xff" and set(occupied.iterdir()) == {sentinel},
                "existing destination mutated")
        passed("existing-destination-preserved")

        def refused_export(name, expected):
            result = command([sys.executable, "-I", "-S", "-B", str(source / TOOL), "export",
                              "--source-root", str(source), "--output-dir", str(root / (name + "-output")),
                              "--expected-commit", head], root, success=False)
            (root / (name + ".stdout")).write_bytes(result.stdout)
            (root / (name + ".stderr")).write_bytes(result.stderr)
            require(result.returncode != 0 and expected in result.stderr.decode(), "source drift accepted")

        binary = source / "binary-over-one-MiB.dat"
        saved = binary.read_bytes()
        git(source, "update-index", "--assume-unchanged", "binary-over-one-MiB.dat")
        binary.write_bytes(b"!" + saved[1:])
        require(git(source, "status", "--porcelain") == b"", "actual assume-unchanged hidden drift")
        refused_export("hidden-byte-drift", "source bytes differ from raw HEAD blob")
        binary.write_bytes(saved)
        git(source, "update-index", "--no-assume-unchanged", "binary-over-one-MiB.dat")
        passed("original-helper-rejects-index-hidden-byte-drift")
        git(source, "config", "core.fileMode", "false")
        (source / "run.sh").chmod(0o644)
        require(git(source, "status", "--porcelain") == b"", "actual core.fileMode hidden drift")
        refused_export("hidden-mode-drift", "source mode differs from raw HEAD tree")
        (source / "run.sh").chmod(0o755)
        git(source, "config", "core.fileMode", "true")
        passed("original-helper-rejects-config-hidden-mode-drift")
        require(git(source, "status", "--porcelain") == b"", "source not restored")
        require(git(source, "rev-parse", "HEAD").decode().strip() == head, "source HEAD changed")
        report["status"] = "PASS"
    except BaseException as exc:
        report["exception"] = {"type": type(exc).__name__, "message": str(exc),
                               "traceback": traceback.format_exc()}
        raise
    finally:
        report["executed_controls"] = len(report["controls"])
        report["wall_seconds"] = time.monotonic() - started
        (root / "report.json").write_bytes(encoded(report))
        print(json.dumps({k: report[k] for k in ("status", "executed_controls", "wall_seconds")}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--original-helper", type=Path, required=True)
    args = parser.parse_args()
    run(args.evidence_dir.absolute(), args.original_helper.resolve(strict=True))
