#!/usr/bin/env python3
"""Fail-closed local Hepta exact-HEAD blocker inventory and scoped runner.

This tool does not certify full GitHub blocking-ci, signer custody, target devices,
trained NDU improvement or production authority. Use its JSON as diagnostic-only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass

SCHEMA = "hepta.exact-head-local-blocker-diagnostic.v1"
REPO_NAME = "hepta-private-ci"
OUTPUT_CAP_BYTES = 2 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024

# These are deliberately SCOPED local commands, not a substitute for the
# repository's unmodified complete cross-platform blocking-ci workflow.
SUITES = {
    "format": [
        ("rustfmt", "codex-rs", ["cargo", "fmt", "--all", "--", "--check"]),
        ("worktree-whitespace", ".", ["git", "diff", "--check"]),
    ],
    "native": [
        ("neuron-owner", "codex-rs", ["cargo", "test", "--locked", "-p", "codex-hepta-neuron", "--lib"]),
        ("ndu-owner", "codex-rs", ["cargo", "test", "--locked", "-p", "codex-hepta-ndu", "--lib"]),
        ("infer-worker-owner", "codex-rs", ["cargo", "test", "--locked", "-p", "codex-hepta-infer-worker-host", "--lib"]),
    ],
    "security": [
        ("cargo-deny", "codex-rs", ["cargo", "deny", "--locked", "check", "advisories", "bans", "licenses", "sources"]),
    ],
    "documentation": [
        ("readiness", ".", ["python3", "-B", "scripts/hepta-readiness.py", "verify"]),
        ("implementation-dossiers", ".", ["python3", "-B", "scripts/hepta-implementation-dossiers.py", "verify"]),
        ("technical-closure", ".", ["python3", "-B", "scripts/hepta-technical-closure.py", "verify"]),
    ],
}

EXTERNAL_GATES = [
    ("blocking-ci", "Exactly this HEAD, complete Linux/macOS/Windows and all required checks"),
    ("architecture", "Source-head and prospective base-merge checks at the same frozen source"),
    ("v8", "Required actual native jobs; skipped/queued/cancelled are not success"),
    ("physical-stem", "Signed original pretrained weights and physically attested Encoder forward"),
    ("multimodal-ood", "Independent source-disjoint, future and OOD evaluation"),
    ("system2-ndu", "Matched-cost independent outcome improvement over strong baselines"),
    ("4096-target-host", "Original target host: end-to-end CPU/RSS/GPU/p99/WAL/recovery/energy"),
    ("independent-custody", "Independent signer, observer, CAS/FinalUse and operator approval"),
]

@dataclass(frozen=True)
class ExecResult:
    status: str
    exit_code: int | None
    elapsed_seconds: float
    output_sha256: str
    output_utf8_tail: str
    bytes_seen: int
    error: str | None = None


def git(repo: Path, *args: str) -> tuple[int, str]:
    try:
        cp = subprocess.run(["git", "-C", str(repo), *args], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, timeout=15, check=False)
        return cp.returncode, cp.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


def inspect_repo(repo: Path) -> dict:
    repo = repo.expanduser().resolve()
    info: dict = {"path": str(repo), "valid": False, "head_sha": None,
                  "clean": None, "blockers": []}
    if not repo.is_dir():
        info["blockers"].append("repository-directory-unavailable")
        return info
    rc, top = git(repo, "rev-parse", "--show-toplevel")
    if rc or not top or Path(top).resolve() != repo or repo.name != REPO_NAME:
        info["blockers"].append("incorrect-or-not-top-level-git-repository")
        return info
    rc, sha = git(repo, "rev-parse", "--verify", "HEAD^{commit}")
    if rc or len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha):
        info["blockers"].append("head-sha-unavailable")
        return info
    rc, dirty = git(repo, "status", "--porcelain=v1", "--untracked-files=all")
    if rc:
        info["blockers"].append("worktree-status-unavailable")
    info.update(valid=True, head_sha=sha, clean=(rc == 0 and not dirty))
    if dirty:
        info["blockers"].append("dirty-worktree")
    for path in ["codex-rs/Cargo.lock", ".github/workflows/blocking-ci.yml"]:
        if not (repo / path).is_file():
            info["blockers"].append(f"required-source-missing:{path}")
    return info


def run_bounded(argv: list[str], cwd: Path, timeout_s: int = 900,
                cap: int = OUTPUT_CAP_BYTES) -> ExecResult:
    """Bound elapsed time and actual output bytes; kill process group on overrun."""
    start = time.monotonic()
    if not cwd.is_dir():
        return ExecResult("unavailable", None, 0.0, "", "", 0, "working-directory-missing")
    if not argv or shutil.which(argv[0]) is None:
        return ExecResult("unavailable", None, 0.0, "", "", 0, "executable-missing")
    out = bytearray()
    digest = hashlib.sha256()
    total = 0
    overflow = False
    expired = False
    proc = None
    try:
        proc = subprocess.Popen(argv, cwd=str(cwd), stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                start_new_session=(os.name == "posix"), bufsize=0)
        assert proc.stdout is not None
        os.set_blocking(proc.stdout.fileno(), False)
        sel = selectors.DefaultSelector()
        sel.register(proc.stdout, selectors.EVENT_READ)
        eof = False
        while not eof or proc.poll() is None:
            if time.monotonic() - start > timeout_s:
                expired = True
                break
            for _key, _events in sel.select(timeout=0.1):
                try:
                    chunk = os.read(proc.stdout.fileno(), READ_CHUNK_BYTES)
                except BlockingIOError:
                    continue
                if not chunk:
                    eof = True
                    sel.unregister(proc.stdout)
                    break
                total += len(chunk)
                digest.update(chunk)
                remaining = max(0, cap - len(out))
                out.extend(chunk[:remaining])
                if total > cap:
                    overflow = True
                    break
            if overflow:
                break
        if overflow or expired:
            try:
                if os.name == "posix":
                    os.killpg(proc.pid, signal.SIGKILL)
                else:
                    proc.kill()
            except ProcessLookupError:
                pass
        try:
            code = proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            code = proc.wait(timeout=8)
        sel.close()
        status = ("output-limit" if overflow else "timeout" if expired else
                  "passed" if code == 0 else "failed")
        tail = bytes(out[-6000:]).decode("utf-8", errors="replace")
        return ExecResult(status, code, round(time.monotonic() - start, 4),
                          digest.hexdigest(), tail, total)
    except Exception as exc:
        if proc and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGKILL) if os.name == "posix" else proc.kill()
                proc.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                pass
        return ExecResult("indeterminate", None, round(time.monotonic() - start, 4),
                          digest.hexdigest(), bytes(out[-6000:]).decode("utf-8", "replace"),
                          total, f"{type(exc).__name__}:{exc}")
    finally:
        if proc is not None and proc.stdout is not None:
            proc.stdout.close()


def write_create_only(path: Path, report: dict) -> None:
    path = path.expanduser().absolute()
    if not path.parent.is_dir() or path.is_symlink():
        raise ValueError("output parent must exist and destination may not be a symlink")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    raw = (json.dumps(report, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode()
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise


def build_report(repo: Path, expected_sha: str | None, suite_names: list[str],
                 execute: bool, timeout_s: int) -> dict:
    info = inspect_repo(repo)
    if expected_sha and info["head_sha"] != expected_sha:
        info["blockers"].append("source-head-mismatch")
    host = {"platform": platform.platform(), "python": sys.version.split()[0],
            "tools": {x: shutil.which(x) for x in ["git", "python3", "cargo", "rustc", "rustfmt", "just", "bazel", "gh"]}}
    can_run = bool(info["valid"] and info["clean"] and not info["blockers"] and
                   expected_sha and expected_sha == info["head_sha"])
    results = []
    for suite in suite_names:
        for name, rel, argv in SUITES[suite]:
            row = {"suite": suite, "gate": name, "argv": argv, "cwd": rel,
                   "status": "not-run"}
            if execute:
                if not can_run:
                    row["status"] = "blocked-by-source-identity"
                else:
                    result = run_bounded(argv, repo.resolve() / rel, timeout_s)
                    row.update(result.__dict__)
            results.append(row)
    if execute and can_run:
        after = inspect_repo(repo)
        if after["head_sha"] != info["head_sha"] or not after["clean"] or after["blockers"]:
            info["blockers"].append("source-or-worktree-mutated-during-checks")
            for row in results:
                if row["status"] == "passed":
                    row["status"] = "invalidated-by-source-mutation"
    info["blockers"] = sorted(set(info["blockers"]))
    report = {"schema": SCHEMA, "purpose": "diagnostic-only", "authority": "DENY_ALL",
              "production_qualified": False, "all_blockers_closed": False,
              "source": info, "host": host, "scoped_local_checks": results,
              "external_gates": [{"gate": g, "status": "unverified", "requirement": d}
                                 for g, d in EXTERNAL_GATES],
              "observability_limits": [
                  "No tool-generated or self-reported receipt is an independent signature",
                  "This report does not query current GitHub Actions or verify release checks",
                  "An actual downstream target host and physical model are mandatory",
                  "A mathematical fixture or synthetic training is not real System2/NDU efficacy",
              ]}
    return report


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, required=True)
    p.add_argument("--expected-sha", help="Required when --run; must be the exact 40-char commit")
    p.add_argument("--suite", action="append", choices=sorted(SUITES),
                   help="Repeat to run multiple scoped suites (default all for inventory)")
    p.add_argument("--run", action="store_true", help="Actually run selected tests; never runs if source dirty/mismatched")
    p.add_argument("--timeout", type=int, default=900, help="Per-command bound in seconds")
    p.add_argument("--out", type=Path, help="Create a new JSON diagnostic receipt; refuses overwrite")
    a = p.parse_args()
    if a.timeout < 1 or a.timeout > 7200:
        p.error("--timeout must be 1..7200")
    if a.expected_sha and (len(a.expected_sha) != 40 or
                           any(c not in "0123456789abcdef" for c in a.expected_sha)):
        p.error("--expected-sha must be a lowercase 40-character Git SHA")
    if a.run and not a.expected_sha:
        p.error("--run requires --expected-sha")
    report = build_report(a.repo, a.expected_sha, a.suite or list(SUITES), a.run, a.timeout)
    if a.out:
        write_create_only(a.out, report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if not report["source"]["blockers"] and not a.run else 2 if (
        report["source"]["blockers"] or any(x["status"] != "passed" for x in report["scoped_local_checks"])) else 0

if __name__ == "__main__":
    raise SystemExit(main())
