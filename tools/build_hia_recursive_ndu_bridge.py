#!/usr/bin/env python3
"""Build the pinned original NDU crates with source, tool and binary evidence.

The upstream checkout must be clean and every declared compiler input must
match its pinned Git blob. A tracked lockfile is required. Actual command
stdout/stderr bytes are retained on success and failure. An external target
directory keeps reproducible Cargo objects out of the durable evidence tree.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import time


def _sha(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def _write_json(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


class CommandLog:
    """Persist the actual subprocess streams before interpreting their result."""

    def __init__(self, output: Path):
        self.output = output
        self.directory = output / "commands"
        self.directory.mkdir()
        self.records: list[dict] = []

    def run(self, argv: list[str], *, cwd: Path, env: dict[str, str]) -> str:
        number = len(self.records) + 1
        stem = self.directory / f"{number:03d}"
        started = time.monotonic_ns()
        launch_error = None
        try:
            completed = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, check=False)
            stdout, stderr, code = completed.stdout, completed.stderr, completed.returncode
        except OSError as error:
            stdout, stderr, code = b"", b"", None
            launch_error = f"{type(error).__name__}: {error}"
        elapsed = time.monotonic_ns() - started
        row = {"argv": argv, "cwd": str(cwd), "returncode": code,
               "wall_ns": elapsed, "launch_error": launch_error}
        for name, raw in (("stdout", stdout), ("stderr", stderr)):
            path = stem.with_suffix(f".{name}")
            with path.open("xb") as stream:
                stream.write(raw)
            row[name] = {"path": str(path.relative_to(self.output)), "bytes": len(raw),
                         "sha256": hashlib.sha256(raw).hexdigest()}
        _write_json(stem.with_suffix(".json"), row)
        self.records.append(row)
        if launch_error is not None or code != 0:
            raise RuntimeError(f"command {number} failed ({code}); see {stem}.json")
        return stdout.decode("utf-8", errors="strict").strip()


def source_inventory(root: Path, paths: list[Path]) -> tuple[str, dict[str, str]]:
    inventory = {str(path.relative_to(root)): _sha(path) for path in sorted(set(paths))}
    digest = hashlib.sha256(json.dumps(inventory, sort_keys=True,
                                      separators=(",", ":")).encode()).hexdigest()
    return digest, inventory


def source_admission(root: Path, commit: str, inputs: dict[str, str], *,
                     log: CommandLog, env: dict[str, str]) -> dict:
    """Reject a changed HEAD, dirty checkout or bytes not in the pinned tree."""
    head = log.run(["git", "rev-parse", "HEAD"], cwd=root, env=env)
    tree = log.run(["git", "rev-parse", "HEAD^{tree}"], cwd=root, env=env)
    status = log.run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=root, env=env)
    if head != commit:
        raise RuntimeError("source commit differs from the requested pin")
    if status:
        raise RuntimeError("upstream source checkout is not clean")
    checked = {}
    for name, expected in sorted(inputs.items()):
        # This byte comparison also rejects untracked/ignored source additions
        # that happen to be absent from git status. Never trust HEAD alone.
        completed = subprocess.run(["git", "cat-file", "blob", f"{commit}:{name}"],
                                   cwd=root, env=env, capture_output=True, check=False)
        if completed.returncode != 0:
            raise RuntimeError(f"compiler input has no pinned Git blob: {name}")
        git_sha = hashlib.sha256(completed.stdout).hexdigest()
        if git_sha != expected or _sha(root / name) != expected:
            raise RuntimeError(f"compiler input differs from its pinned Git blob: {name}")
        checked[name] = git_sha
    return {"head": head, "tree": tree, "status_porcelain": status,
            "input_git_blob_sha256": checked, "all_declared_inputs_match_pinned_blobs": True}


def build(args: argparse.Namespace) -> Path:
    started, cpu = time.monotonic_ns(), time.process_time_ns()
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    root = args.ndu_source.resolve(strict=True)
    bridge = root / "tools/hia-ndu-bridge"
    output = args.output.resolve()
    requested_target = getattr(args, "target_dir", None)
    target_dir = requested_target.resolve() if requested_target else output / "target"
    if output.is_relative_to(root) or target_dir.is_relative_to(root):
        raise RuntimeError("build outputs must be outside the pinned upstream checkout")
    # Evidence from an earlier successful or failed attempt must not be replaced.
    output.mkdir(parents=True, exist_ok=False)
    log = CommandLog(output)
    try:
        target_preexisting = target_dir.exists()
        cargo = str(args.cargo.resolve(strict=True))
        rustc = str(args.rustc.resolve(strict=True))
        tools = {"builder_sha256": _sha(Path(__file__)),
                 "cargo_sha256": _sha(Path(cargo)), "rustc_sha256": _sha(Path(rustc))}
        env = dict(os.environ)
        env["RUSTC"] = rustc
        env["CARGO_TARGET_DIR"] = str(target_dir)
        if args.cargo_home:
            env["CARGO_HOME"] = str(args.cargo_home.resolve())
        env["PATH"] = os.pathsep.join([str(Path(cargo).parent), str(Path(rustc).parent), env.get("PATH", "")])
        commit = log.run(["git", "rev-parse", "HEAD"], cwd=root, env=env)
        if args.expected_source and commit != args.expected_source:
            raise RuntimeError("source commit differs from the requested pin")
        native_paths = [root / "codex-rs/Cargo.toml"]
        for name in ("hepta-ndu", "hepta-types", "hepta-contracts"):
            crate = root / "codex-rs" / name
            native_paths.append(crate / "Cargo.toml")
            native_paths.extend((crate / "src").rglob("*.rs"))
        if not (bridge / "Cargo.lock").is_file():
            raise RuntimeError("a tracked pinned bridge Cargo.lock is required")
        native_digest, native_inventory = source_inventory(root, native_paths)
        bridge_paths = [bridge / "Cargo.toml", bridge / "Cargo.lock", *(bridge / "src").rglob("*.rs")]
        bridge_digest, bridge_inventory = source_inventory(root, bridge_paths)
        before = source_admission(root, commit, {**native_inventory, **bridge_inventory}, log=log, env=env)
        compiler = log.run([rustc, "--version"], cwd=root, env=env)
        cargo_version = log.run([cargo, "--version"], cwd=root, env=env)
        env.update(HEPTA_NDU_SOURCE_COMMIT=commit, HEPTA_NDU_SOURCE_DIGEST=native_digest,
                   HEPTA_NDU_BRIDGE_DIGEST=bridge_digest, HEPTA_NDU_RUSTC=compiler)
        command = [cargo, "build", "--release", "--locked", "--manifest-path", str(bridge / "Cargo.toml")]
        if args.offline:
            command.append("--offline")
        log.run(command, cwd=bridge, env=env)
        filename = "hepta-hia-ndu-bridge.exe" if os.name == "nt" else "hepta-hia-ndu-bridge"
        compiled = target_dir / "release" / filename
        binary = compiled
        if requested_target:
            (output / "native").mkdir()
            binary = output / "native" / filename
            shutil.copy2(compiled, binary)
            if _sha(compiled) != _sha(binary):
                raise RuntimeError("durable native executable differs from the Cargo output")
        identity = json.loads(log.run([str(binary), "--identity"], cwd=bridge, env=env))
        if (identity.get("source_commit") != commit or identity.get("source_digest") != native_digest
                or identity.get("bridge_digest") != bridge_digest or identity.get("rustc") != compiler
                or identity.get("authority") != "DENY_ALL" or identity.get("safety_certificate") is not False):
            raise RuntimeError("built executable has stale or invalid source/tool identity")
        after = source_admission(root, commit, {**native_inventory, **bridge_inventory}, log=log, env=env)
        after_native_paths = [root / "codex-rs/Cargo.toml"]
        for name in ("hepta-ndu", "hepta-types", "hepta-contracts"):
            crate = root / "codex-rs" / name
            after_native_paths.extend([crate / "Cargo.toml", *(crate / "src").rglob("*.rs")])
        after_bridge_paths = [bridge / "Cargo.toml", bridge / "Cargo.lock", *(bridge / "src").rglob("*.rs")]
        if (source_inventory(root, native_paths)[0] != native_digest
                or source_inventory(root, bridge_paths)[0] != bridge_digest
                or set(after_native_paths) != set(native_paths)
                or set(after_bridge_paths) != set(bridge_paths) or before != after):
            raise RuntimeError("source changed during compilation")
        if tools != {"builder_sha256": _sha(Path(__file__)),
                     "cargo_sha256": _sha(Path(cargo)), "rustc_sha256": _sha(Path(rustc))}:
            raise RuntimeError("build tool changed during compilation")
        _write_json(output / "build-commands.json", log.records)
        manifest = {"schema": "hepta.hia.ndu.build.v1", "binary": str(binary),
                    "binary_sha256": _sha(binary), "compiled_binary": str(compiled),
                    "compiled_binary_sha256": _sha(compiled), "target_directory": str(target_dir),
                    "identity": identity, "native_sources": native_inventory,
                    "bridge_sources": bridge_inventory, "build_command": command,
                    "build_tools": tools,
                    "tool_versions": {"cargo": cargo_version, "rustc": compiler},
                    "source_admission": {"before": before, "after": after},
                    "command_evidence": {"path": "build-commands.json",
                                         "sha256": _sha(output / "build-commands.json"),
                                         "original_streams_retained": True},
                    "native_source_repository": "https://github.com/TrillionniumFoundation/hepta-private-ci",
                    "authority": "DENY_ALL", "safety_certificate": False}
        after_children = resource.getrusage(resource.RUSAGE_CHILDREN)
        manifest["build_cost"] = {
            "wall_ns": time.monotonic_ns() - started,
            "parent_cpu_ns": time.process_time_ns() - cpu,
            "child_cpu_ns": round(1e9 * ((after_children.ru_utime - children.ru_utime) +
                                          (after_children.ru_stime - children.ru_stime))),
            "target_cache": "existing" if target_preexisting else "empty",
            "dependency_cache": "caller supplied; downloads charged if incurred",
            "scope": "source/blob admission, inventory, cargo, raw command evidence, binary/tool admission; excludes this manifest write and process startup",
            "fully_cold_machine_claim": False,
        }
        result = output / "identity.json"
        _write_json(result, manifest)
        return result
    except Exception as error:
        _write_json(output / "build-failure.json", {
            "schema": "hepta.hia.ndu.build-failure.v1", "status": "failed",
            "error": f"{type(error).__name__}: {error}", "commands": log.records,
            "wall_ns": time.monotonic_ns() - started,
            "authority": "DENY_ALL", "safety_certificate": False})
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndu-source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-dir", type=Path,
                        help="optional reproducible Cargo cache outside the durable evidence directory")
    parser.add_argument("--cargo", type=Path, required=True)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--cargo-home", type=Path)
    parser.add_argument("--expected-source")
    parser.add_argument("--offline", action="store_true")
    print(build(parser.parse_args()))


if __name__ == "__main__":
    main()
