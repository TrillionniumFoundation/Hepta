#!/usr/bin/env python3
"""Build the actual pinned NDU libraries with a bounded compiler adapter.

Exports immutable Git objects, never copies an unverified working tree. Only
workspace packaging is narrowed; every upstream source byte is retained.
This is an isolated integration build, not the monorepo qualification suite.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
BRIDGE = ROOT / "rust/hia-ndu-bridge"
UPSTREAM = "f8c9419df6ddeb36ff8b522a50219981fb8d9345"
CRATES = ("hepta-ndu", "hepta-contracts", "hepta-types")


def _sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _git_environment():
    # A local refs/replace entry must not change the bytes exported under the
    # pinned commit's identity. The checkout's working tree is never input.
    return dict(os.environ, GIT_NO_REPLACE_OBJECTS="1")


def _toml(value):
    if isinstance(value, str):
        return json.dumps(value)
    if type(value) is bool:
        return str(value).lower()
    if isinstance(value, list):
        return "[" + ", ".join(_toml(x) for x in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{k} = {_toml(v)}" for k, v in value.items()) + " }"
    return str(value)


def prepare(source: Path):
    commit = subprocess.check_output(
        ["git", "rev-parse", UPSTREAM + "^{commit}"], cwd=source,
        env=_git_environment(), text=True, timeout=10).strip()
    if commit != UPSTREAM:
        raise ValueError("exact registered upstream commit required")
    paths = ["codex-rs/" + name for name in CRATES]
    archive = subprocess.check_output(
        ["git", "archive", "--format=tar", UPSTREAM, "codex-rs/Cargo.toml", *paths],
        cwd=source, env=_git_environment(), timeout=60)
    if len(archive) > 16 * 1024 * 1024:
        raise ValueError("upstream source archive exceeds integration budget")
    upstream = BRIDGE / "upstream"
    if upstream.is_symlink():
        raise ValueError("upstream output cannot be a symlink")
    # Rebuild only our ignored, generated source export. A marker prevents
    # deleting any unrelated directory passed or created by a user.
    marker = upstream / ".hia-pinned-export"
    if upstream.exists():
        if not marker.is_file() or marker.read_text() != UPSTREAM:
            raise ValueError("refusing to replace unrecognized upstream directory")
        shutil.rmtree(upstream)
    upstream.mkdir()
    marker.write_text(UPSTREAM)
    hashes = {}
    source_workspace = None
    with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
        for member in bundle:
            if member.isdir():
                continue
            name = Path(member.name)
            if (not member.isfile() or name.is_absolute() or ".." in name.parts
                    or member.size > 4 * 1024 * 1024):
                raise ValueError("unreviewed upstream archive member")
            data = bundle.extractfile(member).read()
            hashes[member.name] = hashlib.sha256(data).hexdigest()
            if member.name == "codex-rs/Cargo.toml":
                source_workspace = tomllib.loads(data.decode())
                continue
            if len(name.parts) < 3 or name.parts[0] != "codex-rs" or name.parts[1] not in CRATES:
                raise ValueError("upstream path outside registered crates")
            destination = upstream.joinpath(*name.parts[1:])
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
    local = tomllib.loads((BRIDGE / "Cargo.toml").read_text())
    for name, spec in local["workspace"]["dependencies"].items():
        if source_workspace["workspace"]["dependencies"][name] != spec:
            raise ValueError("production dependency declaration drift: " + name)
    if source_workspace["workspace"]["package"] | local["workspace"]["package"] != source_workspace["workspace"]["package"]:
        raise ValueError("upstream package metadata drift")
    # Upstream test-only workspace dependencies refer to unrelated monorepo
    # members. Exclude those manifests, not production source or dependencies.
    manifest_changes = {}
    for name in CRATES:
        path = upstream / name / "Cargo.toml"
        original = path.read_text()
        doc = tomllib.loads(original)
        sections = []
        for section in ("package", "lib", "features", "lints", "dependencies"):
            if section in doc:
                sections.append("[" + section + "]\n" + "\n".join(
                    key + " = " + _toml(value) for key, value in doc[section].items()))
        prepared = "\n\n".join(sections) + "\n"
        path.write_text(prepared)
        manifest_changes[name] = {
            "original_sha256": hashlib.sha256(original.encode()).hexdigest(),
            "prepared_sha256": hashlib.sha256(prepared.encode()).hexdigest(),
            "change": "retain package/lib/features/lints/production dependencies; omit test-only manifest sections"}
    return {"upstream_repository": "TrillionniumFoundation/hepta-private-ci",
            "upstream_commit": UPSTREAM, "source_sha256": hashes,
            "manifest_adaptations": manifest_changes,
            "source_modified": False,
            "upstream_monorepo_qualification_claimed": False}


def _export_snapshot(report):
    """Rehash the actual exported build inputs, including adapted manifests."""
    upstream = BRIDGE / "upstream"
    expected = {}
    for name, digest in report["source_sha256"].items():
        if name == "codex-rs/Cargo.toml":
            continue  # Compared at prepare-time; not a Cargo build input.
        relative = Path(name).relative_to("codex-rs").as_posix()
        expected[relative] = digest
    for name, change in report["manifest_adaptations"].items():
        expected[name + "/Cargo.toml"] = change["prepared_sha256"]
    actual = {}
    for path in upstream.rglob("*"):
        if path.is_symlink():
            raise ValueError("symlink in prepared upstream source")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError("non-ordinary prepared upstream source")
        relative = path.relative_to(upstream).as_posix()
        if relative == ".hia-pinned-export":
            if path.read_text() != UPSTREAM:
                raise ValueError("upstream marker changed")
            continue
        actual[relative] = _sha(path)
    if actual != expected:
        raise ValueError("prepared upstream build inputs differ from pinned export")
    return actual


def _local_build_inputs():
    paths = [BRIDGE / "Cargo.toml", BRIDGE / "Cargo.lock", Path(__file__).resolve()]
    paths.extend(path for path in (BRIDGE / "src").rglob("*") if not path.is_dir())
    inputs = {}
    for path in sorted(paths):
        if path.is_symlink() or not path.is_file():
            raise ValueError("local build input must be an ordinary file")
        inputs[str(path.absolute())] = _sha(path)
    if str((BRIDGE / "src/main.rs").absolute()) not in inputs:
        raise ValueError("bridge entry source missing")
    return inputs


def _build_inputs(report):
    return {"upstream": _export_snapshot(report), "local": _local_build_inputs()}


def _verify_inputs_unchanged(report, before):
    after = _build_inputs(report)
    if after != before:
        raise ValueError("local or upstream build inputs changed during compilation")
    return after


def _resolve_executable(command, label, env):
    located = shutil.which(command, path=env.get("PATH"))
    if located is None:
        raise ValueError(label + " executable not found")
    selected = Path(located).absolute()
    # Hash and invoke the actual toolchain executable, not rustup's argv[0]
    # dispatcher, whose selected toolchain can otherwise change independently.
    if selected.resolve().name in {"rustup", "rustup.exe"}:
        actual = subprocess.check_output(
            [str(selected.resolve()), "which", label], cwd=BRIDGE, env=env,
            text=True, timeout=10).strip()
        selected = Path(actual)
    selected = selected.resolve(strict=True)
    if not selected.is_file():
        raise ValueError(label + " is not an ordinary executable")
    return selected


def _tool_identity(path, label, env):
    command = [str(path), "-vV" if label == "rustc" else "--version"]
    version = subprocess.check_output(command, cwd=BRIDGE, env=env,
                                      text=True, timeout=10).strip()
    identity = {"path": str(path), "sha256": _sha(path), "version": version}
    if label == "rustc":
        hosts = [line.removeprefix("host: ") for line in version.splitlines()
                 if line.startswith("host: ")]
        if len(hosts) != 1:
            raise ValueError("rustc must report one host triple")
        identity["host"] = hosts[0]
    return identity


def _build_environment(target, rustc, inherited):
    env = dict(inherited)
    env.pop("CARGO_BUILD_TARGET", None)
    env["CARGO_TARGET_DIR"] = str(target)
    env["RUSTC"] = str(rustc)
    # Empty values disable wrapper settings inherited from Cargo configuration
    # too. The recorded compiler is the executable this integration invokes.
    env["RUSTC_WRAPPER"] = ""
    env["RUSTC_WORKSPACE_WRAPPER"] = ""
    return env


def _build_command(cargo, target):
    return [str(cargo), "build", "--release", "--locked", "--manifest-path",
            str(BRIDGE / "Cargo.toml"), "--target-dir", str(target),
            "--message-format=json-render-diagnostics", "-p", "hia-ndu-bridge"]


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate Cargo JSON field")
        result[key] = value
    return result


def _select_artifact(output, target):
    """Select Cargo's actual executable, including its reported target path."""
    artifacts = []
    finished = []
    for line in output.splitlines():
        message = json.loads(line, object_pairs_hook=_unique_pairs)
        if type(message) is not dict:
            raise ValueError("Cargo output must contain JSON objects")
        if message.get("reason") == "build-finished":
            finished.append(message.get("success") is True)
        if message.get("reason") != "compiler-artifact":
            continue
        metadata = message.get("target", {})
        if (metadata.get("name") != "hia-ndu-bridge"
                or metadata.get("kind") != ["bin"]
                or Path(metadata.get("src_path", "")).resolve() != (BRIDGE / "src/main.rs").resolve()
                or message.get("profile", {}).get("test") is not False):
            continue
        artifact = message.get("executable")
        if type(artifact) is not str:
            raise ValueError("Cargo did not identify the bridge executable")
        path = Path(artifact)
        if (not path.is_absolute() or path.is_symlink() or not path.is_file()
                or not path.resolve().is_relative_to(target.resolve())
                or not 0 < path.stat().st_size <= 128 * 1024 * 1024):
            raise ValueError("Cargo executable is outside the isolated target directory")
        artifacts.append((path.resolve(), message))
    if finished != [True] or len(artifacts) != 1:
        raise ValueError("Cargo did not report exactly one successful bridge artifact")
    return artifacts[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-checkout", required=True, type=Path)
    parser.add_argument("--cargo", default="cargo")
    parser.add_argument("--rustc", default=None)
    parser.add_argument("--generate-lock", action="store_true")
    args = parser.parse_args()
    report = prepare(args.source_checkout.resolve())
    inherited = dict(os.environ)
    cargo = _resolve_executable(args.cargo, "cargo", inherited)
    rustc_command = args.rustc or inherited.get("RUSTC") or str(cargo.with_name("rustc"))
    rustc = _resolve_executable(rustc_command, "rustc", inherited)
    target = (BRIDGE / "target").absolute()
    env = _build_environment(target, rustc, inherited)
    tools_before = {"cargo": _tool_identity(cargo, "cargo", env),
                    "rustc": _tool_identity(rustc, "rustc", env)}
    if args.generate_lock:
        subprocess.run([str(cargo), "generate-lockfile", "--manifest-path", str(BRIDGE / "Cargo.toml")],
                       cwd=BRIDGE, env=env, check=True, timeout=300)
    before = _build_inputs(report)
    command = _build_command(cargo, target)
    built = subprocess.run(command, cwd=BRIDGE, env=env, text=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=600)
    if built.returncode:
        raise RuntimeError("Cargo build failed: " + built.stderr[-4000:])
    binary, artifact = _select_artifact(built.stdout, target)
    binary_digest = _sha(binary)
    after = _verify_inputs_unchanged(report, before)
    tools_after = {"cargo": _tool_identity(cargo, "cargo", env),
                   "rustc": _tool_identity(rustc, "rustc", env)}
    if tools_after != tools_before or _sha(binary) != binary_digest:
        raise ValueError("toolchain or executable changed during build verification")
    report.update(binary=str(binary), binary_sha256=binary_digest,
                  lock_sha256=_sha(BRIDGE / "Cargo.lock"), command=command,
                  cargo_version=tools_before["cargo"]["version"],
                  toolchain=tools_before, build_inputs_before=before, build_inputs_after=after,
                  build_inputs_unchanged=True,
                  cargo_reported_artifact={"package_id": artifact.get("package_id"),
                                           "target": artifact["target"], "profile": artifact["profile"],
                                           "fresh": artifact.get("fresh")},
                  cargo_output_sha256=hashlib.sha256(built.stdout.encode()).hexdigest(),
                  build_environment={key: env.get(key) for key in (
                      "CARGO_BUILD_TARGET", "CARGO_TARGET_DIR", "RUSTC", "RUSTC_WRAPPER",
                      "RUSTC_WORKSPACE_WRAPPER", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS")},
                  git_replace_objects_disabled=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=BRIDGE,
                                     prefix=".build-provenance-", delete=False) as stream:
        receipt = Path(stream.name)
        stream.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    try:
        receipt.replace(BRIDGE / "build-provenance.json")
    finally:
        receipt.unlink(missing_ok=True)
    print(json.dumps({k: report[k] for k in ("upstream_commit", "binary", "binary_sha256", "lock_sha256")}))


if __name__ == "__main__":
    main()
