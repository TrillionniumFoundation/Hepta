#!/usr/bin/env python3
"""Build source-bound prerequisites for the unchanged full retained runner.

This reconstructs the inspected local driver after the execution environment
became unavailable. Its exact submitted revision still requires actual CI.
All original builders and the original preparation observer remain unchanged.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import sys
import time
import workflow_process

UPSTREAM = "https://github.com/TrillionniumFoundation/hepta-private-ci.git"
PINS = {
    "ranking": "d3c2d760eca5065fc966820379c35c6e8d56e855",
    "model": "8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d",
    "recursive": "2590c0c94c5bf9a9004caeeb7b75edd6faf3eb8b",
    "finite": "4b6391e116949af0c7e59776baead67271856bdb",
    "stream": "c4a1bbed3a39beba43a6abf1a18b6f75c5725c21",
}
PACKAGES = ["pip==25.1.1", "setuptools==78.1.1", "wheel==0.46.3",
            "z3-solver==4.15.4.0", "jsonschema==4.25.1", "zstandard==0.25.0"]

def record(path):
    path = Path(path)
    before = path.stat()
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    after = path.stat()
    signature = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if signature(before) != signature(after) or not stat.S_ISREG(before.st_mode):
        raise RuntimeError("dependency changed during read: " + str(path))
    return dict(path=str(path), bytes=before.st_size,
                mode=stat.S_IMODE(before.st_mode), sha256=digest)

def write(path, value):
    with Path(path).open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")

class Driver:
    def __init__(self, args):
        self.source = args.source.resolve(strict=True)
        self.out = args.output.absolute()
        self.cache = args.cache_root.absolute()
        self.temporary = args.temporary_root.absolute()
        roots = (self.out, self.cache, self.temporary)
        for path in roots:
            if path == self.source or path.is_relative_to(self.source):
                raise ValueError("outputs must be outside the pinned source")
            if path.exists() or any(p.is_symlink() for p in (path, *path.parents)):
                raise ValueError("output must be new and without symlink ancestors: " + str(path))
        if any(a.is_relative_to(b) for a in roots for b in roots if a != b):
            raise ValueError("output/cache/temporary roots must be separate")
        self.out.mkdir(parents=True, mode=0o700)
        self.cache.mkdir(parents=True, mode=0o700)
        self.commands = self.out / "commands"
        self.commands.mkdir()
        self.base = self.out / "prerequisites"
        self.base.mkdir()
        (self.base / "evidence").mkdir()
        self.env = dict(os.environ)
        for key in list(self.env):
            if key.startswith(("HEPTA_", "HIA_TEST_")) or key in {
                "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "VIRTUAL_ENV", "LD_PRELOAD",
                "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET",
                "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC", "CARGO_TARGET_DIR",
                "CARGO_NET_OFFLINE", "LEAN_PATH", "LEAN_SRC_PATH", "LEAN_SYSROOT",
            }:
                self.env.pop(key, None)
        self.env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1",
                        GIT_TERMINAL_PROMPT="0", LANG="C.UTF-8", LC_ALL="C.UTF-8",
                        CARGO_HOME=str(self.cache / "cargo-home"),
                        RUSTUP_HOME=str(self.base / "toolchains-rustup"))
        self.rows = []
        self.hints = {}
        self.summary = dict(
            schema="hia-fresh-full-retained-prerequisites-v2",
            status="BUILDING", source=str(self.source), upstream_pins=PINS,
            package_pins=PACKAGES, platform=platform.platform(), python=sys.version,
            execution_environment="github-actions" if os.environ.get("GITHUB_ACTIONS") == "true" else "local",
            started_unix_ns=time.time_ns(), qualification_executed=False,
            whole_stack_closed=False, old_4157_failure_relabelled=False,
            inner_limits_changed=False)

    def run(self, label, argv, *, cwd=None, env=None, seconds=1200):
        stem = self.commands / f"{len(self.rows) + 1:03d}-{label}"
        stdout, stderr = stem.with_suffix(".stdout"), stem.with_suffix(".stderr")
        row = dict(label=label, argv=list(map(str, argv)),
                   cwd=str(cwd or self.source), external_wall_seconds=seconds)
        started = time.monotonic_ns()
        self.rows.append(row)
        print(json.dumps(dict(starting=label)), flush=True)
        owner = workflow_process.run_workflow_step(
            row["argv"], cwd=row["cwd"], env=self.env if env is None else env,
            stdout_path=stdout, stderr_path=stderr,
            receipt_path=stem.with_suffix(".owner.json"), seconds=seconds)
        row.update(owner=owner, returncode=owner.get("returncode"),
                   timed_out=owner.get("timed_out"), wall_ns=time.monotonic_ns() - started,
                   stdout=record(stdout), stderr=record(stderr))
        write(stem.with_suffix(".json"), row)
        print(json.dumps({k: row[k] for k in ("label", "returncode", "timed_out", "wall_ns")}), flush=True)
        if (row["returncode"] != 0 or row["timed_out"] is not False
                or owner.get("status") != "WORKFLOW_STEP_COMPLETED"
                or owner.get("cleanup", {}).get("complete") is not True):
            raise RuntimeError("prerequisite command failed: " + label)
        return stdout.read_text(encoding="utf-8")

    def checkout(self, profile, pin):
        folder = self.base / (profile + "-ndu-upstream")
        folder.mkdir()
        git = ["git", "--no-replace-objects", "-C", folder]
        commands = [
            ("init", [*git, "init", "--quiet"]),
            ("remote", [*git, "remote", "add", "origin", UPSTREAM]),
            ("promisor", [*git, "config", "remote.origin.promisor", "true"]),
            ("filter", [*git, "config", "remote.origin.partialclonefilter", "blob:none"]),
            ("fetch", [*git, "fetch", "--depth=1", "--no-tags", "--filter=blob:none", "origin", pin]),
            ("sparse-init", [*git, "sparse-checkout", "init", "--cone"]),
        ]
        for label, argv in commands:
            self.run(profile + "-git-" + label, argv)
        paths = ["codex-rs/hepta-ndu", "codex-rs/hepta-types", "codex-rs/hepta-contracts"]
        if profile in {"recursive", "finite", "stream"}:
            paths.append("tools/hia-ndu-bridge")
        self.run(profile + "-git-sparse-paths", [*git, "sparse-checkout", "set", *paths])
        self.run(profile + "-git-checkout", [*git, "checkout", "--quiet", "--detach", pin])
        head = self.run(profile + "-git-head", [*git, "rev-parse", "HEAD"]).strip()
        dirty = self.run(profile + "-git-status", [*git, "status", "--porcelain=v1", "--untracked-files=all"])
        if head != pin or dirty:
            raise RuntimeError("upstream checkout is not exact and clean")
        return folder

    def build(self):
        sys.path.insert(0, str(self.source))
        from tools.hia_core_source_identity import ROOT, _source_state
        if ROOT.resolve() != self.source:
            raise RuntimeError("source checker belongs to another tree")
        before = _source_state()
        if before["status"]:
            raise RuntimeError("preparation requires clean complete source")
        if os.environ.get("GITHUB_ACTIONS") == "true" and before["head"] != os.environ.get("GITHUB_SHA"):
            raise RuntimeError("source HEAD differs from GitHub event")
        write(self.out / "source-before.json", before)
        self.summary.update(source_head=before["head"], source_tree=before["tree"])

        venv = self.base / "venv"
        self.run("python-venv", [sys.executable, "-m", "venv", venv])
        python = venv / "bin/python"
        self.run("python-packages", [python, "-m", "pip", "--disable-pip-version-check",
                                     "install", "--no-input", *PACKAGES])
        self.hints["PYTHON"] = str(python)
        rustup = shutil.which("rustup")
        if not rustup:
            raise RuntimeError("runner rustup executable missing")
        self.summary["rustup_image"] = record(Path(rustup).resolve())
        rustbins = {}
        for version in ("1.90.0", "1.95.0"):
            self.run("rust-" + version, [rustup, "toolchain", "install", version,
                                         "--profile", "minimal", "--no-self-update"])
            rustbins[version] = self.base / "toolchains-rustup/toolchains" / (version + "-x86_64-unknown-linux-gnu/bin")
        self.summary["rust_tools"] = {
            version: {name: record(folder / name) for name in ("cargo", "rustc")}
            for version, folder in rustbins.items()}
        self.env["RUSTC"] = str(rustbins["1.90.0"] / "rustc")
        self.env["PATH"] = os.pathsep.join((str(rustbins["1.90.0"]), str(venv / "bin"), self.env["PATH"]))
        self.hints["RUSTC"] = self.env["RUSTC"]

        self.run("fixed-lean-and-qemu-installer",
                 [python, "-B", self.source / "tools/bootstrap_verification.py",
                  "--directory", self.base / "verification-tools"])
        self.hints["LEAN"] = str(self.base / "verification-tools/lean-4.19.0/bin/lean")
        boost = self.base / "toolchains-boost183"
        boost.mkdir()
        self.run("boost-original-package", ["apt-get", "download", "libboost1.83-dev"], cwd=boost)
        packages = list(boost.glob("libboost1.83-dev_*.deb"))
        if len(packages) != 1:
            raise RuntimeError("expected one actual Boost package")
        self.run("boost-original-extraction", ["dpkg-deb", "--extract", packages[0], boost])
        write(self.base / "evidence/qualification-boost183-01.json",
              dict(package=packages[0].name, sha256=record(packages[0])["sha256"],
                   fresh_download=True, old_receipt_reused=False))

        checkouts = {profile: self.checkout(profile, pin) for profile, pin in PINS.items()}
        profiles = (
            ("ranking", "ranking", "build_hia_ndu_bridge.py", "hia-ndu-bridge", "HEPTA_NDU", "HEPTA_NDU_BUILD"),
            ("raw", "model", "build_hia_raw_model_bridge.py", "hia-ndu-raw-model", "HEPTA_RAW_MODEL", "HEPTA_RAW_MODEL_BUILD"),
            ("dynamic", "model", "build_hia_ndu_dynamic_bridge.py", "hia-ndu-dynamic-model", "HEPTA_DYNAMIC_POLICY", "HEPTA_DYNAMIC_POLICY_MANIFEST"),
        )
        for profile, checkout, script, adapter, prefix, receipt_key in profiles:
            pin = json.loads((self.source / "rust" / adapter / "upstream.json").read_bytes())
            if pin["commit"] != PINS[checkout] or pin["repository"] != UPSTREAM:
                raise RuntimeError("current adapter upstream pin differs")
            output = self.base / "evidence" / ("ndu-" + profile + "-build")
            env = dict(self.env, CARGO_TARGET_DIR=str(self.cache / (profile + "-target")))
            self.run("build-" + profile,
                     [python, "-B", self.source / "tools" / script,
                      "--upstream", checkouts[checkout], "--output", output,
                      "--cargo", rustbins["1.90.0"] / "cargo"], env=env)
            receipt = output / "build-receipt.json"
            value = json.loads(receipt.read_bytes())
            self.hints[prefix + ("_BINARY" if profile == "dynamic" else "_BRIDGE")] = value["binary"]
            self.hints[receipt_key] = str(output if profile == "ranking" else receipt)
            if profile == "ranking":
                self.hints["HEPTA_NDU_UPSTREAM"] = str(checkouts[checkout])
            durable = output / "native"
            durable.mkdir()
            shutil.copy2(value["binary"], durable / "hia-ndu-bridge")
            if record(durable / "hia-ndu-bridge")["sha256"] != value["binary_sha256"]:
                raise RuntimeError("durable bridge image differs")

        for profile, prefix, version in (
                ("recursive", "HEPTA_RECURSIVE_NDU", "1.90.0"),
                ("finite", "HEPTA_FINITE_NDU", "1.95.0"),
                ("stream", "HEPTA_NDU_STREAM", "1.90.0")):
            output = self.base / "evidence" / ("ndu-" + profile + "-build")
            self.run("build-" + profile,
                     [python, "-B", self.source / "tools/build_hia_recursive_ndu_bridge.py",
                      "--ndu-source", checkouts[profile], "--output", output,
                      "--target-dir", self.cache / (profile + "-target"),
                      "--cargo", rustbins[version] / "cargo", "--rustc", rustbins[version] / "rustc",
                      "--cargo-home", self.cache / "cargo-home", "--expected-source", PINS[profile]])
            receipt = output / "identity.json"
            value = json.loads(receipt.read_bytes())
            self.hints[prefix + "_BRIDGE"] = value["binary"]
            self.hints[prefix + "_IDENTITY"] = str(receipt)
            self.hints[prefix + "_UPSTREAM"] = str(checkouts[profile])

        self.run("fetch-locked-shadow", [rustbins["1.90.0"] / "cargo", "fetch", "--locked",
                  "--manifest-path", self.source / "rust/hia-core-shadow/Cargo.toml"])
        self.run("verify-offline-shadow", [rustbins["1.90.0"] / "cargo", "metadata", "--locked",
                  "--offline", "--format-version=1", "--manifest-path",
                  self.source / "rust/hia-core-shadow/Cargo.toml"])
        hints = self.out / "candidate-environment.json"
        write(hints, self.hints)
        observer = self.source / "review-evidence/hia-native-rewrite-20261111/prepare_remote_qualification_v2.py"
        self.run("original-preparation-observer",
                 [python, "-B", observer, "--source", self.source,
                  "--output", self.out / "preparation", "--temporary-root", self.temporary,
                  "--prereq-root", self.base, "--python", python, "--candidate-environment", hints])
        prepared = self.out / "preparation/preparation.json"
        preparation = json.loads(prepared.read_bytes())
        if preparation["status"] != "READY" or preparation["missing"]:
            raise RuntimeError("original complete preparation observer is not READY")
        after = _source_state()
        write(self.out / "source-after.json", after)
        if before != after:
            raise RuntimeError("candidate source changed during prerequisites")
        self.summary.update(status="READY", original_preparation=record(prepared),
                            source_preserved=True, original_six_builders_used=True)
        if os.environ.get("GITHUB_ACTIONS") == "true":
            with Path(os.environ["GITHUB_ENV"]).open("a") as stream:
                stream.write("CARGO_HOME=" + self.env["CARGO_HOME"] + "\n")
                stream.write("RUSTUP_HOME=" + self.env["RUSTUP_HOME"] + "\n")

    def save(self):
        self.summary.update(ended_unix_ns=time.time_ns(), commands=self.rows)
        write(self.out / "summary.json", self.summary)
        print(json.dumps(dict(status=self.summary["status"], commands=len(self.rows),
                              qualification_executed=False, whole_stack_closed=False)), flush=True)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "output", "cache-root", "temporary-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    driver = Driver(args)
    try:
        driver.build()
    except Exception as error:
        driver.summary.update(status="HOLD", error=repr(error))
        raise
    finally:
        driver.save()

if __name__ == "__main__":
    main()
