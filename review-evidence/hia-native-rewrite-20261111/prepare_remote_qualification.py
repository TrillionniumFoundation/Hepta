#!/usr/bin/env python3
"""Observe current rog prerequisites and prepare a fresh qualification environment.

This does not run qualification, replay an old job, install a system package, or
change the candidate repository or old prerequisite workspace. Existing receipts
are candidate paths only: their current files, hashes and source bindings are
read again. Missing/changed prerequisites remain explicit HOLD entries.

Example:
  python3 prepare_remote_qualification.py --source /new/task/Hepta \
    --output /new/task/preparation
  python3 /new/task/preparation/launch.py /new/task/run_hia_qualification.py \
    --source /new/task/Hepta --output /new/task/qualification --full

If no existing venv satisfies the package pins, --install-python-deps permits a
NEW venv under --output. --wheelhouse makes that installation offline. Neither
option modifies an existing venv. Without the flag, installation is never tried.
"""
from __future__ import annotations

import argparse
import ast
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import time


DEFAULT_PREREQUISITES = (
    "/home/qian-qi/.openclaw/workspaces/azi5/tasks/"
    "hia-selfhost-completion-20261109"
)
PINS = {"setuptools": "78.1.1", "wheel": "0.46.3",
        "z3-solver": "4.15.4.0"}
EXTRA_PACKAGES = ("jsonschema", "pip")
DROP_PREFIXES = ("HEPTA_HIA_", "HEPTA_NDU_", "HEPTA_RAW_MODEL_",
                 "HEPTA_DYNAMIC_POLICY_", "HEPTA_FINITE_NDU_",
                 "HEPTA_RECURSIVE_NDU_")
DROP_NAMES = {
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "VIRTUAL_ENV",
    "LD_PRELOAD", "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS",
    "CARGO_BUILD_TARGET", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTC", "LEAN_PATH", "LEAN_SRC_PATH", "LEAN_SYSROOT",
}
PYTHON_PROBE = r"""
import importlib.metadata as m, importlib.util as u, json, sys
packages={}
for name in ("setuptools","wheel","z3-solver","jsonschema","pip"):
    try: packages[name]=m.version(name)
    except m.PackageNotFoundError: packages[name]=None
result={"executable":sys.executable,"prefix":sys.prefix,
        "base_prefix":sys.base_prefix,"version":sys.version,
        "version_info":list(sys.version_info[:3]),"packages":packages}
try:
    import z3, jsonschema
    result["z3_runtime"]=z3.get_version_string()
    result["jsonschema_import"]=True
except Exception as e: result["import_error"]=repr(e)
print(json.dumps(result,sort_keys=True))
"""
LAUNCHER = r'''#!/usr/bin/env python3
"""Apply freshly observed environment; execute only the caller's NEW command."""
from hashlib import sha256
import json, os
from pathlib import Path
import sys
here=Path(__file__).resolve().parent
value=json.loads((here/"environment.json").read_text())
if not value.get("python"):
    raise SystemExit("No pinned user-owned Python venv was admitted; read preparation.json")
for path,expected in value["recheck_sha256"].items():
    digest=sha256()
    with open(path,"rb") as stream:
        for block in iter(lambda:stream.read(1024*1024),b""): digest.update(block)
    if digest.hexdigest()!=expected:
        raise SystemExit("Prerequisite changed after preparation: "+path)
if len(sys.argv)<2:
    raise SystemExit("usage: launch.py NEW_RUNNER.py [arguments...]")
env={key:val for key,val in os.environ.items()
     if key not in value["unset"] and not key.startswith(tuple(value["unset_prefixes"]))}
env.update(value["set"])
os.chdir(value["source"])
os.execve(value["python"],[value["python"],"-B",*sys.argv[1:]],env)
'''


class Preparation:
    def __init__(self, args):
        self.args = args
        self.source = args.source.resolve(strict=True)
        self.base = args.prereq_root.resolve()
        self.out = args.output.resolve()
        if self.out == self.source or self.out.is_relative_to(self.source):
            raise ValueError("--output must be outside the frozen repository")
        if self.out == self.base or self.out.is_relative_to(self.base):
            raise ValueError("--output must be outside the old prerequisite workspace")
        self.out.mkdir(parents=True, exist_ok=False, mode=0o700)
        (self.out / "temporary").mkdir(mode=0o700)
        self.env = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1",
                    "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                    "TMPDIR": str(self.out / "temporary"), "CARGO_NET_OFFLINE": "true",
                    "CARGO_TARGET_DIR": str(self.out / "cargo-target")}
        self.paths = []
        self.tool_variables = set()
        self.bindings = {}
        self.python = None
        self.hints = {}
        self.report = {
            "schema": "hepta.hia.remote-qualification-preparation.v1",
            "started_unix_ns": time.time_ns(),
            "source": str(self.source), "prerequisite_root": str(self.base),
            "host": platform.node(), "platform": platform.platform(),
            "package_pins": PINS, "checks": {}, "missing": [],
            "qualification_executed": False, "old_jobs_replayed": False,
            "system_packages_installed": False,
            "whole_native_delivery_qualified": False,
        }
        if args.candidate_environment:
            raw = json.loads(args.candidate_environment.read_text())
            for key in ("selected_environment", "settings", "environment", "set"):
                if isinstance(raw, dict) and isinstance(raw.get(key), dict):
                    raw = raw[key]
                    break
            if not isinstance(raw, dict):
                raise ValueError("candidate environment must contain a JSON object")
            self.hints = {k: v for k, v in raw.items()
                          if isinstance(k, str) and isinstance(v, str)}
            self.report["candidate_environment_only_not_evidence"] = self.info(
                args.candidate_environment, bind=True)

    def info(self, value, *, executable=False, bind=False):
        requested = Path(value).absolute()
        resolved = requested.resolve(strict=True)
        with resolved.open("rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > (1 << 30):
                raise ValueError("not a bounded regular file: " + str(requested))
            digest = sha256()
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
            after = os.fstat(stream.fileno())
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity(before) != identity(after) or requested.resolve(strict=True) != resolved:
            raise ValueError("file changed while reading: " + str(requested))
        if executable and not os.access(requested, os.X_OK):
            raise ValueError("file is not executable: " + str(requested))
        row = {"path": str(requested), "resolved": str(resolved),
               "bytes": before.st_size, "sha256": digest.hexdigest(),
               "mode": oct(stat.S_IMODE(before.st_mode)), "uid": before.st_uid}
        if bind:
            self.bindings[str(requested)] = row["sha256"]
        return row

    def command(self, argv, *, timeout=30, env=None, cwd=None):
        started = time.monotonic()
        try:
            p = subprocess.run(list(map(str, argv)), cwd=cwd or self.out,
                               env=env, stdin=subprocess.DEVNULL,
                               capture_output=True, timeout=timeout, check=False)
            return {"argv": list(map(str, argv)), "returncode": p.returncode,
                    "stdout": p.stdout.decode("utf-8", "replace")[:16384],
                    "stderr": p.stderr.decode("utf-8", "replace")[:16384],
                    "seconds": time.monotonic() - started}
        except (OSError, subprocess.TimeoutExpired) as error:
            return {"argv": list(map(str, argv)), "returncode": None,
                    "error": str(error), "seconds": time.monotonic() - started}

    def missing(self, label, effect):
        self.report["missing"].append({"prerequisite": label, "effect": effect})

    def tool(self, label, variables, candidates, *, pattern=None, expected_hash=None):
        self.tool_variables.update(variables)
        attempts = []
        candidates = [*(self.hints.get(k) for k in variables), *candidates]
        seen = set()
        for value in candidates:
            if not value:
                continue
            found = shutil.which(str(value))
            if not found or found in seen:
                if str(value) not in seen:
                    attempts.append({"path": str(value), "available": False})
                    seen.add(str(value))
                continue
            seen.add(found)
            try:
                row = self.info(found, executable=True)
                version = self.command([found, "--version"])
                row["version"] = version
                if version["returncode"] != 0:
                    raise ValueError("version probe failed")
                output = version.get("stdout", "") + version.get("stderr", "")
                if pattern and not re.search(pattern, output, re.I):
                    raise ValueError("version does not match " + pattern)
                if expected_hash and row["sha256"] != expected_hash:
                    raise ValueError("executable differs from the source-pinned hash")
                self.bindings[row["path"]] = row["sha256"]
                for key in variables:
                    self.env[key] = row["path"]
                self.paths.append(str(Path(row["path"]).parent))
                row["available"] = True
                row["rejected_candidates"] = attempts
                self.report["checks"][label] = row
                return row["path"]
            except (OSError, ValueError) as error:
                attempts.append({"path": found, "available": False, "error": str(error)})
        self.report["checks"][label] = {"available": False, "attempts": attempts}
        return None

    def python_environment(self):
        candidates = [self.args.python, self.hints.get("PYTHON"),
                      self.base / "venv/bin/python", sys.executable]
        attempts = []
        for value in dict.fromkeys(str(p) for p in candidates if p):
            try:
                image = self.info(value, executable=True)
                result = self.command([value, "-I", "-B", "-c", PYTHON_PROBE])
                if result["returncode"] != 0:
                    raise ValueError("Python package probe failed: " + str(result))
                row = json.loads(result["stdout"])
                row["image"] = image
                prefix = Path(row["prefix"])
                if prefix == Path(row["base_prefix"]) or prefix.stat().st_uid != os.getuid():
                    raise ValueError("interpreter is not in a user-owned venv")
                if any(row["packages"].get(k) != v for k, v in PINS.items()):
                    raise ValueError("required exact package versions unavailable: " + str(row["packages"]))
                if any(not row["packages"].get(k) for k in EXTRA_PACKAGES):
                    raise ValueError("jsonschema/pip missing")
                if row.get("jsonschema_import") is not True or row.get("z3_runtime") != "4.15.4":
                    raise ValueError("solver or jsonschema import failed")
                self.python = str(Path(value).absolute())
                self.bindings[self.python] = image["sha256"]
                self.paths.insert(0, str(Path(self.python).parent))
                self.env["VIRTUAL_ENV"] = str(prefix)
                row["available"] = True
                row["rejected_candidates"] = attempts
                self.report["checks"]["python"] = row
                return
            except (OSError, ValueError, KeyError) as error:
                attempts.append({"path": value, "error": str(error)})
        if self.args.install_python_deps:
            venv = self.out / "venv"
            created = self.command([sys.executable, "-m", "venv", str(venv)], timeout=60)
            self.report["venv_creation"] = created
            if created["returncode"] == 0:
                command = [venv / "bin/python", "-m", "pip", "--disable-pip-version-check",
                           "install", "--no-input"]
                if self.args.wheelhouse:
                    command += ["--no-index", "--find-links", self.args.wheelhouse.resolve()]
                command += [f"{k}=={v}" for k, v in PINS.items()] + list(EXTRA_PACKAGES)
                installed = self.command(command, timeout=180)
                self.report["user_venv_installation"] = installed
                if installed["returncode"] == 0:
                    self.args.python = venv / "bin/python"
                    self.args.install_python_deps = False
                    return self.python_environment()
        self.report["checks"]["python"] = {"available": False, "attempts": attempts}
        self.missing("python", "Exact package environment unavailable; source/native/full suite cannot be qualified.")

    def read_receipt(self, path):
        row = self.info(path, bind=True)
        if row["bytes"] > (4 << 20):
            raise ValueError("receipt exceeds 4 MiB")
        return json.loads(Path(path).read_bytes()), row

    def inventory(self, root):
        if not root.is_dir():
            raise ValueError("source directory missing: " + str(root))
        return {p.relative_to(root).as_posix(): self.info(p, bind=True)["sha256"]
                for p in sorted(root.rglob("*")) if p.is_file()}

    def check_inventory(self, root, expected):
        if not isinstance(expected, dict) or not expected or len(expected) > 10000:
            raise ValueError("invalid file inventory")
        for name, digest in expected.items():
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("inventory path escapes root")
            if self.info(root / relative, bind=True)["sha256"] != digest:
                raise ValueError("source/input hash differs: " + str(root / relative))

    def git_pin(self, checkout, commit):
        if not re.fullmatch(r"[0-9a-f]{40}", str(commit)):
            raise ValueError("invalid Git source pin")
        result = self.command(["git", "-C", checkout, "rev-parse", commit + "^{commit}"])
        if result["returncode"] != 0 or result.get("stdout", "").strip() != commit:
            raise ValueError("required source commit unavailable in " + str(checkout))
        return {"path": str(checkout), "commit": commit, "probe": result}

    def ndu_build(self, profile, directory, adapter, prefix, receipt_key):
        receipt = Path(self.hints.get(receipt_key, directory))
        if profile == "ranking":
            receipt = receipt / "build-receipt.json"
        elif receipt.is_dir() or receipt == directory:
            receipt = receipt / "build-receipt.json"
        try:
            value, record = self.read_receipt(receipt)
            if (value.get("schema") != "hepta.hia.ndu-build.v1"
                    or value.get("original_rust_sources_unchanged") is not True
                    or value.get("all_original_non_manifest_inputs_unchanged") is not True):
                raise ValueError("original source receipt is not valid")
            local = self.source / "rust" / adapter
            if value.get("adapter_files") != self.inventory(local):
                raise ValueError("receipt does not match the current candidate adapter sources")
            pin, _ = self.read_receipt(local / "upstream.json")
            if value.get("upstream") != pin:
                raise ValueError("upstream source pin differs")
            builder = self.source / "tools/build_hia_ndu_bridge.py"
            if value.get("builder_sha256") != self.info(builder, bind=True)["sha256"]:
                raise ValueError("builder source hash differs from the current candidate")
            self.check_inventory(receipt.parent, value.get("build_inputs"))
            if self.info(receipt.parent / "Cargo.lock", bind=True)["sha256"] != value.get("cargo_lock_sha256"):
                raise ValueError("Cargo.lock hash differs")
            binary_key = prefix + ("_BINARY" if profile == "dynamic" else "_BRIDGE")
            binary = Path(self.hints.get(binary_key, value["binary"]))
            image = self.info(binary, executable=True, bind=True)
            if image["sha256"] != value.get("binary_sha256"):
                raise ValueError("current binary hash differs from its receipt")
            record.update(available=True, binary=image, adapter_source_binding=True,
                          build_input_files=len(value["build_inputs"]))
            if profile == "ranking":
                checkout = Path(self.hints.get("HEPTA_NDU_UPSTREAM", self.base / "ndu-upstream"))
                record["upstream"] = self.git_pin(checkout, pin["commit"])
                self.env["HEPTA_NDU_UPSTREAM"] = str(checkout)
            self.env[binary_key] = str(binary)
            self.env[receipt_key] = str(receipt.parent if profile == "ranking" else receipt)
            self.report["checks"]["ndu_" + profile] = record
        except (OSError, ValueError, KeyError) as error:
            self.report["checks"]["ndu_" + profile] = {"available": False, "receipt": str(receipt), "error": str(error)}
            self.missing("ndu_" + profile, "Its native/provenance tests will skip or remain unqualified; no old receipt is relabelled as current PASS.")

    def ndu_identity(self, profile, prefix):
        folder = self.base / "evidence" / ("ndu-" + profile + "-build-01")
        receipt = Path(self.hints.get(prefix + "_IDENTITY", folder / "identity.json"))
        try:
            value, record = self.read_receipt(receipt)
            if value.get("schema") != "hepta.hia.ndu.build.v1":
                raise ValueError("wrong native identity schema")
            binary = Path(self.hints.get(prefix + "_BRIDGE", value["binary"]))
            image = self.info(binary, executable=True, bind=True)
            if (image["sha256"] != value.get("compiled_binary_sha256")
                    or image["sha256"] != value.get("binary_sha256")):
                raise ValueError("native binary differs from its build identity")
            # Several retained session tests read manifest["binary"] directly.
            manifest_image = self.info(value["binary"], executable=True, bind=True)
            if manifest_image["sha256"] != image["sha256"]:
                raise ValueError("manifest binary and configured native binary differ")
            identity = value["identity"]
            if identity.get("authority") != "DENY_ALL" or identity.get("safety_certificate") is not False:
                raise ValueError("identity authority fields differ")
            if profile == "finite" and (
                    identity.get("source_commit") != "4b6391e116949af0c7e59776baead67271856bdb"
                    or not str(identity.get("rustc", "")).startswith("rustc 1.95.0 ")):
                raise ValueError("finite profile requires exact source/Rust 1.95.0 identity")
            if profile == "stream" and identity.get("source_commit") not in {
                    "c4a1bbed3a39beba43a6abf1a18b6f75c5725c21",
                    "8e52e1187f47f6d4edc8d942fc7cb7eca4bc447d"}:
                raise ValueError("unknown stream profile source pin")
            checkout = self.base / (profile + "-ndu-upstream")
            # A receipt's build argv is read as data, never executed. This
            # recovers the actual old source path without assuming its spelling.
            argv = value.get("build_command", [])
            if isinstance(argv, list) and "--manifest-path" in argv:
                at = argv.index("--manifest-path") + 1
                if at < len(argv) and isinstance(argv[at], str):
                    recorded = Path(argv[at]).parent.parent.parent
                    if recorded.is_relative_to(self.base) and recorded.is_dir():
                        checkout = recorded
            checkout = Path(self.hints.get(prefix + "_UPSTREAM", checkout))
            upstream = self.git_pin(checkout, identity["source_commit"])
            self.check_inventory(checkout, value.get("native_sources"))
            self.check_inventory(checkout, value.get("bridge_sources"))
            probe = self.command([binary, "--identity"])
            if probe["returncode"] != 0 or json.loads(probe.get("stdout", "{}")) != identity:
                raise ValueError("actual native --identity differs from manifest")
            self.env[prefix + "_BRIDGE"] = str(binary)
            self.env[prefix + "_IDENTITY"] = str(receipt)
            self.env[prefix + "_UPSTREAM"] = str(checkout)
            record.update(available=True, binary=image, manifest_binary=manifest_image, upstream=upstream,
                          actual_identity_probe=probe, current_source_files_rehashed=True)
            self.report["checks"]["ndu_" + profile] = record
        except (OSError, ValueError, KeyError) as error:
            self.report["checks"]["ndu_" + profile] = {"available": False, "receipt": str(receipt), "error": str(error)}
            self.missing("ndu_" + profile, "Native " + profile + " NDU, isolation and dependent integration tests cannot count as qualified.")

    def boost(self):
        receipt = self.base / "evidence/qualification-boost183-01.json"
        include = self.base / "toolchains-boost183/usr/include"
        try:
            value, record = self.read_receipt(receipt)
            package = self.base / "toolchains-boost183" / value["package"]
            image = self.info(package, bind=True)
            if image["sha256"] != value["sha256"]:
                raise ValueError("Boost package receipt hash differs")
            version = include / "boost/version.hpp"
            self.info(version, bind=True)
            if not re.search(r'#\s*define\s+BOOST_LIB_VERSION\s+"1_83"', version.read_text()):
                raise ValueError("Boost headers are not 1.83")
            self.env["CPLUS_INCLUDE_PATH"] = str(include)
            record.update(available=True, package=image, include=str(include))
            self.report["checks"]["boost"] = record
        except (OSError, ValueError, KeyError) as error:
            self.report["checks"]["boost"] = {"available": False, "error": str(error)}
            self.missing("boost", "Retained Boost/STB/C++ native controls may fail to compile; no replacement headers are installed.")

    def references(self):
        """Static dependency map only; do not import tests or execute their setup."""
        keys = set(self.env) | {"LEAN", "HEPTA_QEMU_AARCH64", "HEPTA_QEMU_X86_64",
                               "HEPTA_QEMU_RISCV64", "HEPTA_LLD", "CLANG", "RUSTC"}
        for profile in ("HEPTA_NDU", "HEPTA_RAW_MODEL", "HEPTA_FINITE_NDU",
                        "HEPTA_RECURSIVE_NDU", "HEPTA_NDU_STREAM", "HEPTA_DYNAMIC_POLICY"):
            keys.update(profile + suffix for suffix in ("_BRIDGE", "_IDENTITY", "_BUILD", "_BINARY", "_MANIFEST", "_UPSTREAM"))
        rows = {}
        for path in sorted((self.source / "tests").glob("test*.py")):
            try:
                tree = ast.parse(path.read_text())
                strings = {node.value for node in ast.walk(tree)
                           if isinstance(node, ast.Constant) and isinstance(node.value, str)}
            except (OSError, SyntaxError):
                continue
            names = sorted(strings & keys)
            if names:
                rows[path.relative_to(self.source).as_posix()] = names
        self.report["test_environment_references"] = rows

    def run(self):
        self.python_environment()
        llvm = Path("/usr/lib/llvm-20/bin")
        clang = self.tool("clang", ("CLANG", "HEPTA_CLANG", "HEPTA_NATIVE_CLANG",
                          "HEPTA_TEST_CLANG", "HIA_TEST_CLANG20", "HIA_KERNEL_CLANG"),
                          ["/usr/bin/clang-20", llvm / "clang"], pattern=r"clang version 20\.")
        specs = [
            ("clangxx", ("CLANGXX",), ["/usr/bin/clang++-20", llvm / "clang++"], r"clang version 20\."),
            ("lld", ("HEPTA_LLD",), [llvm / "ld.lld", "/usr/bin/ld.lld-20"], r"LLD 20\."),
            ("objdump", ("HIA_KERNEL_OBJDUMP",), [llvm / "llvm-objdump", "/usr/bin/llvm-objdump-20"], None),
            ("profdata", ("HEPTA_PROFDATA",), [llvm / "llvm-profdata", "/usr/bin/llvm-profdata-20"], None),
            ("readobj", ("HEPTA_LLVM_READOBJ",), [llvm / "llvm-readobj", "/usr/bin/llvm-readobj-20"], None),
            ("gcc", ("CC", "HEPTA_STB_GCC"), ["/usr/bin/gcc", "gcc"], None),
            ("qemu_x86_64", ("HEPTA_QEMU_X86_64",), ["/usr/bin/qemu-x86_64", "/usr/bin/qemu-x86_64-static"], None),
            ("qemu_riscv64", ("HEPTA_QEMU_RISCV64",), ["/usr/bin/qemu-riscv64", "/usr/bin/qemu-riscv64-static"], None),
            ("qemu_aarch64", ("HEPTA_QEMU_AARCH64",), [self.base / "verification-tools/qemu-8.2.2/qemu-aarch64-static",
                                                          "/usr/bin/qemu-aarch64", "/usr/bin/qemu-aarch64-static"], None),
        ]
        for label, variables, candidates, pattern in specs:
            if not self.tool(label, variables, candidates, pattern=pattern):
                self.missing(label, "Related native retained controls cannot execute; LLVM/qemu target-profile gates may fail rather than skip.")
        if not clang:
            self.missing("clang", "Cold compiler/native construction and C/LLVM retained gates cannot be qualified.")
        rust_bin = self.base / "toolchains-rustup/toolchains/1.90.0-x86_64-unknown-linux-gnu/bin"
        rustc = self.tool("rustc", ("RUSTC", "HEPTA_RUSTC", "HIA_TEST_SOURCE_RUSTC"),
                         [rust_bin / "rustc", "/home/qian-qi/.cargo/bin/rustc", "rustc"])
        cargo = self.tool("cargo", (), [rust_bin / "cargo", "/home/qian-qi/.cargo/bin/cargo", "cargo"])
        if not (rustc and cargo):
            self.missing("rust_toolchain", "Rust shadow/VM/execution/ownership parity classes skip; missing offline crate cache can still fail later.")
        lock_path = self.source / "formal/toolchain-lock.json"
        lean_lock, _ = self.read_receipt(lock_path)
        lean = self.tool("lean", ("LEAN",), [self.base / "verification-tools/lean-4.19.0/bin/lean"],
                         expected_hash=lean_lock["lean_binary_sha256"])
        if not lean:
            self.missing("lean", "The two actual RegisterSafety theorem-evidence tests skip; ordinary source tests do not substitute for Lean proofs.")
        tracer = self.tool("strace", (), ["/usr/bin/strace", "strace"])
        ptrace = self.command([tracer, "-f", "-qq", "-e", "trace=execve",
                               "-o", self.out / "strace-probe.log", "/bin/true"]) if tracer else {"returncode": None}
        self.report["checks"]["ptrace"] = ptrace
        if ptrace["returncode"] != 0:
            self.missing("ptrace", "Standalone Agent/Core CLI syscall allowlist and injected EINTR tests fail; no tracing gate will be weakened or skipped.")
        if self.python:
            probe_code = ("import fcntl,os; f=os.memfd_create('hia-preparation',os.MFD_ALLOW_SEALING);"
                          "os.write(f,b'x');fcntl.fcntl(f,1033,15);assert fcntl.fcntl(f,1034)==15;"
                          "assert os.path.isdir('/proc/self/fd');os.close(f);print('sealed-memfd-ok')")
            sealed = self.command([self.python, "-I", "-B", "-c", probe_code])
            self.report["checks"]["sealed_memfd"] = sealed
            if sealed["returncode"] != 0:
                self.missing("sealed_memfd", "Linux sealed-image NDU/native/Rust custody tests cannot be qualified.")
        for profile, directory, adapter, prefix, key in [
                ("ranking", "core-controls-ndu-original-prerequisite-01", "hia-ndu-bridge", "HEPTA_NDU", "HEPTA_NDU_BUILD"),
                ("raw", "core-retained-ndu-raw-model-prerequisite-01", "hia-ndu-raw-model", "HEPTA_RAW_MODEL", "HEPTA_RAW_MODEL_BUILD"),
                ("dynamic", "core-controls-ndu-dynamic-prerequisite-01", "hia-ndu-dynamic-model", "HEPTA_DYNAMIC_POLICY", "HEPTA_DYNAMIC_POLICY_MANIFEST")]:
            self.ndu_build(profile, self.base / "evidence" / directory, adapter, prefix, key)
        for profile, prefix in [("recursive", "HEPTA_RECURSIVE_NDU"), ("finite", "HEPTA_FINITE_NDU"),
                                ("stream", "HEPTA_NDU_STREAM")]:
            self.ndu_identity(profile, prefix)
        self.boost()
        if clang and self.python and sys.platform == "linux":
            self.env["HEPTA_RUN_ARTIFACT_SESSION"] = "1"
        else:
            self.missing("artifact_session", "PreparedArtifactSession native/solver tests skip.")
        self.env["HEPTA_RAW_MODEL_TRANSCRIPT"] = str(self.out / "raw-model-transcript.jsonl")
        # Do not preserve stale output paths or write into earlier evidence.
        fresh_outputs = {
            "HEPTA_STB_UPDATE_TEST_EVIDENCE": "stb-native",
            "HEPTA_RUST_SCOPED_CLEANUP_EVIDENCE_DIR": "rust-scoped-cleanup",
            "HEPTA_RUST_FINITE_HEAP_EVIDENCE_DIR": "rust-finite-heap",
            "HEPTA_BORROWED_EXTENT_EVIDENCE_DIR": "borrowed-extent",
            "HEPTA_FINITE_V8_EVIDENCE_DIR": "finite-v8",
            "HEPTA_FILECHECK_TARGET_EVIDENCE": "filecheck-target",
        }
        for key, name in fresh_outputs.items():
            self.env[key] = str(self.out / name)
        # Explicit private argv-name aliases are needed by tests using which("clang").
        aliases = self.out / "bin"
        aliases.mkdir(mode=0o700)
        for name, value in [("clang", clang), ("clang++", self.env.get("CLANGXX")),
                            ("ld.lld", self.env.get("HEPTA_LLD")), ("cargo", cargo),
                            ("rustc", rustc), ("lean", lean)]:
            if value:
                (aliases / name).symlink_to(value)
        self.env["PATH"] = os.pathsep.join(dict.fromkeys([
            str(aliases), *(self.paths), "/usr/local/bin", "/usr/bin", "/bin"]))
        self.references()
        usage = shutil.disk_usage(self.out)
        fs = os.statvfs(self.out)
        self.report["storage"] = {"free_bytes": usage.free, "free_inodes": fs.f_favail,
                                  "suggested_full_suite_minimum_bytes": 8 << 30}
        if usage.free < (8 << 30) or fs.f_favail < 100000:
            self.missing("storage", "Full retained suite has insufficient observed disk/inode reserve.")
        self.report["limits"] = [
            "Preparation is current prerequisite observation, not a test or delivery PASS.",
            "Old receipt files are rehashed, not recreated or relabelled as this run's results.",
            "Cargo is offline; cached crate completeness is established only by subsequent actual builds.",
            "No existing qualification jobs, services, production state, or system packages are changed.",
            "The parent runner must still enforce current source/cold identity and zero skipped/expected-failure tests.",
        ]

    def save(self):
        configured_names = set(self.env) | self.tool_variables
        configured_names.update({"LEAN", "CLANG", "CLANGXX", "RUSTC", "HEPTA_CLANG",
                                 "HEPTA_TEST_CLANG", "HEPTA_NATIVE_CLANG", "HIA_TEST_CLANG20",
                                 "HIA_KERNEL_CLANG", "HIA_KERNEL_OBJDUMP", "HEPTA_LLD",
                                 "HEPTA_PROFDATA", "HEPTA_LLVM_READOBJ", "HEPTA_QEMU_X86_64",
                                 "HEPTA_QEMU_AARCH64", "HEPTA_QEMU_RISCV64", "HEPTA_RUSTC",
                                 "HIA_TEST_SOURCE_RUSTC", "CPLUS_INCLUDE_PATH", "HEPTA_RUN_ARTIFACT_SESSION"})
        environment = {"schema": "hepta.hia.qualification-environment.v1",
                       "source": str(self.source), "python": self.python,
                       "set": self.env, "unset": sorted(DROP_NAMES | configured_names),
                       "unset_prefixes": list(DROP_PREFIXES),
                       "recheck_sha256": self.bindings}
        self.report.update(status="READY" if not self.report["missing"] else "HOLD",
                           python=self.python, environment_file=str(self.out / "environment.json"),
                           ended_unix_ns=time.time_ns())
        for name, value in [("environment.json", environment), ("preparation.json", self.report)]:
            with (self.out / name).open("x") as stream:
                json.dump(value, stream, sort_keys=True, indent=2)
                stream.write("\n")
        (self.out / "launch.py").write_text(LAUNCHER)
        (self.out / "launch.py").chmod(0o700)
        print(json.dumps({"status": self.report["status"], "python": self.python,
                          "report": str(self.out / "preparation.json"),
                          "missing": self.report["missing"]}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prereq-root", type=Path, default=Path(DEFAULT_PREREQUISITES))
    parser.add_argument("--python", type=Path, help="existing user-owned pinned venv interpreter")
    parser.add_argument("--candidate-environment", type=Path, help="untrusted candidate paths; all are rechecked")
    parser.add_argument("--install-python-deps", action="store_true",
                        help="only if needed, create a new venv under output and install pinned user packages")
    parser.add_argument("--wheelhouse", type=Path, help="existing offline wheel directory for a new venv")
    args = parser.parse_args()
    os.umask(0o077)
    preparation = Preparation(args)
    try:
        preparation.run()
    except Exception as error:
        preparation.report["unexpected_error"] = repr(error)
        preparation.missing("preparation_interrupted", "Preparation incomplete; no qualification PASS may be inferred.")
    finally:
        preparation.save()
    return 0 if preparation.report["status"] == "READY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
