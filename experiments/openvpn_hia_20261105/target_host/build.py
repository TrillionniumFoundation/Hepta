#!/usr/bin/env python3
"""Build and freeze the exact OpenVPN/HIA experiment on a dedicated Actions VM.

This provisions packages and, only if needed, the pinned official ovpn backport
on a disposable VM. It refuses to run outside GitHub Actions. It is not a local
container escape or a production-host installation tool. Network namespace and
traffic execution belong to run_matrix.py, after this build receipt is complete.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time


HERE = Path(__file__).resolve().parent
EXPERIMENT = HERE.parent
REPO = HERE.parents[2]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task-root", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "Linux":
        parser.error("this provisioning entrypoint requires its dedicated GitHub Actions Linux VM")
    task = args.task_root.resolve()
    work, public = task / "work", task / "public"
    if work.exists() or public.exists():
        parser.error("task root must be new; do not overwrite earlier evidence")
    work.mkdir(parents=True)
    public.mkdir()
    report = {
        "schema": "hepta.openvpn-hia.target-build.v1", "ok": False,
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "commands": [], "runtime_acceptance": False,
        "runner": {key: os.environ.get(key) for key in (
            "GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "RUNNER_OS",
            "RUNNER_ARCH", "ImageOS", "ImageVersion", "HEPTA_EXPECTED_SHA")},
        "kernel": platform.uname()._asdict(),
        "source_lock_sha256": digest(HERE / "source-lock.json"),
    }
    environment = dict(os.environ)
    deadline = time.monotonic() + 900

    def command(label, argv, *, cwd=REPO, timeout=300, required=True):
        argv = list(map(str, argv))
        start = time.monotonic()
        row = {"label": label, "argv": argv, "cwd": str(cwd)}
        remaining = deadline - start
        if remaining <= 0:
            raise TimeoutError("fixed 900-second build budget exhausted")
        timeout = min(timeout, remaining)
        proc = None
        try:
            proc = subprocess.Popen(argv, cwd=cwd, env=environment, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, start_new_session=True)
            row["pid"] = proc.pid
            stdout, stderr = proc.communicate(timeout=timeout)
            code = proc.returncode
        except subprocess.TimeoutExpired as exc:
            row["timeout"] = True
            for sig in (signal.SIGTERM, signal.SIGKILL):
                try:
                    os.killpg(proc.pid, sig)
                except PermissionError:
                    subprocess.run(["sudo", "-n", "/usr/bin/kill", "-" + sig.name.removeprefix("SIG"),
                                    "--", "-" + str(proc.pid)], timeout=5, capture_output=True)
                except ProcessLookupError:
                    pass
                try:
                    stdout, stderr = proc.communicate(timeout=3)
                    break
                except subprocess.TimeoutExpired:
                    continue
            else:
                stdout, stderr = exc.stdout or b"", exc.stderr or b""
                row["process_group_cleanup_failed"] = True
            code = 124
        except OSError as exc:
            stdout, stderr, code = b"", str(exc).encode(), 127
        (public / (label + ".stdout")).write_bytes(stdout)
        (public / (label + ".stderr")).write_bytes(stderr)
        row.update(exit_code=code, elapsed_seconds=time.monotonic() - start,
                   stdout_sha256=hashlib.sha256(stdout).hexdigest(),
                   stderr_sha256=hashlib.sha256(stderr).hexdigest())
        report["commands"].append(row)
        save(public / "build.json", report)
        print(json.dumps({"step": label, "exit_code": code,
                          "elapsed_seconds": row["elapsed_seconds"]}), flush=True)
        if code and required:
            raise RuntimeError(f"{label} failed with exit {code}; original output retained")
        return code, stdout.decode("utf-8", errors="replace")

    def download(label, url, destination, expected):
        command(label, ["curl", "--fail", "--location", "--retry", "2",
                        "--connect-timeout", "15", "--max-time", "120",
                        "--output", destination, url], timeout=390)
        observed = digest(destination)
        if observed != expected:
            raise RuntimeError(f"{label} digest mismatch: {observed}")

    try:
        _, commit = command("source-commit", ["git", "rev-parse", "HEAD"])
        _, tree = command("source-tree", ["git", "rev-parse", "HEAD^{tree}"])
        expected_commit = os.environ.get("HEPTA_EXPECTED_SHA") or os.environ["GITHUB_SHA"]
        report["expected_hepta_commit"] = expected_commit
        if commit.strip() != expected_commit:
            raise RuntimeError("checkout is not the exact expected source commit")
        report.update(hepta_commit=commit.strip(), hepta_tree=tree.strip())
        command("source-clean", ["git", "diff", "--exit-code", "HEAD"])
        command("sudo-available", ["sudo", "-n", "true"])
        command("privileged-capabilities", ["sudo", "-n", "python3", "-c",
            "from pathlib import Path; import re; t=Path('/proc/self/status').read_text(); "
            "c=int(re.search(r'^CapEff:\\s*(\\w+)',t,re.M).group(1),16); "
            "print(t); assert c & (1<<12) and c & (1<<21)"])
        command("apt-update", ["sudo", "-n", "apt-get", "update"], timeout=300)
        packages = ["build-essential", "pkg-config", "libssl-dev", "libcap-ng-dev",
                    "libnl-3-dev", "libnl-genl-3-dev", "libelf-dev", "libedit2",
                    "libxml2", "libz3-4", "libzstd1", "openssl", "iproute2",
                    "iputils-ping", "iperf3", "linux-tools-common", "kmod", "ethtool"]
        command("apt-build-dependencies", ["sudo", "-n", "env",
                "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y",
                "--no-install-recommends", *packages], timeout=480)
        command("apt-perf", ["sudo", "-n", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get",
                "install", "-y", "--no-install-recommends", "linux-tools-" + platform.release()],
                timeout=300, required=False)
        command("tun-module", ["sudo", "-n", "modprobe", "tun"])
        lock = json.loads((HERE / "source-lock.json").read_text())
        llvm = json.loads((EXPERIMENT / "toolchain-lock.json").read_text())
        compiler_root = work / "toolchain"
        compiler_root.mkdir()
        for index, package in enumerate(llvm["llvm_packages"]):
            archive = work / Path(package["Filename"]).name
            download(f"llvm-download-{index}", package["url"], archive, package["SHA256"])
            command(f"llvm-extract-{index}", ["dpkg-deb", "-x", archive, compiler_root])
        compiler = compiler_root / "usr/lib/llvm-20/bin/clang"
        if digest(compiler) != lock["clang_sha256"]:
            raise RuntimeError("Clang executable differs from the frozen compiler")
        environment["LD_LIBRARY_PATH"] = str(compiler_root / "usr/lib/x86_64-linux-gnu")
        environment["CLANG"] = str(compiler)
        command("clang-version", [compiler, "--version"])
        report["compiler_sha256"] = digest(compiler)

        # Do not silently replace an already available kernel implementation.
        module_rc, _ = command("ovpn-kernel-modprobe", ["sudo", "-n", "modprobe", "ovpn"], required=False)
        if module_rc or not Path("/sys/module/ovpn").exists():
            kr = platform.release()
            command("apt-kernel-headers", ["sudo", "-n", "env", "DEBIAN_FRONTEND=noninteractive",
                    "apt-get", "install", "-y", "--no-install-recommends", "linux-headers-" + kr], timeout=480)
            module_archive = work / "ovpn-backports.tar.gz"
            module_lock = lock["ovpn_backports_fallback"]
            download("module-download", module_lock["url"], module_archive, module_lock["archive_sha256"])
            with tarfile.open(module_archive) as tf:
                tf.extractall(work, filter="data")
            module_source = work / ("ovpn-backports-" + module_lock["commit"])
            command("module-build", ["make", "-j2", "KERNEL_SRC=/lib/modules/" + kr + "/build",
                    "KERNEL_CFG=/boot/config-" + kr], cwd=module_source, timeout=480)
            module = module_source / "drivers/net/ovpn/ovpn.ko"
            report["backport_module_sha256"] = digest(module)
            destination = Path("/lib/modules") / kr / "extra/hepta-openvpn-pilot/ovpn.ko"
            command("module-install", ["sudo", "-n", "install", "-D", "-m", "0644", module, destination])
            command("module-depmod", ["sudo", "-n", "depmod", "-a", kr])
            command("module-load", ["sudo", "-n", "modprobe", "ovpn"])
            report["dco_provider"] = "pinned official ovpn-backports source"
        else:
            report["dco_provider"] = "target VM's official kernel ovpn module"
        if not Path("/sys/module/ovpn").exists():
            raise RuntimeError("ovpn module is not visible after successful loading")
        command("module-info", ["modinfo", "ovpn"])
        _, module_path = command("module-path", ["modinfo", "-n", "ovpn"])
        module_file = Path(module_path.strip())
        if module_file.is_file():
            report["loaded_module_file_sha256"] = digest(module_file)
        kernel_config = Path("/boot/config-" + platform.release())
        if kernel_config.exists():
            shutil.copyfile(kernel_config, public / "kernel-config.txt")
            report["kernel_config_sha256"] = digest(kernel_config)
        report["tun_exists_after_provisioning"] = Path("/dev/net/tun").exists()

        archive = work / "openvpn-2.7.8.tar.gz"
        download("openvpn-download", lock["openvpn"]["url"], archive, lock["openvpn"]["archive_sha256"])
        with tarfile.open(archive) as tf:
            tf.extractall(work, filter="data")
        source = work / "openvpn-2.7.8"
        spec = importlib.util.spec_from_file_location("baseline", REPO / "tools/openvpn_hia_baseline.py")
        baseline = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(baseline)
        report["official_source_freeze"] = baseline.source_freeze(source, archive)

        # Keep the downloaded upstream archive pristine. Build every application
        # arm from a separate copy carrying the exact, source-locked P2P fairness
        # patch. This patch changes only the userspace dual-read dispatcher;
        # packet codec/replay oracles continue to use the pristine source above.
        dispatch_lock = lock.get("p2p_fair_dispatch")
        if not isinstance(dispatch_lock, dict):
            raise RuntimeError("pinned P2P fairness patch is absent from source lock")
        if dispatch_lock.get("upstream_commit") != lock["openvpn"]["commit"]:
            raise RuntimeError("P2P fairness patch targets a different OpenVPN commit")
        patch_path = HERE / dispatch_lock["path"]
        patch_sha256 = digest(patch_path)
        if patch_sha256 != dispatch_lock["sha256"]:
            raise RuntimeError("P2P fairness patch differs from source lock")
        build_source = work / "openvpn-2.7.8-p2p-fair-dispatch"
        shutil.copytree(source, build_source)
        command("p2p-fair-dispatch-check", ["git", "apply", "--check", patch_path], cwd=build_source)
        command("p2p-fair-dispatch-apply", ["git", "apply", patch_path], cwd=build_source)

        init_source = (source / "src/openvpn/init.c").read_text()
        reset_pattern = r"void\s+context_clear_2\s*\(\s*struct context \*c\s*\)\s*\{\s*CLEAR\(c->c2\);\s*\}"
        if not re.search(reset_pattern, init_source, re.S):
            raise RuntimeError("context_clear_2 no longer zeroes the context-local fairness state")
        patched_forward = (build_source / "src/openvpn/forward.c").read_text()
        patched_header = (build_source / "src/openvpn/openvpn.h").read_text()
        process_start = patched_forward.index("process_io(struct context *c, struct link_socket *sock)")
        process_io = patched_forward[process_start:]
        if patched_header.count("bool prefer_tun_read;") != 1:
            raise RuntimeError("context-local fairness field is absent or duplicated")
        for required in ("status &= ~SOCKET_READ;", "c->c2.prefer_tun_read = true;",
                         "c->c2.prefer_tun_read = false;"):
            if process_io.count(required) != 1:
                raise RuntimeError("patched process_io is missing a unique fairness operation: " + required)
        ordered = ("if (status & SOCKET_WRITE)", "else if (status & TUN_WRITE)",
                   "else if (status & SOCKET_READ)", "else if (status & TUN_READ)",
                   "else if (status & DCO_READ)")
        positions = [process_io.index(token) for token in ordered]
        if positions != sorted(positions):
            raise RuntimeError("P2P fairness patch changed write or DCO dispatch priority")
        dispatch_receipt = {
            "enabled": True,
            "patch_path": dispatch_lock["path"],
            "patch_sha256": patch_sha256,
            "upstream_commit": lock["openvpn"]["commit"],
            "source_archive_sha256": lock["openvpn"]["archive_sha256"],
            "policy": dispatch_lock["policy"],
            "original_files": {name: digest(source / name) for name in dispatch_lock["files"]},
            "patched_files": {name: digest(build_source / name) for name in dispatch_lock["files"]},
            "context_reset_verified": True,
            "pending_write_priority_preserved": True,
            "dco_read_branch_present": True,
        }
        if any(dispatch_receipt["original_files"][name] == dispatch_receipt["patched_files"][name]
               for name in dispatch_lock["files"]):
            raise RuntimeError("P2P fairness patch did not change every pinned source file")
        report["p2p_fair_dispatch"] = dispatch_receipt
        build = work / "build-c"
        build.mkdir()
        flags = lock["application_cflags"]
        environment["CC"] = str(compiler)
        command("configure", [build_source / "configure", "--disable-lzo", "--disable-lz4",
                "--disable-plugin-auth-pam", "--disable-plugin-down-root", "--disable-unit-tests",
                "CFLAGS=" + flags, "LDFLAGS="], cwd=build, timeout=180)
        command("make", ["make", "-j2"], cwd=build, timeout=480)
        if "#define ENABLE_DCO 1" not in (build / "config.h").read_text():
            raise RuntimeError("official application lacks compiled DCO support")
        c_binary = build / "src/openvpn/openvpn"
        command("c-version", [c_binary, "--version"])
        _, libraries = command("libraries", ["ldd", c_binary])
        report["runtime_libraries"] = {p: digest(p) for p in sorted(set(
            re.findall(r"(?:=>\s*)?(/[^\s()]+)", libraries))) if Path(p).is_file()}
        command("openssl", ["openssl", "version", "-a"])
        command("regressions", [sys.executable, "-B", "-m", "unittest", "-v",
                "tests.test_hia_foreign_buffer_abi", "tests.test_hia_composite_abi",
                "tests.test_hia_program_llvm", "tests.test_hia_source_exports",
                "tests.test_hia_native_command_log"], timeout=180)
        native = public / "native"
        command("native-qualification", [sys.executable, "-B", REPO / "tools/qualify_openvpn_hia.py",
                "--openvpn-source", source, "--openvpn-build", build, "--clang", compiler,
                "--output", native, "--benchmark", "--sanitize"], timeout=180)
        report["sanitizer_note"] = "Inherited native runner disables LeakSanitizer by profile; this does not establish that the new VM lacks leak-scan access. C-side ASan/UBSan and separate HIA guard-page/lifetime checks remain enabled."
        replay = public / "replay"
        command("replay-qualification", [sys.executable, "-B", EXPERIMENT / "run_replay.py",
                "--upstream", source, "--config", build, "--clang", compiler,
                "--hia-object", native / "packet.o", "--hia-receipt", native / "hia-build.json",
                "--output", replay], timeout=180)
        trace = work / "trace.o"
        command("trace-compile", [compiler, "-O3", "-g", "-fPIC", "-std=c11", "-c",
                EXPERIMENT / "openvpn_hia_trace.c", "-o", trace])
        binaries = work / "binaries"
        binaries.mkdir()
        hia, hia_trace = binaries / "openvpn-hia", binaries / "openvpn-hia-trace"
        common_link = ["make", "-f", "Makefile", "-f", EXPERIMENT / "baseline_link.mk", "hia-openvpn",
                       "HIA_OBJECT=" + str(native / "packet.o"), "HIA_ADAPTER=" + str(native / "adapter.o")]
        command("link-hia", [*common_link, "HIA_OUTPUT=" + str(hia)], cwd=build / "src/openvpn")
        command("link-hia-trace", [*common_link, "HIA_OUTPUT=" + str(hia_trace), "HIA_TRACE=" + str(trace)],
                cwd=build / "src/openvpn")
        command("hia-version", [hia, "--version"])
        objects = {p.name: digest(p) for p in sorted((build / "src/openvpn").glob("*.o"))}
        report["link"] = {"official_objects": objects, "official_object_count": len(objects),
            "c_binary_sha256": digest(c_binary), "hia_binary_sha256": digest(hia),
            "hia_trace_binary_sha256": digest(hia_trace), "trace_object_sha256": digest(trace),
            "hia_object_sha256": digest(native / "packet.o"),
            "adapter_object_sha256": digest(native / "adapter.o"),
            "config_h_sha256": digest(build / "config.h"), "application_cflags": flags}
        for name in ("config.h", "config.log"):
            shutil.copyfile(build / name, public / name)
        # Perf is diagnostic only. An unavailable collector is retained, not
        # silently treated as completed production-hotspot identification.
        kr = platform.release()
        candidates = [Path("/usr/lib/linux-tools") / kr / "perf", Path("/usr/bin/perf")]
        candidates += sorted(Path("/usr/lib/linux-tools").glob("*/perf"), reverse=True)
        perf = None
        for i, candidate in enumerate(dict.fromkeys(candidates)):
            if candidate.is_file():
                rc, _ = command("perf-version-" + str(i), [candidate, "--version"], required=False)
                if rc == 0:
                    perf = candidate.resolve()
                    break
        report["perf"] = {"path": str(perf), "sha256": digest(perf)} if perf else None
        run_env = {"c": str(c_binary), "hia": str(hia), "hia_trace": str(hia_trace),
                   "source": str(source), "build_source": str(build_source), "build": str(build),
                   "p2p_fair_dispatch": dispatch_receipt, "perf": str(perf) if perf else None,
                   "ld_library_path": environment["LD_LIBRARY_PATH"], "hepta_commit": commit.strip()}
        save(public / "build-env.json", run_env)
        command("source-clean-after", ["git", "diff", "--exit-code", "HEAD"])
        report["official_source_after"] = baseline.source_freeze(source, archive)
        report["ok"] = True
        return 0
    except Exception as exc:
        report["failure"] = repr(exc)
        print(json.dumps({"build_failed": repr(exc)}), flush=True)
        return 1
    finally:
        report["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        save(public / "build.json", report)


if __name__ == "__main__":
    raise SystemExit(main())
