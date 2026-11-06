#!/usr/bin/env python3
"""Run real LLVM20/HIA wrapper import/replay smoke tests in isolated directories."""
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
import urllib.request

FIXTURES = {
    "wrapper_config.h": "36bf1040efca28efea0bc851acd5a26036193212",
    "wrapper_main.c": "6b4a61b549b8e693c8704267b661ca83a14092d5",
    "wrapper_machine.S": "c070b0656e6f1634041c5617b2b7edd7f4a42536",
    "wrapper_raw.s": "87b836847e19bf0fb3866caf6c9eea2b4db3beed",
    "wrapper_offsets.c": "85ed23a59ed9518141d979a82bdbcd058b9ba72c",
    "wrapper_host.cpp": "6ed31f9a653febc3b07470097e46fa6dbce8f4ae",
    "asm_goto.c": "cd3ba1818272002c75adfbe9d44ac6095c97fe84",
}
KERNEL_REF = "f45ed76d6791cf72ff1265ee93511175bbbc2f18"
KERNEL_FILES = {
    "scripts/basic/fixdep.c": "cdd5da7e009b6f3ab18aae649434e65495877afc",
    "scripts/include/xalloc.h": "cdadb07d05922e21242ad5657983be0c12730d9e",
}


def blob(data):
    return hashlib.sha1(("blob " + str(len(data)) + "\0").encode() + data).hexdigest()


def bind(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {"path": str(path), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--codec", type=Path, required=True)
    parser.add_argument("--llvm-bin", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--expected-wrapper-blob", default="9e04d2ec52b7b1296bbd1e4a90417706d87596a9")
    parser.add_argument("--expected-codec-sha256",
                        default="96371a8af0f392514dd12264a446964509631a402099ac75873fa36385b934b7")
    args = parser.parse_args()
    checkout, work = args.checkout.resolve(), args.work_dir.resolve()
    work.mkdir(parents=True, exist_ok=False)
    source = work / "source"
    source.mkdir()
    logs = work / "logs"
    logs.mkdir()
    report = {"schema": "hepta.hia.native-wrapper-smoke.v1", "status": "RUNNING",
              "source_commit": args.source_commit, "kernel_ref": KERNEL_REF,
              "commands": [], "checks": [], "source_files": {}}
    report_path = work / "report.json"

    def save():
        report_path.write_text(json.dumps(report, indent=2) + "\n")

    def require(value, message):
        if not value:
            raise RuntimeError(message)

    def checked(name, **details):
        report["checks"].append({"name": name, "status": "PASS", **details})
        save()

    environment = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(checkout))

    def run(name, command, cwd, *, env=None, stdin=None, expected=0):
        index = len(report["commands"])
        out, err = logs / f"{index:03d}-{name}.stdout", logs / f"{index:03d}-{name}.stderr"
        start = time.monotonic_ns()
        with out.open("xb") as stdout, err.open("xb") as stderr:
            process = subprocess.run([str(item) for item in command], cwd=cwd,
                                     env=env or environment, input=stdin, stdout=stdout,
                                     stderr=stderr, timeout=180, check=False)
        receipt = {"name": name, "argv": [str(item) for item in command], "cwd": str(cwd),
                   "exit_code": process.returncode, "wall_ns": time.monotonic_ns() - start,
                   "stdout": bind(out), "stderr": bind(err)}
        report["commands"].append(receipt)
        save()
        ok = process.returncode != 0 if expected == "nonzero" else process.returncode == expected
        require(ok, f"{name}: exit {process.returncode}, expected {expected}; "
                    f"{err.read_text(errors='replace')[-5000:]}")
        return receipt

    try:
        wrapper_path = checkout / "hepta/hia_system.py"
        require(blob(wrapper_path.read_bytes()) == args.expected_wrapper_blob, "wrapper Git blob mismatch")
        report["wrapper"] = {**bind(wrapper_path), "git_blob": args.expected_wrapper_blob}
        report["test_script"] = {**bind(__file__), "git_blob": blob(Path(__file__).read_bytes())}
        tools = {name: bind(path) for name, path in {
            "clang": args.llvm_bin / "clang", "clangxx": args.llvm_bin / "clang++",
            "llvm_dis": args.llvm_bin / "llvm-dis", "codec": args.codec}.items()}
        require(tools["codec"]["sha256"] == args.expected_codec_sha256, "qualified codec changed")
        report["tools"] = tools
        version = run("llvm-version", [tools["clang"]["path"], "--version"], work)
        require("20.1.8" in Path(version["stdout"]["path"]).read_text(), "LLVM version is not pinned")
        for name, expected in FIXTURES.items():
            original = checkout / "tools/hia_system/tests/fixtures" / name
            data = original.read_bytes()
            require(blob(data) == expected, "fixture Git blob mismatch: " + name)
            (source / name).write_bytes(data)
            report["source_files"][name] = {**bind(source / name), "git_blob": expected}
        for name, expected in KERNEL_FILES.items():
            url = f"https://raw.githubusercontent.com/gregkh/linux/{KERNEL_REF}/{name}"
            data = urllib.request.urlopen(url, timeout=90).read()
            require(blob(data) == expected, "kernel helper Git blob mismatch: " + name)
            path = source / Path(name).name
            path.write_bytes(data)
            report["source_files"][path.name] = {**bind(path), "git_blob": expected, "url": url}

        baseline, imported, replayed = [work / name for name in ("baseline", "imported", "replayed")]
        for directory in (baseline, imported, replayed):
            (directory / "data").mkdir(parents=True)
            for name, data in {"payload.bin": bytes([7, 8, 9]),
                               "module.bin": bytes([8, 1]), "inline.bin": bytes([9, 2])}.items():
                (directory / "data" / name).write_bytes(data)
        program_root = work / "programs"
        manifests, environments = {}, {}
        for mode, directory in (("import", imported), ("replay", replayed)):
            ledger = work / (mode + "-ledger")
            ledger.mkdir()
            manifest = {"schema": "hepta.hia.system-build-environment.v1", "mode": mode,
                        "source_commit": args.source_commit, "source_root": str(source),
                        "build_root": str(directory), "program_root": str(program_root),
                        "ledger_root": str(ledger), "tools": tools}
            path = work / (mode + "-manifest.json")
            path.write_text(json.dumps(manifest, indent=2) + "\n")
            manifests[mode] = manifest
            environments[mode] = dict(environment, HIA_SYSTEM_MANIFEST=str(path))
        cc = [sys.executable, checkout / "tools/hia_system_cc.py"]
        host_cc = [sys.executable, checkout / "tools/hia_system_host_cc.py"]
        host_cxx = [sys.executable, checkout / "tools/hia_system_host_cxx.py"]
        common = ["-O2", "-g0", "-std=gnu11", "-ffreestanding", "-fno-builtin",
                  "-fno-stack-protector", "-fno-pie", "-I", str(source)]
        cases = [
            ("ordinary", [*common, "-Wp,-MMD,ordinary.d", "-c",
                          str(source / "wrapper_main.c"), "-o", "ordinary.o"]),
            ("asm-goto", [*common, "-Wp,-MD,asm_goto.d", "-c",
                          str(source / "asm_goto.c"), "-o", "asm_goto.o"]),
            ("assembly", ["-I", str(source), "-D__ASSEMBLY__", "-Wp,-MMD,machine.d",
                          "-Wa,--noexecstack", "-c", str(source / "wrapper_machine.S"), "-o", "machine.o"]),
            ("raw-assembly", ["-c", str(source / "wrapper_raw.s"), "-o", "raw.o"]),
            ("offsets", [*common, "-Wp,-MMD,offsets.d", "-fverbose-asm", "-S",
                         str(source / "wrapper_offsets.c"), "-o", "offsets.s"]),
        ]
        for name, argv in cases:
            run("baseline-" + name, [tools["clang"]["path"], *argv], baseline)
        run("baseline-link", [tools["clang"]["path"], "ordinary.o", "asm_goto.o",
                              "machine.o", "raw.o", "-no-pie", "-o", "smoke-native"], baseline)
        run("baseline-run", [baseline / "smoke-native"], baseline)
        checked("ordinary_native_baseline_executes")

        for mode, directory in (("import", imported), ("replay", replayed)):
            env = environments[mode]
            for name, argv in cases:
                run(mode + "-" + name, [*cc, *argv], directory, env=env)
            run(mode + "-object-link", [*cc, "ordinary.o", "asm_goto.o", "machine.o", "raw.o",
                                        "-no-pie", "-o", "smoke-native"], directory, env=env)
            run(mode + "-native-execution", [directory / "smoke-native"], directory, env=env)
            require("->SAMPLE_B 8" in (directory / "offsets.s").read_text(), "offset marker changed")
            for dep, target in (("ordinary.d", "ordinary.o"), ("machine.d", "machine.o"),
                                ("asm_goto.d", "asm_goto.o"), ("offsets.d", "offsets.s")):
                data = (directory / dep).read_text()
                require(data.startswith(target + ":"), "dependency target is not original target: " + data)
                require("frontend.bc" not in data and "frontend.d" not in data,
                        "staging file leaked into dependencies")
            run(mode + "-host-cxx-link", [*host_cxx, "-O2", str(source / "wrapper_host.cpp"),
                                          "-o", "host-cxx"], directory, env=env)
            execution = run(mode + "-host-cxx-run", [directory / "host-cxx"], directory, env=env)
            require(Path(execution["stdout"]["path"]).read_text() == "HIA HOSTCXX\n",
                    "C++ default runtime libraries did not link/execute")
            if mode == "import":
                run("host-build-fixdep", [*host_cc, "-O2", "-I", str(source),
                                         str(source / "fixdep.c"), "-o", "fixdep"], directory, env=env)
            for dep, target in (("ordinary.d", "ordinary.o"), ("machine.d", "machine.o"),
                                ("offsets.d", "offsets.s")):
                result = run(mode + "-fixdep-" + target, [imported / "fixdep", dep, target,
                              "recorded HIA CC command"], directory, env=env)
                content = Path(result["stdout"]["path"]).read_text()
                require("savedcmd_" + target in content, "fixdep did not preserve target")
                require("frontend.bc" not in content, "fixdep consumed staging dependency target")

            receipts = [json.loads(path.read_text()) for path in
                        Path(manifests[mode]["ledger_root"]).glob("*/RESULT.json")]
            payloads = [item for item in receipts if item["role"] == "target_payload"]
            require(len(payloads) == len(cases), "payload count differs from full smoke command list")
            for item in payloads:
                require(item["status"] == "PASS" and item["canonical_roundtrip_equal"],
                        "payload failed canonical roundtrip")
                require(item["fallback_c_compilation"] is False, "native C fallback recorded")
                require(item["pruned_intermediates"], "successful payload retained all bulky staging data")
                require(Path(item["retained_program"]["path"]).is_file(), "retained HIA is missing")
                for artifact in item["pruned_intermediates"]:
                    require(not Path(artifact["path"]).exists(), "staging artifact was not removed")
                if mode == "replay":
                    require(all(command["name"] not in ("clang-c-frontend-only",
                                "clang-assembly-preprocess", "encode-typed-hia")
                                for command in item["commands"]), "replay called a source frontend")
            dependencies = {Path(item["path"]).name for receipt in payloads
                            for item in receipt.get("external_inputs", [])}
            require(dependencies == {"payload.bin", "module.bin", "inline.bin"},
                    "explicit module/inline/standalone assembly dependencies differ")
            checked(mode + "_real_pipeline_executes_and_retains_replay_evidence",
                    payload_count=len(payloads), external_inputs=sorted(dependencies))

        objects = ("ordinary.o", "asm_goto.o", "machine.o", "raw.o", "offsets.s", "smoke-native")
        equality = {}
        for name in objects:
            same = (imported / name).read_bytes() == (replayed / name).read_bytes()
            require(same, "replay changed native output: " + name)
            equality[name] = {"import_replay_equal": same,
                             "baseline_import_equal": (baseline / name).read_bytes() == (imported / name).read_bytes(),
                             "baseline": bind(baseline / name), "import": bind(imported / name),
                             "replay": bind(replayed / name)}
        report["native_outputs"] = equality
        checked("import_and_replay_native_outputs_are_byte_identical",
                baseline_equal_count=sum(item["baseline_import_equal"] for item in equality.values()))

        # Actual negative compiler probes are build feature results, not payload failures.
        (replayed / ".tmp_31761").mkdir()
        run("empty-device-capability", [*cc, "-Werror", "-c", "-xc", "/dev/null",
                                       "-o", ".tmp_31761/tmp"], replayed, env=environments["replay"])
        run("stdin-capability", [*cc, "-Werror", "-c", "-xc", "-"], replayed,
            env=environments["replay"], stdin=b"int capability_probe;\n")
        run("negative-capability", [*cc, "-Werror", "-fnot-a-real-hia-option", "-c",
                                    "-xc", "/dev/null", "-o", "/dev/null"], replayed,
            env=environments["replay"], expected="nonzero")
        run("unregistered-replay", [*cc, *cases[0][1], "-DUNREGISTERED_HIA_KEY=1"],
            replayed, env=environments["replay"], expected="nonzero")
        original_data = (replayed / "data/payload.bin").read_bytes()
        (replayed / "data/payload.bin").write_bytes(b"changed binary payload")
        run("changed-incbin-replay", [*cc, *cases[2][1]], replayed,
            env=environments["replay"], expected="nonzero")
        (replayed / "data/payload.bin").write_bytes(original_data)
        receipts = [json.loads(path.read_text()) for path in
                    Path(manifests["replay"]["ledger_root"]).glob("*/RESULT.json")]
        rejected = [item for item in receipts if item["status"] == "COMPILER_REJECTED"]
        require(len(rejected) == 1 and rejected[0]["payload_failure"] is False,
                "negative feature probe was misclassified as a payload failure")
        failures = [item for item in receipts if item["status"] == "FAIL"]
        require(len(failures) == 2, "missing replay/dependency rejection receipts")
        require(all(not any(command["name"] in ("hia-native-codegen", "clang-c-frontend-only")
                            for command in item["commands"]) for item in failures),
                "rejected replay performed codegen or native C fallback")
        checked("real_replay_rejects_unregistered_programs_and_changed_incbin")
        checked("capability_probes_are_logged_without_payload_failure")
        for name, item in tools.items():
            require(bind(item["path"]) == item, "bound compiler/codec changed: " + name)
        report["status"] = "PASS"
        report["manifests"] = {mode: bind(work / (mode + "-manifest.json")) for mode in manifests}
        save()
        print(json.dumps({"status": "PASS", "commands": len(report["commands"]),
                          "checks": len(report["checks"]), "report": str(report_path)}))
        return 0
    except Exception as error:
        report["status"], report["error"] = "FAIL", str(error)
        save()
        print(str(error), file=sys.stderr)
        print(json.dumps({"status": "FAIL", "report": str(report_path)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
