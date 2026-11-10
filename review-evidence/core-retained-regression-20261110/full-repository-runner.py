"""Exact-source full-repository invocation with real prerequisite identities."""
from pathlib import Path
import hashlib
import json
import os
import resource
import subprocess
import sys

BASE = Path(__file__).resolve().parents[1]
EVIDENCE = BASE / "evidence"
ROOT = Path('/home/qian-qi/.openclaw/workspaces/azi5/tasks/hia-selfhost-completion-20261109/agent-core-retained-regression-full-qualification')
PYTHON = BASE / "venv/bin/python"
RUST = BASE / "toolchains-rustup/toolchains/1.90.0-x86_64-unknown-linux-gnu/bin"
LEAN = BASE / "verification-tools/lean-4.19.0/bin/lean"
EXPECTED = '17bb8c49ec9f259dfd0e1c76ee02b826e508ebef'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_build(name):
    directory = EVIDENCE / name
    receipt = directory / "build-receipt.json"
    row = json.loads(receipt.read_bytes())
    binary = Path(row["binary"])
    if digest(binary) != row["binary_sha256"]:
        raise ValueError("built prerequisite no longer matches receipt: " + name)
    return directory, binary, receipt


def main():
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() != EXPECTED:
        raise ValueError("wrong qualification source")
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT):
        raise ValueError("qualification source is not clean")
    original, rank_binary, rank_receipt = read_build("core-controls-ndu-original-prerequisite-01")
    raw, raw_binary, raw_receipt = read_build("core-retained-ndu-raw-model-prerequisite-01")
    dynamic, dynamic_binary, dynamic_receipt = read_build("core-controls-ndu-dynamic-prerequisite-01")
    # Refuse a same-filename generic adapter: exact raw-model source inventory is mandatory.
    raw_identity = json.loads(raw_receipt.read_bytes())
    adapter = ROOT / 'rust/hia-ndu-raw-model'
    expected_adapter = {p.relative_to(adapter).as_posix(): digest(p)
                        for p in sorted(adapter.rglob('*')) if p.is_file()}
    if raw_identity['adapter_files'] != expected_adapter:
        raise ValueError('raw-model prerequisite has the wrong source adapter identity')
    settings = {
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": "/var/tmp/hia-core-full-04",
        "CLANG": "/usr/bin/clang-20", "CLANGXX": "/usr/bin/clang++-20",
        "HEPTA_CLANG": "/usr/bin/clang-20", "HEPTA_NATIVE_CLANG": "/usr/bin/clang-20",
        "HEPTA_TEST_CLANG": "/usr/bin/clang-20", "HIA_TEST_CLANG20": "/usr/bin/clang-20",
        "HIA_KERNEL_CLANG": "/usr/bin/clang-20",
        "HIA_KERNEL_OBJDUMP": "/usr/lib/llvm-20/bin/llvm-objdump",
        "CC": "/usr/bin/gcc", "HEPTA_STB_GCC": "/usr/bin/gcc",
        "RUSTC": str(RUST / "rustc"), "HEPTA_RUSTC": str(RUST / "rustc"),
        "HIA_TEST_SOURCE_RUSTC": str(RUST / "rustc"),
        "LEAN": str(LEAN), "HEPTA_LLD": "/usr/lib/llvm-20/bin/ld.lld",
        "HEPTA_PROFDATA": "/usr/lib/llvm-20/bin/llvm-profdata",
        "HEPTA_LLVM_READOBJ": "/usr/lib/llvm-20/bin/llvm-readobj",
        "HEPTA_QEMU_X86_64": "/usr/bin/qemu-x86_64",
        "HEPTA_QEMU_AARCH64": str(BASE / "verification-tools/qemu-8.2.2/qemu-aarch64-static"),
        "CPLUS_INCLUDE_PATH": str(BASE / "toolchains-boost183/usr/include"),
        "HEPTA_QEMU_RISCV64": "/usr/bin/qemu-riscv64",
        "HEPTA_RUN_ARTIFACT_SESSION": "1",
        "HEPTA_STB_UPDATE_TEST_EVIDENCE": str(EVIDENCE / 'agent-core-retained-regression-stb-native-repository'),
        "HEPTA_NDU_BRIDGE": str(rank_binary), "HEPTA_NDU_BUILD": str(original),
        "HEPTA_NDU_UPSTREAM": str(BASE / "ndu-upstream"),
        "HEPTA_RAW_MODEL_BRIDGE": str(raw_binary), "HEPTA_RAW_MODEL_BUILD": str(raw_receipt),
        "HEPTA_DYNAMIC_POLICY_BINARY": str(dynamic_binary),
        "HEPTA_DYNAMIC_POLICY_MANIFEST": str(dynamic_receipt),
    }
    receipts = [rank_receipt, raw_receipt, dynamic_receipt]
    cold=Path("/var/tmp/hia-ci6/core-installed-cold.json")
    accepted=json.loads(cold.read_bytes())
    assert accepted["status"]=="COLD_SELFHOST_REPLAY_PASS" and all(accepted["checks"].values())
    qualification=json.loads((EVIDENCE/"agent-core-retained-regression-final-qualification-05.json").read_bytes())
    assert qualification["status"]=="PASS" and qualification["source_commit"]==EXPECTED
    receipts.extend([cold,EVIDENCE/"agent-core-retained-regression-final-qualification-05.json"])
    for profile, prefix in (("recursive", "HEPTA_RECURSIVE_NDU"),
                            ("finite", "HEPTA_FINITE_NDU"), ("stream", "HEPTA_NDU_STREAM")):
        folder = EVIDENCE / ("ndu-" + profile + "-build-01")
        identity = folder / "identity.json"
        binary = folder / "native/hepta-hia-ndu-bridge"
        row = json.loads(identity.read_bytes())
        if digest(binary) != row["compiled_binary_sha256"]:
            raise ValueError("native profile differs from identity: " + profile)
        settings[prefix + "_BRIDGE"] = str(binary)
        settings[prefix + "_IDENTITY"] = str(identity)
        receipts.append(identity)
    qemu = BASE / "verification-tools/qemu-8.2.2/qemu-aarch64-static"
    if digest(qemu) != "e4f8d99e9ff69c3cefffab71cee358ce2af1ecba1282d04c3eeb44ef76f5a71e":
        raise ValueError("wrong locked QEMU")
    boost = EVIDENCE / "qualification-boost183-01.json"
    boost_package = BASE / "toolchains-boost183" / json.loads(boost.read_bytes())["package"]
    if digest(boost_package) != json.loads(boost.read_bytes())["sha256"]:
        raise ValueError("Boost package differs from dependency receipt")
    receipts.append(boost)
    environment = {k:v for k,v in os.environ.items() if not k.startswith("HEPTA_HIA_") and k not in {"PYTHONPATH","PYTHONHOME"}}
    environment.update(settings)
    environment["HEPTA_HIA_AGENT_STDIO_COLD_REPORT"]="/var/tmp/hia-ci6/core-installed-cold.json"
    for selection in ('HEPTA_HIA_JSON_PREFLIGHT_MANIFEST', 'HEPTA_HIA_JSON_DECODE_MANIFEST', 'HEPTA_HIA_JSON_CANONICAL_MANIFEST','HEPTA_HIA_SHA256_MANIFEST','HEPTA_HIA_SOURCE_LEXER_MANIFEST','HEPTA_HIA_TYPE_PARSER_MANIFEST','HEPTA_HIA_SOURCE_PARSER_MANIFEST','HEPTA_HIA_SOURCE_EFFECTS_MANIFEST'):
        environment.pop(selection, None)
    environment["PATH"] = os.pathsep.join([str(BASE / "verification-tools/bin"), str(RUST), "/usr/lib/llvm-20/bin",
        str(LEAN.parent), str(PYTHON.parent), "/usr/local/bin", "/usr/bin", "/bin"])
    import shutil
    assert shutil.disk_usage("/var/tmp").free>=8<<30 and os.statvfs("/var/tmp").f_favail>=100000
    Path(settings["TMPDIR"]).mkdir(mode=0o700)
    probe = subprocess.check_output([str(PYTHON),'-B','-c','import tempfile; print(tempfile.gettempdir())'],env=environment,text=True).strip()
    if probe != settings['TMPDIR']:raise ValueError('tempfile silently fell back from declared full-run directory')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    command = [str(PYTHON), "-B", str(EVIDENCE / "qualify_agent_core_retained_regression_all_tests_04.py"), "--repository-wide",
               "--output", str(EVIDENCE / "agent-core-retained-regression-all-repository-tests-04.json")]
    with (EVIDENCE / "agent-core-retained-regression-all-repository-tests-04.request.json").open("x") as stream:
        json.dump({"source_head": EXPECTED, "command": command, "cwd": str(ROOT),
                   "selected_environment": settings,
                   "passive_read_only_failure_artifact_watch": True,
                   "prerequisite_receipts": {str(p): digest(p) for p in receipts},
                   "scope": "all repository unittest modules; no skipped tests counted as passes"},
                  stream, sort_keys=True, indent=2)
    with (EVIDENCE / "agent-core-retained-regression-all-repository-tests-04.log").open("x") as output:
        child = subprocess.Popen(command, cwd=ROOT, env=environment,
                                 stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT)
        retained = set()
        watch = EVIDENCE / 'agent-core-retained-regression-stb-failure-watch-repository'
        watch.mkdir(mode=0o700)
        cold_watch=EVIDENCE/'agent-core-retained-regression-cold-failure-watch-full-04'
        cold_watch.mkdir(mode=0o700)
        while True:
            # Preserve actual small diagnostics before temporary-test cleanup;
            # observation only, no wrapping, retries or result alterations.
            for cold_dir in Path(settings["TMPDIR"]).glob('hia-cold-replay-test-*/cold.cold'):
                for relative in ('request.json','process-owner.json','stdout.log','stderr.log',
                                 'qualification.json','qualification.evidence/phase-index.json'):
                    try:data=(cold_dir/relative).read_bytes()
                    except OSError:continue
                    if not data or len(data)>8388608:continue
                    identity=hashlib.sha256(data).hexdigest()
                    target=cold_watch/(cold_dir.parent.name+'-'+relative.replace('/','_')+'-'+identity)
                    if not target.exists():
                        with target.open('xb') as stream:stream.write(data)
            # Read-only collection of an already-failed migration, before the
            # unittest's TemporaryDirectory is finalized. No test is wrapped,
            # skipped, retried or monkeypatched; its result remains original.
            for path in Path(settings["TMPDIR"]).glob("hia-stb-native-*/capture/MIGRATION.json"):
                try:
                    data = path.read_bytes()
                    record = json.loads(data)
                except (OSError, ValueError):
                    continue
                if record.get("ok") is not False:
                    continue
                identity = hashlib.sha256(data).hexdigest()
                if identity not in retained:
                    with (watch / (identity + ".json")).open("xb") as stream:
                        stream.write(data)
                    retained.add(identity)
            try:
                returncode = child.wait(timeout=1)
                break
            except subprocess.TimeoutExpired:
                pass
        (watch / "watch-result.json").write_text(json.dumps({
            "passive_read_only_failure_collection": True,
            "source_commit": EXPECTED, "failed_migration_sha256": sorted(retained),
            "test_process_returncode": returncode, "tests_or_outcomes_modified": False,
        }, sort_keys=True, indent=2) + "\n")
    return returncode


if __name__ == "__main__":
    sys.exit(main())
