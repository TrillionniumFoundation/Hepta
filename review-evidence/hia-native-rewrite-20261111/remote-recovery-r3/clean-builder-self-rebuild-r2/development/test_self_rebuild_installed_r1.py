"""Actual installation and complete installed second-generation fixed point."""
from pathlib import Path
import hashlib
import json
import stat
import struct
import sys

ROOT = Path(__file__).resolve().parent
ORIGINAL = ROOT / "original-r13"
REFERENCE = ROOT / "reference-kit-r13"
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT), str(REFERENCE)]
from self_rebuild_test_common import Gate, identity, digest, unpack

PACKAGE = ROOT / "development/self-rebuild-generation1-r1/package.raw"
BUILDER = ROOT / "development/build-self-rebuild-r1/hia-build-self-rebuilding"
sources = [Path(__file__), ROOT / "self_rebuild_test_common.py", PACKAGE, BUILDER,
           ORIGINAL / "development/native-whole-r2/package.raw",
           ROOT / "development/self-rebuild-generation1-r1/summary.json",
           ROOT / "development/self-rebuild-generation1-r1/post-output-budget.json"]
gate = Gate(ROOT / "development/self-rebuild-installed-generation2-r1", sources,
            "LOCAL_ACTUAL_INSTALL_AND_SECOND_GENERATION_FULL_FIXED_POINT_NOT_COLD")
try:
    assert json.loads(sources[-2].read_bytes())["status"] == "PASS"
    prior_usage = json.loads(sources[-1].read_bytes())
    assert prior_usage["aggregate_cpu_seconds"] < 90 and prior_usage["elapsed_ns"] < 150000000000
    raw = PACKAGE.read_bytes()
    files = unpack(raw)
    original_files = unpack(sources[4].read_bytes())
    for name in ("hia", "hia-release", "compiler.bin"):
        assert files[name] == original_files[name]
    bootstrap = gate.out / "bootstrap-hia-release"
    bootstrap.write_bytes(files["hia-release"][1])
    bootstrap.chmod(0o700)
    target = gate.out / "releases"
    target.mkdir(mode=0o700)
    package_sha = digest(raw)
    installed = target / package_sha
    _, output, _ = gate.run("install", bootstrap, ["install", str(target), package_sha], input_path=PACKAGE, wall=40)
    assert json.loads(output) == {"schema": "hepta.hia.release-install.v1", "sha256": package_sha,
                                  "files": 6, "bytes": len(raw), "published": True}
    before_inode = installed.stat().st_ino
    assert stat.S_IMODE(installed.stat().st_mode) == 0o500
    assert sorted(p.name for p in target.iterdir()) == [package_sha]
    installed_before = {}
    for name, (mode, data) in files.items():
        path = installed / name
        st = path.lstat()
        assert stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and stat.S_IMODE(st.st_mode) == mode
        assert path.read_bytes() == data
        installed_before[name] = {**identity(path), "inode": st.st_ino}
    gate.summary["installed_inventory"] = installed_before
    gate.run("install-no-replace", bootstrap, ["install", str(target), package_sha], input_path=PACKAGE, expected=14, wall=40)
    assert installed.stat().st_ino == before_inode
    _, output, _ = gate.run("installed-verify", installed / "hia-release", ["verify", str(target), package_sha], input_path=PACKAGE, wall=40)
    assert json.loads(output) == {"schema": "hepta.hia.release-install.v1", "sha256": package_sha,
                                  "files": 6, "bytes": len(raw), "published": False}
    # The failed no-replace stage is retained, fully checked, and not deleted.
    stages = [p for p in target.iterdir() if p.name != package_sha]
    assert len(stages) == 1 and stages[0].name.startswith(".hia-stage-")
    for path in stages:
        assert stat.S_IMODE(path.stat().st_mode) == 0o500
        assert sorted(p.name for p in path.iterdir()) == sorted(files)
        for name, (mode, data) in files.items():
            child = path / name
            assert child.read_bytes() == data and stat.S_IMODE(child.stat().st_mode) == mode and child.stat().st_nlink == 1
    gate.summary["retained_no_replace_stage"] = str(stages[0])
    # Use exact previously recorded oracle inputs and outputs from all original
    # eleven public stdio cases; run each newly installed command afresh.
    previous = ORIGINAL / "development/installed-chain-r3"
    labels = ("capabilities", "verify", "compile", "render", "assemble", "empty-argv", "bad-argv",
              "bad-json-verify", "bad-json-compile", "bad-json-render", "bad-asm")
    products = {}
    for label in labels:
        folder = previous / ("old-stdio-" + label)
        request = json.loads((folder / "request.json").read_bytes())
        source = (folder / "input.raw").read_bytes()
        assert digest(source) == request["input_sha256"] and len(source) == request["input_bytes"]
        expected = json.loads((folder / "result.json").read_bytes())
        expected_out = (folder / "stdout.raw").read_bytes()
        expected_err = (folder / "stderr.raw").read_bytes()
        assert digest(expected_out) == expected["stdout_sha256"] and digest(expected_err) == expected["stderr_sha256"]
        record, actual_out, actual_err = gate.run("installed-stdio-" + label, installed / "hia", request["argv"], raw=source, expected=None, wall=20)
        assert (record["returncode"], actual_out, actual_err) == (expected["returncode"], expected_out, expected_err), label
        products[label] = actual_out
    assert products["compile"] == products["assemble"]
    gate.summary["fresh_complete_stdio_cases"] = len(labels)
    kit = installed / "source-kit.hiabuild"
    record, rebuilt, terminal = gate.run("installed-builder-generation2", installed / "hia-build", [digest(kit.read_bytes())], input_path=kit, wall=150)
    assert len(terminal) == 128 and terminal[96:128] == hashlib.sha256(rebuilt).digest()
    event = struct.unpack("<16Q", terminal)
    assert event[0] == int.from_bytes(b"HIABBE01", "little") and event[1] == 0 and event[4] == len(rebuilt)
    assert rebuilt == raw
    for name, prior in installed_before.items():
        path = installed / name
        assert {**identity(path), "inode": path.stat().st_ino} == prior
    gate.summary.update(status="PASS", installed_complete_second_generation_package_equal=True,
                        package_bytes=len(raw), package_sha256=package_sha,
                        generated_hia_build_used=True, original_builder_retained_copy_used=False,
                        actual_install_no_replace_and_verify_calls=3)
except BaseException as exc:
    gate.fail(exc)
finally:
    gate.finish()
