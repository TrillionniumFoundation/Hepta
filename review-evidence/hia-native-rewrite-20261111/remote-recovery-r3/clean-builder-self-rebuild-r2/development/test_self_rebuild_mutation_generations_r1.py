"""Each changed-source generation has the unchanged full 90 CPU/150 wall gate.

The first runs the existing builder on changed HIA source.  The second runs
only the actual builder produced by that first native invocation and requires
complete package equality.  Neither generation calls a host compiler.
"""
from pathlib import Path
import argparse
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from self_rebuild_test_common import Gate, digest, identity, unpack

parser = argparse.ArgumentParser()
parser.add_argument("--generation", required=True, choices=("first", "second"))
args = parser.parse_args()
MUTATION = ROOT / "development/self-rebuild-mutation-r2"
BUILD = ROOT / "development/build-self-rebuild-r2"
FIRST = ROOT / "development/self-rebuild-mutation-generation1-r1"
OUT = FIRST if args.generation == "first" else ROOT / "development/self-rebuild-mutation-generation2-r1"
KIT = MUTATION / "source-kit.hiabuild"
EXE = BUILD / "hia-build-self-rebuilding" if args.generation == "first" else FIRST / "package-files/hia-build"
BASE_PACKAGE = ROOT / "development/self-rebuild-generation1-r2/calls/generation1/stdout.raw"
sources = [Path(__file__), ROOT / "self_rebuild_test_common.py", KIT, EXE, BASE_PACKAGE,
           MUTATION / "mutation.json", MUTATION / "evidence/summary.json", MUTATION / "evidence/post-output-budget.json",
           MUTATION / "mutated-clean-build-driver.image.bin", MUTATION / "clean_build_driver.hiaasm",
           MUTATION / "clean_build_self_rebuild.py", MUTATION / "independent-mutated-builder",
           BUILD / "agent-data-json.image.bin"]
if args.generation == "second":
    sources += [FIRST / "summary.json", FIRST / "post-output-budget.json", FIRST / "calls/mutated-generation/stdout.raw"]
gate = Gate(OUT, sources, "LOCAL_ACTUAL_OWN_SOURCE_CHANGE_GENERATION_" + args.generation.upper() + "_NOT_COLD")
try:
    assert json.loads((MUTATION / "evidence/summary.json").read_bytes())["status"] == "PASS"
    usage = json.loads((MUTATION / "evidence/post-output-budget.json").read_bytes())
    assert usage["status"] == "PASS" and usage["usage"]["aggregate_cpu_seconds"] < 90 and usage["usage"]["elapsed_ns"] < 150000000000
    proof = json.loads((MUTATION / "mutation.json").read_bytes())
    assert proof["old_base_bytes_unchanged"] and proof["cold_and_original_seven_recipes_unchanged"]
    if args.generation == "second":
        assert json.loads((FIRST / "summary.json").read_bytes())["status"] == "PASS"
        first_usage = json.loads((FIRST / "post-output-budget.json").read_bytes())
        assert first_usage["status"] == "PASS" and first_usage["usage"]["aggregate_cpu_seconds"] < 90 and first_usage["usage"]["elapsed_ns"] < 150000000000
    record, raw, terminal = gate.run("mutated-generation", EXE, [digest(KIT.read_bytes())], input_path=KIT, wall=150)
    assert len(terminal) == 128 and terminal[96:128] == hashlib.sha256(raw).digest()
    event = struct.unpack("<16Q", terminal)
    assert event[0] == int.from_bytes(b"HIABBE01", "little") and event[1] == 0 and event[4] == len(raw)
    files = unpack(raw)
    baseline = unpack(BASE_PACKAGE.read_bytes())
    for name in ("hia", "hia-release", "compiler.bin"): assert files[name] == baseline[name]
    assert files["source-kit.hiabuild"] == (0o400, KIT.read_bytes())
    expected_builder = (MUTATION / "independent-mutated-builder").read_bytes()
    assert files["hia-build"] == (0o500, expected_builder)
    assert expected_builder != (BUILD / "hia-build-self-rebuilding").read_bytes()
    report = json.loads(files["build.json"][1])
    expected = json.loads(baseline["build.json"][1])
    changed_image = (MUTATION / "mutated-clean-build-driver.image.bin").read_bytes()
    decoder = (BUILD / "agent-data-json.image.bin").read_bytes()
    frame = struct.pack("<4Q", int.from_bytes(b"HIABPK01", "little"), len(changed_image), len(decoder), 0) + changed_image + decoder
    expected["kit_sha256"] = digest(KIT.read_bytes())
    expected["builder_sha256"] = digest(expected_builder)
    expected["images"][9] = {"input_sha256": digest((MUTATION / "clean_build_driver.hiaasm").read_bytes()),
                              "image_sha256": digest(changed_image), "image_bytes": len(changed_image)}
    expected["images"][12] = {"input_sha256": digest(frame), "image_sha256": digest(expected_builder), "image_bytes": len(expected_builder)}
    assert report == expected
    assert files["hia-build"][1] != EXE.read_bytes() if args.generation == "first" else files["hia-build"][1] == EXE.read_bytes()
    if args.generation == "second":
        assert raw == (FIRST / "calls/mutated-generation/stdout.raw").read_bytes()
    destination = gate.out / "package-files"
    destination.mkdir()
    for name, (mode, data) in files.items():
        path = destination / name
        path.write_bytes(data)
        path.chmod(mode)
    gate.summary.update(status="PASS", actual_changed_hia_source_compiled=True,
                        first_builder_was_not_copied=(args.generation == "first"),
                        complete_second_generation_fixed_point=(args.generation == "second"),
                        complete_original_recipe_products_equal=True, full_13_row_receipt_equal=True,
                        package_bytes=len(raw), package_sha256=digest(raw), builder_sha256=digest(expected_builder),
                        actual_invoked_builder_sha256=identity(EXE)["sha256"])
except BaseException as exc:
    gate.fail(exc)
finally:
    gate.finish()
