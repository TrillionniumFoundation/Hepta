"""Full first generation after the exact five-word-helper optimization."""
from pathlib import Path
import hashlib
import json
import struct
import sys

ROOT = Path(__file__).resolve().parent
ORIGINAL = ROOT / "original-r13"
BUILD = ROOT / "development/build-self-rebuild-r2"
KIT_ROOT = ROOT / "development/self-rebuild-kit-r2"
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT))
from self_rebuild_test_common import Gate, digest, identity, unpack

EXE = BUILD / "hia-build-self-rebuilding"
KIT = KIT_ROOT / "source-kit.hiabuild"
MANIFESTS = {label: BUILD / (label + ".manifest.json") for label in ("clean-build-driver", "agent-data-json", "clean-build-packer")}
sources = [Path(__file__), ROOT / "self_rebuild_test_common.py", EXE, KIT, KIT_ROOT / "manifest.json",
           ORIGINAL / "development/native-whole-r2/package.raw", ORIGINAL / "development/native-whole-r2/summary.json",
           ROOT / "development/self-rebuild-word-pairs-r1/summary.json", ROOT / "development/self-rebuild-word-pairs-r1/post-output-budget.json"]
sources += [Path(row["original_path"]) for row in json.loads((KIT_ROOT / "manifest.json").read_bytes())["own_sources"]]
for path in MANIFESTS.values():
    value = json.loads(path.read_bytes())
    sources += [path, Path(value["source_path"]), Path(value["image_path"])]
gate = Gate(ROOT / "development/self-rebuild-generation1-r2", sources,
            "LOCAL_OPTIMIZED_ACTUAL_COMPLETE_NATIVE_SELF_BUILD_NOT_COLD")
try:
    assert json.loads((ROOT / "development/self-rebuild-word-pairs-r1/summary.json").read_bytes())["status"] == "PASS"
    usage = json.loads((ROOT / "development/self-rebuild-word-pairs-r1/post-output-budget.json").read_bytes())
    assert usage["status"] == "PASS" and usage["usage"]["aggregate_cpu_seconds"] < 90 and usage["usage"]["elapsed_ns"] < 150000000000
    record, raw, terminal = gate.run("generation1", EXE, [digest(KIT.read_bytes())], input_path=KIT, wall=150)
    assert len(terminal) == 128 and terminal[96:128] == hashlib.sha256(raw).digest()
    event = struct.unpack("<16Q", terminal)
    assert event[0] == int.from_bytes(b"HIABBE01", "little") and event[1] == 0 and event[4] == len(raw)
    files = unpack(raw)
    original = unpack((ORIGINAL / "development/native-whole-r2/package.raw").read_bytes())
    for name in ("hia", "hia-release", "compiler.bin"): assert files[name] == original[name]
    assert files["source-kit.hiabuild"] == (0o400, KIT.read_bytes())
    assert files["hia-build"] == (0o500, EXE.read_bytes())
    report = json.loads(files["build.json"][1])
    old_report = json.loads((ORIGINAL / "development/native-whole-r2/summary.json").read_bytes())["native_receipt"]
    rows = list(old_report["images"])
    images = {}
    for label, path in MANIFESTS.items():
        manifest = json.loads(path.read_bytes())
        source, image = Path(manifest["source_path"]).read_bytes(), Path(manifest["image_path"]).read_bytes()
        assert digest(source) == manifest["source_sha256"] and digest(image) == manifest["image_sha256"]
        rows.append({"input_sha256": digest(source), "image_sha256": digest(image), "image_bytes": len(image)})
        images[label] = image
    packet = struct.pack("<4Q", int.from_bytes(b"HIABPK01", "little"), len(images["clean-build-driver"]), len(images["agent-data-json"]), 0) + images["clean-build-driver"] + images["agent-data-json"]
    rows.append({"input_sha256": digest(packet), "image_sha256": digest(EXE.read_bytes()), "image_bytes": EXE.stat().st_size})
    expected = {**old_report, "schema": "hepta.hia.native-clean-build.v2", "status": "SELF_REBUILT_NATIVE_BUILD",
                "kit_sha256": digest(KIT.read_bytes()), "builder_sha256": digest(EXE.read_bytes()), "images": rows,
                "builder_recompiled_from_kit_source": True, "builder_copy_used": False}
    assert report == expected
    materialized = gate.out / "package-files"
    materialized.mkdir()
    for name, (mode, data) in files.items():
        path = materialized / name
        path.write_bytes(data)
        path.chmod(mode)
    gate.summary.update(status="PASS", complete_original_seven_recipes_and_two_application_packers_equal=True,
                        complete_13_row_receipt_equal_to_independent_full_expected_object=True,
                        own_builder_complete_bytes_equal_to_independent_native_seed=True,
                        package_bytes=len(raw), package_sha256=digest(raw),
                        package_path=str(gate.out / "calls/generation1/stdout.raw"),
                        files={name: {"bytes": len(data), "sha256": digest(data), "mode": mode} for name, (mode, data) in files.items()})
except BaseException as exc:
    gate.fail(exc)
finally:
    gate.finish()
