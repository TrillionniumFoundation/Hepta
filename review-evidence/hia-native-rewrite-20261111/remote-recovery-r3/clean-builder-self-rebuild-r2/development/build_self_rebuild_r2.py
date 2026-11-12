"""Build a new inactive self-rebuilding ELF using the exact original B3.

Original per-call 10 CPU / 20 wall / 256 MiB compiler and packer limits are
provided by the unchanged original qualification transport.  This host is a
local development domain, not the original Ubuntu24 qualification domain.
"""
from pathlib import Path
import hashlib
import json
import stat
import struct
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parent
ORIGINAL = ROOT / "original-r13"
REFERENCE = ROOT / "reference-kit-r13"
OUT = ROOT / "development/build-self-rebuild-r2"
OUT.mkdir(parents=True, exist_ok=False)
sys.dont_write_bytecode = True
sys.path.insert(0, str(REFERENCE))
COMPILER = ROOT / "B3-35ee.original.image.bin"
SOURCES = {
    "clean-build-driver": ROOT / "development/generate-self-rebuild-r4/clean_build_driver.hiaasm",
    "agent-data-json": ORIGINAL / "development/gate-compile-r2/source/1/agent_data_json.hiaasm",
    "clean-build-packer": ORIGINAL / "development/driver-compile-r2/source/1/clean_build_packer.hiaasm",
}
EXPECTED = {
    "clean-build-driver": "4087a7ef00b5a17a254eefea73e46889b021fb36bf6ffef36a8faa4a474a4138",
    "agent-data-json": "bfb36b20e6e2def7a484c794b71f6ff7a202ecdc5452605bc0ad63251b03308e",
    "clean-build-packer": "0aa86fe701b4417e01b22ed845977bc15074b492c56e8e8c787e20c8e6ad5e4d",
}
EXPECTED_IMAGES = {
    "agent-data-json": "c84b865a6ffe497bab96a3de1fcb3a8c3c26c3ec483b0e824966bc5f7a09abbd",
    "clean-build-packer": "87bb61f172a6197cbf6abdeba397178cc6a426069accde1d39479a29c0bc229a",
}

def digest(raw): return hashlib.sha256(raw).hexdigest()
def identity(p):
    raw = p.read_bytes()
    return {"path": str(p), "bytes": len(raw), "sha256": digest(raw),
            "mode": stat.S_IMODE(p.stat().st_mode)}

prefix_path = ORIGINAL / "development/executor-prefix-r1.bin"
layout_path = ORIGINAL / "development/executor-layout-r1.json"
inputs = sorted({*REFERENCE.rglob("*.py"), COMPILER, *SOURCES.values(), prefix_path,
                 layout_path, ORIGINAL / "tools/clean_build_executor.S", Path(__file__),
                 ROOT / "clean_build_self_rebuild_r4.py", ROOT / "generate_self_rebuild_r4.py"}, key=str)
before = [identity(p) for p in inputs]
(OUT / "source-before.json").write_text(json.dumps(before, indent=2, sort_keys=True) + "\n")
summary = {"schema": "hia-clean-builder-self-rebuild-build-r2", "status": "INCOMPLETE",
           "scope": "LOCAL_DEVELOPMENT_NOT_UBUNTU24_QUALIFICATION_NOT_COLD", "completed_compiles": [],
           "packer_calls": 0, "original_budget_unchanged": True, "activation": False}
started = time.monotonic_ns()
primary = None
after_errors = []
try:
    seed = COMPILER.read_bytes()
    assert len(seed) == 669556 and digest(seed) == "35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
    assert json.loads((ROOT / "development/generate-self-rebuild-r4/summary.json").read_bytes())["status"] == "PASS"
    from tools.qualify_hia_selfhost import compile_stage, invoke
    from tools.qualify_hia_selfhost_cli import inspect_executable
    manifests = {}
    images = {}
    for label, source in SOURCES.items():
        raw = source.read_bytes()
        assert digest(raw) == EXPECTED[label]
        image, receipt = compile_stage(OUT, label, COMPILER, raw)
        produced = image.read_bytes()
        assert receipt["artifact_sha256"] == digest(seed) and receipt["input_sha256"] == digest(raw)
        assert receipt["produced_sha256"] == digest(produced)
        if label in EXPECTED_IMAGES: assert digest(produced) == EXPECTED_IMAGES[label]
        copy = OUT / (label + ".hiaasm")
        copy.write_bytes(raw)
        manifest = {"schema": "hepta.hia.clean-build-development.v1", "source_path": str(copy),
                    "source_sha256": digest(raw), "image_path": str(image), "image_sha256": digest(produced),
                    "compiler_sha256": digest(seed), "scope": "LOCAL_SELF_REBUILD_DEVELOPMENT_NOT_COLD"}
        path = OUT / (label + ".manifest.json")
        path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        manifests[label] = str(path)
        images[label] = (image, produced)
        summary["completed_compiles"].append({"label": label, **identity(image)})
    driver = images["clean-build-driver"][1]
    decoder = images["agent-data-json"][1]
    packet = struct.pack("<4Q", int.from_bytes(b"HIABPK01", "little"), len(driver), len(decoder), 0) + driver + decoder
    receipt, output = invoke(OUT, "actual-native-builder-pack", images["clean-build-packer"][0], packet)
    summary["packer_calls"] = 1
    assert receipt["status"] == "returned" and receipt["abi_status"] == 0
    size = receipt["core_u32"]
    assert 0 < size <= len(output)
    executable = output[:size]
    inspection = inspect_executable(executable)
    prefix = bytearray(prefix_path.read_bytes())
    layout = json.loads(layout_path.read_bytes())
    assert len(prefix) == layout["bytes"] == 2744
    holes = layout["holes"]
    expected_size = len(prefix) + len(driver) + len(decoder)
    struct.pack_into("<Q", prefix, 96, expected_size)
    struct.pack_into("<Q", prefix, 104, expected_size)
    struct.pack_into("<I", prefix, holes["driver_call_hole"], len(prefix) - holes["driver_call_hole"] - 4)
    struct.pack_into("<Q", prefix, holes["decoder_offset_value"], len(prefix) + len(driver))
    struct.pack_into("<Q", prefix, holes["self_size_value"], expected_size)
    expected = bytes(prefix) + driver + decoder
    assert executable == expected
    target = OUT / "hia-build-self-rebuilding"
    target.write_bytes(executable)
    target.chmod(0o700)
    bundle = {"schema": "hepta.hia.clean-self-rebuilding-development.v1", "executable": str(target),
              "executable_sha256": digest(executable), "executable_bytes": len(executable),
              "image_manifests": manifests, "original_fixed_executor_unchanged": True,
              "complete_elf_equal_to_independent_template_and_images": True,
              "scope": "LOCAL_DEVELOPMENT_NOT_COLD_INACTIVE", "activation": False}
    (OUT / "bundle.json").write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    summary.update(status="PASS", bundle=bundle, inspection=inspection)
except BaseException as exc:
    primary = exc
    summary.update(status="FAIL", error_class=type(exc).__name__, error=str(exc))
    (OUT / "primary-traceback.txt").write_text(traceback.format_exc())
finally:
    for row in before:
        try: assert identity(Path(row["path"])) == row
        except BaseException as exc:
            after_errors.append({"path": row["path"], "error_class": type(exc).__name__, "error": str(exc)})
    summary["after_errors"] = after_errors
    summary["all_source_bytes_and_modes_unchanged"] = not after_errors
    if after_errors: summary["status"] = "FAIL"
    summary["elapsed_ns"] = time.monotonic_ns() - started
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True), flush=True)
if primary is not None: raise primary
assert not after_errors
