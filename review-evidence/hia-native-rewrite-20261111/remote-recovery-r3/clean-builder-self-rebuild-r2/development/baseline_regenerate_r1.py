"""Reproduce the exact R13 authoring output, without executing old tests.

This is a local development source-regeneration observation, not cold/native
qualification.  All source inputs are the independently restored originals.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import stat
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parent
ORIGINAL = ROOT / "original-r13"
REFERENCE = ROOT / "reference-kit-r13"
OUT = ROOT / "development" / "baseline-regenerate-r1"
OUT.mkdir(parents=True, exist_ok=False)
DEPENDENCIES = ROOT / "authoring-dependencies"
helper = ORIGINAL / "development/driver-compile-r3/source/15/hia_agent_edit_source_views.py"
helper_raw = helper.read_bytes()
assert len(helper_raw) == 23950
assert hashlib.sha256(helper_raw).hexdigest() == "555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c"
copied_helper = DEPENDENCIES / "tools/hia_agent_edit_source_views.py"
copied_helper.parent.mkdir(parents=True, exist_ok=True)
if copied_helper.exists():
    assert copied_helper.read_bytes() == helper_raw
else:
    copied_helper.write_bytes(helper_raw)

sys.dont_write_bytecode = True
sys.path[:0] = [str(DEPENDENCIES), str(REFERENCE), str(ORIGINAL / "tools")]

def identity(path):
    raw = path.read_bytes()
    return {"path": str(path), "bytes": len(raw), "mode": stat.S_IMODE(path.stat().st_mode),
            "sha256": hashlib.sha256(raw).hexdigest()}

inputs = sorted({*REFERENCE.rglob("*.py"), *ORIGINAL.joinpath("tools").glob("*.py"),
                 copied_helper, Path(__file__)}, key=str)
before = [identity(p) for p in inputs]
(OUT / "source-before.json").write_text(json.dumps(before, indent=2, sort_keys=True) + "\n")
summary = {"schema": "hia-clean-builder-exact-authoring-regeneration-r1", "status": "INCOMPLETE",
           "scope": "LOCAL_SOURCE_REGENERATION_NOT_COLD_NOT_NATIVE", "native_calls": 0,
           "compiler_calls": 0, "old_tests_executed": 0}
started = time.monotonic_ns()
primary = None
after_errors = []
try:
    import generate_hia_clean_build_driver as generator
    import build_authoring
    from hepta.hia_agent_assembly import render_assembly
    body = generator.source()
    doc = build_authoring.document(body, "clean_build_driver")
    raw = render_assembly(doc).encode("utf-8")
    original_path = ORIGINAL / "development/driver-compile-r3/source/0/clean_build_driver.hiaasm"
    original_raw = original_path.read_bytes()
    assert hashlib.sha256(original_raw).hexdigest() == "3b845b935c68b383567f1eb8210b351e129e17f4b7b4c474db5443f30b0dac8c"
    (OUT / "generated.authoring.py").write_text(body)
    (OUT / "generated.hiaasm").write_bytes(raw)
    assert raw == original_raw, {"generated": hashlib.sha256(raw).hexdigest(),
                                 "original": hashlib.sha256(original_raw).hexdigest()}
    profile = build_authoring.profile(doc)
    loaded = sorted({str(Path(m.__file__).resolve()) for m in sys.modules.values()
                     if getattr(m, "__file__", None) and
                     (m.__name__ == "hepta" or m.__name__.startswith("hepta.") or
                      m.__name__ == "tools" or m.__name__.startswith("tools.") or
                      m.__name__.startswith("clean_build_") or m.__name__ == "build_authoring" or
                      m.__name__ == "generate_hia_clean_build_driver")})
    for name in loaded:
        p = Path(name)
        assert p.is_relative_to(REFERENCE) or p.is_relative_to(DEPENDENCIES) or p.is_relative_to(ORIGINAL / "tools"), name
    summary.update(status="PASS", complete_hia_bytes_equal=True, bytes=len(raw),
                   sha256=hashlib.sha256(raw).hexdigest(), profile=profile,
                   loaded_source_files=[identity(Path(p)) for p in loaded])
except BaseException as exc:
    primary = exc
    summary.update(status="FAIL", error_class=type(exc).__name__, error=str(exc))
    (OUT / "primary-traceback.txt").write_text(traceback.format_exc())
finally:
    for prior in before:
        try:
            assert identity(Path(prior["path"])) == prior
        except BaseException as exc:
            after_errors.append({"path": prior["path"], "error_class": type(exc).__name__, "error": str(exc)})
    summary["after_errors"] = after_errors
    summary["all_source_bytes_and_modes_unchanged"] = not after_errors
    if after_errors:
        summary["status"] = "FAIL"
    summary["elapsed_ns"] = time.monotonic_ns() - started
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "loaded_source_files"}, sort_keys=True), flush=True)
if primary is not None:
    raise primary
assert not after_errors
