"""Fresh local source/profile gate for the explicit self-rebuilding owner."""
from pathlib import Path
import hashlib
import json
import re
import stat
import sys
import time
import traceback

ROOT = Path(__file__).resolve().parent
ORIGINAL = ROOT / "original-r13"
REFERENCE = ROOT / "reference-kit-r13"
OUT = ROOT / "development/generate-self-rebuild-r1"
OUT.mkdir(parents=True, exist_ok=False)
sys.dont_write_bytecode = True
sys.path[:0] = [str(ROOT / "authoring-dependencies"), str(REFERENCE), str(ORIGINAL / "tools"), str(ROOT)]

def identity(p):
    raw = p.read_bytes()
    return {"path": str(p), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "mode": stat.S_IMODE(p.stat().st_mode)}

paths = sorted({*REFERENCE.rglob("*.py"), *ORIGINAL.joinpath("tools").glob("*.py"),
                ROOT / "authoring-dependencies/tools/hia_agent_edit_source_views.py",
                ROOT / "clean_build_self_rebuild.py", Path(__file__)}, key=str)
before = [identity(p) for p in paths]
(OUT / "source-before.json").write_text(json.dumps(before, indent=2, sort_keys=True) + "\n")
summary = {"schema": "hia-clean-builder-self-rebuild-generation-r1", "status": "INCOMPLETE",
           "scope": "LOCAL_NEW_SOURCE_GENERATION_NOT_COLD_NOT_NATIVE", "native_calls": 0,
           "compiler_calls": 0, "old_tests_executed": 0}
start = time.monotonic_ns()
primary = None
after_errors = []
try:
    import generate_hia_clean_build_driver as old
    import clean_build_self_rebuild as new
    import build_authoring
    from hepta.hia_agent_assembly import render_assembly
    original = render_assembly(build_authoring.document(old.source(), "clean_build_driver")).encode()
    assert hashlib.sha256(original).hexdigest() == "3b845b935c68b383567f1eb8210b351e129e17f4b7b4c474db5443f30b0dac8c"
    expected = ORIGINAL / "development/driver-compile-r3/source/0/clean_build_driver.hiaasm"
    assert original == expected.read_bytes()
    body, edits = new.source()
    doc = build_authoring.document(body, "clean_build_driver")
    raw = render_assembly(doc).encode()
    (OUT / "clean_build_driver.authoring.py").write_text(body)
    (OUT / "clean_build_driver.hiaasm").write_bytes(raw)
    (OUT / "exact-inverse-edits.json").write_text(json.dumps(edits, indent=2, sort_keys=True) + "\n")
    profile = build_authoring.profile(doc)
    names = []
    def walk(v):
        if isinstance(v, dict):
            for x in v.values(): walk(x)
        elif isinstance(v, list):
            for x in v: walk(x)
        elif isinstance(v, str) and re.fullmatch(r"v[0-9]+", v):
            names.append(int(v[1:]))
    walk(doc)
    profile["max_ssa_index"] = max(names, default=-1)
    (OUT / "profile.json").write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n")
    assert len(raw) <= 1048576
    assert profile["functions"] <= 128 and profile["blocks"] <= 1536 and profile["ops"] <= 8192, profile
    assert profile["max_params"] <= 16 and profile["max_ssa_index"] < 2048, profile
    summary.update(status="PASS", original_source_reproduced=True, exact_inverse_edits=len(edits),
                   bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(), profile=profile)
except BaseException as exc:
    primary = exc
    summary.update(status="FAIL", error_class=type(exc).__name__, error=str(exc))
    (OUT / "primary-traceback.txt").write_text(traceback.format_exc())
finally:
    for row in before:
        try:
            assert identity(Path(row["path"])) == row
        except BaseException as exc:
            after_errors.append({"path": row["path"], "error_class": type(exc).__name__, "error": str(exc)})
    summary["after_errors"] = after_errors
    summary["all_source_bytes_and_modes_unchanged"] = not after_errors
    if after_errors: summary["status"] = "FAIL"
    summary["elapsed_ns"] = time.monotonic_ns() - start
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True), flush=True)
if primary is not None: raise primary
assert not after_errors
