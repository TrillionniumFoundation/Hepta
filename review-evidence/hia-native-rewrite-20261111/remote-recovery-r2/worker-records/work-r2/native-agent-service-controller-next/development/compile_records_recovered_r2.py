"""New ROG development compile; historical cloud observations are not reused as a run."""
from __future__ import annotations
import ast
from hashlib import sha256
import json
from pathlib import Path
import stat
import sys
import time
import traceback

HERE = Path(__file__).resolve()
ROOT = HERE.parents[1]
BASE = ROOT.parent
REFERENCE = BASE / "Hepta-agent-edit-native"
COMPILER = BASE / "dependencies/f50-B3.image.bin"
OUT = ROOT / "development/records-compile-recovered-r2"
SOURCE = ROOT / "examples/hia_bootstrap/agent_service_records.hiaasm"
sys.path[:0] = [str(ROOT / "tools"), str(REFERENCE)]
from generate_hia_service_records import document
from hepta.hia_agent_assembly import render_assembly, assemble_program
from tools.qualify_hia_selfhost import compile_stage

def info(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=sha256(raw).hexdigest(),
                mode=stat.S_IMODE(path.stat().st_mode))

OUT.mkdir(parents=True, exist_ok=False)
paths = [
    HERE, ROOT / "tools/service_records.py", ROOT / "tools/generate_hia_service_records.py",
    BASE / "native-agent-worker-next/tools/generate_hia_worker_report.py",
    REFERENCE / "tools/generate_hia_agent_edit_apply_graph.py",
    REFERENCE / "tools/generate_hia_graph_merge.py",
    REFERENCE / "tools/hia_agent_edit_source_views.py",
    REFERENCE / "tools/generate_hia_selfhost.py",
    REFERENCE / "tools/qualify_hia_selfhost.py",
    REFERENCE / "hepta/hia_agent_assembly.py",
    REFERENCE / "hepta/hia_program.py",
    COMPILER,
]
before = [info(p) for p in paths]
(OUT / "source-before.json").write_text(json.dumps(before, indent=2, sort_keys=True) + "\n")
for index, row in enumerate(before):
    source_path = Path(row["path"])
    target = OUT / "source" / str(index) / source_path.name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(source_path.read_bytes())
    target.chmod(row["mode"])
    assert info(target)["sha256"] == row["sha256"]
assert info(COMPILER)["sha256"] == "0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
start = time.monotonic_ns()
summary = dict(status="INCOMPLETE", scope="NEW_SOURCE_BOUND_DEVELOPMENT_NOT_COLD_OR_WHOLE_WORKER",
               compile_limits=dict(cpu_seconds=10, wall_seconds=20, address_space_bytes=256 << 20))
try:
    value = document()
    fs = value["functions"]
    counts = dict(functions=len(fs), blocks=sum(len(f["blocks"]) for f in fs),
                  instructions=sum(len(b["ops"]) for f in fs for b in f["blocks"]),
                  max_function_blocks=max(len(f["blocks"]) for f in fs),
                  max_block_parameters=max(len(b["params"]) for f in fs for b in f["blocks"]))
    raw = render_assembly(value).encode()
    assemble_program(raw)
    SOURCE.parent.mkdir(parents=True, exist_ok=True)
    if SOURCE.exists():
        assert SOURCE.read_bytes() == raw, "existing current source differs"
    else:
        SOURCE.write_bytes(raw)
    (OUT / "service-records.input.hiaasm").write_bytes(raw)
    historical_source = "ca8c522d9986ef77ebab7047ae01c142820f55c4200147e402e0e219a1c64a9e"
    historical_image = "9c3fd57c3914a1d2775a16a5369c21b96802656c28c966bde727575afe53cacb"
    assert sha256(raw).hexdigest() == historical_source, "new generation differs from historical observed source"
    image, receipt = compile_stage(OUT, "service-records", COMPILER, raw)
    image = Path(image).resolve()
    receipt_path = OUT / "service-records.receipt.json"
    actual_receipt = json.loads(receipt_path.read_bytes())
    image_bytes = image.read_bytes()
    image_sha = sha256(image_bytes).hexdigest()
    assert actual_receipt["input_sha256"] == sha256(raw).hexdigest()
    assert actual_receipt["produced_sha256"] == image_sha
    assert actual_receipt["image_sha256"] == before[-1]["sha256"]
    assert SOURCE.read_bytes() == raw
    manifest = dict(
        schema="hepta.hia.agent-service-records-development.v1",
        source_path=str(SOURCE.resolve()), source_bytes=len(raw), source_sha256=sha256(raw).hexdigest(),
        image_path=str(image), image_bytes=len(image_bytes), image_sha256=image_sha,
        compiler_path=str(COMPILER.resolve()), compiler_sha256=before[-1]["sha256"],
        receipt_path=str(receipt_path.resolve()),
        scope="NEW_ROG_DEVELOPMENT_NOT_COLD_OR_NAMESPACE_OR_COMPLETE_WORKER",
    )
    (OUT / "service-records.manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    summary.update(status="PASS", counts=counts, manifest=manifest,
                   historical_observed_source_equal=sha256(raw).hexdigest() == historical_source,
                   historical_observed_image_equal=image_sha == historical_image,
                   historical_cloud_original_receipt_recovered=False)
except BaseException as exc:
    summary.update(status="FAIL", error_class=type(exc).__name__, error=str(exc))
    traceback.print_exc()
    raise
finally:
    after = [info(p) for p in paths]
    (OUT / "source-after.json").write_text(json.dumps(after, indent=2, sort_keys=True) + "\n")
    summary["all_source_before_after_exact"] = before == after
    summary["wall_elapsed_ns"] = time.monotonic_ns() - start
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True), flush=True)
    assert before == after, "bound compile input changed"
