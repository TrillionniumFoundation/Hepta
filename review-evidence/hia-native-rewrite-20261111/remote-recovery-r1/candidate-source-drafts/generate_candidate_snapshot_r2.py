"""New HIA candidate snapshot budget owner; public native editor mode only.

A separate revision preserves caller insertion order before the original
caller-owned snapshot traversal. Frozen R13 source and images remain intact.
This file must generate and compile under the existing B3 limits before use.
"""
import ast
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys
import time
import traceback

HOMEBASE = Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
BASE = HOMEBASE / "root-recovery/workspace"
REFERENCE = HOMEBASE / "root-recovery/reference-0ef-r2"
ROOT = BASE / "native-edit-candidate-snapshot-next"
FROZEN = BASE / "native-edit-candidate-next"
OLD_PREFIX = "/workspace/scratch/9acdfa9f5639/"
SNAPSHOT_MAGIC = int.from_bytes(b"HIAPLS01", "little")
BYTE_MAGIC = int.from_bytes(b"HIAPLB01", "little")
NEED = 0xfffffffe
MESSAGES = {
    6: "E_HIA_LIMIT: caller-owned tree exceeds snapshot budget",
    7: "E_HIA_LIMIT: caller-owned tree exceeds queued-node budget",
}
PINS = {}

def read(path):
    path = Path(path)
    raw = path.read_bytes()
    if path in PINS:
        assert PINS[path] == raw
    PINS[path] = raw
    return raw

def mapped(path):
    return BASE / path[len(OLD_PREFIX):] if path.startswith(OLD_PREFIX) else Path(path)

def load(name, path):
    read(path)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

SNAPSHOT_SOURCE = '''
def candidate_snapshot_refusal(o:mutbuf, reason:u64, seen:u64, depth:u64, queued:u64, children:u64) -> u64:
    put(o, 0, SNAPSHOT_MAGIC)
    put(o, 8, 1 | (reason << 32))
    put(o, 16, seen | (depth << 32))
    put(o, 24, queued | (children << 32))
    return 4294967294

def candidate_snapshot_budget(o:mutbuf, w:mutbuf, root:u64) -> u64:
    node = root
    depth = 0
    seen = 0
    queued = 1
    going = True
    while going:
        queued = queued - 1
        seen = seen + 1
        if seen > 262144 or depth > 64:
            return candidate_snapshot_refusal(o, 1, seen, depth, queued, 0)
        k = kind(w, node)
        if k == 5 or k == 6:
            children = count(w, node)
            if children > 262144 - seen - queued:
                return candidate_snapshot_refusal(o, 2, seen, depth, queued, children)
            queued = queued + children
        if (k == 5 or k == 6) and count(w, node) > 0:
            node = child(w, node)
            depth = depth + 1
        else:
            moving = True
            while moving:
                if node == root:
                    going = False
                    moving = False
                elif next_node(w, node) != 18446744073709551615:
                    node = next_node(w, node)
                    moving = False
                else:
                    node = get(w, 64 + node * 56 + 8)
                    depth = depth - 1
    return 0
'''

WITNESS_SOURCE = '''
def candidate_snapshot_result(w:mutbuf, result:u64, obs:u64) -> u64:
    if result != 4294967294:
        return refuse(w, 1680)
    header = get(w, obs + 8)
    if (header & 4294967295) != 1:
        return refuse(w, 1681)
    reason = header >> 32
    if reason != 1 and reason != 2:
        return refuse(w, 1682)
    seen_depth = get(w, obs + 16)
    queued_children = get(w, obs + 24)
    seen = seen_depth & 4294967295
    depth = seen_depth >> 32
    queued = queued_children & 4294967295
    children = queued_children >> 32
    if seen < 1 or seen > 262145 or depth > 65:
        return refuse(w, 1683)
    if queued > 262144 or children > 262144:
        return refuse(w, 1684)
    if reason == 1:
        if seen <= 262144 and depth <= 64:
            return refuse(w, 1685)
        if children != 0:
            return refuse(w, 1686)
        if seen > 262144:
            if queued != 0:
                return refuse(w, 1687)
        elif queued > 262144 - seen:
            return refuse(w, 1688)
        return apply_error(w, 6, 4294967294)
    if seen > 262144 or depth > 64:
        return refuse(w, 1689)
    if queued > 262144 - seen:
        return refuse(w, 1690)
    if children <= 262144 - seen - queued:
        return refuse(w, 1691)
    return apply_error(w, 7, 4294967294)
'''

def document_from_patch(patch, source, expand):
    original = patch.source_program
    try:
        patch.source_program = lambda: source
        document = patch.document()
    finally:
        patch.source_program = original
    for index, function in enumerate(document["functions"]):
        if function["name"] in ("f54", "f55"):
            document["functions"][index], _ = expand(function)
    return document

def profile(document, raw):
    out = dict(functions=len(document["functions"]),
               blocks=sum(len(f["blocks"]) for f in document["functions"]),
               max_blocks=max(len(f["blocks"]) for f in document["functions"]),
               ops=sum(len(b["ops"]) for f in document["functions"] for b in f["blocks"]),
               max_block_params=max(len(b["params"]) for f in document["functions"] for b in f["blocks"]),
               source_bytes=len(raw))
    assert out["functions"] <= 128 and out["blocks"] <= 1536
    assert out["max_blocks"] <= 256 and out["ops"] <= 8192
    assert out["max_block_params"] <= 16 and len(raw) <= 1 << 20
    return out

def main():
    assert REFERENCE.is_dir()
    assert not ROOT.exists(), "Preserve any earlier attempt and choose a new revision"
    ROOT.mkdir()
    (ROOT / "tools").mkdir()
    (ROOT / "development").mkdir()
    (ROOT / "examples/hia_bootstrap").mkdir(parents=True)
    (ROOT / "tools/generate_candidate_snapshot_r2.py").write_bytes(read(Path(__file__)))
    sys.path[:0] = [str(REFERENCE), str(BASE / "native-edit-performance-next/tools")]
    from hepta.hia_agent_assembly import assemble_program, render_assembly
    from tools import generate_hia_core_patch as patch
    from unroll_word_accessors import expand
    apply = load("frozen_apply_snapshot_revision", BASE / "native-edit-apply-next/tools/generate_hia_edit_apply.py")
    frozen = json.loads(read(FROZEN / "development/source-r1.json"))
    old60 = read(FROZEN / "development/core_patch_candidate_limit.authoring.py").decode()
    old59 = read(FROZEN / "development/agent_edit_apply_candidate_limit.authoring.py").decode()
    old60_raw = read(mapped(frozen["components"]["60"]["source_path"]))
    old59_raw = read(mapped(frozen["components"]["59"]["source_path"]))
    assert sha256(old60_raw).hexdigest() == frozen["components"]["60"]["source_sha256"]
    assert sha256(old59_raw).hexdigest() == frozen["components"]["59"]["source_sha256"]
    old60_doc = document_from_patch(patch, old60, expand)
    assert render_assembly(old60_doc).encode() == old60_raw
    old59_doc = apply.authoring.document(old59, "agent_edit_apply_driver")
    assert render_assembly(old59_doc).encode() == old59_raw

    tree = ast.parse(old60)
    patch_main = next(f for f in tree.body if f.name == "patch_main")
    renders = [n for n in ast.walk(patch_main) if isinstance(n, ast.Call)
               and isinstance(n.func, ast.Name) and n.func.id == "render_fragment"
               and isinstance(n.args[-1], ast.Name) and n.args[-1].id == "request"]
    assert len(renders) == 1
    renders[0].func.id = "render_fragment_preserving_order"
    at = next(i for i, n in enumerate(patch_main.body) if isinstance(n, ast.Assign)
              and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and n.targets[0].id == "applied")
    assert isinstance(patch_main.body[at+1], ast.If)
    patch_main.body[at+2:at+2] = ast.parse("""
if mode == 2:
    snapshot_status = candidate_snapshot_budget(o, w, base)
    if snapshot_status != 0:
        return snapshot_status
""").body
    renderer = deepcopy(next(f for f in tree.body if f.name == "render_fragment"))
    renderer.name = "render_fragment_preserving_order"
    removed = []
    class PreserveOrder(ast.NodeTransformer):
        def visit_Expr(self, node):
            if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name) and node.value.func.id == "sort_object":
                removed.append(ast.unparse(node))
                return None
            return self.generic_visit(node)
        def visit_If(self, node):
            node = self.generic_visit(node)
            if not node.body:
                assert not node.orelse
                return None
            return node
    renderer = PreserveOrder().visit(renderer)
    assert len(removed) == 1
    tree.body.append(renderer)
    new_helpers = ast.parse(SNAPSHOT_SOURCE.replace("SNAPSHOT_MAGIC", str(SNAPSHOT_MAGIC)))
    tree.body.extend(new_helpers.body)
    after60 = ast.unparse(ast.fix_missing_locations(tree)) + "\n"
    document60 = document_from_patch(patch, after60, expand)
    assert len(document60["functions"]) == len(old60_doc["functions"]) + 3
    assert document60["functions"][1:len(old60_doc["functions"])] == old60_doc["functions"][1:]

    atree = ast.parse(old59)
    phases = [n for n in ast.walk(atree) if isinstance(n, ast.If)
              and ast.unparse(n.test) == "phase == 60110"]
    assert len(phases) == 1
    phase = phases[0]
    assert isinstance(phase.body[0], ast.Assign) and phase.body[0].targets[0].id == "result"
    old_witness = phase.body[1]
    assert isinstance(old_witness, ast.If) and isinstance(old_witness.test, ast.Compare)
    assert old_witness.test.comparators[0].value == BYTE_MAGIC
    observed = ast.unparse(old_witness.test.left)
    assert observed.startswith("get(w, ")
    obs = ast.unparse(old_witness.test.left.args[1])
    branch = ast.parse("if " + observed + " == " + str(SNAPSHOT_MAGIC) + ":\n    return candidate_snapshot_result(w, result, " + obs + ")\n").body[0]
    phase.body.insert(1, branch)
    errors = next(f for f in atree.body if f.name == "apply_error")
    old_error = next(n for n in errors.body if isinstance(n, ast.If)
                     and ast.unparse(n.test) == "stage == 5 and code == 4294967294")
    terminal = old_error.body[-1].value
    assert terminal.func.id == "edit_error_start" and len(terminal.args) == 7
    wire = ast.unparse(terminal.args[5])
    slot = ast.unparse(terminal.args[4])
    assert terminal.args[1].value == 2
    for stage, message in MESSAGES.items():
        raw = message.encode()
        lines = ["if stage == " + str(stage) + " and code == 4294967294:"]
        end = len(raw) // 8 * 8
        for offset in range(0, end, 8):
            lines.append("    put(w, " + wire + " + " + str(offset) + ", " + str(int.from_bytes(raw[offset:offset+8], "little")) + ")")
        for offset in range(end, len(raw)):
            lines.append("    store(w, " + wire + " + " + str(offset) + ", " + str(raw[offset]) + ")")
        lines.append("    return edit_error_start(w, 2, " + str(200+stage) + ", code, " + slot + ", " + wire + ", " + str(len(raw)) + ")")
        errors.body.insert(-1, ast.parse("\n".join(lines)).body[0])
    atree.body.extend(ast.parse(WITNESS_SOURCE).body)
    after59 = ast.unparse(ast.fix_missing_locations(atree)) + "\n"
    document59 = apply.authoring.document(after59, "agent_edit_apply_driver")
    rows = {}
    for role, name, source, doc in (
        (59, "agent_edit_apply_candidate_snapshot", after59, document59),
        (60, "core_patch_candidate_snapshot", after60, document60),
    ):
        path = ROOT / "examples/hia_bootstrap" / (name + ".hiaasm")
        raw = render_assembly(doc).encode()
        assemble_program(raw)
        path.write_bytes(raw)
        authoring = ROOT / "development" / (name + ".authoring.py")
        authoring.write_text(source)
        rows[str(role)] = dict(role=role, source_path=str(path), source_bytes=len(raw),
                              source_sha256=sha256(raw).hexdigest(), profile=profile(doc, raw),
                              original=frozen["components"][str(role)])
    manifest = dict(schema="hia-candidate-snapshot-witness-source-v1", status="GENERATED_NOT_COMPILED",
                    components=rows, origin="Exact regenerated R13 owners plus explicit new HIA changes",
                    superseded_unexecuted_generator_blob="3fd295f60d84c1325ae0bac0ae6cb7e5cd605cd1",
                    source_only_revision_fix="Remove the empty conditional left by removing in-place object sorting",
                    witness=dict(magic="HIAPLS01", status=NEED,
                        words=["magic", "ABI1_low32_cause_high32", "seen_low32_depth_high32", "queued_low32_children_high32"],
                        causes={"1":"snapshot count/depth", "2":"queued children"}, public_error_domain=2,
                        exact_messages=MESSAGES),
                    original_byte_witness_retained=True, gate_only_in_editor_mode2=True,
                    request_measurement_preserves_insertion_order=True,
                    all_prior_role60_nonentry_functions_unchanged=True,
                    original_owner_sources_unchanged=True, whole_stack_closed=False)
    (ROOT / "development/source-r1.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"source_manifest":str(ROOT / "development/source-r1.json"),
                      "components":rows}, sort_keys=True), flush=True)

started = time.monotonic()
try:
    main()
except BaseException:
    traceback.print_exc()
    raise
finally:
    if ROOT.exists():
        receipt = dict(schema="hia-candidate-snapshot-authoring-pins-v1",
                       elapsed_seconds=time.monotonic()-started,
                       source_before_after_equal=all(p.read_bytes()==raw for p,raw in PINS.items()),
                       pins={str(p):dict(bytes=len(raw),sha256=sha256(raw).hexdigest()) for p,raw in PINS.items()})
        (ROOT / "development/authoring-pins-r1.json").write_text(json.dumps(receipt, indent=2, sort_keys=True)+"\n")
        assert receipt["source_before_after_equal"]
