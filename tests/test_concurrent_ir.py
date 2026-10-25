import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from hepta.checker import check
from hepta.concurrent_ir import verify_concurrent_ir
from hepta.concurrent_lowering import lower_concurrent_ir
from hepta.parser import parse
from hepta.pipeline import analyze, concurrent_ir_analysis

ROOT = Path(__file__).resolve().parents[1]
SOURCE = """module lifecycle;
fn work(data: take Buffer<u8>, token: read Cancellation, out: read Sender<u64>) -> u64
effects {alloc, block, panic, write} {
    let sent = group_send(read out, 7);
    release(move data);
    return 1;
}
fn main() -> Unit effects {alloc, block, spawn, panic, write} {
    let mut group = task_group(1, 8, 1);
    let input = buffer(8);
    let accepted = group_spawn(mut group, work, move input);
    group_cancel(mut group);
    let report = group_join(move group);
}
"""


def graph(source=SOURCE):
    program = parse(source)
    checked = check(program)
    if not checked.ok:
        raise AssertionError([d.to_dict() for d in checked.diagnostics])
    return lower_concurrent_ir(program, checked)


def operations(doc, function="main"):
    return next(fn for fn in doc["functions"] if fn["name"] == function)["blocks"][0]["operations"]


def adversarial_graphs(original):
    result = {}
    def variant(name, mutate):
        doc = copy.deepcopy(original)
        mutate(doc)
        result[name] = doc
    variant("cancellation_discharges_join", lambda d: operations(d).__setitem__(-1, {"op": "group", "src": operations(d)[-1]["src"], "mode": "group_cancel"}))
    variant("missing_worker_drop", lambda d: operations(d, "work").pop())
    variant("wrong_worker", lambda d: next(o for o in operations(d) if o["op"] == "spawn").update(worker="main"))
    variant("invented_sender", lambda d: operations(d, "work")[0].update(src="invented"))
    variant("join_twice", lambda d: operations(d).append(copy.deepcopy(operations(d)[-1])))
    variant("use_after_group_join", lambda d: operations(d).append({"op": "group", "src": operations(d)[-1]["src"], "mode": "group_snapshot"}))
    variant("unknown_operation", lambda d: operations(d).append({"op": "silently_skip"}))
    variant("worker_takes_cancellation", lambda d: d["functions"][0]["params"][1].update(mode="take"))
    variant("task_handle_forgery", lambda d: next(o for o in operations(d) if o["op"] == "create").update(type="Task<u64>"))
    variant("source_refinement_claim", lambda d: d["claims"].update(source_to_ir_refinement_proved=True))
    variant("numeric_claim", lambda d: d["claims"].update(worker_input_transfer_verified=1))
    variant("capability_in_owner_slots", lambda d: d["functions"][0]["slots"].update(v1="Cancellation"))
    variant("duplicate_function", lambda d: d["functions"].append(copy.deepcopy(d["functions"][0])))
    variant("unreachable_operations", lambda d: d["functions"][-1]["blocks"].append({"id": "unreachable", "operations": [{"op": "unknown"}], "terminator": {"op": "return", "owner": None}}))
    variant("missing_successor", lambda d: d["functions"][-1]["blocks"][0].update(terminator={"op": "jump", "targets": ["missing"]}))
    return result


class ConcurrentIRTests(unittest.TestCase):
    def test_owned_worker_and_cancel_then_join(self):
        result = verify_concurrent_ir(json.loads(json.dumps(graph())))
        self.assertTrue(result["ok"], result)
        self.assertEqual((result["functions"], result["group_spawns"], result["normal_exits"]), (2, 1, 2))

    def test_independent_adversarial_graphs(self):
        for label, doc in adversarial_graphs(graph()).items():
            with self.subTest(label=label):
                self.assertFalse(verify_concurrent_ir(doc)["ok"], label)

    def test_loop_backedge_preserves_group_obligation(self):
        source = SOURCE.replace("let input = buffer(8);\n    let accepted = group_spawn(mut group, work, move input);",
                                "for i in 0..2 { let input = buffer(4); let accepted = group_spawn(mut group, work, move input); }")
        doc = graph(source)
        self.assertTrue(verify_concurrent_ir(doc)["ok"])
        main = doc["functions"][-1]
        main["slots"]["leftover"] = "Buffer<u8>"
        body = next(b for b in main["blocks"] if any(o["op"] == "spawn" for o in b["operations"]))
        body["operations"].append({"op": "create", "dest": "leftover", "type": "Buffer<u8>"})
        result = verify_concurrent_ir(doc)
        self.assertFalse(result["ok"])
        self.assertEqual(result["diagnostics"][0]["code"], "E_CIR_JOIN_STATE")

    def test_branch_without_join_fails(self):
        doc = graph()
        main = doc["functions"][-1]
        main["blocks"][0]["operations"].pop()
        main["blocks"][0]["terminator"] = {"op": "jump", "targets": ["joined", "leaked"]}
        src = main["blocks"][0]["operations"][-1]["dest"]
        main["blocks"] += [
            {"id": "joined", "operations": [{"op": "join", "src": src, "mode": "group_join"}], "terminator": {"op": "return", "owner": None}},
            {"id": "leaked", "operations": [], "terminator": {"op": "return", "owner": None}},
        ]
        self.assertFalse(verify_concurrent_ir(doc)["ok"])

    def test_short_circuit_spawns_do_not_lose_ownership(self):
        source = SOURCE.replace("let input = buffer(8);\n    let accepted = group_spawn(mut group, work, move input);",
                                "let accepted = false && group_spawn(mut group, work, move buffer(8));")
        doc = graph(source)
        self.assertTrue(verify_concurrent_ir(doc)["ok"], verify_concurrent_ir(doc))
        self.assertGreater(len(doc["functions"][-1]["blocks"]), 1)

    def test_existing_group_sources_and_standalone_tasks(self):
        for source in [ROOT / "examples/tasks.hepta", *(ROOT / "examples/groups" / (name + ".hepta")
                      for name in ["bounded_pipeline", "admission_budgets", "cancellation", "worker_failure"])]:
            with self.subTest(source=source.name):
                report = verify_concurrent_ir(graph(source.read_text()))
                self.assertTrue(report["ok"], report)

    def test_aggregate_and_ffi_profiles_fail_explicitly(self):
        for relative in ["examples/groups/timeouts.hepta", "examples/owned/main.hepta"]:
            analysis = analyze((ROOT / relative).read_text(), str(ROOT / relative), native=False)
            exported = concurrent_ir_analysis(analysis)
            self.assertFalse(exported["ok"])
            self.assertIsNone(exported["concurrent_ir"])

    def test_malformed_graphs_are_rejections(self):
        for doc in [None, [], {}, 1, {"schema": "wrong"}]:
            self.assertFalse(verify_concurrent_ir(doc)["ok"])
        doc = graph()
        operations(doc)[0]["dest"] = []
        self.assertFalse(verify_concurrent_ir(doc)["ok"])

    def test_cli_never_claims_source_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "graph.json"
            path.write_text(json.dumps(graph()))
            proc = subprocess.run([sys.executable, "-m", "hepta.concurrent_ir", str(path)], cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertFalse(json.loads(proc.stdout)["source_binding_verified"])
            path.write_text('{"schema": 1, "schema": 2}')
            proc = subprocess.run([sys.executable, "-m", "hepta.concurrent_ir", str(path)], cwd=ROOT, text=True, capture_output=True)
            self.assertEqual(proc.returncode, 1)
            self.assertEqual(json.loads(proc.stdout)["diagnostics"][0]["code"], "E_CIR_JSON")


if __name__ == "__main__":
    unittest.main()
