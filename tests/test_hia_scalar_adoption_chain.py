"""The capped-add family must satisfy its mathematical contract and native chain."""
from copy import deepcopy
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import platform
import shutil
import tempfile
import unittest

from tools.qualify_hia_scalar_adoption_chain import capped_add_program, specification_proof, main


AVAILABLE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
             and shutil.which("ld") is not None and importlib.util.find_spec("z3") is not None)


@unittest.skipUnless(AVAILABLE, "Linux x86-64, GNU ld and pinned Z3 are required")
class ScalarAdoptionChainTests(unittest.TestCase):
    def test_u64_specification_retains_the_carry_and_covers_all_raw_abi_words(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "proof"
            report = specification_proof(capped_add_program("u64"), directory)
            self.assertEqual(report["status"], "proved_in_independent_core_model")
            self.assertEqual([row["result"] for row in report["obligations"]], ["sat", "unsat", "unsat"])
            data = (directory / report["obligations"][-1]["query_file"]).read_text()
            self.assertIn("zero_extend 1", data)
            self.assertFalse(report["kernel_checked_core_soundness"])
            self.assertFalse(report["execution_authority_granted"])

    def test_valid_core_with_a_wrong_capped_result_does_not_pass_the_specification(self):
        document = deepcopy(capped_add_program("u64"))
        limited = document["functions"][0]["blocks"][-1]
        limited["ops"] = [{"op": "const", "args": [],
                           "out": [{"name": "wrong", "type": "u64"}], "attrs": {"value": 0}}]
        limited["term"]["values"] = ["wrong"]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "proof"
            with self.assertRaisesRegex(ValueError, "core_equals_unbounded_sum"):
                specification_proof(document, directory)
            report = json.loads((directory / "specification.json").read_bytes())
            self.assertEqual(report["status"], "refuted")
            self.assertEqual(report["obligations"][-1]["result"], "sat")
            vector = report["counterexample"]
            self.assertGreater(min(vector["x"] + vector["y"], vector["cap"]), 0)

    def test_nontrivial_planned_adoption_retains_replayable_proofs_and_exact_bytes(self):
        import z3
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "chain"
            self.assertEqual(main(["--output", str(output), "--types", "u32",
                                   "--campaign-id", "capped-chain-test"]), 0)
            report = json.loads((output / "report.json").read_bytes())
            self.assertEqual(report["status"], "passed")
            row = report["families"][0]
            chain = row["identity_chain"]
            directory = output / "u32"
            for reference, filename in ((chain["plan"], "machine-plan.json"),
                                        (chain["object"], "planned.o"),
                                        (chain["final_image"], "planned.so"),
                                        (chain["machine_proof"], "planned-machine-proof.json")):
                self.assertEqual(reference["sha256"], sha256((directory / filename).read_bytes()).hexdigest())
            self.assertEqual(chain["owner_artifact"], chain["final_image"])
            self.assertNotEqual(chain["final_image"], row["rollback"]["active_artifact"])
            self.assertEqual(row["native_workload_vectors"], 125)
            self.assertEqual(row["observed_owner_calls"], 10)
            self.assertFalse(row["full_search_cost_complete"])
            self.assertFalse(row["net_optimization_benefit_proved"])
            queries = [(directory / "specification" / q["query_file"], q)
                       for q in row["specification"]["obligations"]]
            for name in ("canonical", "planned"):
                evidence = json.loads((directory / (name + "-machine-evidence.json")).read_bytes())
                queries.extend((directory / (name + "-" + q["query_file"]), q)
                               for q in evidence["validation"]["obligations"])
            self.assertEqual(len(queries), 13)
            for path, obligation in queries:
                with self.subTest(query=path.name):
                    data = path.read_bytes()
                    self.assertEqual(sha256(data).hexdigest(), obligation["query_sha256"])
                    solver = z3.Solver(ctx=z3.Context())
                    solver.set(timeout=15000)
                    solver.from_string(data.decode())
                    self.assertEqual(str(solver.check()), obligation["expected"])


if __name__ == "__main__":
    unittest.main()
