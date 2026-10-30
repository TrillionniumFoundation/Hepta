"""Native positive/negative controls for the selected audited Rust Vec API."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tools/fixtures/hia_agent_resource.rs"


def instrumented_source(candidate):
    return ("#![forbid(unsafe_code)]\n" + FIXTURE.read_text() + "\n"
        "mod candidate {\n"
        "use super::audited::{Vec, drop};\n"
        "macro_rules! vec { ($value:expr; $length:expr) => { super::audited::make_vec($value,$length) }; }\n"
        + candidate + "\n"
        "pub fn invoke(x:u32,y:u32)->u32 {let target_contract:fn(u32,u32)->u32=target;target_contract(x,y)}\n"
        "}\n"
        "fn main() {use std::io::{self,Read};let mut input=String::new();"
        "io::stdin().read_to_string(&mut input).unwrap();let mut words=input.split_whitespace();"
        "while let Some(word)=words.next(){let x:u32=word.parse().unwrap();"
        "let y:u32=words.next().unwrap().parse().unwrap();audited::begin(x,y);"
        "let result=candidate::invoke(x,y);let ledger=audited::finish(result);"
        "println!(\"{}\",result);eprintln!(\"HIA_RUST_AUDIT {}\",ledger);}}\n")


class RustVecAuditControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.qualify_hia_agent_public_tools import TASK_MODULE, protocol, task_for
        cls.rustc = protocol()["rustc"]
        if not Path(cls.rustc).is_file():
            raise unittest.SkipTest("native audit controls require the registered Rust compiler")
        cls.task = task_for("buffer_lane")
        cls.reference = TASK_MODULE.reference("buffer_lane", "rust")
        cls.pairs = TASK_MODULE.cases(cls.task, hidden=True)
        cls.expected = [TASK_MODULE.oracle("buffer_lane", *pair) for pair in cls.pairs]

    def run_candidate(self, source, *, pairs=None):
        with tempfile.TemporaryDirectory(prefix="hia-rust-vec-audit-") as temporary:
            root = Path(temporary)
            path, binary = root / "main.rs", root / "candidate"
            path.write_text(instrumented_source(source))
            compiled = subprocess.run([self.rustc, "--edition=2021", "-C", "opt-level=2", "-C",
                "overflow-checks=on", "-C", "panic=abort", str(path), "-o", str(binary)],
                capture_output=True, text=True, timeout=35)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            inputs = self.pairs if pairs is None else pairs
            return subprocess.run([str(binary)], input="".join(f"{x} {y}\n" for x, y in inputs),
                                  capture_output=True, text=True, timeout=8)

    def test_reference_actual_vec_calls_produce_complete_per_invocation_ledgers(self):
        observed = self.run_candidate(self.reference)
        self.assertEqual(observed.returncode, 0, observed.stderr)
        self.assertEqual([int(line) for line in observed.stdout.splitlines()], self.expected)
        rows = [json.loads(line.removeprefix("HIA_RUST_AUDIT ")) for line in observed.stderr.splitlines()]
        self.assertEqual(len(rows), len(self.pairs))
        for epoch, (row, pair) in enumerate(zip(rows, self.pairs), 1):
            self.assertEqual(row["epoch"], epoch)
            self.assertEqual(row["length"], pair[0] % 17 + 1)
            self.assertEqual(row["index"], pair[1] % row["length"])
            self.assertEqual(row["expected_byte"], (pair[0] + pair[1]) % 256)
            self.assertEqual([row[k] for k in ("allocations", "releases", "explicit_releases", "live")], [1, 1, 1, 0])
            self.assertGreater(row["matched_reads"], 0)
            self.assertEqual([entry["event"] for entry in row["events"]],
                             ["allocate", "mutable_index", "indexed_read", "release"])

    def test_comment_and_uncalled_helper_cannot_satisfy_resource_task(self):
        shortcut = "256*(x%17+1)+x.wrapping_add(y)%256"
        for candidate in (
            "fn target(x:u32,y:u32)->u32 { /* vec![0u8;1]; drop(fake); fake[0] */ " + shortcut + " }",
            "fn unused(){let mut a=vec![0u8;1];a[0]=1;let _b=a[0];drop(a);}\n"
            "fn target(x:u32,y:u32)->u32 { " + shortcut + " }",
        ):
            with self.subTest(candidate=candidate):
                observed = self.run_candidate(candidate, pairs=[[2, 1000]])
                self.assertNotEqual(observed.returncode, 0)
                self.assertIn("E_AGENT_BUFFER_UNBALANCED_OR_IMPLICIT_RELEASE", observed.stderr)

    def test_implicit_drop_wrong_index_and_wrong_stored_value_are_rejected(self):
        variants = [self.reference.replace("drop(data);", ""),
                    self.reference.replace("data[index]=", "data[0]="),
                    self.reference.replace("x.wrapping_add(y) as u8", "0u8")]
        for candidate in variants:
            with self.subTest(candidate=candidate):
                observed = self.run_candidate(candidate, pairs=[[2, 1000]])
                self.assertNotEqual(observed.returncode, 0)
                self.assertIn("E_AGENT_BUFFER_", observed.stderr)

    def test_repeated_equivalent_accesses_are_allowed_and_huge_allocation_refuses_before_allocating(self):
        repeated = self.reference.replace("let readback=", "data[index]=x.wrapping_add(y) as u8;let _again=data[index];let readback=")
        observed = self.run_candidate(repeated)
        self.assertEqual(observed.returncode, 0, observed.stderr)
        self.assertEqual([int(line) for line in observed.stdout.splitlines()], self.expected)
        huge = self.reference.replace("vec![0u8;n]", "vec![0u8;4294967295usize]")
        refused = self.run_candidate(huge, pairs=[[2, 1000]])
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("E_AGENT_BUFFER_ALLOCATION_LENGTH", refused.stderr)


if __name__ == "__main__":
    unittest.main()
