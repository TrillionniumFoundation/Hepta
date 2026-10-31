"""Executable discovery, version isolation, and mandatory resource guards."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from hepta.hia_agent_assembly import assemble_program, render_assembly
from hepta.hia_incremental import IncrementalVerifier
from hepta.hia_opcodes import (OPCODES, TRAP_CODES, OpcodeRejected, check_instruction,
                               opcode_catalog, opcode_spec, render_opcode_reference)
from hepta.hia_program import HIAProgramRejected, verify_program
from hepta.hia_program_runtime import HIAProgramTrap, execute_program
from hepta.hia_schema import SCHEMA_V8, schema_registry
from tests.test_hia_program import arithmetic, b, c, f, i, m, resource_program, ret
from tests.test_hia_returned_loans import loan_program, multiple_shared

ROOT = Path(__file__).resolve().parents[1]


class OpcodeCatalogTests(unittest.TestCase):
    def test_closed_inventory_contains_real_comparisons_and_every_version(self):
        expected = {"const", "select", "int.cast", "call", "int.neg.checked",
                    "borrow.read", "borrow.mut", "loan.end", "owner.move", "owner.drop",
                    "buffer.new", "buffer.try_new", "buffer.len", "buffer.load", "buffer.store",
                    "buffer.fill", "buffer.copy", "buffer.move_within", "buffer.swap",
                    "buffer.copy_range", "buffer.fill_range", "chain.empty", "chain.try_push",
                    "chain.pop", "chain.is_empty", "chain.head_read", "chain.head_mut"}
        expected |= {f"int.{op}.{mode}" for op in ("add", "sub", "mul") for mode in ("wrap", "checked")}
        expected |= {f"int.{op}.checked" for op in ("div", "rem", "shl", "shr")}
        expected |= {"compare." + op for op in ("eq", "ne", "lt", "le", "gt", "ge")}
        expected |= {"bit." + op for op in ("not", "and", "or", "xor")}
        expected |= {"bool." + op for op in ("not", "and", "or")}
        catalog = opcode_catalog()
        self.assertEqual({row["name"] for row in catalog["instructions"]}, expected)
        self.assertEqual({row["name"] for row in catalog["terminators"]}, {"ret", "jump", "branch", "trap"})
        for version in range(1, 9):
            rows = opcode_catalog(f"hepta.hia.program.v{version}")["instructions"]
            self.assertEqual({row["name"] for row in rows}, {name for name in expected if OPCODES[name].since <= version})
        for guessed in ("int.lt", "int.gt", "cmp.lt", "int.cmp.lt", "alloc", "load"):
            with self.assertRaises(OpcodeRejected):
                opcode_spec(guessed)

    def test_reviewed_safety_registry_is_bound_to_generated_v8_catalog(self):
        # The safety matrix is an independently reviewed identity, not
        # admission authority. A catalog fix must update that exact review
        # before the full source-bound safety suite can qualify.
        contract = json.loads((ROOT / "docs/HIA_SAFETY_CONTRACT.json").read_text())
        reviewed = contract["registry"]["instruction_catalog"]
        generated = json.loads(json.dumps(opcode_catalog()))
        self.assertEqual(reviewed, generated,
                         "E_SAFETY_REGISTRY: reviewed v8 catalog drift")

    def test_catalog_is_detached_and_invalid_schemas_do_not_guess(self):
        detached = opcode_catalog()
        detached["instructions"][0]["name"] = "forged"
        self.assertNotEqual(opcode_catalog()["instructions"][0]["name"], "forged")
        self.assertEqual(schema_registry()["instruction_catalog"], opcode_catalog())
        for unknown in ("hepta.hia.composite.v4", "hepta.hia.program.v99", "v8"):
            with self.assertRaises(OpcodeRejected):
                opcode_catalog(unknown)

    def test_versioned_type_groups_never_offer_types_rejected_by_that_version(self):
        for version in range(1, 9):
            catalog = opcode_catalog(f"hepta.hia.program.v{version}")
            visible = set(catalog["types"])
            for group, members in catalog["type_groups"].items():
                with self.subTest(version=version, group=group):
                    self.assertLessEqual(set(members), visible)
            self.assertEqual("chain" in catalog["type_groups"]["owner"], version >= 7)
        document = m(f("empty", [], [], ["alloc"], [b("entry", [], [
            i("chain.empty", [], [("owned", "chain")]), i("owner.drop", ["owned"]),
        ], ret())]))
        document["schema"] = "hepta.hia.program.v6"
        with self.assertRaises(HIAProgramRejected):
            verify_program(document)
        document["schema"] = "hepta.hia.program.v7"
        self.assertEqual(execute_program(document, "empty", [])["status"], "returned")

    def test_generated_docs_and_cli_are_the_actual_catalog(self):
        self.assertEqual((ROOT / "docs/HIA_OPCODE_REFERENCE.md").read_text(), render_opcode_reference())
        self.assertEqual(json.loads((ROOT / "docs/hia-opcode-catalog.v8.json").read_text()),
                         json.loads(json.dumps(opcode_catalog())))
        run = subprocess.run([sys.executable, "-B", "-m", "hepta", "hia", "catalog", "--schema", SCHEMA_V8],
                             cwd=ROOT, text=True, capture_output=True, timeout=20)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(json.loads(run.stdout), json.loads(json.dumps(opcode_catalog())))

    def test_local_signature_effect_and_attribute_constraints_are_live(self):
        original = arithmetic()
        variants = []
        wrong_type = deepcopy(original)
        wrong_type["functions"][0]["blocks"][0]["ops"][0]["out"][0]["type"] = "u64"
        variants.append(wrong_type)
        wrong_effect = deepcopy(original)
        wrong_effect["functions"][0]["effects"] = []
        variants.append(wrong_effect)
        wrong_attribute = deepcopy(original)
        wrong_attribute["functions"][0]["blocks"][0]["ops"][0]["attrs"] = {"unchecked": True}
        variants.append(wrong_attribute)
        wrong_arity = deepcopy(original)
        wrong_arity["functions"][0]["blocks"][0]["ops"][0]["args"].pop()
        variants.append(wrong_arity)
        for document in variants:
            with self.subTest(document=document), self.assertRaises(HIAProgramRejected):
                verify_program(document)
        self.assertEqual(execute_program(original, "calculate", [17, 29])["result"], 46)
        # Changing only the central row changes the actual check, which proves
        # this is consumed metadata rather than a disconnected help table.
        bad = replace(OPCODES["int.add.checked"], operands=())
        with patch("hepta.hia_program.opcode_spec", return_value=bad):
            with self.assertRaises(HIAProgramRejected):
                verify_program(original)

    def test_all_six_comparisons_are_executable_discovered_spellings(self):
        functions = {"eq": lambda a, b: a == b, "ne": lambda a, b: a != b,
                     "lt": lambda a, b: a < b, "le": lambda a, b: a <= b,
                     "gt": lambda a, b: a > b, "ge": lambda a, b: a >= b}
        for op, oracle in functions.items():
            document = m(f("compare", [("a", "i32"), ("b", "i32")], ["bool"], [],
                [b("entry", [("a", "i32"), ("b", "i32")], [i("compare." + op, ["a", "b"], [("r", "bool")])], ret("r"))]))
            for left, right in ((-1, 1), (7, 7), (9, -4)):
                self.assertEqual(execute_program(document, "compare", [left, right])["result"], oracle(left, right))

    def test_guards_do_not_allow_live_owner_drop_or_unended_loans(self):
        original = resource_program()
        for index in (4, 7):
            broken = deepcopy(original)
            del broken["functions"][0]["blocks"][0]["ops"][index]
            with self.assertRaises(HIAProgramRejected):
                verify_program(broken)
        broken = deepcopy(original)
        broken["functions"][0]["blocks"][0]["ops"][-1]["args"] = ["owner"]
        with self.assertRaises(HIAProgramRejected):
            verify_program(broken)
        self.assertEqual(execute_program(original, "owned", [4, 119])["result"], 119)

    def test_bulk_version_is_checked_by_table_even_for_valid_types(self):
        args = [("view", "mutbuf"), ("value", "u8")]
        document = m(f("fill", args, [], ["write"], [b("entry", args, [i("buffer.fill", ["view", "value"])], ret())]))
        # Not an exported resource entry. A well-formed internal function still
        # has to respect its explicitly selected primitive grammar.
        document["exports"] = []
        with self.assertRaises(HIAProgramRejected) as caught:
            verify_program(document)
        self.assertEqual(caught.exception.code, "E_HIA_OPCODE")
        document["schema"] = "hepta.hia.program.v2"
        verify_program(document)

    def test_cache_invalidates_when_imported_opcode_checker_changes(self):
        source = arithmetic()
        session = IncrementalVerifier(source)
        from hepta import hia_program as core
        original = core.check_instruction
        calls = []
        def observed(*args):
            calls.append(args[0].name)
            return original(*args)
        with patch("hepta.hia_program.check_instruction", side_effect=observed):
            session.verify(source)
        self.assertIn("int.add.checked", calls)

    def test_cache_cannot_keep_literal_after_catalog_width_rebinding(self):
        from hepta import hia_opcodes as opcodes
        source = m(f("literal", [], ["i32"], [],
                     [b("entry", [], [c("number", "i32", 65536)], ret("number"))]))
        session = IncrementalVerifier(source)
        changed = dict(opcodes.WIDTHS)
        changed["i32"] = 16
        with patch.object(opcodes, "WIDTHS", changed):
            with self.assertRaises(HIAProgramRejected):
                verify_program(source)
            with self.assertRaises(HIAProgramRejected):
                session.verify(source)


    def test_trap_catalog_uses_executable_codes_for_conditional_cast(self):
        # Regression: the original catalog published "overflow_when_checked",
        # which is not any HIA runtime trap code. The mode is conditional,
        # but the advertised possible trap must be the actual "overflow".
        for version in range(1, 9):
            with self.subTest(core_version=version):
                catalog = opcode_catalog(f"hepta.hia.program.v{version}")
                for instruction in catalog["instructions"]:
                    self.assertFalse(
                        set(instruction["traps"]) - TRAP_CODES,
                        (instruction["name"], instruction["traps"]),
                    )
                cast = next(row for row in catalog["instructions"]
                            if row["name"] == "int.cast")
                self.assertEqual(cast["traps"], ["overflow"])

        self.assertEqual(check_instruction(OPCODES["int.cast"], ["u64"], ["i8"],
                                           {"mode": "wrap"}), frozenset())
        self.assertEqual(check_instruction(OPCODES["int.cast"], ["u64"], ["i8"],
                                           {"mode": "checked"}), frozenset({"trap"}))
        for mode in ("wrap", "checked"):
            document = m(f("cast", [("input", "u64")], ["i8"],
                           ["trap"] if mode == "checked" else [], [
                b("entry", [("input", "u64")], [
                    i("int.cast", ["input"], [("result", "i8")], mode=mode),
                ], ret("result")),
            ]))
            document["schema"] = SCHEMA_V8
            verified = verify_program(document)
            self.assertEqual(execute_program(verified, "cast", [127])["result"], 127)
            if mode == "checked":
                with self.assertRaises(HIAProgramTrap) as error:
                    execute_program(verified, "cast", [255])
                self.assertEqual(error.exception.code, "overflow")
                invalid = deepcopy(document)
                invalid["functions"][0]["effects"] = []
                with self.assertRaises(HIAProgramRejected):
                    verify_program(invalid)
            else:
                self.assertEqual(execute_program(verified, "cast", [255])["result"], -1)

class AssemblyV8ContractTests(unittest.TestCase):
    def test_returned_read_mutable_and_cfg_loans_roundtrip_and_execute(self):
        for mode in ("read", "mut"):
            for construction in ("forward", "child", "cfg", "recursive"):
                original = verify_program(loan_program(mode, construction))
                rendered = render_assembly(original)
                self.assertIn('return_loans(["input"])', rendered)
                restored = assemble_program(rendered)
                self.assertEqual(restored.canonical_bytes, original.canonical_bytes)
                fn = f"entry_{mode}_{construction}"
                for length, value in ((1, 0), (7, 255)):
                    self.assertEqual(execute_program(restored, fn, [length, value]),
                                     execute_program(original, fn, [length, value]))

    def test_explicit_contract_and_absence_remain_distinct(self):
        document = arithmetic()
        document["schema"] = SCHEMA_V8
        for explicit in (False, True):
            value = deepcopy(document)
            if explicit:
                value["functions"][0]["return_loans"] = [None]
            original = verify_program(value)
            self.assertEqual(assemble_program(render_assembly(original)).canonical_bytes, original.canonical_bytes)

    def test_wrong_origin_downgrade_and_malformed_contract_refuse(self):
        source = render_assembly(loan_program())
        for bad in (source.replace('["input"]', '["missing"]'),
                    source.replace(SCHEMA_V8, "hepta.hia.program.v7"),
                    source.replace('["input"]', '{"input":"input"}'),
                    source.replace('["input"]', '[NaN]'),
                    source.replace(' return_loans(["input"])', '')):
            with self.subTest(source=bad), self.assertRaises(HIAProgramRejected):
                assemble_program(bad)


if __name__ == "__main__":
    unittest.main()
