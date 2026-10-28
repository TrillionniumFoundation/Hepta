"""Actual v8 loan contracts must survive every Agent interface boundary."""
from copy import deepcopy
import unittest

from hepta.hia_edit_batch import apply_batch, prepare_batch, render_batch_context
from hepta.hia_edit_query import apply_edit, prepare_edit, render_edit_context
from hepta.hia_optimization import verify_optimization
from hepta.hia_patch_impact import analyze_patch_impact
from hepta.hia_program import verify_program
from hepta.hia_program_runtime import execute_program
from hepta.hia_program_tools import HIAEditRejected, apply_program_patch, inspect_program
from hepta.hia_routes import route_inventory
from hepta.hia_translation_validation import validate_translation
from tests.test_hia_program import b, c, f, i, m, ret


def choose_loan():
    helper = f("pick", [("left", "readbuf"), ("right", "readbuf")], ["readbuf"], [], [
        b("entry", [("left", "readbuf"), ("right", "readbuf")],
          [c("marker", "u8", 1)], ret("left"))])
    helper["return_loans"] = ["left"]
    ops = [c("size", "usize", 1), c("zero", "usize", 0),
           c("left_byte", "u8", 17), c("right_byte", "u8", 29)]
    for name in ("left", "right"):
        ops += [i("buffer.new", ["size"], [(name + "_owner", "buffer")]),
                i("borrow.mut", [name + "_owner"], [(name + "_write", "mutbuf")]),
                i("buffer.store", [name + "_write", "zero", name + "_byte"]),
                i("loan.end", [name + "_write"]),
                i("borrow.read", [name + "_owner"], [(name + "_read", "readbuf")])]
    ops += [i("call", ["left_read", "right_read"], [("selected", "readbuf")], function="pick"),
            i("buffer.load", ["selected", "zero"], [("answer", "u8")]),
            i("loan.end", ["selected"]), i("loan.end", ["left_read"]),
            i("loan.end", ["right_read"]), i("owner.drop", ["left_owner"]),
            i("owner.drop", ["right_owner"])]
    main = f("entrypoint", [], ["u8"], ["alloc", "read", "write", "trap"], [b("entry", [], ops, ret("answer"))])
    document = m(main, helper)
    document["schema"] = "hepta.hia.program.v8"
    document["exports"] = ["entrypoint"]
    return document


def scalar(version=8):
    document = m(f("scalar", [], ["u32"], [], [b("entry", [], [c("seven", "u32", 7)], ret("seven"))]))
    document["schema"] = "hepta.hia.program.v" + str(version)
    return document


def select(output="left_byte", function="entrypoint"):
    return {"function": function, "block": "entry", "output": output, "fields": ["attrs"]}


def migration(source, schema="hepta.hia.patch.v2", policy="migrate"):
    replacement = deepcopy(source["functions"][1])
    replacement["return_loans"] = ["right"]
    replacement["blocks"][0]["term"] = ret("right")
    request = {"schema": schema, "expected_sha256": verify_program(source).sha256,
               "edits": [{"action": "replace_function", "function": "pick", "definition": replacement}]}
    if schema == "hepta.hia.patch.v2":
        request["interface_policy"] = policy
    return request


class ReturnedLoanInterfaceTests(unittest.TestCase):
    def test_inspection_has_versioned_normalized_contracts(self):
        source = choose_loan()
        view = inspect_program(source)
        self.assertEqual(view["schema"], "hepta.hia.inspect.v2")
        self.assertEqual([fn["return_loans"] for fn in view["functions"]], [[None], ["left"]])
        view["functions"][1]["return_loans"][0] = "right"
        self.assertEqual(source["functions"][1]["return_loans"], ["left"])

    def test_function_and_callee_context_expose_origin(self):
        source = choose_loan()
        query = prepare_edit(source, **select())
        self.assertEqual(query["schema"], "hepta.hia.edit-query.v3")
        self.assertEqual(query["context"]["function"]["return_loans"], [None])
        self.assertEqual(query["context"]["callees"][0]["return_loans"], ["left"])
        text = render_edit_context(query)
        self.assertIn('return_loans[null]', text)
        self.assertIn('"return_loans":["left"]', text)
        helper = prepare_edit(source, **select("marker", "pick"))
        self.assertIn('return_loans["left"]', render_edit_context(helper))

    def test_local_edit_executes_and_receipt_keeps_query_v3(self):
        source = choose_loan()
        candidate, receipt = apply_edit(source, prepare_edit(source, **select()), {"attrs": {"value": 31}})
        self.assertEqual(receipt["edit_query"]["schema"], "hepta.hia.edit-query.v3")
        run = execute_program(candidate, "entrypoint", [])
        self.assertEqual(run["result"], 31)
        self.assertEqual(run["resources"]["live_owners"], 0)
        self.assertEqual(run["resources"]["live_local_loans"], 0)
        self.assertEqual(execute_program(source, "entrypoint", [])["result"], 17)

    def test_source_reconstruction_rejects_structurally_plausible_origin_forgery(self):
        source = choose_loan()
        for selector, key in ((select(), "callees"), (select("marker", "pick"), "function")):
            query = prepare_edit(source, **selector)
            signature = query["context"][key]
            if key == "callees":
                signature = signature[0]
            signature["return_loans"] = ["right"]
            # A renderer has no source oracle; both parameter names are valid.
            render_edit_context(query)
            with self.assertRaises(HIAEditRejected):
                apply_edit(source, query, {"attrs": {"value": 31}})

    def test_render_rejects_malformed_and_permission_escalating_contracts(self):
        query = prepare_edit(choose_loan(), **select("marker", "pick"))
        mutations = (
            lambda sig: sig.pop("return_loans"),
            lambda sig: sig.__setitem__("return_loans", []),
            lambda sig: sig.__setitem__("return_loans", [None]),
            lambda sig: sig.__setitem__("return_loans", ["missing"]),
            lambda sig: sig.__setitem__("return_loans", {"0": "left"}),
            lambda sig: sig["params"][0].__setitem__("type", "buffer"),
            lambda sig: sig.__setitem__("returns", ["mutbuf"]),
            lambda sig: sig.__setitem__("unexpected", True),
        )
        for change in mutations:
            bad = deepcopy(query)
            change(bad["context"]["function"])
            with self.subTest(change=change), self.assertRaises(HIAEditRejected):
                render_edit_context(bad)
        scalar_query = prepare_edit(scalar(), **select("seven", "scalar"))
        scalar_query["context"]["function"]["return_loans"] = ["seven"]
        with self.assertRaises(HIAEditRejected):
            render_edit_context(scalar_query)

    def test_single_query_downgrade_never_becomes_an_apply_authority(self):
        source = choose_loan()
        query = prepare_edit(source, **select())
        query["schema"] = "hepta.hia.edit-query.v2"
        with self.assertRaises(HIAEditRejected):
            render_edit_context(query)
        for signature in [query["context"]["function"], *query["context"]["callees"]]:
            signature.pop("return_loans")
        render_edit_context(query)
        with self.assertRaises(HIAEditRejected):
            apply_edit(source, query, {"attrs": {"value": 31}})

    def test_batch_keeps_contracts_and_executes_atomic_value_edits(self):
        source = choose_loan()
        query = prepare_batch(source, [select(), select("right_byte")])
        self.assertEqual(query["schema"], "hepta.hia.edit-batch-query.v3")
        self.assertTrue(all(site["query"]["schema"] == "hepta.hia.edit-query.v3" for site in query["sites"]))
        text = render_batch_context(query)
        self.assertEqual(text.count('"return_loans":["left"]'), 1)
        self.assertIn('return_loans[null]', text)
        candidate, receipt = apply_batch(source, query, {"edits": [
            {"site": 0, "changes": {"attrs": {"value": 31}}},
            {"site": 1, "changes": {"attrs": {"value": 47}}}]})
        self.assertEqual(receipt["edit_batch"]["schema"], "hepta.hia.edit-batch-query.v3")
        self.assertEqual(execute_program(candidate, "entrypoint", [])["result"], 31)

    def test_batch_conflicting_origin_downgrade_and_forged_consensus_reject(self):
        source = choose_loan()
        original = prepare_batch(source, [select(), select("right_byte")])
        bad = deepcopy(original)
        bad["sites"][1]["query"]["context"]["callees"][0]["return_loans"] = ["right"]
        with self.assertRaisesRegex(HIAEditRejected, "conflicting"):
            render_batch_context(bad)
        for site in bad["sites"]:
            site["query"]["context"]["callees"][0]["return_loans"] = ["right"]
        render_batch_context(bad)
        response = {"edits": [{"site": index, "changes": {"attrs": {"value": 31}}} for index in range(2)]}
        with self.assertRaises(HIAEditRejected):
            apply_batch(source, bad, response)
        for nested in (False, True):
            bad = deepcopy(original)
            if nested:
                bad["sites"][0]["query"]["schema"] = "hepta.hia.edit-query.v2"
            else:
                bad["schema"] = "hepta.hia.edit-batch-query.v2"
            with self.subTest(nested=nested), self.assertRaises(HIAEditRejected):
                render_batch_context(bad)
            with self.assertRaises(HIAEditRejected):
                apply_batch(source, bad, response)

    def test_interface_preservation_includes_loan_origin(self):
        source = choose_loan()
        for schema in ("hepta.hia.patch.v1", "hepta.hia.patch.v2"):
            with self.subTest(schema=schema), self.assertRaisesRegex(HIAEditRejected, "interface change"):
                apply_program_patch(source, migration(source, schema, "preserve"))
        candidate, receipt = apply_program_patch(source, migration(source))
        self.assertEqual(receipt["interface_changes"], ["pick"])
        self.assertFalse(receipt["claims"]["interface_preserved"])
        self.assertFalse(receipt["claims"]["external_callers_revalidated"])
        self.assertEqual(execute_program(candidate, "entrypoint", [])["result"], 29)

    def test_migration_impact_tracks_direct_and_transitive_callers(self):
        source = choose_loan()
        source["functions"] += [
            f("through_entry", [], ["u8"], ["alloc", "read", "write", "trap"], [b("entry", [], [
                i("call", [], [("answer", "u8")], function="entrypoint")], ret("answer"))]),
            f("unrelated", [], ["u32"], [], [b("entry", [], [c("answer", "u32", 7)], ret("answer"))])]
        source["exports"] += ["through_entry", "unrelated"]
        candidate, receipt, impact = analyze_patch_impact(source, migration(source))
        self.assertEqual(receipt["interface_changes"], ["pick"])
        self.assertEqual(impact["interface_changed_functions"], ["pick"])
        self.assertEqual(impact["direct_changed_functions"], ["pick"])
        self.assertEqual(impact["potentially_affected_functions"], ["entrypoint", "pick", "through_entry"])
        self.assertEqual(impact["unaffected_by_static_callgraph"], ["unrelated"])
        edges = [{"caller": "entrypoint", "callee": "pick"}, {"caller": "through_entry", "callee": "entrypoint"}]
        self.assertEqual(impact["old_call_edges"], edges)
        self.assertEqual(impact["new_call_edges"], edges)
        run = execute_program(candidate, "through_entry", [])
        self.assertEqual(run["result"], 29)
        self.assertEqual(run["resources"]["live_owners"], 0)
        self.assertEqual(run["resources"]["live_local_loans"], 0)

    def test_explicit_and_implicit_null_contracts_have_one_interface(self):
        for explicit_before in (False, True):
            source = scalar()
            if explicit_before:
                source["functions"][0]["return_loans"] = [None]
            replacement = deepcopy(source["functions"][0])
            if explicit_before:
                replacement.pop("return_loans")
            else:
                replacement["return_loans"] = [None]
            candidate, receipt, impact = analyze_patch_impact(source, {
                "schema": "hepta.hia.patch.v1", "expected_sha256": verify_program(source).sha256,
                "edits": [{"action": "replace_function", "function": "scalar", "definition": replacement}]})
            self.assertEqual(receipt["interface_changes"], [])
            self.assertEqual(impact["interface_changed_functions"], [])
            self.assertEqual(execute_program(candidate, "scalar", [])["result"], 7)

    def test_old_versions_retain_their_wire_protocols(self):
        for version in range(1, 8):
            source = scalar(version)
            selection = select("seven", "scalar")
            query, batch = prepare_edit(source, **selection), prepare_batch(source, [selection])
            with self.subTest(version=version):
                self.assertEqual(query["schema"], "hepta.hia.edit-query.v2")
                self.assertEqual(batch["schema"], "hepta.hia.edit-batch-query.v2")
                self.assertEqual(inspect_program(source)["schema"], "hepta.hia.inspect.v1")
                self.assertNotIn("return_loans", query["context"]["function"])
                render_edit_context(query)
                render_batch_context(batch)

    def test_v8_does_not_inherit_existing_optimization_proof_qualification(self):
        for source in (scalar(), choose_loan()):
            compositional = verify_optimization(source, source)
            selected = validate_translation(source, source, function=source["functions"][0]["name"])
            self.assertEqual(compositional["status"], "unknown")
            self.assertIn("v1-v7", compositional["reason"])
            self.assertEqual(compositional["resource_delta"], {})
            self.assertEqual(selected["status"], "unknown")
            self.assertEqual(selected["reason"], "core_schema_outside_qualified_v1_v7_profile")
        # Actual pinned Z3 is required for these positive controls, not mocked.
        self.assertEqual(verify_optimization(scalar(7), scalar(7))["status"], "verified")
        self.assertEqual(validate_translation(scalar(7), scalar(7))["status"], "proved")

    def test_routes_show_current_admission_and_distinct_proof_boundary(self):
        inventory = route_inventory()
        self.assertIn("v1-v8", inventory["inputs"][0]["input"])
        self.assertEqual(inventory["versions"]["latest_core_schema"], "hepta.hia.program.v8")
        self.assertTrue(all("v1-v7" in entry["scope"] for entry in inventory["optimization_profiles"][:2]))


if __name__ == "__main__":
    unittest.main()
