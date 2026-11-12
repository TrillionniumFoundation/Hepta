"""Real node edits and adversarial transaction controls, without inference."""
import copy
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from experiments.hia_agent_factorial_v4_20261028 import calibration, evaluator
from experiments.hia_agent_structured_v7_20261029 import editing as edit
from experiments.hia_agent_structured_v7_20261029.rust_syntax import MAX_DEPTH, SyntaxRejected, parse_function, validate_fragment
from experiments.hia_agent_structured_v7_20261029.session import ValidatedTaskSession
from hepta.hia_program import HIAProgramRejected
from hepta.hia_program_runtime import execute_program
from tests.test_hia_edit_batch import loans
from tests.test_hia_program import b, c, f, i, ret


def rust_project():
    return {"api.rs": "pub fn span(a:u32,b:u32)->u64 { 2*(a as u64)+(b as u64) }",
            "client.rs": "use crate::api; pub fn entrypoint(a:u32,b:u32,c:u32)->u64 { api::span(a,b)+(c as u64) }",
            "audit.rs": "pub fn audit_tag(c:u32)->u32 { c & 7 }",
            "utility.rs": "pub fn utility(x:u32)->u32 { x & 255 }"}


SYMBOLS = {"api.rs": "span", "client.rs": "entrypoint"}


def rust_node(query, file, text, category="expression"):
    matches = [n for n in query["nodes"] if n["file"] == file and n["text"] == text and n["category"] == category]
    if len(matches) != 1:
        raise AssertionError((file, text, len(matches)))
    return matches[0]["id"]


def upgrade_program():
    api = f("identity", [("x", "u16")], ["u16"], [], [b("entry", [("x", "u16")], [], ret("x"))])
    client = f("entrypoint", [("a", "u32")], ["u32"], [], [b("entry", [("a", "u32")], [
        i("int.cast", ["a"], [("small", "u16")], mode="wrap"),
        i("call", ["small"], [("result", "u16")], function="identity"),
        i("int.cast", ["result"], [("wide", "u32")], mode="wrap")], ret("wide"))])
    return {"schema": "hepta.hia.program.v6", "module": "node_upgrade", "exports": ["entrypoint"], "functions": [api, client]}


class StructuredRustTests(unittest.TestCase):
    def setUp(self):
        self.source = rust_project()
        self.query = edit.prepare_rust(self.source, SYMBOLS)

    def apply(self, edits, query=None, source=None):
        return edit.propose_rust(source or self.source, query or self.query,
                                 edit.response_for(query or self.query, edits), editable_symbols=SYMBOLS)

    def test_actual_expression_node_preserves_every_other_source_byte(self):
        ident = rust_node(self.query, "api.rs", "2")
        candidate, receipt = self.apply([{"node": ident, "changes": {"text": "4"}}])
        self.assertEqual(candidate["api.rs"], self.source["api.rs"].replace("2*", "4*"))
        self.assertEqual({n:v for n,v in candidate.items() if n != "api.rs"}, {n:v for n,v in self.source.items() if n != "api.rs"})
        self.assertEqual(self.source, rust_project())
        self.assertEqual(receipt["whole_functions_supplied_by_model"], 0)
        self.assertFalse(receipt["type_or_ownership_admitted"])
        self.assertTrue(receipt["unselected_ast_context_preserved"])

    def test_query_binds_even_unchanged_source_files(self):
        changed = dict(self.source); changed["utility.rs"] += "\n"
        with self.assertRaisesRegex(edit.EditRejected, "stale or altered"):
            self.apply([{"node": rust_node(self.query,"api.rs","2"), "changes": {"text":"4"}}], source=changed)

    def test_altered_catalogue_profile_or_digest_cannot_grant_authority(self):
        for mutate in (lambda q:q["nodes"].pop(), lambda q:q.__setitem__("profile","arbitrary"),
                       lambda q:q.__setitem__("query_sha256","0"*64), lambda q:q["editable_symbols"].update({"utility.rs":"utility"})):
            query = copy.deepcopy(self.query); mutate(query)
            with self.assertRaises(edit.EditRejected):
                self.apply([{"node": rust_node(self.query,"api.rs","2"), "changes":{"text":"4"}}], query=query)

    def test_unknown_duplicate_and_whole_file_edits_refuse(self):
        item = {"node": rust_node(self.query,"api.rs","2"), "changes":{"text":"4"}}
        for edits in ([item,item], [{"node":"utility.rs/utility/n0","changes":{"text":"0"}}],
                      [{"node":item["node"],"changes":{"files":{"api.rs":"replacement"}}}]):
            with self.assertRaises(edit.EditRejected):
                self.apply(edits)

    def test_overlapping_ancestor_and_descendant_nodes_refuse(self):
        parent = rust_node(self.query,"api.rs","2*(a as u64)")
        child = rust_node(self.query,"api.rs","2")
        with self.assertRaisesRegex(edit.EditRejected,"overlapping"):
            self.apply([{"node":parent,"changes":{"text":"a as u64"}}, {"node":child,"changes":{"text":"4"}}])
        self.assertEqual(self.source, rust_project())

    def test_fragment_escape_and_macro_source_refuse_without_mutation(self):
        for replacement in ("4; drop(a)", "4 } pub fn escape()->u64 { 0", "{ macro_rules! x { () => { 0 }; } x!() }", "$a", "4 // comment"):
            with self.assertRaises((edit.EditRejected, SyntaxRejected)):
                self.apply([{"node":rust_node(self.query,"api.rs","2"),"changes":{"text":replacement}}])
            self.assertEqual(self.source, rust_project())

    def test_precedence_change_outside_selected_node_fails_closed(self):
        ident = rust_node(self.query,"api.rs","2")
        with self.assertRaisesRegex(edit.EditRejected,"enclosing or unselected"):
            self.apply([{"node":ident,"changes":{"text":"2+3"}}])
        candidate, _ = self.apply([{"node":ident,"changes":{"text":"(2+3)"}}])
        self.assertIn("(2+3)*(a as u64)", candidate["api.rs"])

    def test_crlf_offsets_are_exact_ascii_bytes_and_unicode_refuses(self):
        source = {name:text.replace(" {", "\r\n {") for name,text in self.source.items()}
        query = edit.prepare_rust(source,SYMBOLS)
        candidate, _ = edit.propose_rust(source,query,edit.response_for(query,[{"node":rust_node(query,"api.rs","2"),"changes":{"text":"4"}}]),editable_symbols=SYMBOLS)
        self.assertEqual(candidate["api.rs"],source["api.rs"].replace("2*","4*"))
        source["api.rs"] += "é"
        with self.assertRaises(edit.EditRejected):
            edit.prepare_rust(source,SYMBOLS)

    def test_type_fragment_does_not_allow_parameter_or_statement_injection(self):
        source = {"api.rs":"pub fn span(a:u16,b:u16)->u32 { (a as u32)*(b as u32) }", **{k:v for k,v in self.source.items() if k!='api.rs'}}
        query = edit.prepare_rust(source,SYMBOLS,interface_policy="migrate")
        ident = next(n["id"] for n in query["nodes"] if n["file"]=="api.rs" and n["category"]=="type" and n["text"]=="u16")
        with self.assertRaises(SyntaxRejected):
            edit.propose_rust(source,query,edit.response_for(query,[{"node":ident,"changes":{"text":"u32,c:u32"}}]),editable_symbols=SYMBOLS,interface_policy="migrate")
        candidate, _ = edit.propose_rust(source,query,edit.response_for(query,[{"node":ident,"changes":{"text":"u32"}}]),editable_symbols=SYMBOLS,interface_policy="migrate")
        self.assertTrue(candidate["api.rs"].startswith("pub fn span(a:u32,b:u16)"))

    def test_signature_nodes_require_host_migration_authority(self):
        node = next(n for n in self.query["nodes"] if n.get("role")=="parameter_type")
        self.assertEqual(node["fields"],[])
        with self.assertRaisesRegex(edit.EditRejected,"selected node fields"):
            self.apply([{"node":node["id"],"changes":{"text":"u16"}}])

    def test_source_revision_and_query_digest_both_required(self):
        value=edit.response_for(self.query,[{"node":rust_node(self.query,"api.rs","2"),"changes":{"text":"4"}}])
        for key in ("base_sha256","query_sha256"):
            wrong=copy.deepcopy(value);wrong[key]="0"*64
            with self.assertRaisesRegex(edit.EditRejected,"stale response"):
                edit.propose_rust(self.source,self.query,wrong,editable_symbols=SYMBOLS)

    def test_else_if_and_iterative_postfix_respect_64_level_depth(self):
        # The leaf is one level: 63 enclosing if/call nodes produce depth 64;
        # a 64th enclosing node would produce depth 65 and must be refused.
        for build in (lambda n:"if true {} else "*n+"{}",
                      lambda n:"0"+".wrapping_add(0)"*n):
            validate_fragment(build(MAX_DEPTH-1),"expression")
            with self.assertRaisesRegex(SyntaxRejected,"depth"):
                validate_fragment(build(MAX_DEPTH),"expression")


class StructuredHIATests(unittest.TestCase):
    def test_atomic_loan_swap_uses_real_production_batch(self):
        source=loans(); query=edit.prepare_hia(source,["work"])
        response=edit.response_for(query,[{"node":"work/entry/instruction3","changes":{"args":["z"]}},
                                          {"node":"work/entry/instruction4","changes":{"args":["a"]}}])
        changed,receipt=edit.apply_hia(source,query,response,editable_functions=["work"])
        self.assertEqual(receipt["structured_editor"]["backend"],"production_apply_batch")
        self.assertFalse(receipt["edit_batch"]["intermediate_candidates_admitted"])
        self.assertEqual(execute_program(changed,"work",[])["result"],0)
        self.assertEqual(source,loans())

    def test_failed_whole_module_ownership_check_is_atomic(self):
        source=loans();query=edit.prepare_hia(source,["work"])
        with self.assertRaises(HIAProgramRejected):
            edit.apply_hia(source,query,edit.response_for(query,[{"node":"work/entry/instruction3","changes":{"args":["z"]}}]),editable_functions=["work"])
        self.assertEqual(source,loans())

    def test_interface_upgrade_is_explicit_node_edits_and_reported_container_rebuild(self):
        source=upgrade_program();query=edit.prepare_hia(source,["identity","entrypoint"],interface_policy="migrate")
        params=[{"name":"x","type":"u32"}]
        changes=[{"node":"identity/signature","changes":{"params":params,"returns":["u32"]}},
                 {"node":"identity/entry/parameters","changes":{"params":params}},
                 {"node":"entrypoint/entry/instruction0","changes":{"out":[{"name":"small","type":"u32"}]}},
                 {"node":"entrypoint/entry/instruction1","changes":{"out":[{"name":"result","type":"u32"}]}}]
        changed,receipt=edit.apply_hia(source,query,edit.response_for(query,changes),editable_functions=["identity","entrypoint"],interface_policy="migrate")
        self.assertEqual(execute_program(source,"entrypoint",[70000])["result"],4464)
        self.assertEqual(execute_program(changed,"entrypoint",[70000])["result"],70000)
        self.assertEqual(receipt["structured_editor"]["container_rebuilt_functions"],["identity"])
        self.assertEqual(receipt["structured_editor"]["whole_functions_supplied_by_model"],0)
        self.assertFalse(receipt["claims"]["external_callers_revalidated"])
        preserved=edit.prepare_hia(source,["identity","entrypoint"])
        with self.assertRaises(edit.EditRejected):
            edit.apply_hia(source,preserved,edit.response_for(preserved,changes),editable_functions=["identity","entrypoint"])

    def test_insert_and_terminator_change_are_atomic_without_implicit_repair(self):
        source={"schema":"hepta.hia.program.v6","module":"insertions","functions":[f("work",[("x","u32")],["u32"],[],[b("entry",[("x","u32")],[c("factor","u32",2),i("int.mul.wrap",["x","factor"],[("value","u32")])],ret("value"))])]}
        query=edit.prepare_hia(source,["work"])
        response=edit.response_for(query,[{"node":"work/entry/insert2","changes":{"operations":[c("one","u32",1),i("int.add.wrap",["value","one"],[("adjusted","u32")])]}},
                                          {"node":"work/entry/terminator","changes":{"term":ret("adjusted")}}])
        changed,receipt=edit.apply_hia(source,query,response,editable_functions=["work"])
        self.assertEqual(execute_program(changed,"work",[7])["result"],15)
        self.assertEqual(receipt["structured_editor"]["container_rebuilt_functions"],["work"])

    def test_source_bound_scope_unknown_node_duplicate_and_delete_failure(self):
        source=loans();query=edit.prepare_hia(source,["work"])
        for edits in ([{"node":"work/entry/instruction0","changes":{"delete":True}}],
                      [{"node":"not_allowed/entry/instruction0","changes":{"attrs":{"value":2}}}],
                      [{"node":"work/entry/instruction0","changes":{"attrs":{"value":2}}}]*2):
            with self.assertRaises((edit.EditRejected,HIAProgramRejected)):
                edit.apply_hia(source,query,edit.response_for(query,edits),editable_functions=["work"])
            self.assertEqual(source,loans())
        altered=copy.deepcopy(query);altered["nodes"].pop()
        with self.assertRaisesRegex(edit.EditRejected,"stale or altered"):
            edit.apply_hia(source,altered,edit.response_for(altered,[{"node":"work/entry/instruction0","changes":{"attrs":{"value":2}}}]),editable_functions=["work"])


class StructuredTransactionMockTests(unittest.TestCase):
    """Mocks isolate transaction ordering, never count as native controls."""
    def fixture(self):
        task=calibration.problems()[0]
        session=ValidatedTaskSession(task,"rust",clang="unused",rustc="unused")
        query=session.query()
        edits=[{"node":rust_node(query["edit_query"],"api.rs","(a as u64)"),"changes":{"text":"(4*(a as u64))"}},
               {"node":rust_node(query["edit_query"],"client.rs","api::span(a,b)"),"changes":{"text":"api::span(a,b)+(c as u64)"}}]
        observed={"status":"correct","artifact_unchanged":True,"observations":task["public_expected"],
                  "expected":task["public_expected"],"resource_contract_passed":True,"vm_contract_passed":True}
        return session,session.response(query,edits),observed

    def test_concurrent_old_revision_cannot_overwrite_first_commit(self):
        session,response,observed=self.fixture()
        entered,release,second_started=threading.Event(),threading.Event(),threading.Event()
        results={}
        def build(*args,**kwargs):
            entered.set()
            if not release.wait(3):
                raise RuntimeError("test release barrier expired")
            return {"native_built":True,"status":"compiled"}
        with tempfile.TemporaryDirectory() as folder, patch.object(evaluator,"build",side_effect=build) as builder, patch.object(evaluator,"execute",return_value=observed):
            first=threading.Thread(target=lambda:results.update(first=session.apply(response,Path(folder)/"first")),daemon=True)
            def second_call():
                second_started.set();results["second"]=session.apply(response,Path(folder)/"second")
            second=threading.Thread(target=second_call,daemon=True)
            first.start()
            try:
                self.assertTrue(entered.wait(2))
                second.start();self.assertTrue(second_started.wait(2))
            finally:
                release.set()
            first.join(3);second.join(3)
            self.assertFalse(first.is_alive());self.assertFalse(second.is_alive())
            self.assertTrue(results["first"]["accepted"])
            self.assertFalse(results["second"]["accepted"])
            self.assertIn("stale project revision",results["second"]["error"]["message"])
            self.assertEqual(builder.call_count,1)
            self.assertEqual(session.revision,results["first"]["after_revision"])

    def test_receipt_write_failure_does_not_advance_source(self):
        session,response,observed=self.fixture();before=session.revision;original=evaluator.save
        def save(path,value):
            if Path(path).name=="TRANSACTION.json":
                raise OSError("simulated receipt storage failure")
            original(path,value)
        with tempfile.TemporaryDirectory() as folder, patch.object(evaluator,"build",return_value={"native_built":True,"status":"compiled"}), patch.object(evaluator,"execute",return_value=observed), patch.object(evaluator,"save",side_effect=save):
            with self.assertRaises(OSError):
                session.apply(response,Path(folder)/"attempt")
        self.assertEqual(session.revision,before)

    def test_failed_compiler_identity_gate_never_executes_native_image(self):
        session,response,_=self.fixture();before=session.revision
        with tempfile.TemporaryDirectory() as folder, patch.object(evaluator,"build",return_value={"native_built":True,"status":"infrastructure_failure"}), patch.object(evaluator,"execute") as execute:
            result=session.apply(response,Path(folder)/"attempt")
        execute.assert_not_called()
        self.assertEqual(result["status"],"infrastructure_failure")
        self.assertFalse(result["accepted"])
        self.assertEqual(session.revision,before)

    def test_post_validation_candidate_digest_failure_cannot_commit(self):
        session,response,observed=self.fixture();before=session.revision;source=session.files
        original_digest=edit.digest;after_execution=False;injected=False
        def execute(*args,**kwargs):
            nonlocal after_execution
            after_execution=True
            return observed
        def digest(value):
            nonlocal injected
            if after_execution and not injected and type(value) is dict and set(value)==set(source) and value!=source:
                injected=True
                raise RuntimeError("simulated candidate revision failure")
            return original_digest(value)
        with tempfile.TemporaryDirectory() as folder, patch.object(evaluator,"build",return_value={"native_built":True,"status":"compiled"}), patch.object(evaluator,"execute",side_effect=execute), patch.object(edit,"digest",side_effect=digest):
            result=session.apply(response,Path(folder)/"attempt")
        self.assertTrue(injected)
        self.assertEqual(result["status"],"infrastructure_failure")
        self.assertFalse(result["accepted"])
        self.assertEqual(result["after_revision"],before)
        self.assertEqual(session.revision,before)
        self.assertEqual(session.files,source)


if __name__ == "__main__":
    unittest.main()
