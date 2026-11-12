#!/usr/bin/env python3
"""Proposed inert source controls. Not executed when this draft is frozen.

Only AST-extract Supply.rust195 into a synthetic namespace. All external effects
(get, operation, step, file_record, executable, inventory) are fakes. No supplier
module import, Rustup invocation, process, network, APT, or qualification.
"""
import ast
import copy
import hashlib
import json
from pathlib import Path
import tomllib
import types
import unittest
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
OLD = ROOT / "originals/supply_v87.py"
NEW = ROOT / "candidate/supply_v87.py"
EXPECTED_OLD = "cb25fcc04be3414afce234e8842247639e6390d825198a329bb7460c089a4321"
EXPECTED_NEW = "90849452cce97468e70059bd4f1cc2e5b5ce2b849ca4d4bd58ba9911dd81fbfd"
HOST = "x86_64-unknown-linux-gnu"
FLAG = "--no-self-update"
class ControlledFailure(Exception): pass
class FakeSupply:
    """No filesystem mutation. Values model the already frozen method interface."""
    def __init__(self, install_error=None, verify_error=None, changed_tool=False):
        self.output = Path("/fixed-new-supply")
        self.network_env = {"PATH":"/fixed-tools", "HOME":"/real-home",
                            "HTTP_PROXY":"http://proxy.invalid:3128"}
        self.report, self.immutable, self.events = {}, {}, []
        self.install_error, self.verify_error, self.changed_tool = install_error, verify_error, changed_tool
        self.tool_reads = 0
        self.bodies = {}
        self.prefix = self.output / "rustup195/toolchains" / ("1.95.0-" + HOST)
        channel = ['manifest-version = "2"', '[pkg.rust]', 'version = "1.95.0 (synthetic)"']
        for name in ("rustc","cargo","rust-std"):
            archive = name+"-1.95.0-"+HOST+".tar.xz"
            channel += ["[pkg."+name+".target."+HOST+"]", "available = true",
                        'xz_url = "https://static.rust-lang.org/dist/'+archive+'"',
                        'xz_hash = "'+hashlib.sha256(name.encode()).hexdigest()+'"']
        self.channel = ("\n".join(channel)+"\n").encode()
        self.channel_sha = hashlib.sha256(self.channel).hexdigest()
        self.mutation_would_be_rejected = False
    def get(self,label,url,**kwargs):
        self.events.append(("get",label,url,kwargs))
        path = self.output / "downloads" / kwargs["filename"]
        if label == "rust195-channel": raw=self.channel
        elif label == "rust195-channel-checksum": raw=(self.channel_sha+" channel-rust-1.95.0.toml\n").encode()
        else: raw=label.encode()
        self.bodies[str(path)]=raw
        return path
    def executable(self,name):
        self.events.append(("executable",name))
        return "/fixed-tools/rustup"
    def step(self,label,command,**kwargs):
        self.events.append(("step",label,list(command),kwargs))
        if label=="rust195-install" and self.install_error is not None:
            raise self.install_error
        path=self.output/"logs"/(label+".stdout")
        if label=="rust195-which": raw=(str(self.prefix/"bin/cargo")+"\n").encode()
        elif label in ("rust195-cargo-version","rust195-rustc-version"):
            raw=(label.split("-")[1]+" 1.95.0 (synthetic)\n").encode()
        else: raw=b"synthetic stdout, not an executed tool"
        self.bodies[str(path)]=raw
        return path
    def operation(self,label,kind,data,**kwargs):
        self.events.append(("operation",label,kind,data,kwargs))
        if kind=="verify_rust" and self.verify_error is not None:
            raise self.verify_error
    def file_record(self,path,body=False,**kwargs):
        raw=self.bodies[str(path)]
        row={"path":str(path),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
        return (row,raw) if body else row
    def resolved_record(self,path):
        self.tool_reads += 1
        return {"path":str(path),"sha256":("b" if self.changed_tool and self.tool_reads>1 else "a")*64}
    def inventory(self,path):
        self.events.append(("inventory",str(path)))
        return {"synthetic_complete_inventory":True}
def extracted_method(path, fake):
    raw=path.read_bytes()
    assert hashlib.sha256(raw).hexdigest()==(EXPECTED_NEW if path==NEW else EXPECTED_OLD)
    module=ast.parse(raw)
    cls=next(n for n in module.body if isinstance(n,ast.ClassDef) and n.name=="Supply")
    function=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name=="rust195")
    function=copy.deepcopy(function)
    synthetic=ast.Module(body=[function],type_ignores=[])
    ast.fix_missing_locations(synthetic)
    def require(ok, message):
        if not ok: raise ControlledFailure(message)
    namespace={"Path":Path,"HOST":HOST,"tomllib":tomllib,"re":__import__("re"),"urllib":urllib}
    namespace.update(file_record=fake.file_record,resolved_record=fake.resolved_record,
                     inventory=fake.inventory,require=require)
    exec(compile(synthetic,"<AST-extracted-source-method>","exec"),namespace)
    return types.MethodType(namespace["rust195"],fake)
class Rust195SelfUpdateR5SourceControls(unittest.TestCase):
    def test_exact_whole_source_inverse_and_single_literal(self):
        old,new=OLD.read_bytes(),NEW.read_bytes()
        self.assertEqual(hashlib.sha256(old).hexdigest(),EXPECTED_OLD)
        self.assertEqual(hashlib.sha256(new).hexdigest(),EXPECTED_NEW)
        self.assertEqual(new.count(b', "--no-self-update"'),1)
        self.assertEqual(new.replace(b', "--no-self-update"',b''),old)
        a,b=ast.parse(old),ast.parse(new)
        added=[n for n in ast.walk(b) if isinstance(n,ast.Constant) and n.value==FLAG]
        self.assertEqual(len(added),1)
        for n in ast.walk(b):
            if isinstance(n,ast.List): n.elts=[x for x in n.elts if not(isinstance(x,ast.Constant) and x.value==FLAG)]
        self.assertEqual(ast.dump(a,include_attributes=False),ast.dump(b,include_attributes=False))
    def test_original_failed_command_projection_and_private_environment(self):
        old,new=FakeSupply(),FakeSupply()
        extracted_method(OLD,old)();extracted_method(NEW,new)()
        a=[x for x in old.events if x[0]=="step" and x[1]=="rust195-install"][0]
        b=[x for x in new.events if x[0]=="step" and x[1]=="rust195-install"][0]
        self.assertEqual(b[2][:-1],a[2]);self.assertEqual(b[2][-1],FLAG)
        self.assertEqual(b[3],a[3]);self.assertEqual(b[3]["seconds"],1200)
        self.assertEqual(b[3]["env"]["HOME"],"/real-home")
        self.assertEqual(b[3]["env"]["CARGO_HOME"],"/fixed-new-supply/rustup195-cargo")
        self.assertEqual(b[3]["env"]["RUSTUP_HOME"],"/fixed-new-supply/rustup195")
        self.assertEqual(b[3]["env"]["HTTP_PROXY"],"http://proxy.invalid:3128")
    def test_mock_install_failure_preserves_same_exception_and_stops(self):
        sentinel=ControlledFailure("original nonzero command retained")
        fake=FakeSupply(install_error=sentinel)
        try: extracted_method(NEW,fake)()
        except ControlledFailure as got:self.assertIs(got,sentinel)
        else:self.fail("failed command was accepted")
        labels=[x[1] for x in fake.events]
        self.assertNotIn("rust195-which",labels);self.assertNotIn("rust195_provenance",fake.report)
        self.assertNotIn("rust195",fake.immutable)
    def test_mock_verify_failure_preserves_same_exception_and_stops(self):
        sentinel=ControlledFailure("full payload mismatch")
        fake=FakeSupply(verify_error=sentinel)
        try: extracted_method(NEW,fake)()
        except ControlledFailure as got:self.assertIs(got,sentinel)
        else:self.fail("payload mismatch was accepted")
        self.assertNotIn("rust195-cargo-version",[x[1] for x in fake.events])
        self.assertNotIn("rust195_provenance",fake.report)
    def test_mock_unchanged_three_payloads_and_postconditions(self):
        fake=FakeSupply();result=extracted_method(NEW,fake)()
        self.assertEqual(result,fake.prefix)
        ops=[x for x in fake.events if x[0]=="operation" and x[2]=="verify_rust"]
        self.assertEqual([x[1] for x in ops],["rust195-rustc-verify","rust195-cargo-verify","rust195-rust-std-verify"])
        self.assertTrue(all(x[4]["seconds"]==120 for x in ops))
        self.assertEqual([x[1] for x in fake.events if x[0]=="step"],
                         ["rustup-version","rust195-install","rust195-which","rust195-cargo-version","rust195-rustc-version"])
        self.assertEqual(fake.tool_reads,2)
        self.assertTrue(fake.report["rust195_provenance"]["actual_installed_payloads_compared"])
        self.assertFalse(fake.report["rust195_provenance"]["historical_archive_digest_claimed"])
        self.assertNotIn("qualification_executed",fake.report)
    def test_mock_changed_manager_is_still_rejected(self):
        fake=FakeSupply(changed_tool=True)
        with self.assertRaisesRegex(ControlledFailure,"Rustup executable changed"):
            extracted_method(NEW,fake)()
        self.assertNotIn("rust195_provenance",fake.report)
    def test_all_unrelated_function_bodies_and_budgets_identical(self):
        def functions(raw):
            tree=ast.parse(raw)
            return {(n.name,n.lineno):ast.dump(n,include_attributes=False) for n in ast.walk(tree)
                    if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.name!="rust195"}
        self.assertEqual(functions(OLD.read_bytes()),functions(NEW.read_bytes()))
        self.assertEqual(hashlib.sha256((ROOT/"originals/supply-plan.json").read_bytes()).hexdigest(),
                         "df00181c200be9465d56c4dcae5e330e4de58ead0ba4a8e9fc566a577e88a504")
    def test_version_pinned_primary_reference_files(self):
        manifest=json.loads((ROOT/"evidence/STATIC-DELTA.json").read_bytes())
        self.assertEqual(manifest["upstream_commit"],"d8c92c6765f85625b20482e165066bf1e98e7297")
        for pin in manifest["upstream_reference_byte_verification"]:
            raw=(ROOT/pin["path"]).read_bytes()
            self.assertEqual(len(raw),pin["bytes"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(),pin["sha256"])
            self.assertEqual(hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest(),pin["git_blob"])
if __name__=="__main__":
    unittest.main(verbosity=2)
