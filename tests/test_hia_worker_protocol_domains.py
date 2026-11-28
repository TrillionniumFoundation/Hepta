"""Source-domain controls for complete native Worker protocol variants.

These controls do not claim native execution or a matching cold installation.
The separate Linux gates retain every original protocol call and budget.
"""
import ast
import hashlib
import json
from pathlib import Path
import tempfile
import types
import sys
from unittest.mock import patch
import unittest

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = "tests/fixtures/hia_worker_protocol_original_manifest_v1.json"
FIXTURE_SHA256 = "30e9ce1d24331173b1e570463f9a11b342dcf7d1f492be6f3f3a13d0608081df"


class WorkerProtocolDomainTests(unittest.TestCase):
    def test_protocol_is_an_explicit_fixed_domain(self):
        from tools.hia_worker_protocols import protocol
        self.assertEqual(protocol().number, "03")
        for n in ("01", "02", "03"):
            p = protocol(n)
            self.assertEqual(p.options_magic, ("HIAWOP"+n).encode())
            self.assertEqual(p.request_magic, ("HIAWMF"+n).encode())
            self.assertEqual(p.table_magic, ("HIAWMT"+n).encode())
            self.assertEqual((p.owner_executable, p.entry_executable),
                             ("hia-worker-install-owner", "hia-worker-install"))
        for bad in (None, 1, True, b"03", "", "3", "04", "03 ", "../03"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                protocol(bad)

    def test_product_authors_require_explicit_native_authority(self):
        from tools.generate_hia_worker_protocol_sources import generated_files
        from tools.generate_hia_worker_protocol_manifest import generated_files as manifest_files
        with self.assertRaisesRegex(ValueError,"explicit native source authority"):
            generated_files()
        for number in ("01","02","03"):
            with self.subTest(protocol=number), self.assertRaisesRegex(ValueError,"explicit native source authority"):
                manifest_files(protocol=number)

    def test_captured_native_authority_parser_ignores_later_path_contents(self):
        from tools.hia_native_worker_source_authority import parse_native_source_authority, load_native_source_authority
        first=json.dumps({"schema":"hepta.hia.native-source-authority.v1","paths":["a.hepta"]}).encode()
        second=json.dumps({"schema":"hepta.hia.native-source-authority.v1","paths":["b.hepta"]}).encode()
        with tempfile.TemporaryDirectory(prefix="hia-worker-authority-") as tmp:
            path=Path(tmp)/"authority.json";path.write_bytes(first)
            captured=path.read_bytes();path.write_bytes(second)
            self.assertEqual(parse_native_source_authority(captured),("a.hepta",))
            self.assertEqual(load_native_source_authority(path),("b.hepta",))
        for bad in (b'{"schema":"hepta.hia.native-source-authority.v1","paths":["a.hepta"],"paths":["b.hepta"]}',
                    b'{"schema":"hepta.hia.native-source-authority.v1","paths":["x.py"]}',None):
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                parse_native_source_authority(bad)

    def test_default_aggregate_cannot_be_rebound_to_new_sources(self):
        from tools.qualify_hia_default_worker_manifest import check_original_aggregate
        from copy import deepcopy
        policy=b"actual installed policy";image=b"actual installed aggregate";compiler=b"actual compiler"
        resources={"source.hepta":"a"*64};runtime={"packer.hepta":"b"*64}
        value=dict(schema="hepta.hia.native-continuation-inprocess.v2",
            policy_bundle_sha256=hashlib.sha256(policy).hexdigest(),
            image_sha256=hashlib.sha256(image).hexdigest(),
            compiler_sha256=hashlib.sha256(compiler).hexdigest(),
            resource_sha256=resources,runtime_sha256=runtime)
        kwargs=dict(policy=policy,image=image,compiler=compiler,schema=value["schema"],
                    resource_pins=resources,runtime_pins=runtime)
        check_original_aggregate(value,**kwargs)
        for field,replacement in (("policy_bundle_sha256","c"*64),("image_sha256","c"*64),
                 ("compiler_sha256","c"*64),("resource_sha256",{"source.hepta":"c"*64}),
                 ("runtime_sha256",{"packer.hepta":"c"*64}),("schema","hepta.hia.native-continuation-inprocess.v1")):
            changed=deepcopy(value);changed[field]=replacement
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,"installed aggregate binding"):
                check_original_aggregate(changed,**kwargs)

    def test_fixed_filter_stays_exact_and_physical_mapping_is_closed(self):
        from tools.hia_worker_protocols import canonical_module, member_source_map, protocol
        self.assertEqual(hashlib.sha256((ROOT/"examples/hia_bootstrap/source_filter_member.hepta").read_bytes()).hexdigest(),
                         "7f2c8e916bc0d7ce419e23f688d2653cdc0c2703e023fcfd5e421ed97200f51b")
        for number in ("01", "02", "03"):
            p=protocol(number)
            self.assertEqual(member_source_map(number),
                {"worker_install_"+kind+".hepta":p.install_stem+"_"+kind+".hepta"
                 for kind in ("owner","dag","owner_packer")})
            for kind in ("owner","dag","owner_packer","entry","entry_bind","entry_packer"):
                self.assertEqual(canonical_module(number,p.install_stem+"_"+kind),"worker_install_"+kind)
            for bad in ("../worker_install_owner", p.install_stem+"_other", None,
                        p.install_stem+"_owner.hepta", b"worker_install_owner"):
                with self.subTest(number=number,bad=bad),self.assertRaises(ValueError):
                    canonical_module(number,bad)
        for number in (None, 1, True, "3", "../03"):
            with self.subTest(number=number),self.assertRaises(ValueError):
                member_source_map(number)

    def test_all_sixteen_graph_paths_are_separate(self):
        from tools.hia_worker_protocols import recipe_path
        from tools.generate_hia_worker_install_owner import STAGES
        self.assertEqual(len(STAGES), 16)
        sets = [{recipe_path(n, kind) for kind in STAGES} for n in ("01","02","03")]
        self.assertEqual([len(s) for s in sets], [16,16,16])
        self.assertEqual(len(set.union(*sets)), 48)
        for n in ("01","02","03"):
            for bad in ("", "configuration", "../helpers", None):
                with self.subTest(n=n,bad=bad), self.assertRaises(ValueError):
                    recipe_path(n,bad)

    def test_complete_helper_domains_preserve_the_prior_members(self):
        from tools.generate_hia_worker_manifest import model, current_model, recipes
        from tools.hia_worker_protocol_model import worker_model
        models = [worker_model(ROOT,protocol=n) for n in ("01","02","03")]
        self.assertEqual(models[0]["helpers"], model(ROOT)["helpers"])
        self.assertEqual(models[1]["helpers"], current_model(ROOT)["helpers"])
        self.assertEqual(models[1]["helpers"][:37], models[0]["helpers"])
        self.assertEqual(models[2]["helpers"][:41], models[1]["helpers"])
        self.assertEqual([len(m["helpers"]) for m in models], [37,41,45])
        self.assertEqual([len(recipes(m)) for m in models], [130,134,145])
        self.assertEqual([h["name"] for h in models[2]["helpers"][41:]],
                         ["agent-query","cli-inspect","agent-native-metadata","agent-json-wire"])
        self.assertEqual([h["role"] for h in models[2]["helpers"]], list(range(1,46)))

    def test_both_original_framer_apis_are_entirely_byte_equal(self):
        from tools.generate_hia_worker_manifest import render
        raw = (ROOT/FIXTURE).read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), FIXTURE_SHA256)
        record = json.loads(raw)
        source = record["text"].encode()
        self.assertEqual((len(source), hashlib.sha256(source).hexdigest()),
                         (record["bytes"], record["sha256"]))
        prior = types.ModuleType("hia_worker_original_manifest_author")
        prior.__file__ = str(ROOT/record["path"])
        with patch.dict(sys.modules, {prior.__name__: prior}):
            exec(compile(source, str(ROOT/FIXTURE), "exec"), prior.__dict__)
            for extension in (False, True):
                with self.subTest(extension=extension):
                    self.assertEqual(prior.render(ROOT,helper_extensions=extension),
                                     render(ROOT,helper_extensions=extension))
        self.assertEqual((ROOT/FIXTURE).read_bytes(),raw)

    def test_core_v2_has_all_thirty_nine_controls_and_its_pool(self):
        from tools.hia_worker_protocol_model import worker_model
        models = [worker_model(ROOT,protocol=n) for n in ("01","02","03")]
        cores = [next(f for f in m["families"] if f["name"]=="core-lowering") for m in models]
        self.assertEqual(cores[0], cores[1])
        self.assertEqual([len(f["units"]) for f in cores],[33,33,40])
        self.assertEqual([len([u for f in m["families"] for u in f["units"]]) for m in models],
                         [72,72,79])
        current = cores[2]
        self.assertEqual(current["continuation_schema"],"hepta.hia.native-continuation-inprocess.v2")
        self.assertEqual(current["continuation_pack_magic"],"HIACTPK2")
        self.assertEqual(current["units"][0]["name"],"core_lowering_v2_pool")
        self.assertEqual([u["name"] for u in current["units"][1:]],current["abi"]["units"])
        self.assertEqual(len(current["continuation_resources"]),7)
        self.assertNotIn("continuation_schema",cores[0])

    def test_native_authority_requires_every_v2_dependency(self):
        from tools.hia_worker_protocol_model import worker_model
        from tools.hia_native_worker_source_authority import CONTINUATION_RUNTIME, CONTINUATION_RUNTIME_V2
        m=worker_model(ROOT,protocol="03")
        paths=set(CONTINUATION_RUNTIME)|set(CONTINUATION_RUNTIME_V2)|set(m["continuation_resources"])
        paths.update(h["source"] for h in m["helpers"])
        paths.update(f["abi_source"] for f in m["families"])
        paths.update(u["source"] for f in m["families"] for u in f["units"])
        for f in m["families"]:paths.update(f.get("continuation_resources",()))
        with tempfile.TemporaryDirectory(prefix="hia-worker-domain-") as tmp:
            p=Path(tmp)/"authority.json"
            def write(values):
                p.write_text(json.dumps({"schema":"hepta.hia.native-source-authority.v1","paths":sorted(values)}))
            write(paths)
            current=worker_model(ROOT,p,protocol="03")
            core=next(f for f in current["families"] if f["name"]=="core-lowering")
            self.assertEqual(core["continuation_runtime"],list(CONTINUATION_RUNTIME+CONTINUATION_RUNTIME_V2))
            self.assertEqual(current["continuation_runtime"],list(CONTINUATION_RUNTIME))
            self.assertFalse(any(n.endswith(".py") for n in current["runtime_files"]))
            for name in CONTINUATION_RUNTIME_V2:
                write(paths-{name})
                with self.subTest(name=name),self.assertRaisesRegex(ValueError,"omits required"):
                    worker_model(ROOT,p,protocol="03")
            write(paths|{"hepta/hia_program_native.py"})
            with self.assertRaisesRegex(ValueError,"invalid native source"):
                worker_model(ROOT,p,protocol="03")

    def test_entry_keeps_the_original_argument_and_root_abi(self):
        from tools.generate_hia_worker_install_entry import policy_source, WORKER_FUNCTIONS
        from tools.hia_worker_protocols import protocol
        self.assertIn("count > 82",WORKER_FUNCTIONS)
        self.assertIn("count >= 32",WORKER_FUNCTIONS)
        class Domain(ast.NodeTransformer):
            def __init__(self,value):self.value=value
            def visit_Constant(self,node):
                return ast.Constant(value="FIXED_OPTIONS_DOMAIN") if node.value==self.value else node
        normalized=[]
        for n in ("01","02","03"):
            normalized.append(ast.dump(Domain(int.from_bytes(protocol(n).options_magic,"little")).visit(
                ast.parse(policy_source(n))),include_attributes=False))
        self.assertEqual(normalized[0],normalized[1])
        self.assertEqual(normalized[0],normalized[2])

    def test_all_graphs_keep_current_full_custody_and_distinct_tables(self):
        from tools.generate_hia_worker_install_recipes import recipes
        from tools.hia_worker_protocols import protocol
        from tools.generate_hia_worker_install_owner import STAGES
        for n in ("01","02","03"):
            selected=protocol(n)
            graphs=recipes(protocol=n)
            self.assertEqual(tuple(graphs),STAGES)
            for kind,recipe in graphs.items():
                wire=recipe.binary()
                self.assertLess(len(wire),1<<20)
                self.assertTrue(wire)
            self.assertIn(selected.manifest_table.encode(),graphs["helpers"].binary())
            self.assertIn(selected.request_magic,graphs["helpers"].binary())
            core=graphs["core_lowering"].binary()
            self.assertIn(b"HIAWCP02" if n=="03" else b"HIAWCP01",core)
            self.assertIn(b"core_lowering_v2_pool.hepta" if n=="03" else b"core_lowering_pool.hepta",core)
            report=graphs["report"].binary()
            if n=="01":
                self.assertNotIn(b"core_host_custody.hiadat",report)
            else:
                self.assertIn(b"core_host_custody.hiadat",report)

if __name__=="__main__":
    unittest.main()
