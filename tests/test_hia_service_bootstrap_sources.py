"""Static source contracts only; these tests do not establish runtime equivalence."""
from __future__ import annotations
import ast
from hashlib import sha256
import json
from pathlib import Path
import unittest
ROOT=Path(__file__).resolve().parents[1]
FIXTURE=ROOT/'tests/fixtures/hia_service_bootstrap_original_r12'
NAMES=('__init__','close','_profiles','_profile','_program')
def assigned(tree,name):
    for node in tree.body:
        if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id==name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError('missing fixed source declaration: '+name)
class ServiceBootstrapStaticSourceTests(unittest.TestCase):
    def test_five_original_definitions_signatures_and_retained_prefix(self):
        raw=(ROOT/'hepta/hia_agent_service.py').read_bytes()
        frozen=json.loads((FIXTURE/'source-identity.json').read_bytes())
        from tests.hia_store_delivery_successor import retained_bootstrap_service
        historical=retained_bootstrap_service(raw)
        prefix=historical[:frozen['service']['bytes']]
        self.assertEqual(sha256(prefix).hexdigest(),frozen['service']['sha256'])
        source=historical.decode();lines=source.splitlines(keepends=True)
        cls=next(n for n in ast.parse(source).body if isinstance(n,ast.ClassDef) and n.name=='HIAAgentService')
        for expected in frozen['methods']:
            node=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name==expected['name'])
            start=min([node.lineno]+[d.lineno for d in node.decorator_list])
            actual=''.join(lines[start-1:node.end_lineno]).encode()
            original=(FIXTURE/(expected['name']+'.py.txt')).read_bytes()
            self.assertEqual(actual,original)
            self.assertEqual(sha256(original).hexdigest(),expected['sha256'])
            self.assertEqual(len(original),expected['bytes'])
        source=raw.decode()
        for mode,name in enumerate(NAMES,1):
            self.assertIn('HIAAgentService.'+name+' = _service_bootstrap_dispatch_'+name,source)
        self.assertNotIn('gc.collect(',source[len(prefix.decode()):])
    def test_complete_protocol_graph_and_effect_set(self):
        protocol=ast.parse((ROOT/'hepta/hia_service_bootstrap_protocol.py').read_text())
        ports=assigned(protocol,'PORTS');graph=assigned(protocol,'GRAPH')
        self.assertEqual(len(ports),98);self.assertEqual(len(set(ports)),98)
        self.assertEqual(set(graph),set(ports))
        adapter=ast.parse((ROOT/'hepta/hia_service_bootstrap_native.py').read_text())
        cls=next(n for n in adapter.body if isinstance(n,ast.ClassDef) and n.name=='ServiceBootstrapFrame')
        effects=[n.name[6:] for n in cls.body if isinstance(n,ast.FunctionDef) and n.name.startswith('_port_')]
        self.assertEqual(set(effects),set(ports));self.assertEqual(len(effects),98)
        def targets(value):
            if type(value)is str:
                return [] if value in ('RETURN','PROPAGATE','YIELD') else [value]
            found=[]
            for key,item in value.items():
                if key=='mode':
                    for inner in item.values():found.extend(targets(inner))
                else:found.extend(targets(item))
            return found
        for name,edges in graph.items():
            self.assertEqual(set(edges),{'next','raised'})
            for target in targets(edges['next'])+targets(edges['raised']):
                self.assertIn(target,ports)
        self.assertEqual(graph['close_budget_call']['raised'],'close_store_exception')
        self.assertEqual(graph['init_store']['raised'],'init_stack_unwind')
        self.assertEqual(graph['init_budget_construct']['raised'],'init_exception_match')
        self.assertEqual(graph['init_cleanup_note']['next'],{'leave':'init_clear_failure'})
    def test_packaged_source_and_complete_original_caller_scope(self):
        source_name='examples/hia_bootstrap/service_bootstrap.hepta'
        self.assertTrue((ROOT/source_name).is_file())
        contracts=ast.parse((ROOT/'hepta/hia_agent_contract.py').read_text())
        self.assertIn(source_name,assigned(contracts,'NATIVE_SOURCE_FILES'))
        helpers=assigned(ast.parse((ROOT/'hepta/hia_native_helpers.py').read_text()),'HELPERS')
        self.assertEqual(helpers['HEPTA_HIA_SERVICE_BOOTSTRAP_MANIFEST'],
                         ('hia_service_bootstrap_native','NativeServiceBootstrap'))
        raw=(FIXTURE/'caller-scopes.json').read_bytes()
        self.assertEqual(sha256(raw).hexdigest(),'b8056f8c056409952ff219d4e1b789d40d754de4718023c9fcb467c02c893af4')
        scopes=json.loads(raw)['scopes']
        for name,count in (('ordinary',112),('journal',21),('context',15)):
            self.assertEqual(len(scopes[name]['ordered_ids']),count)
            self.assertEqual(scopes[name]['outer_seconds'],1800)
            from tools.qualify_hia_service_bootstrap_callers import admit_original_scope
            admitted,proof=admit_original_scope(ROOT,name)
            self.assertEqual(admitted,scopes[name])
            self.assertEqual(proof['original_files'],scopes[name]['files'])
            self.assertEqual(proof['original_ordered_ids'],scopes[name]['ordered_ids'])
            self.assertTrue(proof['terminal_reread_identical'])
            self.assertEqual(proof['production_source_exceptions'],[])
            from tools.qualify_hia_service_bootstrap_callers import bind_scope_admission_to_source_capture
            physical = {path: sha256((ROOT / path).read_bytes()).hexdigest() for path in proof['captured_files']}
            bind_scope_admission_to_source_capture(proof, physical)

    def test_reviewed_scope_proof_matches_physical_captures_and_independent_reader(self):
        from copy import deepcopy
        from tempfile import TemporaryDirectory
        from unittest.mock import patch
        from tools import qualify_hia_service_bootstrap_callers as producer
        from tools import read_hia_service_bootstrap as reader

        for name, count in (('ordinary', 3), ('journal', 1), ('context', 1)):
            scope, proof = producer.admit_original_scope(ROOT, name)
            histories = proof['reviewed_scope_predecessors']
            self.assertEqual(len(histories), count)
            digests = {path: pin['sha256'] for path, pin in proof['captured_files'].items()}
            observed = {'caller_source_admission': proof, 'source_before': digests, 'source_after': digests}
            captured = []
            self.assertEqual(reader._read_caller_source_admission(name, scope, observed, captured), proof)
            reader.unchanged(captured)
            with TemporaryDirectory() as directory, patch.object(reader, 'ROOT', Path(directory).resolve()):
                stage = Path(directory).resolve()
                for path, data in captured:
                    target = stage / path.relative_to(ROOT)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(data)
                for path in histories:
                    with self.subTest(scope=name, path=path):
                        def digest_paths(value, prefix=()):
                            if type(value) is dict:
                                for key, item in value.items():
                                    if key == 'sha256':
                                        yield prefix + (key,)
                                    else:
                                        yield from digest_paths(item, prefix + (key,))
                            elif type(value) is list:
                                for index, item in enumerate(value):
                                    yield from digest_paths(item, prefix + (index,))
                        addresses = list(digest_paths(histories[path]))
                        self.assertTrue(addresses)
                        for address in addresses:
                            altered = deepcopy(observed)
                            target = altered['caller_source_admission']['reviewed_scope_predecessors'][path]
                            for key in address[:-1]:
                                target = target[key]
                            target[address[-1]] = '0' * 64
                            with self.subTest(proof_field=address), self.assertRaises(ValueError):
                                reader._read_caller_source_admission(name, scope, altered, [])
                        target = stage / path
                        raw = target.read_bytes()
                        for index in (0, len(raw) // 2, len(raw) - 1):
                            changed = bytearray(raw)
                            changed[index] ^= 1
                            target.write_bytes(changed)
                            with self.assertRaises(ValueError):
                                producer.admit_original_scope(stage, name)
                            with self.assertRaises(ValueError):
                                reader._read_caller_source_admission(name, scope, observed, [])
                        target.write_bytes(raw)

    def test_historical_service_inverse_refuses_changed_physical_input(self):
        from tests.hia_store_delivery_successor import retained_bootstrap_service
        physical = (ROOT / 'hepta/hia_agent_service.py').read_bytes()
        for offset in (0, len(physical) // 2, len(physical) - 1):
            changed = bytearray(physical)
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                retained_bootstrap_service(bytes(changed))
if __name__=='__main__':
    unittest.main()
