"""Pure integration protocol tests: stub migrator and native builder, not a native qualification."""
from hashlib import sha256
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch
from hepta.hia_migrate import migrate_scalar_to_hia


def h(data): return sha256(data).hexdigest()


def fake_migrate(path, out, **kwargs):
    source = Path(path).read_bytes()
    code = b'module migrated;\nexport "C" fn f(x:i32)->i32 effects {} { return x; }\n'
    Path(out).write_bytes(code)
    return {'ok': True, 'status': 'frontend_checked_not_native_qualified',
            'native_validation': 'not_run', 'source_sha256':h(source), 'output_sha256':h(code),
            'source_equivalence_proved':False,'behavioral_equivalence_proved':False,'cpp_abi_preserved':False}


def fake_build(src, out, **kwargs):
    data = b'fake-object-only-not-a-Hepta-compiler-output'
    Path(out).write_bytes(data)
    return {
        'ok':True,'status':'cross_object_only_not_executed' if kwargs['target'] else 'native_host_compiled_unqualified',
        'claims':{
            'native_rust_reference_required':True, 'hia_scalar_core_source_replayed':True,
            'independent_scalar_ssa_structure_checked':True,'native_artifact_compiled':True,
            'backend_refinement_proved':False},
        'identities':{'hia_scalar_core_schema':'hepta.hia.scalar-core.v0','hia_scalar_core_sha256':'a'*64},
        'native_backend':{'artifact_sha256':h(data),'artifact_bytes':len(data)}
    }


class MigrationProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.src=Path(self.tmp.name)/'input.c';self.src.write_text('int f(int x) { return x; }')
        self.dest=Path(self.tmp.name)/'bundle'
    def run_migration(self,language='c',target=None,build=fake_build):
        with patch('hepta.hia_migrate.migrate_c',side_effect=fake_migrate), \
             patch('hepta.hia_migrate.migrate_cpp',side_effect=fake_migrate), \
             patch('hepta.hia_migrate.build_llvm_ssa_source',side_effect=build):
            return migrate_scalar_to_hia(self.src,self.dest,language=language,target=target)
    def test_success_writes_source_object_and_manifest_last(self):
        res=self.run_migration()
        self.assertTrue(res['ok'],res)
        self.assertEqual(sorted(p.name for p in self.dest.iterdir()),['candidate.hepta','candidate.so','migration-hia.json'])
        receipt=json.loads((self.dest/'migration-hia.json').read_text())
        self.assertEqual(receipt['status'],'native_emitted_L1_not_equivalence_proved')
        self.assertFalse(receipt['claims']['original_c_or_cpp_semantics_proved'])
        self.assertEqual(receipt['artifacts']['candidate.so']['sha256'],h((self.dest/'candidate.so').read_bytes()))
    def test_cpp_does_not_promote_abi(self):
        self.src.rename(self.src.with_suffix('.cc')); self.src=self.src.with_suffix('.cc')
        res=self.run_migration('cpp',target='aarch64-unknown-linux-gnu')
        self.assertTrue(res['ok'],res)
        self.assertFalse(res['claims']['cpp_mangled_abi_preserved'])
        self.assertTrue((self.dest/'candidate.o').is_file())
    def test_hia_claim_mismatch_never_publishes(self):
        def bogus(*a,**k):
            p=fake_build(*a,**k)
            p['claims']['hia_scalar_core_source_replayed']=False
            return p
        res=self.run_migration(build=bogus)
        self.assertFalse(res['ok'])
        self.assertFalse(self.dest.exists())
    def test_forged_proof_and_core_digest_reject(self):
        def bogus(*a, **k):
            p = fake_build(*a, **k)
            p["identities"]["hia_scalar_core_sha256"] = "X"*64
            return p
        self.assertFalse(self.run_migration(build=bogus)["ok"])
        self.assertFalse(self.dest.exists())

    def test_wrong_binary_receipt_rejects(self):
        def bogus(*a,**k):
            p=fake_build(*a,**k)
            p['native_backend']['artifact_sha256']='0'*64
            return p
        res=self.run_migration(build=bogus)
        self.assertFalse(res['ok'])
        self.assertFalse(self.dest.exists())
    def test_source_mutation_during_native_build_rejects(self):
        def malicious(*a,**k):
            p=fake_build(*a,**k)
            self.src.write_text('int f(int x) { return 55; }')
            return p
        res=self.run_migration(build=malicious)
        self.assertFalse(res['ok'])
        self.assertFalse(self.dest.exists())
    def test_existing_destination_preserved(self):
        self.dest.mkdir(); (self.dest/'protected').write_text('do-not-touch')
        res=self.run_migration()
        self.assertFalse(res['ok'])
        self.assertEqual((self.dest/'protected').read_text(),'do-not-touch')
    def test_unsupported_language_rejected(self):
        res=self.run_migration(language='rust')
        self.assertFalse(res['ok'])
        self.assertFalse(self.dest.exists())

if __name__=='__main__':unittest.main()
