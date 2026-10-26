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
    data = b'fake-object-not-an-actual-native-Hepta-result'
    Path(out).write_bytes(data)
    artifact = {'sha256': h(data), 'bytes': len(data)}
    source_digest = h(Path(src).read_bytes())
    target = kwargs['target']
    kind = kwargs['kind']
    return {
        'schema': 'hepta.build-checked-hia-source.v1',
        'ok': True, 'status': 'native_compiled_not_executed',
        'output': str(out), 'target': target,
        'rust_reference': {
            'ok': True, 'source_sha256': source_digest, 'compiler_sha256': 'e'*64,
            'checks': {'rust_borrows_types': 'rustc_checked'}},
        'claims': {
            'pinned_rust_reference_validated': True,
            'source_bound_resource_ir_checked': True,
            'native_codegen_consumed_verified_hia_core': True,
            'native_executed': False,
            'source_to_core_refinement_proved': False,
            'whole_language_soundness_proved': False},
        'identities': {
            'project_sha256': 'f'*64, 'compiler_sha256': 'e'*64,
            'source_semantic_sha256': 'a'*64, 'resource_ir_sha256': 'b'*64,
            'hia_program_sha256': 'c'*64, 'llvm_ir_sha256': 'd'*64,
            'scalar_ssa_sha256': 'a'*64, 'ssa_verification_sha256': 'b'*64},
        'native_backend': {
            'status': 'native_compiled_not_executed', 'target': target,
            'kind': kind, 'core_sha256': 'c'*64, 'llvm_ir_sha256': 'd'*64,
            'claims': {'backend_refinement_proved': False,
                       'native_execution_qualified': False},
            'artifact_sha256': h(data), 'artifact_bytes': len(data)},
        'publication': artifact}


class MigrationProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.src=Path(self.tmp.name)/'input.c';self.src.write_text('int f(int x) { return x; }')
        self.dest=Path(self.tmp.name)/'bundle'
    def run_migration(self,language='c',target=None,build=fake_build):
        with patch('hepta.hia_migrate.migrate_c',side_effect=fake_migrate), \
             patch('hepta.hia_migrate.migrate_cpp',side_effect=fake_migrate), \
             patch('hepta.hia_migrate.build_checked_hepta_hia_native',side_effect=build):
            return migrate_scalar_to_hia(self.src,self.dest,language=language,target=target)
    def test_success_writes_source_object_and_manifest_last(self):
        res=self.run_migration()
        self.assertTrue(res['ok'],res)
        self.assertEqual(sorted(p.name for p in self.dest.iterdir()),['candidate.hepta','candidate.so','migration-hia.json'])
        receipt=json.loads((self.dest/'migration-hia.json').read_text())
        self.assertEqual(receipt['status'],'native_emitted_L1_not_equivalence_proved')
        self.assertEqual(receipt['publication'], 'linux_renameat2_noreplace_fsync_v1')
        self.assertEqual(res['publication'], 'linux_renameat2_noreplace_fsync_v1')
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
            p['claims']['native_codegen_consumed_verified_hia_core']=False
            return p
        res=self.run_migration(build=bogus)
        self.assertFalse(res['ok'])
        self.assertFalse(self.dest.exists())
    def test_forged_proof_and_core_digest_reject(self):
        def bogus(*a, **k):
            p = fake_build(*a, **k)
            p["identities"]["hia_program_sha256"] = "X"*64
            return p
        self.assertFalse(self.run_migration(build=bogus)["ok"])
        self.assertFalse(self.dest.exists())

    def test_forged_hia_source_identity_rejects(self):
        def bogus(*a, **k):
            result=fake_build(*a, **k)
            result['rust_reference']['source_sha256']='c'*64
            return result
        self.assertFalse(self.run_migration(build=bogus)['ok'])
        self.assertFalse(self.dest.exists())

    def test_forged_native_llvm_identity_rejects(self):
        def bogus(*a, **k):
            result=fake_build(*a, **k)
            result['native_backend']['llvm_ir_sha256']='d'*64
            return result
        self.assertFalse(self.run_migration(build=bogus)['ok'])
        self.assertFalse(self.dest.exists())

    def test_reference_receipt_and_native_stage_binding_required(self):
        for field in ('rust_reference', 'native_backend'):
            def bogus(*a, **k):
                result=fake_build(*a, **k)
                if field == 'rust_reference':
                    result[field]['checks']['rust_borrows_types']='frontend_only'
                else:
                    result[field]['core_sha256']='d'*64
                return result
            with self.subTest(field=field):
                self.assertFalse(self.run_migration(build=bogus)['ok'])
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

    def test_atomic_destination_race_refuses_replacement(self):
        from hepta import hia_bundle_atomic
        original = hia_bundle_atomic._rename_noreplace
        def race(parent_fd, staged, target):
            self.dest.mkdir()
            return original(parent_fd, staged, target)
        with patch('hepta.hia_bundle_atomic._rename_noreplace', side_effect=race):
            outcome = self.run_migration()
        self.assertFalse(outcome['ok'])
        self.assertTrue(self.dest.is_dir())
        self.assertEqual(list(self.dest.iterdir()), [])

    def test_parent_fsync_failure_is_recovery_required_not_success(self):
        from hepta import hia_bundle_atomic
        import os
        original = os.fsync
        def fault(fd):
            if os.fstat(fd).st_ino == self.dest.parent.stat().st_ino:
                raise OSError('injected parent directory fsync failure')
            return original(fd)
        with patch('hepta.hia_bundle_atomic.os.fsync', side_effect=fault):
            outcome = self.run_migration()
        self.assertFalse(outcome['ok'])
        self.assertEqual(outcome['status'], 'recovery_required')
        self.assertEqual(outcome['diagnostics'][0]['code'], 'E_HIA_BUNDLE_UNCERTAIN')
        self.assertTrue((self.dest/'candidate.hepta').is_file())
        self.assertTrue((self.dest/'migration-hia.json').is_file())

    def test_source_race_after_atomic_commit_reports_recovery(self):
        from hepta import hia_bundle_atomic
        original = hia_bundle_atomic._rename_noreplace
        def publish_then_change(parent_fd, staged, target):
            original(parent_fd, staged, target)
            self.src.write_text('int f(int x) { return 13; }')
        with patch('hepta.hia_bundle_atomic._rename_noreplace',
                   side_effect=publish_then_change):
            outcome = self.run_migration()
        self.assertFalse(outcome['ok'])
        self.assertEqual(outcome['status'], 'recovery_required')
        self.assertTrue((self.dest/'candidate.hepta').exists())

    def test_legacy_scalar_core_v0_receipt_is_never_accepted(self):
        def bogus(*a, **k):
            result = fake_build(*a, **k)
            result['schema'] = 'hepta.build-llvm-ssa.v1'
            result['identities']['hia_scalar_core_schema'] = 'hepta.hia.scalar-core.v0'
            return result
        self.assertFalse(self.run_migration(build=bogus)['ok'])
        self.assertFalse(self.dest.exists())

    def test_wrong_core_provenance_or_compiler_identity_rejects(self):
        for case in ('core', 'compiler', 'native', 'proof'):
            def bogus(*a, **k):
                result = fake_build(*a, **k)
                if case == 'core':
                    result['native_backend']['core_sha256'] = '0'*64
                elif case == 'compiler':
                    result['rust_reference']['compiler_sha256'] = '0'*64
                elif case == 'native':
                    result['native_backend']['kind'] = 'shared' if k['kind'] == 'object' else 'object'
                else:
                    result['claims']['source_to_core_refinement_proved'] = True
                return result
            with self.subTest(case=case):
                self.assertFalse(self.run_migration(build=bogus)['ok'])
                self.assertFalse(self.dest.exists())

    def test_native_publication_receipt_mismatch_rejects(self):
        def bogus(*a, **k):
            result = fake_build(*a, **k)
            result['publication']['bytes'] += 1
            return result
        self.assertFalse(self.run_migration(build=bogus)['ok'])
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
