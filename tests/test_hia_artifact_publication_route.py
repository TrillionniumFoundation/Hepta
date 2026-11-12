"""Explicit source-tree native publisher routing, no default/fallback change."""
from pathlib import Path
from tools.hia_artifact_publication_custody import temporary_directory
import json,os,tempfile,unittest
from unittest.mock import patch
from hepta.artifact_publication import publish_verified,verify_published,withdraw_own_link,PublicationRejected


class PublicationRouteSourceTests(unittest.TestCase):
    def test_explicit_selection_routes_all_operations_and_never_falls_back(self):
        receipt={'sha256':'a'*64,'bytes':3}
        with patch.dict(os.environ,{'HEPTA_HIA_ARTIFACT_PUBLICATION_MANIFEST':'explicit-build.json'}),\
             patch('hepta.artifact_publication._read_exact',side_effect=AssertionError('host payload read')),\
             patch('hepta.artifact_publication.sha256',side_effect=AssertionError('host payload hash')),\
             patch('hepta.artifact_publication_native.invoke_native',side_effect=[receipt,receipt,True]) as invoke:
            self.assertEqual(publish_verified('/tmp/stage','/tmp/out',b'abc'),receipt)
            self.assertEqual(verify_published('/tmp/stage','/tmp/out',b'abc'),receipt)
            self.assertTrue(withdraw_own_link('/tmp/stage','/tmp/out'))
            self.assertEqual([c.args[1] for c in invoke.call_args_list],['publish','verify','withdraw'])
        with patch.dict(os.environ,{'HEPTA_HIA_ARTIFACT_PUBLICATION_MANIFEST':'explicit-build.json'}),\
             patch('hepta.artifact_publication._read_exact',side_effect=AssertionError('forbidden fallback')),\
             patch('hepta.artifact_publication_native.invoke_native',side_effect=PublicationRejected('E_PUBLISH_IO')):
            with self.assertRaisesRegex(PublicationRejected,'E_PUBLISH_IO'):
                publish_verified('/tmp/stage','/tmp/out',b'abc')

    def test_missing_or_malformed_selected_manifest_fails_before_effects(self):
        with temporary_directory(prefix='hia-publication-route-refusal-') as folder:
            root=Path(folder);stage=root/'stage';stage.write_bytes(b'abc');dest=root/'new'
            manifest=root/'build.json'
            for data in (None,b'{',b'{}'):
                if data is not None:manifest.write_bytes(data)
                with patch.dict(os.environ,{'HEPTA_HIA_ARTIFACT_PUBLICATION_MANIFEST':str(manifest)}):
                    with self.assertRaisesRegex(PublicationRejected,'E_PUBLISH_NATIVE_CUSTODY'):
                        publish_verified(stage,dest,b'abc')
                self.assertFalse(dest.exists());self.assertEqual(stage.read_bytes(),b'abc')


class PublicationRouteNativeTests(unittest.TestCase):
    def test_real_selected_API_uses_sealed_code_and_native_filesystem_only(self):
        # This path is mandatory under source-bound qualification; local source
        # development still tests the standalone real-kernel route separately.
        cold_path=os.environ.get('HEPTA_HIA_ARTIFACT_PUBLICATION_COLD_REPORT')
        from tools.build_hia_artifact_publication import build,current_sources,SOURCES,OPERATIONS
        from tools.hia_selfhost_contract import PROFILE
        from hashlib import sha256
        import fcntl,subprocess
        with temporary_directory(prefix='hia-publication-real-route-') as folder:
            root=Path(folder)
            if cold_path:
                outer=json.loads(Path(cold_path).read_bytes());inner=json.loads(Path(outer['nested_report']).read_bytes())
                app=build(root/'build',Path(inner['generations'][-1]['produced_image']),Path(cold_path))
            else:
                # Actual current HIA compilation using B0/B1/B2; this explicit
                # development receipt does NOT invent a passed cold replay.
                from tests.test_hia_artifact_publication_native import ArtifactPublicationKernelTests
                ArtifactPublicationKernelTests.setUpClass()
                self.addCleanup(ArtifactPublicationKernelTests.tearDownClass)
                build_root=root/'build';build_root.mkdir()
                app=build_root/'hia-artifact';app.write_bytes(ArtifactPublicationKernelTests.app.read_bytes());app.chmod(0o700)
                source_root=Path(__file__).resolve().parents[1]
                development={'schema':'hepta.hia.artifact-publication-build.v1','status':'NATIVE_ARTIFACT_PUBLICATION_BUILT',
                    'profile':PROFILE,'source_manifest':current_sources(),'operations':OPERATIONS,
                    'executable_path':'hia-artifact','executable_sha256':sha256(app.read_bytes()).hexdigest(),
                    'source_sha256':{name:sha256((source_root/name).read_bytes()).hexdigest() for name in SOURCES},
                    'development_only':True,'matching_source_cold_qualified':False}
                (build_root/'build.json').write_text(json.dumps(development))
            manifest=app.parent/'build.json' 
            stage=root/'stage';stage.write_bytes(b'actual\0native\xff');dest=root/'published';payload=stage.read_bytes();observed=[]
            original_run=subprocess.run
            def sealed_run(argv,*args,**kwargs):
                self.assertTrue(argv[0].startswith('/proc/self/fd/'))
                fd=int(argv[0].rsplit('/',1)[1]);seals=fcntl.fcntl(fd,fcntl.F_GET_SEALS)
                required=fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL
                self.assertEqual(seals&required,required)
                with self.assertRaises(OSError):os.write(fd,b'X')
                # Replace the admitted on-disk path before exec: only the
                # already sealed descriptor may run. Restore between calls.
                before=app.read_bytes();app.write_bytes(b'not executable')
                try:result=original_run(argv,*args,**kwargs)
                finally:app.write_bytes(before)
                observed.append(argv[1]);return result
            with patch.dict(os.environ,{'HEPTA_HIA_ARTIFACT_PUBLICATION_MANIFEST':str(manifest)}),\
                 patch('hepta.artifact_publication._read_exact',side_effect=AssertionError('host payload read')),\
                 patch('hepta.artifact_publication.sha256',side_effect=AssertionError('host payload hash')),\
                 patch('hepta.artifact_publication_native.subprocess.run',side_effect=sealed_run):
                receipt=publish_verified(stage,dest,payload)
                self.assertEqual(verify_published(stage,dest,payload),receipt)
                self.assertTrue(withdraw_own_link(stage,dest));self.assertFalse(dest.exists())
            self.assertEqual(observed,['publish','verify','withdraw'])
