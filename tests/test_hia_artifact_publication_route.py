"""Explicit source-tree native publisher routing, no default/fallback change."""
from pathlib import Path
import errno,fcntl,json,os,subprocess,tempfile,unittest
from types import SimpleNamespace
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
        with tempfile.TemporaryDirectory(prefix='hia-publication-route-refusal-') as folder:
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
        with tempfile.TemporaryDirectory(prefix='hia-publication-real-route-') as folder:
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
                fd=int(argv[0].rsplit('/',1)[1]);seals=fcntl.fcntl(fd,1034)
                required=0x0008|0x0004|0x0002|0x0001
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


class PublicationSealedDescriptorTests(unittest.TestCase):
    """Real Linux memfd custody; the child mock cannot supply kernel seals."""

    def assert_closed(self, fd):
        with self.assertRaises(OSError) as caught:
            os.fstat(fd)
        self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_missing_python_fcntl_constants_still_require_real_complete_seals(self):
        import hepta.artifact_publication_native as native
        code = b'admitted executable bytes\x00\xff'
        observed = []

        def inspect_sealed(argv, **kwargs):
            fd = int(argv[0].rsplit('/', 1)[1])
            observed.append(fd)
            self.assertEqual(fcntl.fcntl(fd, 1034) & 15, 15)
            self.assertEqual(os.pread(fd, len(code) + 1, 0), code)
            self.assertEqual(kwargs['pass_fds'], (fd,))
            for mutation in (lambda: os.write(fd, b'!'),
                             lambda: os.ftruncate(fd, len(code) + 1),
                             lambda: os.ftruncate(fd, len(code) - 1),
                             lambda: fcntl.fcntl(fd, 1033, 0x0010)):
                with self.assertRaises(OSError) as caught:
                    mutation()
                self.assertEqual(caught.exception.errno, errno.EPERM)
            return subprocess.CompletedProcess(argv, 0, b'checked', b'')

        # The proxy intentionally exports no F_* names, while retaining the
        # real kernel syscall function. This also exercises newer Python hosts.
        without_constants = SimpleNamespace(fcntl=fcntl.fcntl)
        with patch.object(native, '_validated_code', return_value=code), \
             patch.object(native, 'fcntl', without_constants), \
             patch.object(native.subprocess, 'run', side_effect=inspect_sealed) as run:
            self.assertEqual(native._execute_native('selected', 'withdraw', 'stage', 'dest', b''), b'checked')
            run.assert_called_once()
        self.assertEqual(len(observed), 1)
        self.assert_closed(observed[0])

    def test_kernel_refusal_closes_descriptor_without_starting_or_replaying(self):
        import hepta.artifact_publication_native as native
        create = os.memfd_create
        descriptors = []

        def without_sealing(name, flags):
            # A real nonsealable memfd has F_SEAL_SEAL set from creation, so
            # the kernel itself refuses the subsequent ADD_SEALS operation.
            fd = create(name, flags & ~os.MFD_ALLOW_SEALING)
            descriptors.append(fd)
            self.assertEqual(fcntl.fcntl(fd, 1034), 1)
            return fd

        with patch.object(native, '_validated_code', return_value=b'admitted'), \
             patch.object(native.os, 'memfd_create', side_effect=without_sealing), \
             patch.object(native.subprocess, 'run') as run:
            with self.assertRaisesRegex(PublicationRejected, 'E_PUBLISH_NATIVE_CUSTODY') as caught:
                native._execute_native('selected', 'withdraw', 'stage', 'dest', b'')
            self.assertIsInstance(caught.exception.__cause__, OSError)
            self.assertEqual(caught.exception.__cause__.errno, errno.EPERM)
            run.assert_not_called()
        self.assertEqual(len(descriptors), 1)
        self.assert_closed(descriptors[0])

    def test_incomplete_kernel_seal_readback_refuses_before_child_start(self):
        import hepta.artifact_publication_native as native
        kernel_fcntl = fcntl.fcntl
        observed = []

        def incomplete_sealing(fd, command, *args):
            if command == 1033:
                # Inject only F_SEAL_SEAL into the real kernel. The real
                # GET_SEALS result then lacks write and extent protection.
                return kernel_fcntl(fd, command, 1)
            result = kernel_fcntl(fd, command, *args)
            if command == 1034:
                self.assertEqual(result, 1)
                observed.append(fd)
            return result

        with patch.object(native, '_validated_code', return_value=b'admitted'), \
             patch.object(native.fcntl, 'fcntl', side_effect=incomplete_sealing), \
             patch.object(native.subprocess, 'run') as run:
            with self.assertRaisesRegex(PublicationRejected, 'E_PUBLISH_NATIVE_CUSTODY.*seals differ'):
                native._execute_native('selected', 'withdraw', 'stage', 'dest', b'')
            run.assert_not_called()
        self.assertEqual(len(observed), 1)
        self.assert_closed(observed[0])

    def test_absent_memfd_support_is_a_typed_refusal_without_child_start(self):
        import hepta.artifact_publication_native as native
        without_memfd = SimpleNamespace(fspath=os.fspath, close=os.close)
        with patch.object(native, '_validated_code', return_value=b'admitted'), \
             patch.object(native, 'os', without_memfd), \
             patch.object(native.subprocess, 'run') as run:
            with self.assertRaisesRegex(PublicationRejected, 'E_PUBLISH_NATIVE_CUSTODY'):
                native._execute_native('selected', 'withdraw', 'stage', 'dest', b'')
            run.assert_not_called()
