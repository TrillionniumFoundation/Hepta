"""Explicit source-tree native publisher routing, no default/fallback change."""
from pathlib import Path
import errno,fcntl,json,os,subprocess,tempfile,unittest
from types import SimpleNamespace
from unittest.mock import patch
from hepta.artifact_publication import publish_verified,verify_published,withdraw_own_link,PublicationRejected


class PublicationRouteSourceTests(unittest.TestCase):
    def assert_descriptor_closed(self, descriptor):
        with self.assertRaises(OSError) as caught:
            os.fstat(descriptor)
        self.assertEqual(caught.exception.errno, errno.EBADF)

    def assert_capture_refused(self, fault, descriptors):
        """Real descriptor faults must stop the public route before any child."""
        import hepta.artifact_publication_native as native
        with tempfile.TemporaryDirectory(prefix='hia-publication-capture-refusal-') as folder:
            root=Path(folder);stage=root/'stage';stage.write_bytes(b'payload');destination=root/'new'
            with fault, patch.dict(os.environ,{'HEPTA_HIA_ARTIFACT_PUBLICATION_MANIFEST':'selected'}), \
                 patch.object(native,'_validated_code',return_value=b'admitted descriptor control'), \
                 patch.object(native.subprocess,'run') as run, \
                 patch('hepta.artifact_publication._read_exact',side_effect=AssertionError('host fallback')):
                with self.assertRaisesRegex(PublicationRejected,'E_PUBLISH_NATIVE_CUSTODY') as caught:
                    publish_verified(stage,destination,b'payload')
                run.assert_not_called()
                self.assertFalse(destination.exists())
                self.assertEqual(stage.read_bytes(),b'payload')
            for descriptor in set(descriptors):self.assert_descriptor_closed(descriptor)
            return caught.exception

    def test_real_short_writes_preserve_exact_sealed_bytes_without_python_fcntl_names(self):
        import hepta.artifact_publication_native as native
        code=b'admitted descriptor control\x00\xff';observed=[];counts=[]
        write=os.write
        def short_write(fd, data):
            written=write(fd,data[:2]);counts.append(written);return written
        def inspect_sealed(argv, **kwargs):
            fd=int(argv[0].rsplit('/',1)[1]);observed.append(fd)
            self.assertEqual(fcntl.fcntl(fd,1034)&15,15)
            self.assertEqual(os.fstat(fd).st_size,len(code))
            self.assertEqual(os.pread(fd,len(code)+1,0),code)
            self.assertEqual(kwargs['pass_fds'],(fd,))
            for effect in (lambda:os.pwrite(fd,b'!',0),lambda:os.ftruncate(fd,0),
                           lambda:os.ftruncate(fd,len(code)+1)):
                with self.assertRaises(OSError) as caught:effect()
                self.assertEqual(caught.exception.errno,errno.EPERM)
            return subprocess.CompletedProcess(argv,0,b'observed',b'')
        # This intercepts child creation, not the real memfd/write/seal/readback.
        with patch.object(native,'_validated_code',return_value=code), \
             patch.object(native,'fcntl',SimpleNamespace(fcntl=fcntl.fcntl)), \
             patch.object(native.os,'write',side_effect=short_write), \
             patch.object(native.subprocess,'run',side_effect=inspect_sealed) as run:
            self.assertEqual(native._execute_native('selected','withdraw','stage','dest',b''),b'observed')
            run.assert_called_once()
        self.assertGreater(len(counts),1)
        self.assertEqual(sum(counts),len(code))
        self.assertEqual(len(observed),1)
        self.assert_descriptor_closed(observed[0])

    def test_real_zero_progress_after_short_write_refuses_before_publication(self):
        import hepta.artifact_publication_native as native
        write=os.write;descriptors=[];counts=[]
        def interrupted_write(fd, data):
            descriptors.append(fd)
            count=write(fd,data[:2] if not counts else b'');counts.append(count);return count
        self.assert_capture_refused(patch.object(native.os,'write',side_effect=interrupted_write),descriptors)
        self.assertEqual(counts,[2,0])

    def test_real_changed_extent_or_bytes_refuse_even_with_complete_kernel_seals(self):
        import hepta.artifact_publication_native as native
        kernel_fcntl=fcntl.fcntl
        for change in ('short','long','bytes'):
            with self.subTest(change=change):
                descriptors=[];observed_seals=[]
                def alter_before_sealing(fd, command, *args):
                    if command==1033:
                        descriptors.append(fd)
                        size=os.fstat(fd).st_size
                        if change=='bytes':os.pwrite(fd,b'X',0)
                        else:os.ftruncate(fd,size+(-1 if change=='short' else 1))
                    result=kernel_fcntl(fd,command,*args)
                    if command==1034:observed_seals.append(result)
                    return result
                error=self.assert_capture_refused(
                    patch.object(native.fcntl,'fcntl',side_effect=alter_before_sealing),descriptors)
                self.assertIn('bytes or extent differ',str(error))
                self.assertEqual(observed_seals,[15])
                self.assertEqual(len(descriptors),1)

    def test_real_kernel_seal_failure_is_typed_custody_without_publication(self):
        import hepta.artifact_publication_native as native
        create=os.memfd_create;descriptors=[]
        def nonsealable(name, flags):
            fd=create(name,flags&~os.MFD_ALLOW_SEALING);descriptors.append(fd)
            self.assertEqual(fcntl.fcntl(fd,1034),1)
            return fd
        error=self.assert_capture_refused(patch.object(native.os,'memfd_create',side_effect=nonsealable),descriptors)
        self.assertIsInstance(error.__cause__,OSError)
        self.assertEqual(error.__cause__.errno,errno.EPERM)
        self.assertEqual(len(descriptors),1)

    def test_incomplete_real_kernel_seals_refuse_before_publication(self):
        import hepta.artifact_publication_native as native
        kernel_fcntl=fcntl.fcntl;descriptors=[]
        def partial_sealing(fd, command, *args):
            if command==1033:
                descriptors.append(fd)
                return kernel_fcntl(fd,command,1)
            return kernel_fcntl(fd,command,*args)
        error=self.assert_capture_refused(
            patch.object(native.fcntl,'fcntl',side_effect=partial_sealing),descriptors)
        self.assertIn('complete kernel seals',str(error))
        self.assertEqual(len(descriptors),1)

    def test_absent_memfd_api_is_typed_custody_without_publication(self):
        import hepta.artifact_publication_native as native
        without_memfd=SimpleNamespace(fspath=os.fspath,close=os.close)
        error=self.assert_capture_refused(patch.object(native,'os',without_memfd),[])
        self.assertIsInstance(error.__cause__,AttributeError)

    def test_actual_kernel_requires_all_executable_seals(self):
        from hepta.artifact_publication_native import _require_sealed_executable
        import errno,fcntl
        for seals in (0,1,2,4,8,7,11,13,14,15):
            with self.subTest(seals=seals):
                fd=os.memfd_create('hia-publication-seal-control',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
                try:
                    os.write(fd,b'original')
                    if seals:fcntl.fcntl(fd,1033,seals)
                    self.assertEqual(fcntl.fcntl(fd,1034),seals)
                    if seals!=15:
                        with self.assertRaisesRegex(PublicationRejected,'complete kernel seals'):
                            _require_sealed_executable(fd)
                        continue
                    _require_sealed_executable(fd)
                    for effect in (lambda:os.write(fd,b'changed'),lambda:os.ftruncate(fd,0),
                                   lambda:os.ftruncate(fd,64)):
                        with self.assertRaises(OSError) as error:effect()
                        self.assertEqual(error.exception.errno,errno.EPERM)
                    self.assertEqual(os.pread(fd,64,0),b'original')
                finally:os.close(fd)

    def test_actual_descriptor_without_seal_support_refuses(self):
        from hepta.artifact_publication_native import _require_sealed_executable
        read_fd,write_fd=os.pipe()
        try:
            with self.assertRaises(OSError):_require_sealed_executable(read_fd)
        finally:os.close(read_fd);os.close(write_fd)

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
                fd=int(argv[0].rsplit('/',1)[1]);seals=fcntl.fcntl(fd,getattr(fcntl,'F_GET_SEALS',1034))
                required=(getattr(fcntl,'F_SEAL_WRITE',8)|getattr(fcntl,'F_SEAL_GROW',4)
                          |getattr(fcntl,'F_SEAL_SHRINK',2)|getattr(fcntl,'F_SEAL_SEAL',1))
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
