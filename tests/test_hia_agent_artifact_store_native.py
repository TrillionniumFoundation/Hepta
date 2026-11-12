"""Actual native Agent artifact file storage, not SQLite/journal replacement."""
from __future__ import annotations
from hashlib import sha256
from pathlib import Path
from tools.hia_artifact_publication_custody import observed_popen
import json,os,struct,subprocess,time,unittest,uuid
from unittest.mock import patch
from tests.test_hia_artifact_publication_native import observe,fields
import tests.test_hia_artifact_publication_native as _publication_helpers


class AgentArtifactStorePolicyTests(unittest.TestCase):
    def test_commands_root_and_only_exact_lower_hex_file_names(self):
        for name,op,destination in [('store-put',4,b'-'),('store-get',5,b'abcdef0123456789'*4),('store-hash',6,b'-')]:
            args=[name.encode(),b'/tmp/store/.',destination,b'/']
            wire=struct.pack('<4Q',*[len(v) for v in args])+b''.join(args)
            result,raw=observe(wire,b'',fields(p0=0),range(11))
            self.assertEqual(result,op)
            if op!=6:self.assertEqual(raw,b'/tmp/store\0')
        for bad in (b'../'+b'a'*61,b'F'*64,b'g'*64,b'a'*63,b'a'*65):
            args=[b'store-get',b'/tmp',bad,b'/'];wire=struct.pack('<4Q',*[len(v) for v in args])+b''.join(args)
            self.assertEqual(observe(wire,b'',fields(p0=0))[0],16)

    def test_owned_non_writable_directory_guard_and_full_store_quota(self):
        for mode,uid,wanted in [(0o40700,1000,0),(0o40750,1000,0),(0o40722,1000,10),(0o100600,1000,10),(0o40700,1,10)]:
            self.assertEqual(observe(b'',b'',fields(p0=10,p120=1000,p2072=mode|(uid<<32)))[0],wanted)
        for size,wanted in [(0,0),(64<<20,0),((64<<20)+1,17)]:
            self.assertEqual(observe(b'',b'',fields(p0=16,p16=size))[0],wanted)
            self.assertEqual(observe(b'',b'',fields(p0=11,p296=0o100400,p320=size,p112=1))[0],wanted)
        self.assertEqual(observe(b'',b'',fields(p0=20,p16=7,p24=8,p40=0))[0],11)

    def test_temporary_name_UUID4_bits_and_content_SHA_are_formed_in_HIA(self):
        random=bytes(range(16));w=bytearray(fields(p0=12));w[2200:2216]=random
        result,raw=observe(b'',b'',w,workspace_offsets=range(2336,2376))
        self.assertEqual(result,0);self.assertEqual(raw,b'.write-'+uuid.UUID(bytes=random,version=4).hex.encode()+b'\0')
        digest=sha256(b'content').digest()
        result,raw=observe(b'',digest,fields(p0=13),workspace_offsets=range(2256,2321))
        self.assertEqual(result,0);self.assertEqual(raw,digest.hex().encode()+b'\0')
        w=bytearray(fields(p0=14));w[2256:2320]=digest.hex().encode();w[2416:2480]=digest.hex().encode()
        self.assertEqual(observe(b'',b'',w)[0],0)
        w[2416]=ord('0') if w[2416]!=ord('0') else ord('1')
        self.assertEqual(observe(b'',b'',w)[0],11)


class AgentArtifactStoreKernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Uses genuine current-source cold under qualification, or actual
        # current HIA B0/B1/B2 in development. Never a fabricated cold receipt.
        _publication_helpers.ArtifactPublicationKernelTests.setUpClass()
        cls.app=_publication_helpers.ArtifactPublicationKernelTests.app;cls.folder=_publication_helpers.ArtifactPublicationKernelTests.folder
        cls.serial=0

    @classmethod
    def tearDownClass(cls):_publication_helpers.ArtifactPublicationKernelTests.tearDownClass()

    def setUp(self):
        type(self).serial+=1;self.case=self.folder/('store-case-'+str(self.serial));self.case.mkdir()
        self.root=self.case/'artifacts';self.root.mkdir(mode=0o700)

    def run_store(self,op,wire=b'',digest='-',code=0,prefix=(),root=None):
        result=subprocess.run([*prefix,str(self.app),op,str(root or self.root),digest],input=wire,capture_output=True,env={'PATH':''},timeout=60)
        self.assertEqual(result.returncode,code,(result.stdout,result.stderr))
        self.assertEqual(result.stderr,b'');return result

    def test_actual_empty_binary_and_multichunk_put_get_dedup_private_file(self):
        for payload in (b'',b'\0HIA\xff',bytes(range(256))*1025):
            digest=sha256(payload).hexdigest();receipt=json.loads(self.run_store('store-hash',payload).stdout)
            self.assertEqual(receipt,{'sha256':digest,'bytes':len(payload)})
            self.assertEqual(json.loads(self.run_store('store-put',payload).stdout),receipt)
            path=self.root/digest;before=path.stat();self.assertEqual(path.read_bytes(),payload)
            self.assertEqual(before.st_mode&0o777,0o400);self.assertEqual(before.st_uid,os.geteuid())
            self.assertEqual(self.run_store('store-get',digest=digest).stdout,payload)
            self.assertEqual(json.loads(self.run_store('store-put',payload).stdout),receipt)
            self.assertEqual(path.stat().st_ino,before.st_ino)
            self.assertEqual(sorted(p.name for p in self.root.iterdir()),sorted(sha256(v).hexdigest() for v in (b'',b'\0HIA\xff',bytes(range(256))*1025)[:(b'',b'\0HIA\xff',bytes(range(256))*1025).index(payload)+1]))
        self.assertFalse(list(self.root.glob('.write-*')))

    def test_corrupt_existing_file_and_different_digest_refuse_without_replacing(self):
        payload=b'good';digest=sha256(payload).hexdigest();target=self.root/digest;target.write_bytes(b'bad')
        self.run_store('store-put',payload,code=11);self.assertEqual(target.read_bytes(),b'bad')
        self.run_store('store-get',digest=digest,code=11);self.assertEqual(target.read_bytes(),b'bad')
        self.assertFalse(list(self.root.glob('.write-*')))

    def test_symlink_FIFO_root_permissions_and_path_traversal_refuse(self):
        payload=b'good';digest=sha256(payload).hexdigest();other=self.case/'other';other.write_bytes(payload)
        target=self.root/digest;target.symlink_to(other)
        self.run_store('store-put',payload,code=10);self.run_store('store-get',digest=digest,code=10)
        self.assertTrue(target.is_symlink());self.assertEqual(other.read_bytes(),payload)
        target.unlink();os.mkfifo(target)
        self.run_store('store-get',digest=digest,code=10)
        for bad in ('../escape','A'*64,'z'*64):self.run_store('store-get',digest=bad,code=16)
        self.root.chmod(0o722);self.run_store('store-put',payload,code=10)
        self.root.chmod(0o700);alias=self.case/'alias';alias.symlink_to(self.root,target_is_directory=True)
        self.run_store('store-put',payload,root=alias,code=15)

    def test_real_file_and_directory_fsync_and_post_fsync_receipt_boundary(self):
        trace=self.case/'fsync.trace';payload=b'durable';digest=sha256(payload).hexdigest()
        self.run_store('store-put',payload,prefix=('/usr/bin/strace','-o',str(trace),'-e','trace=fsync,openat,linkat,unlinkat,write'))
        text=trace.read_text();self.assertEqual(text.count('fsync('),2)
        self.assertLess(text.index('fsync('),text.index('linkat('))
        self.assertLess(text.index('linkat('),text.rindex('fsync('))
        self.assertLess(text.rindex('fsync('),text.index('write(1,'))
        self.assertEqual(self.run_store('store-get',digest=digest).stdout,payload)

    def test_actual_file_fsync_failure_no_content_or_success_receipt(self):
        trace=self.case/'file-sync-failure.trace';payload=b'not durable';digest=sha256(payload).hexdigest()
        result=self.run_store('store-put',payload,code=15,prefix=('/usr/bin/strace','-o',str(trace),'-e','trace=fsync,linkat,unlinkat','-e','inject=fsync:error=EIO:when=1'))
        self.assertEqual(result.stdout,b'');self.assertFalse((self.root/digest).exists());self.assertFalse(list(self.root.glob('.write-*')))
        self.assertIn('EIO',trace.read_text())

    def test_actual_directory_fsync_failure_leaves_no_success_and_preserves_possible_content(self):
        trace=self.case/'dir-sync-failure.trace';payload=b'no issuance';digest=sha256(payload).hexdigest()
        result=self.run_store('store-put',payload,code=15,prefix=('/usr/bin/strace','-o',str(trace),'-e','trace=fsync,linkat,unlinkat','-e','inject=fsync:error=EIO:when=2'))
        self.assertEqual(result.stdout,b'');self.assertEqual((self.root/digest).read_bytes(),payload)
        self.assertFalse(list(self.root.glob('.write-*')))

    def test_quota_is_original_64MiB_and_never_applied_to_generic_publisher(self):
        # Actual accepted inclusive boundary AND first rejected byte. Generic
        # publisher's separate65MiB proof is not an Agent quota qualification.
        accepted=b'x'*(64<<20);digest=sha256(accepted).hexdigest()
        expected={'sha256':digest,'bytes':len(accepted)}
        self.assertEqual(json.loads(self.run_store('store-put',accepted).stdout),expected)
        self.assertEqual(self.run_store('store-get',digest=digest).stdout,accepted)
        (self.root/digest).unlink()
        payload=b'x'*((64<<20)+1)
        self.run_store('store-hash',payload,code=17);self.run_store('store-put',payload,code=17)
        self.assertEqual(list(self.root.iterdir()),[])

    def delayed_link_race(self,mutation,expected):
        payload=b'actual native store race';digest=sha256(payload).hexdigest()
        target=self.root/digest;trace=self.case/'race.trace'
        process=observed_popen(['/usr/bin/strace','-o',str(trace),'-e','trace=linkat,unlinkat',
            '-e','inject=linkat:delay_exit=500ms',str(self.app),'store-put',str(self.root),'-'],offered_input=payload,
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':''})
        try:
            process.stdin.write(payload);process.stdin.close();process.stdin=None
            deadline=time.monotonic()+5
            while not target.exists() and process.poll() is None and time.monotonic()<deadline:time.sleep(.001)
            self.assertTrue(target.exists(),'native link checkpoint not reached')
            mutation(target)
            out,err=process.communicate(timeout=10)
            self.assertEqual((process.returncode,out,err),(expected,b'',b''),trace.read_text())
        finally:
            if process.poll() is None:process.kill();process.communicate(timeout=5)
        self.assertFalse(list(self.root.glob('.write-*')))
        return target

    def test_real_post_link_corruption_withdraws_only_own_content_inode(self):
        def corrupt(target):
            target.chmod(0o600);target.write_bytes(b'corrupted in place')
        target=self.delayed_link_race(corrupt,11)
        self.assertFalse(target.exists())

    def test_real_post_link_competitor_inode_is_never_deleted(self):
        competitor=self.case/'competitor';competitor.write_bytes(b'other writer')
        target=self.delayed_link_race(lambda target:os.replace(competitor,target),10)
        self.assertEqual(target.read_bytes(),b'other writer')


class AgentArtifactStoreRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _publication_helpers.ArtifactPublicationKernelTests.setUpClass()
        cls.folder=_publication_helpers.ArtifactPublicationKernelTests.folder
        cls.app=_publication_helpers.ArtifactPublicationKernelTests.app
        cls.serial=0
        cls.manifest=cls.app.parent/'build.json'
        if not cls.manifest.exists():
            # Actual development B0/B1/B2 image, explicitly NOT a fabricated
            # cold receipt. Qualification uses the strict current-cold builder.
            from tools.build_hia_artifact_publication import current_sources,SOURCES,OPERATIONS,ROOT
            from tools.hia_selfhost_contract import PROFILE
            cls.manifest.write_text(json.dumps({
                'schema':'hepta.hia.artifact-publication-build.v1','status':'NATIVE_ARTIFACT_PUBLICATION_BUILT',
                'profile':PROFILE,'source_manifest':current_sources(),'operations':OPERATIONS,
                'executable_path':'hia-artifact','executable_sha256':sha256(cls.app.read_bytes()).hexdigest(),
                'source_sha256':{name:sha256((ROOT/name).read_bytes()).hexdigest() for name in SOURCES},
                'development_only':True,'matching_source_cold_qualified':False}))

    @classmethod
    def tearDownClass(cls):_publication_helpers.ArtifactPublicationKernelTests.tearDownClass()

    def setUp(self):
        from hepta.hia_agent_store import AgentStore
        type(self).serial+=1;self.case=self.folder/('route-'+str(self.serial));self.case.mkdir()
        self.selected=patch.dict(os.environ,{'HEPTA_HIA_AGENT_ARTIFACT_STORE_MANIFEST':str(self.manifest)})
        self.selected.start();self.addCleanup(self.selected.stop)
        self.store=AgentStore(self.case/'state');self.addCleanup(self.store.close)

    def test_real_store_bytes_metadata_dedup_restart_and_namespace_authority(self):
        import hepta.hia_agent_store as store
        payloads=(b'',b'\0independent HIA file layer\xff',bytes(range(256))*1100)
        def no_payload_hash(raw):
            if raw in payloads:raise AssertionError('host payload SHA')
            return sha256(raw)  # metadata/ref identity hashing remains hosted.
        with patch.object(store,'sha256',side_effect=no_payload_hash),\
             patch.object(store,'stable_read',side_effect=AssertionError('host payload read')),\
             patch.object(store.os,'link',side_effect=AssertionError('host artifact link')),\
             patch.object(store.os,'fsync',side_effect=AssertionError('host artifact fsync')):
            refs=[]
            for payload in payloads:
                ref=self.store.put(payload,'input',{'label':'雪','n':len(payload)})
                self.assertEqual(ref['sha256'],sha256(payload).hexdigest())
                self.assertEqual(self.store.get(ref,kind='input'),(payload,{'label':'雪','n':len(payload)}))
                self.assertEqual(self.store.put(payload,'input',{'label':'雪','n':len(payload)}),ref)
                distinct=self.store.put(payload,'other',{'label':'雪','n':len(payload)})
                self.assertNotEqual(distinct['id'],ref['id']);refs.append(ref)
            reopened=store.AgentStore(self.store.root)
            try:
                for ref,payload in zip(refs,payloads):self.assertEqual(reopened.get(ref)[0],payload)
            finally:reopened.close()
            foreign=store.AgentStore(self.case/'foreign')
            try:
                with self.assertRaises(store.AgentRejected) as error:foreign.get(refs[0])
                self.assertEqual(error.exception.code,'E_HIA_ARTIFACT_IDENTITY')
            finally:foreign.close()
        self.assertFalse(list(self.store.artifacts.glob('.write-*')))

    def test_ref_and_kind_checks_precede_native_file_access_and_corruption_refuses(self):
        import hepta.hia_agent_store as store
        ref=self.store.put(b'original','input')
        with patch.object(store,'_native_artifact_file',side_effect=AssertionError('unauthorized native access')):
            for changed,kind,code in [({**ref,'sha256':'f'*64},None,'E_HIA_ARTIFACT_IDENTITY'),
                                     (ref,'profile','E_HIA_ARTIFACT_AUTHORITY')]:
                with self.assertRaises(store.AgentRejected) as error:self.store.get(changed,kind=kind)
                self.assertEqual(error.exception.code,code)
        path=self.store.artifacts/ref['sha256'];path.chmod(0o600);path.write_bytes(b'corrupt!')
        with patch.object(store,'stable_read',side_effect=AssertionError('host fallback')):
            for action in (lambda:self.store.get(ref),lambda:self.store.put(b'original','input')):
                with self.assertRaises(store.AgentRejected) as error:action()
                self.assertEqual(error.exception.code,'E_HIA_ARTIFACT_CORRUPT')
        self.assertEqual(path.read_bytes(),b'corrupt!')

    def test_missing_selected_code_never_falls_back_or_issues_reference(self):
        import hepta.hia_agent_store as store
        with patch.dict(os.environ,{'HEPTA_HIA_AGENT_ARTIFACT_STORE_MANIFEST':str(self.case/'missing.json')}),\
             patch.object(store,'sha256',side_effect=AssertionError('host fallback')):
            with self.assertRaises(store.AgentRejected) as error:self.store.put(b'input','input')
            self.assertEqual(error.exception.code,'E_HIA_ARTIFACT_NATIVE_CUSTODY')
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM artifacts').fetchone()[0],0)
        self.assertEqual(list(self.store.artifacts.iterdir()),[])

    def test_one_put_uses_one_immutable_code_admission_but_next_call_revalidates(self):
        import hepta.hia_agent_store as store
        import hepta.artifact_publication_native as native
        original_run=subprocess.run;original_admit=native._admitted_code
        code=self.app.read_bytes();operations=[]
        def replace_between_hash_and_put(argv,*args,**kwargs):
            result=original_run(argv,*args,**kwargs);operations.append(argv[1])
            if argv[1]=='store-hash':self.app.write_bytes(b'changed mutable executable path')
            return result
        try:
            with patch.object(native,'_admitted_code',wraps=original_admit) as admit,\
                 patch.object(native.subprocess,'run',side_effect=replace_between_hash_and_put):
                ref=self.store.put(b'one admitted version','input')
                self.assertEqual(operations,['store-hash','store-put'])
                self.assertEqual(admit.call_count,1)
                # No persistent code cache may let a new public call execute
                # stale code after the on-disk selected program has changed.
                with self.assertRaises(store.AgentRejected) as error:self.store.put(b'next call','input')
                self.assertEqual(error.exception.code,'E_HIA_ARTIFACT_NATIVE_CUSTODY')
                self.assertEqual(admit.call_count,2)
                self.assertEqual(self.store.db.execute('SELECT count(*) FROM artifacts').fetchone()[0],1)
        finally:self.app.write_bytes(code)
        self.assertEqual(self.store.get(ref)[0],b'one admitted version')

    def test_selection_cannot_change_between_hash_and_file_publication(self):
        import hepta.hia_agent_store as store
        import hepta.artifact_publication_native as native
        original_run=subprocess.run
        for replacement in ('',str(self.case/'different.json')):
            def change_selection(argv,*args,**kwargs):
                result=original_run(argv,*args,**kwargs)
                if argv[1]=='store-hash':os.environ['HEPTA_HIA_AGENT_ARTIFACT_STORE_MANIFEST']=replacement
                return result
            with patch.dict(os.environ,{'HEPTA_HIA_AGENT_ARTIFACT_STORE_MANIFEST':str(self.manifest)}),\
                 patch.object(native.subprocess,'run',side_effect=change_selection):
                with self.assertRaises(store.AgentRejected) as error:self.store.put(b'no mixed admission','input')
                self.assertEqual(error.exception.code,'E_HIA_ARTIFACT_NATIVE_CUSTODY')
            self.assertEqual(self.store.db.execute('SELECT count(*) FROM artifacts').fetchone()[0],0)
            self.assertEqual(list(self.store.artifacts.iterdir()),[])

    def test_actual_native_fsync_failures_cannot_issue_DB_refs_or_replay_effects(self):
        import hepta.hia_agent_store as store
        import hepta.artifact_publication_native as native
        original_run=subprocess.run
        for when in (1,2):
            payload=('fsync-fail-'+str(when)).encode();digest=sha256(payload).hexdigest();calls=[]
            trace=self.case/('fsync-'+str(when)+'.trace')
            def injected(argv,*args,**kwargs):
                calls.append(argv[1])
                if argv[1]=='store-put':
                    argv=['/usr/bin/strace','-o',str(trace),'-e','trace=fsync,linkat,unlinkat',
                          '-e','inject=fsync:error=EIO:when='+str(when),*argv]
                return original_run(argv,*args,**kwargs)
            with patch.object(native.subprocess,'run',side_effect=injected):
                with self.assertRaises(store.AgentRejected) as error:self.store.put(payload,'input')
            self.assertEqual(error.exception.code,'E_HIA_ARTIFACT_FILE')
            self.assertEqual(calls,['store-hash','store-put'])
            self.assertEqual(self.store.db.execute('SELECT count(*) FROM artifacts').fetchone()[0],0)
            self.assertFalse(list(self.store.artifacts.glob('.write-*')))
            path=self.store.artifacts/digest
            self.assertEqual(path.exists(),when==2)
            if path.exists():self.assertEqual(path.read_bytes(),payload)
            self.assertIn('EIO',trace.read_text())
