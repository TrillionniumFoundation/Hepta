import hashlib
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import patch
from hepta import c_project_publish as m


class PublishTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name); self.stage = self.root/'stage'; self.stage.mkdir(mode=0o700)
        self.dest = self.root/'output'; self.expected = {}
        for name in ('source.hepta','bridge.rs','generated.rs','migration.json'):
            data = (name + ': validated').encode()
            (self.stage/name).write_bytes(data)
            self.expected[name] = {'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
    def facade(self, **kw):
        obj = types.SimpleNamespace(**(vars(os) | kw))
        # Preserve actual capability membership when wrapping a supported op.
        obj.supports_dir_fd = set(os.supports_dir_fd)
        obj.supports_follow_symlinks = set(os.supports_follow_symlinks)
        obj.supports_fd = set(os.supports_fd)
        for name, fn in kw.items():
            if callable(fn) and getattr(os,name,None) in os.supports_dir_fd: obj.supports_dir_fd.add(fn)
            if callable(fn) and getattr(os,name,None) in os.supports_follow_symlinks: obj.supports_follow_symlinks.add(fn)
            if callable(fn) and getattr(os,name,None) in os.supports_fd: obj.supports_fd.add(fn)
        return obj
    def run_publish(self): return m.publish_no_replace(self.stage,self.dest,expected=self.expected)
    def assert_rejected_clean(self, fn=None):
        with self.assertRaises((m.PublicationRejected,OSError)) as caught:
            (fn or self.run_publish)()
        self.assertFalse(self.dest.exists())
        if hasattr(caught.exception,'cleanup'): self.assertTrue(caught.exception.cleanup['confirmed'])
        return caught.exception
    def test_positive_digest_new_regular_inodes(self):
        receipt=self.run_publish(); self.assertEqual(receipt['artifacts'],self.expected)
        for name in self.expected:
            self.assertFalse((self.dest/name).is_symlink())
            self.assertNotEqual((self.dest/name).stat().st_ino,(self.stage/name).stat().st_ino)
            self.assertEqual(hashlib.sha256((self.dest/name).read_bytes()).hexdigest(),self.expected[name]['sha256'])
    def test_manifest_created_last(self):
        names=[]
        def open_(path,flags,*a,**kw):
            if flags & os.O_CREAT: names.append(path)
            return os.open(path,flags,*a,**kw)
        linked=[]
        def link(a,b,**kw):
            linked.append(b)
            self.assertTrue(str(a).startswith('.hepta-manifest-ready-'))
            self.assertEqual(kw['src_dir_fd'],kw['dst_dir_fd'])
            return os.link(a,b,**kw)
        with patch.object(m,'os',self.facade(open=open_,link=link)): self.run_publish()
        self.assertTrue(names[-1].startswith('.hepta-manifest-ready-'))
        self.assertEqual(linked,['migration.json'])
        self.assertEqual(set(p.name for p in self.dest.iterdir()),set(self.expected))
    def test_existing_directory_preserved(self):
        self.dest.mkdir(); (self.dest/'foreign').write_text('keep')
        with self.assertRaises(FileExistsError): self.run_publish()
        self.assertEqual((self.dest/'foreign').read_text(),'keep')
    def test_dangling_output_symlink_preserved(self):
        self.dest.symlink_to(self.root/'missing')
        with self.assertRaises(FileExistsError): self.run_publish()
        self.assertTrue(self.dest.is_symlink())
    def test_unsupported_before_creation(self):
        facade=self.facade(); facade.supports_dir_fd=set()
        with patch.object(m,'os',facade): self.assert_rejected_clean()
    def test_writable_parent_refused_no_permission_change(self):
        self.root.chmod(0o777)
        try:
            self.assert_rejected_clean()
            self.assertEqual(stat.S_IMODE(self.root.stat().st_mode),0o777)
        finally: self.root.chmod(0o700)  # Restore only this test-owned directory.
    def test_symlink_ancestor_refused(self):
        alias=self.root/'alias'; alias.symlink_to(self.stage,target_is_directory=True)
        with self.assertRaises((m.PublicationRejected,OSError)):
            m.publish_no_replace(alias/'stage',alias/'out',expected=self.expected)
    def test_foreign_entry_on_acquisition_rejected_preserved(self):
        def mkdir(name,*a,**kw):
            os.mkdir(name,*a,**kw)
            if name==self.dest.name: (self.dest/'foreign').write_text('keep')
        with patch.object(m,'os',self.facade(mkdir=mkdir)):
            with self.assertRaises(m.PublicationRejected) as caught: self.run_publish()
        self.assertFalse(caught.exception.cleanup['confirmed'])
        self.assertEqual(list(p.name for p in self.dest.iterdir()),['foreign'])
    def test_stage_symlink_refused(self):
        p=self.stage/'source.hepta'; p.unlink();p.symlink_to(self.stage/'bridge.rs')
        self.assert_rejected_clean()
    def test_stage_directory_refused(self):
        p=self.stage/'source.hepta';p.unlink();p.mkdir();self.assert_rejected_clean()
    def test_stage_fifo_refused_without_blocking(self):
        p=self.stage/'source.hepta';p.unlink();os.mkfifo(p);self.assert_rejected_clean()
    def test_stage_digest_mismatch_refused(self):
        (self.stage/'source.hepta').write_text('wrong');self.assert_rejected_clean()
    def test_unexpected_stage_file_refused(self):
        (self.stage/'extra').write_text('x');self.assert_rejected_clean()
    def test_missing_stage_manifest_refused(self):
        (self.stage/'migration.json').unlink();self.assert_rejected_clean()
    def swap_after_source_acquisition(self, symlink):
        def mkdir(name,*a,**kw):
            os.mkdir(name,*a,**kw)
            if name==self.dest.name:
                p=self.stage/'source.hepta';p.rename(self.stage/'original')
                if symlink: p.symlink_to(self.stage/'bridge.rs')
                else: p.write_text('unvalidated replacement')
        with patch.object(m,'os',self.facade(mkdir=mkdir)):
            # Rename changes retained inode ctime on this filesystem: reject,
            # rather than use the substituted pathname. No manifest survives.
            try: self.run_publish()
            except m.PublicationRejected:
                self.assertFalse(self.dest.exists());return
        self.assertEqual((self.dest/'source.hepta').read_bytes(),(self.stage/'original').read_bytes())
        self.assertFalse((self.dest/'source.hepta').is_symlink())
    def test_stage_symlink_replacement_never_copied(self): self.swap_after_source_acquisition(True)
    def test_stage_regular_replacement_never_copied(self): self.swap_after_source_acquisition(False)
    def test_source_inplace_mutation_refused(self):
        def mkdir(name,*a,**kw):
            os.mkdir(name,*a,**kw)
            if name==self.dest.name: (self.stage/'source.hepta').write_text('changed')
        with patch.object(m,'os',self.facade(mkdir=mkdir)): self.assert_rejected_clean()
    def test_short_writes_are_completed(self):
        def write(fd,data): return os.write(fd,data[:1])
        with patch.object(m,'os',self.facade(write=write)): self.run_publish()
        self.assertEqual((self.dest/'source.hepta').read_bytes(),(self.stage/'source.hepta').read_bytes())
    def test_zero_write_refused_cleaned(self):
        with patch.object(m,'os',self.facade(write=lambda fd,data:0)): self.assert_rejected_clean()
    def test_partial_copy_failure_cleaned(self):
        count=[]
        def write(fd,data):
            count.append(True)
            if len(count)>1: raise OSError('synthetic copy failure')
            return os.write(fd,data[:1])
        with patch.object(m,'os',self.facade(write=write)): self.assert_rejected_clean()
    def test_fsync_failure_cleaned(self):
        def fail(fd): raise OSError('synthetic fsync failure')
        with patch.object(m,'os',self.facade(fsync=fail)): self.assert_rejected_clean()
    def test_postopen_directory_symlink_swap_no_redirect(self):
        outside=self.root/'outside';outside.mkdir();moved=self.root/'moved';swapped=[]
        def fstat(fd):
            value=os.fstat(fd)
            if self.dest.exists() and not swapped:
                swapped.append(True); self.dest.rename(moved);self.dest.symlink_to(outside,target_is_directory=True)
            return value
        with patch.object(m,'os',self.facade(fstat=fstat)):
            with self.assertRaises(m.PublicationRejected): self.run_publish()
        self.assertEqual(list(outside.iterdir()),[]);self.assertEqual(list(moved.iterdir()),[])
        self.assertTrue(self.dest.is_symlink())
    def test_cleanup_failure_explicit_not_confirmed(self):
        def fsync(fd): raise OSError('synthetic fsync failure')
        def unlink(*a,**kw): raise OSError('synthetic cleanup failure')
        with patch.object(m,'os',self.facade(fsync=fsync,unlink=unlink)):
            with self.assertRaises(OSError) as caught: self.run_publish()
        self.assertFalse(caught.exception.cleanup['confirmed'])
        self.assertTrue(caught.exception.cleanup['remaining_entries'])
    def test_source_changes_during_copy_rejected(self):
        changed=[]
        def write(fd,data):
            result=os.write(fd,data)
            if not changed:
                changed.append(True);(self.stage/'bridge.rs').write_text('mid-copy mutation')
            return result
        with patch.object(m,'os',self.facade(write=write)): self.assert_rejected_clean()
    def test_manifest_fsync_failure_removes_manifest_first(self):
        order=[]
        def fsync(fd):
            if self.dest.exists() and (self.dest/'migration.json').exists():
                order.clear()  # Exclude normal ready-name removal before failure.
                raise OSError('synthetic manifest fsync failure')
            return os.fsync(fd)
        def unlink(name,**kw): order.append(name);return os.unlink(name,**kw)
        with patch.object(m,'os',self.facade(fsync=fsync,unlink=unlink)): self.assert_rejected_clean()
        self.assertEqual(order[0],'migration.json')
    def test_missing_mkdir_capability_rejected(self):
        facade=self.facade();facade.supports_dir_fd.remove(os.mkdir)
        with patch.object(m,'os',facade): self.assert_rejected_clean()
    def test_replacement_directory_foreign_entry_preserved(self):
        def mkdir(name,*a,**kw):
            os.mkdir(name,*a,**kw)
            if name==self.dest.name:
                self.dest.rename(self.root/'original');self.dest.mkdir()
                (self.dest/'foreign').write_text('not ours')
        with patch.object(m,'os',self.facade(mkdir=mkdir)):
            with self.assertRaises(m.PublicationRejected) as caught: self.run_publish()
        self.assertFalse(caught.exception.cleanup['confirmed'])
        self.assertEqual((self.dest/'foreign').read_text(),'not ours')
        self.assertFalse((self.dest/'migration.json').exists())
    def test_output_leaf_replacement_never_deleted_as_ours(self):
        changed=[]
        def fsync(fd):
            if not changed:
                changed.append(True)
                path=self.dest/'bridge.rs';path.rename(self.root/'owned-original')
                path.write_text('foreign')
                raise OSError('synthetic failure after output substitution')
            return os.fsync(fd)
        with patch.object(m,'os',self.facade(fsync=fsync)):
            with self.assertRaises(OSError) as caught: self.run_publish()
        self.assertFalse(caught.exception.cleanup['confirmed'])
        self.assertEqual((self.dest/'bridge.rs').read_text(),'foreign')
        self.assertFalse((self.dest/'migration.json').exists())
    def test_directory_fsync_failure_cleanup(self):
        def fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode): raise OSError('synthetic directory fsync failure')
            return os.fsync(fd)
        with patch.object(m,'os',self.facade(fsync=fsync)): self.assert_rejected_clean()
    def test_created_but_unacquired_directory_cleanup_unknown(self):
        def open_(name,flags,*a,**kw):
            if name==self.dest.name and flags & os.O_DIRECTORY:
                raise OSError('synthetic acquisition failure')
            return os.open(name,flags,*a,**kw)
        with patch.object(m,'os',self.facade(open=open_)):
            with self.assertRaises(OSError) as caught: self.run_publish()
        self.assertFalse(caught.exception.cleanup['confirmed'])
        self.assertEqual(list(self.dest.iterdir()),[])
    def manifest_observer(self, *, write_failure=False, fsync_failure=False, foreign=False):
        ready=[];counts=[];synced=[];linked=[]
        def open_(name,flags,*a,**kw):
            fd=os.open(name,flags,*a,**kw)
            if flags & os.O_CREAT and str(name).startswith('.hepta-manifest-ready-'):
                ready.append(fd)
                self.assertFalse((self.dest/'migration.json').exists())
            return fd
        def write(fd,data):
            if fd in ready:
                self.assertFalse((self.dest/'migration.json').exists())
                counts.append(True)
                if write_failure and len(counts)>1: raise OSError('synthetic ready copy failure')
                return os.write(fd,data[:1])
            return os.write(fd,data)
        def fsync(fd):
            if fd in ready:
                self.assertFalse((self.dest/'migration.json').exists())
                if fsync_failure: raise OSError('synthetic ready fsync failure')
                synced.append(fd)
            return os.fsync(fd)
        def link(a,b,**kw):
            self.assertEqual(b,'migration.json')
            self.assertEqual(len(synced),1)
            self.assertFalse((self.dest/b).exists())
            # At the only publication syscall the ready inode is fully copied,
            # hash-checked and fsynced, and exactly the fd held by the publisher.
            st=os.stat(a,dir_fd=kw['src_dir_fd'],follow_symlinks=False)
            self.assertEqual(st.st_ino,os.fstat(ready[0]).st_ino)
            self.assertEqual(os.pread(ready[0],10000,0),(self.stage/b).read_bytes())
            if foreign:(self.dest/b).write_text('foreign marker')
            result=os.link(a,b,**kw);linked.append(True)
            self.assertEqual((self.dest/b).read_bytes(),(self.stage/b).read_bytes())
            return result
        with patch.object(m,'os',self.facade(open=open_,write=write,fsync=fsync,link=link)):
            if write_failure or fsync_failure:
                self.assert_rejected_clean()
            elif foreign:
                with self.assertRaises(FileExistsError) as caught:self.run_publish()
                self.assertFalse(caught.exception.cleanup['confirmed'])
                self.assertEqual((self.dest/'migration.json').read_text(),'foreign marker')
                self.assertTrue(set(self.expected).issubset(p.name for p in self.dest.iterdir()))
                self.assertFalse(caught.exception.cleanup['final_marker_absence_confirmed'])
                for name in set(self.expected)-{'migration.json'}:
                    self.assertEqual((self.dest/name).read_bytes(),(self.stage/name).read_bytes())
            else:self.run_publish()
        if not(write_failure or fsync_failure or foreign):
            self.assertGreater(len(counts),1);self.assertEqual(linked,[True])
    def test_manifest_invisible_during_all_short_writes(self): self.manifest_observer()
    def test_ready_copy_failure_never_exposes_manifest(self): self.manifest_observer(write_failure=True)
    def test_ready_fsync_failure_never_exposes_manifest(self): self.manifest_observer(fsync_failure=True)
    def test_foreign_manifest_at_exclusive_commit_never_overwritten(self): self.manifest_observer(foreign=True)
    def test_link_succeeds_then_interrupt_cleanup_knows_final_alias(self):
        def link(a,b,**kw):
            os.link(a,b,**kw)
            raise KeyboardInterrupt('synthetic interrupt after successful link')
        with patch.object(m,'os',self.facade(link=link)):
            with self.assertRaises(KeyboardInterrupt) as caught:self.run_publish()
        self.assertTrue(caught.exception.cleanup['confirmed'])
        self.assertTrue(caught.exception.cleanup['final_marker_absence_confirmed'])
        self.assertFalse(self.dest.exists())
    def test_marker_unlink_failure_preserves_all_data_without_retry(self):
        unlinks=[]
        def fsync(fd):
            if self.dest.exists() and (self.dest/'migration.json').exists():
                raise OSError('synthetic postcommit directory sync failure')
            return os.fsync(fd)
        def unlink(name,**kw):
            unlinks.append(name)
            if name=='migration.json':raise PermissionError('synthetic marker cleanup denial; no OS denial')
            return os.unlink(name,**kw)
        with patch.object(m,'os',self.facade(fsync=fsync,unlink=unlink)):
            with self.assertRaises(OSError) as caught:self.run_publish()
        self.assertEqual(unlinks.count('migration.json'),1)
        self.assertEqual(unlinks[-1],'migration.json')
        self.assertFalse(caught.exception.cleanup['confirmed'])
        self.assertFalse(caught.exception.cleanup['final_marker_absence_confirmed'])
        for name in self.expected:
            self.assertEqual((self.dest/name).read_bytes(),(self.stage/name).read_bytes())
    def test_marker_stat_unknown_preserves_all_data(self):
        failed=[];stats=[]
        def fsync(fd):
            if self.dest.exists() and (self.dest/'migration.json').exists():
                failed.append(True);raise OSError('synthetic sync failure')
            return os.fsync(fd)
        def stat_(name,*a,**kw):
            if failed and name=='migration.json' and 'dir_fd' in kw:
                stats.append(name);raise OSError('synthetic marker status unknown')
            return os.stat(name,*a,**kw)
        with patch.object(m,'os',self.facade(fsync=fsync,stat=stat_)):
            with self.assertRaises(OSError) as caught:self.run_publish()
        self.assertEqual(stats,['migration.json'])
        self.assertFalse(caught.exception.cleanup['final_marker_absence_confirmed'])
        for name in self.expected:self.assertEqual((self.dest/name).read_bytes(),(self.stage/name).read_bytes())
    def test_oversized_source_rejected_before_read(self):
        (self.stage/'bridge.rs').write_bytes(b'x'*(2*1024*1024));reads=[]
        def read(fd,size):reads.append(size);return os.read(fd,size)
        with patch.object(m,'os',self.facade(read=read)):self.assert_rejected_clean()
        self.assertEqual(reads,[])
    def test_digest_growth_reads_at_most_expected_plus_one(self):
        original=self.stage/'bridge.rs';fd=os.open(original,os.O_RDONLY)
        self.addCleanup(os.close,fd);budget=self.expected['bridge.rs']['bytes'];reads=[]
        def read(source,size):
            if not reads:original.write_bytes(b'x'*(2*1024*1024))
            data=os.read(source,size);reads.append(len(data));return data
        with patch.object(m,'os',self.facade(read=read)):
            with self.assertRaises(m.PublicationRejected):m._digest_fd(fd,budget)
        self.assertLessEqual(sum(reads),budget+1)
    def test_copy_growth_cannot_read_or_write_unbounded_data(self):
        source=self.stage/'bridge.rs';budget=self.expected['bridge.rs']['bytes'];copying=[];reads=[];writes=[]
        def open_(name,flags,*a,**kw):
            fd=os.open(name,flags,*a,**kw)
            if name=='bridge.rs' and flags & os.O_CREAT:copying.append(fd)
            return fd
        def read(fd,size):
            if copying and not reads:source.write_bytes(b'x'*(2*1024*1024))
            data=os.read(fd,size)
            if copying:reads.append(len(data))
            return data
        def write(fd,data):writes.append(len(data));return os.write(fd,data)
        with patch.object(m,'os',self.facade(open=open_,read=read,write=write)):
            self.assert_rejected_clean()
        self.assertLessEqual(sum(reads),budget+1)
        self.assertLessEqual(sum(writes),budget)
    def test_copy_truncation_rejected_promptly(self):
        copying=[]
        def open_(name,flags,*a,**kw):
            fd=os.open(name,flags,*a,**kw)
            if name=='bridge.rs' and flags & os.O_CREAT:copying.append(True)
            return fd
        def read(fd,size):
            if copying:(self.stage/'bridge.rs').write_bytes(b'')
            return os.read(fd,size)
        with patch.object(m,'os',self.facade(open=open_,read=read)):self.assert_rejected_clean()
    def close_failure_control(self, *, early_parent=False, success=False):
        opened=[];closed=[]
        def open_(name,flags,*a,**kw):
            fd=os.open(name,flags,*a,**kw);opened.append(fd);return fd
        def close(fd):
            closed.append(fd);os.close(fd)
            if len(closed)==1:raise OSError('synthetic close error AFTER actual close')
        def read(fd,size):
            if not success:raise OSError('original read failure')
            return os.read(fd,size)
        if early_parent:self.root.chmod(0o777)
        try:
            with patch.object(m,'os',self.facade(open=open_,close=close,read=read)):
                with self.assertRaises((OSError,m.PublicationRejected)) as caught:self.run_publish()
        finally:
            if early_parent:self.root.chmod(0o700)
        self.assertEqual(len(closed),len(set(closed)))
        self.assertEqual(set(closed),set(opened))
        self.assertFalse(caught.exception.cleanup['confirmed'])
        self.assertEqual(len(caught.exception.cleanup['fd_close_errors']),1)
        if not early_parent and not success:self.assertEqual(str(caught.exception),'original read failure')
        if early_parent:self.assertIsInstance(caught.exception,m.PublicationRejected)
        for fd in opened:
            with self.assertRaises(OSError):os.fstat(fd)
        if success:
            self.assertTrue(caught.exception.cleanup['complete_marker_may_remain'])
            for name in self.expected:self.assertEqual((self.dest/name).read_bytes(),(self.stage/name).read_bytes())
    def test_close_failure_preserves_primary_and_closes_remaining_once(self):self.close_failure_control()
    def test_parent_chain_close_failure_preserves_rejection(self):self.close_failure_control(early_parent=True)
    def test_successful_commit_close_failure_is_not_success(self):self.close_failure_control(success=True)


import hepta
from hepta import c_migration_project as migration_service

class Translator:
    contracts={}; inventory=[];inventory_complete=True
    def __init__(self,*a): pass
    def emit(self): return 'validated Hepta\n','bridge\n',[]

class Integration(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);self.root=Path(temp.name)
        replacements=[patch.object(migration_service,'capture_project',return_value={'dependencies':[],'configurations':[]}),
          patch.object(migration_service,'CTranslator',Translator),patch.object(migration_service,'verify_capture'),
          patch('hepta.parser.parse',return_value=object()),
          patch('hepta.checker.check',return_value=types.SimpleNamespace(ok=True)),
          patch('hepta.backend.emit_rust',return_value='generated\n'),
          patch('hepta.backend.compile_rust',side_effect=AssertionError('native forbidden'))]
        for p in replacements:p.start();self.addCleanup(p.stop)
    def test_public_entrypoint_positive_manifest_hashes(self):
        import json,hashlib
        report=migration_service.migrate_project('unused-db',self.root/'out')
        self.assertTrue(report['ok']);self.assertEqual(report['native_validation'],'not_run')
        manifest=json.loads((self.root/'out/migration.json').read_text())
        self.assertEqual(manifest,report)
        for name,item in report['artifacts'].items():
            data=(self.root/'out'/name).read_bytes()
            self.assertEqual(item,{'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)})
    def test_public_entrypoint_trust_refusal(self):
        self.root.chmod(0o777)
        try:
            report=migration_service.migrate_project('unused-db',self.root/'out')
            self.assertFalse(report['ok']);self.assertFalse((self.root/'out').exists())
            self.assertEqual(report['diagnostics'][-1]['code'],'E_C_PROJECT_PUBLISH')
        finally:self.root.chmod(0o700)
    def test_public_entrypoint_cleanup_evidence_retained(self):
        error=hepta.c_project_publish.PublicationRejected('synthetic publication failure')
        error.cleanup={'confirmed':False,'remaining_entries':['foreign'],'errors':['changed']}
        with patch('hepta.c_project_publish.publish_no_replace',side_effect=error):
            report=migration_service.migrate_project('unused-db',self.root/'out')
        self.assertFalse(report['ok']);self.assertEqual(report['publication_cleanup'],error.cleanup)
    def test_real_postlink_error_report_rejected_and_marker_removed(self):
        publisher=hepta.c_project_publish
        def link(a,b,**kw):
            os.link(a,b,**kw);raise OSError('synthetic postlink error')
        facade=types.SimpleNamespace(**(vars(os)|{'link':link}))
        facade.supports_dir_fd=os.supports_dir_fd|{link}
        with patch.object(publisher,'os',facade):report=migration_service.migrate_project('unused-db',self.root/'out')
        self.assertFalse(report['ok']);self.assertEqual(report['status'],'rejected')
        self.assertTrue(report['publication_cleanup']['final_marker_absence_confirmed'])
        self.assertFalse((self.root/'out').exists())
    def test_real_marker_cleanup_unknown_returns_rejected_preserves_data(self):
        publisher=hepta.c_project_publish
        def fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError('synthetic postcommit sync failure')
            return os.fsync(fd)
        calls=[]
        def unlink(name,**kw):
            if name=='migration.json':
                calls.append(name);raise OSError('synthetic marker cleanup failure')
            return os.unlink(name,**kw)
        facade=types.SimpleNamespace(**(vars(os)|{'fsync':fsync,'unlink':unlink}))
        facade.supports_dir_fd=os.supports_dir_fd|{unlink}
        with patch.object(publisher,'os',facade):report=migration_service.migrate_project('unused-db',self.root/'out')
        self.assertFalse(report['ok']);self.assertEqual(report['status'],'rejected')
        self.assertFalse(report['publication_cleanup']['confirmed'])
        self.assertFalse(report['publication_cleanup']['final_marker_absence_confirmed'])
        self.assertEqual(calls,['migration.json'])
        for name in ('migration.json','source.hepta','bridge.rs','generated.rs'):
            self.assertTrue((self.root/'out'/name).is_file())
    def test_public_primary_and_unknown_cleanup_survive_close_failure(self):
        publisher=hepta.c_project_publish;opened=[];closed=[]
        def open_(name,flags,*a,**kw):
            fd=os.open(name,flags,*a,**kw);opened.append(fd);return fd
        def close(fd):
            closed.append(fd);os.close(fd)
            if len(closed)==1:raise OSError('synthetic secondary close failure after effect')
        def fsync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):raise OSError('primary directory fsync failure')
            return os.fsync(fd)
        def unlink(name,**kw):
            if name=='migration.json':raise OSError('synthetic marker cleanup failure')
            return os.unlink(name,**kw)
        facade=types.SimpleNamespace(**(vars(os)|{'open':open_,'close':close,'fsync':fsync,'unlink':unlink}))
        facade.supports_dir_fd=os.supports_dir_fd|{open_,unlink}
        with patch.object(publisher,'os',facade):report=migration_service.migrate_project('unused-db',self.root/'out')
        self.assertFalse(report['ok']);self.assertEqual(report['status'],'rejected')
        self.assertEqual(report['diagnostics'][-1]['message'],'primary directory fsync failure')
        self.assertFalse(report['publication_cleanup']['confirmed'])
        self.assertFalse(report['publication_cleanup']['final_marker_absence_confirmed'])
        self.assertEqual(len(report['publication_cleanup']['fd_close_errors']),1)
        self.assertEqual(set(opened),set(closed));self.assertEqual(len(closed),len(set(closed)))
        for fd in opened:
            with self.assertRaises(OSError):os.fstat(fd)
        for name in ('migration.json','source.hepta','bridge.rs','generated.rs'):
            self.assertTrue((self.root/'out'/name).is_file())


if __name__=="__main__": unittest.main()
