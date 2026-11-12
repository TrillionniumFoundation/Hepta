"""Real lossless-stage roundtrip and no-retirement failure controls."""
from pathlib import Path
from hashlib import sha256
import json
import os
import random
import stat
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from tools import hia_evidence_archive as archive_tools
from tools.hia_evidence_archive import OWNER, archive_completed_stage,verify_archive,read_retained_evidence

class EvidenceArchiveTests(unittest.TestCase):
    def fresh_stage(self,temporary,payload=b'original\x00evidence'):
        root=Path(temporary)/'new-stage';root.mkdir();(root/OWNER).write_text('fresh')
        (root/'nested').mkdir();(root/'nested/bytes').write_bytes(payload)
        (root/'empty').write_bytes(b'')
        return root,payload

    def assert_originals_preserved(self,root,payload):
        self.assertEqual((root/OWNER).read_text(),'fresh')
        self.assertEqual((root/'nested/bytes').read_bytes(),payload)
        self.assertEqual((root/'empty').read_bytes(),b'')
        self.assertFalse((root/'ARCHIVED.json').exists())

    @staticmethod
    def rewrite_first_byte(path,restore=False):
        info=path.stat()
        with path.open('r+b') as stream:
            original=stream.read(1);stream.seek(0);stream.write(bytes([original[0]^1]));stream.flush()
            if restore:stream.seek(0);stream.write(original);stream.flush()
        os.utime(path,ns=(info.st_atime_ns,info.st_mtime_ns))

    @staticmethod
    def replace_published(temporary,destination,real_link):
        # Preserve bytes, mode, mtime and the expected link count on BOTH inodes.
        # A digest or link-count-only check must not accept this substitution.
        info=destination.stat();replacement=destination.parent/'replacement.zip'
        replacement.write_bytes(destination.read_bytes());replacement.chmod(stat.S_IMODE(info.st_mode))
        os.utime(replacement,ns=(info.st_atime_ns,info.st_mtime_ns));replacement.replace(destination)
        real_link(temporary,destination.parent/'old-inode-alias')
        real_link(destination,destination.parent/'new-inode-alias')

    def test_exact_binary_modes_and_nested_members_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'new-stage';root.mkdir();(root/OWNER).write_text('fresh')
            (root/'nested').mkdir();payload=bytes(range(256))*8192
            (root/'nested/image.bin').write_bytes(payload);(root/'nested/image.bin').chmod(0o700)
            (root/'empty').write_bytes(b'')
            with patch('tools.hia_evidence_archive.verify_archive',wraps=verify_archive) as replay:
                result=archive_completed_stage(root,'fresh')
            self.assertEqual(replay.call_count,1)
            manifest=verify_archive(result['archive'])
            self.assertEqual(result['archive_sha256'],sha256(Path(result['archive']).read_bytes()).hexdigest())
            self.assertEqual(result['packed_bytes'],Path(result['archive']).stat().st_size)
            self.assertEqual(Path(result['archive']).stat().st_nlink,1)
            self.assertTrue(result['every_original_byte_verified_before_retirement'])
            self.assertFalse((root/'nested/image.bin').exists())
            with zipfile.ZipFile(result['archive']) as archive:self.assertEqual(archive.read('nested/image.bin'),payload)
            self.assertEqual(manifest['files']['nested/image.bin']['mode'],0o700)
            self.assertEqual(result['files'],3)
            with self.assertRaises((ValueError,FileNotFoundError)):archive_completed_stage(root,'fresh')

    def test_missing_owner_symlink_or_failed_replay_preserves_originals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'new-stage';root.mkdir();original=root/'bytes';original.write_bytes(b'original\x00')
            with self.assertRaises(FileNotFoundError):archive_completed_stage(root,'fresh')
            (root/OWNER).write_text('fresh')
            with patch('tools.hia_evidence_archive.verify_archive',side_effect=ValueError('failed replay')):
                with self.assertRaisesRegex(ValueError,'failed replay'):archive_completed_stage(root,'fresh')
            self.assertEqual(original.read_bytes(),b'original\x00')
            self.assertFalse(root.with_suffix('.zip').exists())
            alias=root/'alias';alias.symlink_to(original)
            with self.assertRaises(ValueError):archive_completed_stage(root,'fresh')
            self.assertEqual(original.read_bytes(),b'original\x00')

    def test_original_and_retired_nested_artifact_have_identical_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'stage';root.mkdir();(root/OWNER).write_text('owner')
            path=root/'nested'/'object.o';path.parent.mkdir();payload=bytes(range(256))*17
            path.write_bytes(payload)
            self.assertEqual(read_retained_evidence(path),payload)
            archive_completed_stage(root,'owner')
            self.assertEqual(read_retained_evidence(path),payload)
            self.assertFalse(path.exists())
            with self.assertRaises(FileNotFoundError):read_retained_evidence(root/'not-in-inventory')

    def test_wrong_receipt_or_changed_archive_cannot_substitute_retired_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'stage';root.mkdir();(root/OWNER).write_text('owner')
            path=root/'object.o';path.write_bytes(b'actual original object bytes')
            result=archive_completed_stage(root,'owner');receipt=root/'ARCHIVED.json'
            for key,value in [('archive_sha256','0'*64),('manifest_sha256','0'*64),
                    ('archive',str(root.parent/'unrelated.zip')),('raw_paths_available',True),
                    ('every_original_byte_verified_before_retirement',False),('files',0)]:
                changed={**result,key:value};receipt.write_text(json.dumps(changed))
                with self.subTest(field=key),self.assertRaises(ValueError):read_retained_evidence(path)
            receipt.write_text(json.dumps(result))
            archive=Path(result['archive']);archive.write_bytes(archive.read_bytes()+b'changed')
            with self.assertRaisesRegex(ValueError,'archive digest'):read_retained_evidence(path)

    def test_temporary_replacement_during_replay_preserves_originals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root,payload=self.fresh_stage(temporary)
            def replace_after_replay(stream):
                result=verify_archive(stream)
                packed=next(Path(temporary).glob('.hia-archive-*'))
                substitute=Path(temporary)/'replacement.zip'
                substitute.write_bytes(packed.read_bytes());substitute.replace(packed)
                return result
            with patch('tools.hia_evidence_archive.verify_archive',side_effect=replace_after_replay):
                with self.assertRaises(ValueError):archive_completed_stage(root,'fresh')
            self.assert_originals_preserved(root,payload)
            self.assertFalse(root.with_name(root.name+'.zip').exists())

    def test_in_place_rewrite_during_replay_preserves_originals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root,payload=self.fresh_stage(temporary)
            def rewrite_after_replay(stream):
                result=verify_archive(stream)
                self.rewrite_first_byte(next(Path(temporary).glob('.hia-archive-*')))
                return result
            with patch('tools.hia_evidence_archive.verify_archive',side_effect=rewrite_after_replay):
                with self.assertRaises(ValueError):archive_completed_stage(root,'fresh')
            self.assert_originals_preserved(root,payload)

    def test_link_boundary_byte_change_with_restored_mtime_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root,payload=self.fresh_stage(temporary);real_link=os.link
            def rewrite_at_link(source,destination):
                real_link(source,destination);self.rewrite_first_byte(Path(destination))
            with patch('tools.hia_evidence_archive.os.link',side_effect=rewrite_at_link):
                with self.assertRaisesRegex(ValueError,'published archive bytes differ'):
                    archive_completed_stage(root,'fresh')
            self.assert_originals_preserved(root,payload)

    def test_published_replacement_with_same_bytes_and_link_counts_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root,payload=self.fresh_stage(temporary);real_link=os.link
            def replace_at_link(source,destination):
                real_link(source,destination)
                self.replace_published(Path(source),Path(destination),real_link)
            with patch('tools.hia_evidence_archive.os.link',side_effect=replace_at_link):
                with self.assertRaises(ValueError):archive_completed_stage(root,'fresh')
            self.assert_originals_preserved(root,payload)

    def test_published_replacement_after_digest_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root,payload=self.fresh_stage(temporary);real_digest=archive_tools._archive_sha256;calls=0
            def replace_after_digest(*args):
                nonlocal calls
                result=real_digest(*args);calls+=1
                if calls==3:
                    self.replace_published(next(Path(temporary).glob('.hia-archive-*')),
                                           root.with_name(root.name+'.zip'),os.link)
                return result
            with patch('tools.hia_evidence_archive._archive_sha256',side_effect=replace_after_digest):
                with self.assertRaises(ValueError):archive_completed_stage(root,'fresh')
            self.assert_originals_preserved(root,payload)

    def test_mid_hash_rewrites_even_when_bytes_and_mtime_are_restored_are_rejected(self):
        payload=random.Random(17).randbytes(2*1024*1024)
        for target_hash in (1,3):
            for restore in (False,True):
                with self.subTest(hash=target_hash,restored=restore),tempfile.TemporaryDirectory() as temporary:
                    root,_=self.fresh_stage(temporary,payload);real_pread=os.pread;hashes=0
                    def rewrite_mid_hash(descriptor,size,offset):
                        nonlocal hashes
                        result=real_pread(descriptor,size,offset)
                        if offset==0:
                            hashes+=1
                            if hashes==target_hash:
                                self.assertLess(size,os.fstat(descriptor).st_size)
                                packed=(next(Path(temporary).glob('.hia-archive-*')) if target_hash==1
                                        else root.with_name(root.name+'.zip'))
                                self.rewrite_first_byte(packed,restore)
                        return result
                    with patch('tools.hia_evidence_archive.os.pread',side_effect=rewrite_mid_hash):
                        with self.assertRaises(ValueError):archive_completed_stage(root,'fresh')
                    self.assert_originals_preserved(root,payload)

    def test_changed_original_is_detected_before_any_retirement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root,payload=self.fresh_stage(temporary);changed=payload+b' changed'
            def change_original(stream):
                result=verify_archive(stream);(root/'nested/bytes').write_bytes(changed);return result
            with patch('tools.hia_evidence_archive.verify_archive',side_effect=change_original):
                with self.assertRaisesRegex(ValueError,'stage changed before seal'):
                    archive_completed_stage(root,'fresh')
            self.assert_originals_preserved(root,changed)
            self.assertFalse(root.with_name(root.name+'.zip').exists())

    def test_member_bytes_changed_during_zip_write_fail_independent_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root,payload=self.fresh_stage(temporary);real_write=zipfile.ZipFile.writestr
            def change_captured_member(archive,member,data,*args,**kwargs):
                if isinstance(member,zipfile.ZipInfo) and member.filename=='nested/bytes':
                    data=bytes([data[0]^1])+data[1:]
                return real_write(archive,member,data,*args,**kwargs)
            with patch('tools.hia_evidence_archive.zipfile.ZipFile.writestr',new=change_captured_member):
                with self.assertRaisesRegex(ValueError,'archive member digest'):
                    archive_completed_stage(root,'fresh')
            self.assert_originals_preserved(root,payload)
            self.assertFalse(root.with_name(root.name+'.zip').exists())

    def test_member_mutation_during_capture_preserves_all_originals(self):
        with tempfile.TemporaryDirectory() as temporary:
            root,payload=self.fresh_stage(temporary);real_read=Path.read_bytes;changed=payload+b' change'
            def change_after_capture(path):
                result=real_read(path)
                if path==root/'nested/bytes':path.write_bytes(changed)
                return result
            with patch('tools.hia_evidence_archive.Path.read_bytes',new=change_after_capture):
                with self.assertRaisesRegex(ValueError,'stage changed while reading'):
                    archive_completed_stage(root,'fresh')
            self.assert_originals_preserved(root,changed)
            self.assertFalse(root.with_name(root.name+'.zip').exists())

    def test_receipt_time_replacement_preserves_originals_and_discards_unsealed_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root,payload=self.fresh_stage(temporary);real_dump=json.dump
            def replace_while_writing_receipt(*args,**kwargs):
                result=real_dump(*args,**kwargs)
                self.replace_published(next(Path(temporary).glob('.hia-archive-*')),
                                       root.with_name(root.name+'.zip'),os.link)
                return result
            with patch('tools.hia_evidence_archive.json.dump',side_effect=replace_while_writing_receipt):
                with self.assertRaises(ValueError):archive_completed_stage(root,'fresh')
            self.assert_originals_preserved(root,payload)
