"""Real lossless-stage roundtrip and no-retirement failure controls."""
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch
import zipfile
from tools.hia_evidence_archive import OWNER, archive_completed_stage,verify_archive,read_retained_evidence

class EvidenceArchiveTests(unittest.TestCase):
    def test_exact_binary_modes_and_nested_members_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'new-stage';root.mkdir();(root/OWNER).write_text('fresh')
            (root/'nested').mkdir();payload=bytes(range(256))*8192
            (root/'nested/image.bin').write_bytes(payload);(root/'nested/image.bin').chmod(0o700)
            (root/'empty').write_bytes(b'')
            result=archive_completed_stage(root,'fresh')
            manifest=verify_archive(result['archive'])
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
