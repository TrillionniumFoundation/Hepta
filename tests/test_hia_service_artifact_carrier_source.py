"""Strict v6 source composition; original six terminal controls remain unchanged."""
from pathlib import Path
from hashlib import sha256
import copy
import itertools
import json
import tempfile
import unittest
from tests import hia_service_artifact_worker_terminal as producer
from tools import read_hia_service_artifact_worker_terminal as reader

ROOT=Path(__file__).resolve().parents[1]

class ServiceArtifactCarrierSourceTests(unittest.TestCase):
    def tree(self, root, values):
        for name, raw in values.items():
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)

    def current(self):
        value=producer.SourceAuthority(ROOT)
        value.finish()
        return value

    def both(self, root):
        value=producer.SourceAuthority(root)
        captured=reader.Captures()
        self.assertEqual(reader.admit_source_authority(captured,root),value.summary())
        value.finish();captured.stable()
        return value,captured

    def test_all_four_exact_old_current_compositions_preserve_complete_old_authority(self):
        actual=self.current();records=producer.CARRIER_SOURCES
        self.assertEqual(len(records),2)
        self.assertEqual(sha256(actual.captured[producer.AUTHORITY]).hexdigest(),producer.AUTHORITY_SHA256)
        old={name:producer.carrier_predecessor(actual.captured[name],row['original'],path=name)[0]
             for name,row in records.items()}
        for name,row in records.items():
            self.assertEqual(producer.pin(old[name]),row['original'])
            self.assertEqual(producer.pin(actual.captured[name]),row['current'])
        with tempfile.TemporaryDirectory(prefix='artifact-carrier-sources-') as temporary:
            for index,flags in enumerate(itertools.product((False,True),repeat=2)):
                root=Path(temporary)/str(index);values=dict(actual.captured)
                expected=[]
                for name,selected in zip(records,flags):
                    if selected:expected.append(name)
                    else:values[name]=old[name]
                if not expected:values.pop(producer.CARRIER_AUTHORITY)
                self.tree(root,values)
                admitted,_=self.both(root)
                self.assertEqual(set(admitted.carrier_sources),set(expected))
                self.assertEqual(admitted.originals,actual.originals)
                self.assertEqual(admitted.value,actual.value)
                self.assertEqual(admitted.profile,actual.profile)
                if not expected:self.assertNotIn('carrier_source_admission',admitted.summary())
        actual.finish()

    def test_every_current_input_requires_fresh_capture_and_terminal_reread(self):
        actual=self.current();names=(*producer.CARRIER_SOURCES,producer.CARRIER_AUTHORITY)
        with tempfile.TemporaryDirectory(prefix='artifact-carrier-refusal-') as temporary:
            root=Path(temporary);self.tree(root,actual.captured)
            for name in names:
                path=root/name;raw=path.read_bytes()
                for missing in (False,True):
                    value,captured=self.both(root)
                    path.unlink() if missing else path.write_bytes(raw+b'\n')
                    for call in (lambda:producer.SourceAuthority(root),lambda:reader.admit_source_authority(reader.Captures(),root),value.finish,captured.stable):
                        with self.subTest(path=name,missing=missing),self.assertRaises((OSError,ValueError)):
                            call()
                    path.write_bytes(raw)
                    self.both(root)
            for name,row in producer.CARRIER_SOURCES.items():
                path=root/name;raw=path.read_bytes();value,captured=self.both(root)
                path.write_bytes(producer.carrier_predecessor(raw,row['original'],path=name)[0])
                with self.assertRaises(ValueError):value.finish()
                with self.assertRaises(ValueError):captured.stable()
                self.both(root)
                path.write_bytes(raw)
        actual.finish()

    def test_whole_inverse_rejects_typed_splice_and_authority_refresh(self):
        actual=self.current()
        fixture=json.loads(actual.captured[producer.CARRIER_AUTHORITY])
        for name,specification in fixture['source_successors'].items():
            raw=actual.captured[name]
            for invert in (producer.inverse,reader.original_source):
                restored=invert(raw,specification)
                self.assertEqual(producer.pin(restored),specification['original'])
                for invalid in (True,-1,0.0,'0'):
                    broken=copy.deepcopy(specification);broken['splices'][0]['offset']=invalid
                    with self.subTest(path=name,offset=invalid),self.assertRaises(ValueError):invert(raw,broken)
                for key in ('original','current'):
                    broken=copy.deepcopy(specification);broken[key]['sha256']='0'*64
                    with self.assertRaises(ValueError):invert(raw,broken)
            for check in (producer.carrier_predecessor,reader.carrier_predecessor):
                with self.assertRaises(ValueError):check(raw+b'\n',specification['original'],path=name)
                with self.assertRaises(ValueError):check(raw,specification['original'],path='tools/unrelated.py')
                for field in ('old_pass_transferred','source_admission_only'):
                    broken=copy.deepcopy(fixture);broken[field]=not broken[field]
                    changed=(json.dumps(broken,sort_keys=True,separators=(',',':'))+'\n').encode()
                    with self.assertRaises(ValueError):check(raw,specification['original'],path=name,read=lambda ignored:changed)
        actual.finish()

if __name__=='__main__':unittest.main()
