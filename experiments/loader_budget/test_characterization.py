"""Existing-loader observations, not claims that budgets are implemented."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from hepta import modules,packages
from hepta.ast import HeptaError
from experiments.c_char_boundary import test_prototype as fixtures


class LoaderReadCharacterization(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='hepta-loader-observation-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.entry=self.root/'main.hepta'
        self.entry.write_text('fn main()->Unit effects {} {}')

    def package(self):
        (self.root/'hepta.toml').write_text('[package]\nname="example"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')

    def observe(self,action):
        reads=[]
        original=Path.read_bytes
        def recording(path):
            data=original(path)
            reads.append((str(path),len(data)))
            return data
        with patch.object(Path,'read_bytes',recording):
            result=action()
        return result,reads

    def test_source_bytes_materialized_before_parser(self):
        payload=b'//'+b'x'*(2*1024*1024)+b'\nfn main()->Unit effects {} {}'
        self.entry.write_bytes(payload)
        parsed=[];original=modules.parse
        def record(text,path):
            parsed.append(len(text.encode('utf-8')))
            return original(text,path)
        with patch.object(modules,'parse',record):
            result,reads=self.observe(lambda:modules.load_project(self.entry))
        self.assertEqual(parsed,[len(payload)])
        self.assertEqual(result.source_bytes[str(self.entry)],payload)
        self.assertGreaterEqual(sum(p==str(self.entry) and n==len(payload) for p,n in reads),2)

    def test_unused_package_source_is_read_before_graph_completion(self):
        self.package();unused=self.root/'unused.hepta';unused.write_bytes(b'//'+b'x'*(2*1024*1024))
        result,reads=self.observe(lambda:modules.load_project(self.entry))
        self.assertNotIn(str(unused),result.source_bytes)
        self.assertIn((str(unused),unused.stat().st_size),reads)
        self.assertIn('unused.hepta',result.package_state['files'])

    def test_manifest_padding_is_read_before_toml(self):
        self.package();manifest=self.root/'hepta.toml'
        manifest.write_bytes(b'#'+b'x'*200_000+b'\n'+manifest.read_bytes())
        _,reads=self.observe(lambda:modules.load_project(self.entry))
        self.assertIn((str(manifest),manifest.stat().st_size),reads)

    def test_valid_lock_padding_is_fully_read_and_lock_is_still_enforced(self):
        self.package();packages.write_lock(self.root);lock=self.root/'Hepta.lock'
        lock.write_bytes(b' '*2_000_000+lock.read_bytes())
        result,reads=self.observe(lambda:modules.load_project(self.entry,locked=True))
        self.assertTrue(result.locked)
        self.assertIn((str(lock),lock.stat().st_size),reads)
        self.entry.write_text(self.entry.read_text()+'\n')
        with self.assertRaises(HeptaError) as error:modules.load_project(self.entry,locked=True)
        self.assertEqual(error.exception.diagnostic.code,'E_LOCK_STALE')

    @unittest.skipUnless(fixtures.CC,'GCC required to generate a real C import')
    def test_sidecar_and_original_header_materialized_by_loader(self):
        fixture=fixtures.CharPrototypeTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        entry,_=fixture.fixture()
        metadata=json.loads(fixture.sidecar.read_text());metadata['observation_padding']='x'*2_000_000
        fixture.sidecar.write_text(json.dumps(metadata))
        header=fixture.root/'api.h';header.write_bytes(b'/*'+b'x'*2_000_000+b'*/\n'+header.read_bytes())
        metadata['header_sha256']=packages.digest(header.read_bytes());fixture.sidecar.write_text(json.dumps(metadata))
        result,reads=self.observe(lambda:modules.load_project(entry))
        self.assertIn((str(fixture.sidecar),fixture.sidecar.stat().st_size),reads)
        self.assertIn((str(header),header.stat().st_size),reads)
        self.assertIn(str(header),result.source_bytes)

    def test_revalidation_rereads_whole_changed_source(self):
        result=modules.load_project(self.entry)
        self.entry.write_bytes(b'//'+b'x'*2_000_000+b'\nfn main()->Unit effects {} {}')
        unchanged,reads=self.observe(result.unchanged)
        self.assertFalse(unchanged)
        self.assertIn((str(self.entry),self.entry.stat().st_size),reads)
