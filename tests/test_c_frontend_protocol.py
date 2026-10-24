"""Transport failures cannot fall back to the unaudited AST-only path."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from hepta import c_frontend as f

class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.source=b'int f(int x){return x;}\n'
        self.data={'schema':1,'compiler':'Debian clang version 19.1.7 (3+b1)',
                   'target':'x86_64-pc-linux-gnu','source_sha256':hashlib.sha256(self.source).hexdigest(),
                   'source_size':len(self.source),'int_bits':32,'long_bits':64,'long_long_bits':64,'pointer_bits':64,
                   'main_macro_expansions':[],'ast_json':'{"kind":"TranslationUnitDecl","inner":[]}'}
    def invoke(self,raw):
        with patch.dict('os.environ',{'HEPTA_C_FRONTEND':sys.executable}), patch.object(f,'_capture',side_effect=['Debian clang version 19.1.7 (3+b1)\n','/resource\n','x86_64-pc-linux-gnu\n',raw]):
            return f.scalar_frontend(Path('/input.c'),self.source,'clang')
    def test_corrupt_bindings_fail_closed(self):
        for key,value in [('schema',2),('schema',True),('compiler','clang 20'),('target','other'),('source_sha256','0'*64),('source_size',0),('int_bits',64),('long_long_bits',32),('pointer_bits',None),('ast_json',{}),('main_macro_expansions',[{'name':'PLUS','offset':-1}])]:
            with self.subTest(key=key):
                d=copy.deepcopy(self.data);d[key]=value
                with self.assertRaises(f.FrontendError) as c:self.invoke(json.dumps(d))
                self.assertEqual(c.exception.code,'E_C_FRONTEND_PROTOCOL')
    def test_multiple_and_duplicate_envelopes_rejected(self):
        raw=json.dumps(self.data)
        for text in [raw+raw,raw[:-1]+',"schema":1}', 'not json']:
            with self.subTest(text=text):
                with self.assertRaises(f.FrontendError) as c:self.invoke(text)
                self.assertEqual(c.exception.code,'E_C_FRONTEND_PROTOCOL')
    def test_valid_protocol_and_original_ast_key_order(self):
        self.data['ast_json']='{"kind":"TranslationUnitDecl","loc":{},"inner":[]}'
        ast,model=self.invoke(json.dumps(self.data))
        self.assertEqual(list(ast),['kind','loc','inner']);self.assertEqual(model['sizeof_long_long'],8)
    def test_output_limit_while_running(self):
        with patch.object(f,'LIMIT',1024):
            with self.assertRaises(f.FrontendError) as c:f._capture([sys.executable,'-c','import sys;sys.stdout.write("x"*100000)'])
        self.assertEqual(c.exception.code,'E_C_FRONTEND_SIZE')
    def test_stderr_is_also_bounded(self):
        with patch.object(f,'LIMIT',1024):
            with self.assertRaises(f.FrontendError) as c:f._capture([sys.executable,'-c','import sys;sys.stderr.write("x"*100000)'])
        self.assertEqual(c.exception.code,'E_C_FRONTEND_SIZE')
    def test_timeout_and_nonzero_even_with_json(self):
        with patch.object(f,'TIMEOUT',0.05):
            with self.assertRaises(f.FrontendError) as c:f._capture([sys.executable,'-c','import time;time.sleep(1)'])
        self.assertEqual(c.exception.code,'E_C_FRONTEND_TIMEOUT')
        with self.assertRaises(f.FrontendError) as c:f._capture([sys.executable,'-c','print("{}");raise SystemExit(1)'])
        self.assertEqual(c.exception.code,'E_CLANG_REJECT')

    def test_wrong_driver_version_rejected_before_parse(self):
        with patch.dict('os.environ',{'HEPTA_C_FRONTEND':sys.executable}), patch.object(f,'_capture',return_value='clang version 20.0.0\n') as capture:
            with self.assertRaises(f.FrontendError) as c:
                f.scalar_frontend(Path('/input.c'),self.source,'clang')
        self.assertEqual(c.exception.code,'E_C_FRONTEND_ENV')
        self.assertEqual(capture.call_count,1)
