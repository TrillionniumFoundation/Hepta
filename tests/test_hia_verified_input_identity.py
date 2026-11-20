"""Input execution must match the canonical bytes named by a final-code proof.

The stale-cache controls change neither the trusted interpreter nor functions
in a running process. They use ordinary timestamp bytecode with the original
source size and timestamp, then start a fresh process. This models the same
stale deployment case as the established loaded-source admission contract.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
AVAILABLE = (platform.system() == "Linux" and platform.machine().lower() in {"x86_64", "amd64"}
             and shutil.which("ld") is not None and importlib.util.find_spec("z3") is not None)
INPUT_MODULES = (
    "hia_json_decode.py", "hia_json_canonical_native.py", "hia_sha256_native.py",
    "hia_core_admission_native.py", "hia_function_shape_native.py",
    "hia_program_shape_native.py", "hia_instruction_policy_native.py",
)
PRELUDE = r'''
import ctypes, hashlib, importlib, json, os, py_compile, struct, subprocess, sys
from pathlib import Path
root = Path(sys.argv[1])
sys.path.insert(0, str(root))
core = {
    'schema': 'hepta.hia.program.v1', 'module': 'input_identity',
    'functions': [{
        'name': 'calculate',
        'params': [{'name':'a','type':'u64'}, {'name':'b','type':'u64'}],
        'returns': ['u64'], 'effects': [], 'entry': 'entry',
        'blocks': [{
            'id': 'entry',
            'params': [{'name':'a','type':'u64'}, {'name':'b','type':'u64'}],
            'ops': [{'op':'int.add.wrap','args':['a','b'],
                     'out':[{'name':'answer','type':'u64'}],'attrs':{}}],
            'term': {'op':'ret','values':['answer']},
        }],
    }],
}
wire = json.dumps(core, sort_keys=True, separators=(',', ':')).encode()
source_digest = hashlib.sha256(wire).hexdigest()

def execute(path):
    function = ctypes.CDLL(str(path)).calculate
    function.argtypes = (ctypes.c_uint64, ctypes.c_uint64)
    function.restype = ctypes.c_uint64
    return function(7, 3)

def proof(value=None, filename='candidate.so'):
    from hepta.hia_verified_scalar import build_verified_scalar
    return build_verified_scalar(core if value is None else value, root / filename)

def stale_timestamp(filename, before, after):
    path = root / 'hepta' / filename
    original = path.read_text()
    assert original.count(before) == 1, (filename, before)
    changed = original.replace(before, after)
    # Make an old, functional source version of exactly the current byte
    # length. Only a module docstring is padded or shortened; py_compile
    # itself writes the timestamp header. No bytecode/header is forged.
    delta = len(changed.encode()) - len(original.encode())
    begin = changed.index('"""') + 3
    end = changed.index('"""', begin)
    assert end - begin > max(0, delta)
    changed = (changed[:begin] + changed[begin + delta:] if delta >= 0 else
               changed[:begin] + ' ' * (-delta) + changed[begin:])
    assert len(changed.encode()) == len(original.encode())
    metadata = path.stat()
    path.write_text(changed)
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    cached = Path(py_compile.compile(str(path), doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP))
    path.write_text(original)
    os.utime(path, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
    assert path.read_text() == original and path.stat().st_size == metadata.st_size
    assert struct.unpack('<III', cached.read_bytes()[4:16]) == (
        0, int(metadata.st_mtime), metadata.st_size)

def reject_build(value=None):
    from hepta.hia_loaded_source import VerifiedSourceRejected
    try:
        result = proof(value)
    except VerifiedSourceRejected:
        pass
    else:
        observed = execute(root / 'candidate.so')
        raise AssertionError('unbound input execution produced a completed proof: ' + json.dumps({
            'ok':result['validation']['ok'], 'complete':result['validation']['complete'],
            'reported_core_sha256':result['validation']['core_sha256'],
            'expected_source_sha256':source_digest, 'observed_for_7_3':observed,
            'expected_for_7_3':10,
        }))
    assert not (root / 'candidate.so').exists()
'''
DECODER_STALE = r'''
stale_timestamp('hia_json_decode.py', 'return json.loads(wire)',
    'return json.loads(wire.replace(b\'"int.add.wrap"\', b\'"int.sub.wrap"\'))')
'''


@unittest.skipUnless(AVAILABLE, "Linux x86-64, GNU ld and pinned Z3 are required")
class VerifiedInputIdentityTests(unittest.TestCase):
    def child(self, source):
        with tempfile.TemporaryDirectory(prefix="hia-input-identity-") as directory:
            root = Path(directory)
            shutil.copytree(ROOT / "hepta", root / "hepta", ignore=shutil.ignore_patterns("__pycache__"))
            completed = subprocess.run([sys.executable, "-I", "-B", "-c",
                PRELUDE + textwrap.dedent(source), str(root)],
                capture_output=True, text=True, timeout=60)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_fresh_scalar_input_forms_bind_decoder_execution_and_actual_source_hash(self):
        self.child(r'''
from hepta.hia_program import VerifiedProgram
for number, value in enumerate((core, wire, VerifiedProgram(wire))):
    path = str(number) + '.so'
    report = proof(value, path)['validation']
    assert report['ok'] and report['complete']
    assert report['core_sha256'] == report['subject']['core_sha256'] == source_digest
    assert execute(root / path) == 10
    identity = report['checker']['input_execution']['python_sources']
    for filename in MODULES:
        assert identity[filename] == hashlib.sha256((root / 'hepta' / filename).read_bytes()).hexdigest()
'''.replace("MODULES", repr(INPUT_MODULES)))

    def test_matching_timestamp_decoder_cache_is_still_accepted(self):
        self.child(r'''
path = root / 'hepta/hia_json_decode.py'
py_compile.compile(str(path), doraise=True, invalidation_mode=py_compile.PycInvalidationMode.TIMESTAMP)
report = proof()['validation']
assert report['ok'] and report['complete'] and report['core_sha256'] == source_digest
assert execute(root / 'candidate.so') == 10
''')

    def test_stale_canonical_decoder_cannot_relabel_subtraction_with_the_original_add_hash(self):
        for form in ("dict", "wire", "verified"):
            with self.subTest(input_form=form):
                self.child(DECODER_STALE + r'''
from hepta.hia_program import VerifiedProgram
form = FORM
value = core if form == 'dict' else wire if form == 'wire' else VerifiedProgram(wire)
reject_build(value)
'''.replace("FORM", repr(form)))

    def test_independent_consumer_also_rejects_the_stale_decoder_without_emitting_code(self):
        self.child(r'''
# Prepare an intentionally mismatched subtraction artifact in an independent
# fresh process. The tested consumer receives the original addition Core.
prepare = r"""
import json,sys
from pathlib import Path
root=Path(sys.argv[1]); sys.path.insert(0,str(root))
from hepta.hia_verified_scalar import emit_verified_scalar, build_verified_scalar
core=json.loads(sys.argv[2]); core['functions'][0]['blocks'][0]['ops'][0]['op']='int.sub.wrap'
image=emit_verified_scalar(core)
(root/'supplied.o').write_bytes(image.object_bytes)
build_verified_scalar(core,root/'supplied.so',image=image)
"""
prepared = subprocess.run([sys.executable,'-I','-B','-c',prepare,str(root),wire.decode()],
    capture_output=True,text=True,timeout=30)
assert prepared.returncode == 0, prepared.stdout + prepared.stderr
''' + DECODER_STALE + r'''
from hepta.hia_loaded_source import VerifiedSourceRejected
from hepta.hia_safe_core import validate_safe_core_artifact
from unittest.mock import patch
try:
    with patch('hepta.hia_verified_scalar.emit_verified_scalar', side_effect=AssertionError('producer called')):
        report = validate_safe_core_artifact(core,(root/'supplied.o').read_bytes(),
                                             (root/'supplied.so').read_bytes(),profile_version=2)
except VerifiedSourceRejected:
    pass
else:
    raise AssertionError('consumer attached original add SHA to subtraction: ' + json.dumps({
        'ok':report['ok'], 'complete':report['complete'],
        'reported_core_sha256':report['core_sha256'], 'original_add_sha256':source_digest,
        'observed_for_7_3':execute(root/'supplied.so'),
    }))
''')

    def test_stale_payload_hasher_cannot_issue_a_successful_report_with_a_false_subject_hash(self):
        self.child(r'''
stale_timestamp('hia_sha256_native.py', 'return _foreign_sha256(wire).digest()',
                "return b'\\0' * 32")
reject_build()
''')

    def test_each_executed_input_entry_source_is_rechecked_after_import(self):
        for filename in INPUT_MODULES:
            with self.subTest(module=filename):
                self.child(r'''
filename = FILENAME
importlib.import_module('hepta.' + filename[:-3])
path = root / 'hepta' / filename
path.write_text(path.read_text() + '\n# changed after input module execution\n')
reject_build()
'''.replace("FILENAME", repr(filename)))

    def test_fresh_simd_consumer_reports_the_same_executed_input_closure(self):
        self.child(r'''
from hepta.hia_verified_simd import emit_verified_simd, simd_kernel_program
from hepta.hia_verified_simd_check import validate_verified_simd_artifact
document = simd_kernel_program('sum_u8')
image = emit_verified_simd(document,unroll=1)
obj,final=root/'simd.o',root/'simd.so';obj.write_bytes(image.object_bytes)
linked=subprocess.run(['ld','-m','elf_x86_64','-shared','-z','defs','-z','noexecstack',
    '-z','relro','-z','now','--hash-style=both','--build-id=none',str(obj),'-lc','-o',str(final)],
    capture_output=True,text=True,timeout=30)
assert linked.returncode == 0, linked.stdout + linked.stderr
report=validate_verified_simd_artifact(document,image.object_bytes,final.read_bytes())
assert report['ok'] and report['complete']
identity=report['checker']['input_execution']['python_sources']
for filename in MODULES:
    assert identity[filename]==hashlib.sha256((root/'hepta'/filename).read_bytes()).hexdigest()
'''.replace("MODULES", repr(INPUT_MODULES)))


if __name__ == "__main__":
    unittest.main()
