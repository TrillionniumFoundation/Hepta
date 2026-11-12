"""Source-only byte/AST/loader checks; no unittest methods or native execution."""
import ast
from hashlib import sha256
import json
from pathlib import Path
import sys
import unittest
ROOT=Path(__file__).resolve().parent
SOURCE=ROOT.parent/'source'
sys.path.insert(0,str(SOURCE))
from tools.hia_selfhost_contract import support_contract
from tests.test_hia_selfhost_language_coverage import coverage_manifest
from tools.qualify_hia_artifact_publication_tests import ORIGINAL_TEST_IDS,MODULES

def encoded(x):return (json.dumps(x,sort_keys=True,indent=2)+'\n').encode()
support=support_contract();coverage=coverage_manifest()
assert encoded(support)==(SOURCE/'docs/HIA_SELFHOST_CORE_SUPPORT.json').read_bytes()
assert encoded(coverage)==(SOURCE/'docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json').read_bytes()
loader=unittest.TestLoader();suite=loader.loadTestsFromNames(MODULES)
def flatten(s):
    for t in s:
        if isinstance(t,unittest.TestSuite):yield from flatten(t)
        else:yield t
ids=[t.id() for t in flatten(suite)];assert ids==list(ORIGINAL_TEST_IDS) and len(ids)==len(set(ids))==39 and not loader.errors
plan=json.loads((ROOT.parent/'V85-SOURCE-PLAN.json').read_bytes())
unchanged=[]
for row in plan['files']:
    name=row['path']
    if name in ['tools/hia_artifact_publication_custody.py','tools/qualify_hia_artifact_publication_tests.py','docs/HIA_SELFHOST_CORE_SUPPORT.json']:continue
    raw=(SOURCE/name).read_bytes();assert len(raw)==row['bytes'] and sha256(raw).hexdigest()==row['sha256'];unchanged.append(name)
old=ast.parse((ROOT/'original/tools/hia_artifact_publication_custody.py').read_bytes())
new=ast.parse((SOURCE/'tools/hia_artifact_publication_custody.py').read_bytes())
original_paths=[]
for cls,methods in [('_ObservedPopen',['communicate','kill']),('Session',['run','popen','temporary_directory'])]:
    a=next(n for n in old.body if isinstance(n,ast.ClassDef) and n.name==cls)
    b=next(n for n in new.body if isinstance(n,ast.ClassDef) and n.name==cls)
    for name in methods:
        x=next(n for n in a.body if isinstance(n,ast.FunctionDef) and n.name==name)
        y=next(n for n in b.body if isinstance(n,ast.FunctionDef) and n.name==name)
        assert ast.dump(x,include_attributes=False)==ast.dump(y,include_attributes=False);original_paths.append(cls+'.'+name)
report={'status':'SOURCE_ONLY_READBACK_PASS','loaded_ids':ids,'loader_errors':loader.errors,'methods_executed':0,
        'unchanged_prior_product_files':unchanged,'unchanged_original_termination_and_call_bodies':original_paths,
        'support_actual_python_recomputed':True,'coverage_actual_python_recomputed':True,
        'profile':support['profile'],'declared_source_files':len(support['source_identity']['files']),
        'source_pins':{name:sha256((SOURCE/name).read_bytes()).hexdigest() for name in
            ['tools/hia_artifact_publication_custody.py','tools/qualify_hia_artifact_publication_tests.py',
             'docs/HIA_SELFHOST_CORE_SUPPORT.json','docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json']},
        'product_39_or_native_executed':False}
(ROOT/'SOURCE-READBACK.json').write_bytes(encoded(report));print(json.dumps({k:v for k,v in report.items() if k not in ['loaded_ids','source_pins']}))
