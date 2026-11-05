#!/usr/bin/env python3
"""Require exact inherited and joint method inventories on one composed source."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tests')]


def flatten(suite):
    for item in suite:
        if isinstance(item,unittest.TestSuite):yield from flatten(item)
        else:yield item


def identity():
    return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
            for folder in ('hepta','tests','tools','stdlib','examples','docs','.github')
            for p in sorted((ROOT/folder).rglob('*'))
            if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc'}


class StrictResult(unittest.TextTestResult):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs);self.started=[];self.finished=[];self.passed=[]
    def startTest(self,test):self.started.append(test.id());super().startTest(test)
    def stopTest(self,test):self.finished.append(test.id());super().stopTest(test)
    def addSuccess(self,test):self.passed.append(test.id());super().addSuccess(test)


def main():
    if not __debug__:raise SystemExit('Assertions must remain enabled; do not use Python -O')
    os.chdir(ROOT)
    os.environ['PYTHONDONTWRITEBYTECODE']='1'
    os.environ['PYTHONPATH']=str(ROOT)
    backend=os.environ.get('HEPTA_VERSIONED_STDLIB_BACKEND','c')
    if backend not in ('c','rust'):raise SystemExit('Expected c or rust backend')
    for key in ('HEPTA_PACKAGE_TEST_BACKEND','HEPTA_INTEGRATION_BACKEND','HEPTA_BYTES_BACKEND',
                'HEPTA_ORDERING_BACKEND','HEPTA_UTF8_BACKEND','HEPTA_BASE64_BACKEND'):
        if key in os.environ and os.environ[key]!=backend:raise SystemExit('Conflicting backend: '+key)
        os.environ[key]=backend
    # No absent selected compiler may be converted to a skip or a pass.
    if backend=='rust':
        from hepta.backend import find_rustc,toolchain_info
        toolchain=toolchain_info(find_rustc())
    else:
        cc=os.environ.get('CC','gcc')
        toolchain={'requested':cc,'version':subprocess.check_output([cc,'--version'],text=True).strip()}
    from test_versioned_stdlib import verify_components
    verify_components()
    inherited=json.loads((ROOT/'tests/package_integration_inventory.json').read_bytes())
    if len(inherited)!=65 or len(set(inherited))!=65:raise SystemExit('Invalid inherited package inventory')
    modules={'test_stdlib_bytes':13,'test_stdlib_ordering':12,'test_stdlib_utf8':12,
             'test_stdlib_base64':11,'test_stdlib_integration':12,
             'test_parser':35,'test_checker':114,'test_versioned_stdlib':11}
    suite=unittest.defaultTestLoader.loadTestsFromNames(inherited)
    for name,count in modules.items():
        part=unittest.defaultTestLoader.loadTestsFromName(name)
        if part.countTestCases()!=count:raise SystemExit('Discovery count differs: '+name)
        suite.addTest(part)
    actual=[test.id() for test in flatten(suite)]
    planned=json.loads((ROOT/'tests/versioned_stdlib_inventory.json').read_bytes())
    if len(planned)!=285 or len(set(planned))!=285 or planned!=actual:
        raise SystemExit('Frozen inventory differs from complete selected discovery')
    before=identity()
    print('VERSIONED_STDLIB_IDENTITY '+json.dumps({'python':sys.version,'backend':backend,'toolchain':toolchain,'source_sha256':before},sort_keys=True),flush=True)
    result=unittest.TextTestRunner(verbosity=2,resultclass=StrictResult).run(suite)
    report={'planned':planned,'started':result.started,'finished':result.finished,'passed':result.passed,
            'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped),
            'expected_failures':len(result.expectedFailures),'unexpected_successes':len(result.unexpectedSuccesses)}
    print('VERSIONED_STDLIB_METHODS '+json.dumps(report,sort_keys=True),flush=True)
    if (not result.wasSuccessful() or result.skipped or result.expectedFailures or result.unexpectedSuccesses
        or planned!=result.started or planned!=result.finished or planned!=result.passed):
        raise SystemExit('Strict composed method gate failed')
    if before!=identity():raise SystemExit('Source changed during methods')
    for module in ('tests.package_resolution_oracle','tests.lock_diff_graph_oracle','tests.package_integration_oracle'):
        subprocess.run([sys.executable,'-B','-m',module],check=True,cwd=ROOT)
    if backend=='c':
        for oracle in ('tests/stdlib_bytes_boundary_oracle.py','tests/stdlib_ordering_oracle.py',
                       'tools/stdlib_utf8_oracle.py','tools/stdlib_base64_oracle.py',
                       'tools/stdlib_integration_oracle.py','tools/versioned_stdlib_oracle.py'):
            subprocess.run([sys.executable,'-B',oracle],check=True,cwd=ROOT)
    if before!=identity():raise SystemExit('Source changed during oracles')
    print('VERSIONED_STDLIB_PASS '+json.dumps({'methods':285,'backend':backend,'python':sys.version.split()[0],
          'source_unchanged':True,'whole_project_blockers_closed':False}),flush=True)


if __name__=='__main__':main()
