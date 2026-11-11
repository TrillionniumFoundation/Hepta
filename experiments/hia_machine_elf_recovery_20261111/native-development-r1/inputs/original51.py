"""Run the exact original four modules/51 IDs under the selected ELF image.

Additional full-dataclass and fresh -I -S -B child observations are recorded
separately. They do not change the original unittest denominator.
"""
from __future__ import annotations
import argparse
from dataclasses import fields
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from common import SOURCE, ORACLE_SHA, create, load_exact, read_json, require, stable_file, wire

def flatten(suite):
    result = []
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            result.extend(flatten(item))
        else:
            result.append(item)
    return result

def encoded(value):
    if type(value) is bytes:
        return {'kind':'bytes', 'size':len(value), 'sha256':sha256(value).hexdigest(),
                'hex':value.hex()}
    if type(value) is tuple:
        return {'kind':'tuple', 'items':[encoded(item) for item in value]}
    if type(value) is list:
        return [encoded(item) for item in value]
    if type(value) is dict:
        return {key:encoded(item) for key, item in value.items()}
    return value

FRESH = r'''
import json,pathlib,sys
sys.path.insert(0,sys.argv[1])
from hepta import hia_machine_elf as writer
from hepta.hia_machine_elf_native import installed_machine_elf
from hepta.hia_program import verify_program
from hepta.hia_program_native import emit_program_machine
called=[]
def forbidden(*args,**kwargs):
    called.append("retained_writer")
    raise AssertionError("retained writer disabled in actual fresh child")
writer._reference_write_elf_object=forbidden
image=installed_machine_elf(sys.argv[2])
value=emit_program_machine(verify_program(json.loads(sys.argv[3])))
assert value.object_bytes.startswith(b"\x7fELF")
assert not called and sum(image.calls.values())>0
print(json.dumps({"status":"PASS","retained_owner_calls":called,
                 "native_operation_counts":dict(image.calls),
                 "object_sha256":value.sha256,"object_bytes":len(value.object_bytes)}))
'''

class ObservedResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.executed = []
    def startTest(self, test):
        self.executed.append(test.id())
        super().startTest(test)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--oracle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not args.output.exists(), 'new original-caller evidence directory required')
    args.output.mkdir(mode=0o700)
    report = {'schema':'hepta.hia.machine-elf.reconstructed-original-51.v1',
              'status':'HOLD','historical_results_inherited':False,
              'whole_writer_qualified':False,'foreign_sort_schedule_closed':False}
    error = None
    started = time.monotonic()
    try:
        require(os.environ.get('HEPTA_HIA_MACHINE_ELF_MANIFEST') == str(args.manifest),
                'selected ELF environment is not exact')
        sys.path.insert(0, str(SOURCE))
        inventory, inventory_pin = read_json(args.inventory)
        require(inventory['base_commit'] == '608157e52b0b94e0d294f6b99c4e809869f183aa'
                and inventory['total_source_declared_methods'] == 51
                and len(inventory['modules']) == 4, 'original inventory differs')
        expected = []
        names = []
        for row in inventory['modules']:
            stable_file(SOURCE / row['path'], row['sha256'])
            expected.extend(row['source_declared_ids'])
            names.append(row['path'][:-3].replace('/', '.'))
        require(len(set(expected)) == 51, 'original test identifiers differ')
        from hepta import hia_machine_elf as public
        from hepta import hia_program_native as backend
        from hepta.hia_machine_elf_native import installed_machine_elf
        from hepta.hia_program import verify_program
        from tests.test_hia_program_native import minimal_document
        oracle = load_exact('complete_original_608_elf', args.oracle, ORACLE_SHA)
        selected = public.write_elf_object
        document = minimal_document()
        program = verify_program(document)
        original_backend_writer = backend.write_elf_object
        try:
            backend.write_elf_object = oracle.write_elf_object
            reference_object = backend.emit_program_machine(program)
        finally:
            backend.write_elf_object = original_backend_writer
        require(backend.write_elf_object is selected, 'ordinary backend import does not select public writer')
        legacy = []
        def forbidden(*unused, **ignored):
            legacy.append('retained_writer')
            raise AssertionError('retained writer is disabled in selected parent')
        public._reference_write_elf_object = forbidden
        image = installed_machine_elf(str(args.manifest))
        selected_object = backend.emit_program_machine(program)
        same = reference_object == selected_object
        report['complete_return_object'] = {
            'pass':same,
            'field_names':[field.name for field in fields(reference_object)],
            'reference':{field.name:encoded(getattr(reference_object,field.name))
                         for field in fields(reference_object)},
            'selected':{field.name:encoded(getattr(selected_object,field.name))
                        for field in fields(selected_object)}}
        require(same, 'full backend return object or metadata differs')
        create(args.output / 'fresh-child.py', FRESH.encode())
        child_stdout, child_stderr = args.output / 'fresh-child.stdout', args.output / 'fresh-child.stderr'
        with child_stdout.open('xb') as out, child_stderr.open('xb') as err:
            child = subprocess.run(
                [sys.executable,'-I','-S','-B',str(args.output/'fresh-child.py'),
                 str(SOURCE),str(args.manifest),json.dumps(document)],
                cwd=SOURCE, env=os.environ.copy(), stdin=subprocess.DEVNULL,
                stdout=out, stderr=err, timeout=20)
        child_result = json.loads(child_stdout.read_text()) if child.returncode == 0 else None
        report['fresh_selected_child'] = {
            'returncode':child.returncode,'result':child_result,
            'stdout':stable_file(child_stdout)[0],'stderr':stable_file(child_stderr)[0]}
        require(child.returncode == 0 and child_result['status']=='PASS'
                and child_result['retained_owner_calls']==[]
                and sum(child_result['native_operation_counts'].values())>0,
                'fresh actual selected child failed')
        suite = unittest.defaultTestLoader.loadTestsFromNames(names)
        tests = flatten(suite)
        loaded = [test.id() for test in tests]
        report['loaded_test_ids'] = loaded
        report['source_declared_test_ids'] = expected
        report['tests_loaded'] = len(loaded)
        require(len(loaded)==51 and len(set(loaded))==51 and set(loaded)==set(expected),
                'actual loaded original test set differs')
        result = unittest.TextTestRunner(verbosity=2, resultclass=ObservedResult).run(suite)
        counts = {'errors':len(result.errors),'failures':len(result.failures),
                  'skips':len(result.skipped),'expected_failures':len(result.expectedFailures),
                  'unexpected_successes':len(result.unexpectedSuccesses)}
        report.update(tests_run=result.testsRun, executed_test_ids=result.executed,
                      anomaly_counts=counts, retained_owner_calls=legacy,
                      native_operation_counts=dict(image.calls),
                      errors=[(test.id(),trace) for test,trace in result.errors],
                      failures=[(test.id(),trace) for test,trace in result.failures])
        require(result.testsRun==51 and result.executed==loaded
                and all(value==0 for value in counts.values())
                and not legacy and sum(image.calls.values())>0,
                'complete original 51 result conjunction failed')
        require(stable_file(args.inventory,inventory_pin['sha256'])[0]==inventory_pin,
                'original inventory changed')
        report['status'] = 'PASS'
    except BaseException as exc:
        error = exc
        import traceback
        report['failure']={'type':type(exc).__name__,'text':str(exc),
                           'traceback':traceback.format_exc()}
    finally:
        report['seconds']=time.monotonic()-started
        create(args.output / 'report.json',wire(report))
    print(json.dumps({'stage':'original_51','status':report['status'],
                      'tests_loaded':report.get('tests_loaded'),
                      'tests_run':report.get('tests_run')}),flush=True)
    if error is not None:
        raise error

if __name__ == '__main__':
    main()
