from pathlib import Path
import hashlib,json,os,sys,time,traceback
root=Path('/home/qian-qi/hia-slot-snapshot-20261127-2ac5')
source=root/'source'
compiler=Path('/home/qian-qi/hia-native-current-20261127-0862/final-f-native-chain-v1/qualification/cold/qualification/base/B1.flat')
assert hashlib.sha256(compiler.read_bytes()).hexdigest()=='acb6478d1a466d17210611c5fcbbd5aeec3109b0813e917f0bb5c8419f3c33a9'
os.environ['HEPTA_HIA_SLOT_OPERATIONS_DEVELOPMENT_COMPILER']=str(compiler)
os.environ['HEPTA_HIA_SLOT_OPERATIONS_EVIDENCE']=str(root/'qualification-v2')
os.environ.pop('HEPTA_HIA_SLOT_OPERATIONS_COLD_REPORT',None)
sys.path.insert(0,str(source))
from tests.test_hia_slot_mechanical_native import SlotMechanicalV5NativeTests as Case
started=time.monotonic()
setup=False
failure=None
report=None
try:
    Case.setUpClass()
    setup=True
    case=Case('test_00_full_original248_derived7574_original_first_native_v5')
    evidence=Case.folder/case._testMethodName/'observations'
    case.run_complete('complete-7822-atomic-snapshots-v2','tools/qualify_hia_slot_mechanical_observations.py',[
        '--backend','native','--manifest',Case.controller,
        '--product-freeze',Case.product_freeze,
        '--product-freeze-sha256',Case.product_freeze_sha256,
        '--bridge-bundle',Case.bundle,'--expected-bridge-sha256',Case.bundle_pin['sha256'],
        '--capture-version','atomic-snapshots-v2','--evidence',evidence])
    report=json.loads((evidence/'independent-readback/report.json').read_bytes())
    assert report['status']=='PASS',report['status']
except BaseException as error:
    failure={'type':type(error).__module__+'.'+type(error).__qualname__,'message':str(error),'traceback':traceback.format_exc()}
    traceback.print_exc()
finally:
    if setup:
        try:Case.tearDownClass()
        except BaseException as error:
            failure={'type':type(error).__module__+'.'+type(error).__qualname__,'message':str(error),'traceback':traceback.format_exc(),'earlier_failure':failure}
            traceback.print_exc()
    value={'status':'PASS' if failure is None and report is not None else 'HOLD',
           'wall_seconds':time.monotonic()-started,'python':sys.version,'failure':failure,
           'capture_version':'atomic-snapshots-v2','whole_native_stack_qualified':False,
           'scope':'EXPLICIT_DEVELOPMENT_COMPONENT_NOT_COLD_QUALIFIED',
           'compiler_sha256':'acb6478d1a466d17210611c5fcbbd5aeec3109b0813e917f0bb5c8419f3c33a9',
           'original_v1_failure_preserved':True,'original_v1_default_unchanged':True,
           'report':None if report is None else {'status':report['status'],'comparisons':report['comparisons'],'total_cases_per_backend':report['total_cases_per_backend']}}
    (root/'evidence/full-v2-driver.json').write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
    print('SLOT_FULL_V2_RESULT '+json.dumps(value,sort_keys=True),flush=True)
raise SystemExit(0 if failure is None and report is not None else 1)
