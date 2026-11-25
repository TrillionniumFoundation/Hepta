"""Actual complete nominal ELF versus original Core verification and elaboration."""
from pathlib import Path
import argparse,hashlib,json,os,sys,fcntl,subprocess,struct,copy,unittest,importlib,io,time

FRAME=struct.Struct('<8s7Q')
MAX=8<<20
def digest(raw):return hashlib.sha256(raw).hexdigest()
def main():
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--normalizer',type=Path,required=True);p.add_argument('--directory',type=Path,required=True);a=p.parse_args()
    D=a.directory;D.mkdir(mode=0o700,exist_ok=False);sys.path.insert(0,str(a.source));os.chdir(a.source)
    for key in list(os.environ):
        if key.startswith('HEPTA_'):del os.environ[key]
    import hepta.hia_program as hp
    original=hp.verify_program;cases={};origin='direct'
    def capture(value):
        if isinstance(value,hp.VerifiedProgram):return
        if isinstance(value,dict):
            try:raw=json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()
            except (ValueError,UnicodeError,TypeError):return
        elif type(value) is bytes:raw=value
        elif type(value) is str:raw=value.encode()
        else:return
        key=digest(raw)
        if key not in cases:cases[key]={'raw':raw,'labels':[]}
        if origin not in cases[key]['labels']:cases[key]['labels'].append(origin)
    def observed(value):
        capture(value);return original(value)
    hp.verify_program=observed;hp.verify_core=observed
    specs={
      'tests.test_hia_program_composite':['CompositeExecutionTests','CompositeRejectionTests'],
      'tests.test_hia_partial_record':['PartialRecordExecutionTests','PartialRecordRejectionTests','PartialRecordCompatibilityTests'],
      'tests.test_hia_composite_returned_loans':['CompositeReturnedLoans'],
    }
    suite=unittest.TestSuite()
    for mod,names in specs.items():
        m=importlib.import_module(mod)
        for name in names:
            for test in unittest.defaultTestLoader.loadTestsFromTestCase(getattr(m,name)):
                if test._testMethodName=='test_actual_cli_nominal_verify_inspect_and_execute_roundtrip':continue
                suite.addTest(test)
    class Result(unittest.TextTestResult):
        def startTest(self,test):
            nonlocal origin
            origin=test.id();super().startTest(test)
    log=io.StringIO();result=unittest.TextTestRunner(stream=log,verbosity=2,resultclass=Result).run(suite)
    (D/'original-tests.log').write_text(log.getvalue())
    if not result.wasSuccessful():raise AssertionError(log.getvalue())
    print('ORIGINAL_TESTS_PASS',result.testsRun,'captured',len(cases),flush=True)
    # Every captured raw input is replayed against the original verifier fresh.
    hp.verify_program=original;hp.verify_core=original
    from tools.qualify_hia_multiversion_components import profile_cases
    for label,document,_ in profile_cases():
        origin='multiversion-profile/'+label;capture(document)
    for path in sorted((a.source/'examples').rglob('*.hepta')):
        raw=path.read_bytes()
        if raw.lstrip().startswith(b'{'):
            origin='repository/'+str(path.relative_to(a.source));capture(raw)
    for label,raw in [
        ('empty',b''),('malformed',b'{broken'),('invalid-utf8',b'\xff'),
        ('isolated-surrogate',br'{"name":"\uD800"}'),('escaped-duplicate',br'{"x":1,"\u0078":2}'),
        ('fraction',b'{"x":1.0}'),('depth65',b'['*65+b'0'+b']'*65),
        ('node-budget',b'['+b'0,'*262144+b'0]'),
    ]:origin='ingress/'+label;capture(raw)
    # Pretty composites preserve structured input identity independently of Core identity.
    for row in tuple(cases.values()):
        try:obj=json.loads(row['raw'])
        except (ValueError,UnicodeError):continue
        if isinstance(obj,dict) and str(obj.get('schema','')).startswith('hepta.hia.composite.v'):
            origin='pretty/'+row['labels'][0];capture(json.dumps(obj,ensure_ascii=False,indent=2).encode())
    sourcefiles={}
    from tools.build_hia_nominal_constructor import COMPONENTS,TRANSPORT_TEMPLATES,TRANSPORT_ROLES,ADAPTER
    for name in set(COMPONENTS.values())|set(TRANSPORT_TEMPLATES.values())|set(TRANSPORT_ROLES)|{ADAPTER}:
        sourcefiles[name]=digest((a.source/name).read_bytes())
    image=a.normalizer.read_bytes();fd=os.memfd_create('native-normalization-qualified',os.MFD_ALLOW_SEALING|os.MFD_CLOEXEC);os.write(fd,image);os.lseek(fd,0,0);os.fchmod(fd,0o500);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15)
    rows=[];fixture=D/'inputs';fixture.mkdir(mode=0o700)
    def run(alias,raw):
        started=time.monotonic_ns()
        out=subprocess.run([alias],executable='/proc/self/fd/'+str(fd),input=raw,capture_output=True,pass_fds=(fd,),env={'PATH':''},timeout=30)
        assert not out.stderr,(alias,out.returncode,out.stderr)
        assert len(out.stdout)<=64+2*MAX,(alias,len(out.stdout))
        return out,time.monotonic_ns()-started
    for index,(key,item) in enumerate(cases.items()):
        raw=item['raw'];(fixture/(key+'.json')).write_bytes(raw)
        try:
            verified=original(raw);error=None
            canon=verified.canonical_bytes;structured=verified.structured_bytes
            originalbytes=canon if structured is None else structured
            profile=0 if structured is None else int(json.loads(structured)['schema'][-1])
        except hp.HIAProgramRejected as exc:
            error=str(exc);verified=None
        actual,elapsed=run('hia-admit-agent-json',raw)
        if verified is not None:
            expected=FRAME.pack(b'HIAVCF01',0,0,profile,len(originalbytes),len(canon),0,0)+originalbytes+canon
            ok=actual.returncode==0 and actual.stdout==expected
            extra={'profile':profile,'canonical_bytes':len(canon),'canonical_sha256':digest(canon),'input_sha256':digest(originalbytes)}
        else:
            diagnostic,de=run('hia-verify-core-json',raw)
            try:obj=json.loads(diagnostic.stdout);message=obj['diagnostics'][0]['message']
            except (ValueError,KeyError,IndexError,TypeError):message=None
            ok=actual.returncode in (2,3) and diagnostic.returncode==2 and message==error
            extra={'error':error,'native_error':message,'diagnostic_returncode':diagnostic.returncode,'diagnostic_elapsed_ns':de}
        row={'case':index,'labels':item['labels'],'bytes':len(raw),'sha256':key,'native_returncode':actual.returncode,'stdout_sha256':digest(actual.stdout),'elapsed_ns':elapsed,'pass':ok,**extra};rows.append(row)
        print('NORMALIZE_PAIR',index,ok,item['labels'][0],actual.returncode,flush=True)
        if not ok:
            (D/'failed.input').write_bytes(raw);(D/'failed.output').write_bytes(actual.stdout)
            if verified is not None:(D/'failed.expected').write_bytes(expected)
            else:(D/'failed.diagnostic').write_bytes(diagnostic.stdout)
            (D/'failure.json').write_text(json.dumps(row,indent=2)+'\n');raise AssertionError(row)
    os.close(fd)
    assert a.normalizer.read_bytes()==image
    report={'schema':'hepta.hia.multiversion-native-normalization.qualification.v1','scope':'actual original Core/composite verification and exact canonical primitive/original input, not full multiversion publication or proof','whole_native_runtime':False,'original_tests':result.testsRun,'passed':len(rows),'failed':0,'image':{'path':str(a.normalizer),'bytes':len(image),'sha256':digest(image),'seals':15},'source_sha256':sourcefiles,'cases':rows}
    (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('NORMALIZATION_PASS',len(rows),flush=True)
if __name__=='__main__':main()

