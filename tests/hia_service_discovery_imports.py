"""Bounded original-first captured-import controls, separate from the 56 cases."""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
import types
ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,''):
    sys.path.insert(0,str(ROOT))
from tests import hia_service_discovery_oracle as oracle

SPECS=(
    ('describe','normal',None,None),('examples','normal',None,None),
    ('describe','import-raised','import.hook.enter','ValueError'),
    ('examples','import-raised','import.hook.enter','MemoryError'),
    ('describe','alternate-module',None,None),('examples','alternate-module',None,None),
    ('describe','first-name','import.module.get.opcode_catalog','AttributeError'),
    ('examples','first-name','import.module.get.assemble_program','AttributeError'),
    ('examples','second-name','import.module.get.render_assembly','AttributeError'),
    ('examples','second-runtime','import.module.get.render_assembly','RuntimeError'),
)
CASES=tuple({'id':'import.'+mode+'.'+scenario+'.outer'+str(int(outer)),
             'mode':mode,'scenario':scenario,'outer':outer,'base_fault':fault,
             'import_family':family}
            for mode,scenario,fault,family in SPECS for outer in (False,True))

def write(path,value):
    raw=oracle.canonical(value)+b'\n'
    with Path(path).open('xb') as stream:stream.write(raw)
    return sha256(raw).hexdigest()

class Alternate:
    __slots__=('world','target')
    def __init__(self,world,target):self.world,self.target=world,target
    def __call__(self,value):
        self.world.hit('import.alternate.call',oracle.role(value))
        return self.target(value)

class ImportedModule:
    __slots__=('world','provider','__name__','__file__','__spec__')
    def __init__(self,world,provider,name):
        self.world,self.provider=world,provider
        self.__name__,self.__file__,self.__spec__='hepta.'+name,'frozen-import-provider.py',None
        world.record('import.module.created',self.__name__)
    def __getattribute__(self,name):
        if name in ('opcode_catalog','assemble_program','render_assembly'):
            world=object.__getattribute__(self,'world')
            world.hit('import.module.get.'+name)
            target=getattr(object.__getattribute__(self,'provider'),name)
            if world.case['scenario']=='alternate-module' and name in ('opcode_catalog','assemble_program'):
                return Alternate(world,target)
            return target
        return object.__getattribute__(self,name)
    def __del__(self):
        object.__getattribute__(self,'world').record('import.module.deleted',
                                                    object.__getattribute__(self,'__name__'))

class ImportHook:
    __slots__=('world','namespace_id','provider')
    def __init__(self,world,namespace,provider):
        self.world,self.namespace_id,self.provider=world,id(namespace),provider
    def __call__(self,name,globals=None,locals=None,fromlist=(),level=0):
        world=self.world
        wanted=['self','args'] if world.case['mode']=='describe' else []
        actual=list(locals) if locals is not None else None
        world.hit('import.hook.enter',{'name':name,'same_namespace':id(globals)==self.namespace_id,
            'initial_locals':actual,'fromlist':list(fromlist),'level':level})
        if id(globals)!=self.namespace_id or (actual is not None and actual!=wanted):
            raise AssertionError('business import globals/initial locals differ')
        module=self.provider(name,globals,locals,fromlist,level)
        return ImportedModule(world,module,name)

class OriginalImports:
    def __call__(self,namespace,mode,providers):
        world=namespace['verify_program'].__self__
        family=world.case.get('import_family')
        if family is not None:world.fault=oracle.ERRORS[family]('frozen fault')
        builtins=namespace['__builtins__']
        builtins['__import__']=ImportHook(world,namespace,builtins['__import__'])
        return oracle.original_function(namespace,mode)

class SelectedImports:
    def __init__(self,factory):self.factory=factory
    def __call__(self,namespace,mode,providers):
        world=namespace['verify_program'].__self__
        family=world.case.get('import_family')
        if family is not None:world.fault=oracle.ERRORS[family]('frozen fault')
        builtins=namespace['__builtins__']
        builtins['__import__']=ImportHook(world,vars(self.factory.api),builtins['__import__'])
        return self.factory(namespace,mode,providers)

def explicit_namespaces(image):
    """Internal raw Frame binds original code/builtins even after a globals rebind."""
    from hepta import hia_agent_service as api,hia_service_discovery_native as native
    from tests.hia_service_discovery_controls import real_service,PlainStore
    rows=[]
    for mode in (1,2):
        namespace=dict(vars(api));captured=dict(api._SERVICE_DISCOVERY_GLOBAL_BUILTINS[mode])
        calls=[];default_import=captured['__import__']
        def importer(name,globals=None,locals=None,fromlist=(),level=0):
            assert globals is namespace
            calls.append({'name':name,'locals':None if locals is None else list(locals),'fromlist':list(fromlist),'level':level})
            return default_import(name,globals,locals,fromlist,level)
        captured['__import__']=importer;namespace['__builtins__']=captured
        reference=(api._SERVICE_DISCOVERY_DESCRIBE_REFERENCE if mode==1 else api._SERVICE_DISCOVERY_EXAMPLES_REFERENCE)
        original=types.FunctionType(reference.__code__,namespace,reference.__name__)
        capsule=types.FunctionType(api._SERVICE_DISCOVERY_IMPORTS[mode].__code__,namespace)
        def forbidden(*args,**kwargs):raise AssertionError('later globals builtins was consulted')
        namespace['__builtins__']={'__import__':forbidden}
        if mode==1:
            expected=original(real_service(PlainStore()),{'section':'manifest'})
            original_calls=list(calls);calls.clear()
            actual=native.ServiceDiscoveryFrame(image,mode,real_service(PlainStore()),{'section':'manifest'},
                namespace=namespace,global_builtins=captured,import_capsules={mode:capsule}).finish()
        else:
            expected=original();original_calls=list(calls);calls.clear()
            actual=native.ServiceDiscoveryFrame(image,mode,namespace=namespace,global_builtins=captured,
                                                 import_capsules={mode:capsule}).finish()
        assert oracle.canonical(actual)==oracle.canonical(expected) and calls==original_calls
        rows.append({'mode':mode,'captured_before_rebind':True,'calls':calls,'equal_output':True})
        calls=[];before_entries=image._entry.calls
        try:
            native.ServiceDiscoveryFrame(image,mode,namespace=namespace,global_builtins=captured)
        except ValueError as error:
            assert str(error)=='discovery import capsule differs from its captured namespace' and not calls
            assert image._entry.calls==before_entries
        else:raise AssertionError('inconsistent explicit captured namespace admitted')
        rows.append({'mode':mode,'inconsistent_capture_refused_before_body':True})
    return rows

def run(manifest,output):
    output=Path(output);output.mkdir(mode=0o700)
    if any(name=='hepta' or name.startswith('hepta.') for name in sys.modules):
        raise AssertionError('original import controls require a fresh pre-product process')
    declared=[Path(__file__),Path(oracle.__file__)]
    declared += [oracle.ORIGINALS/name for name in oracle.PINNED]
    sources={str(p.absolute()):p.read_bytes() for p in declared}
    inputs_pin=write(output/'inputs.json',{'schema':'hepta.hia.discovery-import-controls.v1','cases':CASES})
    original=[];original_traces=[]
    factory=OriginalImports()
    for case in CASES:
        row,traces=oracle.observe(case,factory=factory)
        assert row['fault_count']==(1 if case['base_fault'] else 0)
        original.append(row);original_traces.append({'id':case['id'],'tracebacks':traces})
    original_raw=b''.join(oracle.canonical(row)+b'\n' for row in original)
    with (output/'original-observations.jsonl').open('xb') as stream:stream.write(original_raw)
    with (output/'original-tracebacks.jsonl').open('xb') as stream:
        for row in original_traces:stream.write(oracle.canonical(row)+b'\n')
    write(output/'original-before-product.json',{'original_sha256':sha256(original_raw).hexdigest(),
        'count':len(CASES),'inputs_sha256':inputs_pin,'product_modules':[],
        'runtime':sys.version,'runtime_version':list(sys.version_info[:3]),
        'source_pins':{p:sha256(raw).hexdigest() for p,raw in sources.items()}})
    product_names=('hepta/hia_service_discovery_native.py','hepta/hia_service_discovery_protocol.py',
        'hepta/hia_agent_service.py','hepta/hia_native_delivery.py','hepta/hia_native_helpers.py',
        'hepta/hia_json_preflight_native.py','examples/hia_bootstrap/service_discovery.hepta',
        'tests/hia_service_discovery_observer.py')
    product_bytes={str(ROOT/name):(ROOT/name).read_bytes() for name in product_names}
    manifest=Path(manifest).absolute();manifest_raw=manifest.read_bytes()
    product_bytes[str(manifest)]=manifest_raw;manifest_value=json.loads(manifest_raw)
    image_path=manifest.parent/manifest_value['image_path'];image_raw=image_path.read_bytes()
    assert sha256(image_raw).hexdigest()==manifest_value['image_sha256']
    product_bytes[str(image_path)]=image_raw
    # The complete original observations above are written before this import.
    from tests.hia_service_discovery_observer import PublicFactory,differences
    public=PublicFactory('native',manifest)
    selected=SelectedImports(public);actual=[];diffs=[];actual_traces=[]
    try:
        for case,expected in zip(CASES,original):
            try:row,traces=oracle.observe(case,factory=selected)
            finally:public.restore_case()
            actual.append(row);actual_traces.append({'id':case['id'],'tracebacks':traces})
            diff=differences(expected,row)
            diffs.append({'id':case['id'],'equal_bytes':oracle.canonical(expected)==oracle.canonical(row),'differences':diff})
        entries=public.image._entry.calls
        assert public.retained_calls==0 and entries>0
        internal=explicit_namespaces(public.image)
    finally:
        public.close()
    for name,rows in (('candidate-observations.jsonl',actual),('candidate-tracebacks.jsonl',actual_traces),
                      ('differences.jsonl',diffs)):
        with (output/name).open('xb') as stream:
            for row in rows:stream.write(oracle.canonical(row)+b'\n')
    if (output/'original-observations.jsonl').read_bytes()!=original_raw:
        raise ValueError('original import-control bytes changed during candidate')
    for name,raw in sources.items():
        if Path(name).read_bytes()!=raw:raise ValueError('original import-control source changed')
    for name,raw in product_bytes.items():
        if Path(name).read_bytes()!=raw:raise ValueError('import candidate source/image changed')
    passed=all(row['equal_bytes'] is True and row['differences']==[] for row in diffs)
    write(output/'report.json',{'status':'PASS' if passed else 'HOLD','count':len(CASES),
        'originals_frozen_before_product':True,'actual_native_entries':entries,'actual_image_sha256':manifest_value['image_sha256'],
        'runtime':sys.version,'runtime_version':list(sys.version_info[:3]),
        'candidate_source_manifest_image_pins':{p:sha256(raw).hexdigest() for p,raw in product_bytes.items()},
        'exact_captured_namespace_controls':internal,'retained_body_calls':0,
        'differences':sum(not row['equal_bytes'] for row in diffs),
        'source_before':{p:sha256(raw).hexdigest() for p,raw in sources.items()},
        'source_after':{p:sha256(Path(p).read_bytes()).hexdigest() for p in sources},
        'files':{name:sha256((output/name).read_bytes()).hexdigest() for name in (
            'inputs.json','original-before-product.json','original-observations.jsonl','original-tracebacks.jsonl',
            'candidate-observations.jsonl','candidate-tracebacks.jsonl','differences.jsonl')},
        'whole_native':False})
    return 0 if passed else 1

def read_imports(output, expected_image):
    """Pure raw reader; it imports neither product nor a candidate factory."""
    output=Path(output).absolute();consumed={}
    def raw(name,pin=None):
        path=output/name
        data=consumed.setdefault(str(path),path.read_bytes())
        if pin is not None and sha256(data).hexdigest()!=pin:
            raise ValueError('import-control consumed raw differs')
        return data
    report_raw=raw('report.json');report=json.loads(report_raw)
    required={'inputs.json','original-before-product.json','original-observations.jsonl','original-tracebacks.jsonl',
              'candidate-observations.jsonl','candidate-tracebacks.jsonl','differences.jsonl'}
    if set(report['files'])!=required:raise ValueError('import-control raw domain differs')
    files={name:raw(name,pin) for name,pin in report['files'].items()}
    inputs=json.loads(files['inputs.json']);authority=json.loads(files['original-before-product.json'])
    ids=[x['id'] for x in CASES]
    if oracle.canonical(inputs['cases'])!=oracle.canonical(CASES):
        raise ValueError('import-control fixed inputs differ')
    if (type(report['count']) is not int or report['count']!=len(CASES)
            or authority['count']!=len(CASES) or type(authority['count']) is not int
            or report['status']!='PASS' or report['originals_frozen_before_product'] is not True
            or report['runtime']!=authority['runtime'] or report['runtime_version']!=authority['runtime_version']
            or report['actual_image_sha256']!=expected_image
            or type(report['actual_native_entries']) is not int or report['actual_native_entries']<=0
            or report['source_before']!=report['source_after'] or report['source_before']!=authority['source_pins']
            or type(report['differences']) is not int or report['differences']!=0
            or type(report['retained_body_calls']) is not int or report['retained_body_calls']!=0
            or authority['product_modules']!=[]
            or authority['inputs_sha256']!=sha256(files['inputs.json']).hexdigest()
            or authority['original_sha256']!=sha256(files['original-observations.jsonl']).hexdigest()):
        raise ValueError('import-control original/candidate authority differs')
    if files['original-observations.jsonl']!=files['candidate-observations.jsonl']:
        raise ValueError('import-control complete observation bytes differ')
    for name in ('original-observations.jsonl','original-tracebacks.jsonl',
                 'candidate-observations.jsonl','candidate-tracebacks.jsonl','differences.jsonl'):
        rows=[json.loads(line) for line in files[name].splitlines()]
        if [x['id'] for x in rows]!=ids:raise ValueError('import-control raw ordered IDs differ')
        if name=='differences.jsonl':
            if any(type(x.get('equal_bytes')) is not bool or x!={'id':case_id,'equal_bytes':True,'differences':[]}
                   for case_id,x in zip(ids,rows)):
                raise ValueError('import-control complete differences were not rejected')
    controls=report['exact_captured_namespace_controls']
    if (len(controls)!=4 or [x['mode'] for x in controls]!=[1,1,2,2]
            or any(type(x['mode']) is not int for x in controls)
            or any(controls[i].get('captured_before_rebind') is not True
                   or controls[i].get('equal_output') is not True for i in (0,2))
            or any(controls[i].get('inconsistent_capture_refused_before_body') is not True for i in (1,3))):
        raise ValueError('explicit captured namespace controls differ')
    for table in (report['source_before'],report['candidate_source_manifest_image_pins']):
        for path,pin in table.items():
            data=Path(path).read_bytes()
            if sha256(data).hexdigest()!=pin:raise ValueError('import-control source/image custody differs')
            previous=consumed.setdefault(path,data)
            if previous!=data:raise ValueError('import-control source changed between captures')
    for path,data in consumed.items():
        if Path(path).read_bytes()!=data:raise ValueError('import-control raw changed during readback')
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();raise SystemExit(run(a.manifest,a.output))
if __name__=='__main__':main()
