"""Exact Evaluation/import policies with held real IMPORT_FROM errors."""
from __future__ import annotations
import argparse
import builtins
from contextlib import ExitStack
from hashlib import sha256
import json
from pathlib import Path
import sys
from unittest.mock import patch
import weakref


def observe(fixtures, image, family, module_name, missing, outer):
    ports=fixtures.Ports('eval-ok' if family=='_hia_evaluate' else 'invoke-ok',image)
    provider=fixtures.runner if module_name=='hia_agent_runner' else fixtures.buffers
    events=[];weak=[];held=[]
    class Module:
        __name__='hepta.evaluation_import_proxy'
        __file__='/virtual/evaluation-import-proxy.py'
        def __init__(self):weak.append(weakref.ref(self))
        def __getattr__(self,name):
            events.append(['field',name])
            if name==missing:raise AttributeError(name)
            return getattr(provider,name)
        def __del__(self):
            active=sys.exception()
            events.append(['module-del',None if active is None else type(active).__name__])
    original_import=builtins.__import__
    def hooked(name,globals=None,locals=None,fromlist=(),level=0):
        if name==module_name and level==1:
            events.append(['import',list(fromlist)])
            return Module()
        return original_import(name,globals,locals,fromlist,level)
    def invoke():
        try:
            value=ports.invoke_case()
            return {'kind':'value','value':fixtures.normalize(value)}
        except BaseException as error:
            held.append(error)
            context=error.__context__
            return {'kind':'error','type':type(error).__name__,'args':fixtures.normalize(error.args),
                'name':getattr(error,'name',None),'path':getattr(error,'path',None),
                'context':None if context is None else [type(context).__name__,fixtures.normalize(context.args)],
                'suppress_context':error.__suppress_context__}
    def run():
        value=invoke()
        before={'alive':[ref() is not None for ref in weak],'events':list(events)}
        held.clear()
        return {'result':value,'while_error_held':before,
            'after_error_release':{'alive':[ref() is not None for ref in weak],'events':list(events)},
            'business':fixtures.normalize(ports.events),'publications':fixtures.normalize(ports.store.published)}
    with ExitStack() as stack:
        stack.enter_context(patch.object(fixtures.api,'time',ports.clock))
        stack.enter_context(patch.object(fixtures.api,'validate',lambda *args,**kwargs:ports.events.append(['validate'])))
        stack.enter_context(patch.object(fixtures.runner,'run_reference_batch',ports.reference_batch))
        stack.enter_context(patch.object(fixtures.runner,'run_native_batch',ports.native_batch))
        stack.enter_context(patch.object(fixtures.buffers,'validate_cases',lambda *args:ports.events.append(['validate_cases'])))
        stack.enter_context(patch.object(fixtures.buffers,'validate_arguments',lambda *args:ports.events.append(['validate_arguments'])))
        stack.enter_context(patch.object(builtins,'__import__',hooked))
        if outer:
            try:raise LookupError('outer')
            except LookupError:return run()
        return run()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    sys.path.insert(0,str(args.source.resolve()))
    from tests import hia_service_evaluation_fixtures as fixtures
    from hepta.hia_service_evaluation_native import NativeEvaluationImage
    manifest_raw=args.manifest.read_bytes();manifest=json.loads(manifest_raw)
    image_path=args.manifest.parent/manifest['image_path'];image_raw=image_path.read_bytes()
    assert sha256(image_raw).hexdigest()==manifest['image_sha256']
    files=('hepta/hia_service_evaluation_native.py','hepta/hia_service_evaluation_foreign.py',
        'tools/generate_hia_service_evaluation_foreign.py','tools/hia_service_evaluation_policy.py')
    before={name:sha256((args.source/name).read_bytes()).hexdigest() for name in files}
    image=NativeEvaluationImage(image_raw,manifest['image_sha256'])
    rows=[]
    groups=(('_hia_evaluate','hia_agent_runner',(None,'run_native_batch','run_reference_batch')),
        ('_hia_evaluate','hia_agent_buffers',(None,'validate_cases')),
        ('invoke_lease','hia_agent_runner',(None,'run_native_batch')),
        ('invoke_lease','hia_agent_buffers',(None,'validate_arguments')))
    for family,module,names in groups:
        for name in names:
            for outer in (False,True):
                reference=observe(fixtures,None,family,module,name,outer)
                start=image.entries
                actual=observe(fixtures,image,family,module,name,outer)
                rows.append({'family':family,'module':module,'missing':name,'outer':outer,
                    'reference':reference,'native':actual,'equal':reference==actual,
                    'actual_entries':image.entries-start})
    after={name:sha256((args.source/name).read_bytes()).hexdigest() for name in files}
    report={'schema':'hia.evaluation.import-module-retirement.v1','python':sys.version,
        'cases':len(rows),'equal':sum(row['equal'] for row in rows),'observations':rows,
        'image_sha256':manifest['image_sha256'],'source_before':before,'source_after':after,
        'inputs_unchanged':before==after and args.manifest.read_bytes()==manifest_raw and image_path.read_bytes()==image_raw,
        'whole_native':False,'current_cold':False,'garbage_collection_used':False}
    report['status']='PASS' if (report['equal']==report['cases'] and report['inputs_unchanged']
        and all(row['actual_entries']>0 for row in rows)) else 'FAIL'
    args.output.mkdir(mode=0o700)
    (args.output/'REPORT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('status','cases','equal','inputs_unchanged')}))
    return report['status']!='PASS'


if __name__=='__main__':raise SystemExit(main())
