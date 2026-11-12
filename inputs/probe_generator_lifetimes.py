"""Actual-interpreter generator scope/destructor observations, outside old45.

This controlled-provider differential neither edits the original component
corpus nor grants cold authority. It keeps the original caught exception alive
before releasing it, without unittest.assertRaises or manual traceback edits.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import weakref
from unittest.mock import patch


def observe(implementation, family, failure, outer, image):
    from hepta import hia_agent_service as api
    from hepta import hia_service_emission_native as native
    from tests.hia_service_emission_fixtures import REFERENCE
    trace, references = [], []
    def ambient():
        value=sys.exception()
        return None if value is None else type(value).__name__
    class Item:
        def __getitem__(self, key):
            trace.append(['item-get',key,ambient()])
            if failure:raise KeyError('lifetime-item')
            return 'readbuf' if family=='parameter' else ('lowering_refinement' if key=='claim' else 'proved')
        def __hash__(self):
            trace.append(['item-hash',ambient()])
            if failure:raise KeyError('lifetime-type')
            return hash('not-a-supported-return')
        def __del__(self):trace.append(['item-del',ambient()])
    class Iterator:
        def __init__(self):self.done=False
        def __iter__(self):return self
        def __next__(self):
            trace.append(['next',ambient()])
            if self.done:raise StopIteration
            self.done=True;item=Item();references.append(weakref.ref(item));return item
        def __del__(self):trace.append(['iterator-del',ambient()])
    class Values:
        def __iter__(self):
            trace.append(['iter',ambient()]);iterator=Iterator();references.append(weakref.ref(iterator));return iterator
        def __len__(self):trace.append(['len',ambient()]);return 1
    values=Values()
    owner=None
    if family in ('parameter','return'):
        program=SimpleNamespace(sha256='a'*64,scalar_entrypoints={'f0'},as_dict=lambda:{'functions':[
            {'name':'f0','params':values if family=='parameter' else [],'returns':values if family=='return' else []}]})
        if implementation=='reference':call=lambda:REFERENCE['_signatures'](program)
        else:
            owner=native.NativeEmissionService(None,image);call=lambda:owner.signatures(program)
        patches=[]
    else:
        program=SimpleNamespace(sha256='a'*64,scalar_entrypoints=set(),as_dict=lambda:{'functions':[]})
        args={'backend_profile':'backend','context':'context','candidate':'candidate','verification_receipts':[],
              'output_kind':'object','codegen':{'kind':'plan','plan_profile':'plan-profile','plan':'plan','verification_receipt':'receipt'}}
        receipt={'subject':{'kind':'agent_machine_plan','backend_profile':'backend','plan_profile':'plan-profile','plan':'plan'},'checks':values}
        class Store:
            def get_json(self,*unused):return {},None
            def put(self,*unused):trace.append(['native-put',ambient()]);return 'native'
            def json(self,*unused):trace.append(['receipt-put',ambient()]);return 'build-receipt'
        service=SimpleNamespace(store=Store(),identities={},_profile=lambda *unused:None,
            _context=lambda *unused:{'target_profile':'target'},_program=lambda *unused:program,
            _verification=lambda *unused:receipt,_remaining_ms=lambda *unused:1000,
            _compile=lambda *unused,**ignored:(b'X',{'object_artifact':'object','object_sha256':'b'*64}))
        if implementation=='reference':call=lambda:REFERENCE['_hia_emit'](service,args)
        else:
            owner=native.NativeEmissionService(service,image);call=lambda:owner.emit(args)
        patches=[patch.object(api,'validate',return_value=None)]
    def run():
        held=None;result=None;shape=None
        try:result=call()
        except BaseException as error:
            held=error
            shape={'type':type(error).__name__,'message':str(error),
                   'cause':None if error.__cause__ is None else type(error.__cause__).__name__,
                   'context':None if error.__context__ is None else type(error.__context__).__name__}
        before_release=list(trace)
        alive_before=[reference() is not None for reference in references]
        held=None
        after_release=list(trace)
        alive_after=[reference() is not None for reference in references]
        return {'result':result,'error':shape,'before_release':before_release,'alive_before':alive_before,
                'after_release':after_release,'alive_after':alive_after}
    from contextlib import ExitStack
    with ExitStack() as stack:
        for manager in patches:stack.enter_context(manager)
        if outer:
            try:raise ArithmeticError('outer-handled')
            except ArithmeticError:observation=run()
        else:observation=run()
    if owner is not None and (owner.active or owner.unknown):
        raise AssertionError('normal known generator outcome left unconfirmed active state')
    return observation


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();root=args.source.resolve(strict=True);output=args.output.absolute()
    output.mkdir(mode=0o700,exist_ok=False);sys.path.insert(0,str(root))
    from hepta import hia_service_emission_native as native
    manifest=args.manifest.resolve(strict=True)
    value=json.loads(manifest.read_bytes());paths=(manifest,manifest.parent/value['image_path'],native.SOURCE,
        root/'hepta/hia_service_emission_native.py',root/'tests/hia_service_emission_fixtures.py',
        root/'tests/fixtures/hia_service_emission_original_v76.json',Path(__file__).resolve())
    before={str(path):sha256(path.read_bytes()).hexdigest() for path in paths}
    image=native.installed_emission(manifest);rows=[]
    for family in ('parameter','return','check'):
        for failure in (False,True):
            for outer in (False,True):
                expected=observe('reference',family,failure,outer,image)
                actual=observe('native',family,failure,outer,image)
                rows.append({'family':family,'failure':failure,'outer':outer,
                             'expected':expected,'actual':actual,'equal':expected==actual})
    after={str(path):sha256(path.read_bytes()).hexdigest() for path in paths}
    report={'schema':'hia.emission.generator-lifetimes.v77.r1','python':sys.version,'observations':rows,
            'matches':sum(row['equal'] for row in rows),'total':len(rows),
            'inputs_before':before,'inputs_after':after,'inputs_unchanged':before==after,
            'no_manual_traceback_clear':True,'no_gc':True,'scope':'DEVELOPMENT_ONLY',
            'current_source_cold':False,'whole_native':False}
    report['status']='PASS' if report['matches']==report['total'] and before==after else 'FAIL'
    (output/'REPORT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps({key:report[key] for key in ('status','matches','total','inputs_unchanged')}))
    return 0 if report['status']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
