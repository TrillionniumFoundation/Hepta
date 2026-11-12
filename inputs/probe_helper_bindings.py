"""Observe exact pre/post-admission global binding against the retained body.

This first probe runs the original authored candidate unchanged. Differences
are actual failures, never expected-failure decorations or a qualification.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys
import traceback


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    args.source=args.source.resolve(strict=True)
    args.output.mkdir(mode=0o700)
    sys.path.insert(0,str(args.source))
    from hepta import hia_agent_service as api
    from hepta import hia_service_evaluation_native as native
    from tests import hia_service_evaluation_fixtures as fixtures
    manifest_raw=args.manifest.read_bytes()
    manifest=json.loads(manifest_raw)
    image_path=args.manifest.parent/manifest['image_path']
    image_raw=image_path.read_bytes()
    assert sha256(image_raw).hexdigest()==manifest['image_sha256']
    anchors={name:vars(api)[name] for name in ('_connection_arguments','_value_observation')}
    records=[];held_images=[];current_error=None
    def observe(helper,kind,when,selected):
        events=[];image=None
        anchor=anchors[helper]
        def replacement(value):
            events.append(['call',helper])
            return anchor(value)
        class Foreign:
            def __getattribute__(self,name):
                if name=='__module__':
                    events.append(['metadata',name])
                    if kind=='object_metadata_error':
                        raise LookupError('metadata must not run during helper selection')
                    return 'foreign_evaluation_fixture'
                return object.__getattribute__(self,name)
            def __call__(self,value):
                events.append(['call',helper])
                return anchor(value)
        def mutate():
            if kind=='absent':
                del vars(api)[helper]
            elif kind=='original':
                vars(api)[helper]=anchor
            elif kind=='none':
                vars(api)[helper]=None
            elif kind=='function':
                vars(api)[helper]=replacement
            else:
                vars(api)[helper]=Foreign()
        try:
            if when=='pre':
                mutate()
            if selected:
                try:
                    image=native.NativeEvaluationImage(image_raw,manifest['image_sha256'])
                except BaseException as error:
                    return {'admission_events':list(events),'admission_error':{
                        'type':type(error).__name__,'args':list(error.args)},
                        'business':None,'helper_events':[],'actual_entries':0}
                held_images.append(image)
            admission_events=list(events);events.clear()
            if when=='post':
                mutate()
            before=0 if image is None else image.entries
            business=fixtures.fixture_call('eval-ok',image)
            return {'admission_events':admission_events,'admission_error':None,
                    'business':business,'helper_events':list(events),
                    'actual_entries':0 if image is None else image.entries-before}
        finally:
            vars(api)[helper]=anchor
    try:
        for helper in anchors:
            for when in ('pre','post'):
                for kind in ('original','function','none','object','absent','object_metadata_error'):
                    expected=observe(helper,kind,when,False)
                    actual=observe(helper,kind,when,True)
                    comparable={key:actual[key] for key in expected if key!='actual_entries'}
                    reference={key:expected[key] for key in expected if key!='actual_entries'}
                    reached=(actual['actual_entries']>0 or actual['admission_error'] is not None)
                    records.append({'helper':helper,'timing':when,'kind':kind,'reference':expected,
                                    'native':actual,'equal':comparable==reference,'native_observed':reached})
    except BaseException:
        current_error=traceback.format_exc()
    finally:
        for name,anchor in anchors.items():
            assert vars(api).get(name) is anchor
        stable=args.manifest.read_bytes()==manifest_raw and image_path.read_bytes()==image_raw
        passed=(len(records)==24 and current_error is None and stable
                and all(row['equal'] and row['native_observed'] for row in records))
        report={'schema':'hia.evaluation.pre-post-helper-binding.v1','status':'PASS' if passed else 'FAIL',
                'python':sys.version,'cases':records,'case_count':len(records),
                'equal_count':sum(row['equal'] for row in records),
                'source':{'runtime':sha256((args.source/'hepta/hia_service_evaluation_native.py').read_bytes()).hexdigest(),
                          'service':sha256((args.source/'hepta/hia_agent_service.py').read_bytes()).hexdigest()},
                'image_sha256':manifest['image_sha256'],'manifest_sha256':sha256(manifest_raw).hexdigest(),
                'input_bytes_unchanged':stable,'exception':current_error,
                'historical_results_transferred':False,'current_cold':False}
        raw=(json.dumps(report,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
        (args.output/'REPORT.json').write_bytes(raw)
        print(json.dumps({'status':report['status'],'cases':len(records),
              'equal':report['equal_count'],'report_sha256':sha256(raw).hexdigest()}),flush=True)
    return int(not passed)
if __name__=='__main__':raise SystemExit(main())
