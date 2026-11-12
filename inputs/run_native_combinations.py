"""Real Artifact/Evaluation mappings through the three shared public facades."""
from pathlib import Path
from collections import Counter
from contextlib import ExitStack
from types import MethodType
from unittest.mock import patch
import ctypes
import hashlib
import json
import struct
import sys

import argparse
_parser=argparse.ArgumentParser()
_parser.add_argument('--source',type=Path,required=True)
_parser.add_argument('--output',type=Path,required=True)
_parser.add_argument('--artifacts',type=Path,required=True)
_parser.add_argument('--evaluation',type=Path,required=True)
_args=_parser.parse_args()
SOURCE=_args.source.resolve(strict=True)
sys.path.insert(0,str(SOURCE))
from hepta import hia_agent_service as api
from hepta import hia_service_artifacts_native as artifacts
from hepta import hia_service_evaluation_native as evaluation
from tests import hia_service_artifacts_fixtures as fixtures

NAMES=('_native','_build_inputs','_build_receipt')
ALIASES=tuple('_NATIVE_ARTIFACTS_'+name.strip('_').upper()+'_REFERENCE' for name in NAMES)

def main():
    output=_args.output.absolute();output.mkdir()
    paths={'artifacts':_args.artifacts.resolve(strict=True),
           'evaluation':_args.evaluation.resolve(strict=True)}
    captures={'artifacts':artifacts.installed_artifacts(paths['artifacts'],capture_identity=True),
              'evaluation':evaluation.installed_evaluation(paths['evaluation'],capture_identity=True)}
    owners={'artifacts':artifacts.NativeArtifactsService(captures['artifacts'].image,checker_custody=captures['artifacts']),
            'evaluation':evaluation.NativeEvaluationService(captures['evaluation'].image,checker_custody=captures['evaluation'])}
    original=fixtures.original_class()
    counts={name:Counter() for name in owners};old_entries={}
    images={name:owner.image for name,owner in owners.items()}
    input_files={}
    for name,path in paths.items():
        data=json.loads(path.read_bytes())
        for p in (path,path.parent/data['image_path'],SOURCE/('examples/hia_bootstrap/service_'+name+'.hiaasm')):
            input_files[str(p)]=hashlib.sha256(p.read_bytes()).hexdigest()
    for name,image in images.items():
        old=image._entry;old_entries[name]=old
        def observed(source,size,result,capacity,state,extent,*,_old=old,_image=image,_name=name):
            outcome=_old(source,size,result,capacity,state,extent)
            if size==len(_image.table):
                assert capacity==2048 and extent==_image.workspace_bytes
                words=struct.unpack('<21Q',ctypes.string_at(state,168))
                counts[_name][str(words[19])]+=1
            return outcome
        image._entry=observed
    rows=[]
    try:
        for selected in ('artifacts','evaluation','both','neither'):
            for connection in (False,True):
                for kind in ('object','linked'):
                    for mode in NAMES:
                        for broken in (False,True):
                            left=fixtures.service(connection=connection,output_kind=kind)
                            right=fixtures.service(connection=connection,output_kind=kind)
                            for name in NAMES:
                                setattr(left,name,MethodType(getattr(original,name),left))
                                setattr(right,name,MethodType(getattr(api.HIAAgentService,name),right))
                            if broken:
                                left.metadata['installation']={'wrong':'installation'}
                                right.metadata['installation']={'wrong':'installation'}
                            right._native_artifacts=owners['artifacts'] if selected in ('artifacts','both') else None
                            right._native_evaluation=owners['evaluation'] if selected in ('evaluation','both') else None
                            expected=fixtures.observed(lambda:fixtures.invoke_original(mode,left))
                            before={name:sum(value.values()) for name,value in counts.items()}
                            values=fixtures.arguments(mode,right)
                            with ExitStack() as stack:
                                if selected!='neither':
                                    for name in NAMES:
                                        stack.enter_context(patch.object(api.HIAAgentService,name+'_reference',side_effect=AssertionError('native route entered old body')))
                                    for alias in ALIASES:
                                        stack.enter_context(patch.object(api,alias,side_effect=AssertionError('native route entered old alias')))
                                actual=fixtures.observed(lambda:getattr(api.HIAAgentService,mode)(right,*values,_connection=right.store.connection))
                            assert actual==expected,(selected,connection,kind,mode,broken,actual,expected)
                            assert right.store.events==left.store.events,(selected,mode,right.store.events,left.store.events)
                            delta={name:sum(value.values())-before[name] for name,value in counts.items()}
                            chosen='artifacts' if selected in ('artifacts','both') else 'evaluation' if selected=='evaluation' else None
                            assert all((delta[name]>0)==(name==chosen) for name in delta),(selected,delta)
                            rows.append({'selected':selected,'mode':mode,'connection':connection,'kind':kind,'broken':broken,
                                         'expected':expected,'actual':actual,'store_events':right.store.events,'native_returns':delta})
        after={p:hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in input_files}
        assert after==input_files
        report={'schema':'hia.evaluation-artifact-real-combinations.v1','status':'PASS','python':sys.version,
                'scope':'new local development source; actual two images, original3 bodies and public facades; no cold authority',
                'comparisons':len(rows),'rows':rows,'actual_returns':{n:dict(c) for n,c in counts.items()},
                'input_before':input_files,'input_after':after,'current_cold':False,'whole_native':False,
                'original_budget_gates_run':False}
        (output/'REPORT.json').write_text(json.dumps(report,sort_keys=True,indent=2,default=lambda value: {'__bytes_hex__': value.hex()} if type(value) is bytes else (_ for _ in ()).throw(TypeError(type(value).__name__)))+'\n')
        print(json.dumps({k:report[k] for k in ('status','comparisons','actual_returns')}))
    finally:
        for name,image in images.items():image._entry=old_entries[name]

if __name__=='__main__':main()
