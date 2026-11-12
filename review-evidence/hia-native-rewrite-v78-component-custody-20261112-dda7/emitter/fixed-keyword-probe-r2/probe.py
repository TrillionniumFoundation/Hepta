from pathlib import Path
import json,sys
from types import SimpleNamespace
from unittest.mock import patch

ROOT=Path('/workspace/scratch/dda74a4fae35/v78-emitter-development-r1/source')
sys.path.insert(0,str(ROOT))
from hepta import hia_program_native as backend
from hepta.hia_core_emitter_native import NativeCoreEmitter
MANIFEST=ROOT.parent/'compile-r2/image/manifest.json'
spec=json.loads(MANIFEST.read_bytes())
owner=NativeCoreEmitter((MANIFEST.parent/spec['image_path']).read_bytes(),spec['image_sha256'],vars(backend))

def observe(native,outer,fail):
    events=[];held=None
    def handled():
        e=sys.exception();return None if e is None else [type(e).__name__,str(e)]
    class Alignment:
        def __del__(self):events.append(['alignment-del',handled()])
    def choose(*values):events.append(['max',handled()]);return Alignment()
    def writer(text,symbols,relocations,*,text_alignment):
        events.append(['writer-enter',handled()])
        text_alignment=None
        events.append(['writer-after-param-clear',handled()])
        if fail:raise ValueError('writer rejected')
        return b'object'
    receiver=SimpleNamespace(document={'schema':sorted(backend.CORE_SCHEMAS)[0],'functions':[],'exports':['f']},machine_plan=None,exports=['f'],symbols=[],function_alignment=16,c=SimpleNamespace(data=b'x',finalize=lambda:(b'text',[])))
    def invoke():
        nonlocal held
        try:
            result=owner.invoke('_Emitter.render',(receiver,)) if native else backend._Emitter.render(receiver)
            events.append(['return',list(map(bytes.hex,result)),handled()])
        except BaseException as error:
            held=error;events.append(['error',type(error).__name__,list(error.args),handled()])
        events.append(['held-before-release',handled()])
        held=None
        events.append(['held-after-release',handled()])
    with patch.dict(vars(backend),{'max':choose,'write_elf_object':writer}):
        if outer:
            try:raise LookupError('outer')
            except LookupError:invoke()
        else:invoke()
    return events

rows=[]
for outer in (False,True):
    for fail in (False,True):
        original=observe(False,outer,fail);native=observe(True,outer,fail)
        assert any(x[0]=='writer-enter' for x in original) and any(x[0]=='writer-enter' for x in native), 'target effect not reached'
        rows.append({'outer':outer,'callee_raises':fail,'original':original,'native':native,'equal':original==native})
out={'python':sys.version,'scope':'ACTUAL_ORIGINAL_RENDER_FIXED_KEYWORD_CALL_PROTOCOL','source':'Frozen R4 after successful116; no source or image mutation','rows':rows,'pass':all(x['equal'] for x in rows)}
Path(__file__).with_name('RESULT.json').write_text(json.dumps(out,indent=2)+'\n');print(json.dumps(out,indent=2));raise SystemExit(0 if out['pass'] else 1)
