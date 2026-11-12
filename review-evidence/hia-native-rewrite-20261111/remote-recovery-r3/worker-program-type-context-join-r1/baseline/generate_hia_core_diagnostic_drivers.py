"""Independent revision of program/publication drivers retaining full errors.

The published program sources are immutable dependencies. Only their exact Core
refusal path gains readonly diagnostic rendering, followed by the original
cleanup order. The complete checker and text renderer remain separate images.
"""
import ast
from hashlib import sha256
import importlib.util
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
PROGRAM=ROOT.parent/'native-program-admission-next'
ORDINARY=ROOT.parent/'native-composite-driver-reconstructed'
BASE=ROOT.parent/'Hepta-v66-restored'
sys.path[:0]=[str(PROGRAM),str(ORDINARY),str(BASE)]
from tools.program_authoring import document as build
from hepta.hia_agent_assembly import render_assembly

DEPENDENCIES={
 'program':(PROGRAM/'tools/generate_hia_program_admission_driver.py','aaedd6b85df7cb20dd7b3f08610b514fb1b12d63750b3f67769981457137db48'),
 'publication':(ORDINARY/'tools/generate_hia_composite_publication_driver.py','e30dfdc977e532c812f985a52d683198203654c260ca52c23e4d38772825a93f'),
}

EXTRA={
 'DIAG_IMAGE':55,'DIAG_SLOT':57,'DIAG_MAGIC':int.from_bytes(b'HIACDT01','little'),
 'DIAG_STATUS':28672,'DIAG_SOURCE_BYTES':28680,'DIAG_RESUME':28688,'DIAG_NEEDED':28696,
 'DIAG_REQUEST':28704,'DIAG_HEADER':28736,'DIAG_BOUND':8388608+262144+1024,
 'NEED':0xfffffffe,
}

DIAGNOSTICS=r'''
def diagnostic_start(w:mutbuf, status:u64, source_bytes:u64, resume:u64) -> u64:
    if status == 0 or cap(w, DIAG_SLOT) != 0 or source_bytes == 0 or source_bytes > 8388608:
        return refuse(w, 1100)
    put(w, DIAG_STATUS, status)
    put(w, DIAG_SOURCE_BYTES, source_bytes)
    put(w, DIAG_RESUME, resume)
    put(w, C_PHASE, 800)
    return 0

def diagnostic_header(w:mutbuf, status:u64, extent:u64, source_bytes:u64) -> u64:
    if get(w, OBS) != DIAG_MAGIC or get(w, OBS + 8) != 1 or get(w, OBS + 16) != status:
        return 0
    message = get(w, OBS + 24)
    size = get(w, OBS + 32)
    needed = get(w, OBS + 40)
    nodes = get(w, OBS + 48)
    if message == 0 or message > 92 or size == 0 or size > DIAG_BOUND - 64:
        return 0
    if needed != size + 64 or nodes == 0 or nodes > 262144 or get(w, OBS + 56) != 0:
        return 0
    if source_bytes == 0 or source_bytes > 8388608 or needed > source_bytes + nodes + 1024:
        return 0
    if extent != 0 and extent != needed:
        return 0
    return 1

def diagnostic_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 800:
        return protect(o, w, B_ADMISSION_STATE, 1, 801)
    if phase == 801:
        return protect(o, w, B_ADMISSION_ARENA, 1, 802)
    if phase == 802:
        return grow(o, w, DIAG_SLOT, 64, 803)
    if phase == 803:
        return invoke(o, w, DIAG_IMAGE, B_ADMISSION_ARENA, 0, cap(w, B_ADMISSION_ARENA), B_ADMISSION_STATE, cap(w, B_ADMISSION_STATE), DIAG_SLOT, cap(w, DIAG_SLOT), DIAG_SLOT, 0, 64, 804)
    if phase == 804:
        if get(w, C_RETURN) != NEED or cap(w, DIAG_SLOT) != 64:
            return refuse(w, 1101)
        if diagnostic_header(w, get(w, DIAG_STATUS), 0, get(w, DIAG_SOURCE_BYTES)) == 0:
            return refuse(w, 1102)
        put(w, DIAG_NEEDED, get(w, OBS + 40))
        i = 0
        while i < 64:
            store(w, DIAG_HEADER + i, byte(w, OBS + i))
            i = i + 1
        return grow(o, w, DIAG_SLOT, get(w, DIAG_NEEDED), 805)
    if phase == 805:
        return invoke(o, w, DIAG_IMAGE, B_ADMISSION_ARENA, 0, cap(w, B_ADMISSION_ARENA), B_ADMISSION_STATE, cap(w, B_ADMISSION_STATE), DIAG_SLOT, cap(w, DIAG_SLOT), DIAG_SLOT, 0, 64, 806)
    if phase == 806:
        needed = get(w, DIAG_NEEDED)
        if get(w, C_RETURN) != needed or cap(w, DIAG_SLOT) != needed:
            return refuse(w, 1103)
        i = 0
        while i < 64:
            if byte(w, DIAG_HEADER + i) != byte(w, OBS + i):
                return refuse(w, 1104)
            i = i + 1
        return protect(o, w, DIAG_SLOT, 1, 807)
    if phase == 807:
        return release(o, w, B_ADMISSION_STATE, 808)
    if phase == 808:
        return release(o, w, B_ADMISSION_ARENA, 809)
    if phase == 809:
        put(w, C_PHASE, get(w, DIAG_RESUME))
        return 0
    return refuse(w, 1105)
'''

CHILD=r'''
def child_diagnostic_start(o:mutbuf, w:mutbuf) -> u64:
    if get(w, OBS + 32) != 8 or get(w, OBS + 144) != 45:
        return refuse(w, 1110)
    target = get(w, M_CHILD_TARGET)
    needed = cap(w, target)
    if needed < 65 or needed > DIAG_BOUND or cap(w, DIAG_SLOT) != 0:
        return refuse(w, 1111)
    mirror_frame(w)
    put(w, DIAG_STATUS, get(w, OBS + 40))
    put(w, DIAG_REQUEST, get(w, OBS + 48))
    put(w, DIAG_NEEDED, needed)
    return view(o, w, target, 0, 64, 41)

def child_diagnostic_step(o:mutbuf, w:mutbuf) -> u64:
    phase = get(w, C_PHASE)
    if phase == 41:
        if diagnostic_header(w, get(w, DIAG_STATUS), get(w, DIAG_NEEDED), 8388608) == 0:
            return refuse(w, 1112)
        return grow(o, w, DIAG_SLOT, get(w, DIAG_NEEDED), 42)
    if phase == 42:
        return copy(o, w, get(w, M_CHILD_TARGET), 0, DIAG_SLOT, 0, get(w, DIAG_NEEDED), 43)
    if phase == 43:
        return protect(o, w, DIAG_SLOT, 1, 44)
    if phase == 44:
        return release(o, w, get(w, M_CHILD_TARGET), 45)
    if phase == 45:
        return finish(o, w, 8, get(w, DIAG_STATUS), get(w, DIAG_REQUEST))
    return refuse(w, 1113)
'''


def replace_node(tree,name,before,after):
    function=next(n for n in tree.body if n.name==name)
    matches=[n for n in ast.walk(function) if ast.unparse(n)==before]
    assert len(matches)==1,(name,before,len(matches))
    target=matches[0]
    class Replace(ast.NodeTransformer):
        def visit(self,node):
            return ast.parse(after).body[0] if node is target else super().visit(node)
    Replace().visit(tree)


def load(which):
    path,expected=DEPENDENCIES[which];raw=path.read_bytes()
    assert sha256(raw).hexdigest()==expected,(path,sha256(raw).hexdigest())
    spec=importlib.util.spec_from_file_location('frozen_diagnostic_'+which,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def source_program(which):
    module=load(which);base=module.source_program();tree=ast.parse(base)
    constants=dict(module.CONSTANTS);constants.update(EXTRA)
    step='program_step' if which=='program' else 'publication_step'
    function=next(n for n in tree.body if n.name==step)
    function.body[1:1]=ast.parse('if phase >= 800 and phase < 810:\n    return diagnostic_step(o, w)').body
    if which=='program':
        function.body[2:2]=ast.parse('if phase >= 41 and phase <= 45:\n    return child_diagnostic_step(o, w)').body
        phase=22; resume=24; stored='M_ERROR'; extent='M_INPUT_BYTES'; release_next=23
        replace_node(tree,'program_step','return child_error(o, w)',
            'if get(w, OBS + 32) == 8:\n    return child_diagnostic_start(o, w)\nelse:\n    return child_error(o, w)')
        child=next(n for n in tree.body if n.name=='child_result')
        group=next(n for n in child.body if isinstance(n,ast.If) and ast.unparse(n.test)=='group != 0')
        group.body=ast.parse('''
if error == 0:
    return 0
extent = get(w, OBS + 128)
if group == 8:
    if role != 45 or admission_status(error) == 0 or extent < 65 or extent > DIAG_BOUND:
        return 0
    put(w, CAPS + target * 8, extent)
elif extent != 0:
    return 0
return 1
''').body
    else:
        phase=15; resume=17; stored='F_ERROR'; extent='F_BYTES'; release_next=16
    branch=next(n for n in function.body if isinstance(n,ast.If) and ast.unparse(n.test)==f'phase == {phase}')
    assert isinstance(branch.body[-1],ast.Return)
    branch.body[-1:-1]=ast.parse(f'if result != 0:\n    return diagnostic_start(w, result, get(w, {extent}), {resume})').body
    invoke=next(n for n in tree.body if n.name=='invoke')
    bound=28 if which=='program' else 27
    matches=[n for n in ast.walk(invoke.body[0].test) if isinstance(n,ast.Compare) and ast.unparse(n)==f'image > {bound}']
    assert len(matches)==1
    comparison=matches[0]
    class PermitRenderer(ast.NodeTransformer):
        def visit_Compare(self,node):
            if node is comparison:
                return ast.parse(f'image > {bound} and image != 55',mode='eval').body
            return self.generic_visit(node)
    invoke.body[0].test=PermitRenderer().visit(invoke.body[0].test)
    tree.body+=ast.parse(DIAGNOSTICS+(CHILD if which=='program' else '')).body
    class Expand(ast.NodeTransformer):
        def visit_Name(self,node):
            if isinstance(node.ctx,ast.Load) and node.id in constants:
                return ast.copy_location(ast.Constant(constants[node.id]),node)
            return node
    tree=ast.fix_missing_locations(Expand().visit(tree))
    result=ast.unparse(tree)+'\n'
    ledger={'scope':'DIAGNOSTIC_ONLY_INDEPENDENT_DRIVER_REVISION','base_expanded_sha256':sha256(base.encode()).hexdigest(),
        'new_expanded_sha256':sha256(result.encode()).hexdigest(),'published_source_modified':False,
        'new_image_role':55,'new_error_view_slot':57,'terminal_layout_bytes':128,
        'terminal_sequence_is_actual_new_event_sequence':True}
    (ROOT/'development'/('driver-'+which+'-transform.json')).write_text(json.dumps(ledger,indent=2,sort_keys=True)+'\n')
    (ROOT/'development'/('driver-'+which+'-authoring.py')).write_text(result)
    return result


if __name__=='__main__':
    for which in ('program','publication'):
        name='diagnostic_'+which+'_driver'
        value=build(source_program(which),name)
        raw=render_assembly(value).encode()
        target=ROOT/'examples/hia_bootstrap'/(name+'.hiaasm');target.write_bytes(raw)
        counts={'functions':len(value['functions']),
            'blocks':sum(len(f['blocks']) for f in value['functions']),
            'instructions':sum(len(b['ops']) for f in value['functions'] for b in f['blocks'])}
        print(json.dumps({'name':name,'bytes':len(raw),'sha256':sha256(raw).hexdigest(),'counts':counts}),flush=True)
