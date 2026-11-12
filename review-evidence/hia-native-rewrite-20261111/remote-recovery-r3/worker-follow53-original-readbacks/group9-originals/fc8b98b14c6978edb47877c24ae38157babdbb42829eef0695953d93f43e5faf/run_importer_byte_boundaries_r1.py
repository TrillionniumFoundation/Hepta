"""Actual full importer at the +2-byte rename boundary and original old errors.

Unused, well-formed enum declarations carry the near-limit source without
expanding Core. No malformed opaque filler or changed language limit is used.
"""
from importer_panel_support import Panel,BASE,compact
import sys
sys.path.insert(0,str(BASE))
from tests.test_hia_program import f,b,c,ret
from tests.test_hia_program_composite import record,enum

LIMIT=8<<20

def exact_source(size,kind='valid'):
    empty='E'*128
    definitions=[record(empty,[])]
    for n in range(15):
        definitions.append(enum('Choice'+str(n),[(f'v{v}',[(f'f{i:02d}',empty) for i in range(64)]) for v in range(32)]))
    fn=f('ok',[],[],[],[b('entry',[],[],ret())])
    if kind=='lower-error':fn['blocks']=None
    if kind=='core-error':fn['blocks'][0]['ops']=[c('bad','u32','not-an-integer')]
    doc={'schema':'hepta.hia.program.v2','module':'boundary','types':definitions,'functions':[fn]}
    need=size-len(compact(doc));assert need>=0
    for definition in definitions[1:]:
        for variant in definition['variants']:
            for field in variant['fields']:
                add=min(128-len(field['name']),need)
                field['name']+='x'*add;need-=add
    assert need==0,need
    wire=compact(doc);assert len(wire)==size
    return wire

panel=Panel('byte-boundaries-r1',__file__);error=None
try:
    for delta in (-2,-1,0):
        wire=exact_source(LIMIT+delta)
        row=panel.run('original-limit'+str(delta),wire,expected_stage=None if delta==-2 else (9,3),timeout=180)
        if delta==-2:assert row['oracle']['accepted']
        else:assert row['oracle']['error']=='E_HIA_LIMIT: program exceeds byte budget before encoding'
    panel.run('old-lowering-before-renamed-byte-limit',exact_source(LIMIT,'lower-error'),timeout=180)
    row=panel.run('old-primitive-before-renamed-byte-limit',exact_source(LIMIT,'core-error'),timeout=180)
    assert row['stderr_words'][4]==8
except BaseException as exc:
    error=exc;raise
finally:panel.close(error)
