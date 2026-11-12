"""Complete primitive-v1 publication for the old historical lowering pass.

The independent ordinary publication source/image is unchanged. The only
semantic addition here is the required v6→v1 schema substitution before the
same complete primitive Core admission.
"""
from tools.legacy_authoring import source,document as build,write_document
from tools.generate_hia_composite_publication_driver import BODY as ORIGINAL,CONSTANTS as ORIGINAL_CONSTANTS
from tools.hia_composite_lowering_driver_common import COMMON

CONSTANTS=dict(ORIGINAL_CONSTANTS)
CONSTANTS.update(PUBLIC_DRIVER=47,PUBLIC_STATE=int.from_bytes(b'HIALPB01','little'))


def source_program():
    body=ORIGINAL.replace('def publication_begin(s:readbuf, w:mutbuf) -> u64:\n',
        'def publication_begin(s:readbuf, w:mutbuf) -> u64:\n    if get(w, C_LEGACY) != 1 or get(w, C_PROFILE) != 1:\n        return 0\n')
    needle='        put(w, F_BYTES, size)\n        return protect(o, w, B_CANONICAL_CORE, 1, 10)'
    assert body.count(needle)==1
    suffix=b',"schema":"hepta.hia.program.v6"}'
    replacement=f'''        put(w, F_BYTES, size)
        if size < {len(suffix)}:
            return refuse(w, 710)
        return view(o, w, B_CANONICAL_CORE, size - {len(suffix)}, {len(suffix)}, 901)
    if phase == 901:
        if legacy_suffix(w) == 0:
            return refuse(w, 711)
        store(w, WIRE, 49)
        return copy(o, w, B_CONTROLLER, WIRE, B_CANONICAL_CORE, get(w, F_BYTES) - 3, 1, 902)
    if phase == 902:
        return protect(o, w, B_CANONICAL_CORE, 1, 10)'''
    body=body.replace(needle,replacement)
    extra='\ndef legacy_suffix(w:mutbuf) -> u64:\n'
    for i,b in enumerate(suffix):extra+=f'    if byte(w, OBS + {i}) != {b}:\n        return 0\n'
    extra+='    return 1\n'
    common=COMMON.replace('or image > 23:','or image > 27:')
    return source(body+extra+'\n'+common,CONSTANTS,'publication')

def document(): return build(source_program(),'legacy_composite_publication')
if __name__=='__main__': write_document(document(),'legacy_composite_publication.hiaasm')
