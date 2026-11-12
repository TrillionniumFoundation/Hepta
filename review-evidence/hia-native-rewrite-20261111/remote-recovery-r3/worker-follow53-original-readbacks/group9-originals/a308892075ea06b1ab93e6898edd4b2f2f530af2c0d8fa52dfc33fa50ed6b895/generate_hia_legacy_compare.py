"""Compare complete, independently admitted primitive-v1 and primitive-v6 Core."""
from tools.legacy_authoring import source,document as build,write_document
from tools.hia_composite_lowering_driver_common import COMMON

CONSTANTS={'BAD':0xfffffffd,'MAGIC':int.from_bytes(b'HIALCP01','little')}
BODY=r'''
def compare(s:readbuf, r:readbuf, w:mutbuf) -> u32:
    if length(w) < 64:
        return BAD
    if length(s) == 0 or length(s) > 8388608 or length(r) == 0 or length(r) > 8388608:
        return BAD
    if old_suffix(s) == 0 or new_suffix(r) == 0:
        return BAD
    different = 0
    if length(s) != length(r):
        different = 1
    else:
        at = 0
        while at < length(s):
            if at != length(s) - 3 and byte(s, at) != byte(r, at):
                different = 1
            at = at + 1
    put(w, 0, MAGIC)
    put(w, 8, different)
    put(w, 16, length(s))
    put(w, 24, length(r))
    put(w, 32, 0)
    put(w, 40, 0)
    put(w, 48, 0)
    put(w, 56, 0)
    return 64
'''

def source_program():
    extra=''
    for name,version in [('old_suffix','1'),('new_suffix','6')]:
        raw=(',"schema":"hepta.hia.program.v'+version+'"}').encode()
        extra+=f'\ndef {name}(s:readbuf) -> u64:\n    if length(s) < {len(raw)}:\n        return 0\n    at = length(s) - {len(raw)}\n'
        for i,b in enumerate(raw): extra+=f'    if byte(s, at + {i}) != {b}:\n        return 0\n'
        extra+='    return 1\n'
    return source(BODY+extra+'\n'+COMMON,CONSTANTS,'compare')

def document(): return build(source_program(),'legacy_composite_compare')
if __name__=='__main__': write_document(document(),'legacy_composite_compare.hiaasm')
