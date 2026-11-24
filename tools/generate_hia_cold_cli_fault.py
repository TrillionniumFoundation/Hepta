"""Author exact CLI negative descriptor/resource setup in HIA.

Uses the already pinned, syscall-only cold-owner mechanical capsule.  Policy
sets the same three original conditions, then execveat replaces this process.
"""
import ast
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cold_document import document
from tools.generate_hia_release_owner import POLICY

ROOT = Path(__file__).resolve().parents[1]

SOURCE = r'''def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) != 128 or length(o) != 128 or length(w) != 4194304:
        return 0
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        if word_load(s, 0) != MAGIC or word_load(s, 8) > 3 or word_load(s, 16) < 3 or word_load(s, 24) < 3 or word_load(s, 16) == word_load(s, 24):
            return finish(o, w, 65)
        i = 32
        while i < 128:
            if byte(s, i) != 0:
                return finish(o, w, 65)
            i = i + 1
        constants(w)
        return call(o, w, 1, 72, word_load(s, 16), 1034, 0, 0, 0, 0, 0)
    if failed(result):
        return finish(o, w, 74)
    if phase == 1:
        if result & 15 != 15:
            return finish(o, w, 65)
        return call(o, w, 2, 72, word_load(s, 24), 1034, 0, 0, 0, 0, 0)
    if phase == 2:
        if result & 15 != 15:
            return finish(o, w, 65)
        return call(o, w, 3, 8, word_load(s, 24), 0, 0, 0, 0, 0, 0)
    if phase == 3:
        if result != 0:
            return finish(o, w, 74)
        return call(o, w, 4, 33, word_load(s, 24), 0, 0, 0, 0, 0, 0)
    if phase == 4:
        return call(o, w, 5, 157, 4, 0, 0, 0, 0, 0, 0)
    if phase == 5:
        return call(o, w, 6, 157, 3, 0, 0, 0, 0, 0, 0)
    if phase == 6:
        if result != 0:
            return finish(o, w, 74)
        return call(o, w, 7, 160, 4, 500, 0, 0, 0, 0, 12)
    if phase == 7:
        mode = word_load(s, 8)
        if mode == 1:
            return call(o, w, 11, 3, 0, 0, 0, 0, 0, 0, 0)
        if mode == 2:
            return call(o, w, 8, 257, 18446744073709551516, 2000, 131073, 0, 0, 0, 12)
        if mode == 3:
            put(w, 520, 2097152)
            put(w, 528, 2097152)
            return call(o, w, 11, 160, 9, 520, 0, 0, 0, 0, 12)
        return resume(s, o, w, 11)
    if phase == 8:
        if result < 3:
            return finish(o, w, 74)
        put(w, 600, result)
        return call(o, w, 9, 33, result, 1, 0, 0, 0, 0, 0)
    if phase == 9:
        return call(o, w, 11, 3, get(w, 600), 0, 0, 0, 0, 0, 0)
    if phase == 11:
        put(w, 1000, 2016)
        put(w, 1008, 18446744073709551615)
        put(w, 1016, 2032)
        put(w, 1024, 2048)
        put(w, 1032, 2080)
        put(w, 1040, 2112)
        put(w, 1048, 18446744073709551615)
        put(o, 0, 1000)
        put(o, 8, 7)
        put(o, 16, 1100)
        put(w, 0, 12)
        return 2
    if phase == 12:
        return call(o, w, 13, 322, word_load(s, 16), 2144, 1100, 1116, 4096, 0, 252)
    return finish(o, w, 74)
'''


def source():
    text=SOURCE.replace('MAGIC',str(int.from_bytes(b'HIAQCF01','little')))
    nodes={node.name:ast.get_source_segment(POLICY,node) for node in ast.parse(POLICY).body}
    text+='\n\n'+'\n\n'.join(nodes[name] for name in ('get','getn','put','call','finish','resume','failed'))
    text=text.replace('return getn(w, at, 8)','return word_load(w, at)')
    text+='\n\ndef constants(w:mutbuf) -> u64:\n'
    for at,raw in [(2000,b'/dev/full'),(2016,b'hia-cli'),(2032,b'PATH='),(2048,b'LANG=C.UTF-8'),(2080,b'LC_ALL=C.UTF-8'),(2112,b'TZ=UTC'),(2144,b'')]:
        raw+=b'\0'
        for i in range(0,len(raw),8):text+=f'    put(w, {at+i}, {int.from_bytes(raw[i:i+8],"little")})\n'
    return text+'    return 0\n'


if __name__=='__main__':
    path=ROOT/'examples/hia_bootstrap/cold_cli_fault.hepta'
    path.write_text(render_assembly(document(source(),'cold_cli_fault')))
    print(path.name,path.stat().st_size)
