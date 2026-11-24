"""Author the HIA top-level root control / unprivileged supervisor dispatcher."""
from __future__ import annotations
import argparse
from pathlib import Path
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_system_jobctl_request import document
from tools.generate_hia_system_jobctl_supervisor_common import helpers,literals,substitute
ROOT=Path(__file__).resolve().parents[1]

POLICY=r'''
def entry(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(o) != 128 or length(w) != STATE_BYTES:
        return 0
    mode = get(w, SUP_ENTRY_MODE)
    if mode == 0:
        if length(s) < 32 or uint(s, 0) != ARG_MAGIC or uint(s, 24) != length(s):
            return 0
        count = uint(s, 8)
        if count != 1 and count != 3:
            return 0
        index = 0
        at = 32
        while index < count:
            if at > length(s) or length(s) - at < 9:
                return 0
            size = uint(s, at)
            if size > 131072 or size >= length(s) - at - 8 or byte(s, at + 8 + size) != 0:
                return 0
            target = choose(index == 2, SUP_JOB, SUP_TEMP)
            cursor = 0
            while cursor < size:
                store(w, target + cursor, byte(s, at + 8 + cursor))
                cursor = cursor + 1
            store(w, target + size, 0)
            if kernel_text(w, target, size) == 0:
                return call(o, w, 99999, 231, 101, 0, 0, 0, 0, 0, 0)
            if index == 1:
                end = text_supervise(w, SUP_PATH)
                if equal(w, target, size, SUP_PATH, end - SUP_PATH) == 1:
                    put(w, SUP_INTERACTIVE, 0)
                else:
                    end = text_supervise_pty(w, SUP_PATH)
                    if equal(w, target, size, SUP_PATH, end - SUP_PATH) == 0:
                        return 0
                    put(w, SUP_INTERACTIVE, 1)
            if index == 2:
                put(w, SUP_JOB_SIZE, size)
            at = at + size + 9
            index = index + 1
        mode = choose(count == 1, 1, 2)
        put(w, SUP_ENTRY_MODE, mode)
        if mode == 2:
            put(w, 0, 2000)
    if mode == 1:
        return 25
    if mode != 2:
        return 0
    phase = get(w, 0)
    if (phase >= 1000 and phase < 1010) or (phase >= 1100 and phase < 1120):
        return 25
    if phase >= 2000 and phase < 2200:
        return 16
    if phase >= 2200 and phase < 2300:
        return 18
    if phase >= 2300 and phase < 2500:
        return 19
    if phase >= 2500 and phase < 2600:
        return 20
    if phase >= 3000 and phase < 3100:
        return 21
    if phase >= 3100 and phase < 3500:
        return 22
    if phase >= 3500 and phase < 4000:
        return 23
    return 0
'''

def source_program():
    return substitute(POLICY+'\n'+helpers(['get','put','putn','uint','call','kernel_text','equal'])+literals({'supervise':'supervise','supervise_pty':'supervise-pty'}))

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--check',action='store_true');args=parser.parse_args()
    doc=document(source_program(),'system_jobctl_entry');text=render_assembly(doc);p=ROOT/'examples/hia_bootstrap/system_jobctl_entry.hepta'
    if args.check:assert p.read_text()==text
    else:p.write_text(text)
    print(p.name,len(doc['functions']),sum(len(b['ops']) for f in doc['functions'] for b in f['blocks']),flush=True)
if __name__=='__main__':main()
