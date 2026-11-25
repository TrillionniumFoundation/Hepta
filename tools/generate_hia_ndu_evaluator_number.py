"""HIA default-serde binary64 parser and zmij-compatible shortest presentation.

The pinned bridge uses serde_json 1.0.154 without float_roundtrip.  Its u64
significand truncation, separately rounded cast and IEEE multiply/divide are
therefore reproduced explicitly, using only integer/rational HIA arithmetic.
"""
from pathlib import Path
import ast,struct
from tools.generate_hia_ndu_evaluator import document
from tools.generate_hia_agent_binary64 import SOURCE as DECIMAL
from tools.generate_hia_agent_binary64_format import FORMAT
from hepta.hia_agent_assembly import render_assembly

ROOT=Path(__file__).resolve().parents[1]
ENTRY=r'''
def ndu_number(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) == 0 or length(s) > 1048576 or length(o) < 96 or length(w) < 16384:
        return 4294967293
    put(o, 0, 2)
    put(o, 8, 0)
    put(o, 16, 0)
    put(o, 24, 0)
    status = read_parts(s, w)
    put(o, 8, get(w, 8192))
    if status != 0:
        put(o, 0, status)
        return 32
    set64(w, 0, get(w, 8208))
    set64(w, 1040, 1)
    value = round_ratio(w)
    power = get(w, 8216)
    going = True
    while going:
        if power >= 4294967296:
            exponent = power - 4294967296
            if exponent > 308:
                if value != 0:
                    put(o, 0, 1)
                    return 32
            else:
                value = float_binary(w, value, pow10(exponent), 0)
            going = False
        else:
            exponent = 4294967296 - power
            if exponent <= 308:
                value = float_binary(w, value, pow10(exponent), 1)
                going = False
            else:
                if value == 0:
                    going = False
                else:
                    value = float_binary(w, value, pow10(308), 1)
                    power = power + 308
    if value >= 9218868437227405312:
        put(o, 0, 1)
        return 32
    value = value | get(w, 8200)
    put(o, 16, value)
    size = render_number(w, value)
    if size > 64:
        return 4294967293
    put(o, 0, 0)
    put(o, 24, size)
    i = 0
    while i < size:
        store(o, 32 + i, byte(w, 6144 + i))
        i = i + 1
    return 32 + size

def read_parts(s:readbuf, w:mutbuf) -> u64:
    n = length(s)
    i = 0
    sign = 0
    if byte(s, 0) == 45:
        sign = 9223372036854775808
        i = 1
    put(w, 8200, sign)
    put(w, 8192, i)
    if i >= n:
        return 2
    ch = byte(s, i)
    if ch < 48 or ch > 57:
        return 2
    sig = ch - 48
    first = ch
    i = i + 1
    excess = 0
    full = False
    going = True
    while going and i < n:
        ch = byte(s, i)
        if ch >= 48 and ch <= 57:
            if first == 48:
                put(w, 8192, i + 1)
                return 2
            digit = ch - 48
            if full or sig > 1844674407370955161 or (sig == 1844674407370955161 and digit > 5):
                full = True
                excess = excess + 1
            else:
                sig = sig * 10 + digit
            i = i + 1
        else:
            going = False
    power = 4294967296 + excess
    if i < n and byte(s, i) == 46:
        i = i + 1
        start = i
        full = False
        going = True
        while going and i < n:
            ch = byte(s, i)
            if ch >= 48 and ch <= 57:
                digit = ch - 48
                if sig > 1844674407370955161 or (sig == 1844674407370955161 and digit > 5):
                    full = True
                if full == False:
                    sig = sig * 10 + digit
                    power = power - 1
                i = i + 1
            else:
                going = False
        if i == start:
            put(w, 8192, i)
            return 2
    if i < n and (byte(s, i) == 69 or byte(s, i) == 101):
        i = i + 1
        negative = False
        if i < n and (byte(s, i) == 43 or byte(s, i) == 45):
            negative = byte(s, i) == 45
            i = i + 1
        start = i
        value = 0
        overflow = False
        going = True
        while going and i < n:
            ch = byte(s, i)
            if ch >= 48 and ch <= 57:
                digit = ch - 48
                if overflow == False:
                    if value > 214748364 or (value == 214748364 and digit > 7):
                        overflow = True
                        if sig != 0 and negative == False:
                            put(w, 8192, i + 1)
                            return 1
                    else:
                        value = value * 10 + digit
                i = i + 1
            else:
                going = False
        if i == start:
            put(w, 8192, i)
            return 2
        if overflow:
            sig = 0
            power = 4294967296
        else:
            if negative:
                power = power - value
                if power < 2147483648:
                    power = 2147483648
            else:
                power = power + value
                if power > 6442450943:
                    power = 6442450943
    put(w, 8192, i)
    if i != n:
        return 2
    put(w, 8208, sig)
    put(w, 8216, power)
    return 0

def float_binary(w:mutbuf, a:u64, b:u64, divide:u64) -> u64:
    ma = a & 4503599627370495
    mb = b & 4503599627370495
    ea = a >> 52
    eb = b >> 52
    if ea != 0:
        ma = ma | 4503599627370496
    else:
        ea = 1
    if eb != 0:
        mb = mb | 4503599627370496
    else:
        eb = 1
    if ma == 0:
        return 0
    set64(w, 0, ma)
    if divide == 1:
        set64(w, 1040, mb)
        power = 4096 + ea - eb
    else:
        multiply(w, 0, mb & 4294967295, 0)
        set64(w, 2080, ma)
        multiply(w, 2080, mb >> 32, 0)
        shift(w, 2080, 32)
        add_big(w, 0, 2080)
        set64(w, 1040, 1)
        power = 1946 + ea + eb
    if power >= 4096:
        shift(w, 0, power - 4096)
    else:
        shift(w, 1040, 4096 - power)
    return round_ratio(w)

def get(w:mutbuf, at:u64) -> u64:
    return word_load(w, at)

def put(w:mutbuf, at:u64, value:u64) -> u64:
    word_store(w, at, value)
    return value
'''
def ratio():
    part=DECIMAL[DECIMAL.index('    # Exponents have'):DECIMAL.index('\n    put(o, 0, result | sign)')]
    part=part.replace('return 4294967292','return 9218868437227405312')
    part=part.replace(' or get(w, 3136) != 0','')
    return 'def round_ratio(w:mutbuf) -> u64:\n    if get(w, 0) == 1 and get(w, 8) == 0:\n        return 0\n'+part+'\n    return result\n'
def formatter():
    t=FORMAT.replace('def render_binary64(s:readbuf, o:mutbuf, w:mutbuf) -> u32:',
                     'def render_number(w:mutbuf, original:u64) -> u64:')
    t=t.replace('    if length(s) != 8:\n        return 4294967295\n','')
    t=t.replace('    original = read64(s, 0)\n','')
    a=t.index('    if length(o) < cursor:');b=t.index('    return cursor',a)
    t=t[:a]+t[b:]
    t=t.replace('order < 2044 or order >= 2064','order < 2043 or order >= 2064')
    t=t.replace('            cursor = emit(w, cursor, tens + 48)',
                '            if hundreds != 0 or tens != 0:\n                cursor = emit(w, cursor, tens + 48)')
    t=t[:t.index('\ndef read64')]
    return t
def powers():
    out=[]
    for group in range(10):
        lines=[f'def pow10_{group}(value:u64) -> u64:']
        for n in range(group*32,min(309,(group+1)*32)):
            bits=struct.unpack('<Q',struct.pack('<d',float('1e'+str(n))))[0]
            lines += [f'    if value == {n}:',f'        return {bits}']
        lines+=['    return 0'];out.append('\n'.join(lines))
    lines=['def pow10(value:u64) -> u64:']
    for group in range(10):
        lines+=[f'    if value < {(group+1)*32}:',f'        return pow10_{group}(value)']
    lines+=['    return 0']
    return '\n\n'.join(['\n'.join(lines),*out])
def program():
    names={'multiply','bits','copy_big','normalize','shift','compare_big','subtract'}
    helpers=[ast.get_source_segment(DECIMAL,n) for n in ast.parse(DECIMAL).body if n.name in names]
    return '\n\n'.join([ENTRY,ratio(),formatter(),*helpers,powers()])
def render():
    return render_assembly(document(program(),'ndu_evaluator_number'))
if __name__=='__main__':
    p=ROOT/'examples/hia_bootstrap/ndu_evaluator_number.hepta';p.write_text(render())
    print(p.name,p.stat().st_size)
