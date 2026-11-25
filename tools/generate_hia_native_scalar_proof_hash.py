"""Private nonalias SHA-256 for the native scalar proof closure.

The only caller is the fixed proof policy/transport. Its input, 32-byte output
and 1184-byte work spans are pairwise disjoint; this does not replace the old
public one-shot SHA ABI or change its alias/short-work behavior.
Compression is copied verbatim from the fully qualified cold SHA HIA source.
"""
from pathlib import Path
import ast
from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_cold_sha256_stream import Builder as WordBuilder
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from tools.generate_hia_sha256 import INITIAL,ROUND

class Builder(WordBuilder):
    def expr(self,node):
        if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id=='word_load_be':
            args=[self.expr(v) for v in node.args]
            return self.op('buffer.load.u64.be',[args[0],self.cast(args[1],'usize')],'u64')
        return super().expr(node)

COMPRESSION_SOURCE='def compress(w: mutbuf) -> u64:\n    i = 0\n    while i < 16:\n        source_at = 1112 + i * 4\n        schedule_at = 512 + i * 8\n        cold_input_word = word_load_be(w, source_at)\n        word_store(w, schedule_at, cold_input_word >> 32)\n        word_store(w, schedule_at + 8, cold_input_word & 4294967295)\n        cold_input_word = word_load_be(w, source_at + 8)\n        word_store(w, schedule_at + 16, cold_input_word >> 32)\n        word_store(w, schedule_at + 24, cold_input_word & 4294967295)\n        i = i + 4\n    while i < 64:\n        schedule_at = 512 + i * 8\n        x = word_load(w, schedule_at - 120)\n        y = word_load(w, schedule_at - 16)\n        cold_x = x * 4294967297\n        cold_y = y * 4294967297\n        sx = cold_x >> 7 ^ cold_x >> 18 ^ x >> 3\n        sy = cold_y >> 17 ^ cold_y >> 19 ^ y >> 10\n        value = word_load(w, schedule_at - 128) + sx + word_load(w, schedule_at - 56) + sy & 4294967295\n        word_store(w, schedule_at, value)\n        x = word_load(w, schedule_at - 112)\n        y = word_load(w, schedule_at - 8)\n        cold_x = x * 4294967297\n        cold_y = y * 4294967297\n        sx = cold_x >> 7 ^ cold_x >> 18 ^ x >> 3\n        sy = cold_y >> 17 ^ cold_y >> 19 ^ y >> 10\n        value = word_load(w, schedule_at - 120) + sx + word_load(w, schedule_at - 48) + sy & 4294967295\n        word_store(w, schedule_at + 8, value)\n        x = word_load(w, schedule_at - 104)\n        y = word_load(w, schedule_at)\n        cold_x = x * 4294967297\n        cold_y = y * 4294967297\n        sx = cold_x >> 7 ^ cold_x >> 18 ^ x >> 3\n        sy = cold_y >> 17 ^ cold_y >> 19 ^ y >> 10\n        value = word_load(w, schedule_at - 112) + sx + word_load(w, schedule_at - 40) + sy & 4294967295\n        word_store(w, schedule_at + 16, value)\n        x = word_load(w, schedule_at - 96)\n        y = word_load(w, schedule_at + 8)\n        cold_x = x * 4294967297\n        cold_y = y * 4294967297\n        sx = cold_x >> 7 ^ cold_x >> 18 ^ x >> 3\n        sy = cold_y >> 17 ^ cold_y >> 19 ^ y >> 10\n        value = word_load(w, schedule_at - 104) + sx + word_load(w, schedule_at - 32) + sy & 4294967295\n        word_store(w, schedule_at + 24, value)\n        i = i + 4\n    a = word_load(w, 1024)\n    b = word_load(w, 1032)\n    c = word_load(w, 1040)\n    d = word_load(w, 1048)\n    e = word_load(w, 1056)\n    f = word_load(w, 1064)\n    g = word_load(w, 1072)\n    h = word_load(w, 1080)\n    i = 0\n    round_at = i * 8\n    s1 = (e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25 | e << 7)\n    choose_bits = g ^ e & (f ^ g)\n    t1 = h + s1 + choose_bits + word_load(w, round_at) + word_load(w, round_at + 512)\n    s0 = (a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22 | a << 10)\n    majority = a & b | c & (a | b)\n    t2 = s0 + majority\n    h = g\n    g = f\n    f = e\n    e = d + t1 & 4294967295\n    d = c\n    c = b\n    b = a\n    a = t1 + t2 & 4294967295\n    cold_e = e * 4294967297\n    s1 = cold_e >> 6 ^ cold_e >> 11 ^ cold_e >> 25\n    choose_bits = g ^ e & (f ^ g)\n    t1 = h + s1 + choose_bits + word_load(w, round_at + 8) + word_load(w, round_at + 520)\n    cold_a = a * 4294967297\n    s0 = cold_a >> 2 ^ cold_a >> 13 ^ cold_a >> 22\n    majority = a & b | c & (a | b)\n    t2 = s0 + majority\n    h = g\n    g = f\n    f = e\n    e = d + t1 & 4294967295\n    d = c\n    c = b\n    b = a\n    a = t1 + t2 & 4294967295\n    cold_e = e * 4294967297\n    s1 = cold_e >> 6 ^ cold_e >> 11 ^ cold_e >> 25\n    choose_bits = g ^ e & (f ^ g)\n    t1 = h + s1 + choose_bits + word_load(w, round_at + 16) + word_load(w, round_at + 528)\n    cold_a = a * 4294967297\n    s0 = cold_a >> 2 ^ cold_a >> 13 ^ cold_a >> 22\n    majority = a & b | c & (a | b)\n    t2 = s0 + majority\n    h = g\n    g = f\n    f = e\n    e = d + t1 & 4294967295\n    d = c\n    c = b\n    b = a\n    a = t1 + t2 & 4294967295\n    cold_e = e * 4294967297\n    s1 = cold_e >> 6 ^ cold_e >> 11 ^ cold_e >> 25\n    choose_bits = g ^ e & (f ^ g)\n    t1 = h + s1 + choose_bits + word_load(w, round_at + 24) + word_load(w, round_at + 536)\n    cold_a = a * 4294967297\n    s0 = cold_a >> 2 ^ cold_a >> 13 ^ cold_a >> 22\n    majority = a & b | c & (a | b)\n    t2 = s0 + majority\n    h = g\n    g = f\n    f = e\n    e = d + t1 & 4294967295\n    d = c\n    c = b\n    b = a\n    a = t1 + t2 & 4294967295\n    i = i + 4\n    while i < 64:\n        round_at = i * 8\n        cold_e = e * 4294967297\n        s1 = cold_e >> 6 ^ cold_e >> 11 ^ cold_e >> 25\n        choose_bits = g ^ e & (f ^ g)\n        t1 = h + s1 + choose_bits + word_load(w, round_at) + word_load(w, round_at + 512)\n        cold_a = a * 4294967297\n        s0 = cold_a >> 2 ^ cold_a >> 13 ^ cold_a >> 22\n        majority = a & b | c & (a | b)\n        t2 = s0 + majority\n        h = g\n        g = f\n        f = e\n        e = d + t1 & 4294967295\n        d = c\n        c = b\n        b = a\n        a = t1 + t2 & 4294967295\n        cold_e = e * 4294967297\n        s1 = cold_e >> 6 ^ cold_e >> 11 ^ cold_e >> 25\n        choose_bits = g ^ e & (f ^ g)\n        t1 = h + s1 + choose_bits + word_load(w, round_at + 8) + word_load(w, round_at + 520)\n        cold_a = a * 4294967297\n        s0 = cold_a >> 2 ^ cold_a >> 13 ^ cold_a >> 22\n        majority = a & b | c & (a | b)\n        t2 = s0 + majority\n        h = g\n        g = f\n        f = e\n        e = d + t1 & 4294967295\n        d = c\n        c = b\n        b = a\n        a = t1 + t2 & 4294967295\n        cold_e = e * 4294967297\n        s1 = cold_e >> 6 ^ cold_e >> 11 ^ cold_e >> 25\n        choose_bits = g ^ e & (f ^ g)\n        t1 = h + s1 + choose_bits + word_load(w, round_at + 16) + word_load(w, round_at + 528)\n        cold_a = a * 4294967297\n        s0 = cold_a >> 2 ^ cold_a >> 13 ^ cold_a >> 22\n        majority = a & b | c & (a | b)\n        t2 = s0 + majority\n        h = g\n        g = f\n        f = e\n        e = d + t1 & 4294967295\n        d = c\n        c = b\n        b = a\n        a = t1 + t2 & 4294967295\n        cold_e = e * 4294967297\n        s1 = cold_e >> 6 ^ cold_e >> 11 ^ cold_e >> 25\n        choose_bits = g ^ e & (f ^ g)\n        t1 = h + s1 + choose_bits + word_load(w, round_at + 24) + word_load(w, round_at + 536)\n        cold_a = a * 4294967297\n        s0 = cold_a >> 2 ^ cold_a >> 13 ^ cold_a >> 22\n        majority = a & b | c & (a | b)\n        t2 = s0 + majority\n        h = g\n        g = f\n        f = e\n        e = d + t1 & 4294967295\n        d = c\n        c = b\n        b = a\n        a = t1 + t2 & 4294967295\n        i = i + 4\n    word_store(w, 1024, word_load(w, 1024) + a & 4294967295)\n    word_store(w, 1032, word_load(w, 1032) + b & 4294967295)\n    word_store(w, 1040, word_load(w, 1040) + c & 4294967295)\n    word_store(w, 1048, word_load(w, 1048) + d & 4294967295)\n    word_store(w, 1056, word_load(w, 1056) + e & 4294967295)\n    word_store(w, 1064, word_load(w, 1064) + f & 4294967295)\n    word_store(w, 1072, word_load(w, 1072) + g & 4294967295)\n    word_store(w, 1080, word_load(w, 1080) + h & 4294967295)\n    return 0\n\ndef get(w: mutbuf, index: u64) -> u64:\n    return word_load(w, index)\n\ndef put(w: mutbuf, index: u64, value: u64) -> u64:\n    if index <= length(w) and length(w) - index >= 8:\n        word_store(w, index, value)\n        return 0\n    store(w, index + 0, value >> 0 & 255)\n    store(w, index + 1, value >> 8 & 255)\n    store(w, index + 2, value >> 16 & 255)\n    store(w, index + 3, value >> 24 & 255)\n    store(w, index + 4, value >> 32 & 255)\n    store(w, index + 5, value >> 40 & 255)\n    store(w, index + 6, value >> 48 & 255)\n    store(w, index + 7, value >> 56 & 255)\n    return 0\n'
COMPRESSION_ORIGIN={'source': '/home/qian-qi/.local/state/hia-azi5-b843-qa/slot-strict-lifetime-20261124/cold-sha-repeat-source/examples/hia_bootstrap/cold_sha256_nonalias.hepta', 'source_sha256': '49febd0f0535a1bf0a3c17e7356ebe80c00b7e95bbbb2bef800f30c888cccee6', 'author_sha256': 'ce4ef1bdd8f85fca17e9056dc67909799c9798b01b38db1e2e6032415d690cc8', 'lifted_compression_sha256': '1916d727e235224860a8fc259716bfa9e343f9d243977e49ccaee1699d117bbb'}

def source_program():
    s='def native_scalar_proof_hash(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n'
    s+='    if length(s) > 8388608 or length(o) < 32 or length(w) < 1184:\n        return 4294967293\n'
    for i,value in enumerate(ROUND):s+=f'    word_store(w, {8*i}, {value})\n'
    for i,value in enumerate(INITIAL):s+=f'    word_store(w, {1024+8*i}, {value})\n'
    s+='''    padded = (length(s) + 72) & 18446744073709551552
    block = 0
    while block < padded:
        if block <= length(s) and length(s) - block >= 64:
'''
    for i in range(8):
        s+=f'            word_store(w, {1112+8*i}, word_load(s, block + {8*i}))\n'
    s+='''        else:
            i = 0
            while i < 64:
                store(w, 1112 + i, padded_byte(s, block + i, padded))
                i = i + 1
        compress(w)
        block = block + 64
    i = 0
    while i < 8:
        value = word_load(w, 1024 + 8 * i)
        j = 0
        while j < 4:
            store(o, 4 * i + j, (value >> (24 - 8 * j)) & 255)
            j = j + 1
        i = i + 1
    return 32

def padded_byte(s:readbuf, index:u64, total:u64) -> u64:
    if index < length(s):
        return byte(s, index)
    if index == length(s):
        return 128
    if index < total - 8:
        return 0
    return ((length(s) << 3) >> ((total - 1 - index) * 8)) & 255
'''
    return s+'\n'+COMPRESSION_SOURCE

def program():
    nodes=ast.parse(source_program()).body
    retained={'native_scalar_proof_hash'}
    while True:
        called={x.func.id for n in nodes if n.name in retained for x in ast.walk(n) if isinstance(x,ast.Call) and isinstance(x.func,ast.Name)}
        if called<=retained:break
        retained.update(called)
    nodes=[n for n in nodes if n.name in retained]
    names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
    signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
    total=total_scalar_functions(nodes);functions=[]
    for node in nodes:
        b=Builder(node,names,signatures,total);b.statements(node.body)
        functions.append({'name':names[node.name],'params':[b.param(v) for v in b.params],'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
    return compact_authoring_cfg({'schema':'hepta.hia.program.v9','module':'native_scalar_proof_hash','functions':functions})

if __name__=='__main__':
    (Path(__file__).resolve().parents[1]/'examples/hia_bootstrap/native_scalar_proof_hash.hepta').write_text(render_assembly(program()))
