"""Exact-body bootstrap hot-function rewrites, with complete old fallbacks.

The SHA fast arm changes only scheduling/compression after each original
message word has been read and stored. It neither prefetches message bytes nor
adds scratch bytes, and therefore keeps cross-view alias behavior. The bound
also excludes writes to the indirection word at workspace offset 40.
"""
import ast,copy,json
from hashlib import sha256
from hepta.hia_agent_assembly import assemble_program,render_assembly
from tools.generate_hia_worker_config_json import ConfigBuilder as Builder
from tools.generate_hia_selfhost import compact_authoring_cfg,total_scalar_functions
from tools.generate_hia_sha256 import INITIAL,ROUND
from tools.generate_hia_core_json_frontend import KEYS

def fingerprint(fn):
 value=copy.deepcopy(fn);value.pop('name',None);value.pop('effects',None)
 return json.dumps(value,sort_keys=True,separators=(',',':'))

def pin(fn):return sha256(fingerprint(fn).encode()).hexdigest()

def compiled(body):
 nodes=ast.parse(body).body
 names={n.name:'f'+str(i) for i,n in enumerate(nodes)}
 signatures={n.name:([a.annotation.id for a in n.args.args],n.returns.id) for n in nodes}
 total=total_scalar_functions(nodes);functions=[]
 for node in nodes:
  b=Builder(node,names,signatures,total);b.statements(node.body)
  functions.append({'name':names[node.name],'params':[b.param(v) for v in b.params],'returns':[b.returns],'effects':['read','write','trap'],'entry':'b0','blocks':b.blocks})
 doc=compact_authoring_cfg({'schema':'hepta.hia.program.v9','module':'seed_front_hot','functions':functions})
 return json.loads(assemble_program(render_assembly(doc)).canonical_bytes)['functions']

def mapped(fn,names):
 f=copy.deepcopy(fn);f['name']=names[f['name']]
 for block in f['blocks']:
  for op in block['ops']:
   if op['op']=='call':op['attrs']['function']=names[op['attrs']['function']]
 return f

def require(doc,pins):
 for index,expected in pins.items():
  actual=pin(doc['functions'][index])
  if actual!=expected:raise ValueError(('unreviewed hot helper',index,actual,expected))

KEY_PINS={21:'9b705477964089eb0b31d135dbc7c2b0be5ce182ad11ab36ff06b94109c764b5',19:'18d6028ce43150767a235b7a79ce5e8d17af9701a948bb483322c7468ae145e7',40:'6619779d137b3fc9272d882de42e90961d7731d861b174a1f2fe18baee78cef2'}
SHA_PINS={5:'d615623890b5f21c7362c0b63e22a7253ad85a8a4bc7c06694f098cee100e9f8',6:'75805a22db202aadf53c2be9beb783e7b5d85272588d361466bb94029c52719a',8:'b4a4846d6b0aeff4e3d6a485d85e81624e2ade37638ff5bc2e735d5c89a80205',9:'0ec841bb955951fe607ad55572b722767012be6d237bbc1c05655dd223dd9909',10:'fcfd91782682235e860aa907f87cc35ec2fea5feb55a6b88487be3a9340f9260',11:'6619779d137b3fc9272d882de42e90961d7731d861b174a1f2fe18baee78cef2',12:'4dbdf08733d5175f0a9b1f47538e7c5cf277196bff1dd303b63b68e65cc8ee3d'}

def key_source():
 lines=['def key_fast(w:mutbuf,node:u64) -> u64:',
 '    start = get(w,64 + node * 56 + 40)',
 '    size = get(w,64 + node * 56 + 48)',
 '    if start <= length(w) and length(w) - start >= 16:',
 '        low = word_load(w,start)',
 '        high = word_load(w,start + 8)']
 for width in sorted({len(k) for k in KEYS}):
  lines.append(f'        if size == {width}:')
  lines.append('            value = '+(f'low & {(1<<(8*width))-1}' if width<8 else 'low'))
  if width>8:lines.append(f'            tail = high & {(1<<(8*(width-8)))-1}')
  for index,key in enumerate(KEYS):
   if len(key)!=width:continue
   a=int.from_bytes(key.encode()[:8],'little');b=int.from_bytes(key.encode()[8:],'little')
   condition=f'value == {a}' if width<=8 else f'value == {a} and tail == {b}'
   lines.extend([f'            if {condition}:',f'                return {1<<index}'])
  lines.append('            return 0')
 lines.extend(['        return 0','    return old_key(w,node)',
 '', 'def get(w:mutbuf,index:u64) -> u64:', '    return 0',
 '', 'def old_key(w:mutbuf,node:u64) -> u64:', '    return 0'])
 return '\n'.join(lines)+'\n'

COMPRESSION_ORIGIN_SHA256='1916d727e235224860a8fc259716bfa9e343f9d243977e49ccaee1699d117bbb'
COMPRESSION_SOURCE='def compress(w: mutbuf, base: u64) -> u64:\n    i = 16\n    while i < 64:\n        schedule_at = 512 + i * 8\n        x = word_load(w, base + (schedule_at - 120))\n        y = word_load(w, base + (schedule_at - 16))\n        cold_x = x * 4294967297\n        cold_y = y * 4294967297\n        sx = cold_x >> 7 ^ cold_x >> 18 ^ x >> 3\n        sy = cold_y >> 17 ^ cold_y >> 19 ^ y >> 10\n        value = word_load(w, base + (schedule_at - 128)) + sx + word_load(w, base + (schedule_at - 56)) + sy & 4294967295\n        word_store(w, base + schedule_at, value)\n        x = word_load(w, base + (schedule_at - 112))\n        y = word_load(w, base + (schedule_at - 8))\n        cold_x = x * 4294967297\n        cold_y = y * 4294967297\n        sx = cold_x >> 7 ^ cold_x >> 18 ^ x >> 3\n        sy = cold_y >> 17 ^ cold_y >> 19 ^ y >> 10\n        value = word_load(w, base + (schedule_at - 120)) + sx + word_load(w, base + (schedule_at - 48)) + sy & 4294967295\n        word_store(w, base + (schedule_at + 8), value)\n        x = word_load(w, base + (schedule_at - 104))\n        y = word_load(w, base + schedule_at)\n        cold_x = x * 4294967297\n        cold_y = y * 4294967297\n        sx = cold_x >> 7 ^ cold_x >> 18 ^ x >> 3\n        sy = cold_y >> 17 ^ cold_y >> 19 ^ y >> 10\n        value = word_load(w, base + (schedule_at - 112)) + sx + word_load(w, base + (schedule_at - 40)) + sy & 4294967295\n        word_store(w, base + (schedule_at + 16), value)\n        x = word_load(w, base + (schedule_at - 96))\n        y = word_load(w, base + (schedule_at + 8))\n        cold_x = x * 4294967297\n        cold_y = y * 4294967297\n        sx = cold_x >> 7 ^ cold_x >> 18 ^ x >> 3\n        sy = cold_y >> 17 ^ cold_y >> 19 ^ y >> 10\n        value = word_load(w, base + (schedule_at - 104)) + sx + word_load(w, base + (schedule_at - 32)) + sy & 4294967295\n        word_store(w, base + (schedule_at + 24), value)\n        i = i + 4\n    a = word_load(w, base + 1024)\n    b = word_load(w, base + 1032)\n    c = word_load(w, base + 1040)\n    d = word_load(w, base + 1048)\n    e = word_load(w, base + 1056)\n    f = word_load(w, base + 1064)\n    g = word_load(w, base + 1072)\n    h = word_load(w, base + 1080)\n    i = 0\n    round_at = i * 8\n    s1 = (e >> 6 | e << 26) ^ (e >> 11 | e << 21) ^ (e >> 25 | e << 7)\n    choose_bits = g ^ e & (f ^ g)\n    t1 = h + s1 + choose_bits + word_load(w, base + round_at) + word_load(w, base + (round_at + 512))\n    s0 = (a >> 2 | a << 30) ^ (a >> 13 | a << 19) ^ (a >> 22 | a << 10)\n    majority = a & b | c & (a | b)\n    t2 = s0 + majority\n    h = g\n    g = f\n    f = e\n    e = d + t1 & 4294967295\n    d = c\n    c = b\n    b = a\n    a = t1 + t2 & 4294967295\n    cold_e = e * 4294967297\n    s1 = cold_e >> 6 ^ cold_e >> 11 ^ cold_e >> 25\n    choose_bits = g ^ e & (f ^ g)\n    t1 = h + s1 + choose_bits + word_load(w, base + (round_at + 8)) + word_load(w, base + (round_at + 520))\n    cold_a = a * 4294967297\n    s0 = cold_a >> 2 ^ cold_a >> 13 ^ cold_a >> 22\n    majority = a & b | c & (a | b)\n    t2 = s0 + majority\n    h = g\n    g = f\n    f = e\n    e = d + t1 & 4294967295\n    d = c\n    c = b\n    b = a\n    a = t1 + t2 & 4294967295\n    cold_e = e * 4294967297\n    s1 = cold_e >> 6 ^ cold_e >> 11 ^ cold_e >> 25\n    choose_bits = g ^ e & (f ^ g)\n    t1 = h + s1 + choose_bits + word_load(w, base + (round_at + 16)) + word_load(w, base + (round_at + 528))\n    cold_a = a * 4294967297\n    s0 = cold_a >> 2 ^ cold_a >> 13 ^ cold_a >> 22\n    majority = a & b | c & (a | b)\n    t2 = s0 + majority\n    h = g\n    g = f\n    f = e\n    e = d + t1 & 4294967295\n    d = c\n    c = b\n    b = a\n    a = t1 + t2 & 4294967295\n    cold_e = e * 4294967297\n    s1 = cold_e >> 6 ^ cold_e >> 11 ^ cold_e >> 25\n    choose_bits = g ^ e & (f ^ g)\n    t1 = h + s1 + choose_bits + word_load(w, base + (round_at + 24)) + word_load(w, base + (round_at + 536))\n    cold_a = a * 4294967297\n    s0 = cold_a >> 2 ^ cold_a >> 13 ^ cold_a >> 22\n    majority = a & b | c & (a | b)\n    t2 = s0 + majority\n    h = g\n    g = f\n    f = e\n    e = d + t1 & 4294967295\n    d = c\n    c = b\n    b = a\n    a = t1 + t2 & 4294967295\n    i = i + 4\n    while i < 64:\n        round_at = i * 8\n        cold_e = e * 4294967297\n        s1 = cold_e >> 6 ^ cold_e >> 11 ^ cold_e >> 25\n        choose_bits = g ^ e & (f ^ g)\n        t1 = h + s1 + choose_bits + word_load(w, base + round_at) + word_load(w, base + (round_at + 512))\n        cold_a = a * 4294967297\n        s0 = cold_a >> 2 ^ cold_a >> 13 ^ cold_a >> 22\n        majority = a & b | c & (a | b)\n        t2 = s0 + majority\n        h = g\n        g = f\n        f = e\n        e = d + t1 & 4294967295\n        d = c\n        c = b\n        b = a\n        a = t1 + t2 & 4294967295\n        cold_e = e * 4294967297\n        s1 = cold_e >> 6 ^ cold_e >> 11 ^ cold_e >> 25\n        choose_bits = g ^ e & (f ^ g)\n        t1 = h + s1 + choose_bits + word_load(w, base + (round_at + 8)) + word_load(w, base + (round_at + 520))\n        cold_a = a * 4294967297\n        s0 = cold_a >> 2 ^ cold_a >> 13 ^ cold_a >> 22\n        majority = a & b | c & (a | b)\n        t2 = s0 + majority\n        h = g\n        g = f\n        f = e\n        e = d + t1 & 4294967295\n        d = c\n        c = b\n        b = a\n        a = t1 + t2 & 4294967295\n        cold_e = e * 4294967297\n        s1 = cold_e >> 6 ^ cold_e >> 11 ^ cold_e >> 25\n        choose_bits = g ^ e & (f ^ g)\n        t1 = h + s1 + choose_bits + word_load(w, base + (round_at + 16)) + word_load(w, base + (round_at + 528))\n        cold_a = a * 4294967297\n        s0 = cold_a >> 2 ^ cold_a >> 13 ^ cold_a >> 22\n        majority = a & b | c & (a | b)\n        t2 = s0 + majority\n        h = g\n        g = f\n        f = e\n        e = d + t1 & 4294967295\n        d = c\n        c = b\n        b = a\n        a = t1 + t2 & 4294967295\n        cold_e = e * 4294967297\n        s1 = cold_e >> 6 ^ cold_e >> 11 ^ cold_e >> 25\n        choose_bits = g ^ e & (f ^ g)\n        t1 = h + s1 + choose_bits + word_load(w, base + (round_at + 24)) + word_load(w, base + (round_at + 536))\n        cold_a = a * 4294967297\n        s0 = cold_a >> 2 ^ cold_a >> 13 ^ cold_a >> 22\n        majority = a & b | c & (a | b)\n        t2 = s0 + majority\n        h = g\n        g = f\n        f = e\n        e = d + t1 & 4294967295\n        d = c\n        c = b\n        b = a\n        a = t1 + t2 & 4294967295\n        i = i + 4\n    word_store(w, base + 1024, word_load(w, base + 1024) + a & 4294967295)\n    word_store(w, base + 1032, word_load(w, base + 1032) + b & 4294967295)\n    word_store(w, base + 1040, word_load(w, base + 1040) + c & 4294967295)\n    word_store(w, base + 1048, word_load(w, base + 1048) + d & 4294967295)\n    word_store(w, base + 1056, word_load(w, base + 1056) + e & 4294967295)\n    word_store(w, base + 1064, word_load(w, base + 1064) + f & 4294967295)\n    word_store(w, base + 1072, word_load(w, base + 1072) + g & 4294967295)\n    word_store(w, base + 1080, word_load(w, base + 1080) + h & 4294967295)\n    return 0\n'

def hash_source():
 s='def hash_fast(s:readbuf,w:mutbuf,size:u64,start:u64) -> u64:\n    if size > 8388608:\n        return 4294967293\n    if length(w) >= 48:\n        base = word_load(w,40)\n        if base >= 48 and base <= length(w) and length(w) - base >= 1120:\n            return hash_body(s,w,size,start,base)\n    return old_hash(s,w,size,start)\n\ndef hash_body(s:readbuf,w:mutbuf,size:u64,start:u64,base:u64) -> u64:\n'
 for i,value in enumerate(ROUND):s+=f'    word_store(w,base + {8*i},{value})\n'
 for i,value in enumerate(INITIAL):s+=f'    word_store(w,base + {1024+8*i},{value})\n'
 s+='    padded = (size + 72) & 18446744073709551552\n    block = 0\n    while block < padded:\n        i = 0\n        while i < 16:\n            value = 0\n            j = 0\n            while j < 4:\n                value = (value << 8) | padded_byte(s,block + i * 4 + j,padded,size,start)\n                j = j + 1\n            word_store(w,base + 512 + i * 8,value)\n            i = i + 1\n        compress(w,base)\n        block = block + 64\n    i = 0\n    while i < 8:\n        value = word_load(w,base + 1024 + i * 8)\n        j = 0\n        while j < 4:\n            store(w,base + 1088 + i * 4 + j,(value >> ((3-j) * 8)) & 255)\n            j = j + 1\n        i = i + 1\n    return 32\n\n'
 return s+COMPRESSION_SOURCE+'\ndef old_hash(s:readbuf,w:mutbuf,size:u64,start:u64) -> u64:\n    return 0\n\ndef padded_byte(s:readbuf,index:u64,total:u64,size:u64,start:u64) -> u64:\n    return 0\n'

def rewrite(doc,rel):
 changes=[]
 if rel=='core_admission.hepta':
  require(doc,KEY_PINS);old=copy.deepcopy(doc['functions'][21]);oldname='f'+str(len(doc['functions']));old['name']=oldname
  functions=compiled(key_source());assert len(functions)==3
  new=mapped(functions[0],{'f0':'f21','f1':'f40','f2':oldname});doc['functions'][21]=new;doc['functions'].append(old)
  changes.append({'function':'f21','transformation':'length_grouped_exact_key_words_with_original_fallback','original_sha256':KEY_PINS[21],'replacement_sha256':pin(new),'fallback_function':oldname})
 if rel=='core_cli/assembly_diagnostic_report.hepta':
  require(doc,SHA_PINS);old=copy.deepcopy(doc['functions'][8]);n=len(doc['functions']);names={'f0':'f8','f1':'f'+str(n),'f2':'f'+str(n+1),'f3':'f'+str(n+2),'f4':'f9'}
  functions=compiled(hash_source());assert len(functions)==5
  new=mapped(functions[0],names);old['name']=names['f3'];doc['functions'][8]=new
  doc['functions'] += [mapped(functions[1],names),mapped(functions[2],names),old]
  changes.append({'function':'f8','transformation':'guarded_sha_schedule_rounds_same_message_order_and_workspace','original_sha256':SHA_PINS[8],'replacement_sha256':pin(new),'fallback_function':old['name'],'added_function_sha256':[pin(f) for f in doc['functions'][-3:]],'compression_origin_sha256':COMPRESSION_ORIGIN_SHA256})
 return changes
