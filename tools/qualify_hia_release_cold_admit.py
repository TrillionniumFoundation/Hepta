"""External fixtures for native cold admission; synthetic PASS is not cold qualification."""
from pathlib import Path
from hashlib import sha256
import os,sys,copy,json,struct,subprocess,time,traceback

import argparse
ROOT=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description='Compare the native cold admission ELF with the original full contract gate.')
parser.add_argument('--image',type=Path,required=True)
parser.add_argument('--compiler',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--contract-root',type=Path,default=ROOT)
parser.add_argument('--case',action='append')
parser.add_argument('--trace',action='store_true')
args=parser.parse_args()
F=args.contract_root.resolve();D=args.output.resolve();D.mkdir(mode=0o700)
sys.path.insert(0,str(F))

from tools.hia_selfhost_contract import support_contract,CONTRACT_PATH,PROFILE
import tools.build_hia_json_preflight as reference
image=args.image.resolve()
compiler=args.compiler.read_bytes();compiler_pin=sha256(compiler).digest()
expected_contract=support_contract(F);files=expected_contract['source_identity']['files']
check_names=['export_manifest_matches_qualification','isolated_python_without_site','nested_full_qualification_pass','nested_process_exit_zero','no_ancestor_git_identity','no_bytecode_cache_created','no_inherited_home_or_python_cache','no_inherited_seed_or_successor_images','origin_hashes_preserved','owned_process_tree_cleanup_confirmed','source_export_hashes_preserved']
cases=[]
def encode(value):return (json.dumps(value,sort_keys=True,indent=2,ensure_ascii=False)+'\n').encode()
def frame(inv):
 rows=sorted(inv.items());return struct.pack('<8sQ',b'HIASPI01',len(rows))+b''.join(struct.pack('<Q',len(n.encode()))+bytes.fromhex(pin)+n.encode() for n,pin in rows)
def add(name,edit=None,contract_edit=None,inventory_edit=None,cold_text=None,contract_text=None,wire_edit=None,mirror=False):
 c=copy.deepcopy(expected_contract)
 if contract_edit:contract_edit(c)
 cr=encode(c)
 if contract_text:cr=contract_text(cr,c)
 inv=dict(c['source_identity']['files'] if mirror else files);inv[CONTRACT_PATH]=sha256(cr).hexdigest()
 q={'schema':'hepta.hia.selfhost-cold-replay.v1','profile':PROFILE,'status':'COLD_SELFHOST_REPLAY_PASS','returncode':0,'checks':{k:True for k in check_names},'generation_sha256':[compiler_pin.hex()]*3,'source_manifest':dict(inv)}
 if edit:edit(q)
 qr=encode(q)
 if cold_text:qr=cold_text(qr,q)
 if inventory_edit:inventory_edit(inv)
 ir=frame(inv)
 wire=struct.pack('<8sQQQ',b'HIACLD01',len(qr),len(ir),len(cr))+compiler_pin+qr+ir+cr
 if wire_edit:wire=wire_edit(wire)
 ok=True
 try:
  declared=json.loads(cr)
  if declared!=expected_contract:raise ValueError('full support contract mismatch')
  expected={**files,CONTRACT_PATH:sha256(cr).hexdigest()}
  if inv!=expected:raise ValueError('inventory mismatch')
  saved=reference.current_sources
  reference.current_sources=lambda:expected
  try:reference.admit_cold_build(compiler,qr)
  finally:reference.current_sources=saved
  if wire_edit:ok=False
 except (ValueError,TypeError,KeyError):ok=False
 cases.append((name,wire,ok))
add('valid-current-snapshot')
def reverse(value):
 if isinstance(value,dict):return {k:reverse(value[k]) for k in reversed(list(value))}
 if isinstance(value,list):return [reverse(x) for x in value]
 return value
add('valid-reordered',cold_text=lambda raw,q:json.dumps(reverse(q),ensure_ascii=False,separators=(',',':')).encode(),contract_text=lambda raw,c:json.dumps(reverse(c),ensure_ascii=False,separators=(',',':')).encode())
add('valid-escaped-keys',cold_text=lambda raw,q:raw.replace(b'"schema"',b'"\\u0073chema"'),contract_text=lambda raw,c:raw.replace(b'"source_identity"',b'"source_\\u0069dentity"'))
add('valid-ascii-escapes',contract_text=lambda raw,c:json.dumps(c,ensure_ascii=True,sort_keys=True,separators=(',',':')).encode())
add('valid-last-duplicate',cold_text=lambda raw,q:b'{"returncode": false, '+raw.strip()[1:])
add('valid-extra-observations',edit=lambda q:q.update(extra={'float':1.25e-10,'unicode':'中文','nested':[None,True,False,-17,{'x':'\\\n"'}]}))
add('returncode-bool',edit=lambda q:q.update(returncode=False))
add('returncode-float',edit=lambda q:q.update(returncode=0.0))
add('returncode-nonzero',edit=lambda q:q.update(returncode=1))
add('wrong-schema',edit=lambda q:q.update(schema='wrong'))
add('wrong-profile',edit=lambda q:q.update(profile='wrong'))
add('wrong-status',edit=lambda q:q.update(status='INCOMPLETE'))
add('missing-check',edit=lambda q:q['checks'].pop(check_names[0]))
add('extra-check',edit=lambda q:q['checks'].update(extra=True))
add('false-check',edit=lambda q:q['checks'].update({check_names[0]:False}))
add('integer-check',edit=lambda q:q['checks'].update({check_names[0]:1}))
add('two-generations',edit=lambda q:q.update(generation_sha256=[compiler_pin.hex()]*2))
add('four-generations',edit=lambda q:q.update(generation_sha256=[compiler_pin.hex()]*4))
add('wrong-generation',edit=lambda q:q['generation_sha256'].__setitem__(1,'0'*64))
add('missing-manifest-source',edit=lambda q:q['source_manifest'].pop(next(iter(files))))
add('extra-manifest-source',edit=lambda q:q['source_manifest'].update(unrelated='0'*64))
add('wrong-manifest-pin',edit=lambda q:q['source_manifest'].__setitem__(next(iter(files)),'0'*64))
add('missing-inventory-source',inventory_edit=lambda inv:inv.pop(next(iter(files))))
add('extra-inventory-source',inventory_edit=lambda inv:inv.update(unrelated='0'*64))
add('wrong-inventory-pin',inventory_edit=lambda inv:inv.__setitem__(next(iter(files)),'0'*64))
add('wrong-contract-metadata',contract_edit=lambda c:c['claims'].__setitem__('whole_HIA_language_self_hosted',not c['claims']['whole_HIA_language_self_hosted']))
add('extra-contract-metadata',contract_edit=lambda c:c.update(unrelated='not part of supported contract'))
add('wrong-contract-source',contract_edit=lambda c:c['source_identity']['files'].__setitem__(next(iter(files)),'0'*64))
add('coherently-truncated-path-set',contract_edit=lambda c:c['source_identity']['files'].pop(next(iter(files))),mirror=True)
add('contract-source-extra',contract_edit=lambda c:c['source_identity']['files'].update(unrelated='0'*64),mirror=True)
add('wrong-magic',wire_edit=lambda raw:b'BADCLD01'+raw[8:])
add('wrong-compiler-pin',wire_edit=lambda raw:raw[:32]+bytes(32)+raw[64:])
add('truncated-frame',wire_edit=lambda raw:raw[:-1])
add('trailing-frame',wire_edit=lambda raw:raw+b'x')
add('invalid-cold-json',cold_text=lambda raw,q:raw+b'null')
add('cold-root-array',cold_text=lambda raw,q:b'[]')

def float_integral_values(value):
 if isinstance(value,bool):return float(value)
 if isinstance(value,int) and abs(value)<=2**53:return float(value)
 if isinstance(value,dict):return {k:float_integral_values(v) for k,v in value.items()}
 if isinstance(value,list):return [float_integral_values(v) for v in value]
 return value
def integer_booleans(value):
 if isinstance(value,bool):return int(value)
 if isinstance(value,dict):return {k:integer_booleans(v) for k,v in value.items()}
 if isinstance(value,list):return [integer_booleans(v) for v in value]
 return value
add('valid-contract-bool-numeric-equality',contract_text=lambda raw,c:encode(integer_booleans(c)))
add('valid-contract-float-integral-equality',contract_text=lambda raw,c:encode(float_integral_values(c)))
add('valid-contract-scientific-integer',contract_text=lambda raw,c:raw.replace(b'"invalid_source": 4294967295',b'"invalid_source": 4.294967295e9'))
add('valid-contract-float-rounds-to-one',contract_text=lambda raw,c:raw.replace(b'"discarded_nonzero_sticky_bit": true',b'"discarded_nonzero_sticky_bit": 1.0000000000000001'))
add('valid-contract-negative-zero',contract_text=lambda raw,c:raw.replace(b'"whole_HIA_language_self_hosted": false',b'"whole_HIA_language_self_hosted": -0.0'))
add('valid-contract-tiny-underflow-zero',contract_text=lambda raw,c:raw.replace(b'"whole_HIA_language_self_hosted": false',b'"whole_HIA_language_self_hosted": 1e-99999'))
add('valid-extra-nonfinite-observations',edit=lambda q:q.update(extra=[float('nan'),float('inf'),float('-inf')]))
add('invalid-contract-nonintegral',contract_text=lambda raw,c:raw.replace(b'"discarded_nonzero_sticky_bit": true',b'"discarded_nonzero_sticky_bit": 1.01'))
add('invalid-contract-large-rounded-integer',contract_text=lambda raw,c:raw.replace(b'9223372036854775807',b'9.223372036854776e18'))
add('invalid-contract-nonfinite',contract_text=lambda raw,c:raw.replace(b'"discarded_nonzero_sticky_bit": true',b'"discarded_nonzero_sticky_bit": NaN'))
add('invalid-contract-float-overflow',contract_text=lambda raw,c:raw.replace(b'"discarded_nonzero_sticky_bit": true',b'"discarded_nonzero_sticky_bit": 1e99999'))
add('invalid-contract-tiny-nonzero',contract_text=lambda raw,c:raw.replace(b'"whole_HIA_language_self_hosted": false',b'"whole_HIA_language_self_hosted": 1e-100'))

if args.case:
 selected=set(args.case)
 if not selected.issubset({row[0] for row in cases}):raise SystemExit('unknown case name')
 cases=[row for row in cases if row[0] in selected]
results=[]
record={'scope':'component semantics and real native execution; successful report is a synthetic field fixture, not a completed cold qualification','image':str(image),'image_sha256':sha256(image.read_bytes()).hexdigest(),'compiler_sha256':compiler_pin.hex(),'source_count':len(files)+1,'cases':results}
def save():(D/'results.json').write_text(json.dumps(record,indent=2)+'\n')
save()
for index,(name,wire,expected) in enumerate(cases):
 case=D/name;case.mkdir(mode=0o700)
 started=time.monotonic()
 command=[str(image),'build']
 if index==0 and args.trace:command=['/usr/bin/strace','-f','-qq','-o',str(case/'trace.log'),'-e','trace=process',*command]
 r=subprocess.run(command,input=wire,capture_output=True,env={'PATH':''},timeout=30)
 actual=r.returncode==0 and r.stdout==b'HIAADC01'+compiler_pin+struct.pack('<Q',len(files)+1) and r.stderr==b''
 passed=actual==expected and (expected or (r.returncode!=0 and r.stdout==b''))
 item={'case':name,'expected':expected,'passed':passed,'rc':r.returncode,'stdout_hex':r.stdout.hex(),'stderr':r.stderr.decode(errors='replace'),'seconds':time.monotonic()-started,'request_sha256':sha256(wire).hexdigest()};results.append(item);save()
 print(json.dumps(item),flush=True)
 if not passed:
  (case/'request.bin').write_bytes(wire);(D/'run.rc').write_text('1\n');raise AssertionError(item)
record['passed']=True;record['case_count']=len(cases);save();(D/'run.rc').write_text('0\n')
print('COLD_ADMISSION_CASES_PASSED',len(cases),flush=True)

