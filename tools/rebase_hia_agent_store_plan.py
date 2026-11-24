"""Regenerate pinned Agent Store images through admitted native HIA compilers.

This developer migration command writes a separate candidate directory. It
first reproduces every previous raw image and every previous filtered image.
Observed native function records map the existing leaf patches to the new
compiler; the replacement bytes and the source programs remain unchanged.
The native word filter validates its complete input frame SHA, then native
bundle and root packers build every resulting image. The ordinary release
continues to require the checked-in exact pins and never invokes this tool.
Use the same compiler for both arguments with --check for a current-plan
reproducibility check. This tool never overwrites the checked-in contract.
"""
from pathlib import Path
from hashlib import sha256
import argparse,copy,ctypes,json,re,struct,subprocess,sys,traceback
F=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--previous-compiler',required=True,type=Path)
parser.add_argument('--compiler',required=True,type=Path)
parser.add_argument('--output',required=True,type=Path)
parser.add_argument('--check',action='store_true',help='require exact regeneration of the checked-in plan, filter, packer and adapter')
args=parser.parse_args();D=args.output;D.mkdir(mode=0o700)
sys.path.insert(0,str(F))
from tools.qualify_hia_selfhost import compile_stage
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.build_hia_agent_batch_commit import verify_placement,assemble_adapter
from tools.generate_hia_native_filter import read_adapter_binding,bind_adapter,elf_header,assemble_program
from hepta.hia_agent_assembly import render_assembly
oldcompiler=args.previous_compiler;compiler=args.compiler
root=F/'examples/hia_bootstrap/agent_store';original=json.loads((root/'build-plan.json').read_text());plan=copy.deepcopy(original);filter_source=(root/'word_filter.hepta').read_text()
source_paths=[Path(__file__).resolve(),root/'build-plan.json',root/'word_filter.hepta',root/'bundle_packer.hepta',root/'packer.hepta',F/'tools/hia_agent_store_syscalls.S',*[root/v['source'] for v in original['units'].values()]]
captured_sources={str(p.relative_to(F)):p.read_bytes() for p in source_paths}
compiler_pins={str(p):sha256(p.read_bytes()).hexdigest() for p in [oldcompiler,compiler]}
r={'source_identity':{n:sha256(b).hexdigest() for n,b in captured_sources.items()},'phase':'compile','items':{},'module_receipts':{},'negative_cases':[],'compiler_sha256':sha256(compiler.read_bytes()).hexdigest(),'old_compiler_sha256':sha256(oldcompiler.read_bytes()).hexdigest()}
def save():(D/'status.json').write_text(json.dumps(r,indent=2)+'\n')
def dig(raw):return sha256(raw).hexdigest()
def compile_one(label,code,cc,observe=False):
 path,receipt=compile_stage(D,label,cc,code,compiler_function_offsets=tuple([56,240,1024]+[4096+320*i for i in range(128)]) if observe else ())
 assert receipt['artifact_sha256']==compiler_pins[str(cc)]
 compiler_pins[str(path)]=sha256(path.read_bytes()).hexdigest()
 return path,path.read_bytes(),receipt
def run_filter(image,frame,size):
 canary=b'\xb3'*64
 source=bytearray(canary+frame+canary);out=bytearray(canary+b'\xa7'*size+canary);state=bytearray(canary+bytes(16384)+canary)
 ptr=[ctypes.addressof(ctypes.c_ubyte.from_buffer(b))+64 for b in [source,out,state]]
 for n in range(1,4097):
  status=image._entry(ptr[0],len(frame),ptr[1],size,ptr[2],16384)
  if status:break
 else:raise AssertionError('filter no terminal')
 assert source[64:-64]==frame and all(b[:64]==canary and b[-64:]==canary for b in [source,out,state])
 return status,bytes(out[64:-64]),n
def locations(p):
 result={}
 for m in p['modules']:
  at=136
  for name in m['units']:
   result[(m['role'],at)]=name
   at=(at+p['units'][name]['image_bytes']+7)//8*8
 return result

def rebind_root_adapter(oldplan,plan,old_source,old_packer):
 r['adapter_changes']=[]
 old=locations(oldplan);new=locations(plan);newnames={name:key for key,name in new.items()}
 source=old_source.decode();before,marker,table=source.partition('unit_table:\n');assert marker and table.count('.quad ')==25
 def row(m):
  role,offset=int(m[1]),int(m[2])
  if offset==0:return m[0]
  name=old[(role,offset)];newrole,newoffset=newnames[name];assert role==newrole
  r['adapter_changes'].append({'unit':name,'old':offset,'new':newoffset})
  return ' .quad '+str(role)+','+str(newoffset)+','+m[3]
 table=re.sub(r' \.quad (\d+),(\d+),([^\n]+)',row,table)
 source=before+marker+table
 oldproducer=next(at for (role,at),name in old.items() if name=='producer');newproducer=newnames['producer'][1]
 needle=' add r11,'+str(oldproducer)+'\n';assert source.count(needle)==1;source=source.replace(needle,' add r11,'+str(newproducer)+'\n')
 (D/'hia_agent_store_syscalls.S').write_text(source)
 od=D/'old-adapter';nd=D/'new-adapter';od.mkdir();nd.mkdir()
 oldstub,oldsym,_=assemble_adapter(od,'hia_agent_store_syscalls.S',old_source)
 newstub,newsym,_=assemble_adapter(nd,'hia_agent_store_syscalls.S',source.encode())
 assert len(oldstub)==len(newstub) and oldsym==newsym
 digest,size,holes=read_adapter_binding(old_packer,old_source,calls=4)
 assert digest==sha256(oldstub).digest() and size==len(oldstub)
 oldprefix=elf_header()+oldstub;newprefix=elf_header()+newstub
 oldprefix+=bytes((-len(oldprefix))%8);newprefix+=bytes((-len(newprefix))%8)
 document=assemble_program(old_packer).as_dict();seen=bytearray(len(oldprefix));changed=0
 for function in document['functions']:
  if function['name'] not in ['f'+str(i) for i in range(4,20)]:continue
  assert len(function['blocks'])==1
  ops=function['blocks'][0]['ops']
  for i,op in enumerate(ops):
   if op['op']!='call' or op['attrs'].get('function') not in ['f2','f3']:continue
   off,val=ops[i-2:i];assert off['op']==val['op']=='const'
   assert op['args']==['v0',off['out'][0]['name'],val['out'][0]['name']]
   at=off['attrs']['value'];width=8 if op['attrs']['function']=='f2' else 4
   assert at>=0 and at+width<=len(oldprefix)
   assert val['attrs']['value']==int.from_bytes(oldprefix[at:at+width],'little'),(function['name'],at,'literal mismatch')
   assert not any(seen[at:at+width]);seen[at:at+width]=bytes([1])*width
   fresh=int.from_bytes(newprefix[at:at+width],'little')
   changed+=fresh!=val['attrs']['value'];val['attrs']['value']=fresh
 assert all(covered or oldprefix[i]==newprefix[i]==0 for i,covered in enumerate(seen)),'uncovered adapter literal differs from zero-fill'
 r['unchanged_zero_fill_bytes']=sum(covered==0 for covered in seen)
 document['functions']=[f for f in document['functions'] if f['name']!='adapter_binding']
 bind_adapter(document,source.encode(),newstub,holes);text=render_assembly(document);(D/'packer.hepta').write_text(text)
 binding=read_adapter_binding(text.encode(),source.encode(),calls=4)
 return source.encode(),text.encode(),binding


save()
try:
 old_raw={};new_raw={};old_receipts={};new_receipts={};frames={};shapes={};old_filtered={}
 oldfilter_path,oldfilter,receipt=compile_one('old-word-filter',(root/'word_filter.hepta').read_bytes(),oldcompiler)
 oldimage=NativeHiaJsonImage(oldfilter,dig(oldfilter))
 for name,spec in original['units'].items():
  source=(root/spec['source']).read_bytes()
  oldpath,old,oldreceipt=compile_one('old-'+name,source,oldcompiler,'id' in spec)
  newpath,new,newreceipt=compile_one('new-'+name,source,compiler,'id' in spec)
  old_raw[name]=old;new_raw[name]=new;old_receipts[name]=oldreceipt;new_receipts[name]=newreceipt
  if 'id' not in spec:continue
  assert dig(old)==spec['raw_sha256'],(name,'old raw mismatch')
  prefix=bytes.fromhex(spec['input_prefix_hex']);frame=prefix+old;assert dig(frame)==spec['frame_sha256']
  code,image,n=run_filter(oldimage,frame,spec['image_bytes']);assert code==spec['image_bytes'] and dig(image)==spec['image_sha256'],(name,'old filter mismatch',code)
  old_filtered[name]=image
  hdr=list(struct.unpack_from('<8s7Q',prefix));assert hdr[1]==1 and hdr[2]==spec['id'] and hdr[3]==len(old) and hdr[6]==spec['image_bytes'] and hdr[7]==0
  ow=oldreceipt['workspace_header'];nw=newreceipt['workspace_header'];count=ow['1024'];assert count==nw['1024']
  oldstarts=[ow[str(4096+320*i)] for i in range(count)]+[len(old)]
  newstarts=[nw[str(4096+320*i)] for i in range(count)]+[len(new)]
  patches=[];replacements=[]
  for i in range(hdr[4]):
   at,span,replace_at,replace_size=struct.unpack_from('<4Q',prefix,64+32*i);ordinal=oldstarts.index(at);assert oldstarts[ordinal+1]-at==span
   new_at=newstarts[ordinal];new_span=newstarts[ordinal+1]-new_at;assert replace_size+5<=new_span
   replacements.append({'ordinal':ordinal,'old_offset':at,'old_size':span,'new_offset':new_at,'new_size':new_span,'replacement_sha256':dig(prefix[replace_at:replace_at+replace_size])})
   patches.append((new_at,new_span,replace_at,replace_size))
  size=len(new)
  for _,span,_,_ in patches:size=(size+7)//8*8+span
  hdr[3]=len(new);hdr[6]=size
  newprefix=struct.pack('<8s7Q',*hdr)+b''.join(struct.pack('<4Q',*p) for p in patches)+prefix[64+32*len(patches):]
  assert len(newprefix)==len(prefix);newframe=newprefix+new;frames[name]=newframe
  fresh=plan['units'][name];fresh.update(input_prefix_hex=newprefix.hex(),raw_sha256=dig(new),frame_sha256=dig(newframe),image_bytes=size)
  for left,right in zip(struct.unpack('<4Q',bytes.fromhex(spec['frame_sha256'])),struct.unpack('<4Q',bytes.fromhex(fresh['frame_sha256']))):
   oldliteral='{"value":'+str(left)+'}';newliteral='{"value":'+str(right)+'}'
   assert filter_source.count(oldliteral)==1,(name,'filter pin occurrence')
   filter_source=filter_source.replace(oldliteral,newliteral)
  shapes[name]=replacements;r['items'][name]={'old_raw_sha256':dig(old),'new_raw_sha256':dig(new),'new_frame_sha256':dig(newframe),'old_image_sha256':dig(image),'functions':replacements};r['active']=name;save()
 old_bundle_path,old_bundle,_=compile_one('old-bundle-packer',(root/'bundle_packer.hepta').read_bytes(),oldcompiler)
 assert dig(old_bundle)==original['bundle_packer_sha256'],'previous bundle packer differs'
 old_records=[]
 for group in original['modules']:
  old_parts=[old_filtered[n] for n in group['units']];old_sizes=list(map(len,old_parts))
  old_payload=struct.pack('<8s11Q',b'HIAUBPK1',1,len(old_parts),0,*(old_sizes+[0]*(8-len(old_parts))))+b''.join(old_parts)
  old_path,old_bytes,_=compile_one('old-module-'+str(group['role']),old_payload,old_bundle_path)
  assert dig(old_bytes)==group['sha256'],'previous module differs'
  old_name='module-'+str(group['role'])+'.bin'
  old_records.append(old_name.encode().ljust(64,b'\0')+struct.pack('<Q',len(old_bytes))+sha256(old_bytes).digest()+struct.pack('<3Q',group['workspace'],group['output'],group['role']))
 old_manifest=struct.pack('<8s3Q',b'HIAMSI01',1,len(old_records),0)+b''.join(old_records)
 assert dig(old_manifest)==original['expected_manifest_sha256'],'previous module manifest differs'
 old_parts=[old_filtered['loader'],old_filtered['owner'],old_manifest,old_filtered['JSON_hub']]
 old_frame=struct.pack('<8s4Q',b'HIA4PK01',*map(len,old_parts))+b''.join(old_parts)
 _,old_root,_=compile_one('old-hia-agent-store',old_frame,D/'old-packer.image.bin')
 assert dig(old_root)==original['expected_root_sha256'],'previous Store root differs'
 r['previous_root_reproduced']=dig(old_root);save()
 (D/'word_filter.hepta').write_text(filter_source)
 _,newfilter,receipt=compile_one('new-word-filter',filter_source.encode(),compiler)
 image=NativeHiaJsonImage(newfilter,dig(newfilter));filtered={}
 r['phase']='native-filter';r['word_filter_sha256']=dig(newfilter);save()
 for name,frame in frames.items():
  spec=plan['units'][name];code,raw,calls=run_filter(image,frame,spec['image_bytes'])
  assert code==len(raw)==spec['image_bytes'],(name,'new filter failure',code,len(raw))
  spec['image_sha256']=dig(raw);filtered[name]=raw;(D/(name+'.filtered.bin')).write_bytes(raw)
  r['items'][name].update(image_sha256=dig(raw),image_bytes=len(raw),filter_calls=calls)
  oldspec=original['units'][name];oldframe=bytes.fromhex(oldspec['input_prefix_hex'])+old_raw[name]
  for label,bad in [('old-compiler',oldframe),('mutated-code',frame[:-1]+bytes([frame[-1]^1]))]:
   if label=='old-compiler' and bad==frame:continue
   status,_,_=run_filter(image,bad,max(spec['image_bytes'],oldspec['image_bytes']))
   assert status!=spec['image_bytes'] and status<=9,(name,label,status)
   r['negative_cases'].append({'unit':name,'case':label,'status':status})
  save()
 bundle_path,bundle,_=compile_one('new-bundle-packer',(root/'bundle_packer.hepta').read_bytes(),compiler);plan['bundle_packer_sha256']=dig(bundle)
 records=[]
 for group in plan['modules']:
  parts=[filtered[n] for n in group['units']];sizes=list(map(len,parts))
  payload=struct.pack('<8s11Q',b'HIAUBPK1',1,len(parts),0,*(sizes+[0]*(8-len(parts))))+b''.join(parts)
  path,raw,receipt=compile_one('module-'+str(group['role']),payload,bundle_path)
  group['sha256']=dig(raw);name='module-'+str(group['role'])+'.bin';(D/name).write_bytes(raw)
  records.append(name.encode().ljust(64,b'\0')+struct.pack('<Q',len(raw))+sha256(raw).digest()+struct.pack('<3Q',group['workspace'],group['output'],group['role']))
  r['module_receipts'][name]={'sha256':dig(raw),'bytes':len(raw)};save()
 manifest=struct.pack('<8s3Q',b'HIAMSI01',1,len(records),0)+b''.join(records);plan['expected_manifest_sha256']=dig(manifest);(D/'modules.bin').write_bytes(manifest)
 parts={'loader':filtered['loader'],'owner':filtered['owner'],'manifest':manifest,'json':filtered['JSON_hub']}
 frame=struct.pack('<8s4Q',b'HIA4PK01',*(len(v) for v in parts.values()))+b''.join(parts.values())
 adapter_source,packer_source,binding=rebind_root_adapter(original,plan,captured_sources['tools/hia_agent_store_syscalls.S'],captured_sources['examples/hia_bootstrap/agent_store/'+original['units']['packer']['source']])
 packer,_,_=compile_one('new-packer-rebound',packer_source,compiler)
 path,elf,receipt=compile_one('hia-agent-store',frame,packer)
 plan['expected_root_sha256']=dig(elf);(D/'hia-agent-store').write_bytes(elf);(D/'hia-agent-store').chmod(0o500)
 binding=read_adapter_binding(packer_source,adapter_source,calls=4)
 verify_placement(elf,binding,parts,instructions=(b'\xe8',b'\xe8',b'\x48\x8d\x35',b'\xe8'))
 (D/'build-plan.json').write_text(json.dumps(plan,indent=2)+'\n');(D/'patch-function-map.json').write_text(json.dumps(shapes,indent=2)+'\n')
 assert all((F/n).read_bytes()==b for n,b in captured_sources.items()),'source changed during regeneration'
 assert all(sha256(Path(p).read_bytes()).hexdigest()==pin for p,pin in compiler_pins.items()),'compiler changed during regeneration'
 if args.check:
  assert (D/'build-plan.json').read_bytes()==(root/'build-plan.json').read_bytes(),'current plan is not reproducible'
  assert (D/'word_filter.hepta').read_bytes()==(root/'word_filter.hepta').read_bytes(),'current filter is not reproducible'
  assert (D/'packer.hepta').read_bytes()==(root/'packer.hepta').read_bytes(),'current root packer is not reproducible'
  assert (D/'hia_agent_store_syscalls.S').read_bytes()==(F/'tools/hia_agent_store_syscalls.S').read_bytes(),'current syscall adapter is not reproducible'
 r.update(phase='completed',status='passed',root_sha256=dig(elf),plan_sha256=dig((D/'build-plan.json').read_bytes()),units=len(filtered),negative_count=len(r['negative_cases']))
except BaseException:r.update(phase='failed',error=traceback.format_exc());raise
finally:save()
