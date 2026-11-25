"""Actual original raw admission versus the captured strict MV profile."""
from pathlib import Path
import os,sys,ctypes as C,struct,json,hashlib,time
B=Path('/home/qian-qi/.local/state/hia-azi5-b843-qa/cleanup-audit-20261124T0745Z');V=B/'native-multiversion-source';sys.path.insert(0,str(V))
source=(V/'tools/qualify_hia_multiversion_prepare_intake.py').read_text().replace('hia_mv_prepare_intake','hia_mv_prepare_admission')
ns={'__name__':'qualified_client'};exec(compile(source,'<qualified-admission-client>','exec'),ns)
Intake=ns['Intake'];get=ns['get'];sealed=ns['sealed'];sha=ns['sha'];verify_program=ns['verify_program'];HIAProgramRejected=ns['HIAProgramRejected'];MultiversionRejected=ns['MultiversionRejected'];REASONS=ns['REASONS'];basic=ns['basic'];abi_bytes=ns['abi_bytes']
def packet(raw,fd,total=False,digits=4300):
 return struct.pack('<8s15Q',b'HIAMVNQ2',int(total),fd,0,0,len(raw),digits,*([0]*9))+raw
MESSAGES={201:'E_HIA_LIMIT: program exceeds byte budget',202:'E_HIA_FORMAT: invalid/deep UTF-8 JSON',203:'E_HIA_LIMIT: program exceeds structural budget before JSON allocation',205:'E_HIA_VERSION_COLLISION: historical nominal v2 requires import_legacy_composite_v2; the primitive v2 namespace cannot infer a producer profile'}
def main():
 import argparse
 p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--normalizer',type=Path,required=True);a=p.parse_args();D=a.directory
 native=Intake(D/'prepare-admission-component.so');image=a.normalizer.read_bytes();fd=sealed(image);_,profile=ns['original_functions']();rows=[];cases={}
 def add(label,raw,total=False,digits=4300):
  key=sha(raw),total,digits
  if key not in cases:cases[key]={'raw':raw,'total':total,'digits':digits,'labels':[]}
  cases[key]['labels'].append(label)
 for label,d,total in ns['profile_cases']():add('profile/'+label,json.dumps(d,ensure_ascii=False,separators=(',',':')).encode(),total)
 raw=json.dumps(basic(),separators=(',',':')).encode()
 for label,value in [('empty',b''),('empty-object',b'{}'),('null',b'null'),('truncated',raw[:-1]),('tail',raw+b'0'),('bad-utf8',raw+b'\xff'),('utf8-bom',b'\xef\xbb\xbf'+raw),('duplicate',raw.replace(b'{',b'{"schema":"hepta.hia.program.v1",',1)),('exact-byte-limit',raw+b' '*(8388608-len(raw))),('byte-limit-before-utf8',raw+b'\xff'+b' '*(8388608-len(raw))),('byte-limit-before-syntax',b' '*(8388609)),('depth-overflow',b'['*65+b'0'+b']'*65),('node-overflow',b'['+b'0,'*262144+b'0]')]:
  add(label,value)
 for encoding in ('utf-16','utf-16-le','utf-16-be','utf-32','utf-32-le','utf-32-be'):add(encoding,raw.decode().encode(encoding))
 collision={'schema':'hepta.hia.program.v2','types':[]}
 for d in [collision,{**basic(),'schema':'hepta.hia.program.v2','types':[]},{'types':[],**basic(),'schema':'hepta.hia.program.v2'},{'nested':collision,**basic()}]:
  r=json.dumps(d,separators=(',',':')).encode();add('historical-v2/types',r)
  add('escaped-historical-v2/types',r.replace(b'"schema"',b'"sch\\u0065ma"').replace(b'"types"',b'"t\\u0079pes"').replace(b'program.v2',b'program.\\u00762'))
 for policy in (0,640,4300,2147483647):
  for n in (1,639,640,641,4299,4300,4301,5000):
   add('integer-policy/'+str(policy)+'/'+str(n),b'{"schema":"hepta.hia.program.v2","types":[],"unused":'+b'9'*n+b'}',digits=policy)
  for label,value in [('float-first',b'{"schema":"hepta.hia.program.v2","types":[],"a":1.0,"b":'+b'9'*5000+b'}'),('fraction',b'{"a":'+b'9'*5000+b'.0}'),('exponent',b'{"a":1e'+b'9'*5000+b'}'),('integer-in-string',b'{"schema":"hepta.hia.program.v2","types":[],"a":"'+b'9'*5000+b'"}')]:add(label,value,digits=policy)
 olddigits=sys.get_int_max_str_digits()
 try:
  for i,item in enumerate(cases.values()):
   sys.set_int_max_str_digits(item['digits'])
   raw=item['raw'];total=item['total'];program=None;error=None;abi=None;detail=None
   try:
    program=verify_program(raw)
    try:abi=profile(program,program.as_dict(),prove_total=total);expected=0;detail=0
    except MultiversionRejected as exc:
     expected=3;msg=str(exc).removeprefix('E_HIA_MULTIVERSION: ');detail=next(k for k,v in REASONS.items() if v==msg)
   except HIAProgramRejected as exc:expected=1;error=str(exc)
   req=packet(raw,fd,total,item['digits']);rc,out,streams,elapsed=native.run(req)
   if rc!=expected or (rc==3 and get(out,16)!=detail):
    (D/'strict-failed.input').write_bytes(req);(D/'strict-failed.output').write_bytes(out[:65536]);raise AssertionError((i,item['labels'],rc,expected,get(out,16),detail,error))
   if rc==1:
    if get(out,16) in MESSAGES:
     actual=MESSAGES[get(out,16)];assert streams==[None,None] and get(out,248)==0
    else:
     assert streams[0] is not None and streams[1]==b''
     actual=json.loads(streams[0])['diagnostics'][0]['message']
    assert actual==error,(i,item['labels'],actual,error)
    assert out[320:576]==b'\xa5'*256
   elif rc==0:
    core=program.canonical_bytes;orig=program.structured_bytes or core;aw=abi_bytes(program,abi);end=320+len(orig)+len(core)+len(aw)
    assert out[80:112]==hashlib.sha256(raw).digest()
    assert out[112:144]==hashlib.sha256(orig).digest() and out[144:176]==hashlib.sha256(core).digest()
    assert out[176:208]==hashlib.sha256(aw).digest()
    assert out[320:end]==orig+core+aw and out[end:end+64]==b'\xa5'*64
    assert get(out,248)==63 and streams==[None,None]
   rows.append(dict(index=i,labels=item['labels'],digits=item['digits'],input_bytes=len(raw),input_sha256=sha(raw),status=rc,detail=get(out,16),original_error=error,elapsed_ns=elapsed))
   if i%16==0:print('STRICT_ADMISSION_PAIR',i,item['labels'][0],rc,get(out,16),flush=True)
 finally:sys.set_int_max_str_digits(olddigits)
 base=packet(json.dumps(basic(),separators=(',',':')).encode(),fd)
 variants=[('truncated',base[:-1]),('tail',base+b'0'),('foreign-magic',b'INVALID!'+base[8:])]
 for at,values in [(8,[2,2**64-1]),(16,[0,2,2147483648]),(24,[1,2**64-1]),(32,[8]),(40,[2**64-1]),(48,[1,639,2147483648,2**64-1])]+[(n,[1]) for n in range(56,128,8)]:
  for val in values:
   r=bytearray(base);struct.pack_into('<Q',r,at,val);variants.append((str(at)+'/'+str(val),bytes(r)))
 for label,req in variants:
  rc,out,_,_=native.run(req);assert rc==0xfffffffd and out[:320]==b'\xa5'*320,(label,rc)
  rows.append(dict(index='private/'+label,status=rc))
 for label,oc,wc in [('short-output',319,len(native.w)),('short-work',len(native.o),len(native.w)-1)]:
  rc,out,_,_=native.run(base,oc,wc);assert rc==0xfffffffd and out[:320]==b'\xa5'*320
  rows.append(dict(index=label,status=rc))
 os.close(fd);assert image==a.normalizer.read_bytes()
 report=dict(schema='hepta.hia.multiversion-strict-admission.v1',whole_native_runtime=False,passed=len(rows),failed=0,image_sha256=sha((D/'prepare-admission-component.so').read_bytes()),normalizer_sha256=sha(image),raw_original_pairs=len(cases),cases=rows)
 (D/'strict-qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('STRICT_ADMISSION_ALL_PASS',len(rows),flush=True)
if __name__=='__main__':main()
