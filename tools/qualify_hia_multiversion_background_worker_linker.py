from pathlib import Path
import argparse,ctypes as C,hashlib,json,struct
from tools.qualify_hia_multiversion_components import Image
get=lambda b,n:struct.unpack_from('<Q',b,n)[0]
def main():
 p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--queue-directory',type=Path,required=True);p.add_argument('--payload-directory',type=Path,required=True);a=p.parse_args();D=a.directory
 product=Image(D/'multiversion_background_worker_linker.flat');old=Image(a.queue_directory/'elf_shared_linker.flat');raw=(D/'worker-component.o').read_bytes();expected=(D/'worker-component.so').read_bytes();rows=[]
 def call(name,wire,valid,on=None,wn=1<<20,engine=product):
  on=len(expected)+16384 if on is None else on;out=C.create_string_buffer(on);C.memset(out,0xa5,on);work=C.create_string_buffer(wn);before=out.raw
  rc=engine(wire,out,work)
  if valid:
   assert rc<len(out),(name,rc);data=out.raw[:rc]
   if name=='actual-pthread-object':assert data==expected
  else:assert rc>=0xfffffff0 and out.raw==before,(name,rc)
  rows.append({'name':name,'returncode':rc,'passed':True})
  return out.raw[:rc] if valid else b''
 call('actual-pthread-object',raw,True)
 call('old-import-profile-refuses-pthread-object',raw,False,engine=old)
 call('worker-profile-refuses-malloc-free-payload', (a.payload_directory/'payload-component.o').read_bytes(),False)
 queue_raw=(a.queue_directory/'queue-component.o').read_bytes();q1=call('no-import-queue-original',queue_raw,True,on=len(queue_raw)+16384,engine=old);q2=call('no-import-queue-worker-profile',queue_raw,True,on=len(queue_raw)+16384);assert q1==q2==(a.queue_directory/'queue-component.so').read_bytes()
 h=get(raw,40);text=get(raw,h+88);rela=get(raw,h+152);sym=get(raw,h+216);strings=get(raw,h+280);r0=get(raw,rela)
 changes=[('magic',0,8,0),('not-relocatable',16,2,3),('phoff',32,8,1),('section-offset',40,8,1),('text-flags',h+72,8,7),('text-empty',h+96,8,0),('text-align',h+112,8,3),('text-out-of-bounds',h+88,8,len(raw)),('relocation-kind',rela+8,4,2),('relocation-symbol',rela+12,4,999),('relocation-addend',rela+16,8,0),('overlap-relocations',rela+24,8,r0),('relocated-opcode',text+r0-1,1,0x90),('relocated-immediate',text+r0,4,1),('strtab-leading-zero',strings,1,1),('import-tag',sym+3*24+4,4,18),('duplicate-import-name',sym+4*24,4,struct.unpack_from('<I',raw,sym+3*24)[0])]
 for name,off,width,value in changes:
  blob=bytearray(raw);blob[off:off+width]=value.to_bytes(width,'little');call(name,bytes(blob),False)
 for index,replacement in ((3,b'pthread_detach'),(4,b'pthread_exit'),(3,b'free')):
  blob=bytearray(raw);at=strings+struct.unpack_from('<I',blob,sym+index*24)[0];blob[at:at+len(replacement)+1]=replacement+b'\0';call('unlisted-import-'+replacement.decode(),bytes(blob),False)
 for n in (0,1,63,len(expected)-1):call('short-output-'+str(n),raw,False,on=n)
 call('short-work',raw,False,wn=(1<<20)-1)
 for n in (0,63,511,len(raw)-1):call('truncated-object-'+str(n),raw[:n],False)
 report={'schema':'hepta.hia.background-native-worker-linker.qualification.v1','whole_background_qualified':False,'scope':'Exact pthread_create/pthread_join import profile; original linker unchanged; original layout/symbol/relocation/capacity checks preserved.','image_sha256':hashlib.sha256(expected).hexdigest(),'linker_sha256':hashlib.sha256((D/'multiversion_background_worker_linker.flat').read_bytes()).hexdigest(),'old_linker_sha256':hashlib.sha256((a.queue_directory/'elf_shared_linker.flat').read_bytes()).hexdigest(),'passed':len(rows),'failed':0,'cases':rows}
 (D/'linker-qualification.json').write_text(json.dumps(report,indent=2)+'\n');print('BG_WORKER_LINKER_QUALIFIED',len(rows),flush=True)
if __name__=='__main__':main()
