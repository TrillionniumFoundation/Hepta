"""Native Q2 cwd and actual OSError text framing; retains all Q1 oracle assertions."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,platform,struct,traceback
from tools import qualify_hia_program_llvm_public_log_codec as prior
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def run(image,owner,out):
 assert platform.python_version()=='3.14.4';out.mkdir(parents=True,exist_ok=False)
 original_packet=prior.packet
 def packet(op,**kw):
  if op==0:kw['cwd']=os.fsdecode(kw.get('cwd',b'')).encode('utf-8','surrogatepass')
  return b'HIALLGQ2'+original_packet(op,**kw)[8:]
 prior.packet=packet
 try:old=prior.run(image,owner,out/'original-codec-domain')
 finally:prior.packet=original_packet
 codec=prior.Codec(image);groups=[];report=dict(passed=False,whole_public_llvm_qualified=False)
 try:
  cases=0
  text=lambda s:s.encode('utf-8','surrogatepass')
  names=[None,'','relative','a/b','a\\b',"a'b",'a"b','é\U0001f600','a\udcffb','\ud800','a\nb',b'',bytes(range(256))]
  for number in (1,2,5,9,11,13,17,20,32,75,110,114,115,999,-1):
   for first in names:
    for second in (None,'','dest','a\udcffb',b'\xff'):
     reason='actual\nreason é\ud800'
     error=OSError(number,reason,first,None,second)
     f1=error.filename;f2=error.filename2
     flags=int(f1 is not None)|(2 if f1 is not None and f2 is not None else 0)
     fields=[text(str(error.errno)),text(str(error.strerror)),b''if not flags&1 else text(repr(f1)),b''if not flags&2 else text(repr(f2))]
     request=struct.pack('<8s7Q',b'HIACLOM1',flags,*map(len,fields),0,0)+b''.join(fields)
     expected=text(str(error));n,data=codec.call(request,max(4096,len(expected)))
     assert data==expected,(number,first,second,data,expected)
     if cases<20:
      codec.call(request,max(0,n-1),want=0xfffffffe)
      assert codec.call(request,n)==(n,expected)
     cases+=1
  groups.append(dict(case='actual-oserror-slots-filename-repr-and-specialized-types',cases=cases))
  print('LOG_NATIVE_CODEC_PASS oserror',cases,flush=True)
  cwd_cases=0
  for cwd in ('/', '/tmp/\udcff', '/tmp/\ud800\udc00', '/'+'x'*20000, '/tmp/é\U0001f600'):
   raw=b'HIALLGQ2'+original_packet(0,frame=prior.capture_frame(['clang','--version']),cwd=text(cwd))[8:]
   value,data=codec.value(raw);assert value['cwd']==cwd
   codec.call(raw,len(data)-1,want=0xfffffffe)
   assert codec.call(raw,len(data))==(len(data),data)
   cwd_cases+=1
  groups.append(dict(case='actual-WTF8-cwd-including-lone-and-adjacent-surrogates-long-path',cases=cwd_cases))
  controls=[]
  good=struct.pack('<8s7Q',b'HIACLOM1',0,1,1,0,0,0,0)+b'2x'
  controls.extend([good[:n]for n in (0,1,8,63,64,65)])
  controls.extend([good+b'\0',original_packet(1,known=1,flags=6)])
  for at,value in ((8,2),(8,4),(16,0),(16,(1<<64)-1),(32,1),(40,1),(48,1),(56,1)):
   raw=bytearray(good);struct.pack_into('<Q',raw,at,value);controls.append(bytes(raw))
  for raw in controls:codec.call(raw,4096,want=0xfffffffd)
  groups.append(dict(case='new-private-mode-strict-framing-old-Q1-rejected-and-no-partial-write',cases=len(controls)))
  report.update(passed=True,pure_codec_qualified=True,groups=groups,calls=codec.calls,
   original_domain=dict(path=str(out/'original-codec-domain/report.json'),**pin((out/'original-codec-domain/report.json').read_bytes()),calls=old['calls']),
   product=pin(image.read_bytes()),source=pin(Path(__file__).read_bytes()),owner=pin(owner.read_bytes()))
  print('LOG_NATIVE_CODEC_ALL_PASS',codec.calls,flush=True)
 except BaseException as error:report.update(error=repr(error),traceback=traceback.format_exc());raise
 finally:(out/'report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
 return report
def main():
 p=argparse.ArgumentParser()
 for key in ('image','owner','output'):p.add_argument('--'+key,type=Path,required=True)
 a=p.parse_args();run(a.image,a.owner,a.output)
if __name__=='__main__':main()
