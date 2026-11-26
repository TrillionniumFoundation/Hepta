"""Actual Clang objects and retained generic ELF64 oracle against native HIA."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,random,struct,subprocess,traceback
from tools.qualify_hia_publication_cancellation import Image
from hepta.object_symbols import inspect_object_symbols,ObjectSymbolsRejected
ALLOWED={'abort','calloc','free','malloc','memset','memcpy','memmove'}
class Inventory:
 def __init__(self,flat):self.image=Image(flat.read_bytes());self.calls=0;self.grows=0
 def run(self,raw,machine,expected):
  tail=b''.join(struct.pack('<Q',len(x.encode('ascii')))+x.encode('ascii')for x in expected)
  wire=b'HIAOEL01'+struct.pack('<7Q',machine,len(raw),len(expected),0,0,0,0)+raw+tail;src=C.create_string_buffer(wire)
  outn=1024;workn=1024
  while True:
   out=C.create_string_buffer(outn);work=C.create_string_buffer(workn);self.calls+=1
   n=self.image.entry(src,len(wire),out,outn,work,workn)
   if n==0xfffffffe:
    wanted=struct.unpack_from('<2Q',bytes(work),16)
    assert wanted[0]>outn or wanted[1]>workn,wanted
    outn=max(outn*2,wanted[0]);workn=max(workn*2,wanted[1]);self.grows+=1;continue
   assert 64<=n<=outn,hex(n);header=struct.unpack_from('<8Q',bytes(out))
   assert bytes(out)[:8]==b'HIAOER01'
   if header[1]:return header[1],None
   assert n==64+header[2]*24
   result={'defined':set(),'undefined':set()}
   for at in range(64,n,24):
    offset,size,kind=struct.unpack_from('<3Q',bytes(out),at);assert kind in(0,1)and offset>=64 and offset+size<=64+len(raw)
    result['defined'if kind else'undefined'].add(wire[offset:offset+size].decode('ascii'))
   assert len(result['defined'])==header[3]and len(result['undefined'])==header[4]
   return 0,{k:frozenset(v)for k,v in result.items()}
def oracle(raw,machine,expected):
 try:result=inspect_object_symbols(raw,'ELF64',machine)
 except ObjectSymbolsRejected as e:
  text=str(e)
  if text.startswith('E_OBJECT_SYMBOL_SHAPE'):code=1
  elif text.startswith('E_OBJECT_SYMBOL_TABLE'):code=2
  elif text.startswith('E_OBJECT_SYMBOL_NAME'):
   code=4 if 'unterminated'in text else 5 if 'non-ASCII'in text else 3
  elif text.startswith('E_OBJECT_SYMBOL_DUPLICATE'):code=7
  elif text.startswith('E_OBJECT_SYMBOL_WEAK'):code=8
  elif text.startswith('E_OBJECT_SYMBOL_LOCATION'):code=9
  elif text.startswith('E_OBJECT_SYMBOL_EXPORT_KIND'):code=6 if'binding'in text else 10
  elif text.startswith('E_OBJECT_SYMBOL_EXPORT'):code=11
  else:raise
  return code,None
 if machine==243 and int.from_bytes(raw[48:52],'little')!=5:return 13,None
 if result['defined']!=frozenset(expected)or not result['undefined']<=ALLOWED:return 12,None
 return 0,result
def synthetic(entries,machine=62,extra_symtab=False):
 strings=bytearray(b'\0');symbols=bytearray(bytes(24))
 for item in entries:
  name=item[0];info=item[1]if len(item)>1 else 0x12;section=item[2]if len(item)>2 else 1
  value=item[3]if len(item)>3 else 0;size=item[4]if len(item)>4 else 1
  at=len(strings);strings.extend(name+b'\0');symbols.extend(struct.pack('<IBBHQQ',at,info,0,section,value,size))
 raw=bytearray(bytes(64));raw.extend(b'\xc3');raw.extend(bytes((-len(raw))%8));sym_at=len(raw);raw.extend(symbols);str_at=len(raw);raw.extend(strings);raw.extend(bytes((-len(raw))%8));sh=len(raw)
 rows=[bytes(64),struct.pack('<IIQQQQIIQQ',0,1,6,0,64,1,0,0,1,0),struct.pack('<IIQQQQIIQQ',0,2,0,0,sym_at,len(symbols),3,1,8,24),struct.pack('<IIQQQQIIQQ',0,3,0,0,str_at,len(strings),0,0,1,0)]
 if extra_symtab:rows.append(rows[2])
 raw.extend(b''.join(rows));raw[:64]=struct.pack('<16sHHIQQQIHHHHHH',b'\x7fELF\x02\x01\x01'+bytes(9),1,machine,1,0,0,sh,5 if machine==243 else 0,64,0,0,64,len(rows),0)
 return bytes(raw)
def main():
 p=argparse.ArgumentParser();p.add_argument('--flat',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();a.output.mkdir(mode=0o700)
 native=Inventory(a.flat);rows=[];report=dict(schema='hepta.hia.clang-object-inventory-qualification.v1',passed=False,whole_clang_outer_qualified=False,groups=rows,product=dict(bytes=a.flat.stat().st_size,sha256=hashlib.sha256(a.flat.read_bytes()).hexdigest()))
 def save():(a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
 def check(label,raw,machine=62,expected=('calculate',)):
  wanted=oracle(raw,machine,expected);got=native.run(raw,machine,expected);assert got==wanted,(label,wanted,got)
  return dict(name=label,bytes=len(raw),native_status=got[0],machine=machine)
 try:
  llvm=b'declare void @abort()\ndefine i64 @calculate(i64 %a) {\nentry:\n %z = icmp eq i64 %a, 0\n br i1 %z, label %bad, label %good\nbad:\n call void @abort()\n unreachable\ngood:\n %v = add i64 %a, 7\n ret i64 %v\n}\n'
  targets=[('x86_64-unknown-linux-gnu',62),('aarch64-unknown-linux-gnu',183),('riscv64-unknown-linux-gnu',243)]
  fixtures=[]
  for target,machine in targets:
   output=a.output/(str(machine)+'.o');command=['/usr/bin/clang-20','--target='+target,'-x','ir','-O3','-fPIC','-c','-o',str(output),'-']
   if machine==243:command[1:1]=['-march=rv64gc','-mabi=lp64d']
   result=subprocess.run(command,input=llvm,capture_output=True,timeout=60);assert result.returncode==0,result.stderr
   raw=output.read_bytes();rows.append(check('actual-clang-'+target,raw,machine));fixtures.append((raw,machine))
  cases=[
   ('one-function',[(b'calculate',)],('calculate',)),
   ('weak-function',[(b'calculate',0x22,1)],('calculate',)),
   ('unknown-binding',[(b'calculate',0xa2,1)],('calculate',)),
   ('global-data',[(b'calculate',),(b'data',0x11,1)],('calculate',)),
   ('undefined-duplicate',[(b'calculate',),(b'abort',0x10,0,0,0),(b'abort',0x20,0,0,0)],('calculate',)),
   ('defined-duplicate',[(b'calculate',),(b'calculate',)],('calculate',)),
   ('export-also-imported',[(b'calculate',),(b'calculate',0x10,0,0,0)],('calculate',)),
   ('import-also-exported',[(b'calculate',0x10,0,0,0),(b'calculate',)],('calculate',)),
   ('non-ascii-name',[(b'calculate',),(b'bad\xff',0x10,0,0,0)],('calculate',)),
   ('local-non-ascii-ignored',[(b'calculate',),(b'bad\xff',0x02,1)],('calculate',)),
   ('function-outside-section',[(b'calculate',0x12,1,1,1)],('calculate',)),
   ('zero-length-function',[(b'calculate',0x12,1,0,0)],('calculate',)),
   ('no-export',[(b'abort',0x10,0,0,0)],('calculate',)),
   ('permitted-nonidentifier-ascii',[(b'\ncalculate',)],('\ncalculate',)),
   ('long-function-name',[(b'c'*65537,)],('c'*65537,)),
   ('long-prefix-trie',[(b'c'*65537+b'a',),(b'c'*65537+b'b',)],('c'*65537+'a','c'*65537+'b')),
   ('all-allowed-imports',[(b'calculate',)]+[(name.encode(),0x10,0,0,0)for name in sorted(ALLOWED)],('calculate',)),
  ]
  for label,entries,expected in cases:rows.append(check(label,synthetic(entries),expected=expected))
  rows.append(check('duplicate-symbol-tables',synthetic([(b'calculate',)],extra_symtab=True)))
  many=synthetic([(b'calculate',)]+[('external_'+str(i)).encode()and(('external_'+str(i)).encode(),0x10,0,0,0)for i in range(70000)])
  rows.append(check('more-than-65536-distinct-symbols',many))
  mutations=0;codes={}
  for raw,machine in fixtures:
   for length in (0,1,5,16,63,64,len(raw)//2,len(raw)-1):
    row=check('truncate-'+str(length),raw[:length],machine);mutations+=1;codes[row['native_status']]=codes.get(row['native_status'],0)+1
   offsets=list(range(64))
   table=struct.unpack_from('<Q',raw,40)[0];count=struct.unpack_from('<H',raw,60)[0]
   offsets.extend(range(table,table+count*64))
   for pos in offsets:
    for value in (0,255):
     changed=bytearray(raw);changed[pos]=value;row=check('byte-'+str(pos)+'-'+str(value),bytes(changed),machine)
     mutations+=1;codes[row['native_status']]=codes.get(row['native_status'],0)+1
  rows.append(dict(name='original-structure-and-symbol-mutations',vectors=mutations,status_counts=codes))
  report.update(passed=True,native_invocations=native.calls,actual_buffer_growth_replays=native.grows,original_generic_elf_oracle_equal=True)
  print('OBJECT_INVENTORY_ACTUAL_QUALIFICATION_PASS',len(rows),mutations,native.calls,native.grows,flush=True)
 except BaseException as e:report['failure']=repr(e);report['traceback']=traceback.format_exc();raise
 finally:save()
if __name__=='__main__':main()
