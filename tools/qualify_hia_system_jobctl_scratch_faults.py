from pathlib import Path
import ctypes,hashlib,json,mmap,os,re,shutil,signal,stat,struct,subprocess,sys,traceback
import argparse
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--components',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--oracle',type=Path,required=True)
parser.add_argument('--oracle-sha256',required=True)
parser.add_argument('--owner-qualifier',type=Path,default=Path(__file__).with_name('qualify_hia_system_jobctl_scratch.py'))
parser.add_argument('--interposer-source',type=Path,default=Path(__file__).with_name('hia_system_jobctl_scratch_faults.c'))
parser.add_argument('--cc',default=shutil.which('cc'))
args=parser.parse_args();D=args.components.resolve(strict=True);Q=args.output.resolve();Q.mkdir(mode=0o700);binary=args.oracle.resolve(strict=True)
assert hashlib.sha256(binary.read_bytes()).hexdigest()==args.oracle_sha256
manifest=json.loads((D/'build-status.json').read_text());assert manifest['phase']=='ready'
(Q/'qualifier.py').write_text(Path(__file__).read_text())
source=args.owner_qualifier.read_text();part=source[source.index('NONE=(1<<64)-1;'):source.index('rows=[]')]
part=part.replace('   ctypes.set_errno(0);result=libc.syscall(ctypes.c_long(number),*args)', '''   if hasattr(self,'fault') and not self.fired and operation==self.fault[0] and self.get(0)==self.fault[1]:
    self.fired=True;self.put(8,self.fault[2]);continue
   ctypes.set_errno(0);result=libc.syscall(ctypes.c_long(number),*args)''')
exec(part,globals());(Q/'native-mechanical-harness.py').write_text(part)
interposer=Q/'faults.so';shutil.copyfile(args.interposer_source,Q/'faults.c');p=subprocess.run([args.cc,'-shared','-fPIC','-O2','-o',str(interposer),str(Q/'faults.c'),'-ldl'],capture_output=True);(Q/'build.log').write_bytes(p.stdout+p.stderr);assert p.returncode==0,p.stderr
phases={'tmp-open':(0,3061),'write-1':(0,3062),'write-2':(0,3063),'rename':(0,3065),'state-open':(0,3066),'root-open':(0,3120),'leaf-open':(0,3103),'fsync-1':(0,3106),'fsync-2':(0,3107),'fsync-3':(0,3064),'fsync-4':(0,3067),'fsync-5':(3,3242),'readdir':(3,3210)}
rows=[]
for fault,(operation,phase) in phases.items():
 for error in [5,4]+([0]if fault in ['write-1','write-2']else[]):
  name=fault+'-'+str(error);case=Q/name;case.mkdir();oldroot=case/'original';newroot=case/'native';oldroot.mkdir();newroot.mkdir();oldstate=oldroot/'state';newstate=newroot/'state';oldstate.mkdir(mode=0o700);newstate.mkdir(mode=0o700)
  fired=case/'original-fired';env={**os.environ,'LD_PRELOAD':str(interposer),'SC_FAULT':fault,'SC_FAULT_ERRNO':str(error),'SC_FAULT_LOG':str(fired)}
  if error==0:env['SC_FAULT_ZERO']='1'
  p=subprocess.Popen([binary],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env);p.stdin.write(enc({'state':str(oldstate),'id':'job-test','nonce':'n'*32})+b'\n');p.stdin.flush();original_first=read(p);n=Native();n.init(newstate);n.fault=(operation,phase,-error);n.fired=False
  try:
   native_first=n.run(0);assert normalize(original_first,oldroot)==normalize(native_first,newroot),(name,original_first,native_first)
   if original_first['ok']:
    next={'op':'finish','pid':123,'stopped':True};p.stdin.write(enc(next)+b'\n');p.stdin.flush();expected=read(p);n.put(62128,123);n.put(62136,1);actual=n.run(3)
   else:expected=original_first;actual=native_first
   p.stdin.close();assert p.wait(timeout=10)==0;assert fired.read_text()=='1'and n.fired,(name,'fault was not exercised',n.fired,fired.read_text())
   oldtree=normalize(tree(oldroot),oldroot);newtree=normalize(tree(newroot),newroot);equal=normalize(expected,oldroot)==normalize(actual,newroot)and oldtree==newtree
   row={'case':name,'original':normalize(expected,oldroot),'native':normalize(actual,newroot),'tree_equal':oldtree==newtree,'pass':equal};rows.append(row);(Q/'status.json').write_text(json.dumps({'state':'running','rows':rows},indent=2)+'\n');assert equal,(row,oldtree,newtree)
  finally:
   n.close()
   if p.poll()is None:p.kill();p.wait()
assert hashlib.sha256(binary.read_bytes()).hexdigest()==args.oracle_sha256
report={'state':'passed','cases':len(rows),'rows':rows,'scope':'one-shot EIO/EINTR/WriteZero host-fact injection against unchanged Rust via QA LD_PRELOAD and the HIA syscall continuation; product budgets and decisions unchanged','oracle_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'interposer_sha256':hashlib.sha256(interposer.read_bytes()).hexdigest()};(Q/'status.json').write_text(json.dumps(report,indent=2)+'\n');print('SCRATCH FAULT PASS',len(rows),flush=True)
