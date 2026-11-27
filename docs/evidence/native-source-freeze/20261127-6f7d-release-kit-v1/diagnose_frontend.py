from pathlib import Path
from hashlib import sha256
import os,fcntl,subprocess,struct,json,time,traceback
R=Path('/home/qian-qi/hia-native-cold-edge-6f7d-20261127-2ac5');S=R/'source';D=R/'release-frontend-diagnostic-v1'
D.mkdir(mode=0o700);cold=json.loads((R/'chain/cold/final-cold.json').read_bytes());pins=cold['source_manifest']
report={'schema':'hepta.hia.release-frontend-diagnostic.v1','scope':'independent native short-tail diagnostic, not release qualification','source_head':'6f7dfb2defd8852d2fe58e02ff8c5cf78c5e7807','calls':[],'sources':{}}
def digest(b):return {'bytes':len(b),'sha256':sha256(b).hexdigest()}
def save():(D/'report.json').write_text(json.dumps(report,indent=2)+'\n')
def source(name):
 p='examples/hia_bootstrap/'+name;b=(S/p).read_bytes();assert sha256(b).hexdigest()==pins[p];report['sources'][p]=digest(b);return b
def wire(sources,tag=b'HIANAM01'):
 o=bytearray(struct.pack('<8sQ',tag,len(sources)))
 for n,b in sources.items():
  e=n.encode();o+=struct.pack('<2Q',len(e),len(b))+e+b
 return bytes(o)
def run(label,image,args,data):
 (D/(label+'.input')).write_bytes(data);fd=os.memfd_create('release-diagnostic-'+label,os.MFD_ALLOW_SEALING);os.write(fd,image);os.fchmod(fd,0o500);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15)
 t=time.monotonic_ns()
 try:r=subprocess.run(['/proc/self/fd/'+str(fd),*args],pass_fds=(fd,),input=data,capture_output=True,env={'PATH':''},cwd=D,timeout=60)
 finally:os.close(fd)
 row={'label':label,'image':digest(image),'input':digest(data),'argv':args,'returncode':r.returncode,'stdout':digest(r.stdout),'stderr':digest(r.stderr),'ns':time.monotonic_ns()-t}
 report['calls'].append(row);(D/(label+'.stdout')).write_bytes(r.stdout);(D/(label+'.stderr')).write_bytes(r.stderr);save();print(json.dumps(row),flush=True)
 assert r.returncode==0 and not r.stderr
 return r.stdout
try:
 seed=(R/'chain/.hia-build-bed45864da51a4a38448d27369efeb15/stage/hia-source-build').read_bytes();report['seed']=digest(seed);assert report['seed']['sha256']=='494833999e25ac74ea6ad1de41235c01bfa036951f212604026cb8be686c78af'
 aliases=['source_build_policy.hepta','selfhost.hepta','source_build_packer.hepta']
 def kit(policy,packer):return {a:source(n) for a,n in zip(aliases,[policy,'selfhost.hepta',packer])}
 bundle=run('composer-sources',seed,['sources'],wire(kit('source_release_kit.hepta','source_build_packer.hepta')))
 composer=run('composer-pack',seed,['pack'],bundle)
 builder=run('frontend-builder',composer,['build'],wire(kit('source_filter_member.hepta','release_build_entry_packer.hepta'),b'HIAKIT01'))
 frame=run('frontend-frame',builder,['build'],wire({'hia-release-build.hepta':source('release_build_entry.hepta'),'sha256_stream.hepta':source('sha256_stream.hepta')},b'HIAMUL01'))
 footer=struct.unpack('<4Q8s',frame[-40:]);elfsize,n1,n2,count,magic=footer;unbound=frame[:elfsize];h=struct.unpack('<22Q',unbound[:176])
 report['footer']={'elfsize':elfsize,'object_sizes':[n1,n2],'count':count,'magic':magic.decode(),'total':len(frame),'valid':elfsize+n1+n2+40==len(frame) and count==2 and magic==b'HIAOBJS1'}
 report['header_words']=list(h)
 checks={0:282584257676671,1:0,2:4299030530,3:4194480,4:64,5:0,6:15762873573703680,7:2,8:21474836481,9:0,10:4194304,11:4194304,12:elfsize,13:elfsize,14:4096,15:27455186257,21:16}
 checks.update({i:0 for i in range(16,21)})
 report['header_checks']=[{'word':i,'expected':v,'actual':h[i],'passed':h[i]==v} for i,v in checks.items()];save()
 binder=run('frontend-binder',composer,['build'],wire(kit('release_build_entry_bind.hepta','source_build_packer.hepta'),b'HIAKIT01'))
 stages=R/'chain/.hia-build-bed45864da51a4a38448d27369efeb15/stage'
 roles=['hia-release-owner','hia-subprocess','hia-source-build','hia-source-capture']
 rawroles=[(stages/n).read_bytes() for n in roles];report['capabilities']={n:digest(b) for n,b in zip(roles,rawroles)}
 bound=run('frontend-bound',binder,['build'],b'HIAENBD1'+b''.join(sha256(b).digest() for b in rawroles)+unbound)
 report['same_size']=len(bound)==len(unbound)
 report['passed']=report['footer']['valid'] and all(x['passed'] for x in report['header_checks']) and report['same_size'];save()
 print('FRONTEND_DIAGNOSTIC',json.dumps({k:report[k] for k in ['footer','header_checks','same_size','passed']}),flush=True)
except BaseException:
 report['error']=traceback.format_exc();save();raise
