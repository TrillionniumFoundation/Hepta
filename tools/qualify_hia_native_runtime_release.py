from pathlib import Path
from hashlib import sha256
import fcntl,json,os,struct,subprocess,sys,traceback
import argparse
ap=argparse.ArgumentParser();ap.add_argument('--compiler',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
F=Path(__file__).resolve().parents[1];D=args.output.resolve()
D.mkdir(mode=0o700,parents=True,exist_ok=False);sys.path.insert(0,str(F))
from tools.generate_hia_native_runtime_release import build_recipe,BOOT,FILTER_POLICY
from tools.build_hia_source_build import _named_source_request
from tools.build_hia_native_store_release import _kit_with_objects
compiler=args.compiler.resolve()
recipe=json.loads((F/'docs/HIA_NATIVE_NDU_EVALUATOR_RECIPE.json').read_text())
receipt=json.loads((F/'docs/HIA_NATIVE_NDU_EVALUATOR_BUILD.json').read_text())
report={'schema':'hepta.hia.native-runtime-release-stage-qualification.v1','passed':False,
 'scope':'Actual native construction of frozen NDU public products from current HIA sources; complete native release and final cold gates remain separate.',
 'full_release_pass':False,'whole_public_runtime_closed':False,'source_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=F,text=True).strip(),'sources':{},'calls':[],'checks':[]}
def save(): (D/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
fds=[]
def seal(name,raw):
 fd=os.memfd_create(name,os.MFD_ALLOW_SEALING);os.write(fd,raw);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15)
 assert fcntl.fcntl(fd,fcntl.F_GET_SEALS)==15;fds.append(fd);return fd
root=compiler.read_bytes()
assert sha256(root).hexdigest()==receipt['build_inputs']['compiler']['sha256']
assert len(root)==receipt['build_inputs']['compiler']['bytes']
rootfd=seal('runtime-source-builder',root)
def run(fd,args,data,refused=False):
 p=subprocess.run(['/proc/self/fd/'+str(fd),*args],pass_fds=(fd,),input=data,capture_output=True,timeout=120,env={'PATH':'','LANG':'C','LC_ALL':'C'})
 report['calls'].append({'image_sha256':sha256(os.pread(fd,os.fstat(fd).st_size,0)).hexdigest(),'argv':args,'input_bytes':len(data),'input_sha256':sha256(data).hexdigest(),'returncode':p.returncode,'stdout_bytes':len(p.stdout),'stdout_sha256':sha256(p.stdout).hexdigest(),'stderr_bytes':len(p.stderr)})
 if refused: assert p.returncode!=0 and not p.stdout,(p.returncode,p.stdout[:100],p.stderr[:500])
 else: assert p.returncode==0 and not p.stderr,(p.returncode,p.stderr[:1000])
 return p.stdout
def keep(name,data):
 p=D/name;p.write_bytes(data);p.chmod(0o500);return seal(name,data)
try:
 r,paths,resources=build_recipe();raw=r.binary()
 assert raw==(F/'examples/hia_bootstrap/release_stage_runtime.hiastd').read_bytes()
 report['recipe']={'sha256':sha256(raw).hexdigest(),'bytes':len(raw),'nodes':len(r.nodes),'handles':r.next_handle-1,'published':r.published}
 sources={p:(F/p).read_bytes() for p in set(paths)|{BOOT+'selfhost.hepta',BOOT+'source_release_kit.hepta',BOOT+'source_build_packer.hepta'}}
 images={}
 for path in sorted(sources):
  data=sources[path];a=run(rootfd,['compile'],data);b=run(rootfd,['compile'],data);assert a==b
  images[path]=a;(D/(Path(path).name+'.flat')).write_bytes(a)
  report['sources'][path]={'bytes':len(data),'sha256':sha256(data).hexdigest(),'flat_bytes':len(a),'flat_sha256':sha256(a).hexdigest(),'two_native_compilations_equal':True}
 for row in recipe['compile']['roles']:
  entry=report['sources'][row['source_path']]
  assert entry['bytes']==row['source_bytes'] and entry['sha256']==row['source_sha256']
  assert entry['flat_bytes']==row['flat_bytes'] and entry['flat_sha256']==row['flat_sha256']
 report['checks'].append('all-five-frozen-source-and-flat-pins')
 for path,pin in receipt['source_files'].items():assert sha256((F/path).read_bytes()).hexdigest()==pin,path
 report['checks'].append('all-eleven-frozen-runtime-source-pins')
 aliases=('source_build_policy.hepta','selfhost.hepta','source_build_packer.hepta')
 roots=('source_release_kit.hepta','selfhost.hepta','source_build_packer.hepta')
 bundle=run(rootfd,['sources'],_named_source_request({a:sources[BOOT+b] for a,b in zip(aliases,roots,strict=True)}))
 composer_raw=run(rootfd,['pack'],bundle);composer=keep('actual-native-kit-composer',composer_raw)
 names={a:sources[BOOT+b] for a,b in zip(aliases,(FILTER_POLICY,'selfhost.hepta','native_filter_packer.hepta'),strict=True)}
 framed=run(composer,['build'],_named_source_request(names,tag=b'HIAKOBJ1'))
 builder_raw,objects=_kit_with_objects(framed)
 for alias,body in names.items():assert objects[alias]==run(rootfd,['compile'],body)
 builder=keep('actual-native-filter-builder',builder_raw)
 packerflat=images[BOOT+'ndu_evaluator_packer.hepta']
 wrapper=run(builder,['build'],b'HIANPF01'+struct.pack('<2Q',1,len(packerflat))+packerflat)
 assert sha256(wrapper).hexdigest()==receipt['build_inputs']['packer_wrapper_sha256']
 packer=keep('actual-ndu-evaluator-packer',wrapper)
 parts=[images[next(row['source_path'] for row in recipe['compile']['roles'] if row['role']==name)] for name in recipe['pack']['tail_roles']]
 wire=b'HIANDP01'+struct.pack('<5Q',*[len(x) for x in parts],0)+b''.join(parts)
 image=run(packer,[],wire)
 assert len(image)==receipt['binary_bytes'] and sha256(image).hexdigest()==receipt['binary_sha256']
 imagefd=keep('hia-ndu-evaluator',image)
 (D/'hia-ndu-evaluator-build.json').write_bytes((F/'docs/HIA_NATIVE_NDU_EVALUATOR_BUILD.json').read_bytes())
 report['checks'].append('complete-frozen-wrapper-and-product-byte-identity')
 for name,at in [('magic',0),('reserved',40),('first-length',8)]:
  bad=bytearray(wire);bad[at]^=1;run(packer,[],bad,True);report['checks'].append('native-packer-reject-'+name)
 for name,bad in [('short',wire[:-1]),('tail',wire+b'x')]:
  run(packer,[],bad,True);report['checks'].append('native-packer-reject-'+name)
 request={'schema': 'hepta.hia.ndu-request.v1', 'objective_sha256': '1111111111111111111111111111111111111111111111111111111111111111', 'generation': 1, 'resource_cap_q32': 4294967296, 'candidates': [{'id': 'abstain', 'cost_q32': 0, 'uncertainty_q32': 0, 'resource_q32': 0, 'hard_violation': False, 'support_sha256': '1111111111111111111111111111111111111111111111111111111111111111'}]}
 actual=run(imagefd,[],json.dumps(request,separators=(',',':')).encode())
 (D/'actual-empty-response.json').write_bytes(actual);value=json.loads(actual)
 assert value['schema']=='hepta.hia.ndu-native-response.v1' and value['entry_point']=='hepta.hia.ndu_evaluator.v1',value
 report['checks'].append('actual-public-native-entry');report['prior_fixture_failure']='v1 actual empty/cap0 request and follow-up missing abstain fixture correctly refused rc2; all source, flat, wrapper and image pins had matched; unchanged product and original failures retained'
 for path,data in sources.items():assert (F/path).read_bytes()==data
 for path,pin in receipt['source_files'].items():assert sha256((F/path).read_bytes()).hexdigest()==pin
 report['checks'].append('all-source-post-read-stable')
 report['actual_tools']={'compiler':{'bytes':len(root),'sha256':sha256(root).hexdigest()},'kit_composer':{'bytes':len(composer_raw),'sha256':sha256(composer_raw).hexdigest()},'filter_builder':{'bytes':len(builder_raw),'sha256':sha256(builder_raw).hexdigest()},'packer':{'bytes':len(wrapper),'sha256':sha256(wrapper).hexdigest()}}
 report['products']={n:{'bytes':(D/n).stat().st_size,'sha256':sha256((D/n).read_bytes()).hexdigest()} for n in r.published}
 report['frozen_receipt_not_relabelled']=True;report['preserved_v2_fixture_failure']='v2 incorrectly asserted the old Rust response schema; actual qualified native schema and explicit HIA entry point are preserved';report['count']=len(report['checks']);report['passed']=True;save()
 print('PASS',report['count'],report['products'],flush=True)
except BaseException:
 report['failure']=traceback.format_exc();save();raise
finally:
 for fd in fds:os.close(fd)
