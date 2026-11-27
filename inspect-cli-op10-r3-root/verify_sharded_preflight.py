"""Read-only Root admission of the bounded op10 metadata successor."""
import ast, copy, hashlib, json, os, stat, time
from pathlib import Path
BASE=Path('/tmp/hia-inspect-cli-controls-r3-dda7')
OUT=Path('/tmp/hia-root-v141-dda7/op10-r3-sharded-root-preflight.json')
started=time.monotonic_ns()
seen={}
def seven(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(path, mode=None):
    p=Path(path)
    s=p.lstat()
    assert stat.S_ISREG(s.st_mode) and not p.is_symlink(), str(p)
    with p.open('rb') as f: raw=f.read()
    assert seven(s)==seven(p.lstat()), str(p)
    if mode is not None: assert stat.S_IMODE(s.st_mode)==mode, str(p)
    previous=seen.setdefault(str(p),seven(s))
    assert previous==seven(s),str(p)
    return raw
def pin(raw):
    return {'bytes':len(raw),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),'mode':'100644','sha256':hashlib.sha256(raw).hexdigest()}
def fixed(d):
    raw=read(d['path'],d['posix_mode'])
    assert pin(raw)==d['pin'],d['path']
    return raw
def enc(v):
    return (json.dumps(v,sort_keys=True,indent=2,ensure_ascii=False)+'\n').encode()
def tree(rows):
    root={}
    for name,row in rows.items():
        node=root
        parts=name.split('/')
        for part in parts[:-1]: node=node.setdefault(part,{})
        node[parts[-1]]=(row['mode'],row['git_blob'])
    def walk(node):
        raw=b''
        for name,value in sorted(node.items(),key=lambda kv:(kv[0]+('/' if isinstance(kv[1],dict) else '')).encode()):
            if isinstance(value,dict): mode,digest='40000',walk(value)
            else: mode,digest=value
            raw+=mode.encode()+b' '+name.encode()+b'\0'+bytes.fromhex(digest)
        return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    return walk(root)
request_raw=read(BASE/'PREPARATION-PLAN.json',0o644)
assert pin(request_raw)['git_blob']=='1903e42f7fc025c6e37df3a6fe3472a68b8f057d'
request=json.loads(request_raw)
launch_raw=read(BASE/'PREPARATION-LAUNCH.json',0o644)
assert pin(launch_raw)['git_blob']=='0f528be18a07ad25673e8150eda9f82521d3a5ae'
launch=json.loads(launch_raw)
assert fixed(launch['request'])==request_raw
assert fixed(launch['runner'])==fixed(request['author_files']['bind_sharded_plan.py'])
assert launch['product_executions']==0 and launch['retry'] is False
assert launch['argv']==[
 '/workspace/scratch/dda74a4fae35/v96-union-r13/local-runtime-r1/venv/bin/python3.14',
 '-I','-B',str(BASE/'bind_sharded_plan.py'),'--prepare',str(BASE/'PREPARATION-PLAN.json'),
 '--request-sha256',pin(request_raw)['sha256']]
assert launch['cwd']==str(BASE)
for d in request['author_files'].values(): fixed(d)
proposed_raw=fixed(request['proposed_plan']); old_raw=fixed(request['original_bound_plan'])
assert len(proposed_raw)<=16<<20 and pin(proposed_raw)['git_blob']=='9858ef43a7b04d4be692f558c990b7130034dd97'
assert pin(old_raw)['git_blob']=='3bfc23690e0693f830983e6b1010d08b277166f4'
p=json.loads(proposed_raw);old=json.loads(old_raw)
assert enc(old)==old_raw and enc(p)==proposed_raw
assert sorted(k for k in p if p[k]!=old[k])==['attempt','controls','predecessor_evidence']
extra=('r3_executor','r3_control_support_copy','r3_witness_tests_copy')
assert len(old['controls'])==10 and len(p['controls'])==13
assert {k:v for k,v in p['controls'].items() if k not in extra}==old['controls']
for key,name in zip(extra,('run_inspect_cli_controls.py','inspect_cli_control_support.py','test_inspect_cli_witness_controls.py')):
    assert p['controls'][key]==request['author_files'][name]
for key in ('controls','retained_authorities'):
    for d in p[key].values(): fixed(d)
fixed(p['compiler']);fixed(p['predecessor_inspect_image'])
new_runner=fixed(p['controls']['r3_executor']).decode()
old_runner=fixed(old['controls']['run_inspect_cli_controls.py']).decode()
added_start=new_runner.index('def admit_predecessor_parts(')
added_end=new_runner.index('def execute(',added_start)
inverse_runner=new_runner[:added_start]+new_runner[added_end:]
assert inverse_runner.count('    admit_predecessor_parts(plan)\n')==1
inverse_runner=inverse_runner.replace('    admit_predecessor_parts(plan)\n',"    for row in plan['predecessor_evidence']:\n        fixed(row)\n")
assert inverse_runner==old_runner
a=ast.parse(new_runner);b=ast.parse(old_runner)
af={n.name:ast.get_source_segment(new_runner,n) for n in a.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
bf={n.name:ast.get_source_segment(old_runner,n) for n in b.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))}
assert set(af)==set(bf)|{'admit_predecessor_parts'}
for name in set(bf)-{'execute'}: assert af[name]==bf[name],name
for name,key in [('inspect_cli_control_support.py','r3_control_support_copy'),('test_inspect_cli_witness_controls.py','r3_witness_tests_copy')]:
    assert fixed(p['controls'][key])==fixed(old['controls'][name])
    before=Path(old['controls'][name]['path']).lstat();after=Path(p['controls'][key]['path']).lstat()
    assert (before.st_dev,before.st_ino)!=(after.st_dev,after.st_ino)
rows=[];parts=[];predecessor_bytes=0
value=p['predecessor_evidence']
assert set(value)=={'schema','row_count','ordered_rows_pin','parts'}
assert value['row_count']==61550 and len(value['parts'])==4
for i,part in enumerate(value['parts']):
    assert part['ordinal']==i and part['first_row']==len(rows)
    raw=fixed(part['descriptor'])
    assert len(raw)<=8<<20
    chunk=json.loads(raw);assert len(chunk)==part['row_count']
    for d in chunk:
        predecessor_bytes+=len(fixed(d))
    rows.extend(chunk)
    parts.append({'ordinal':i,'rows':len(chunk),'bytes':len(raw),'pin':pin(raw)})
assert len(rows)==61550 and rows==old['predecessor_evidence']
assert pin(enc(rows))==value['ordered_rows_pin']
inverse=copy.deepcopy(p);inverse['attempt']=old['attempt'];inverse['predecessor_evidence']=rows
for key in extra: del inverse['controls'][key]
assert enc(inverse)==old_raw
source=Path(p['source'])
source_map=json.loads(fixed(p['source_manifest']));modes=json.loads(fixed(p['source_modes']))
assert len(source_map)==3191 and set(source_map)==set(modes)
actual_names=set()
for directory,dirs,files in os.walk(source,followlinks=False):
    for name in dirs: assert not (Path(directory)/name).is_symlink()
    for name in files: actual_names.add((Path(directory)/name).relative_to(source).as_posix())
assert actual_names==set(source_map)
source_bytes=0;inodes=set()
for name,expected in source_map.items():
    path=source/name;raw=read(path,modes[name]);s=path.lstat()
    assert s.st_nlink==1
    identity=(s.st_dev,s.st_ino);assert identity not in inodes;inodes.add(identity)
    got=pin(raw);got['mode']='100755' if s.st_mode&0o111 else '100644'
    assert got==expected,name
    source_bytes+=len(raw)
assert tree(source_map)==p['source_tree']=='65e6f3b81f864f2629e73fc371f2576a67185744'
for name,expected in p['adapter_files'].items(): assert source_map[name]==expected
runtime=[]
for key in ('executable','library'):
    d=p['runtime'][key];path=Path(d['path']).resolve()
    raw=read(path,d['mode']);s=path.stat()
    assert len(raw)==d['bytes'] and hashlib.sha256(raw).hexdigest()==d['sha256']
    for item,actual in [('device',s.st_dev),('inode',s.st_ino),('ctime_ns',s.st_ctime_ns),('mtime_ns',s.st_mtime_ns)]:
        assert actual==d[item],(key,item)
    runtime.append({'kind':key,'path':str(path),'bytes':len(raw),'sha256':d['sha256'],'stat':seven(s)})
assert p['limits']=={'owner_seconds':180,'cleanup_seconds':3,'compile_seconds':20,'image_bytes':1048576,'vm_steps':10000000,'storage_free_bytes':1073741824}
assert len(p['group_order'])==18 and len(p['groups'])==18
assert sum(len(g['ids']) for g in p['groups'].values())==76
assert sum(g.get('real_compile_calls',0) for g in p['groups'].values())==7
assert not Path(request['new_root']).exists() and not Path(p['attempt']).exists() and not Path(old['attempt']).exists()
free=os.statvfs('/dev/shm').f_bavail*os.statvfs('/dev/shm').f_frsize
assert free>=(1<<30)+source_bytes+(32<<20)
for path,before in seen.items(): assert seven(Path(path).lstat())==before,path
proof={'schema':'hepta.root.inspect-cli-sharded-preflight.v1','status':'PASS_READ_ONLY_NO_BINDER_NO_PRODUCT',
 'request':pin(request_raw),'launch':pin(launch_raw),'proposed_plan':pin(proposed_raw),'original_plan':pin(old_raw),
 'new_runner':pin(new_runner.encode()),'whole_runner_inverse_equal':True,'unchanged_original_functions':sorted(set(bf)-{'execute'}),
 'original_10_and_actual_3_runtime_controls_fixed':True,'all_predecessor_rows':len(rows),'predecessor_bytes_including_duplicate_rows':predecessor_bytes,
 'all_predecessor_full_bytes_modes_seven_stats_and_order_verified':True,'parts':parts,'complete_plan_inverse_equal':True,
 'source':str(source),'source_files':len(source_map),'source_bytes':source_bytes,'source_tree':p['source_tree'],
 'source_full_bytes_modes_pathset_and_independent_nlink1_inodes_verified':True,'runtime':runtime,'limits':p['limits'],
 'groups':18,'method_invocations':76,'real_compile_calls':7,'all_original_ids_order_budgets_retained':True,
 'original_cli43_B_flag_retained':"flags = ['-B'] if label == 'original-cli43' else ['-I', '-B']" in new_runner,
 'current_unique_file_seven_stats_rechecked':len(seen),'shm_free_bytes':free,
 'product_executions':0,'binder_executions':0,'default_activated':False,'whole_native':False,
 'elapsed_ns':time.monotonic_ns()-started}
assert proof['original_cli43_B_flag_retained']
raw=enc(proof)
with OUT.open('xb') as f: f.write(raw)
print(json.dumps({'proof':str(OUT),'pin':pin(raw),'elapsed_seconds':proof['elapsed_ns']/1e9,'unique_files':len(seen)},sort_keys=True))
