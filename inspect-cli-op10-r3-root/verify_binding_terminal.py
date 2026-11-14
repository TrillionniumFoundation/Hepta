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
binding_root=Path('/dev/shm/hia-inspect-cli-controls-r3-dda7')
outer_root=Path('/tmp/hia-inspect-cli-controls-r3-preparation-outer-dda7')
OUT=Path('/tmp/hia-root-v141-dda7/op10-r3-sharded-binding-root-terminal.json')
binding_raw=read(binding_root/'BINDING-RESULT.json',0o600)
assert pin(binding_raw)['git_blob']=='c359853cafd7932109ae52cd380c2998999ec0bb'
binding=json.loads(binding_raw)
assert binding['status']=='BOUND_NOT_EXECUTED' and binding['product_execution'] is False
plan_raw=fixed(binding['plan'])
assert pin(plan_raw)['git_blob']=='9858ef43a7b04d4be692f558c990b7130034dd97'
assert plan_raw==read(BASE/'PROPOSED-EXECUTION-PLAN.json',0o644)
p=json.loads(plan_raw)
outer_raw=read(outer_root/'OUTER.json')
assert pin(outer_raw)['git_blob']=='3a314eb9b25f5b6669e985c68c89b822f17efaf8'
outer=json.loads(outer_raw)
before_raw=read(binding_root/'SOURCE-BEFORE.json',0o600)
assert before_raw==read(binding_root/'SOURCE-AFTER.json',0o600)
assert pin(before_raw)['git_blob']=='46707061f2a196468002676e17af51a797c8eaf5'
boundguard=json.loads(before_raw)
assert boundguard['tree']==p['source_tree'] and boundguard['count']==3191
source_map=json.loads(fixed(p['source_manifest']));modes=json.loads(fixed(p['source_modes']))
assert boundguard['modes']==modes
source=Path(p['source']);names=set()
for directory,dirs,files in os.walk(source,followlinks=False):
    for name in dirs: assert not (Path(directory)/name).is_symlink()
    for name in files: names.add((Path(directory)/name).relative_to(source).as_posix())
assert names==set(source_map)==set(modes)
inodes=set();source_bytes=0
for name,row in source_map.items():
    raw=read(source/name,modes[name]);s=(source/name).lstat()
    got=pin(raw);got['mode']='100755' if s.st_mode&0o111 else '100644'
    assert got==row and s.st_nlink==1
    key=(s.st_dev,s.st_ino);assert key not in inodes;inodes.add(key)
    source_bytes+=len(raw)
assert tree(source_map)==p['source_tree']=='65e6f3b81f864f2629e73fc371f2576a67185744'
for key in ('controls','retained_authorities'):
    for d in p[key].values(): fixed(d)
fixed(p['compiler']);fixed(p['predecessor_inspect_image'])
for part in p['predecessor_evidence']['parts']: fixed(part['descriptor'])
fixed(binding['original_bound_plan'])
for path in sorted(outer_root.rglob('*')):
    assert not path.is_symlink()
    if path.is_file(): read(path)
for path,before in seen.items(): assert seven(Path(path).lstat())==before,path
assert not Path(p['attempt']).exists()
assert not Path('/dev/shm/hia-inspect-cli-controls-dda7/attempt-r1').exists()
proof={'schema':'hepta.root.inspect-cli-sharded-binding-terminal.v1','status':'PASS_BOUND_NOT_PRODUCT_EXECUTED',
 'binding':pin(binding_raw),'installed_plan':pin(plan_raw),'installed_plan_posix_mode':0o600,
 'installed_plan_equals_complete_preflight_proposed':True,'actual_outer':outer,
 'source_before_after_raw_equal':pin(before_raw),'current_source_files':len(source_map),
 'current_source_bytes':source_bytes,'current_source_tree':tree(source_map),
 'complete_current_source_bytes_modes_pathset_nlink1_seven_stats':True,
 'actual_controls_and_all_four_parts_still_exact':True,'original_bound_plan_preserved':True,
 'predecessor_whole_rows_readback_prior_root':'a1656cbdb7fe79ead5907586805990c6cb45c856',
 'unique_files_final_seven_stats_checked':len(seen),'product_attempts_absent':True,
 'binder_executions':1,'product_executions':0,'automatic_retry':False,'whole_native':False,
 'elapsed_ns':time.monotonic_ns()-started}
raw=enc(proof)
with OUT.open('xb') as f:f.write(raw)
print(json.dumps({'proof':str(OUT),'pin':pin(raw),'elapsed_seconds':proof['elapsed_ns']/1e9,'outer':outer},sort_keys=True))
