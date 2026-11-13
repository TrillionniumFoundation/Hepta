"""Freeze finite WAL snapshot native inputs by complete stdlib-only byte reads.
No HIA author, original test, Core VM, compiler, oracle, or native code executes.
"""
from pathlib import Path
import ast,hashlib,json,os,platform,stat,sys,time

ROOT=Path(__file__).resolve().parents[1]
P=ROOT.parent
DONOR=P/'sqlite-wal-native-r2'
OUTPUT=P/'sqlite-wal-snapshot-native-r1-actual'
EXPECTED_ROOT=P/'sqlite-wal-snapshot-native-r1'
IDENTITY_KEYS=('bytes','sha256','git_blob','identity')
def require(value,message):
    if not value:raise RuntimeError(message)
def identity(s):
    return [s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns]
def read(path,system=False):
    path=Path(path)
    require(path.is_absolute() and path.resolve(strict=True)==path,'fixed nonalias input '+str(path))
    s=path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_size<=128<<20,'bounded regular input')
    if system:
        require(s.st_uid==0 and s.st_nlink>=1 and not s.st_mode&0o022,'root-owned read-only system role')
    else:
        require(s.st_uid==os.getuid() and s.st_gid==os.getgid() and s.st_nlink==1 and not s.st_mode&0o022,'owned single-link input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        require(identity(os.fstat(fd))==identity(s),'opened identity')
        pieces=[];count=0;sha=hashlib.sha256();git=hashlib.sha1(b'blob '+str(s.st_size).encode()+b'\0')
        while True:
            b=os.read(fd,1<<20)
            if not b:break
            count+=len(b);require(count<=s.st_size,'input grew')
            pieces.append(b);sha.update(b);git.update(b)
        require(count==s.st_size and identity(os.fstat(fd))==identity(s)==identity(path.lstat()),'full read identity changed')
    finally:os.close(fd)
    return {'path':str(path),'bytes':count,'sha256':sha.hexdigest(),'git_blob':git.hexdigest(),'identity':identity(s)},b''.join(pieces)
def wire(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def create(path,value):
    body=value if type(value)is bytes else wire(value)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb')as f:f.write(body);f.flush();os.fsync(f.fileno())
    pin,actual=read(path);require(actual==body,'new metadata readback')
    return pin
def exact(pin,expected,label):
    require(all(pin[k]==expected[k] for k in IDENTITY_KEYS),'frozen input changed '+label)
def file_set(root):
    found=set()
    for base,dirs,names in os.walk(root,followlinks=False):
        for name in dirs:
            q=Path(base)/name;require(stat.S_ISDIR(q.lstat().st_mode),'symlink/special directory')
        for name in names:
            q=Path(base)/name;require(stat.S_ISREG(q.lstat().st_mode),'nonregular source')
            found.add(str(q.relative_to(root)))
    return found

require(ROOT==EXPECTED_ROOT and not os.path.lexists(OUTPUT),'new exact absent output')
for name in ('REQUEST.json','LAUNCH.json','STATIC-FREEZE.json','PREEXEC.json'):
    require(not os.path.lexists(ROOT/name),'metadata already exists '+name)
require(sys.version_info[:3]==(3,14,4) and sys.platform=='linux' and platform.machine()=='x86_64'
    and sys.flags.isolated==1 and sys.flags.no_site==1 and sys.dont_write_bytecode,'fixed static runtime')
started=time.monotonic_ns()
dp,dr=read(DONOR/'REQUEST.json')
require(dp['sha256']=='f81436adba2e858327e474facfbf54476100d8d046e5eb8fcdf92a7488d52e92','old WAL request pin')
old=json.loads(dr)
runtime,_=read(Path(sys.executable).resolve(),system=True)
require(runtime==old['runtime'] and sys.version==old['python_version']
    and Path('/proc/sys/kernel/random/boot_id').read_text().strip()==old['boot_id'],'same bound ai395 runtime/boot')
sp,sraw=read(ROOT/'SOURCE-BASE.json')
require(all(sp[k]==old['inputs']['SOURCE-BASE.json'][k] for k in ('bytes','sha256','git_blob')),'original source inventory bytes')
source=json.loads(sraw)
require(source['source_commit']==old['source_commit']=='0504beb11c0dae875d8590660c42488b7bc634fb'
    and source['source_tree']==old['source_tree']=='596ab07e8813e4811a8dca51800cd51eb397aeb2'
    and source['source_root']==old['source_root'] and source['input_count']==len(source['files'])==1686
    and source['bytes']==40890650,'fixed full physical source population')
source_names=set();source_bytes=0
for row in source['files']:
    name=row['path']
    require(type(name)is str and not name.startswith('/') and '..'not in Path(name).parts and name not in source_names,'source unique relative path')
    p,_=read(Path(source['source_root'])/name);exact(p,row,name)
    require(('100755'if p['identity'][2]&0o111 else'100644')==row['mode'],'source Git mode')
    source_names.add(name);source_bytes+=p['bytes']
require(source_names==file_set(Path(source['source_root'])) and source_bytes==40890650,'complete source namespace')
yp,yraw=read(ROOT/'SYSTEM-INPUTS.json')
require(all(yp[k]==old['inputs']['SYSTEM-INPUTS.json'][k] for k in ('bytes','sha256','git_blob')),'original system inventory bytes')
system=json.loads(yraw)
require(system['host']=='ai395' and system['count']==len(system['files'])==old['system_count']==4806
    and system['bytes']==old['system_bytes']==179325490,'complete system population')
system_names=set();system_bytes=0
for row in system['files']:
    p,_=read(row['path'],system=True)
    require(p==row and p['path']not in system_names,'system input differs')
    system_names.add(p['path']);system_bytes+=p['bytes']
for alias,target in system['aliases'].items():
    require(str(Path(alias).resolve(strict=True))==target,'system alias target')
require(system_bytes==179325490,'system total bytes')
control_pins=json.loads(read(ROOT/'CONTROL-PINS.json')[1])['controls']
require(len(control_pins)==12 and {str(x.relative_to(ROOT))for x in (ROOT/'control').iterdir()}==set(control_pins),'exact twelve control files')
controls={}
for name,expected in control_pins.items():
    p,b=read(ROOT/name)
    require(all(p[k]==expected[k]for k in ('bytes','sha256','git_blob')),'stopped control changed')
    ast.parse(b,filename=name);controls[name]=p
original_tests=ROOT/'candidate/inputs/tests/test_hia_sqlite_wal_snapshot_source.py'
tp,tb=read(original_tests)
require(tp['bytes']==27618 and tp['sha256']=='2bde9e21ca1de533449658464edea5dcd1597d9e880d9c9dfa0e1fab3cb10659','original twelve test full bytes')
cls=[x for x in ast.parse(tb).body if isinstance(x,ast.ClassDef)and x.name=='SQLiteWalSnapshotSourceTests']
require(len(cls)==1,'original class')
names=[x.name for x in cls[0].body if isinstance(x,ast.FunctionDef)and x.name.startswith('test_')]
mp,mraw=read(ROOT/'EXPECTED-MATRIX.json');matrix=json.loads(mraw)
require(mp['bytes']==682670 and mp['sha256']=='3dd86711aae8526ce2aa6660277050d66d198dee0ed87709e9b9b2c2918ca35c','fixed complete matrix')
ids=list(matrix['counts'])
require(ids[:12]==['tests.hia_sqlite_wal_snapshot_source_r1.SQLiteWalSnapshotSourceTests.'+x for x in names]
    and len(names)==12 and len(ids)==13
    and ids[12]=='tests.hia_wal_snapshot_native_pages_r1.FullPageSizesNativeTests.test_13_complete_frames_lookup_and_recovery_all_page_sizes'
    and list(matrix['counts'].values())==[0,76,46,141,108,136,24,43,7,13,14,0,2096]
    and sum(matrix['counts'].values())==2704 and matrix['populations']['original12']==608
    and matrix['C_calls_each']==639 and matrix['combined_trace_bytes']==203187698,'all fixed method/native/C populations')
require(matrix['streams']=={
    'hia':{'bytes':58947530,'maximum_record_bytes':132553,'records':5408,'sha256':'3cc9223d34768fb1c0062a6e918cec782a749246a6843eed9c0c597f0facecfe'},
    'C':{'bytes':144240168,'maximum_record_bytes':676506,'records':2556,'sha256':'669fdac758781c872037a68be496a08770d1caa6d1b8a9d650eeff5f1a67cbf3'}},'exact whole trace expectation')
# This is only a static preparation resource observation; launch repeats the fixed gate.
fs=os.statvfs(ROOT.parent)
capacity={'device':ROOT.parent.stat().st_dev,'free_bytes':fs.f_bavail*fs.f_frsize,'free_inodes':fs.f_favail,
    'initial_required_bytes':1<<30,'reserve_required_bytes':512<<20,'required_inodes':4096}
require(capacity['free_bytes']>=1<<30 and capacity['free_inodes']>=4096,'original capacity gate')
frozen={
 'schema':'hia.wal-snapshot.native-static-freeze.v1','status':'NATIVE_UNEXECUTED',
 'scope':'Complete stdlib file/AST reads only; no generation, original tests, VM, compiler, oracle or native execution.',
 'root':str(ROOT),'output':str(OUTPUT),'output_absent':True,'runtime':runtime,'python_version':sys.version,'boot_id':old['boot_id'],
 'original_WAL_native_request':dp,'source':{'map':sp,'files':1686,'bytes':source_bytes,'whole_namespace_verified':True},
 'system':{'map':yp,'files':4806,'bytes':system_bytes,'whole_namespace_roles_verified':True},
 'stopped_controls':controls,'original_test':tp,'matrix':mp,'ids':ids,'native_counts':matrix['counts'],
 'native_returns':2704,'C_calls_each':639,'whole_trace_bytes':203187698,'capacity_observation':capacity,
 'elapsed_ns':time.monotonic_ns()-started}
freeze_pin=create(ROOT/'STATIC-FREEZE.json',frozen)
# All regular inputs existing before the request, including all authoring receipts.
# No permission or identity changes are made after these pins.
inputs={}
for name in sorted(file_set(ROOT)):
    require(name not in ('REQUEST.json','LAUNCH.json','PREEXEC.json'),'future metadata already present')
    inputs[name]=read(ROOT/name)[0]
require(set(n for n in inputs if n.startswith('control/'))==set(control_pins),'complete control closure')
environment=dict(old['environment']);environment['TMPDIR']=str(OUTPUT/'tmp')
request={k:old[k]for k in ('boot_id','cleanup_seconds','compiler_cpu_seconds','compiler_output_capacity','compiler_wall_seconds',
 'compiler_workspace_bytes','development_compiler','free_inodes','gid','host','initial_free_bytes','original_caps',
 'original_child_sha256','output_bytes_limit','output_files_limit','python_version','qualification_seconds',
 'reserve_free_bytes','runtime','source_commit','source_map','source_root','source_tree','system_binaries',
 'system_bytes','system_count','system_map','trace_bytes_limit','trace_chunk_limit','trace_record_limit','uid')}
request.update({
 'schema':'hia.wal-snapshot.native-finite-request.v1','status':'SNAPSHOT_ORIGINAL12_PLUS_FULL_PAGES_NATIVE_UNEXECUTED',
 'root':str(ROOT),'output':str(OUTPUT),
 'command':[runtime['path'],'-I','-S','-B',str(ROOT/'control/worker.py'),str(ROOT/'REQUEST.json'),'@REQUEST_SHA256@'],
 'environment':environment,'inputs':inputs,'expected_ids':ids,'expected_methods':13,'native_counts':matrix['counts'],
 'native_returns':2704,'original_source_methods':12,'original_VM_calls':608,'original_VM_actual_retained':True,
 'original_test_bytes':tp['bytes'],'original_test_sha256':tp['sha256'],
 'source12_request_commit':'d217e137db1b46b70199a56d7c9cde94811b68f4',
 'source12_actual_commit':'9f2aed8b240ebe70a3de8084f062fae04f93709d','source12_VM_reexecute':False,
 'added_full_page_method_count':1,'added_full_page_scenarios':144,'added_full_page_native_calls':2096,
 'C_calls_each':639,'C_original_drives_each':175,'C_full_page_drives_each':464,
 'C_domain':'Frozen finite full WAL or fixed snapshot prefix <=8 MiB, chosen without HIA status; excluded original protocol/large-extent cases still execute in HIA.',
 'C_raw_recording':'Record complete source before/after, all32 raw words and all read-pair buffer before/after first; then independently apply accepted snapshot and database-page projection.',
 'new_same_owner_source_generation':False,'original_test_independent_reemission_retained':True,
 'actual_HIA_source':inputs['reference/source12-actual/sqlite_wal_snapshot.hiaasm'],
 'trace_expected':matrix['streams'],'trace_expected_total_bytes':matrix['combined_trace_bytes'],
 'old_WAL_native_request':dp,'static_freeze':freeze_pin,
 'scope':'Original12/608 plus one independent144-scenario full-page method/2096 calls and two639-call original C recovery/find oracles. Historicaldevelopment B3 only. No matching-current-cold, SQL, locks, database I/O, checkpoint, transactions, crash-durability or AgentStore activation claim.',
 'stage_order':['one_HIA_compile_20wall_10CPU_1MiB','two_C_compiles_each20wall_10CPU_1MiB','one_native_child_original12_plus_full_page1','whole_trace_reread_inside_same180_owner','exact_input_source_system_after_reads'],
 'forbidden':'No retry, extra qualification time, substituted B3, VM execution, method omission, partial-trace acceptance or failed-C-domain inferred from HIA status.'
})
qpin=create(ROOT/'REQUEST.json',request)
command=[runtime['path'],'-I','-S','-B',str(ROOT/'control/clean_exec.py'),str(ROOT/'REQUEST.json'),qpin['sha256']]
launch={
 'schema':'hia.wal-snapshot.native-launch.v1','status':'UNEXECUTED','host':'ai395',
 'executable':runtime['path'],'args':command[1:],'command':command,'cwd':str(ROOT),
 'environment':environment,'request':qpin,'clean_exec':inputs['control/clean_exec.py'],
 'root':str(ROOT),'output':str(OUTPUT),'owner':{'qualification_seconds':180,'cleanup_seconds':3,'implementation':inputs['control/process_owner_impl.py']},
 'unique_execution':'Root only. The outer wrapper may invoke once. A transport UNKNOWN is reconciled from that same job; never replay the request.',
 'purpose':'One finite development-native qualification only; no CI or production activation.'
}
lpin=create(ROOT/'LAUNCH.json',launch)
preexec={
 'schema':'hia.wal-snapshot.native-preexec.v1','status':'FROZEN_UNEXECUTED','request':qpin,'launch':lpin,
 'inputs':len(inputs),'input_bytes':sum(x['bytes']for x in inputs.values()),'source_files':1686,'source_bytes':40890650,
 'system_files':4806,'system_bytes':179325490,'controls':12,'original_source_methods':12,'original_VM_calls':608,
 'new_methods':1,'new_full_page_scenarios':144,'new_full_page_native_calls':2096,'all_methods':13,'native_returns':2704,
 'C_calls_each':639,'trace_bytes':203187698,'output_absent':not os.path.lexists(OUTPUT),
 'qualification_seconds':180,'cleanup_seconds':3,'compiler_wall_seconds':20,'compiler_CPU_seconds':10,
 'compiler_output_and_workspace_each':1<<20,'capacity_observation':capacity,
 'no_frozen_input_metadata_mutations':True,
 'limitations':['native not executed','actual Source12 source/VM pass not promoted','historical compiler not matching cold',
                'finite C oracle does not provide external locking, IO, SQL, checkpoint, transactions or crash durability']}
ppin=create(ROOT/'PREEXEC.json',preexec)
for name,expected in inputs.items():exact(read(ROOT/name)[0],expected,name)
require(not os.path.lexists(OUTPUT),'static freeze created no actual output')
print(json.dumps({'status':'FROZEN_UNEXECUTED','request':qpin,'launch':lpin,'preexec':ppin,
 'input_count':len(inputs),'input_bytes':sum(x['bytes']for x in inputs.values()),
 'source_count':1686,'system_count':4806,'expected_methods':13,'native_returns':2704,
 'C_calls_each':639,'trace_bytes':203187698,'capacity':capacity},sort_keys=True))
