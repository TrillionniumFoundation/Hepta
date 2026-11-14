"""Private R8 size/pack support; importing performs no product call."""
from pathlib import Path
import ast
import hashlib
import json
import os
import platform
import stat
import sys
import time
import traceback
ROOT = Path(__file__).resolve().parent
PLAN_PATH = ROOT / 'EXECUTION-PLAN.json'
PLAN_RAW = PLAN_PATH.read_bytes()
PLAN = json.loads(PLAN_RAW)
SOURCE = Path(PLAN['source']['path'])
OUT = Path(PLAN['output'])
CAPACITY = 1 << 20
STAT_KEYS = ('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')

def require(value, message):
    if not value:
        raise AssertionError(message)


def pin(raw, mode=None):
    value = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
             'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}
    if mode is not None:
        value.update(mode=mode, git_mode='100755' if mode & 0o111 else '100644')
    return value


def state(value):
    return {key: getattr(value, key) for key in STAT_KEYS}


def read_regular(path):
    path = Path(path)
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode), 'nonregular fixed file: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        require(state(os.fstat(fd)) == state(before), 'opened fixed file differs')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(before.st_size + 1)
        require(len(raw) == before.st_size and state(os.fstat(fd)) == state(before)
                and state(path.lstat()) == state(before), 'fixed file changed during complete read')
    finally:
        os.close(fd)
    return raw, stat.S_IMODE(before.st_mode), state(before)


def identity(path):
    raw, mode, _ = read_regular(path)
    return pin(raw, mode)


def write(path, raw, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, mode)
    observed, actual_mode, _ = read_regular(path)
    require(observed == raw and actual_mode == mode, 'new evidence readback differs')


def dump(path, value):
    write(path, (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode())


def source_snapshot(destination):
    expected = json.loads((ROOT / 'FROZEN-3180-SOURCE.json').read_bytes())
    files, stamps = {}, {}
    for directory, directories, names in os.walk(SOURCE, followlinks=False):
        directories.sort()
        for name in directories:
            require(stat.S_ISDIR((Path(directory) / name).lstat().st_mode), 'source directory symlink')
        for name in sorted(names):
            path = Path(directory) / name
            relative = path.relative_to(SOURCE).as_posix()
            raw, mode, stamp = read_regular(path)
            require(relative in expected, 'unexpected source path: ' + relative)
            files[relative], stamps[relative] = pin(raw, mode), stamp
    require(files == expected and len(files) == 3180, 'full frozen source bytes/modes differ')
    result = {'files': files, 'inode_states': stamps, 'tree': PLAN['source']['tree'],
              'identity_is_complete_frozen_manifest_equality': True}
    dump(destination, result)
    return result


def same_source(before, destination):
    after = source_snapshot(destination)
    require(before is not None and after == before, 'complete source bytes/modes/inodes changed')
    return {'files': len(after['files']), 'tree': after['tree'], 'whole_before_after_equal': True}


def controls():
    observed = {}
    for key, row in PLAN['controls'].items():
        actual = identity(row['path'])
        require(actual == row['identity'], 'fixed control differs: ' + key)
        observed[key] = actual
    require(PLAN_PATH.read_bytes() == PLAN_RAW, 'fixed execution plan changed')
    return observed


def runtime():
    expected = PLAN['runtime']
    require(sys.version_info[:3] == (3, 14, 4) and sys.executable == expected['executable']['path'],
            'actual interpreter is not the fixed 3.14.4 argv executable')
    require(sys.flags.isolated == 1 and sys.flags.ignore_environment == 1
            and sys.flags.no_site == 1 and sys.flags.dont_write_bytecode == 1,
            'fixed isolated non-site no-bytecode launch flags differ')
    resolved = Path(sys.executable).resolve(strict=True)
    require(str(resolved) == expected['executable']['resolved_path']
            and identity(resolved) == expected['executable']['identity'], 'runtime executable differs')
    require(identity(expected['library']['path']) == expected['library']['identity'], 'fixed libpython differs')
    require(dict(os.environ) == PLAN['environment'] and 'LD_PRELOAD' not in os.environ,
            'runtime environment differs from the complete fixed dictionary')
    require(platform.system() == 'Linux' and platform.machine().lower() in ('x86_64', 'amd64'),
            'fixed Linux x86-64 profile required')
    return {'executable': str(resolved), 'argv_executable': sys.executable, 'version': sys.version,
            'isolated': sys.flags.isolated, 'ignore_environment': sys.flags.ignore_environment,
            'no_site': sys.flags.no_site, 'dont_write_bytecode': sys.flags.dont_write_bytecode,
            'environment': dict(os.environ), 'library': expected['library']}


def function_text(path, name):
    text = Path(path).read_text()
    node = next(node for node in ast.parse(text).body if isinstance(node, ast.FunctionDef) and node.name == name)
    return ''.join(text.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])


def owner_return(receipt_path, returned):
    raw = Path(receipt_path).read_bytes()
    expected = json.loads(raw)
    expected.update(supervisor_returncode=returned.get('supervisor_returncode'),
                    receipt_sha256=hashlib.sha256(raw).hexdigest())
    if expected['supervisor_returncode'] != 0 and expected['status'] == 'OWNED_PROCESS_COMPLETED':
        expected['status'] = 'OWNER_EXIT_MISMATCH_HOLD'
    require(returned == expected, 'actual owner receipt plus wrapper fields differ')


def complete_owner(returned, seconds):
    require(returned['status'] == 'OWNED_PROCESS_COMPLETED' and returned['returncode'] == 0
            and returned['supervisor_returncode'] == 0 and returned['qualification_seconds'] == seconds
            and returned['cleanup_seconds'] == 3 and returned['timed_out'] is False
            and returned['exit_observed_before_deadline'] is True
            and returned['cleanup']['complete'] is True and returned['cleanup']['observed_echild'] is True,
            'qualification or complete descendant cleanup did not pass')


def projection_guard():
    spec = json.loads((ROOT / 'PROJECTION.json').read_bytes())
    for name, row in spec['functions'].items():
        original = function_text(spec['original_builder'], name)
        captured = function_text(ROOT / 'retained_pack_contract.py', name)
        require(original == row['text'] == captured, 'original pack function differs: ' + name)
    for name, row in spec['unchanged_loader_files'].items():
        require(read_regular(ROOT / name)[0] == read_regular(Path(row['origin']))[0]
                and identity(ROOT / name) == row['captured_identity'], 'retained loader changed: ' + name)
    return {'three_original_functions_full_bytes_equal': True, 'loader_files_exact': True,
            'production_R5_pin_changed': False, 'ordinary_SOURCE_rebound': False}


def input_bytes(name):
    return read_regular(ROOT / 'inputs' / name)[0]


def input_guard():
    manifest = json.loads((ROOT / 'INPUTS.json').read_bytes())
    rows = {}
    for row in manifest['files']:
        raw, mode, _ = read_regular(ROOT / row['captured'])
        original, original_mode, original_stat = read_regular(Path(row['origin']))
        require(raw == original and pin(raw,mode) == row['captured_identity']
                and pin(original,original_mode) == row['origin_identity']
                and original_stat == row['origin_stat'], 'actual retained input changed: '+row['captured'])
        rows[row['captured']] = pin(raw,mode)
    extras={'artifact_sha256','case','format','input_bytes','input_sha256','produced_bytes',
            'produced_image','produced_sha256','runner_sha256','wall_elapsed_ns'}
    provider=input_bytes('retained/captured-compiler.image.bin')
    require(pin(provider)['sha256']=='6e8d31b694721b79c693417f0687338bc15277971496f6deaa7ff6e1ed357338',
            'retained ordinary profile provider differs')
    report=json.loads(input_bytes('retained/REPORT.json'))
    require(report['status']=='DEVELOPMENT_BUILD' and report['compiler_sha256']==pin(provider)['sha256']
            and report['matching_cold'] is False, 'retained development provenance differs')
    for label, stage in (('controller',0),('representation',1),('packer',3),('B3',None)):
        folder='u32/' if stage is None else 'retained/'
        image=input_bytes(folder+label+'.image.bin');source=input_bytes(folder+label+'.input.bin')
        output=input_bytes(folder+label+'.output.bin')
        request=json.loads(input_bytes(folder+label+'.request.json'))
        stdout=json.loads(input_bytes(folder+label+'.stdout.log'))
        receipt=json.loads(input_bytes(folder+label+'.receipt.json'))
        expected_provider=pin(image)['sha256'] if stage is None else pin(provider)['sha256']
        require(input_bytes(folder+label+'.stderr.log')==b'', 'old child stderr not empty')
        require(set(receipt)==set(stdout)|extras and all(receipt[k]==v for k,v in stdout.items()),
                'old actual stdout/receipt complete projection differs')
        require(receipt['status']=='returned' and receipt['abi_status']==0
                and receipt['result_u64']==receipt['core_u32']==receipt['produced_bytes']==len(image)
                and receipt['produced_sha256']==pin(image)['sha256']
                and receipt['input_bytes']==len(source) and receipt['input_sha256']==pin(source)['sha256']
                and receipt['source_sha256']==pin(source)['sha256'] and receipt['source_unchanged'] is True
                and receipt['image_sha256']==receipt['artifact_sha256']==expected_provider
                and receipt['forbidden_compiler_modules_loaded']==[], 'old actual compile binding differs')
        require(len(output)==CAPACITY and output[:len(image)]==image
                and output[len(image):]==b'\xa5'*(CAPACITY-len(image))
                and receipt['output_sha256']==pin(output)['sha256'], 'old actual image/output prefix or tail differs')
        require(request['image_sha256']==expected_provider and request['source_sha256']==pin(source)['sha256']
                and request['capacity']==request['workspace_size']==CAPACITY
                and request['workspace_fill']==(90 if stage is None else 0)
                and request['format']=='flat-x86-64', 'old actual compile request differs')
        require(receipt['limits']=={'address_bytes':256<<20,'core_dumpable':False,'cpu_seconds':10,
                'output_capacity':CAPACITY,'stack_bytes':8<<20,'workspace_bytes':CAPACITY}, 'old loader limit differs')
        if stage is not None:
            require(input_bytes(folder+label+'.hepta')==source and report['stages'][stage]==receipt,
                    'retained actual source or build report differs')
    require(input_bytes('u32/B3.input.bin')==read_regular(SOURCE/PLAN['new_source_relative'])[0],
            'u32 B3 actual source differs from frozen 3180 lineage')
    require(pin(input_bytes('u32/B3.image.bin'))['sha256']==
            '56cddd318fbdd7cd269c103fa70c8061d43a3bf9130e877961a5b8af2078c764', 'u32 B3 is not exact hosted image')
    extraction=json.loads((ROOT/'ACTUAL-INPUT-MANIFEST.json').read_bytes())
    require(extraction['source_tree']==PLAN['source']['tree'] and extraction['source_files']==3180,
            'actual original member extraction source lineage differs')
    original_rows={row['name']:row for row in extraction['files']}
    for suffix in ('image.bin','input.bin','output.bin','request.json','receipt.json','stdout.log','stderr.log'):
        name='B3.'+suffix
        row=original_rows[name]
        captured_raw=input_bytes('u32/'+name)
        require(pin(captured_raw)==row['identity']
                and all(row['original_member'][key]==value for key,value in row['identity'].items())
                and all(row['original_NODE'][key]==value for key,value in row['identity'].items())
                and row['original_member']['path']=='retained/'+row['original_NODE']['storage_path']
                and row['original_NODE']['path']=='scope/evidence/full-qualification-r2/qualification.evidence/'+name,
                'actual original ZIP/member/NODE binding differs: '+name)
    old=json.loads(input_bytes('history/R8-REPORT.json'))
    size=json.loads(input_bytes('history/R8-SIZE-RESULT.json'))
    require(old['input_sha256']==pin(input_bytes('R8.hepta'))['sha256']
            and old['image']==size['image']==PLAN['original_R8_history']['image']
            and old['compiler']==PLAN['original_R8_history']['compiler_image']
            and old['actual_compile_count']==size['actual_compile_count']==1
            and old['runtime_semantic_controls_run'] is False and size['aggregate_not_packed'] is True,
            'retained original R8 size-only history differs')
    return {'retained_files':rows,'old_actual_compiler_receipts':4,
            'actual_B3_original_member_bindings':7,'old_R8_history_retained':True,
            'matching_current_new_cold':False,'ordinary_SOURCE_rebound':False}


def observe(label, image_path, source):
    from retained_buffer_observer import native
    require(label in ('compile-r8','pack-r8') and 0<len(source)<=CAPACITY, 'fixed call/extent required')
    image,_,_=read_regular(image_path)
    before=(source,b'\xa5'*CAPACITY,bytes(CAPACITY))
    names=('source','output','workspace')
    folder=OUT/label
    capture=OUT/'frames'/label
    capture.mkdir(parents=True,exist_ok=False)
    frames={'label':label,'status':'STARTED','before':{},'after':{},'errors':[],'image':pin(image)}
    for name,value in zip(names,before,strict=True):
        write(capture/(name+'.before.bin'),value)
        frames['before'][name]=pin(value)
    observed=None
    try:
        observed=native(folder,image_path,*before,b'','ordinary')
    finally:
        for name,value in zip(names,before,strict=True):
            path=folder/(name+'.shared')
            try:
                raw,mode,_=read_regular(path)
                require(len(raw)==len(value)+128,'complete physical span length differs')
                write(capture/(name+'.after.bin'),raw[64:-64])
                frames['after'][name]={'logical':pin(raw[64:-64]),'physical':pin(raw),
                    'mode':mode,'canaries':raw[:64]==b'\xd3'*64 and raw[-64:]==b'\xd3'*64}
            except BaseException as error:
                frames['errors'].append({'name':name,'type':type(error).__name__,'error':str(error)})
        frames['status']='CAPTURED_ALL_SIX' if not frames['errors'] else 'PARTIAL_FAILURE_RETAINED'
        dump(capture/'FRAME.json',frames)
    require(observed is not None and frames['status']=='CAPTURED_ALL_SIX', 'missing actual complete observation')
    child=observed['child'];returned=child.get('result_u64') if type(child)is dict else None
    require(observed['returncode']==0 and observed['timed_out'] is False
            and observed['timeout_seconds']==20 and observed['cleanup_seconds']==3
            and observed['canaries']==[True,True,True]
            and observed['stdout_hex']==observed['stderr_hex']=='' and observed['stdin_consumed']==0
            and observed['source_hex']==source.hex() and type(returned)is int and 0<returned<=CAPACITY,
            'actual native invocation failed original bounds or invariants')
    require(child['status']=='returned' and child['forbidden_modules_loaded']==[]
            and child['image_sha256']==pin(image)['sha256']
            and child['request_sha256']==pin(read_regular(folder/'request.json')[0])['sha256']
            and child['limits']=={'wall_seconds':20,'cpu_seconds':10,'source_output_workspace_bytes':CAPACITY,
                'address_bytes':256<<20,'stack_bytes':8<<20,'core_dumpable':False}, 'actual loader report differs')
    for name,value in zip(names,before,strict=True):
        after=read_regular(capture/(name+'.after.bin'))[0]
        require(after.hex()==observed[name+'_hex'] and frames['after'][name]['canaries'], 'after frame differs')
    output=read_regular(capture/'output.after.bin')[0]
    require(output[returned:]==before[1][returned:], 'real output tail differs from A5 initial bytes')
    require(read_regular(image_path)[0]==image, 'actual selected image changed')
    return output[:returned],{'returned':returned,'image':pin(image),'source':pin(source),
        'six_complete_buffers':True,'three_canaries':True,'source_unchanged':True,'output_tail_unchanged':True,
        'request':identity(folder/'request.json'),'child_report':identity(folder/'CHILD-REPORT.json'),
        'observation':identity(folder/'OBSERVATION.json'),'frames':identity(capture/'FRAME.json')}


def frame_inventory(compiles,packs,require_complete):
    labels=(['compile-r8'] if compiles else [])+(['pack-r8'] if packs else [])
    rows={}
    for label in labels:
        for name in ('source','output','workspace'):
            for when in ('before','after'):
                p=OUT/'frames'/label/(name+'.'+when+'.bin')
                if p.is_file():rows[p.relative_to(OUT).as_posix()]=identity(p)
                else:require(not require_complete,'missing complete actual six-buffer file')
    if require_complete:require(len(labels)==2 and len(rows)==12,'exact two full six-buffer calls required')
    result={'attempted_compiles':compiles,'attempted_packs':packs,'buffer_files':rows,'require_complete':require_complete}
    dump(OUT/'ACTUAL-FRAMES.json',result)
    return result


def raw_inventory():
    rows={}
    for p in sorted(OUT.rglob('*')):
        if p.is_file():rows[p.relative_to(OUT).as_posix()]=identity(p)
        else:require(p.is_dir() and not p.is_symlink(),'nonordinary evidence path')
    result={'files':rows,'count':len(rows),'raw_bytes':sum(row['bytes'] for row in rows.values()),
            'excludes_this_index_itself':True}
    dump(OUT/'RAW-INDEX.json',result)
    return {'files':len(rows),'bytes':result['raw_bytes'],'index':identity(OUT/'RAW-INDEX.json')}
