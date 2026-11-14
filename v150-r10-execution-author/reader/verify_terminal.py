from pathlib import Path
import ast,base64,hashlib,json,os,stat,sys,time,traceback,zlib
AUTHOR=Path('/tmp/hia-r10-execution-author-r1-dda7')
PLAN_RAW=(AUTHOR/'PREFIX-PLAN.json').read_bytes()
PLAN=json.loads(PLAN_RAW)
SOURCE=Path(PLAN['source']['path'])
EXEC=Path('/tmp/hia-r10-prefix-independent-readback-r1-dda7')
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
def require(value, message):
    if not value: raise ValueError(message)


def encode(value):
    return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def pin(raw,mode=None):
    result={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
    if mode is not None: result.update(mode=mode,git_mode='100755' if mode&0o111 else '100644')
    return result


def seven(s):
    return [getattr(s,k) for k in FIELDS]


def read(path):
    path=Path(path)
    for parent in reversed(path.parents):
        require(stat.S_ISDIR(parent.lstat().st_mode),'input ancestor is not a real directory')
    before=path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink==1,'input is not an independent regular file')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        require(seven(os.fstat(fd))==seven(before),'opened input changed')
        chunks=[];left=before.st_size+1
        while left:
            part=os.read(fd,min(left,1048576))
            if not part: break
            chunks.append(part);left-=len(part)
        raw=b''.join(chunks)
        require(len(raw)==before.st_size and seven(os.fstat(fd))==seven(before)==seven(path.lstat()),'input changed while reading')
    finally: os.close(fd)
    return raw,stat.S_IMODE(before.st_mode),seven(before)


def identity(path):
    raw,mode,stamp=read(path)
    return {'identity':pin(raw,mode),'seven_stats':stamp,'path':str(path)}


def fixed(row):
    raw,mode,stamp=read(row['path'])
    require(pin(raw,mode)==row['identity'],'fixed bytes or mode differ: '+row['path'])
    if 'seven_stats' in row: require(stamp==row['seven_stats'],'fixed seven-stat identity differs')
    return raw,stamp


def mkdir(path):
    path=Path(path)
    require(path.is_absolute() and EXEC in (path,*path.parents),'output is outside explicit execution root')
    chain=list(reversed(path.parents))+[path]
    for q in chain:
        try:s=q.lstat()
        except FileNotFoundError:
            require(q==EXEC or EXEC in q.parents,'cannot create outside execution root')
            q.mkdir(mode=0o700);s=q.lstat()
        require(stat.S_ISDIR(s.st_mode),'output ancestor is not a real directory')


def write(path,raw,mode=0o644):
    path=Path(path);mkdir(path.parent)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
    path.chmod(mode)
    actual,m,_=read(path)
    require(actual==raw and m==mode,'new output readback differs')


def dump(path,value):
    write(path,encode(value))


def controls_guard():
    observed={}
    for name,row in PLAN['fixed_controls'].items():
        _,stamp=fixed(row);observed[name]={'identity':row['identity'],'seven_stats':stamp}
    for name,row in PLAN['author_files'].items():
        raw,mode,stamp=read(AUTHOR/name)
        require(pin(raw,mode)==row,'author control differs: '+name)
        observed['author:'+name]={'identity':row,'seven_stats':stamp}
    require(read(AUTHOR/'PREFIX-PLAN.json')[0]==PLAN_RAW,'prefix plan changed')
    return observed


def snapshot(path,names=None):
    raw,_=fixed(PLAN['fresh_mapping'])
    mapping=json.loads(raw);groups=[];total=0;count=0
    for group in mapping['groups']:
        if names is not None and group['name'] not in names: continue
        root=Path(group['root']);files={};directories={}
        for here,children,leaves in os.walk(root,followlinks=False):
            here=Path(here);s=here.lstat();rel=here.relative_to(root).as_posix()
            require(stat.S_ISDIR(s.st_mode) and rel in group['directories'],'unexpected directory')
            before=group['directories'][rel]
            require(stat.S_IMODE(s.st_mode)==before['mode'] and seven(s)==before['seven_stats'],'directory changed')
            directories[rel]={'mode':stat.S_IMODE(s.st_mode),'seven_stats':seven(s)}
            for child in children:require(stat.S_ISDIR((here/child).lstat().st_mode),'directory alias')
            for name in sorted(leaves):
                p=here/name;relative=p.relative_to(root).as_posix()
                require(relative in group['files'],'unexpected fixed path')
                row=group['files'][relative];b,mode,stamp=read(p)
                require(pin(b,mode)==row['identity'] and stamp==row['seven_stats'],'fresh fixed payload differs: '+relative)
                files[relative]={'identity':pin(b,mode),'seven_stats':stamp}
                total+=len(b);count+=1
        require(set(files)==set(group['files']) and directories==group['directories'],'complete group pathset differs')
        groups.append({'name':group['name'],'root':str(root),'files':files,'directories':directories})
    if names is None:
        extras=[]
        for row in mapping['extra_authorities']:
            b,stamp=fixed(row);extras.append({'path':row['path'],'identity':row['identity'],'seven_stats':stamp})
            total+=len(b);count+=1
        require(count==6777 and total==948620735,'complete old fresh domain differs')
    else:
        extras=[];require(set(names)=={'source','runtime'} and count==5676 and total==206668287,'full source/runtime denominator differs')
    result={'groups':groups,'extra_authorities':extras,'files':count,'bytes':total}
    dump(path,result);return result


BASE=Path('/workspace/hia-r10-prefix-r1-dda7')
ROOT_OUTER=Path('/tmp/hia-r10-prefix-outer-r1-dda7')
READER_AUTHOR=Path('/tmp/hia-r10-prefix-terminal-reader-r1-dda7')
READER_BINDING_RAW=(READER_AUTHOR/'ACTUAL-BINDING.json').read_bytes()
READER_BINDING=json.loads(READER_BINDING_RAW)
_original_read=read
READS=[]
def read(path):
    b,m,s=_original_read(path)
    READS.append({'path':str(path),'identity':pin(b,m),'seven_stats':s})
    return b,m,s
def obj(path):return json.loads(read(path)[0])
def original_owner(folder,launch):
    raw=read(folder/'OWNER.json')[0];actual=json.loads(raw);returned=obj(folder/'OWNER-RETURNED.json')
    require(returned==dict(actual,supervisor_returncode=0,receipt_sha256=pin(raw)['sha256']),'actual owner wrapper mismatch')
    require(actual['status']=='OWNED_PROCESS_COMPLETED' and actual['returncode']==0
        and actual['qualification_seconds']==180 and actual['cleanup_seconds']==3
        and actual['qualification_started']is True and actual['timed_out']is False
        and actual['exit_observed_before_deadline']is True and actual['event_overflow']is False
        and actual['interrupted_signals']==[] and actual['subreaper_enabled']is True
        and actual['cleanup']['complete']is True and actual['cleanup']['observed_echild']is True
        and actual['cleanup']['remaining_direct_children']==[],'original owner not complete')
    request_raw=read(folder/'OWNER.json.request.json')[0];request=json.loads(request_raw)
    require(request['command']==launch['command'] and request['cwd']==launch['cwd']==str(SOURCE)
        and request['env']==launch['env']==PLAN['environment']
        and request['qualification_seconds']==180 and request['cleanup_seconds']==3
        and actual['request_sha256']==pin(request_raw)['sha256']
        and actual['implementation_sha256']==request['implementation_sha256']==
            '8ab7a238f52412b639aaf318bc75b26f408f3927de4ac69cbac45cc63c92e2be','owner request binding differs')
    return returned
def machine_frames(label,source,result_bytes,expected_result):
    directory=BASE/'size-pack'/label;frames=BASE/'size-pack/frames'/label
    record=obj(frames/'FRAME.json');request_raw=read(directory/'request.json')[0];request=json.loads(request_raw)
    child_raw=read(directory/'CHILD-REPORT.json')[0];child=json.loads(child_raw);observation=obj(directory/'OBSERVATION.json')
    require(record['status']=='CAPTURED_ALL_SIX' and record['errors']==[] and record['label']==label,'frame record incomplete')
    image=read(Path(request['image']))[0]
    require(pin(image)==record['image'] and pin(image)['sha256']==request['image_sha256']==child['image_sha256'],'Native image differs')
    require(child==observation['child'] and child['status']=='returned' and child['result_u64']==expected_result
        and child['request_sha256']==pin(request_raw)['sha256'] and child['forbidden_modules_loaded']==[]
        and child['limits']=={'address_bytes':268435456,'core_dumpable':False,'cpu_seconds':10,
            'source_output_workspace_bytes':1048576,'stack_bytes':8388608,'wall_seconds':20}
        and child['matched_cold']is False and child['whole']is False,'Native child binding differs')
    require(request['schema']=='hia.linux-stdio.native-request.v1' and request['mode']=='ordinary'
        and request['report']==str(directory/'CHILD-REPORT.json') and len(request['buffers'])==3,'request schema differs')
    require(observation['returncode']==0 and observation['timed_out']is False
        and observation['timeout_seconds']==20 and observation['cleanup_seconds']==3
        and observation['stdin_consumed']==0 and observation['stdout_hex']==observation['stderr_hex']==''
        and observation['canaries']==[True,True,True],'actual Native terminal differs')
    for n in ('stdin.bin','stdout.bin','stderr.bin'):require(read(directory/n)[0]==b'','Native I/O differs')
    before=(source,bytes([0xa5])*1048576,bytes(1048576));after=[]
    for name,wanted,request_row in zip(('source','output','workspace'),before,request['buffers'],strict=True):
        b,m,s=read(frames/(name+'.before.bin'));a,am,ss=read(frames/(name+'.after.bin'))
        require(b==wanted and pin(b)==record['before'][name] and pin(a)==record['after'][name]['logical'],'six logical frames differ')
        physical,mode,_=read(directory/(name+'.shared'));guard=bytes([0xd3])*64
        require(physical==guard+a+guard and pin(physical)==record['after'][name]['physical']
            and record['after'][name]['canaries']is True and mode==record['after'][name]['mode'],'physical canaries/frame differ')
        require(request_row=={'bytes':len(b)+128,'extent':len(b),'path':str(directory/(name+'.shared')),
            'sha256':pin(guard+b+guard)['sha256']},'before physical request differs')
        require(bytes.fromhex(observation[name+'_hex'])==a,'observed full hex differs')
        expected_pin=SIZE_RESULT['actual_frames']['buffer_files']
        require(expected_pin['frames/'+label+'/'+name+'.before.bin']==pin(b,m)
            and expected_pin['frames/'+label+'/'+name+'.after.bin']==pin(a,am),'actual frame inventory differs')
        after.append(a)
    require(after[0]==source and after[1][:expected_result]==result_bytes
        and after[1][expected_result:]==before[1][expected_result:],'Native source/output/tail differs')
    if label=='pack-r8':require(after[2]==before[2],'packer workspace differs')
    part=SIZE_RESULT['compile' if label=='compile-r8' else 'pack']
    require(part['returned']==expected_result and part['image']==pin(image) and part['source']==pin(source)
        and part['child_report']==pin(child_raw,read(directory/'CHILD-REPORT.json')[1])
        and part['request']==pin(request_raw,read(directory/'request.json')[1])
        and all(part[k]is True for k in ('six_complete_buffers','source_unchanged','output_tail_unchanged','three_canaries')),'size child frame summary differs')
    return {'label':label,'image':pin(image),'returned':expected_result,'logical_frames':6,'physical_spans':3,'complete_bytes_equal':True}

def validate_scalar_byte_proof(generated):
    """Consume the complete new bounded proof without changing original gates."""
    require(set(generated) == {'functions', 'blocks', 'ops', 'word64_projection', 'scalar_byte_projection'},
            'R10 generated result keys differ')
    require({k: generated[k] for k in ('functions', 'blocks', 'ops')}
            == {'functions': 107, 'blocks': 1456, 'ops': 6299}, 'R10 complete Core counts differ')
    prior = generated['word64_projection']
    proof = generated['scalar_byte_projection']
    require(set(proof) == {'schema', 'original_counts', 'after_counts', 'original_core_sha256',
            'after_core_sha256', 'full_word_bits', 'ordered_full_byte_effects_equal',
            'new_field_range_or_initialization_assumption', 'refusal_branch_unchanged',
            'all_102_other_functions_unchanged', 'external_f0_and_all_function_ABIs_unchanged',
            'whole_inverse_equal', 'edits', 'helpers', 'complete_original_Core_verifier_returned',
            'public_compiler_or_VM_changed', 'machine_size_or_fuel_PASS_claim'},
            'R10 scalar proof keys differ')
    require(proof['schema'] == 'hia.R10.private-scalar-byte-Core-projection.v1'
            and proof['original_counts'] == {'functions': 107, 'blocks': 1456, 'ops': 6347}
            and proof['after_counts'] == {'functions': 107, 'blocks': 1456, 'ops': 6299}
            and proof['original_core_sha256'] == prior['after_core_sha256']
            and type(proof['after_core_sha256']) is str and len(proof['after_core_sha256']) == 64
            and all(c in '0123456789abcdef' for c in proof['after_core_sha256'])
            and proof['full_word_bits'] == 64, 'R10 proof chain or complete counts differ')
    for key in ('ordered_full_byte_effects_equal', 'refusal_branch_unchanged',
                'all_102_other_functions_unchanged', 'external_f0_and_all_function_ABIs_unchanged',
                'whole_inverse_equal', 'complete_original_Core_verifier_returned'):
        require(proof[key] is True, 'R10 proof missing true claim: '+key)
    for key in ('new_field_range_or_initialization_assumption', 'public_compiler_or_VM_changed',
                'machine_size_or_fuel_PASS_claim'):
        require(proof[key] is False, 'R10 forbidden proof claim: '+key)
    helpers = []
    paths = []
    for fi, width, writing, old_count, new_count in (
            (22, 8, True, 54, 33), (23, 8, False, 51, 39),
            (24, 4, True, 26, 17), (25, 4, False, 23, 19),
            (92, 2, True, 11, 9)):
        trace = {'accesses': [['store', i, 8*i] for i in range(width)] if writing
                           else [['load', i] for i in range(width)],
                 'returned_value': ['const', 0] if writing
                           else ['packed', [[i, 8*i] for i in range(width)]]}
        row = {'function': 'f'+str(fi), 'width_bytes': width, 'writing': writing,
               'before_ops': old_count, 'after_ops': new_count,
               'normalized_trace': trace, 'equal': True}
        if fi == 92:
            row['complete_refusal_and_first_error_blocks_unchanged'] = True
            paths.append(['functions', fi, 'blocks', 2, 'ops'])
        else:
            paths.extend([['functions', fi, 'blocks', 0, 'ops'],
                          ['functions', fi, 'blocks', 0, 'term']])
        helpers.append(row)
    require(proof['helpers'] == helpers, 'R10 complete ordered byte trace proof differs')
    require(type(proof['edits']) is list and len(proof['edits']) == 9
            and all(type(edit) is dict and set(edit) == {'path', 'before', 'after'}
                    for edit in proof['edits'])
            and [edit['path'] for edit in proof['edits']] == paths,
            'R10 whole inverse edit domain differs')

def complete_original_capsule():
    raw,_=fixed(PLAN['size_author_capsule']);wrapper=json.loads(raw)
    packed=base64.b64decode(wrapper['data'],validate=True)
    require(pin(packed)==wrapper['compressed'],'original capsule compressed pin differs')
    decoder=zlib.decompressobj();data=decoder.decompress(packed,wrapper['decoded']['bytes']+1)
    require(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
        and pin(data)==wrapper['decoded'],'original capsule full decode differs')
    value=json.loads(data);rows={}
    for row in value['files']:
        name=row['path']
        require(name not in rows and not Path(name).is_absolute() and '..' not in Path(name).parts,
            'unsafe/duplicate capsule member')
        b=base64.b64decode(row['data_base64'],validate=True)
        require(pin(b,row['identity']['mode'])==row['identity'],'complete original capsule member differs')
        rows[name]={'identity':row['identity'],'actual_full_bytes_read':True}
    require(len(rows)==70,'original complete author capsule denominator differs')
    require(obj(BASE/'ORIGINAL-CAPSULE-READBACK.json')=={
        'complete_members':70,'all_complete_bytes_modes_verified':True,
        'capsule':PLAN['size_author_capsule']},'actual original capsule readback differs')
    return rows


def source_function_inverse(generated):
    before,_=fixed(PLAN['fixed_controls']['R10-author:before/file_render_checker_word64.hepta'])
    def split(raw):
        segments=raw.split(b'\nfn ')
        require(len(segments)==108 and segments[0]==b'hia-asm.v1 hepta.hia.program.v8 file_render_checker_v4',
            'complete assembly function denominator or module differs')
        functions={}
        for index,part in enumerate(segments[1:]):
            body=b'fn '+part
            name=body.split(b'(',1)[0]
            require(name==('fn f'+str(index)).encode(),'assembly function order differs')
            functions[index]=body
        return functions
    old,new=split(before),split(generated)
    changed={22,23,24,25,92}
    for index in range(107):
        require(old[index].split(b'\n',1)[0]==new[index].split(b'\n',1)[0],
            'original function ABI/header differs')
        if index not in changed:require(old[index]==new[index],'unchanged complete function differs')
    require(old[92].split(b'\nblock b2(',1)[0]==new[92].split(b'\nblock b2(',1)[0],
        'complete cp16 refusal/first-error blocks differ')
    restored=generated
    for index in sorted(changed):
        require(restored.count(new[index])==1,'new function inverse is not unique')
        restored=restored.replace(new[index],old[index],1)
    require(restored==before,'complete rendered source inverse differs')
    return {'functions':107,'unchanged_complete_functions':102,'all_function_ABIs_equal':True,
        'refusal_and_first_error_blocks_equal':True,'complete_rendered_source_inverse_equal':True,
        'before':pin(before),'after':pin(generated),'changed_functions':sorted(changed)}


def current_tree(path,label):
    path=Path(path);files={};directories={}
    expected=READER_BINDING['actual_raw_layouts'][label]
    require(expected['root']==str(path),'actual raw layout root differs')
    require(path.is_absolute() and stat.S_ISDIR(path.lstat().st_mode),'actual raw root is not a directory')
    for here,children,leaves in os.walk(path,followlinks=False):
        here=Path(here);s=here.lstat();relative=here.relative_to(path).as_posix()
        require(stat.S_ISDIR(s.st_mode),'actual raw directory alias')
        directories[relative]={'mode':stat.S_IMODE(s.st_mode),'seven_stats':seven(s)}
        for child in children:require(stat.S_ISDIR((here/child).lstat().st_mode),'actual raw child alias')
        for name in sorted(leaves):
            p=here/name;b,m,s=read(p);rel=p.relative_to(path).as_posix()
            require(rel not in files,'duplicate raw path')
            require(rel in expected['files'] and expected['files'][rel]=={'mode':m,'seven_stats':s},
                'actual raw frozen metadata differs')
            files[rel]={'source_path':str(p),'identity':pin(b),'mode':m,'seven_stats':s}
    require(files and set(files)==set(expected['files']) and directories==expected['directories'],
        'complete actual raw frozen layout differs')
    second_files=set();second_directories={}
    for here,children,leaves in os.walk(path,followlinks=False):
        here=Path(here);s=here.lstat();relative=here.relative_to(path).as_posix()
        require(stat.S_ISDIR(s.st_mode),'terminal actual raw directory alias')
        second_directories[relative]={'mode':stat.S_IMODE(s.st_mode),'seven_stats':seven(s)}
        for child in children:require(stat.S_ISDIR((here/child).lstat().st_mode),'terminal actual raw child alias')
        for name in leaves:second_files.add((here/name).relative_to(path).as_posix())
    require(second_files==set(files) and second_directories==directories,'actual raw terminal pathset changed')
    for row in files.values():require(seven(Path(row['source_path']).lstat())==row['seven_stats'],'actual raw inode drift')
    return {'label':label,'root':str(path),'files':files,'directories':directories,
        'file_count':len(files),'logical_bytes':sum(row['identity']['bytes'] for row in files.values()),
        'all_complete_bytes_read':True,'historical_archive_authority_or_remote_custody_claim':False}


def actual_root_outer():
    launch_raw=read(AUTHOR/'PREFIX-LAUNCH.json')[0];launch=json.loads(launch_raw)
    outer=obj(ROOT_OUTER/'RESULT.json');intent=obj(ROOT_OUTER/'INTENT.json')
    spawned=obj(ROOT_OUTER/'SPAWNED.json')
    require(outer['schema']=='hia.root.r10.private-prefix.outer-result.v1'
        and outer['status']=='PASS_R10_PREFIX_PARENT_PROCESS_ONLY' and outer['returncode']==0
        and outer['direct_restored_interpreter_invocations']==outer['maximum_attempts']==1
        and outer['timeout']is False and outer['subreaper']is True and outer['ECHILD']is True
        and outer['process_group_absent']is True and outer['adopted']==[],'actual Root outer did not close')
    require(intent['status']=='ROOT_AUTHORIZED_FROZEN_R10_PREFIX_ONCE'
        and intent['launch']==pin(launch_raw)
        and intent['launch_seven_stats']==seven((AUTHOR/'PREFIX-LAUNCH.json').lstat())
        and intent['original_owner_seconds']==180 and intent['outer_watchdog_seconds']==1800
        and intent['cleanup_seconds']==3 and intent['maximum_attempts']==1
        and outer['pid']==spawned['pid']==spawned['pgid'],'actual Root launch/intent differs')
    require(launch['outer_seconds']==1800 and launch['outer_cleanup_seconds']==3
        and launch['new_product_root']==str(BASE) and launch['automatic_retry']is False,
        'Root launch original limits differ')
    for name in ('stdout','stderr'):
        require(pin(read(ROOT_OUTER/(name+'.bin'))[0])==outer[name],'actual Root stream differs')
    return outer


def main():
    global SIZE_RESULT
    require(not os.path.lexists(EXEC),'reader output already exists')
    mkdir(EXEC);started=time.monotonic_ns();report={'status':'FAIL','products':0,'project_imports':0,'whole_native':False,'matching_current_cold':False}
    try:
        require(pin(PLAN_RAW)['git_blob']=='55814ed9d129d6df96ad2d5e2683fdb0fe6ae75a','frozen prefix plan differs')
        for name,row in READER_BINDING['fixed_actual_inputs'].items():fixed(row)
        require(read(READER_AUTHOR/'ACTUAL-BINDING.json')[0]==READER_BINDING_RAW,'reader binding drift')
        root_outer=actual_root_outer()
        original_capsule=complete_original_capsule()
        controls=controls_guard()
        require(controls==obj(BASE/'CONTROLS-BEFORE.json')==obj(BASE/'CONTROLS-AFTER.json'),'prefix control snapshots differ')
        fresh=snapshot(EXEC/'FULL-FRESH.json')
        require(fresh==obj(BASE/'FULL-FRESH-BEFORE.json')==obj(BASE/'FULL-FRESH-AFTER.json'),'full fresh 6777-domain differs')
        selected=[g for g in fresh['groups'] if g['name'] in ('source','runtime')]
        short={'groups':selected,'extra_authorities':[],'files':5676,'bytes':206668287}
        owners=[]
        for stage in ('generate','check'):
            folder=BASE/'generation'/stage;launch=obj(folder/'LAUNCH.json')
            require(launch['command']==[PLAN['runtime']['executable']['path'],'-I','-S','-B',str(AUTHOR/'run_prefix.py'),
                '--plan-sha256',PLAN['authorization_pin'],'--stage',stage],'original generator argv differs')
            owner=original_owner(folder,launch);owners.append(owner)
            actual=obj(folder/'RESULT.json')
            require(actual['status']=='PASS_ORIGINAL_R10_GENERATOR_STAGE' and actual['stage']==stage
                and actual['generator_main_attempted']==1 and actual['frozen_source_runtime_equal']is True
                and actual['finalization_errors']==[] and actual['compile_calls']==actual['VM_calls']==actual['ELF_calls']==0,'generation terminal differs')
            require(obj(folder/'SOURCE-RUNTIME-BEFORE.json')==obj(folder/'SOURCE-RUNTIME-AFTER.json')==short,'generation complete source/runtime differs')
            require(obj(folder/'CONTROLS-BEFORE.json')==obj(folder/'CONTROLS-AFTER.json')==controls,'generation control closure differs')
            for name in ('RUNTIME-BEFORE.json','RUNTIME-AFTER.json'):
                rt=obj(folder/name);require(rt['executable']==PLAN['runtime']['executable']['path'] and rt['environment']==PLAN['environment'],'generation runtime differs')
        generated=read(BASE/'generated/file_render_checker_word64_bytes.hepta')[0]
        gr=read(BASE/'generation/generate/report.json')[0]
        require(gr==read(BASE/'generation/check/report.json')[0],'real generator reports differ')
        g=json.loads(gr);proof=g['generated']['word64_projection']
        require(g['source_bytes']==len(generated)==397114 and g['source_sha256']==pin(generated)['sha256']
            and pin(generated)['git_blob']=='dcf7ab874951a9e0742b8cc17138095cd2af0973'
            and {k:g['generated'][k] for k in ('functions','blocks','ops')}=={'functions':107,'blocks':1456,'ops':6299}
            and proof['original_counts']=={'functions':107,'blocks':1456,'ops':6664}
            and proof['after_counts']=={'functions':107,'blocks':1456,'ops':6347}
            and len(proof['removed_identity_casts'])==317 and proof['whole_inverse_equal']is True
            and proof['complete_original_Core_verifier_returned']is True and proof['external_f0_unchanged']is True
            and proof['all_other_operations_kept_in_order']is True and proof['machine_size_or_fuel_PASS_claim']is False,'actual generation proof differs')
        validate_scalar_byte_proof(g['generated'])
        prior=json.loads(fixed(READER_BINDING['fixed_actual_inputs']['R9_generation_report'])[0])
        require(g['generated']['word64_projection']==prior['generated']['word64_projection'],
            'complete original 317-cast proof and all edits differ')
        scalar_proof=g['generated']['scalar_byte_projection']
        require(scalar_proof['original_core_sha256']==proof['after_core_sha256']
            and scalar_proof['original_core_sha256']=='8d2395a2e9eecae59c00a3b58f3a2e98fbcd5ae28d5602e02ffc7647571985a8'
            and scalar_proof['after_core_sha256']=='78840dad95faa8c09a6f7532b13e7534baf82e3903fc191914e3da35b107b93c',
            'actual dual Core proof hashes differ')
        source_inverse=source_function_inverse(generated)
        binding=obj(BASE/'GENERATED-BINDING.json');require(binding==obj(BASE/'size-context/CANDIDATE-BINDING.json'),'source binding copies differ')
        for row in binding['files'].values():fixed(row)
        require(obj(BASE/'GENERATED-BINDING-AFTER.json')=={'schema':binding['schema'],'files':binding['files'],'actual_complete_readback':True},'binding after differs')
        folder=BASE/'size-pack';launch=obj(folder/'LAUNCH-INTENT.json')
        size_plan_raw=read(BASE/'size-context/EXECUTION-PLAN.json')[0];sp=json.loads(size_plan_raw)
        require(launch['command']==[PLAN['runtime']['executable']['path'],'-I','-S','-B',str(BASE/'size-context/run_size_pack.py'),
            '--plan-sha256',pin(size_plan_raw)['sha256'],'--child'],'original size owner argv differs')
        owners.append(original_owner(folder,launch));outer=obj(folder/'OUTER.json');SIZE_RESULT=obj(folder/'RESULT.json')
        require(outer['status']==SIZE_RESULT['status']=='PASS_EXPLICIT_U32_SIZE_AND_PRIVATE_PACK_ONLY'
            and outer['actual_child_result']==SIZE_RESULT and outer['owner']==owners[-1]
            and outer['finalization_errors']==SIZE_RESULT['finalization_errors']==[]
            and outer['compile_calls_attempted']==outer['pack_calls_attempted']==SIZE_RESULT['compile_calls_attempted']==SIZE_RESULT['pack_calls_attempted']==1,'size original parent/child differs')
        source_group=next(x for x in fresh['groups'] if x['name']=='source')
        frozen_files={n:r['identity'] for n,r in source_group['files'].items()}
        frozen_states={n:dict(zip(FIELDS,r['seven_stats'])) for n,r in source_group['files'].items()}
        for name in ('SOURCE-CHILD-BEFORE.json','SOURCE-CHILD-AFTER.json','SOURCE-OUTER-BEFORE.json','SOURCE-OUTER-AFTER.json'):
            sc=obj(folder/name);require(sc['files']==frozen_files and sc['inode_states']==frozen_states and sc['tree']==PLAN['source']['tree'],'size source full snapshots differ')
        image=read(folder/'R8.u32.image.bin')[0];elf=read(folder/'R8.private-nonexecuted.elf.bin')[0];frame=read(folder/'packer-input.bin')[0]
        require(pin(image)==SIZE_RESULT['image'] and pin(image)['git_blob']=='78b32200cc4843860a6e60a9870d6ac306ae76d7'
            and pin(elf)==SIZE_RESULT['ELF'] and pin(elf)['git_blob']=='ab04592093e9f4e8b3d7d5f8abf402253ecd050c','actual image/ELF differs')
        input_rows=obj(BASE/'size-context/INPUTS.json')['files']
        material={r['captured']:read(BASE/'size-context'/r['captured'])[0] for r in input_rows}
        for row in input_rows:
            b,m,s=read(BASE/'size-context'/row['captured']);origin,om,oss=read(Path(row['origin']))
            require(b==origin and pin(b,m)==row['captured_identity']==pin(origin,om)==row['origin_identity']
                and dict(zip(FIELDS,oss))==row['origin_stat'],'old 36 full inputs/copies differ')
        require(len(input_rows)==len(material)==36,'complete original copied input denominator differs')
        controller=next(b for b in material.values() if len(b)==59889 and pin(b)['sha256']=='5f23e0aefb1cb4749c7ce4a8c50c694367357051144f34cec8867e32d5eba6e2')
        representation=next(b for b in material.values() if len(b)==430261 and pin(b)['sha256']=='0ba4d693b9533b13aa059b7e4bb68ba482119f2109f1ae87c44c0d6a72cddba7')
        code=read(BASE/'size-context/retained_pack_contract.py')[0]
        require(pin(code,0o644)==sp['controls']['author:retained_pack_contract.py']['identity'],'retained pure pack checks differ')
        tree=ast.parse(code);require([n.name for n in tree.body if isinstance(n,ast.FunctionDef)]==['_digest','_frame','_elf_structure'],'pure retained function inventory differs')
        require(all(isinstance(n,(ast.Expr,ast.Import,ast.ImportFrom,ast.Assign,ast.FunctionDef)) for n in tree.body),'pure contract added top-level effect')
        ns={};exec(compile(code,'<fixed-stdlib-only-pack-inspection>','exec'),ns)
        require(ns['_frame']((controller,representation,image))==frame and ns['_elf_structure'](elf,(controller,representation,image))==SIZE_RESULT['elf_inspection'],'whole original frame/ELF contract differs')
        frames=[machine_frames('compile-r8',generated,image,544696),machine_frames('pack-r8',frame,elf,1036288)]
        parent=obj(BASE/'RESULT.json')
        require(parent['status']=='PASS_PRIVATE_R10_GENERATION_AND_SIZE_PACK_ONLY' and parent['not_started']==[]
            and [(x['stage'],x['status']) for x in parent['stages']]==[('generate','PASS'),('check','PASS'),('size-pack','PASS')]
            and parent['generation_owner_launches']==2 and parent['size_driver_attempts']==parent['compile_calls_attempted']==parent['pack_calls_attempted']==1
            and parent['VM_calls']==parent['semantic_Native_cases']==parent['aggregate_cases']==parent['ELF_exec_calls']==0
            and parent['finalization_errors']==[] and parent['actual_image']==pin(image) and parent['actual_ELF']==pin(elf)
            and parent['actual_size']==SIZE_RESULT['size'] and parent['whole_native']is False,'whole prefix result differs')
        raw_trees=[current_tree(BASE,'prefix'),current_tree(ROOT_OUTER,'Root_outer')]
        raw_count=sum(tree['file_count'] for tree in raw_trees)
        raw_bytes=sum(tree['logical_bytes'] for tree in raw_trees)
        dump(EXEC/'COMPLETE-ACTUAL-RAW-INVENTORY.json',{'schema':'hia.R10.prefix.actual-raw-current-inventory.v1',
            'files':raw_count,'logical_bytes':raw_bytes,'trees':raw_trees,'remote_custody_claim':False})
        for name,row in READER_BINDING['fixed_actual_inputs'].items():fixed(row)
        require(controls_guard()==controls,'terminal control drift')
        for row in READS:require(seven(Path(row['path']).lstat())==row['seven_stats'],'terminal inode drift')
        report.update(status='PASS_INDEPENDENT_R10_PREFIX_TERMINAL_ONLY',original_product_status=parent['status'],
            fresh_domain_files=6777,fresh_domain_bytes=948620735,source_files=3180,runtime_files=2496,
            original_product_owners=3,generation=2,compile=1,pack=1,Native_physical_frames=2,
            full_logical_buffers=12,physical_canary_spans=6,raw_originals=raw_count,raw_logical_bytes=raw_bytes,
            original_capsule_members=len(original_capsule),actual_Root_outer=root_outer,
            source_function_inverse=source_inverse,scalar_byte_projection=scalar_proof,
            exact_scalar_editpaths=9,word64_then_scalar_proof_chain=True,remote_custody_claim=False,
            source=pin(generated),image=pin(image),ELF=pin(elf),original_frame_ELF_checks_full=True,
            all_test_limits_unchanged=True,all_before_after_source_runtime_maps_equal=True,
            semantic_VM=0,semantic_Native=0,ELF_execution=0,all_groups_qualification=False,frames=frames)
    except BaseException:
        report.update(error=traceback.format_exc(),status='FAIL')
    finally:
        report.update(fresh_reads=len(READS),unique_read_paths=len({x['path'] for x in READS}),elapsed_ns=time.monotonic_ns()-started)
        dump(EXEC/'ALL-READS.json',READS);dump(EXEC/'RESULT.json',report);print(json.dumps(report,sort_keys=True))
    return 0 if report['status']=='PASS_INDEPENDENT_R10_PREFIX_TERMINAL_ONLY' else 1
if __name__=='__main__':raise SystemExit(main())
