from pathlib import Path
import ast,hashlib,json,os,stat,time,traceback
AUTHOR=Path('/tmp/hia-r10-helper-controls-author-r1-dda7')
PLAN_RAW=(AUTHOR/'EXECUTION-PLAN.json').read_bytes()
PLAN=json.loads(PLAN_RAW)
SOURCE=Path(PLAN['source']['path'])
BASE=Path('/workspace/hia-r10-helper-controls-r1-dda7')
ROOT_OUTER=Path('/tmp/hia-r10-helper-controls-outer-r1-dda7')
READER_AUTHOR=Path('/tmp/hia-r10-helper-terminal-reader-r1-dda7')
READER_BINDING_RAW=(READER_AUTHOR/'ACTUAL-BINDING.json').read_bytes()
READER_BINDING=json.loads(READER_BINDING_RAW)
EXEC=Path('/tmp/hia-r10-helper-independent-readback-r1-dda7')
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
    require(read(AUTHOR/'EXECUTION-PLAN.json')[0]==PLAN_RAW,'prefix plan changed')
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


_original_read=read
READS=[]
def read(path):
    raw,mode,stamp=_original_read(path)
    READS.append({'path':str(path),'identity':pin(raw,mode),'seven_stats':stamp})
    return raw,mode,stamp

def obj(path):
    return json.loads(read(path)[0])

def attempt(errors,name,action):
    try:return action()
    except BaseException as error:
        errors.append({'where':name,'type':type(error).__name__,'traceback':traceback.format_exc()})
        return None

def reader_controls():
    require(read(READER_AUTHOR/'ACTUAL-BINDING.json')[0]==READER_BINDING_RAW,'reader binding changed')
    observed={}
    for name,row in READER_BINDING['author_files'].items():
        raw,mode,stamp=read(READER_AUTHOR/name)
        require(pin(raw,mode)==row['identity'] and stamp==row['seven_stats'],'reader author changed: '+name)
        observed[name]={'identity':pin(raw,mode),'seven_stats':stamp}
    for name,row in READER_BINDING['fixed_controls'].items():
        _,stamp=fixed(row);observed['fixed:'+name]={'identity':row['identity'],'seven_stats':stamp}
    return observed

def actual_root_outer():
    launch_raw=read(AUTHOR/'LAUNCH.json')[0];launch=json.loads(launch_raw)
    outer=obj(ROOT_OUTER/'RESULT.json');intent=obj(ROOT_OUTER/'INTENT.json');spawned=obj(ROOT_OUTER/'SPAWNED.json')
    require(outer['schema']=='hia.root.r10.private-helper.outer-result.v1'
        and outer['status']=='PASS_R10_HELPER_PARENT_PROCESS_ONLY' and outer['returncode']==0
        and outer['direct_restored_interpreter_invocations']==outer['maximum_attempts']==1
        and outer['timeout']is False and outer['subreaper']is True and outer['ECHILD']is True
        and outer['process_group_absent']is True and outer['adopted']==[], 'actual Root helper outer did not close')
    require(intent['status']=='ROOT_AUTHORIZED_ADDITIONAL_R10_HELPER_GATE_ONCE'
        and intent['launch']==pin(launch_raw) and intent['launch_seven_stats']==seven((AUTHOR/'LAUNCH.json').lstat())
        and intent['planned_helper_pairs']==553 and intent['maximum_VM_calls']==1106
        and intent['original_eight_groups_executed']==0 and intent['original_owner_seconds']==180
        and intent['outer_watchdog_seconds']==1800 and intent['cleanup_seconds']==3
        and intent['maximum_attempts']==1 and outer['pid']==spawned['pid']==spawned['pgid'], 'Root intent differs')
    require(launch['outer_root']==str(ROOT_OUTER) and launch['outer_seconds']==1800
        and launch['outer_cleanup_seconds']==3 and launch['automatic_retry']is False,'Root original budgets differ')
    for name in ('stdout','stderr'):
        require(pin(read(ROOT_OUTER/(name+'.bin'))[0])==outer[name],'Root complete stream differs')
    require(read(ROOT_OUTER/'stderr.bin')[0]==b'','Root helper stderr is nonempty')
    require(json.loads(read(ROOT_OUTER/'stdout.bin')[0])=={
        'status':'PASS_ADDITIONAL_PRIVATE_HELPERS_ONLY','owner_attempts':1,'errors':[]},'Root stdout summary differs')
    return outer

def parse_selected_helpers(raw):
    """Read only the six existing assembly bodies; no assembler or VM runs."""
    names={'f21','f22','f23','f24','f25','f92'};found={};function=None;block=None
    for original in raw.decode('utf-8').splitlines():
        line=original.strip()
        if line.startswith('fn '):
            name=line[3:].split('(',1)[0]
            function=name if name in names else None;block=None
            if function is not None:
                require(function not in found,'duplicate selected helper');found[function]={}
        elif line=='end':function=None;block=None
        elif function is not None and line.startswith('block '):
            block=line[6:].split('(',1)[0]
            require(block not in found[function],'duplicate selected block')
            found[function][block]={'ops':[],'term':None}
        elif function is not None and ' = ' in line:
            require(block is not None,'operation outside selected block')
            op=line.split(' = ',1)[1].split('(',1)[0]
            callee=json.loads(line[line.index('{'):])['function'] if op=='call' else None
            require(callee is None or callee in names,'selected helper calls outside fixed closure')
            found[function][block]['ops'].append({'op':op,'callee':callee})
        elif function is not None and line:
            term='ret' if line.startswith('ret(') else line.split()[0]
            require(term in ('ret','branch','jump') and found[function][block]['term']is None,'selected terminator differs')
            found[function][block]['term']=term
    require(set(found)==names and all(b['term']is not None for f in found.values() for b in f.values()),'selected helpers incomplete')
    return found

def expected_trace(case,helpers,byte_events):
    """Validate the finite recorded opcode path without executing arithmetic."""
    sequence=[];steps=0;byte_index=0;stopped=False
    class ExpectedAbort(Exception):pass
    initial=bytes.fromhex(case['initial_hex'])
    def walk(name,depth):
        nonlocal steps,byte_index,stopped
        require(depth<=2,'unexpected selected helper depth')
        steps+=1
        if name=='f92':path=('b0','b1') if case['value']>65535 else ('b0','b2')
        elif name=='f21':path=('b0','b1','b3') if len(initial)>40 and initial[40]==0 else ('b0','b3')
        else:path=('b0',)
        for number,block in enumerate(path):
            body=helpers[name][block]
            for ins in body['ops']:
                sequence.append({'op':ins['op'],'depth':depth});steps+=1
                if ins['op'] in ('buffer.load','buffer.store'):
                    require(byte_index<len(byte_events),'trace has more byte accesses than oracle')
                    event=byte_events[byte_index];byte_index+=1
                    require(event['op']==ins['op'],'trace byte access kind differs')
                    if event['outcome']=='raised':stopped=True;raise ExpectedAbort()
                elif ins['op']=='call':walk(ins['callee'],depth+1)
            steps+=1
            require(body['term']==('ret' if number==len(path)-1 else 'branch' if block=='b0' else 'jump'),
                    'finite selected path/terminator differs')
    try:walk(case['function'],0)
    except ExpectedAbort:pass
    require(byte_index==len(byte_events),'trace omitted an oracle access')
    require(stopped==bool(byte_events and byte_events[-1]['outcome']=='raised'),'trace stop outcome differs')
    return sequence,steps

RESOURCE_KEYS=('allocations','frees','allocation_attempts','owners_created','owners_dropped','live_owners',
    'live_bytes','peak_bytes','loans_started','loans_ended','live_local_loans','chains_created','chains_consumed',
    'live_chains','chain_nodes_created','chain_nodes_dropped','live_chain_nodes')

def observe_pair(index,case,expected,programs,helpers,declared_pair,declared_calls):
    folder=BASE/'helper-controls/cases'/str(index).zfill(4)
    require(obj(folder/'CASE.json')==case and obj(folder/'ORACLE.json')==expected,'case/oracle saved bytes differ')
    pair=obj(folder/'PAIR.json')
    require(pair==declared_pair and pair['id']==case['id'] and pair['group']==case['group']
        and pair['status']=='PASS' and set(pair['versions'])=={'R9','R10'},'complete pair summary differs')
    observations={};summaries=[];last_stop=None
    for offset,label in enumerate(('R9','R10')):
        directory=folder/label;before=read(directory/'buffer.before.bin')[0];after=read(directory/'buffer.after.bin')[0]
        request=obj(directory/'REQUEST.json');state=obj(directory/'OBSERVATION.json')
        require(before==bytes.fromhex(case['initial_hex']) and after==bytes.fromhex(expected['after_hex']),
                'complete actual one-buffer preimage/result differs')
        view={'mutable':case['view']!='readonly','active':case['view']!='expired_view','owner_active':case['view']!='expired_owner'}
        arguments=[case['offset']]+([] if case['function'] in ('f23','f25') else [case['value']])
        require(request=={'case':case,'program_sha256':programs[label]['Core_sha256'],
            'program_input_sha256':programs[label]['input_sha256'],'function':case['function'],
            'scalar_arguments':arguments,'actual_initial_buffer':pin(before),'view_state':view,
            'limits':{'max_steps':10000000,'max_heap_bytes':1048576,'max_call_depth':128,'allocation_fail_at':None},
            'one_actual_borrowed_buffer_ABI':True,'synthetic_source_output_buffers':False},'actual helper request differs')
        require(obj(directory/'CALL-INTENT.json')=={'id':case['id'],'version':label,'one_invocation':True},'call intent differs')
        require(all(state[k]==expected[k] for k in ('status','values','error','events')),'actual outcome/effect sequence differs')
        require(state['actual_before']==pin(before) and state['actual_after']==pin(after)
            and state['owner_active']==view['owner_active'] and state['view_active']==view['active']
            and state['view_mutable']==view['mutable'],'observed bytes or view state differ')
        require(state['resources']=={name:0 for name in RESOURCE_KEYS},'private helper unexpectedly changed resources')
        trace,steps=expected_trace(case,helpers[label],expected['events'])
        require(state['operation_events']==trace and state['steps']==steps and 0<steps<=10000000,
                'complete actual opcode trace / charged ticks differ')
        byte_indices=[i for i,e in enumerate(trace) if e['op'] in ('buffer.load','buffer.store')]
        require(state['byte_event_op_indices']==byte_indices,'actual byte/op association differs')
        if label=='R10' and byte_indices:
            require(all(e['op']!='int.add.wrap' for e in trace[byte_indices[-1]+1:]),'new address increment follows final access')
        require(state['call_attempts']==1 and state['Native_calls']==state['compile_calls']==0
            and state['observation_only_VM']is True,'unexpected product or retry')
        require(type(state['started_ns'])is int and type(state['stopped_ns'])is int
            and state['stopped_ns']>=state['started_ns'] and state['elapsed_ns']==state['stopped_ns']-state['started_ns'],
            'actual helper timing fields differ')
        if last_stop is not None:require(state['started_ns']>=last_stop,'R10 started before R9 completed')
        last_stop=state['stopped_ns']
        if expected['error']is None:require(not os.path.lexists(directory/'EXCEPTION.txt'),'success has exception witness')
        else:
            text=read(directory/'EXCEPTION.txt')[0].decode('utf-8')
            require(text.startswith('Traceback (most recent call last):')
                and text.endswith(expected['error']['type']+': '+expected['error']['message']+'\n'),
                'actual exception witness missing or different')
        comparison={'outcome_equal':True,'complete_actual_buffer_equal':True,'before_exact':True,
            'original_limit':True,'one_invocation':True,'no_Native_or_compile':True}
        require(obj(folder/(label+'-COMPARISON.json'))==comparison and pair['versions'][label]=={
            'comparison':comparison,'observation':identity(directory/'OBSERVATION.json')},'saved comparison/observation identity differs')
        require(declared_calls[index*2+offset]=={'id':case['id'],'version':label,'steps':steps,'after_captured':True},
                'actual invocation order/steps differ')
        observations[label]=(state,after)
        summaries.append({'id':case['id'],'version':label,'function':case['function'],'status':state['status'],
            'steps':steps,'before':pin(before),'after':pin(after),'observation':identity(directory/'OBSERVATION.json'),
            'actual_complete_bytes_read':True,'ordered_events_equal':True,'opcode_trace_equal':True})
    old,new=observations['R9'],observations['R10']
    require(old[1]==new[1] and all(old[0][k]==new[0][k] for k in
        ('status','values','error','events','resources','owner_active','view_active','view_mutable')),'R9/R10 full observable state differs')
    return summaries

def main():
    start=time.monotonic_ns();errors=[];inventories=[];case_rows=[];fresh=None;original_controls=None;own_controls=None
    result={'schema':'hia.R10.helper.independent-terminal-readback.v1','status':'FAIL','products':0,'project_imports':0,
        'whole_native':False,'matching_current_cold':False,'original_eight_groups_executed':0,'errors':errors}
    require(not os.path.lexists(EXEC),'one-shot reader output exists');mkdir(EXEC)
    try:
        own_controls=reader_controls();original_controls=controls_guard()
        material=dict(PLAN);auth=material.pop('authorization_pin')
        require(pin(encode(material))['sha256']==auth,'helper authorization differs')
        require(PLAN['case_count']==553 and PLAN['maximum_VM_calls']==1106
            and PLAN['budgets']=={'VM_max_steps':10000000,'VM_max_heap_bytes':1048576,'VM_max_call_depth':128,
                'qualification_seconds':180,'cleanup_seconds':3,'outer_watchdog_seconds':1800,'outer_cleanup_seconds':3},'limits differ')
        fresh=snapshot(EXEC/'FULL-FRESH-6777.json')
        for name in ('executable','library'):fixed(PLAN['runtime'][name])
        inventories=[current_tree(BASE,'helper'),current_tree(ROOT_OUTER,'outer')]
        outer=actual_root_outer();launch=obj(BASE/'LAUNCH.json');owner=original_owner(BASE,launch)
        expected_command=[PLAN['runtime']['executable']['path'],'-I','-S','-B',str(AUTHOR/'run_helper_gate.py'),
            '--plan-sha256',auth,'--child']
        require(launch=={'command':expected_command,'cwd':str(SOURCE),'env':PLAN['environment'],
            'supervisor_env':PLAN['environment'],'qualification_seconds':180,'cleanup_seconds':3,'automatic_retry':False},'actual owner launch differs')
        request=obj(BASE/'OWNER.json.request.json')
        require(request['stdout_path']==str(BASE/'stdout.bin') and request['stderr_path']==str(BASE/'stderr.bin')
            and request['receipt_path']==str(BASE/'OWNER.json') and request['deadline_ns']-request['started_ns']==180000000000,
            'original owner paths/deadline differ')
        parent=obj(BASE/'RESULT.json');child=obj(BASE/'helper-controls/RESULT.json')
        require(parent['schema']=='hia.R10.helper-boundary-owner.v1' and parent['status']=='PASS_ADDITIONAL_PRIVATE_HELPERS_ONLY'
            and parent['errors']==[] and parent['owner_attempts']==1 and parent['owner']==owner
            and parent['actual_child_result']==child and parent['retry']is False,'actual parent/owner/child binding differs')
        require(child['schema']=='hia.R10.helper-boundary-result.v1' and child['status']=='PASS_ADDITIONAL_PRIVATE_HELPERS_ONLY'
            and child['errors']==[] and child['not_started']==[]
            and child['attempted_cases']==child['declared_cases']==child['completed_pairs']==553
            and child['actual_VM_calls']==child['VM_invocation_attempts']==1106
            and len(child['case_pairs'])==553 and len(child['invocations'])==1106,'complete helper result differs')
        for data in (parent,child):
            require(data['Native_calls']==data['compile_calls']==data['original_eight_groups_executed']==0
                and data['whole_native']is False and data['matching_current_cold']is False,'result claims other qualification')
        require(child['generation_calls']==child['semantic_f0_calls']==0,'unexpected generator/public entry')
        for folder in (BASE,BASE/'helper-controls'):
            for when in ('BEFORE','AFTER'):
                require(obj(folder/('FULL-FRESH-'+when+'.json'))==fresh,'saved full fresh map differs')
                require(obj(folder/('CONTROLS-'+when+'.json'))==original_controls,'saved complete controls differ')
                runtime=obj(folder/('RUNTIME-'+when+'.json'))
                require(runtime['executable']==PLAN['runtime']['executable']['path'] and runtime['environment']==PLAN['environment']
                    and runtime['version'].startswith('3.14.4 '),'saved runtime context differs')
        require(read(BASE/'stderr.bin')[0]==b'' and read(BASE/'OWNER.json.stderr.log')[0]==b'','actual helper stderr differs')
        require(json.loads(read(BASE/'stdout.bin')[0])=={'status':'PASS_ADDITIONAL_PRIVATE_HELPERS_ONLY','completed_pairs':553,'errors':[]},'child stdout differs')
        report=json.loads(fixed(PLAN['fixed_controls']['actual_R10_generation_report'])[0]);scalar=report['generated']['scalar_byte_projection']
        validate_scalar_byte_proof(report['generated'])
        programs={label:{'Core_sha256':scalar[key],'input_sha256':scalar[key]}
            for label,key in (('R9','original_core_sha256'),('R10','after_core_sha256'))}
        require(obj(BASE/'helper-controls/ACTUAL-PROGRAMS.json')==programs,'actual full-program Core identity differs')
        raw_programs={'R9':fixed(PLAN['fixed_controls']['R10-author:before/file_render_checker_word64.hepta'])[0],
            'R10':fixed(PLAN['fixed_controls']['actual_R10_source'])[0]}
        helpers={label:parse_selected_helpers(raw) for label,raw in raw_programs.items()}
        cases=obj(AUTHOR/'CASES.json');require(len(cases)==553 and [c['id'] for c in cases]==PLAN['case_order'],'case order differs')
        oracle_raw=read(READER_AUTHOR/'boundary_cases.py')[0]
        require(oracle_raw==read(AUTHOR/'boundary_cases.py')[0] and not any(isinstance(n,(ast.Import,ast.ImportFrom)) for n in ast.walk(ast.parse(oracle_raw))),
                'frozen independent byte oracle changed or imports a product')
        namespace={'__name__':'_readback_only_byte_oracle'}
        exec(compile(oracle_raw,'<fixed-independent-byte-oracle>','exec'),namespace)
        require(namespace['cases']()==cases,'case factory differs')
        groups={};outcomes={'R9':{},'R10':{}};max_steps={'R9':0,'R10':0}
        for index,case in enumerate(cases):
            rows=observe_pair(index,case,namespace['oracle'](case),programs,helpers,child['case_pairs'][index],child['invocations'])
            case_rows.extend(rows);groups[case['group']]=groups.get(case['group'],0)+1
            for row in rows:
                label=row['version'];outcomes[label][row['status']]=outcomes[label].get(row['status'],0)+1
                max_steps[label]=max(max_steps[label],row['steps'])
        require(groups==PLAN['case_groups'] and len(case_rows)==1106,'complete case domain differs')
        require(controls_guard()==original_controls and reader_controls()==own_controls,'control bytes/stats changed during reader')
        for inventory in inventories:
            for row in inventory['files'].values():require(seven(Path(row['source_path']).lstat())==row['seven_stats'],'actual raw changed during full readback')
        result.update(status='PASS_INDEPENDENT_R10_HELPER_TERMINAL_ONLY',case_pairs=553,actual_VM_calls=1106,
            logical_before_after_buffers=2212,groups=groups,outcomes=outcomes,max_steps=max_steps,
            full_original_domain_files=fresh['files'],full_original_domain_bytes=fresh['bytes'],
            original_owner=owner,actual_Root_outer=outer,complete_byte_event_error_resource_and_trace_equal=True,
            runtime_files=2496,source_files=3180,all_original_budgets_kept=True)
    except BaseException as error:
        errors.append({'where':'independent-helper-reader','type':type(error).__name__,'traceback':traceback.format_exc()})
    finally:
        result.update(elapsed_ns=time.monotonic_ns()-start,fresh_reads=len(READS),unique_read_paths=len({r['path'] for r in READS}),
            raw_files=sum(r['file_count'] for r in inventories),raw_logical_bytes=sum(r['logical_bytes'] for r in inventories))
        attempt(errors,'write-complete-actual-inventory',lambda:dump(EXEC/'COMPLETE-ACTUAL-RAW-INVENTORY.json',inventories))
        attempt(errors,'write-all-observation-readbacks',lambda:dump(EXEC/'ALL-HELPER-READBACKS.json',case_rows))
        attempt(errors,'write-all-reads',lambda:dump(EXEC/'ALL-READS.json',READS))
        if errors:result['status']='FAIL'
        attempt(errors,'write-reader-result',lambda:dump(EXEC/'RESULT.json',result))
        if errors:result['status']='FAIL'
        print(json.dumps({'status':result['status'],'case_observations':len(case_rows),'errors':errors,'products':0},sort_keys=True),flush=True)
    return 0 if result['status']=='PASS_INDEPENDENT_R10_HELPER_TERMINAL_ONLY' and not errors else 1

if __name__=='__main__':raise SystemExit(main())
