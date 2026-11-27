from pathlib import Path
import ast,copy,hashlib,json,os,stat,time,traceback
AUTHOR=Path('/tmp/hia-r11-predicate-controls-author-r1-dda7')
PLAN_RAW=(AUTHOR/'EXECUTION-PLAN.json').read_bytes()
PLAN=json.loads(PLAN_RAW)
SOURCE=Path(PLAN['source']['path'])
BASE=Path('/workspace/hia-r11-predicate-controls-r1-dda7')
ROOT_OUTER=Path('/tmp/hia-r11-predicate-controls-outer-r1-dda7')
READER_AUTHOR=Path('/tmp/hia-r11-predicate-terminal-reader-r1-dda7')
READER_BINDING_RAW=(READER_AUTHOR/'ACTUAL-BINDING.json').read_bytes()
READER_BINDING=json.loads(READER_BINDING_RAW)
EXEC=Path('/tmp/hia-r11-predicate-independent-readback-r1-dda7')
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


def validate_ascii_predicate_proof(generated):
    """Consume all three actual projection proofs without weakening prior checks."""
    require(set(generated) == {'functions', 'blocks', 'ops', 'word64_projection',
            'scalar_byte_projection', 'ascii_predicate_projection'}, 'R11 generated result keys differ')
    require({key: generated[key] for key in ('functions', 'blocks', 'ops')}
            == {'functions':107,'blocks':1456,'ops':6270}, 'R11 complete Core counts differ')
    # The complete R10 verifier is unchanged. This is its predecessor report view,
    # not a substitution for the actual R11 generated counts checked above.
    predecessor = {'functions':107,'blocks':1456,'ops':6299,
                   'word64_projection':generated['word64_projection'],
                   'scalar_byte_projection':generated['scalar_byte_projection']}
    validate_scalar_byte_proof(predecessor)
    proof = generated['ascii_predicate_projection']
    require(set(proof) == {'schema','original_counts','after_counts','original_core_sha256',
            'after_core_sha256','full_word_bits','all_byte_loads_and_casts_unchanged',
            'all_calls_stores_hashes_and_error_branches_unchanged','all_105_other_functions_unchanged',
            'all_function_and_block_ABIs_and_terminators_unchanged','new_range_or_initialization_assumption',
            'whole_inverse_equal','edits','predicates','complete_original_Core_verifier_returned',
            'public_compiler_or_VM_changed','machine_size_or_fuel_PASS_claim'}, 'R11 proof keys differ')
    require(proof['schema'] == 'hia.R11.private-ASCII-predicate-Core-projection.v1'
            and proof['original_counts'] == {'functions':107,'blocks':1456,'ops':6299}
            and proof['after_counts'] == {'functions':107,'blocks':1456,'ops':6270}
            and proof['original_core_sha256'] == predecessor['scalar_byte_projection']['after_core_sha256']
            and type(proof['after_core_sha256']) is str and len(proof['after_core_sha256']) == 64
            and all(c in '0123456789abcdef' for c in proof['after_core_sha256'])
            and type(proof['full_word_bits']) is int and proof['full_word_bits'] == 64,
            'R11 proof chain, full width, or complete counts differ')
    for key in ('all_byte_loads_and_casts_unchanged','all_calls_stores_hashes_and_error_branches_unchanged',
                'all_105_other_functions_unchanged','all_function_and_block_ABIs_and_terminators_unchanged',
                'whole_inverse_equal','complete_original_Core_verifier_returned'):
        require(proof[key] is True, 'R11 proof missing true claim: '+key)
    for key in ('new_range_or_initialization_assumption','public_compiler_or_VM_changed',
                'machine_size_or_fuel_PASS_claim'):
        require(proof[key] is False, 'R11 forbidden proof claim: '+key)
    expected = json.loads('{"edits":[{"after":[{"args":["v83","v85"],"attrs":{},"op":"buffer.load","out":[{"name":"v98","type":"u8"}]},{"args":["v98"],"attrs":{"mode":"wrap"},"op":"int.cast","out":[{"name":"v99","type":"usize"}]},{"args":[],"attrs":{"value":64},"op":"const","out":[{"name":"v100","type":"usize"}]},{"args":["v99","v100"],"attrs":{},"op":"compare.lt","out":[{"name":"v101","type":"bool"}]},{"args":[],"attrs":{"value":7205815478885811200},"op":"const","out":[{"name":"v102","type":"usize"}]},{"args":[],"attrs":{"value":2882303762188206080},"op":"const","out":[{"name":"v103","type":"usize"}]},{"args":["v101","v102","v103"],"attrs":{},"op":"select","out":[{"name":"v104","type":"usize"}]},{"args":[],"attrs":{"value":63},"op":"const","out":[{"name":"v105","type":"usize"}]},{"args":["v99","v105"],"attrs":{},"op":"bit.and","out":[{"name":"v106","type":"usize"}]},{"args":["v104","v106"],"attrs":{},"op":"int.shr.checked","out":[{"name":"v107","type":"usize"}]},{"args":[],"attrs":{"value":1},"op":"const","out":[{"name":"v108","type":"usize"}]},{"args":["v107","v108"],"attrs":{},"op":"bit.and","out":[{"name":"v109","type":"usize"}]},{"args":["v109","v108"],"attrs":{},"op":"compare.eq","out":[{"name":"v110","type":"bool"}]},{"args":[],"attrs":{"value":128},"op":"const","out":[{"name":"v111","type":"usize"}]},{"args":["v99","v111"],"attrs":{},"op":"compare.lt","out":[{"name":"v112","type":"bool"}]},{"args":["v112","v110"],"attrs":{},"op":"bool.and","out":[{"name":"v134","type":"bool"}]}],"before":[{"args":["v83","v85"],"attrs":{},"op":"buffer.load","out":[{"name":"v98","type":"u8"}]},{"args":["v98"],"attrs":{"mode":"wrap"},"op":"int.cast","out":[{"name":"v99","type":"usize"}]},{"args":[],"attrs":{"value":10},"op":"const","out":[{"name":"v100","type":"usize"}]},{"args":["v99","v100"],"attrs":{},"op":"compare.eq","out":[{"name":"v101","type":"bool"}]},{"args":[],"attrs":{"value":40},"op":"const","out":[{"name":"v102","type":"usize"}]},{"args":["v99","v102"],"attrs":{},"op":"compare.eq","out":[{"name":"v103","type":"bool"}]},{"args":["v101","v103"],"attrs":{},"op":"bool.or","out":[{"name":"v104","type":"bool"}]},{"args":[],"attrs":{"value":41},"op":"const","out":[{"name":"v105","type":"usize"}]},{"args":["v99","v105"],"attrs":{},"op":"compare.eq","out":[{"name":"v106","type":"bool"}]},{"args":["v104","v106"],"attrs":{},"op":"bool.or","out":[{"name":"v107","type":"bool"}]},{"args":[],"attrs":{"value":44},"op":"const","out":[{"name":"v108","type":"usize"}]},{"args":["v99","v108"],"attrs":{},"op":"compare.eq","out":[{"name":"v109","type":"bool"}]},{"args":["v107","v109"],"attrs":{},"op":"bool.or","out":[{"name":"v110","type":"bool"}]},{"args":[],"attrs":{"value":58},"op":"const","out":[{"name":"v111","type":"usize"}]},{"args":["v99","v111"],"attrs":{},"op":"compare.eq","out":[{"name":"v112","type":"bool"}]},{"args":["v110","v112"],"attrs":{},"op":"bool.or","out":[{"name":"v113","type":"bool"}]},{"args":[],"attrs":{"value":61},"op":"const","out":[{"name":"v114","type":"usize"}]},{"args":["v99","v114"],"attrs":{},"op":"compare.eq","out":[{"name":"v115","type":"bool"}]},{"args":["v113","v115"],"attrs":{},"op":"bool.or","out":[{"name":"v116","type":"bool"}]},{"args":[],"attrs":{"value":123},"op":"const","out":[{"name":"v117","type":"usize"}]},{"args":["v99","v117"],"attrs":{},"op":"compare.eq","out":[{"name":"v118","type":"bool"}]},{"args":["v116","v118"],"attrs":{},"op":"bool.or","out":[{"name":"v119","type":"bool"}]},{"args":[],"attrs":{"value":125},"op":"const","out":[{"name":"v120","type":"usize"}]},{"args":["v99","v120"],"attrs":{},"op":"compare.eq","out":[{"name":"v121","type":"bool"}]},{"args":["v119","v121"],"attrs":{},"op":"bool.or","out":[{"name":"v122","type":"bool"}]},{"args":[],"attrs":{"value":45},"op":"const","out":[{"name":"v123","type":"usize"}]},{"args":["v99","v123"],"attrs":{},"op":"compare.eq","out":[{"name":"v124","type":"bool"}]},{"args":["v122","v124"],"attrs":{},"op":"bool.or","out":[{"name":"v125","type":"bool"}]},{"args":[],"attrs":{"value":62},"op":"const","out":[{"name":"v126","type":"usize"}]},{"args":["v99","v126"],"attrs":{},"op":"compare.eq","out":[{"name":"v127","type":"bool"}]},{"args":["v125","v127"],"attrs":{},"op":"bool.or","out":[{"name":"v128","type":"bool"}]},{"args":[],"attrs":{"value":91},"op":"const","out":[{"name":"v129","type":"usize"}]},{"args":["v99","v129"],"attrs":{},"op":"compare.eq","out":[{"name":"v130","type":"bool"}]},{"args":["v128","v130"],"attrs":{},"op":"bool.or","out":[{"name":"v131","type":"bool"}]},{"args":[],"attrs":{"value":93},"op":"const","out":[{"name":"v132","type":"usize"}]},{"args":["v99","v132"],"attrs":{},"op":"compare.eq","out":[{"name":"v133","type":"bool"}]},{"args":["v131","v133"],"attrs":{},"op":"bool.or","out":[{"name":"v134","type":"bool"}]}],"path":["functions",16,"blocks",7,"ops"]},{"after":[{"args":["v44","v46"],"attrs":{},"op":"int.add.wrap","out":[{"name":"v59","type":"usize"}]},{"args":["v41","v59"],"attrs":{},"op":"buffer.load","out":[{"name":"v61","type":"u8"}]},{"args":["v61"],"attrs":{"mode":"wrap"},"op":"int.cast","out":[{"name":"v62","type":"usize"}]},{"args":[],"attrs":{"value":32},"op":"const","out":[{"name":"v63","type":"usize"}]},{"args":["v62","v63"],"attrs":{},"op":"bit.or","out":[{"name":"v64","type":"usize"}]},{"args":[],"attrs":{"value":97},"op":"const","out":[{"name":"v65","type":"usize"}]},{"args":["v64","v65"],"attrs":{},"op":"int.sub.wrap","out":[{"name":"v66","type":"usize"}]},{"args":[],"attrs":{"value":26},"op":"const","out":[{"name":"v67","type":"usize"}]},{"args":["v66","v67"],"attrs":{},"op":"compare.lt","out":[{"name":"v68","type":"bool"}]},{"args":[],"attrs":{"value":95},"op":"const","out":[{"name":"v69","type":"usize"}]},{"args":["v62","v69"],"attrs":{},"op":"compare.eq","out":[{"name":"v70","type":"bool"}]},{"args":["v68","v70"],"attrs":{},"op":"bool.or","out":[{"name":"v71","type":"bool"}]},{"args":[],"attrs":{"value":48},"op":"const","out":[{"name":"v72","type":"usize"}]},{"args":["v62","v72"],"attrs":{},"op":"int.sub.wrap","out":[{"name":"v73","type":"usize"}]},{"args":[],"attrs":{"value":10},"op":"const","out":[{"name":"v74","type":"usize"}]},{"args":["v73","v74"],"attrs":{},"op":"compare.lt","out":[{"name":"v75","type":"bool"}]},{"args":[],"attrs":{"value":0},"op":"const","out":[{"name":"v76","type":"usize"}]},{"args":["v46","v76"],"attrs":{},"op":"compare.ne","out":[{"name":"v77","type":"bool"}]},{"args":["v77","v75"],"attrs":{},"op":"bool.and","out":[{"name":"v78","type":"bool"}]},{"args":["v71","v78"],"attrs":{},"op":"bool.or","out":[{"name":"v79","type":"bool"}]},{"args":["v79"],"attrs":{},"op":"bool.not","out":[{"name":"v88","type":"bool"}]}],"before":[{"args":["v44","v46"],"attrs":{},"op":"int.add.wrap","out":[{"name":"v59","type":"usize"}]},{"args":["v41","v59"],"attrs":{},"op":"buffer.load","out":[{"name":"v61","type":"u8"}]},{"args":["v61"],"attrs":{"mode":"wrap"},"op":"int.cast","out":[{"name":"v62","type":"usize"}]},{"args":[],"attrs":{"value":0},"op":"const","out":[{"name":"v63","type":"usize"}]},{"args":[],"attrs":{"value":65},"op":"const","out":[{"name":"v64","type":"usize"}]},{"args":["v62","v64"],"attrs":{},"op":"compare.ge","out":[{"name":"v65","type":"bool"}]},{"args":[],"attrs":{"value":90},"op":"const","out":[{"name":"v66","type":"usize"}]},{"args":["v62","v66"],"attrs":{},"op":"compare.le","out":[{"name":"v67","type":"bool"}]},{"args":["v65","v67"],"attrs":{},"op":"bool.and","out":[{"name":"v68","type":"bool"}]},{"args":[],"attrs":{"value":97},"op":"const","out":[{"name":"v69","type":"usize"}]},{"args":["v62","v69"],"attrs":{},"op":"compare.ge","out":[{"name":"v70","type":"bool"}]},{"args":[],"attrs":{"value":122},"op":"const","out":[{"name":"v71","type":"usize"}]},{"args":["v62","v71"],"attrs":{},"op":"compare.le","out":[{"name":"v72","type":"bool"}]},{"args":["v70","v72"],"attrs":{},"op":"bool.and","out":[{"name":"v73","type":"bool"}]},{"args":["v68","v73"],"attrs":{},"op":"bool.or","out":[{"name":"v74","type":"bool"}]},{"args":[],"attrs":{"value":95},"op":"const","out":[{"name":"v75","type":"usize"}]},{"args":["v62","v75"],"attrs":{},"op":"compare.eq","out":[{"name":"v76","type":"bool"}]},{"args":["v74","v76"],"attrs":{},"op":"bool.or","out":[{"name":"v77","type":"bool"}]},{"args":[],"attrs":{"value":1},"op":"const","out":[{"name":"v78","type":"usize"}]},{"args":["v77","v78","v63"],"attrs":{},"op":"select","out":[{"name":"v79","type":"usize"}]},{"args":["v46","v63"],"attrs":{},"op":"compare.ne","out":[{"name":"v80","type":"bool"}]},{"args":[],"attrs":{"value":48},"op":"const","out":[{"name":"v81","type":"usize"}]},{"args":["v62","v81"],"attrs":{},"op":"compare.ge","out":[{"name":"v82","type":"bool"}]},{"args":["v80","v82"],"attrs":{},"op":"bool.and","out":[{"name":"v83","type":"bool"}]},{"args":[],"attrs":{"value":57},"op":"const","out":[{"name":"v84","type":"usize"}]},{"args":["v62","v84"],"attrs":{},"op":"compare.le","out":[{"name":"v85","type":"bool"}]},{"args":["v83","v85"],"attrs":{},"op":"bool.and","out":[{"name":"v86","type":"bool"}]},{"args":["v86","v78","v79"],"attrs":{},"op":"select","out":[{"name":"v87","type":"usize"}]},{"args":["v87","v63"],"attrs":{},"op":"compare.eq","out":[{"name":"v88","type":"bool"}]}],"path":["functions",79,"blocks",4,"ops"]}],"predicates":[{"after_pure_ops":14,"all_256_byte_values_checked":true,"all_u64_character_boundary_controls_equal":true,"before_pure_ops":35,"block":"b7","finite_evaluations_per_side":300,"full_u64_algebra":"c>=128 forces false; c<128 exhaustively checked; shift=c&63 always 0..63","function":"f16","index_classes":["zero"],"kind":"delimiter","new_buffer_accesses":0,"new_calls":0,"new_effects_or_traps":false,"terminator_unchanged":true,"unchanged_prefix_ops":2},{"after_pure_ops":18,"all_256_byte_values_checked":true,"all_u64_character_boundary_controls_equal":true,"before_pure_ops":26,"block":"b4","finite_evaluations_per_side":900,"full_u64_algebra":"(c|32)-97 modulo 2**64 <26 iff 65<=c<=90 or 97<=c<=122; (c-48) modulo 2**64 <10 iff 48<=c<=57; index is tested only for zero","function":"f79","index_classes":["zero","nonzero"],"kind":"identifier","new_buffer_accesses":0,"new_calls":0,"new_effects_or_traps":false,"terminator_unchanged":true,"unchanged_prefix_ops":3}]}')
    for key in ('edits','predicates'):
        require(json.dumps(proof[key],sort_keys=True,separators=(',',':'),allow_nan=False)
                == json.dumps(expected[key],sort_keys=True,separators=(',',':'),allow_nan=False),
                'R11 complete exact predicate proof differs: '+key)


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

def obj(path):return json.loads(read(path)[0])

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
    require(outer['schema']=='hia.root.r11.private-predicate.outer-result.v1'
        and outer['status']=='PASS_R11_PREDICATE_PARENT_PROCESS_ONLY' and outer['returncode']==0
        and outer['direct_restored_interpreter_invocations']==outer['maximum_attempts']==1
        and outer['timeout']is False and outer['subreaper']is True and outer['ECHILD']is True
        and outer['process_group_absent']is True and outer['adopted']==[], 'actual Root predicate outer did not close')
    require(intent['status']=='ROOT_AUTHORIZED_ADDITIONAL_R11_PREDICATE_GATE_ONCE'
        and intent['launch']==pin(launch_raw) and intent['launch_seven_stats']==seven((AUTHOR/'LAUNCH.json').lstat())
        and intent['planned_predicate_pairs']==1806 and intent['maximum_VM_calls']==3612
        and intent['original_eight_groups_executed']==0 and intent['original_owner_seconds']==180
        and intent['outer_watchdog_seconds']==1800 and intent['cleanup_seconds']==3
        and intent['maximum_attempts']==1 and outer['pid']==spawned['pid']==spawned['pgid'], 'Root intent differs')
    require(launch['outer_root']==str(ROOT_OUTER) and launch['outer_seconds']==1800
        and launch['outer_cleanup_seconds']==3 and launch['automatic_retry']is False,'Root original budgets differ')
    for name in ('stdout','stderr'):
        require(pin(read(ROOT_OUTER/(name+'.bin'))[0])==outer[name],'Root complete stream differs')
    require(read(ROOT_OUTER/'stderr.bin')[0]==b'','Root predicate stderr is nonempty')
    require(json.loads(read(ROOT_OUTER/'stdout.bin')[0])=={
        'status':'PASS_ADDITIONAL_PRIVATE_PREDICATES_ONLY','owner_attempts':1,'errors':[]},'Root stdout summary differs')
    return outer

RESOURCE_KEYS=('allocations','frees','allocation_attempts','owners_created','owners_dropped','live_owners',
    'live_bytes','peak_bytes','loans_started','loans_ended','live_local_loans','chains_created','chains_consumed',
    'live_chains','chain_nodes_created','chain_nodes_dropped','live_chain_nodes')

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()

def actual_programs(logic):
    generated=json.loads(fixed(PLAN['fixed_controls']['actual_R11_generation_report'])[0])['generated']
    validate_ascii_predicate_proof(generated);proof=generated['ascii_predicate_projection']
    documents={label:logic['parse_program'](fixed(PLAN['fixed_controls']['actual_'+label+'_source'])[0]) for label in ('R10','R11')}
    full={}
    for label,count,key in (('R10',6299,'original_core_sha256'),('R11',6270,'after_core_sha256')):
        doc=documents[label]
        require([f['name'] for f in doc['functions']]==['f'+str(i) for i in range(107)]
            and sum(len(f['blocks']) for f in doc['functions'])==1456
            and sum(len(b['ops']) for f in doc['functions'] for b in f['blocks'])==count,
            'complete actual Core counts differ')
        digest=pin(canonical(doc))['sha256'];require(digest==proof[key],'full exact text-to-Core identity differs')
        full[label]={'Core_sha256':digest,'input_sha256':digest}
    inverse=copy.deepcopy(documents['R11'])
    specs=(
        {'kind':'delimiter','function':'f16','fn_index':16,'block':'b7','block_index':7,'prefix':2,
         'params':[{'name':'v99','type':'usize'}],'result':'v134'},
        {'kind':'identifier_invalid','function':'f79','fn_index':79,'block':'b4','block_index':4,'prefix':3,
         'params':[{'name':'v62','type':'usize'},{'name':'v46','type':'usize'}],'result':'v88'})
    fragments={'R10':{},'R11':{}};fragment_pins={'R10':{},'R11':{}};observed=[]
    for spec,edit in zip(specs,proof['edits']):
        fi,bi=spec['fn_index'],spec['block_index'];a,b=(documents[label]['functions'][fi]['blocks'][bi] for label in ('R10','R11'))
        require(edit['path']==['functions',fi,'blocks',bi,'ops'] and a['ops']==edit['before'] and b['ops']==edit['after']
            and a['id']==b['id']==spec['block'] and a['params']==b['params'] and a['term']==b['term']
            and a['ops'][:spec['prefix']]==b['ops'][:spec['prefix']],'actual selected load/cast/block changed')
        inverse['functions'][fi]['blocks'][bi]['ops']=copy.deepcopy(edit['before'])
        item={'spec':spec,'actual_blocks':{'R10':a,'R11':b},'fragments':{}}
        for label,block in (('R10',a),('R11',b)):
            ops=copy.deepcopy(block['ops'][spec['prefix']:])
            fn={'name':'predicate','params':copy.deepcopy(spec['params']),'returns':['bool'],'effects':['trap'],'entry':'entry',
                'blocks':[{'id':'entry','params':copy.deepcopy(spec['params']),'ops':ops,'term':{'op':'ret','values':[spec['result']]}}]}
            doc={'schema':documents[label]['schema'],'module':'r11_predicate_boundary','functions':[fn]}
            folder=BASE/'predicate-controls/fragments'/label/spec['kind']
            require(obj(folder/'DERIVED-DOCUMENT.json')==doc,'actual derived fragment differs from exact source slice')
            raw=read(folder/'VERIFIED-CORE.json')[0]
            require(raw==canonical(doc),'actual verified fragment byte stream differs')
            digest=pin(raw)['sha256'];fragments[label][spec['kind']]=doc
            fragment_pins[label][spec['kind']]={'Core_sha256':digest,'input_sha256':digest}
            item['fragments'][label]=dict(fragment_pins[label][spec['kind']],
                derived_document=identity(folder/'DERIVED-DOCUMENT.json'),verified_core=identity(folder/'VERIFIED-CORE.json'),ops=len(ops))
        observed.append(item)
    require(inverse==documents['R10'],'full actual R11 document does not invert to R10')
    require(obj(BASE/'predicate-controls/ACTUAL-CORE-INVERSE.json')=={'full_programs':full,'whole_inverse_equal':True,
        '107_functions':True,'1456_blocks':True,'unchanged_functions':105,'actual_selected_blocks_and_fragments':observed},
        'actual complete inverse/fragment record differs')
    return documents,full,fragments,fragment_pins

def predicate_observations(case,state,insns,oracle):
    if case['kind']=='scalar':return [oracle(case)]
    wanted='v134' if case['function']=='f16' else 'v88';load_name='v98' if case['function']=='f16' else 'v61'
    effect_at=0;character=None;values=[]
    for event,ins in zip(state['operation_events'],insns):
        if ins['op']=='call' or ins['op'].startswith('buffer.'):
            effect=state['effects'][effect_at];effect_at+=1
            if event['depth']==0 and ins['op']=='buffer.load' and load_name in event['out']:
                if effect['outcome']=='completed':character=effect['values'][0]
        if event['depth']==0 and wanted in event['out']:
            require(character is not None,'actual predicate has no preceding actual byte load')
            probe={'predicate':'delimiter' if case['function']=='f16' else 'identifier_invalid',
                   'character':character,'index':0 if not values else 1}
            values.append(oracle(probe))
    return values

def observe_pair(index,case,documents,full,fragments,fragment_pins,logic,oracle,declared_pair,declared_calls):
    folder=BASE/'predicate-controls/cases'/str(index).zfill(4)
    require(obj(folder/'CASE.json')==case,'complete original case differs')
    pair=obj(folder/'PAIR.json')
    require(pair==declared_pair and pair['id']==case['id'] and pair['group']==case['group']
        and pair['kind']==case['kind'] and pair['status']=='PASS' and set(pair['versions'])=={'R10','R11'},'complete pair summary differs')
    if case['kind']=='scalar':require(obj(folder/'SCALAR-ORACLE.json')=={'value':oracle(case)},'independent scalar oracle differs')
    observations={};summaries=[];last_stop=None
    for offset,label in enumerate(('R10','R11')):
        directory=folder/label;request=obj(directory/'REQUEST.json');state=obj(directory/'OBSERVATION.json')
        roles=() if case['kind']=='scalar' else ('source','workspace')
        before={r:read(directory/(r+'.before.bin'))[0] for r in roles}
        after={r:read(directory/(r+'.after.bin'))[0] for r in roles}
        physical,owner_count=logic['expected_physical_state'](case)
        function='predicate' if case['kind']=='scalar' else case['function']
        document=fragments[label][case['predicate']] if case['kind']=='scalar' else documents[label]
        program=fragment_pins[label][case['predicate']] if case['kind']=='scalar' else full[label]
        arguments=[]
        if case['kind']=='scalar':arguments=[case['character']]+([case['index']] if case['predicate']=='identifier_invalid' else [])
        require(request=={'case':case,'program_sha256':program['Core_sha256'],'program_input_sha256':program['input_sha256'],
            'function':function,'scalar_arguments':arguments,'actual_initial_buffers':{r:pin(b) for r,b in before.items()},
            'view_state':physical,'physical_owner_count':owner_count,
            'limits':{'max_steps':10000000,'max_heap_bytes':1048576,'max_call_depth':128,'allocation_fail_at':None},
            'synthetic_source_output_buffers':False,'scalar_fragment_has_zero_buffers':case['kind']=='scalar'},'actual request differs')
        require(obj(directory/'CALL-INTENT.json')=={'id':case['id'],'version':label,'one_invocation':True},'actual one-call intent differs')
        require(state['status'] in ('returned','trapped','rejected') and state['actual_before']=={r:pin(b) for r,b in before.items()}
            and state['actual_after']=={r:pin(b) for r,b in after.items()}
            and state['physical_state']==physical and state['physical_owner_count']==owner_count,'actual outcome/buffers/view state differs')
        require(state['resources']=={name:0 for name in RESOURCE_KEYS},'predicate invocation changed ownership resources')
        require(state['call_attempts']==1 and state['Native_calls']==state['compile_calls']==0
            and state['observation_only_VM']is True,'unexpected product or retry')
        require(type(state['started_ns'])is int and type(state['stopped_ns'])is int
            and state['stopped_ns']>=state['started_ns'] and state['elapsed_ns']==state['stopped_ns']-state['started_ns'],'actual timing differs')
        if last_stop is not None:require(state['started_ns']>=last_stop,'new invocation overlaps the old one')
        last_stop=state['stopped_ns']
        insns=logic['trace_structure'](document,function,state['operation_events'],state['effects'],state['steps'],state['status'])
        canaries=logic['replay_bytes'](case,state['effects'],before,after,state)
        require(state['predicate_values']==predicate_observations(case,state,insns,oracle),'actual predicate values differ from captured-byte scalar oracle')
        comparison={'one_actual_invocation':True,'original_limit':True,'expected_outcome_class':True,'no_Native_or_compile':True}
        if case['kind']=='scalar':
            require(state['status']=='returned' and state['error']is None and state['values']==[oracle(case)]
                and state['predicate_values']==[oracle(case)] and before==after=={} and state['effects']==[], 'actual scalar predicate differs')
            comparison.update(real_scalar_result=True,no_scalar_buffers_or_effects=True)
        else:
            initial={'source':bytes.fromhex(case['source_hex']),'workspace':bytes.fromhex(case['workspace_hex'])}
            require(before==initial and all(canaries.values()) and all(len(after[r])==len(before[r]) for r in roles),'actual complete initial/final buffers differ')
            require(case['same_physical_owner'] or before['source']==after['source'],'unaliased source changed')
            require(not case['same_physical_owner'] or after['source']==after['workspace'],'shared-owner final observations differ')
            require(obj(folder/(label+'-UNTOUCHED.json'))==canaries,'actual untouched-byte record differs')
            comparison.update(complete_initial_buffers=True,complete_final_extents=True,all_untouched_bytes=True,
                source_unchanged_or_explicit_alias=True,shared_owner_consistent=True)
        if state['error']is None:require(not os.path.lexists(directory/'EXCEPTION.txt'),'successful invocation has exception witness')
        else:
            text=read(directory/'EXCEPTION.txt')[0].decode()
            require(text.startswith('Traceback (most recent call last):')
                and text.endswith(state['error']['type']+': '+state['error']['message']+'\n'),'full actual exception witness differs')
        require(obj(folder/(label+'-COMPARISON.json'))==comparison and pair['versions'][label]=={
            'comparison':comparison,'observation':identity(directory/'OBSERVATION.json')},'actual comparison/readback binding differs')
        require(declared_calls[index*2+offset]=={'id':case['id'],'version':label,'steps':state['steps'],'after_captured':True},'actual VM invocation order differs')
        observations[label]=(state,before,after)
        summaries.append({'id':case['id'],'version':label,'kind':case['kind'],'function':function,'status':state['status'],
            'steps':state['steps'],'before':{r:pin(b) for r,b in before.items()},'after':{r:pin(b) for r,b in after.items()},
            'operation_events':len(state['operation_events']),'ordered_effects':len(state['effects']),
            'observation':identity(directory/'OBSERVATION.json'),'complete_physical_bytes_and_effect_replay_equal':True,
            'fixed_Core_structural_trace_and_ticks_admitted':True,'exact_scalar_predicates_from_actual_loads':True})
    old,new=observations['R10'],observations['R11']
    require(old[1:]==new[1:] and all(old[0][k]==new[0][k] for k in
        ('status','values','error','effects','resources','physical_state','physical_owner_count','predicate_values')),
        'R10/R11 complete buffers/outcomes/original ordered effects differ')
    require(obj(folder/'PAIR-COMPARISON.json')=={'all_actual_buffers_outcomes_effects_resources_equal':True},'actual full pair comparison differs')
    return summaries


def main():
    start=time.monotonic_ns();errors=[];inventories=[];case_rows=[];fresh=None;original_controls=None;own_controls=None
    result={'schema':'hia.R11.predicate.independent-terminal-readback.v1','status':'FAIL','products':0,'project_imports':0,
        'whole_native':False,'matching_current_cold':False,'original_eight_groups_executed':0,'errors':errors}
    require(not os.path.lexists(EXEC),'one-shot reader output exists');mkdir(EXEC)
    try:
        own_controls=reader_controls();original_controls=controls_guard()
        material=dict(PLAN);auth=material.pop('authorization_pin')
        require(pin(encode(material))['sha256']==auth,'predicate authorization differs')
        require(PLAN['case_count']==1806 and PLAN['maximum_VM_calls']==3612
            and PLAN['budgets']=={'VM_max_steps':10000000,'VM_max_heap_bytes':1048576,'VM_max_call_depth':128,
                'qualification_seconds':180,'cleanup_seconds':3,'outer_watchdog_seconds':1800,'outer_cleanup_seconds':3},'limits differ')
        fresh=snapshot(EXEC/'FULL-FRESH-6777.json')
        for name in ('executable','library'):fixed(PLAN['runtime'][name])
        inventories=[current_tree(BASE,'predicate'),current_tree(ROOT_OUTER,'outer')]
        outer=actual_root_outer();launch=obj(BASE/'LAUNCH.json');owner=original_owner(BASE,launch)
        expected_command=[PLAN['runtime']['executable']['path'],'-I','-S','-B',str(AUTHOR/'run_predicate_gate.py'),
            '--plan-sha256',auth,'--child']
        require(launch=={'command':expected_command,'cwd':str(SOURCE),'env':PLAN['environment'],
            'supervisor_env':PLAN['environment'],'qualification_seconds':180,'cleanup_seconds':3,'automatic_retry':False},'actual owner launch differs')
        request=obj(BASE/'OWNER.json.request.json')
        require(request['stdout_path']==str(BASE/'stdout.bin') and request['stderr_path']==str(BASE/'stderr.bin')
            and request['receipt_path']==str(BASE/'OWNER.json') and request['deadline_ns']-request['started_ns']==180000000000,
            'original owner paths/deadline differ')
        parent=obj(BASE/'RESULT.json');child=obj(BASE/'predicate-controls/RESULT.json')
        require(parent['schema']=='hia.R11.predicate-boundary-owner.v1' and parent['status']=='PASS_ADDITIONAL_PRIVATE_PREDICATES_ONLY'
            and parent['errors']==[] and parent['owner_attempts']==1 and parent['owner']==owner
            and parent['actual_child_result']==child and parent['retry']is False,'actual parent/owner/child binding differs')
        require(child['schema']=='hia.R11.predicate-boundary-result.v1' and child['status']=='PASS_ADDITIONAL_PRIVATE_PREDICATES_ONLY'
            and child['errors']==[] and child['not_started']==[]
            and child['attempted_cases']==child['declared_cases']==child['completed_pairs']==1806
            and child['actual_VM_calls']==child['VM_invocation_attempts']==3612
            and len(child['case_pairs'])==1806 and len(child['invocations'])==3612,'complete predicate result differs')
        for data in (parent,child):
            require(data['Native_calls']==data['compile_calls']==data['original_eight_groups_executed']==0
                and data['whole_native']is False and data['matching_current_cold']is False,'result claims other qualification')
        require(child['generation_calls']==child['semantic_f0_calls']==0
            and child['missing_frames_policy']=='Failure retained, never filled from expected bytes','unexpected generator/public entry or missing-frame policy')
        for folder in (BASE,BASE/'predicate-controls'):
            for when in ('BEFORE','AFTER'):
                require(obj(folder/('FULL-FRESH-'+when+'.json'))==fresh,'saved full fresh map differs')
                require(obj(folder/('CONTROLS-'+when+'.json'))==original_controls,'saved complete controls differ')
                runtime=obj(folder/('RUNTIME-'+when+'.json'))
                require(runtime['executable']==PLAN['runtime']['executable']['path'] and runtime['environment']==PLAN['environment']
                    and runtime['version'].startswith('3.14.4 '),'saved runtime context differs')
        require(read(BASE/'stderr.bin')[0]==b'' and read(BASE/'OWNER.json.stderr.log')[0]==b'','actual predicate stderr differs')
        require(json.loads(read(BASE/'stdout.bin')[0])=={
            'status':'PASS_ADDITIONAL_PRIVATE_PREDICATES_ONLY','completed_pairs':1806,'errors':[]},'child stdout differs')
        prefix=json.loads(fixed(PLAN['fixed_controls']['actual_Root_prefix_proof'])[0])
        require(prefix['status']=='PASS_INDEPENDENT_R11_PREFIX_TERMINAL_ONLY'
            and prefix['exact_scalar_editpaths']==9 and prefix['exact_ascii_editpaths']==2
            and prefix['word64_then_scalar_proof_chain']is True
            and prefix['word64_then_scalar_then_ascii_proof_chain']is True,'actual independent prefix predecessor differs')
        logic_raw=read(READER_AUTHOR/'observation_logic.py')[0]
        logic_tree=ast.parse(logic_raw)
        require(all(isinstance(n,ast.Import) and all(a.name in ('copy','json','re') for a in n.names)
            for n in ast.walk(logic_tree) if isinstance(n,(ast.Import,ast.ImportFrom))),'readback logic imports a product')
        logic={'__name__':'_recorded_byte_and_structural_readback'}
        exec(compile(logic_raw,'<fixed-recorded-byte-and-structural-readback>','exec'),logic)
        documents,full,fragments,fragment_pins=actual_programs(logic)
        cases=obj(AUTHOR/'CASES.json')
        require(len(cases)==1806 and [c['id'] for c in cases]==PLAN['case_order'],'case order differs')
        oracle_raw=read(READER_AUTHOR/'boundary_cases.py')[0]
        require(oracle_raw==read(AUTHOR/'boundary_cases.py')[0] and not any(isinstance(n,(ast.Import,ast.ImportFrom)) for n in ast.walk(ast.parse(oracle_raw))),
            'frozen independent scalar oracle changed or imports a product')
        namespace={'__name__':'_readback_only_scalar_oracle'}
        exec(compile(oracle_raw,'<fixed-independent-scalar-oracle>','exec'),namespace)
        require(namespace['cases']()==cases,'case factory differs')
        groups={};outcomes={'R10':{},'R11':{}};max_steps={'R10':0,'R11':0};kinds={};spans=0
        for index,case in enumerate(cases):
            rows=observe_pair(index,case,documents,full,fragments,fragment_pins,logic,namespace['scalar_oracle'],
                child['case_pairs'][index],child['invocations'])
            case_rows.extend(rows);groups[case['group']]=groups.get(case['group'],0)+1
            kinds[case['kind']]=kinds.get(case['kind'],0)+1
            for row in rows:
                label=row['version'];outcomes[label][row['status']]=outcomes[label].get(row['status'],0)+1
                max_steps[label]=max(max_steps[label],row['steps']);spans+=len(row['before'])+len(row['after'])
        require(groups==PLAN['case_groups'] and len(case_rows)==3612
            and kinds=={'scalar':1056,'function':750} and spans==6000,'complete case/physical-span domain differs')
        require(controls_guard()==original_controls and reader_controls()==own_controls,'control bytes/stats changed during reader')
        for inventory in inventories:
            for row in inventory['files'].values():require(seven(Path(row['source_path']).lstat())==row['seven_stats'],'actual raw changed during full readback')
        result.update(status='PASS_INDEPENDENT_R11_PREDICATE_TERMINAL_ONLY',case_pairs=1806,actual_VM_calls=3612,
            logical_before_after_buffers=6000,scalar_pairs_without_buffers=1056,full_function_pairs=750,
            groups=groups,outcomes=outcomes,max_steps=max_steps,
            full_original_domain_files=fresh['files'],full_original_domain_bytes=fresh['bytes'],
            original_owner=owner,actual_Root_outer=outer,complete_byte_event_error_resource_and_trace_equal=True,
            actual_Core_structural_path_and_tick_reconstruction=True,
            recorded_pure_opcode_values_not_reexecuted=True,
            exact_scalar_predicates_from_actual_load_values=True,
            actual_prefix_independent_proof=PLAN['fixed_controls']['actual_Root_prefix_proof'],
            runtime_files=2496,source_files=3180,all_original_budgets_kept=True)
    except BaseException as error:
        errors.append({'where':'independent-predicate-reader','type':type(error).__name__,'traceback':traceback.format_exc()})
    finally:
        result.update(elapsed_ns=time.monotonic_ns()-start,fresh_reads=len(READS),unique_read_paths=len({r['path'] for r in READS}),
            raw_files=sum(r['file_count'] for r in inventories),raw_logical_bytes=sum(r['logical_bytes'] for r in inventories))
        attempt(errors,'write-complete-actual-inventory',lambda:dump(EXEC/'COMPLETE-ACTUAL-RAW-INVENTORY.json',inventories))
        attempt(errors,'write-all-observation-readbacks',lambda:dump(EXEC/'ALL-PREDICATE-READBACKS.json',case_rows))
        attempt(errors,'write-all-reads',lambda:dump(EXEC/'ALL-READS.json',READS))
        if errors:result['status']='FAIL'
        attempt(errors,'write-reader-result',lambda:dump(EXEC/'RESULT.json',result))
        if errors:result['status']='FAIL'
        print(json.dumps({'status':result['status'],'case_observations':len(case_rows),'errors':errors,'products':0},sort_keys=True),flush=True)
    return 0 if result['status']=='PASS_INDEPENDENT_R11_PREDICATE_TERMINAL_ONLY' and not errors else 1

if __name__=='__main__':raise SystemExit(main())
