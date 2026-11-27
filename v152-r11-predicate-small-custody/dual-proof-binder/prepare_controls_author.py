"""Metadata-only R11 projection of the eight frozen groups; no project import."""
from pathlib import Path
import argparse,ast,base64,copy,hashlib,json,os,stat

ROOT=Path(__file__).resolve().parent
OLD=Path('/tmp/hia-u32-r8-post-reset-r4-dda7')
PREFIX=Path('/workspace/hia-r11-prefix-r1-dda7')
OUTPUT=Path('/workspace/hia-r11-controls-r1-dda7')
AUTHOR=Path('/tmp/hia-r11-execution-author-r1-dda7')
CANDIDATE=Path('/tmp/hia-r11-ascii-predicate-author-r1-dda7/overlay/tools/generate_hia_file_render_checker_word64_ascii.py')
FIELDS=('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')

def encode(v):return (json.dumps(v,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def pin(b,m=None):
    p={'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest(),'git_blob':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()}
    if m is not None:p.update(mode=m,git_mode='100755' if m&0o111 else '100644')
    return p
def read(p):
    p=Path(p)
    for parent in reversed(p.parents):assert stat.S_ISDIR(parent.lstat().st_mode),parent
    s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1,p
    stamp=[getattr(s,k) for k in FIELDS]
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        assert [getattr(os.fstat(fd),k) for k in FIELDS]==stamp
        with os.fdopen(fd,'rb',closefd=False) as f:b=f.read(s.st_size+1)
        assert len(b)==s.st_size and [getattr(os.fstat(fd),k) for k in FIELDS]==stamp==[getattr(p.lstat(),k) for k in FIELDS]
    finally:os.close(fd)
    return b,stat.S_IMODE(s.st_mode),stamp
def identity(p):
    b,m,s=read(p);return {'path':str(p),'identity':pin(b,m),'seven_stats':s}
def origin(p):
    r=identity(p);return {'path':r['path'],'identity':r['identity'],'stat':dict(zip(FIELDS,r['seven_stats'],strict=True))}
def write(n,b,m=0o644):
    p=ROOT/n;p.parent.mkdir(parents=True,exist_ok=True)
    with p.open('xb') as f:f.write(b)
    p.chmod(m);assert read(p)[:2]==(b,m)
def functions(b):
    lines=b.decode().splitlines(True)
    return {n.name:''.join(lines[n.lineno-1:n.end_lineno]).encode() for n in ast.parse(b).body if isinstance(n,ast.FunctionDef)}
def check_owner(folder):
    raw=read(folder/'OWNER.json')[0];ret=json.loads(read(folder/'OWNER-RETURNED.json')[0]);r=json.loads(raw)
    r.update(supervisor_returncode=ret['supervisor_returncode'],receipt_sha256=pin(raw)['sha256']);assert r==ret
    assert r['status']=='OWNED_PROCESS_COMPLETED' and r['returncode']==r['supervisor_returncode']==0
    assert r['qualification_seconds']==180 and r['cleanup_seconds']==3 and not r['timed_out']
    assert r['exit_observed_before_deadline'] and r['cleanup']['complete'] and r['cleanup']['observed_echild']
    return r

def require(value, message):
    if not value: raise AssertionError(message)

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


def admit_predicate_proof(raw, prefix_proof):
    """Require the actual complete independent boundary result, not a prediction."""
    r=json.loads(raw)
    assert r['schema']=='hia.R11.predicate.independent-terminal-readback.v1'
    assert r['status']=='PASS_INDEPENDENT_R11_PREDICATE_TERMINAL_ONLY' and r['errors']==[]
    assert r['products']==r['project_imports']==r['original_eight_groups_executed']==0
    assert r['whole_native'] is False and r['matching_current_cold'] is False
    assert (r['case_pairs'],r['actual_VM_calls'],r['logical_before_after_buffers'])==(1806,3612,6000)
    assert (r['scalar_pairs_without_buffers'],r['full_function_pairs'])==(1056,750)
    assert (r['full_original_domain_files'],r['full_original_domain_bytes'],r['source_files'],r['runtime_files'])==(6777,948620735,3180,2496)
    assert r['complete_byte_event_error_resource_and_trace_equal'] is True
    assert r['actual_Core_structural_path_and_tick_reconstruction'] is True
    assert r['recorded_pure_opcode_values_not_reexecuted'] is True
    assert r['exact_scalar_predicates_from_actual_load_values'] is True and r['all_original_budgets_kept'] is True
    assert r['actual_prefix_independent_proof']==prefix_proof
    assert r['groups']=={'borrow_state':15,'delimiter_neighbors':28,'identifier_edges':20,'identifier_offsets':9,
        'identifier_tail_byte':256,'lexer_edges':25,'lexer_first_byte':256,'preexisting_error':21,'same_owner':3,
        'scalar_delimiter':264,'scalar_identifier_invalid':792,'short_source':12,'short_workspace':74,'short_workspace_error':31}
    assert set(r['outcomes'])==set(r['max_steps'])=={'R10','R11'}
    for name in ('R10','R11'):
        assert set(r['outcomes'][name])<={'returned','trapped','rejected'}
        assert sum(r['outcomes'][name].values())==1806 and all(type(n)is int and n>=0 for n in r['outcomes'][name].values())
        assert type(r['max_steps'][name])is int and 0<r['max_steps'][name]<=10000000
    assert r['fresh_reads']>=6777 and r['raw_files']>0 and r['raw_logical_bytes']>0
    owner=r['original_owner'];outer=r['actual_Root_outer']
    assert owner['status']=='OWNED_PROCESS_COMPLETED' and owner['returncode']==owner['supervisor_returncode']==0
    assert owner['qualification_seconds']==180 and owner['cleanup_seconds']==3 and owner['timed_out'] is False
    assert owner['exit_observed_before_deadline'] is True and owner['cleanup']['complete'] is True
    assert owner['cleanup']['observed_echild'] is True and owner['cleanup']['remaining_direct_children']==[]
    assert outer['status']=='PASS_R11_PREDICATE_PARENT_PROCESS_ONLY' and outer['returncode']==0
    assert outer['direct_restored_interpreter_invocations']==outer['maximum_attempts']==1
    assert outer['timeout'] is False and outer['ECHILD'] is True and outer['process_group_absent'] is True and outer['adopted']==[]
    return r

def main(root_proof,root_proof_git,root_predicate_proof,root_predicate_proof_git):
    assert not OUTPUT.exists() and not OUTPUT.is_symlink()
    root_proof=identity(root_proof);assert root_proof['identity']['git_blob']==root_proof_git
    root_result=json.loads(read(root_proof['path'])[0])
    assert root_result['status']=='PASS_INDEPENDENT_R11_PREFIX_TERMINAL_ONLY'
    assert root_result['exact_scalar_editpaths']==9 and root_result['word64_then_scalar_proof_chain'] is True
    assert root_result['exact_ascii_editpaths']==2 and root_result['word64_then_scalar_then_ascii_proof_chain'] is True
    assert (root_result['generation'],root_result['compile'],root_result['pack'],root_result['original_product_owners'])==(2,1,1,3)
    assert root_result['semantic_Native']==root_result['semantic_VM']==root_result['ELF_execution']==0
    assert root_result['all_before_after_source_runtime_maps_equal'] and root_result['all_test_limits_unchanged']
    assert root_result['original_frame_ELF_checks_full'] and root_result['full_logical_buffers']==12 and root_result['physical_canary_spans']==6
    assert (root_result['fresh_domain_files'],root_result['fresh_domain_bytes'],root_result['source_files'],root_result['runtime_files'])==(6777,948620735,3180,2496)
    assert root_predicate_proof.is_absolute()
    predicate_proof=identity(root_predicate_proof)
    assert predicate_proof['identity']['git_blob']==root_predicate_proof_git
    admit_predicate_proof(read(predicate_proof['path'])[0],root_proof)
    old_raw=read(OLD/'EXECUTION-PLAN.json')[0];old=json.loads(old_raw)
    assert len(old['fixed_inputs'])==948 and len(old['phases'])==8
    before={n:read(OLD/n) for n in old['controls']}
    assert all(pin(b,m)==old['controls'][n] for n,(b,m,_) in before.items())
    prefix=json.loads(read(PREFIX/'RESULT.json')[0]);generated=json.loads(read(PREFIX/'GENERATED-BINDING.json')[0])
    assert prefix['status']=='PASS_PRIVATE_R11_GENERATION_AND_SIZE_PACK_ONLY' and prefix['finalization_errors']==[]
    assert prefix['generation_owner_launches']==2 and prefix['size_driver_attempts']==1
    assert prefix['compile_calls_attempted']==prefix['pack_calls_attempted']==1
    assert prefix['VM_calls']==prefix['semantic_Native_cases']==prefix['aggregate_cases']==prefix['ELF_exec_calls']==0
    assert prefix['not_started']==[] and [r['stage'] for r in prefix['stages']]==['generate','check','size-pack']
    assert all(r['status']=='PASS' for r in prefix['stages'])
    for row in generated['files'].values():assert identity(row['path'])==row
    first=read(PREFIX/'generation/generate/report.json')[0];assert first==read(PREFIX/'generation/check/report.json')[0]
    report=json.loads(first);counts=report['generated'];p=counts['word64_projection']
    assert set(counts)=={'functions','blocks','ops','word64_projection','scalar_byte_projection','ascii_predicate_projection'}
    assert {k:counts[k] for k in ('functions','blocks','ops')}=={'functions':107,'blocks':1456,'ops':6270}
    assert p['whole_inverse_equal'] and p['complete_original_Core_verifier_returned'] and len(p['removed_identity_casts'])==317
    validate_ascii_predicate_proof(counts)
    for stage in ('generate','check'):check_owner(PREFIX/'generation'/stage)
    size=PREFIX/'size-pack';check_owner(size)
    actual=json.loads(read(size/'RESULT.json')[0]);outer=json.loads(read(size/'OUTER.json')[0])
    assert actual['status']==outer['status']=='PASS_EXPLICIT_U32_SIZE_AND_PRIVATE_PACK_ONLY'
    assert actual['compile_calls_attempted']==actual['pack_calls_attempted']==1 and actual['finalization_errors']==[]
    assert actual==outer['actual_child_result'] and outer['finalization_errors']==[]
    source=identity(PREFIX/'generated/file_render_checker_word64_ascii.hepta')
    image=identity(size/'R8.u32.image.bin');elf=identity(size/'R8.private-nonexecuted.elf.bin')
    assert source==prefix['actual_generated_source']==generated['files']['source']
    assert {k:image['identity'][k] for k in ('bytes','sha256','git_blob')}==actual['image']==prefix['actual_image']
    assert {k:elf['identity'][k] for k in ('bytes','sha256','git_blob')}==actual['ELF']==prefix['actual_ELF']
    for name,observed in (('source',source),('image',image),('ELF',elf)):
        assert {k:observed['identity'][k] for k in ('bytes','sha256','git_blob')}==root_result[name]
    assert source['identity']['sha256']==report['source_sha256'] and source['identity']['bytes']==report['source_bytes']
    assert source['identity']['mode']==image['identity']['mode']==elf['identity']['mode']==0o644
    assert actual['size']['frame_admitted'] and actual['size']['ELF_admitted'] and image['identity']['bytes']<=557376 and elf['identity']['bytes']<=1048576
    candidate=identity(CANDIDATE);assert candidate['identity']['git_blob']=='5d7d76b60aac581bbd1d2238be574debaba6ef2d'
    candidate_raw=read(CANDIDATE)[0]
    assert functions(candidate_raw)['source_program']==functions(before['inputs/R8-GENERATOR.py'][0])['source_program']
    edits={};after={n:(b,m) for n,(b,m,_) in before.items()}
    def replace(n,a,b,count):
        raw,m=after[n];assert raw.count(a.encode())==count,(n,a,raw.count(a.encode()))
        changed=raw.replace(a.encode(),b.encode())
        assert changed.count(b.encode())==count and changed.replace(b.encode(),a.encode())==raw
        edits.setdefault(n,[]).append({'before':a,'after':b,'count':count});after[n]=(changed,m)
    for role,count in [('R8-source',2),('R8-image',2),('R8-elf',1),('R8-result',1),('R8-generator',1)]:
        replace('r8_common.py',repr(role),repr(role.replace('R8-','R11-')),count)
    for name,count in [('R8-GENERATOR.py',2),('R8-OWNER.json',1),('R8-RESULT.json',1)]:
        replace('r8_common.py',repr('inputs/'+name),repr('inputs/'+name.replace('R8-','R11-')),count)
    replace('r8_private_reference.py',old['fixed_inputs']['R8-source']['identity']['sha256'],source['identity']['sha256'],1)
    replace('r8_private_reference.py',"PROFILE = 'hepta.test-only.u32-r8-roundtrip-reference.v1'","PROFILE = 'hepta.test-only.u32-r11-ascii-roundtrip-reference.v1'",1)
    for n,suffix in [('semantic/authoring/support.py','semantic'),('aggregate/successor-r2/authoring/support.py','aggregate/successor-r2'),('aggregate/successor-r3/authoring/support.py','aggregate/successor-r3')]:
        replace(n,repr(str(Path(old['output'])/suffix)),repr(str(OUTPUT/suffix)),1)
    fixture=json.loads(before['fixtures/REPORT.json'][0])
    fixture['build']['executable']=str(OUTPUT/'aggregate/successor-r2/evidence/build-r2/built/private-R8.elf')
    fixture['build']['elf_inspection']=actual['elf_inspection'];fixture['image']=actual['image']
    fixture['images']['semantic']={k:actual['image'][k] for k in ('bytes','sha256')}
    fixture['input_sha256']=source['identity']['sha256'];fixture['origin']=origin(size/'RESULT.json')
    fixture['status_meaning']='fixed input projection of actual completed R11 generation/size/pack only; no semantic result'
    fixture_raw=encode(fixture);after['fixtures/REPORT.json']=(fixture_raw,before['fixtures/REPORT.json'][1])
    fixture_outer=json.loads(before['fixtures/OUTER.json'][0])
    fixture_outer.update(actual_outer=origin(size/'OUTER.json'),actual_owner=origin(size/'OWNER.json'),
        status_meaning='admitted actual R11 size owner/input view; no new semantic owner execution')
    after['fixtures/OUTER.json']=(encode(fixture_outer),before['fixtures/OUTER.json'][1])
    old_elf=old['fixed_inputs']['R8-elf']['identity'];new_elf=elf['identity']
    kernel='aggregate/successor-r2/authoring/run_kernel_130_r1.py';observer='aggregate/successor-r3/authoring/run_observer_build.py';pipeline='aggregate/successor-r3/authoring/run_pipeline_vm_r1.py'
    replace(kernel,old_elf['sha256'],new_elf['sha256'],1)
    # The retained method contains this original literal. The later R4 input
    # fixture has a different path-bound hash; R4 never reached kernel130.
    # Preserve both facts and invert this exact method literal, not an assumed
    # equality between its historical literal and the current R4 fixture.
    replace(kernel,repr('232b616bebcd49dd129725aeee83460813fd47ad94eaa5a60d5939d5c20d0ea8'),repr(pin(fixture_raw)['sha256']),1)
    replace(kernel,'len(elf) == '+str(old_elf['bytes']),'len(elf) == '+str(new_elf['bytes']),1)
    replace(observer,old_elf['sha256'],new_elf['sha256'],1)
    replace(observer,'assert len(original_elf) == '+str(old_elf['bytes'])+' and','assert len(original_elf) == '+str(new_elf['bytes'])+' and',1)
    replace(observer,'len(elf) == len(original_elf) == '+str(old_elf['bytes']),'len(elf) == len(original_elf) == '+str(new_elf['bytes']),1)
    replace(pipeline,'len(elf) == '+str(old_elf['bytes']),'len(elf) == '+str(new_elf['bytes']),1)
    plan=copy.deepcopy(old);plan['output']=str(OUTPUT);plan['runtime']['environment']['HOME']=str(OUTPUT)
    paths={'R11-source':Path(source['path']),'R11-image':Path(image['path']),'R11-elf':Path(elf['path']),
        'R11-generator':CANDIDATE,'R11-owner':size/'OWNER.json','R11-result':size/'RESULT.json','R11-outer':size/'OUTER.json',
        'R11-root-proof':Path(root_proof['path']),'R11-prefix-result':PREFIX/'RESULT.json','R11-generated-binding':PREFIX/'GENERATED-BINDING.json',
        'R11-generate-report':PREFIX/'generation/generate/report.json','R11-check-report':PREFIX/'generation/check/report.json',
        'R11-generate-owner':PREFIX/'generation/generate/OWNER-RETURNED.json','R11-check-owner':PREFIX/'generation/check/OWNER-RETURNED.json',
        'R11-predicate-independent-proof':Path(predicate_proof['path'])}
    active={n:identity(p) for n,p in paths.items()}
    for n,row in active.items():
        assert n not in plan['fixed_inputs'];plan['fixed_inputs'][n]={'path':row['path'],'identity':row['identity'],'phases':['*']}
    for n,filename in [('R11-generator','R11-GENERATOR.py'),('R11-owner','R11-OWNER.json'),('R11-result','R11-RESULT.json')]:
        b,m,_=read(active[n]['path']);after['inputs/'+filename]=(b,m)
    plan['R11_explicit_successor']={'schema':'hia.R11.actual-input-projection.v1','private_candidate_only':True,
        'prefix_result':identity(PREFIX/'RESULT.json'),'prefix_plan':identity(AUTHOR/'PREFIX-PLAN.json'),
        'root_prefix_proof':root_proof,'root_predicate_proof':predicate_proof,
        'independent_prefix_and_boundary_required':True,
        'retained_prior_candidate_roles':14,'additional_predicate_proof_roles':1,
        'actual_candidate_roles':active,'old948_retained_exact':True,
        'old_R4_semantics_qualification':'FAIL_VM_FUEL_RETAINED','original_ORACLE_RESTORE_PLAN_unchanged':True,
        'new_oracle_owner_executions':0,'ordinary_B3_and_profile_compiler_unchanged':True,
        'original_SIZE_history_unchanged':True,'old_R8_labels_are_legacy_role_names_only':True,
        'new_source_image_and_ELF_from_actual_prefix':True,'product_executions_before_Root_authorization':0}
    changes=[]
    for n,(b,m) in after.items():
        if n in before:
            prior,prior_mode,_=before[n];assert m==prior_mode
            if n in edits:
                back=b
                for e in reversed(edits[n]):
                    assert back.count(e['after'].encode())==e['count'];back=back.replace(e['after'].encode(),e['before'].encode())
                assert back==prior,(n,'whole inverse')
            elif n not in ('fixtures/REPORT.json','fixtures/OUTER.json'):assert b==prior,(n,'unapproved byte change')
            if b!=prior:changes.append({'path':n,'before':pin(prior,m),'after':pin(b,m),
                'before_base64':base64.b64encode(prior).decode(),'after_base64':base64.b64encode(b).decode(),
                'literal_replacements':edits.get(n),'explicit_fixture_JSON_projection':n.startswith('fixtures/')})
        if n.endswith('.py'):ast.parse(b,filename=n)
        write(n,b,m)
    for n in ('_checked_components','execute_linux_file_roundtrip','execute_program'):
        assert functions(after['r8_private_reference.py'][0])[n]==functions(before['r8_private_reference.py'][0])[n]
    assert after['run_controls.py'][0]==before['run_controls.py'][0]
    assert after['ORACLE-RESTORE-PLAN.json']==before['ORACLE-RESTORE-PLAN.json'][:2]
    protected=('phases','budgets','maximum_actual_calls','minimum_free_bytes','fail_stop','automatic_retry',
        'original_kernel130_order','original_native162_order','original_semantic_six_order','original_observation_paths',
        'public_component_pins','source','requires_prior_original_oracle_restore','native_guard_hex')
    assert all(plan[k]==old[k] for k in protected)
    assert {k:plan['fixed_inputs'][k] for k in old['fixed_inputs']}==old['fixed_inputs']
    plan['controls']={n:pin(b,m) for n,(b,m) in after.items()}
    inverse={'schema':'hia.R11.eight-group-exact-inverse.v1','status':'PASS_AUTHORING_ONLY',
        'original_plan':identity(OLD/'EXECUTION-PLAN.json'),'original_control_count':len(before),
        'changed_existing_files':changes,'new_control_files':['inputs/R11-GENERATOR.py','inputs/R11-OWNER.json','inputs/R11-RESULT.json'],
        'old948_fixed_inputs_full_exact_projection':True,'new_R11_roles':list(active),
        'old_original_role_count':948,'new_total_role_count':len(plan['fixed_inputs']),
        'original_phase_budgets_case_order_and_assert_operators_preserved':True,
        'private_three_functions_whole_bytes_unchanged':True,'run_controls_whole_bytes_unchanged':True,
        'ORACLE_RESTORE_PLAN_fullbytes_unchanged':True,'root_proof':root_proof,'product_executions':0,
        'retained_kernel_fixture_binding':{'original_method_literal':'232b616bebcd49dd129725aeee83460813fd47ad94eaa5a60d5939d5c20d0ea8',
            'current_R4_fixture_sha256':pin(before['fixtures/REPORT.json'][0])['sha256'],
            'R4_kernel_group_executed':False,'R11_actual_fixture_sha256':pin(fixture_raw)['sha256'],
            'original_assert_operator_and_whole_inverse_preserved':True}}
    write('R11-EXACT-INVERSE.json',encode(inverse));plan['controls']['R11-EXACT-INVERSE.json']=pin(encode(inverse),0o644)
    plan.pop('authorization_pin');plan['authorization_pin']=pin(encode(plan))['sha256']
    reverse=copy.deepcopy(plan);reverse.pop('R11_explicit_successor');reverse['authorization_pin']=old['authorization_pin']
    reverse['output']=old['output'];reverse['runtime']=old['runtime']
    for n in active:reverse['fixed_inputs'].pop(n)
    reverse['controls']=old['controls'];assert encode(reverse)==old_raw,'whole old plan inverse'
    write('EXECUTION-PLAN.json',encode(plan))
    launch={'schema':'hia.R11.eight-groups.launch-author.v1','status':'AUTHORING_ONLY','cwd':old['source']['path'],
        'argv':['/usr/bin/env','-i']+[k+'='+v for k,v in sorted(plan['runtime']['environment'].items())]
            +[plan['runtime']['executable']['path'],'-B',str(ROOT/'run_controls.py'),'--plan-sha256',plan['authorization_pin']],
        'outer_root':'/tmp/hia-r11-controls-outer-r1-dda7','outer_seconds':1800,'outer_cleanup_seconds':3,
        'outer_is_watchdog_not_run_owned_180_limit':True,'each_product_owner_seconds':180,'each_cleanup_seconds':3,
        'output':str(OUTPUT),'plan':identity(ROOT/'EXECUTION-PLAN.json'),'products':0,'no_stage_retries':True}
    write('PRODUCT-LAUNCH.json',encode(launch))
    result={'schema':'hia.R11.eight-group-authoring-result.v1','status':'PASS_AUTHORING_ONLY',
        'plan':identity(ROOT/'EXECUTION-PLAN.json'),'launch':identity(ROOT/'PRODUCT-LAUNCH.json'),
        'inverse':identity(ROOT/'R11-EXACT-INVERSE.json'),'old_controls':len(before),'new_controls':len(plan['controls']),
        'old_roles':948,'new_roles':len(active),'new_total_roles':len(plan['fixed_inputs']),
        'phase_count':8,'full_original_methods_except_listed_actual_length_hash_literals':True,
        'source_tree':old['source']['tree'],'source_files':3180,'actual_prefix':identity(PREFIX/'RESULT.json'),
        'scope':str(ROOT),'output_exists':OUTPUT.exists(),'metadata_binding_invocations':1,'product_executions':0}
    write('R11-AUTHORING-RESULT.json',encode(result));print(json.dumps(result,sort_keys=True))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root-prefix-proof',type=Path,required=True);p.add_argument('--root-prefix-proof-git',required=True)
    p.add_argument('--root-predicate-proof',type=Path,required=True);p.add_argument('--root-predicate-proof-git',required=True)
    a=p.parse_args();main(a.root_prefix_proof,a.root_prefix_proof_git,a.root_predicate_proof,a.root_predicate_proof_git)
