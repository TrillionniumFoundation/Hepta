"""Integer finite-native compile/loader joins. Definitions only on import.

This candidate consumes the fully read current v89 cold B3 originals.
The integer candidate remains an isolated finite development, outside that cold source.
It never calls build_seed, generation, a Core VM or a cold/full qualifier.
No function in this file grants permission to execute a request by itself.
"""
from __future__ import annotations
from hashlib import sha256
import ctypes
import json
from pathlib import Path
import sys

HIA_SHA='56f86dc443f72655a9713eff24fadad121ab1157a858552e19c19dc53220c63c'
ABI_SHA='18b7bf7e60751a4a2ad82700cceba8bbb8875fd705bd695f0e652cfae5344a14'
BRIDGE_SHA='cb1ec83aba55439e3eb848e97846a4034f9932ba2fad490b9065cae7498bae3e'
B3_SHA='9de8606c153e50f2e742a18d4eb9f3b7c210b404f005346e95b550648d8f2892'
RECEIPT_ADDITIONS={'case','input_sha256','input_bytes','artifact_sha256','format',
                  'runner_sha256','wall_elapsed_ns','produced_image',
                  'produced_bytes','produced_sha256'}
COMPILER_LIMITS={'cpu_seconds':10,'address_bytes':256<<20,'core_dumpable':False,
                 'stack_bytes':8<<20,'output_capacity':1<<20,'workspace_bytes':1<<20}

def require(value,message):
    if not value: raise ValueError(message)

def unique(pairs):
    result={}
    for key,value in pairs:
        require(key not in result,'duplicate original JSON key')
        result[key]=value
    return result

def json_original(raw):
    return json.loads(raw,object_pairs_hook=unique,
                      parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))

def read_pinned(path, expected, read_file):
    raw,record=read_file(Path(path),expected['bytes'])
    require(record['size']==expected['bytes'] and record['sha256']==expected['sha256'],
            'finite native input bytes differ: '+str(path))
    return raw,record

def seven_compiler_originals(originals,read_file):
    require(set(originals)=={'image.bin','input.bin','output.bin','request.json',
                              'stdout.log','stderr.log','receipt.json'},
            'all seven current B3 originals are required')
    values={name:read_pinned(row['path'],row,read_file) for name,row in originals.items()}
    receipt=json_original(values['receipt.json'][0]);child=json_original(values['stdout.log'][0])
    request=json_original(values['request.json'][0])
    require({k:v for k,v in receipt.items() if k not in RECEIPT_ADDITIONS}==child
            and set(RECEIPT_ADDITIONS)<=set(receipt),'current full receipt projection differs')
    require(receipt['status']=='returned' and receipt['abi_status']==0
            and receipt['source_unchanged'] is True and receipt['forbidden_compiler_modules_loaded']==[]
            and receipt['limits']==COMPILER_LIMITS
            and receipt['image_sha256']==receipt['artifact_sha256']==receipt['produced_sha256']==B3_SHA
            and receipt['core_u32']==receipt['produced_bytes']==670467
            and values['image.bin'][1]['sha256']==B3_SHA
            and values['input.bin'][1]['sha256']==receipt['source_sha256']==receipt['input_sha256']
            and len(values['input.bin'][0])==receipt['input_bytes']==462939,
            'current B3 source/image/receipt differs')
    require(len(values['output.bin'][0])==1<<20
            and values['output.bin'][0][:670467]==values['image.bin'][0]
            and values['output.bin'][1]['sha256']==receipt['output_sha256']
            and values['stderr.log'][0]==b'','current full compiler output differs')
    require(request['format']=='flat-x86-64' and request['image_sha256']==B3_SHA
            and request['capacity']==request['workspace_size']==1<<20
            and request['workspace_fill']==90 and request['source_sha256']==receipt['source_sha256']
            and request['image'].endswith('/B2.image.bin')
            and request['source'].endswith('/B3.input.bin')
            and request['output'].endswith('/B3.output.bin'),
            'current B3 original request differs')
    return {'schema':'hepta.hia.integer-current-B3-admission.v1',
            'status':'COMPLETE_SEVEN_ORIGINALS_VERIFIED',
            'scope':'CURRENT_V89_B3_ORIGINALS_FOR_NEW_FINITE_INTEGER_DEVELOPMENT',
            'originals':{k:v[1] for k,v in values.items()},'receipt':receipt,'request':request}

def current_compiler(root,policy,read_file):
    """Bind all62 original compiler-chain bodies to the actual v89 cold seal.

    The prior independent38phase reader is frozen evidence of physical reads,
    not a substitute qualification. No phase or compiler is rerun here.
    """
    root=Path(root)
    rows=policy['current_compiler_capsule']['originals']
    require(type(rows) is list and len(rows)==62 and len({r['member'] for r in rows})==62,
            'current compiler capsule must retain all62 distinct originals')
    bodies={}
    actual={}
    for row in rows:
        raw,record=read_pinned(root/row['path'],row,read_file)
        require(row['path']=='current-cold/'+row['member'],'current capsule path mapping differs')
        bodies[row['member']]=raw;actual[row['member']]=record
    prefix='hia-cold.cold/qualification.evidence/'
    source='hia-cold.cold/source/'
    cold=json_original(bodies['hia-cold.json'])
    q=json_original(bodies['hia-cold.cold/qualification.json'])
    owner=json_original(bodies['hia-cold.cold/process-owner.json'])
    owner_request=json_original(bodies['hia-cold.cold/process-owner.json.request.json'])
    cold_request=json_original(bodies['hia-cold.cold/request.json'])
    contract_name='docs/HIA_SELFHOST_CORE_SUPPORT.json'
    contract=json_original(bodies[source+contract_name])
    expected=policy['current_compiler_capsule']
    require(expected['artifact']=={'id':13960883405,'run_id':43247845814,'bytes':652195421,
            'sha256':'477587001905c3f6e63c2c15fa94a6200777b6b477cf7d98a68d024d65e6a332'}
            and expected['source_commit']=='784f088fcc5ad81c65de541d54e26d380c86293c'
            and expected['source_tree']=='d9e8407c70e44a3ea0152b8b4c5eb2ed3833d790',
            'current source/provider identity differs')
    require(cold['schema']=='hepta.hia.selfhost-cold-replay.v1'
            and cold['status']=='COLD_SELFHOST_REPLAY_PASS' and cold['returncode']==0
            and len(cold['checks'])==11 and all(v is True for v in cold['checks'].values())
            and cold['qualification_wall_limit_seconds']==180
            and cold['cleanup_wall_limit_seconds']==3
            and cold['wall_elapsed_ns']==112596083185
            and cold['nested_report_sha256']==sha256(bodies['hia-cold.cold/qualification.json']).hexdigest(),
            'actual current cold status/whole nested seal differs')
    require(q['schema']=='hepta.hia.selfhost-qualification.v6'
            and q['status']=='SELF_HOSTED_FIXED_CORE_PASS'
            and len(q['checks'])==5051 and all(v is True for v in q['checks'].values())
            and q['source_manifest']==cold['source_manifest']==cold_request['source_manifest']
            and len(q['source_manifest'])==841
            and {**contract['source_identity']['files'],contract_name:sha256(bodies[source+contract_name]).hexdigest()}==q['source_manifest']
            and q['profile']==cold['profile']==contract['profile']
            and q['support_contract']=={'path':contract_name,'sha256':q['source_manifest'][contract_name]},
            'current complete cold source/contract/report join differs')
    wrapper=cold['process_owner']
    require(set(wrapper)==set(owner)|{'receipt_sha256','supervisor_returncode'}
            and {k:v for k,v in wrapper.items() if k not in {'receipt_sha256','supervisor_returncode'}}==owner
            and wrapper['supervisor_returncode']==0
            and wrapper['receipt_sha256']==sha256(bodies['hia-cold.cold/process-owner.json']).hexdigest()
            and owner['request_sha256']==sha256(bodies['hia-cold.cold/process-owner.json.request.json']).hexdigest()
            and owner['schema']==owner_request['schema']=='hepta.hia.selfhost-process-owner.v1'
            and owner['implementation_sha256']==owner_request['implementation_sha256']=='36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2'
            and owner['qualification_seconds']==owner_request['qualification_seconds']==180
            and owner['cleanup_seconds']==owner_request['cleanup_seconds']==3
            and owner['status']=='OWNED_PROCESS_COMPLETED' and owner['returncode']==0
            and owner['timed_out'] is False and owner['exit_observed_before_deadline'] is True
            and owner['event_overflow'] is False and owner['interrupted_signals']==[]
            and owner['cleanup']['complete'] is True and owner['cleanup']['leader_reaped'] is True
            and owner['cleanup']['observed_echild'] is True and owner['cleanup']['remaining_direct_children']==[]
            and owner['cleanup']['errors']==[] and owner['cleanup']['deadline_exceeded'] is False
            and [x['kind'] for x in owner['events']]==['qualification_started','owned_child_observed','qualification_exit_observed','owned_child_reaped']
            and cold_request['command']==owner_request['command'],
            'current original natural owner does not bind complete raw request/lifecycle')
    current7={name:{**row,'path':str(root/row['path'])}
              for name,row in policy['current_compiler_originals'].items()}
    seven=seven_compiler_originals(current7,read_file)
    require(seven['receipt']==q['generations'][2]
            and [r['case'] for r in q['generations']]==['B1','B2','B3']
            and [r['case'] for r in q['modified_generations']]==['M1','M2','M3']
            and q['seed']==json_original(bodies[prefix+'B0.receipt.json'])
            and sha256(bodies[prefix+'B0.so']).hexdigest()==q['seed']['artifact_sha256']==cold['seed_sha256'],
            'current original B0/B3 chain differs')
    for field in ('generations','modified_generations'):
        for row in q[field]:
            label=row['case'];receipt=json_original(bodies[prefix+label+'.receipt.json'])
            request=json_original(bodies[prefix+label+'.request.json'])
            stdout=json_original(bodies[prefix+label+'.stdout.log'])
            image=bodies[prefix+label+'.image.bin'];output=bodies[prefix+label+'.output.bin']
            require(receipt==row and {k:v for k,v in receipt.items() if k not in RECEIPT_ADDITIONS}==stdout
                    and len(image)==row['produced_bytes'] and sha256(image).hexdigest()==row['produced_sha256']
                    and len(output)==1<<20 and output[:len(image)]==image
                    and sha256(output).hexdigest()==row['output_sha256']
                    and sha256(bodies[prefix+label+'.input.bin']).hexdigest()==row['source_sha256']==request['source_sha256']
                    and row['artifact_sha256']==request['image_sha256']
                    and sha256(bodies[request['image'].removeprefix('/home/runner/work/_temp/')]).hexdigest()==request['image_sha256']
                    and row['limits']==COMPILER_LIMITS,'current full six-stage original bytes differ')
    audit_rows={}
    for name,row in expected['independent_readback'].items():
        raw,rec=read_pinned(root/row['path'],row,read_file)
        audit_rows[name]=(json_original(raw),rec)
    physical= audit_rows['PHYSICAL-READBACK.json'][0]
    completed=audit_rows['COMPLETED-COMPILER-CAPSULE.json'][0]
    require(physical['status']=='ALL_38_ORIGINAL_PHASE_BYTES_VERIFIED_NAMES_CUSTODY_FIXED'
            and physical['errors']==[] and physical['check_count']==169419
            and physical['artifact']['sha256']==expected['artifact']['sha256']
            and physical['artifact']['checkout_commit']==expected['source_commit']
            and physical['artifact']['checkout_tree']==expected['source_tree']
            and physical['phases']['totals']['phases']==38
            and physical['phases']['totals']['member_files']==42899
            and physical['phases']['totals']['physical_invocation_receipts']==6058
            and physical['phases']['history_gaps']==[]
            and completed['phase_read_completed'] is True
            and completed['reader_report']['sha256']==audit_rows['PHYSICAL-READBACK.json'][1]['sha256'],
            'fixed independent current38 physical reader report differs')
    return {'schema':'hepta.hia.integer-current-v89-B3-admission.v1',
            'status':'COMPLETE_CURRENT_62_ORIGINALS_AND_INDEPENDENT_38_READBACK_BOUND',
            'source_commit':expected['source_commit'],'source_tree':expected['source_tree'],
            'artifact':expected['artifact'],'originals':actual,'B3':seven,
            'readback':{k:v[1] for k,v in audit_rows.items()},
            'compiler_from_current_v89_cold':True,'integer_itself_was_in_original_v89_cold':False}

