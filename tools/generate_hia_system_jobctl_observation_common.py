"""Shared authoring constants for root jobctl observation policy and rendering."""
from __future__ import annotations
import ast,re
from tools import generate_hia_system_jobctl_control as control
from tools import generate_hia_system_jobctl_start as start
from tools import generate_hia_system_jobctl_record as record
from tools import generate_hia_system_jobctl_terminal as terminal
from tools.generate_hia_system_jobctl_request import POLICY as REQUEST_POLICY

CONSTANTS={**start.CONSTANTS,
 **{k:v for k,v in terminal.CONSTANTS.items() if k.startswith(('T_','EXIT_','CAPTURE_','STREAM_','WITNESS_','TERMINAL_'))},
 'SUBOP':52800,'SUBOP_NEXT':52808,'PROBE_PRESENT':52816,'INVOCATION_PRESENT':52824,'INVOCATION_AT':52832,'INVOCATION_SIZE':52840,
 'ATOMIC_FAILURE_NEXT':41688,'ATOMIC_ERROR':41696,
 'DATA_DIR':12288,'DATA_SIZE':56800,'OBS_KIND':56808,'OBS_REASON':56816,'OBS_WITNESSED':56824,
 'TERMINAL_NEXT':56832,'EXIT_SIZE':56840,'STATE_CODE':56848,'PROBE_NEXT':56856,'PROBE_ERROR':56864,
 'PROPERTY_COUNT':56872,'PROPERTY_USED':56880,'OUT_SIZE':56888,'OUT_USED':56896,'SCRATCH_SIZE':56904,
 'RETAINED':56912,'MISSING_REASON':56928,'READ_SIDE':56936,'PAGE_OFFSET':56944,'PAGE_SIZE':56952,
 'PAGE_USED':56960,'PAGE_FD':56968,'PAGE_EXPECTED':56976,'PAGE_PRESENT':56984,
 'PROPERTY_FD':57000,'PROPERTY_ERROR_FD':57008,'PROPERTY_BYTES':57016,'PROPERTY_READ':57024,
 'RETAIN_NEXT':57032,'RENDER_KIND':57040,'READ_AT':57048,'PROPERTY_CLOSE_NEXT':57056,
 'IO_NEXT':57200,'IO_ERROR':57208,'IO_FD':57216,'IO_TARGET':57224,'IO_LIMIT':57232,'IO_USED':57240,
 'IO_META_LIMIT':57248,'HASH_USED':57300,'HASH_TAKE':57308,
 'INTERNAL_LOCK':57328,'INTERNAL_STEP':57336,
 'OUTPUT':80<<20,'OUTPUT_END':88<<20,'PROP_RAW':88<<20,'PROP_TEXT':92<<20,'PROP_CAP':4<<20,
 'EXIT_RAW':96<<20,'WITNESS_RAW':97<<20,'RETAIN_RAW':98<<20,
 'HASH_INPUT':99<<20,'LOG_RAW':99<<20,'LOG_TEXT':(99<<20)+32768,
 'PROP_TABLE':108<<20,'PROP_TABLE_END':112<<20,'SCRATCH_VALUE':114<<20,'SCRATCH_CAP':4<<20,
 'CANON_WORK':4<<20,'CANON_BYTES':64+524289*56+(8<<20)+16384,'CANON_RESULT':48<<20,
 'PROCESS_MODE':51200,'PROCESS_NEXT':51208,'PROCESS_ERRNO':51232,'PROCESS_STATUS':51224,
 'PROCESS_OUT_BYTES':51240,'PROCESS_ERR_BYTES':51248,'PROCESS_FDS':52000,
 'PROCESS_FAILURE_NEXT':51360,'PROCESS_FAILURE':51368,
 'NEG20':(1<<64)-20,'NEG22':(1<<64)-22}

KEYS=('job_id','state','backend','reason','outcome','status_authoritative','automatic_retry',
      'systemd','launch_state','exit_code','timed_out','cancelled','scratch_cleanup',
      'scratch_cleanup_publication','terminal_publication_protocol','launch_nonce','at_unix_ms',
      'log_bytes','log_truncated','log_synced','log_errors','stdout','stderr','seen','saved',
      'stored','eof','truncated','drain_timeout','read_error','write_error','sync_error','synced',
      'offset','next_offset','size','text','bytes_hex','log_limit_bytes','result','invocation_id',
      'output_complete','output_durable','terminal_receipt_observed','terminal_publication',
      'terminal_publication_confirmed','capture')
TOKENS={
 'null':'null','true':'true','false':'false','systemd':'"systemd_system"',
 'metadata_open':'{"capture":','job_open':'{"job_id":','stream_open':'{"seen":',
 'stdout_open':'{"stdout":','seen_open':'{"seen":','page_open':'{"offset":',
 'reused':'{"backend":"systemd_system","ok":true,"reused_remote":true,"status":',
 'running':'"running"','failed':'"failed"','lost':'"lost"','cancelled':'"cancelled"',
 'timed_out':'"timed_out"','succeeded':'"succeeded"','finalizing':'"finalizing"',
 'unknown':'"unknown"','not_observed':'"not_observed"','legacy_unknown':'"legacy_unknown"',
 'confirmed':'"confirmed"','publication_pending':'"publication_pending"',
 'target_reboot':'"target_reboot"','receipt_missing':'"terminal_receipt_missing"',
 'capture_failed':'"output_capture_incomplete_or_not_durable"',
 'retained':'"retained_without_terminal"','already_exited':'"already_exited"','stop_requested':'"stop_requested"',
 'unreadable':'"terminal_receipt_unreadable"','invalid':'"terminal_receipt_invalid"',
 'protocol_mismatch':'"terminal_protocol_mismatch"','capture_invalid':'"terminal_capture_invalid"',
 'witness_unavailable':'"terminal_witness_unavailable"','witness_mismatch':'"terminal_witness_mismatch"',
 'data_prefix':'/var/lib/hepta-job-','exit':'/exit.json','witness':'/exit.witness',
 'retained_file':'/engine-scratch.retained.json','stdout_log':'/stdout.log','stderr_log':'/stderr.log',
 'description':'Hepta Runtime ','cancelled_raw':'cancelled',
 'systemctl':'/usr/bin/systemctl','show':'show','no_pager':'--no-pager',
 'properties':'--property=LoadState,ActiveState,SubState,Result,InvocationID,Description,ExecMainStatus,ExecMainCode',
 'separator':'--','stop':'stop'}
TOKEN_IDS={name:i for i,name in enumerate(TOKENS)}
CONSTANTS.update({'L_'+k.upper():v for k,v in TOKEN_IDS.items()})
CONSTANTS.update({'K_'+name.upper():i for i,name in enumerate(KEYS)})

def functions(source):
    return {n.name:ast.get_source_segment(source,n) for n in ast.parse(source).body if isinstance(n,ast.FunctionDef)}

def compose(source):
    helpers={**functions(record.source_program()),**functions(control.source_program()),**functions(start.source_program())}
    helpers['quote']=functions(REQUEST_POLICY)['quote'].replace('REQUEST_OUT + REQUEST_CAP','OUTPUT_END')
    helpers['bounded_lossy']=helpers['lossy'].replace('def lossy(w:mutbuf, target:u64, source:u64, size:u64)',
        'def bounded_lossy(w:mutbuf, target:u64, source:u64, size:u64, capacity:u64)').replace(
        '            copy(w, target + out, source + at, width)',
        '            if out >= capacity or width >= capacity - out:\n                return NONE\n            copy(w, target + out, source + at, width)').replace(
        '            store(w, target + out, 239)',
        '            if out >= capacity or 3 >= capacity - out:\n                return NONE\n            store(w, target + out, 239)')
    defined=set(functions(source))
    while True:
        called={n.func.id for n in ast.walk(ast.parse(source)) if isinstance(n,ast.Call) and isinstance(n.func,ast.Name)}
        needed=sorted((called-defined)&helpers.keys())
        if not needed:break
        for name in needed:source+='\n'+helpers[name]+'\n';defined.add(name)
    values=list(TOKENS.values())
    source+=record.texts('lit',values)
    source+=record.texts('key',[',"'+name+'":' for name in KEYS])
    for name,values in (
      ('property_id',('LoadState','ActiveState','InvocationID','Description')),
      ('state_id',('active','activating','deactivating','failed','cancelled'))):
        source+=record.matcher(name,values)
    for key in sorted(CONSTANTS,key=len,reverse=True):source=re.sub(r'\b'+key+r'\b',str(CONSTANTS[key]),source)
    return source
