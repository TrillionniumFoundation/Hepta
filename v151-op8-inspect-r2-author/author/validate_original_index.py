"""Root-run, data-only check of the retained large R1 INDEX and AFTER files.

This does not import the project, load an ELF, invoke a test, replay a VM,
rewrite a predecessor or qualify the new source.  It writes a new report.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time
import traceback

FIELDS=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')


def require(value,message):
    if not value:raise AssertionError(message)


def seven(info):return {key:getattr(info,key) for key in FIELDS}


def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()


def pin(raw,mode='100644'):
    return {'bytes':len(raw),'mode':mode,'sha256':hashlib.sha256(raw).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}


def pairs(items):
    result={}
    for key,value in items:
        require(type(key)is str and key not in result,'duplicate/nonstring JSON key')
        result[key]=value
    return result


def decode(raw):return json.loads(raw,object_pairs_hook=pairs)


def small_read(path,expected=None):
    path=Path(path);require(path.is_absolute() and '..' not in path.parts,'absolute path required')
    fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and 0<=before.st_size<=16<<20
                and seven(before)==seven(path.lstat()),'original bounded unique regular input required')
        pieces=[];count=0
        while True:
            raw=os.read(fd,min(65536,before.st_size+1-count))
            if not raw:break
            pieces.append(raw);count+=len(raw)
            require(count<=before.st_size,'input grew')
        raw=b''.join(pieces)
        require(len(raw)==before.st_size and seven(before)==seven(os.fstat(fd))==seven(path.lstat()),
                'complete small input changed')
        row={'path':str(path),'pin':pin(raw,'100755' if before.st_mode&0o111 else '100644'),'stat':seven(before)}
        if expected is not None:require(row==expected,'fixed small input differs')
        return raw,row
    finally:os.close(fd)


def state(directory):
    directory=Path(directory);info=directory.lstat()
    require(stat.S_ISDIR(info.st_mode),'actual frame directory required')
    result={'.':seven(info)}
    for path in sorted(directory.iterdir()):
        info=path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink==1
                and re.fullmatch(r'[0-9]{8}-(?:BEFORE|AFTER)\.json',path.name),
                'unexpected actual frame entry')
        result[path.name]=seven(info)
    return result


def publish(path,value):
    raw=encoded(value)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_CLOEXEC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw)
    require(Path(path).read_bytes()==raw,'new data-only report readback differs')


def main(request_path,request_sha):
    request_raw,descriptor=small_read(request_path)
    require(descriptor['pin']['sha256']==request_sha,'fixed validation request differs')
    request=decode(request_raw)
    require(request['state']=='AUTHOR_ONLY_NOT_EXECUTED' and request['product_execution'] is False
            and request['qualification_transfer'] is False,'data-only scope required')
    require(Path(__file__).absolute()==Path(request['reader']['path']),'fixed validation reader required')
    small_read(request['reader']['path'],request['reader'])
    small_read(request['helper']['path'],request['helper'])
    output=Path(request['output']);require(not os.path.lexists(output),'fresh data-only report required')
    output.mkdir(mode=0o700)
    report={'status':'FAIL','started_ns':time.monotonic_ns(),'request':descriptor,
        'products_executed':0,'project_imports':0,'Native_or_VM_executions':0,
        'old_or_new_qualification_transferred':False,'payload_buffers_read':0,'complete_AFTER_reads':0}
    try:
        require(sys.implementation.name=='cpython' and sys.version_info[:3]==(3,14,4)
                and sys.flags.isolated and sys.flags.dont_write_bytecode,'fixed3.14.4 -I -B required')
        sys.path.insert(0,str(Path(request['helper']['path']).parent))
        import streaming_metadata as helper
        require(Path(helper.__file__).absolute()==Path(request['helper']['path']),'fixed helper import required')
        before=state(request['frames'])
        after_paths=[Path(request['frames'])/name for name in sorted(before) if name.endswith('-AFTER.json')]
        before_indices={int(name[:8]) for name in before if name.endswith('-BEFORE.json')}
        require(len(after_paths)==request['expected_complete_calls']
                and before_indices==set(range(request['expected_started_calls']))
                and len(before)==1+len(after_paths)+len(before_indices),'exact retained frame sequence differs')
        def read_after(path):
            raw,row=small_read(path)
            require(row['stat']==before[path.name],'actual AFTER seven-stat differs')
            value=decode(raw);require(value['index']==int(path.name[:8]),'actual AFTER index differs')
            report['complete_AFTER_reads']+=1
            return value
        actual=helper.stream_index(request['index']['path'],after_paths,len(before_indices),read_after)
        require(actual['binding']==request['index'] and actual['complete_calls']==request['expected_complete_calls']
                and actual['started_calls']==request['expected_started_calls'],'full original INDEX identity differs')
        require(state(request['frames'])==before,'retained frame directory changed')
        small_read(request['helper']['path'],request['helper']);small_read(request['reader']['path'],request['reader'])
        small_read(request_path,descriptor)
        publish(output/'FRAME-STATE.json',before)
        report.update(status='PASS_COMPLETE_R1_INDEX_METADATA_ONLY',index=actual,
            frame_state_pin=pin(encoded(before)),original_capture_limit_bytes=16<<20,
            no_product_gate_bypassed=True,helper_called_once=True,
            scope='Full INDEX and all AFTER objects only; no buffer, Native or VM qualification.')
    except BaseException:
        report['traceback']=traceback.format_exc()
    finally:
        report['finished_ns']=time.monotonic_ns();publish(output/'RESULT.json',report)
    return 0 if report['status']=='PASS_COMPLETE_R1_INDEX_METADATA_ONLY' else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--request',required=True)
    parser.add_argument('--request-sha256',required=True);args=parser.parse_args()
    raise SystemExit(main(args.request,args.request_sha256))
