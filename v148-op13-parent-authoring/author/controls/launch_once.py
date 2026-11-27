"""Shell-free outer recorder for one separately authorized descriptor.

Original products are bounded by the parent's individual 180+3 owners. This
outer recorder reports actual exit and never promotes a lost owner receipt.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time
import traceback


def require(ok,message):
    if not ok:raise ValueError(message)


def read(row):
    path=Path(row['path']);before=path.lstat()
    require(stat.S_ISREG(before.st_mode)and before.st_nlink==1,'unique fixed launch file required')
    fields=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
    require({k:getattr(before,k)for k in fields}==row['stat'],'launch-file stat differs')
    raw=path.read_bytes()
    require({k:getattr(path.lstat(),k)for k in fields}==row['stat']and len(raw)==row['pin']['bytes']
            and hashlib.sha256(raw).hexdigest()==row['pin']['sha256']
            and hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==row['pin']['git_blob'],
            'fixed full launch file differs')
    return raw


def publish(path,value):
    raw=(json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
    with path.open('xb')as f:f.write(raw)
    require(path.read_bytes()==raw,'outer readback differs')


def launch(path,sha):
    path=Path(path);raw=path.read_bytes()
    require(len(raw)<=8<<20 and hashlib.sha256(raw).hexdigest()==sha,'launch identity differs')
    value=json.loads(raw)
    require(value['schema']=='hepta.hia.op13.explicit-launch.v1'and
            value['state']=='FROZEN_REQUIRES_SEPARATE_ROOT_AUTHORIZATION','only exact reviewed launch')
    for row in value['fixed_inputs'].values():read(row)
    require(value['argv'][0]==value['fixed_inputs']['runtime_exe']['path']and
            value['argv'][1:3]==['-I','-B']and value['argv'][3]==value['fixed_inputs']['entry']['path'],
            'actual entry/isolated runtime argv differs')
    require(value['product_owner_seconds']==180 and value['cleanup_seconds']==3
            and value['storage_floor']==1073741824,'original bounds changed')
    outer=Path(value['outer']);require(not os.path.lexists(outer),'exclusive outer already exists')
    info=os.statvfs(value['output_filesystem']);free=info.f_bavail*info.f_frsize
    require(free>=1073741824,'actual output filesystem1GiB floor')
    outer.mkdir(mode=0o700)
    publish(outer/'LAUNCH-USED.json',value)
    result={'schema':'hepta.hia.op13.outer.v1','status':'FAIL','mode':value['mode'],
        'started_ns':time.monotonic_ns(),'free_bytes_before':free,'child_started':False,
        'outer_is_not_a_product_owner':True,'automatic_retry':False}
    process=None
    try:
        with(outer/'stdout.raw').open('xb')as out,(outer/'stderr.raw').open('xb')as err:
            process=subprocess.Popen(value['argv'],cwd=value['cwd'],env=value['environment'],
                stdin=subprocess.DEVNULL,stdout=out,stderr=err,start_new_session=True,close_fds=True)
            result.update(child_started=True,pid=process.pid)
            publish(outer/'STARTED.json',result)
            code=process.wait();result.update(returncode=code,status='EXIT_ZERO'if code==0 else'EXIT_NONZERO')
    except BaseException:
        result.update(error=traceback.format_exc(),status='OUTER_UNCONFIRMED_HOLD')
        # Do not kill original subreapers or call replay on uncertain ownership.
        if process is not None:result['actual_poll']=process.poll()
    finally:
        result['finished_ns']=time.monotonic_ns()
        result['product_qualification_not_inferred_from_outer_exit']=True
        try:
            for row in value['fixed_inputs'].values():read(row)
        except BaseException:result.update(status='FAIL',terminal_guard_error=traceback.format_exc())
        publish(outer/'OUTER.json',result)
    return 0 if result['status']=='EXIT_ZERO'else 1


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--launch',required=True)
    p.add_argument('--launch-sha256',required=True);a=p.parse_args()
    raise SystemExit(launch(a.launch,a.launch_sha256))
