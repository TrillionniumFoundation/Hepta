"""Mechanical full-case runner with explicit self/children CPU observation."""
from pathlib import Path
import ctypes,json,os,resource,runpy,sys,time

resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
libc=ctypes.CDLL(None,use_errno=True)
libc.prctl.argtypes=[ctypes.c_int]+[ctypes.c_ulong]*4
libc.prctl.restype=ctypes.c_int
assert libc.prctl(4,0,0,0,0)==0 and libc.prctl(3,0,0,0,0)==0
target=Path(sys.argv[1]).resolve()
sys.argv=sys.argv[1:]
destination=Path(os.environ['HIA_ACCOUNTING_OUTPUT'])
def snapshot():
    own=resource.getrusage(resource.RUSAGE_SELF)
    children=resource.getrusage(resource.RUSAGE_CHILDREN)
    return dict(self_user=own.ru_utime,self_system=own.ru_stime,
                children_user=children.ru_utime,children_system=children.ru_stime,
                cpu_limit=list(resource.getrlimit(resource.RLIMIT_CPU)),
                address_limit=list(resource.getrlimit(resource.RLIMIT_AS)),
                process_times=list(os.times()),
                thread_ids=sorted(p.name for p in Path('/proc/self/task').iterdir()),
                pid=os.getpid(),monotonic_ns=time.monotonic_ns())
record=dict(before=snapshot())
assert record['before']['cpu_limit']==[90,90]
assert record['before']['address_limit']==[1073741824,1073741824]
try:
    runpy.run_path(str(target),run_name='__main__')
finally:
    record['after']=snapshot()
    module=sys.modules.get('evidence_bytes_cache_r1')
    if module is not None:
        record['evidence_cache']=module.evidence_cache_statistics()
    destination.write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
