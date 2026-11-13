"""One fixed GCC oracle build in the existing 20-wall/10-CPU child envelope."""
from pathlib import Path
import hashlib,json,os,resource,subprocess,sys,time,traceback
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common
def main():
    path=Path(sys.argv[1]);pin,raw=common.read(path,1<<20)
    common.require(pin['sha256']==sys.argv[2],'exact C child request')
    q=json.loads(raw);out=Path(q['output'])
    common.require(q['wall_seconds']==20 and q['cpu_seconds']==10 and q['max_image_bytes']==1<<20,
                   'original finite C compile limits')
    report={'schema':'hia.wal-snapshot.C-compile.v1','status':'HOLD','request':pin,
            'argv':q['argv'],'cwd':q['cwd'],'environment':q['environment'],
            'attempted':False,'returncode':None,'timed_out':False,'exception':None,'secondary_errors':[],
            'limits':{'wall_seconds':20,'cpu_seconds':10,'address_bytes':256<<20,
                      'stack_bytes':8<<20,'file_bytes':1<<20,'core_bytes':0}}
    started=time.monotonic_ns()
    try:
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        resource.setrlimit(resource.RLIMIT_CPU,(10,10))
        resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
        resource.setrlimit(resource.RLIMIT_STACK,(8<<20,8<<20))
        resource.setrlimit(resource.RLIMIT_FSIZE,(1<<20,1<<20))
        report['inputs_before']={}
        for name,expected in q['source_inputs'].items():
            actual,_=common.read(name)
            common.require(all(actual[k]==expected[k] for k in ('bytes','sha256','git_blob','identity')),'original C input')
            report['inputs_before'][name]=actual
        report['attempted']=True
        with (out/'gcc.stdout.log').open('xb',buffering=0) as stdout,(out/'gcc.stderr.log').open('xb',buffering=0) as stderr:
            process=subprocess.run(q['argv'],cwd=q['cwd'],env=q['environment'],stdin=subprocess.DEVNULL,
                                   stdout=stdout,stderr=stderr,timeout=20,close_fds=True)
        report['returncode']=process.returncode
        common.require(process.returncode==0,'C compiler nonzero')
        image_pin,image=common.read(out/'oracle.so',1<<20)
        common.require(image[:6]==b'\x7fELF\x02\x01' and int.from_bytes(image[16:18],'little')==3
            and int.from_bytes(image[18:20],'little')==62,'x86-64 shared oracle ELF')
        report['image']=image_pin
        report['inputs_after']={name:common.read(name)[0] for name in q['source_inputs']}
        common.require(report['inputs_after']==report['inputs_before'],'C source modified')
        report['status']='C_ORIGINAL_ALGORITHMS_COMPILED_ONLY'
    except subprocess.TimeoutExpired as e:
        report['status']='HOLD';report['timed_out']=True
        report['exception']=type(e).__name__+': '+str(e)
    except BaseException as e:
        report['status']='HOLD';report['exception']=type(e).__module__+'.'+type(e).__qualname__+': '+str(e)[:1024]
        report['traceback']=traceback.format_exc()
    finally:
        report['elapsed_ns']=time.monotonic_ns()-started
        if report['elapsed_ns']>20000000000 or report['exception'] is not None:report['status']='HOLD'
        common.create(out/'COMPILE.json',report)
    return 0 if report['status']=='C_ORIGINAL_ALGORITHMS_COMPILED_ONLY' else 1
if __name__=='__main__':raise SystemExit(main())
