"""Native callback Exception diagnostics against the original CPython rendering.

The product executes source-bound HIA functions and real Value exception objects.
Python supplies oracle values and captures fd 2; it does not run native callbacks.
"""
from pathlib import Path
import argparse,ctypes as C,json,os,signal,tempfile,traceback
from tools import qualify_hia_future_native_callbacks as callback
word,cap,pin,save=callback.word,callback.cap,callback.pin,callback.save

def exception_line(exc):
    return ('exception calling callback\n'+''.join(traceback.format_exception_only(exc))).encode('utf8','backslashreplace')

def construct(f,args,custom=None):
    v=f.v;base=v.builtin(24);native_args=[v.scalar(x)for x in args]
    cls=base;oracle=ValueError(*args)
    if custom is not None:
        label,result,disposition=custom
        if disposition==2:
            raised=v.exception(v.builtin(23),v.tuple([v.scalar('str failure')]))
            fn=v.function(callback.inv.echo_field(1,2),env=raised)
            def original(self):raise TypeError('str failure')
        else:
            if label=='subclass':
                sub=v.cls('NativeString',[v.builtin(6)])
                env=v.inherited(sub,v.scalar(result))
                class NativeString(str):pass
                def original(self):return NativeString(result)
            else:
                env=v.scalar(result)
                def original(self):return result
            fn=v.function(callback.inv.echo_field(1),env=env)
        namespace=v.dictionary([]);key=v.scalar('__str__');v.raw(10,a=namespace,b=key,c=fn)
        name=v.scalar('NativeError');bases=v.lst([base])
        cls=v.keep(v.raw(33,a=name,b=bases,c=namespace))
        oracle_type=type('NativeError',(ValueError,),{'__module__':'builtins','__str__':original})
        oracle=oracle_type(*args)
    return v.exception(cls,v.tuple(native_args)),oracle

def one(path,args,custom=None,continue_after=False):
    f=callback.Fixture(path);fac=f.public.factory();resource,weak=f.resource(fac);strong,pair=f.acquire(resource)
    exc,oracle=construct(f,args,custom)
    fn=f.v.function(callback.inv.echo_field(1,2),env=exc)
    f.register(resource,fn)
    events=None
    if continue_after:
        events=f.v.lst([])
        next_callback=f.v.function(callback.SOURCE,env=events)
        f.register(resource,next_callback)
    none=f.v.scalar(None)
    keep={resource,strong,none}
    if events is not None:keep.add(events)
    for item in list(f.v.held):
        if item not in keep:f.v.drop(item)
    with tempfile.TemporaryFile() as capture:
        saved=os.dup(2)
        try:
            os.dup2(capture.fileno(),2)
            r=f.public.call(22,*pair,value=none,kind=1)
        finally:
            os.dup2(saved,2);os.close(saved)
        capture.seek(0);actual=capture.read()
    expected=exception_line(oracle)
    assert actual==expected,(repr(args),custom,actual,expected)
    assert word(f.public.ctx.raw,224)==0,'native temporary cleanup guard remains'
    if continue_after:
        f.assert_events(events,resource,1);f.v.drop(events)
    f.v.drop(none);f.v.drop(strong);f.v.drop(resource)
    f.v.raw(80,a=weak,arg0=1,want=3);f.finish()
    return dict(args=[repr(x)for x in args],custom=None if custom is None else custom[0],
                continued_after_caught_Exception=continue_after,passed=True,
                exact_cpython_diagnostic=pin(actual),real_guard_retired=True,
                same_arena_and_native_code_custody_retired=True)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--owner',required=True,type=Path);ap.add_argument('--output',required=True,type=Path)
    args=ap.parse_args();args.output.mkdir(parents=True,exist_ok=False)
    signal.alarm(400)
    cases=[((),None,False),(('',),None,False),(('actual failure',),None,True),
           (('before\ud800after\U0001f600',),None,False),
           ((None,),None,False),((False,),None,False),((True,),None,False),
           ((0,),None,False),((-10**180,),None,False),
           ((-0.0,),None,False),((0.125,),None,False),((1e-7,),None,False),
           ((1e20,),None,False),((5e-324,),None,False),
           ((float('nan'),),None,False),((float('inf'),),None,False),((-float('inf'),),None,False),
           (('ignored',),('string','actual custom __str__',1),False),
           (('ignored',),('empty','',1),False),
           (('ignored',),('subclass','actual str subclass',1),False),
           (('ignored',),('wrong-type',17,1),False),
           (('ignored',),('raised',None,2),False)]
    report=dict(schema='hia.Future-native-exception-log-component.v1',passed=False,component_qualified=False,
                whole_public_Future_closed=False,whole_background_closed=False,
                generic_container_repr_qualified=False,traceback_capture_qualified=False,
                product=pin(args.owner.read_bytes()),python_callback_handlers=False,cases=[])
    save(args.output/'report.json',report)
    for i,(values,custom,following)in enumerate(cases):
        row=one(args.owner,values,custom,following);report['cases'].append(row);save(args.output/'report.json',report)
        print('ACTUAL_NATIVE_EXCEPTION_LOG_CASE',i,repr(values),None if custom is None else custom[0],flush=True)
    report['passed']=report['component_qualified']=True;save(args.output/'report.json',report)
    print('ACTUAL_NATIVE_EXCEPTION_LOG_PASS',len(cases),flush=True)
if __name__=='__main__':main()
