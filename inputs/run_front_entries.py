"""First actual public-front source/table/entry differential, development only.

The original thirteen function objects are used before their code is poisoned.
The selected route runs the HIA image; primitive semantics/JSON/regex providers
remain explicit. This is not public-wiring, installed, cold or whole-domain
qualification.
"""
from __future__ import annotations
import argparse
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys
import traceback

def snapshot(value):
    from hepta.hia_program import VerifiedProgram
    if isinstance(value, VerifiedProgram):
        return {'kind':'VerifiedProgram','canonical_hex':value.canonical_bytes.hex(),
                'structured_hex':None if value.structured_bytes is None else value.structured_bytes.hex()}
    if type(value) is bytes: return {'kind':'bytes','hex':value.hex()}
    if type(value) is tuple: return {'kind':'tuple','values':[snapshot(v) for v in value]}
    if type(value) is list: return [snapshot(v) for v in value]
    if type(value) is dict: return {k:snapshot(v) for k,v in value.items()}
    if value is None or type(value) in (str,int,bool,float): return value
    raise TypeError('first differential contains an unreviewed result type')

def exception(error, active=()):
    if error is None: return None
    if id(error) in active: return {'cycle':True}
    active=active+(id(error),)
    return {'type':type(error).__module__+'.'+type(error).__qualname__,
            'message':str(error),'code':getattr(error,'code',None),
            'phase':getattr(error,'phase',None),'line':getattr(error,'line',None),
            'name':getattr(error,'name',None),
            'cause':exception(error.__cause__,active),
            'context':exception(error.__context__,active),
            'suppress_context':error.__suppress_context__,
            'notes':getattr(error,'__notes__',None)}

def observe(function, arguments):
    try: return {'return':snapshot(function(*arguments))}
    except BaseException as error: return {'exception':exception(error)}

POISON_CALLS=[]
def forbidden(*args,**kwargs):
    POISON_CALLS.append('original-policy-body')
    raise AssertionError('original public-front policy body executed')

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source',required=True,type=Path)
    parser.add_argument('--compiler',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    root=args.source.resolve(strict=True);out=args.output.absolute()
    out.mkdir(exist_ok=False)
    sys.path.insert(0,str(root))
    report={'schema':'hia.public-front.actual-first-differential.v80.r1',
            'status':'STARTED','python':sys.version,'source':str(root),
            'scope':'DEVELOPMENT_DIRECT_ENTRY_ONLY','whole_normalization':False,
            'physical_recursion':False,'public_wiring':False,'cold':False,'cases':[]}
    try:
        from tools.generate_hia_public_front import program, table, ports_source
        from tools.qualify_hia_selfhost import compile_stage
        source=root/'examples/hia_bootstrap/public_front.hiaasm'
        assembly=source.read_bytes();compiler=args.compiler.read_bytes()
        policy=program();data=table(policy)
        report['policy']={'functions':len(policy.functions),
            'entries':list(policy.by_name),'instructions':sum(len(f.instructions) for f in policy.functions),
            'table_bytes':len(data),'table_sha256':sha256(data).hexdigest(),
            'call_shapes':sorted(policy.call_shapes),'string_shapes':sorted(policy.string_shapes)}
        image,receipt=compile_stage(out,'public-front',args.compiler,assembly)
        report['compilation']=receipt
        if args.compiler.read_bytes()!=compiler or source.read_bytes()!=assembly:
            raise AssertionError('actual compile input changed')
        # Retain concrete opcode profiles even if a new fixed guard refuses.
        import dis, importlib.util
        profile={}
        rawports=root/'hepta/hia_public_front_ports.py'
        code=compile(rawports.read_bytes(),str(rawports),'exec')
        def collect(parent,prefix=''):
            for child in parent.co_consts:
                if isinstance(child,type(code)):
                    if child.co_name.startswith(('_string_','_import_template_')):
                        profile[prefix+child.co_name]={
                            'co_consts':repr(child.co_consts),
                            'instructions':[{'offset':i.offset,'opname':i.opname,'arg':i.arg,
                                             'argval':repr(i.argval),'argrepr':i.argrepr}
                                            for i in dis.get_instructions(child,show_caches=True,adaptive=False)]}
                    collect(child,prefix+child.co_name+'.')
        collect(code)
        (out/'actual-fixed-opcode-profile.json').write_text(json.dumps(profile,sort_keys=True,indent=2)+'\n')
        from hepta import hia_agent_assembly as assembly_module, hia_program as program_module
        from hepta.hia_public_front_native import NativePublicFront,ARITIES
        from tests.test_hia_agent_assembly import SOURCE
        from tests.test_hia_program import arithmetic
        old={name:(getattr(program_module,name) if name=='verify_program' else getattr(assembly_module,name))
             for name in ARITIES}
        checked=old['assemble_program'](SOURCE);document=checked.as_dict()
        factories=[
            ('reject-basic','_reject',lambda:('failed',None,False)),
            ('reject-line-limit','_reject',lambda:('failed',7,True)),
            ('source-text','_source',lambda:(SOURCE,)),
            ('source-bytes','_source',lambda:(SOURCE.encode(),)),
            ('source-bytearray-reject','_source',lambda:(bytearray(b'x'),)),
            ('source-invalid-utf8','_source',lambda:(b'\xff',)),
            ('source-control','_source',lambda:('x\x00',)),
            ('source-crlf','_source',lambda:(SOURCE.replace('\n','\r\n'),)),
            ('items-empty','_items',lambda:('',3)),
            ('items-valid','_items',lambda:(' a, b ',3)),
            ('items-empty-member','_items',lambda:('a,,b',3)),
            ('names-valid','_names',lambda:('alpha,beta',4)),
            ('names-invalid','_names',lambda:('alpha,é',4)),
            ('parameters-empty','_parameters',lambda:('',5)),
            ('parameters-valid','_parameters',lambda:('a:u8,b : mutbuf',5)),
            ('parameters-invalid','_parameters',lambda:('a::u8',5)),
            ('attrs-none','_attrs',lambda:(None,6)),
            ('attrs-object','_attrs',lambda:('{"value":4,"s":"é"}',6)),
            ('attrs-list','_attrs',lambda:('[]',6)),
            ('attrs-duplicate','_attrs',lambda:('{"x":1,"x":2}',6)),
            ('attrs-invalid','_attrs',lambda:('{',6)),
            ('parse-valid','_parse_assembly_document',lambda:(SOURCE,)),
            ('parse-invalid-header','_parse_assembly_document',lambda:('bad\n',)),
            ('parse-missing-end','_parse_assembly_document',lambda:(SOURCE.rsplit('end\n',1)[0],)),
            ('assemble-valid','assemble_program',lambda:(SOURCE,)),
            ('assemble-semantic-error','assemble_program',lambda:(SOURCE.replace('ret(answer)','ret(a)'),)),
            ('render-parameters-empty','_render_parameters',lambda:([],)),
            ('render-parameters-valid','_render_parameters',lambda:([{'name':'a','type':'u8'},{'name':'b','type':'bool'}],)),
            ('render-document-valid','_render_assembly_document',lambda:(json.loads(json.dumps(document)),)),
            ('render-checked','render_assembly',lambda:(checked,)),
            ('render-document','render_assembly',lambda:(json.loads(json.dumps(document)),)),
            ('diagnose-valid','diagnose_assembly',lambda:(SOURCE,)),
            ('diagnose-invalid','diagnose_assembly',lambda:('bad\n',)),
            ('diagnose-semantic','diagnose_assembly',lambda:(SOURCE.replace('ret(answer)','ret(a)'),)),
            ('verify-dict','verify_program',lambda:(arithmetic('int.add.wrap','u8'),)),
            ('verify-raw','verify_program',lambda:(checked.canonical_bytes,)),
            ('verify-checked','verify_program',lambda:(checked,)),
            ('verify-format-error','verify_program',lambda:([],)),
            ('verify-version-error','verify_program',lambda:({'schema':'bad'},)),
        ]
        def reference(name,args):
            if name=='_reject':
                return old[name](args[0],line=args[1],limit=args[2])
            return old[name](*args)
        expectations=[observe(lambda *args,n=name:reference(n,args),factory())
                      for _,name,factory in factories]
        owner=NativePublicFront(image.read_bytes(),sha256(image.read_bytes()).hexdigest())
        if owner.table!=data:raise AssertionError('actual image table differs from independent authoring bytes')
        report['actual_table_equal']=True
        report['actual_image_sha256']=sha256(image.read_bytes()).hexdigest()
        calls=Counter();poison_calls=POISON_CALLS
        actual_entry=owner._entry
        nonce_modes={}
        def entry(source,n,*args):
            if source is not owner._table_buffer or n!=len(data) or len(args)!=4:
                raise AssertionError('actual selected table entry arguments differ')
            command,nonce,sequence,value=struct.unpack_from('<4Q',args[2],0)
            if command==0:nonce_modes[nonce]=value
            mode=nonce_modes.get(nonce)
            if mode is None:raise AssertionError('actual native frame lacks initial mode')
            result=actual_entry(source,n,*args)
            calls[mode]+=1
            return result
        owner._entry=entry
        originals=[(function,function.__code__) for function in dict.fromkeys(old.values())]
        poison_namespaces=(vars(assembly_module),vars(program_module))
        if any('POISON_CALLS' in namespace for namespace in poison_namespaces):
            raise AssertionError('poison fixture unexpectedly collides with module global')
        try:
            for namespace in poison_namespaces:namespace['POISON_CALLS']=poison_calls
            for function,_ in originals:function.__code__=forbidden.__code__
            for (label,name,factory),expected in zip(factories,expectations):
                before=owner.entries
                actual=observe(lambda *arguments,n=name:owner.run(n,*arguments),factory())
                report['cases'].append({'name':label,'entry':name,'expected':expected,'actual':actual,
                                        'match':expected==actual,'native_entries':owner.entries-before})
        finally:
            for function,code in originals:function.__code__=code
            for namespace in poison_namespaces:
                if namespace.pop('POISON_CALLS') is not poison_calls:
                    raise AssertionError('original-body poison bookkeeping changed')
        report['original_code_objects_restored']=all(function.__code__ is code for function,code in originals)
        report['global_anchor_cases']=[]
        for group,root_name,global_name in ((0,'_names','_items'),(1,'verify_program','verify_program')):
            namespace=vars(assembly_module if group==0 else program_module)
            for when in ('before-admission','after-admission'):
                for deletion in (False,True):
                    original=namespace[global_name]
                    trace=[]
                    candidate=program_module.VerifiedProgram(b'[]',b'x')
                    class Replacement:
                        def __call__(self,*arguments):
                            trace.append('replacement')
                            return ['changed'] if group==0 else candidate
                        def __getattribute__(self,name):
                            if name in ('__name__','__qualname__','__module__'):
                                trace.append('replacement-metadata-'+name)
                                raise AssertionError('admission observed replacement metadata')
                            return object.__getattribute__(self,name)
                    def change():
                        if deletion:del namespace[global_name]
                        else:namespace[global_name]=Replacement()
                    arguments=('old',2) if group==0 else (candidate,)
                    try:
                        change()
                        expected=observe(old[root_name],arguments)
                        expected_trace=trace[:]
                    finally:namespace[global_name]=original
                    trace.clear()
                    try:
                        if when=='before-admission':change()
                        current=NativePublicFront(image.read_bytes(),sha256(image.read_bytes()).hexdigest())
                        if when=='after-admission':change()
                        actual=observe(lambda *arguments:current.run(root_name,*arguments),arguments)
                        actual_trace=trace[:]
                        report['global_anchor_cases'].append({
                            'group':group,'when':when,'deleted':deletion,
                            'expected':expected,'actual':actual,
                            'expected_trace':expected_trace,'actual_trace':actual_trace,
                            'native_entries':current.entries,
                            'match':expected==actual and expected_trace==actual_trace})
                    finally:namespace[global_name]=original
        if len(report['global_anchor_cases'])!=8 or any(not row['match'] or row['native_entries']<=0 for row in report['global_anchor_cases']):
            raise AssertionError('fixed entry pre/post admission replacement or deletion differs')
        report['poison_calls']=poison_calls
        report['actual_native_returns_by_mode']=dict(sorted(calls.items()))
        report['native_entries']=owner.entries
        report['cases_run']=len(report['cases'])
        report['matches']=sum(row['match'] for row in report['cases'])
        if (poison_calls or report['matches']!=len(factories) or sum(calls.values())!=owner.entries
                or any(row['native_entries']<=0 for row in report['cases'])):
            raise AssertionError('original/native differential or old-body exclusion failed')
        report['status']='DEVELOPMENT_DIRECT_ENTRY_PASS'
    except BaseException:
        report.update(status='FAIL',traceback=traceback.format_exc())
    finally:
        (out/'REPORT.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
        print(json.dumps({'status':report['status'],'cases':report.get('cases_run'),
                          'matches':report.get('matches'),'native_entries':report.get('native_entries')}),flush=True)
    return 0 if report['status']=='DEVELOPMENT_DIRECT_ENTRY_PASS' else 1

if __name__=='__main__':
    raise SystemExit(main())
