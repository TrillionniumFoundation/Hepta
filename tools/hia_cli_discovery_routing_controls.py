"""Retained actual CLI comparison controls, with portable fixture inputs.

The reports are observations, never cold authority.  Runtime code imports none
of this module.  Every VM comparison uses complete actual input/output/workspace.
"""
from pathlib import Path
import argparse,base64,builtins,contextlib,ctypes,hashlib,io,json,os,re,struct,sys,time,traceback,types,weakref,zlib
from unittest.mock import patch


def _snapshot(source):
    return {p.relative_to(source).as_posix(): {
        'bytes': p.stat().st_size, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest(),
        'mode': p.stat().st_mode & 511}
        for p in sorted(source.rglob('*')) if p.is_file()
        and '__pycache__' not in p.parts and p.suffix != '.pyc'}


def packed(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'zlib_base64':base64.b64encode(zlib.compress(raw,1)).decode()}


def unpacked(row):
    raw=zlib.decompress(base64.b64decode(row['zlib_base64'],validate=True))
    if len(raw)!=row['bytes'] or hashlib.sha256(raw).hexdigest()!=row['sha256']:
        raise ValueError('retained complete buffer identity differs')
    return raw


def metadata_mutations(manifest,evidence):
    """Actual detached dict/JSON effects after in-place standard metadata edits."""
    ROOT=Path(__file__).resolve().parents[1];SOURCE=ROOT;OUT=Path(evidence).absolute();OUT.mkdir(mode=0o700)
    def save(name,value):(OUT/name).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
    before=_snapshot(SOURCE);save('SOURCE-BEFORE.json',before);started=time.monotonic_ns()
    report={'schema':'hia-cli-routing-metadata-mutation-observations.v1',
            'scope':'OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY','status':'FAIL','cases':[]}
    try:
        from hepta import cli,hia_opcodes
        from hepta.hia_cli_native import installed_cli
        owner=installed_cli(str(manifest));original=cli._HIA_DISCOVERY_DEFINITIONS[2]
        real=owner.discovery._entry;entries=[]
        def entry(*args):entries.append(True);return real(*args)
        owner.discovery._entry=entry
        spec=next(iter(hia_opcodes.OPCODES.values()))
        def outcome(selected,field,value,events):
            output,errors=io.StringIO(),io.StringIO();saved=getattr(spec,field)
            initial=len(entries)
            try:
                object.__setattr__(spec,field,value)
                with contextlib.redirect_stdout(output),contextlib.redirect_stderr(errors):
                    try:
                        result=owner.run(['catalog'],cli) if selected else original(['catalog'])
                        error=None
                    except BaseException as caught:
                        result=None;error=[type(caught).__name__,str(caught),
                            None if caught.__context__ is None else type(caught.__context__).__name__]
            finally:object.__setattr__(spec,field,saved)
            return {'result':result,'exception':error,'stdout':output.getvalue(),'stderr':errors.getvalue(),
                    'events':list(events)},len(entries)-initial
        baseline,_=outcome(False,'semantic_rule',spec.semantic_rule,[])
        for field,value in (('name','changed-name'),('operands',('unit',)),('effects',('write',)),
                            ('since',9),('resource_transition','changed-transition'),
                            ('semantic_rule','changed-rule')):
            expected,_=outcome(False,field,value,[]);actual,count=outcome(True,field,value,[])
            report['cases'].append({'name':'spec-'+field,'expected':expected,'actual':actual,
                                    'equal':expected==actual,'json_native_entries':count,
                                    'expected_native_entries':0,'semantic_change':True,
                                    'baseline_output_differs':expected['stdout']!=baseline['stdout']})
        class CopyValue:
            def __init__(self,events):self.events=events
            def __deepcopy__(self,memo):self.events.append('real-provider-deepcopy');return 'copied-rule'
        events=[];expected,_=outcome(False,'semantic_rule',CopyValue(events),events)
        events=[];actual,count=outcome(True,'semantic_rule',CopyValue(events),events)
        report['cases'].append({'name':'actual-dataclass-deepcopy','expected':expected,'actual':actual,
                                'equal':expected==actual,'json_native_entries':count,
                                'expected_native_entries':0,'semantic_change':True,
                                'baseline_output_differs':expected['stdout']!=baseline['stdout']})
        import dataclasses
        for field_name,attribute,change,semantic in (
                ('name','repr',lambda value:not value,False),
                ('effects','compare',lambda value:not value,False),
                ('name','name',lambda value:'semantic_rule',True),
                ('effects','_field_type',lambda value:dataclasses._FIELD_CLASSVAR,True)):
            field=hia_opcodes.OpcodeSpec.__dataclass_fields__[field_name];saved=getattr(field,attribute)
            try:
                setattr(field,attribute,change(saved))
                value=spec.semantic_rule
                expected,_=outcome(False,'semantic_rule',value,[])
                actual,count=outcome(True,'semantic_rule',value,[])
                report['cases'].append({'name':'field-'+field_name+'-'+attribute,'expected':expected,
                    'actual':actual,'equal':expected==actual,'json_native_entries':count,
                    'expected_native_entries':0 if semantic else 1,'semantic_change':semantic,
                    'baseline_output_differs':expected['stdout']!=baseline['stdout']})
            finally:setattr(field,attribute,saved)
        assert len(report['cases'])==11
        assert all(row['equal'] and row['json_native_entries']==row['expected_native_entries']
                   and row['baseline_output_differs']==row['semantic_change'] for row in report['cases'])
        assert report['cases'][6]['actual']['events']==['real-provider-deepcopy']
        report['status']='PASS'
    except BaseException:report['traceback']=traceback.format_exc()
    finally:
        if 'real' in locals():owner.discovery._entry=real
        after=_snapshot(SOURCE);save('SOURCE-AFTER.json',after);report['source_unchanged']=before==after
        report['wall_ns']=time.monotonic_ns()-started
        if before!=after:report['status']='FAIL'
        save('REPORT.json',report)
    return report


def differential(manifest, evidence):
    ROOT=Path(__file__).resolve().parents[1];SOURCE=ROOT;OUT=Path(evidence).absolute()
    OUT.mkdir(mode=0o700)
    def save(name,value):
        (OUT/name).write_text(json.dumps(value,indent=2,sort_keys=True,ensure_ascii=True)+'\n')
    before=_snapshot(SOURCE);save('SOURCE-BEFORE.json',before);started=time.monotonic_ns()
    report={'schema':'hia-cli-discovery-routing-differential.v1','scope':'LOCAL_CPYTHON312_DEVELOPMENT_NOT_COLD','python':sys.version,'status':'FAIL','cases':[],'frames':[],'whole_cli_native':False}
    report['scope']='OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY'
    report['retained_control_sha256']='63730a4d6844ba65d94253bd03d8906822cee685c124e3748362513d5e4ef6e0'
    try:
        from hepta import cli,hia_opcodes
        from hepta.hia_cli_native import installed_cli
        from hepta.hia_cli_discovery_routing_native import _UNKNOWN
        manifest=Path(manifest)
        owner=installed_cli(str(manifest));original=cli._reference_hia_main
        entries={'routing':0,'json':0}
        routing_entry=owner.routing._entry;json_entry=owner.discovery._entry
        def packed(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'zlib_base64':base64.b64encode(zlib.compress(raw,1)).decode()}
        def observe(entry,name):
            def call(s,sn,o,on,w,wn):
                item={'owner':name,'s':packed(ctypes.string_at(s,sn)),'o_before':packed(ctypes.string_at(o,on)),'w_before':packed(ctypes.string_at(w,wn))}
                code=entry(s,sn,o,on,w,wn);entries[name]+=1
                item.update(result=code,o_after=packed(ctypes.string_at(o,on)),w_after=packed(ctypes.string_at(w,wn)))
                report['frames'].append(item);return code
            return call
        owner.routing._entry=observe(routing_entry,'routing');owner.discovery._entry=observe(json_entry,'json')
        def outcome(argv,selected,setup=None):
            events=[];out=io.StringIO();err=io.StringIO();counts=dict(entries)
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.dict(os.environ,{k:v for k,v in os.environ.items() if not k.startswith('HEPTA_') and k not in ('PYTHON_COLORS','NO_COLOR','FORCE_COLOR','TERM','COLUMNS')},clear=True))
                stack.enter_context(contextlib.redirect_stdout(out));stack.enter_context(contextlib.redirect_stderr(err))
                if setup:setup(stack,events)
                try:result=(owner.run(argv,cli) if selected else original(argv));exc=None
                except BaseException as error:result=None;exc={'type':type(error).__name__,'text':str(error),'name':getattr(error,'name',None),'context':None if error.__context__ is None else type(error.__context__).__name__}
            return {'result':result,'exception':exc,'stdout':out.getvalue(),'stderr':err.getvalue(),'events':events}, {key:entries[key]-counts[key] for key in entries}
        def case(name,argv,setup=None,expected_native=None):
            expected,_=outcome(argv,False,setup);actual,count=outcome(argv,True,setup)
            row={'name':name,'argv':argv,'expected':expected,'actual':actual,'equal':expected==actual,'entries':count,'route':owner.last_expression,'unknown_count':len(_UNKNOWN)}
            if expected_native is not None:row['native_expected']=expected_native;row['route_matched']=(count['json']>0)==expected_native
            report['cases'].append(row);save('PARTIAL.json',report)
        case('capabilities',['capabilities'],expected_native=True)
        case('catalog-default',['catalog'],expected_native=True)
        for i in range(1,9):case('catalog-v'+str(i),['catalog','--schema','hepta.hia.program.v'+str(i)],expected_native=True)
        for args in (['--help'],['--version'],['catalog','--schema','invalid'],['catalog','--schema','\u2603'],['unknown']):case('parser-'+repr(args),args)
        def callback(stack,events):
            def output(value):events.append({'type':type(value).__name__,'value':value,'first_spec_type':type(value['opcodes'][0]['inputs']).__name__ if 'opcodes' in value else None})
            stack.enter_context(patch.object(cli,'output_json',output))
        case('custom-capability-output',['capabilities'],callback,False)
        case('custom-catalog-output',['catalog'],callback,False)
        def mutate_output(stack,events):
            def initial(value):events.append(['initial',value])
            def later(value):events.append(['later',value])
            def provider():events.append('provider');cli.output_json=later;return {'actual':'dict'}
            stack.enter_context(patch.object(cli,'output_json',initial));stack.enter_context(patch.object(cli,'agent_capabilities',provider))
        case('provider-replaces-output',['capabilities'],mutate_output,False)
        def domain_error(stack,events):
            def output(value):events.append(['output',value,type(sys.exception()).__name__])
            def provider():events.append('provider');raise ValueError('actual failure')
            stack.enter_context(patch.object(cli,'output_json',output));stack.enter_context(patch.object(cli,'agent_capabilities',provider))
        case('domain-error',['capabilities'],domain_error,False)
        def dumps_replacement(stack,events):
            function=json.dumps
            def replacement(*args,**kwargs):events.append(['dumps',dict(kwargs)]);return function(*args,**kwargs)
            stack.enter_context(patch.object(json,'dumps',replacement))
        case('dumps-replaced-capabilities',['capabilities'],dumps_replacement,False)
        case('dumps-replaced-catalog',['catalog'],dumps_replacement,False)
        report['status']='PASS' if all(row['equal'] and row.get('route_matched',True) for row in report['cases']) else 'FAIL'
        report['entries']=entries

    except BaseException:
        report['status']='FAIL';report['traceback']=traceback.format_exc()
    finally:
        if 'routing_entry' in locals(): owner.routing._entry=routing_entry
        if 'json_entry' in locals(): owner.discovery._entry=json_entry
        after=_snapshot(SOURCE);save('SOURCE-AFTER.json',after)
        report['source_unchanged']=before==after;report['wall_ns']=time.monotonic_ns()-started
        if before!=after:report['status']='FAIL'
        save('REPORT.json',report)
    return report

def ordered(manifest, evidence):
    ROOT=Path(__file__).resolve().parents[1];SOURCE=ROOT;OUT=Path(evidence).absolute()
    OUT.mkdir(mode=0o700)
    def save(name,value):
        (OUT/name).write_text(json.dumps(value,indent=2,sort_keys=True,ensure_ascii=True)+'\n')
    before=_snapshot(SOURCE);save('SOURCE-BEFORE.json',before);started=time.monotonic_ns()
    report={'schema':'hia-cli-discovery-ordered-controls.v1','scope':'LOCAL_CPYTHON312_DEVELOPMENT_NOT_COLD','status':'FAIL','python':sys.version,'cases':[],'frames':[]}
    report['scope']='OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY'
    report['retained_control_sha256']='44b9aa6c813f98c138bf9836cca68a2985d18b6dadfe12cfad0b5f47fd27e230'
    try:
        from hepta import cli,hia_opcodes,hia_program,hia_program_tools
        from hepta.hia_cli_native import installed_cli
        from hepta.hia_cli_discovery_routing_native import DiscoveryExpression,_UNKNOWN
        owner=installed_cli(str(manifest));reference=cli._reference_hia_main
        entry=owner.routing._entry
        def packed(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'zlib_base64':base64.b64encode(zlib.compress(raw,1)).decode()}
        def recorded(s,sn,o,on,w,wn):
         row={'s':packed(ctypes.string_at(s,sn)),'o_before':packed(ctypes.string_at(o,on)),'w_before':packed(ctypes.string_at(w,wn))};value=entry(s,sn,o,on,w,wn)
         row.update(result=value,o_after=packed(ctypes.string_at(o,on)),w_after=packed(ctypes.string_at(w,wn)));report['frames'].append(row);return value
        owner.routing._entry=recorded
        def active():return type(sys.exception()).__name__ if sys.exception() else None
        def compare(name,fn):
         expected=fn(False);actual=fn(True);report['cases'].append({'name':name,'expected':expected,'actual':actual,'equal':expected==actual});save('PARTIAL.json',report)
        def call(action,selected):return owner.run([action],cli) if selected else reference([action])
        def invoke(action,selected):
         try:return call(action,selected),None
         except BaseException as error:return None,error
        def run_outer(action,selected,outer):
         if outer:
          try:raise LookupError('outer')
          except LookupError:return invoke(action,selected)
         return invoke(action,selected)
        def common(selected,failed,outer):
         events=[];names=('verify_program','read_bounded','decode_json','inspect_program','apply_program_patch','publish_program')
         places=[(hia_program,names[0])]+[(hia_program_tools,name) for name in names[1:]]+[(hia_opcodes,'opcode_catalog')]
         originals=[getattr(m,n) for m,n in places];refs=[];saved_output=cli.output_json
         def restore():
          for (module,name),value in zip(places,originals):setattr(module,name,value)
         class Probe:
          def __init__(self,name):self.name=name
          def __call__(self,*args):
           events.append(['call',self.name,active()]);restore()
           if failed:raise RuntimeError('named failure')
           return {'same':True}
          def __del__(self):events.append(['del',self.name,active()])
         def output(value):events.append(['output',type(value).__name__,value,active()])
         try:
          for module,name in places:
           value=Probe(name);refs.append(weakref.ref(value));setattr(module,name,value);del value
          cli.output_json=output;result,error=run_outer('catalog',selected,outer)
          held={'result':result,'error':None if error is None else type(error).__name__,'events':list(events),'alive':[ref() is not None for ref in refs]}
          if error is not None:error.__traceback__=None;error=None
          return {'held':held,'released':{'events':list(events),'alive':[ref() is not None for ref in refs]}}
         finally:restore();cli.output_json=saved_output
        for failed in (False,True):
         for outer in (False,True):compare('common-named-'+str((failed,outer)),lambda selected,f=failed,o=outer:common(selected,f,o))
        def stack(selected,failed,outer):
         events=[];saved_output=cli.output_json;saved_provider=cli.agent_capabilities;refs=[]
         class Output:
          def __call__(self,value):events.append(['output',value,active()])
          def __del__(self):events.append(['output-del',active()])
         class Provider:
          def __call__(self):
           cli.output_json=saved_output;cli.agent_capabilities=saved_provider;events.append(['provider',active()])
           if failed:raise RuntimeError('stack failure')
           return {'real':'dict'}
          def __del__(self):events.append(['provider-del',active()])
         try:
          value=Output();refs.append(weakref.ref(value));cli.output_json=value;del value
          value=Provider();refs.append(weakref.ref(value));cli.agent_capabilities=value;del value
          result,error=run_outer('capabilities',selected,outer)
          held={'result':result,'error':None if error is None else type(error).__name__,'events':list(events),'alive':[ref() is not None for ref in refs]}
          if error is not None:error.__traceback__=None;error=None
          return {'held':held,'released':{'events':list(events),'alive':[ref() is not None for ref in refs]}}
         finally:cli.output_json=saved_output;cli.agent_capabilities=saved_provider
        for failed in (False,True):
         for outer in (False,True):compare('nested-call-stack-'+str((failed,outer)),lambda selected,f=failed,o=outer:stack(selected,f,o))
        def handler(selected,outer):
         events=[];saved_output=cli.output_json;saved_provider=cli.agent_capabilities
         class Stop(BaseException):pass
         class Output:
          def __init__(self,name):self.name=name
          def __call__(self,value):events.append(['output',self.name,value,active()])
          def __del__(self):events.append(['output-del',self.name,active()])
         class Error(ValueError):
          def __str__(self):
           events.append(['str',active()]);cli.output_json=saved_output;raise Stop('handler stopped')
         class Provider:
          def __call__(self):
           cli.agent_capabilities=saved_provider;cli.output_json=Output('handler');raise Error()
          def __del__(self):events.append(['provider-del',active()])
         try:
          cli.output_json=Output('body');cli.agent_capabilities=Provider();result,error=run_outer('capabilities',selected,outer)
          held={'result':result,'error':type(error).__name__,'context':type(error.__context__).__name__ if error.__context__ else None,'events':list(events)}
          error.__traceback__=None;error=None
          return {'held':held,'released':list(events)}
         finally:cli.output_json=saved_output;cli.agent_capabilities=saved_provider
        for outer in (False,True):compare('handler-str-stack-'+str(outer),lambda selected,o=outer:handler(selected,o))
        def deleted(selected,outer):
         saved=cli.agent_capabilities
         try:
          del cli.agent_capabilities
          result,error=run_outer('capabilities',selected,outer)
          return {'result':result,'type':type(error).__name__,'text':str(error),'name':error.name,'context':type(error.__context__).__name__ if error.__context__ else None}
         finally:cli.agent_capabilities=saved
        for outer in (False,True):compare('provider-name-missing-'+str(outer),lambda selected,o=outer:deleted(selected,o))
        report['unknown_count']=len(_UNKNOWN);report['status']='PASS' if all(row['equal'] for row in report['cases']) else 'FAIL'

    except BaseException:
        report['status']='FAIL';report['traceback']=traceback.format_exc()
    finally:
        if 'entry' in locals(): owner.routing._entry=entry
        after=_snapshot(SOURCE);save('SOURCE-AFTER.json',after)
        report['source_unchanged']=before==after;report['wall_ns']=time.monotonic_ns()-started
        if before!=after:report['status']='FAIL'
        save('REPORT.json',report)
    return report

def admission(manifest, evidence):
    ROOT=Path(__file__).resolve().parents[1];SOURCE=ROOT;OUT=Path(evidence).absolute()
    OUT.mkdir(mode=0o700)
    def save(name,value):
        (OUT/name).write_text(json.dumps(value,indent=2,sort_keys=True,ensure_ascii=True)+'\n')
    before=_snapshot(SOURCE);save('SOURCE-BEFORE.json',before);started=time.monotonic_ns()
    report={'scope':'LOCAL_CPYTHON312_MECHANICAL_FACT_OBSERVATION_NOT_COLD','status':'FAIL','cases':[]}
    report['scope']='OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY'
    report['retained_control_sha256']='4ab0d70b761d0e3b75c8a7ee4c1d141337ac808adddc9f2e9200599bde0fae5f'
    try:
        from hepta import cli,hia_opcodes
        from hepta.hia_cli_discovery_facts import observation
        events=[]
        class Meta(type):
         def __eq__(self,other):events.append('metaclass-equality');return False
         __hash__=type.__hash__
        class Value(metaclass=Meta):pass
        spec=next(iter(hia_opcodes.OPCODES.values()));field='name';old=getattr(spec,field)
        try:
         object.__setattr__(spec,field,Value());value=observation(2,cli,cli.output_json,hia_opcodes.opcode_catalog,hia_opcodes)
         report['cases'].append({'name':'metadata-custom-metaclass','admitted_facts':value is not None,'callbacks':list(events),'pass':value is None and not events})
        finally:object.__setattr__(spec,field,old)
        events=[]
        class Descriptor:
         def __get__(self,instance,owner):events.append('module-descriptor');return 'hepta.hia_opcodes'
        # Since CPython 3.13, assigning __module__ also deletes the real
        # __firstlineno__ entry.  Assigning the old module string back cannot
        # restore its original dictionary position.  Execute this unchanged
        # mutation/observer/refusal control in a forked copy, then verify that
        # every parent namespace key, order and value identity is untouched.
        original_namespace=tuple(vars(hia_opcodes.OpcodeSpec).items())
        read_fd,write_fd=os.pipe();child=os.fork()
        if child==0:
         os.close(read_fd);code=1
         try:
          old=hia_opcodes.OpcodeSpec.__module__
          try:
           hia_opcodes.OpcodeSpec.__module__=Descriptor();value=observation(2,cli,cli.output_json,hia_opcodes.opcode_catalog,hia_opcodes)
           record={'name':'metadata-class-descriptor','admitted_facts':value is not None,'callbacks':list(events),'pass':value is None and not events}
          finally:hia_opcodes.OpcodeSpec.__module__=old
          result={'case':record,'firstlineno_present_after_restore':'__firstlineno__' in vars(hia_opcodes.OpcodeSpec)}
          code=0 if record['pass'] else 1
         except BaseException:result={'traceback':traceback.format_exc()}
         try:
          raw=(json.dumps(result,sort_keys=True)+'\n').encode()
          assert os.write(write_fd,raw)==len(raw)
         finally:os.close(write_fd)
         os._exit(code)
        os.close(write_fd)
        with os.fdopen(read_fd,'rb') as stream:raw=stream.read()
        waited,status=os.waitpid(child,0)
        (OUT/'metadata-class-descriptor.child.json').write_bytes(raw)
        report['descriptor_child']={'pid':child,'waited_pid':waited,'wait_status':status,
                                    'stdout_sha256':hashlib.sha256(raw).hexdigest()}
        assert waited==child and os.WIFEXITED(status) and os.WEXITSTATUS(status)==0
        restored_namespace=tuple(vars(hia_opcodes.OpcodeSpec).items())
        assert len(restored_namespace)==len(original_namespace)
        assert all(a==b and x is y for (a,x),(b,y) in zip(original_namespace,restored_namespace))
        report['descriptor_parent_namespace_identity_and_order_unchanged']=True
        record=json.loads(raw)['case'];assert record['pass'] is True
        report['cases'].append(record)
        events=[];old_len=builtins.len
        def replacement(value):
         frame=sys._getframe(1)
         if frame.f_code.co_filename.endswith('hia_cli_discovery_facts.py'):events.append('observer-len')
         return old_len(value)
        try:
         builtins.len=replacement;value=observation(1,cli,cli.output_json,cli.agent_capabilities)
        finally:builtins.len=old_len
        report['cases'].append({'name':'mechanical-builtin-replacement','admitted_facts':value is not None,'callbacks':list(events),'pass':not events})
        report['status']='PASS' if all(x['pass'] for x in report['cases']) else 'FAIL'

    except BaseException:
        report['status']='FAIL';report['traceback']=traceback.format_exc()
    finally:
        after=_snapshot(SOURCE);save('SOURCE-AFTER.json',after)
        report['source_unchanged']=before==after;report['wall_ns']=time.monotonic_ns()-started
        if before!=after:report['status']='FAIL'
        save('REPORT.json',report)
    return report

def foreign_lifetimes(manifest, evidence):
    ROOT=Path(__file__).resolve().parents[1];SOURCE=ROOT;OUT=Path(evidence).absolute()
    OUT.mkdir(mode=0o700)
    def save(name,value):
        (OUT/name).write_text(json.dumps(value,indent=2,sort_keys=True,ensure_ascii=True)+'\n')
    before=_snapshot(SOURCE);save('SOURCE-BEFORE.json',before);started=time.monotonic_ns()
    report={'schema':'hia-cli-discovery-routing-boundaries.v1','scope':'LOCAL_CPYTHON312_DEVELOPMENT_NOT_COLD','status':'FAIL','python':sys.version,'parser':[],'lifetime':[]}
    report['scope']='OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY'
    report['retained_control_sha256']='152c04e0c6830048f2ae7aad0bfe5362441081daf10d6654494558b5ecec9a03'
    try:
        from hepta import cli,hia_opcodes
        from hepta.hia_cli_native import installed_cli
        from hepta.hia_cli_discovery_routing_native import _UNKNOWN
        new=installed_cli(str(manifest))
        from hepta.hia_cli_native import NativeCli
        old=NativeCli(new.control,new.formatter)
        reference=cli._reference_hia_main
        def context(error):
            if error is None:return None
            value={'type':type(error).__name__,'text':str(error),'dictionary':{k:v for k,v in vars(error).items() if type(v) in (str,int,bool,type(None))},'args':[],'traceback':[]}
            for item in error.args:
                if type(item) in (str,int,bool,type(None)):value['args'].append(item)
                else:
                    value['args'].append({'type':type(item).__name__,'fields':{k:v if type(v) in (str,int,bool,type(None),tuple,list) else {'type':type(v).__name__} for k,v in vars(item).items()}})
            tb=error.__traceback__
            while tb:value['traceback'].append(tb.tb_frame.f_code.co_name);tb=tb.tb_next
            value['context']=context(error.__context__)
            return value
        for argv in (['catalog','--schema','invalid'],['catalog','--schema','\u2603'],['unknown']):
            row={'argv':argv,'outcomes':{}}
            for label,call in (('reference',reference),('old-native',lambda x:old.run(x,cli)),('routing-native',lambda x:new.run(x,cli))):
                output,errors=io.StringIO(),io.StringIO()
                with contextlib.redirect_stdout(output),contextlib.redirect_stderr(errors):
                    try:call(argv)
                    except BaseException as error:value=context(error)
                row['outcomes'][label]={'exception':value,'stdout':output.getvalue(),'stderr':errors.getvalue()}
            row['old_and_routing_equal']=row['outcomes']['old-native']==row['outcomes']['routing-native']
            report['parser'].append(row)
        def lifecycle(selected,action,outer):
            events=[];route=new.run if selected else None;module=cli if action=='capabilities' else hia_opcodes;name='agent_capabilities' if action=='capabilities' else 'opcode_catalog';original=getattr(module,name)
            class Provider:
                def __call__(self,*args):
                    setattr(module,name,original);events.append(['call',type(sys.exception()).__name__ if sys.exception() else None]);raise RuntimeError('foreign failure')
                def __del__(self):events.append(['del',type(sys.exception()).__name__ if sys.exception() else None])
            provider=Provider();alive=weakref.ref(provider);setattr(module,name,provider);del provider
            def invoke():
                try:
                    if selected:new.run([action],cli)
                    else:reference([action])
                except BaseException as error:return error
            if outer:
                try:raise LookupError('outer')
                except LookupError:error=invoke()
            else:error=invoke()
            held={'events':list(events),'alive':alive() is not None,'type':type(error).__name__,'context':type(error.__context__).__name__ if error.__context__ else None}
            error.__traceback__=None;error=None
            released={'events':list(events),'alive':alive() is not None}
            setattr(module,name,original)
            return {'held':held,'released':released}
        for action in ('capabilities','catalog'):
            for outer in (False,True):
                expected=lifecycle(False,action,outer);actual=lifecycle(True,action,outer)
                report['lifetime'].append({'action':action,'outer':outer,'expected':expected,'actual':actual,'equal':expected==actual})
        report['unknown_count']=len(_UNKNOWN)
        report['status']='PASS' if all(row['equal'] for row in report['lifetime']) else 'FAIL'

    except BaseException:
        report['status']='FAIL';report['traceback']=traceback.format_exc()
    finally:
        after=_snapshot(SOURCE);save('SOURCE-AFTER.json',after)
        report['source_unchanged']=before==after;report['wall_ns']=time.monotonic_ns()-started
        if before!=after:report['status']='FAIL'
        save('REPORT.json',report)
    return report

def parser_graph(manifest, evidence):
    ROOT=Path(__file__).resolve().parents[1];SOURCE=ROOT;OUT=Path(evidence).absolute()
    OUT.mkdir(mode=0o700)
    def save(name,value):
        (OUT/name).write_text(json.dumps(value,indent=2,sort_keys=True,ensure_ascii=True)+'\n')
    before=_snapshot(SOURCE);save('SOURCE-BEFORE.json',before);started=time.monotonic_ns()
    report={'schema':'hia-cli-parser-object-graph-differential.v1','status':'FAIL','scope':'LOCAL_CPYTHON312_DEVELOPMENT_NOT_COLD','python':sys.version,'cases':[],'old_parser_bodies_native_entries':0}
    report['scope']='OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY'
    report['retained_control_sha256']='4e0a7ee5d91a9a11b74f9eb0904f834490f71b38e17482d0ae16f7ff9119d2db'
    try:
        from hepta import cli
        from hepta.hia_cli_native import installed_cli,_print_parser_message
        from hepta.hia_cli_parser_context_native import NativeParserContext,ParserContext,SOURCE_NAME,SCHEMA,_UNKNOWN
        from hepta.hia_cli_parser_context_data import SHARED_PATHS,SHARED_SIGNATURES
        from hepta.hia_cli_parser_context_foreign import shared_objects,definition_sha
        from hepta.hia_json_preflight_native import _load_manifest
        base=installed_cli(str(manifest));native=base.parser_context
        reference=cli._HIA_DISCOVERY_DEFINITIONS[2]
        shared=shared_objects(cli,SHARED_PATHS,SHARED_SIGNATURES)
        shared_ids={id(value):index for index,value in enumerate(shared)}
        class Observation:
            root=None;action=None;frame=None
        def graph(roots):
            nodes=[];seen={}
            def visit(value):
                ident=id(value)
                if ident in seen:return seen[ident]
                index=len(nodes);seen[ident]=index;nodes.append(None);t=type(value)
                if ident in shared_ids:row=['shared',shared_ids[ident]]
                elif value is None:row=['none']
                elif t is bool:row=['bool',value]
                elif t is int:row=['int',value]
                elif t is str:row=['str',value]
                elif t is bytes:row=['bytes',value.hex()]
                elif t is list:row=['list',[visit(item) for item in value]]
                elif t is set:row=['set',[visit(item) for item in value]]
                elif t is dict:row=['dict',[[visit(key),visit(item)] for key,item in value.items()]]
                elif t is tuple:row=['tuple',[visit(item) for item in value]]
                elif t is types.FunctionType:
                    row=['function',value.__module__,value.__name__,value.__qualname__,definition_sha(value.__code__),value.__globals__ is vars(argparse),visit(value.__defaults__),visit(value.__kwdefaults__),visit(value.__closure__),visit(value.__dict__),visit(value.__annotations__)]
                elif t is re.Pattern:row=['pattern',visit(value.pattern),visit(value.flags)]
                elif t.__module__ in ('argparse','_colorize'):row=['object',t.__module__,t.__qualname__,visit(vars(value))]
                else:raise AssertionError(('unknown graph type',t))
                nodes[index]=row;return index
            root=[visit(value) for value in roots]
            return {'roots':root,'nodes':nodes}
        def exception(error):
            if error is None:return None
            ctx=error.__context__
            return {'type':type(error).__module__+'.'+type(error).__qualname__,'args':[str(x) for x in error.args],'text':str(error),'name':getattr(error,'name',None),'suppress':error.__suppress_context__,'cause':None if error.__cause__ is None else type(error.__cause__).__qualname__,
                    'context':None if ctx is None else {'type':type(ctx).__module__+'.'+type(ctx).__qualname__,'text':str(ctx),'message':getattr(ctx,'message',None),'argument_name':getattr(ctx,'argument_name',None),'action_type':None if not ctx.args or ctx.args[0] is None else type(ctx.args[0]).__qualname__,'context':None if ctx.__context__ is None else [type(ctx.__context__).__qualname__,str(ctx.__context__)],'suppress':ctx.__suppress_context__,'cause':None if ctx.__cause__ is None else type(ctx.__cause__).__qualname__}}
        def run_native(argv,observation):
            session=base.prepare(argv,cli)
            first,second=base.format_result(session)
            if session.kind!=3:
                assert session.kind in (1,2)
                _print_parser_message(first+second,sys.stdout)
                raise SystemExit(session.exit_code)
            frame=ParserContext(native,session,second);observation.frame=frame
            kind,root,action,message=frame.run();observation.root=root;observation.action=action
            if kind:
                try:raise argparse.ArgumentError(action,message)
                except argparse.ArgumentError:
                    _print_parser_message(first,sys.stderr);_print_parser_message(second,sys.stderr)
                    raise SystemExit(session.exit_code)
            _print_parser_message(first,sys.stderr);_print_parser_message(second,sys.stderr)
            raise SystemExit(session.exit_code)
        parser_codes={value.__code__ for value in vars(argparse.ArgumentParser).values() if type(value) is types.FunctionType}
        forbidden={reference.__code__,*parser_codes}
        def outcome(argv,selected,outer,poison,environment=None):
            observation=Observation();out=io.StringIO();err=io.StringIO();caught=None;calls=[]
            def profile(frame,event,arg):
                if event=='call' and frame.f_code in forbidden:calls.append(frame.f_code.co_qualname)
            def invoke():
                nonlocal caught
                try:
                    if selected:run_native(argv,observation)
                    else:reference(argv)
                except BaseException as error:caught=error
            with contextlib.ExitStack() as stack:
                captured_environment={k:v for k,v in os.environ.items() if not k.startswith('HEPTA_') and k not in ('PYTHON_COLORS','NO_COLOR','FORCE_COLOR','TERM','COLUMNS')}
                if environment is not None:captured_environment.update(environment)
                stack.enter_context(patch.dict(os.environ,captured_environment,clear=True))
                stack.enter_context(contextlib.redirect_stdout(out));stack.enter_context(contextlib.redirect_stderr(err))
                if selected and poison:
                    def forbidden_body(*args,**kwargs):raise AssertionError('retained parser body executed')
                    stack.enter_context(patch.object(argparse,'ArgumentParser',forbidden_body));stack.enter_context(patch.object(cli,'_reference_hia_main',forbidden_body))
                if selected:sys.setprofile(profile)
                try:
                    if outer:
                        try:raise LookupError('held outer error')
                        except LookupError:invoke()
                    else:invoke()
                finally:sys.setprofile(None)
            assert caught is not None
            if not selected:
                tb=caught.__traceback__
                while tb is not None:
                    if tb.tb_frame.f_code is reference.__code__:observation.root=tb.tb_frame.f_locals['parser']
                    tb=tb.tb_next
                context=caught.__context__
                if type(context) is argparse.ArgumentError:observation.action=context.args[0]
            value={'stdout':out.getvalue(),'stderr':err.getvalue(),'exception':exception(caught)}
            layout=None if observation.action is None else graph((observation.root,observation.action))
            return value,layout,calls,observation,caught
        inputs=[['catalog','--schema','invalid'],['catalog','--schema','\u2603'],['unknown'],['catalog','--schema'],['build','source.hepta','--output','out','--backend','bad'],[],['verify'],['catalog','--unexpected'],['catalog','--schema','x: error: y'],['catalog','--schema','\ud800'],['build','in.hepta','-o','out','--selfhost-m'],['catalog','--help=x'],['--version=x'],['catalog','-hx']]
        for index,argv in enumerate(inputs):
            for outer in (False,True):
                expected,expected_graph,_,oldob,old_error=outcome(argv,False,outer,False)
                actual,actual_graph,calls,newob,new_error=outcome(argv,True,outer,True)
                save(f'case-{index:02d}-{int(outer)}-expected-graph.json',expected_graph)
                save(f'case-{index:02d}-{int(outer)}-actual-graph.json',actual_graph)
                equal_graph=expected_graph==actual_graph
                difference=None
                if not equal_graph and expected_graph is not None and actual_graph is not None:
                    difference=next(({'node':i,'expected':a,'actual':b} for i,(a,b) in enumerate(zip(expected_graph['nodes'],actual_graph['nodes'])) if a!=b),{'lengths':[len(expected_graph['nodes']),len(actual_graph['nodes'])]})
                row={'argv':argv,'outer':outer,'expected':expected,'actual':actual,'equal':expected==actual,'graph_equal':equal_graph,'first_difference':difference,'forbidden_calls':calls,'entries':None if newob.frame is None else newob.frame.entries,'unknown_count':len(_UNKNOWN)}
                report['cases'].append(row);save('PARTIAL.json',report)
                old_error.__traceback__=None;new_error.__traceback__=None
                del old_error,new_error,oldob,newob
        # Keep all original 28 observations above.  3.14 retains a formatter in
        # each parser, so its environment-dependent graph is separately tested
        # in full, including cached-vs-fresh integer aliases and stdlib palette
        # identities.  These are actual original constructor/selected pairs.
        report['dynamic_layout_cases']=[]
        environments=(
            ('small-width',{'COLUMNS':'10'}),
            ('noncached-width',{'COLUMNS':'1000'}),
            ('arbitrary-integer-width',{'COLUMNS':str((1<<200)+1000)}),
            ('unicode-width',{'COLUMNS':'１０００'}),
            ('underscored-width',{'COLUMNS':'1_000'}),
            ('zero-width',{'COLUMNS':'0'}),
            ('negative-width',{'COLUMNS':'-5'}),
            ('invalid-width',{'COLUMNS':'not-an-integer'}),
            ('forced-color',{'FORCE_COLOR':'1','COLUMNS':'1000'}),
            ('no-color-precedence',{'FORCE_COLOR':'1','NO_COLOR':'1'}),
            ('python-color-precedence',{'PYTHON_COLORS':'0','FORCE_COLOR':'1'}),
        )
        digit_limit=sys.get_int_max_str_digits()
        if digit_limit:
            environments+=(("integer-digit-limit",{'COLUMNS':'9'*(digit_limit+1)}),)
        for index,(name,environment) in enumerate(environments):
            for outer in (False,True):
                argv=['catalog','--schema','bad']
                expected,expected_graph,_,oldob,old_error=outcome(argv,False,outer,False,environment)
                actual,actual_graph,calls,newob,new_error=outcome(argv,True,outer,True,environment)
                save(f'dynamic-{index:02d}-{int(outer)}-expected-graph.json',expected_graph)
                save(f'dynamic-{index:02d}-{int(outer)}-actual-graph.json',actual_graph)
                difference=None
                if expected_graph!=actual_graph and expected_graph is not None and actual_graph is not None:
                    difference=next(({'node':i,'expected':a,'actual':b} for i,(a,b) in enumerate(zip(expected_graph['nodes'],actual_graph['nodes'])) if a!=b),{'lengths':[len(expected_graph['nodes']),len(actual_graph['nodes'])]})
                row={'name':name,'environment':environment,'outer':outer,'expected':expected,'actual':actual,
                     'equal':expected==actual,'graph_equal':expected_graph==actual_graph,'first_difference':difference,
                     'forbidden_calls':calls,'entries':None if newob.frame is None else newob.frame.entries,
                     'unknown_count':len(_UNKNOWN)}
                report['dynamic_layout_cases'].append(row);save('PARTIAL.json',report)
                old_error.__traceback__=None;new_error.__traceback__=None
                del old_error,new_error,oldob,newob
        report['shared_palette_mutations']=[]
        if sys.version_info[:2]==(3,14):
            import _colorize
            palettes=[vars(vars(_colorize)[name])['argparse'] for name in ('theme_no_color','_theme')]
            assert len({id(value) for value in palettes})==2
            actual_entry=native._entry;entries=[]
            def observed_entry(*args):entries.append(True);return actual_entry(*args)
            native._entry=observed_entry
            try:
                for index,palette in enumerate(palettes):
                    namespace=vars(palette)
                    field=next(key for key,value in namespace.items() if type(value) is str)
                    getter=namespace['_name_to_value']
                    assert type(getter) is types.BuiltinMethodType and type(getter.__self__) is dict
                    for label,mapping,key in (('palette-field',namespace,field),
                                              ('bound-getter-dictionary',getter.__self__,next(iter(getter.__self__)))):
                        parent=base.prepare(['catalog','--schema','bad'],cli)
                        first,second=base.format_result(parent)
                        saved=mapping[key];signature=definition_sha(palette);before_entries=len(entries)
                        try:
                            mapping[key]=saved+' changed'
                            assert definition_sha(palette)!=signature
                            try:ParserContext(native,parent,second)
                            except ValueError as error:
                                refused=str(error)=='shared parser definition differs from the admitted graph'
                            else:refused=False
                        finally:mapping[key]=saved
                        restored=definition_sha(palette)==signature
                        current=shared_objects(cli,SHARED_PATHS,SHARED_SIGNATURES)
                        identity=any(value is palette for value in current)
                        row={'palette':index,'mutation':label,'refused':refused,'restored':restored,
                             'same_shared_palette':identity,'native_entries':len(entries)-before_entries}
                        report['shared_palette_mutations'].append(row);save('PARTIAL.json',report)
                        assert refused and restored and identity and len(entries)==before_entries
            finally:native._entry=actual_entry
            assert len(report['shared_palette_mutations'])==4
        complete=report['cases']+report['dynamic_layout_cases']
        report['old_parser_bodies_native_entries']=sum(len(row['forbidden_calls']) for row in complete)
        report['status']='PASS' if all(row['equal'] and row['graph_equal'] and not row['forbidden_calls'] and row['unknown_count']==0 for row in complete) else 'FAIL'

    except BaseException:
        report['status']='FAIL';report['traceback']=traceback.format_exc()
    finally:
        after=_snapshot(SOURCE);save('SOURCE-AFTER.json',after)
        report['source_unchanged']=before==after;report['wall_ns']=time.monotonic_ns()-started
        if before!=after:report['status']='FAIL'
        save('REPORT.json',report)
    return report

def parser_protocol(manifest, evidence):
    ROOT=Path(__file__).resolve().parents[1];SOURCE=ROOT;OUT=Path(evidence).absolute()
    OUT.mkdir(mode=0o700)
    def save(name,value):
        (OUT/name).write_text(json.dumps(value,indent=2,sort_keys=True,ensure_ascii=True)+'\n')
    before=_snapshot(SOURCE);save('SOURCE-BEFORE.json',before);started=time.monotonic_ns()
    report={'schema':'hia-cli-parser-context-protocol-and-lifetime.v1','scope':'LOCAL_CPYTHON312_DEVELOPMENT_NOT_COLD','python':sys.version,'status':'FAIL','controls':[],'frames':[],'vm':[],'all_native_calls':0,'frame_selection':'first complete actual native frame for each command/result/operation tuple plus terminal kind; no claim that every repeated graph link is VM-replayed'}
    report['scope']='OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY'
    report['retained_control_sha256']='7917507dfb63e78cee9961862e66a0a568680ec97516fc5642728e189bb0e724'
    try:
        from hepta import cli
        from hepta.hia_cli_native import installed_cli,_q
        from hepta.hia_cli_parser_context_native import ParserContext,_UNKNOWN,SOURCE_NAME
        from hepta.hia_cli_parser_context_foreign import _EMPTY
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine,_Owner,_View
        owner=installed_cli(str(manifest));image=owner.parser_context;real=image._entry
        seen=set()
        def traced(s,sn,o,on,w,wn):
            raw=ctypes.string_at(s,sn);ob=ctypes.string_at(o,on);wb=ctypes.string_at(w,wn)
            code=real(s,sn,o,on,w,wn);report['all_native_calls']+=1
            after_o=ctypes.string_at(o,on);after_w=ctypes.string_at(w,wn)
            key=(struct.unpack_from('<Q',raw,8)[0],code,struct.unpack_from('<Q',after_o,16)[0],struct.unpack_from('<Q',after_o,56)[0] if code==2 else -1)
            if key not in seen:
                seen.add(key);report['frames'].append({'key':key,'s':packed(raw),'o_before':packed(ob),'w_before':packed(wb),'result':code,'o_after':packed(after_o),'w_after':packed(after_w)})
            return code
        image._entry=traced
        def frame(argv=('catalog','--schema','bad')):
            parent=owner.prepare(list(argv),cli);first,second=owner.format_result(parent);assert parent.kind==3
            return ParserContext(image,parent,second)
        class Lost(BaseException):pass
        def control(name,body):
            row={'name':name,'status':'FAIL'}
            try:row['observations']=body();row['status']='PASS'
            except BaseException:row['traceback']=traceback.format_exc()
            report['controls'].append(row);save('PARTIAL.json',report)
        def replay_refused(value,before_entries):
            errors=[]
            for _ in range(3):
                for method in (value.step,value.observe):
                    try:method()
                    except RuntimeError:errors.append(True)
                    else:errors.append(False)
            assert all(errors) and value.entries==before_entries
            assert value.unknown and value.closed and _UNKNOWN[id(value)] is value
            return errors
        def loss(kind):
            value=frame();assert value.step()==1
            effects=[];effect=value.objects.effect
            def observe_effect(*args):effects.append(args[:4]);return effect(*args)
            value.objects.effect=observe_effect
            if kind=='effect-ack':value.observe()
            if kind in ('release-ack','terminal-ack'):
                while not (value.pending and value.pending[1]==(13 if kind=='release-ack' else 14)):
                    value.observe();assert value.step()==1
                destination=value.pending[2];value.observe()
                if kind=='release-ack':assert value.objects.handles[destination] is _EMPTY
            actual_entry=value._entry;observed=[]
            def interrupt(packet):
                answer=actual_entry(packet);observed.append({'command':struct.unpack_from('<Q',packet,8)[0],'result':answer[0],'output_words':answer[1]})
                raise Lost(kind)
            value._entry=interrupt
            try:
                if kind=='claim':value.observe()
                else:value.step()
            except Lost:pass
            else:raise AssertionError('actual native response was not interrupted')
            entries=value.entries;events=list(effects);replay=replay_refused(value,entries);assert effects==events
            assert len(observed)==1 and observed[0]['result']==(3 if kind=='claim' else 2 if kind=='terminal-ack' else 1)
            if kind=='claim':assert not effects
            return {'actual_response':observed,'entries':entries,'effects':len(effects),'replay_refused':replay,'known_fence':True}
        for name in ('claim','effect-ack','release-ack','terminal-ack'):control('lost-real-'+name,lambda name=name:loss(name))
        def contexts():
            values=[]
            for args,expected in (([],1),(['catalog','--unexpected'],0),(['catalog','--schema','bad'],2)):
                value=frame(args);result=value.run();assert result[0]==expected
                values.append({'argv':args,'kind':result[0],'entries':value.entries,'closed':value.closed,'unknown':value.unknown})
                entries=value.entries
                for method in (value.step,value.observe):
                    try:method()
                    except RuntimeError:pass
                    else:raise AssertionError('terminal parser context replay accepted')
                assert value.entries==entries
            return values
        control('all-three-context-kinds-and-terminal-replay',contexts)
        def reentry():
            value=frame();actual=value._entry;events=[];inside=False
            def boundary(packet):
                nonlocal inside
                if not inside:
                    inside=True
                    try:value.step()
                    except RuntimeError:events.append('rejected')
                    else:events.append('accepted')
                return actual(packet)
            value._entry=boundary
            try:value.step()
            except RuntimeError:pass
            assert events==['rejected'] and value.entries<=1,(events,value.entries)
            return {'events':events,'entries':value.entries}
        control('inflight-step-reentry-before-native-call',reentry)
        def capture(call):
            try:call()
            except SystemExit as error:return error
            raise AssertionError('expected real parser exit')
        def root_observation(error,code,events):
            class Probe:
                def __del__(self):events.append('root-retired')
            tb=error.__traceback__;root=None
            while tb is not None:
                if tb.tb_frame.f_code is code:root=tb.tb_frame.f_locals['parser']
                tb=tb.tb_next
            assert root is not None
            root._lifetime_probe=Probe();reference=weakref.ref(root);root=None
            return reference
        def lifetime(selected,outer):
            events=[]
            function=cli._HIA_DISCOVERY_DEFINITIONS[2]
            def call():
                if selected:return owner.run(['catalog','--schema','bad'],cli)
                return function(['catalog','--schema','bad'])
            with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                if outer:
                    try:raise LookupError('outer')
                    except LookupError:error=capture(call)
                else:error=capture(call)
            code=type(image).raise_error.__code__ if selected else function.__code__
            reference=root_observation(error,code,events)
            result=[{'stage':'held-both','alive':reference() is not None,'events':list(events)}]
            error.__traceback__=None
            result.append({'stage':'exit-tb-detached','alive':reference() is not None,'events':list(events)})
            error.__context__.__traceback__=None
            result.append({'stage':'argument-tb-detached','alive':reference() is not None,'events':list(events)})
            error=None
            result.append({'stage':'error-released','alive':reference() is not None,'events':list(events)})
            return result
        for outer in (False,True):
            def compare(outer=outer):
                expected=lifetime(False,outer);actual=lifetime(True,outer)
                assert expected==actual,(expected,actual)
                assert expected[0]['alive'] and expected[-1]['events']==['root-retired'] and not expected[-1]['alive']
                return {'outer':outer,'expected':expected,'actual':actual,'gc_called':False}
            control('original-root-traceback-retirement-'+str(outer),compare)
        image._entry=real
        program=assemble_program((SOURCE/SOURCE_NAME).read_bytes())
        for index,row in enumerate(report['frames']):
            s,ob,wb=(unpacked(row[key]) for key in ('s','o_before','w_before'))
            owners=[_Owner(-1,bytearray(s)),_Owner(-2,bytearray(ob)),_Owner(-3,bytearray(wb))]
            machine=_Machine(program,10000000,8<<20,None,128)
            result=machine.invoke(program.as_dict()['functions'][0],[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
            equal=result==row['result'] and bytes(owners[0].data)==s and bytes(owners[1].data)==unpacked(row['o_after']) and bytes(owners[2].data)==unpacked(row['w_after'])
            report['vm'].append({'frame':index,'key':row['key'],'result':result,'expected':row['result'],'complete_buffers_equal':equal})
            save('PARTIAL.json',report)
        report['status']='PASS' if all(row['status']=='PASS' for row in report['controls']) and all(row['complete_buffers_equal'] for row in report['vm']) and len(report['vm'])==len(report['frames']) else 'FAIL'

    except BaseException:
        report['status']='FAIL';report['traceback']=traceback.format_exc()
    finally:
        if 'real' in locals(): image._entry=real
        after=_snapshot(SOURCE);save('SOURCE-AFTER.json',after)
        report['source_unchanged']=before==after;report['wall_ns']=time.monotonic_ns()-started
        if before!=after:report['status']='FAIL'
        save('REPORT.json',report)
    return report

def routing_protocol(manifest, evidence):
    ROOT=Path(__file__).resolve().parents[1];SOURCE=ROOT;OUT=Path(evidence).absolute()
    OUT.mkdir(mode=0o700)
    def save(name,value):
        (OUT/name).write_text(json.dumps(value,indent=2,sort_keys=True,ensure_ascii=True)+'\n')
    before=_snapshot(SOURCE);save('SOURCE-BEFORE.json',before);started=time.monotonic_ns()
    report={'schema':'hia-cli-discovery-routing-protocol-vm.v1','scope':'LOCAL_CPYTHON312_DEVELOPMENT_NOT_COLD','status':'FAIL','python':sys.version,'protocol':[],'original_inputs':[],'vm':[],'injected_frames':[]}
    report['scope']='OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY'
    report['retained_control_sha256']='aa7a137f058d871db536948f5b842aacfce71d96440cb3b34bed9439048056a5'
    try:
        from hepta import cli,hia_opcodes
        from hepta.hia_cli_native import installed_cli,_q
        from hepta.hia_cli_discovery_routing_native import DiscoveryExpression,_UNKNOWN
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program_runtime import _Machine,_Owner,_View
        owner=installed_cli(str(manifest))
        real_entry=owner.routing._entry
        class LostReturn(BaseException):pass
        for label,cmd,op in [('claim-return-lost',2,9),('effect-ack-return-lost',1,9),('retirement-ack-return-lost',1,20)]:
         events=[];saved_provider=hia_opcodes.opcode_catalog;saved_output=cli.output_json
         class Provider:
          def __call__(self,schema):
           events.append(['provider',schema]);hia_opcodes.opcode_catalog=saved_provider
           return {'schema':schema,'actual':'dict'}
          def __del__(self):events.append(['provider-del'])
         def output(value):events.append(['output',type(value).__name__,value])
         value=Provider();provider_ref=weakref.ref(value);hia_opcodes.opcode_catalog=value;del value
         cli.output_json=output
         parent=owner.prepare(['catalog'],cli);frame=DiscoveryExpression(owner,parent)
         real_entries=[];injected=[]
         def intercepted(s,sn,o,on,w,wn):
          packet=ctypes.string_at(s,sn);words=struct.unpack_from('<6Q',packet)
          is_named_provider_retirement=(_q(w,256)==_q(w,160))
          row={'label':label,'s':packed(packet),'o_before':packed(ctypes.string_at(o,on)),'w_before':packed(ctypes.string_at(w,wn))}
          result=real_entry(s,sn,o,on,w,wn)
          row.update(result=result,o_after=packed(ctypes.string_at(o,on)),w_after=packed(ctypes.string_at(w,wn)))
          real_entries.append((words[1],words[4],result));report['injected_frames'].append(row)
          if not injected and words[1]==cmd and words[4]==op and (op!=20 or is_named_provider_retirement):
           injected.append({'actual_command':words[1],'actual_operation':words[4],'actual_native_result':result,'workspace_after_sha256':row['w_after']['sha256']})
           raise LostReturn(label)
          return result
         owner.routing._entry=intercepted
         try:
          try:frame.run()
          except BaseException as error:
           original={'type':type(error).__name__,'text':str(error)}
           error.__traceback__=None
          else:raise AssertionError('real returned receipt was not interrupted')
          held={'unknown':frame.unknown,'finished':frame.finished,'registry_same':_UNKNOWN.get(frame.nonce) is frame,'provider_alive':provider_ref() is not None,'events':list(events),'entries':len(real_entries),'workspace':packed(frame.workspace.raw)}
          replays=[]
          for name,call in [('step',frame.step),('observe',frame.observe),('run',frame.run),('retire',frame._retire)]:
           try:call();outcome='returned'
           except BaseException as error:outcome=type(error).__name__
           replays.append({'method':name,'outcome':outcome,'entries':len(real_entries),'events':list(events)})
          expected_provider_calls=0 if cmd==2 else 1
          expected_output_calls=expected_provider_calls
          expected_provider_alive=op!=20
          ok=(len(injected)==1 and original['type']=='LostReturn' and held['unknown'] and held['finished'] and held['registry_same']
              and sum(x[0]=='provider' for x in events)==expected_provider_calls
              and sum(x[0]=='output' for x in events)==expected_output_calls
              and held['provider_alive']==expected_provider_alive
              and all(x['entries']==held['entries'] and x['events']==held['events'] for x in replays))
          report['protocol'].append({'name':label,'pass':ok,'actual_interruption':injected,'error':original,'held':held,'replays':replays,'actual_native_entries':real_entries})
         finally:
          owner.routing._entry=real_entry;hia_opcodes.opcode_catalog=saved_provider;cli.output_json=saved_output
         save('PARTIAL.json',report)
        program=assemble_program((SOURCE/'examples/hia_bootstrap/cli_discovery_routing.hepta').read_bytes())
        frames=[]
        for name in ():
         # The original 803 complete frames already passed; this successor replays only the newly observed targeted retirement frames.
         path=ROOT/'evidence'/name/'REPORT.json';raw=path.read_bytes();original=json.loads(raw)
         report['original_inputs'].append({'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'original_status':original['status'],'all_frames':len(original['frames'])})
         frames.extend((name,i,row) for i,row in enumerate(original['frames']) if row.get('owner','routing')=='routing')
        frames.extend(('protocol-lost-return',i,row) for i,row in enumerate(report['injected_frames']))
        for name,index,row in frames:
         source=unpacked(row['s']);output=unpacked(row['o_before']);workspace=unpacked(row['w_before'])
         owners=[_Owner(-1,bytearray(source)),_Owner(-2,bytearray(output)),_Owner(-3,bytearray(workspace))]
         machine=_Machine(program,10000000,8<<20,None,128)
         result=machine.invoke(program.as_dict()['functions'][0],[_View(owners[0],False),_View(owners[1],True),_View(owners[2],True)])[0]
         output_after=bytes(owners[1].data);workspace_after=bytes(owners[2].data)
         equal=(result==row['result'] and bytes(owners[0].data)==source and output_after==unpacked(row['o_after']) and workspace_after==unpacked(row['w_after']))
         report['vm'].append({'source_case':name,'index':index,'equal':equal,'result':result,'output':packed(output_after),'workspace':packed(workspace_after)})
         if len(report['vm'])%50==0:save('PARTIAL.json',report)
         if not equal:raise AssertionError('complete original native/VM frame differs: '+name+'/'+str(index))
        report['status']='PASS' if len(report['protocol'])==3 and all(x['pass'] for x in report['protocol']) and len(report['vm'])==len(frames) and all(x['equal'] for x in report['vm']) else 'FAIL'

    except BaseException:
        report['status']='FAIL';report['traceback']=traceback.format_exc()
    finally:
        after=_snapshot(SOURCE);save('SOURCE-AFTER.json',after)
        report['source_unchanged']=before==after;report['wall_ns']=time.monotonic_ns()-started
        if before!=after:report['status']='FAIL'
        save('REPORT.json',report)
    return report

def inflight_route(manifest,evidence):
    ROOT=Path(__file__).resolve().parents[1];SOURCE=ROOT;OUT=Path(evidence).absolute();OUT.mkdir(mode=0o700)
    def save(name,value):(OUT/name).write_text(json.dumps(value,indent=2,sort_keys=True)+'\n')
    before=_snapshot(SOURCE);save('SOURCE-BEFORE.json',before);started=time.monotonic_ns()
    report={'schema':'hia-cli-routing-inflight-reentry.v1','scope':'LOCAL_CPYTHON312_DEVELOPMENT_NOT_COLD','status':'FAIL','python':sys.version}
    report['scope']='OBSERVATIONS_ONLY_NOT_COLD_AUTHORITY'
    try:
        from hepta import cli
        from hepta.hia_cli_native import installed_cli
        from hepta.hia_cli_discovery_routing_native import DiscoveryExpression,_UNKNOWN
        owner=installed_cli(str(manifest))
        frame=DiscoveryExpression(owner,owner.prepare(['capabilities'],cli))
        real=owner.routing._entry;boundary=frame._entry;entries=[];attempts=[];inside=False;effects=[]
        effect=frame._effect
        def trace_effect(*args):effects.append(args[:1]);return effect(*args)
        def actual(s,sn,o,on,w,wn):
         result=real(s,sn,o,on,w,wn);entries.append(result);return result
        def entry(packet):
         nonlocal inside
         if not inside:
          inside=True
          try:frame.step();attempts.append('accepted')
          except RuntimeError:attempts.append('rejected')
         return boundary(packet)
        frame._effect=trace_effect;frame._entry=entry;owner.routing._entry=actual
        try:
         try:frame.run();outcome='returned'
         except BaseException as error:outcome=type(error).__name__;error.__traceback__=None
        finally:owner.routing._entry=real
        before_replay=len(entries)
        for method in (frame.step,frame.observe,frame.run,frame._retire):
         try:method()
         except BaseException:pass
        report.update(attempts=attempts,native_entries=entries,effects=effects,outcome=outcome,
                      replay_entries=len(entries)-before_replay,unknown=frame.unknown,finished=frame.finished,
                      quarantined=_UNKNOWN.get(frame.nonce) is frame)
        assert attempts==['rejected'] and len(entries)<=1 and not effects
        assert frame.unknown and frame.finished and _UNKNOWN.get(frame.nonce) is frame
        assert len(entries)==before_replay
        report['status']='PASS'

    except BaseException:report['status']='FAIL';report['traceback']=traceback.format_exc()
    finally:
        after=_snapshot(SOURCE);save('SOURCE-AFTER.json',after);report['source_unchanged']=before==after;report['wall_ns']=time.monotonic_ns()-started
        if before!=after:report['status']='FAIL'
        save('REPORT.json',report)
    return report
