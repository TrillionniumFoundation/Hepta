"""Independent original verification bodies and controlled-provider corpus.

The retained fixture contains the exact pre-owner seven function bodies. They
are compiled solely as a test oracle, using the original live provider globals.
Production never imports this module or executes its oracle source.
"""
from __future__ import annotations
from contextlib import ExitStack
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
from types import FunctionType
from unittest.mock import patch
from hepta import hia_agent_service as api
from hepta import hia_program_native as backend
from hepta import hia_machine_plan as plan_module
from hepta import hia_safe_core_elf as safe_elf
from hepta import hia_checker_identity as checker
from hepta.hia_service_verification_native import ARITIES

ORIGINAL=Path(__file__).with_name('fixtures')/'hia_service_verification_original_v78.json'
ORIGINAL_SHA='c89fbcc755afb0ad6c7acc7beed01e89b76e5e7de9fb9a01287313cbd3408540'

def original_functions():
    raw=ORIGINAL.read_bytes()
    if sha256(raw).hexdigest()!=ORIGINAL_SHA:
        raise AssertionError('original verification oracle bytes changed')
    document=json.loads(raw)
    pieces=['class HIAAgentService:']
    for name in ARITIES:
        method=document['methods'][name]
        for decorator in method['decorators']:
            pieces.append('    @'+decorator)
        pieces.append('    '+method['source'])
    namespace=dict(vars(api))
    exec(compile('\n'.join(pieces)+'\n',str(ORIGINAL),'exec'),namespace)
    result={}
    for name in ARITIES:
        captured=getattr(namespace['HIAAgentService'],name)
        retained=FunctionType(captured.__code__,vars(api),name,captured.__defaults__,captured.__closure__)
        retained.__kwdefaults__=captured.__kwdefaults__
        result[name]=retained
    return result

REFERENCE=originals=original_functions()

class Program:
    sha256='candidate-sha';input_sha256='input-sha';canonical_bytes=b'core'
    def as_dict(self):return {'functions':[{'name':'f0'},{'name':'f1'}]}

class Emitted:
    def __init__(self,label):self.sha256=label;self.function_frames=(('f0',8),)

class Store:
    def __init__(self,fixture):self.owner=fixture;self.documents={};self.bytes={};self.published=[]
    def get_json(self,ref,*,kind=None,_connection=None):
        self.owner.events.append(['get_json',ref,kind,_connection])
        return self.documents[ref],{'row':ref}
    def get(self,ref,*,kind=None,_connection=None):
        self.owner.events.append(['get',ref,kind,_connection])
        return self.bytes[ref],{'row':ref}
    def json(self,value,kind):
        ref='published-'+str(len(self.published))
        self.owner.events.append(['publish',kind,ref]);self.published.append((kind,deepcopy(value)))
        self.documents[ref]=deepcopy(value)
        return ref

class Ports:
    def __init__(self,native=False):
        self.events=[];self.native=native;self.identities={'installed':'same'}
        self.store=Store(self);self.program=Program();self.clock=50
        self.context={'target_profile':'target','foreign_buffer_exports':[],'ref':'ctx','objective':'objective'}
        self.tools={'hia_verify':{'outputSchema':{'properties':{'result':{'properties':{'checks':{'checks-schema':True}}}}}}}
        self.build={'candidate':'candidate','output_kind':'shared','machine_plan':None,
                    'object_artifact':'object','native_build':{'object_sha256':'object-sha','foreign_buffer_exports':[]}}
        self.store.bytes={'native':b'native','object':b'object','query':b'(check-sat)'}
        self.store.documents={'objective':{'required_claims':[]},'plan':{'plan':True}}
        self.validation_error=None;self.behavior=('proved','behavior-domain',{'method':'behavior'})
        self.independent=('proved','independent-domain',{'method':'independent'})
        self.reemit=b'native';self.rebuilt={'object_sha256':'object-sha'}
    def _held_checker_owners(self):self.events.append(['held']);return ()
    def _profile(self,ref,kind,*,_connection=None):self.events.append(['profile',ref,kind,_connection]);return {'profile':ref}
    def _context(self,ref,*,_connection=None):self.events.append(['context',ref,_connection]);return self.context
    def _program(self,ref,*,_connection=None):self.events.append(['program',ref,_connection]);return self.program
    def _remaining_ms(self,context):self.events.append(['remaining']);return self.clock
    def _build_receipt(self,ref,context,artifact,*,_connection=None):self.events.append(['build',ref,context,artifact,_connection]);return self.build
    def _build_inputs(self,ref,context,artifact,*,_connection=None):self.events.append(['build_inputs',ref,context,artifact,_connection]);return self.build,b'native',b'object',self.program
    def _behavior_equivalence(self,left,right,remaining):self.events.append(['behavior',remaining]);return deepcopy(self.behavior)
    def _independent_native_refinement(self,args,program,context):self.events.append(['independent']);return deepcopy(self.independent)
    def _compile(self,program,kind,plan,timeout,**kwargs):self.events.append(['compile',kind,plan,timeout,kwargs]);return self.reemit,self.rebuilt
    def _native(self,artifact,context,*,_connection=None):self.events.append(['native',artifact,context,_connection]);return b'native',{'candidate':'candidate','machine_plan':None,'codegen':None},self.program

class Reference(Ports):pass
for name,function in originals.items():
    setattr(Reference,name,staticmethod(function) if name=='_native_refinement_binding' else function)

class Native(Ports):
    def _subject(self,args,program,*,_connection=None):return self._verification_image.run('_subject',self,args,program,_connection)
    def _hia_verify(self,args):return self._verification_image.run('_hia_verify',self,args)
    def _verification(self,ref,context,candidate=None,*,_connection=None):return self._verification_image.run('_verification',self,ref,context,candidate,_connection)
    def _replay_verification(self,response,arguments,*,_connection=None):return self._verification_image.run('_replay_verification',self,response,arguments,_connection)
    def _required_claims(self,context,candidate_artifact,refs,baseline_core_sha=None,*,_connection=None):return self._verification_image.run('_required_claims',self,context,candidate_artifact,refs,baseline_core_sha,_connection)
    def _check_native_refinement_evidence(self,evidence,subject,context,program,*,_connection=None):return self._verification_image.run('_check_native_refinement_evidence',self,evidence,subject,context,program,_connection)
    def _native_refinement_binding(self,subject,built,program,object_bytes,final_bytes):return self._verification_image.run('_native_refinement_binding',subject,built,program,object_bytes,final_bytes)

def error_record(error):
    def basic(value):
        return None if value is None else {'type':type(value).__name__,'message':str(value),'code':getattr(value,'code',None)}
    return {'error':basic(error),'cause':basic(error.__cause__),'context':basic(error.__context__),
            'suppress':error.__suppress_context__,'notes':getattr(error,'__notes__',None)}

def arguments(kind='core',claims=('core_admission',)):
    subject={'kind':kind}
    if kind!='core':subject['backend_profile']='backend'
    if kind=='canonical_lowering':subject['lowering_profile']='lowering'
    if kind=='agent_machine_plan':subject.update(plan_profile='plan-profile',plan='plan')
    if kind=='native_artifact':subject.update(build_receipt='build',native_artifact='native')
    return {'subject':subject,'context':'ctx','candidate':'candidate','base_program':None,
            'validation_profile':'validation','claims':list(claims)}

def fixture_call(case,native,image=None):
    f=Native(True) if native else Reference()
    if native:
        if image is None:raise ValueError('actual verification image required')
        f._verification_image=image
    args=arguments()
    def validate(value,schema,path):
        f.events.append(['validate',path])
        if f.validation_error is not None:raise f.validation_error
    def proof_subject(value,target):f.events.append(['proof_subject',target]);return deepcopy(value)
    def proof_result(**value):
        f.events.append(['proof_result',value['claim'],value['status']])
        return {key:deepcopy(item) for key,item in value.items() if key not in ('evidence','held_native_owners')}
    def assumptions(value):f.events.append(['assumptions']);return {'proof':deepcopy(value)}
    def emit(program,**kwargs):f.events.append(['emit',kwargs]);return Emitted('planned' if 'machine_plan'in kwargs else 'canonical')
    with ExitStack() as stack:
        for target,name,value in ((api,'validate',validate),(api,'proof_subject',proof_subject),
            (api,'proof_result',proof_result),(api,'assumptions_document',assumptions),
            (api,'installation_manifest',lambda:f.identities),
            (checker,'checker_native_selection',lambda **kwargs:{}),
            (backend,'validate_block_layout_plan',lambda p,x:x),(backend,'emit_program_machine',emit),
            (plan_module,'preservation_checks',lambda p,x:{'choice':True}),
            (safe_elf,'bind_final_artifact',lambda *args:{'binding':{'bound':True}})):
            stack.enter_context(patch.object(target,name,value))
        try:
            if case.startswith('subject-'):
                kind=case.removeprefix('subject-');args=arguments(kind)
                if kind=='native-wrong':args=arguments('native_artifact');f.build['candidate']='wrong'
                value=f._subject(args,f.program,_connection='connection')
            elif case.startswith('verify-'):
                label=case.removeprefix('verify-')
                if label=='core':pass
                elif label=='behavior-missing':args['claims']=['behavior_equivalence']
                elif label=='behavior':args.update(base_program='base',claims=['behavior_equivalence'])
                elif label=='canonical':args=arguments('canonical_lowering',('lowering_refinement',))
                elif label=='plan':args=arguments('agent_machine_plan',('lowering_refinement',))
                elif label=='independent':args=arguments('native_artifact',('lowering_refinement',))
                elif label=='late-deadline':
                    args=arguments('native_artifact',('lowering_refinement',));f.clock=0
                    f.independent=('proved','independent-domain',{'method':api.SAFE_CORE_METHOD})
                elif label=='encoding':args=arguments('native_artifact',('encoding_check',))
                elif label=='encoding-refuted':args=arguments('native_artifact',('encoding_check',));f.reemit=b'changed'
                elif label=='late-unknown':args['claims']=['core_admission','invalid-claim']
                else:raise AssertionError(case)
                value=f._hia_verify(args)
            elif case=='binding':
                value=f._native_refinement_binding(arguments('native_artifact')['subject'],f.build,f.program,b'object',b'native')
            elif case.startswith('evidence-'):
                subject=arguments('native_artifact')['subject']
                evidence={'artifact_binding':originals['_native_refinement_binding'](subject,f.build,f.program,b'object',b'native'),
                          'validation':None,'queries':[]}
                label=case.removeprefix('evidence-')
                if label=='subject':subject['kind']='core'
                elif label=='binding':evidence['artifact_binding']={}
                elif label=='queries-type':evidence['queries']=None
                elif label=='queries-shape':evidence['queries']=[{}]
                elif label=='queries-hash':evidence['queries']=[{'artifact':'query','name':'q','sha256':'wrong'}]
                elif label=='validation':evidence['validation']={'image_binding':{'bound':True},'obligations':[]}
                elif label=='validation-binding':evidence['validation']={'image_binding':{},'obligations':[]}
                elif label!='success':raise AssertionError(case)
                value=f._check_native_refinement_evidence(evidence,subject,'ctx',f.program,_connection='connection')
            elif case.startswith(('receipt-','replay-','required-')):
                made=f._hia_verify(args);ref=made['verification_receipt'];record=f.store.documents[ref]
                # This setup is real original/native production of the same
                # controlled proof record, not a second run of one oracle.
                label=case.split('-',1)[1]
                if case.startswith('receipt-'):
                    if label=='wrong-context':record['context']='wrong'
                    elif label=='wrong-program':record['candidate_core_sha256']='wrong'
                    elif label=='wrong-base':record['base_core_sha256']='wrong'
                    elif label=='duplicate':record['checks']*=2
                    elif label=='schema':f.validation_error=api.AgentRejected('SCHEMA','original invalid schema','scope')
                    elif label=='scope':record['checks'][0]['status']='unknown'
                    elif label!='success':raise AssertionError(case)
                    value=f._verification(ref,'ctx','candidate',_connection='connection')
                elif case.startswith('replay-'):
                    response={'result':made}
                    if label=='subject':args['subject']={'kind':'canonical_lowering'}
                    elif label=='claims':args['claims']=[]
                    elif label=='schema':f.validation_error=api.AgentRejected('SCHEMA','original invalid schema','scope')
                    elif label!='success':raise AssertionError(case)
                    value=f._replay_verification(response,args,_connection='connection')
                else:
                    if label=='success':f.store.documents['objective']['required_claims']=['core_admission']
                    elif label=='missing':f.store.documents['objective']['required_claims']=['encoding_check']
                    elif label=='empty':pass
                    else:raise AssertionError(case)
                    value=f._required_claims(f.context,'native',[ref],_connection='connection')
            else:raise AssertionError(case)
            outcome={'value':value,'error':None}
        except BaseException as error:
            outcome={'value':None,**error_record(error)}
        return {'outcome':deepcopy(outcome),'events':deepcopy(f.events),'published':deepcopy(f.store.published)}

CASES=('subject-core','subject-canonical_lowering','subject-agent_machine_plan','subject-native_artifact','subject-native-wrong',
 'verify-core','verify-behavior-missing','verify-behavior','verify-canonical','verify-plan','verify-independent','verify-late-deadline',
 'verify-encoding','verify-encoding-refuted','verify-late-unknown','binding',
 'evidence-success','evidence-subject','evidence-binding','evidence-queries-type','evidence-queries-shape','evidence-queries-hash',
 'evidence-validation','evidence-validation-binding',
 'receipt-success','receipt-wrong-context','receipt-wrong-program','receipt-wrong-base','receipt-duplicate','receipt-schema','receipt-scope',
 'replay-success','replay-subject','replay-claims','replay-schema','required-success','required-missing','required-empty')
