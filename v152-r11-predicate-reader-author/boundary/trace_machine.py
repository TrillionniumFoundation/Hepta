"""Observe the original VM once per operation without replacing its behavior.

The inherited invoke, tick, allocation and operation implementation is the
fixed original _Machine. Effect records inspect already-evaluated operands;
they do not call _underlying, validate a view, load a byte, or advance fuel.
"""
from hepta.hia_program_runtime import _Machine

class PredicateTraceMachine(_Machine):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.effects=[]
        self.operation_events=[]
        self.predicate_values=[]
        self.observed_views={}
        self.predicate_output=None

    def operand_record(self,value):
        for name,view in self.observed_views.items():
            if value is view:return {'borrowed_view':name}
        if value is None or type(value) in (bool,int,str):return value
        return {'unexpected_runtime_type':type(value).__name__}

    def operation(self,ins,env,depth):
        names=[out['name'] for out in ins['out']]
        self.operation_events.append({'op':ins['op'],'depth':depth,'out':names})
        event=None
        if ins['op'].startswith('buffer.') or ins['op']=='call':
            event={'op':ins['op'],'depth':depth,'attrs':dict(ins['attrs']),
                'args':[self.operand_record(env[name]) for name in ins['args']]}
            self.effects.append(event)
        try:
            result=super().operation(ins,env,depth)
        except BaseException as error:
            if event is not None:
                event.update(outcome='raised',error={'type':type(error).__name__,
                    'code':getattr(error,'code',None),'message':str(error)})
            raise
        else:
            if event is not None:
                event.update(outcome='completed',values=[self.operand_record(env[name]) for name in names])
            if depth==0 and self.predicate_output in names:
                self.predicate_values.append(env[self.predicate_output])
            return result
