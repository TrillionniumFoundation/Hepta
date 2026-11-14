"""Observation-only subclass of the actual original VM.

The original invoke/tick/operation bodies are neither copied nor changed.
Every operation is delegated exactly once; only physical byte attempts and
the already-observed result are appended to a separate host journal.
"""
from hepta.hia_program_runtime import _Machine

class TraceMachine(_Machine):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.byte_events=[]
        self.operation_events=[]
        self.byte_event_op_indices=[]

    def operation(self,ins,env,depth):
        self.operation_events.append({'op':ins['op'],'depth':depth})
        if ins['op'] not in ('buffer.load','buffer.store'):
            return super().operation(ins,env,depth)
        event={'op':ins['op'],'index':env[ins['args'][1]]}
        if ins['op']=='buffer.store':event['value']=env[ins['args'][2]]
        self.byte_events.append(event)
        self.byte_event_op_indices.append(len(self.operation_events)-1)
        try:
            result=super().operation(ins,env,depth)
        except BaseException as error:
            event['outcome']='raised'
            event['error']={'type':type(error).__name__,'code':getattr(error,'code',None),'message':str(error)}
            raise
        else:
            event['outcome']='completed'
            if ins['op']=='buffer.load':event['loaded']=env[ins['out'][0]['name']]
            return result
