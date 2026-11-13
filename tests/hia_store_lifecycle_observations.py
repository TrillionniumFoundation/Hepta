"""Retained Store R2 observation bodies, with only fixed reference-name projection.

The original failure and PASS scripts remain in the immutable R2 custody.
These helpers add no success conditions and remove no original assertions.
"""
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import hashlib, json, os, sys, time, traceback, weakref
from hepta import hia_agent_store as api
from hepta import hia_store_lifecycle_native as native
from hepta import hia_front_continuation as bridge
from tests import hia_store_lifecycle_fixtures as base
fixtures = fixture = base
ORIGINAL_INIT = api._NATIVE_STORE_INITIALIZE_REFERENCE


def run_case(image, scenario, selected, ambient, closing=False):
    fixture = fixtures.Fixture(scenario, ambient=ambient)
    store = fixtures.StoreObject(fixture)
    if closing:
        for name, label in (('slot_ledger', 'ledger'), ('artifact_namespace', 'namespace'),
                            ('request_journal', 'request'), ('execution_budgets', 'budget')):
            object.__setattr__(store, name, None if scenario == 'close_missing_optional' and label != 'budget'
                               else fixtures.Owner(fixture, label))
        object.__setattr__(store, 'db', fixture.db)
    with fixture.install(api):
        if selected:
            with patch.object(api.AgentStore, '__init__', side_effect=AssertionError('retained init entered')) as init, \
                 patch.object(api.AgentStore, 'close', side_effect=AssertionError('retained close entered')) as close:
                call = (lambda: image.close_store(store)) if closing else (lambda: image.initialize(store, 'root'))
                result = fixtures.outcome(fixture, call, store)
                assert init.call_count == close.call_count == 0
        else:
            call = (lambda: api._NATIVE_STORE_CLOSE_REFERENCE(store)) if closing else (lambda: api._NATIVE_STORE_INITIALIZE_REFERENCE(store, 'root'))
            result = fixtures.outcome(fixture, call, store)
    return result


class WatchedFailure(RuntimeError):
 def __init__(self,fixture,label):
  super().__init__(label);self.fixture=fixture;self.label=label
 def add_note(self,note):
  f=self.fixture;f.note_count+=1;f.event('add-note',note)
  if f.scenario=='clear-owner-references' and f.note_count==1:
   for name in ('slot_ledger','artifact_namespace','request_journal','execution_budgets'):
    object.__setattr__(f.store(),name,None)
  if f.scenario=='note-failure-'+str(f.note_count):
   raise f.failure('note:'+str(f.note_count))
  return super().add_note(note)
 def __del__(self):
  self.fixture.trace.append(['error-del',self.label,self.fixture.active_error()])


class WatchedOwner(base.Owner):
 def close(self):
  self.fixture.event('close:'+self.name)
  if self.fixture.cleanup_errors:
   raise self.fixture.failure('cleanup:'+self.name)
 def __del__(self):
  self.fixture.trace.append(['owner-del',self.name,self.fixture.active_error()])


class WatchedDatabase(base.Database):
 def close(self):
  self.fixture.event('close:database')
  if self.fixture.cleanup_errors:
   raise self.fixture.failure('cleanup:database')


class Fixture(base.Fixture):
 def __init__(self,scenario):
  super().__init__(scenario);self.refs={};self.note_count=0;self.store=None
  self.cleanup_errors=scenario not in ('handler-unmatched','handler-invalid')
  self.db=WatchedDatabase(self)
 def failure(self,label):
  value=WatchedFailure(self,label);self.refs[label]=weakref.ref(value);return value
 def event(self,label,*args,**kwargs):
  self.trace.append([label,self.clean(args),self.clean(kwargs),self.active_error()])
  if label=='create:ledger':raise self.failure(label)
 def factory(self,name):
  def call(store,admission,**kwargs):
   self.event('create:'+name,admission,**kwargs)
   value=WatchedOwner(self,name);self.refs['owner:'+name]=weakref.ref(value);return value
  return call
 def type_port(self,value):
  self.event('type-port',value)
  if self.scenario=='type-failure':raise self.failure('type')
  f=self
  typename=type(value).__name__
  class Name:
   @property
   def __name__(self):
    f.event('type-name')
    if f.scenario=='type-name-failure':raise f.failure('type-name')
    return typename
  return Name()
 def install(self,module):
  stack=super().install(module)
  if self.scenario=='handler-unmatched':stack.enter_context(patch.object(module,'BaseException',KeyError,create=True))
  if self.scenario=='handler-invalid':stack.enter_context(patch.object(module,'BaseException',None,create=True))
  if self.scenario in ('type-failure','type-name-failure'):
   stack.enter_context(patch.object(module,'type',self.type_port,create=True))
  return stack


def error_view(error,seen=None):
 if error is None:return None
 if seen is None:seen=set()
 if id(error) in seen:return {'cycle':True}
 seen.add(id(error))
 return {'type':type(error).__name__,'args':list(error.args),'notes':list(getattr(error,'__notes__',[])),
         'cause':error_view(error.__cause__,seen),'context':error_view(error.__context__,seen),
         'suppress_context':error.__suppress_context__}


def capture(call,store):
 try:call(store,'root')
 except BaseException as error:return error
 raise AssertionError('initializer was expected to fail')


def observe(image,scenario,selected):
 fixture=Fixture(scenario);store=base.StoreObject(fixture);fixture.store=weakref.ref(store)
 frames=[];real_prepare=image.prepare
 def observed_prepare(*args,**kwargs):
  frame=real_prepare(*args,**kwargs);frames.append(weakref.ref(frame));return frame
 with fixture.install(api),patch.object(image,'prepare',observed_prepare):
  if selected:
   with patch.object(api.AgentStore,'__init__',side_effect=AssertionError('retained initializer entered')) as old_init,patch.object(api.AgentStore,'close',side_effect=AssertionError('retained close entered')) as old_close:
    error=capture(image.initialize,store)
    assert old_init.call_count==old_close.call_count==0
  else:error=capture(ORIGINAL_INIT,store)
 store=None
 result={'error':error_view(error),'held_trace':list(fixture.trace),
         'held_error_liveness':{key:value() is not None for key,value in fixture.refs.items()},
         'store_alive_held':fixture.store() is not None}
 if selected:
  if len(frames)!=1 or frames[0]() is None:raise AssertionError('native held error lost its original logical frame')
 error=None
 result.update(final_trace=list(fixture.trace),final_error_liveness={key:value() is not None for key,value in fixture.refs.items()},store_alive_final=fixture.store() is not None)
 # No collection is invoked to force reference cycles to disappear. A final
 # lifetime equality with both primary objects still alive is not a success.
 result['finally_released']=not result['store_alive_final'] and not result['final_error_liveness'].get('create:ledger',True)
 return result


def reject(call):
 try:call()
 except RuntimeError:return True
 raise AssertionError('spent or unavailable permission was accepted')


def unknown_observation(image,case,out):
 f=fixture.Fixture('fail:create:ledger+cleanup_failure' if case=='handled-pop-ack' else 'no_native_admissions')
 obj=fixture.StoreObject(f)
 if case=='retirement-ack':
  for name,label in (('slot_ledger','ledger'),('artifact_namespace','namespace'),('request_journal','request'),('execution_budgets','budget')):object.__setattr__(obj,name,fixture.Owner(f,label))
  object.__setattr__(obj,'db',f.db)
  frame=image.prepare('close',(obj,))
 else:frame=image.prepare('__init__',(obj,'root'))
 with f.install(api),patch.object(api.AgentStore,'__init__',side_effect=AssertionError('old init entered')) as old_init,patch.object(api.AgentStore,'close',side_effect=AssertionError('old close entered')) as old_close:
  if case=='retirement-ack':
   assert frame.drive()==0 and frame.take() is None
   issued=None
  else:
   while True:
    assert frame.step()==1
    op,dest,args,raw,vector=frame._parts()
    target=(op==27) if case=='handled-pop-ack' else (op==9 and args and getattr(frame._get(args[0]),'__func__',None) is fixture.Fixture.connect)
    if target:break
    frame.service(frame.pending)
   issued=frame.pending
   entries=image.entries
   reject(lambda:frame.service(bridge.Issued(issued.raw)))
   reject(frame.step)
   assert image.entries==entries
   frame.service(issued)
   assert frame.executed and frame.completed
   if case=='call-ack':assert all(frame.values[i] is bridge._EMPTY for i in args)
   reject(lambda:frame.service(issued))
   (out/(case+'.issued.bin')).write_bytes(issued.raw)
  before=list(f.trace);entries=image.entries
  before_state=bytes(frame.state);before_output=bytes(frame.output)
  failure=KeyboardInterrupt('after the actual '+case+' native acknowledgement')
  returned=[];real=frame._invoke
  def lose(command,*args,**kwargs):
   result=real(command,*args,**kwargs)
   if command==1:
    returned.append(result);raise failure
   return result
  with patch.object(frame,'_invoke',lose):
   try:
    if case=='retirement-ack':frame.close()
    else:frame.step()
   except KeyboardInterrupt as error:assert error is failure
   else:raise AssertionError('actual lost ACK did not escape')
  assert len(returned)==1 and frame.closed and frame._uncertain
  after_entries=image.entries
  replays=[reject(frame.step),reject(frame.drive),reject(frame.take),reject(lambda:frame.service(issued))]
  assert image.entries==after_entries and f.trace==before
  frame.close()
  assert bridge._UNCONFIRMED_RETIREMENTS.get(frame.nonce) is frame
  assert old_init.call_count==old_close.call_count==0
  for suffix,rawbytes in (('state-before',before_state),('output-before',before_output),('state-after',bytes(frame.state)),('output-after',bytes(frame.output))):(out/(case+'.'+suffix+'.bin')).write_bytes(rawbytes)
  return {'case':case,'actual_ack_return':returned,'entries_before':entries,'entries_after':after_entries,'replays_refused':replays,'foreign_trace_unchanged_after_actual_ack':True,'unknown_retained':True,'old_body_calls':0,'trace':f.trace,'nonempty_slots_retained':sum(v is not bridge._EMPTY for v in frame.values)}
