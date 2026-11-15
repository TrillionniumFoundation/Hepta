"""Qualification observation of real HIA Native and Core VM byte entries.

This is not a filesystem provider or a production Store backend. No project
module is imported until Root explicitly runs one frozen qualification child.
"""
from __future__ import annotations
import ctypes
import hashlib
import json
from pathlib import Path
import time
import traceback

LIMITS={'max_steps':10000000,'max_heap_bytes':8388608,'max_call_depth':128}
FRAME_NAMES=('source','output','workspace')

def require(ok,text):
    if not ok:raise AssertionError(text)

def pin(raw):
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest(),
        git_blob=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest())

def dump(path,value):
    raw=(json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    with Path(path).open('xb') as f:f.write(raw)
    require(Path(path).read_bytes()==raw,'complete observation write differs')

def save(path,raw):
    with Path(path).open('xb') as f:f.write(raw)
    require(Path(path).read_bytes()==raw,'complete physical/logical buffer write differs')
    return dict(path=str(path),**pin(raw))

class Span:
    def __init__(self,raw,tag):
        require(type(raw) is bytes and len(raw)<=1048576,'original Native buffer capacity')
        self.size=len(raw);self.left=bytes([tag])*64;self.right=bytes([tag^0xff])*64
        initial=self.left+raw+self.right
        self.owner=ctypes.create_string_buffer(initial,len(initial))
        self.base=ctypes.addressof(self.owner);self.pointer=self.base+64
    def physical(self):return ctypes.string_at(self.base,self.size+128)
    def payload(self):return ctypes.string_at(self.pointer,self.size)
    def guards(self):
        raw=self.physical();return raw[:64]==self.left and raw[-64:]==self.right

class PairEngine:
    def __init__(self,program,image,source_sha,output):
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        self.raw=program;self.source_sha=source_sha;self.output=Path(output)
        require(hashlib.sha256(program).hexdigest()==source_sha,'fixed generated source changed')
        self.checked=assemble_program(program)
        entry=self.checked.as_dict()['functions'][0]
        require(entry['name']=='f0' and [p['type'] for p in entry['params']]==['readbuf','mutbuf','mutbuf']
            and entry['returns']==['u32'] and entry['effects']==['read','write','trap'],
            'actual generated three-buffer/u32 typed first entry differs')
        self.image_pin=pin(image)
        self.native=NativeHiaJsonImage(image,self.image_pin['sha256'])
        require(isinstance(self.native._entry,ctypes._CFuncPtr),'real mapped Native entry required')
        self.entry=self.native._entry;self.calls=[];self.cases=[];self.sessions=[];self.closed=False
        self.output.mkdir(mode=0o700)
        dump(self.output/'PROGRAM.json',dict(source=pin(program),image=self.image_pin,
            core_sha256=self.checked.sha256,input_sha256=self.checked.input_sha256,limits=LIMITS,
            actual_entry='f0',whole=False,durability=False,default=False))
    def session(self,name,output=None,workspace=None):
        require(name not in self.cases,'duplicate explicit case')
        self.cases.append(name)
        value=Session(self,name,bytes([0xa5])*1152 if output is None else output,
            bytes(2048) if workspace is None else workspace)
        self.sessions.append(value);return value
    def close(self):
        require(not self.closed,'one explicit mapped owner cleanup')
        self.closed=True;failure=None
        try:
            require(self.native._entry is self.entry,'mapped entry replaced')
            self.native._entry=None;self.entry=None
            self.native._mapping.close()
        except BaseException:failure=traceback.format_exc()
        dump(self.output/'INDEX.json',dict(schema='hepta.hia.store-codecs.full-native-vm-pairs.v1',
            source_sha256=self.source_sha,image=self.image_pin,cases=self.cases,calls=self.calls,
            actual_native_attempts=len(self.calls),actual_vm_attempts=sum(r.get('vm_attempts',0) for r in self.calls),
            all_complete=all(r.get('complete') is True for r in self.calls),cleanup_error=failure,
            mapping_closed=failure is None,limits=LIMITS,whole=False,durability=False))
        require(failure is None and all(r.get('complete') is True for r in self.calls),'mapping cleanup/full frame incomplete')

class Session:
    def __init__(self,engine,name,output,workspace):
        from hepta.hia_program_runtime import _Owner,_View
        require(type(name) is str and name and '/' not in name,'fixed case component required')
        self.engine=engine;self.name=name;self.n=0
        self.output=Span(output,0x93);self.workspace=Span(workspace,0xc5)
        self.vm_output=_Owner(-2,bytearray(output));self.vm_workspace=_Owner(-3,bytearray(workspace))
        self.vm_views=(_View(self.vm_output,True),_View(self.vm_workspace,True))
        require(self.vm_output is not self.vm_workspace,'distinct mutable VM owners required')
        self.directory=engine.output/name;self.directory.mkdir(mode=0o700)
    def buffers(self):return self.output.payload(),self.workspace.payload()
    def replace_private_workspace_for_control(self,raw):
        """Explicit fault injection on this control's private owner, never admission."""
        require(type(raw) is bytes and len(raw)==self.workspace.size,'same private extent required')
        before=self.workspace.payload();ctypes.memmove(self.workspace.pointer,raw,len(raw))
        self.vm_workspace.data[:]=raw
        dump(self.directory/('INJECTION-%04d.json'%self.n),dict(before=pin(before),after=pin(raw),
            control_only=True,grants_production_capability=False,physical_owner_preserved=True))
    def call(self,source,label):
        from hepta.hia_program_runtime import _Machine,_Owner,_View
        require(type(source) is bytes and type(label) is str,'exact source/label')
        folder=self.directory/('%04d-'%self.n+label);folder.mkdir(mode=0o700);self.n+=1
        span=Span(source,0x6d);spans=(span,self.output,self.workspace)
        ranges=sorted((s.base,s.base+s.size+128) for s in spans)
        require(all(a[1]<=b[0] for a,b in zip(ranges,ranges[1:])),'three Native physical owners overlap')
        vm_source=_Owner(-1,bytearray(source));owners=(vm_source,self.vm_output,self.vm_workspace)
        require(len({id(x) for x in owners})==3,'three VM owners must be distinct')
        views=(_View(vm_source,False),*self.vm_views)
        before=tuple(s.payload() for s in spans)
        require(before==tuple(bytes(x.data) for x in owners),'same actual Native/VM preimages required')
        row=dict(index=len(self.engine.calls),case=self.name,label=label,native_attempts=0,vm_attempts=0,
            returned=False,complete=False,limits=LIMITS,source_sha256=self.engine.source_sha,image=self.engine.image_pin,
            physical_ranges=[dict(begin=s.base,end=s.base+s.size+128,payload=s.pointer,extent=s.size) for s in spans],
            vm_owner_ids=[id(x) for x in owners],vm_view_mutable=[False,True,True])
        for name,s,raw in zip(FRAME_NAMES,spans,before):
            row[name+'_before']=save(folder/(name+'.before.bin'),raw)
            row[name+'_physical_before']=save(folder/(name+'.physical-before.bin'),s.physical())
        dump(folder/'BEFORE.json',row);self.engine.calls.append(row)
        pending=None;native_after=None;machine=None;vm_after=None
        try:
            row['native_attempts']=1;row['native_started_ns']=time.monotonic_ns()
            returned=self.engine.entry(span.pointer,span.size,self.output.pointer,self.output.size,self.workspace.pointer,self.workspace.size)
            row['native_finished_ns']=time.monotonic_ns();row['native_result_u64']=returned
            require(type(returned) is int and 0<=returned<=0xffffffff,'actual zero-extended u32 result required')
            row['returned']=True
        except BaseException:
            pending=sys_exception();row['native_exception']=traceback.format_exc()
        finally:
            errors=[];native_after=[]
            for name,s in zip(FRAME_NAMES,spans):
                try:
                    raw=s.payload();native_after.append(raw)
                    row[name+'_after']=save(folder/(name+'.after.bin'),raw)
                    row[name+'_physical_after']=save(folder/(name+'.physical-after.bin'),s.physical())
                    row[name+'_canaries_unchanged']=s.guards()
                except BaseException:errors.append(traceback.format_exc())
            row['native_observation_errors']=errors
            dump(folder/'NATIVE-AFTER.json',row)
        if pending is not None:raise pending[1].with_traceback(pending[2])
        require(not errors and len(native_after)==3 and native_after[0]==source
            and all(row[n+'_canaries_unchanged'] for n in FRAME_NAMES),'full actual Native/source/canaries failed')
        try:
            machine=_Machine(self.engine.checked,LIMITS['max_steps'],LIMITS['max_heap_bytes'],None,LIMITS['max_call_depth'])
            row['vm_attempts']=1;row['vm_started_ns']=time.monotonic_ns()
            values=machine.invoke(machine.functions['f0'],list(views))
            row['vm_finished_ns']=time.monotonic_ns();row['vm_values']=values
            require(values==[returned],'real VM result differs from actual Native')
        except BaseException:
            pending=sys_exception();row['vm_exception']=traceback.format_exc()
        finally:
            errors=[];vm_after=[]
            for name,owner in zip(FRAME_NAMES,owners):
                try:
                    raw=bytes(owner.data);vm_after.append(raw);row[name+'_vm_after']=save(folder/(name+'.vm-after.bin'),raw)
                except BaseException:errors.append(traceback.format_exc())
            row['vm_observation_errors']=errors
            if machine is not None:row.update(vm_steps=machine.steps,vm_resources=machine.resources())
            row['complete']=len(native_after)==len(vm_after)==3 and not errors and pending is None
            row['all_three_complete_buffers_equal']=native_after==vm_after
            row['vm_owners_active']=[x.active for x in owners]
            row['vm_views_active']=[x.active for x in views]
            dump(folder/'AFTER.json',row)
        if pending is not None:raise pending[1].with_traceback(pending[2])
        require(row['complete'] and row['all_three_complete_buffers_equal'] and row['vm_steps']<=10000000
            and all(row['vm_owners_active']) and all(row['vm_views_active']),'real full Native/VM bytes/limits/owner outcome differs')
        return returned,native_after[1],native_after[2]

def sys_exception():
    import sys
    return sys.exc_info()
