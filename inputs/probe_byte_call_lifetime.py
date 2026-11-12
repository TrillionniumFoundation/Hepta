"""Bounded original Byte emit_wrapper temporary CALL operand differential.

No product edits and no compilation; accepts an already admitted development
manifest. Actual CPython profile is recorded, never inferred from a forced ABI.
"""
from __future__ import annotations
import argparse,gc,hashlib,json,sys,types
from pathlib import Path

def case(call,outer,throw):
    events=[];held=[];counts={'names':0}
    failure=TypeError('controlled function_symbol')
    def mark(label):
        active=sys.exception()
        events.append([label,None if active is None else type(active).__name__])
    class Name(str):
        def __new__(cls):
            counts['names']+=1;value=super().__new__(cls,'f');value.number=counts['names'];return value
        def __del__(self):mark('name-del:'+str(self.number))
    class Order:
        def get(self,name):
            mark('get-enter')
            if throw:raise failure
            return str(name)
        def __del__(self):mark('order-del')
    class Function:
        def __getitem__(self,key):
            if key=='params':return [{'type':'readbuf'},{'type':'u8'}]
            if key=='name':mark('name-read');return Name()
            raise KeyError(key)
    class Code:
        def __init__(self):self.data=bytearray()
        def __getattr__(self,name):
            def operation(*args):
                if name=='call':mark('code-call')
            return operation
    class Emitter:
        def __init__(self):self.c=Code();self.symbols=[];self.exports=[];self.labels=0
        def label(self,name):self.labels+=1;return name+'_'+str(self.labels)
        @property
        def function_symbol(self):mark('function_symbol-read');return Order().get
    def body():
        try:
            result=call(Emitter(),Function(),32);events.append(['returned',result])
        except BaseException as error:
            events.append(['error',type(error).__name__,str(error),error is failure]);held.append(error)
    if outer:
        try:raise LookupError('outer')
        except LookupError:body();mark('after-call')
    else:body();mark('after-call')
    held.clear();failure=None;gc.collect();mark('after-clear')
    if not any(row[0]=='get-enter' for row in events):raise AssertionError('intended function_symbol CALL not reached')
    return events

def main():
    a=argparse.ArgumentParser();a.add_argument('--source',type=Path,required=True);a.add_argument('--manifest',type=Path,required=True);a.add_argument('--output',type=Path,required=True);args=a.parse_args()
    root=args.source.resolve();sys.path.insert(0,str(root))
    from hepta.hia_native_byte_abi_selection import installed_native_byte_abi
    fixture=root/'tests/fixtures/hia_native_byte_abi_4b.py.txt';module=types.ModuleType('hepta._byte_original_call_probe');module.__package__='hepta';exec(compile(fixture.read_bytes(),str(fixture),'exec'),module.__dict__)
    owner=installed_native_byte_abi(args.manifest)
    source_paths=('hepta/hia_native_byte_abi.py','hepta/hia_native_byte_abi_native.py','hepta/hia_native_byte_abi_selection.py','hepta/hia_machine_plan_control_native.py','examples/hia_bootstrap/native_byte_abi.hiaasm','tests/fixtures/hia_native_byte_abi_4b.py.txt')
    before={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in source_paths};rows=[]
    for throw in (False,True):
        for outer in (False,True):
            reference=case(module.emit_wrapper,outer,throw);native=case(owner.emit_wrapper,outer,throw)
            rows.append({'outer':outer,'throw':throw,'reference':reference,'native':native,'equal':reference==native})
    assert before=={n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in source_paths}
    r={'schema':'hia.native-byte-abi.call-lifetime-probe.v1','scope':'ACTUAL_BYTE_PUBLIC_BUSINESS_BODY_AND_SHARED_PLAN_CALL_DEVELOPMENT','python':sys.version,'sources':before,'image_sha256':owner.image_sha256,'manifest_sha256':hashlib.sha256(args.manifest.read_bytes()).hexdigest(),'source_stable':True,'observations':rows,'matched':sum(row['equal'] for row in rows),'total':len(rows),'product_changed':False}
    args.output.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2));return 0 if all(row['equal'] for row in rows) else 1
if __name__=='__main__':raise SystemExit(main())
