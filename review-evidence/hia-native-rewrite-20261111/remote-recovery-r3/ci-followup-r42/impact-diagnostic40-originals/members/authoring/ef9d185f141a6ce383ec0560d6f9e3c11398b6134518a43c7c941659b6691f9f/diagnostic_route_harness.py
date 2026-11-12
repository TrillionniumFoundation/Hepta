"""Mechanical development forwarding of the complete diagnostic route.

No formatting, schema dispatch, Core decision or continuation plan is hosted.
Fixed syscall executor integration is a separate owner/test identity.
"""
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys

ROOT=Path(__file__).resolve().parents[1]
OLD=ROOT.parent/'native-composite-driver-reconstructed'
PROGRAM=ROOT.parent/'native-program-admission-next'
BASE=ROOT.parent/'Hepta-v66-restored'
sys.path[:0]=[str(OLD/'development'),str(OLD),str(BASE)]
from publication_mechanical_executor import PublicBundle,PublicExecutor,Buffer,C
from raw_mechanical_executor import RawExecutor,CTOR_INIT
import mechanical_executor
from hepta.hia_json_preflight_native import NativeHiaJsonImage


class Bundle(PublicBundle):
    def __init__(self):
        super().__init__(OLD/'development/publication-bundle-r2/bundle.json')
        def read(p):
            p=Path(p).resolve();raw=p.read_bytes()
            if p in self.pins:assert self.pins[p]==raw
            self.pins[p]=raw;return raw
        self.read=read
        new={}
        for manifest,roles in [(ROOT/'development/build-r1/bundle.json',
            {27:'core_diagnostic_check',55:'core_diagnostic_text'}),
            (ROOT/'development/build-drivers-r1/bundle.json',
            {45:'diagnostic_publication_driver',46:'diagnostic_program_driver'})]:
            data=json.loads(read(manifest));assert data['status']=='PASS'
            for role,name in roles.items():
                row=data['components'][name];expected=ROOT/'examples/hia_bootstrap'/(name+'.hiaasm')
                assert Path(row['source_path']).resolve()==expected.resolve()
                source=read(expected);assert source==read(row['frozen_source_path'])
                assert len(source)==row['source_bytes'] and sha256(source).hexdigest()==row['source_sha256']
                raw=read(row['image_path']);assert len(raw)==row['image_bytes'] and sha256(raw).hexdigest()==row['image_sha256']
                receipt=json.loads(read(row['receipt_path']))
                assert receipt['input_sha256']==row['source_sha256'] and receipt['produced_sha256']==row['image_sha256']
                assert receipt['artifact_sha256']==data['compiler_sha256']=='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
                new[role]={**row,'role':role,'expected_source_path':str(expected),'compiler_sha256':data['compiler_sha256']}
        frozen=json.loads(read(PROGRAM/'checkpoints/source-r1/source.json'))
        for name,row in frozen['files'].items():
            raw=read(PROGRAM/name);assert len(raw)==row['bytes'] and sha256(raw).hexdigest()==row['sha256']
        data=json.loads(read(PROGRAM/'development/build-r2/bundle.json'));row=data['components']['28']
        source=read(row['source_path']);assert source==read(row['expected_source_path'])
        assert sha256(source).hexdigest()==row['source_sha256']
        raw=read(row['image_path']);assert len(raw)==row['image_bytes'] and sha256(raw).hexdigest()==row['image_sha256']
        receipt=json.loads(read(row['receipt_path']));assert receipt['input_sha256']==row['source_sha256'] and receipt['produced_sha256']==row['image_sha256']
        new[28]=row
        for p in (BASE/'hepta').glob('*.py'):read(p)
        read(Path(__file__))
        self.readback()
        for role,row in new.items():
            if role in self.images:self.images[role]._mapping.close()
            self.components[role]=row
            self.images[role]=NativeHiaJsonImage(self.pins[Path(row['image_path']).resolve()],row['image_sha256'])
        mechanical_executor.TWO_READ.add(55)


class DiagnosticPublicExecutor(PublicExecutor):
    def operate(self,frame):
        if frame[1]!=1 or frame[4]!=55:return super().operate(frame)
        image,first,at,size,second,secondsize,work,worksize,observe,offset,count,zero=frame[4:]
        assert zero==0 and count==64 and self.buffers[first].readonly and self.buffers[second].readonly
        self.events[1]+=1
        result=self.native(image,first,at,size,second,secondsize,work,worksize)
        observed=self.buffers[observe].read(offset,count)
        return struct.pack('<8Q',C['ACK_MAGIC'],frame[2],frame[3],1,0,result,len(observed),0)+observed


class ProgramExecutor(RawExecutor):
    def __init__(self,bundle,wire,directory):
        super().__init__(bundle,wire,directory)
        self.children=[];self.diagnostic_calls=[]

    def operate(self,frame):
        if frame[1]==1:
            image,first,at,size,second,secondsize,work,worksize,observe,offset,count,zero=frame[4:]
            assert image in self.bundle.images and (1<=image<=28 or image==55) and zero==0 and count<=256
            if image==55:
                assert self.buffers[first].readonly and self.buffers[second].readonly and not self.buffers[work].readonly
                self.diagnostic_calls.append({'first':first,'second':second,'output':work,'capacity':worksize})
            self.events[1]+=1;result=self.native(image,first,at,size,second,secondsize,work,worksize)
            observed=self.buffers[observe].read(offset,count)
            return struct.pack('<8Q',C['ACK_MAGIC'],frame[2],frame[3],1,0,result,len(observed),0)+observed
        if frame[1]!=15:return super().operate(frame)
        mode,source,offset,extent,target,lease,*reserved=frame[4:]
        assert mode==0 and offset==0 and not any(reserved) and target not in self.buffers
        original=self.buffers[source].read(0,extent);assert self.buffers[source].readonly
        before=self.buffers[2].read(0,C['MIN_WORK'])
        child=DiagnosticPublicExecutor(self.bundle,original,self.directory/('child-'+str(len(self.children))))
        child.identifier=lease;child.buffers[2].write(12288+24,struct.pack('<Q',lease))
        try:
            terminal=child.run();raw=struct.pack('<16Q',*terminal);capacity=0;transferred=None
            if terminal[4:6]==(0,0):transferred=child.buffers[45]
            elif 57 in child.buffers:transferred=child.buffers[57]
            if transferred is not None:
                assert transferred.readonly
                data=transferred.read(0,transferred.size)
                self.buffers[target]=Buffer(len(data),data,True);capacity=len(data)
            observed=raw+struct.pack('<4Q',capacity,target,child.controller,0)
            self.children.append({'controller':child.controller,'terminal':list(terminal),'calls':dict(child.calls),
                'transfer_capacity':capacity,'transfer_readonly':transferred is not None,
                'admission_buffers_released':47 not in child.buffers and 48 not in child.buffers})
        finally:child.close()
        assert self.buffers[source].read(0,extent)==original
        self.events[15]+=1
        ack=struct.pack('<8Q',C['ACK_MAGIC'],frame[2],frame[3],15,0,128,160,0)+observed
        self.child_resume=(before,ack)
        (self.directory/'actual-child-ack.bin').write_bytes(ack)
        return ack

    def run(self):
        while True:
            initial=self.controller==44 and self.calls[44]==0
            command=self.buffers[44] if initial else Buffer(len(self.command),self.command,True)
            out=Buffer(128)
            try:
                result=int(self.bundle.images[self.controller]._entry(command.address,command.size,out.address,128,
                    self.buffers[2].address,C['MIN_WORK']))
                self.calls[self.controller]+=1
                command.check();out.check();self.buffers[2].check()
                assert command.read(0,command.size)==self.command
                raw=out.read(0,128)
            finally:
                if not initial:command.close()
                out.close()
            frame=struct.unpack('<16Q',raw)
            self.log({'role':self.controller,'return':result,'phase':self.read_state('C_PHASE'),
                'reason':self.read_state('C_REASON'),'frame':raw.hex(),'input_sha256':sha256(self.command).hexdigest()})
            assert result==128 and frame[0]==C['EVENT_MAGIC'] and frame[2]==self.identifier,(result,frame,self.read_state('C_REASON'))
            if frame[1]==7:
                assert frame[3]==self.sequence
                if self.controller==44:
                    if frame[4]==7:self.final=frame;return frame
                    assert frame[4]==CTOR_INIT and frame[5]==self.identifier+1 and frame[6]==0 and frame[8]==48 and not any(frame[9:])
                    assert set(self.buffers)=={0,2,48} and self.buffers[48].readonly and self.buffers[48].size==frame[7]
                    self.buffers[1]=self.buffers.pop(48);self.identifier=frame[5];self.sequence=0;self.controller=46
                    self.command=struct.pack('<8Q',int.from_bytes(b'HIAPAI01','little'),self.identifier,0,frame[7],0,0,0,0)
                    continue
                assert self.controller==46
                self.final=frame;return frame
            assert frame[3]==self.sequence+1
            self.sequence=frame[3];self.command=self.operate(frame)
