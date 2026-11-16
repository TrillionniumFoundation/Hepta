"""Build the separate raw descriptor primitive; this is not a cold HIA owner gate.

The input is one frozen assembly file. No publication, authority, retry, cleanup
or descriptor-lifetime policy is implemented by this builder or its raw image.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import time
ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,''):sys.path.insert(0,str(ROOT))
from tools.qualify_hia_store_file_capture_originals import stop_owned
SOURCE='tools/hia_capture_descriptor_syscalls.S'

def capture_text(raw):
    if len(raw)<64 or raw[:16]!=b'\x7fELF\x02\x01\x01'+b'\0'*9:
        raise ValueError('descriptor object must be exact little-endian ELF64')
    header=struct.unpack_from('<16sHHIQQQIHHHHHH',raw)
    if header[1:4]!=(1,62,1) or header[8]!=64 or header[11]!=64 or header[12]<1:
        raise ValueError('descriptor object type or section layout differs')
    offset,count,names_index=header[6],header[12],header[13]
    if names_index>=count or offset+64*count>len(raw):
        raise ValueError('descriptor object section table is out of range')
    sections=[struct.unpack_from('<IIQQQQIIQQ',raw,offset+64*i) for i in range(count)]
    def bytes_for(section):
        start,size=section[4:6]
        if start+size>len(raw):raise ValueError('ELF section is out of range')
        return raw[start:start+size]
    names=bytes_for(sections[names_index])
    def name_at(start):
        if start>=len(names):raise ValueError('section name is out of range')
        stop=names.find(b'\0',start)
        if stop<0:raise ValueError('section name is unterminated')
        return names[start:stop]
    matches=[i for i,s in enumerate(sections) if name_at(s[0])==b'.text']
    if len(matches)!=1:raise ValueError('descriptor object lacks one complete text section')
    text_index=matches[0];section=sections[text_index];text=bytes_for(section)
    if section[1]!=1 or section[2]&6!=6 or not text:
        raise ValueError('descriptor text is not an executable allocated section')
    for row in sections:
        if row[1] in (4,9) and row[7]==text_index and row[5]:
            raise ValueError('raw descriptor entry must contain no linker relocations')
    found=[]
    for row in sections:
        if row[1]!=2:continue
        if row[9]!=24 or row[5]%24 or row[6]>=count:raise ValueError('ELF symbol table differs')
        symbols=bytes_for(row);strings=bytes_for(sections[row[6]])
        for point in range(0,len(symbols),24):
            n,info,other,index,value,size=struct.unpack_from('<IBBHQQ',symbols,point)
            if n>=len(strings):raise ValueError('ELF symbol string differs')
            stop=strings.find(b'\0',n)
            if stop<0:raise ValueError('ELF symbol is unterminated')
            if strings[n:stop]==b'hia_capture_descriptor_entry':
                found.append((info,other,index,value,size))
    if found!=[(18,0,text_index,0,len(text))]:
        raise ValueError('raw descriptor must be the single complete global function at entry zero')
    return text

def build(output,assembler):
    output=Path(output);assembler=Path(assembler).resolve(strict=True)
    source=(ROOT/SOURCE).read_bytes();compiler=assembler.read_bytes()
    output.mkdir(mode=0o700,parents=True,exist_ok=False)
    (output/'input.S').write_bytes(source)
    command=[str(assembler),'-c','-x','assembler','-target','x86_64-linux-gnu',
             str(output/'input.S'),'-o',str(output/'descriptor.o')]
    start=time.monotonic();process=None;timeout=False;cleanup_error=None;cleanup=None
    with (output/'assembler.stdout.log').open('xb') as out,(output/'assembler.stderr.log').open('xb') as err:
        try:
            process=subprocess.Popen(command,cwd=output,stdin=subprocess.DEVNULL,
                                     stdout=out,stderr=err,start_new_session=True)
            (output/'assembler-start.json').write_text(json.dumps(
                {'command':command,'cwd':str(output),'pid':process.pid,'pgid':process.pid,
                 'body_seconds':30,'cleanup_seconds':3},sort_keys=True)+'\n')
            try:process.wait(timeout=30)
            except subprocess.TimeoutExpired:timeout=True
        finally:
            if process is not None:
                try:
                    cleanup=stop_owned(process)
                except BaseException as error:cleanup_error=type(error).__name__+': '+str(error)
    receipt={'command':command,'pid':None if process is None else process.pid,
             'returncode':None if process is None else process.returncode,'timeout':timeout,
             'cleanup_error':cleanup_error,'cleanup':cleanup,'elapsed_seconds':time.monotonic()-start,
             'assembler_sha256':sha256(compiler).hexdigest(),'source_sha256':sha256(source).hexdigest()}
    (output/'assembler-result.json').write_text(json.dumps(receipt,sort_keys=True)+'\n')
    if process is None or process.returncode!=0 or timeout or cleanup_error:
        raise RuntimeError('raw descriptor assembly did not complete normally')
    object_raw=(output/'descriptor.o').read_bytes();text=capture_text(object_raw)
    if assembler.read_bytes()!=compiler or (ROOT/SOURCE).read_bytes()!=source:
        raise ValueError('descriptor assembler or source changed')
    (output/'descriptor.bin').write_bytes(text)
    report={'schema':'hepta.hia.raw-capture-descriptor.v1','scope':'EXPLICIT_RAW_ABI_DEVELOPMENT',
            'architecture':'linux-x86_64','image_path':'descriptor.bin','image_sha256':sha256(text).hexdigest(),
            'source':SOURCE,'source_sha256':sha256(source).hexdigest(),
            'object_sha256':sha256(object_raw).hexdigest(),'assembler':receipt,
            'ABI_operations':['openat','fstat','read','close'],
            'same_cold_HIA_qualification':False,'public_OS_provider_substituted':False,
            'artifact_publication_or_retirement_policy_replaced':False}
    (output/'descriptor.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    return output/'descriptor.json'

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--assembler',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();print(build(a.output,a.assembler))
if __name__=='__main__':main()
