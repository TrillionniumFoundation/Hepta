"""Compare the actual native diagnostic flat with an independently built original Rust oracle."""
from __future__ import annotations
import argparse
import ctypes
from hashlib import sha256
import json
import mmap
from pathlib import Path
import subprocess
from tests.hia_mcp_input_diagnostic_cases import cases


def qualify(flat_path,oracle_path,output,*,stress=True):
    flat_path=Path(flat_path).resolve(strict=True)
    oracle_path=Path(oracle_path).resolve(strict=True)
    output=Path(output).resolve();output.mkdir(mode=0o700)
    source=Path(__file__).resolve().parents[1]
    raw=(source/'docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json').read_bytes()
    records=list(cases(raw,stress=stress))
    request=b''.join(json.dumps(r,ensure_ascii=False,allow_nan=False).encode()+b'\n' for r in records)
    (output/'original-inputs.jsonl').write_bytes(request)
    oracle_bytes=oracle_path.read_bytes()
    run=subprocess.run([str(oracle_path)],input=request,capture_output=True,timeout=180)
    (output/'oracle.stdout').write_bytes(run.stdout);(output/'oracle.stderr').write_bytes(run.stderr)
    if run.returncode or run.stderr:raise AssertionError(('original oracle failed',run.returncode,run.stderr[:1000]))
    expected=[json.loads(line) for line in run.stdout.splitlines()]
    if len(expected)!=len(records):raise AssertionError('original oracle omitted an observation')
    image=flat_path.read_bytes()
    memory=mmap.mmap(-1,len(image),prot=mmap.PROT_READ|mmap.PROT_WRITE|mmap.PROT_EXEC)
    memory.write(image)
    signature=ctypes.CFUNCTYPE(ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint64,
        ctypes.c_void_p,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_uint64)
    function=signature(ctypes.addressof(ctypes.c_char.from_buffer(memory)))
    work=ctypes.create_string_buffer(32<<20)
    result=ctypes.create_string_buffer((8<<20)+512)
    pin=sha256(raw).hexdigest().encode()
    roles={tool['name']:index+1 for index,tool in enumerate(json.loads(raw)['tools'])}
    rows=[]
    for record,original in zip(records,expected,strict=True):
        data=original['canonical'].encode()
        if len(data)>8<<20:
            raise AssertionError(('case exceeds admitted raw domain',record['id'],len(data)))
        buffer=ctypes.create_string_buffer(data)
        ctypes.c_uint64.from_buffer(work).value=roles[record['tool']]
        ctypes.memmove(ctypes.addressof(work)+8,pin,64)
        code=function(buffer,len(data),result,len(result),work,len(work))
        encoded=result.raw[:code] if code<len(result) else b''
        try:actual=None if code==0 else json.loads(encoded)
        except (ValueError,UnicodeError):actual={'native_invalid_json':encoded[:256].hex(),'returncode':code}
        wanted=None if original['ok'] else original['rpc']
        expected_bytes=b'' if original['ok'] else original['rpc_encoded'].encode()
        row={'id':record['id'],'tool':record['tool'],'label':record['label'],
             'canonical_bytes':len(data),'canonical_sha256':sha256(data).hexdigest(),
             'native_return':code,'same':actual==wanted and encoded==expected_bytes,
             'rpc_bytes_same':encoded==expected_bytes}
        if not row['same']:
            row.update(actual=actual,expected=wanted)
            if len([r for r in rows if not r['same']])<8:print('DIAGNOSTIC_DIFFERENCE',json.dumps(row,ensure_ascii=False),flush=True)
        rows.append(row)
    controls=[]
    minimal=b'{"section":"manifest"}'
    def control(label,data,role=1,selected_pin=pin,output_length=len(result),work_length=len(work),exact=4294967293):
        buffer=ctypes.create_string_buffer(data)
        ctypes.c_uint64.from_buffer(work).value=role
        ctypes.memmove(ctypes.addressof(work)+8,selected_pin,64)
        code=function(buffer,len(data),result,output_length,work,work_length)
        admitted=(code==exact) if exact is not None else code>=4294967292
        controls.append({'case':label,'returncode':code,'refused':admitted})
        if not admitted:raise AssertionError(('native ABI refusal failed',label,code))
    control('catalog-pin',minimal,selected_pin=b'0'*64)
    for role in (0,12,(1<<64)-1):control('role-'+str(role),minimal,role=role)
    control('workspace-bound',minimal,work_length=len(work)-1)
    control('output-bound',minimal,output_length=len(result)-1)
    control('input-bound',b' '*(8<<20)+b'0')
    for index,data in enumerate((b'',b'{',b'null null',b'{"x":1,"x":2}',b'"\xff"')):
        control('malformed-'+str(index),data,exact=None)
    if flat_path.read_bytes()!=image or oracle_path.read_bytes()!=oracle_bytes:
        raise ValueError('selected executable custody changed during qualification')
    report={'schema':'hepta.hia.mcp-input-diagnostic-qualification.v1',
        'flat':str(flat_path),'flat_sha256':sha256(image).hexdigest(),
        'original_oracle':str(oracle_path),'original_oracle_sha256':sha256(oracle_bytes).hexdigest(),
        'catalog_sha256':pin.decode(),'cases':len(rows),'matches':sum(r['same'] for r in rows),
        'all_match':all(r['same'] for r in rows),'abi_controls':controls,'raw_canonical_source':'original serde_json::Value to_string',
        'rows':rows}
    (output/'report.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:report[k] for k in ('cases','matches','all_match','flat_sha256')},sort_keys=True),flush=True)
    if not report['all_match']:raise AssertionError('native input diagnostics differ from the original Rust implementation')
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--flat',type=Path,required=True)
    parser.add_argument('--oracle',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--no-stress',action='store_true')
    a=parser.parse_args();qualify(a.flat,a.oracle,a.output,stress=not a.no_stress)
if __name__=='__main__':main()
