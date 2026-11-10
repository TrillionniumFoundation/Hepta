"""Host supervision of the HIA-emitted syscall-only native byte-ABI observer.

This is an explicit qualification transport, not a compiler, parser, production
activation or security sandbox. Each call execs a new sealed immutable ELF and
loads the supplied flat image RW-to-RX. Seed/shared-library loading and shared
post-trap writes retain the independent Python loader. No child is reused.
"""
from __future__ import annotations
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
PACKER = ROOT/'examples/hia_bootstrap/native_observer_packer.hiaasm'
LIMIT = 1 << 20
WORKSPACE_FIELDS = (0,8,16,24,40,48,56,64,72,80,88,96,104,112,224,248,1024)


def digest(data):
    return sha256(data).hexdigest()


def independent_reference():
    """VM executes the actual HIA ELF packer, before any B0 is generated."""
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    from tools.generate_hia_native_observer import reference_image
    image = reference_image()
    from tools.hia_selfhost_bulk import Body
    observations = []
    # The Core ABI has a bounded return list. Observe disjoint windows from
    # fresh executions, covering EVERY byte without hashes standing for data.
    for begin in range(0,len(image),128):
        end = min(begin+128,len(image))
        body = Body(0); owners=[]; views=[]
        for count in (0,len(image),0):
            owner=body.value('buffer','buffer.new',[body.const('usize',count)])
            view=body.value('mutbuf','borrow.mut',[owner])
            owners.append(owner);views.append(view)
        body.effect('buffer.fill',[views[1],body.const('u8',165)])
        body.effect('loan.end',[views[0]])
        views[0]=body.value('readbuf','borrow.read',[owners[0]])
        result=body.value('u32','call',views,{'function':'f0'})
        values=[result]+[body.value('u8','buffer.load',[views[1],body.const('usize',at)])
                        for at in range(begin,end)]
        for view in views:body.effect('loan.end',[view])
        for owner in owners:body.effect('owner.drop',[owner])
        returns=','.join(['u32']+['u8']*(end-begin))
        wrapper=('hia-asm.v1 hepta.hia.program.v8 observer_reference\n'
            +'fn reference_entry() -> ('+returns+') effects(alloc,read,write,trap) entry(b0)\n'
            +'block b0()\n'+body.text()+'  ret('+','.join(values)+')\nend\n'
            +PACKER.read_text().split('\n',1)[1])
        checked=assemble_program(wrapper.encode())
        observed=execute_program(checked,'reference_entry',[])
        if observed.get('status')!='returned' or observed['values']!=[len(image),*image[begin:end]]:
            raise AssertionError('independent VM did not reproduce exact observer ELF window')
        observations.append({'begin':begin,'end':end,'vm_core_sha256':checked.sha256,'result':observed})
    return {'before_B0':True, 'packer_source_sha256':digest(PACKER.read_bytes()),
        'vm_windows':observations, 'expected_image_sha256':digest(image),
        'expected_image_bytes':len(image), 'every_output_byte_compared':True,
        'whole_stack_rewritten_in_hia':False, 'all_input_equivalence_proved':False}


def build(directory, compiler, reference):
    from tools.qualify_hia_selfhost import compile_stage, invoke
    directory = Path(directory)
    packer, compilation = compile_stage(directory, 'native-observer-packer', compiler, PACKER.read_bytes())
    execution, output = invoke(directory, 'native-observer-emit', packer, b'')
    size = reference['expected_image_bytes']
    if (execution.get('status') != 'returned' or execution.get('abi_status') != 0
            or execution.get('core_u32') != size or not execution.get('source_unchanged')
            or digest(output[:size]) != reference['expected_image_sha256']):
        raise AssertionError('HIA packer output differs from independent VM')
    executable = directory/'native-observer.elf'
    executable.write_bytes(output[:size])
    executable.chmod(0o700)
    receipt = {'compiler_sha256':digest(Path(compiler).read_bytes()),
        'source_sha256':digest(PACKER.read_bytes()), 'executable_sha256':digest(output[:size]),
        'independent_reference_before_B0':reference['before_B0'],
        'native_compilation':compilation, 'native_emission':execution,
        'production_activated':False, 'whole_stack_rewritten_in_hia':False}
    (directory/'native-observer-build.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
    return executable, receipt


def frame(image, source, capacity, workspace_size, workspace_fill):
    if (not isinstance(image, bytes) or not 0 < len(image) <= 4*LIMIT
            or not isinstance(source, bytes) or len(source) > LIMIT
            or type(capacity) is not int or not 0 <= capacity <= LIMIT
            or type(workspace_size) is not int or not 0 <= workspace_size <= LIMIT
            or type(workspace_fill) is not int or not 0 <= workspace_fill <= 255):
        raise ValueError('native observer frame exceeds the unchanged byte ABI limits')
    return b'HIAOBS01'+struct.pack('<5Q',len(image),len(source),capacity,workspace_size,workspace_fill)+image+source


def execute(executable_bytes, request, *, cwd, timeout=20, arguments=()):
    """Exec exact sealed bytes, with binary stdin/stdout; never interpret them."""
    fd = os.memfd_create('hia-native-observer', os.MFD_ALLOW_SEALING)
    try:
        view = memoryview(executable_bytes)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError('short observer image write')
            view = view[written:]
        fcntl.fcntl(fd, getattr(fcntl,'F_ADD_SEALS',1033), 15)
        if fcntl.fcntl(fd, getattr(fcntl,'F_GET_SEALS',1034)) & 15 != 15:
            raise OSError('observer image sealing failed')
        return subprocess.run(['/proc/self/fd/'+str(fd), *arguments], input=request,
            cwd=cwd, capture_output=True, timeout=timeout, pass_fds=(fd,),
            env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','TZ':'UTC'})
    finally:
        os.close(fd)


def invoke(directory, label, observer, image, source, *, capacity, workspace_size, workspace_fill):
    directory, image, observer = Path(directory), Path(image), Path(observer)
    image_bytes, executable = image.read_bytes(), observer.read_bytes()
    payload = frame(image_bytes,source,capacity,workspace_size,workspace_fill)
    input_path = directory/(label+'.input.bin')
    output_path = directory/(label+'.output.bin')
    input_path.write_bytes(source)
    request = {'format':'flat-x86-64', 'transport':'HIA-emitted-static-ELF-observer-v1',
        'image':str(image.resolve()), 'image_sha256':digest(image_bytes),
        'source':str(input_path.resolve()), 'source_sha256':digest(source),
        'capacity':capacity, 'workspace_size':workspace_size, 'workspace_fill':workspace_fill,
        'observer_sha256':digest(executable), 'frame_sha256':digest(payload),
        'output':str(output_path.resolve())}
    (directory/(label+'.request.json')).write_text(json.dumps(request,sort_keys=True)+'\n')
    began = time.monotonic_ns()
    output = b''
    try:
        process = execute(executable,payload,cwd=directory)
    except subprocess.TimeoutExpired as exc:
        stderr = exc.stderr or b''
        if exc.stdout:
            (directory/(label+'.failure-stdout.raw')).write_bytes(exc.stdout)
        result = {'status':'timeout','wall_limit_seconds':20}
    else:
        stderr = process.stderr
        if process.returncode:
            if process.stdout:
                (directory/(label+'.failure-stdout.raw')).write_bytes(process.stdout)
            result = {'status':'child_failed','returncode':process.returncode,
                'stderr':stderr.decode('utf-8','replace')[-4096:]}
        else:
            raw = process.stdout
            if len(raw) != 24+len(source)+capacity+workspace_size or raw[:8] != b'HIAOBR01' or stderr:
                (directory/(label+'.failure-stdout.raw')).write_bytes(raw)
                result = {'status':'protocol_failed','returncode':0,
                    'response_bytes':len(raw),'response_sha256':digest(raw),
                    'error':'native observer response framing differs'}
            else:
                returned, elapsed = struct.unpack_from('<2Q',raw,8)
                actual_source = raw[24:24+len(source)]
                output = raw[24+len(source):24+len(source)+capacity]
                workspace = raw[24+len(source)+capacity:]
                output_path.write_bytes(output)
                if actual_source != source:
                    (directory/(label+'.modified-source.bin')).write_bytes(actual_source)
                result = {'status':'returned','result_u64':returned,'abi_status':returned>>32,
                    'return_encoding':'zero-extended-u32','core_u32':returned & 0xffffffff,
                    'source_sha256':digest(source),'image_sha256':digest(image_bytes),
                    'output_sha256':digest(output),'source_unchanged':actual_source==source,
                    'output_unchanged':output==b'\xa5'*capacity,
                    'workspace_header':{str(at):int.from_bytes(workspace[at:at+8],'little')
                        for at in WORKSPACE_FIELDS if workspace_size>=at+8},
                    'native_elapsed_ns':elapsed,'forbidden_compiler_modules_loaded':[],
                    'loader_operations':'HIA-emitted static ELF; sealed exec; RW-to-RX image; fixed ABI call',
                    'limits':{'cpu_seconds':10,'address_bytes':256<<20,'core_dumpable':False,
                        'stack_bytes':8<<20,'output_capacity':capacity,'workspace_bytes':workspace_size}}
    result.update(case=label,input_sha256=digest(source),input_bytes=len(source),
        artifact_sha256=digest(image_bytes),format='flat-x86-64',runner_sha256=digest(executable),
        wall_elapsed_ns=time.monotonic_ns()-began,transport=request['transport'],
        fresh_native_exec=True,successor_process_reuse=False)
    if observer.read_bytes()!=executable or image.read_bytes()!=image_bytes or input_path.read_bytes()!=source:
        raise AssertionError('native observer or immutable inputs changed')
    (directory/(label+'.stdout.log')).write_text(json.dumps(result,sort_keys=True)+'\n')
    (directory/(label+'.stderr.log')).write_bytes(stderr)
    (directory/(label+'.receipt.json')).write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    return result, output
