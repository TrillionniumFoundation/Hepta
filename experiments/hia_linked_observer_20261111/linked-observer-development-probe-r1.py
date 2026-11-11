"""First real linked ELF vertical path; development only, exact files retained."""
from pathlib import Path
import hashlib,json,subprocess,sys,traceback

ROOT=Path('/workspace/scratch/e26ed3e2edcf/hia-preflight-diagnostics-93')
OUT=Path('/tmp/hia-e26e-linked-development-r1')
sys.path.insert(0,str(ROOT))
from tools.qualify_hia_selfhost import compile_stage,invoke
from tools.generate_hia_linked_observer import reference_image
from tools.hia_selfhost_native_observer import execute,frame
from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program_runtime import _Machine,_Owner,_View

def sha(b):return hashlib.sha256(b).hexdigest()
def main():
    OUT.mkdir(mode=0o700)
    compiler=Path('/workspace/scratch/e26ed3e2edcf/journal-recovered-development-r1/development-compiler.bin')
    assert sha(compiler.read_bytes())=='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
    sources={n:(ROOT/'examples/hia_bootstrap'/('linked_observer_'+n+'.hiaasm')).read_bytes() for n in ('policy','packer')}
    manifest={'scope':'DEVELOPMENT ONLY; reused exact earlier B3; no cold qualification',
      'compiler':str(compiler),'compiler_sha256':sha(compiler.read_bytes()),
      'source_sha256':{n:sha(s) for n,s in sources.items()}}
    (OUT/'manifest.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    # Independent Core interpretation of the full packer output, before native emission.
    checked=assemble_program(sources['packer'])
    sample=bytes(range(32))
    expected=reference_image(sample)
    owner_s=_Owner(1,bytearray(sample)); owner_o=_Owner(2,bytearray([165])*len(expected)); owner_w=_Owner(3,bytearray())
    machine=_Machine(checked,20_000_000,1<<20,None,128)
    observed=machine.invoke(machine.functions['f0'],[_View(owner_s,False),_View(owner_o,True),_View(owner_w,True)])
    assert observed==[len(expected)],observed
    assert bytes(owner_o.data)==expected
    (OUT/'vm-packer.json').write_text(json.dumps({'result':observed,'every_byte_compared':True,
       'bytes':len(expected),'sha256':sha(expected),'steps':machine.steps},sort_keys=True)+'\n')
    print('VM packer every byte PASS',len(expected),flush=True)
    policy,pr=compile_stage(OUT,'policy',compiler,sources['policy'])
    packer,pa=compile_stage(OUT,'packer',compiler,sources['packer'])
    result,output=invoke(OUT,'emission',packer,policy.read_bytes())
    expected=reference_image(policy.read_bytes())
    assert result['core_u32']==len(expected),result
    assert output[:len(expected)]==expected
    executable=OUT/'linked-observer.elf';executable.write_bytes(output[:len(expected)]);executable.chmod(0o700)
    (OUT/'minimal.S').write_text('.text\n.global f0\n.type f0,@function\nf0:\n mov $42,%eax\n ret\n.section .note.GNU-stack,"",@progbits\n')
    subprocess.run(['as','--64',str(OUT/'minimal.S'),'-o',str(OUT/'minimal.o')],check=True)
    subprocess.run(['ld','-shared','-o',str(OUT/'minimal.so'),str(OUT/'minimal.o')],check=True)
    request=frame((OUT/'minimal.so').read_bytes(),b'abc',17,32,90)
    (OUT/'request.bin').write_bytes(request)
    actual=execute(executable.read_bytes(),request,cwd=OUT)
    (OUT/'stdout.bin').write_bytes(actual.stdout);(OUT/'stderr.bin').write_bytes(actual.stderr)
    observation={'returncode':actual.returncode,'stdout_bytes':len(actual.stdout),
      'stdout_sha256':sha(actual.stdout),'stderr_hex':actual.stderr.hex(),
      'policy_native_sha256':sha(policy.read_bytes()),'observer_sha256':sha(executable.read_bytes()),
      'actual_shared_elf_sha256':sha((OUT/'minimal.so').read_bytes()),'expected_response_bytes':24+3+17+32}
    (OUT/'actual-observation.json').write_text(json.dumps(observation,sort_keys=True,indent=2)+'\n')
    print(json.dumps(observation,sort_keys=True),flush=True)
    assert actual.returncode==0 and actual.stderr==b''
    assert actual.stdout[:8]==b'HIAOBR02' and int.from_bytes(actual.stdout[8:16],'little')==42
    assert actual.stdout[24:]==b'abc'+b'\xa5'*17+b'Z'*32
    print('actual GNU-ld ELF dlopen/f0/dlclose PASS',flush=True)

if __name__=='__main__':
    try:main()
    except BaseException:
        if OUT.is_dir():(OUT/'FAILURE.txt').write_text(traceback.format_exc())
        raise
