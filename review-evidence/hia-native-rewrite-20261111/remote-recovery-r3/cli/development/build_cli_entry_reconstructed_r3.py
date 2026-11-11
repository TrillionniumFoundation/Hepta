"""Development-only exact-source build of the native CLI entry slice.

This script orchestrates authoring/validation evidence. It is not installed by
the runtime and performs no CLI language decision. The emitted ELF uses only
the seven native HIA images and fixed Linux mechanics.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes,json,os,struct,subprocess,sys,time,traceback
ROOT=Path(__file__).resolve().parents[1]
BASE=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/source")
RECOVERY=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/cli-recovery")
OLD14=RECOVERY/'r14-exact-original'
ROOT_WORK=Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111/root-recovery/workspace")
sys.path.insert(0,str(BASE))
from tools.qualify_hia_selfhost import compile_stage
from hepta.hia_agent_assembly import assemble_program
from hepta.hia_json_preflight_native import NativeHiaJsonImage

def digest(raw):return sha256(raw).hexdigest()
def dump(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def guarded(raw,capacity=None):
    size=len(raw) if capacity is None else capacity
    assert len(raw)<=size
    guard=b'!CLI-CANARY-EXACT-32-BYTES-GUARD'
    assert len(guard)==32
    backing=ctypes.create_string_buffer(32+max(size,1)+32)
    ctypes.memmove(ctypes.addressof(backing),guard,32)
    ctypes.memmove(ctypes.addressof(backing)+32,raw,len(raw))
    ctypes.memmove(ctypes.addressof(backing)+32+max(size,1),guard,32)
    return backing,ctypes.addressof(backing)+32,size,guard
def check_guard(record):
    backing,ptr,size,guard=record
    assert ctypes.string_at(ptr-32,32)==guard
    assert ctypes.string_at(ptr+max(size,1),32)==guard

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output',required=True,type=Path)
    parser.add_argument('--compiler',required=True,type=Path)
    args=parser.parse_args()
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    result={'scope':'SOURCE_BOUND_DEVELOPMENT_NOT_COLD_NOT_INSTALLED',
            'status':'INCOMPLETE','generations':[],'compiles':[],'mapping_entries':0}
    started=time.monotonic_ns();frozen={};pins=[]
    def freeze(path,label):
        path=Path(path).resolve();raw=path.read_bytes()
        if path in frozen:assert frozen[path]==raw
        frozen[path]=raw
        destination=out/'frozen'/label;destination.parent.mkdir(parents=True,exist_ok=True)
        if destination.exists():assert destination.read_bytes()==raw
        else:destination.write_bytes(raw)
        assert destination.read_bytes()==raw
        row={'original':str(path),'copy':str(destination),'bytes':len(raw),'sha256':digest(raw)}
        pins.append(row)
        return raw,row
    try:
        compiler_raw,compiler_pin=freeze(args.compiler,'compiler/B3.image.bin')
        for name in ('cli_authoring.py','cli_entry_owner.py','generate_hia_cli_entry.py',
                     'cli_native_executor.S','generate_hia_cli_native_packer.py'):
            freeze(ROOT/'tools'/name,'authoring/'+name)
        freeze(ROOT.parent/'native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_common.py',
               'authoring/hia_composite_lowering_driver_common.py')
        freeze(ROOT.parent/'Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py',
               'authoring/hia_agent_edit_source_views.py')
        freeze(Path(__file__),'build-source.py')
        # Complete foreign authoring output is retained even if generation fails.
        for tool in ('generate_hia_cli_entry.py','generate_hia_cli_native_packer.py'):
            process=subprocess.run([sys.executable,str(ROOT/'tools'/tool)],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            (out/(tool+'.stdout')).write_bytes(process.stdout)
            (out/(tool+'.stderr')).write_bytes(process.stderr)
            result['generations'].append({'tool':tool,'exit_code':process.returncode})
            if process.returncode != 0:
                print("HIA_GENERATOR_FAILURE " + json.dumps(
                    {"tool":tool,"exit_code":process.returncode,
                     "stdout_bytes":len(process.stdout),"stderr_bytes":len(process.stderr),
                     "stdout_sha256":digest(process.stdout),"stderr_sha256":digest(process.stderr)},
                    sort_keys=True), flush=True)
                sys.stdout.buffer.write(process.stdout);sys.stdout.buffer.flush()
                sys.stderr.buffer.write(process.stderr);sys.stderr.buffer.flush()
            assert process.returncode==0,tool
        paths={
          1:ROOT/'development/capture-reconstructed-compile-r1/cli-capture.manifest.json',
          2:OLD14/'development/argv-compile-r1/cli-argv-owner.manifest.json',
          3:OLD14/'development/formatter-compile-r3/cli-formatter.manifest.json',
          4:ROOT_WORK/'native-program-service-next/development/metadata-compile-r3/program-metadata.manifest.json',
          5:ROOT/'development/pretty-reconstructed-compile-r1/cli-pretty.manifest.json',
          6:ROOT/'development/file-reconstructed-compile-r2/cli-file.manifest.json'}
        def mapped(rawpath,role):
            p=Path(rawpath)
            if role in (2,3):
                p=OLD14/str(p).split('/native-hia-cli-next/',1)[1]
            elif role==4:
                p=ROOT_WORK/'native-program-service-next'/str(p).split('/native-program-service-next/',1)[1]
            return p
        images={};components={}
        for role,path in paths.items():
            manifest_raw,manifest_pin=freeze(path,f'role-{role}/manifest.json')
            manifest=json.loads(manifest_raw)
            source_raw,source_pin=freeze(mapped(manifest.get('source_path',manifest.get('source')),role),f'role-{role}/source.hiaasm')
            image_raw,image_pin=freeze(mapped(manifest.get('image_path',manifest.get('image')),role),f'role-{role}/image.bin')
            assert digest(source_raw)==manifest['source_sha256']
            assert digest(image_raw)==manifest['image_sha256']
            images[role]=image_raw
            components[role]={'manifest':manifest_pin,'source':source_pin,'image':image_pin}
        for label,role,filename in (('cli-entry',7,'cli_entry_controller.hiaasm'),
                                     ('cli-packer',0,'cli_native_packer.hiaasm')):
            source_raw,source_pin=freeze(ROOT/'examples/hia_bootstrap'/filename,label+'/source.hiaasm')
            assemble_program(source_raw)
            image,receipt=compile_stage(out,label,Path(compiler_pin['copy']),source_raw)
            image_raw=image.read_bytes()
            assert receipt['artifact_sha256']==digest(compiler_raw)
            assert receipt['input_sha256']==digest(source_raw)
            assert receipt['produced_sha256']==digest(image_raw)
            assert image.read_bytes()==image_raw
            frozen_image,image_pin=freeze(image,label+'/image.bin')
            assert frozen_image==image_raw
            manifest={'schema':'hepta.hia.cli-entry-development.v1',
                      'scope':'DEVELOPMENT_NOT_COLD_NOT_INSTALLED',
                      'source_path':source_pin['copy'],'source_sha256':digest(source_raw),
                      'image_path':str(image),'image_sha256':digest(image_raw),
                      'compiler_sha256':digest(compiler_raw)}
            dump(out/(label+'.manifest.json'),manifest)
            result['compiles'].append({'label':label,'manifest':manifest,'receipt':receipt})
            images[role]=image_raw
            components[role]={'source':source_pin,'image_path':str(image),'manifest':manifest}
        assembly_pin=next(row for row in pins if row['original']==str((ROOT/'tools/cli_native_executor.S').resolve()))
        actual=json.loads((ROOT/'development/executor-template-reconstructed-r1/source.json').read_bytes())
        assert actual['sha256']==assembly_pin['sha256'] and actual['bytes']==assembly_pin['bytes']
        for p in (ROOT/'development/executor-template-reconstructed-r1').iterdir():
            freeze(p,'executor/raw/'+p.name)
        prefix=(ROOT/'development/entry-executor-prefix-r1.bin').read_bytes()
        freeze(ROOT/'development/entry-executor-prefix-r1.bin','executor/prefix.bin')
        freeze(ROOT/'development/entry-executor-layout-r1.json','executor/layout.json')
        sizes=[len(images[i]) for i in range(1,8)]
        header=struct.pack('<8Q',int.from_bytes(b'HIACLP01','little'),1,7,120+sum(sizes),64,0,0,0)
        packet=header+struct.pack('<7Q',*sizes)+b''.join(images[i] for i in range(1,8))
        expected=len(prefix)
        for size in sizes:expected=((expected+15)&~15)+size
        (out/'packer-input.bin').write_bytes(packet)
        packer=NativeHiaJsonImage(images[0],expected_sha256=digest(images[0]))
        source_buffer=guarded(packet);output_buffer=guarded(b'',expected);workspace=guarded(b'',64)
        before_workspace=ctypes.string_at(workspace[1],64)
        ret=int(packer._entry(source_buffer[1],source_buffer[2],output_buffer[1],output_buffer[2],
                              workspace[1],workspace[2]))
        result['mapping_entries']+=1
        for buffer in (source_buffer,output_buffer,workspace):check_guard(buffer)
        assert ctypes.string_at(source_buffer[1],len(packet))==packet
        assert ctypes.string_at(workspace[1],64)==before_workspace
        assert ret==expected,(ret,expected)
        executable=ctypes.string_at(output_buffer[1],ret)
        assert executable[:4]==b'\x7fELF'
        layout=json.loads((ROOT/'development/entry-executor-layout-r1.json').read_bytes())
        reference=bytearray(prefix)
        for role in range(1,8):
            reference+=bytes((-len(reference))&15)
            struct.pack_into('<Q',reference,layout['image_table']+role*8,0x400000+len(reference))
            reference+=images[role]
        struct.pack_into('<Q',reference,96,len(reference));struct.pack_into('<Q',reference,104,len(reference))
        assert bytes(reference)==executable
        (out/'independent-mechanical-expected.elf').write_bytes(reference)
        image_path=out/'hia-cli-development'
        image_path.write_bytes(executable);image_path.chmod(0o700)
        assert image_path.read_bytes()==executable
        bundle={'schema':'hepta.hia.cli-entry-bundle-development.v1',
                'scope':'DEVELOPMENT_COMPONENT_SLICE_NOT_INSTALLED_NOT_COLD',
                'components':components,'executable_path':str(image_path),
                'executable_sha256':digest(executable),'executable_bytes':len(executable),
                'compiler':compiler_pin,'limitations':['successful input file awaits business service',
                    'UTF-8 Linux capture profile','no installed entry activation']}
        dump(out/'bundle.json',bundle)
        result.update(status='PASS',bundle=bundle)
    except BaseException as error:
        result.update(status='FAIL',error_class=type(error).__name__,error=str(error))
        traceback.print_exc()
        raise
    finally:
        original_error=sys.exc_info()[1]
        try:
            result['source_pins_unchanged']=all(path.read_bytes()==raw for path,raw in frozen.items())
            result['elapsed_ns']=time.monotonic_ns()-started
            if not result['source_pins_unchanged']:
                result['status']='FAIL'
                result['custody_error']='source pins changed during the build'
            dump(out/'source-pins.json',pins);dump(out/'summary.json',result)
            print(json.dumps(result,sort_keys=True),flush=True)
            assert result['source_pins_unchanged']
        except BaseException as custody_error:
            if original_error is None:
                raise
            original_error.add_note('Final evidence/custody capture failed: '+repr(custody_error))
if __name__=='__main__':main()
