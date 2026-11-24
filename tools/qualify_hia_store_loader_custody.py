"""Exercise the complete native Store loader at its real custody commands.

Kernel observations are supplied by this qualifier. The actual filtered f0
policy consumes its real manifest and issues every intervening command.
Mutable Store namespace policy and whole installation are separate gates.
"""
from pathlib import Path
from hashlib import sha256
import argparse,ctypes,json,stat,struct,sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from tools.build_hia_agent_store import apply_filter

MAGIC=3553139188603898184

def qualify(build,output):
    report=json.loads((build/'build.json').read_bytes())
    if report['status']!='passed':
        raise ValueError('native component build did not pass')
    source='examples/hia_bootstrap/agent_store/loader.hepta'
    if report['source_sha256'][source]!=sha256((ROOT/source).read_bytes()).hexdigest():
        raise ValueError('component does not bind current loader source')
    plan=json.loads((ROOT/'examples/hia_bootstrap/agent_store/build-plan.json').read_bytes())
    filter_raw=(build/'word_filter.hepta.flat').read_bytes()
    raw=(build/'loader.hepta.flat').read_bytes()
    filtered,_=apply_filter(NativeHiaJsonImage(filter_raw,sha256(filter_raw).hexdigest()),raw,plan['units']['loader'])
    if filtered!=(build/'loader.word-image.bin').read_bytes():
        raise ValueError('loader word-filter reproduction differs')
    image=NativeHiaJsonImage(filtered,sha256(filtered).hexdigest())
    manifest=(build/'manifest.bin').read_bytes()
    if sha256(manifest).hexdigest()!=plan['expected_manifest_sha256']:
        raise ValueError('module manifest changed')
    output.mkdir(mode=0o700)
    cases=[]
    def session(uid):
        work=ctypes.create_string_buffer(65536)
        out=ctypes.create_string_buffer(131072)
        def call(frame):
            inp=ctypes.create_string_buffer(frame)
            rc=image._entry(inp,len(frame),out,len(out),work,len(work))
            assert inp.raw==frame+b'\0'
            assert rc>=64 and rc<=len(out),(rc,len(frame))
            return struct.unpack_from('<8Q',out.raw)
        cmd=call(manifest+struct.pack('<2Q',uid,0))
        assert cmd[2:4]==(41,20),cmd
        return call,cmd
    def observation(cmd,owner,mode,nlink,size,flags,seals=None):
        b=bytearray(184 if seals is None else 192)
        struct.pack_into('<4Q',b,0,MAGIC,cmd[1],cmd[2],0)
        struct.pack_into('<Q',b,32,7)
        struct.pack_into('<Q',b,40,19)
        struct.pack_into('<Q',b,48,nlink)
        struct.pack_into('<Q',b,56,(owner<<32)|mode)
        struct.pack_into('<Q',b,80,size)
        struct.pack_into('<Q',b,176,flags)
        if seals is not None:struct.pack_into('<Q',b,184,seals)
        return bytes(b)
    def simple(cmd,result):
        return struct.pack('<4Q',MAGIC,cmd[1],cmd[2],result)
    def checked(name,cmd,wanted,nextcode,values):
        admitted=cmd[2]==nextcode
        assert admitted==wanted,(name,wanted,cmd)
        if not admitted:assert cmd[2:4]==(9,73),(name,cmd)
        cases.append({'case':name,'admitted':admitted,'expected':wanted,'command':list(cmd[2:4]),'observations':values})
    directories=[
      ('own-0700',1000,1000,stat.S_IFDIR|0o700,2,0x38000,True),
      ('own-0500',1000,1000,stat.S_IFDIR|0o500,2,0x38000,True),
      ('root-0555',63146,0,stat.S_IFDIR|0o555,2,0x38000,True),
      ('root-caller-0700',0,0,stat.S_IFDIR|0o700,2,0x38000,True),
      ('foreign-0555',63146,1000,stat.S_IFDIR|0o555,2,0x38000,False),
      ('root-owner-write',63146,0,stat.S_IFDIR|0o755,2,0x38000,False),
      ('root-group-write',63146,0,stat.S_IFDIR|0o575,2,0x38000,False),
      ('root-other-write',63146,0,stat.S_IFDIR|0o557,2,0x38000,False),
      ('root-setuid',63146,0,stat.S_IFDIR|0o4555,2,0x38000,False),
      ('root-setgid',63146,0,stat.S_IFDIR|0o2555,2,0x38000,False),
      ('root-symlink',63146,0,stat.S_IFLNK|0o555,2,0x38000,False),
      ('root-file',63146,0,stat.S_IFREG|0o555,2,0x38000,False),
      ('root-low-nlink',63146,0,stat.S_IFDIR|0o555,1,0x38000,False),
      ('root-opath',63146,0,stat.S_IFDIR|0o555,2,0x238000,False),
      ('root-no-directory-flag',63146,0,stat.S_IFDIR|0o555,2,0x28000,False),
      ('root-rdwr',63146,0,stat.S_IFDIR|0o555,2,0x38002,False),
      ('own-group-readable',1000,1000,stat.S_IFDIR|0o750,2,0x38000,False),
    ]
    for name,caller,owner,mode,nlink,flags,wanted in directories:
        call,cmd=session(caller)
        after=call(observation(cmd,owner,mode,nlink,4096,flags))
        checked('directory-'+name,after,wanted,40,{'caller':caller,'owner':owner,'mode':oct(mode),'nlink':nlink,'flags':flags})
    def module_session(caller):
        call,cmd=session(caller)
        cmd=call(observation(cmd,0,stat.S_IFDIR|0o555,2,4096,0x38000))
        assert cmd[2:4]==(40,20),cmd
        cmd=call(simple(cmd,16));assert cmd[2:4]==(41,16),cmd
        return call,cmd
    size=struct.unpack_from('<Q',manifest,96)[0]
    files=[
      ('own-0400',1000,1000,stat.S_IFREG|0o400,1,size,0x28000,True),
      ('root-0444',63146,0,stat.S_IFREG|0o444,1,size,0x28000,True),
      ('foreign-0444',63146,1000,stat.S_IFREG|0o444,1,size,0x28000,False),
      ('root-owner-write',63146,0,stat.S_IFREG|0o644,1,size,0x28000,False),
      ('root-group-write',63146,0,stat.S_IFREG|0o464,1,size,0x28000,False),
      ('root-other-write',63146,0,stat.S_IFREG|0o446,1,size,0x28000,False),
      ('root-executable',63146,0,stat.S_IFREG|0o555,1,size,0x28000,False),
      ('root-setuid',63146,0,stat.S_IFREG|0o4444,1,size,0x28000,False),
      ('root-symlink',63146,0,stat.S_IFLNK|0o444,1,size,0x28000,False),
      ('root-directory',63146,0,stat.S_IFDIR|0o444,1,size,0x28000,False),
      ('root-hardlink',63146,0,stat.S_IFREG|0o444,2,size,0x28000,False),
      ('root-wrong-size',63146,0,stat.S_IFREG|0o444,1,size+1,0x28000,False),
      ('root-opath',63146,0,stat.S_IFREG|0o444,1,size,0x228000,False),
      ('root-wronly',63146,0,stat.S_IFREG|0o444,1,size,0x28001,False),
      ('root-rdwr',63146,0,stat.S_IFREG|0o444,1,size,0x28002,False),
      ('own-group-readable',1000,1000,stat.S_IFREG|0o440,1,size,0x28000,False),
    ]
    for name,caller,owner,mode,nlink,nbytes,flags,wanted in files:
        call,cmd=module_session(caller)
        after=call(observation(cmd,owner,mode,nlink,nbytes,flags))
        checked('module-'+name,after,wanted,43,{'caller':caller,'owner':owner,'mode':oct(mode),'nlink':nlink,'bytes':nbytes,'flags':flags})
    for name,owner,mode,nlink,flags,seals,wanted in [
      ('own-private',63146,stat.S_IFREG|0o400,0,2,0,True),
      ('root-0444-refused',0,stat.S_IFREG|0o444,0,2,0,False),
      ('foreign-0400-refused',1000,stat.S_IFREG|0o400,0,2,0,False),
      ('own-hardlink-refused',63146,stat.S_IFREG|0o400,1,2,0,False),
      ('own-wrong-flags',63146,stat.S_IFREG|0o400,0,0,0,False),
      ('own-wrong-seals',63146,stat.S_IFREG|0o400,0,2,1,False),
    ]:
        call,cmd=module_session(63146)
        cmd=call(observation(cmd,0,stat.S_IFREG|0o444,1,size,0x28000));assert cmd[2]==43
        cmd=call(simple(cmd,17));assert cmd[2:4]==(44,17)
        after=call(observation(cmd,owner,mode,nlink,0,flags,seals))
        checked('memfd-'+name,after,wanted,42,{'owner':owner,'mode':oct(mode),'nlink':nlink,'flags':flags,'seals':seals})
    result={'schema':'hia.store-loader-custody-qualification.v1','status':'passed','scope':'complete native loader f0 real command boundaries','whole_installation_qualified':False,'state_namespace_qualified':False,'source_sha256':sha256((ROOT/source).read_bytes()).hexdigest(),'raw_sha256':sha256(raw).hexdigest(),'image_sha256':sha256(filtered).hexdigest(),'case_count':len(cases),'cases':cases}
    (output/'qualification.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':'passed','cases':len(cases),'image_sha256':result['image_sha256']}))
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build',required=True,type=Path)
    p.add_argument('--output',required=True,type=Path)
    a=p.parse_args();qualify(a.build.resolve(),a.output.resolve())

if __name__=='__main__':main()
