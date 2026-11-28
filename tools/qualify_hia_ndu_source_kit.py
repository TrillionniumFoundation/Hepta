"""Exercise exact native NDU source-kit template and compiled-image admission.

Inputs are complete outputs from the independently recorded ordinary native
construction. This component gate grants no whole-cold or installed-release PASS.
"""
from pathlib import Path
import argparse,ctypes,fcntl,hashlib,json,mmap,os,struct,sys,time

def pin(raw):
    return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--construction",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args();S,Q,D=args.source,args.construction,args.output
    D.mkdir(mode=0o700)
    sys.path.insert(0,str(S));sys.dont_write_bytecode=True
    from tools.build_hia_native_store_release import _kit_with_objects
    from tools.generate_hia_source_build import template as original_template
    from tools.generate_hia_ndu_rank_source_kit import current_template,composer_source,render,OUTPUT,POLICY_OUTPUT,ORIGINALS,POLICY_ORIGINAL
    names=(*ORIGINALS,POLICY_ORIGINAL,OUTPUT,POLICY_OUTPUT,
           "tools/generate_hia_ndu_rank_source_kit.py","tools/build_hia_native_store_release.py")
    captured={S/n:(S/n).read_bytes()for n in names}
    captured[Path(__file__)]=Path(__file__).read_bytes()
    original,holes=original_template();current,current_holes=current_template()
    assert len(original)==len(current)==905 and holes==current_holes
    policy_source,review=composer_source()
    assert captured[S/POLICY_OUTPUT]==policy_source and captured[S/OUTPUT]==render()
    ordinary=json.loads((Q/"terminal.json").read_bytes())
    assert ordinary["passed"]is True and ordinary["ordinary_constructions"]==2 and ordinary["all_eight_complete_products_equal"]is True
    captured[Q/"terminal.json"]=(Q/"terminal.json").read_bytes()
    def call_output(number,expected):
        path=Q/"calls"/str(number)/"native.stdout"
        raw=path.read_bytes()
        assert hashlib.sha256(raw).hexdigest()==expected,(path,pin(raw))
        captured[path]=raw
        return raw
    outer=call_output(7,"5b4a1679575cd200fa3614b0036b1fbc2f0ab900af069039875ee55782f9b8c7")
    packet=call_output(8,"3c72395bd9ef0b7046ada4d7cc252af40b8251514d853afbfc8cba58ba6c187a")
    old_executable=call_output(1,"68f3086de87e964ba93f0d070976f672e7066a4b736cf6575f2c7fa708496ef7")
    _,outer_images=_kit_with_objects(outer)
    program,images=_kit_with_objects(packet)
    order=("source_build_policy.hepta","selfhost.hepta","source_build_packer.hepta")
    slots=("policy_hole","compiler_hole","packer_hole")
    # Use the original declared role order; names are part of the pinned author.
    from tools.generate_hia_source_build import ROLE_NAMES
    assert tuple(ROLE_NAMES)==order
    slot_order=slots
    assert set(holes)=={"policy_initial_hole",*slots}
    starts=[holes[n]+4+struct.unpack_from("<i",old_executable,holes[n])[0]for n in slot_order]
    assert starts==sorted(starts)and starts[0]==len(original)
    original_policy=old_executable[starts[0]:starts[1]]
    def compose(prefix):
        raw=bytearray(prefix)
        at=holes["policy_initial_hole"]
        struct.pack_into("<i",raw,at,len(raw)-at-4)
        for name,hole in zip(order,slot_order,strict=True):
            at=holes[hole];struct.pack_into("<i",raw,at,len(raw)-at-4);raw+=images[name]
        struct.pack_into("<2Q",raw,96,len(raw),len(raw))
        return bytes(raw)
    assert compose(current)==program
    prior_program=compose(original)
    maps=[]
    ENTRY=ctypes.CFUNCTYPE(ctypes.c_uint32,*([ctypes.c_void_p,ctypes.c_uint64]*3))
    def mapped(raw):
        fd=os.memfd_create("exact-source-kit-control",os.MFD_ALLOW_SEALING)
        try:
            at=0
            while at<len(raw):at+=os.write(fd,raw[at:])
            os.fchmod(fd,0o500);fcntl.fcntl(fd,fcntl.F_ADD_SEALS,15)
            lib=ctypes.CDLL(None,use_errno=True)
            lib.mmap.argtypes=(ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_int,ctypes.c_int,ctypes.c_long)
            lib.mmap.restype=ctypes.c_void_p
            address=lib.mmap(None,len(raw),mmap.PROT_READ|mmap.PROT_EXEC,mmap.MAP_PRIVATE,fd,0)
            assert address not in(None,ctypes.c_void_p(-1).value)
            maps.append((lib,address,len(raw)))
            return ENTRY(address)
        finally:os.close(fd)
    current_entry=mapped(outer_images[order[0]]);old_entry=mapped(original_policy)
    workspace=ctypes.create_string_buffer(4259840)
    rows=[]
    def check(label,raw,entry=current_entry,expected=18,declared=None):
        ctypes.memset(workspace,0,len(workspace))
        def put(at,v):struct.pack_into("<Q",workspace,at,v)
        for at,v in ((0,5),(16,5),(32,6),(40,0),(72,len(raw)if declared is None else declared),
                     (224,int.from_bytes(b"HIAKIT01","little"))):put(at,v)
        for index,name in enumerate(order):
            part=images[name];put(272+index*32,len(part))
            ctypes.memmove(ctypes.addressof(workspace)+1114112+index*(1<<20),part,len(part))
        output=ctypes.create_string_buffer(raw,len(raw))
        rc=entry(None,0,output,len(raw),workspace,len(workspace))
        length=struct.unpack_from("<Q",workspace,88)[0]
        assert rc==expected,(label,rc,expected)
        if expected==0:assert length==len(raw)and output.raw==raw
        else:assert length==0,(label,"rejected image was published")
        rows.append({"case":label,"status":rc,"published_bytes":length,"input":pin(raw),"passed":True})
    started=time.monotonic()
    try:
        check("current-complete-template-and-images",program,expected=0)
        check("original-complete-template-and-images",prior_program,entry=old_entry,expected=0)
        check("current-refuses-original-template",prior_program)
        check("original-refuses-current-template",program,entry=old_entry)
        for at in range(len(current)):
            raw=bytearray(program);raw[at]^=1
            check("header-byte-"+str(at),bytes(raw))
        at=len(current)
        for name in order:
            n=len(images[name])
            for offset in (at,at+n-1):
                raw=bytearray(program);raw[offset]^=1
                check("image-"+name+"-byte-"+str(offset),bytes(raw))
            at+=n
        check("truncated-complete-image",program[:-1])
        check("trailing-complete-image",program+b"\0")
        check("declared-short",program,declared=len(program)-1)
        check("declared-long",program,declared=len(program)+1)
        assert all(p.read_bytes()==raw for p,raw in captured.items())
        report={"schema":"hepta.hia.ndu-source-kit-native-admission.v1",
                "passed":True,"count":len(rows),"header_bytes":len(current),
                "source_unchanged":True,"current_policy":pin(outer_images[order[0]]),
                "original_policy":pin(original_policy),"source_pins":{str(p):pin(v)for p,v in captured.items()},
                "review":review,"elapsed_s":time.monotonic()-started,"cases":rows,
                "matching_cold":False,"whole_installed_release":False}
        (D/"report.json").write_text(json.dumps(report,indent=2)+"\n")
        print(json.dumps({k:v for k,v in report.items()if k not in("cases","source_pins")}),flush=True)
    finally:
        for lib,address,size in maps:
            lib.munmap.argtypes=(ctypes.c_void_p,ctypes.c_size_t)
            assert lib.munmap(address,size)==0
    return 0

if __name__=="__main__":raise SystemExit(main())
