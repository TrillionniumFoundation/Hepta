"""Development mechanical construction of the HIA image-owner component.

The resulting shared component contains only the fixed assembly adapter plus
the actual HIA policy/SHA/ELF/mapping flats. This is not the final production
packer; it retains exact byte provenance for that native packaging step.
"""
from pathlib import Path
import argparse,hashlib,json,re,subprocess
ROOT=Path(__file__).resolve().parents[1]
ROLES={'policy':'multiversion_image','sha':'sha256_stream','elf':'safe_core_elf_inventory','mapping':'native_mapping'}
def build(directory):
    directory=Path(directory)
    assembly=(ROOT/'tools/hia_multiversion_image_bridge.S').read_text()
    components=[]
    for label,role in ROLES.items():
        p=directory/(role+'.flat');raw=p.read_bytes();assert raw
        pattern=r'\.byte 0xe8\s*'+label+r'_hole:\s*\.long 0'
        assembly,n=re.subn(pattern,'call .L'+label+'_flat',assembly)
        assert n==1,(label,n)
        assembly+='\n.text\n.balign 16\n.L'+label+'_flat:\n.incbin '+json.dumps(str(p))+'\n'
        components.append({'role':role,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
    source=directory/'image-component.S';source.write_text(assembly)
    result=subprocess.run(['/usr/bin/cc','-shared','-nostdlib','-Wl,-z,now,-z,noexecstack','-Wl,--hash-style=sysv',str(source),'-o',str(directory/'image-component.so'),'-lc'],capture_output=True)
    (directory/'mechanical-build.stderr').write_bytes(result.stderr)
    if result.returncode:raise RuntimeError(result.stderr.decode())
    raw=(directory/'image-component.so').read_bytes()
    report={'schema':'hepta.hia.multiversion-image-development-construction.v1','production_packer_complete':False,'components':components,'mechanical_source_sha256':hashlib.sha256((ROOT/'tools/hia_multiversion_image_bridge.S').read_bytes()).hexdigest(),'image_bytes':len(raw),'image_sha256':hashlib.sha256(raw).hexdigest()}
    (directory/'mechanical-build.json').write_text(json.dumps(report,indent=2)+'\n');return report
def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);a=p.parse_args();print(json.dumps(build(a.directory)),flush=True)
if __name__=='__main__':main()
