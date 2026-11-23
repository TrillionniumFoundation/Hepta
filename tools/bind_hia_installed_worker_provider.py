"""Bind an existing Rust MCP runtime configuration to an installed HIA Worker."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
from tempfile import NamedTemporaryFile


def read_runtime(path):
    def unique(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError('duplicate MCP runtime configuration key')
            value[key] = item
        return value
    config = json.loads(path.read_bytes(), object_pairs_hook=unique)
    worker = config['hia_worker']
    hosts = config['hosts']
    host = hosts[worker['host']]
    if not isinstance(worker, dict) or not isinstance(host, dict):
        raise ValueError('runtime requires a configured HIA Worker and host')
    return config


def artifact_roots(config):
    roots = config['hia_worker'].get('artifact_roots', [])
    if not isinstance(roots, list) or len(roots)>32 or any(type(p) is not str or not Path(p).is_absolute() for p in roots):
        raise ValueError('invalid artifact roots in the existing HIA Worker configuration')
    return tuple(map(Path,roots))


def bind(installation, source, destination):
    installation = Path(installation).resolve(strict=True)
    profile = installation/'worker.json'
    executable = installation/'hia-agent-worker'
    config = read_runtime(source)
    worker = config['hia_worker']
    # Query the installed native executable, independently of the process
    # running this installer, and bind its original public installation pins.
    digest = sha256(profile.read_bytes()).hexdigest()
    result = subprocess.run([executable,'-B','-E','-s','-m','hepta.hia_agent_worker',
                             '--installation-manifest','--native-helpers-manifest',profile,
                             '--expected-native-helpers-sha256',digest],env={'PATH':''},
                            capture_output=True,check=True,timeout=15)
    pins = json.loads(result.stdout)
    fields = ('worker_sha256','backend_sha256','catalog_sha256','native_helpers_sha256')
    if (result.stderr or set(pins)!=set(fields) or pins['native_helpers_sha256']!=digest
        or any(not isinstance(pins[k],str) or len(pins[k])!=64 or any(c not in '0123456789abcdef' for c in pins[k]) for k in fields)):
        raise ValueError('native Worker installation identity differs from its profile')
    selected = {k:v for k,v in worker.items()}
    selected.update(pins, python_executable=str(executable), native_helpers_manifest=str(profile))
    # The companion entry checks all these exact options at execution. Detect
    # mismatched independently rebound artifact roots without touching the Store.
    descriptor = json.loads((installation/'evaluate-full-worker.json').read_bytes())
    if descriptor.get('capsule')!='evaluate-full-worker-capsule.bin':
        raise ValueError('invalid installed native Worker capsule name')
    capsule = (installation/'evaluate-full-worker-capsule.bin').read_bytes()
    if sha256(capsule).hexdigest()!=descriptor['capsule_sha256']:
        raise ValueError('native Worker capsule differs from its installed descriptor')
    from tools.generate_hia_readonly_worker_capsule import ARTIFACT_CONFIG
    import struct
    magic, version, count, dossier, base, docs, artifact = struct.unpack_from('<8s6Q',capsule)
    start=56+48*count+dossier+base+docs
    if version!=1 or start+artifact!=len(capsule) or capsule[start:start+8]!=ARTIFACT_CONFIG:
        raise ValueError('invalid native Worker artifact scope')
    size, configured = struct.unpack_from('<2Q',capsule,start+72)
    pos=start+88+size
    expected=[]
    for _ in range(configured):
        if pos+8>len(capsule):
            raise ValueError('truncated native Worker artifact roots')
        n=struct.unpack_from('<Q',capsule,pos)[0]
        if n>4095 or pos+8+n>len(capsule):
            raise ValueError('truncated native Worker artifact root')
        expected.append(os.fsdecode(capsule[pos+8:pos+8+n]))
        pos+=8+n
    if pos!=len(capsule) or list(map(str,artifact_roots(config)))!=expected:
        raise ValueError('configured artifact roots differ from the installed native Worker')
    config['hia_worker']=selected
    data=(json.dumps(config,ensure_ascii=False,sort_keys=True,indent=2)+'\n').encode()
    with NamedTemporaryFile(dir=destination.parent,prefix='.hia-runtime-config-') as tmp:
        tmp.write(data)
        tmp.flush()
        os.fchmod(tmp.fileno(),0o600)
        os.link(tmp.name,destination)
    return destination


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installation',required=True,type=Path)
    parser.add_argument('--runtime-config',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    print(bind(args.installation,args.runtime_config,args.output))


if __name__=='__main__':
    main()
