"""Install the authenticated HIA Worker as the existing MCP process executable."""
from hashlib import sha256
from pathlib import Path
import os
import struct
from tempfile import NamedTemporaryFile

from hepta.hia_agent_store import wire
from hepta.hia_native_helpers import _read
from tools.build_hia_json_preflight import ROOT, admit_cold_build, current_sources
from tools.build_hia_source_build import _check_pack_output
from tools.generate_hia_installed_worker_entry import SOURCE, PACKER, ADAPTER, MAGIC, CONFIG_MAGIC
from tools.generate_hia_native_filter import read_adapter_binding, verify_adapter
from tools.qualify_hia_selfhost import compile_stage, invoke

PREFIX = ('-B', '-E', '-s', '-m', 'hepta.hia_agent_worker')
LAUNCHER_LIMIT = 1 << 20
ENTRY_LIMIT = 1 << 20

def vector(words):
    words = tuple(map(os.fsencode, words))
    if any(not word or b'\0' in word or len(word) > 4095 for word in words):
        raise ValueError('invalid installed Worker argument')
    return b''.join(word+b'\0' for word in words)

def configuration(profile, release, capsule, capsule_pin, launcher, identities, roots, install_root=None):
    profile_raw = _read(profile, 1 << 20).raw
    if sha256(profile_raw).hexdigest() != identities['native_helpers_sha256']:
        raise ValueError('installed Worker profile differs from its admitted identity')
    if sha256(_read(capsule, 2 << 20).raw).hexdigest() != capsule_pin:
        raise ValueError('installed Worker capsule differs from its admitted identity')
    def installed_path(path):
        return path if install_root is None else path.relative_to(install_root)
    def bound_vector(before, after):
        prefix = vector(before)
        return struct.pack('<Q',len(prefix))+prefix+vector(after)
    suffix = ('--expected-native-helpers-sha256', identities['native_helpers_sha256'])
    tail = []
    for key in ('worker', 'backend', 'catalog'):
        tail.extend(('--expected-'+key+'-sha256', identities[key+'_sha256']))
    for root in roots:
        tail.extend(('--artifact-root', Path(root).resolve(strict=True)))
    tail.append('--native-helpers-manifest')
    sections = (vector([installed_path(profile)]), profile_raw, vector([installed_path(release)]),
                vector([installed_path(capsule), capsule_pin]), launcher, wire(identities)+b'\n',
                bound_vector(tail, (*suffix,'--request-json-stdin')), vector(PREFIX), vector(['--state-root']),
                bound_vector(('--installation-manifest','--native-helpers-manifest'),suffix),
                vector(['--installation-manifest']))
    offsets = []
    position = 16 + 8*len(sections)
    chunks = []
    for section in sections:
        offsets.append(position)
        chunks += [struct.pack('<Q',len(section)), section]
        position += 8+len(section)
    return struct.pack('<13Q',CONFIG_MAGIC,position,*offsets)+b''.join(chunks)

def build(target, scratch, compiler, cold_report, *, profile, release, capsule, capsule_pin,
          expected_launcher, identities, artifact_roots):
    """Freeze the provider-visible argv, selected identities and exact cold launcher."""
    compiler_bytes=compiler.read_bytes()
    report_bytes=cold_report.read_bytes()
    admitted=admit_cold_build(compiler_bytes,report_bytes)
    sources={p:(ROOT/p).read_bytes() for p in
             (SOURCE,PACKER,ADAPTER,'tools/generate_hia_installed_worker_entry.py',
              'tools/build_hia_installed_worker_entry.py')}
    if any(admitted.get(p)!=sha256(raw).hexdigest() for p,raw in sources.items()):
        raise ValueError('installed Worker source differs from cold replay')
    binding=read_adapter_binding(sources[PACKER],sources[ADAPTER],calls=3)
    launcher=_read(release/'hia-agent-evaluate-full-launcher',LAUNCHER_LIMIT).raw
    if launcher!=expected_launcher.read_bytes():
        raise ValueError('public Worker launcher differs from the cold build')
    config=configuration(profile,release,capsule,capsule_pin,launcher,identities,artifact_roots,target.parent)
    scratch.mkdir(mode=0o700)
    policy,policy_receipt=compile_stage(scratch,'entry',compiler,sources[SOURCE])
    packer,packer_receipt=compile_stage(scratch,'packer',compiler,sources[PACKER])
    app=policy.read_bytes()
    packer_bytes=packer.read_bytes()
    if sha256(app).hexdigest()!=policy_receipt['produced_sha256'] or sha256(packer_bytes).hexdigest()!=packer_receipt['produced_sha256']:
        raise ValueError('installed Worker native compiler output differs')
    code=app+config+struct.pack('<Q',len(config))
    packet=struct.pack('<2Q',MAGIC,len(code))+code
    receipt,output=invoke(scratch,'pack-executable',packer,packet,capacity=ENTRY_LIMIT)
    executable=_check_pack_output(receipt,output,artifact=packer_bytes,source=packet,capacity=ENTRY_LIMIT)
    verify_adapter(executable,code,binding,entries=(0,0,0))
    if current_sources()!=admitted or compiler.read_bytes()!=compiler_bytes or cold_report.read_bytes()!=report_bytes:
        raise ValueError('installed Worker cold authority changed during build')
    if configuration(profile,release,capsule,capsule_pin,_read(release/'hia-agent-evaluate-full-launcher',LAUNCHER_LIMIT).raw,identities,artifact_roots,target.parent)!=config:
        raise ValueError('installed Worker authority changed before publication')
    with NamedTemporaryFile(dir=target.parent, prefix='.hia-worker-entry-') as out:
        out.write(executable)
        out.flush()
        os.fchmod(out.fileno(),0o500)
        os.link(out.name,target)
    return target
