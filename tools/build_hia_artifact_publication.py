"""Build an explicitly selected, source-bound native filesystem publisher.

Build/install/code custody are hosted; runtime policy, exact byte verification,
receipt and SHA are HIA behind a fixed Linux syscall adapter. Not default Agent
persistence, a transaction journal or native-only release. The explicitly
selected Agent byte layer adds file/directory fsync, not SQLite replacement.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
import json,struct
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.build_hia_json_preflight import admit_cold_build, current_sources
from tools.hia_component_input_custody import capture_component_custody, verify_component_custody
from tools.build_hia_source_build import _check_pack_output
from tools.hia_selfhost_contract import PROFILE
from tools.qualify_hia_selfhost import compile_stage,invoke
from hepta.hia_artifact_delivery_protocol import control_descriptor, private_executable, ACK_BYTES, NONCE_BYTES
from tools.generate_hia_artifact_publication import MAGIC
from hepta.artifact_publication_native import NATIVE_PUBLICATION_OPERATIONS,NATIVE_PUBLICATION_SOURCES
OPERATIONS=list(NATIVE_PUBLICATION_OPERATIONS)
SOURCES=NATIVE_PUBLICATION_SOURCES
INPUTS=tuple(dict.fromkeys((*SOURCES, 'tools/build_hia_artifact_publication.py',
    'tools/hia_component_input_custody.py', 'hepta/artifact_publication_native.py')))


def build(output:Path,compiler:Path,cold_report:Path):
    paths=[compiler,cold_report,*(ROOT/name for name in INPUTS)]
    pins={path:path.read_bytes() for path in paths}
    try:
        sources=admit_cold_build(pins[compiler],pins[cold_report])
    except ValueError as exc:
        raise ValueError('completed matching-source cold qualification required for native publication') from exc
    captured={name:pins[ROOT/name] for name in INPUTS}
    custody=capture_component_custody(pins[compiler],pins[cold_report],sources,captured,root=ROOT)
    output.mkdir(mode=0o700);images={};receipts={}
    for label,name in zip(('policy','packer','sha256'),SOURCES[:3]):
        image,receipts[label]=compile_stage(output,label,compiler,pins[ROOT/name])
        images[label]=(image,image.read_bytes())
    policy,sha=images['policy'][1],images['sha256'][1]
    frame=struct.pack('<3Q',MAGIC,len(policy),len(sha))+policy+sha
    result,packed=invoke(output,'publication-pack',images['packer'][0],frame)
    executable=_check_pack_output(result,packed,artifact=images['packer'][1],source=frame)
    descriptor=control_descriptor(executable)
    private=private_executable(executable)
    inspection={'elf_type':'ET_EXEC','machine':'EM_X86_64','entry':descriptor.public_entry,
        'program_headers':['PT_LOAD_RX','PT_GNU_STACK_RW','PT_NOTE_HIADELIV'],
        'interpreter':None,'dynamic_loader':False,'libc':False,
        'bytes':len(executable),'sha256':sha256(executable).hexdigest(),
        'private_delivery_entry':descriptor.private_entry,'private_delivery_ack_bytes':ACK_BYTES,
        'private_delivery_prefix_bytes':NONCE_BYTES,
        'public_cli_unchanged':True,'argv_env_stdin_control_markers':False}
    if (any(path.read_bytes()!=raw for path,raw in pins.items()) or current_sources()!=sources
            or any(path.read_bytes()!=raw for path,raw in images.values())):
        raise ValueError('native publication build custody changed')
    verify_component_custody(custody,pins[compiler],pins[cold_report],sources,captured,root=ROOT)
    path=output/'hia-artifact'
    with path.open('xb') as stream:stream.write(executable)
    path.chmod(0o700)
    report={'schema':'hepta.hia.artifact-publication-build.v1','status':'NATIVE_ARTIFACT_PUBLICATION_BUILT',
        'profile':PROFILE,'source_manifest':sources,'source_sha256':{name:sha256(pins[ROOT/name]).hexdigest() for name in SOURCES},
        'component_inputs':{name:sha256(raw).hexdigest() for name,raw in captured.items()},
        'component_input_custody':custody,
        'compiler_sha256':sha256(pins[compiler]).hexdigest(),'cold_report_sha256':sha256(pins[cold_report]).hexdigest(),
        'executable_path':path.name,'executable_sha256':sha256(executable).hexdigest(),'executable':inspection,
        'public_executable_sha256':sha256(executable).hexdigest(),
        'private_executable_sha256':sha256(private).hexdigest(),
        'image_sha256':{label:sha256(raw).hexdigest() for label,(_,raw) in images.items()},
        'compile_receipts':receipts,'native_packer_receipt':result,'frame_sha256':sha256(frame).hexdigest(),
        'operations':OPERATIONS,'artifact_payload_fixed_size_limit':None,
        'Agent_artifact_file_limit_bytes':64<<20,'Agent_artifact_empty_supported':True,
        'Agent_artifact_put_file_and_directory_fsync':True,'SQLite_journal_replaced':False,
        'runtime_Python_or_libc_or_child_required':False,'host_build_and_code_custody':True,
        'point_in_time_consistency_only':True,'generic_publication_directory_fsync':False,'crash_recovery_provided':False,
        'full_Agent_persistence_replaced':False,'default_changed':False,'whole_native_delivery_qualified':False}
    with (output/'build.json').open('x') as stream:json.dump(report,stream,indent=2,sort_keys=True);stream.write('\n')
    return path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('compiler','cold-report','output'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();print(build(args.output.resolve(),args.compiler.resolve(),args.cold_report.resolve()))

if __name__=='__main__':main()
