"""Explicit host workspace custody -> HIA names/graph -> native Core compiler.

The workspace is inline and closed: no filesystem import discovery or package
manager, no high-level resolver, no reference-policy fallback. Selecting the
workspace JSON image also replaces host framing, fact encoding and Core JSON
materialization. The explicit complete pipeline runs full primitive Core
admission before the existing mandatory bounded native compiler. General Core
support and filesystem/build/install custody remain OPEN; no path silently
falls back or changes the default selection.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
from hepta.hia_core_module_graph_native import installed_module_graph, link_workspace, MAX_BYTES
from tools.compile_hia_core_json import compile_core


def _seal_code_descriptor(descriptor):
    """Require actual Linux kernel seals before executing captured code bytes."""
    import fcntl
    seals=(getattr(fcntl,'F_SEAL_WRITE',0x0008)|getattr(fcntl,'F_SEAL_GROW',0x0004)
           |getattr(fcntl,'F_SEAL_SHRINK',0x0002)|getattr(fcntl,'F_SEAL_SEAL',0x0001))
    fcntl.fcntl(descriptor,getattr(fcntl,'F_ADD_SEALS',1033),seals)
    observed=fcntl.fcntl(descriptor,getattr(fcntl,'F_GET_SEALS',1034))
    if type(observed) is not int or observed&seals!=seals:
        raise OSError('native workspace executable lacks complete kernel seals')


def compile_workspace(wire, graph_manifest, frontend_manifest, compiler, output, *, output_profile='elf', workspace_json_manifest=None, pipeline_manifest=None):
    if output_profile != 'elf':
        raise ValueError('workspace public scalar exports require explicit ELF output; no silent export stripping')
    if pipeline_manifest is not None:
        if any(value is not None for value in (graph_manifest,frontend_manifest,compiler,workspace_json_manifest)):
            raise ValueError('select only the complete native pipeline; no mixed image or fallback selection')
        return compile_pipeline(wire,pipeline_manifest,output)
    if workspace_json_manifest is not None:
        from hepta.hia_core_workspace_json_native import installed_workspace_json, link_workspace as native_link
        if graph_manifest is not None:
            raise ValueError('select exactly one workspace image; no fallback manifest')
        manifest=workspace_json_manifest
        native=installed_workspace_json(str(manifest))
        selected_link=native_link
    else:
        manifest=graph_manifest
        native=installed_module_graph(str(manifest))
        selected_link=link_workspace
    pin = manifest.read_bytes()
    verified, receipt = selected_link(wire, native=native)
    image = compile_core(verified.canonical_bytes, frontend_manifest, compiler, output, output_profile=output_profile)
    if manifest.read_bytes() != pin:
        raise ValueError('Core module graph manifest changed during build')
    receipt['workspace_json_manifest_sha256' if workspace_json_manifest is not None else 'graph_manifest_sha256']=sha256(pin).hexdigest()
    receipt.update(status='NATIVE_LINKED_CORE_COMPILED',
                   output_profile=output_profile, output_sha256=sha256(image.read_bytes()).hexdigest())
    (output/'workspace.receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True)+'\n')
    return image


def compile_pipeline(wire,manifest_path,output):
    """Host byte/file custody only; payload checking is mandatory native HIA."""
    import os,platform,struct,subprocess
    from tools.build_hia_core_workspace_pipeline import ROOT,SCHEMA,SOURCES,current_sources,PROFILE,BUNDLE_LIMIT
    from hepta.hia_core_module_graph_native import CoreModuleRejected
    from hepta.hia_json_preflight_native import _unique_manifest_pairs
    if platform.system()!='Linux' or platform.machine()!='x86_64':
        raise ValueError('native workspace pipeline requires Linux x86-64')
    if type(wire) is not bytes or len(wire)>MAX_BYTES:
        raise ValueError('native workspace pipeline requires <=8 MiB immutable JSON wire bytes')
    manifest_raw=manifest_path.read_bytes()
    if len(manifest_raw)>1<<20:raise ValueError('native workspace manifest exceeds local custody profile')
    metadata=json.loads(manifest_raw,object_pairs_hook=_unique_manifest_pairs);sources=current_sources()
    if (type(metadata) is not dict or metadata.get('schema')!=SCHEMA
            or metadata.get('status')!='NATIVE_WORKSPACE_PIPELINE_BUILT' or metadata.get('profile')!=PROFILE
            or metadata.get('mandatory_complete_primitive_Core_admission') is not True
            or metadata.get('source_manifest')!=sources
            or metadata.get('source_sha256')!={name:sources.get(name) for name in SOURCES}
            or metadata.get('executable_path')!='hia-workspace-compile'):
        raise ValueError('native workspace pipeline source identity mismatch')
    code=(manifest_path.parent/'hia-workspace-compile').read_bytes()
    if (not 64<=len(code)<=BUNDLE_LIMIT or sha256(code).hexdigest()!=metadata.get('executable_sha256')
            or code[:7]!=b'\x7fELF\x02\x01\x01' or struct.unpack_from('<HH',code,16)!=(2,62)):
        raise ValueError('native workspace pipeline executable identity mismatch')
    # Execute the exact immutable bytes just admitted, not a mutable path that
    # can be replaced between hashing and exec. This is trusted code custody,
    # not an untrusted executable sandbox or a native-only installation claim.
    descriptor=os.memfd_create('hia-workspace-pipeline',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
    try:
        remaining=memoryview(code)
        while remaining:remaining=remaining[os.write(descriptor,remaining):]
        _seal_code_descriptor(descriptor)
        result=subprocess.run(['/proc/self/fd/'+str(descriptor)],input=wire,capture_output=True,
            pass_fds=(descriptor,),env={'PATH':''},timeout=20)
    finally:os.close(descriptor)
    if result.returncode==2:raise CoreModuleRejected('mandatory native workspace policy/representation/semantic refusal')
    if result.returncode==3:raise OverflowError('native workspace pipeline byte or arena capacity')
    if result.returncode!=0 or result.stderr:raise OSError('native workspace pipeline execution failed: '+str(result.returncode))
    obj=result.stdout
    if not 64<=len(obj)<=1<<20 or obj[:7]!=b'\x7fELF\x02\x01\x01' or struct.unpack_from('<HH',obj,16)!=(1,62):
        raise ValueError('native workspace pipeline did not return an ELF object')
    if manifest_path.read_bytes()!=manifest_raw or current_sources()!=sources:
        raise ValueError('native workspace pipeline custody changed during compilation')
    output.mkdir(mode=0o700);image=output/'core.o'
    with image.open('xb') as stream:stream.write(obj)
    receipt={'schema':'hepta.hia.core-workspace-pipeline-compilation.v1','status':'NATIVE_LINKED_CORE_COMPILED',
        'workspace_sha256':sha256(wire).hexdigest(),'output_sha256':sha256(obj).hexdigest(),
        'manifest_sha256':sha256(manifest_raw).hexdigest(),'executable_sha256':sha256(code).hexdigest(),
        'host_payload_decoder_materializer_renderer_and_semantic_checker':False,
        'mandatory_native_semantic_compiler':True,'sealed_code_descriptor':True,
        'mandatory_complete_primitive_Core_admission':True,
        'host_filesystem_build_install_custody':True,'whole_native_delivery_qualified':False,'production_activated':False}
    with (output/'workspace.receipt.json').open('x') as stream:json.dump(receipt,stream,indent=2,sort_keys=True);stream.write('\n')
    return image

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'output'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('frontend-manifest','compiler'):
        p.add_argument('--'+name,type=Path)
    selection=p.add_mutually_exclusive_group(required=True)
    selection.add_argument('--graph-manifest',type=Path)
    selection.add_argument('--workspace-json-manifest',type=Path)
    selection.add_argument('--pipeline-manifest',type=Path)
    p.add_argument('--output-profile', choices=('elf',), default='elf')
    a = p.parse_args()
    if a.pipeline_manifest is not None:
        if a.frontend_manifest is not None or a.compiler is not None:p.error('complete pipeline cannot select separate frontend/compiler')
    elif a.frontend_manifest is None or a.compiler is None:p.error('separate workspace images require frontend-manifest and compiler')
    with a.source.open('rb') as f: wire = f.read(MAX_BYTES + 1)
    print(compile_workspace(wire, a.graph_manifest.resolve() if a.graph_manifest else None,
                            a.frontend_manifest.resolve() if a.frontend_manifest else None,
                            a.compiler.resolve() if a.compiler else None, a.output.resolve(),
                            output_profile=a.output_profile,
                            workspace_json_manifest=a.workspace_json_manifest.resolve() if a.workspace_json_manifest else None,
                            pipeline_manifest=a.pipeline_manifest.resolve() if a.pipeline_manifest else None))
