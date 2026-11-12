"""Explicit source-bound native scheduling; no new ambient selector is needed."""
from hashlib import sha256
from pathlib import Path
import json

from .hia_native_continuation import NativeContinuation,MAX_EXECUTABLE
from .hia_native_helpers import _read
from .hia_json_preflight_native import _source_resource_path,_unique_manifest_pairs
from .hia_execution_observation_native import NativeExecutionObservation
from .hia_core_lowering_native import NativeCoreLowering
from .hia_core_emitter_native import NativeCoreEmitter
from .hia_byte_wrapper_native import NativeByteWrapper
from .hia_machine_object_native import NativeMachineObject

SCHEMA='hepta.hia.native-continuation.v1'
INPROCESS_SCHEMA='hepta.hia.native-continuation-inprocess.v1'
_RUNTIME=('hia_native_continuation.py','hia_native_continuation_selection.py','hia_native_continuation_inprocess.py')
_OWNER_CACHE=[]


class _Continuation:
    def invoke(self,name,arguments):
        return self._continuation.invoke(self,name,arguments)


class ContinuationExecutionObservation(_Continuation,NativeExecutionObservation):pass
class ContinuationCoreLowering(_Continuation,NativeCoreLowering):pass
class ContinuationCoreEmitter(_Continuation,NativeCoreEmitter):pass
class ContinuationByteWrapper(_Continuation,NativeByteWrapper):pass
class ContinuationMachineObject(_Continuation,NativeMachineObject):pass

_FAMILIES={
    'execution-observation':('execution_observation',ContinuationExecutionObservation),
    'core-lowering':('core_lowering',ContinuationCoreLowering),
    'core-emitter':('core_emitter',ContinuationCoreEmitter),
    'byte-wrapper':('byte_wrapper',ContinuationByteWrapper),
    'machine-object':('machine_object',ContinuationMachineObject),
}


def installed_native_continuation(manifest_path,namespace,*,kind='execution-observation'):
    from .hia_agent_contract import CONTINUATION_BUILD_FILES
    from importlib import import_module
    if type(kind) is not str or kind not in _FAMILIES:raise ValueError('native continuation family differs')
    module_name,factory=_FAMILIES[kind]
    selection=import_module('.hia_'+module_name+'_selection',__package__)
    installed=getattr(selection,'installed_'+module_name)
    if type(namespace) is not dict:raise TypeError('native continuation requires an actual module namespace')
    path=Path(manifest_path).resolve(strict=True)
    raw=_read(path,16384).raw
    value=json.loads(raw,object_pairs_hook=_unique_manifest_pairs)
    fields={'schema','kind','policy_bundle','policy_bundle_sha256','compiler_sha256',
        'image_path','image_sha256','resource_sha256','runtime_sha256'}
    if (type(value) is not dict or set(value)!=fields or value['schema'] not in (SCHEMA,INPROCESS_SCHEMA)
            or value['kind']!=kind or (value['schema']==SCHEMA and kind!='execution-observation') or value['policy_bundle']!='policy/manifest.json'
            or value['image_path']!=('continuation.image.bin' if value['schema']==INPROCESS_SCHEMA else 'continuation.native')):
        raise ValueError('native continuation bundle shape differs')
    def digest(v):return type(v) is str and len(v)==64 and all(c in '0123456789abcdef' for c in v)
    if any(not digest(value[k]) for k in ('policy_bundle_sha256','compiler_sha256','image_sha256')):
        raise ValueError('native continuation bundle identity differs')
    resources={name:sha256(_source_resource_path(name).read_bytes()).hexdigest() for name in CONTINUATION_BUILD_FILES}
    runtime={'hepta/'+name:sha256((Path(__file__).parent/name).read_bytes()).hexdigest() for name in _RUNTIME}
    if value['resource_sha256']!=resources or value['runtime_sha256']!=runtime:
        raise ValueError('native continuation resource or runtime source identity mismatch')
    basepath=path.parent/'policy/manifest.json';base_raw=_read(basepath,16384).raw
    if sha256(base_raw).hexdigest()!=value['policy_bundle_sha256']:
        raise ValueError('native continuation complete policy bundle identity mismatch')
    base=json.loads(base_raw,object_pairs_hook=_unique_manifest_pairs)
    if type(base) is not dict or base.get('compiler_sha256')!=value['compiler_sha256']:
        raise ValueError('native continuation compiler identity differs across bundles')
    image=path.parent/value['image_path'];image_raw=_read(image,MAX_EXECUTABLE).raw
    if sha256(image_raw).hexdigest()!=value['image_sha256']:
        raise ValueError('native continuation executable identity mismatch')
    policy=installed(str(basepath),namespace)
    loaded=policy._admitted_bundle
    for previous_path,previous_raw,previous_loaded,previous_namespace,owner in _OWNER_CACHE:
        if previous_path==str(path) and previous_raw==raw and previous_loaded is loaded and previous_namespace is namespace:
            return owner
    owner=factory(loaded.images[1:],loaded.images[0],loaded.abi,namespace)
    owner._admitted_bundle=loaded
    if value['schema']==INPROCESS_SCHEMA:
        from .hia_native_continuation_inprocess import InProcessContinuation
        owner._continuation=InProcessContinuation(image_raw,value['image_sha256'],pool_bytes=loaded.abi['pool_bytes'])
    else:owner._continuation=NativeContinuation(image,value['image_sha256'],pool_bytes=loaded.abi['pool_bytes'])
    owner._native_continuation_identity=('\0'.join((value['schema'],sha256(raw).hexdigest(),value['image_sha256'],*resources.values(),*runtime.values()))).encode('ascii')
    _OWNER_CACHE.append((str(path),raw,loaded,namespace,owner))
    matching=[i for i,entry in enumerate(_OWNER_CACHE) if type(entry[-1]) is factory]
    if len(matching)>3:del _OWNER_CACHE[matching[0]]
    return owner
