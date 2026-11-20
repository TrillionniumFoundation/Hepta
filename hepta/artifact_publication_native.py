"""Explicit native publisher custody for source trees and installed packages.

Only operator-selected code is executed, via a sealed descriptor. Filesystem
payload bytes are passed to HIA, never re-read or hashed by a hosted verifier.
"""
from __future__ import annotations
from hashlib import sha256
import fcntl,json,os,re,struct,subprocess
from pathlib import Path
from .hia_artifact_delivery import (take_invocation as _take_artifact_invocation,
    handoff as _artifact_handoff, payload as _artifact_payload)


NATIVE_PUBLICATION_OPERATIONS = ('publish','verify','withdraw','store-put','store-get','store-hash')
NATIVE_PUBLICATION_SOURCES = (
    'examples/hia_bootstrap/artifact_publication_policy.hepta',
    'examples/hia_bootstrap/artifact_publication_packer.hepta',
    'examples/hia_bootstrap/sha256_stream.hepta',
    'tools/hia_artifact_publication_syscalls.S',
    'tools/generate_hia_artifact_publication.py',
    'hepta/hia_artifact_delivery_protocol.py',
)

# Linux UAPI values also cover Python builds that omit the fcntl names.
_EXECUTABLE_SEALS = (getattr(fcntl,'F_SEAL_WRITE',0x0008)
    |getattr(fcntl,'F_SEAL_GROW',0x0004)|getattr(fcntl,'F_SEAL_SHRINK',0x0002)
    |getattr(fcntl,'F_SEAL_SEAL',0x0001))


def _require_sealed_executable(fd):
    observed=fcntl.fcntl(fd,getattr(fcntl,'F_GET_SEALS',1034))
    if type(observed) is not int or observed&_EXECUTABLE_SEALS!=_EXECUTABLE_SEALS:
        _reject('E_PUBLISH_NATIVE_CUSTODY','selected executable lacks complete kernel seals')


def _installed_source_custody(root):
    """Bind installed production bytes/assets to their owned full build contract.

    Absent build tools are not imported, inferred as present, or searched in a
    different checkout. The full build-source manifest remains bound through
    the exact package-owned contract; it is not a claim those tools are installed.
    """
    from .hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES, BYTE_WRAPPER_BUILD_FILES, MACHINE_OBJECT_BUILD_FILES, EXECUTION_OBSERVATION_BUILD_FILES, CONTINUATION_BUILD_FILES
    from .hia_json_preflight_native import _source_resource_path
    contract_name='docs/HIA_SELFHOST_CORE_SUPPORT.json'
    contract_path=_source_resource_path(contract_name);raw=contract_path.read_bytes()
    contract=json.loads(raw)
    if type(contract) is not dict or contract.get('schema')!='hepta.hia.selfhost-core-support.v1':
        _reject('E_PUBLISH_NATIVE_CUSTODY','installed source contract unavailable')
    files=contract['source_identity']['files']
    if type(files) is not dict or any(type(n) is not str or type(d) is not str or re.fullmatch('[0-9a-f]{64}',d) is None for n,d in files.items()):
        _reject('E_PUBLISH_NATIVE_CUSTODY','installed source contract inventory invalid')
    actual_python={p.relative_to(root).as_posix() for p in (root/'hepta').rglob('*.py') if p.relative_to(root/'hepta').parts[0]!='_data'}
    expected_python={n for n in files if n.startswith('hepta/') and n.endswith('.py')}
    if actual_python!=expected_python:
        _reject('E_PUBLISH_NATIVE_CUSTODY','installed production module inventory changed')
    assets=(tuple('docs/'+n for n in DISCOVERY_FILES)+NATIVE_SOURCE_FILES+SOURCE_BUILD_FILES+COMPILER_BUILD_FILES+PUBLICATION_BUILD_FILES) + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES + BYTE_WRAPPER_BUILD_FILES + MACHINE_OBJECT_BUILD_FILES + EXECUTION_OBSERVATION_BUILD_FILES + CONTINUATION_BUILD_FILES
    for name in (*sorted(actual_python),*assets):
        if name==contract_name:continue  # The outer manifest binds this exact JSON.
        path=root/name if name in actual_python else _source_resource_path(name)
        if name not in files or sha256(path.read_bytes()).hexdigest()!=files[name]:
            _reject('E_PUBLISH_NATIVE_CUSTODY','installed production or build-input bytes changed')
    if contract_path.read_bytes()!=raw:
        _reject('E_PUBLISH_NATIVE_CUSTODY','installed source contract changed during admission')
    return contract['profile'],{**files,contract_name:sha256(raw).hexdigest()}


def _reject(code,message):
    from .artifact_publication import PublicationRejected
    raise PublicationRejected(code+': '+message)


def _scoped_artifact_code(manifest):
    from .hia_artifact_delivery_worker import ARTIFACT_SCHEMA, NativeArtifactExecutable
    from .hia_native_helpers import pinned_bundle
    owner = pinned_bundle(manifest, ARTIFACT_SCHEMA, NativeArtifactExecutable)
    return None if owner is None else owner.current_code()


def _admitted_code(manifest):
    captured = _scoped_artifact_code(manifest)
    return _current_admitted_code(manifest) if captured is None else captured


def _binding_sources():
    # Build-source admission remains unchanged in a checkout. An installed
    # package binds its actual owned bytes/assets plus the exact build contract,
    # without importing or falling back to an external source tree.
    root=Path(__file__).resolve().parents[1]
    if (root/'pyproject.toml').is_file():
        from tools.build_hia_artifact_publication import current_sources
        from tools.hia_selfhost_contract import PROFILE
        sources=current_sources()
    else:
        PROFILE,sources=_installed_source_custody(root)
    return root,PROFILE,sources


def _current_admitted_code(manifest):
    root,PROFILE,sources=_binding_sources()
    SOURCES=NATIVE_PUBLICATION_SOURCES;OPERATIONS=list(NATIVE_PUBLICATION_OPERATIONS)
    from .hia_json_preflight_native import _source_resource_path
    path=Path(manifest);raw=path.read_bytes();record=json.loads(raw)
    if (type(record) is not dict or record.get('schema')!='hepta.hia.artifact-publication-build.v1'
            or record.get('status')!='NATIVE_ARTIFACT_PUBLICATION_BUILT'
            or record.get('profile')!=PROFILE or record.get('source_manifest')!=sources
            or record.get('operations')!=OPERATIONS
            or record.get('executable_path')!='hia-artifact'
            or type(record.get('source_sha256')) is not dict
            or set(record['source_sha256'])!=set(SOURCES)):
        _reject('E_PUBLISH_NATIVE_CUSTODY','selected manifest is not the current explicit native application')
    if any(sha256((root/name if name.startswith('hepta/') else _source_resource_path(name)).read_bytes()).hexdigest()!=digest
            for name,digest in record['source_sha256'].items()):
        _reject('E_PUBLISH_NATIVE_CUSTODY','native application source identity changed')
    with (path.parent/'hia-artifact').open('rb') as stream:code=stream.read((1<<20)+1)
    if (not 176<=len(code)<=1<<20 or code[:7]!=b'\x7fELF\x02\x01\x01'
            or struct.unpack_from('<HH',code,16)!=(2,62)
            or sha256(code).hexdigest()!=record.get('executable_sha256')
            or path.read_bytes()!=raw):
        _reject('E_PUBLISH_NATIVE_CUSTODY','selected native executable identity changed')
    from .hia_artifact_delivery_protocol import private_executable
    private=private_executable(code)
    # This is a fixed admission result, never a call/nonce/context-dependent
    # rewrite. Existing manual current-source manifests bind the same note via
    # their complete public image SHA; pre-capability sources fail above.
    if ('public_executable_sha256' in record or 'private_executable_sha256' in record):
        if (record.get('public_executable_sha256')!=sha256(code).hexdigest()
                or record.get('private_executable_sha256')!=sha256(private).hexdigest()):
            _reject('E_PUBLISH_NATIVE_CUSTODY','public/private executable admission differs')
    return private


def _validated_code(manifest):
    from .artifact_publication import PublicationRejected
    try:return _admitted_code(manifest)
    except PublicationRejected:raise
    except (OSError,ValueError,TypeError,KeyError) as exc:
        raise PublicationRejected('E_PUBLISH_NATIVE_CUSTODY: selected executable unavailable or invalid') from exc


class _StoreAdmission(tuple):
    """Call-local immutable code, never cached between public store calls."""
    def __new__(cls,manifest,code):
        return tuple.__new__(cls,(os.fspath(manifest),code))


def admit_artifact_store(manifest):
    # One AgentStore.put is one code-admission boundary. Its pure hash and
    # durable put must use the SAME admitted bytes, even if the mutable build
    # path changes between them. The next public call rehashes every source.
    return _StoreAdmission(manifest,_validated_code(manifest))


def _execute_native(manifest,operation,stage,destination,expected,_admission=None,*,_delivery_required=None):
    delivery=_take_artifact_invocation(_delivery_required)
    if _admission is None:code=_validated_code(manifest)
    else:
        if (type(_admission) is not _StoreAdmission or _admission[0]!=os.fspath(manifest)
                or operation not in ('store-hash','store-put','store-get')):
            _reject('E_PUBLISH_NATIVE_CUSTODY','call-local artifact code admission differs')
        code=_admission[1]
        scoped = _scoped_artifact_code(manifest)
        if scoped is not None and scoped != code:
            _reject('E_PUBLISH_NATIVE_CUSTODY','call-local artifact code differs from worker pin')
    if delivery is not None:code=delivery.code(code)
    else:
        # The explicit direct private helper keeps its old bytes/stdin CLI
        # surface. Canonical selected public providers always carry delivery;
        # they never enter this branch after an error or missing capability.
        from .hia_artifact_delivery_protocol import public_executable
        try:code=public_executable(code)
        except ValueError:pass  # Retain original injected sealed-byte controls.
    return _execute_code(code, operation, stage, destination, expected, delivery=delivery)


def _execute_code(code, operation, stage, destination, expected, *, output=None, delivery=None):
    result=_run_sealed_native(code, (operation, os.fspath(stage), os.fspath(destination)), expected,
                              output=output, delivery=delivery)
    codes={10:'E_PUBLISH_IDENTITY',11:'E_PUBLISH_BYTES',12:'E_PUBLISH_RACE',
           14:'E_PUBLISH_LINK',15:'E_PUBLISH_IO',16:'E_PUBLISH_INPUT',17:'E_PUBLISH_LIMIT',64:'E_PUBLISH_INPUT'}
    if delivery is not None:delivery.returned(result)
    if result.returncode or (delivery is None and result.stderr):
        _reject(codes.get(result.returncode,'E_PUBLISH_IO'),
                'native '+operation+' refused or I/O failed; no automatic replay')
    return result.stdout


def _run_sealed_native(code, argv, input_bytes, *, output=None, delivery=None):
    from .artifact_publication import PublicationRejected
    fd=None
    try:
        try:
            fd=os.memfd_create('hia-artifact-publication',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
            view=memoryview(code)
            while view:
                written=os.write(fd,view)
                if written<=0:_reject('E_PUBLISH_NATIVE_CUSTODY','could not seal selected executable')
                view=view[written:]
            fcntl.fcntl(fd,getattr(fcntl,'F_ADD_SEALS',1033),_EXECUTABLE_SEALS)
            _require_sealed_executable(fd)
            # Read the actual sealed descriptor, not the mutable source path.
            # Complete kernel seals freeze the bytes before this identity check.
            if os.fstat(fd).st_size!=len(code) or os.pread(fd,len(code)+1,0)!=code:
                _reject('E_PUBLISH_NATIVE_CUSTODY','sealed executable bytes or extent differ')
        except (OSError,AttributeError) as exc:
            raise PublicationRejected('E_PUBLISH_NATIVE_CUSTODY: sealed executable snapshot unavailable') from exc
        # No new wall-time or payload-size profile is imposed by this custody
        # bridge. Original synchronous filesystem operations are not replayed.
        command=['/proc/self/fd/'+str(fd), *argv]
        if output is None:
            return subprocess.run(command,input=_artifact_payload(delivery,input_bytes),
                capture_output=True,pass_fds=(fd,),env=_artifact_handoff(delivery,{'PATH':''}))
        return subprocess.run(command,input=input_bytes,stdout=output,stderr=subprocess.PIPE,
            pass_fds=(fd,),env={'PATH':''})
    except OSError as exc:
        raise PublicationRejected('E_PUBLISH_IO: native execution unavailable; no automatic replay') from exc
    finally:
        if fd is not None:
            try:os.close(fd)
            except OSError:pass  # Linux close(EINTR) does not authorize retry/reuse.


def invoke_native(manifest,operation,stage,destination,expected=b''):
    if operation not in ('publish','verify','withdraw'):
        _reject('E_PUBLISH_INPUT','unknown native publication operation')
    if operation!='withdraw' and (type(expected) is not bytes or not expected):
        _reject('E_PUBLISH_INPUT','nonempty exact bytes required')
    from .hia_artifact_delivery import ArtifactInvocation
    with ArtifactInvocation(operation) as delivery:
        raw=_execute_native(manifest,operation,stage,destination,
                            delivery.arm(expected if operation!='withdraw' else b''),
                            _delivery_required=delivery)
        try:receipt=json.loads(raw)
        except (ValueError,UnicodeError):_reject('E_PUBLISH_IO','native receipt invalid; effects must not be replayed')
        if operation=='withdraw':
            if type(receipt) is not dict or set(receipt)!={'withdrawn'} or type(receipt['withdrawn']) is not bool:
                _reject('E_PUBLISH_IO','native withdrawal receipt invalid')
            returned=receipt['withdrawn']
            delivery.confirmed()
            return returned
        if (type(receipt) is not dict or set(receipt)!={'sha256','bytes'}
                or type(receipt['bytes']) is not int or receipt['bytes']!=len(expected)
                or type(receipt['sha256']) is not str or re.fullmatch('[0-9a-f]{64}',receipt['sha256']) is None):
            _reject('E_PUBLISH_IO','native publication receipt invalid; effects must not be replayed')
        delivery.confirmed()
        return receipt


def invoke_artifact_store(manifest,operation,root,*,data=b'',digest='-',_admission=None):
    """Only the artifact byte layer; DB-issued refs and journal stay in AgentStore."""
    def execute(operation, root, destination, payload, delivery):
        return _execute_native(manifest, operation, root, destination, payload,
                               delivery.arm(_admission), _delivery_required=delivery)
    return _invoke_artifact_store(execute, operation, root, data, digest)


def invoke_pinned_artifact_store(code, operation, root, *, data=b'', digest='-'):
    """Transport to an immutable artifact image already pinned by the operator."""
    from .hia_artifact_delivery_protocol import private_executable

    def execute(operation, root, destination, payload, delivery):
        selected = _take_artifact_invocation(delivery.arm(delivery))
        return _execute_code(selected.code(private_executable(code)), operation, root,
                             destination, payload, delivery=selected)
    return _invoke_artifact_store(execute, operation, root, data, digest)


def capture_pinned_artifact(code, root, digest, output):
    """Let the pinned Store verify and write directly to a private descriptor."""
    if type(digest) is not str or re.fullmatch('[0-9a-f]{64}', digest) is None:
        _reject('E_PUBLISH_INPUT', 'Agent artifact key is not exact lower hexadecimal')
    _execute_code(code, 'store-get', root, digest, b'', output=output)


def _invoke_artifact_store(execute, operation, root, data, digest):
    if operation not in ('store-hash','store-put','store-get'):
        _reject('E_PUBLISH_INPUT','unknown native Agent artifact operation')
    if type(data) is not bytes or len(data)>64<<20:
        _reject('E_PUBLISH_LIMIT','Agent artifact exceeds original 64 MiB quota')
    if operation=='store-get' and (type(digest) is not str or re.fullmatch('[0-9a-f]{64}',digest) is None):
        _reject('E_PUBLISH_INPUT','Agent artifact key is not exact lower hexadecimal')
    from .hia_artifact_delivery import ArtifactInvocation
    with ArtifactInvocation(operation) as delivery:
        raw = execute(operation, Path(root), digest if operation == 'store-get' else '-',
                      data if operation != 'store-get' else b'', delivery)
        if operation=='store-get':
            if len(raw)>64<<20:_reject('E_PUBLISH_LIMIT','native artifact output exceeds original quota')
            delivery.confirmed()
            return raw
        try:receipt=json.loads(raw)
        except (ValueError,UnicodeError):_reject('E_PUBLISH_IO','native artifact receipt invalid; no replay')
        if (type(receipt) is not dict or set(receipt)!={'sha256','bytes'}
                or type(receipt['bytes']) is not int or receipt['bytes']!=len(data)
                or type(receipt['sha256']) is not str or re.fullmatch('[0-9a-f]{64}',receipt['sha256']) is None):
            _reject('E_PUBLISH_IO','native artifact receipt invalid; no issuance or replay')
        delivery.confirmed()
        return receipt
