"""Explicit native publisher custody for source trees and installed packages.

Only operator-selected code is executed, via a sealed descriptor. Filesystem
payload bytes are passed to HIA, never re-read or hashed by a hosted verifier.
"""
from __future__ import annotations
from hashlib import sha256
import fcntl,json,os,re,struct,subprocess
from pathlib import Path


NATIVE_PUBLICATION_OPERATIONS = ('publish','verify','withdraw','store-put','store-get','store-hash')
NATIVE_PUBLICATION_SOURCES = (
    'examples/hia_bootstrap/artifact_publication_policy.hepta',
    'examples/hia_bootstrap/artifact_publication_packer.hepta',
    'examples/hia_bootstrap/sha256_stream.hepta',
    'tools/hia_artifact_publication_syscalls.S',
    'tools/generate_hia_artifact_publication.py',
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
    from .hia_agent_contract import DISCOVERY_FILES, NATIVE_SOURCE_FILES, SOURCE_BUILD_FILES, COMPILER_BUILD_FILES, PUBLICATION_BUILD_FILES, BACKEND_BUILD_FILES, EMITTER_BUILD_FILES
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
    assets=(tuple('docs/'+n for n in DISCOVERY_FILES)+NATIVE_SOURCE_FILES+SOURCE_BUILD_FILES+COMPILER_BUILD_FILES+PUBLICATION_BUILD_FILES) + BACKEND_BUILD_FILES + EMITTER_BUILD_FILES
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


def _admitted_code(manifest):
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
    if any(sha256(_source_resource_path(name).read_bytes()).hexdigest()!=digest for name,digest in record['source_sha256'].items()):
        _reject('E_PUBLISH_NATIVE_CUSTODY','native application source identity changed')
    with (path.parent/'hia-artifact').open('rb') as stream:code=stream.read((1<<20)+1)
    if (not 176<=len(code)<=1<<20 or code[:7]!=b'\x7fELF\x02\x01\x01'
            or struct.unpack_from('<HH',code,16)!=(2,62)
            or sha256(code).hexdigest()!=record.get('executable_sha256')
            or path.read_bytes()!=raw):
        _reject('E_PUBLISH_NATIVE_CUSTODY','selected native executable identity changed')
    return code


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


def _execute_native(manifest,operation,stage,destination,expected,_admission=None):
    from .artifact_publication import PublicationRejected
    if _admission is None:code=_validated_code(manifest)
    else:
        if (type(_admission) is not _StoreAdmission or _admission[0]!=os.fspath(manifest)
                or operation not in ('store-hash','store-put','store-get')):
            _reject('E_PUBLISH_NATIVE_CUSTODY','call-local artifact code admission differs')
        code=_admission[1]
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
        result=subprocess.run(['/proc/self/fd/'+str(fd),operation,os.fspath(stage),os.fspath(destination)],
            input=expected,capture_output=True,
            pass_fds=(fd,),env={'PATH':''})
    except OSError as exc:
        raise PublicationRejected('E_PUBLISH_IO: native execution unavailable; no automatic replay') from exc
    finally:
        if fd is not None:
            try:os.close(fd)
            except OSError:pass  # Linux close(EINTR) does not authorize retry/reuse.
    codes={10:'E_PUBLISH_IDENTITY',11:'E_PUBLISH_BYTES',12:'E_PUBLISH_RACE',
           14:'E_PUBLISH_LINK',15:'E_PUBLISH_IO',16:'E_PUBLISH_INPUT',17:'E_PUBLISH_LIMIT',64:'E_PUBLISH_INPUT'}
    if result.returncode or result.stderr:
        _reject(codes.get(result.returncode,'E_PUBLISH_IO'),
                'native '+operation+' refused or I/O failed; no automatic replay')
    return result.stdout


def invoke_native(manifest,operation,stage,destination,expected=b''):
    if operation not in ('publish','verify','withdraw'):
        _reject('E_PUBLISH_INPUT','unknown native publication operation')
    if operation!='withdraw' and (type(expected) is not bytes or not expected):
        _reject('E_PUBLISH_INPUT','nonempty exact bytes required')
    raw=_execute_native(manifest,operation,stage,destination,expected if operation!='withdraw' else b'')
    try:receipt=json.loads(raw)
    except (ValueError,UnicodeError):_reject('E_PUBLISH_IO','native receipt invalid; effects must not be replayed')
    if operation=='withdraw':
        if type(receipt) is not dict or set(receipt)!={'withdrawn'} or type(receipt['withdrawn']) is not bool:
            _reject('E_PUBLISH_IO','native withdrawal receipt invalid')
        return receipt['withdrawn']
    if (type(receipt) is not dict or set(receipt)!={'sha256','bytes'}
            or type(receipt['bytes']) is not int or receipt['bytes']!=len(expected)
            or type(receipt['sha256']) is not str or re.fullmatch('[0-9a-f]{64}',receipt['sha256']) is None):
        _reject('E_PUBLISH_IO','native publication receipt invalid; effects must not be replayed')
    return receipt


def invoke_artifact_store(manifest,operation,root,*,data=b'',digest='-',_admission=None):
    """Only the artifact byte layer; DB-issued refs and journal stay in AgentStore."""
    if operation not in ('store-hash','store-put','store-get'):
        _reject('E_PUBLISH_INPUT','unknown native Agent artifact operation')
    if type(data) is not bytes or len(data)>64<<20:
        _reject('E_PUBLISH_LIMIT','Agent artifact exceeds original 64 MiB quota')
    if operation=='store-get' and (type(digest) is not str or re.fullmatch('[0-9a-f]{64}',digest) is None):
        _reject('E_PUBLISH_INPUT','Agent artifact key is not exact lower hexadecimal')
    raw=_execute_native(manifest,operation,Path(root),digest if operation=='store-get' else '-',
                        data if operation!='store-get' else b'',_admission)
    if operation=='store-get':
        if len(raw)>64<<20:_reject('E_PUBLISH_LIMIT','native artifact output exceeds original quota')
        return raw
    try:receipt=json.loads(raw)
    except (ValueError,UnicodeError):_reject('E_PUBLISH_IO','native artifact receipt invalid; no replay')
    if (type(receipt) is not dict or set(receipt)!={'sha256','bytes'}
            or type(receipt['bytes']) is not int or receipt['bytes']!=len(data)
            or type(receipt['sha256']) is not str or re.fullmatch('[0-9a-f]{64}',receipt['sha256']) is None):
        _reject('E_PUBLISH_IO','native artifact receipt invalid; no issuance or replay')
    return receipt
