"""Explicit native publisher custody; not a native-only installed Agent store.

Only operator-selected code is executed, via a sealed descriptor. Filesystem
payload bytes are passed to HIA, never re-read or hashed by a hosted verifier.
"""
from __future__ import annotations
from hashlib import sha256
import fcntl,json,os,re,struct,subprocess
from pathlib import Path


def _reject(code,message):
    from .artifact_publication import PublicationRejected
    raise PublicationRejected(code+': '+message)


def _admitted_code(manifest):
    # This explicit development/source-tree route retains hosted code custody.
    # Do not advertise it as a clean-machine or native-only installation path.
    from tools.build_hia_artifact_publication import current_sources,SOURCES,OPERATIONS
    from tools.hia_selfhost_contract import PROFILE
    path=Path(manifest);raw=path.read_bytes();record=json.loads(raw)
    if (type(record) is not dict or record.get('schema')!='hepta.hia.artifact-publication-build.v1'
            or record.get('status')!='NATIVE_ARTIFACT_PUBLICATION_BUILT'
            or record.get('profile')!=PROFILE or record.get('source_manifest')!=current_sources()
            or record.get('operations')!=OPERATIONS
            or record.get('executable_path')!='hia-artifact'
            or type(record.get('source_sha256')) is not dict
            or set(record['source_sha256'])!=set(SOURCES)):
        _reject('E_PUBLISH_NATIVE_CUSTODY','selected manifest is not the current explicit native application')
    root=Path(__file__).resolve().parents[1]
    if any(sha256((root/name).read_bytes()).hexdigest()!=digest for name,digest in record['source_sha256'].items()):
        _reject('E_PUBLISH_NATIVE_CUSTODY','native application source identity changed')
    with (path.parent/'hia-artifact').open('rb') as stream:code=stream.read((1<<20)+1)
    if (not 176<=len(code)<=1<<20 or code[:7]!=b'\x7fELF\x02\x01\x01'
            or struct.unpack_from('<HH',code,16)!=(2,62)
            or sha256(code).hexdigest()!=record.get('executable_sha256')
            or path.read_bytes()!=raw):
        _reject('E_PUBLISH_NATIVE_CUSTODY','selected native executable identity changed')
    return code


def _execute_native(manifest,operation,stage,destination,expected):
    from .artifact_publication import PublicationRejected
    try:code=_admitted_code(manifest)
    except PublicationRejected:raise
    except (OSError,ValueError,TypeError,KeyError) as exc:
        raise PublicationRejected('E_PUBLISH_NATIVE_CUSTODY: selected executable unavailable or invalid') from exc
    fd=None
    try:
        fd=os.memfd_create('hia-artifact-publication',os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
        view=memoryview(code)
        while view:
            written=os.write(fd,view)
            if written<=0:_reject('E_PUBLISH_NATIVE_CUSTODY','could not seal selected executable')
            view=view[written:]
        fcntl.fcntl(fd,fcntl.F_ADD_SEALS,
            fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
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


def invoke_artifact_store(manifest,operation,root,*,data=b'',digest='-'):
    """Only the artifact byte layer; DB-issued refs and journal stay in AgentStore."""
    if operation not in ('store-hash','store-put','store-get'):
        _reject('E_PUBLISH_INPUT','unknown native Agent artifact operation')
    if type(data) is not bytes or len(data)>64<<20:
        _reject('E_PUBLISH_LIMIT','Agent artifact exceeds original 64 MiB quota')
    if operation=='store-get' and (type(digest) is not str or re.fullmatch('[0-9a-f]{64}',digest) is None):
        _reject('E_PUBLISH_INPUT','Agent artifact key is not exact lower hexadecimal')
    raw=_execute_native(manifest,operation,Path(root),digest if operation=='store-get' else '-',
                        data if operation!='store-get' else b'')
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
