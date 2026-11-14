"""Optional discovery expressions; the original fifteen-action CLI stays live.

The companion HIA controller owns expression order, exact-fact admission,
native/foreign choice, error-object construction and terminal selection. Its
ports move actual Python callees and values; bytes are never a dict surrogate.
"""
from __future__ import annotations
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import struct
import sys
import types

from .hia_cli_native import NativeCli, DOMAIN_ERRORS, _q, _text, _print_parser_message
from .hia_cli_discovery_json_native import installed_cli_discovery_json
from .hia_cli_discovery_facts import observation
from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path, _load_manifest

SOURCE_NAME='examples/hia_bootstrap/cli_discovery_routing.hepta'
SOURCE=_source_resource_path(SOURCE_NAME)
SCHEMA='hepta.hia.cli-discovery-routing-native.v1'
BUNDLE_SCHEMA='hepta.hia.cli-discovery-bundle.v2'
CONTEXT_BUNDLE_SCHEMA='hepta.hia.cli-discovery-bundle.v3'
MAGIC=int.from_bytes(b'HCLROUT1','little')
COMMAND=int.from_bytes(b'HCLCMD01','little')
_EMPTY=object()
_MISSING=object()
_UNKNOWN={}
_LITERALS=('ok','status','diagnostics','code','message','phase','error','E_DRIVER','driver',False)
_COMMON=('verify_program','read_bounded','decode_json','inspect_program','apply_program_patch','publish_program')


def _global(function, name):
    namespace=function.__globals__
    value=dict.get(namespace,name,_MISSING)
    if value is _MISSING and not dict.__contains__(namespace,name):
        value=dict.get(function.__builtins__,name,_MISSING)
        if value is _MISSING and not dict.__contains__(function.__builtins__,name):
            raise NameError("name '"+name+"' is not defined",name=name)
    return value


class DiscoveryExpression:
    def __init__(self, owner, parent):
        self.owner=owner
        self.parent=parent
        self.cli=parent.cli
        self.reference=types.ModuleType.__getattribute__(self.cli,'__dict__')['_HIA_DISCOVERY_DEFINITIONS'][2]
        self.nonce=parent.nonce
        self.action=_q(parent.workspace,16)
        self.workspace=ctypes.create_string_buffer(2048)
        self.output=ctypes.create_string_buffer(128)
        self.handles=[_EMPTY]
        self.pending=None
        self.busy=False
        self.finished=False
        self.domain_failure=False
        self.effect_failed=False
        self.retired=False
        self.unknown=False
        self.opcode_module=None
        self.output_handle=0
        self.provider_handle=0
        self.schema_handle=0
        self.claimed=None
        self.legacy_permission=None
        self.legacy_consumed=False
        self.route_events=[]
        self.packet=self._packet(0,0,0,0,self.action,_q(parent.raw,24))

    def register(self, value):
        self.handles.append(value)
        return len(self.handles)-1

    def value(self, handle):
        if type(handle) is not int or not 0<handle<len(self.handles) or self.handles[handle] is _EMPTY:
            raise RuntimeError('discovery handle is absent or consumed')
        return self.handles[handle]

    def take(self, handle):
        value=self.value(handle)
        self.handles[handle]=_EMPTY
        return value

    def _packet(self, command, sequence, operation, failed, a=0,b=0,c=0,d=0,
                digest=b'\0'*32, schema=b''):
        if type(digest) is not bytes or len(digest)!=32 or type(schema) is not bytes:
            raise RuntimeError('invalid discovery acknowledgement fields')
        return struct.pack('<10Q',MAGIC,command,self.nonce,sequence,operation,failed,a,b,c,d)+digest+struct.pack('<2Q',len(schema),0)+schema

    def _entry(self, packet):
        source=ctypes.create_string_buffer(packet,len(packet))
        result=self.owner.routing._entry(source,len(packet),self.output,len(self.output),self.workspace,len(self.workspace))
        if bytes(source.raw)!=packet:
            raise RuntimeError('discovery controller wrote to read-only input')
        return result,struct.unpack('<16Q',self.output.raw)

    def step(self):
        if self.busy or self.pending is not None or self.finished or self.unknown:
            self.finished=True
            raise RuntimeError('discovery continuation reentry or consumed step')
        self.busy=True
        try:
            code,words=self._entry(self.packet)
            if self.finished:
                raise RuntimeError('discovery step reentered its continuation')
            if words[0]!=COMMAND or any(words[9:]):
                raise RuntimeError('discovery command envelope refused')
            if code==2:
                if words[2] or words[8] not in (0,2,3,4):
                    raise RuntimeError('discovery terminal envelope refused')
                self.finished=True
                return code,words[8]
            if code!=1 or not 1<=words[2]<=21 or words[1]==0 or words[3] not in (0,1) or words[8]:
                raise RuntimeError('discovery effect envelope refused')
            self.pending=words[1:8]
            return code,0
        except BaseException:
            self.finished=True
            self.unknown=True
            _UNKNOWN[self.nonce]=self
            raise
        finally:
            self.busy=False

    def _pair(self, pending, observed):
        return self.register(pending),self.register(observed),0

    def _effect(self, operation,a,b,c,d):
        zero=(0,0,0)
        if operation==1:
            return self.parent._effect(35,0,0,0,0)
        if operation==2:
            from .hia_opcodes import opcode_catalog
            self.opcode_module=sys.modules[__package__+'.hia_opcodes']
            return self.register(opcode_catalog),0,0
        if operation==3:
            return self.register(_global(self.reference,'output_json')),0,0
        if operation==4:
            # The pending output callee is on the real operand stack while
            # the next LOAD_GLOBAL happens. A load error unwinds it there.
            return self._pair(self.take(a),_global(self.reference,'agent_capabilities'))
        if operation==5:
            return self._pair(self.take(a),self.parent.namespace.schema)
        if operation==6:
            self.output_handle,self.provider_handle,self.schema_handle=a,b,c
            value=observation(self.action,self.cli,self.value(a),self.value(b),self.opcode_module)
            schema=b''
            if self.action==2:
                actual=self.value(c)
                if type(actual) is not str:
                    return 0,0,0
                schema=actual.encode('utf-8','surrogatepass')
            if value is None or len(schema)>20:
                self.route_events.append('foreign-facts')
                return 0,0,0
            self.route_events.append('observed-standard-facts')
            return (1,0,0,value[1],schema)
        if operation==7:
            return self.register(_global(self.value(self.output_handle),'print')),0,0
        if operation==8:
            self.route_events.append('foreign-capabilities')
            self.take(a)(self.take(b)())
            return zero
        if operation==9:
            self.route_events.append('foreign-catalog')
            # The imported provider is a named local in the original frame.
            # Keep its separate owner until the handled exception unwinds.
            self.take(a)(self.value(b)(self.take(c)))
            return zero
        if operation==10:
            return self._legacy_port(1,a,b,c,d)
        if operation==11:
            return self._legacy_port(2,a,b,c,d)
        if operation==12:
            return self._legacy_port(22,a,b,c,d)
        if operation==13:
            return self._pair(self.take(a),_global(self.reference,'str'))
        if operation==14:
            # Carry the outer output callable on the actual operand stack
            # through str(error), including the latter's exceptional unwind.
            return self._pair(self.take(a),self.take(b)(self.value(c)))
        if operation==15:
            return self.register({}),0,0
        if operation==16:
            return self.register([]),0,0
        if operation==17:
            key=_LITERALS[b]
            if d==0:
                self.value(a)[key]=self.take(c)
            elif d==1:
                self.value(a)[key]=_LITERALS[c]
            else:
                raise RuntimeError('discovery literal operand tag')
            return zero
        if operation==18:
            self.value(a).append(self.take(b))
            return zero
        if operation==19:
            self.take(a)(self.take(b))
            return zero
        if operation==20:
            if type(a) is not int or not 0<a<len(self.handles):
                raise RuntimeError('discovery retirement handle outside its arena')
            if self.handles[a] is not _EMPTY:
                self.take(a)
            return zero
        if operation==21:
            if type(a) is not int or not 0<=a<len(_COMMON):
                raise RuntimeError('discovery named import index outside its arena')
            del self.parent.common[_COMMON[a]]
            return zero
        raise RuntimeError('unknown discovery effect')

    def _legacy_port(self,operation,a,b,c,d):
        if self.parent.discovery_permission is not None or self.legacy_permission is not None:
            self.finished=True
            raise RuntimeError('discovery shared port permission is already held')
        self.legacy_permission=(operation,a,b,c,d)
        self.legacy_consumed=False
        self.parent.discovery_permission=self
        try:
            result=self.parent._effect(operation,a,b,c,d)
            if not self.legacy_consumed or self.finished:
                raise RuntimeError('discovery shared port was not consumed exactly once')
            return result
        finally:
            self.parent.discovery_permission=None
            self.legacy_permission=None

    def consume_legacy_port(self,parent,operation,a,b,c,d):
        # This is the actual common CLI effect entry, under the separate new
        # image's claimed permission. The retained profile keeps its original
        # dict-returning ports. The new profile has explicit JSON-text/print
        # ports and never presents that text as an original Python dict.
        expected=10 if operation==1 else 11 if operation==2 else 12 if operation==22 else 0
        if (parent is not self.parent or parent.discovery_permission is not self
                or not self.busy or self.finished or self.legacy_consumed
                or self.legacy_permission!=(operation,a,b,c,d)
                or self.claimed is None or self.claimed[1]!=expected
                or _q(self.workspace,24)!=expected or _q(self.workspace,32)!=1):
            self.finished=True
            raise RuntimeError('discovery shared port lacks its actual HIA claim')
        self.legacy_consumed=True
        if operation==22:
            self.take(a)(self.take(b))
            return 0,0,0
        if operation==1:
            self.route_events.append('native-capabilities')
            raw=self.owner.discovery.capabilities_json()
        else:
            self.route_events.append('native-catalog')
            raw=self.owner.discovery.catalog_json(self.value(a).encode('utf-8','surrogatepass'))
        if not raw.endswith(b'\n'):
            raise RuntimeError('discovery JSON publication lacks its final newline')
        return self.register(raw[:-1].decode('utf-8')),0,0

    def observe(self):
        if self.pending is None or self.busy or self.finished or self.unknown:
            self.finished=True
            raise RuntimeError('discovery permission absent or reentered')
        sequence,operation,catching,a,b,c,d=self.pending
        self.pending=None
        self.busy=True
        self.domain_failure=False
        self.effect_failed=False
        try:
            code,words=self._entry(self._packet(2,sequence,operation,0))
            if code!=3 or words[:8]!=(COMMAND,sequence,operation,catching,a,b,c,d) or any(words[8:]):
                raise RuntimeError('discovery claim refused or acknowledgement lost')
            self.claimed=(sequence,operation,catching,a,b,c,d)
            try:
                result=self._effect(operation,a,b,c,d)
            except BaseException as error:
                self.effect_failed=True
                if isinstance(error,DOMAIN_ERRORS) and catching:
                    self.domain_failure=True
                    self.failed_command=(sequence,operation)
                raise
            if self.finished:
                raise RuntimeError('discovery effect reentered its continuation')
            if len(result)==5:
                x,y,z,digest,schema=result
                self.packet=self._packet(1,sequence,operation,0,x,y,z,digest=digest,schema=schema)
            else:
                self.packet=self._packet(1,sequence,operation,0,*result)
        finally:
            self.claimed=None
            self.busy=False

    def _drive(self):
        while True:
            code,result=self.step()
            if code==2:
                return result
            try:
                self.observe()
            except DOMAIN_ERRORS as error:
                if not self.domain_failure or self.finished:
                    raise
                self.domain_failure=False
                sequence,operation=self.failed_command
                self.packet=self._packet(1,sequence,operation,1,self.register(error))
                # Run the actual handler under the actual handled exception.
                try:
                    return self._drive()
                finally:
                    self._release_handled()

    def _release_handled(self):
        code,words=self._entry(self._packet(5,0,0,0))
        if code!=4 or words[0]!=COMMAND or any(words[9:]):
            self.unknown=True
            _UNKNOWN[self.nonce]=self
            raise RuntimeError('discovery handled exception release permission lost')
        if words[8]:
            self.take(words[8])

    def _retire(self):
        if self.retired or self.unknown:
            return
        self.finished=False
        self.pending=None
        self.packet=self._packet(4,0,0,0)
        try:
            result=self._drive()
            if _q(self.workspace,40)!=1 or any(value is not _EMPTY for value in self.handles[1:]):
                raise RuntimeError('discovery retirement left a foreign owner')
            self.retired=True
            self.opcode_module=None
        except BaseException:
            self.finished=True
            self.unknown=True
            _UNKNOWN[self.nonce]=self
            raise

    def __del__(self):
        if hasattr(self,'retired') and not self.retired and not self.unknown:
            try:self._retire()
            except BaseException:pass

    def run(self):
        try:
            result=self._drive()
        except BaseException:
            self.finished=True
            if self.effect_failed and not self.unknown:
                sequence,operation=self.failed_command if self.domain_failure else (_q(self.workspace,16),_q(self.workspace,24))
                try:
                    code,words=self._entry(self._packet(3,sequence,operation,0))
                    if code!=5 or _q(self.workspace,40)!=2:
                        raise RuntimeError('discovery known foreign error custody refused')
                except BaseException:
                    self.unknown=True
                    _UNKNOWN[self.nonce]=self
            else:
                self.unknown=True
                _UNKNOWN[self.nonce]=self
            raise
        self._retire()
        return result


class NativeDiscoveryCli(NativeCli):
    def __init__(self, base, discovery, routing, parser_context=None):
        super().__init__(base.control,base.formatter)
        self.discovery=discovery
        self.routing=routing
        self.parser_context=parser_context
        self.last_expression=None

    def format_result(self, session):
        # Preserve the original formatter call and text order, retaining its
        # HIA-selected facts for the separately owned error-object graph.
        workspace = ctypes.create_string_buffer(131072 + session.argc * 24)
        ctypes.memmove(workspace, session.workspace, 1024)
        extras = _q(session.workspace, 80)
        if extras > session.argc:
            raise RuntimeError('invalid native CLI extra-argument extent')
        if extras:
            ctypes.memmove(ctypes.addressof(workspace) + 131072,
                           ctypes.addressof(session.workspace) + 32768 + session.argc * 48,
                           extras * 24)
        code, raw, split = self._format_call(session.raw, workspace)
        if code != 0:
            raise RuntimeError('unexpected native CLI formatter continuation')
        session.parser_formatter_facts = (_q(workspace, 1040), _q(workspace, 1064))
        return _text(raw[:split * 4]), _text(raw[split * 4:])

    def run(self, argv, cli):
        session=self.prepare(argv,cli)
        if session.kind:
            first,second=self.format_result(session)
            session.finished=True
            if session.kind==3:
                if self.parser_context is not None:
                    self.parser_context.raise_error(session,first,second)
                _print_parser_message(first,sys.stderr)
                _print_parser_message(second,sys.stderr)
            else:
                _print_parser_message(first+second,sys.stdout)
            raise SystemExit(session.exit_code)
        expression=DiscoveryExpression(self,session)
        result=expression.run()
        self.last_expression={'events':tuple(expression.route_events),'nonce':expression.nonce}
        if result==3:
            return session.run()
        session.finished=True
        return result


def _child(path, relative, expected):
    if (type(relative) is not str or not relative or Path(relative).is_absolute()
            or '..' in Path(relative).parts or type(expected) is not str or len(expected)!=64):
        raise ValueError('invalid discovery bundle child identity')
    target=(path.parent/relative).resolve(strict=True)
    if not target.is_relative_to(path.parent):
        raise ValueError('discovery bundle child left its directory')
    raw=target.read_bytes()
    if len(raw)>16384 or sha256(raw).hexdigest()!=expected:
        raise ValueError('discovery bundle child bytes differ')
    return target,raw


def installed_bundle(path, raw, bundle, *, strict=False):
    from .hia_cli_native import SOURCES,CONTROL_SCHEMA,FORMAT_SCHEMA,_relative_path
    from .hia_json_preflight_native import _unique_manifest_pairs
    keys={'schema','control_manifest','control_manifest_sha256','format_manifest',
          'format_manifest_sha256','discovery_manifest','discovery_manifest_sha256',
          'routing_manifest','routing_manifest_sha256'}
    components=('control','format','discovery','routing')
    has_context=type(bundle) is dict and bundle.get('schema')==CONTEXT_BUNDLE_SCHEMA
    if has_context:
        keys|={'parser_context_manifest','parser_context_manifest_sha256'}
        components+=('parser_context',)
    if type(bundle) is not dict or set(bundle)!=keys or bundle['schema'] not in (BUNDLE_SCHEMA,CONTEXT_BUNDLE_SCHEMA):
        raise ValueError('invalid optional discovery CLI bundle')
    path=Path(path).resolve(strict=True)
    children={name:_child(path,bundle[name+'_manifest'],bundle[name+'_manifest_sha256'])
              for name in components}
    compilers=[];images={}
    for name,(child,child_raw) in children.items():
        metadata=json.JSONDecoder(object_pairs_hook=_unique_manifest_pairs).decode(child_raw.decode('utf-8'))
        if type(metadata) is not dict or not _relative_path(metadata.get('image_path')):
            raise ValueError('invalid discovery companion image path')
        compilers.append(metadata.get('compiler_sha256'))
        if strict:
            image=(child.parent/metadata['image_path']).resolve(strict=True)
            if not image.is_relative_to(child.parent):
                raise ValueError('discovery companion image leaves its component')
            with image.open('rb') as stream:image_raw=stream.read((1<<20)+1)
            if not 0<len(image_raw)<=1<<20 or sha256(image_raw).hexdigest()!=metadata.get('image_sha256'):
                raise ValueError('native CLI child image identity mismatch')
            images[name]=(image,image_raw)
    if any(value!=compilers[0] for value in compilers[1:]):
        raise ValueError('native discovery companion compilers differ')
    sources={name:source.read_bytes() for name,source in SOURCES.items()}
    control=_load_manifest(str(children['control'][0]),children['control'][1],sha256(sources['control']).hexdigest(),CONTROL_SCHEMA,NativeHiaJsonImage)
    formatter=_load_manifest(str(children['format'][0]),children['format'][1],sha256(sources['format']).hexdigest(),FORMAT_SCHEMA,NativeHiaJsonImage)
    base=NativeCli(control,formatter)
    discovery=installed_cli_discovery_json(str(children['discovery'][0]))
    source=SOURCE.read_bytes()
    routing=_load_manifest(str(children['routing'][0]),children['routing'][1],sha256(source).hexdigest(),SCHEMA,NativeHiaJsonImage)
    parser_context=None
    if has_context:
        from .hia_cli_parser_context_native import load_context_manifest,SOURCE as context_path
        context_source=context_path.read_bytes()
        parser_context=load_context_manifest(str(children['parser_context'][0]),children['parser_context'][1],sha256(context_source).hexdigest())
        if context_path.read_bytes()!=context_source:
            raise ValueError('parser context source changed during selection')
    if (path.read_bytes()!=raw or SOURCE.read_bytes()!=source
            or any(target.read_bytes()!=value for target,value in children.values())
            or any(SOURCES[name].read_bytes()!=value for name,value in sources.items())
            or any(target.read_bytes()!=value for target,value in images.values())):
        raise ValueError('optional discovery CLI changed while loading')
    return NativeDiscoveryCli(base,discovery,routing,parser_context)
