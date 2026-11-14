"""HIA-owned native build/emission coordination with fixed foreign ports.

No retained coordinator body is called by this route. The image contains the
complete policy and controls every branch, effect preclaim, outcome and object
retirement. Python supplies actual object operations, import and context-manager
protocols; verifier, compiler subowners, linker, inspectors and publisher remain
declared separately selected dependencies.
"""
from __future__ import annotations

import builtins
import importlib
import struct
import sys

from .hia_json_preflight_native import _source_resource_path
from .hia_machine_plan_control_native import PlanFrame, NativeMachinePlanControl, _Cell, _EMPTY
# A default import must not admit a selected-only CPython ABI. Keep the
# original mutable global binding: only its untouched initial sentinel loads.
_FOREIGN_NOT_LOADED = object()
_FOREIGN_MODULE_NAMESPACE = globals()
foreign = _FOREIGN_NOT_LOADED


def _load_foreign_ports():
    global foreign
    if _FOREIGN_MODULE_NAMESPACE.get('foreign') is _FOREIGN_NOT_LOADED:
        from . import hia_native_build_foreign as foreign

SOURCE=_source_resource_path('examples/hia_bootstrap/native_build.hepta')
SCHEMA='hepta.hia.native-build-native.v1'
SELECTOR='HEPTA_HIA_NATIVE_BUILD_MANIFEST'
ARITIES={'_implementation_hash':0,'validate_block_layout_plan':2,'emit_program_machine':4,
         '_inspect_object':2,'_read_artifact':1,'_run_logged':4,'_host':0,
         'compile_program_machine':9,'build_program_machine':8,'_reject':2}
_WITH_UNKNOWN={}
_IMPORTS={
    None:frozenset(('hia_native_byte_abi','hia_machine_elf')),
    'hia_byte_policy_selection':frozenset(('native_byte_policy_scope',)),
    'hia_byte_wrapper_selection':frozenset(('native_implementation_identity',)),
    'hia_machine_object_selection':frozenset(('native_implementation_identity',)),
    'hia_json_preflight_native':frozenset(('_source_resource_path',)),
    'hia_checker_identity':frozenset(('checker_digest',)),
    'hia_machine_x64':frozenset(('native_implementation_identity','native_encoding_scope')),
    'hia_machine_elf':frozenset(('native_implementation_identity','native_elf_scope')),
    'hia_machine_plan':frozenset(('native_implementation_identity','MachinePlanRejected','validate_plan')),
    'hia_core_lowering_selection':frozenset(('native_implementation_identity','native_core_lowering_scope')),
    'hia_core_emitter_selection':frozenset(('native_implementation_identity','native_core_emitter_scope')),
    'hia_native_byte_abi_selection':frozenset(('native_implementation_identity','native_byte_abi_scope')),
    'hia_native_build_selection':frozenset(('native_implementation_identity',)),
    'hia_machine_plan_native':frozenset(('native_machine_plan_scope',)),
    'hia_program':frozenset(('verify_program','VerifiedProgram')),
    'hia_native_byte_abi':frozenset(('normalize_exports','PROFILE')),
    'hia_static_budget':frozenset(('qualify_bounded_resources',)),
}


class NativeBuildUnknown(RuntimeError):
    """An actual claimed native/foreign handoff has no confirmed outcome."""


def _match_exception(frame,slot):
    try:
        frame.image._delivery.deliver(frame.error)
    except frame._get(slot) as delivered:
        if delivered is not frame.error:
            frame._uncertain=True
            raise
        return 1
    except BaseException as delivered:
        if delivered is not frame.error:
            frame._uncertain=True
            raise
        return 0
    frame._uncertain=True
    raise NativeBuildUnknown('native-build exception matcher returned')


class NativeBuildFrame(PlanFrame):
    def __init__(self,*args,**kwargs):
        self._region_child=None
        self._region_value=_EMPTY
        self._region_returned=False
        super().__init__(*args,**kwargs)

    def _global(self,name):
        namespace=self.image.namespace
        if name=='globals' and name not in namespace:return self.image._original_globals
        if name in self.image._helpers:
            current=namespace.get(name,_EMPTY)
            if current is self.image.public_entries.get(name):
                return self.image._helpers[name]
            if current is not _EMPTY:return current
        if name in namespace:return namespace[name]
        if name in vars(builtins):return vars(builtins)[name]
        raise NameError("name '"+name+"' is not defined",name=name)

    def _move(self,slot):
        value=self._get(slot)
        self._clear(slot)
        return value

    def _load_named(self,slot,name,role):
        if type(slot) is not int or not 0<=slot<len(self.values):
            raise NativeBuildUnknown('native-build named slot is outside the frame')
        value=self.values[slot]
        if slot in self.cells:value=value.value
        if value is _EMPTY:
            return foreign.unbound(name,role)
        return value

    def _call(self,args,raw):
        if raw==(0,251):
            if args:raise NativeBuildUnknown('native-build re-raise operands differ')
            raise
        if raw==(0,253):
            if len(args)!=2 or type(self._get(args[0])) is not dict:
                raise NativeBuildUnknown('native-build dictionary-update representation differs')
            return foreign.update_dict(self,*args)
        if raw==(0,254):
            if len(args)!=3 or type(self._get(args[1])) is not tuple:
                raise NativeBuildUnknown('native-build mapping-prepare representation differs')
            return foreign.merge_empty(self,*args)
        if raw==(0,255):
            if len(args)!=3:raise NativeBuildUnknown('native-build mapping-call representation differs')
            return foreign.mapping_call(self,*args)
        if len(raw)<2 or len(raw)!=2+raw[1] or len(args)!=1+raw[0]+raw[1]:
            raise NativeBuildUnknown('native-build ordinary CALL representation differs')
        key=(raw[0],tuple(self.image.literal(i) for i in raw[2:]))
        call=foreign.CALLS.get(key)
        if call is None:raise NativeBuildUnknown('native-build CALL shape differs from fixed policy')
        return call(self,args)

    def _function(self,args,raw,vector):
        mode,generator=raw
        captures=tuple(self.values[slot] for slot in vector)
        if any(type(cell) is not _Cell for cell in captures):
            raise NativeBuildUnknown('native-build closure captured a non-cell')
        if generator:
            frame=NativeBuildFrame(self.image,mode,(self._get(args[0]),),captures)
            def native_generator():
                value=None
                try:
                    while True:
                        value=None
                        if frame.drive()==0:return
                        value=frame.take(yielded=True)
                        yield value
                finally:value=None
            return native_generator()
        image=self.image
        def native_function(*arguments):
            frame=NativeBuildFrame(image,mode,arguments,captures)
            arguments=None
            return image.finish(frame)
        return native_function

    def _drive_region(self,mode,vector):
        captures=tuple(self.values[slot] for slot in vector)
        if any(type(cell) is not _Cell for cell in captures):
            raise NativeBuildUnknown('native-build with region captured a non-cell')
        child=NativeBuildFrame(self.image,mode,(),captures)
        self._region_child=child
        captures=None
        child.handled=self.handled
        self._region_value=self.image.finish(child)
        if type(self._region_value) is not tuple or len(self._region_value)!=2:
            self._uncertain=True
            raise NativeBuildUnknown('native-build region lacks its HIA terminal record')
        self._region_returned=True

    def _with_region(self,manager,mode,target,vector):
        if self._region_child is not None or self._region_value is not _EMPTY:
            self._uncertain=True
            raise NativeBuildUnknown('native-build context-manager port is reentered')
        self._region_returned=False
        try:
            if target==65535:
                with self._move(manager):
                    self._drive_region(mode,vector)
            else:
                with self._move(manager) as entered:
                    self._set(target,entered)
                    entered=None
                    self._drive_region(mode,vector)
            child=self._region_child
            if (child is None or child._uncertain or not child.closed
                    or not child._terminal_taken or child.pending is not None):
                self._uncertain=True
                raise NativeBuildUnknown('context manager suppressed an unconfirmed HIA body')
            if self._region_returned:
                if child._status!=5 or not child._retired:
                    self._uncertain=True
                    raise NativeBuildUnknown('context manager returned a non-successful HIA body')
                return self._region_value,1
            if child._status!=3:
                self._uncertain=True
                raise NativeBuildUnknown('context manager has no confirmed suppressed exception')
            return None,0
        finally:
            child=self._region_child
            if self._uncertain or (child is not None and child._uncertain):
                self._uncertain=True
                _WITH_UNKNOWN[self.nonce]=self
            else:
                self._region_value=_EMPTY
                self._region_child=None

    def service(self,issued):
        super().service(issued)
        if self._uncertain:
            _WITH_UNKNOWN[self.nonce]=self
            self.close(release=False)
            raise NativeBuildUnknown('native-build claimed foreign outcome is unconfirmed')

    def _effect(self):
        op,destinations,args,raw,vector=self._parts()
        if op==9 and len(raw)==3 and raw[1]==250:
            if len(args)!=1 or len(destinations)!=1:
                raise NativeBuildUnknown('native-build with-region representation differs')
            result,flag=self._with_region(args[0],raw[0],raw[2],vector)
            # CALL keeps its original canonical zero ACK. Its fixed outcome
            # envelope is inspected by subsequent HIA UNPACK/TRUTH requests;
            # no new truth/branch authority is added to the shared engine.
            self._set(destinations[0],(flag,result))
            result=None
            return 0
        if op==19:
            if len(raw)<2 or len(destinations)!=1 or vector:
                raise NativeBuildUnknown('native-build import representation differs')
            if raw[0]==0 and not args:
                module=self.image.literal(raw[1])
                names=tuple(self.image.literal(i) for i in raw[2:])
                if module not in _IMPORTS or any(name not in _IMPORTS[module] for name in names):
                    raise NativeBuildUnknown('native-build module import is outside its fixed ports')
                port=self.image._import_names.get((module,names))
                if port is None:raise NativeBuildUnknown('native-build import group differs')
                self._set(destinations[0],port())
            elif raw[0]==1 and len(raw)==2 and len(args)==1:
                name=self.image.literal(raw[1])
                port=self.image._import_from.get(name)
                if port is None:raise NativeBuildUnknown('native-build imported field differs')
                self._set(destinations[0],port(self._get(args[0])))
            else:raise NativeBuildUnknown('native-build import phase differs')
            return 0
        if op==15 and raw:
            if len(raw)!=2 or len(args)!=1 or len(destinations)!=1 or vector:
                raise NativeBuildUnknown('native-build named-load representation differs')
            self._set(destinations[0],self._load_named(args[0],self.image.literal(raw[0]),raw[1]))
            return 0
        if op==21:
            if len(args)!=1 or destinations or raw or vector:
                raise NativeBuildUnknown('native-build exception matcher representation differs')
            return _match_exception(self,args[0])
        return super()._effect()


class NativeBuild(NativeMachinePlanControl):
    def __init__(self,image,expected_sha256,namespace=None):
        super().__init__(image,expected_sha256)
        self._bind_namespace(namespace)

    def literal(self,index):
        if type(index) is int and 0<=index<self._literal_count and index not in self._literals:
            at=struct.unpack_from('<I',self.table,self._literal_offsets+4*index)[0]
            kind,size=struct.unpack_from('<BQ',self.table,at)
            if kind==5:
                if at+9+size>len(self.table):raise NativeBuildUnknown('native-build bytes literal extent differs')
                self._literals[index]=self.table[at+9:at+9+size]
        if index in self._literals:return self._literals[index]
        return super().literal(index)

    def _bind_namespace(self,namespace=None):
        _load_foreign_ports()
        from . import hia_program_native
        if namespace is None:namespace=vars(hia_program_native)
        if type(namespace) is not dict:raise TypeError('native-build requires its actual module namespace')
        self.namespace=namespace
        self._import_names,self._import_from=foreign.import_ports(namespace)
        self.public_entries=vars(hia_program_native).get('_NATIVE_BUILD_PUBLIC_ENTRIES',
            {name:vars(hia_program_native).get(name) for name in ARITIES})
        self.modes={name:(i,arity) for i,(name,arity) in enumerate(ARITIES.items(),1)}
        for mode,arity in self.modes.values():
            if self.function(mode)[2]!=arity:raise NativeBuildUnknown('native-build public arity differs')
        def original_globals():return self.namespace
        self._original_globals=original_globals
        # These are exact-signature dispatch facades, not policy implementations.
        def implementation_hash():return self.finish(self.prepare('_implementation_hash',()))
        def validate_block_layout_plan(program,machine_plan):
            frame=self.prepare('validate_block_layout_plan',(program,machine_plan));program=machine_plan=None
            return self.finish(frame)
        def emit_program_machine(program,*,target=hia_program_native.TARGET,machine_plan=None,foreign_buffer_exports=()):
            frame=self.prepare('emit_program_machine',(program,target,machine_plan,foreign_buffer_exports))
            program=target=machine_plan=foreign_buffer_exports=None
            return self.finish(frame)
        def inspect_object(data,exports):
            frame=self.prepare('_inspect_object',(data,exports));data=exports=None
            return self.finish(frame)
        def read_artifact(path):
            frame=self.prepare('_read_artifact',(path,));path=None
            return self.finish(frame)
        def run_logged(argv,*,command_log=None,parent_death_guard=False,**kwargs):
            frame=self.prepare('_run_logged',(argv,command_log,parent_death_guard,kwargs))
            argv=command_log=parent_death_guard=kwargs=None
            return self.finish(frame)
        def host():return self.finish(self.prepare('_host',()))
        def compile_program_machine(image,*,program,output,kind='shared',linker='cc',command_log=None,
                                    machine_plan=None,parent_death_guard=False,timeout_seconds=None):
            frame=self.prepare('compile_program_machine',(image,program,output,kind,linker,command_log,
                machine_plan,parent_death_guard,timeout_seconds))
            image=program=output=kind=linker=command_log=machine_plan=parent_death_guard=timeout_seconds=None
            return self.finish(frame)
        def build_program_machine(document,output,*,kind='shared',linker='cc',target=hia_program_native.TARGET,
                                  command_log=None,bounded_resource_limits=None,foreign_buffer_exports=()):
            frame=self.prepare('build_program_machine',(document,output,kind,linker,target,command_log,
                bounded_resource_limits,foreign_buffer_exports))
            document=output=kind=linker=target=command_log=bounded_resource_limits=foreign_buffer_exports=None
            return self.finish(frame)
        def reject(message,code='E_HIA_PROGRAM_NATIVE'):
            frame=self.prepare('_reject',(message,code));message=code=None
            return self.finish(frame)
        self._helpers=dict(zip(ARITIES,(implementation_hash,validate_block_layout_plan,emit_program_machine,
            inspect_object,read_artifact,run_logged,host,compile_program_machine,build_program_machine,reject)))
        for name,function in self._helpers.items():
            function.__name__=function.__qualname__=name;function.__module__=hia_program_native.__name__

    def prepare(self,name,arguments,captures=(),*,witness=None):
        if type(name) is str:
            mode,arity=self.modes[name]
            if type(arguments) is not tuple or len(arguments)!=arity:
                raise TypeError('native-build argument arity differs')
        else:mode=name
        return NativeBuildFrame(self,mode,arguments,captures,witness=witness)

    def finish(self,frame):
        returned=False
        try:
            if frame.drive()!=0:raise NativeBuildUnknown('native-build public entry yielded')
            returned=True
            return frame.take()
        except BaseException:
            returned=False
            raise
        finally:frame.close(release=returned)

    def run(self,mode,*arguments,_captures=(),_witness=None):
        frame=self.prepare(mode,arguments,_captures,witness=_witness)
        arguments=_captures=None
        return self.finish(frame)


def installed_native_build(manifest_path):
    from .hia_native_build_selection import installed_native_build as admitted
    return admitted(manifest_path)
