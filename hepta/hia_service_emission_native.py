"""Explicit HIA Agent emission policy with pinned executable custody.

HIA issues the emission/compilation/signature decisions, iteration and one-use
effect claims. Python retains real object identities and executes fixed ports.
The physical emission-manager protocol, scalar foreign numeric protocols and
the existing verifier, machine emitter, linker, file and artifact providers
remain explicit dependencies; this owner is not a whole-runtime claim.
"""
from __future__ import annotations
import ctypes
from dataclasses import dataclass
from functools import lru_cache
from hashlib import sha256
import json
import os
from pathlib import Path
import stat
import struct
import sys
import threading
from .hia_json_preflight_native import NativeHiaJsonImage, _source_resource_path
from .hia_exception_delivery import ExceptionDelivery

SOURCE=_source_resource_path('examples/hia_bootstrap/service_emission.hepta')
SCHEMA='hepta.hia.service-emission-native.v2'
SELECTOR='HEPTA_HIA_SERVICE_EMISSION_MANIFEST'
REQUEST_MAGIC=int.from_bytes(b'HIAEMQ01','little')
RESULT_MAGIC=int.from_bytes(b'HIAEMR01','little')
STATE_BYTES=128
TEMPORARIES=('receipts_iterator', 'subject_fields', 'checks_iterator', 'check_value', 'compile_kind', 'compile_remaining', 'compile_kwargs', 'metadata_fields', 'export_list', 'export_iterator', 'export_pair', 'build_document', 'clock_first', 'quotient', 'manager', 'publisher_callee', 'object_metadata', 'object_artifact_result', 'functions_iterator_comp', 'fn_comp', 'parameter_iterator_check', 'p_check', 'return_iterator_check', 'typ_check', 'signature_key', 'parameter_list', 'parameter_iterator_build', 'p_build', 'signature_value_fields', 'signature_value', 'functions_iterator_outer', 'parameter_iterator_outer', 'p_outer', 'outer_signature_fields', 'outer_signature_value', 'outer_signature_key', 'path_left', 'compile_callee', 'clock_second', 'difference', 'floor', 'timeout_value', 'yield_value')
LOCAL_SLOTS=('service_local', 'args', 'context', 'program', 'ref', 'codegen', 'plan', '_', 'receipt', 'expected_subject', 'exports', 'data', 'native_build', 'pair', 'metadata', 'artifact', 'kind', 'machine_plan', 'timeout_ms', 'foreign_buffer_exports', 'emit_program_machine', 'compile_program_machine', 'deadline', 'image', 'object_bytes', 'commands', 'directory', 'output', 'build_result', 'normalize_exports', 'BUFFER_PROFILE', 'document', 'fn', 'p', 'signatures', 'WIDTHS', 'iterator', 'item')
PREDICATES=frozenset([5, 8, 19, 21, 22, 35, 49, 202, 208, 215, 216, 218, 219, 220, 404, 405, 411, 419, 432, 433, 435, 702, 709, 712, 801, 802, 851, 852, 1001, 1003])

class EmissionUnknown(RuntimeError):
    """An effect or native acknowledgement is unconfirmed; never a rejection."""

_UNCONFIRMED_IMAGE_CLEANUP = []
_UNCONFIRMED_LOCAL_RETIREMENTS = []

def _runtime_profile():
    if sys.implementation.name != 'cpython' or sys.version_info[:2] not in ((3, 12), (3, 13), (3, 14)):
        raise EmissionUnknown('emission local retirement requires the reviewed CPython 3.12, 3.13 or 3.14 ABI')
    return sys.version_info.major * 100 + sys.version_info.minor

class NativeEmissionImage(NativeHiaJsonImage):
    def __init__(self, image, expected_sha256):
        super().__init__(image, expected_sha256)
        try:
            self.delivery = ExceptionDelivery.from_hia(self)
        except BaseException:
            # This object was never returned or admitted. Do not retain a live
            # entry point merely because the original exception keeps its
            # constructor traceback. Only these private mappings are retired.
            self._entry = None
            for resource in (getattr(self, 'delivery', None), self._mapping):
                if resource is not None:
                    try:
                        resource.close()
                    except BaseException:
                        _UNCONFIRMED_IMAGE_CLEANUP.append((self, resource))
            raise

def admitted_emission(*, capture_identity=False):
    selected = os.environ.get(SELECTOR)
    if not selected:
        return None
    return installed_emission(selected, capture_identity=capture_identity)

def _manifest_pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError('duplicate service-emission manifest field')
        value[key] = item
    return value

def _regular_bytes(path, limit):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError('service-emission input must be a bounded ordinary file')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if (len(raw) != before.st_size
            or any(getattr(before, name) != getattr(after, name) for name in fields)):
        raise ValueError('service-emission input changed while being read')
    return raw

@lru_cache(maxsize=3)
def _mapped_emission(image, image_sha256):
    return NativeEmissionImage(image, image_sha256)

def installed_emission(manifest_path, *, capture_identity=False):
    """Fresh complete manifest/source/image reads before each new selection.

    The returned service owner keeps the selected immutable image. A later
    selector or disk change cannot replace that held image. A new selection
    still checks every actual byte, including when the immutable map is cached.
    An active explicit worker bundle remains the authority; no ambient fallback
    is introduced for a component not yet registered in that bundle family.
    """
    from .hia_native_helpers import pinned_image
    selected = pinned_image(manifest_path, SOURCE, SCHEMA, NativeEmissionImage)
    path = Path(manifest_path).resolve(strict=True)
    raw = _regular_bytes(path, 16384)
    value = json.loads(raw, object_pairs_hook=_manifest_pairs)
    if (type(value) is not dict or set(value) != {
            'schema', 'source_sha256', 'image_path', 'image_sha256', 'compiler_sha256'}
            or value['schema'] != SCHEMA
            or any(type(value[name]) is not str or len(value[name]) != 64
                   or any(char not in '0123456789abcdef' for char in value[name])
                   for name in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('invalid service-emission manifest')
    name = value['image_path']
    if (type(name) is not str or not name or name in ('.', '..')
            or any(ord(char) < 32 for char in name) or Path(name).name != name):
        raise ValueError('service-emission image must be a sibling basename')
    source_raw = _regular_bytes(SOURCE, 8 << 20)
    if sha256(source_raw).hexdigest() != value['source_sha256']:
        raise ValueError('service-emission source identity mismatch')
    image_path = path.parent / name
    image_raw = _regular_bytes(image_path, 1 << 20)
    if sha256(image_raw).hexdigest() != value['image_sha256']:
        raise ValueError('service-emission image identity mismatch')
    if selected is None:
        selected = _mapped_emission(image_raw, value['image_sha256'])
    elif type(selected) is not NativeEmissionImage or selected.image_sha256 != value['image_sha256']:
        raise ValueError('service-emission selection differs from its pinned worker image')
    if (_regular_bytes(path, 16384) != raw or _regular_bytes(SOURCE, 8 << 20) != source_raw
            or _regular_bytes(image_path, 1 << 20) != image_raw):
        raise ValueError('service-emission selection changed during admission')
    if capture_identity:
        from .hia_checker_identity import hold_native_owner
        return hold_native_owner(SELECTOR, selected, raw, source_raw)
    return selected

@dataclass(frozen=True)
class EmissionReceipt:
    words: tuple[int, ...]
    raw: bytes

    @property
    def action(self):
        return self.words[3]

    @property
    def sequence(self):
        return self.words[4]

    @property
    def stage(self):
        return self.words[5]

class EmissionState:
    def __init__(self, owner, mode, data):
        self.owner, self.mode, self.data = owner, mode, data
        self.profile = owner.profile
        self._retiring = False
        self._retired = False
        self.retirement_thread = None
        self.creator, self.thread = os.getpid(), threading.get_ident()
        self.identity = struct.unpack('<2Q', os.urandom(16))
        self.buffer = ctypes.create_string_buffer(STATE_BYTES)
        self.receipt = None
        self.fenced = False
        self.closed = False
        self.error = None
        self.child = None

    def check(self):
        retiring = self._retiring and self.owner.retiring.get(self.identity) is self
        if ((self.closed or self.owner.closed) and not retiring or self.fenced or self.creator != os.getpid()
                or (self.retirement_thread if retiring else self.thread) != threading.get_ident()
                or self.owner.active.get(self.identity) is not self and not retiring):
            raise EmissionUnknown('emission continuation is not live in its original owner, process and thread')

    def call(self, event, observation=0):
        self.check()
        if (type(event) is not int or type(observation) is not int
                or not 0 <= event <= 7 or not 0 <= observation <= 3):
            raise EmissionUnknown('emission packet does not have exact integer fields')
        sequence = 0 if self.receipt is None else self.receipt.sequence
        raw = struct.pack('<8Q', REQUEST_MAGIC, event, sequence, *self.identity,
                          observation, self.mode, self.profile)
        source = ctypes.create_string_buffer(raw, len(raw))
        output = ctypes.create_string_buffer(144)
        try:
            size = self.owner.image._entry(source, len(raw), output, len(output), self.buffer, len(self.buffer))
            self.check()
            if type(size) is not int or size != 144 or source.raw != raw:
                raise EmissionUnknown('emission native ABI refused or changed its request')
            returned = output.raw
            if struct.unpack('<2Q', returned[:16]) != (RESULT_MAGIC, 0):
                raise EmissionUnknown('emission native receipt is not a successful exact result')
            owned = self.buffer.raw
            if returned[16:] != owned:
                raise EmissionUnknown('emission native receipt differs from its retained state')
            words = struct.unpack('<16Q', owned)
            if (words[1] != 2 or words[2] != self.mode or words[6:8] != self.identity
                    or words[9] >= (1 << len(TEMPORARIES)) or words[10] not in (0, 1)
                    or words[12] != self.profile or words[13] > 16 or words[14] > 3
                    or words[15] not in (0, 5, 7)):
                raise EmissionUnknown('emission native receipt belongs to a different operation')
            receipt = EmissionReceipt(words, owned)
            self.receipt = receipt
            return receipt
        except EmissionUnknown:
            self.fenced = True
            raise
        except Exception as error:
            self.fenced = True
            raise EmissionUnknown('emission native call or receipt handoff is unconfirmed') from error
        except BaseException:
            self.fenced = True
            raise

    def retire(self):
        """Consume HIA-issued original-local slots, never infer a retry grant.

        Normal returns retire before returning the actual result. A confirmed
        original error retains its locals on the real traceback; __del__ calls
        this same HIA continuation only when that state actually becomes dead.
        The internal with-body shares its parent's scope and cannot retire it.
        """
        if self.mode == 4 or self._retired:
            return
        if self._retiring:
            raise EmissionUnknown('emission local retirement is already in progress')
        if (self.fenced or self.receipt is None or self.receipt.stage not in (5, 7)
                or self.receipt.raw != self.buffer.raw):
            raise EmissionUnknown('emission locals lack confirmed terminal custody')
        self.retirement_thread = threading.get_ident()
        self._retiring = True
        self.owner.retiring[self.identity] = self
        try:
            self.call(7)
            while self.receipt.stage == 9:
                receipt = self.receipt
                if (type(receipt) is not EmissionReceipt or type(receipt.words) is not tuple
                        or len(receipt.words) != 16 or any(type(word) is not int for word in receipt.words)
                        or receipt.raw != struct.pack('<16Q', *receipt.words)
                        or receipt.raw != self.buffer.raw
                        or not 1100 <= receipt.action < 1100 + len(LOCAL_SLOTS)):
                    raise EmissionUnknown('emission retirement is not the exact issued local slot')
                claimed = self.call(1)
                if (claimed.stage != 10 or claimed.action != receipt.action
                        or claimed.sequence != receipt.sequence):
                    raise EmissionUnknown('emission local retirement preclaim was not confirmed')
                self.data.pop(LOCAL_SLOTS[claimed.action - 1100], None)
                self.call(2)
            if self.receipt.stage != 11 or self.receipt.action != 0:
                raise EmissionUnknown('emission original-local retirement did not complete')
            self._retired = True
            self._retiring = False
            self.retirement_thread = None
            self.owner.retiring.pop(self.identity)
        except BaseException:
            self.fenced = True
            self.owner.unknown[self.identity] = self
            raise

    def __del__(self):
        # No clearing of unconfirmed or partially prepared operations. Their
        # retained owner remains the authority. A known error has already been
        # removed from active; its original traceback controls this point.
        if (getattr(self, 'mode', 4) == 4 or getattr(self, '_retired', False)
                or getattr(self, 'receipt', None) is None):
            return
        if self.receipt.stage not in (5, 7):
            return
        try:
            self.retire()
        except BaseException:
            _UNCONFIRMED_LOCAL_RETIREMENTS.append(self)

    def invoke(self, receipt):
        self.check()
        if (receipt is not self.receipt or type(receipt) is not EmissionReceipt
                or type(receipt.words) is not tuple or len(receipt.words) != 16
                or any(type(word) is not int for word in receipt.words)
                or receipt.raw != struct.pack('<16Q', *receipt.words)
                or receipt.raw != self.buffer.raw or receipt.stage != 1):
            raise EmissionUnknown('foreign operation is not the current exact HIA result')
        action, sequence = receipt.action, receipt.sequence
        claimed = self.call(1)
        if claimed.stage != 2 or claimed.action != action or claimed.sequence != sequence:
            raise EmissionUnknown('emission effect preclaim was not confirmed')
        captured = error = None
        try:
            captured = self._capture_effect(action)
            if not captured[0]:
                error = captured[1]
                # The catcher has returned: temporary retirement must observe
                # the original outer handled exception, not this returned one.
                if self.receipt.words[10]:
                    raise EmissionUnknown('emission error retirement outcome is unconfirmed') from error
                self.error = error
                if isinstance(error, EmissionUnknown) or not isinstance(error, Exception):
                    self.owner.delivery.deliver(error)
                self.call(3)
                self._finish_error()
                raise EmissionUnknown('emission original error delivery returned unexpectedly')
            observed = captured[1]
            if action in (211, 407, 413):
                limit=3 if action==211 else 2
                if type(observed) is not int or not 0 <= observed <= limit:
                    raise EmissionUnknown('with mechanism did not return attested local flags')
                observation = observed
            elif action in PREDICATES:
                if type(observed) is not bool:
                    raise EmissionUnknown('emission foreign predicate did not return an exact bool')
                observation = int(observed)
            else:
                if observed is not None:
                    raise EmissionUnknown('emission foreign void operation returned a value')
                observation = 0
            return self.call(2, observation)
        finally:
            captured = error = None

    def _capture_effect(self, action):
        try:
            return True, self._effect(action)
        except BaseException as error:
            return False, error

    def _finish_error(self):
        error = self.error
        try:
            while self.receipt.stage == 1:
                if not 900 <= self.receipt.action < 900 + len(TEMPORARIES):
                    raise EmissionUnknown('emission error cleanup issued a business operation')
                self.invoke(self.receipt)
            if self.receipt.stage != 4 or self.receipt.words[10] != 1:
                raise EmissionUnknown('emission error cleanup did not finish')
            delivered = self.call(4)
            if delivered.stage != 7 or delivered.words[9]:
                raise EmissionUnknown('emission original error lacks consumed delivery permission')
            self.owner.delivery.deliver(error)
        finally:
            # The original exception remains rooted on the state until the
            # public run handler observes that exact delivered instance. Loss
            # between native grant and physical delivery cannot become a
            # successful terminal error merely because stage 7 was reached.
            error = None

    def _next(self, iterator, target):
        # Only StopIteration raised by this exact next operation is consumed.
        # A returned object is assigned with the original for-target lifetime.
        try:
            self.data[target] = next(self.data[iterator])
        except StopIteration:
            del self.data[iterator]
            return False
        return True


    def _next_check(self):
        child,generator=self.data['checks_iterator']
        try: self.data['check_value']=next(generator)
        except StopIteration:
            if child.receipt is None or child.receipt.stage!=11 or child.receipt.words[15]!=5 or not child.closed:
                raise EmissionUnknown('check generator ended without native completion')
            self.data.pop('checks_iterator')
            return False
        if child.receipt.stage!=8:
            raise EmissionUnknown('check generator yield lacks native consumption')
        return True

    def _next_predicate(self,name):
        child,generator=self.data[name]
        try: value=next(generator)
        except StopIteration:
            if child.receipt is None or child.receipt.stage!=11 or child.receipt.words[15]!=5 or not child.closed:
                raise EmissionUnknown('generator ended without native completion')
            self.data.pop(name)
            return 2
        if type(value) is not bool or child.receipt.stage!=8:
            raise EmissionUnknown('generator yield lacks native consumption')
        return int(value)

    def _close_predicate(self,name):
        child,generator=self.data[name]
        if self.receipt.stage!=2 or self.receipt.action not in (24,410,416):
            raise EmissionUnknown('generator cancellation lacks parent permission')
        child.call(6)
        generator.close()
        self.owner._finish_generator(child)
        self.data.pop(name)

    def _with_body(self):
        """Only the interpreter's context-manager mechanism is hosted here.

        No build decision or provider call is present in this body: each is
        issued by the internal HIA mode. The ordinary with statement preserves
        actual-version special lookup, enter/exit diagnostics and suppression.
        A suppressed *unknown* child cannot produce a confirmed local mask.
        """
        if self.child is not None:
            raise EmissionUnknown('with continuation has already acquired a child')
        with self.data.pop('manager') as directory:
            self.data['directory'] = directory
            # The original function owns the as-target in its named scope;
            # this fixed with mechanism must not add a second target owner.
            directory = None
            self.child = self.owner._new_state(4, self.data, parent=self)
            self.owner._drive(self.child, clear_locals=False)
        child = self.child
        if (child is None or child.receipt is None or child.receipt.stage not in (5, 7)
                or child.fenced or not child.closed or child.identity in self.owner.active
                or child.receipt.raw != child.buffer.raw):
            raise EmissionUnknown('context manager suppressed an unconfirmed HIA body')
        flags = child.receipt.words[14]
        self.child = None
        return flags

    def _effect(self, action):
        from . import hia_agent_service as api
        d,s=self.data,self.owner.service
        if 900 <= action < 900+len(TEMPORARIES):
            d.pop(TEMPORARIES[action-900],None)
            return None
        if action == 1: s._profile(d['args']['backend_profile'],'backend')
        elif action == 2: d['context']=s._context(d['args']['context'])
        elif action == 3: d['program']=s._program(d['args']['candidate'])
        elif action == 4: d['receipts_iterator']=iter(d['args']['verification_receipts'])
        elif action == 5: return self._next('receipts_iterator','ref')
        elif action == 6: s._verification(d['ref'],d['args']['context'],d['args']['candidate'])
        elif action == 7: d['codegen'],d['plan']=d['args']['codegen'],None
        elif action == 8:
            if d['codegen']['kind']=='canonical': return True
            return False
        elif action == 9: s._profile(d['codegen']['lowering_profile'],'lowering')
        elif action == 10: s._profile(d['codegen']['plan_profile'],'plan')
        elif action == 11: d['plan'],d['_']=s.store.get_json(d['codegen']['plan'])
        elif action == 12: api.validate(d['plan'],api.PLAN_SCHEMA,'machine_plan')
        elif action == 13: d['receipt']=s._verification(d['codegen']['verification_receipt'],d['args']['context'],d['args']['candidate'])
        elif action == 14: d['subject_fields']=['agent_machine_plan']
        elif action == 15: d['subject_fields'].append(d['args']['backend_profile'])
        elif action == 16: d['subject_fields'].append(d['codegen']['plan_profile'])
        elif action == 17: d['subject_fields'].append(d['codegen']['plan'])
        elif action == 18: d['expected_subject']=dict(zip(('kind','backend_profile','plan_profile','plan'),d.pop('subject_fields')))
        elif action == 19:
            if d['receipt']['subject']!=d['expected_subject']: return True
            return False
        elif action == 20:
            iterator=iter(d['receipt']['checks'])
            d['checks_iterator']=self.owner._predicates(7,iterator,None,parent=self)
        elif action == 21: return self._next_check()
        elif action == 22:
            if d.pop('check_value'): return True
            return False
        elif action == 24: self._close_predicate('checks_iterator')
        elif action == 29: api.reject('E_HIA_PLAN_RECEIPT','plan lacks an exact subject-bound qualified layout receipt','codegen')
        elif action == 30: d['exports']=tuple(map(tuple,d['context'].get('foreign_buffer_exports',[])))
        elif action == 31: d['compile_callee']=s._compile
        elif action == 32: d['compile_kind']=d['args']['output_kind']
        elif action == 33: d['compile_remaining']=s._remaining_ms(d['context'])
        elif action == 35:
            if d['exports']: return True
            return False
        elif action == 36: d['compile_kwargs']={'foreign_buffer_exports':d['exports']}
        elif action == 37: d['compile_kwargs']={}
        elif action == 38:
            d['data'],d['native_build']=d.pop('compile_callee')(d['program'],d.pop('compile_kind'),d['plan'],d.pop('compile_remaining'),**d.pop('compile_kwargs'))
        elif action == 40: d['metadata_fields']=[d['args']['context']]
        elif action == 41: d['metadata_fields'].append(d['args']['candidate'])
        elif action == 42: d['metadata_fields'].append(d['program'].sha256)
        elif action == 43: d['metadata_fields'].append(d['args']['output_kind'])
        elif action == 44: d['metadata_fields'].append(d['codegen'])
        elif action == 45: d['metadata_fields'].append(d['plan'])
        elif action == 46: d['metadata_fields'].append(s.identities)
        elif action == 47: d['metadata_fields'].append(self.owner.signatures(d['program'],d['exports']))
        elif action == 48:
            d['export_list']=[];d['export_iterator']=iter(d['exports'])
        elif action == 49: return self._next('export_iterator','export_pair')
        elif action == 50: d['export_list'].append(list(d['export_pair']))
        elif action == 51:
            d.pop('export_pair',None);d['metadata_fields'].append(d.pop('export_list'))
        elif action == 52: d['metadata_fields'].append(d['native_build']['object_artifact'])
        elif action == 53: d['metadata_fields'].append(d['native_build']['object_sha256'])
        elif action == 54:
            d['metadata']=dict(zip(('context','candidate','core_sha256','output_kind','codegen','machine_plan',
                'installation','signatures','foreign_buffer_exports','object_artifact','object_sha256'),d.pop('metadata_fields')))
        elif action == 55: d['artifact']=s.store.put(d['data'],'native',d['metadata'])
        elif action == 56: d['build_document']={'schema':'hepta.hia.agent.build.v1',**d['metadata']}
        elif action == 57: d['build_document']['native_artifact']=d['artifact']
        elif action == 58: d['build_document']['native_build']=d['native_build']
        elif action == 59: d['build_document']['backend_profile']=d['args']['backend_profile']
        elif action == 60: d['build_document']['target_profile']=d['context']['target_profile']
        elif action == 61: d['build_document']['verification_receipts']=d['args']['verification_receipts']
        elif action == 62: d['receipt']=s.store.json(d.pop('build_document'),'build-receipt')
        elif action == 63:
            d['result']={'candidate':d['args']['candidate'],'native_artifact':d['artifact'],'build_receipt':d['receipt'],
                'backend_profile':d['args']['backend_profile'],'target_profile':d['context']['target_profile'],
                'codegen_backend':'hia-direct','llvm_codegen_used':False,'external_assembler_used':False,
                'linker_used':d['args']['output_kind']=='shared','native_execution_observed':False,'adopted':False}
        elif action == 201:
            from .hia_program_native import emit_program_machine,compile_program_machine
            d['emit_program_machine'],d['compile_program_machine']=emit_program_machine,compile_program_machine
        elif action == 202:
            if d['timeout_ms']<=0: return True
            return False
        elif action == 203: d['clock_first']=api.time.monotonic()
        elif action == 204: d['quotient']=d['timeout_ms']/1000
        elif action == 205: d['deadline']=d.pop('clock_first')+d.pop('quotient')
        elif action == 206: d['image']=d['emit_program_machine'](d['program'],machine_plan=d['machine_plan'],foreign_buffer_exports=d['foreign_buffer_exports'])
        elif action == 207: d['object_bytes']=d['image'].object_bytes
        elif action == 208: return type(d['object_bytes']) is bytes
        elif action == 209: d['commands']=[]
        elif action == 210: d['manager']=api.tempfile.TemporaryDirectory(prefix='build-',dir=s.store.root)
        elif action == 211: return self._with_body()
        elif action == 213: d['build_result'].pop('output',None)
        elif action == 214: d['build_result']['commands']=d['commands']
        elif action == 215:
            if d['build_result'].get('object_sha256')!=api.sha256(d['object_bytes']).hexdigest(): return True
            return False
        elif action == 216:
            if d['build_result'].get('core_sha256')!=d['program'].sha256: return True
            return False
        elif action == 218:
            if d['build_result'].get('artifact_sha256')!=api.sha256(d['data']).hexdigest(): return True
            return False
        elif action == 219:
            if d['kind']=='object': return True
            return False
        elif action == 220:
            if d['data']!=d['object_bytes']: return True
            return False
        elif action == 221: d['publisher_callee']=s.store.put
        elif action == 222:
            d['object_metadata']={'schema':'hepta.hia.agent.build-object.v1','core_sha256':d['program'].sha256,
                'machine_plan_sha256':d['build_result']['machine_plan_sha256'],'installation':s.identities}
        elif action == 223: d['object_artifact_result']=d.pop('publisher_callee')(d['object_bytes'],'build-object',d.pop('object_metadata'))
        elif action == 224: d['build_result']['object_artifact']=d.pop('object_artifact_result')
        elif action == 225: d['result']=(d['data'],d['build_result'])
        elif action == 290: api.reject('E_HIA_BUDGET','frozen context deadline expired before emission','codegen')
        elif action == 291: api.reject('E_HIA_RECEIPT_BINDING','emission did not produce immutable object bytes','codegen')
        elif action == 292: api.reject('E_HIA_RECEIPT_BINDING','native build metadata differs from the actual emitted bytes','codegen')
        elif action == 294: _unbound_result()
        elif action == 295: _unbound_data()
        elif action == 401:
            from .hia_program_native import WIDTHS
            from .hia_native_byte_abi import normalize_exports
            from .hia_agent_buffers import PROFILE as BUFFER_PROFILE
            d['WIDTHS'],d['normalize_exports'],d['BUFFER_PROFILE']=WIDTHS,normalize_exports,BUFFER_PROFILE
        elif action == 402: d['document']=d['program'].as_dict()
        elif action == 403:
            d['signatures']={};d['functions_iterator_comp']=iter(d['document']['functions'])
        elif action == 404: return self._next('functions_iterator_comp','fn_comp')
        elif action == 405:
            if d['fn_comp']['name'] in d['program'].scalar_entrypoints: return True
            return False
        elif action == 406:
            iterator=iter(d['fn_comp']['params'])
            d['parameter_iterator_check']=self.owner._predicates(5,iterator,d['WIDTHS'],parent=self)
        elif action == 407: return self._next_predicate('parameter_iterator_check')
        elif action == 409: pass
        elif action == 410: self._close_predicate('parameter_iterator_check')
        elif action == 411:
            if len(d['fn_comp']['returns'])<=1: return True
            return False
        elif action == 412:
            iterator=iter(d['fn_comp']['returns'])
            d['return_iterator_check']=self.owner._predicates(6,iterator,d['WIDTHS'],parent=self)
        elif action == 413: return self._next_predicate('return_iterator_check')
        elif action == 415: pass
        elif action == 416: self._close_predicate('return_iterator_check')
        elif action == 417: d['signature_key']=d['fn_comp']['name']
        elif action == 418:
            d['parameter_list']=[];d['parameter_iterator_build']=iter(d['fn_comp']['params'])
        elif action == 419: return self._next('parameter_iterator_build','p_build')
        elif action == 420: d['parameter_list'].append(d['p_build']['type'])
        elif action == 421:
            d.pop('p_build',None);d['signature_value_fields']=[d.pop('parameter_list')]
        elif action == 422: d['signature_value_fields'].append(d['fn_comp']['returns'])
        elif action == 423: d['signature_value']=dict(zip(('params','returns'),d.pop('signature_value_fields')))
        elif action == 424: d['signatures'][d.pop('signature_key')]=d.pop('signature_value')
        elif action == 430:
            d.pop('fn_comp',None)
            d['exports']=dict(d['normalize_exports'](d['foreign_buffer_exports'],d['program']))
        elif action == 431: d['functions_iterator_outer']=iter(d['document']['functions'])
        elif action == 432: return self._next('functions_iterator_outer','fn')
        elif action == 433:
            if d['fn']['name'] in d['exports']: return True
            return False
        elif action == 434:
            d['parameter_list']=[];d['parameter_iterator_outer']=iter(d['fn']['params'])
        elif action == 435: return self._next('parameter_iterator_outer','p_outer')
        elif action == 436: d['parameter_list'].append(d['p_outer']['type'])
        elif action == 437:
            d.pop('p_outer',None);d['outer_signature_fields']=[d.pop('parameter_list')]
        elif action == 438: d['outer_signature_fields'].append(d['fn']['returns'])
        elif action == 439: d['outer_signature_fields'].append(d['BUFFER_PROFILE'])
        elif action == 440: d['outer_signature_fields'].append(d['exports'][d['fn']['name']])
        elif action == 441: d['outer_signature_value']=dict(zip(('params','returns','abi','max_buffer_bytes'),d.pop('outer_signature_fields')))
        elif action == 442: d['outer_signature_key']=d['fn']['name']
        elif action == 443: d['signatures'][d.pop('outer_signature_key')]=d.pop('outer_signature_value')
        elif action == 449: d['result']=d['signatures']
        elif action == 601: pass
        elif action == 701: d['path_left']=api.Path(d['directory'])
        elif action == 702:
            if d['kind']=='object': return True
            return False
        elif action == 703: d['filename']='program.o'
        elif action == 704: d['filename']='program.so'
        elif action == 705: d['output']=d.pop('path_left')/d['filename']
        elif action == 706: d['compile_callee']=d['compile_program_machine']
        elif action == 707: d['clock_second']=api.time.monotonic()
        elif action == 708: d['difference']=d['deadline']-d.pop('clock_second')
        elif action == 709:
            if d['difference']>0: return True
            return False
        elif action == 710:
            d.pop('difference');d['floor']=0
        elif action == 711: d['floor']=d.pop('difference')
        elif action == 712:
            if d['floor']<3600: return True
            return False
        elif action == 713: d['timeout_value']=d.pop('floor')
        elif action == 714:
            d.pop('floor');d['timeout_value']=3600
        elif action == 715:
            d['build_result']=d.pop('compile_callee')(d['image'],program=d['program'],output=d['output'],kind=d['kind'],
                linker='ld',command_log=d['commands'],machine_plan=d['machine_plan'],parent_death_guard=True,
                timeout_seconds=d.pop('timeout_value'))
        elif action == 716: d['data']=d['output'].read_bytes()
        elif action == 717: pass
        elif action in (801,851):
            try: d['item']=next(d['iterator'])
            except StopIteration: return False
            return True
        elif action == 802:
            if d['item']['type'] in set(d['WIDTHS'])|{'bool'}: return True
            return False
        elif action == 852:
            if d['item'] in set(d['WIDTHS'])|{'bool','unit'}: return True
            return False
        elif action in (804,854): pass
        elif action in (805,855): pass
        elif action in (806,856): pass
        elif action == 1001:
            try: d['item']=next(d['iterator'])
            except StopIteration: return False
            return True
        elif action == 1002: d['yield_value']=d['item']['claim']=='lowering_refinement'
        elif action == 1003:
            if d['yield_value']: return True
            return False
        elif action == 1004: d.pop('yield_value')
        elif action == 1005: d['yield_value']=d['item']['status']=='proved'
        elif action == 1009: pass
        elif action == 1010: pass
        elif action == 1011: pass
        else: raise EmissionUnknown('HIA requested an unknown emission primitive')
        return None


def _unbound_result():
    if False: result = None
    return result


def _unbound_data():
    if False: data = None
    return data


class NativeEmissionService:
    def __init__(self,service,image,*,checker_custody=None):
        self.profile = _runtime_profile()
        self.service,self.image=service,image
        if checker_custody is not None and checker_custody.image is not image:
            raise ValueError('emission checker custody belongs to a different held image')
        self._checker_custody=checker_custody
        self.delivery=getattr(image,'delivery',None)
        if self.delivery is None: self.delivery=ExceptionDelivery.from_hia(image)
        self.creator=os.getpid();self.active={};self.retiring={};self.unknown={};self.last=None;self.closed=False

    def checker_owner(self):
        if self._checker_custody is None or self._checker_custody.image is not self.image:
            raise ValueError('emission service lacks admitted checker image custody')
        return self._checker_custody

    def _new_state(self,mode,data,*,parent=None):
        if self.closed or self.creator!=os.getpid():
            raise EmissionUnknown('emission owner is closed or belongs to another process')
        if mode==4:
            if (parent is None or parent.owner is not self or parent.receipt is None
                    or parent.receipt.stage!=2 or parent.receipt.action!=211
                    or parent.receipt.raw!=parent.buffer.raw or self.active.get(parent.identity) is not parent):
                raise EmissionUnknown('build body has no claimed original with continuation')
        elif mode in (5,6,7):
            if (parent is None or parent.owner is not self or parent.receipt is None
                    or parent.receipt.stage!=2 or parent.receipt.action!={5:406,6:412,7:20}[mode]
                    or parent.receipt.raw!=parent.buffer.raw or self.active.get(parent.identity) is not parent):
                raise EmissionUnknown('signature generator has no claimed original continuation')
        elif parent is not None:
            raise EmissionUnknown('only an issued body or generator accepts parent custody')
        state=EmissionState(self,mode,data)
        self.active[state.identity]=state
        return state

    def _finish_generator(self,state):
        while state.receipt.stage==1: state.invoke(state.receipt)
        if state.receipt.stage!=3:
            raise EmissionUnknown('generator did not reach native completion')
        receipt=state.call(4)
        if receipt.stage!=5:
            raise EmissionUnknown('generator completion was not consumed')
        state.retire()
        self.last=receipt;self.active.pop(state.identity);state.closed=True

    def _predicates(self,mode,iterator,widths,*,parent):
        state=self._new_state(mode,{'WIDTHS':widths,'iterator':iterator},parent=parent)
        def native_generator():
            value=None
            try:
                state.call(0)
                while True:
                    while state.receipt.stage==1: state.invoke(state.receipt)
                    if state.receipt.stage==3:
                        self._finish_generator(state)
                        return
                    if state.receipt.stage!=6:
                        raise EmissionUnknown('generator did not reach native yield')
                    receipt=state.call(4)
                    if receipt.stage!=8:
                        raise EmissionUnknown('generator yield was not consumed')
                    if mode==7:
                        # Yield consumes the original comparison result. It
                        # must not remain in a Python wrapper local while any
                        # performs its distinct truth observation.
                        yield state.data.pop('yield_value')
                    else:
                        value=bool(receipt.words[14])
                        yield value
                        value=None
                    state.call(5)
            except GeneratorExit:
                # Parent HIA has already consumed cancellation. The parent
                # resumes native local retirement after this handler exits.
                if state.receipt is None or state.receipt.stage!=1 or state.receipt.action not in (804,854,1009):
                    self.unknown[state.identity]=state;state.fenced=True
                raise
            except BaseException as error:
                if (state.receipt is not None and state.receipt.stage==7 and not state.fenced and error is state.error):
                    self.last=state.receipt;self.active.pop(state.identity,None);state.closed=True;state.error=None
                else:
                    self.unknown[state.identity]=state;state.fenced=True
                raise
            finally:
                # On error the actual generator traceback owns state and its
                # original iterator/target locals. Do not clear those locals.
                value=None
        return state,native_generator()

    def _drive(self,state,*,clear_locals=True):
        data=state.data
        try:
            state.call(0)
            while state.receipt.stage==1: state.invoke(state.receipt)
            if state.receipt.stage!=3: raise EmissionUnknown('emission did not reach native completion')
            delivered=state.call(4)
            if delivered.stage!=5: raise EmissionUnknown('emission return permission was not consumed')
            result=None if state.mode==4 else data.pop('result')
            if clear_locals: state.retire()
            self.last=delivered;self.active.pop(state.identity);state.closed=True
            return result
        except BaseException as error:
            if (state.receipt is not None and state.receipt.stage==7 and not state.fenced and error is state.error):
                self.last=state.receipt;self.active.pop(state.identity,None);state.closed=True;state.error=None
            else:
                self.unknown[state.identity]=state;state.fenced=True
            raise

    def run(self,mode,**data):
        return self._drive(self._new_state(mode,data))

    def emit(self,args):
        state=self._new_state(1,{'args':args})
        del args
        return self._drive(state)

    def compile(self,program,kind,machine_plan,timeout_ms,*,foreign_buffer_exports=()):
        state=self._new_state(2,{'program':program,'kind':kind,'machine_plan':machine_plan,
                               'timeout_ms':timeout_ms,'foreign_buffer_exports':foreign_buffer_exports})
        del program,kind,machine_plan,timeout_ms,foreign_buffer_exports
        return self._drive(state)

    def signatures(self,program,foreign_buffer_exports=()):
        state=self._new_state(3,{'program':program,'foreign_buffer_exports':foreign_buffer_exports})
        del program,foreign_buffer_exports
        return self._drive(state)
