"""Type/UTF-8/ABI/exception adapter; no host decimal recognition or parsing."""
import ctypes
import os
import json
import struct
from pathlib import Path
from hashlib import sha256
import threading
from .hia_agent_store import reject

class NativeUInt64:
    def __init__(self,library,expected):
        self.owner = _SealedLibrary(library, expected, ("parse_u64",))
        self.library=self.owner.library
        self.call=self.library.parse_u64
        self.call.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*2
        self.call.restype=ctypes.c_uint64
    def uint64(self,value,label):
        if type(value) is not str:
            reject('E_HIA_RANGE',label+' must be a canonical u64 decimal string')
        try: raw=value.encode('utf-8')
        except UnicodeEncodeError:
            reject('E_HIA_RANGE',label+' must be a canonical u64 decimal string')
        source=ctypes.create_string_buffer(raw)
        result=ctypes.c_uint64(0)
        status=self.call(source,len(raw),ctypes.byref(result),8)
        if status:
            reject('E_HIA_RANGE',label+' must be a canonical u64 decimal string')
        return result.value

class NativeNumericPolicy:
    def __init__(self, library, expected):
        self.owner = _SealedLibrary(library, expected, ("select_plan",))
        self.library = self.owner.library
        self.kernel = self.library.select_plan
        # HIA foreign-buffer wrapper returns packed status:u32/result:u32.
        self.kernel.argtypes = [ctypes.c_void_p,ctypes.c_uint64]+[ctypes.c_uint64]*4
        self.kernel.restype = ctypes.c_uint64

    def select(self, state, *, elapsed_ns=0):
        from .hia_agent_macro_policy import _state, _integer
        totals = _state(state)
        _integer(elapsed_ns,'controller elapsed time')
        wall=state['budget']['wall_ns']-totals['observed_wall_ns']-elapsed_ns
        tokens=state['budget']['model_tokens']-totals['observed_model_tokens']
        result={'selected_id':'abstain','next_action':'stop','disposition':'keep_existing',
                'status':'ADVISORY','reason':'incumbent_minimum_or_tie',
                'remaining_wall_ns':wall,'remaining_model_tokens':tokens,
                'considered_plans':[],'forecast_is_observed_benefit':False}
        if not totals['complete']:
            result.update(status='BLOCKED',reason='unknown_observed_costs')
            return result
        if wall<=0 or tokens<0:
            result.update(status='BLOCKED',reason='lifecycle_budget_exhausted')
            return result
        # Stable identifier order is wire encoding, not a cost-based choice.
        plans=sorted(state['plans'],key=lambda row:row['id'])
        data=b''.join(struct.pack('<QQQ',p['remaining_cost_ns'],p['uncertainty_ns'],p['model_tokens']) for p in plans)
        buffer=ctypes.create_string_buffer(data,max(1,len(data)))
        packed=self.kernel(buffer,len(data),len(plans),wall,tokens,state['stop_remaining_ns'])
        if packed>>32:
            raise ValueError('native ABI rejected validated encoding: '+str(packed>>32))
        ordinal=packed&0xffffffff
        if ordinal>len(plans):
            raise ValueError('native returned invalid ordinal')
        # Metadata only: these fields do not select or override the native result.
        result['considered_plans']=[{'id':p['id'],
            'robust_cost_ns':p['remaining_cost_ns']+p['uncertainty_ns'],
            'model_tokens':p['model_tokens'],
            'budget_feasible':p['remaining_cost_ns']+p['uncertainty_ns']<=wall and p['model_tokens']<=tokens}
            for p in plans]
        if ordinal:
            chosen=plans[ordinal-1]
            disposition=('no_adopt' if 'no_adopt' in chosen['actions'] else
                         'keep_existing' if 'keep_existing' in chosen['actions'] else
                         'stop' if chosen['actions']==['stop'] else 'continue')
            result.update(selected_id=chosen['id'],next_action=chosen['actions'][0],
                          disposition=disposition,reason='ordinary_full_budget_minimum')
        return result

SCHEMA = "hepta.hia.native-numeric.v1"
SOURCE_HASHES = {'ordinary_select.hiaasm': 'b90fa945ed0da8ebf85e957e325d2c20f6f200ff60ae64a223f0575c6fba9ff5', 'uint64.hiaasm': '66d005a11c7ea505c602c09b63b61f220e2dea2d9a99c8262b93e8f384fa6ad2'}

def legacy_enabled():
    mode = os.environ.get("HIA_NATIVE_NUMERIC", "required")
    if mode not in ("required", "legacy"):
        reject("E_HIA_NATIVE_NUMERIC", "invalid HIA_NATIVE_NUMERIC mode", retry_action="stop")
    return mode == "legacy"

class _SealedLibrary:
    """Own the exact sealed descriptor and dlopen reference for process lifetime."""
    def __init__(self, path, expected, symbols):
        from .hia_native_differential import _pin_native_artifact
        from .native_mapping_identity import verify_loaded_symbols
        self.fd = None
        self.library = None
        raw, _, self.fd = _pin_native_artifact(Path(path))
        try:
            if sha256(raw).hexdigest() != expected:
                raise ValueError("native numeric sealed snapshot digest mismatch")
            self.library = ctypes.CDLL('/proc/self/fd/' + str(self.fd), mode=os.RTLD_LOCAL | os.RTLD_NOW)
            self.mapping_identity = verify_loaded_symbols(self.fd,
                {name: getattr(self.library, name) for name in symbols})
        except BaseException:
            self.close()
            raise

    def close(self):
        """Internal failed-admission cleanup; never close an admitted owner."""
        if self.library is not None:
            import _ctypes
            _ctypes.dlclose(self.library._handle)
            self.library = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

# A bounded process-lifetime cache retains owners and descriptors, so an active
# ctypes symbol never outlives its sealed file object. No eviction/dlclose races.
_LOADED = {}
_LOAD_LOCK = threading.RLock()


def _load(directory):
    from .hia_agent_store import stable_read
    from .hia_program_native import _implementation_hash
    root = Path(directory)
    # All current admission checks run OUTSIDE the owner cache on every public
    # entry, including after a prior successful load at the same pathname.
    manifest = json.loads(stable_read(root / "manifest.json", 1024 * 1024))
    if manifest.get("schema") != SCHEMA or manifest.get("sources") != SOURCE_HASHES:
        raise RuntimeError("native numeric source/ABI version mismatch")
    backend = _implementation_hash()
    if manifest.get("backend_sha256") != backend:
        raise RuntimeError("native numeric backend version mismatch")
    for name, expected in SOURCE_HASHES.items():
        if sha256(stable_read(Path(__file__).with_name("native_numeric") / name, 1024 * 1024)).hexdigest() != expected:
            raise RuntimeError("installed native numeric source mismatch")
    hashes = []
    for name in ("uint64.so", "policy.so"):
        expected = manifest["libraries"][name]
        if type(expected) is not str or len(expected) != 64:
            raise ValueError("invalid native numeric artifact digest")
        if sha256(stable_read(root / name, 64 * 1024 * 1024)).hexdigest() != expected:
            raise RuntimeError("native numeric artifact hash mismatch")
        hashes.append(expected)
    key = (str(root), backend, *hashes)
    with _LOAD_LOCK:
        if key not in _LOADED:
            if len(_LOADED) >= 8:
                raise RuntimeError("native numeric process version capacity exhausted; restart worker")
            uint64 = NativeUInt64(root / "uint64.so", hashes[0])
            try:
                policy = NativeNumericPolicy(root / "policy.so", hashes[1])
            except BaseException:
                uint64.owner.close()
                raise
            _LOADED[key] = (uint64, policy)
        return _LOADED[key]


def _native_numeric():
    directory = os.environ.get("HIA_NATIVE_NUMERIC_ARTIFACT_DIR")
    if not directory:
        raise RuntimeError("native numeric required: build artifacts and set HIA_NATIVE_NUMERIC_ARTIFACT_DIR")
    return _load(str(Path(directory).resolve()))


def native_numeric():
    from .hia_agent_store import AgentRejected
    try:
        return _native_numeric()
    except (OSError, ValueError, KeyError, RuntimeError, AttributeError) as exc:
        raise AgentRejected("E_HIA_NATIVE_NUMERIC", str(exc), retry_action="stop") from exc
