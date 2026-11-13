"""Native bounded JSON token recognition; no JSON value construction."""
import ctypes,json,os,sys,threading
from hashlib import sha256
from pathlib import Path
from .hia_native_numeric import _SealedLibrary
SCHEMA='hepta.hia.native-json-integer.v7'
INTEGER_SOURCE_SHA256='befaddfbaa2d5eabd228c752fe0c77b6f2b6189da67bedbaa92c0f7ec8c6aeee'
KEYTABLE_SOURCE_SHA256='3dd74172721a65ffcbccde6bdbe1d3be7843d698e1ea1693e1bf74a9bc98d2cb'
KEYDECODE_SOURCE_SHA256='2cf99981dd042910d86eabc1a423e15318b8d45f98225d49c5c18e29b008a55d'
KEYSET_SOURCE_SHA256='65e8fd788c2c55ce9230874091a1519039895b33104dee80d733e1397e04e9d5'
GRAMMAR_SOURCE_SHA256='f719d91922665c29a3e2fd385bafbec7d40c6f5886101b565b25fabacf8781c9'
STRING_SOURCE_SHA256='c73fce1fa875f8e7ac4422a6906470280699db4f7ccb38dba7d2bc7baaa0edb0'
SOURCE_SHA256='529bd3f07f91ab6b245700488ee3612760ab046401fb4d79451d5c0414b0eb8f'
_OWNERS={}
_LOCK=threading.RLock()

def legacy_enabled():
    mode=os.environ.get('HIA_NATIVE_JSON_SCAN','required')
    if mode not in ('required','legacy'):
        raise ValueError('invalid HIA_NATIVE_JSON_SCAN mode')
    return mode=='legacy'

class NativeJSONAtoms:
    def __init__(self,path,digest):
        self.owner=_SealedLibrary(path,digest,('scan_atom','skip_whitespace','scan_string_chunk','grammar_step','grammar_init','grammar_head','key_compare_chunk','key_hash_chunk','decode_key_chunk','table_init','table_begin','table_step','integer_scan_chunk','integer_magnitude_page'))
        self.scan=self.owner.library.scan_atom
        self.scan.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*2+[ctypes.c_uint64]
        self.scan.restype=ctypes.c_uint64
        self.skip=self.owner.library.skip_whitespace
        self.skip.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*2
        self.skip.restype=ctypes.c_uint64
        self.string=self.owner.library.scan_string_chunk
        self.string.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*2+[ctypes.c_uint64]*2
        self.string.restype=ctypes.c_uint64
        self.grammar_step=self.owner.library.grammar_step
        self.grammar_step.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*2+[ctypes.c_uint64,ctypes.c_uint32,ctypes.c_uint32]
        self.grammar_step.restype=ctypes.c_uint64
        self.grammar_init=self.owner.library.grammar_init
        self.grammar_init.argtypes=[ctypes.c_void_p,ctypes.c_uint64]+[ctypes.c_uint64]*4
        self.grammar_init.restype=ctypes.c_uint64
        self.grammar_head=self.owner.library.grammar_head
        self.grammar_head.argtypes=[ctypes.c_void_p,ctypes.c_uint64]
        self.grammar_head.restype=ctypes.c_uint64
        self.key_compare=self.owner.library.key_compare_chunk
        self.key_compare.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*2+[ctypes.c_uint64]*3
        self.key_compare.restype=ctypes.c_uint64
        self.key_hash=self.owner.library.key_hash_chunk
        self.key_hash.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*2+[ctypes.c_uint64]
        self.key_hash.restype=ctypes.c_uint64
        self.key_decode=self.owner.library.decode_key_chunk
        self.key_decode.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*4+[ctypes.c_uint64,ctypes.c_bool]
        self.key_decode.restype=ctypes.c_uint64
        self.table_init=self.owner.library.table_init
        self.table_init.argtypes=[ctypes.c_void_p,ctypes.c_uint64]
        self.table_init.restype=ctypes.c_uint64
        self.table_begin=self.owner.library.table_begin
        self.table_begin.argtypes=[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_uint32]+[ctypes.c_uint64]*3
        self.table_begin.restype=ctypes.c_uint64
        self.table_step=self.owner.library.table_step
        self.table_step.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*3+[ctypes.c_uint64]*2+[ctypes.c_uint32]
        self.table_step.restype=ctypes.c_uint64

        self.integer_scan=self.owner.library.integer_scan_chunk
        self.integer_page=self.owner.library.integer_magnitude_page
        for fn in (self.integer_scan,self.integer_page):
            fn.argtypes=[ctypes.c_void_p,ctypes.c_uint64]*2+[ctypes.c_uint64]
            fn.restype=ctypes.c_uint64

    def integer(self, token):
        # Source and all intermediate magnitude pages are private to this
        # conversion. No decimal arithmetic or classification occurs here.
        raw=token.encode('ascii')
        state=(ctypes.c_uint64*16)();state[0]=1;state[8]=1
        state[14]=sys.get_int_max_str_digits();state[15]=len(raw)
        pages={}
        while True:
            position=state[2];chunk=raw[position:position+64]
            source=(ctypes.c_ubyte*len(chunk)).from_buffer_copy(chunk)
            action=self.integer_scan(state,128,source,len(chunk),position)
            if action==5:
                # Preserve the observed Python decimal-conversion diagnostic.
                count=state[15]-state[4]
                raise ValueError('Exceeds the limit ('+str(state[14])+' digits) for integer string conversion: value has '+str(count)+' digits; use sys.set_int_max_str_digits() to increase the limit')
            if action in (4,6):raise ValueError('native strict JSON integer rejected')
            if action==3:
                binary=[]
                for index in range(state[10]):
                    page=bytes(pages[index//32]);offset=(index%32)*8
                    binary.append(page[offset:offset+4])
                value=int.from_bytes(b''.join(binary),'little')
                return -value if state[4] else value
            if action==1:
                if state[2]<=position:raise ValueError('native integer made no source progress')
                continue
            if action!=2:raise ValueError('invalid native integer action')
            while True:
                requested=state[11]
                page=pages.setdefault(requested,(ctypes.c_ubyte*256)())
                action=self.integer_page(state,128,page,256,requested)
                if action==3:break
                if action!=2 or state[11]<=requested:
                    raise ValueError('native integer page rejected or made no progress')

    def _call(self,text,index,*,atom,continuing=False):
        # Encoding and bounded chunk dispatch are host boundaries. Only native
        # code recognizes token bytes. Every accepted span is ASCII, so its byte
        # length is also its Python-character span; string scanning is delegated.
        raw=text[index:index+64].encode('utf-8','surrogatepass')
        source=ctypes.create_string_buffer(raw)
        result=ctypes.c_uint64(0)
        args=(source,len(raw),ctypes.byref(result),8)
        status=self.scan(*args,continuing) if atom else self.skip(*args)
        if status>>32 or result.value>len(raw):
            raise ValueError('native JSON scanner ABI rejection')
        return status,result.value,len(raw)

    def whitespace(self,text,index):
        while index<len(text):
            status,count,size=self._call(text,index,atom=False)
            if status:raise ValueError('native JSON whitespace status')
            index+=count
            if count!=size:return index
        return index

    def atom(self,text,index):
        continuing=False
        while True:
            status,count,size=self._call(text,index,atom=True,continuing=continuing)
            if status==1:raise ValueError('HIA JSON preflight: missing JSON value')
            if status==2:raise ValueError('HIA JSON preflight: expected JSON integer or literal')
            if status==3:return 'string',index
            if status not in (0,4):raise ValueError('native JSON atom status')
            index+=count
            if status==0 or index==len(text):return 'value',index
            if not count or count!=size:raise ValueError('native JSON progress rejection')
            continuing=True

    def string_token(self,text,index):
        first=index
        total=len(text)-first
        state=(ctypes.c_uint64*8)()
        while True:
            end=min(index+64,len(text))
            raw=text[index:end].encode('utf-8','surrogatepass')
            source=ctypes.create_string_buffer(raw)
            packed=self.string(source,len(raw),state,64,total,end==len(text))
            if packed>>32:raise ValueError('native JSON string ABI rejection')
            status=packed&0xffffffff
            if status==0:
                count=state[7]
                if count>total:raise ValueError('native JSON string character extent rejected')
                return text[first:first+count],first+count
            if status==10:
                if end==index:raise ValueError('native JSON string progress rejected')
                index=end
                continue
            messages={1:'expected JSON string',2:'unescaped control or isolated Unicode surrogate',
                3:'unterminated JSON escape',4:'invalid JSON escape',5:'invalid Unicode escape',
                6:'unpaired high Unicode surrogate',7:'unpaired low Unicode surrogate',8:'unterminated JSON string'}
            if status not in messages:raise ValueError('native JSON string state rejected')
            raise ValueError('HIA JSON preflight: '+messages[status])


    def decode_key(self, token):
        # Only source-wire encoding and page dispatch remain here. Native code
        # recognizes escapes/surrogates, emits UTF8 and accumulates the key hash.
        wire=token.encode('utf-8','surrogatepass')
        state=(ctypes.c_uint64*12)();state[8]=14695981039346656037;state[11]=1
        chunks=[]
        for offset in range(0,len(wire),64):
            raw=wire[offset:offset+64];source=ctypes.create_string_buffer(raw)
            output=ctypes.create_string_buffer(256);scratch=ctypes.create_string_buffer(96)
            status=self.key_decode(source,len(raw),state,96,output,256,scratch,96,
                                   len(token),offset+len(raw)==len(wire))
            if status not in (0,10) or state[10]>256:
                raise ValueError('native JSON key decoder rejected')
            chunks.append(output.raw[:state[10]])
        if not chunks or status!=0:raise ValueError('native JSON key decoder incomplete')
        return b''.join(chunks),state[8]

    def _legacy_host_key_insert(self, token, buckets):
        raw,hashed=self.decode_key(token)
        candidates=buckets.setdefault(hashed,[])
        for prior in candidates:
            offset=0
            while True:
                left=raw[offset:offset+256]
                right=prior[offset:offset+256]
                status=self.key_compare(ctypes.create_string_buffer(left),len(left),
                    ctypes.create_string_buffer(right),len(right),offset,len(raw),len(prior))
                if status==0:break
                if status==2:
                    raise ValueError('HIA JSON preflight: duplicate decoded object key')
                if status!=1:raise ValueError('native JSON decoded key comparison rejected')
                offset+=len(left)
        candidates.append(raw)

    def preflight(self,text,max_nodes,max_depth):
        state=(ctypes.c_uint64*12)()
        mask=(1<<64)-1
        # Exact PyLong representation boundary, not a host budget decision.
        packed=self.grammar_init(state,96,max_nodes&mask,max_nodes.bit_length(),
                                 max_depth&mask,max_depth.bit_length())
        if packed:raise ValueError('native JSON grammar initialization rejected')
        pages={0:(ctypes.c_uint64*32)()}
        loaded=0
        table=OpaqueNativeKeyTable(self)
        index=0
        event=0
        head=0
        messages={32:'missing JSON value',33:'extra JSON data',34:'incomplete JSON value',
            35:'unexpected value completion',36:'expected array separator/end',
            37:'invalid array preflight state',38:'expected object field name',
            39:'expected object colon',40:'expected object separator/end',41:'invalid object preflight state'}
        while True:
            if event==0:
                index=self.whitespace(text,index)
                raw=text[index:index+64].encode('utf-8','surrogatepass')
                source=ctypes.create_string_buffer(raw)
                packed=self.grammar_head(source,len(raw))
                if packed>>32:raise ValueError('native JSON head ABI rejected')
                head=packed&0xffffffff
            packed=self.grammar_step(state,96,pages[loaded],256,loaded,event,head)
            if packed>>32:raise ValueError('native JSON grammar ABI rejected')
            action=packed&0xffffffff
            if action==0:
                event=0
            elif action==1:
                index+=1
                event=0
            elif action==2:
                kind,following=self.atom(text,index)
                if kind=='string':_,index=self.string_token(text,index)
                else:index=following
                event=1
            elif action==3:
                token,index=self.string_token(text,index)
                table.insert(state[9],token)
                event=2
            elif action==4:
                table.close(state[9])
                event=3
            elif action==5:
                loaded=state[8]
                if loaded not in pages:pages[loaded]=(ctypes.c_uint64*32)()
            elif action==6:
                return
            elif action==42:
                raise OverflowError('HIA JSON exceeds node/depth budget before decoding')
            elif action in messages:
                raise ValueError('HIA JSON preflight: '+messages[action])
            else:
                raise ValueError('native JSON grammar state rejected')


class OpaqueNativeKeyTable:
    """Storage/ABI driver only; every table decision is a native action.

    ABI state words exposed to this driver are request-page id (7), requested
    input-page index (8), and release-page id (26). Other words stay opaque.
    """
    def __init__(self,native):
        self.native=native
        self.state=(ctypes.c_uint64*32)()
        self.pages={}
        self._empty_page=ctypes.create_string_buffer(256)
        self._empty_key=ctypes.create_string_buffer(256)
        self._page=self._empty_page
        self._key=self._empty_key
        self._loaded=self._keyloaded=(1<<64)-1
        self._raw=b''
        if native.table_init(self.state,256):raise ValueError('native JSON table initialization rejected')

    def _step(self,event=0):
        return self.native.table_step(self.state,256,self._page,256,self._key,256,
                                      self._loaded,self._keyloaded,event)

    def _drive(self,action):
        try:
            while action not in (0,5,6,7):
                event=0
                if action in (1,3):
                    page_id=self.state[7]
                    self._page=self.pages.setdefault(page_id,ctypes.create_string_buffer(256))
                    self._loaded=page_id
                elif action==2:
                    index=self.state[8];offset=index*208
                    self._key=ctypes.create_string_buffer(self._raw[offset:offset+208],256)
                    self._keyloaded=index
                elif action==4:
                    self.pages.pop(self.state[26],None)
                    self._page=self._empty_page
                    self._loaded=(1<<64)-1
                    event=1
                else:
                    raise ValueError('native JSON table ABI action rejected')
                action=self._step(event)
            if action in (0,5,7):
                self._raw=b''
                self._key=self._empty_key
                self._keyloaded=(1<<64)-1
            return action
        except (MemoryError,OSError):
            # Native code cancels uncommitted insertion and enumerates every
            # reserved id. Post-close-commit cleanup remains retryable, never
            # silently reopens the tombstone on a provider failure.
            recovery=self._step(9)
            while recovery==4:
                self.pages.pop(self.state[26],None)
                self._page=self._empty_page
                self._loaded=(1<<64)-1
                recovery=self._step(1)
            raise

    def _begin(self,operation,scope,raw,hashed):
        self._raw=raw
        self._page=self._empty_page
        self._key=self._empty_key
        self._loaded=self._keyloaded=(1<<64)-1
        return self._drive(self.native.table_begin(self.state,256,operation,scope,len(raw),hashed))

    def insert(self,scope,token):
        raw,hashed=self.native.decode_key(token)
        result=self._begin(1,scope,raw,hashed)
        if result==5:raise ValueError('HIA JSON preflight: duplicate decoded object key')
        if result!=0:raise ValueError('native JSON key table insertion rejected')

    def close(self,scope):
        if self._begin(2,scope,b'',0)!=0:raise ValueError('native JSON key table close rejected')

    def cancel(self):
        return self._drive(self._step(3))


def scanner():
    from .hia_agent_store import stable_read
    from .hia_program_native import _implementation_hash
    directory=os.environ.get('HIA_NATIVE_JSON_SCAN_ARTIFACT_DIR')
    if not directory:raise ValueError('native JSON scanner required: configure HIA_NATIVE_JSON_SCAN_ARTIFACT_DIR')
    root=Path(directory).resolve()
    # Decode only bounded administrator configuration through a separate
    # stdlib decoder; never route data input or scanner admission recursively.
    expected=os.environ.get('HIA_NATIVE_JSON_MANIFEST_SHA256')
    if not expected or len(expected)!=64 or any(c not in '0123456789abcdef' for c in expected):
        raise ValueError('native JSON scanner requires external administrator manifest SHA256')
    manifest_raw=stable_read(root/'manifest.json',1024*1024)
    if sha256(manifest_raw).hexdigest()!=expected:
        raise ValueError('native JSON scanner external manifest SHA256 mismatch')
    manifest=json.JSONDecoder().decode(manifest_raw.decode('utf-8'))
    if manifest.get('integer_source_sha256')!=INTEGER_SOURCE_SHA256 or manifest.get('keytable_source_sha256')!=KEYTABLE_SOURCE_SHA256 or manifest.get('keydecode_source_sha256')!=KEYDECODE_SOURCE_SHA256 or manifest.get('keyset_source_sha256')!=KEYSET_SOURCE_SHA256 or manifest.get('schema')!=SCHEMA or manifest.get('source_sha256')!=SOURCE_SHA256 or manifest.get('string_source_sha256')!=STRING_SOURCE_SHA256 or manifest.get('grammar_source_sha256')!=GRAMMAR_SOURCE_SHA256:
        raise ValueError('native JSON scanner source/ABI mismatch')
    if manifest.get('backend_sha256')!=_implementation_hash():
        raise ValueError('native JSON scanner backend mismatch')
    if sha256(stable_read(Path(__file__).with_name('native_numeric')/'json_atom.hiaasm',1024*1024)).hexdigest()!=SOURCE_SHA256:
        raise ValueError('native JSON scanner installed source mismatch')
    if sha256(stable_read(Path(__file__).with_name('native_numeric')/'json_string.hiaasm',1024*1024)).hexdigest()!=STRING_SOURCE_SHA256:
        raise ValueError('native JSON string installed source mismatch')
    if sha256(stable_read(Path(__file__).with_name('native_numeric')/'json_grammar.hiaasm',1024*1024)).hexdigest()!=GRAMMAR_SOURCE_SHA256:
        raise ValueError('native JSON grammar installed source mismatch')
    if sha256(stable_read(Path(__file__).with_name('native_numeric')/'json_keyset.hiaasm',1024*1024)).hexdigest()!=KEYSET_SOURCE_SHA256:
        raise ValueError('native JSON keyset installed source mismatch')
    if sha256(stable_read(Path(__file__).with_name('native_numeric')/'json_keydecode.hiaasm',1024*1024)).hexdigest()!=KEYDECODE_SOURCE_SHA256:
        raise ValueError('native JSON key decoder installed source mismatch')
    if sha256(stable_read(Path(__file__).with_name('native_numeric')/'json_keytable.hiaasm',1024*1024)).hexdigest()!=KEYTABLE_SOURCE_SHA256:
        raise ValueError('native JSON key table installed source mismatch')
    if sha256(stable_read(Path(__file__).with_name('native_numeric')/'json_integer.hiaasm',1024*1024)).hexdigest()!=INTEGER_SOURCE_SHA256:
        raise ValueError('native JSON integer installed source mismatch')
    digest=manifest['library_sha256']
    if type(digest) is not str or len(digest)!=64 or sha256(stable_read(root/'scanner.so',8*1024*1024)).hexdigest()!=digest:
        raise ValueError('native JSON scanner artifact mismatch')
    key=(str(root),digest)
    with _LOCK:
        if key not in _OWNERS:
            if len(_OWNERS)>=8:raise ValueError('native JSON scanner version capacity exhausted')
            _OWNERS[key]=NativeJSONAtoms(root/'scanner.so',digest)
        return _OWNERS[key]


def _legacy_decimal_integer(token):
    """Old decimal constructor retained only for explicit legacy qualification."""
    return int(token)


def integer_value(token):
    return _legacy_decimal_integer(token) if legacy_enabled() else scanner().integer(token)
