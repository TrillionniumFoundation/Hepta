"""Independent action traces, byte-format oracle, and private-frame faults."""
from hashlib import sha256
import struct
from observations import require,dump,pin

ABI=0xfffffffd
U64=(1<<64)-1
UUID=bytes(range(1,17));NONCE=bytes(range(33,49));TXN=bytes(range(65,81))
ROOT=sha256(b'expected-catalog-root').digest();TARGET=sha256(b'proposed-ten-table-root').digest();REQUEST=sha256(b'request-record').digest()
GROUPS=('head-genesis-commit','head-partial-eintr','head-replay-conflict','head-lost-ack',
    'head-eintr-refusals','head-effect-errors','head-protocol-errors','head-sha-format',
    'head-generation-boundaries','head-abi-extents','head-dirty-seal','head-terminal-observe')

def replace(raw,at,value):
    b=bytearray(raw);b[at:at+len(value)]=value;return bytes(b)
def word(raw,at,value):return replace(raw,at,struct.pack('<Q',value))
def rehash(raw):return raw[:224]+sha256(raw[:224]).digest()
def seal(raw):
    value=1469598103934665603
    for i,b in enumerate(raw):
        if not 248<=i<256:value=(((value<<7)|(value>>57))^b)&U64
    return word(raw,248,value)
def head(O,generation=0,root=ROOT,uuid=UUID,txn=None):
    return O.encode_head(store_uuid=uuid,generation=generation,parent_generation=max(0,generation-1),root=root,
        parent_root=bytes(32) if generation==0 else sha256(b'parent-root').digest(),
        transaction_uuid=bytes(16) if generation==0 else (bytes(range(17,33)) if txn is None else txn),
        request_digest=bytes(32) if generation==0 else sha256(b'prior-request').digest())

class Frame:
    def __init__(self,engine,O,name,expected=None,current=None):
        self.O=O;self.session=engine.session(name);self.expected=head(O) if expected is None else expected
        self.target=O.target_head(self.expected,TARGET,TXN,REQUEST)
        self.current=self.expected if current is None else current
        self.serial=1;self.action=1;self.phase=1;self.status=1;self.claimed=0
        self.possible=0;self.sync=0;self.replay=0;self.desired=0;self.reason=0
        self.read_position=0;self.write_position=0
        source=O.initial_request(nonce=NONCE,expected=self.expected,root=TARGET,transaction_uuid=TXN,request_digest=REQUEST)
        value,output,workspace=self.session.call(source,'initialize')
        self.expect(value,output)
        require(workspace[256:512]==self.expected and workspace[512:768]==self.target,
            'actual independently checksummed expected/target head bytes differ')
    def expect(self,value,output):
        receipt=self.O.decode_receipt(output,value)
        expected=dict(status=self.status,action=self.action,serial=self.serial,phase=self.phase,claimed=self.claimed,
            possible_publication=self.possible,directory_sync_ack=self.sync,exact_target_replay=self.replay,
            nonce_low=int.from_bytes(NONCE[:8],'little'),nonce_high=int.from_bytes(NONCE[8:],'little'),
            desired_outcome=self.desired,reason=self.reason)
        if self.action in (2,6,9):expected.update(payload=b'',offset=self.read_position,extent=256-self.read_position)
        elif self.action==4:expected.update(payload=self.target[self.write_position:],offset=self.write_position,extent=256-self.write_position)
        elif self.action in (3,7):expected.update(payload=b'.hiah-'+NONCE.hex().encode()+b'\0',offset=0,extent=0)
        else:expected.update(payload=b'',offset=0,extent=0)
        expected['payload_length']=len(expected['payload'])
        require(receipt==expected,'independent full head receipt differs: '+self.session.name+' / '+str(self.session.n))
        dump(self.session.directory/('ORACLE-%04d.json'%self.session.n),
            {k:(v.hex() if type(v)is bytes else v) for k,v in expected.items()})
    def source(self,event,*,serial=None,action=None,result=0,payload=b'',nonce=NONCE):
        return self.O.request(event=event,serial=self.serial if serial is None else serial,
            action=self.action if action is None else action,result=result,nonce=nonce,payload=payload)
    def call(self,raw,label):
        value,output,workspace=self.session.call(raw,label);self.expect(value,output);return workspace
    def claim(self):
        raw=self.source(1);self.serial+=1;self.claimed=1
        if self.action==7:self.possible=1
        return self.call(raw,'claim-'+str(self.action))
    def acknowledge(self,result=0,payload=b'',next_action=None,reason=None):
        action=self.action;raw=self.source(2,result=result,payload=payload)
        if reason is not None:
            self.status=3;self.phase=15;self.action=0;self.reason=reason
        else:
            require(next_action is not None,'expected next action must be explicit')
            self.serial+=1;self.claimed=0
            if result==U64-3:
                require(next_action==action,'EINTR does not advance an effect')
            else:
                if action in (2,6,9):self.read_position=(self.read_position+result)%256
                if action==4:self.write_position+=result
                if action==8:self.sync=1
                if action==2 and next_action==8:self.possible=1;self.replay=1
                if action==2 and next_action==11:self.desired=2
            self.action=next_action
            self.phase=next_action if next_action else (14 if self.desired==2 else 13)
            self.status=1 if next_action else (2 if self.desired==2 else 0)
        return self.call(raw,'ack-'+str(action))
    def advance_one(self):
        action=self.action;self.claim()
        if action==1:self.acknowledge(next_action=2)
        elif action==2:
            nxt=8 if self.current==self.target else 3 if self.current==self.expected else 11
            self.acknowledge(256-self.read_position,self.current[self.read_position:],nxt)
        elif action==3:self.acknowledge(19,next_action=4)
        elif action==4:self.acknowledge(256-self.write_position,next_action=5)
        elif action==5:self.acknowledge(next_action=6)
        elif action==6:self.acknowledge(256-self.read_position,self.target[self.read_position:],7)
        elif action==7:self.acknowledge(next_action=8)
        elif action==8:self.acknowledge(next_action=9)
        elif action==9:self.acknowledge(256-self.read_position,self.target[self.read_position:],11 if self.replay else 10)
        elif action==10:self.acknowledge(next_action=11)
        elif action==11:self.acknowledge(next_action=12)
        elif action==12:self.acknowledge(next_action=0)
        else:raise AssertionError('no effect after terminal receipt')
    def to(self,action):
        for _ in range(16):
            if self.action==action:return
            require(self.action!=0,'requested effect not on declared success path');self.advance_one()
        raise AssertionError('independent fixed trace length exceeded')
    def finish(self):self.to(0)
    def quarantine(self,raw,label,reason):
        self.status=3;self.phase=15;self.action=0;self.reason=reason;self.call(raw,label)
    def rejected(self,raw,label):
        before=self.session.buffers();value,output,workspace=self.session.call(raw,label)
        require(value==ABI and (output,workspace)==before,'bad ABI/state must not change an admitted frame')
    def observe(self):self.call(self.source(90,action=0),'observe')

def raw_initial(O,expected,*,nonce=NONCE,txn=TXN):
    return O.request(event=0,serial=0,action=0,result=0,nonce=nonce,
        payload=expected+TARGET+txn+REQUEST)

def run(engine,O,group):
    require(group in GROUPS,'fixed head group required')
    def init_bad(name,source,output=None,workspace=None,unchanged=False):
        session=engine.session(name,output,workspace);before=session.buffers()
        value,after,work=session.call(source,'rejected-initialize')
        require(value==ABI,'invalid head initialization accepted: '+name)
        if unchanged:require((after,work)==before,'ABI preflight modified scratch: '+name)
    if group==GROUPS[0]:
        for generation in (0,1,7):
            f=Frame(engine,O,'generation-'+str(generation),head(O,generation));f.finish()
            require(f.status==0 and f.phase==13 and f.possible==f.sync==1,'full commit trace did not confirm')
    elif group==GROUPS[1]:
        f=Frame(engine,O,'all-positive-partials')
        for action in range(1,13):
            f.to(action)
            if action in (2,6,9):
                data=f.expected if action==2 else f.target
                for count in (1,63,192):
                    offset=f.read_position;f.claim();f.acknowledge(count,data[offset:offset+count],action if offset+count<256 else {2:3,6:7,9:10}[action])
            elif action==4:
                for count in (1,63,192):
                    offset=f.write_position;f.claim();f.acknowledge(count,next_action=4 if offset+count<256 else 5)
            else:f.advance_one()
        require(f.status==0,'partial IO trace did not confirm')
        for action in (1,2,4,5,6,8,9):
            f=Frame(engine,O,'eintr-retry-'+str(action));f.to(action);f.claim()
            offset=f.read_position;written=f.write_position
            f.acknowledge(U64-3,next_action=action)
            require((f.read_position,f.write_position)==(offset,written),'EINTR advanced offsets')
            f.finish()
    elif group==GROUPS[2]:
        expected=head(O);target=O.target_head(expected,TARGET,TXN,REQUEST)
        replay=Frame(engine,O,'exact-entire-target-replay',expected,target);replay.finish()
        require(replay.replay==1 and replay.possible==replay.sync==1,'replay durability receipt incomplete')
        conflict=head(O,2,root=sha256(b'other-writer-root').digest())
        f=Frame(engine,O,'other-writer-conflict',expected,conflict);f.finish()
        require(f.status==2 and f.phase==14 and f.possible==f.sync==0,'conflict silently published')
        foreign=head(O,1,uuid=bytes(range(16,0,-1)))
        f=Frame(engine,O,'foreign-store-read',expected);f.to(2);f.claim();f.acknowledge(256,foreign,reason=20)
    elif group==GROUPS[3]:
        for action in range(1,13):
            f=Frame(engine,O,'lost-ack-'+str(action));f.to(action);f.claim();raw=f.source(3)
            f.quarantine(raw,'lost',4);f.observe()
            require(f.possible==(1 if action>=7 else 0),'publication uncertainty boundary differs')
            f.rejected(f.source(1,action=action),'no-retry-after-unknown')
    elif group==GROUPS[4]:
        for action in (3,7,10,11,12):
            f=Frame(engine,O,'eintr-no-retry-'+str(action));f.to(action);f.claim();f.acknowledge(U64-3,reason=8);f.observe()
    elif group==GROUPS[5]:
        for action,value,reason in ((1,1,10),(3,1<<31,11),(4,0,12),(4,257,12),(5,1,13),(7,1,13),(8,1,13),(10,1,13),(11,1,13),(12,1,13)):
            f=Frame(engine,O,'effect-'+str(action)+'-'+str(value));f.to(action);f.claim();f.acknowledge(value,reason=reason)
        for action in (2,6,9):
            f=Frame(engine,O,'read-zero-'+str(action));f.to(action);f.claim();f.acknowledge(0,reason=16)
        f=Frame(engine,O,'actual-negative-errno');f.to(7);f.claim();f.acknowledge(U64-27,reason=8)
        f=Frame(engine,O,'payload-on-nonread');f.to(3);f.claim();f.acknowledge(19,b'x',reason=9)
    elif group==GROUPS[6]:
        f=Frame(engine,O,'wrong-nonce');f.rejected(f.source(1,nonce=bytes(range(49,65))),'foreign-nonce')
        f=Frame(engine,O,'wrong-serial');f.quarantine(f.source(1,serial=0),'serial',1)
        f=Frame(engine,O,'wrong-action');f.quarantine(f.source(1,action=2),'action',1)
        f=Frame(engine,O,'ack-without-claim');f.quarantine(f.source(2),'unclaimed',6)
        f=Frame(engine,O,'duplicate-claim');f.claim();f.quarantine(f.source(1),'second-claim',5)
        f=Frame(engine,O,'unknown-event');f.quarantine(f.source(4),'event',6)
        f=Frame(engine,O,'malformed-lost-response');f.quarantine(f.source(3,result=1),'lost-with-value',3)
        f=Frame(engine,O,'serial-exhaustion')
        _,w=f.session.buffers();f.serial=U64-1;f.session.replace_private_workspace_for_control(seal(word(w,24,f.serial)))
        f.quarantine(f.source(1),'serial-no-wrap',2)
    elif group==GROUPS[7]:
        good=head(O)
        for at in (0,7,8,16,32,40,80,112,128,160,168,223,224,255):
            bad=replace(good,at,bytes([good[at]^1]));init_bad('corrupt-'+str(at),raw_initial(O,bad))
        for at,value in ((8,2),(16,0),(40,1),(160,2),(168,1)):
            bad=word(good,at,value)
            if at==16:bad=replace(bad,16,bytes(16))
            init_bad('well-hashed-invalid-'+str(at),raw_initial(O,rehash(bad)))
        for action in (2,6,9):
            f=Frame(engine,O,'bad-read-hash-'+str(action));f.to(action);f.claim()
            data=f.expected if action==2 else f.target;bad=replace(data,255,bytes([data[255]^1]))
            f.acknowledge(256,bad,reason=17 if action==2 else 18)
    elif group==GROUPS[8]:
        init_bad('generation-exhaustion',raw_initial(O,head(O,U64)))
        f=Frame(engine,O,'last-generation',head(O,U64-1));f.finish()
        require(O.decode_head(f.target)['generation']==U64,'last generation did not stay exact')
        prior=head(O,3,txn=TXN);init_bad('transaction-reuse',raw_initial(O,prior))
        init_bad('zero-transaction',raw_initial(O,head(O),txn=bytes(16)))
    elif group==GROUPS[9]:
        base=raw_initial(O,head(O))
        for size in (0,127,128,463,465):
            b=base[:size] if size<len(base) else base+bytes(size-len(base))
            init_bad('source-'+str(size),b,unchanged=True)
        for size in (0,1151):init_bad('output-'+str(size),base,output=bytes(size),unchanged=True)
        for size in (0,2047,2049):init_bad('workspace-'+str(size),base,workspace=bytes(size),unchanged=True)
        for at in (0,40,95,112,127):init_bad('header-'+str(at),replace(base,at,b'\xff'),unchanged=True)
        for at in (16,24,32):init_bad('init-word-'+str(at),word(base,at,1),unchanged=True)
        init_bad('zero-nonce',replace(base,96,bytes(16)),unchanged=True)
    elif group==GROUPS[10]:
        base=raw_initial(O,head(O))
        for at in (0,247,248,1104,2047):init_bad('dirty-init-'+str(at),base,
            workspace=replace(bytes(2048),at,b'\x01'),unchanged=True)
        for at in (0,8,24,96,144,248,256,512,768,1104,2047):
            f=Frame(engine,O,'corrupt-private-state-'+str(at));_,w=f.session.buffers();bad=replace(w,at,bytes([w[at]^1]))
            f.session.replace_private_workspace_for_control(bad);f.rejected(f.source(90,action=0),'invalid-seal-or-state')
        f=Frame(engine,O,'well-sealed-invalid-reserved');_,w=f.session.buffers();f.session.replace_private_workspace_for_control(seal(replace(w,144,b'\x01')))
        f.rejected(f.source(90,action=0),'well-sealed-malformed-state')
    elif group==GROUPS[11]:
        f=Frame(engine,O,'confirmed-terminal-observe');f.finish();f.observe();f.observe()
        for event in (1,2,3):f.rejected(f.source(event,action=1),'terminal-event-'+str(event))
        f.rejected(f.source(90,serial=f.serial-1,action=0),'stale-observe')
        f=Frame(engine,O,'conflict-terminal-observe',current=head(O,2));f.finish();f.observe()
    require(engine.cases,'whole head group absent')
    return dict(group=group,cases=engine.cases,independent_head_hash_oracle=True,independently_specified_action_traces=True,
        syscall_results_are_test_inputs=True,actual_filesystem_IO=False,durability=False,default=False)
