"""Run both real ELF arms against native HIA reference observations."""
from contextlib import ExitStack
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import tempfile
import time
import unittest

from hepta.hia_agent_service import _signatures
from hepta.hia_elf_shared_linker_native import NativeSharedLinker
from hepta.hia_program import verify_program
from hepta.hia_program_native import emit_program_machine
from hepta.hia_scalar_reference_native import sealed_reference_bytes
from tests.test_hia_program import b, c, f, i, jump, m, ret
from tools.generate_hia_evaluate_paired_batch import ADAPTER, PACKER, PACK_MAGIC, SOURCE
from tools.generate_hia_native_filter import read_adapter_binding, verify_adapter
from tools.qualify_hia_selfhost import compile_stage

ROOT = Path(__file__).resolve().parents[1]


def run_pair(executable, inputs, *, unsealed=None):
    with ExitStack() as stack:
        sources = [stack.enter_context(sealed_reference_bytes(data)) for data in inputs]
        if unsealed is not None:
            file = stack.enter_context(tempfile.TemporaryFile())
            file.write(inputs[unsealed])
            file.flush()
            sources[unsealed] = file.fileno()
        out = stack.enter_context(tempfile.TemporaryFile())
        err = stack.enter_context(tempfile.TemporaryFile())
        actions = []
        for fd, target in zip((*sources, out.fileno(), err.fileno()), (*range(3,3+len(inputs)),1,2), strict=True):
            copy = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 32)
            stack.callback(os.close, copy)
            actions.append((os.POSIX_SPAWN_DUP2, copy, target))
        child = os.posix_spawn(executable, [str(executable)], {'PATH': ''}, file_actions=actions)
        _, status = os.waitpid(child, 0)
        out.seek(0)
        err.seek(0)
        return os.waitstatus_to_exitcode(status), out.read(), err.read()


class PairedMeasurementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tests.test_hia_evaluate_reference_batch import NativeReferenceBatchTests
        from tools.build_hia_direct_call import assemble, ROLES
        NativeReferenceBatchTests.setUpClass()
        cls.addClassCleanup(NativeReferenceBatchTests.doClassCleanups)
        cls.reference = NativeReferenceBatchTests()
        root = cls.reference.owned.parent.parent
        compiler = root / 'B2.image.bin'
        image, _ = compile_stage(root, 'pair-image', compiler, (ROOT/SOURCE).read_bytes())
        packer, _ = compile_stage(root, 'pair-packer', compiler, (ROOT/PACKER).read_bytes())
        raw = image.read_bytes()
        cls.pair, _ = compile_stage(root, 'paired-role', packer,
            struct.pack('<2Q', PACK_MAGIC,len(raw))+raw, output_extension='.elf')
        cls.pair.chmod(0o500)
        binding = read_adapter_binding((ROOT/PACKER).read_bytes(), (ROOT/ADAPTER).read_bytes(), calls=1)
        verify_adapter(cls.pair.read_bytes(), raw, binding, entries=(0,))
        source, pack, adapter, _, _ = ROLES['direct-call']
        sources = {name: (ROOT/name).read_bytes() for name in (source,pack,adapter)}
        direct = root/'direct'
        direct.mkdir()
        binding = read_adapter_binding(sources[pack], sources[adapter], calls=1)
        cls.owner, _ = assemble(direct,compiler,sources,binding)
        link, _ = compile_stage(root,'shared-linker',compiler,
                                (ROOT/'examples/hia_bootstrap/elf_shared_linker.hepta').read_bytes())
        raw = link.read_bytes()
        cls.linker = NativeSharedLinker(raw, sha256(raw).hexdigest())

    def fixture(self, doc, cases, *, other=None, exports=(), warmup=2, repetitions=4, deadline=None, double=False):
        checked = verify_program(doc)
        def artifact(program):
            return self.linker.link(emit_program_machine(program,foreign_buffer_exports=exports).object_bytes)
        baseline = artifact(checked)
        candidate = baseline if other is None else artifact(verify_program(other))
        workload = dict(schema='hepta.hia.agent.workload.v1', cases=cases,
                        warmup_iterations=warmup, repetitions=repetitions)
        if exports:
            workload.update(schema='hepta.hia.agent.workload.v2',
                foreign_buffer_exports=[{'function': n,'max_buffer_bytes': s} for n,s in exports])
        code, reference, err = self.reference.invoke(checked, workload)
        self.assertEqual((code,err),(0,b''))
        data = json.dumps([_signatures(checked,exports),workload],separators=(',',':')).encode()
        limits = struct.pack('<8sQQ', b'HIAEPL01',64<<20,
                             time.monotonic_ns()+5_000_000_000 if deadline is None else deadline)
        inputs = [data,baseline,candidate,self.owner,reference,limits]
        if double:
            second = checked if other is None else verify_program(other)
            code, second_reference, err = self.reference.invoke(second,workload)
            self.assertEqual((code,err),(0,b''))
            inputs[5] = b'HIAEPL02'+limits[8:]
            inputs.extend((second_reference,checked.canonical_bytes,second.canonical_bytes))
        return inputs

    def result(self, fixture):
        code, raw, err = run_pair(self.pair,fixture)
        self.assertEqual((code,err),(0,b''), raw[:128])
        header = struct.unpack_from('<8s9Q',raw)
        self.assertEqual(header[0],b'HIAEPM01')
        self.assertEqual(len(raw),80+64*header[3])
        rows = list(struct.iter_unpack('<8Q',raw[80:]))
        return header, rows

    def archived(self, inputs):
        inputs = list(inputs)
        inputs[5] = b'HIAEPL03'+inputs[5][8:]
        code, data, errors = run_pair(self.pair,inputs)
        self.assertEqual((code,errors),(0,b''))
        magic,pair_size,event_size,count = struct.unpack_from('<8s3Q',data)
        self.assertEqual(magic,b'HIAEMT01')
        self.assertEqual(len(data),32+pair_size+event_size)
        pair = data[32:32+pair_size]
        header = struct.unpack_from('<8s9Q',pair)
        self.assertEqual((header[0],pair_size),(b'HIAEPM01',80+64*header[3]))
        samples = list(struct.iter_unpack('<8Q',pair[80:]))
        pos = 32+pair_size
        events = []
        for _ in range(count):
            row = struct.unpack_from('<8s11Q',data,pos)
            self.assertEqual(row[0],b'HIAEEV01')
            pos += 96
            raw_size = row[9]+row[10] if row[1] == 2 else row[7] if row[1] == 3 else 0
            events.append((row,data[pos:pos+raw_size]))
            pos += raw_size
        self.assertEqual(pos,len(data))
        return header,samples,events

    def test_archive_keeps_actual_exit_clocks_streams_and_loan_bytes(self):
        from tests.test_hia_agent_buffer_lifecycle import trap_program
        params = [('arg','mutbuf')]
        def writer(value):
            return m(f('write_input',params,['u32'],['write','trap'],[b('entry',params,[
                c('at','usize',0),c('value','u8',value),i('buffer.store',['arg','at','value']),
                c('ok','u32',0)],ret('ok'))]))
        cases = [{'function':'write_input','arguments':[{'bytes_hex':'0401'}]},
                 {'function':'write_input','arguments':[{'byte_length':0,'fill_byte':7}]}]
        inputs = self.fixture(writer(41),cases,exports=(('write_input',16),),double=True)
        # Make the selected ELF disagree without substituting a new reference.
        inputs[2] = self.linker.link(emit_program_machine(verify_program(writer(42)),
                              foreign_buffer_exports=(('write_input',16),)).object_bytes)
        before = time.monotonic_ns()
        h,samples,events = self.archived(inputs)
        after = time.monotonic_ns()
        self.assertEqual((h[1],h[8:10]),(1,(0,1)))
        self.assertEqual([event[0][1] for event in events],[1,2,3,4]*4)
        for n, (sample,expected) in enumerate(zip(samples,[bytes([41,1]),b'',bytes([42,1]),b''],strict=True)):
            begin,(owner,payload),(loan,snapshot),end = events[4*n:4*n+4]
            self.assertEqual([event[0][2:4] for event in events[4*n:4*n+4]],[sample[:2]]*4)
            clocks = (before,begin[0][4],owner[4],owner[5],loan[4],end[0][4],after)
            self.assertEqual(clocks,tuple(sorted(clocks)))
            self.assertEqual(owner[6],int.from_bytes(b'HIADRT01','little'))
            self.assertEqual(owner[7:9],(sample[3],0))
            self.assertEqual(owner[10],0)
            self.assertEqual(loan[5:8],(0,2,len(expected)))
            self.assertEqual(snapshot,expected)
            actual = b'' if sample[3] else struct.pack('<8s3Q',b'HIADRR02',*sample[4:7])
            self.assertEqual((owner[9],payload),(len(actual),actual))
        inputs = self.fixture(trap_program(),[{'function':'write_then_trap','arguments':[{'bytes_hex':'0807'}]}],
                              exports=(('write_then_trap',16),),double=True)
        h,samples,events = self.archived(inputs)
        self.assertEqual((h[1], [r[3] for r in samples]),(0,[2**64-6]*2))
        self.assertEqual([body for event,body in events if event[1]==3],[bytes([91,7])]*2)

    def test_archive_distinguishes_reaped_timeout_from_unstarted_reference(self):
        params = [('x','u64')]
        baseline = m(f('id',params,['u64'],[],[b('entry',params,[],ret('x'))]))
        loop = m(f('id',params,['u64'],[],[b('entry',params,[],jump('spin')),b('spin',[],[],jump('spin'))]))
        inputs = self.fixture(baseline,[{'function':'id','arguments':[4]}],double=True)
        inputs[2] = self.linker.link(emit_program_machine(verify_program(loop)).object_bytes)
        deadline = time.monotonic_ns()+300_000_000
        inputs[5] = struct.pack('<8sQQ',b'HIAEPL03',64<<20,deadline)
        h,samples,events = self.archived(inputs)
        self.assertEqual((h[1],h[8:10],len(samples)),(2,(0,1),1))
        self.assertEqual([e[0][1] for e in events],[1,2,4,1,2,4])
        owner,payload = events[4]
        self.assertEqual((owner[8],payload),(1,b''))
        self.assertGreaterEqual(owner[5],deadline)
        inputs[5] = struct.pack('<8sQQ',b'HIAEPL03',64<<20,1)
        h,samples,events = self.archived(inputs)
        self.assertEqual((h[1],samples,events),(2,[],[]))

    def test_distinct_real_arms_and_measurements(self):
        params=[('x','i64')]
        def doc(value):
            ops = [c('addend','i64',value), i('int.add.wrap',['x','addend'],[('y','i64')])]
            return m(f('answer',params,['i64'],[],[b('entry',params,ops,ret('y'))]))
        cases = [{'function':'answer','arguments':[-4]}, {'function':'answer','arguments':[27]}]
        h, rows = self.result(self.fixture(doc(0),cases))
        self.assertEqual(h[1:4], (0,2,4))
        self.assertGreater(min(h[4:6]),0)
        self.assertEqual(h[6:8],(8,8))
        self.assertEqual([(r[0],r[1],r[4]) for r in rows],[(0,0,2**64-4),(1,0,27),(0,1,2**64-4),(1,1,27)])
        self.assertEqual(h[4],sum(r[5] for r in rows if r[1]==0))
        self.assertEqual(h[5],sum(r[5] for r in rows if r[1]==1))
        h, rows = self.result(self.fixture(doc(0),cases,other=doc(1)))
        self.assertEqual((h[1],h[8:10]), (1,(0,1)))
        self.assertEqual([r[4] for r in rows if r[1] == 1], [2**64-3,28])

    def test_loan_snapshots_and_signal_confirmed_traps(self):
        from tests.test_hia_agent_buffer_lifecycle import trap_program
        params=[('arg','mutbuf')]
        def writer(value):
            return m(f('write_input',params,['u32'],['write','trap'],[b('entry',params,[
                c('at','usize',0), c('value','u8',value), i('buffer.store',['arg','at','value']),
                c('ok','u32',0)],ret('ok'))]))
        cases=[{'function':'write_input','arguments':[{'bytes_hex':'0401'}]},
               {'function':'write_input','arguments':[{'byte_length':0,'fill_byte':7}]}]
        h, rows = self.result(self.fixture(writer(41),cases,exports=(('write_input',16),)))
        self.assertEqual(h[1:4],(0,2,4))
        self.assertEqual([(r[0],r[3],r[7]) for r in rows],[(0,0,2),(1,2**64-6,0)]*2)
        h, rows = self.result(self.fixture(writer(41),cases,other=writer(42),exports=(('write_input',16),)))
        self.assertEqual((h[1],h[3],h[8:10],rows[2][4]), (1,4,(0,1),0))
        trap=trap_program()
        case={'function':'write_then_trap','arguments':[{'bytes_hex':'0807'}]}
        h, rows = self.result(self.fixture(trap,[case],exports=(('write_then_trap',16),)))
        self.assertEqual(h[1],0)
        self.assertEqual([(r[3],r[7]) for r in rows],[(2**64-6,2)]*2)

    def test_two_reference_values_and_ledger_have_public_scope(self):
        params = [('x','u32')]
        cases = [{'function':'answer','arguments':[n], 'expected':{'status':'returned','values':[n]}} for n in (37,9)]
        plain = m(f('answer',params,['u32'],[],[b('entry',params,[],ret('x'))]))
        # More reference steps have no effect on observable agreement.
        extra = m(f('answer',params,['u32'],[],[b('entry',params,[
            c('zero','u32',0),i('int.add.wrap',['x','zero'],[('y','u32')])],ret('y'))]))
        h, rows = self.result(self.fixture(plain,cases,other=extra,double=True))
        self.assertEqual((h[1],len(rows)),(0,4))
        # Equal native outputs but a real owner lifetime changes the ledger.
        resource = m(f('answer',params,['u32'],['alloc','write','trap'],[b('entry',params,[
            c('n','usize',3),i('buffer.new',['n'],[('storage','buffer')]),i('owner.drop',['storage'])
            ],ret('x'))]))
        h, rows = self.result(self.fixture(plain,cases,other=resource,double=True))
        self.assertEqual((h[1],h[8:10]),(1,(0,2)))
        self.assertEqual([r[4] for r in rows],[37,9,37,9])
        cases[0]['expected']['values'] = [38]
        h, rows = self.result(self.fixture(plain,cases,double=True))
        self.assertEqual((h[1],h[8:10],rows),(5,(0,2),[]))

    def test_candidate_reference_budget_and_malformed_shape_precede_native(self):
        params = [('x','u32')]
        base = m(f('answer',params,['u32'],[],[b('entry',params,[],ret('x'))]))
        recursive = m(f('answer',params,['u32'],[],[b('entry',params,[
            i('call',['x'],[('v','u32')],function='answer')],ret('v'))]))
        cases = [{'function':'answer','arguments':[7]},{'function':'answer','arguments':[9]}]
        inputs = self.fixture(base,cases,other=recursive,double=True)
        h, rows = self.result(inputs)
        self.assertEqual((h[1],h[8:10],rows),(2,(0,2),[]))
        inputs = self.fixture(base,cases,double=True)
        inputs[6] += b'x'
        self.assertEqual(run_pair(self.pair,inputs),(2,b'',b''))

    def test_two_reference_snapshots_and_declarations_use_exact_sha256(self):
        from tests.test_hia_agent_buffer_lifecycle import byte_program
        from hepta.hia_agent_buffers import buffer_observation
        args = [{'bytes_hex':'005aff'}, {'byte_length':5,'fill_byte':165}]
        observed = [buffer_observation(0,'readbuf',bytes.fromhex('005aff')),
                    buffer_observation(1,'mutbuf',bytes.fromhex('005affa5a5'))]
        case = {'function':'copy_bytes','arguments':args,
                'expected':{'status':'returned','values':[0],'buffers':observed}}
        exports=(('copy_bytes',16),)
        base = self.fixture(byte_program(),[case],exports=exports,double=True)
        h, rows = self.result(base)
        self.assertEqual((h[1],len(rows),rows[0][7]),(0,2,8))
        changed = list(base)
        changed[6] = base[6][:-1] + bytes((base[6][-1]^1,))
        h, rows = self.result(changed)
        self.assertEqual((h[1],h[8:10],len(rows)),(1,(0,2),2))
        case['expected']['buffers'][1]['sha256'] = '00'*32
        h, rows = self.result(self.fixture(byte_program(),[case],exports=exports,double=True))
        self.assertEqual((h[1],h[8:10],rows),(5,(0,2),[]))
        for slot in (6,7,8):
            with self.subTest(unsealed_reference_or_core=slot):
                self.assertEqual(run_pair(self.pair,base,unsealed=slot),(2,b'',b''))

    def test_two_reference_trap_classes_and_chain_ledger_presence(self):
        def trapped(code):
            return m(f('test',[],['u32'],['trap'],[b('entry',[],[],{'op':'trap','code':code})]))
        cases=[{'function':'test','arguments':[], 'expected':{'status':'trapped'}}]
        h, rows = self.result(self.fixture(trapped('bounds'),cases,other=trapped('user'),double=True))
        self.assertEqual((h[1],h[8:10]),(1,(0,2)))
        self.assertEqual([r[3] for r in rows],[2**64-6,2**64-6])
        from hepta.hia_schema import PRIMITIVE_PROFILES, supports_feature
        same = m(f('test',[],['u32'],[],[b('entry',[],[c('a','u32',0)],ret('a'))]))
        with_chains = dict(same,schema=next(k for k in PRIMITIVE_PROFILES if supports_feature(k,'recursive_chain')))
        h, rows = self.result(self.fixture(same,[{'function':'test','arguments':[]}],
                                         other=with_chains,double=True))
        self.assertEqual((h[1],h[8:10],len(rows)),(1,(0,2),2))

    def test_read_and_mutable_loans_are_separate_for_every_arm_and_call(self):
        from tests.test_hia_agent_buffer_lifecycle import byte_program
        cases = [{'function':'copy_bytes','arguments':[{'bytes_hex':'005aff'},
                                                       {'byte_length':5,'fill_byte':165}]}]
        args = self.fixture(byte_program(),cases,exports=(('copy_bytes',16),))
        h, rows = self.result(args)
        self.assertEqual(h[1:4],(0,1,2))
        self.assertEqual([(r[3],r[4],r[7]) for r in rows],[(0,0,8)]*2)

    def test_supervisor_stops_and_reaps_running_candidate_at_real_deadline(self):
        params = [('x','u64')]
        baseline = m(f('id',params,['u64'],[],[b('entry',params,[],ret('x'))]))
        loop = m(f('id',params,['u64'],[],[b('entry',params,[],jump('spin')),
                                          b('spin',[],[],jump('spin'))]))
        data = self.fixture(baseline,[{'function':'id','arguments':[4]}],other=loop)
        started = time.monotonic_ns()
        data[5] = struct.pack('<8sQQ',b'HIAEPL01',64<<20,started+300_000_000)
        h, rows = self.result(data)
        self.assertEqual((h[1],h[8:10]),(2,(0,1)))
        self.assertEqual([(r[0],r[1],r[4]) for r in rows],[(0,0,4)])
        self.assertGreaterEqual(time.monotonic_ns()-started,300_000_000)

    def test_deadline_malformed_ownership_and_unsealed_inputs(self):
        params=[('x','u64')]
        doc=m(f('id',params,['u64'],[],[b('entry',params,[],ret('x'))]))
        cases=[{'function':'id','arguments':[42]}]
        data=self.fixture(doc,cases,deadline=1)
        h, rows=self.result(data)
        self.assertEqual((h[1],rows),(2,[]))
        data=self.fixture(doc,cases)
        for i in (1,3,4,5):
            with self.subTest(unsealed=i):
                self.assertEqual(run_pair(self.pair,data,unsealed=i),(2,b'',b''))
        data[4] += b'trailing'
        self.assertEqual(run_pair(self.pair,data),(2,b'',b''))
        data=self.fixture(doc,cases)
        data[3]=self.reference.owned.read_bytes()
        self.assertEqual(run_pair(self.pair,data),(2,b'',b''))
