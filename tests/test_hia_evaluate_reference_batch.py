"""Execute fresh, sealed workload cases through both native reference roles."""

from contextlib import ExitStack
import fcntl
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hepta.hia_program import verify_program
from hepta.hia_scalar_reference_native import sealed_reference_bytes
from hepta.hia_scalar_reference_wire import program_wire, RESOURCE_PROGRAM_MAGIC
from tests.test_hia_program import b, c, f, i, m, ret, resource_program
from tests.test_hia_returned_loans import loan_program
from tools.generate_hia_evaluate_reference_batch import ADAPTER, PACKER, PACK_MAGIC, SOURCE
from tools.generate_hia_native_filter import (EVALUATE_PROJECTOR_FILTER_MAGIC, read_adapter_binding,
                                            verify_adapter)
from tools.generate_hia_owned_reference import ADAPTER_PATH, PACKER_PATH, SOURCE_PATH
from tools.qualify_hia_selfhost import build_seed, compile_stage

ROOT = Path(__file__).resolve().parents[1]
HEADER = struct.Struct('<3Q')
RESULT = int.from_bytes(b'HIAEBT01', 'little')


def native_batch(executable, descriptors):
    # CLOEXEC duplicates above the protocol FDs make every source independent
    # of the caller's descriptor table. posix_spawn performs all bindings.
    with ExitStack() as stack, tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        duplicates = []
        for fd in (*descriptors, out.fileno(), err.fileno()):
            duplicate = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 16)
            stack.callback(os.close, duplicate)
            duplicates.append(duplicate)
        actions = [(os.POSIX_SPAWN_DUP2, fd, dst) for fd, dst in zip(duplicates, (3,4,5,6,1,2), strict=True)]
        child = os.posix_spawn(executable, [str(executable)], {'PATH': ''}, file_actions=actions)
        _, status = os.waitpid(child, 0)
        out.seek(0)
        err.seek(0)
        return os.waitstatus_to_exitcode(status), out.read(), err.read()


def oracle(checked, case, exports, executable):
    name, arguments = case['function'], case['arguments']
    body, registers, bounce, returns, _ = program_wire(checked.canonical_bytes, name, allow_resources=True)
    fn = next(row for row in checked.as_dict()['functions'] if row['name'] == name)
    values, records, regions = [], [], []
    for index, (param, arg) in enumerate(zip(fn['params'], arguments, strict=True)):
        if param['type'] in ('readbuf','mutbuf'):
            data = (bytes.fromhex(arg['bytes_hex']) if 'bytes_hex' in arg else bytes((arg['fill_byte'],))*arg['byte_length'])
            records.extend((index, int(param['type']=='mutbuf'),len(data)))
            regions.append(data)
            values.append(0)
        else:
            values.append(int(arg or 0) & ((1<<64)-1))
    header = struct.pack('<8Q',RESOURCE_PROGRAM_MAGIC,10_000_000 if name in exports else 1_000_000,
                         256,registers,bounce,len(body),len(values),len(returns))
    words = [*values,16<<20,0]
    if regions:
        words += [len(regions),*records]
    command = header+body[64:]+struct.pack(f'<{len(words)}Q',*words)+b''.join(regions)
    return subprocess.run([executable],input=command, capture_output=True, check=True, timeout=5).stdout


class NativeReferenceBatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_owned_reference_cli import assemble
        temp = tempfile.TemporaryDirectory(prefix='hia-native-evaluate-batch-')
        cls.addClassCleanup(temp.cleanup)
        build = Path(temp.name)
        seed,_ = build_seed(build)
        selfhost = (ROOT/'examples/hia_bootstrap/selfhost.hepta').read_bytes()
        first,_=compile_stage(build,'B1',seed,selfhost,image_format='seed-shared')
        compiler,_=compile_stage(build,'B2',first,selfhost)
        if first.read_bytes()!=compiler.read_bytes():
            raise AssertionError('independent selfhost generations disagree')
        def elf(name, source, packer, magic):
            image,_=compile_stage(build,name+'-image',compiler,(ROOT/source).read_bytes())
            pack,_=compile_stage(build,name+'-packer',compiler,(ROOT/packer).read_bytes())
            raw=image.read_bytes()
            output,_=compile_stage(build,name,pack,struct.pack('<2Q',magic,len(raw))+raw,output_extension='.elf')
            output.chmod(0o500)
            return output,raw
        cls.batch,raw=elf('batch',SOURCE,PACKER,PACK_MAGIC)
        binding=read_adapter_binding((ROOT/PACKER).read_bytes(),(ROOT/ADAPTER).read_bytes(),calls=1)
        verify_adapter(cls.batch.read_bytes(),raw,binding,entries=(0,))
        cls.projector,_=elf('projector',SOURCE.with_name('evaluate_reference_wire.hepta'),
                           SOURCE.with_name('evaluate_reference_wire_filter_packer.hepta'),EVALUATE_PROJECTOR_FILTER_MAGIC)
        owned=build/'owned-runtime'
        owned.mkdir()
        sources={name:(ROOT/name).read_bytes() for name in (ADAPTER_PATH,PACKER_PATH,SOURCE_PATH)}
        binding=read_adapter_binding(sources[PACKER_PATH],sources[ADAPTER_PATH],calls=2)
        binary,_=assemble(owned,compiler,sources,binding)
        cls.owned=owned/'hia-owned'
        cls.owned.write_bytes(binary)
        cls.owned.chmod(0o500)

    def invoke(self, checked, workload, *, program_fd=None):
        with ExitStack() as stack:
            def seal(data):
                return stack.enter_context(sealed_reference_bytes(data))
            fds=(seal(checked.canonical_bytes) if program_fd is None else program_fd,
                 seal(json.dumps(workload,separators=(',',':')).encode()),seal(self.projector.read_bytes()),seal(self.owned.read_bytes()))
            return native_batch(self.batch,fds)

    def compare(self, doc, cases, *, exports=None, completed=None):
        checked=verify_program(doc)
        workload={'schema':'hepta.hia.agent.workload.v1','warmup_iterations':0,'repetitions':1,'cases':cases}
        if exports:
            workload['schema']='hepta.hia.agent.workload.v2'
            workload['foreign_buffer_exports']=[{'function':name,'max_buffer_bytes':size} for name,size in exports.items()]
        code,raw,err=self.invoke(checked,workload)
        self.assertEqual((code,err),(0,b''),raw[:128])
        done=len(cases) if completed is None else completed
        self.assertEqual(HEADER.unpack_from(raw),(RESULT,len(cases),done))
        offset=HEADER.size
        for i,case in enumerate(cases[:done]):
            idx,n=struct.unpack_from('<2Q',raw,offset)
            offset+=16
            self.assertEqual(idx,i)
            self.assertEqual(raw[offset:offset+n],oracle(checked,case,exports or {},self.owned))
            offset+=n
        self.assertEqual(offset,len(raw))

    def test_scalar_resource_and_trap_cases(self):
        doc=resource_program()
        scalar=f('identity',[('x','i64')],['i64'],[],[b('entry',[('x','i64')],[],ret('x'))])
        doc['functions'].append(scalar)
        doc.pop('exports',None)
        self.compare(doc,[{'function':'identity','arguments':[-5]},{'function':'owned','arguments':[3,250]},
                          {'function':'owned','arguments':[0,250]},{'function':'identity','arguments':[7]}])
        recursive=loan_program('read','recursive')
        self.compare(recursive,[{'function':recursive['exports'][0],'arguments':[20,211]}])

    def test_captured_external_spans_and_atomic_invalid_case(self):
        params=[('arg','mutbuf')]
        fn=f('write_input',params,['u32'],['write','trap'],[b('entry',params,[
            c('at','usize',1),c('value','u8',197),i('buffer.store',['arg','at','value']),
            c('ok','u32',0)],ret('ok'))])
        doc=m(fn)
        cases=[{'function':'write_input','arguments':[{'bytes_hex':'010203'}]},
               {'function':'write_input','arguments':[{'byte_length':0,'fill_byte':255}]},
               {'function':'write_input','arguments':[{'byte_length':12,'fill_byte':31}]}]
        self.compare(doc,cases,exports={'write_input':16})
        checked=verify_program(doc)
        workload={'schema':'hepta.hia.agent.workload.v2','foreign_buffer_exports':[{'function':'write_input','max_buffer_bytes':16}],
                  'cases':[*cases,{'function':'write_input','arguments':[{'bytes_hex':'not-hex'}]}]}
        self.assertEqual(self.invoke(checked,workload),(2,b'',b''))
        workload['cases'] = cases
        private=tempfile.TemporaryFile()
        with private:
            private.write(checked.canonical_bytes)
            private.flush()
            self.assertEqual(self.invoke(checked,workload,program_fd=private.fileno()),(2,b'',b''))

    def test_sealed_descriptor_arguments_and_effective_budgets(self):
        checked = verify_program(resource_program())
        case = {'function': 'owned', 'arguments': [3, 250]}
        workload = {'schema': 'hepta.hia.agent.workload.v1', 'cases': [case]}
        with ExitStack() as stack:
            fds = [stack.enter_context(sealed_reference_bytes(data)) for data in
                   (checked.canonical_bytes, json.dumps(workload).encode(),
                    self.projector.read_bytes(), self.owned.read_bytes())]
            expected = native_batch(self.batch, fds)
            self.assertEqual((expected[0], expected[2]), (0, b''))
            def call(descriptors, memory, nanoseconds):
                args = [str(self.batch), *map(str, descriptors), str(memory), str(nanoseconds)]
                proc = subprocess.run(args, pass_fds=tuple(fds), capture_output=True, timeout=3)
                return proc.returncode, proc.stdout, proc.stderr
            self.assertEqual(call(fds, 536870912, 1000000000), expected)
            for descriptors, memory, duration in ((fds, 65536, 1000000000),
                                                   (fds, 536870912, 0),
                                                   (fds, 536870912, 86400000000001),
                                                   ([999999, *fds[1:]], 536870912, 1000000000)):
                with self.subTest(memory=memory, duration=duration, descriptors=descriptors):
                    self.assertEqual(call(descriptors, memory, duration), (2, b'', b''))

    def test_reference_budget_stops_batch_in_order(self):
        params=[('x','u32')]
        fn=f('recur',params,['u32'],[],[b('entry',params,[
             i('call',['x'],[('out','u32')],function='recur')],ret('out'))])
        self.compare(m(fn),[{'function':'recur','arguments':[0]},{'function':'recur','arguments':[1]}],completed=1)
