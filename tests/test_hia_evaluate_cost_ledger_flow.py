"""Run the source-bound cost continuation against the original Store transaction."""
from contextlib import ExitStack
import fcntl
from hashlib import sha256
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from hepta.hia_scalar_reference_native import sealed_reference_bytes
from tests.test_hia_evaluate_report_flow import unpack
from tools.generate_hia_evaluate_cost_ledger_flow import ADAPTER, MAGIC, PACKER, PORTS, SOURCE, adapter_source
from tools.generate_hia_native_filter import read_adapter_binding,verify_adapter
from tools.qualify_hia_selfhost import build_seed,compile_stage

ROOT=Path(__file__).resolve().parents[1]


def inherited(executable,files,directories,*,named=True,unseal=False,paths=False):
    with ExitStack() as stack:
        fds=[stack.enter_context(sealed_reference_bytes(x)) for x in files]
        if unseal:
            temp=stack.enter_context(tempfile.TemporaryFile())
            temp.write(files[0]);temp.flush();fds[0]=temp.fileno()
        for path in directories:
            fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY);stack.callback(os.close,fd);fds.append(fd)
        out=stack.enter_context(tempfile.TemporaryFile());err=stack.enter_context(tempfile.TemporaryFile())
        targets=tuple(range(104 if named else 3,(104 if named else 3)+len(fds)))
        actions=[]
        for fd,target in zip((*fds,out.fileno(),err.fileno()),(*targets,1,2),strict=True):
            duplicate=fcntl.fcntl(fd,fcntl.F_DUPFD_CLOEXEC,140)
            stack.callback(os.close,duplicate)
            actions.append((os.POSIX_SPAWN_DUP2,duplicate,target))
        if paths:
            selected=[*(str(i) for i in targets[:len(files)]),*(str(Path(x).absolute()) for x in directories)]
        else:
            selected=[str(i) for i in targets] if named else []
        args=[str(executable),*selected]
        child=os.posix_spawn(executable,args,{'PATH':''},file_actions=actions)
        _,status=os.waitpid(child,0)
        out.seek(0);err.seek(0)
        return os.waitstatus_to_exitcode(status),out.read(),err.read()


def compile_executable(out,compiler,label,source,packer,magic,*,canonical=False):
    app,_=compile_stage(out,label+'-core',compiler,(ROOT/source).read_bytes())
    packing,_=compile_stage(out,label+'-packer',compiler,(ROOT/packer).read_bytes())
    raw=app.read_bytes()
    if canonical:
        second,_=compile_stage(out,label+'-canonical',compiler,(ROOT/'examples/hia_bootstrap/worker_request.hepta').read_bytes())
        rendering=second.read_bytes()
        frame=struct.pack('<3Q',magic,len(raw),len(rendering))+raw+rendering
    else:
        frame=struct.pack('<2Q',magic,len(raw))+raw
    elf,_=compile_stage(out,label,packing,frame,output_extension='.elf')
    elf.chmod(0o500)
    return elf,raw


class LedgerFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from tools import generate_hia_evaluate_cost_ledger as application
        root=tempfile.TemporaryDirectory();cls.addClassCleanup(root.cleanup);out=Path(root.name)
        seed,_=build_seed(out)
        src=(ROOT/'examples/hia_bootstrap/selfhost.hepta').read_bytes()
        a,_=compile_stage(out,'cost-B1',seed,src,image_format='seed-shared')
        b,_=compile_stage(out,'cost-B2',a,src)
        cls.flow,image=compile_executable(out,b,'ledger-flow',SOURCE,PACKER,MAGIC)
        cls.ledger,_=compile_executable(out,b,'cost-image',application.SOURCE,application.PACKER,application.PACK_MAGIC,canonical=True)
        adapter=adapter_source((ROOT/ADAPTER).read_bytes(),(ROOT/PORTS).read_bytes())
        binding=read_adapter_binding((ROOT/PACKER).read_bytes(),adapter,calls=1)
        verify_adapter(cls.flow.read_bytes(),image,binding,entries=(0,))

    def test_invalid_paid_source_and_unsealed_authority_publish_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            files=[b'HIAEMF01'+bytes(1000),self.ledger.read_bytes(),self.ledger.read_bytes(),self.ledger.read_bytes()]
            for named,unseal in ((True,False),(True,True),(False,False)):
                self.assertEqual(inherited(self.flow,files,(tmp,tmp),named=named,unseal=unseal),(2,b'',b''))

    @unittest.skipUnless(os.environ.get('HIA_TEST_PAID_REPORT_BUNDLE'),'real paid HIA Store bundle')
    def test_real_store_prefix_and_frozen_policy(self):
        path=Path(os.environ['HIA_TEST_PAID_REPORT_BUNDLE'])
        data=path.read_bytes()
        state=Path(os.environ['HIA_TEST_PAID_REPORT_STATE'])
        release=Path(os.environ['HIA_TEST_LEDGER_STORE_RELEASE'])
        db=release/'hia-agent-store'; artifact=release/'hia-artifact'
        def direct(args,wire=b''):
            run=subprocess.run(args,input=wire,capture_output=True,env={'PATH':''},timeout=15)
            self.assertEqual((run.returncode,run.stderr),(0,b''));return run.stdout
        claim,_,decision,_=unpack(data)
        fresh=claim[648:]
        plan=direct([self.ledger],b'HIAELQ01'+fresh)
        rows=direct([db,state,'store',release],plan[176:])
        policy=direct([artifact,'store-get',state/'artifacts',plan[53:117].decode()])
        sections=(fresh,decision,rows,policy)
        expected=direct([self.ledger],struct.pack('<8s4Q',b'HIAELR01',*map(len,sections))+b''.join(sections))
        inputs=[data,self.ledger.read_bytes(),db.read_bytes(),artifact.read_bytes()]
        for named,paths in ((False,False),(True,False),(True,True)):
            status,raw,err=inherited(self.flow,inputs,(state,release),named=named,paths=paths)
            self.assertEqual((status,err),(0,b''))
            self.assertEqual(raw,expected)
        import json
        self.assertEqual(json.loads(expected)['evaluation_wall_ns_through_report'],
                         str(struct.unpack_from('<Q',decision,56)[0]))
        term_at=40+len(claim)
        decision_at=term_at+struct.unpack_from('<Q',data,16)[0]
        for index in (term_at+180,decision_at+56,decision_at+72):
            drift=bytearray(data);drift[index]^=1
            self.assertEqual(inherited(self.flow,[bytes(drift),*inputs[1:]],(state,release)),(2,b'',b''))
        with tempfile.TemporaryDirectory() as empty:
            symlink=Path(empty)/'state-link';symlink.symlink_to(state,target_is_directory=True)
            self.assertEqual(inherited(self.flow,inputs,(symlink,release),paths=True),(2,b'',b''))
            self.assertEqual(inherited(self.flow,inputs,(empty,release)),(2,b'',b''))
            self.assertEqual(inherited(self.flow,inputs,(state,empty)),(2,b'',b''))
        if 'HIA_TEST_LEDGER_FLOW_OUTPUT' in os.environ:
            Path(os.environ['HIA_TEST_LEDGER_FLOW_OUTPUT']).write_bytes(expected)
        print('paid report ledger',len(expected),sha256(expected).hexdigest())
