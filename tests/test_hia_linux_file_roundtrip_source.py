"""Exact source and VM controls for the explicitly selected roundtrip profile."""
from pathlib import Path
import base64
from hashlib import sha256
import json
import os
import tempfile
import traceback
import unittest
from unittest.mock import patch
import zlib

ROOT = Path(__file__).resolve().parents[1]
CAPACITY = 1048576
FUEL = 10000000


class LinuxFileRoundtripSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        external=os.environ.get('HEPTA_HIA_CANDIDATE_BUILD_TEST_EVIDENCE')
        cls.temporary=None if external else tempfile.TemporaryDirectory(prefix='hia-roundtrip-source-')
        parent=Path(external) if external else Path(cls.temporary.name)
        cls.evidence=parent/'linux-file-roundtrip-source'
        cls.evidence.mkdir(parents=True,exist_ok=False)

    @classmethod
    def tearDownClass(cls):
        if cls.temporary is not None:
            cls.temporary.cleanup()

    def save(self,name,value):
        data=value if type(value) is bytes else (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
        with (self.evidence/name).open('xb') as stream:
            stream.write(data)

    def test_four_assets_reproduce_twice_and_verify_independently(self):
        from hepta.hia_agent_assembly import assemble_program,render_assembly
        from hepta.hia_program import verify_program
        from hepta.hia_linux_file_roundtrip import PROFILE
        from tools import generate_hia_selfhost_linux_file_roundtrip as compiler
        from tools import generate_hia_linux_file_roundtrip_entry as entry
        from tools import generate_hia_native_file_roundtrip as controller
        from tools import generate_hia_file_render_checker_v4 as checker
        authors=(
            ('selfhost_linux_file_roundtrip',compiler.generated,None),
            ('linux_file_roundtrip_entry_packer',entry.generated,None),
            ('native_file_roundtrip',lambda:render_assembly(controller.document(),profile=PROFILE),PROFILE),
            ('file_render_checker_v4',lambda:render_assembly(checker.document()[0]),None),
        )
        rows=[]
        try:
            for name,generate,profile in authors:
                with self.subTest(asset=name):
                    first,second=generate().encode(),generate().encode()
                    self.assertEqual(first,second)
                    self.assertEqual(first,(ROOT/f'examples/hia_bootstrap/{name}.hepta').read_bytes())
                    doc=assemble_program(first,profile=profile)
                    verify_program(doc,profile=profile)
                    rows.append(dict(asset=name,bytes=len(first),sha256=sha256(first).hexdigest(),
                                     functions=len(doc.as_dict()['functions']),profile=profile,independent_verification=True))
        finally:
            self.save('SOURCE-GENERATION.json',dict(rows=rows,Native_compiles=0,whole_native=False))

    def test_public_dispatch_preserves_all_twelve_original_reference_cases(self):
        import hepta.hia_linux_file_roundtrip as selected
        from hepta.hia_program_runtime import execute_program
        from hepta.hia_program import HIAProgramRejected
        sentinel=object()
        calls=[]
        rows=[]
        def receiver(*args,**kwargs):
            calls.append((args,kwargs))
            return sentinel
        try:
            with patch.object(selected,'execute_linux_file_roundtrip',receiver):
                components,provider,startup=object(),object(),object()
                actual=execute_program('program','entry',(1,),profile=selected.PROFILE,
                    linux_file_provider=provider,linux_process_startup=startup,
                    linux_file_roundtrip_components=components,max_steps=7654321,
                    max_heap_bytes=123456,allocation_fail_at=7,max_call_depth=98)
                self.assertIs(actual,sentinel)
                self.assertEqual(len(calls),1)
                args,kwargs=calls.pop()
                self.assertEqual(args,('program','entry',(1,)))
                self.assertEqual(kwargs,dict(provider=provider,startup=startup,components=components,
                    max_steps=7654321,max_heap_bytes=123456,allocation_fail_at=7,max_call_depth=98))
                rows.append('selected forwards actual arguments and unchanged limits')
                class Foreign(str):
                    def __eq__(self,other):
                        raise AssertionError('foreign equality callback')
                for label,profile in [('unselected',None),('old-file-render','hepta.hia.linux-file-render.v3'),
                        ('old-file','hepta.hia.linux-file.v1'),('stdio','hepta.hia.linux-stdio.v1'),
                        ('non-string',7),('string-subclass',Foreign(selected.PROFILE))]:
                    with self.subTest(profile=label):
                        with self.assertRaises(HIAProgramRejected) as caught:
                            execute_program(None,'f0',(),profile=profile,linux_file_roundtrip_components=components)
                        self.assertEqual(caught.exception.code,'E_HIA_LINUX_FILE_ROUNDTRIP_PROFILE')
                        self.assertEqual(calls,[])
                        rows.append(label+' cannot use roundtrip components')
                for name in ('bounded_resource_limits','linux_stdio_provider','linux_process_provider',
                             'linux_cli_components','linux_file_render_components'):
                    with self.subTest(mixed_authority=name):
                        with self.assertRaises(HIAProgramRejected) as caught:
                            execute_program(None,'f0',(),profile=selected.PROFILE,
                                linux_file_roundtrip_components=components,**{name:object()})
                        self.assertEqual(caught.exception.code,'E_HIA_LINUX_FILE_RENDER_PROFILE')
                        self.assertEqual(calls,[])
                        rows.append('reject mixed '+name)
                self.assertEqual(len(rows),12)
        finally:
            self.save('SOURCE-DISPATCH.json',dict(rows=rows,stub_only_reference_dispatch=True,
                                                 actual_HIA_invocations=0,whole_native=False))

    def test_complete_vm_roundtrip_retains_all_three_original_full_buffers(self):
        from hepta.hia_program_runtime import execute_program
        from hepta.hia_linux_file_roundtrip import PROFILE,LinuxStartupSnapshot
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_program import verify_program
        fixture=json.loads((ROOT/'tests/fixtures/hia_linux_file_roundtrip_source_frames.zlib.json').read_bytes())
        raw=base64.b64decode(fixture['input_base64'],validate=True)
        status_bytes=base64.b64decode(fixture['stat_base64'],validate=True)
        expected={}
        for name,field in fixture['fields'].items():
            data=zlib.decompress(base64.b64decode(field['zlib_base64'],validate=True))
            self.assertEqual(len(data),field['bytes'])
            self.assertEqual(sha256(data).hexdigest(),field['sha256'])
            expected[name]=data
        self.assertEqual({n:len(v) for n,v in expected.items()},
                         dict(file=8388609,output=CAPACITY,workspace=CAPACITY))
        path=b'/hia-source-only/frozen-input.json'
        sent={1:[],2:[]}
        calls=[]
        cursor=0
        def provider(request):
            nonlocal cursor
            operation=request.operation
            row=dict(operation=operation,fd=request.fd,offset=request.offset,
                     count=request.count,extent=request.extent)
            calls.append(row)
            if operation=='linux.file.open':
                self.assertEqual(request.path,path+b'\0')
                self.assertIsNone(request.fd)
                self.assertEqual(request.flags,0xa0800)
                response=(3,b'')
            elif operation=='linux.file.fdflags':
                self.assertEqual(request.fd,3)
                response=(1,b'')
            elif operation=='linux.file.statusflags':
                self.assertEqual(request.fd,3)
                response=(0x28800,b'')
            elif operation=='linux.file.stat':
                self.assertEqual((request.fd,request.count),(3,144))
                response=(0,status_bytes)
            elif operation=='linux.file.read':
                self.assertEqual(request.fd,3)
                payload=raw[cursor:cursor+request.count]
                cursor+=len(payload)
                response=(len(payload),payload)
            elif operation=='linux.file.close':
                self.assertEqual(request.fd,3)
                response=(0,b'')
            else:
                self.assertIn(operation,('linux.stdout.write','linux.stderr.write'))
                self.assertIn(request.fd,(1,2))
                sent[request.fd].append(request.write_bytes)
                response=(request.count,b'')
            row.update(result=response[0],payload_bytes=len(response[1]),
                       payload_sha256=sha256(response[1]).hexdigest())
            return response
        program=assemble_program((ROOT/'examples/hia_bootstrap/native_file_roundtrip.hepta').read_bytes(),profile=PROFILE)
        components=tuple((ROOT/name).read_bytes() for name in (
            'examples/hia_bootstrap/core_representation_private.hepta',
            'examples/hia_bootstrap/file_render_checker_v4.hepta'))
        initial=(bytes(8388609),bytes(CAPACITY),bytes(CAPACITY))
        for name,data in zip(('file','output','workspace'),initial):
            self.save('INITIAL-'+name+'.bin',data)
        self.save('INPUT.json',raw)
        self.save('STAT.bin',status_bytes)
        result=None
        error=None
        try:
            result=execute_program(program,'f0',initial,profile=PROFILE,
                linux_file_provider=provider,linux_file_roundtrip_components=components,
                linux_process_startup=LinuxStartupSnapshot((b'hia-native-file-roundtrip',b'render-assembly',path),
                                                         (b'LC_ALL=C.UTF-8',)),max_steps=FUEL)
            self.assertEqual(result['status'],'returned')
            self.assertEqual(result['values'],[0])
            self.assertLessEqual(result['steps'],FUEL)
            actual={name:bytes.fromhex(result[field]) for field,name in (
                ('source_hex','file'),('output_hex','output'),('workspace_hex','workspace'))}
            for name in expected:
                with self.subTest(full_buffer=name):
                    self.assertEqual(actual[name],expected[name])
            stdout,stderr=b''.join(sent[1]),b''.join(sent[2])
            self.assertEqual(stdout,base64.b64decode(fixture['stdout_base64'],validate=True))
            self.assertEqual(stderr,base64.b64decode(fixture['stderr_base64'],validate=True))
            canonical=verify_program(raw).canonical_bytes
            self.assertEqual(actual['file'][:len(raw)],raw)
            self.assertEqual(actual['file'][CAPACITY:CAPACITY+len(canonical)],canonical)
            self.assertEqual(actual['output'][:len(canonical)],canonical)
            self.assertEqual(actual['file'][2*CAPACITY:2*CAPACITY+len(stdout)],stdout)
            residents=[row for row in result['effects'] if row['operation'].startswith('linux.roundtrip.')]
            self.assertEqual([row['operation'] for row in residents],[
                'linux.roundtrip.representation','linux.roundtrip.semantic',
                'linux.roundtrip.representation','linux.roundtrip.representation','linux.roundtrip.representation'])
            self.assertEqual([residents[i]['result'] for i in (2,4)],[len(canonical)]*2)
        except BaseException as exc:
            if result is None and hasattr(exc,'report'):
                result=exc.report
            error=traceback.format_exc()
            raise
        finally:
            report={} if result is None else dict(result)
            members={}
            for field,name in [('source_hex','file'),('output_hex','output'),('workspace_hex','workspace')]:
                if field in report:
                    data=bytes.fromhex(report.pop(field))
                    filename='FINAL-'+name+'.bin'
                    self.save(filename,data)
                    members[name]=dict(path=filename,bytes=len(data),sha256=sha256(data).hexdigest())
            report.update(full_buffer_members=members,error=error,VM_step_limit=FUEL,
                          Source_only=True,Native_invocations=0,whole_native=False)
            self.save('VM-REPORT.json',report)
            self.save('PROVIDER.json',calls)
            self.save('STDOUT.bin',b''.join(sent[1]))
            self.save('STDERR.bin',b''.join(sent[2]))


if __name__ == '__main__':
    unittest.main()
