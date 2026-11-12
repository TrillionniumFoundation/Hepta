"""Independent Core/ld controls, native resolution and real linked execution."""
from __future__ import annotations
import ctypes
from hashlib import sha256
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from hepta.hia_agent_assembly import assemble_program,render_assembly
from hepta.hia_program import execute_program
from hepta.hia_program_runtime import _Machine,_Owner,_View
from tools.generate_hia_elf_linker import MAGIC,WORKSPACE_BYTES,document
from tools.generate_hia_native_filter import MAGIC as FILTER_MAGIC,document as filter_document
from tools.qualify_hia_selfhost import build_seed,compile_stage,INVALID,NO_SPACE
ROOT=Path(__file__).resolve().parents[1]


def frame(objects,entry=b'entry'):
    return struct.pack('<4Q',MAGIC,len(objects),len(entry),0)+entry+b''.join(struct.pack('<Q',len(v))+v for v in objects)


def reference(checked,payload,capacity=65536,workspace=WORKSPACE_BYTES):
    machine=_Machine(checked,50000000,64<<20,None,256)
    roots=[_Owner(-1,bytearray(payload)),_Owner(-2,bytearray(b'\xa5'*capacity)),_Owner(-3,bytearray(b'\xa5'*workspace))]
    value=machine.invoke(checked.as_dict()['functions'][0],[_View(roots[0],False),_View(roots[1],True),_View(roots[2],True)])
    return value[0],bytes(roots[1].data)


def sections(obj):
    start=struct.unpack_from('<Q',obj,40)[0];n=struct.unpack_from('<H',obj,60)[0]
    return [(start+i*64,struct.unpack_from('<IIQQQQIIQQ',obj,start+i*64)) for i in range(n)]


class ElfLinkerSourceTests(unittest.TestCase):
    def test_checked_in_linker_and_filter_are_exact_ordinary_Core(self):
        for name,doc in (('elf_static_linker',document()),('native_filter_packer',filter_document())):
            source=render_assembly(doc)
            self.assertEqual((ROOT/f'examples/hia_bootstrap/{name}.hepta').read_text(),source)
            assemble_program(source)
            self.assertLessEqual(len(doc['functions']),128)
            self.assertLessEqual(sum(len(f['blocks']) for f in doc['functions']),1536)
            for f in doc['functions']:
                self.assertLessEqual(len(f['blocks']),256)
                for b in f['blocks']:self.assertLessEqual(len(b['params']),16)


class ElfLinkerNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='hia-elf-linker-tests-');cls.folder=Path(cls.tmp.name);cls.serial=0
        cls.checked=assemble_program(render_assembly(document()));cls.packer_checked=assemble_program(render_assembly(filter_document()))
        cls.c_main=cls.c_object('caller','extern unsigned long long answer(void); volatile int data=7; unsigned long long zeros[4]; int entry(void){ if(zeros[0]!=0) return 91; zeros[1]=answer(); return (int)(zeros[1]+data); }')
        cls.c_answer=cls.c_object('answer','unsigned long long answer(void){return 30;}')
        wire=frame([cls.c_main,cls.c_answer]);cls.basic_wire=wire
        cls.reference_value,cls.reference_output=reference(cls.checked,wire)
        assert 0<cls.reference_value<65536
        cls.run_elf(cls.reference_output[:cls.reference_value],37,'independent-Core')
        # Foreign linker and independently executed Core controls precede B0.
        start=cls.folder/'start.S';start.write_text('.global _start\n.text\n_start:\n andq $-16,%rsp\n call entry\n movq %rax,%rdi\n movq $60,%rax\n syscall\n.section .note.GNU-stack,"",@progbits\n')
        subprocess.run(['cc','-c',str(start),'-o',str(cls.folder/'start.o')],check=True,capture_output=True)
        subprocess.run(['ld','-e','_start',str(cls.folder/'start.o'),str(cls.folder/'caller.o'),str(cls.folder/'answer.o'),'-o',str(cls.folder/'foreign-reference')],check=True,capture_output=True)
        assert subprocess.run([str(cls.folder/'foreign-reference')],timeout=2).returncode==37
        # The independent packer control uses ordinary arbitrary image bytes;
        # it does not execute those bytes or substitute a generated successor.
        pack_wire=struct.pack('<2Q',FILTER_MAGIC,3)+b'\x31\xc0\xc3'
        value,packed=reference(cls.packer_checked,pack_wire,capacity=4096,workspace=1)
        assert packed[:4]==b'\x7fELF' and 176<value<4096
        seed,_=build_seed(cls.folder)
        source=(ROOT/'examples/hia_bootstrap/selfhost.hepta').read_bytes()
        first,_=compile_stage(cls.folder,'B1',seed,source,image_format='seed-shared')
        cls.compiler,_=compile_stage(cls.folder,'B2',first,source)
        assert first.read_bytes()==cls.compiler.read_bytes()
        cls.image,_=compile_stage(cls.folder,'linker',cls.compiler,render_assembly(document()).encode())
        cls.packer,_=compile_stage(cls.folder,'packer',cls.compiler,render_assembly(filter_document()).encode())
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        cls.code=NativeHiaJsonImage(cls.image.read_bytes(),sha256(cls.image.read_bytes()).hexdigest())
        cls.pack_code=NativeHiaJsonImage(cls.packer.read_bytes(),sha256(cls.packer.read_bytes()).hexdigest())
        wire=struct.pack('<2Q',FILTER_MAGIC,len(cls.image.read_bytes()))+cls.image.read_bytes()
        expected,output=reference(cls.packer_checked,wire,capacity=1<<20,workspace=1)
        actual,packed=cls.invoke(cls.pack_code,wire,capacity=1<<20,workspace=1)
        assert actual==expected and packed==output
        cls.executable=cls.folder/'hia-elf-link';cls.executable.write_bytes(output[:expected]);cls.executable.chmod(0o700)

    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()

    @classmethod
    def c_object(cls,name,source):
        path=cls.folder/(name+'.c');path.write_text(source+'\n')
        subprocess.run(['cc','-O0','-fno-pie','-fno-stack-protector','-fno-asynchronous-unwind-tables','-fno-unwind-tables','-c',str(path),'-o',str(cls.folder/(name+'.o'))],check=True,capture_output=True)
        return (cls.folder/(name+'.o')).read_bytes()

    @classmethod
    def invoke(cls,code,payload,capacity=65536,workspace=WORKSPACE_BYTES):
        s=ctypes.create_string_buffer(payload);o=ctypes.create_string_buffer(b'\xa5'*capacity,capacity)
        w=ctypes.create_string_buffer(b'\xa5'*workspace,workspace)
        value=code._entry(s,len(payload),o,capacity,w,workspace)
        return value,o.raw

    @classmethod
    def run_elf(cls,raw,expected,label='linked'):
        cls.serial+=1;p=cls.folder/(label+'-'+str(cls.serial));p.write_bytes(raw);p.chmod(0o700)
        result=subprocess.run([str(p)],capture_output=True,timeout=2)
        assert result.returncode==expected and result.stdout==b'' and result.stderr==b'',result
        return p

    def linked(self,objects,expected,entry=b'entry'):
        wire=frame(objects,entry);value,output=self.invoke(self.code,wire)
        self.assertLess(value,65536)
        vm,reference_output=reference(self.checked,wire)
        self.assertEqual((value,output),(vm,reference_output))
        return self.run_elf(output[:value],expected)

    def test_independent_Core_and_native_full_output_data_bss_and_real_execution(self):
        actual,output=self.invoke(self.code,self.basic_wire)
        self.assertEqual((actual,output),(self.reference_value,self.reference_output))
        p=self.run_elf(output[:actual],37)
        raw=p.read_bytes();self.assertEqual(struct.unpack_from('<HH',raw,16),(2,62))
        self.assertEqual(struct.unpack_from('<H',raw,56)[0],3)
        segments=[struct.unpack_from('<IIQQQQQQ',raw,64+i*56) for i in range(3)]
        self.assertEqual([(r[0],r[1]) for r in segments],[(1,5),(1,6),(0x6474e551,6)])
        for row in segments:self.assertNotEqual(row[1]&3,3) # never writable+executable

    def test_two_HIA_objects_private_collisions_exact_names_and_foreign_C_calls(self):
        objects=[]
        for prefix,value in (('left_',30),('right_',7)):
            doc={'schema':'hepta.hia.program.v8','module':prefix+'module','exports':[prefix+'answer'],
                'functions':[{'name':prefix+'answer','params':[],'returns':['u64'],'effects':[],'entry':'b0',
                    'blocks':[{'id':'b0','params':[],'ops':[{'op':'call','args':[],'out':[{'name':'v0','type':'u64'}],'attrs':{'function':'private_value'}}],'term':{'op':'ret','values':['v0']}}]},
                {'name':'private_value','params':[],'returns':['u64'],'effects':[],'entry':'b0',
                    'blocks':[{'id':'b0','params':[],'ops':[{'op':'const','args':[],'out':[{'name':'v0','type':'u64'}],'attrs':{'value':value}}],'term':{'op':'ret','values':['v0']}}]}]}
            checked=assemble_program(render_assembly(doc));self.assertEqual(execute_program(checked,prefix+'answer',[])['values'],[value])
            image,_=compile_stage(self.folder,prefix+'HIA-object',self.compiler,render_assembly(doc).encode());objects.append(image.read_bytes())
        caller=self.c_object('two-HIA-caller','extern unsigned long long left_answer(void),right_answer(void); int entry(void){return left_answer()+right_answer();}')
        self.linked([caller,*objects],37)
        self.linked(objects,30,entry=b'left_answer')
        self.linked(objects[::-1],7,entry=b'right_answer')

    def test_strong_and_weak_resolution_and_undefined_weak_address(self):
        weak=self.c_object('weak','__attribute__((weak)) unsigned long long answer(void){return 88;}')
        self.linked([self.c_main,weak,self.c_answer],37)
        self.linked([self.c_main,self.c_answer,weak],37)
        caller=self.c_object('weak-undefined','extern int optional(void) __attribute__((weak)); int entry(void){if(optional) return optional(); return 11;}')
        self.linked([caller],11)

    def test_absolute_64bit_and_32bit_relocations_and_nonzero_addends(self):
        answer=self.c_object('absolute','unsigned long long values[3]={1,30,2}; unsigned long long *p=values+1; unsigned long long answer(void){return *p;}')
        self.linked([self.c_main,answer],37)

    def test_invalid_object_tables_symbols_properties_relocations_no_output(self):
        rows=[('empty',b''),('bad-magic',b'\0'+self.basic_wire[1:]),('truncated',self.basic_wire[:-1]),('trailing',self.basic_wire+b'\0'),
            ('duplicate-strong',frame([self.c_main,self.c_answer,self.c_answer])),('unresolved',frame([self.c_main])),('absent-entry',frame([self.c_main,self.c_answer],b'not-there')),('nonfunction-entry',frame([self.c_main,self.c_answer],b'data'))]
        for label,offset,value,fmt in (('bad-elf-class',4,1,'B'),('bad-machine',18,3,'H'),('table-overflow',40,2**64-1,'Q'),('no-sections',60,0,'H')):
            obj=bytearray(self.c_main);struct.pack_into('<'+fmt,obj,offset,value);rows.append((label,frame([bytes(obj),self.c_answer])))
        allocated=next((at,h) for at,h in sections(self.c_main) if h[1]==1 and h[2]&4)
        for label,delta,value in (('writable-code',8,7),('non-power-alignment',48,3),('extent-overflow',32,2**64-1)):
            obj=bytearray(self.c_main);struct.pack_into('<Q',obj,allocated[0]+delta,value);rows.append((label,frame([bytes(obj),self.c_answer])))
        rela=next((at,h) for at,h in sections(self.c_main) if h[1]==4)
        for label,delta,value,fmt in (('unknown-relocation',8,42,'I'),('symbol-index-overflow',12,2**32-1,'I'),('target-overflow',0,2**64-1,'Q'),('signed-relocation-overflow',16,1<<62,'Q')):
            obj=bytearray(self.c_main);struct.pack_into('<'+fmt,obj,rela[1][4]+delta,value);rows.append((label,frame([bytes(obj),self.c_answer])))
        obj=bytearray(self.c_main);base=rela[1][4];obj[base+24:base+48]=obj[base:base+24];rows.append(('overlapping-relocations',frame([bytes(obj),self.c_answer])))
        for at,h in sections(self.c_main):
            if h[1]==7 and h[2]&2:
                obj=bytearray(self.c_main);struct.pack_into('<I',obj,h[4]+16,0xc0008002);rows.append(('unknown-needed-property',frame([bytes(obj),self.c_answer])))
        for label,wire in rows:
            with self.subTest(case=label):
                result,output=reference(self.checked,wire);self.assertEqual(result,INVALID)
                self.assertEqual(output,b'\xa5'*65536)
                self.assertEqual(self.invoke(self.code,wire),(result,output))

    def test_capacity_refusals_are_not_partial_publication(self):
        for cap,workspace in ((4095,WORKSPACE_BYTES),(65536,WORKSPACE_BYTES-1)):
            with self.subTest(capacity=cap,workspace=workspace):
                self.assertEqual(self.invoke(self.code,self.basic_wire,capacity=cap,workspace=workspace),(NO_SPACE,b'\xa5'*cap))

    def test_standalone_filter_no_Python_linker_and_real_EINTR(self):
        before=self.executable.read_bytes()
        for trace,interrupt in ((False,False),(True,False),(True,True)):
            command=[str(self.executable)]
            path=self.folder/('trace-'+str(interrupt))
            if trace:
                options=['-e','inject=read:error=EINTR:when=1','-e','inject=write:error=EINTR:when=1'] if interrupt else []
                command=['/usr/bin/strace','-qq','-o',str(path),*options,*command]
            r=subprocess.run(command,input=self.basic_wire,capture_output=True,timeout=5,env={'PATH':'/nonexistent','LANG':'C'})
            self.assertEqual((r.returncode,r.stderr),(0,b''));self.assertEqual(r.stdout,self.reference_output[:self.reference_value])
            if trace:
                import re
                calls=re.findall(rb'^([a-z0-9_]+)\(',path.read_bytes(),re.MULTILINE)
                self.assertEqual(set(calls),{b'execve',b'mmap',b'read',b'write',b'exit'})
                self.assertEqual(calls.count(b'execve'),1)
                if interrupt:self.assertEqual(path.read_bytes().count(b'(INJECTED)'),2)
            self.run_elf(r.stdout,37)
        self.assertEqual(self.executable.read_bytes(),before)
        for command,payload,status in (([str(self.executable),'extra'],b'',64),([str(self.executable)],b'bad',2),([str(self.executable)],b'x'*(8*1024*1024+1),3)):
            r=subprocess.run(command,input=payload,capture_output=True,timeout=5)
            self.assertEqual((r.returncode,r.stdout,r.stderr),(status,b'',b''))

    def test_filter_packer_refuses_invalid_and_short_output_without_publication(self):
        wire=struct.pack('<2Q',FILTER_MAGIC,len(self.image.read_bytes()))+self.image.read_bytes()
        for payload,status,cap in ((b'',INVALID,4096),(b'bad',INVALID,4096),
                (b'\0'+wire[1:],INVALID,65536),(wire+b'\0',INVALID,65536),
                (wire,NO_SPACE,64)):
            with self.subTest(input_bytes=len(payload),capacity=cap):
                expected=reference(self.packer_checked,payload,capacity=cap,workspace=1)
                actual=self.invoke(self.pack_code,payload,capacity=cap,workspace=1)
                self.assertEqual(actual,expected)
                self.assertEqual(actual,(status,b'\xa5'*cap))

    def test_standalone_real_partial_write_terminates_as_IO_failure(self):
        import fcntl,os
        read_fd,write_fd=os.pipe()
        try:
            # Reduce this actual pipe to one page so the 4160-byte ELF cannot
            # fit. No mocked write or product buffer/limit change is involved.
            fcntl.fcntl(write_fd,fcntl.F_SETPIPE_SZ,4096)
            fcntl.fcntl(write_fd,fcntl.F_SETFL,fcntl.fcntl(write_fd,fcntl.F_GETFL)|os.O_NONBLOCK)
            r=subprocess.run([str(self.executable)],input=self.basic_wire,stdout=write_fd,
                stderr=subprocess.PIPE,timeout=5,env={'PATH':'/nonexistent','LANG':'C'})
            os.close(write_fd);write_fd=-1
            parts=[]
            while True:
                part=os.read(read_fd,65536)
                if not part:break
                parts.append(part)
            prefix=b''.join(parts)
            self.assertEqual((r.returncode,r.stderr),(4,b''))
            self.assertGreater(len(prefix),0);self.assertLess(len(prefix),self.reference_value)
            self.assertEqual(prefix,self.reference_output[:len(prefix)])
        finally:
            os.close(read_fd)
            if write_fd!=-1:os.close(write_fd)
