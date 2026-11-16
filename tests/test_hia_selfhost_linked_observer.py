"""Real linked-ELF observation, independent assembler/VM, and loader lifetime controls."""
from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import generate_hia_linked_observer as generator
from tools import hia_selfhost_linked_observer as native
from tools import qualify_hia_selfhost as original

ROOT=Path(__file__).resolve().parents[1]
REFERENCE=ROOT/"tools/hia_linked_observer_bridge.S"
COLD_REPORT="HEPTA_HIA_LINKED_OBSERVER_COLD_REPORT"
DEVELOPMENT_COMPILER="HEPTA_HIA_LINKED_OBSERVER_DEVELOPMENT_COMPILER"
EVIDENCE="HEPTA_HIA_LINKED_OBSERVER_EVIDENCE"
OWNED=(
    "tools/generate_hia_linked_observer.py",
    "tools/hia_selfhost_linked_observer.py",
    "tools/hia_linked_observer_bridge.S",
    "examples/hia_bootstrap/linked_observer_packer.hepta",
    "examples/hia_bootstrap/linked_observer_policy.hepta",
    "tools/generate_hia_artifact_publication.py",
    "tests/test_hia_selfhost_linked_observer.py",
    "tools/generate_hia_native_observer.py",
    "tools/hia_native_observer_template.S",
    "tools/hia_selfhost_native_observer.py",
    "tools/hia_selfhost_child.py",
    "tools/qualify_hia_selfhost.py",
)
FIELDS=("status","result_u64","abi_status","core_u32","return_encoding",
        "source_unchanged","output_unchanged","workspace_header",
        "source_sha256","image_sha256","output_sha256","limits",
        "forbidden_compiler_modules_loaded")


def digest(data):
    return sha256(data).hexdigest()


def elf_contents(data):
    header=struct.unpack_from("<16sHHIQQQIHHHHHH",data)
    if header[0][:7]!=b"\x7fELF\x02\x01\x01" or header[2]!=62:
        raise AssertionError("expected the actual ELF64 x86-64 artifact")
    rows=[struct.unpack_from("<IIQQQQIIQQ",data,header[6]+index*header[11])
          for index in range(header[12])]
    name_row=rows[header[13]]
    names=data[name_row[4]:name_row[4]+name_row[5]]
    def string(raw,at):
        end=raw.index(0,at)
        return raw[at:end].decode("ascii")
    named={string(names,row[0]):row for row in rows}
    text=named[".text"]
    sym=named[".symtab"]; strings=rows[sym[6]]
    strings=data[strings[4]:strings[4]+strings[5]]
    symbols=[struct.unpack_from("<IBBHQQ",data,sym[4]+at)
             for at in range(0,sym[5],sym[9])]
    symbols=[{"name":string(strings,row[0]),"binding":row[1]>>4,"kind":row[1]&15,
              "section":row[3],"value":row[4],"size":row[5]} for row in symbols]
    relas=[]
    for row in rows:
        if row[1]==4 and rows[row[7]]==text:
            for at in range(0,row[5],row[9]):
                offset,info,addend=struct.unpack_from("<QQq",data,row[4]+at)
                relas.append((offset,info&0xffffffff,symbols[info>>32]["name"],addend))
    return {"text":data[text[4]:text[4]+text[5]],"relocations":relas,
            "symbols":symbols,"sections":named}


def assemble(directory,label,source,*,shared=False):
    assembly=directory/(label+".S");assembly.write_text(source)
    obj=directory/(label+".o")
    original.observe_native_tool(directory,label+"-as","as",["--64",assembly,"-o",obj])
    if not shared:return obj
    linked=directory/(label+".so")
    original.observe_native_tool(directory,label+"-ld","ld",[
        "-m","elf_x86_64","-shared","-z","defs","-z","noexecstack",
        "-z","relro","-z","now","--build-id=none",obj,"-lc","-o",linked])
    return linked


@contextmanager
def independent_loader():
    # Keep the retained Python loader as the independent oracle after the new
    # linked-observer dispatch is integrated into the qualifier.
    with patch.object(original,"NATIVE_OBSERVER",None), \
         patch.object(original,"NATIVE_LINKED_OBSERVER",None,create=True):
        yield


def legacy_invoke(*args,**kwargs):
    with independent_loader():
        return original.invoke(*args,image_format="linked-selfhost",**kwargs)


def foreign_bytes(directory,label,code):
    return assemble(directory,label,
        ".intel_syntax noprefix\n.text\n.global f0\n.type f0,@function\nf0:\n"
        +" .byte "+",".join(str(byte) for byte in code)+"\n.size f0,.-f0\n"
        +'.section .note.GNU-stack,"",@progbits\n',shared=True)


def lifetime_source(*,trap=False,noise=0,stderr=False):
    """A foreign ABI fixture, not HIA code or a production serializer.

    mremap(old_size=0) duplicates only a genuine shared mapping. The DSO owns
    that duplicate until fini, so no borrowed Python buffer is used after main
    has released it. The ordinary ctypes path may validly return EINVAL.
    """
    page=os.sysconf("SC_PAGE_SIZE")
    return r'''
.intel_syntax noprefix
.set PAGE, @PAGE@
.set TRAP, @TRAP@
.set NOISE, @NOISE@
.set STDERR, @STDERR@
.section .data
.align 8
mapping_record:
 .quad -1, PAGE, 0
.section .rodata
events_name: .asciz "events.bin"
mapping_name: .asciz "mapping.bin"
stdout_byte: .ascii "!"
stderr_byte: .ascii "?"
.text
.global f0
.type f0,@function
f0:
 push rbx
 mov rbx,rdx
 test rcx,rcx
 jz fixture_failure
 mov byte ptr [rbx],65
 mov edi,70
 call append_event
 .if NOISE==2
 call stdout_noise
 .endif
 mov rdi,rbx
 xor esi,esi
 mov edx,PAGE
 mov r10d,1
 mov eax,25
 syscall
 mov [rip+mapping_record],rax
 mov eax,39
 syscall
 mov [rip+mapping_record+16],rax
 call save_mapping
 .if TRAP
 ud2
 .endif
 mov eax,37
 pop rbx
 ret
.size f0,.-f0
construct:
 sub rsp,8
 mov edi,67
 call append_event
 .if NOISE==1
 call stdout_noise
 .endif
 .if STDERR
 call stderr_noise
 .endif
 add rsp,8
 ret
destruct:
 push rbx
 mov rbx,[rip+mapping_record]
 cmp rbx,-4095
 jae no_mapping
 mov byte ptr [rbx],66
 mov rdi,rbx
 mov esi,PAGE
 mov eax,11
 syscall
 test rax,rax
 jne fixture_failure
no_mapping:
 mov edi,68
 call append_event
 .if NOISE==3
 call stdout_noise
 .endif
 .if STDERR
 call stderr_noise
 .endif
 pop rbx
 ret
append_event:
 sub rsp,16
 mov [rsp],dil
 mov edi,-100
 lea rsi,[rip+events_name]
 mov edx,1089
 mov r10d,384
 mov eax,257
 syscall
 test rax,rax
 js fixture_failure
 mov r8,rax
 mov edi,eax
 lea rsi,[rsp]
 mov edx,1
 mov eax,1
 syscall
 cmp rax,1
 jne fixture_failure
 mov rdi,r8
 mov eax,3
 syscall
 test rax,rax
 jne fixture_failure
 add rsp,16
 ret
save_mapping:
 mov edi,-100
 lea rsi,[rip+mapping_name]
 mov edx,577
 mov r10d,384
 mov eax,257
 syscall
 test rax,rax
 js fixture_failure
 mov r8,rax
 mov edi,eax
 lea rsi,[rip+mapping_record]
 mov edx,24
 mov eax,1
 syscall
 cmp rax,24
 jne fixture_failure
 mov rdi,r8
 mov eax,3
 syscall
 test rax,rax
 jne fixture_failure
 ret
stdout_noise:
 mov edi,1
 lea rsi,[rip+stdout_byte]
 jmp noise
stderr_noise:
 mov edi,2
 lea rsi,[rip+stderr_byte]
noise:
 mov edx,1
 mov eax,1
 syscall
 cmp rax,1
 jne fixture_failure
 ret
fixture_failure:
 ud2
.section .init_array,"aw"
 .quad construct
.section .fini_array,"aw"
 .quad destruct
.section .note.GNU-stack,"",@progbits
'''.replace("@PAGE@",str(page)).replace("@TRAP@",str(int(trap))).replace("@NOISE@",str(noise)).replace("@STDERR@",str(int(stderr)))


def seal_errno_filter():
    """Install a child-only extra restriction; never enable ptrace or relax policy."""
    import ctypes
    class Filter(ctypes.Structure):
        _fields_=[("code",ctypes.c_ushort),("jt",ctypes.c_ubyte),
                  ("jf",ctypes.c_ubyte),("k",ctypes.c_uint32)]
    class Program(ctypes.Structure):
        _fields_=[("len",ctypes.c_ushort),("filter",ctypes.POINTER(Filter))]
    # seccomp_data: arch at4, syscall nr at0, argument1 at24.
    # Keep every other x86-64 syscall under the process's inherited restrictions.
    instructions=((0x20,0,0,4),(0x15,1,0,0xc000003e),(0x06,0,0,0x80000000),
                  (0x20,0,0,0),(0x15,0,3,72),(0x20,0,0,24),(0x15,0,1,1034),
                  (0x06,0,0,0x00050001),(0x06,0,0,0x7fff0000))
    code=(Filter*len(instructions))(*(Filter(*row) for row in instructions))
    program=Program(len(code),code)
    libc=ctypes.CDLL(None,use_errno=True)
    prctl=libc.prctl;prctl.restype=ctypes.c_int
    prctl.argtypes=[ctypes.c_int,ctypes.c_ulong,ctypes.c_void_p,
                   ctypes.c_ulong,ctypes.c_ulong]
    def install():
        if prctl(38,1,None,0,0)!=0:
            raise OSError(ctypes.get_errno(),"PR_SET_NO_NEW_PRIVS")
        if prctl(22,2,ctypes.byref(program),0,0)!=0:
            raise OSError(ctypes.get_errno(),"PR_SET_SECCOMP")
    return install,{"instructions":instructions,"bytes":bytes(code).hex(),
        "restriction":"x86-64 fcntl syscall72 command1034 returns EPERM",
        "other_syscalls":"inherited kernel restrictions unchanged",
        "ptrace_requested":False}


class LinkedObserverSourceTests(unittest.TestCase):
    def test_HIA_source_is_generated_exactly_within_original_profile(self):
        from hepta.hia_agent_assembly import assemble_program,render_assembly
        for name,authoring in (("policy",generator.policy_source()),("packer",generator.packer_source())):
            path=getattr(native,name.upper())
            self.assertEqual(path.read_text(),render_assembly(generator.document(authoring,"linked_observer_"+name)))
            checked=assemble_program(path.read_bytes()).as_dict()
            self.assertLessEqual(len(checked["functions"]),128)
            self.assertLessEqual(sum(len(f["blocks"]) for f in checked["functions"]),1536)
            self.assertLessEqual(sum(len(b["ops"]) for f in checked["functions"] for b in f["blocks"]),8192)
            self.assertLessEqual(max(len(f["blocks"]) for f in checked["functions"]),256)
            self.assertLessEqual(max(len(b["params"]) for f in checked["functions"] for b in f["blocks"]),16)

    @unittest.skipUnless(shutil.which("as"),"independent GNU assembler required")
    def test_independent_assembler_matches_all_text_and_foreign_relocations(self):
        with tempfile.TemporaryDirectory(prefix="hia-linked-observer-reference-") as temporary:
            obj=assemble(Path(temporary),"independent-adapter",REFERENCE.read_text())
            actual=elf_contents(obj.read_bytes())
        policy=b"\xc3"
        expected=elf_contents(generator.reference_object(policy))
        patched=bytearray(actual["text"])
        self.assertEqual(patched[generator.POLICY_HOLE:generator.POLICY_HOLE+4],bytes(4))
        struct.pack_into("<i",patched,generator.POLICY_HOLE,len(patched)-generator.POLICY_HOLE-4)
        self.assertEqual(bytes(patched)+policy,expected["text"])
        self.assertEqual(generator.assembled_bridge(),
            (generator.BRIDGE,generator.BRIDGE_RELOCATIONS,generator.POLICY_HOLE,generator.START_SIZE))
        self.assertEqual(actual["relocations"],expected["relocations"])
        self.assertEqual([row for row in actual["symbols"] if row["name"]=="_start"],
                         [row for row in expected["symbols"] if row["name"]=="_start"])
        self.assertEqual(actual["sections"][".note.GNU-stack"][2]&4,0)
        self.assertEqual({name for _,_,name,_ in actual["relocations"]},set(generator.IMPORTS))

    def test_boundary_whitespace_parser_preserves_every_binary_payload_byte(self):
        frame=b"HIAOBR03"+struct.pack("<2Q",37,0)+b"A \t\r\n"
        for prefix in (b"",b" ",b"\t",b"\r",b"\n",b" \t\r\n"):
            for suffix in (b"",b" ",b"\t",b"\r",b"\n",b" \t\r\n"):
                self.assertEqual(native._response_frame(prefix+frame+suffix,len(frame)),frame)
        for raw in (b"!"+frame,b"x "+frame,b"\0"+frame,b"\xc2\xa0"+frame,
                    b"\xef\xbb\xbf"+frame,frame+b"!",frame+b"\0",frame+frame,frame[:-1]):
            self.assertIsNone(native._response_frame(raw,len(frame)))

    def test_dual_selection_refuses_before_read_or_directory_creation(self):
        with patch.dict(os.environ,{COLD_REPORT:"unread-cold",DEVELOPMENT_COMPILER:"unread-development"}), \
             patch.object(Path,"read_bytes",side_effect=AssertionError("must not read")) as read, \
             patch.object(Path,"mkdir",side_effect=AssertionError("must not create")) as mkdir:
            with self.assertRaisesRegex(ValueError,"mutually exclusive"):
                LinkedObserverNativeTests.setUpClass()
        read.assert_not_called();mkdir.assert_not_called()


@unittest.skipUnless(platform.system()=="Linux" and platform.machine().lower() in ("x86_64","amd64")
    and shutil.which("ld") and shutil.which("as"),"Linux x86-64 and ordinary linker/assembler required")
class LinkedObserverNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cold=os.environ.get(COLD_REPORT); development=os.environ.get(DEVELOPMENT_COMPILER)
        if cold and development:raise ValueError("cold and development inputs are mutually exclusive")
        cls.cold_bytes=cls.cold_sources=None
        if cold:
            from tools.build_hia_json_preflight import admit_cold_build
            cls.cold_bytes=Path(cold).read_bytes()
            outer=json.loads(cls.cold_bytes);nested=json.loads(Path(outer["nested_report"]).read_bytes())
            compiler=Path(nested["generations"][-1]["produced_image"])
            cls.compiler_bytes=compiler.read_bytes()
            cls.cold_sources=admit_cold_build(cls.compiler_bytes,cls.cold_bytes)
            if any(name not in cls.cold_sources for name in OWNED):
                raise ValueError("cold qualification does not bind every linked observer input")
            cls.scope="CURRENT_SOURCE_COLD_BUILT_COMPONENT"
        elif development:
            compiler=Path(development);cls.compiler_bytes=compiler.read_bytes()
            cls.scope="RETAINED_COMPILER_DEVELOPMENT_COMPONENT"
        else:
            compiler=None;cls.scope="ISOLATED_CURRENT_SOURCE_BOOTSTRAP_COMPONENT"
        cls.temp=None
        if os.environ.get(EVIDENCE):
            parent=Path(os.environ[EVIDENCE])
            parent.mkdir(mode=0o700,parents=True,exist_ok=True)
            cls.root=parent/"candidate";cls.root.mkdir(mode=0o700)
        else:
            cls.temp=tempfile.TemporaryDirectory(prefix="hia-linked-observer-")
            cls.root=Path(cls.temp.name)
        names=set(OWNED)
        for folder in ("hepta","tools"):
            names.update(p.relative_to(ROOT).as_posix() for p in (ROOT/folder).rglob("*.py"))
        cls.inputs={name:(ROOT/name).read_bytes() for name in sorted(names)}
        (cls.root/"source-before.json").write_text(json.dumps({k:digest(v) for k,v in cls.inputs.items()},indent=2,sort_keys=True)+"\n")
        # This invocation always precedes NEW native compilation. Only the
        # default seed mode is literally before B0 in this test fixture.
        cls.reference=native.independent_reference(before_B0=not(cold or development))
        (cls.root/"ordinary-vm-reference.json").write_text(json.dumps(cls.reference,indent=2,sort_keys=True)+"\n")
        if compiler is None:
            seed,_=original.build_seed(cls.root)
            compiler,_=original.compile_stage(cls.root,"B1",seed,original.SOURCE.read_bytes(),image_format="seed-shared")
            cls.compiler_bytes=compiler.read_bytes()
        cls.compiler=compiler
        cls.build_dir=cls.root/"build";cls.build_dir.mkdir(mode=0o700)
        cls.executable,cls.build=native.build(cls.build_dir,compiler,cls.reference)
        cls.executable_bytes=cls.executable.read_bytes()
        cls.new_entries=cls.old_entries=cls.differentials=0
        cls.pids=[]
        cls.policy_native_entries=cls.packer_native_entries=0

    @classmethod
    def tearDownClass(cls):
        unchanged=all((ROOT/name).read_bytes()==raw for name,raw in cls.inputs.items())
        held=cls.compiler.read_bytes()==cls.compiler_bytes and cls.executable.read_bytes()==cls.executable_bytes
        if cls.cold_bytes is not None:
            from tools.build_hia_json_preflight import current_sources
            held=held and Path(os.environ[COLD_REPORT]).read_bytes()==cls.cold_bytes and current_sources()==cls.cold_sources
        row={"schema":"hepta.hia.linked-observer-component-observations.v1","scope":cls.scope,
             "source_unchanged":unchanged,"held_inputs_unchanged":held,
             "new_native_entries":cls.new_entries,"retained_loader_entries":cls.old_entries,
             "differentials":cls.differentials,"ordinary_vm_full_packer_cases":len(cls.reference["packer_observations"]),
             "ordinary_vm_policy_frames":len(cls.reference["policy_observations"]),
             "native_policy_frames":cls.policy_native_entries,
             "native_packer_frames":cls.packer_native_entries,
             "whole_stack_rewritten_in_hia":False,"production_activated":False,"observed_fixture_pids":cls.pids}
        (cls.root/"observations.json").write_text(json.dumps(row,indent=2,sort_keys=True)+"\n")
        if cls.temp is not None:cls.temp.cleanup()
        if not unchanged or not held:raise AssertionError("linked observer frozen source/input changed")

    def folder(self,label):
        path=self.root/label;path.mkdir(mode=0o700);return path

    def pair(self,folder,image,source=b"",*,capacity=32,workspace_size=128,workspace_fill=90,
             output_initial=None,observe_trap_writes=False):
        old_dir=folder/"old";new_dir=folder/"new"
        old_dir.mkdir(mode=0o700);new_dir.mkdir(mode=0o700)
        kwargs={"capacity":capacity,"workspace_size":workspace_size,"workspace_fill":workspace_fill,
                "output_initial":output_initial,"observe_trap_writes":observe_trap_writes}
        type(self).old_entries+=1
        old,old_out=legacy_invoke(old_dir,"call",image,source,**kwargs)
        type(self).new_entries+=1
        new,new_out=native.invoke(new_dir,"call",self.executable,image,source,**kwargs)
        type(self).differentials+=1
        self.assertEqual(old["status"],new["status"])
        self.assertEqual(old_out,new_out)
        if old["status"]=="returned":
            for key in FIELDS:self.assertEqual(old[key],new[key],(folder.name,key))
        else:self.assertEqual(old.get("returncode"),new.get("returncode"))
        if observe_trap_writes:
            for key in ("available","initial_sha256","observed_sha256","observed_bytes","unchanged"):
                self.assertEqual(old["shared_output_observation"][key],new["shared_output_observation"][key])
        (folder/"comparison.json").write_text(json.dumps({"original":old,"native":new,
            "output_equal":old_out==new_out,"compared_fields":FIELDS},indent=2,sort_keys=True)+"\n")
        self.assertTrue(new["fresh_native_exec"]);self.assertFalse(new["successor_process_reuse"])
        return old,new,new_out

    def test_actual_HIA_object_emission_matches_every_independent_VM_byte(self):
        self.assertTrue(self.reference["before_native_compilation"])
        self.assertTrue(self.reference["every_output_byte_compared"])
        actual_policy=(self.build_dir/"linked-observer-policy.image.bin").read_bytes()
        self.assertEqual((self.build_dir/"linked-observer.o").read_bytes(),generator.reference_object(actual_policy))
        self.assertTrue(self.build["actual_policy_vm_packing"]["every_output_byte_compared"])
        self.assertEqual(self.build["runtime_loader"],native._runtime_interpreter()[1])
        self.assertFalse(self.build["production_activated"])

    def test_full_word_return_source_output_workspace_and_resource_receipts(self):
        folder=self.folder("full-word")
        image=foreign_bytes(folder,"return64",bytes.fromhex("48 b8 2a 00 00 00 ef be ad de c3"))
        for index,source in enumerate((b"",b"A\0\xff"*137)):
            for capacity in (0,1,257):
                for fill in (0,90,255):
                    pair=folder/(str(index)+"-"+str(capacity)+"-"+str(fill));pair.mkdir()
                    _,new,_=self.pair(pair,image,source,capacity=capacity,workspace_size=1032,workspace_fill=fill)
                    self.assertEqual(new["result_u64"],0xdeadbeef0000002a)

    def test_actual_readonly_source_violation_is_observed(self):
        folder=self.folder("source-violation")
        image=foreign_bytes(folder,"mutator",bytes.fromhex("c6 07 61 31 c0 c3"))
        _,new,out=self.pair(folder,image,b"XYZ")
        self.assertFalse(new["source_unchanged"]);self.assertEqual(out,b"\xa5"*32)

    def test_real_kernel_limits_and_dumpability(self):
        folder=self.folder("kernel-limits")
        # Save all six actual limits to the caller output, then PR_GET_DUMPABLE.
        assembly=[".intel_syntax noprefix",".text",".global f0",".type f0,@function","f0:",
                  " push rbx"," mov rbx,rdx"]
        for index,resource in enumerate((0,9,3,1,7,4)):
            assembly += [" xor edi,edi"," mov esi,"+str(resource)," xor edx,edx",
                         " lea r10,[rbx+"+str(index*16)+"]"," mov eax,302"," syscall",
                         " test rax,rax"," jne failed"]
        assembly += [" mov edi,3"," xor esi,esi"," xor edx,edx"," xor r10d,r10d",
                     " xor r8d,r8d"," mov eax,157"," syscall"," pop rbx"," ret",
                     "failed:"," ud2",'.section .note.GNU-stack,"",@progbits']
        image=assemble(folder,"limits","\n".join(assembly)+"\n",shared=True)
        _,new,out=self.pair(folder,image,capacity=96,workspace_size=0)
        self.assertEqual(new["result_u64"],0)
        self.assertEqual(struct.unpack("<12Q",out),(10,10,256<<20,256<<20,8<<20,8<<20,16<<20,16<<20,32,32,0,0))

    def test_complete_HIA_ELF_has_same_text_as_flat_and_same_observations(self):
        folder=self.folder("hia-bytesum")
        sample=original.SAMPLE.read_bytes()
        flat,_=original.compile_stage(folder,"flat",self.compiler,sample)
        obj,_=original.compile_stage(folder,"object",self.compiler,sample.replace(b"hepta.hia.program.v8 selfhost\n",b"hepta.hia.program.v8 selfhost_elf\n",1),output_extension=".o")
        inventory=original.inspect_selfhost_object(obj.read_bytes())
        self.assertEqual(inventory["text_sha256"],digest(flat.read_bytes()))
        linked=folder/"target.so"
        original.observe_native_tool(folder,"link","ld",["-m","elf_x86_64","-shared","-z","defs","-z","noexecstack","-z","relro","-z","now","--build-id=none",obj,"-o",linked])
        for index,source in enumerate((b"",b"abc",bytes(range(256))*4)):
            pair=folder/str(index);pair.mkdir()
            self.pair(pair,linked,source,capacity=64,workspace_size=2048,workspace_fill=165)

    def test_full_linked_HIA_compiler_success_and_refusal_bytes_are_identical(self):
        folder=self.folder("linked-compiler")
        source=original.SOURCE.read_bytes().replace(b"hepta.hia.program.v8 selfhost\n",b"hepta.hia.program.v8 selfhost_elf\n",1)
        obj,_=original.compile_stage(folder,"compiler",self.compiler,source,output_extension=".o")
        original.inspect_selfhost_object(obj.read_bytes())
        linked=folder/"compiler.so"
        original.observe_native_tool(folder,"link","ld",["-m","elf_x86_64","-shared","-z","defs","-z","noexecstack","-z","relro","-z","now","--build-id=none",obj,"-o",linked])
        for index,source in enumerate((original.SAMPLE.read_bytes(),b"invalid")):
            pair=folder/str(index);pair.mkdir()
            self.pair(pair,linked,source,capacity=1<<20,workspace_size=1<<20,workspace_fill=90)

    def test_owned_libc_imports_and_actual_trap_capture(self):
        from tools.hia_selfhost_owned_elf_cases import cases,reference
        from tools.hia_selfhost_owned_flow_cases import cases as flow_cases
        from tools.qualify_hia_selfhost_owned_elf import inspect_owned_object
        folder=self.folder("owned-libc")
        available=[*cases(),*flow_cases()]
        by_name={case["id"]:case for case in available}
        chosen=[by_name[name] for name in ("new-8","move-nested-loan-and-drop",
                 "flow-forward-owner-through-two-calls","new-allocation-trap-1")]
        for index,case in enumerate(chosen):
            pair=folder/str(index);pair.mkdir()
            expected=reference(case)
            (pair/"ordinary-reference.json").write_text(json.dumps(expected,indent=2,sort_keys=True)+"\n")
            obj,_=original.compile_stage(pair,"owned",self.compiler,case["source"].encode(),output_extension=".o")
            inventory=inspect_owned_object(obj.read_bytes())
            self.assertEqual(inventory["undefined_symbols"],["calloc","free"])
            linked=pair/"owned.so"
            original.observe_native_tool(pair,"link","ld",["-m","elf_x86_64","-shared","-z","defs","-z","noexecstack","-z","relro","-z","now","--build-id=none",obj,"-lc","-o",linked])
            _,new,out=self.pair(pair,linked,capacity=8,workspace_size=0,workspace_fill=0,
                               output_initial=b"\xa5"*8,observe_trap_writes=True)
            if "expected_trap" in case:self.assertEqual(new["returncode"],-4)
            else:self.assertEqual(new["core_u32"],case["expected_result"])
            self.assertEqual(out.hex(),case["expected_output_hex"])

    def test_real_normal_finalization_preserves_preimage_and_shared_postimage_modes(self):
        folder=self.folder("lifetime")
        image=assemble(folder,"lifetime",lifetime_source(),shared=True)
        page=os.sysconf("SC_PAGE_SIZE")
        for index,(initial,shared) in enumerate(((None,False),(b"Z"*page,False),(None,True),(b"Z"*page,True))):
            pair=folder/str(index);pair.mkdir()
            old,new,out=self.pair(pair,image,capacity=page,workspace_size=0,workspace_fill=0,
                                  output_initial=initial,observe_trap_writes=shared)
            before=b"A"+(initial or b"\xa5"*page)[1:]
            after=(b"B"+before[1:]) if shared else before
            self.assertEqual(out,after)
            self.assertEqual(old["output_sha256"],digest(before))
            self.assertEqual(new["output_sha256"],digest(before))
            for kind in ("old","new"):
                self.assertEqual((pair/kind/"events.bin").read_bytes(),b"CFD")
                address,extent,pid=struct.unpack("<3Q",(pair/kind/"mapping.bin").read_bytes())
                type(self).pids.append({"mode":index,"kind":kind,"pid":pid,"address":address,"extent":extent})
                self.assertEqual(extent,page)
                if shared:
                    self.assertLess(address,(1<<64)-4095);self.assertEqual(address%page,0)
        self.assertEqual(len({row["pid"] for row in self.pids}),len(self.pids))

    def test_real_SIGILL_has_no_finalizer_and_retains_actual_shared_writes(self):
        folder=self.folder("trap-lifetime")
        image=assemble(folder,"trap",lifetime_source(trap=True),shared=True)
        page=os.sysconf("SC_PAGE_SIZE")
        _,new,out=self.pair(folder,image,capacity=page,workspace_size=0,workspace_fill=0,
                           observe_trap_writes=True)
        self.assertEqual(new["returncode"],-4)
        self.assertEqual(out,b"A"+b"\xa5"*(page-1))
        for kind in ("old","new"):
            self.assertEqual((folder/kind/"events.bin").read_bytes(),b"CF")
            address,extent,_=struct.unpack("<3Q",(folder/kind/"mapping.bin").read_bytes())
            self.assertLess(address,(1<<64)-4095);self.assertEqual(extent,page)

    def test_constructor_call_and_finalizer_stdout_noise_is_never_searched_past(self):
        folder=self.folder("stdout-noise")
        page=os.sysconf("SC_PAGE_SIZE")
        for where in (1,2,3):
            image=assemble(folder,"noise-"+str(where),lifetime_source(noise=where),shared=True)
            pair=folder/str(where);pair.mkdir()
            old_dir=pair/"old";new_dir=pair/"new";old_dir.mkdir();new_dir.mkdir()
            type(self).old_entries+=1
            with self.assertRaises(json.JSONDecodeError):
                legacy_invoke(old_dir,"call",image,b"",capacity=page,workspace_size=0,workspace_fill=0)
            type(self).new_entries+=1
            new,out=native.invoke(new_dir,"call",self.executable,image,b"",capacity=page,workspace_size=0,workspace_fill=0)
            self.assertEqual(new["status"],"protocol_failed");self.assertEqual(out,b"")
            raw=(new_dir/"call.failure-stdout.raw").read_bytes()
            self.assertEqual(len(raw),24+page+1)
            self.assertEqual(raw.startswith(b"!HIAOBR03"),where in (1,2))
            if where==3:self.assertEqual(raw[-1:],b"!")
            for kind in ("old","new"):self.assertEqual((pair/kind/"events.bin").read_bytes(),b"CFD")

    def test_stderr_from_constructors_and_finalizers_is_preserved_on_success(self):
        folder=self.folder("stderr-lifecycle")
        image=assemble(folder,"stderr",lifetime_source(stderr=True),shared=True)
        self.pair(folder,image,capacity=os.sysconf("SC_PAGE_SIZE"),workspace_size=0)
        for kind in ("old","new"):self.assertEqual((folder/kind/"call.stderr.log").read_bytes(),b"??")

    def test_real_dlopen_and_missing_symbol_refusals(self):
        folder=self.folder("loader-refusals")
        bad=folder/"invalid.so";bad.write_bytes(b"not an ELF object\n")
        missing=assemble(folder,"missing",'.text\n.global unrelated\nunrelated:\n ret\n.section .note.GNU-stack,"",@progbits\n',shared=True)
        for label,image in (("bad",bad),("missing",missing)):
            pair=folder/label;pair.mkdir()
            _,new,out=self.pair(pair,image,capacity=8,workspace_size=0,workspace_fill=0)
            self.assertEqual((new["status"],new["returncode"],out),("child_failed",1,b""))
            self.assertTrue((pair/"new/call.stderr.log").read_bytes())

    def test_private_malformed_frames_and_extra_arguments_refuse_before_target_load(self):
        folder=self.folder("malformed-frames")
        image=foreign_bytes(folder,"unused",b"\xc3").read_bytes()
        with native.output_snapshot(0) as snapshot:
            good=native._linked_frame(image,b"",0,0,0,None,snapshot)
            bad=[b"",good[:47],b"badMAGIC"+good[8:],good+b"\0",good[:-1]]
            for index in range(5):
                altered=bytearray(good);struct.pack_into("<Q",altered,8+index*8,(1<<64)-1);bad.append(bytes(altered))
            for at,values in ((48,(0,1,2,2147483648,0xfffffffe,snapshot)),
                              (52,(0,1,2,2147483648,0xffffffff))):
                for value in values:
                    altered=bytearray(good);struct.pack_into("<I",altered,at,value);bad.append(bytes(altered))
            for index,data in enumerate(bad):
                process=native.execute(self.executable_bytes,data,cwd=folder,snapshot_fd=snapshot)
                self.assertEqual((process.returncode,process.stdout,process.stderr),(2,b"",b""),index)
            process=native.execute(self.executable_bytes,good,cwd=folder,arguments=("unexpected",),snapshot_fd=snapshot)
            self.assertEqual((process.returncode,process.stdout),(64,b""))

    def test_F_GET_SEALS_error_is_rejected_before_real_loader(self):
        import fcntl
        import sys
        folder=self.folder("seals-error")
        image=assemble(folder,"not-entered",lifetime_source(),shared=True)
        install,policy=seal_errno_filter()
        before=len(list(Path("/proc/self/fd").iterdir()))
        probe=os.memfd_create("hia-seals-errno-probe",os.MFD_ALLOW_SEALING)
        observations=[]
        try:
            fcntl.fcntl(probe,1033,15)
            script=('import fcntl,json,sys\n'
                    'try:r={"value":fcntl.fcntl(int(sys.argv[1]),1034)}\n'
                    'except OSError as e:r={"errno":e.errno}\nprint(json.dumps(r))')
            for name,setup in (("baseline",None),("restricted",install)):
                process=subprocess.run([sys.executable,"-I","-S","-B","-c",script,str(probe)],
                    cwd=folder,capture_output=True,timeout=20,pass_fds=(probe,),preexec_fn=setup)
                (folder/(name+".stdout")).write_bytes(process.stdout)
                (folder/(name+".stderr")).write_bytes(process.stderr)
                self.assertEqual(process.returncode,0)
                observations.append({"case":name,"actual_fcntl":json.loads(process.stdout)})
            self.assertEqual(observations[0]["actual_fcntl"],{"value":15})
            self.assertEqual(observations[1]["actual_fcntl"],{"errno":1})
        finally:
            os.close(probe)
        # Sensitive transport negative: forge BOTH foreign feedback words as
        # success in a separate executable. HIA normally observes the full
        # negative errno and exact seal word; one missing bridge branch alone
        # cannot bypass its second independent seal check.
        raw=self.executable.read_bytes()
        prefix=bytes.fromhex("be0a04000031d2b8480000000f05")
        self.assertEqual(raw.count(prefix),1)
        at=raw.index(prefix)+len(prefix)
        self.assertEqual(raw[at:at+9],bytes.fromhex("498946204885c00f88"))
        self.assertEqual(raw[at+13:at+15],bytes.fromhex("31c0"))
        mutant=folder/"sensitive-forged-errno-feedback.elf"
        replacement=bytes.fromhex("49c746200f00000031c0")+b"\x90"*5
        mutant.write_bytes(raw[:at]+replacement+raw[at+15:]);mutant.chmod(0o700)
        policy["sensitivity"]={"offset":at,"original_hex":raw[at:at+15].hex(),
                              "replacement_hex":replacement.hex(),
                              "scope":"deliberately forged trusted foreign feedback, not a sandbox claim",
                              "mutant_sha256":digest(mutant.read_bytes())}
        outcomes=[]
        for name,executable in (("guarded",self.executable),("sensitive-negative",mutant)):
            scope=folder/name;scope.mkdir(mode=0o700)
            with native.output_snapshot(os.sysconf("SC_PAGE_SIZE")) as snapshot:
                payload=native._linked_frame(image.read_bytes(),b"",os.sysconf("SC_PAGE_SIZE"),0,0,None,snapshot)
                process=subprocess.run([str(executable)],input=payload,cwd=scope,
                    capture_output=True,timeout=20,pass_fds=(snapshot,),preexec_fn=install)
                (scope/"stdout.raw").write_bytes(process.stdout)
                (scope/"stderr.raw").write_bytes(process.stderr)
                completed=native.read_output_snapshot(snapshot,os.sysconf("SC_PAGE_SIZE"))
            events=(scope/"events.bin").read_bytes() if (scope/"events.bin").exists() else None
            outcomes.append({"case":name,"returncode":process.returncode,
                "stdout_bytes":len(process.stdout),"stdout_sha256":digest(process.stdout),
                "events":None if events is None else events.decode(),
                "snapshot_available":completed is not None})
        (folder/"actual-kernel-errno-controls.json").write_text(json.dumps({
            "policy":policy,"fcntl":observations,"observer":outcomes,
            "original_ptrace_gate":"separately retained sandbox refusal, not reclassified"},
            indent=2,sort_keys=True)+"\n")
        self.assertEqual((outcomes[0]["returncode"],outcomes[0]["stdout_bytes"],
                          outcomes[0]["events"],outcomes[0]["snapshot_available"]),(4,0,None,False))
        self.assertEqual((outcomes[1]["returncode"],outcomes[1]["events"],
                          outcomes[1]["snapshot_available"]),(0,"CFD",True))
        self.assertEqual(len(list(Path("/proc/self/fd").iterdir())),before)

    def test_prelaunch_storage_failure_releases_parent_shared_descriptor(self):
        import errno
        folder=self.folder("prelaunch-storage")
        image=foreign_bytes(folder,"unused",b"\xc3")
        before=len(list(Path("/proc/self/fd").iterdir()))
        with patch.object(Path,"write_text",side_effect=OSError(errno.ENOSPC,"controlled evidence failure")):
            with self.assertRaises(OSError):
                native.invoke(folder,"call",self.executable,image,b"",capacity=1,workspace_size=0,
                              workspace_fill=0,output_initial=b"X",observe_trap_writes=True)
        self.assertEqual(len(list(Path("/proc/self/fd").iterdir())),before)

    def test_actual_ASCII_stdout_whitespace_matches_original_without_trimming_payload(self):
        folder=self.folder("stdout-whitespace")
        page=os.sysconf("SC_PAGE_SIZE")
        for byte in (32,9,13,10):
            for where in (1,2,3):
                pair=folder/(str(byte)+"-"+str(where));pair.mkdir()
                source=lifetime_source(noise=where).replace('stdout_byte: .ascii "!"',
                                                            "stdout_byte: .byte "+str(byte))
                image=assemble(pair,"whitespace",source,shared=True)
                _,new,out=self.pair(pair,image,b"\0 \t\r\n",capacity=page,
                                   workspace_size=128,workspace_fill=32,output_initial=b" "*page)
                self.assertEqual(new["status"],"returned")
                self.assertEqual(out,b"A"+b" "*(page-1))
                self.assertTrue(new["prefinalizer_output_snapshot"]["available"])
                for kind in ("old","new"):
                    self.assertEqual((pair/kind/"events.bin").read_bytes(),b"CFD")

    def test_finalizer_nonzero_noise_or_signal_retains_preimage_and_shared_postimage(self):
        folder=self.folder("finalizer-failure")
        page=os.sysconf("SC_PAGE_SIZE")
        anchor=" pop rbx\n ret\nappend_event:"
        for kind,noise,code in (("exit",0,23),("exit-noise",3,23),("signal",0,-4)):
            source=lifetime_source(noise=noise)
            self.assertEqual(source.count(anchor),1)
            tail=" pop rbx\n"+(" ud2\n" if kind=="signal" else
                  " mov edi,23\n mov eax,231\n syscall\n ud2\n")+"append_event:"
            source=source.replace(anchor,tail)
            image=assemble(folder,kind,source,shared=True)
            for shared in (False,True):
                pair=folder/(kind+"-"+str(int(shared)));pair.mkdir()
                _,new,out=self.pair(pair,image,capacity=page,workspace_size=0,workspace_fill=0,
                                   output_initial=b" "*page,observe_trap_writes=shared)
                self.assertEqual((new["status"],new["returncode"]),("child_failed",code))
                self.assertEqual(out,(b"B" if shared else b"A")+b" "*(page-1))
                self.assertEqual(new["prefinalizer_output_snapshot"]["sha256"],
                                 digest(b"A"+b" "*(page-1)))
                for which in ("old","new"):
                    self.assertEqual((pair/which/"events.bin").read_bytes(),b"CFD")

    def test_constructor_fake_response_cannot_invent_a_completed_f0_snapshot(self):
        folder=self.folder("constructor-fake")
        raw=b"HIAOBR03"+struct.pack("<2Q",37,0)+b"Q"*8
        source=(".intel_syntax noprefix\n.text\n.global f0\nf0:\n mov eax,37\n ret\n"
                "construct:\n mov edi,1\n lea rsi,[rip+fake]\n mov edx,"+str(len(raw))+
                "\n mov eax,1\n syscall\n mov edi,23\n mov eax,231\n syscall\n ud2\n"
                "fake:\n .byte "+",".join(map(str,raw))+
                '\n.section .init_array,"aw"\n .quad construct\n'
                '.section .note.GNU-stack,"",@progbits\n')
        image=assemble(folder,"fake",source,shared=True)
        _,new,out=self.pair(folder,image,capacity=8,workspace_size=0,workspace_fill=0)
        self.assertEqual((new["status"],new["returncode"],out),("child_failed",23,b""))
        self.assertFalse(new["prefinalizer_output_snapshot"]["available"])

    def test_zero_capacity_return_is_committed_before_finalizer_failure(self):
        folder=self.folder("empty-finalizer-failure")
        source=('.intel_syntax noprefix\n.text\n.global f0\nf0:\n mov eax,37\n ret\n'
                'destruct:\n mov edi,23\n mov eax,231\n syscall\n ud2\n'
                '.section .fini_array,"aw"\n .quad destruct\n'
                '.section .note.GNU-stack,"",@progbits\n')
        image=assemble(folder,"empty",source,shared=True)
        _,new,out=self.pair(folder,image,capacity=0,workspace_size=0,workspace_fill=0)
        self.assertEqual((new["status"],new["returncode"],out),("child_failed",23,b""))
        self.assertTrue(new["prefinalizer_output_snapshot"]["available"])
        self.assertEqual(new["prefinalizer_output_snapshot"]["sha256"],digest(b""))
        self.assertTrue((folder/"new/call.output.bin").exists())

    def test_snapshot_allocation_failure_releases_existing_parent_capture(self):
        import errno
        folder=self.folder("snapshot-allocation-failure")
        image=foreign_bytes(folder,"unused",b"\xc3")
        before=len(list(Path("/proc/self/fd").iterdir()))
        allocator=os.memfd_create;calls=[]
        failure=OSError(errno.ENOSPC,"controlled snapshot allocation failure")
        def allocate(name,flags):
            calls.append(name)
            if len(calls)==2:raise failure
            return allocator(name,flags)
        with patch.object(os,"memfd_create",side_effect=allocate), \
             patch.object(native,"execute",side_effect=AssertionError("no child before full custody")) as enter:
            with self.assertRaises(OSError) as observed:
                native.invoke(folder,"call",self.executable,image,b"",capacity=1,workspace_size=0,
                              workspace_fill=0,output_initial=b"X",observe_trap_writes=True)
        self.assertIs(observed.exception,failure)
        self.assertEqual(calls,["hia-native-output","hia-linked-return-snapshot"])
        enter.assert_not_called()
        self.assertEqual(len(list(Path("/proc/self/fd").iterdir())),before)


    @contextmanager
    def native_policy(self):
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        raw=(self.build_dir/"linked-observer-policy.image.bin").read_bytes()
        image=NativeHiaJsonImage(raw,digest(raw))
        try:yield image
        finally:
            image._entry=None
            image._mapping.close()

    def policy_frame(self,image,wire,control,state,*,kind="policy"):
        import ctypes
        buffers=[bytearray(b"A"*16+raw+b"Z"*16) for raw in (wire,control,state)]
        pointers=[ctypes.addressof(ctypes.c_char.from_buffer(raw))+16 for raw in buffers]
        action=image._entry(pointers[0],len(wire),pointers[1],len(control),pointers[2],len(state))
        if kind=="policy":type(self).policy_native_entries+=1
        elif kind=="packer":type(self).packer_native_entries+=1
        else:raise AssertionError("unknown test frame counter")
        for raw in buffers:
            self.assertEqual(raw[:16],b"A"*16);self.assertEqual(raw[-16:],b"Z"*16)
        self.assertEqual(bytes(buffers[0][16:-16]),wire)
        return [action],bytes(buffers[1][16:-16]),bytes(buffers[2][16:-16])

    def test_actual_policy_all_continuations_and_complete_bytes_match_independent_VM(self):
        from hepta.hia_agent_assembly import assemble_program
        checked=assemble_program(native.POLICY.read_bytes())
        request=native._linked_frame(b"complete ELF remains opaque to policy",b"source\0\xff",17,40,90,None,11)
        frames=[(b"",1,()),(request,2,((16,0),)),
            (request,3,((16,0),(24,7),(32,15))),
            (request,4,((16,0x12340000),)),(request,5,((16,0),(32,0x12340100))),
            (request,6,((16,0),)),
            (request,8,((16,0),(24,11),(32,999999990),(40,12),(48,10),(56,0xdeadbeef0000002a))),
            (request,7,((16,0),)),(request,0,((16,0),))]
        state=bytearray(512);struct.pack_into("<Q",state,8,1);control=bytes(512)
        observations=[]
        with self.native_policy() as image:
            for wire,action,feedback in frames:
                for at,value in feedback:struct.pack_into("<Q",state,at,value)
                vm,vo,vw,steps=native._vm(checked,wire,control,bytes(state))
                actual,ao,aw=self.policy_frame(image,wire,control,bytes(state))
                self.assertEqual((actual,ao,aw),(vm,vo,vw))
                self.assertEqual(actual,[action])
                observations.append({"action":action,"source_sha256":digest(wire),
                    "output_hex":ao.hex(),"workspace_hex":aw.hex(),"VM_steps":steps})
                control=ao;state=bytearray(aw)
        folder=self.folder("policy-positive-frames")
        (folder/"complete-frames.json").write_text(json.dumps(observations,indent=2,sort_keys=True)+"\n")
        self.assertEqual([x["action"] for x in observations],[1,2,3,4,5,6,8,7,0])

    def test_actual_policy_refusals_and_loader_diagnostic_are_HIA_decisions(self):
        from hepta.hia_agent_assembly import assemble_program
        checked=assemble_program(native.POLICY.read_bytes())
        good=native._linked_frame(b"ELF",b"x",0,0,0,None,11)
        cases=[(0,2,(),b"",0,64),(99,1,(),good,0,70)]
        for phase in (1,2,4,5,6,7,8,10):
            cases.append((phase,1,((16,(1<<64)-5),),good,0,1 if phase==4 else 4))
        cases += [(3,1,((16,0),),good,9,None),
                  (4,1,((16,0),(32,0)),good,9,None),
                  (10,1,((16,0),),good,0,1),
                  (2,1,((16,0),(24,7),(32,7)),good,0,4),
                  (2,1,((16,0),(24,7),(32,(1<<64)-1)),good,0,4)]
        for bad in (b"",good[:-1],good+b"x",b"BADMAGIC"+good[8:]):
            cases.append((1,1,(),bad,0,2))
        for at,values in ((48,(0,1,2,2147483648,0xfffffffe,11)),(52,(0,1,2,2147483648,0xffffffff))):
            for value in values:
                bad=bytearray(good);struct.pack_into("<I",bad,at,value)
                cases.append((1,1,(),bytes(bad),0,2))
        observations=[]
        with self.native_policy() as image:
            for phase,argc,feedback,wire,action,status in cases:
                state=bytearray(512);struct.pack_into("<2Q",state,0,phase,argc)
                for at,value in feedback:struct.pack_into("<Q",state,at,value)
                vm,vo,vw,steps=native._vm(checked,wire,bytes(512),bytes(state))
                actual,ao,aw=self.policy_frame(image,wire,bytes(512),bytes(state))
                self.assertEqual((actual,ao,aw),(vm,vo,vw));self.assertEqual(actual,[action])
                if status is not None:self.assertEqual(struct.unpack_from("<Q",ao)[0],status)
                observations.append({"phase":phase,"action":action,"status":status,
                    "source_hex":wire.hex(),"output_hex":ao.hex(),"workspace_hex":aw.hex(),"VM_steps":steps})
            for output,state in ((bytes(511),bytes(512)),(bytes(512),bytes(511))):
                vm,vo,vw,_=native._vm(checked,b"",output,state)
                actual,ao,aw=self.policy_frame(image,b"",output,state)
                self.assertEqual((actual,ao,aw),(vm,vo,vw));self.assertEqual(actual,[70])
        folder=self.folder("policy-refusal-frames")
        (folder/"complete-frames.json").write_text(json.dumps(observations,indent=2,sort_keys=True)+"\n")

    def test_missing_entry_and_process_exit_callbacks_keep_original_lifecycle(self):
        folder=self.folder("process-lifetime")
        source=lifetime_source().replace('.global f0','.global different').replace('.type f0,','.type different,').replace('\nf0:\n','\ndifferent:\n').replace('.size f0,.-f0','.size different,.-different')
        image=assemble(folder,"missing-f0",source,shared=True)
        pair=folder/"missing";pair.mkdir()
        _,new,out=self.pair(pair,image,capacity=4096,workspace_size=0,workspace_fill=0)
        self.assertEqual((new["status"],new["returncode"],out),("child_failed",1,b""))
        for side in ("old","new"):self.assertEqual((pair/side/"events.bin").read_bytes(),b"CD")
        source=lifetime_source();anchor='construct:\n sub rsp,8\n mov edi,67\n call append_event\n'
        self.assertEqual(source.count(anchor),1)
        source=source.replace(anchor,anchor+' lea rdi,[rip+process_exit_callback]\n xor esi,esi\n xor edx,edx\n call __cxa_atexit@PLT\n test eax,eax\n jne fixture_failure\n')
        source+='\n.text\nprocess_exit_callback:\n sub rsp,8\n mov edi,65\n call append_event\n add rsp,8\n ret\n'
        image=assemble(folder,"exit-callback",source,shared=True)
        pair=folder/"exit";pair.mkdir()
        _,new,_=self.pair(pair,image,capacity=4096,workspace_size=0,workspace_fill=0)
        self.assertEqual(new["status"],"returned")
        for side in ("old","new"):self.assertEqual((pair/side/"events.bin").read_bytes(),b"CFAD")

    def test_selected_dispatch_has_no_fallback_and_seed_remains_independent(self):
        folder=self.folder("selected-dispatch")
        image=foreign_bytes(folder,"scalar",bytes.fromhex("b8 25 00 00 00 c3"))
        selected=folder/"selected";selected.mkdir()
        seed=folder/"seed";seed.mkdir()
        with patch.object(original,"NATIVE_LINKED_OBSERVER",self.executable):
            observed,out=original.invoke(selected,"call",image,b"",image_format="linked-selfhost",capacity=0,workspace_size=0)
            independent,raw=original.invoke(seed,"call",image,b"",image_format="seed-shared",capacity=0,workspace_size=0)
        self.assertEqual((observed["status"],observed["core_u32"],out),("returned",37,b""))
        self.assertTrue(observed["fresh_native_exec"]);self.assertNotIn("transport",independent)
        self.assertEqual((independent["core_u32"],raw),(37,b""))
        with patch.object(original,"NATIVE_LINKED_OBSERVER",folder/"missing"), \
             patch.object(subprocess,"run",side_effect=AssertionError("no fallback child")) as child:
            with self.assertRaises(FileNotFoundError):
                original.invoke(folder,"no-fallback",image,b"",image_format="linked-selfhost",capacity=0,workspace_size=0)
        child.assert_not_called()
        # The published shared invoke API has one linked route as well.
        from tools.hia_selfhost_native_observer import invoke as generic_invoke
        routed=folder/"shared-api";routed.mkdir()
        result,_=generic_invoke(routed,"call",self.executable,image,b"",image_format="linked-selfhost",capacity=0,workspace_size=0,workspace_fill=0)
        self.assertEqual((result["status"],result["core_u32"]),("returned",37))

    def test_phase_manifest_binds_actual_linked_observer_and_rejects_drift(self):
        folder=self.folder("phase-inputs")
        for name,raw in (("native-observer.elf",b"flat held bytes"),("linked-observer.elf",self.executable_bytes),
                         ("modified-selfhost.hepta",b"modified source"),("independent-names-reference.json",b"{}")):
            (folder/name).write_bytes(raw)
        inputs=original._phase_inputs(folder,"names",self.compiler,"original")
        self.assertEqual(set(inputs),{"native_observer","linked_observer","compiler","source","sample","modified_source","reference"})
        self.assertEqual(inputs["linked_observer"]["sha256"],digest(self.executable_bytes))
        self.assertEqual(original._read_phase_inputs(inputs)["linked_observer"],self.executable_bytes)
        (folder/"linked-observer.elf").write_bytes(self.executable_bytes+b"x")
        with self.assertRaisesRegex(ValueError,"input changed: linked_observer"):
            original._read_phase_inputs(inputs)
        self.assertEqual(len(original.QUALIFICATION_FAMILIES),19)

    def test_actual_packer_refusal_and_short_output_are_transactional(self):
        import ctypes
        from hepta.hia_agent_assembly import assemble_program
        from hepta.hia_json_preflight_native import NativeHiaJsonImage
        raw=(self.build_dir/"linked-observer-packer.image.bin").read_bytes()
        image=NativeHiaJsonImage(raw,digest(raw))
        checked=assemble_program(native.PACKER.read_bytes())
        try:
            for source,output,status in ((b"",b"UNCHANGED",0xffffffff),
                    (b"\xc3",b"x"*(len(generator.reference_object(b"\xc3"))-1),0xfffffffe)):
                vm,vo,vw,_=native._vm(checked,source,output,b"")
                actual,ao,aw=self.policy_frame(image,source,output,b"",kind="packer")
                self.assertEqual((actual,ao,aw),(vm,vo,vw))
                self.assertEqual((actual,ao,aw),([status],output,b""))
        finally:
            image._entry=None;image._mapping.close()

    def test_timeout_kills_and_reaps_actual_child_and_closes_descriptors(self):
        folder=self.folder("native-timeout")
        image=assemble(folder,"blocks",'''
.text
.global f0
f0:
 sub $8,%rsp
 mov $39,%eax
 syscall
 mov %rax,(%rsp)
 mov $1,%edi
 mov %rsp,%rsi
 mov $8,%edx
 mov $1,%eax
 syscall
1:
 mov $34,%eax
 syscall
 jmp 1b
.section .note.GNU-stack,"",@progbits
''',shared=True)
        before=len(list(Path("/proc/self/fd").iterdir()))
        with native.output_snapshot(0) as snapshot:
            request=native._linked_frame(image.read_bytes(),b"",0,0,0,None,snapshot)
            with self.assertRaises(subprocess.TimeoutExpired) as observed:
                native.execute(self.executable_bytes,request,cwd=folder,timeout=.1,snapshot_fd=snapshot)
            pid=int.from_bytes(observed.exception.stdout,"little")
            self.assertGreater(pid,1)
            with self.assertRaises(ProcessLookupError):os.kill(pid,0)
            self.assertIsNone(native.read_output_snapshot(snapshot,0))
        self.assertEqual(len(list(Path("/proc/self/fd").iterdir())),before)


if __name__=="__main__":
    unittest.main()
