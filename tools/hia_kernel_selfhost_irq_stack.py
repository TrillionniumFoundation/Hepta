"""Experimental raw CPL0 interrupt dispatch on a separate fixed stack.
The GS descriptor is caller-owned; this is not general CPU/page authority.
Native byte emission, checked against an independent GNU as mnemonic oracle.
"""
from tools import hia_kernel_selfhost_kernel_irq as irq
from tools import hia_kernel_selfhost_kernel_frame as frame
WORD = "x86.irq.dispatch_on_stack"
EFFECTS = ("privilege","atomic","read","write","trap")
DISPATCH = bytes.fromhex(
    "4889c7b9010100c00f3248c1e2204809d04885c075020f0ba80774020f0b4889"
    "c248c1ea2f74020f0b488d501f48c1ea2f74020f0b4989c4498b1c244885db75"
    "020f0b4889da48c1ea2f74020f0b4d8b6c24084d8b7424104d85ed75020f0b41"
    "f6c50f74020f0b4c89f248c1ea2f74020f0b498d95004000004939d674020f0b"
    "4d39ee77020f0b498d5424204c39ea76074d39f473020f0b488d97a00000004c"
    "39e2760c498d4c24204839cf73020f0b4c39ea76074c39f773020f0b4831c0ba"
    "01000000f0490fb154241874020f0b4c89eab94000000048813a785634127402"
    "0f0b4883c208ffc975ed4c89f4ffd34989c74c39f474020f0b49391c2474020f"
    "0b4d396c240874020f0b4d3974241074020f0b4c89eab94000000048813a7856"
    "341274020f0b4883c208ffc975ed4d85ff75020f0b4c89fa48c1ea2f74020f0b"
    "41f6c70f74020f0b498d979f00000048c1ea2f74020f0b498d97a00000004c39"
    "ea76074d39f773020f0b4c39e2760c498d4c24204939cf73020f0b9c5a48f7c2"
    "0002000074020f0bb8010000004831d2f0490fb154241874020f0b4c89f8"
)
ORACLE = r""".text
.macro guard condition
\condition 1f
ud2
1:
.endm
/* RAX is original frame, with all 15 GPRs already saved. */
movq %rax,%rdi
movl $0xc0000101,%ecx
rdmsr
shlq $32,%rdx
orq %rdx,%rax
testq %rax,%rax
guard jnz
testb $7,%al
guard jz
movq %rax,%rdx
shrq $47,%rdx
guard jz
leaq 31(%rax),%rdx
shrq $47,%rdx
guard jz
movq %rax,%r12
movq 0(%r12),%rbx
testq %rbx,%rbx
guard jnz
movq %rbx,%rdx
shrq $47,%rdx
guard jz
movq 8(%r12),%r13
movq 16(%r12),%r14
testq %r13,%r13
guard jnz
testb $15,%r13b
guard jz
movq %r14,%rdx
shrq $47,%rdx
guard jz
leaq 16384(%r13),%rdx
cmpq %rdx,%r14
guard je
cmpq %r13,%r14
guard ja
/* descriptor disjoint from stack */
leaq 32(%r12),%rdx
cmpq %r13,%rdx
jbe 2f
cmpq %r14,%r12
guard jae
2:
/* original saved frame disjoint from descriptor and scheduler stack */
leaq 160(%rdi),%rdx
cmpq %r12,%rdx
jbe 3f
leaq 32(%r12),%rcx
cmpq %rcx,%rdi
guard jae
3:
cmpq %r13,%rdx
jbe 4f
cmpq %r14,%rdi
guard jae
4:
/* acquire descriptor, no callback on busy */
xorq %rax,%rax
movl $1,%edx
lock cmpxchgq %rdx,24(%r12)
guard je
/* 512-byte bottom canary */
movq %r13,%rdx
movl $64,%ecx
5:
cmpq $0x12345678,(%rdx)
guard je
addq $8,%rdx
decl %ecx
jnz 5b
/* the only stack switch is in this native export */
movq %r14,%rsp
call *%rbx
movq %rax,%r15
cmpq %r14,%rsp
guard je
cmpq %rbx,0(%r12)
guard je
cmpq %r13,8(%r12)
guard je
cmpq %r14,16(%r12)
guard je
movq %r13,%rdx
movl $64,%ecx
6:
cmpq $0x12345678,(%rdx)
guard je
addq $8,%rdx
decl %ecx
jnz 6b
/* selected frame cannot point into the transient scheduler stack or descriptor */
testq %r15,%r15
guard jnz
movq %r15,%rdx
shrq $47,%rdx
guard jz
testb $15,%r15b
guard jz
leaq 159(%r15),%rdx
shrq $47,%rdx
guard jz
leaq 160(%r15),%rdx
cmpq %r13,%rdx
jbe 7f
cmpq %r14,%r15
guard jae
7:
cmpq %r12,%rdx
jbe 8f
leaq 32(%r12),%rcx
cmpq %rcx,%r15
guard jae
8:
pushfq
popq %rdx
testq $0x200,%rdx
guard jz
/* release only after callback and canary checks */
movl $1,%eax
xorq %rdx,%rdx
lock cmpxchgq %rdx,24(%r12)
guard je
movq %r15,%rax
"""
# Validate the selected control frame while the lease is still acquired.
# Only the actual pop/IRET tail follows release, with no intervening stack use.
_RELEASE = DISPATCH.index(bytes.fromhex("b8010000004831d2f0490fb1542418"))
ENCODING = (irq.SAVE + irq.PRECHECK + DISPATCH[:_RELEASE] +
            bytes.fromhex("4c89f8") + irq.PRECHECK + DISPATCH[_RELEASE:] +
            frame.ENCODING[len(irq.PRECHECK):])


# Separate ABI: never reinterpret the original 0/1 raw descriptor lease.
GENERATION_WORD = "x86.irq.dispatch_gen_stack"
_GENERATION_ACQUIRE = bytes.fromhex("498b442418a80174020f0b4883f8fe72020f0b488d6801f0490fb16c241874020f0b")
_GENERATION_GS = bytes.fromhex("b9010100c00f3248c1e2204809d04c39e074020f0b")
_GENERATION_RELEASE = bytes.fromhex("4889e8488d5501f0490fb154241874020f0b")
_OLD_ACQUIRE = bytes.fromhex("4831c0ba01000000f0490fb154241874020f0b")
_AFTER_CALLBACK = bytes.fromhex("4c39f474020f0b")
_OLD_RELEASE = bytes.fromhex("b8010000004831d2f0490fb154241874020f0b")
assert ENCODING.count(_OLD_ACQUIRE) == ENCODING.count(_AFTER_CALLBACK) == ENCODING.count(_OLD_RELEASE) == 1
GENERATION_ENCODING = (ENCODING.replace(_OLD_ACQUIRE,_GENERATION_ACQUIRE)
    .replace(_AFTER_CALLBACK,_AFTER_CALLBACK+_GENERATION_GS)
    .replace(_OLD_RELEASE,_GENERATION_RELEASE))
GENERATION_ORACLE = (ORACLE.replace("xorq %rax,%rax\nmovl $1,%edx\nlock cmpxchgq %rdx,24(%r12)\nguard je\n", 'movq 24(%r12),%rax\ntestb $1,%al\nguard jz\ncmpq $-2,%rax\nguard jb\nleaq 1(%rax),%rbp\nlock cmpxchgq %rbp,24(%r12)\nguard je\n')
    .replace("cmpq %r14,%rsp\nguard je\n", "cmpq %r14,%rsp\nguard je\n"+'movl $0xc0000101,%ecx\nrdmsr\nshlq $32,%rdx\norq %rdx,%rax\ncmpq %r12,%rax\nguard je\n')
    .replace("movl $1,%eax\nxorq %rdx,%rdx\nlock cmpxchgq %rdx,24(%r12)\nguard je\n", 'movq %rbp,%rax\nleaq 1(%rbp),%rdx\nlock cmpxchgq %rdx,24(%r12)\nguard je\n'))

BOUND_WORD = "x86.irq.dispatch_bound_stack"
_BOUND_ANCHOR = bytes.fromhex("4989c4")
_BOUND_CHECK = bytes.fromhex("b91b0000000f3285d274020f0b25fffeffff3d0008e0fe74020f0bba2000e0fe8b12c1ea1883fa0176020f0b4189d3b9000100c00f3248c1e2204809d04885c075020f0ba81f74020f0b4889c248c1ea2f74020f0b488d503f48c1ea2f74020f0b49c1e3054c01d84c39e074020f0b")
assert GENERATION_ENCODING.count(_BOUND_ANCHOR) == 1
BOUND_ENCODING = GENERATION_ENCODING.replace(_BOUND_ANCHOR,_BOUND_ANCHOR+_BOUND_CHECK)
BOUND_ORACLE = GENERATION_ORACLE.replace("movq %rax,%r12\n", "movq %rax,%r12\n"+'/* r12 = GS candidate; rdi = untouched original frame.\n   FS_BASE is a separately boot-provisioned trusted dense table root. */\nmovl $0x1b,%ecx\nrdmsr\ntestl %edx,%edx\nguard jz\nandl $0xfffffeff,%eax\ncmpl $0xfee00800,%eax\nguard je\nmovl $0xfee00020,%edx\nmovl (%rdx),%edx\nshrl $24,%edx\ncmpl $1,%edx\nguard jbe\nmovl %edx,%r11d\nmovl $0xc0000100,%ecx\nrdmsr\nshlq $32,%rdx\norq %rdx,%rax\ntestq %rax,%rax\nguard jnz\ntestb $31,%al\nguard jz\nmovq %rax,%rdx\nshrq $47,%rdx\nguard jz\nleaq 63(%rax),%rdx\nshrq $47,%rdx\nguard jz\nshlq $5,%r11\naddq %r11,%rax\ncmpq %r12,%rax\nguard je\n')

def emission_segments():
    rest=ENCODING
    for old,new in ((_BOUND_ANCHOR,_BOUND_ANCHOR+_BOUND_CHECK),(_OLD_ACQUIRE,_GENERATION_ACQUIRE),(_AFTER_CALLBACK,_AFTER_CALLBACK+_GENERATION_GS),(_OLD_RELEASE,_GENERATION_RELEASE)):
        head,rest=rest.split(old,1)
        yield head
        yield (old,new)
    yield rest

def extend_source(source, replace_once):
    source = replace_once(source, "def instruction_effects(op:u64) -> u64:",
        """def instruction_effects(op:u64) -> u64:
    if op == @x86.irq.dispatch_bound_stack@:
        return 62
    if op == @x86.irq.dispatch_gen_stack@:
        return 62
    if op == @x86.irq.dispatch_on_stack@:
        return 62""")
    source = replace_once(source,
        "    if op >= @x86.mmio.read32@ and op <= @x86.irq.dispatch_kernel_frame@:",
        "    if op >= @x86.mmio.read32@ and op <= @x86.irq.dispatch_bound_stack@:")
    sig = ("def mmio_instruction(s:readbuf, o:mutbuf, w:mutbuf, op:u64, n:u64, "
           "at:u64, t:u64, v:u64, bt:u64, a:u64, b:u64) -> u64:")
    source = replace_once(source, sig, sig + """
    if op == @x86.irq.dispatch_bound_stack@:
        return irq_stack_instruction(s, w, n, t, 6)
    if op == @x86.irq.dispatch_gen_stack@:
        return irq_stack_instruction(s, w, n, t, 5)
    if op == @x86.irq.dispatch_on_stack@:
        return irq_stack_instruction(s, w, n, t, 4)""")
    anchor = "def export_wrapper(o:mutbuf, w:mutbuf, record:u64) -> u64:"
    source = replace_once(source, anchor, anchor + """
    if get(w, 200) == 6:
        return irq_stack_export(o, w, record)
    if get(w, 200) == 5:
        return irq_stack_export(o, w, record)
    if get(w, 200) == 4:
        return irq_stack_export(o, w, record)""")
    source += """
def irq_stack_instruction(s:readbuf, w:mutbuf, n:u64, t:u64, mode:u64) -> u64:
    if get(w, 200) != 1 or n != 0 or t != 0 or get(w, 288) != 0:
        return fail(w, 65)
    if get(w, 72) != 0 or get(w, 88) != 0 or get(w, 112) != 1 or get(w, 648) != 1:
        return fail(w, 65)
    if get(w, FBASE + 24) != 0 or get(w, FBASE + 184) != 0 or get(w, FBASE + 176) != 62:
        return fail(w, 65)
    expect(s, w, 10)
    if get(w, 8) != @trap@:
        return fail(w, 65)
    if get(w, 40) != 0:
        return 0
    put(w, 200, mode)
    return 0

def irq_stack_export(o:mutbuf, w:mutbuf, record:u64) -> u64:
    put(w, record + 32, get(w, 56))
"""
    def emit(data, indent):
        chunks = []
        while len(data) >= 16:
            a,b = (int.from_bytes(data[k:k+8],"little") for k in (0,8))
            chunks.append(f"{indent}irq_emit_pair(o, w, {a}, {b})\n")
            data=data[16:]
        for off in range(0,len(data),8):
            part=data[off:off+8]
            chunks.append(f"{indent}emit_bytes(o, w, {int.from_bytes(part,'little')}, {len(part)})\n")
        return "".join(chunks)
    for segment in emission_segments():
        if isinstance(segment, tuple):
            old,new = segment
            source += ("    if get(w, 200) == 6:\n" if old == _BOUND_ANCHOR else "    if get(w, 200) >= 5:\n") + emit(new,"        ") + "    else:\n" + emit(old,"        ")
        else:
            source += emit(segment,"    ")
    return source+"    put(w, record + 40, get(w, 56) - get(w, record + 32))\n    return 0\n\ndef irq_emit_pair(o:mutbuf, w:mutbuf, a:u64, b:u64) -> u64:\n    emit_bytes(o, w, a, 8)\n    emit_bytes(o, w, b, 8)\n    return 0\n"

def program(profile, **kw):
    kw.setdefault("effects", EFFECTS)
    return irq.program(profile, **kw).replace(b"x86.irq.dispatch_kernel_frame",WORD.encode())

def qualify(exe, output, profile, legacy, compile_cli, text_bytes, digest, generation=False, bound=False):
    import subprocess
    tag = "irq-bound-stack" if bound else "irq-generation-stack" if generation else "irq-stack"
    encoding = BOUND_ENCODING if bound else GENERATION_ENCODING if generation else ENCODING
    dispatch_oracle = BOUND_ORACLE if bound else GENERATION_ORACLE if generation else ORACLE
    def p(*args, **kwargs):
        result=program(*args, **kwargs)
        return result.replace(WORD.encode(),BOUND_WORD.encode()) if bound else result.replace(WORD.encode(),GENERATION_WORD.encode()) if generation else result
    subject = p(profile)
    obj = compile_cli(exe, subject, output, tag+"-1")
    assert obj == compile_cli(exe, subject, output, tag+"-2")
    machine = text_bytes(output, tag, obj)
    prefix = irq.ORACLE_PREFIX.split("movq %rax,%rdi",1)[0]
    restore = frame.ORACLE.split(" testq %rax,%rax",1)[1]
    check, tail = restore.split(" movq %rax,%rsp",1)
    dispatch = dispatch_oracle.split(".endm\n",1)[1]
    marker = "/* release only after callback and canary checks */"
    assert dispatch.count(marker) == 1
    dispatch = dispatch.replace(marker, "movq %r15,%rax\n testq %rax,%rax"+check+marker)
    asm = output/(tag+"-oracle.S")
    asm.write_text(prefix+dispatch+" movq %rax,%rsp"+tail)
    oracle = output/(tag+"-oracle.o")
    subprocess.run(["as","--64","-o",str(oracle),str(asm)],check=True)
    actual = text_bytes(output,tag+"-oracle-copy",oracle.read_bytes())
    assert actual == encoding
    assert machine.count(encoding) == 1
    other = "fn f1() -> () effects() entry(b0)\nblock b0()\n  ret()\nend\n"
    bad = {
        "legacy":p(legacy,effects=()),
        "legacy-effects":p(legacy),
        "flat":p(profile,module="selfhost",exports=None),
        "no-export":p(profile,exports=None),
        "parameter":p(profile,params="v0:u64"),
        "result":p(profile,op="  v0:u64 = x86.irq.dispatch_on_stack()\n"),
        "operand":p(profile,params="v0:u64",op="  _ = x86.irq.dispatch_on_stack(v0)\n"),
        "attribute":p(profile,op='  _ = x86.irq.dispatch_on_stack() {"trust_me":true}\n'),
        "ordinary-return":p(profile,terminator="ret()"),
        "wrong-trap":p(profile,terminator="trap bounds"),
        "return-value":p(profile,returns="u64"),
        "extra-function":p(profile,extra=other),
        "extra-export":p(profile,exports="f0,f1",extra=other),
        "extra-block":subject.replace(b"end\n",b"block b1()\n  trap user\nend\n",1),
        "preceding-op":p(profile,op='  v0:u64 = const() {"value":1}\n  _ = x86.irq.dispatch_on_stack()\n'),
        "following-op":p(profile,op='  _ = x86.irq.dispatch_on_stack()\n  v0:u64 = const() {"value":1}\n'),
    }
    for effect in EFFECTS:
        bad["missing-"+effect]=p(profile,effects=tuple(x for x in EFFECTS if x!=effect))
    for name, malformed in bad.items():
        compile_cli(exe,malformed,output,tag+"-"+name,expected=2)
    return {"source_sha256":digest(subject),"elf_sha256":digest(obj),
            "text_sha256":digest(machine),"encoding_hex":encoding.hex(),
            "refusals":sorted(bad),"raw_export_required":True,
            "fixed_stack_bytes":16384,"bottom_canary_bytes":512,
            "descriptor_bytes":32,"general_cpu_page_authority_proved":False}
