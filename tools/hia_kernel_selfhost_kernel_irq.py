"""Raw CPL0 no-error-code interrupt gate entry for the experimental native compiler.

A caller-owned aligned GS_BASE descriptor contains a SysV dispatcher pointer.
The dispatcher receives the original integer frame and returns a selected
frame. No general stack, mapping, callback or CPU resource authority is claimed.
"""
import subprocess
from tools import hia_kernel_selfhost_kernel_frame as frame

WORD = "x86.irq.dispatch_kernel_frame"
EFFECTS = ("privilege","read","write","trap")
SAVE = bytes.fromhex("5053515256575541504151415241534154415541564157fc4889e0")
PRECHECK = frame.ENCODING[:frame.ENCODING.index(bytes.fromhex("4889c4"))]
DISPATCH = bytes.fromhex(
    "4889c7b9010100c00f3248c1e2204809d0"
    "4885c075020f0ba80774020f0b4889c248c1ea2f4885d274020f0b"
    "488b004885c075020f0b4889c248c1ea2f4885d274020f0b"
    "4883e4f0ffd0")
PREFIX = SAVE + PRECHECK + DISPATCH
ENCODING = PREFIX + frame.ENCODING
ORACLE_PREFIX = r""".text
.macro guard condition
\condition 1f
ud2
1:
.endm
pushq %rax
pushq %rbx
pushq %rcx
pushq %rdx
pushq %rsi
pushq %rdi
pushq %rbp
pushq %r8
pushq %r9
pushq %r10
pushq %r11
pushq %r12
pushq %r13
pushq %r14
pushq %r15
cld
movq %rsp,%rax
""" + " testq %rax,%rax" + frame.ORACLE.split(" testq %rax,%rax",1)[1].split(" movq %rax,%rsp",1)[0] + r"""
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
testq %rdx,%rdx
guard jz
movq (%rax),%rax
testq %rax,%rax
guard jnz
movq %rax,%rdx
shrq $47,%rdx
testq %rdx,%rdx
guard jz
andq $-16,%rsp
call *%rax
"""

def extend_source(source, replace_once):
    source = replace_once(source, "def instruction_effects(op:u64) -> u64:",
        """def instruction_effects(op:u64) -> u64:
    if op == @x86.irq.dispatch_kernel_frame@:
        return 30""")
    source = replace_once(source,
        "    if op >= @x86.mmio.read32@ and op <= @x86.irq.restore_kernel_frame@:",
        "    if op >= @x86.mmio.read32@ and op <= @x86.irq.dispatch_kernel_frame@:")
    signature = ("def mmio_instruction(s:readbuf, o:mutbuf, w:mutbuf, op:u64, n:u64, "
                 "at:u64, t:u64, v:u64, bt:u64, a:u64, b:u64) -> u64:")
    source = replace_once(source, signature, signature + """
    if op == @x86.irq.dispatch_kernel_frame@:
        return kernel_irq_instruction(s, w, n, t)""")
    source = replace_once(source, "        if get(w, 200) == 2:",
                          "        if get(w, 200) >= 2:")
    source = replace_once(source, "    if get(w, 200) == 2 and code != @user@:",
                          "    if get(w, 200) >= 2 and code != @user@:")
    anchor = "def export_wrapper(o:mutbuf, w:mutbuf, record:u64) -> u64:"
    source = replace_once(source, anchor, anchor + """
    if get(w, 200) == 3:
        return kernel_irq_export(o, w, record)""")
    source += """
def kernel_irq_instruction(s:readbuf, w:mutbuf, n:u64, t:u64) -> u64:
    if get(w, 200) != 1 or n != 0 or t != 0 or get(w, 288) != 0:
        return fail(w, 65)
    if get(w, 72) != 0 or get(w, 88) != 0 or get(w, 112) != 1 or get(w, 648) != 1:
        return fail(w, 65)
    if get(w, FBASE + 24) != 0 or get(w, FBASE + 184) != 0 or get(w, FBASE + 176) != 30:
        return fail(w, 65)
    expect(s, w, 10)
    if get(w, 8) != @trap@:
        return fail(w, 65)
    if get(w, 40) != 0:
        return 0
    put(w, 200, 3)
    return 0

def kernel_irq_export(o:mutbuf, w:mutbuf, record:u64) -> u64:
    put(w, record + 32, get(w, 56))
"""
    for off in range(0,len(ENCODING),8):
        chunk=ENCODING[off:off+8]
        source+=f"    emit_bytes(o, w, {int.from_bytes(chunk,'little')}, {len(chunk)})\n"
    return source+"    put(w, record + 40, get(w, 56) - get(w, record + 32))\n    return 0\n"

def program(profile, *, effects=EFFECTS, params="", op=None, terminator="trap user",
            returns="", module="selfhost_elf", exports="f0", extra=""):
    operation=op if op is not None else "  _ = x86.irq.dispatch_kernel_frame()\n"
    export_line=f"exports({exports})\n" if exports is not None else ""
    return (f"hia-asm.v1 {profile} {module}\n"+export_line+
            f"fn f0({params}) -> ({returns}) effects({','.join(effects)}) entry(b0)\n"
            f"block b0({params})\n"+operation+f"  {terminator}\nend\n"+extra).encode()

def qualify(exe, output, profile, legacy, compile_cli, text_bytes, digest):
    source=program(profile)
    obj=compile_cli(exe,source,output,"kernel-irq-1")
    assert obj==compile_cli(exe,source,output,"kernel-irq-2")
    machine=text_bytes(output,"kernel-irq",obj)
    asm=output/"kernel-irq-oracle.S"
    restore=frame.ORACLE.split(" testq %rax,%rax",1)[1]
    asm.write_text(ORACLE_PREFIX+" testq %rax,%rax"+restore)
    oracle=output/"kernel-irq-oracle.o"
    subprocess.run(["as","--64","-o",str(oracle),str(asm)],check=True)
    actual=text_bytes(output,"kernel-irq-oracle-copy",oracle.read_bytes())
    assert actual==ENCODING,(actual.hex(),ENCODING.hex())
    assert machine.count(ENCODING)==1
    other="fn f1() -> () effects() entry(b0)\nblock b0()\n  ret()\nend\n"
    bad={
        "legacy":program(legacy,effects=()),
        "legacy-effects":program(legacy),
        "flat":program(profile,module="selfhost",exports=None),
        "no-export":program(profile,exports=None),
        "parameter":program(profile,params="v0:u64"),
        "result":program(profile,op="  v0:u64 = x86.irq.dispatch_kernel_frame()\n"),
        "operand":program(profile,params="v0:u64",op="  _ = x86.irq.dispatch_kernel_frame(v0)\n"),
        "attribute":program(profile,op='  _ = x86.irq.dispatch_kernel_frame() {"trust_me":true}\n'),
        "ordinary-return":program(profile,terminator="ret()"),
        "wrong-trap":program(profile,terminator="trap bounds"),
        "return-value":program(profile,returns="u64"),
        "extra-function":program(profile,extra=other),
        "extra-export":program(profile,exports="f0,f1",extra=other),
        "extra-block":source.replace(b"end\n",b"block b1()\n  trap user\nend\n",1),
        "preceding-op":program(profile,op='  v0:u64 = const() {"value":1}\n  _ = x86.irq.dispatch_kernel_frame()\n'),
        "following-op":program(profile,op='  _ = x86.irq.dispatch_kernel_frame()\n  v0:u64 = const() {"value":1}\n'),
    }
    for effect in EFFECTS:
        bad["missing-"+effect]=program(profile,effects=tuple(x for x in EFFECTS if x!=effect))
    for name,malformed in bad.items():
        compile_cli(exe,malformed,output,"kernel-irq-"+name,expected=2)
    return {"source_sha256":digest(source),"elf_sha256":digest(obj),
            "text_sha256":digest(machine),"encoding_hex":ENCODING.hex(),
            "refusals":sorted(bad),"raw_export_required":True}
