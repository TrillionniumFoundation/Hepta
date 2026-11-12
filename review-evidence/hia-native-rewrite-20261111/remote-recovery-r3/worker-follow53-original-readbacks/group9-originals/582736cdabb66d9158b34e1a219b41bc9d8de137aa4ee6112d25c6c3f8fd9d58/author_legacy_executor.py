"""Author the fixed native nested-call executor from the exact frozen template.

This adds only private buffer-context invocation/ownership. All historical
format decisions and ordering belong to the new HIA importer image.
"""
from hashlib import sha256
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
ORIGINAL=ROOT.parent/'native-composite-driver-reconstructed/tools/composite_native_executor.S'
ORIGINAL_SHA='b9b503415bd4f65c5673aef3c51a36fb9c824abce0f3a9172ee45b1c27282817'

RUN=r'''
/* HIA chooses a complete fixed child invocation. No value is decoded here. */
op_run_child:
    cmp qword ptr [r15+ROLE],46
    jne abi_error
    cmp qword ptr [r15+PARENT],0
    jne abi_error
    mov edi,10
    call reserved_tail
    cmp qword ptr [r12+32],1
    ja abi_error
    cmp qword ptr [r12+48],0
    jne abi_error
    mov rax,[r12+40]
    cmp rax,[r12+64]
    je abi_error
    mov rdi,rax
    xor esi,esi
    mov rdx,[r12+56]
    test rdx,rdx
    jz abi_error
    call range_view
    cmp [rcx+8],rdx
    jne abi_error
    cmp qword ptr [rcx+24],1
    jne abi_error
    mov rax,[r12+64]
    cmp rax,4
    jb abi_error
    cmp rax,63
    ja abi_error
    shl rax,5
    cmp qword ptr [r15+rax],0
    jne abi_error
    mov rax,[r12+72]
    test rax,rax
    jz abi_error
    cmp rax,-1
    je abi_error
    xor edi,edi
    mov esi,16384
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae io_error
    mov r10,rax
    mov [r10+PARENT],r15
    mov qword ptr [r10+FDS],-1
    mov qword ptr [r10+FDS+8],-1
    mov rax,[r12+32]
    mov [r10+RUN_MODE],rax
    mov [r10+LEGACY],rax
    mov rax,[r12+64]
    mov [r10+CHILD_TARGET],rax
    mov rax,[r12+72]
    mov [r10+LEASE],rax
    mov rax,[r12+56]
    mov [r10+RAW_LEN],rax
    mov edx,44
    mov qword ptr [r10+PUB_ROLE],45
    cmp qword ptr [r10+RUN_MODE],0
    je child_select_source
    mov edx,1
    mov qword ptr [r10+PUB_ROLE],47
child_select_source:
    mov qword ptr [r10+BORROWED+rdx*8],1
    shl rdx,5
    lea rdi,[r10+rdx]
    mov rsi,[r12+40]
    shl rsi,5
    add rsi,r15
    mov ecx,4
    rep movsq
    mov r15,r10
    xor edi,edi
    mov esi,4096
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae io_error
    mov [r15+CMDMAP],rax
    mov r13,rax
    xor edi,edi
    mov esi,4096
    mov edx,3
    mov r10d,0x22
    mov r8,-1
    xor r9d,r9d
    mov eax,9
    syscall
    cmp rax,-4095
    jae io_error
    mov [r15+FRAMEMAP],rax
    mov r12,rax
    xor edi,edi
    mov esi,1
    call resize_slot
    xor edi,edi
    mov esi,1
    call protect_slot
    mov edi,2
    mov esi,1048576
    call resize_slot
    mov rbx,[r15+2*32]
    mov qword ptr [rbx+4096],1
    mov qword ptr [rbx+4096+16],1048576
    cmp qword ptr [r15+RUN_MODE],0
    jne child_constructor_start
    mov rax,[r15+RAW_LEN]
    mov [rbx+4096+44*8],rax
    mov rax,RAW_CONFIG
    mov [rbx+12288],rax
    mov qword ptr [rbx+12296],0
    mov rax,[rip+executable_policy+8]
    mov [rbx+12304],rax
    mov rax,[r15+LEASE]
    mov [rbx+12312],rax
    mov qword ptr [r15+ROLE],44
    mov rax,[r15+44*32]
    mov [r15+CMDPTR],rax
    mov rax,[r15+RAW_LEN]
    mov [r15+CMDLEN],rax
    jmp controller_entry
child_constructor_start:
    mov rax,[r15+RAW_LEN]
    mov [rbx+4096+8],rax
    mov rax,CTOR_INIT
    mov [r13],rax
    mov rax,[r15+LEASE]
    mov [r13+8],rax
    mov qword ptr [r13+16],1
    mov rax,[r15+RAW_LEN]
    mov [r13+24],rax
    mov [r15+CMDPTR],r13
    mov qword ptr [r15+CMDLEN],64
    mov qword ptr [r15+ROLE],43
    jmp controller_entry

/* Copy only actual terminal bytes and transfer one actual readonly mapping.
 * The parent ACK is inaccessible to HIA child kernels. Its private context
 * and pending sequence remain live and immutable throughout this invocation.
 */
child_complete:
    mov rbx,[r15+PARENT]
    test rbx,rbx
    jz abi_error
    cmp qword ptr [rbx+PARENT],0
    jne abi_error
    cmp qword ptr [rbx+ROLE],46
    jne abi_error
    mov rax,[rbx+FRAMEMAP]
    cmp qword ptr [rax+8],15
    jne abi_error
    mov rcx,[r15+CHILD_TARGET]
    cmp [rax+64],rcx
    jne abi_error
    mov rdi,[rbx+CMDMAP]
    cmp qword ptr [rdi+24],15
    jne abi_error
    mov qword ptr [rdi+40],128
    mov qword ptr [rdi+48],160
    mov qword ptr [rdi+192],0
    mov [rdi+200],rcx
    mov rax,[r15+ROLE]
    mov [rdi+208],rax
    mov qword ptr [rdi+216],0
    add rdi,64
    mov rsi,r12
    mov ecx,16
    rep movsq
    mov qword ptr [rbx+CMDLEN],224
    cmp qword ptr [r12+32],0
    jne child_cleanup
    cmp qword ptr [r12+40],0
    jne abi_error
    mov rax,[r15+ROLE]
    cmp [r15+PUB_ROLE],rax
    jne abi_error
    cmp qword ptr [r15+45*32+24],1
    jne abi_error
    mov edi,45
    xor esi,esi
    mov rdx,[r12+88]
    test rdx,rdx
    jz abi_error
    call range_view
    mov rax,[r15+CHILD_TARGET]
    shl rax,5
    lea rdi,[rbx+rax]
    cmp qword ptr [rdi],0
    jne abi_error
    lea rsi,[r15+45*32]
    mov ecx,4
    rep movsq
    mov rax,[r15+45*32+8]
    mov rdi,[rbx+CMDMAP]
    mov [rdi+192],rax
    lea rdi,[r15+45*32]
    xor eax,eax
    mov ecx,4
    rep stosq
child_cleanup:
    xor r8d,r8d
child_cleanup_maps:
    cmp qword ptr [r15+BORROWED+r8*8],0
    jne child_cleanup_next
    mov r9,r8
    shl r9,5
    mov rdi,[r15+r9]
    test rdi,rdi
    jz child_cleanup_next
    mov rsi,[r15+r9+16]
    mov eax,11
    syscall
    test rax,rax
    jnz io_error
child_cleanup_next:
    inc r8d
    cmp r8d,64
    jb child_cleanup_maps
    xor r8d,r8d
child_cleanup_files:
    mov rdi,[r15+FDS+r8*8]
    test rdi,rdi
    js child_cleanup_file_next
    mov eax,3
    syscall
    test rax,rax
    jnz io_error
child_cleanup_file_next:
    inc r8d
    cmp r8d,2
    jb child_cleanup_files
    mov rdi,r13
    mov esi,4096
    mov eax,11
    syscall
    test rax,rax
    jnz io_error
    mov rdi,r12
    mov esi,4096
    mov eax,11
    syscall
    test rax,rax
    jnz io_error
    mov rdi,r15
    mov esi,16384
    mov eax,11
    syscall
    test rax,rax
    jnz early_io
    mov r15,rbx
    mov r12,[r15+FRAMEMAP]
    mov r13,[r15+CMDMAP]
    jmp controller_entry
'''


def replace(text, old, new, count=1):
    assert text.count(old)==count,(old,text.count(old))
    return text.replace(old,new)


def author():
    raw=ORIGINAL.read_bytes();assert sha256(raw).hexdigest()==ORIGINAL_SHA
    text=raw.decode()
    text=replace(text,'.equ TWO_READ_MASK,0x0000000002ac0462',
        '.equ TWO_READ_MASK,0x0000000022ac0462\n.equ RUN_MODE,2232\n.equ PUB_ROLE,2240\n.equ PARENT,2248\n.equ CHILD_TARGET,2256\n.equ LEGACY,2264\n.equ BORROWED,8192\n.equ IMPORT_INIT,0x313049494c414948')
    text=replace(text,'    mov rax,[rip+executable_policy]\n    cmp rax,1\n    ja abi_error\n    mov [rbx+12296],rax',
        '    cmp qword ptr [rip+executable_policy],2\n    jne abi_error\n    mov qword ptr [rbx+12296],0')
    text=replace(text,'    cmp rax,45\n    ja abi_error','    cmp rax,47\n    ja abi_error')
    text=replace(text,'    cmp rax,27\n    ja abi_error','    cmp rax,29\n    ja abi_error')
    text=replace(text,'    cmp rax,14\n    je op_view\n    jmp abi_error',
        '    cmp rax,14\n    je op_view\n    cmp rax,15\n    je op_run_child\n    jmp abi_error')
    old='''    mov rsi,[rbx+16]
    mov eax,11
    syscall
    test rax,rax
    jnz io_error
    mov rdi,rbx'''
    new='''    mov rcx,[r12+32]
    cmp qword ptr [r15+BORROWED+rcx*8],0
    jne release_borrowed
    mov rsi,[rbx+16]
    mov eax,11
    syscall
    test rax,rax
    jnz io_error
release_borrowed:
    mov rcx,[r12+32]
    mov qword ptr [r15+BORROWED+rcx*8],0
    mov rdi,rbx'''
    text=replace(text,old,new)
    text=replace(text,'    shl rdi,5\n    lea r9,[r15+rdi]',
        '    cmp qword ptr [r15+BORROWED+rdi*8],0\n    je protection_owned\n    cmp rsi,1\n    jne abi_error\nprotection_owned:\n    shl rdi,5\n    lea r9,[r15+rdi]')
    text=replace(text,'    cmp qword ptr [r15+ROLE],45\n    jne abi_error\n    cmp qword ptr [r12+32],0',
        '    cmp qword ptr [r15+ROLE],45\n    je final_publication\n    cmp qword ptr [r15+ROLE],47\n    je final_publication\n    cmp qword ptr [r15+ROLE],46\n    jne abi_error\nfinal_publication:\n    cmp qword ptr [r12+32],0')
    text=replace(text,'    cmp qword ptr [r15+45*32+24],1\n    jne abi_error\n    mov edi,45',
        '    cmp qword ptr [r15+PARENT],0\n    jne child_complete\n    cmp qword ptr [r15+45*32+24],1\n    jne abi_error\n    mov edi,45')
    text=replace(text,'    mov rax,[rip+executable_policy]\n    cmp [r12+48],rax',
        '    mov rax,[r15+LEGACY]\n    cmp [r12+48],rax')
    text=replace(text,'    mov qword ptr [r15+ROLE],43\n    mov rdi,r13',
        '    mov qword ptr [r15+ROLE],43\n    cmp qword ptr [r15+PARENT],0\n    jne raw_target_selected\n    mov qword ptr [r15+ROLE],46\nraw_target_selected:\n    mov rdi,r13')
    text=replace(text,'    mov rax,CTOR_INIT\n    mov [r13],rax',
        '    mov rax,CTOR_INIT\n    cmp qword ptr [r15+PARENT],0\n    jne raw_command_selected\n    mov rax,IMPORT_INIT\nraw_command_selected:\n    mov [r13],rax')
    text=replace(text,'    mov qword ptr [r15+ROLE],45\ncopy_handoff:',
        '    mov rax,[r15+PUB_ROLE]\n    cmp rax,45\n    je selected_publication\n    cmp rax,47\n    jne abi_error\nselected_publication:\n    mov [r15+ROLE],rax\ncopy_handoff:')
    text=replace(text,'semantic_error:\n    mov rsi,r12',
        'semantic_error:\n    cmp qword ptr [r15+PARENT],0\n    jne child_complete\n    mov rsi,r12')
    text=replace(text,'/* Leaf helpers. All quantities are exact unsigned buffer extents, never values. */',
        RUN+'\n/* Leaf helpers. All quantities are exact unsigned buffer extents, never values. */')
    text=replace(text,'    .quad 0,4300','    .quad 2,4300')
    return text


if __name__=='__main__':
    path=ROOT/'tools/legacy_native_executor.S';path.write_text(author())
    print(path,len(path.read_bytes()),sha256(path.read_bytes()).hexdigest())
