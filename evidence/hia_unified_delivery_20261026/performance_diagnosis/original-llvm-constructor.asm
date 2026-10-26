
/tmp/hia-perf-diagnosis-9fe/llvm.so:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .plt.got:

Disassembly of section .text:

00000000000012b0 <constructor_error>:
    12b0:	41 56                	push   %r14
    12b2:	53                   	push   %rbx
    12b3:	50                   	push   %rax
    12b4:	89 f3                	mov    %esi,%ebx
    12b6:	41 b6 01             	mov    $0x1,%r14b
    12b9:	48 85 ff             	test   %rdi,%rdi
    12bc:	74 20                	je     12de <constructor_error+0x2e>
    12be:	78 17                	js     12d7 <constructor_error+0x27>
    12c0:	48 89 fe             	mov    %rdi,%rsi
    12c3:	bf 01 00 00 00       	mov    $0x1,%edi
    12c8:	e8 83 fd ff ff       	call   1050 <calloc@plt>
    12cd:	48 85 c0             	test   %rax,%rax
    12d0:	74 05                	je     12d7 <constructor_error+0x27>
    12d2:	48 89 c7             	mov    %rax,%rdi
    12d5:	eb 09                	jmp    12e0 <constructor_error+0x30>
    12d7:	31 ff                	xor    %edi,%edi
    12d9:	45 31 f6             	xor    %r14d,%r14d
    12dc:	eb 02                	jmp    12e0 <constructor_error+0x30>
    12de:	31 ff                	xor    %edi,%edi
    12e0:	e8 4b fd ff ff       	call   1030 <free@plt>
    12e5:	89 d8                	mov    %ebx,%eax
    12e7:	41 0f b6 ce          	movzbl %r14b,%ecx
    12eb:	83 e1 01             	and    $0x1,%ecx
    12ee:	48 01 c8             	add    %rcx,%rax
    12f1:	48 05 e9 03 00 00    	add    $0x3e9,%rax
    12f7:	48 83 c4 08          	add    $0x8,%rsp
    12fb:	5b                   	pop    %rbx
    12fc:	41 5e                	pop    %r14
    12fe:	c3                   	ret

Disassembly of section .fini:
