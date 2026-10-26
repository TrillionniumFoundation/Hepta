
/tmp/hia-perf-diagnosis-9fe/rust.so:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .fini:

Disassembly of section .text:

0000000000012bf0 <constructor_error>:
   12bf0:	55                   	push   %rbp
   12bf1:	41 56                	push   %r14
   12bf3:	53                   	push   %rbx
   12bf4:	48 83 ec 30          	sub    $0x30,%rsp
   12bf8:	41 be ea 03 00 00    	mov    $0x3ea,%r14d
   12bfe:	48 85 ff             	test   %rdi,%rdi
   12c01:	74 5c                	je     12c5f <constructor_error+0x6f>
   12c03:	41 be e9 03 00 00    	mov    $0x3e9,%r14d
   12c09:	78 54                	js     12c5f <constructor_error+0x6f>
   12c0b:	48 89 fb             	mov    %rdi,%rbx
   12c0e:	89 f5                	mov    %esi,%ebp
   12c10:	48 c7 44 24 20 00 00 	movq   $0x0,0x20(%rsp)
   12c17:	00 00 
   12c19:	48 89 e7             	mov    %rsp,%rdi
   12c1c:	48 8d 4c 24 18       	lea    0x18(%rsp),%rcx
   12c21:	be 01 00 00 00       	mov    $0x1,%esi
   12c26:	48 89 da             	mov    %rbx,%rdx
   12c29:	e8 12 fd ff ff       	call   12940 <_ZN5alloc7raw_vec11finish_grow17h7bea7c01440f6ee8E>
   12c2e:	83 3c 24 01          	cmpl   $0x1,(%rsp)
   12c32:	74 29                	je     12c5d <constructor_error+0x6d>
   12c34:	48 8b 7c 24 08       	mov    0x8(%rsp),%rdi
   12c39:	48 83 fb 01          	cmp    $0x1,%rbx
   12c3d:	48 8d 44 1f ff       	lea    -0x1(%rdi,%rbx,1),%rax
   12c42:	48 0f 44 c7          	cmove  %rdi,%rax
   12c46:	c6 00 00             	movb   $0x0,(%rax)
   12c49:	ba 01 00 00 00       	mov    $0x1,%edx
   12c4e:	48 89 de             	mov    %rbx,%rsi
   12c51:	ff 15 b1 dc 03 00    	call   *0x3dcb1(%rip)        # 50908 <_DYNAMIC+0x1f8>
   12c57:	41 be ea 03 00 00    	mov    $0x3ea,%r14d
   12c5d:	89 ee                	mov    %ebp,%esi
   12c5f:	89 f0                	mov    %esi,%eax
   12c61:	4c 01 f0             	add    %r14,%rax
   12c64:	48 83 c4 30          	add    $0x30,%rsp
   12c68:	5b                   	pop    %rbx
   12c69:	41 5e                	pop    %r14
   12c6b:	5d                   	pop    %rbp
   12c6c:	c3                   	ret

Disassembly of section .plt:
