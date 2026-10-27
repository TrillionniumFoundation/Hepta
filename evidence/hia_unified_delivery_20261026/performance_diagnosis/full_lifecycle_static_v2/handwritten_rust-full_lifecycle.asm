
/tmp/hia-perf-diagnosis-9fe/handwritten_rust.so:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .fini:

Disassembly of section .text:

00000000000129a0 <full_lifecycle>:
   129a0:	55                   	push   %rbp
   129a1:	41 57                	push   %r15
   129a3:	41 56                	push   %r14
   129a5:	53                   	push   %rbx
   129a6:	48 83 ec 38          	sub    $0x38,%rsp
   129aa:	48 85 ff             	test   %rdi,%rdi
   129ad:	74 75                	je     12a24 <full_lifecycle+0x84>
   129af:	41 bf e9 03 00 00    	mov    $0x3e9,%r15d
   129b5:	0f 88 0b 02 00 00    	js     12bc6 <full_lifecycle+0x226>
   129bb:	48 89 fb             	mov    %rdi,%rbx
   129be:	89 f5                	mov    %esi,%ebp
   129c0:	48 c7 44 24 28 00 00 	movq   $0x0,0x28(%rsp)
   129c7:	00 00 
   129c9:	48 8d 7c 24 08       	lea    0x8(%rsp),%rdi
   129ce:	48 8d 4c 24 20       	lea    0x20(%rsp),%rcx
   129d3:	be 01 00 00 00       	mov    $0x1,%esi
   129d8:	48 89 da             	mov    %rbx,%rdx
   129db:	e8 50 ff ff ff       	call   12930 <_ZN5alloc7raw_vec11finish_grow17h7bea7c01440f6ee8E>
   129e0:	83 7c 24 08 01       	cmpl   $0x1,0x8(%rsp)
   129e5:	0f 84 db 01 00 00    	je     12bc6 <full_lifecycle+0x226>
   129eb:	4c 8b 74 24 10       	mov    0x10(%rsp),%r14
   129f0:	4c 89 f0             	mov    %r14,%rax
   129f3:	48 83 fb 01          	cmp    $0x1,%rbx
   129f7:	74 16                	je     12a0f <full_lifecycle+0x6f>
   129f9:	48 8d 53 ff          	lea    -0x1(%rbx),%rdx
   129fd:	4c 89 f7             	mov    %r14,%rdi
   12a00:	31 f6                	xor    %esi,%esi
   12a02:	ff 15 c0 df 03 00    	call   *0x3dfc0(%rip)        # 509c8 <memset@GLIBC_2.2.5>
   12a08:	49 8d 04 1e          	lea    (%r14,%rbx,1),%rax
   12a0c:	48 ff c8             	dec    %rax
   12a0f:	c6 00 00             	movb   $0x0,(%rax)
   12a12:	48 83 fb 04          	cmp    $0x4,%rbx
   12a16:	73 14                	jae    12a2c <full_lifecycle+0x8c>
   12a18:	31 c9                	xor    %ecx,%ecx
   12a1a:	4c 89 f2             	mov    %r14,%rdx
   12a1d:	89 e8                	mov    %ebp,%eax
   12a1f:	e9 4e 01 00 00       	jmp    12b72 <full_lifecycle+0x1d2>
   12a24:	45 31 ff             	xor    %r15d,%r15d
   12a27:	e9 9a 01 00 00       	jmp    12bc6 <full_lifecycle+0x226>
   12a2c:	48 ba f0 ff ff ff ff 	movabs $0x7ffffffffffffff0,%rdx
   12a33:	ff ff 7f 
   12a36:	89 e8                	mov    %ebp,%eax
   12a38:	66 0f 6e c5          	movd   %ebp,%xmm0
   12a3c:	48 83 fb 10          	cmp    $0x10,%rbx
   12a40:	73 07                	jae    12a49 <full_lifecycle+0xa9>
   12a42:	31 c9                	xor    %ecx,%ecx
   12a44:	e9 bf 00 00 00       	jmp    12b08 <full_lifecycle+0x168>
   12a49:	48 89 d9             	mov    %rbx,%rcx
   12a4c:	48 21 d1             	and    %rdx,%rcx
   12a4f:	66 0f 70 c8 00       	pshufd $0x0,%xmm0,%xmm1
   12a54:	66 0f 6f 15 94 21 ff 	movdqa -0xde6c(%rip),%xmm2        # 4bf0 <_ZN3std6thread7current7CURRENT17h069380daa18362bdE+0x4ba8>
   12a5b:	ff 
   12a5c:	66 0f 6f 1d 9c 21 ff 	movdqa -0xde64(%rip),%xmm3        # 4c00 <_ZN3std6thread7current7CURRENT17h069380daa18362bdE+0x4bb8>
   12a63:	ff 
   12a64:	66 0f 6f 25 b4 21 ff 	movdqa -0xde4c(%rip),%xmm4        # 4c20 <_ZN3std6thread7current7CURRENT17h069380daa18362bdE+0x4bd8>
   12a6b:	ff 
   12a6c:	66 0f 6f 2d fc 21 ff 	movdqa -0xde04(%rip),%xmm5        # 4c70 <_ZN3std6thread7current7CURRENT17h069380daa18362bdE+0x4c28>
   12a73:	ff 
   12a74:	31 f6                	xor    %esi,%esi
   12a76:	66 0f 6f 35 32 23 ff 	movdqa -0xdcce(%rip),%xmm6        # 4db0 <_ZN3std6thread7current7CURRENT17h069380daa18362bdE+0x4d68>
   12a7d:	ff 
   12a7e:	66 0f 6f 3d da 22 ff 	movdqa -0xdd26(%rip),%xmm7        # 4d60 <_ZN3std6thread7current7CURRENT17h069380daa18362bdE+0x4d18>
   12a85:	ff 
   12a86:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
   12a8d:	00 00 00 
   12a90:	66 44 0f 6f c1       	movdqa %xmm1,%xmm8
   12a95:	66 44 0f fe c2       	paddd  %xmm2,%xmm8
   12a9a:	66 44 0f 6f c9       	movdqa %xmm1,%xmm9
   12a9f:	66 44 0f fe cb       	paddd  %xmm3,%xmm9
   12aa4:	66 44 0f 6f d1       	movdqa %xmm1,%xmm10
   12aa9:	66 44 0f fe d4       	paddd  %xmm4,%xmm10
   12aae:	66 44 0f 6f d9       	movdqa %xmm1,%xmm11
   12ab3:	66 44 0f fe dd       	paddd  %xmm5,%xmm11
   12ab8:	66 44 0f db de       	pand   %xmm6,%xmm11
   12abd:	66 44 0f db d6       	pand   %xmm6,%xmm10
   12ac2:	66 45 0f 67 da       	packuswb %xmm10,%xmm11
   12ac7:	66 44 0f db ce       	pand   %xmm6,%xmm9
   12acc:	66 44 0f db c6       	pand   %xmm6,%xmm8
   12ad1:	66 45 0f 67 c8       	packuswb %xmm8,%xmm9
   12ad6:	66 45 0f 67 d9       	packuswb %xmm9,%xmm11
   12adb:	f3 45 0f 7f 1c 36    	movdqu %xmm11,(%r14,%rsi,1)
   12ae1:	48 83 c6 10          	add    $0x10,%rsi
   12ae5:	66 0f fe ef          	paddd  %xmm7,%xmm5
   12ae9:	66 0f fe e7          	paddd  %xmm7,%xmm4
   12aed:	66 0f fe df          	paddd  %xmm7,%xmm3
   12af1:	66 0f fe d7          	paddd  %xmm7,%xmm2
   12af5:	48 39 f1             	cmp    %rsi,%rcx
   12af8:	75 96                	jne    12a90 <full_lifecycle+0xf0>
   12afa:	48 39 cb             	cmp    %rcx,%rbx
   12afd:	0f 84 89 00 00 00    	je     12b8c <full_lifecycle+0x1ec>
   12b03:	f6 c3 0c             	test   $0xc,%bl
   12b06:	74 66                	je     12b6e <full_lifecycle+0x1ce>
   12b08:	48 89 ce             	mov    %rcx,%rsi
   12b0b:	48 83 c2 0c          	add    $0xc,%rdx
   12b0f:	48 89 d1             	mov    %rdx,%rcx
   12b12:	48 21 d9             	and    %rbx,%rcx
   12b15:	66 0f 6e ce          	movd   %esi,%xmm1
   12b19:	66 0f 70 c9 00       	pshufd $0x0,%xmm1,%xmm1
   12b1e:	66 0f eb 0d 4a 21 ff 	por    -0xdeb6(%rip),%xmm1        # 4c70 <_ZN3std6thread7current7CURRENT17h069380daa18362bdE+0x4c28>
   12b25:	ff 
   12b26:	49 8d 14 0e          	lea    (%r14,%rcx,1),%rdx
   12b2a:	66 0f 70 c0 00       	pshufd $0x0,%xmm0,%xmm0
   12b2f:	66 0f 6f 15 79 22 ff 	movdqa -0xdd87(%rip),%xmm2        # 4db0 <_ZN3std6thread7current7CURRENT17h069380daa18362bdE+0x4d68>
   12b36:	ff 
   12b37:	66 0f 6f 1d 41 21 ff 	movdqa -0xdebf(%rip),%xmm3        # 4c80 <_ZN3std6thread7current7CURRENT17h069380daa18362bdE+0x4c38>
   12b3e:	ff 
   12b3f:	90                   	nop
   12b40:	66 0f 6f e0          	movdqa %xmm0,%xmm4
   12b44:	66 0f fe e1          	paddd  %xmm1,%xmm4
   12b48:	66 0f db e2          	pand   %xmm2,%xmm4
   12b4c:	66 0f 67 e4          	packuswb %xmm4,%xmm4
   12b50:	66 0f 67 e4          	packuswb %xmm4,%xmm4
   12b54:	66 41 0f 7e 24 36    	movd   %xmm4,(%r14,%rsi,1)
   12b5a:	48 83 c6 04          	add    $0x4,%rsi
   12b5e:	66 0f fe cb          	paddd  %xmm3,%xmm1
   12b62:	48 39 f1             	cmp    %rsi,%rcx
   12b65:	75 d9                	jne    12b40 <full_lifecycle+0x1a0>
   12b67:	48 39 cb             	cmp    %rcx,%rbx
   12b6a:	75 06                	jne    12b72 <full_lifecycle+0x1d2>
   12b6c:	eb 1e                	jmp    12b8c <full_lifecycle+0x1ec>
   12b6e:	49 8d 14 0e          	lea    (%r14,%rcx,1),%rdx
   12b72:	49 8d 34 1e          	lea    (%r14,%rbx,1),%rsi
   12b76:	00 c8                	add    %cl,%al
   12b78:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
   12b7f:	00 
   12b80:	88 02                	mov    %al,(%rdx)
   12b82:	48 ff c2             	inc    %rdx
   12b85:	fe c0                	inc    %al
   12b87:	48 39 f2             	cmp    %rsi,%rdx
   12b8a:	75 f4                	jne    12b80 <full_lifecycle+0x1e0>
   12b8c:	45 31 ff             	xor    %r15d,%r15d
   12b8f:	31 c0                	xor    %eax,%eax
   12b91:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
   12b98:	0f 1f 84 00 00 00 00 
   12b9f:	00 
   12ba0:	4c 89 f9             	mov    %r15,%rcx
   12ba3:	45 0f b6 3c 06       	movzbl (%r14,%rax,1),%r15d
   12ba8:	49 01 cf             	add    %rcx,%r15
   12bab:	72 27                	jb     12bd4 <full_lifecycle+0x234>
   12bad:	48 ff c0             	inc    %rax
   12bb0:	48 39 c3             	cmp    %rax,%rbx
   12bb3:	75 eb                	jne    12ba0 <full_lifecycle+0x200>
   12bb5:	ba 01 00 00 00       	mov    $0x1,%edx
   12bba:	4c 89 f7             	mov    %r14,%rdi
   12bbd:	48 89 de             	mov    %rbx,%rsi
   12bc0:	ff 15 b2 dd 03 00    	call   *0x3ddb2(%rip)        # 50978 <_DYNAMIC+0x1f8>
   12bc6:	4c 89 f8             	mov    %r15,%rax
   12bc9:	48 83 c4 38          	add    $0x38,%rsp
   12bcd:	5b                   	pop    %rbx
   12bce:	41 5e                	pop    %r14
   12bd0:	41 5f                	pop    %r15
   12bd2:	5d                   	pop    %rbp
   12bd3:	c3                   	ret
   12bd4:	48 8d 3d bd ba 03 00 	lea    0x3babd(%rip),%rdi        # 4e698 <__frame_dummy_init_array_entry+0x8>
   12bdb:	ff 15 ef dd 03 00    	call   *0x3ddef(%rip)        # 509d0 <_DYNAMIC+0x250>

Disassembly of section .plt:
