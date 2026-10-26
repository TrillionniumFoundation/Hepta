
/tmp/hia-perf-diagnosis-9fe/rust.so:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .fini:

Disassembly of section .text:

00000000000129b0 <full_lifecycle>:
   129b0:	55                   	push   %rbp
   129b1:	41 57                	push   %r15
   129b3:	41 56                	push   %r14
   129b5:	53                   	push   %rbx
   129b6:	48 83 ec 38          	sub    $0x38,%rsp
   129ba:	48 85 ff             	test   %rdi,%rdi
   129bd:	74 72                	je     12a31 <full_lifecycle+0x81>
   129bf:	41 bf e9 03 00 00    	mov    $0x3e9,%r15d
   129c5:	0f 88 fb 01 00 00    	js     12bc6 <full_lifecycle+0x216>
   129cb:	48 89 fb             	mov    %rdi,%rbx
   129ce:	89 f5                	mov    %esi,%ebp
   129d0:	48 c7 44 24 28 00 00 	movq   $0x0,0x28(%rsp)
   129d7:	00 00 
   129d9:	48 8d 7c 24 08       	lea    0x8(%rsp),%rdi
   129de:	48 8d 4c 24 20       	lea    0x20(%rsp),%rcx
   129e3:	be 01 00 00 00       	mov    $0x1,%esi
   129e8:	48 89 da             	mov    %rbx,%rdx
   129eb:	e8 50 ff ff ff       	call   12940 <_ZN5alloc7raw_vec11finish_grow17h7bea7c01440f6ee8E>
   129f0:	83 7c 24 08 01       	cmpl   $0x1,0x8(%rsp)
   129f5:	0f 84 cb 01 00 00    	je     12bc6 <full_lifecycle+0x216>
   129fb:	4c 8b 74 24 10       	mov    0x10(%rsp),%r14
   12a00:	4c 89 f0             	mov    %r14,%rax
   12a03:	48 83 fb 01          	cmp    $0x1,%rbx
   12a07:	74 16                	je     12a1f <full_lifecycle+0x6f>
   12a09:	48 8d 53 ff          	lea    -0x1(%rbx),%rdx
   12a0d:	4c 89 f7             	mov    %r14,%rdi
   12a10:	31 f6                	xor    %esi,%esi
   12a12:	ff 15 40 df 03 00    	call   *0x3df40(%rip)        # 50958 <memset@GLIBC_2.2.5>
   12a18:	49 8d 04 1e          	lea    (%r14,%rbx,1),%rax
   12a1c:	48 ff c8             	dec    %rax
   12a1f:	c6 00 00             	movb   $0x0,(%rax)
   12a22:	48 83 fb 03          	cmp    $0x3,%rbx
   12a26:	77 11                	ja     12a39 <full_lifecycle+0x89>
   12a28:	31 c0                	xor    %eax,%eax
   12a2a:	89 e9                	mov    %ebp,%ecx
   12a2c:	e9 4b 01 00 00       	jmp    12b7c <full_lifecycle+0x1cc>
   12a31:	45 31 ff             	xor    %r15d,%r15d
   12a34:	e9 8d 01 00 00       	jmp    12bc6 <full_lifecycle+0x216>
   12a39:	48 ba f0 ff ff ff ff 	movabs $0x7ffffffffffffff0,%rdx
   12a40:	ff ff 7f 
   12a43:	89 e9                	mov    %ebp,%ecx
   12a45:	66 0f 6e c5          	movd   %ebp,%xmm0
   12a49:	48 83 fb 10          	cmp    $0x10,%rbx
   12a4d:	73 07                	jae    12a56 <full_lifecycle+0xa6>
   12a4f:	31 c0                	xor    %eax,%eax
   12a51:	e9 c2 00 00 00       	jmp    12b18 <full_lifecycle+0x168>
   12a56:	48 89 d8             	mov    %rbx,%rax
   12a59:	48 21 d0             	and    %rdx,%rax
   12a5c:	66 0f 70 c8 00       	pshufd $0x0,%xmm0,%xmm1
   12a61:	66 0f 6f 15 b7 21 ff 	movdqa -0xde49(%rip),%xmm2        # 4c20 <_ZN3std6thread7current7CURRENT17h069380daa18362bdE+0x4bd8>
   12a68:	ff 
   12a69:	66 0f 6f 1d bf 21 ff 	movdqa -0xde41(%rip),%xmm3        # 4c30 <_ZN3std6thread7current7CURRENT17h069380daa18362bdE+0x4be8>
   12a70:	ff 
   12a71:	66 0f 6f 25 d7 21 ff 	movdqa -0xde29(%rip),%xmm4        # 4c50 <_ZN3std6thread7current7CURRENT17h069380daa18362bdE+0x4c08>
   12a78:	ff 
   12a79:	66 0f 6f 2d 1f 22 ff 	movdqa -0xdde1(%rip),%xmm5        # 4ca0 <_ZN3std6thread7current7CURRENT17h069380daa18362bdE+0x4c58>
   12a80:	ff 
   12a81:	31 f6                	xor    %esi,%esi
   12a83:	66 0f 6f 35 55 23 ff 	movdqa -0xdcab(%rip),%xmm6        # 4de0 <_ZN3std6thread7current7CURRENT17h069380daa18362bdE+0x4d98>
   12a8a:	ff 
   12a8b:	66 0f 6f 3d fd 22 ff 	movdqa -0xdd03(%rip),%xmm7        # 4d90 <_ZN3std6thread7current7CURRENT17h069380daa18362bdE+0x4d48>
   12a92:	ff 
   12a93:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nopw 0x0(%rax,%rax,1)
   12a9a:	84 00 00 00 00 00 
   12aa0:	66 44 0f 6f c1       	movdqa %xmm1,%xmm8
   12aa5:	66 44 0f fe c2       	paddd  %xmm2,%xmm8
   12aaa:	66 44 0f 6f c9       	movdqa %xmm1,%xmm9
   12aaf:	66 44 0f fe cb       	paddd  %xmm3,%xmm9
   12ab4:	66 44 0f 6f d1       	movdqa %xmm1,%xmm10
   12ab9:	66 44 0f fe d4       	paddd  %xmm4,%xmm10
   12abe:	66 44 0f 6f d9       	movdqa %xmm1,%xmm11
   12ac3:	66 44 0f fe dd       	paddd  %xmm5,%xmm11
   12ac8:	66 44 0f db de       	pand   %xmm6,%xmm11
   12acd:	66 44 0f db d6       	pand   %xmm6,%xmm10
   12ad2:	66 45 0f 67 da       	packuswb %xmm10,%xmm11
   12ad7:	66 44 0f db ce       	pand   %xmm6,%xmm9
   12adc:	66 44 0f db c6       	pand   %xmm6,%xmm8
   12ae1:	66 45 0f 67 c8       	packuswb %xmm8,%xmm9
   12ae6:	66 45 0f 67 d9       	packuswb %xmm9,%xmm11
   12aeb:	f3 45 0f 7f 1c 36    	movdqu %xmm11,(%r14,%rsi,1)
   12af1:	48 83 c6 10          	add    $0x10,%rsi
   12af5:	66 0f fe ef          	paddd  %xmm7,%xmm5
   12af9:	66 0f fe e7          	paddd  %xmm7,%xmm4
   12afd:	66 0f fe df          	paddd  %xmm7,%xmm3
   12b01:	66 0f fe d7          	paddd  %xmm7,%xmm2
   12b05:	48 39 f0             	cmp    %rsi,%rax
   12b08:	75 96                	jne    12aa0 <full_lifecycle+0xf0>
   12b0a:	48 39 c3             	cmp    %rax,%rbx
   12b0d:	0f 84 80 00 00 00    	je     12b93 <full_lifecycle+0x1e3>
   12b13:	f6 c3 0c             	test   $0xc,%bl
   12b16:	74 64                	je     12b7c <full_lifecycle+0x1cc>
   12b18:	48 89 c6             	mov    %rax,%rsi
   12b1b:	48 83 c2 0c          	add    $0xc,%rdx
   12b1f:	48 89 d0             	mov    %rdx,%rax
   12b22:	66 0f 6e ce          	movd   %esi,%xmm1
   12b26:	66 0f 70 c9 00       	pshufd $0x0,%xmm1,%xmm1
   12b2b:	66 0f eb 0d 6d 21 ff 	por    -0xde93(%rip),%xmm1        # 4ca0 <_ZN3std6thread7current7CURRENT17h069380daa18362bdE+0x4c58>
   12b32:	ff 
   12b33:	48 21 d8             	and    %rbx,%rax
   12b36:	66 0f 70 c0 00       	pshufd $0x0,%xmm0,%xmm0
   12b3b:	66 0f 6f 15 9d 22 ff 	movdqa -0xdd63(%rip),%xmm2        # 4de0 <_ZN3std6thread7current7CURRENT17h069380daa18362bdE+0x4d98>
   12b42:	ff 
   12b43:	66 0f 6f 1d 65 21 ff 	movdqa -0xde9b(%rip),%xmm3        # 4cb0 <_ZN3std6thread7current7CURRENT17h069380daa18362bdE+0x4c68>
   12b4a:	ff 
   12b4b:	0f 1f 44 00 00       	nopl   0x0(%rax,%rax,1)
   12b50:	66 0f 6f e0          	movdqa %xmm0,%xmm4
   12b54:	66 0f fe e1          	paddd  %xmm1,%xmm4
   12b58:	66 0f db e2          	pand   %xmm2,%xmm4
   12b5c:	66 0f 67 e4          	packuswb %xmm4,%xmm4
   12b60:	66 0f 67 e4          	packuswb %xmm4,%xmm4
   12b64:	66 41 0f 7e 24 36    	movd   %xmm4,(%r14,%rsi,1)
   12b6a:	48 83 c6 04          	add    $0x4,%rsi
   12b6e:	66 0f fe cb          	paddd  %xmm3,%xmm1
   12b72:	48 39 f0             	cmp    %rsi,%rax
   12b75:	75 d9                	jne    12b50 <full_lifecycle+0x1a0>
   12b77:	48 39 c3             	cmp    %rax,%rbx
   12b7a:	74 17                	je     12b93 <full_lifecycle+0x1e3>
   12b7c:	89 c9                	mov    %ecx,%ecx
   12b7e:	66 90                	xchg   %ax,%ax
   12b80:	8d 14 01             	lea    (%rcx,%rax,1),%edx
   12b83:	41 88 14 06          	mov    %dl,(%r14,%rax,1)
   12b87:	48 8d 50 01          	lea    0x1(%rax),%rdx
   12b8b:	48 89 d0             	mov    %rdx,%rax
   12b8e:	48 39 d3             	cmp    %rdx,%rbx
   12b91:	75 ed                	jne    12b80 <full_lifecycle+0x1d0>
   12b93:	31 c0                	xor    %eax,%eax
   12b95:	45 31 ff             	xor    %r15d,%r15d
   12b98:	0f 1f 84 00 00 00 00 	nopl   0x0(%rax,%rax,1)
   12b9f:	00 
   12ba0:	4c 89 f9             	mov    %r15,%rcx
   12ba3:	45 0f b6 3c 06       	movzbl (%r14,%rax,1),%r15d
   12ba8:	49 01 cf             	add    %rcx,%r15
   12bab:	72 27                	jb     12bd4 <full_lifecycle+0x224>
   12bad:	48 ff c0             	inc    %rax
   12bb0:	48 39 c3             	cmp    %rax,%rbx
   12bb3:	75 eb                	jne    12ba0 <full_lifecycle+0x1f0>
   12bb5:	ba 01 00 00 00       	mov    $0x1,%edx
   12bba:	4c 89 f7             	mov    %r14,%rdi
   12bbd:	48 89 de             	mov    %rbx,%rsi
   12bc0:	ff 15 42 dd 03 00    	call   *0x3dd42(%rip)        # 50908 <_DYNAMIC+0x1f8>
   12bc6:	4c 89 f8             	mov    %r15,%rax
   12bc9:	48 83 c4 38          	add    $0x38,%rsp
   12bcd:	5b                   	pop    %rbx
   12bce:	41 5e                	pop    %r14
   12bd0:	41 5f                	pop    %r15
   12bd2:	5d                   	pop    %rbp
   12bd3:	c3                   	ret
   12bd4:	48 8d 3d 1d ba 03 00 	lea    0x3ba1d(%rip),%rdi        # 4e5f8 <__frame_dummy_init_array_entry+0x8>
   12bdb:	ff 15 7f dd 03 00    	call   *0x3dd7f(%rip)        # 50960 <_DYNAMIC+0x250>

Disassembly of section .plt:
