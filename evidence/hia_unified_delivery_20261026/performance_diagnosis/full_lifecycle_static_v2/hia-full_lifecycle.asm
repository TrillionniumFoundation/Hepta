
/tmp/hia-perf-diagnosis-9fe/llvm-candidate.so:     file format elf64-x86-64


Disassembly of section .init:

Disassembly of section .plt:

Disassembly of section .plt.got:

Disassembly of section .text:

0000000000001140 <full_lifecycle>:
    1140:	55                   	push   %rbp
    1141:	41 56                	push   %r14
    1143:	53                   	push   %rbx
    1144:	48 85 ff             	test   %rdi,%rdi
    1147:	74 57                	je     11a0 <full_lifecycle+0x60>
    1149:	89 f5                	mov    %esi,%ebp
    114b:	48 89 fb             	mov    %rdi,%rbx
    114e:	78 2a                	js     117a <full_lifecycle+0x3a>
    1150:	bf 01 00 00 00       	mov    $0x1,%edi
    1155:	48 89 de             	mov    %rbx,%rsi
    1158:	e8 f3 fe ff ff       	call   1050 <calloc@plt>
    115d:	48 85 c0             	test   %rax,%rax
    1160:	74 18                	je     117a <full_lifecycle+0x3a>
    1162:	48 89 c7             	mov    %rax,%rdi
    1165:	b1 01                	mov    $0x1,%cl
    1167:	48 89 d8             	mov    %rbx,%rax
    116a:	f6 c1 01             	test   $0x1,%cl
    116d:	75 16                	jne    1185 <full_lifecycle+0x45>
    116f:	41 be e9 03 00 00    	mov    $0x3e9,%r14d
    1175:	e9 2c 01 00 00       	jmp    12a6 <full_lifecycle+0x166>
    117a:	31 ff                	xor    %edi,%edi
    117c:	31 c0                	xor    %eax,%eax
    117e:	31 c9                	xor    %ecx,%ecx
    1180:	f6 c1 01             	test   $0x1,%cl
    1183:	74 ea                	je     116f <full_lifecycle+0x2f>
    1185:	48 8d 4b ff          	lea    -0x1(%rbx),%rcx
    1189:	48 39 c8             	cmp    %rcx,%rax
    118c:	48 0f 42 c8          	cmovb  %rax,%rcx
    1190:	48 ff c1             	inc    %rcx
    1193:	48 83 f9 10          	cmp    $0x10,%rcx
    1197:	77 11                	ja     11aa <full_lifecycle+0x6a>
    1199:	31 c9                	xor    %ecx,%ecx
    119b:	e9 c7 00 00 00       	jmp    1267 <full_lifecycle+0x127>
    11a0:	31 ff                	xor    %edi,%edi
    11a2:	45 31 f6             	xor    %r14d,%r14d
    11a5:	e9 fc 00 00 00       	jmp    12a6 <full_lifecycle+0x166>
    11aa:	89 ca                	mov    %ecx,%edx
    11ac:	83 e2 0f             	and    $0xf,%edx
    11af:	be 10 00 00 00       	mov    $0x10,%esi
    11b4:	48 0f 45 f2          	cmovne %rdx,%rsi
    11b8:	48 29 f1             	sub    %rsi,%rcx
    11bb:	66 0f 6e c5          	movd   %ebp,%xmm0
    11bf:	66 0f 70 c0 00       	pshufd $0x0,%xmm0,%xmm0
    11c4:	66 0f 6f 0d 34 0e 00 	movdqa 0xe34(%rip),%xmm1        # 2000 <_fini+0xa28>
    11cb:	00 
    11cc:	66 0f 6f 15 3c 0e 00 	movdqa 0xe3c(%rip),%xmm2        # 2010 <_fini+0xa38>
    11d3:	00 
    11d4:	66 0f 6f 1d 44 0e 00 	movdqa 0xe44(%rip),%xmm3        # 2020 <_fini+0xa48>
    11db:	00 
    11dc:	66 0f 6f 25 4c 0e 00 	movdqa 0xe4c(%rip),%xmm4        # 2030 <_fini+0xa58>
    11e3:	00 
    11e4:	31 d2                	xor    %edx,%edx
    11e6:	66 0f 6f 2d 52 0e 00 	movdqa 0xe52(%rip),%xmm5        # 2040 <_fini+0xa68>
    11ed:	00 
    11ee:	66 0f 6f 35 5a 0e 00 	movdqa 0xe5a(%rip),%xmm6        # 2050 <_fini+0xa78>
    11f5:	00 
    11f6:	66 2e 0f 1f 84 00 00 	cs nopw 0x0(%rax,%rax,1)
    11fd:	00 00 00 
    1200:	66 0f 6f f8          	movdqa %xmm0,%xmm7
    1204:	66 0f fe f9          	paddd  %xmm1,%xmm7
    1208:	66 44 0f 6f c0       	movdqa %xmm0,%xmm8
    120d:	66 44 0f fe c2       	paddd  %xmm2,%xmm8
    1212:	66 44 0f 6f c8       	movdqa %xmm0,%xmm9
    1217:	66 44 0f fe cb       	paddd  %xmm3,%xmm9
    121c:	66 44 0f 6f d0       	movdqa %xmm0,%xmm10
    1221:	66 44 0f fe d4       	paddd  %xmm4,%xmm10
    1226:	66 44 0f db d5       	pand   %xmm5,%xmm10
    122b:	66 44 0f db cd       	pand   %xmm5,%xmm9
    1230:	66 45 0f 67 d1       	packuswb %xmm9,%xmm10
    1235:	66 44 0f db c5       	pand   %xmm5,%xmm8
    123a:	66 0f db fd          	pand   %xmm5,%xmm7
    123e:	66 44 0f 67 c7       	packuswb %xmm7,%xmm8
    1243:	66 45 0f 67 d0       	packuswb %xmm8,%xmm10
    1248:	f3 44 0f 7f 14 17    	movdqu %xmm10,(%rdi,%rdx,1)
    124e:	48 83 c2 10          	add    $0x10,%rdx
    1252:	66 0f fe e6          	paddd  %xmm6,%xmm4
    1256:	66 0f fe de          	paddd  %xmm6,%xmm3
    125a:	66 0f fe d6          	paddd  %xmm6,%xmm2
    125e:	66 0f fe ce          	paddd  %xmm6,%xmm1
    1262:	48 39 d1             	cmp    %rdx,%rcx
    1265:	75 99                	jne    1200 <full_lifecycle+0xc0>
    1267:	89 ea                	mov    %ebp,%edx
    1269:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    1270:	48 39 c8             	cmp    %rcx,%rax
    1273:	74 3e                	je     12b3 <full_lifecycle+0x173>
    1275:	8d 34 0a             	lea    (%rdx,%rcx,1),%esi
    1278:	40 88 34 0f          	mov    %sil,(%rdi,%rcx,1)
    127c:	48 ff c1             	inc    %rcx
    127f:	48 39 cb             	cmp    %rcx,%rbx
    1282:	75 ec                	jne    1270 <full_lifecycle+0x130>
    1284:	31 c9                	xor    %ecx,%ecx
    1286:	45 31 f6             	xor    %r14d,%r14d
    1289:	0f 1f 80 00 00 00 00 	nopl   0x0(%rax)
    1290:	48 39 c8             	cmp    %rcx,%rax
    1293:	74 1e                	je     12b3 <full_lifecycle+0x173>
    1295:	0f b6 14 0f          	movzbl (%rdi,%rcx,1),%edx
    1299:	49 01 d6             	add    %rdx,%r14
    129c:	72 15                	jb     12b3 <full_lifecycle+0x173>
    129e:	48 ff c1             	inc    %rcx
    12a1:	48 39 cb             	cmp    %rcx,%rbx
    12a4:	75 ea                	jne    1290 <full_lifecycle+0x150>
    12a6:	e8 85 fd ff ff       	call   1030 <free@plt>
    12ab:	4c 89 f0             	mov    %r14,%rax
    12ae:	5b                   	pop    %rbx
    12af:	41 5e                	pop    %r14
    12b1:	5d                   	pop    %rbp
    12b2:	c3                   	ret
    12b3:	e8 88 fd ff ff       	call   1040 <abort@plt>

Disassembly of section .fini:
