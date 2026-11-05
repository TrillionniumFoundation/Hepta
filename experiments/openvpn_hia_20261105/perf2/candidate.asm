
/workspace/scratch/2719a9027f80/packet-perf2-candidate1/packet.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <ovpn_hia_packet_id_read>:
   0:	55                   	push   rbp
   1:	53                   	push   rbx
   2:	50                   	push   rax
   3:	b8 01 00 fe ff       	mov    eax,0xfffe0001
   8:	48 05 ff ff 01 00    	add    rax,0x1ffff
   e:	48 81 fe 01 00 01 00 	cmp    rsi,0x10001
  15:	73 6c                	jae    83 <ovpn_hia_packet_id_read+0x83>
  17:	49 ba 00 00 00 00 02 	movabs r10,0x200000000
  1e:	00 00 00 
  21:	48 85 f6             	test   rsi,rsi
  24:	41 0f 95 c1          	setne  r9b
  28:	48 85 ff             	test   rdi,rdi
  2b:	41 0f 94 c3          	sete   r11b
  2f:	45 84 cb             	test   r11b,r9b
  32:	75 1c                	jne    50 <ovpn_hia_packet_id_read+0x50>
  34:	49 bb 00 00 00 00 03 	movabs r11,0x300000000
  3b:	00 00 00 
  3e:	49 89 f1             	mov    r9,rsi
  41:	49 01 f9             	add    r9,rdi
  44:	73 14                	jae    5a <ovpn_hia_packet_id_read+0x5a>
  46:	4c 89 d8             	mov    rax,r11
  49:	48 83 c4 08          	add    rsp,0x8
  4d:	5b                   	pop    rbx
  4e:	5d                   	pop    rbp
  4f:	c3                   	ret
  50:	4c 89 d0             	mov    rax,r10
  53:	48 83 c4 08          	add    rsp,0x8
  57:	5b                   	pop    rbx
  58:	5d                   	pop    rbp
  59:	c3                   	ret
  5a:	48 81 f9 00 00 01 00 	cmp    rcx,0x10000
  61:	77 20                	ja     83 <ovpn_hia_packet_id_read+0x83>
  63:	48 85 c9             	test   rcx,rcx
  66:	0f 95 c3             	setne  bl
  69:	48 85 d2             	test   rdx,rdx
  6c:	40 0f 94 c5          	sete   bpl
  70:	4c 89 d0             	mov    rax,r10
  73:	40 84 dd             	test   bpl,bl
  76:	75 0b                	jne    83 <ovpn_hia_packet_id_read+0x83>
  78:	49 89 ca             	mov    r10,rcx
  7b:	4c 89 d8             	mov    rax,r11
  7e:	49 01 d2             	add    r10,rdx
  81:	73 07                	jae    8a <ovpn_hia_packet_id_read+0x8a>
  83:	48 83 c4 08          	add    rsp,0x8
  87:	5b                   	pop    rbx
  88:	5d                   	pop    rbp
  89:	c3                   	ret
  8a:	48 85 c9             	test   rcx,rcx
  8d:	0f 95 c0             	setne  al
  90:	48 85 f6             	test   rsi,rsi
  93:	41 0f 95 c3          	setne  r11b
  97:	49 39 d1             	cmp    r9,rdx
  9a:	41 0f 97 c1          	seta   r9b
  9e:	49 39 fa             	cmp    r10,rdi
  a1:	41 0f 97 c2          	seta   r10b
  a5:	45 20 ca             	and    r10b,r9b
  a8:	41 20 c2             	and    r10b,al
  ab:	45 84 da             	test   r10b,r11b
  ae:	0f 85 86 01 00 00    	jne    23a <ovpn_hia_packet_id_read+0x23a>
  b4:	48 83 f9 20          	cmp    rcx,0x20
  b8:	0f 94 c0             	sete   al
  bb:	41 83 f8 02          	cmp    r8d,0x2
  bf:	0f 92 c1             	setb   cl
  c2:	84 c8                	test   al,cl
  c4:	0f 84 81 01 00 00    	je     24b <ovpn_hia_packet_id_read+0x24b>
  ca:	48 8b 5a 10          	mov    rbx,QWORD PTR [rdx+0x10]
  ce:	48 89 f1             	mov    rcx,rsi
  d1:	48 29 d9             	sub    rcx,rbx
  d4:	0f 82 71 01 00 00    	jb     24b <ovpn_hia_packet_id_read+0x24b>
  da:	4c 8b 52 18          	mov    r10,QWORD PTR [rdx+0x18]
  de:	b8 01 00 fe ff       	mov    eax,0xfffe0001
  e3:	49 39 ca             	cmp    r10,rcx
  e6:	77 9b                	ja     83 <ovpn_hia_packet_id_read+0x83>
  e8:	66 0f ef c0          	pxor   xmm0,xmm0
  ec:	f3 0f 7f 02          	movdqu XMMWORD PTR [rdx],xmm0
  f0:	49 83 fa 04          	cmp    r10,0x4
  f4:	0f 82 5d 01 00 00    	jb     257 <ovpn_hia_packet_id_read+0x257>
  fa:	48 8d 43 03          	lea    rax,[rbx+0x3]
  fe:	48 39 f0             	cmp    rax,rsi
 101:	0f 83 59 01 00 00    	jae    260 <ovpn_hia_packet_id_read+0x260>
 107:	4c 8d 4a 13          	lea    r9,[rdx+0x13]
 10b:	66 0f 6e 04 1f       	movd   xmm0,DWORD PTR [rdi+rbx*1]
 110:	c7 42 04 00 00 00 00 	mov    DWORD PTR [rdx+0x4],0x0
 117:	66 0f ef c9          	pxor   xmm1,xmm1
 11b:	66 0f 60 c1          	punpcklbw xmm0,xmm1
 11f:	f2 0f 70 c0 1b       	pshuflw xmm0,xmm0,0x1b
 124:	66 0f 67 c0          	packuswb xmm0,xmm0
 128:	66 0f 7e 02          	movd   DWORD PTR [rdx],xmm0
 12c:	48 8d 43 04          	lea    rax,[rbx+0x4]
 130:	89 c1                	mov    ecx,eax
 132:	c1 e9 10             	shr    ecx,0x10
 135:	41 c6 41 04 00       	mov    BYTE PTR [r9+0x4],0x0
 13a:	41 c7 01 00 00 00 00 	mov    DWORD PTR [r9],0x0
 141:	88 4a 12             	mov    BYTE PTR [rdx+0x12],cl
 144:	88 62 11             	mov    BYTE PTR [rdx+0x11],ah
 147:	88 42 10             	mov    BYTE PTR [rdx+0x10],al
 14a:	49 8d 4a fc          	lea    rcx,[r10-0x4]
 14e:	48 89 c8             	mov    rax,rcx
 151:	48 c1 e8 38          	shr    rax,0x38
 155:	88 42 1f             	mov    BYTE PTR [rdx+0x1f],al
 158:	48 89 c8             	mov    rax,rcx
 15b:	48 c1 e8 30          	shr    rax,0x30
 15f:	88 42 1e             	mov    BYTE PTR [rdx+0x1e],al
 162:	48 89 c8             	mov    rax,rcx
 165:	48 c1 e8 28          	shr    rax,0x28
 169:	88 42 1d             	mov    BYTE PTR [rdx+0x1d],al
 16c:	48 89 c8             	mov    rax,rcx
 16f:	48 c1 e8 20          	shr    rax,0x20
 173:	88 42 1c             	mov    BYTE PTR [rdx+0x1c],al
 176:	89 c8                	mov    eax,ecx
 178:	c1 e8 18             	shr    eax,0x18
 17b:	88 42 1b             	mov    BYTE PTR [rdx+0x1b],al
 17e:	89 c8                	mov    eax,ecx
 180:	c1 e8 10             	shr    eax,0x10
 183:	88 42 1a             	mov    BYTE PTR [rdx+0x1a],al
 186:	88 6a 19             	mov    BYTE PTR [rdx+0x19],ch
 189:	88 4a 18             	mov    BYTE PTR [rdx+0x18],cl
 18c:	b8 01 00 00 00       	mov    eax,0x1
 191:	45 85 c0             	test   r8d,r8d
 194:	0f 84 e9 fe ff ff    	je     83 <ovpn_hia_packet_id_read+0x83>
 19a:	48 83 f9 04          	cmp    rcx,0x4
 19e:	0f 82 b3 00 00 00    	jb     257 <ovpn_hia_packet_id_read+0x257>
 1a4:	48 8d 4b 07          	lea    rcx,[rbx+0x7]
 1a8:	48 39 f1             	cmp    rcx,rsi
 1ab:	0f 83 af 00 00 00    	jae    260 <ovpn_hia_packet_id_read+0x260>
 1b1:	66 0f 6e 44 1f 04    	movd   xmm0,DWORD PTR [rdi+rbx*1+0x4]
 1b7:	c7 42 0c 00 00 00 00 	mov    DWORD PTR [rdx+0xc],0x0
 1be:	66 0f 60 c1          	punpcklbw xmm0,xmm1
 1c2:	f2 0f 70 c0 1b       	pshuflw xmm0,xmm0,0x1b
 1c7:	66 0f 67 c0          	packuswb xmm0,xmm0
 1cb:	66 0f 7e 42 08       	movd   DWORD PTR [rdx+0x8],xmm0
 1d0:	48 83 c3 08          	add    rbx,0x8
 1d4:	49 83 c2 f8          	add    r10,0xfffffffffffffff8
 1d8:	89 d9                	mov    ecx,ebx
 1da:	c1 e9 10             	shr    ecx,0x10
 1dd:	41 c6 41 04 00       	mov    BYTE PTR [r9+0x4],0x0
 1e2:	41 c7 01 00 00 00 00 	mov    DWORD PTR [r9],0x0
 1e9:	88 4a 12             	mov    BYTE PTR [rdx+0x12],cl
 1ec:	88 7a 11             	mov    BYTE PTR [rdx+0x11],bh
 1ef:	88 5a 10             	mov    BYTE PTR [rdx+0x10],bl
 1f2:	4c 89 d3             	mov    rbx,r10
 1f5:	4c 89 d1             	mov    rcx,r10
 1f8:	48 c1 e9 38          	shr    rcx,0x38
 1fc:	88 4a 1f             	mov    BYTE PTR [rdx+0x1f],cl
 1ff:	4c 89 d1             	mov    rcx,r10
 202:	48 c1 e9 30          	shr    rcx,0x30
 206:	88 4a 1e             	mov    BYTE PTR [rdx+0x1e],cl
 209:	4c 89 d1             	mov    rcx,r10
 20c:	48 c1 e9 28          	shr    rcx,0x28
 210:	88 4a 1d             	mov    BYTE PTR [rdx+0x1d],cl
 213:	4c 89 d1             	mov    rcx,r10
 216:	48 c1 e9 20          	shr    rcx,0x20
 21a:	88 4a 1c             	mov    BYTE PTR [rdx+0x1c],cl
 21d:	89 d9                	mov    ecx,ebx
 21f:	c1 e9 18             	shr    ecx,0x18
 222:	88 4a 1b             	mov    BYTE PTR [rdx+0x1b],cl
 225:	89 d9                	mov    ecx,ebx
 227:	c1 e9 10             	shr    ecx,0x10
 22a:	88 4a 1a             	mov    BYTE PTR [rdx+0x1a],cl
 22d:	88 7a 19             	mov    BYTE PTR [rdx+0x19],bh
 230:	88 5a 18             	mov    BYTE PTR [rdx+0x18],bl
 233:	48 83 c4 08          	add    rsp,0x8
 237:	5b                   	pop    rbx
 238:	5d                   	pop    rbp
 239:	c3                   	ret
 23a:	48 b8 00 00 00 00 04 	movabs rax,0x400000000
 241:	00 00 00 
 244:	48 83 c4 08          	add    rsp,0x8
 248:	5b                   	pop    rbx
 249:	5d                   	pop    rbp
 24a:	c3                   	ret
 24b:	b8 01 00 fe ff       	mov    eax,0xfffe0001
 250:	48 83 c4 08          	add    rsp,0x8
 254:	5b                   	pop    rbx
 255:	5d                   	pop    rbp
 256:	c3                   	ret
 257:	31 c0                	xor    eax,eax
 259:	48 83 c4 08          	add    rsp,0x8
 25d:	5b                   	pop    rbx
 25e:	5d                   	pop    rbp
 25f:	c3                   	ret
 260:	e8 00 00 00 00       	call   265 <ovpn_hia_packet_id_read+0x265>
			261: R_X86_64_PLT32	abort-0x4
 265:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
 26c:	00 00 00 00 

0000000000000270 <ovpn_hia_packet_id_write>:
 270:	55                   	push   rbp
 271:	41 57                	push   r15
 273:	41 56                	push   r14
 275:	41 55                	push   r13
 277:	41 54                	push   r12
 279:	53                   	push   rbx
 27a:	50                   	push   rax
 27b:	b8 01 00 fe ff       	mov    eax,0xfffe0001
 280:	48 05 ff ff 01 00    	add    rax,0x1ffff
 286:	48 81 fe 01 00 01 00 	cmp    rsi,0x10001
 28d:	73 39                	jae    2c8 <ovpn_hia_packet_id_write+0x58>
 28f:	49 89 f7             	mov    r15,rsi
 292:	49 bb 00 00 00 00 02 	movabs r11,0x200000000
 299:	00 00 00 
 29c:	48 85 f6             	test   rsi,rsi
 29f:	41 0f 95 c2          	setne  r10b
 2a3:	48 85 ff             	test   rdi,rdi
 2a6:	0f 94 c3             	sete   bl
 2a9:	44 84 d3             	test   bl,r10b
 2ac:	75 17                	jne    2c5 <ovpn_hia_packet_id_write+0x55>
 2ae:	48 bb 00 00 00 00 03 	movabs rbx,0x300000000
 2b5:	00 00 00 
 2b8:	4d 89 fa             	mov    r10,r15
 2bb:	49 01 fa             	add    r10,rdi
 2be:	73 17                	jae    2d7 <ovpn_hia_packet_id_write+0x67>
 2c0:	48 89 d8             	mov    rax,rbx
 2c3:	eb 03                	jmp    2c8 <ovpn_hia_packet_id_write+0x58>
 2c5:	4c 89 d8             	mov    rax,r11
 2c8:	48 83 c4 08          	add    rsp,0x8
 2cc:	5b                   	pop    rbx
 2cd:	41 5c                	pop    r12
 2cf:	41 5d                	pop    r13
 2d1:	41 5e                	pop    r14
 2d3:	41 5f                	pop    r15
 2d5:	5d                   	pop    rbp
 2d6:	c3                   	ret
 2d7:	48 81 f9 00 00 01 00 	cmp    rcx,0x10000
 2de:	77 e8                	ja     2c8 <ovpn_hia_packet_id_write+0x58>
 2e0:	48 85 c9             	test   rcx,rcx
 2e3:	40 0f 95 c5          	setne  bpl
 2e7:	48 85 d2             	test   rdx,rdx
 2ea:	41 0f 94 c6          	sete   r14b
 2ee:	4c 89 d8             	mov    rax,r11
 2f1:	41 84 ee             	test   r14b,bpl
 2f4:	75 d2                	jne    2c8 <ovpn_hia_packet_id_write+0x58>
 2f6:	49 89 cb             	mov    r11,rcx
 2f9:	48 89 d8             	mov    rax,rbx
 2fc:	49 01 d3             	add    r11,rdx
 2ff:	72 c7                	jb     2c8 <ovpn_hia_packet_id_write+0x58>
 301:	48 85 c9             	test   rcx,rcx
 304:	0f 95 c0             	setne  al
 307:	4d 85 ff             	test   r15,r15
 30a:	0f 95 c3             	setne  bl
 30d:	49 39 d2             	cmp    r10,rdx
 310:	41 0f 97 c2          	seta   r10b
 314:	49 39 fb             	cmp    r11,rdi
 317:	41 0f 97 c3          	seta   r11b
 31b:	45 20 d3             	and    r11b,r10b
 31e:	41 20 c3             	and    r11b,al
 321:	41 84 db             	test   r11b,bl
 324:	75 70                	jne    396 <ovpn_hia_packet_id_write+0x126>
 326:	44 8b 64 24 40       	mov    r12d,DWORD PTR [rsp+0x40]
 32b:	48 83 f9 20          	cmp    rcx,0x20
 32f:	0f 94 c0             	sete   al
 332:	44 89 e1             	mov    ecx,r12d
 335:	44 09 c9             	or     ecx,r9d
 338:	83 f9 02             	cmp    ecx,0x2
 33b:	0f 92 c1             	setb   cl
 33e:	84 c8                	test   al,cl
 340:	74 63                	je     3a5 <ovpn_hia_packet_id_write+0x135>
 342:	4c 8b 52 10          	mov    r10,QWORD PTR [rdx+0x10]
 346:	4d 89 fb             	mov    r11,r15
 349:	4d 29 d3             	sub    r11,r10
 34c:	72 57                	jb     3a5 <ovpn_hia_packet_id_write+0x135>
 34e:	48 8b 4a 18          	mov    rcx,QWORD PTR [rdx+0x18]
 352:	b8 01 00 fe ff       	mov    eax,0xfffe0001
 357:	4c 39 d9             	cmp    rcx,r11
 35a:	0f 87 68 ff ff ff    	ja     2c8 <ovpn_hia_packet_id_write+0x58>
 360:	48 8b 42 08          	mov    rax,QWORD PTR [rdx+0x8]
 364:	48 85 c0             	test   rax,rax
 367:	49 0f 44 c0          	cmove  rax,r8
 36b:	4c 8b 1a             	mov    r11,QWORD PTR [rdx]
 36e:	48 89 42 08          	mov    QWORD PTR [rdx+0x8],rax
 372:	45 85 c9             	test   r9d,r9d
 375:	40 0f 95 c5          	setne  bpl
 379:	49 39 c0             	cmp    r8,rax
 37c:	41 0f 9f c6          	setg   r14b
 380:	bb ff ff ff ff       	mov    ebx,0xffffffff
 385:	49 39 db             	cmp    r11,rbx
 388:	75 25                	jne    3af <ovpn_hia_packet_id_write+0x13f>
 38a:	44 20 f5             	and    bpl,r14b
 38d:	75 20                	jne    3af <ovpn_hia_packet_id_write+0x13f>
 38f:	31 c0                	xor    eax,eax
 391:	e9 32 ff ff ff       	jmp    2c8 <ovpn_hia_packet_id_write+0x58>
 396:	48 b8 00 00 00 00 04 	movabs rax,0x400000000
 39d:	00 00 00 
 3a0:	e9 23 ff ff ff       	jmp    2c8 <ovpn_hia_packet_id_write+0x58>
 3a5:	b8 01 00 fe ff       	mov    eax,0xfffe0001
 3aa:	e9 19 ff ff ff       	jmp    2c8 <ovpn_hia_packet_id_write+0x58>
 3af:	4d 8d 73 01          	lea    r14,[r11+0x1]
 3b3:	49 39 db             	cmp    r11,rbx
 3b6:	4c 0f 45 c0          	cmovne r8,rax
 3ba:	b8 01 00 00 00       	mov    eax,0x1
 3bf:	49 0f 45 c6          	cmovne rax,r14
 3c3:	49 89 c3             	mov    r11,rax
 3c6:	49 c1 eb 38          	shr    r11,0x38
 3ca:	44 88 5a 07          	mov    BYTE PTR [rdx+0x7],r11b
 3ce:	49 89 c3             	mov    r11,rax
 3d1:	49 c1 eb 30          	shr    r11,0x30
 3d5:	44 88 5a 06          	mov    BYTE PTR [rdx+0x6],r11b
 3d9:	49 89 c3             	mov    r11,rax
 3dc:	49 c1 eb 28          	shr    r11,0x28
 3e0:	44 88 5a 05          	mov    BYTE PTR [rdx+0x5],r11b
 3e4:	49 89 c3             	mov    r11,rax
 3e7:	49 c1 eb 20          	shr    r11,0x20
 3eb:	44 88 5a 04          	mov    BYTE PTR [rdx+0x4],r11b
 3ef:	89 c6                	mov    esi,eax
 3f1:	c1 ee 18             	shr    esi,0x18
 3f4:	40 88 72 03          	mov    BYTE PTR [rdx+0x3],sil
 3f8:	41 89 c3             	mov    r11d,eax
 3fb:	41 c1 eb 10          	shr    r11d,0x10
 3ff:	44 88 5a 02          	mov    BYTE PTR [rdx+0x2],r11b
 403:	89 c5                	mov    ebp,eax
 405:	c1 ed 08             	shr    ebp,0x8
 408:	40 88 6a 01          	mov    BYTE PTR [rdx+0x1],bpl
 40c:	88 02                	mov    BYTE PTR [rdx],al
 40e:	4d 89 c6             	mov    r14,r8
 411:	49 c1 ee 38          	shr    r14,0x38
 415:	44 88 72 0f          	mov    BYTE PTR [rdx+0xf],r14b
 419:	4d 89 c6             	mov    r14,r8
 41c:	49 c1 ee 30          	shr    r14,0x30
 420:	44 88 72 0e          	mov    BYTE PTR [rdx+0xe],r14b
 424:	4d 89 c6             	mov    r14,r8
 427:	49 c1 ee 28          	shr    r14,0x28
 42b:	44 88 72 0d          	mov    BYTE PTR [rdx+0xd],r14b
 42f:	4d 89 c6             	mov    r14,r8
 432:	49 c1 ee 20          	shr    r14,0x20
 436:	44 88 72 0c          	mov    BYTE PTR [rdx+0xc],r14b
 43a:	45 89 c6             	mov    r14d,r8d
 43d:	41 c1 ee 18          	shr    r14d,0x18
 441:	44 88 72 0b          	mov    BYTE PTR [rdx+0xb],r14b
 445:	44 89 c3             	mov    ebx,r8d
 448:	c1 eb 10             	shr    ebx,0x10
 44b:	88 5a 0a             	mov    BYTE PTR [rdx+0xa],bl
 44e:	45 89 c5             	mov    r13d,r8d
 451:	41 c1 ed 08          	shr    r13d,0x8
 455:	44 88 6a 09          	mov    BYTE PTR [rdx+0x9],r13b
 459:	44 88 42 08          	mov    BYTE PTR [rdx+0x8],r8b
 45d:	45 85 e4             	test   r12d,r12d
 460:	0f 84 f6 00 00 00    	je     55c <ovpn_hia_packet_id_write+0x2ec>
 466:	4c 8d 62 12          	lea    r12,[rdx+0x12]
 46a:	45 85 c9             	test   r9d,r9d
 46d:	0f 84 9a 00 00 00    	je     50d <ovpn_hia_packet_id_write+0x29d>
 473:	49 83 fa 04          	cmp    r10,0x4
 477:	0f 82 12 ff ff ff    	jb     38f <ovpn_hia_packet_id_write+0x11f>
 47d:	41 89 f1             	mov    r9d,esi
 480:	49 8d 72 ff          	lea    rsi,[r10-0x1]
 484:	4c 39 fe             	cmp    rsi,r15
 487:	0f 83 a2 01 00 00    	jae    62f <ovpn_hia_packet_id_write+0x3bf>
 48d:	46 88 44 17 ff       	mov    BYTE PTR [rdi+r10*1-0x1],r8b
 492:	46 88 6c 17 fe       	mov    BYTE PTR [rdi+r10*1-0x2],r13b
 497:	42 88 5c 17 fd       	mov    BYTE PTR [rdi+r10*1-0x3],bl
 49c:	46 88 74 17 fc       	mov    BYTE PTR [rdi+r10*1-0x4],r14b
 4a1:	49 8d 5a fc          	lea    rbx,[r10-0x4]
 4a5:	48 83 c1 04          	add    rcx,0x4
 4a9:	66 41 c7 44 24 04 00 	mov    WORD PTR [r12+0x4],0x0
 4b0:	00 
 4b1:	41 c7 04 24 00 00 00 	mov    DWORD PTR [r12],0x0
 4b8:	00 
 4b9:	88 7a 11             	mov    BYTE PTR [rdx+0x11],bh
 4bc:	88 5a 10             	mov    BYTE PTR [rdx+0x10],bl
 4bf:	49 89 c8             	mov    r8,rcx
 4c2:	49 c1 e8 38          	shr    r8,0x38
 4c6:	44 88 42 1f          	mov    BYTE PTR [rdx+0x1f],r8b
 4ca:	49 89 c8             	mov    r8,rcx
 4cd:	49 c1 e8 30          	shr    r8,0x30
 4d1:	44 88 42 1e          	mov    BYTE PTR [rdx+0x1e],r8b
 4d5:	49 89 c8             	mov    r8,rcx
 4d8:	49 c1 e8 28          	shr    r8,0x28
 4dc:	44 88 42 1d          	mov    BYTE PTR [rdx+0x1d],r8b
 4e0:	49 89 c8             	mov    r8,rcx
 4e3:	49 c1 e8 20          	shr    r8,0x20
 4e7:	44 88 42 1c          	mov    BYTE PTR [rdx+0x1c],r8b
 4eb:	41 89 c8             	mov    r8d,ecx
 4ee:	41 c1 e8 18          	shr    r8d,0x18
 4f2:	44 88 42 1b          	mov    BYTE PTR [rdx+0x1b],r8b
 4f6:	41 89 c8             	mov    r8d,ecx
 4f9:	41 c1 e8 10          	shr    r8d,0x10
 4fd:	44 88 42 1a          	mov    BYTE PTR [rdx+0x1a],r8b
 501:	88 6a 19             	mov    BYTE PTR [rdx+0x19],ch
 504:	88 4a 18             	mov    BYTE PTR [rdx+0x18],cl
 507:	49 89 da             	mov    r10,rbx
 50a:	44 89 ce             	mov    esi,r9d
 50d:	49 83 fa 03          	cmp    r10,0x3
 511:	0f 86 78 fe ff ff    	jbe    38f <ovpn_hia_packet_id_write+0x11f>
 517:	41 89 f0             	mov    r8d,esi
 51a:	49 8d 72 ff          	lea    rsi,[r10-0x1]
 51e:	4c 39 fe             	cmp    rsi,r15
 521:	0f 83 08 01 00 00    	jae    62f <ovpn_hia_packet_id_write+0x3bf>
 527:	49 8d 72 fc          	lea    rsi,[r10-0x4]
 52b:	48 83 c1 04          	add    rcx,0x4
 52f:	42 88 44 17 ff       	mov    BYTE PTR [rdi+r10*1-0x1],al
 534:	42 88 6c 17 fe       	mov    BYTE PTR [rdi+r10*1-0x2],bpl
 539:	46 88 5c 17 fd       	mov    BYTE PTR [rdi+r10*1-0x3],r11b
 53e:	46 88 44 17 fc       	mov    BYTE PTR [rdi+r10*1-0x4],r8b
 543:	66 41 c7 44 24 04 00 	mov    WORD PTR [r12+0x4],0x0
 54a:	00 
 54b:	41 c7 04 24 00 00 00 	mov    DWORD PTR [r12],0x0
 552:	00 
 553:	66 89 72 10          	mov    WORD PTR [rdx+0x10],si
 557:	e9 c5 00 00 00       	jmp    621 <ovpn_hia_packet_id_write+0x3b1>
 55c:	89 74 24 04          	mov    DWORD PTR [rsp+0x4],esi
 560:	4e 8d 24 11          	lea    r12,[rcx+r10*1]
 564:	4c 89 fe             	mov    rsi,r15
 567:	4c 29 e6             	sub    rsi,r12
 56a:	48 83 fe 04          	cmp    rsi,0x4
 56e:	0f 82 1b fe ff ff    	jb     38f <ovpn_hia_packet_id_write+0x11f>
 574:	45 89 e4             	mov    r12d,r12d
 577:	49 8d 74 24 03       	lea    rsi,[r12+0x3]
 57c:	4c 39 fe             	cmp    rsi,r15
 57f:	0f 83 aa 00 00 00    	jae    62f <ovpn_hia_packet_id_write+0x3bf>
 585:	42 88 44 27 03       	mov    BYTE PTR [rdi+r12*1+0x3],al
 58a:	42 88 6c 27 02       	mov    BYTE PTR [rdi+r12*1+0x2],bpl
 58f:	46 88 5c 27 01       	mov    BYTE PTR [rdi+r12*1+0x1],r11b
 594:	8b 44 24 04          	mov    eax,DWORD PTR [rsp+0x4]
 598:	42 88 04 27          	mov    BYTE PTR [rdi+r12*1],al
 59c:	48 8d 41 04          	lea    rax,[rcx+0x4]
 5a0:	49 89 c3             	mov    r11,rax
 5a3:	49 c1 eb 38          	shr    r11,0x38
 5a7:	44 88 5a 1f          	mov    BYTE PTR [rdx+0x1f],r11b
 5ab:	49 89 c3             	mov    r11,rax
 5ae:	49 c1 eb 30          	shr    r11,0x30
 5b2:	44 88 5a 1e          	mov    BYTE PTR [rdx+0x1e],r11b
 5b6:	49 89 c3             	mov    r11,rax
 5b9:	49 c1 eb 28          	shr    r11,0x28
 5bd:	44 88 5a 1d          	mov    BYTE PTR [rdx+0x1d],r11b
 5c1:	49 89 c3             	mov    r11,rax
 5c4:	49 c1 eb 20          	shr    r11,0x20
 5c8:	44 88 5a 1c          	mov    BYTE PTR [rdx+0x1c],r11b
 5cc:	41 89 c3             	mov    r11d,eax
 5cf:	41 c1 eb 18          	shr    r11d,0x18
 5d3:	44 88 5a 1b          	mov    BYTE PTR [rdx+0x1b],r11b
 5d7:	41 89 c3             	mov    r11d,eax
 5da:	41 c1 eb 10          	shr    r11d,0x10
 5de:	44 88 5a 1a          	mov    BYTE PTR [rdx+0x1a],r11b
 5e2:	88 62 19             	mov    BYTE PTR [rdx+0x19],ah
 5e5:	88 42 18             	mov    BYTE PTR [rdx+0x18],al
 5e8:	45 85 c9             	test   r9d,r9d
 5eb:	74 38                	je     625 <ovpn_hia_packet_id_write+0x3b5>
 5ed:	4c 01 d0             	add    rax,r10
 5f0:	4c 89 fe             	mov    rsi,r15
 5f3:	48 29 c6             	sub    rsi,rax
 5f6:	48 83 fe 04          	cmp    rsi,0x4
 5fa:	0f 82 8f fd ff ff    	jb     38f <ovpn_hia_packet_id_write+0x11f>
 600:	89 c0                	mov    eax,eax
 602:	48 8d 70 03          	lea    rsi,[rax+0x3]
 606:	4c 39 fe             	cmp    rsi,r15
 609:	73 24                	jae    62f <ovpn_hia_packet_id_write+0x3bf>
 60b:	44 88 44 07 03       	mov    BYTE PTR [rdi+rax*1+0x3],r8b
 610:	44 88 6c 07 02       	mov    BYTE PTR [rdi+rax*1+0x2],r13b
 615:	88 5c 07 01          	mov    BYTE PTR [rdi+rax*1+0x1],bl
 619:	44 88 34 07          	mov    BYTE PTR [rdi+rax*1],r14b
 61d:	48 83 c1 08          	add    rcx,0x8
 621:	48 89 4a 18          	mov    QWORD PTR [rdx+0x18],rcx
 625:	b8 01 00 00 00       	mov    eax,0x1
 62a:	e9 99 fc ff ff       	jmp    2c8 <ovpn_hia_packet_id_write+0x58>
 62f:	e8 00 00 00 00       	call   634 <ovpn_hia_packet_id_write+0x3c4>
			630: R_X86_64_PLT32	abort-0x4
 634:	66 66 66 2e 0f 1f 84 	data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
 63b:	00 00 00 00 00 

0000000000000640 <ovpn_hia_packet_id_read_epoch>:
 640:	53                   	push   rbx
 641:	b8 01 00 fe ff       	mov    eax,0xfffe0001
 646:	48 05 ff ff 01 00    	add    rax,0x1ffff
 64c:	48 81 fe 01 00 01 00 	cmp    rsi,0x10001
 653:	73 62                	jae    6b7 <ovpn_hia_packet_id_read_epoch+0x77>
 655:	49 b9 00 00 00 00 02 	movabs r9,0x200000000
 65c:	00 00 00 
 65f:	48 85 f6             	test   rsi,rsi
 662:	41 0f 95 c0          	setne  r8b
 666:	48 85 ff             	test   rdi,rdi
 669:	41 0f 94 c2          	sete   r10b
 66d:	45 84 c2             	test   r10b,r8b
 670:	75 17                	jne    689 <ovpn_hia_packet_id_read_epoch+0x49>
 672:	49 ba 00 00 00 00 03 	movabs r10,0x300000000
 679:	00 00 00 
 67c:	49 89 f0             	mov    r8,rsi
 67f:	49 01 f8             	add    r8,rdi
 682:	73 0a                	jae    68e <ovpn_hia_packet_id_read_epoch+0x4e>
 684:	4c 89 d0             	mov    rax,r10
 687:	5b                   	pop    rbx
 688:	c3                   	ret
 689:	4c 89 c8             	mov    rax,r9
 68c:	5b                   	pop    rbx
 68d:	c3                   	ret
 68e:	48 81 f9 00 00 01 00 	cmp    rcx,0x10000
 695:	77 20                	ja     6b7 <ovpn_hia_packet_id_read_epoch+0x77>
 697:	48 85 c9             	test   rcx,rcx
 69a:	41 0f 95 c3          	setne  r11b
 69e:	48 85 d2             	test   rdx,rdx
 6a1:	0f 94 c3             	sete   bl
 6a4:	4c 89 c8             	mov    rax,r9
 6a7:	44 84 db             	test   bl,r11b
 6aa:	75 0b                	jne    6b7 <ovpn_hia_packet_id_read_epoch+0x77>
 6ac:	49 89 c9             	mov    r9,rcx
 6af:	4c 89 d0             	mov    rax,r10
 6b2:	49 01 d1             	add    r9,rdx
 6b5:	73 02                	jae    6b9 <ovpn_hia_packet_id_read_epoch+0x79>
 6b7:	5b                   	pop    rbx
 6b8:	c3                   	ret
 6b9:	48 85 c9             	test   rcx,rcx
 6bc:	0f 95 c0             	setne  al
 6bf:	48 85 f6             	test   rsi,rsi
 6c2:	41 0f 95 c2          	setne  r10b
 6c6:	49 39 d0             	cmp    r8,rdx
 6c9:	41 0f 97 c0          	seta   r8b
 6cd:	49 39 f9             	cmp    r9,rdi
 6d0:	41 0f 97 c1          	seta   r9b
 6d4:	45 20 c1             	and    r9b,r8b
 6d7:	41 20 c1             	and    r9b,al
 6da:	45 84 d1             	test   r9b,r10b
 6dd:	0f 85 e6 00 00 00    	jne    7c9 <ovpn_hia_packet_id_read_epoch+0x189>
 6e3:	48 83 f9 20          	cmp    rcx,0x20
 6e7:	0f 85 e8 00 00 00    	jne    7d5 <ovpn_hia_packet_id_read_epoch+0x195>
 6ed:	48 8b 5a 10          	mov    rbx,QWORD PTR [rdx+0x10]
 6f1:	49 89 f0             	mov    r8,rsi
 6f4:	49 29 d8             	sub    r8,rbx
 6f7:	0f 82 d8 00 00 00    	jb     7d5 <ovpn_hia_packet_id_read_epoch+0x195>
 6fd:	48 8b 4a 18          	mov    rcx,QWORD PTR [rdx+0x18]
 701:	b8 01 00 fe ff       	mov    eax,0xfffe0001
 706:	4c 39 c1             	cmp    rcx,r8
 709:	77 ac                	ja     6b7 <ovpn_hia_packet_id_read_epoch+0x77>
 70b:	48 83 f9 08          	cmp    rcx,0x8
 70f:	0f 82 c7 00 00 00    	jb     7dc <ovpn_hia_packet_id_read_epoch+0x19c>
 715:	48 8d 43 07          	lea    rax,[rbx+0x7]
 719:	48 39 f0             	cmp    rax,rsi
 71c:	0f 83 be 00 00 00    	jae    7e0 <ovpn_hia_packet_id_read_epoch+0x1a0>
 722:	48 8d 72 13          	lea    rsi,[rdx+0x13]
 726:	0f b7 04 1f          	movzx  eax,WORD PTR [rdi+rbx*1]
 72a:	44 0f b7 44 1f 02    	movzx  r8d,WORD PTR [rdi+rbx*1+0x2]
 730:	66 41 c1 c0 08       	rol    r8w,0x8
 735:	66 c1 c0 08          	rol    ax,0x8
 739:	0f b7 c0             	movzx  eax,ax
 73c:	66 0f 6e 44 1f 04    	movd   xmm0,DWORD PTR [rdi+rbx*1+0x4]
 742:	66 c7 42 06 00 00    	mov    WORD PTR [rdx+0x6],0x0
 748:	66 44 89 42 04       	mov    WORD PTR [rdx+0x4],r8w
 74d:	66 0f ef c9          	pxor   xmm1,xmm1
 751:	66 0f 60 c1          	punpcklbw xmm0,xmm1
 755:	f2 0f 70 c0 1b       	pshuflw xmm0,xmm0,0x1b
 75a:	66 0f 67 c0          	packuswb xmm0,xmm0
 75e:	66 0f 7e 02          	movd   DWORD PTR [rdx],xmm0
 762:	48 83 c3 08          	add    rbx,0x8
 766:	48 83 c1 f8          	add    rcx,0xfffffffffffffff8
 76a:	89 df                	mov    edi,ebx
 76c:	c1 ef 10             	shr    edi,0x10
 76f:	c6 46 04 00          	mov    BYTE PTR [rsi+0x4],0x0
 773:	c7 06 00 00 00 00    	mov    DWORD PTR [rsi],0x0
 779:	40 88 7a 12          	mov    BYTE PTR [rdx+0x12],dil
 77d:	88 7a 11             	mov    BYTE PTR [rdx+0x11],bh
 780:	88 5a 10             	mov    BYTE PTR [rdx+0x10],bl
 783:	48 89 ce             	mov    rsi,rcx
 786:	48 c1 ee 38          	shr    rsi,0x38
 78a:	40 88 72 1f          	mov    BYTE PTR [rdx+0x1f],sil
 78e:	48 89 ce             	mov    rsi,rcx
 791:	48 c1 ee 30          	shr    rsi,0x30
 795:	40 88 72 1e          	mov    BYTE PTR [rdx+0x1e],sil
 799:	48 89 ce             	mov    rsi,rcx
 79c:	48 c1 ee 28          	shr    rsi,0x28
 7a0:	40 88 72 1d          	mov    BYTE PTR [rdx+0x1d],sil
 7a4:	48 89 ce             	mov    rsi,rcx
 7a7:	48 c1 ee 20          	shr    rsi,0x20
 7ab:	40 88 72 1c          	mov    BYTE PTR [rdx+0x1c],sil
 7af:	89 ce                	mov    esi,ecx
 7b1:	c1 ee 18             	shr    esi,0x18
 7b4:	40 88 72 1b          	mov    BYTE PTR [rdx+0x1b],sil
 7b8:	89 ce                	mov    esi,ecx
 7ba:	c1 ee 10             	shr    esi,0x10
 7bd:	40 88 72 1a          	mov    BYTE PTR [rdx+0x1a],sil
 7c1:	88 6a 19             	mov    BYTE PTR [rdx+0x19],ch
 7c4:	88 4a 18             	mov    BYTE PTR [rdx+0x18],cl
 7c7:	5b                   	pop    rbx
 7c8:	c3                   	ret
 7c9:	48 b8 00 00 00 00 04 	movabs rax,0x400000000
 7d0:	00 00 00 
 7d3:	5b                   	pop    rbx
 7d4:	c3                   	ret
 7d5:	b8 01 00 fe ff       	mov    eax,0xfffe0001
 7da:	5b                   	pop    rbx
 7db:	c3                   	ret
 7dc:	31 c0                	xor    eax,eax
 7de:	5b                   	pop    rbx
 7df:	c3                   	ret
 7e0:	e8 00 00 00 00       	call   7e5 <ovpn_hia_packet_id_read_epoch+0x1a5>
			7e1: R_X86_64_PLT32	abort-0x4
 7e5:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
 7ec:	00 00 00 00 

00000000000007f0 <ovpn_hia_packet_id_write_epoch>:
 7f0:	55                   	push   rbp
 7f1:	41 57                	push   r15
 7f3:	41 56                	push   r14
 7f5:	41 55                	push   r13
 7f7:	41 54                	push   r12
 7f9:	53                   	push   rbx
 7fa:	50                   	push   rax
 7fb:	b8 01 00 fe ff       	mov    eax,0xfffe0001
 800:	48 05 ff ff 01 00    	add    rax,0x1ffff
 806:	48 81 fe 01 00 01 00 	cmp    rsi,0x10001
 80d:	73 36                	jae    845 <ovpn_hia_packet_id_write_epoch+0x55>
 80f:	49 bb 00 00 00 00 02 	movabs r11,0x200000000
 816:	00 00 00 
 819:	48 85 f6             	test   rsi,rsi
 81c:	41 0f 95 c2          	setne  r10b
 820:	48 85 ff             	test   rdi,rdi
 823:	0f 94 c3             	sete   bl
 826:	44 84 d3             	test   bl,r10b
 829:	75 17                	jne    842 <ovpn_hia_packet_id_write_epoch+0x52>
 82b:	48 bb 00 00 00 00 03 	movabs rbx,0x300000000
 832:	00 00 00 
 835:	49 89 f2             	mov    r10,rsi
 838:	49 01 fa             	add    r10,rdi
 83b:	73 17                	jae    854 <ovpn_hia_packet_id_write_epoch+0x64>
 83d:	48 89 d8             	mov    rax,rbx
 840:	eb 03                	jmp    845 <ovpn_hia_packet_id_write_epoch+0x55>
 842:	4c 89 d8             	mov    rax,r11
 845:	48 83 c4 08          	add    rsp,0x8
 849:	5b                   	pop    rbx
 84a:	41 5c                	pop    r12
 84c:	41 5d                	pop    r13
 84e:	41 5e                	pop    r14
 850:	41 5f                	pop    r15
 852:	5d                   	pop    rbp
 853:	c3                   	ret
 854:	48 81 f9 00 00 01 00 	cmp    rcx,0x10000
 85b:	77 e8                	ja     845 <ovpn_hia_packet_id_write_epoch+0x55>
 85d:	48 85 c9             	test   rcx,rcx
 860:	40 0f 95 c5          	setne  bpl
 864:	48 85 d2             	test   rdx,rdx
 867:	41 0f 94 c6          	sete   r14b
 86b:	4c 89 d8             	mov    rax,r11
 86e:	41 84 ee             	test   r14b,bpl
 871:	75 d2                	jne    845 <ovpn_hia_packet_id_write_epoch+0x55>
 873:	49 89 cb             	mov    r11,rcx
 876:	48 89 d8             	mov    rax,rbx
 879:	49 01 d3             	add    r11,rdx
 87c:	72 c7                	jb     845 <ovpn_hia_packet_id_write_epoch+0x55>
 87e:	48 85 c9             	test   rcx,rcx
 881:	0f 95 c0             	setne  al
 884:	48 85 f6             	test   rsi,rsi
 887:	0f 95 c3             	setne  bl
 88a:	49 39 d2             	cmp    r10,rdx
 88d:	41 0f 97 c2          	seta   r10b
 891:	49 39 fb             	cmp    r11,rdi
 894:	41 0f 97 c3          	seta   r11b
 898:	45 20 d3             	and    r11b,r10b
 89b:	41 20 c3             	and    r11b,al
 89e:	41 84 db             	test   r11b,bl
 8a1:	0f 85 7c 01 00 00    	jne    a23 <ovpn_hia_packet_id_write_epoch+0x233>
 8a7:	48 83 f9 20          	cmp    rcx,0x20
 8ab:	0f 85 81 01 00 00    	jne    a32 <ovpn_hia_packet_id_write_epoch+0x242>
 8b1:	4c 8b 52 10          	mov    r10,QWORD PTR [rdx+0x10]
 8b5:	49 89 f3             	mov    r11,rsi
 8b8:	4d 29 d3             	sub    r11,r10
 8bb:	0f 82 71 01 00 00    	jb     a32 <ovpn_hia_packet_id_write_epoch+0x242>
 8c1:	48 8b 4a 18          	mov    rcx,QWORD PTR [rdx+0x18]
 8c5:	b8 01 00 fe ff       	mov    eax,0xfffe0001
 8ca:	4c 39 d9             	cmp    rcx,r11
 8cd:	0f 87 72 ff ff ff    	ja     845 <ovpn_hia_packet_id_write_epoch+0x55>
 8d3:	48 8b 42 08          	mov    rax,QWORD PTR [rdx+0x8]
 8d7:	48 85 c0             	test   rax,rax
 8da:	4c 0f 45 c0          	cmovne r8,rax
 8de:	48 8b 02             	mov    rax,QWORD PTR [rdx]
 8e1:	4c 89 42 08          	mov    QWORD PTR [rdx+0x8],r8
 8e5:	49 bb ff ff ff ff ff 	movabs r11,0xffffffffffff
 8ec:	ff 00 00 
 8ef:	4c 39 d8             	cmp    rax,r11
 8f2:	0f 84 44 01 00 00    	je     a3c <ovpn_hia_packet_id_write_epoch+0x24c>
 8f8:	4d 89 c6             	mov    r14,r8
 8fb:	49 c1 ee 30          	shr    r14,0x30
 8ff:	4d 89 c7             	mov    r15,r8
 902:	49 c1 ef 20          	shr    r15,0x20
 906:	45 89 c4             	mov    r12d,r8d
 909:	41 c1 ec 10          	shr    r12d,0x10
 90d:	48 ff c0             	inc    rax
 910:	49 89 c3             	mov    r11,rax
 913:	49 c1 eb 38          	shr    r11,0x38
 917:	44 88 5a 07          	mov    BYTE PTR [rdx+0x7],r11b
 91b:	49 89 c3             	mov    r11,rax
 91e:	49 c1 eb 30          	shr    r11,0x30
 922:	44 88 5a 06          	mov    BYTE PTR [rdx+0x6],r11b
 926:	49 89 c3             	mov    r11,rax
 929:	49 c1 eb 28          	shr    r11,0x28
 92d:	4c 89 1c 24          	mov    QWORD PTR [rsp],r11
 931:	44 88 5a 05          	mov    BYTE PTR [rdx+0x5],r11b
 935:	48 89 c3             	mov    rbx,rax
 938:	48 c1 eb 20          	shr    rbx,0x20
 93c:	88 5a 04             	mov    BYTE PTR [rdx+0x4],bl
 93f:	89 c5                	mov    ebp,eax
 941:	c1 ed 18             	shr    ebp,0x18
 944:	40 88 6a 03          	mov    BYTE PTR [rdx+0x3],bpl
 948:	41 89 c5             	mov    r13d,eax
 94b:	41 c1 ed 10          	shr    r13d,0x10
 94f:	44 88 6a 02          	mov    BYTE PTR [rdx+0x2],r13b
 953:	41 89 c3             	mov    r11d,eax
 956:	41 c1 eb 08          	shr    r11d,0x8
 95a:	44 88 5a 01          	mov    BYTE PTR [rdx+0x1],r11b
 95e:	88 02                	mov    BYTE PTR [rdx],al
 960:	44 88 72 0e          	mov    BYTE PTR [rdx+0xe],r14b
 964:	44 88 7a 0c          	mov    BYTE PTR [rdx+0xc],r15b
 968:	44 88 62 0a          	mov    BYTE PTR [rdx+0xa],r12b
 96c:	44 88 42 08          	mov    BYTE PTR [rdx+0x8],r8b
 970:	49 01 ca             	add    r10,rcx
 973:	49 89 f0             	mov    r8,rsi
 976:	4d 29 d0             	sub    r8,r10
 979:	49 83 f8 08          	cmp    r8,0x8
 97d:	0f 82 b9 00 00 00    	jb     a3c <ovpn_hia_packet_id_write_epoch+0x24c>
 983:	45 89 d0             	mov    r8d,r10d
 986:	4d 8d 50 07          	lea    r10,[r8+0x7]
 98a:	49 39 f2             	cmp    r10,rsi
 98d:	0f 83 b0 00 00 00    	jae    a43 <ovpn_hia_packet_id_write_epoch+0x253>
 993:	41 0f b7 f1          	movzx  esi,r9w
 997:	48 c1 e6 30          	shl    rsi,0x30
 99b:	49 89 c1             	mov    r9,rax
 99e:	49 09 f1             	or     r9,rsi
 9a1:	42 88 44 07 07       	mov    BYTE PTR [rdi+r8*1+0x7],al
 9a6:	46 88 5c 07 06       	mov    BYTE PTR [rdi+r8*1+0x6],r11b
 9ab:	46 88 6c 07 05       	mov    BYTE PTR [rdi+r8*1+0x5],r13b
 9b0:	42 88 6c 07 04       	mov    BYTE PTR [rdi+r8*1+0x4],bpl
 9b5:	42 88 5c 07 03       	mov    BYTE PTR [rdi+r8*1+0x3],bl
 9ba:	48 8b 04 24          	mov    rax,QWORD PTR [rsp]
 9be:	42 88 44 07 02       	mov    BYTE PTR [rdi+r8*1+0x2],al
 9c3:	4c 89 c8             	mov    rax,r9
 9c6:	48 c1 e8 30          	shr    rax,0x30
 9ca:	42 88 44 07 01       	mov    BYTE PTR [rdi+r8*1+0x1],al
 9cf:	49 c1 e9 38          	shr    r9,0x38
 9d3:	46 88 0c 07          	mov    BYTE PTR [rdi+r8*1],r9b
 9d7:	48 83 c1 08          	add    rcx,0x8
 9db:	48 89 c8             	mov    rax,rcx
 9de:	48 c1 e8 38          	shr    rax,0x38
 9e2:	88 42 1f             	mov    BYTE PTR [rdx+0x1f],al
 9e5:	48 89 c8             	mov    rax,rcx
 9e8:	48 c1 e8 30          	shr    rax,0x30
 9ec:	88 42 1e             	mov    BYTE PTR [rdx+0x1e],al
 9ef:	48 89 c8             	mov    rax,rcx
 9f2:	48 c1 e8 28          	shr    rax,0x28
 9f6:	88 42 1d             	mov    BYTE PTR [rdx+0x1d],al
 9f9:	48 89 c8             	mov    rax,rcx
 9fc:	48 c1 e8 20          	shr    rax,0x20
 a00:	88 42 1c             	mov    BYTE PTR [rdx+0x1c],al
 a03:	89 c8                	mov    eax,ecx
 a05:	c1 e8 18             	shr    eax,0x18
 a08:	88 42 1b             	mov    BYTE PTR [rdx+0x1b],al
 a0b:	89 c8                	mov    eax,ecx
 a0d:	c1 e8 10             	shr    eax,0x10
 a10:	88 42 1a             	mov    BYTE PTR [rdx+0x1a],al
 a13:	88 6a 19             	mov    BYTE PTR [rdx+0x19],ch
 a16:	88 4a 18             	mov    BYTE PTR [rdx+0x18],cl
 a19:	b8 01 00 00 00       	mov    eax,0x1
 a1e:	e9 22 fe ff ff       	jmp    845 <ovpn_hia_packet_id_write_epoch+0x55>
 a23:	48 b8 00 00 00 00 04 	movabs rax,0x400000000
 a2a:	00 00 00 
 a2d:	e9 13 fe ff ff       	jmp    845 <ovpn_hia_packet_id_write_epoch+0x55>
 a32:	b8 01 00 fe ff       	mov    eax,0xfffe0001
 a37:	e9 09 fe ff ff       	jmp    845 <ovpn_hia_packet_id_write_epoch+0x55>
 a3c:	31 c0                	xor    eax,eax
 a3e:	e9 02 fe ff ff       	jmp    845 <ovpn_hia_packet_id_write_epoch+0x55>
 a43:	e8 00 00 00 00       	call   a48 <ovpn_hia_packet_id_write_epoch+0x258>
			a44: R_X86_64_PLT32	abort-0x4
