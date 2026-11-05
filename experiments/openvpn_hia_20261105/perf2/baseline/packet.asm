
/workspace/scratch/2719a9027f80/packet-run-final4/packet.o:     file format elf64-x86-64


Disassembly of section .text:

0000000000000000 <__hia_fn_0>:
   0:	55                   	push   rbp
   1:	41 56                	push   r14
   3:	53                   	push   rbx
   4:	48 83 f9 20          	cmp    rcx,0x20
   8:	0f 94 c1             	sete   cl
   b:	41 83 f8 02          	cmp    r8d,0x2
   f:	41 0f 92 c1          	setb   r9b
  13:	b8 01 00 fe ff       	mov    eax,0xfffe0001
  18:	44 84 c9             	test   cl,r9b
  1b:	0f 84 2c 01 00 00    	je     14d <__hia_fn_0+0x14d>
  21:	48 8b 4a 10          	mov    rcx,QWORD PTR [rdx+0x10]
  25:	49 89 f2             	mov    r10,rsi
  28:	49 29 ca             	sub    r10,rcx
  2b:	0f 82 1c 01 00 00    	jb     14d <__hia_fn_0+0x14d>
  31:	4c 8b 4a 18          	mov    r9,QWORD PTR [rdx+0x18]
  35:	4d 39 d1             	cmp    r9,r10
  38:	0f 87 0f 01 00 00    	ja     14d <__hia_fn_0+0x14d>
  3e:	31 c0                	xor    eax,eax
  40:	0f 57 c0             	xorps  xmm0,xmm0
  43:	0f 11 02             	movups XMMWORD PTR [rdx],xmm0
  46:	49 83 f9 04          	cmp    r9,0x4
  4a:	0f 82 fd 00 00 00    	jb     14d <__hia_fn_0+0x14d>
  50:	48 39 ce             	cmp    rsi,rcx
  53:	0f 86 03 01 00 00    	jbe    15c <__hia_fn_0+0x15c>
  59:	48 89 d5             	mov    rbp,rdx
  5c:	4c 8d 51 01          	lea    r10,[rcx+0x1]
  60:	49 39 f2             	cmp    r10,rsi
  63:	0f 83 f3 00 00 00    	jae    15c <__hia_fn_0+0x15c>
  69:	4c 8d 51 02          	lea    r10,[rcx+0x2]
  6d:	49 39 f2             	cmp    r10,rsi
  70:	0f 83 e6 00 00 00    	jae    15c <__hia_fn_0+0x15c>
  76:	4c 8d 51 03          	lea    r10,[rcx+0x3]
  7a:	49 39 f2             	cmp    r10,rsi
  7d:	0f 83 d9 00 00 00    	jae    15c <__hia_fn_0+0x15c>
  83:	48 83 c2 13          	add    rdx,0x13
  87:	44 0f b6 14 0f       	movzx  r10d,BYTE PTR [rdi+rcx*1]
  8c:	44 0f b7 5c 0f 02    	movzx  r11d,WORD PTR [rdi+rcx*1+0x2]
  92:	66 41 c1 c3 08       	rol    r11w,0x8
  97:	0f b6 5c 0f 01       	movzx  ebx,BYTE PTR [rdi+rcx*1+0x1]
  9c:	66 44 89 5d 00       	mov    WORD PTR [rbp+0x0],r11w
  a1:	88 5d 02             	mov    BYTE PTR [rbp+0x2],bl
  a4:	44 88 55 03          	mov    BYTE PTR [rbp+0x3],r10b
  a8:	48 8d 59 04          	lea    rbx,[rcx+0x4]
  ac:	4d 8d 51 fc          	lea    r10,[r9-0x4]
  b0:	c7 45 04 00 00 00 00 	mov    DWORD PTR [rbp+0x4],0x0
  b7:	88 5d 10             	mov    BYTE PTR [rbp+0x10],bl
  ba:	88 7d 11             	mov    BYTE PTR [rbp+0x11],bh
  bd:	41 89 db             	mov    r11d,ebx
  c0:	41 c1 eb 10          	shr    r11d,0x10
  c4:	44 88 5d 12          	mov    BYTE PTR [rbp+0x12],r11b
  c8:	c6 42 04 00          	mov    BYTE PTR [rdx+0x4],0x0
  cc:	c7 02 00 00 00 00    	mov    DWORD PTR [rdx],0x0
  d2:	4c 89 55 18          	mov    QWORD PTR [rbp+0x18],r10
  d6:	45 85 c0             	test   r8d,r8d
  d9:	74 77                	je     152 <__hia_fn_0+0x152>
  db:	49 83 fa 04          	cmp    r10,0x4
  df:	72 6c                	jb     14d <__hia_fn_0+0x14d>
  e1:	48 39 f3             	cmp    rbx,rsi
  e4:	73 76                	jae    15c <__hia_fn_0+0x15c>
  e6:	48 8d 41 05          	lea    rax,[rcx+0x5]
  ea:	48 39 f0             	cmp    rax,rsi
  ed:	73 6d                	jae    15c <__hia_fn_0+0x15c>
  ef:	48 8d 41 06          	lea    rax,[rcx+0x6]
  f3:	48 39 f0             	cmp    rax,rsi
  f6:	73 64                	jae    15c <__hia_fn_0+0x15c>
  f8:	48 8d 41 07          	lea    rax,[rcx+0x7]
  fc:	48 39 f0             	cmp    rax,rsi
  ff:	73 5b                	jae    15c <__hia_fn_0+0x15c>
 101:	0f b6 44 0f 04       	movzx  eax,BYTE PTR [rdi+rcx*1+0x4]
 106:	0f b6 74 0f 05       	movzx  esi,BYTE PTR [rdi+rcx*1+0x5]
 10b:	0f b7 7c 0f 06       	movzx  edi,WORD PTR [rdi+rcx*1+0x6]
 110:	66 c1 c7 08          	rol    di,0x8
 114:	66 89 7d 08          	mov    WORD PTR [rbp+0x8],di
 118:	40 88 75 0a          	mov    BYTE PTR [rbp+0xa],sil
 11c:	88 45 0b             	mov    BYTE PTR [rbp+0xb],al
 11f:	48 83 c1 08          	add    rcx,0x8
 123:	49 83 c1 f8          	add    r9,0xfffffffffffffff8
 127:	c7 45 0c 00 00 00 00 	mov    DWORD PTR [rbp+0xc],0x0
 12e:	88 4d 10             	mov    BYTE PTR [rbp+0x10],cl
 131:	88 6d 11             	mov    BYTE PTR [rbp+0x11],ch
 134:	c1 e9 10             	shr    ecx,0x10
 137:	88 4d 12             	mov    BYTE PTR [rbp+0x12],cl
 13a:	c6 42 04 00          	mov    BYTE PTR [rdx+0x4],0x0
 13e:	c7 02 00 00 00 00    	mov    DWORD PTR [rdx],0x0
 144:	4c 89 4d 18          	mov    QWORD PTR [rbp+0x18],r9
 148:	b8 01 00 00 00       	mov    eax,0x1
 14d:	5b                   	pop    rbx
 14e:	41 5e                	pop    r14
 150:	5d                   	pop    rbp
 151:	c3                   	ret
 152:	b8 01 00 00 00       	mov    eax,0x1
 157:	5b                   	pop    rbx
 158:	41 5e                	pop    r14
 15a:	5d                   	pop    rbp
 15b:	c3                   	ret
 15c:	e8 00 00 00 00       	call   161 <__hia_fn_0+0x161>
			15d: R_X86_64_PLT32	abort-0x4
 161:	66 66 66 66 66 66 2e 	data16 data16 data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
 168:	0f 1f 84 00 00 00 00 
 16f:	00 

0000000000000170 <__hia_fn_1>:
 170:	55                   	push   rbp
 171:	41 57                	push   r15
 173:	41 56                	push   r14
 175:	41 55                	push   r13
 177:	41 54                	push   r12
 179:	53                   	push   rbx
 17a:	48 83 ec 28          	sub    rsp,0x28
 17e:	8b 5c 24 60          	mov    ebx,DWORD PTR [rsp+0x60]
 182:	48 83 f9 20          	cmp    rcx,0x20
 186:	0f 94 c1             	sete   cl
 189:	89 d8                	mov    eax,ebx
 18b:	44 09 c8             	or     eax,r9d
 18e:	83 f8 02             	cmp    eax,0x2
 191:	41 0f 92 c2          	setb   r10b
 195:	b8 01 00 fe ff       	mov    eax,0xfffe0001
 19a:	44 84 d1             	test   cl,r10b
 19d:	0f 84 58 03 00 00    	je     4fb <__hia_fn_1+0x38b>
 1a3:	4c 8b 52 10          	mov    r10,QWORD PTR [rdx+0x10]
 1a7:	48 89 f1             	mov    rcx,rsi
 1aa:	4c 29 d1             	sub    rcx,r10
 1ad:	0f 82 48 03 00 00    	jb     4fb <__hia_fn_1+0x38b>
 1b3:	4c 8b 5a 18          	mov    r11,QWORD PTR [rdx+0x18]
 1b7:	4c 89 5c 24 08       	mov    QWORD PTR [rsp+0x8],r11
 1bc:	49 39 cb             	cmp    r11,rcx
 1bf:	0f 87 36 03 00 00    	ja     4fb <__hia_fn_1+0x38b>
 1c5:	4c 8b 1a             	mov    r11,QWORD PTR [rdx]
 1c8:	48 8b 4a 08          	mov    rcx,QWORD PTR [rdx+0x8]
 1cc:	48 85 c9             	test   rcx,rcx
 1cf:	49 0f 44 c8          	cmove  rcx,r8
 1d3:	48 89 4a 08          	mov    QWORD PTR [rdx+0x8],rcx
 1d7:	45 85 c9             	test   r9d,r9d
 1da:	40 0f 95 c5          	setne  bpl
 1de:	49 39 c8             	cmp    r8,rcx
 1e1:	41 0f 9f c7          	setg   r15b
 1e5:	31 c0                	xor    eax,eax
 1e7:	41 be ff ff ff ff    	mov    r14d,0xffffffff
 1ed:	4d 39 f3             	cmp    r11,r14
 1f0:	75 09                	jne    1fb <__hia_fn_1+0x8b>
 1f2:	44 20 fd             	and    bpl,r15b
 1f5:	0f 84 00 03 00 00    	je     4fb <__hia_fn_1+0x38b>
 1fb:	4d 8d 7b 01          	lea    r15,[r11+0x1]
 1ff:	4d 39 f3             	cmp    r11,r14
 202:	4c 0f 45 c1          	cmovne r8,rcx
 206:	41 bb 01 00 00 00    	mov    r11d,0x1
 20c:	4d 0f 45 df          	cmovne r11,r15
 210:	44 88 1a             	mov    BYTE PTR [rdx],r11b
 213:	44 89 d9             	mov    ecx,r11d
 216:	c1 e9 08             	shr    ecx,0x8
 219:	89 4c 24 04          	mov    DWORD PTR [rsp+0x4],ecx
 21d:	88 4a 01             	mov    BYTE PTR [rdx+0x1],cl
 220:	45 89 df             	mov    r15d,r11d
 223:	41 c1 ef 10          	shr    r15d,0x10
 227:	44 88 7a 02          	mov    BYTE PTR [rdx+0x2],r15b
 22b:	45 89 dc             	mov    r12d,r11d
 22e:	41 c1 ec 18          	shr    r12d,0x18
 232:	44 88 62 03          	mov    BYTE PTR [rdx+0x3],r12b
 236:	4c 89 d9             	mov    rcx,r11
 239:	48 c1 e9 20          	shr    rcx,0x20
 23d:	88 4a 04             	mov    BYTE PTR [rdx+0x4],cl
 240:	4c 89 d9             	mov    rcx,r11
 243:	48 c1 e9 28          	shr    rcx,0x28
 247:	88 4a 05             	mov    BYTE PTR [rdx+0x5],cl
 24a:	4c 89 d9             	mov    rcx,r11
 24d:	48 c1 e9 30          	shr    rcx,0x30
 251:	88 4a 06             	mov    BYTE PTR [rdx+0x6],cl
 254:	4c 89 d9             	mov    rcx,r11
 257:	48 c1 e9 38          	shr    rcx,0x38
 25b:	88 4a 07             	mov    BYTE PTR [rdx+0x7],cl
 25e:	44 88 42 08          	mov    BYTE PTR [rdx+0x8],r8b
 262:	44 89 c5             	mov    ebp,r8d
 265:	c1 ed 08             	shr    ebp,0x8
 268:	40 88 6a 09          	mov    BYTE PTR [rdx+0x9],bpl
 26c:	45 89 c6             	mov    r14d,r8d
 26f:	41 c1 ee 10          	shr    r14d,0x10
 273:	44 88 72 0a          	mov    BYTE PTR [rdx+0xa],r14b
 277:	45 89 c5             	mov    r13d,r8d
 27a:	41 c1 ed 18          	shr    r13d,0x18
 27e:	44 88 6a 0b          	mov    BYTE PTR [rdx+0xb],r13b
 282:	4c 89 c1             	mov    rcx,r8
 285:	48 c1 e9 20          	shr    rcx,0x20
 289:	88 4a 0c             	mov    BYTE PTR [rdx+0xc],cl
 28c:	4c 89 c1             	mov    rcx,r8
 28f:	48 c1 e9 28          	shr    rcx,0x28
 293:	88 4a 0d             	mov    BYTE PTR [rdx+0xd],cl
 296:	4c 89 c1             	mov    rcx,r8
 299:	48 c1 e9 30          	shr    rcx,0x30
 29d:	88 4a 0e             	mov    BYTE PTR [rdx+0xe],cl
 2a0:	4c 89 c1             	mov    rcx,r8
 2a3:	48 c1 e9 38          	shr    rcx,0x38
 2a7:	88 4a 0f             	mov    BYTE PTR [rdx+0xf],cl
 2aa:	85 db                	test   ebx,ebx
 2ac:	0f 84 98 00 00 00    	je     34a <__hia_fn_1+0x1da>
 2b2:	48 89 d1             	mov    rcx,rdx
 2b5:	48 83 c1 12          	add    rcx,0x12
 2b9:	45 85 c9             	test   r9d,r9d
 2bc:	0f 84 ce 01 00 00    	je     490 <__hia_fn_1+0x320>
 2c2:	49 83 fa 04          	cmp    r10,0x4
 2c6:	0f 82 2f 02 00 00    	jb     4fb <__hia_fn_1+0x38b>
 2cc:	49 8d 5a fc          	lea    rbx,[r10-0x4]
 2d0:	48 39 f3             	cmp    rbx,rsi
 2d3:	0f 83 31 02 00 00    	jae    50a <__hia_fn_1+0x39a>
 2d9:	49 89 c9             	mov    r9,rcx
 2dc:	46 88 6c 17 fc       	mov    BYTE PTR [rdi+r10*1-0x4],r13b
 2e1:	49 8d 4a fd          	lea    rcx,[r10-0x3]
 2e5:	48 39 f1             	cmp    rcx,rsi
 2e8:	0f 83 1c 02 00 00    	jae    50a <__hia_fn_1+0x39a>
 2ee:	46 88 74 17 fd       	mov    BYTE PTR [rdi+r10*1-0x3],r14b
 2f3:	49 8d 4a fe          	lea    rcx,[r10-0x2]
 2f7:	48 39 f1             	cmp    rcx,rsi
 2fa:	0f 83 0a 02 00 00    	jae    50a <__hia_fn_1+0x39a>
 300:	42 88 6c 17 fe       	mov    BYTE PTR [rdi+r10*1-0x2],bpl
 305:	49 ff ca             	dec    r10
 308:	49 39 f2             	cmp    r10,rsi
 30b:	0f 83 f9 01 00 00    	jae    50a <__hia_fn_1+0x39a>
 311:	48 8b 4c 24 08       	mov    rcx,QWORD PTR [rsp+0x8]
 316:	48 83 c1 04          	add    rcx,0x4
 31a:	46 88 04 17          	mov    BYTE PTR [rdi+r10*1],r8b
 31e:	88 5a 10             	mov    BYTE PTR [rdx+0x10],bl
 321:	88 7a 11             	mov    BYTE PTR [rdx+0x11],bh
 324:	66 41 c7 41 04 00 00 	mov    WORD PTR [r9+0x4],0x0
 32b:	41 c7 01 00 00 00 00 	mov    DWORD PTR [r9],0x0
 332:	48 89 4c 24 08       	mov    QWORD PTR [rsp+0x8],rcx
 337:	48 89 4a 18          	mov    QWORD PTR [rdx+0x18],rcx
 33b:	48 83 fb 03          	cmp    rbx,0x3
 33f:	0f 87 57 01 00 00    	ja     49c <__hia_fn_1+0x32c>
 345:	e9 b1 01 00 00       	jmp    4fb <__hia_fn_1+0x38b>
 34a:	89 6c 24 14          	mov    DWORD PTR [rsp+0x14],ebp
 34e:	48 8b 4c 24 08       	mov    rcx,QWORD PTR [rsp+0x8]
 353:	4a 8d 2c 11          	lea    rbp,[rcx+r10*1]
 357:	48 89 f3             	mov    rbx,rsi
 35a:	48 29 eb             	sub    rbx,rbp
 35d:	48 83 fb 04          	cmp    rbx,0x4
 361:	0f 82 94 01 00 00    	jb     4fb <__hia_fn_1+0x38b>
 367:	48 39 ee             	cmp    rsi,rbp
 36a:	0f 86 9a 01 00 00    	jbe    50a <__hia_fn_1+0x39a>
 370:	44 88 24 2f          	mov    BYTE PTR [rdi+rbp*1],r12b
 374:	48 8d 5d 01          	lea    rbx,[rbp+0x1]
 378:	48 39 f3             	cmp    rbx,rsi
 37b:	0f 83 89 01 00 00    	jae    50a <__hia_fn_1+0x39a>
 381:	44 88 7c 2f 01       	mov    BYTE PTR [rdi+rbp*1+0x1],r15b
 386:	48 8d 5d 02          	lea    rbx,[rbp+0x2]
 38a:	48 39 f3             	cmp    rbx,rsi
 38d:	0f 83 77 01 00 00    	jae    50a <__hia_fn_1+0x39a>
 393:	8b 5c 24 04          	mov    ebx,DWORD PTR [rsp+0x4]
 397:	88 5c 2f 02          	mov    BYTE PTR [rdi+rbp*1+0x2],bl
 39b:	48 83 c5 03          	add    rbp,0x3
 39f:	48 39 f5             	cmp    rbp,rsi
 3a2:	0f 83 62 01 00 00    	jae    50a <__hia_fn_1+0x39a>
 3a8:	48 8b 5c 24 08       	mov    rbx,QWORD PTR [rsp+0x8]
 3ad:	4c 8d 7b 04          	lea    r15,[rbx+0x4]
 3b1:	44 89 fb             	mov    ebx,r15d
 3b4:	c1 eb 10             	shr    ebx,0x10
 3b7:	89 5c 24 04          	mov    DWORD PTR [rsp+0x4],ebx
 3bb:	44 89 fb             	mov    ebx,r15d
 3be:	c1 eb 18             	shr    ebx,0x18
 3c1:	89 5c 24 10          	mov    DWORD PTR [rsp+0x10],ebx
 3c5:	4c 89 fb             	mov    rbx,r15
 3c8:	48 c1 eb 20          	shr    rbx,0x20
 3cc:	48 89 5c 24 18       	mov    QWORD PTR [rsp+0x18],rbx
 3d1:	4d 89 fc             	mov    r12,r15
 3d4:	49 c1 ec 28          	shr    r12,0x28
 3d8:	4c 89 fb             	mov    rbx,r15
 3db:	48 c1 eb 30          	shr    rbx,0x30
 3df:	4c 89 f9             	mov    rcx,r15
 3e2:	48 c1 e9 38          	shr    rcx,0x38
 3e6:	48 89 4c 24 20       	mov    QWORD PTR [rsp+0x20],rcx
 3eb:	44 88 1c 2f          	mov    BYTE PTR [rdi+rbp*1],r11b
 3ef:	44 88 7a 18          	mov    BYTE PTR [rdx+0x18],r15b
 3f3:	4c 89 f9             	mov    rcx,r15
 3f6:	88 6a 19             	mov    BYTE PTR [rdx+0x19],ch
 3f9:	8b 6c 24 04          	mov    ebp,DWORD PTR [rsp+0x4]
 3fd:	40 88 6a 1a          	mov    BYTE PTR [rdx+0x1a],bpl
 401:	8b 6c 24 10          	mov    ebp,DWORD PTR [rsp+0x10]
 405:	40 88 6a 1b          	mov    BYTE PTR [rdx+0x1b],bpl
 409:	48 8b 4c 24 18       	mov    rcx,QWORD PTR [rsp+0x18]
 40e:	88 4a 1c             	mov    BYTE PTR [rdx+0x1c],cl
 411:	44 88 62 1d          	mov    BYTE PTR [rdx+0x1d],r12b
 415:	88 5a 1e             	mov    BYTE PTR [rdx+0x1e],bl
 418:	48 8b 4c 24 20       	mov    rcx,QWORD PTR [rsp+0x20]
 41d:	88 4a 1f             	mov    BYTE PTR [rdx+0x1f],cl
 420:	45 85 c9             	test   r9d,r9d
 423:	0f 84 cd 00 00 00    	je     4f6 <__hia_fn_1+0x386>
 429:	4d 89 f9             	mov    r9,r15
 42c:	4d 01 d1             	add    r9,r10
 42f:	48 89 f1             	mov    rcx,rsi
 432:	4c 29 c9             	sub    rcx,r9
 435:	48 83 f9 04          	cmp    rcx,0x4
 439:	0f 82 bc 00 00 00    	jb     4fb <__hia_fn_1+0x38b>
 43f:	4c 39 ce             	cmp    rsi,r9
 442:	0f 86 c2 00 00 00    	jbe    50a <__hia_fn_1+0x39a>
 448:	46 88 2c 0f          	mov    BYTE PTR [rdi+r9*1],r13b
 44c:	49 8d 41 01          	lea    rax,[r9+0x1]
 450:	48 39 f0             	cmp    rax,rsi
 453:	8b 4c 24 14          	mov    ecx,DWORD PTR [rsp+0x14]
 457:	0f 83 ad 00 00 00    	jae    50a <__hia_fn_1+0x39a>
 45d:	46 88 74 0f 01       	mov    BYTE PTR [rdi+r9*1+0x1],r14b
 462:	49 8d 41 02          	lea    rax,[r9+0x2]
 466:	48 39 f0             	cmp    rax,rsi
 469:	0f 83 9b 00 00 00    	jae    50a <__hia_fn_1+0x39a>
 46f:	42 88 4c 0f 02       	mov    BYTE PTR [rdi+r9*1+0x2],cl
 474:	49 83 c1 03          	add    r9,0x3
 478:	49 39 f1             	cmp    r9,rsi
 47b:	0f 83 89 00 00 00    	jae    50a <__hia_fn_1+0x39a>
 481:	46 88 04 0f          	mov    BYTE PTR [rdi+r9*1],r8b
 485:	48 8b 4c 24 08       	mov    rcx,QWORD PTR [rsp+0x8]
 48a:	48 83 c1 08          	add    rcx,0x8
 48e:	eb 62                	jmp    4f2 <__hia_fn_1+0x382>
 490:	49 89 c9             	mov    r9,rcx
 493:	4c 89 d3             	mov    rbx,r10
 496:	48 83 fb 03          	cmp    rbx,0x3
 49a:	76 5f                	jbe    4fb <__hia_fn_1+0x38b>
 49c:	48 8d 43 fc          	lea    rax,[rbx-0x4]
 4a0:	48 39 f0             	cmp    rax,rsi
 4a3:	73 65                	jae    50a <__hia_fn_1+0x39a>
 4a5:	44 88 64 1f fc       	mov    BYTE PTR [rdi+rbx*1-0x4],r12b
 4aa:	48 8d 4b fd          	lea    rcx,[rbx-0x3]
 4ae:	48 39 f1             	cmp    rcx,rsi
 4b1:	73 57                	jae    50a <__hia_fn_1+0x39a>
 4b3:	44 88 7c 1f fd       	mov    BYTE PTR [rdi+rbx*1-0x3],r15b
 4b8:	48 8d 4b fe          	lea    rcx,[rbx-0x2]
 4bc:	48 39 f1             	cmp    rcx,rsi
 4bf:	73 49                	jae    50a <__hia_fn_1+0x39a>
 4c1:	8b 4c 24 04          	mov    ecx,DWORD PTR [rsp+0x4]
 4c5:	88 4c 1f fe          	mov    BYTE PTR [rdi+rbx*1-0x2],cl
 4c9:	48 ff cb             	dec    rbx
 4cc:	48 39 f3             	cmp    rbx,rsi
 4cf:	73 39                	jae    50a <__hia_fn_1+0x39a>
 4d1:	48 8b 4c 24 08       	mov    rcx,QWORD PTR [rsp+0x8]
 4d6:	48 83 c1 04          	add    rcx,0x4
 4da:	44 88 1c 1f          	mov    BYTE PTR [rdi+rbx*1],r11b
 4de:	88 42 10             	mov    BYTE PTR [rdx+0x10],al
 4e1:	88 62 11             	mov    BYTE PTR [rdx+0x11],ah
 4e4:	66 41 c7 41 04 00 00 	mov    WORD PTR [r9+0x4],0x0
 4eb:	41 c7 01 00 00 00 00 	mov    DWORD PTR [r9],0x0
 4f2:	48 89 4a 18          	mov    QWORD PTR [rdx+0x18],rcx
 4f6:	b8 01 00 00 00       	mov    eax,0x1
 4fb:	48 83 c4 28          	add    rsp,0x28
 4ff:	5b                   	pop    rbx
 500:	41 5c                	pop    r12
 502:	41 5d                	pop    r13
 504:	41 5e                	pop    r14
 506:	41 5f                	pop    r15
 508:	5d                   	pop    rbp
 509:	c3                   	ret
 50a:	e8 00 00 00 00       	call   50f <__hia_fn_1+0x39f>
			50b: R_X86_64_PLT32	abort-0x4
 50f:	90                   	nop

0000000000000510 <__hia_fn_2>:
 510:	53                   	push   rbx
 511:	b8 01 00 fe ff       	mov    eax,0xfffe0001
 516:	48 83 f9 20          	cmp    rcx,0x20
 51a:	0f 85 f1 00 00 00    	jne    611 <__hia_fn_2+0x101>
 520:	48 8b 4a 10          	mov    rcx,QWORD PTR [rdx+0x10]
 524:	49 89 f1             	mov    r9,rsi
 527:	49 29 c9             	sub    r9,rcx
 52a:	0f 82 e1 00 00 00    	jb     611 <__hia_fn_2+0x101>
 530:	4c 8b 42 18          	mov    r8,QWORD PTR [rdx+0x18]
 534:	4d 39 c8             	cmp    r8,r9
 537:	0f 87 d4 00 00 00    	ja     611 <__hia_fn_2+0x101>
 53d:	31 c0                	xor    eax,eax
 53f:	49 83 f8 08          	cmp    r8,0x8
 543:	0f 82 c8 00 00 00    	jb     611 <__hia_fn_2+0x101>
 549:	48 39 ce             	cmp    rsi,rcx
 54c:	0f 86 c1 00 00 00    	jbe    613 <__hia_fn_2+0x103>
 552:	48 8d 41 01          	lea    rax,[rcx+0x1]
 556:	48 39 f0             	cmp    rax,rsi
 559:	0f 83 b4 00 00 00    	jae    613 <__hia_fn_2+0x103>
 55f:	48 8d 41 02          	lea    rax,[rcx+0x2]
 563:	48 39 f0             	cmp    rax,rsi
 566:	0f 83 a7 00 00 00    	jae    613 <__hia_fn_2+0x103>
 56c:	48 8d 41 03          	lea    rax,[rcx+0x3]
 570:	48 39 f0             	cmp    rax,rsi
 573:	0f 83 9a 00 00 00    	jae    613 <__hia_fn_2+0x103>
 579:	48 8d 41 04          	lea    rax,[rcx+0x4]
 57d:	48 39 f0             	cmp    rax,rsi
 580:	0f 83 8d 00 00 00    	jae    613 <__hia_fn_2+0x103>
 586:	48 8d 41 05          	lea    rax,[rcx+0x5]
 58a:	48 39 f0             	cmp    rax,rsi
 58d:	0f 83 80 00 00 00    	jae    613 <__hia_fn_2+0x103>
 593:	48 8d 41 06          	lea    rax,[rcx+0x6]
 597:	48 39 f0             	cmp    rax,rsi
 59a:	73 77                	jae    613 <__hia_fn_2+0x103>
 59c:	48 8d 41 07          	lea    rax,[rcx+0x7]
 5a0:	48 39 f0             	cmp    rax,rsi
 5a3:	73 6e                	jae    613 <__hia_fn_2+0x103>
 5a5:	48 89 d6             	mov    rsi,rdx
 5a8:	0f b7 04 0f          	movzx  eax,WORD PTR [rdi+rcx*1]
 5ac:	66 c1 c0 08          	rol    ax,0x8
 5b0:	48 83 c6 13          	add    rsi,0x13
 5b4:	44 0f b6 4c 0f 02    	movzx  r9d,BYTE PTR [rdi+rcx*1+0x2]
 5ba:	44 0f b6 54 0f 03    	movzx  r10d,BYTE PTR [rdi+rcx*1+0x3]
 5c0:	44 0f b6 5c 0f 04    	movzx  r11d,BYTE PTR [rdi+rcx*1+0x4]
 5c6:	0f b6 5c 0f 05       	movzx  ebx,BYTE PTR [rdi+rcx*1+0x5]
 5cb:	0f b7 7c 0f 06       	movzx  edi,WORD PTR [rdi+rcx*1+0x6]
 5d0:	66 c1 c7 08          	rol    di,0x8
 5d4:	0f b7 c0             	movzx  eax,ax
 5d7:	66 89 3a             	mov    WORD PTR [rdx],di
 5da:	88 5a 02             	mov    BYTE PTR [rdx+0x2],bl
 5dd:	44 88 5a 03          	mov    BYTE PTR [rdx+0x3],r11b
 5e1:	44 88 52 04          	mov    BYTE PTR [rdx+0x4],r10b
 5e5:	44 88 4a 05          	mov    BYTE PTR [rdx+0x5],r9b
 5e9:	66 c7 42 06 00 00    	mov    WORD PTR [rdx+0x6],0x0
 5ef:	48 83 c1 08          	add    rcx,0x8
 5f3:	49 83 c0 f8          	add    r8,0xfffffffffffffff8
 5f7:	88 4a 10             	mov    BYTE PTR [rdx+0x10],cl
 5fa:	88 6a 11             	mov    BYTE PTR [rdx+0x11],ch
 5fd:	c1 e9 10             	shr    ecx,0x10
 600:	88 4a 12             	mov    BYTE PTR [rdx+0x12],cl
 603:	c6 46 04 00          	mov    BYTE PTR [rsi+0x4],0x0
 607:	c7 06 00 00 00 00    	mov    DWORD PTR [rsi],0x0
 60d:	4c 89 42 18          	mov    QWORD PTR [rdx+0x18],r8
 611:	5b                   	pop    rbx
 612:	c3                   	ret
 613:	e8 00 00 00 00       	call   618 <__hia_fn_2+0x108>
			614: R_X86_64_PLT32	abort-0x4
 618:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
 61f:	00 

0000000000000620 <__hia_fn_3>:
 620:	55                   	push   rbp
 621:	41 57                	push   r15
 623:	41 56                	push   r14
 625:	41 55                	push   r13
 627:	41 54                	push   r12
 629:	53                   	push   rbx
 62a:	50                   	push   rax
 62b:	b8 01 00 fe ff       	mov    eax,0xfffe0001
 630:	48 83 f9 20          	cmp    rcx,0x20
 634:	0f 85 ad 01 00 00    	jne    7e7 <__hia_fn_3+0x1c7>
 63a:	4c 8b 52 10          	mov    r10,QWORD PTR [rdx+0x10]
 63e:	49 89 f3             	mov    r11,rsi
 641:	4d 29 d3             	sub    r11,r10
 644:	0f 82 9d 01 00 00    	jb     7e7 <__hia_fn_3+0x1c7>
 64a:	48 8b 4a 18          	mov    rcx,QWORD PTR [rdx+0x18]
 64e:	4c 39 d9             	cmp    rcx,r11
 651:	0f 87 90 01 00 00    	ja     7e7 <__hia_fn_3+0x1c7>
 657:	4c 8b 22             	mov    r12,QWORD PTR [rdx]
 65a:	48 8b 42 08          	mov    rax,QWORD PTR [rdx+0x8]
 65e:	48 85 c0             	test   rax,rax
 661:	4c 0f 45 c0          	cmovne r8,rax
 665:	4c 89 42 08          	mov    QWORD PTR [rdx+0x8],r8
 669:	31 c0                	xor    eax,eax
 66b:	49 bb ff ff ff ff ff 	movabs r11,0xffffffffffff
 672:	ff 00 00 
 675:	4d 39 dc             	cmp    r12,r11
 678:	0f 84 69 01 00 00    	je     7e7 <__hia_fn_3+0x1c7>
 67e:	49 ff c4             	inc    r12
 681:	44 88 64 24 07       	mov    BYTE PTR [rsp+0x7],r12b
 686:	44 88 22             	mov    BYTE PTR [rdx],r12b
 689:	44 89 e5             	mov    ebp,r12d
 68c:	c1 ed 08             	shr    ebp,0x8
 68f:	40 88 6a 01          	mov    BYTE PTR [rdx+0x1],bpl
 693:	45 89 e6             	mov    r14d,r12d
 696:	41 c1 ee 10          	shr    r14d,0x10
 69a:	44 88 72 02          	mov    BYTE PTR [rdx+0x2],r14b
 69e:	45 89 e7             	mov    r15d,r12d
 6a1:	41 c1 ef 18          	shr    r15d,0x18
 6a5:	44 88 7a 03          	mov    BYTE PTR [rdx+0x3],r15b
 6a9:	4d 89 e3             	mov    r11,r12
 6ac:	49 c1 eb 20          	shr    r11,0x20
 6b0:	44 88 5a 04          	mov    BYTE PTR [rdx+0x4],r11b
 6b4:	4d 89 e5             	mov    r13,r12
 6b7:	49 c1 ed 28          	shr    r13,0x28
 6bb:	44 88 6a 05          	mov    BYTE PTR [rdx+0x5],r13b
 6bf:	4c 89 e3             	mov    rbx,r12
 6c2:	48 c1 eb 30          	shr    rbx,0x30
 6c6:	88 5a 06             	mov    BYTE PTR [rdx+0x6],bl
 6c9:	4c 89 e3             	mov    rbx,r12
 6cc:	48 c1 eb 38          	shr    rbx,0x38
 6d0:	88 5a 07             	mov    BYTE PTR [rdx+0x7],bl
 6d3:	44 89 c3             	mov    ebx,r8d
 6d6:	c1 eb 08             	shr    ebx,0x8
 6d9:	88 5a 09             	mov    BYTE PTR [rdx+0x9],bl
 6dc:	44 89 c3             	mov    ebx,r8d
 6df:	c1 eb 18             	shr    ebx,0x18
 6e2:	88 5a 0b             	mov    BYTE PTR [rdx+0xb],bl
 6e5:	4c 89 c3             	mov    rbx,r8
 6e8:	48 c1 eb 28          	shr    rbx,0x28
 6ec:	88 5a 0d             	mov    BYTE PTR [rdx+0xd],bl
 6ef:	49 c1 e8 38          	shr    r8,0x38
 6f3:	44 88 42 0f          	mov    BYTE PTR [rdx+0xf],r8b
 6f7:	49 01 ca             	add    r10,rcx
 6fa:	49 89 f0             	mov    r8,rsi
 6fd:	4d 29 d0             	sub    r8,r10
 700:	49 83 f8 08          	cmp    r8,0x8
 704:	0f 82 dd 00 00 00    	jb     7e7 <__hia_fn_3+0x1c7>
 70a:	4c 39 d6             	cmp    rsi,r10
 70d:	0f 86 e3 00 00 00    	jbe    7f6 <__hia_fn_3+0x1d6>
 713:	41 0f b7 c1          	movzx  eax,r9w
 717:	48 c1 e0 30          	shl    rax,0x30
 71b:	49 09 c4             	or     r12,rax
 71e:	4c 89 e0             	mov    rax,r12
 721:	48 c1 e8 38          	shr    rax,0x38
 725:	42 88 04 17          	mov    BYTE PTR [rdi+r10*1],al
 729:	49 8d 42 01          	lea    rax,[r10+0x1]
 72d:	48 39 f0             	cmp    rax,rsi
 730:	0f 83 c0 00 00 00    	jae    7f6 <__hia_fn_3+0x1d6>
 736:	49 c1 ec 30          	shr    r12,0x30
 73a:	46 88 64 17 01       	mov    BYTE PTR [rdi+r10*1+0x1],r12b
 73f:	49 8d 42 02          	lea    rax,[r10+0x2]
 743:	48 39 f0             	cmp    rax,rsi
 746:	0f 83 aa 00 00 00    	jae    7f6 <__hia_fn_3+0x1d6>
 74c:	46 88 6c 17 02       	mov    BYTE PTR [rdi+r10*1+0x2],r13b
 751:	49 8d 42 03          	lea    rax,[r10+0x3]
 755:	48 39 f0             	cmp    rax,rsi
 758:	0f 83 98 00 00 00    	jae    7f6 <__hia_fn_3+0x1d6>
 75e:	46 88 5c 17 03       	mov    BYTE PTR [rdi+r10*1+0x3],r11b
 763:	49 8d 42 04          	lea    rax,[r10+0x4]
 767:	48 39 f0             	cmp    rax,rsi
 76a:	0f 83 86 00 00 00    	jae    7f6 <__hia_fn_3+0x1d6>
 770:	46 88 7c 17 04       	mov    BYTE PTR [rdi+r10*1+0x4],r15b
 775:	49 8d 42 05          	lea    rax,[r10+0x5]
 779:	48 39 f0             	cmp    rax,rsi
 77c:	73 78                	jae    7f6 <__hia_fn_3+0x1d6>
 77e:	46 88 74 17 05       	mov    BYTE PTR [rdi+r10*1+0x5],r14b
 783:	49 8d 42 06          	lea    rax,[r10+0x6]
 787:	48 39 f0             	cmp    rax,rsi
 78a:	73 6a                	jae    7f6 <__hia_fn_3+0x1d6>
 78c:	42 88 6c 17 06       	mov    BYTE PTR [rdi+r10*1+0x6],bpl
 791:	49 83 c2 07          	add    r10,0x7
 795:	49 39 f2             	cmp    r10,rsi
 798:	73 5c                	jae    7f6 <__hia_fn_3+0x1d6>
 79a:	0f b6 44 24 07       	movzx  eax,BYTE PTR [rsp+0x7]
 79f:	42 88 04 17          	mov    BYTE PTR [rdi+r10*1],al
 7a3:	48 83 c1 08          	add    rcx,0x8
 7a7:	88 4a 18             	mov    BYTE PTR [rdx+0x18],cl
 7aa:	88 6a 19             	mov    BYTE PTR [rdx+0x19],ch
 7ad:	89 c8                	mov    eax,ecx
 7af:	c1 e8 10             	shr    eax,0x10
 7b2:	88 42 1a             	mov    BYTE PTR [rdx+0x1a],al
 7b5:	89 c8                	mov    eax,ecx
 7b7:	c1 e8 18             	shr    eax,0x18
 7ba:	88 42 1b             	mov    BYTE PTR [rdx+0x1b],al
 7bd:	48 89 c8             	mov    rax,rcx
 7c0:	48 c1 e8 20          	shr    rax,0x20
 7c4:	88 42 1c             	mov    BYTE PTR [rdx+0x1c],al
 7c7:	48 89 c8             	mov    rax,rcx
 7ca:	48 c1 e8 28          	shr    rax,0x28
 7ce:	88 42 1d             	mov    BYTE PTR [rdx+0x1d],al
 7d1:	48 89 c8             	mov    rax,rcx
 7d4:	48 c1 e8 30          	shr    rax,0x30
 7d8:	88 42 1e             	mov    BYTE PTR [rdx+0x1e],al
 7db:	48 c1 e9 38          	shr    rcx,0x38
 7df:	88 4a 1f             	mov    BYTE PTR [rdx+0x1f],cl
 7e2:	b8 01 00 00 00       	mov    eax,0x1
 7e7:	48 83 c4 08          	add    rsp,0x8
 7eb:	5b                   	pop    rbx
 7ec:	41 5c                	pop    r12
 7ee:	41 5d                	pop    r13
 7f0:	41 5e                	pop    r14
 7f2:	41 5f                	pop    r15
 7f4:	5d                   	pop    rbp
 7f5:	c3                   	ret
 7f6:	e8 00 00 00 00       	call   7fb <__hia_fn_3+0x1db>
			7f7: R_X86_64_PLT32	abort-0x4
 7fb:	0f 1f 44 00 00       	nop    DWORD PTR [rax+rax*1+0x0]

0000000000000800 <ovpn_hia_packet_id_read>:
 800:	48 b8 00 00 00 00 01 	movabs rax,0x100000000
 807:	00 00 00 
 80a:	48 81 fe 01 00 01 00 	cmp    rsi,0x10001
 811:	0f 83 a2 00 00 00    	jae    8b9 <ovpn_hia_packet_id_read+0xb9>
 817:	49 ba 00 00 00 00 02 	movabs r10,0x200000000
 81e:	00 00 00 
 821:	48 85 f6             	test   rsi,rsi
 824:	41 0f 95 c1          	setne  r9b
 828:	48 85 ff             	test   rdi,rdi
 82b:	41 0f 94 c3          	sete   r11b
 82f:	45 84 cb             	test   r11b,r9b
 832:	75 16                	jne    84a <ovpn_hia_packet_id_read+0x4a>
 834:	49 bb 00 00 00 00 03 	movabs r11,0x300000000
 83b:	00 00 00 
 83e:	49 89 f1             	mov    r9,rsi
 841:	49 01 f9             	add    r9,rdi
 844:	73 08                	jae    84e <ovpn_hia_packet_id_read+0x4e>
 846:	4c 89 d8             	mov    rax,r11
 849:	c3                   	ret
 84a:	4c 89 d0             	mov    rax,r10
 84d:	c3                   	ret
 84e:	48 81 f9 00 00 01 00 	cmp    rcx,0x10000
 855:	77 62                	ja     8b9 <ovpn_hia_packet_id_read+0xb9>
 857:	55                   	push   rbp
 858:	53                   	push   rbx
 859:	50                   	push   rax
 85a:	48 85 c9             	test   rcx,rcx
 85d:	0f 95 c3             	setne  bl
 860:	48 85 d2             	test   rdx,rdx
 863:	40 0f 94 c5          	sete   bpl
 867:	4c 89 d0             	mov    rax,r10
 86a:	40 84 dd             	test   bpl,bl
 86d:	75 44                	jne    8b3 <ovpn_hia_packet_id_read+0xb3>
 86f:	49 89 ca             	mov    r10,rcx
 872:	4c 89 d8             	mov    rax,r11
 875:	49 01 d2             	add    r10,rdx
 878:	72 39                	jb     8b3 <ovpn_hia_packet_id_read+0xb3>
 87a:	48 85 c9             	test   rcx,rcx
 87d:	0f 95 c0             	setne  al
 880:	48 85 f6             	test   rsi,rsi
 883:	41 0f 95 c3          	setne  r11b
 887:	49 39 d1             	cmp    r9,rdx
 88a:	41 0f 97 c1          	seta   r9b
 88e:	49 39 fa             	cmp    r10,rdi
 891:	41 0f 97 c2          	seta   r10b
 895:	45 20 ca             	and    r10b,r9b
 898:	41 20 c2             	and    r10b,al
 89b:	45 84 da             	test   r10b,r11b
 89e:	75 09                	jne    8a9 <ovpn_hia_packet_id_read+0xa9>
 8a0:	e8 5b f7 ff ff       	call   0 <__hia_fn_0>
 8a5:	89 c0                	mov    eax,eax
 8a7:	eb 0a                	jmp    8b3 <ovpn_hia_packet_id_read+0xb3>
 8a9:	48 b8 00 00 00 00 04 	movabs rax,0x400000000
 8b0:	00 00 00 
 8b3:	48 83 c4 08          	add    rsp,0x8
 8b7:	5b                   	pop    rbx
 8b8:	5d                   	pop    rbp
 8b9:	c3                   	ret
 8ba:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]

00000000000008c0 <ovpn_hia_packet_id_write>:
 8c0:	48 b8 00 00 00 00 01 	movabs rax,0x100000000
 8c7:	00 00 00 
 8ca:	48 81 fe 01 00 01 00 	cmp    rsi,0x10001
 8d1:	73 46                	jae    919 <ovpn_hia_packet_id_write+0x59>
 8d3:	55                   	push   rbp
 8d4:	41 56                	push   r14
 8d6:	53                   	push   rbx
 8d7:	48 83 ec 10          	sub    rsp,0x10
 8db:	49 bb 00 00 00 00 02 	movabs r11,0x200000000
 8e2:	00 00 00 
 8e5:	48 85 f6             	test   rsi,rsi
 8e8:	41 0f 95 c2          	setne  r10b
 8ec:	48 85 ff             	test   rdi,rdi
 8ef:	0f 94 c3             	sete   bl
 8f2:	44 84 d3             	test   bl,r10b
 8f5:	75 17                	jne    90e <ovpn_hia_packet_id_write+0x4e>
 8f7:	48 bb 00 00 00 00 03 	movabs rbx,0x300000000
 8fe:	00 00 00 
 901:	49 89 f2             	mov    r10,rsi
 904:	49 01 fa             	add    r10,rdi
 907:	73 11                	jae    91a <ovpn_hia_packet_id_write+0x5a>
 909:	48 89 d8             	mov    rax,rbx
 90c:	eb 03                	jmp    911 <ovpn_hia_packet_id_write+0x51>
 90e:	4c 89 d8             	mov    rax,r11
 911:	48 83 c4 10          	add    rsp,0x10
 915:	5b                   	pop    rbx
 916:	41 5e                	pop    r14
 918:	5d                   	pop    rbp
 919:	c3                   	ret
 91a:	48 81 f9 00 00 01 00 	cmp    rcx,0x10000
 921:	77 ee                	ja     911 <ovpn_hia_packet_id_write+0x51>
 923:	48 85 c9             	test   rcx,rcx
 926:	40 0f 95 c5          	setne  bpl
 92a:	48 85 d2             	test   rdx,rdx
 92d:	41 0f 94 c6          	sete   r14b
 931:	4c 89 d8             	mov    rax,r11
 934:	41 84 ee             	test   r14b,bpl
 937:	75 d8                	jne    911 <ovpn_hia_packet_id_write+0x51>
 939:	49 89 cb             	mov    r11,rcx
 93c:	48 89 d8             	mov    rax,rbx
 93f:	49 01 d3             	add    r11,rdx
 942:	72 cd                	jb     911 <ovpn_hia_packet_id_write+0x51>
 944:	48 85 c9             	test   rcx,rcx
 947:	0f 95 c0             	setne  al
 94a:	48 85 f6             	test   rsi,rsi
 94d:	0f 95 c3             	setne  bl
 950:	49 39 d2             	cmp    r10,rdx
 953:	41 0f 97 c2          	seta   r10b
 957:	49 39 fb             	cmp    r11,rdi
 95a:	41 0f 97 c3          	seta   r11b
 95e:	45 20 d3             	and    r11b,r10b
 961:	41 20 c3             	and    r11b,al
 964:	41 84 db             	test   r11b,bl
 967:	75 10                	jne    979 <ovpn_hia_packet_id_write+0xb9>
 969:	8b 44 24 30          	mov    eax,DWORD PTR [rsp+0x30]
 96d:	89 04 24             	mov    DWORD PTR [rsp],eax
 970:	e8 fb f7 ff ff       	call   170 <__hia_fn_1>
 975:	89 c0                	mov    eax,eax
 977:	eb 98                	jmp    911 <ovpn_hia_packet_id_write+0x51>
 979:	48 b8 00 00 00 00 04 	movabs rax,0x400000000
 980:	00 00 00 
 983:	eb 8c                	jmp    911 <ovpn_hia_packet_id_write+0x51>
 985:	66 66 2e 0f 1f 84 00 	data16 cs nop WORD PTR [rax+rax*1+0x0]
 98c:	00 00 00 00 

0000000000000990 <ovpn_hia_packet_id_read_epoch>:
 990:	48 b8 00 00 00 00 01 	movabs rax,0x100000000
 997:	00 00 00 
 99a:	48 81 fe 01 00 01 00 	cmp    rsi,0x10001
 9a1:	0f 83 9b 00 00 00    	jae    a42 <ovpn_hia_packet_id_read_epoch+0xb2>
 9a7:	49 b9 00 00 00 00 02 	movabs r9,0x200000000
 9ae:	00 00 00 
 9b1:	48 85 f6             	test   rsi,rsi
 9b4:	41 0f 95 c0          	setne  r8b
 9b8:	48 85 ff             	test   rdi,rdi
 9bb:	41 0f 94 c2          	sete   r10b
 9bf:	45 84 c2             	test   r10b,r8b
 9c2:	75 16                	jne    9da <ovpn_hia_packet_id_read_epoch+0x4a>
 9c4:	49 ba 00 00 00 00 03 	movabs r10,0x300000000
 9cb:	00 00 00 
 9ce:	49 89 f0             	mov    r8,rsi
 9d1:	49 01 f8             	add    r8,rdi
 9d4:	73 08                	jae    9de <ovpn_hia_packet_id_read_epoch+0x4e>
 9d6:	4c 89 d0             	mov    rax,r10
 9d9:	c3                   	ret
 9da:	4c 89 c8             	mov    rax,r9
 9dd:	c3                   	ret
 9de:	48 81 f9 00 00 01 00 	cmp    rcx,0x10000
 9e5:	77 5b                	ja     a42 <ovpn_hia_packet_id_read_epoch+0xb2>
 9e7:	53                   	push   rbx
 9e8:	48 85 c9             	test   rcx,rcx
 9eb:	41 0f 95 c3          	setne  r11b
 9ef:	48 85 d2             	test   rdx,rdx
 9f2:	0f 94 c3             	sete   bl
 9f5:	4c 89 c8             	mov    rax,r9
 9f8:	44 84 db             	test   bl,r11b
 9fb:	75 44                	jne    a41 <ovpn_hia_packet_id_read_epoch+0xb1>
 9fd:	49 89 c9             	mov    r9,rcx
 a00:	4c 89 d0             	mov    rax,r10
 a03:	49 01 d1             	add    r9,rdx
 a06:	72 39                	jb     a41 <ovpn_hia_packet_id_read_epoch+0xb1>
 a08:	48 85 c9             	test   rcx,rcx
 a0b:	0f 95 c0             	setne  al
 a0e:	48 85 f6             	test   rsi,rsi
 a11:	41 0f 95 c2          	setne  r10b
 a15:	49 39 d0             	cmp    r8,rdx
 a18:	41 0f 97 c0          	seta   r8b
 a1c:	49 39 f9             	cmp    r9,rdi
 a1f:	41 0f 97 c1          	seta   r9b
 a23:	45 20 c1             	and    r9b,r8b
 a26:	41 20 c1             	and    r9b,al
 a29:	45 84 d1             	test   r9b,r10b
 a2c:	75 09                	jne    a37 <ovpn_hia_packet_id_read_epoch+0xa7>
 a2e:	e8 dd fa ff ff       	call   510 <__hia_fn_2>
 a33:	89 c0                	mov    eax,eax
 a35:	eb 0a                	jmp    a41 <ovpn_hia_packet_id_read_epoch+0xb1>
 a37:	48 b8 00 00 00 00 04 	movabs rax,0x400000000
 a3e:	00 00 00 
 a41:	5b                   	pop    rbx
 a42:	c3                   	ret
 a43:	66 66 66 66 2e 0f 1f 	data16 data16 data16 cs nop WORD PTR [rax+rax*1+0x0]
 a4a:	84 00 00 00 00 00 

0000000000000a50 <ovpn_hia_packet_id_write_epoch>:
 a50:	48 b8 00 00 00 00 01 	movabs rax,0x100000000
 a57:	00 00 00 
 a5a:	48 81 fe 01 00 01 00 	cmp    rsi,0x10001
 a61:	73 3e                	jae    aa1 <ovpn_hia_packet_id_write_epoch+0x51>
 a63:	55                   	push   rbp
 a64:	41 56                	push   r14
 a66:	53                   	push   rbx
 a67:	49 bb 00 00 00 00 02 	movabs r11,0x200000000
 a6e:	00 00 00 
 a71:	48 85 f6             	test   rsi,rsi
 a74:	41 0f 95 c2          	setne  r10b
 a78:	48 85 ff             	test   rdi,rdi
 a7b:	0f 94 c3             	sete   bl
 a7e:	44 84 d3             	test   bl,r10b
 a81:	75 17                	jne    a9a <ovpn_hia_packet_id_write_epoch+0x4a>
 a83:	48 bb 00 00 00 00 03 	movabs rbx,0x300000000
 a8a:	00 00 00 
 a8d:	49 89 f2             	mov    r10,rsi
 a90:	49 01 fa             	add    r10,rdi
 a93:	73 0d                	jae    aa2 <ovpn_hia_packet_id_write_epoch+0x52>
 a95:	48 89 d8             	mov    rax,rbx
 a98:	eb 03                	jmp    a9d <ovpn_hia_packet_id_write_epoch+0x4d>
 a9a:	4c 89 d8             	mov    rax,r11
 a9d:	5b                   	pop    rbx
 a9e:	41 5e                	pop    r14
 aa0:	5d                   	pop    rbp
 aa1:	c3                   	ret
 aa2:	48 81 f9 00 00 01 00 	cmp    rcx,0x10000
 aa9:	77 f2                	ja     a9d <ovpn_hia_packet_id_write_epoch+0x4d>
 aab:	48 85 c9             	test   rcx,rcx
 aae:	40 0f 95 c5          	setne  bpl
 ab2:	48 85 d2             	test   rdx,rdx
 ab5:	41 0f 94 c6          	sete   r14b
 ab9:	4c 89 d8             	mov    rax,r11
 abc:	41 84 ee             	test   r14b,bpl
 abf:	75 dc                	jne    a9d <ovpn_hia_packet_id_write_epoch+0x4d>
 ac1:	49 89 cb             	mov    r11,rcx
 ac4:	48 89 d8             	mov    rax,rbx
 ac7:	49 01 d3             	add    r11,rdx
 aca:	72 d1                	jb     a9d <ovpn_hia_packet_id_write_epoch+0x4d>
 acc:	48 85 c9             	test   rcx,rcx
 acf:	0f 95 c0             	setne  al
 ad2:	48 85 f6             	test   rsi,rsi
 ad5:	0f 95 c3             	setne  bl
 ad8:	49 39 d2             	cmp    r10,rdx
 adb:	41 0f 97 c2          	seta   r10b
 adf:	49 39 fb             	cmp    r11,rdi
 ae2:	41 0f 97 c3          	seta   r11b
 ae6:	45 20 d3             	and    r11b,r10b
 ae9:	41 20 c3             	and    r11b,al
 aec:	41 84 db             	test   r11b,bl
 aef:	75 09                	jne    afa <ovpn_hia_packet_id_write_epoch+0xaa>
 af1:	e8 2a fb ff ff       	call   620 <__hia_fn_3>
 af6:	89 c0                	mov    eax,eax
 af8:	eb a3                	jmp    a9d <ovpn_hia_packet_id_write_epoch+0x4d>
 afa:	48 b8 00 00 00 00 04 	movabs rax,0x400000000
 b01:	00 00 00 
 b04:	eb 97                	jmp    a9d <ovpn_hia_packet_id_write_epoch+0x4d>
