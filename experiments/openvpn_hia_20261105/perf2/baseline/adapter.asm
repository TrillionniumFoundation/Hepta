
/workspace/scratch/2719a9027f80/packet-run-final4/adapter.o:     file format elf64-x86-64


Disassembly of section .text.hia_packet_id_read:

0000000000000000 <hia_packet_id_read>:
   0:	48 85 ff             	test   rdi,rdi
   3:	0f 94 c0             	sete   al
   6:	48 83 ff f0          	cmp    rdi,0xfffffffffffffff0
   a:	0f 93 c1             	setae  cl
   d:	08 c1                	or     cl,al
   f:	0f 85 27 01 00 00    	jne    13c <hia_packet_id_read+0x13c>
  15:	48 85 f6             	test   rsi,rsi
  18:	0f 94 c0             	sete   al
  1b:	48 83 fe e8          	cmp    rsi,0xffffffffffffffe8
  1f:	0f 93 c1             	setae  cl
  22:	08 c1                	or     cl,al
  24:	0f 85 12 01 00 00    	jne    13c <hia_packet_id_read+0x13c>
  2a:	89 f0                	mov    eax,esi
  2c:	09 f8                	or     eax,edi
  2e:	a8 07                	test   al,0x7
  30:	0f 85 06 01 00 00    	jne    13c <hia_packet_id_read+0x13c>
  36:	4c 8d 57 10          	lea    r10,[rdi+0x10]
  3a:	48 8d 4e 18          	lea    rcx,[rsi+0x18]
  3e:	48 39 f9             	cmp    rcx,rdi
  41:	0f 97 c0             	seta   al
  44:	49 39 f2             	cmp    r10,rsi
  47:	41 0f 97 c0          	seta   r8b
  4b:	41 84 c0             	test   r8b,al
  4e:	0f 85 e8 00 00 00    	jne    13c <hia_packet_id_read+0x13c>
  54:	8b 06                	mov    eax,DWORD PTR [rsi]
  56:	48 3d 00 00 01 00    	cmp    rax,0x10000
  5c:	0f 87 da 00 00 00    	ja     13c <hia_packet_id_read+0x13c>
  62:	4c 63 46 04          	movsxd r8,DWORD PTR [rsi+0x4]
  66:	4d 85 c0             	test   r8,r8
  69:	0f 88 cd 00 00 00    	js     13c <hia_packet_id_read+0x13c>
  6f:	55                   	push   rbp
  70:	41 56                	push   r14
  72:	53                   	push   rbx
  73:	48 83 ec 20          	sub    rsp,0x20
  77:	44 8b 5e 08          	mov    r11d,DWORD PTR [rsi+0x8]
  7b:	45 85 db             	test   r11d,r11d
  7e:	41 0f 98 c1          	sets   r9b
  82:	89 c3                	mov    ebx,eax
  84:	44 29 c3             	sub    ebx,r8d
  87:	40 0f 92 c5          	setb   bpl
  8b:	44 08 cd             	or     bpl,r9b
  8e:	41 39 db             	cmp    r11d,ebx
  91:	41 0f 9f c1          	setg   r9b
  95:	41 08 e9             	or     r9b,bpl
  98:	0f 85 a1 00 00 00    	jne    13f <hia_packet_id_read+0x13f>
  9e:	4c 8b 4e 10          	mov    r9,QWORD PTR [rsi+0x10]
  a2:	48 85 c0             	test   rax,rax
  a5:	0f 95 c3             	setne  bl
  a8:	4d 85 c9             	test   r9,r9
  ab:	40 0f 94 c5          	sete   bpl
  af:	40 84 eb             	test   bl,bpl
  b2:	0f 85 87 00 00 00    	jne    13f <hia_packet_id_read+0x13f>
  b8:	4c 89 cb             	mov    rbx,r9
  bb:	48 01 c3             	add    rbx,rax
  be:	72 7f                	jb     13f <hia_packet_id_read+0x13f>
  c0:	48 85 c0             	test   rax,rax
  c3:	74 25                	je     ea <hia_packet_id_read+0xea>
  c5:	48 39 fb             	cmp    rbx,rdi
  c8:	40 0f 97 c5          	seta   bpl
  cc:	4d 39 ca             	cmp    r10,r9
  cf:	41 0f 97 c2          	seta   r10b
  d3:	41 84 ea             	test   r10b,bpl
  d6:	75 67                	jne    13f <hia_packet_id_read+0x13f>
  d8:	48 39 f3             	cmp    rbx,rsi
  db:	41 0f 97 c2          	seta   r10b
  df:	4c 39 c9             	cmp    rcx,r9
  e2:	0f 97 c1             	seta   cl
  e5:	44 84 d1             	test   cl,r10b
  e8:	75 55                	jne    13f <hia_packet_id_read+0x13f>
  ea:	49 89 fe             	mov    r14,rdi
  ed:	48 89 f3             	mov    rbx,rsi
  f0:	44 89 d9             	mov    ecx,r11d
  f3:	66 0f ef c0          	pxor   xmm0,xmm0
  f7:	66 0f 7f 04 24       	movdqa XMMWORD PTR [rsp],xmm0
  fc:	4c 89 44 24 10       	mov    QWORD PTR [rsp+0x10],r8
 101:	48 89 4c 24 18       	mov    QWORD PTR [rsp+0x18],rcx
 106:	44 0f b6 c2          	movzx  r8d,dl
 10a:	48 89 e2             	mov    rdx,rsp
 10d:	b9 20 00 00 00       	mov    ecx,0x20
 112:	4c 89 cf             	mov    rdi,r9
 115:	48 89 c6             	mov    rsi,rax
 118:	e8 00 00 00 00       	call   11d <hia_packet_id_read+0x11d>
			119: R_X86_64_PLT32	ovpn_hia_packet_id_read-0x4
 11d:	48 83 f8 01          	cmp    rax,0x1
 121:	77 1c                	ja     13f <hia_packet_id_read+0x13f>
 123:	0f 28 04 24          	movaps xmm0,XMMWORD PTR [rsp]
 127:	41 0f 11 06          	movups XMMWORD PTR [r14],xmm0
 12b:	66 0f 70 44 24 10 e8 	pshufd xmm0,XMMWORD PTR [rsp+0x10],0xe8
 132:	66 0f d6 43 04       	movq   QWORD PTR [rbx+0x4],xmm0
 137:	0f 94 c0             	sete   al
 13a:	eb 05                	jmp    141 <hia_packet_id_read+0x141>
 13c:	31 c0                	xor    eax,eax
 13e:	c3                   	ret
 13f:	31 c0                	xor    eax,eax
 141:	48 83 c4 20          	add    rsp,0x20
 145:	5b                   	pop    rbx
 146:	41 5e                	pop    r14
 148:	5d                   	pop    rbp
 149:	c3                   	ret

Disassembly of section .text.hia_packet_id_write:

0000000000000000 <hia_packet_id_write>:
   0:	48 85 ff             	test   rdi,rdi
   3:	0f 94 c0             	sete   al
   6:	48 83 ff f0          	cmp    rdi,0xfffffffffffffff0
   a:	41 0f 93 c0          	setae  r8b
   e:	41 08 c0             	or     r8b,al
  11:	0f 85 3f 01 00 00    	jne    156 <hia_packet_id_write+0x156>
  17:	48 85 f6             	test   rsi,rsi
  1a:	0f 94 c0             	sete   al
  1d:	48 83 fe e8          	cmp    rsi,0xffffffffffffffe8
  21:	41 0f 93 c0          	setae  r8b
  25:	41 08 c0             	or     r8b,al
  28:	0f 85 28 01 00 00    	jne    156 <hia_packet_id_write+0x156>
  2e:	89 f0                	mov    eax,esi
  30:	09 f8                	or     eax,edi
  32:	a8 07                	test   al,0x7
  34:	0f 85 1c 01 00 00    	jne    156 <hia_packet_id_write+0x156>
  3a:	4c 8d 5f 10          	lea    r11,[rdi+0x10]
  3e:	4c 8d 46 18          	lea    r8,[rsi+0x18]
  42:	49 39 f8             	cmp    r8,rdi
  45:	0f 97 c0             	seta   al
  48:	49 39 f3             	cmp    r11,rsi
  4b:	41 0f 97 c1          	seta   r9b
  4f:	41 84 c1             	test   r9b,al
  52:	0f 85 fe 00 00 00    	jne    156 <hia_packet_id_write+0x156>
  58:	8b 06                	mov    eax,DWORD PTR [rsi]
  5a:	48 3d 00 00 01 00    	cmp    rax,0x10000
  60:	0f 87 f0 00 00 00    	ja     156 <hia_packet_id_write+0x156>
  66:	4c 63 4e 04          	movsxd r9,DWORD PTR [rsi+0x4]
  6a:	4d 85 c9             	test   r9,r9
  6d:	0f 88 e3 00 00 00    	js     156 <hia_packet_id_write+0x156>
  73:	55                   	push   rbp
  74:	41 56                	push   r14
  76:	53                   	push   rbx
  77:	48 83 ec 30          	sub    rsp,0x30
  7b:	8b 5e 08             	mov    ebx,DWORD PTR [rsi+0x8]
  7e:	85 db                	test   ebx,ebx
  80:	41 0f 98 c2          	sets   r10b
  84:	89 c5                	mov    ebp,eax
  86:	44 29 cd             	sub    ebp,r9d
  89:	41 0f 92 c6          	setb   r14b
  8d:	45 08 d6             	or     r14b,r10b
  90:	39 eb                	cmp    ebx,ebp
  92:	41 0f 9f c2          	setg   r10b
  96:	45 08 f2             	or     r10b,r14b
  99:	0f 85 ba 00 00 00    	jne    159 <hia_packet_id_write+0x159>
  9f:	4c 8b 56 10          	mov    r10,QWORD PTR [rsi+0x10]
  a3:	48 85 c0             	test   rax,rax
  a6:	40 0f 95 c5          	setne  bpl
  aa:	4d 85 d2             	test   r10,r10
  ad:	41 0f 94 c6          	sete   r14b
  b1:	44 84 f5             	test   bpl,r14b
  b4:	0f 85 9f 00 00 00    	jne    159 <hia_packet_id_write+0x159>
  ba:	4d 89 d6             	mov    r14,r10
  bd:	49 01 c6             	add    r14,rax
  c0:	0f 82 93 00 00 00    	jb     159 <hia_packet_id_write+0x159>
  c6:	48 85 c0             	test   rax,rax
  c9:	74 26                	je     f1 <hia_packet_id_write+0xf1>
  cb:	49 39 fe             	cmp    r14,rdi
  ce:	40 0f 97 c5          	seta   bpl
  d2:	4d 39 d3             	cmp    r11,r10
  d5:	41 0f 97 c3          	seta   r11b
  d9:	41 84 eb             	test   r11b,bpl
  dc:	75 7b                	jne    159 <hia_packet_id_write+0x159>
  de:	49 39 f6             	cmp    r14,rsi
  e1:	41 0f 97 c3          	seta   r11b
  e5:	4d 39 d0             	cmp    r8,r10
  e8:	41 0f 97 c0          	seta   r8b
  ec:	45 84 d8             	test   r8b,r11b
  ef:	75 68                	jne    159 <hia_packet_id_write+0x159>
  f1:	49 89 f6             	mov    r14,rsi
  f4:	89 de                	mov    esi,ebx
  f6:	48 89 fb             	mov    rbx,rdi
  f9:	f3 0f 6f 07          	movdqu xmm0,XMMWORD PTR [rdi]
  fd:	66 0f 7f 44 24 10    	movdqa XMMWORD PTR [rsp+0x10],xmm0
 103:	4c 89 4c 24 20       	mov    QWORD PTR [rsp+0x20],r9
 108:	48 89 74 24 28       	mov    QWORD PTR [rsp+0x28],rsi
 10d:	48 8b 35 00 00 00 00 	mov    rsi,QWORD PTR [rip+0x0]        # 114 <hia_packet_id_write+0x114>
			110: R_X86_64_REX_GOTPCRELX	now-0x4
 114:	4c 8b 06             	mov    r8,QWORD PTR [rsi]
 117:	44 0f b6 ca          	movzx  r9d,dl
 11b:	0f b6 c9             	movzx  ecx,cl
 11e:	89 0c 24             	mov    DWORD PTR [rsp],ecx
 121:	48 8d 54 24 10       	lea    rdx,[rsp+0x10]
 126:	b9 20 00 00 00       	mov    ecx,0x20
 12b:	4c 89 d7             	mov    rdi,r10
 12e:	48 89 c6             	mov    rsi,rax
 131:	e8 00 00 00 00       	call   136 <hia_packet_id_write+0x136>
			132: R_X86_64_PLT32	ovpn_hia_packet_id_write-0x4
 136:	48 83 f8 01          	cmp    rax,0x1
 13a:	77 1d                	ja     159 <hia_packet_id_write+0x159>
 13c:	0f 28 44 24 10       	movaps xmm0,XMMWORD PTR [rsp+0x10]
 141:	0f 11 03             	movups XMMWORD PTR [rbx],xmm0
 144:	66 0f 70 44 24 20 e8 	pshufd xmm0,XMMWORD PTR [rsp+0x20],0xe8
 14b:	66 41 0f d6 46 04    	movq   QWORD PTR [r14+0x4],xmm0
 151:	0f 94 c0             	sete   al
 154:	eb 05                	jmp    15b <hia_packet_id_write+0x15b>
 156:	31 c0                	xor    eax,eax
 158:	c3                   	ret
 159:	31 c0                	xor    eax,eax
 15b:	48 83 c4 30          	add    rsp,0x30
 15f:	5b                   	pop    rbx
 160:	41 5e                	pop    r14
 162:	5d                   	pop    rbp
 163:	c3                   	ret

Disassembly of section .text.hia_packet_id_read_epoch:

0000000000000000 <hia_packet_id_read_epoch>:
   0:	48 85 ff             	test   rdi,rdi
   3:	0f 94 c0             	sete   al
   6:	48 83 ff f0          	cmp    rdi,0xfffffffffffffff0
   a:	0f 93 c1             	setae  cl
   d:	08 c1                	or     cl,al
   f:	0f 85 25 01 00 00    	jne    13a <hia_packet_id_read_epoch+0x13a>
  15:	48 85 f6             	test   rsi,rsi
  18:	0f 94 c0             	sete   al
  1b:	48 83 fe e8          	cmp    rsi,0xffffffffffffffe8
  1f:	0f 93 c1             	setae  cl
  22:	08 c1                	or     cl,al
  24:	0f 85 10 01 00 00    	jne    13a <hia_packet_id_read_epoch+0x13a>
  2a:	89 f0                	mov    eax,esi
  2c:	09 f8                	or     eax,edi
  2e:	a8 07                	test   al,0x7
  30:	0f 85 04 01 00 00    	jne    13a <hia_packet_id_read_epoch+0x13a>
  36:	4c 8d 4f 10          	lea    r9,[rdi+0x10]
  3a:	48 8d 4e 18          	lea    rcx,[rsi+0x18]
  3e:	48 39 f9             	cmp    rcx,rdi
  41:	0f 97 c0             	seta   al
  44:	49 39 f1             	cmp    r9,rsi
  47:	0f 97 c2             	seta   dl
  4a:	84 c2                	test   dl,al
  4c:	0f 85 e8 00 00 00    	jne    13a <hia_packet_id_read_epoch+0x13a>
  52:	8b 06                	mov    eax,DWORD PTR [rsi]
  54:	48 3d 00 00 01 00    	cmp    rax,0x10000
  5a:	0f 87 da 00 00 00    	ja     13a <hia_packet_id_read_epoch+0x13a>
  60:	48 63 56 04          	movsxd rdx,DWORD PTR [rsi+0x4]
  64:	48 85 d2             	test   rdx,rdx
  67:	0f 88 cd 00 00 00    	js     13a <hia_packet_id_read_epoch+0x13a>
  6d:	41 57                	push   r15
  6f:	41 56                	push   r14
  71:	53                   	push   rbx
  72:	48 83 ec 20          	sub    rsp,0x20
  76:	44 8b 56 08          	mov    r10d,DWORD PTR [rsi+0x8]
  7a:	45 85 d2             	test   r10d,r10d
  7d:	41 0f 98 c0          	sets   r8b
  81:	41 89 c3             	mov    r11d,eax
  84:	41 29 d3             	sub    r11d,edx
  87:	0f 92 c3             	setb   bl
  8a:	44 08 c3             	or     bl,r8b
  8d:	45 39 da             	cmp    r10d,r11d
  90:	41 0f 9f c0          	setg   r8b
  94:	41 08 d8             	or     r8b,bl
  97:	0f 85 a0 00 00 00    	jne    13d <hia_packet_id_read_epoch+0x13d>
  9d:	4c 8b 46 10          	mov    r8,QWORD PTR [rsi+0x10]
  a1:	48 85 c0             	test   rax,rax
  a4:	41 0f 95 c3          	setne  r11b
  a8:	4d 85 c0             	test   r8,r8
  ab:	0f 94 c3             	sete   bl
  ae:	41 84 db             	test   r11b,bl
  b1:	0f 85 86 00 00 00    	jne    13d <hia_packet_id_read_epoch+0x13d>
  b7:	4d 89 c3             	mov    r11,r8
  ba:	49 01 c3             	add    r11,rax
  bd:	72 7e                	jb     13d <hia_packet_id_read_epoch+0x13d>
  bf:	48 85 c0             	test   rax,rax
  c2:	74 24                	je     e8 <hia_packet_id_read_epoch+0xe8>
  c4:	49 39 fb             	cmp    r11,rdi
  c7:	0f 97 c3             	seta   bl
  ca:	4d 39 c1             	cmp    r9,r8
  cd:	41 0f 97 c1          	seta   r9b
  d1:	41 84 d9             	test   r9b,bl
  d4:	75 67                	jne    13d <hia_packet_id_read_epoch+0x13d>
  d6:	49 39 f3             	cmp    r11,rsi
  d9:	41 0f 97 c1          	seta   r9b
  dd:	4c 39 c1             	cmp    rcx,r8
  e0:	0f 97 c1             	seta   cl
  e3:	44 84 c9             	test   cl,r9b
  e6:	75 55                	jne    13d <hia_packet_id_read_epoch+0x13d>
  e8:	49 89 fe             	mov    r14,rdi
  eb:	48 89 f3             	mov    rbx,rsi
  ee:	45 89 d7             	mov    r15d,r10d
  f1:	66 0f ef c0          	pxor   xmm0,xmm0
  f5:	66 0f 7f 04 24       	movdqa XMMWORD PTR [rsp],xmm0
  fa:	48 89 54 24 10       	mov    QWORD PTR [rsp+0x10],rdx
  ff:	4c 89 7c 24 18       	mov    QWORD PTR [rsp+0x18],r15
 104:	48 89 e2             	mov    rdx,rsp
 107:	b9 20 00 00 00       	mov    ecx,0x20
 10c:	4c 89 c7             	mov    rdi,r8
 10f:	48 89 c6             	mov    rsi,rax
 112:	e8 00 00 00 00       	call   117 <hia_packet_id_read_epoch+0x117>
			113: R_X86_64_PLT32	ovpn_hia_packet_id_read_epoch-0x4
 117:	48 3d ff ff 00 00    	cmp    rax,0xffff
 11d:	77 1e                	ja     13d <hia_packet_id_read_epoch+0x13d>
 11f:	41 83 ff 08          	cmp    r15d,0x8
 123:	72 07                	jb     12c <hia_packet_id_read_epoch+0x12c>
 125:	48 8b 0c 24          	mov    rcx,QWORD PTR [rsp]
 129:	49 89 0e             	mov    QWORD PTR [r14],rcx
 12c:	66 0f 70 44 24 10 e8 	pshufd xmm0,XMMWORD PTR [rsp+0x10],0xe8
 133:	66 0f d6 43 04       	movq   QWORD PTR [rbx+0x4],xmm0
 138:	eb 05                	jmp    13f <hia_packet_id_read_epoch+0x13f>
 13a:	31 c0                	xor    eax,eax
 13c:	c3                   	ret
 13d:	31 c0                	xor    eax,eax
 13f:	48 83 c4 20          	add    rsp,0x20
 143:	5b                   	pop    rbx
 144:	41 5e                	pop    r14
 146:	41 5f                	pop    r15
 148:	c3                   	ret

Disassembly of section .text.hia_packet_id_write_epoch:

0000000000000000 <hia_packet_id_write_epoch>:
   0:	48 85 ff             	test   rdi,rdi
   3:	0f 94 c0             	sete   al
   6:	48 83 ff f0          	cmp    rdi,0xfffffffffffffff0
   a:	0f 93 c1             	setae  cl
   d:	08 c1                	or     cl,al
   f:	0f 85 35 01 00 00    	jne    14a <hia_packet_id_write_epoch+0x14a>
  15:	48 85 d2             	test   rdx,rdx
  18:	0f 94 c0             	sete   al
  1b:	48 83 fa e8          	cmp    rdx,0xffffffffffffffe8
  1f:	0f 93 c1             	setae  cl
  22:	08 c1                	or     cl,al
  24:	0f 85 20 01 00 00    	jne    14a <hia_packet_id_write_epoch+0x14a>
  2a:	89 d0                	mov    eax,edx
  2c:	09 f8                	or     eax,edi
  2e:	a8 07                	test   al,0x7
  30:	0f 85 14 01 00 00    	jne    14a <hia_packet_id_write_epoch+0x14a>
  36:	4c 8d 4f 10          	lea    r9,[rdi+0x10]
  3a:	48 8d 4a 18          	lea    rcx,[rdx+0x18]
  3e:	48 39 f9             	cmp    rcx,rdi
  41:	0f 97 c0             	seta   al
  44:	49 39 d1             	cmp    r9,rdx
  47:	41 0f 97 c0          	seta   r8b
  4b:	41 84 c0             	test   r8b,al
  4e:	0f 85 f6 00 00 00    	jne    14a <hia_packet_id_write_epoch+0x14a>
  54:	8b 02                	mov    eax,DWORD PTR [rdx]
  56:	48 3d 00 00 01 00    	cmp    rax,0x10000
  5c:	0f 87 e8 00 00 00    	ja     14a <hia_packet_id_write_epoch+0x14a>
  62:	4c 63 42 04          	movsxd r8,DWORD PTR [rdx+0x4]
  66:	4d 85 c0             	test   r8,r8
  69:	0f 88 db 00 00 00    	js     14a <hia_packet_id_write_epoch+0x14a>
  6f:	55                   	push   rbp
  70:	41 56                	push   r14
  72:	53                   	push   rbx
  73:	48 83 ec 20          	sub    rsp,0x20
  77:	44 8b 5a 08          	mov    r11d,DWORD PTR [rdx+0x8]
  7b:	45 85 db             	test   r11d,r11d
  7e:	41 0f 98 c2          	sets   r10b
  82:	89 c3                	mov    ebx,eax
  84:	44 29 c3             	sub    ebx,r8d
  87:	40 0f 92 c5          	setb   bpl
  8b:	44 08 d5             	or     bpl,r10b
  8e:	41 39 db             	cmp    r11d,ebx
  91:	41 0f 9f c2          	setg   r10b
  95:	41 08 ea             	or     r10b,bpl
  98:	0f 85 af 00 00 00    	jne    14d <hia_packet_id_write_epoch+0x14d>
  9e:	4c 8b 52 10          	mov    r10,QWORD PTR [rdx+0x10]
  a2:	48 85 c0             	test   rax,rax
  a5:	0f 95 c3             	setne  bl
  a8:	4d 85 d2             	test   r10,r10
  ab:	40 0f 94 c5          	sete   bpl
  af:	40 84 eb             	test   bl,bpl
  b2:	0f 85 95 00 00 00    	jne    14d <hia_packet_id_write_epoch+0x14d>
  b8:	4c 89 d3             	mov    rbx,r10
  bb:	48 01 c3             	add    rbx,rax
  be:	0f 82 89 00 00 00    	jb     14d <hia_packet_id_write_epoch+0x14d>
  c4:	48 85 c0             	test   rax,rax
  c7:	74 25                	je     ee <hia_packet_id_write_epoch+0xee>
  c9:	48 39 fb             	cmp    rbx,rdi
  cc:	40 0f 97 c5          	seta   bpl
  d0:	4d 39 d1             	cmp    r9,r10
  d3:	41 0f 97 c1          	seta   r9b
  d7:	41 84 e9             	test   r9b,bpl
  da:	75 71                	jne    14d <hia_packet_id_write_epoch+0x14d>
  dc:	48 39 d3             	cmp    rbx,rdx
  df:	41 0f 97 c1          	seta   r9b
  e3:	4c 39 d1             	cmp    rcx,r10
  e6:	0f 97 c1             	seta   cl
  e9:	44 84 c9             	test   cl,r9b
  ec:	75 5f                	jne    14d <hia_packet_id_write_epoch+0x14d>
  ee:	48 89 d3             	mov    rbx,rdx
  f1:	44 89 d9             	mov    ecx,r11d
  f4:	49 89 fe             	mov    r14,rdi
  f7:	f3 0f 6f 07          	movdqu xmm0,XMMWORD PTR [rdi]
  fb:	66 0f 7f 04 24       	movdqa XMMWORD PTR [rsp],xmm0
 100:	4c 89 44 24 10       	mov    QWORD PTR [rsp+0x10],r8
 105:	48 89 4c 24 18       	mov    QWORD PTR [rsp+0x18],rcx
 10a:	48 8b 0d 00 00 00 00 	mov    rcx,QWORD PTR [rip+0x0]        # 111 <hia_packet_id_write_epoch+0x111>
			10d: R_X86_64_REX_GOTPCRELX	now-0x4
 111:	4c 8b 01             	mov    r8,QWORD PTR [rcx]
 114:	44 0f b7 ce          	movzx  r9d,si
 118:	48 89 e2             	mov    rdx,rsp
 11b:	b9 20 00 00 00       	mov    ecx,0x20
 120:	4c 89 d7             	mov    rdi,r10
 123:	48 89 c6             	mov    rsi,rax
 126:	e8 00 00 00 00       	call   12b <hia_packet_id_write_epoch+0x12b>
			127: R_X86_64_PLT32	ovpn_hia_packet_id_write_epoch-0x4
 12b:	48 83 f8 01          	cmp    rax,0x1
 12f:	77 1c                	ja     14d <hia_packet_id_write_epoch+0x14d>
 131:	0f 28 04 24          	movaps xmm0,XMMWORD PTR [rsp]
 135:	41 0f 11 06          	movups XMMWORD PTR [r14],xmm0
 139:	66 0f 70 44 24 10 e8 	pshufd xmm0,XMMWORD PTR [rsp+0x10],0xe8
 140:	66 0f d6 43 04       	movq   QWORD PTR [rbx+0x4],xmm0
 145:	0f 94 c0             	sete   al
 148:	eb 05                	jmp    14f <hia_packet_id_write_epoch+0x14f>
 14a:	31 c0                	xor    eax,eax
 14c:	c3                   	ret
 14d:	31 c0                	xor    eax,eax
 14f:	48 83 c4 20          	add    rsp,0x20
 153:	5b                   	pop    rbx
 154:	41 5e                	pop    r14
 156:	5d                   	pop    rbp
 157:	c3                   	ret

Disassembly of section .text.__wrap_packet_id_read:

0000000000000000 <__wrap_packet_id_read>:
   0:	e9 00 00 00 00       	jmp    5 <__wrap_packet_id_read+0x5>
			1: R_X86_64_PLT32	hia_packet_id_read-0x4

Disassembly of section .text.__wrap_packet_id_write:

0000000000000000 <__wrap_packet_id_write>:
   0:	e9 00 00 00 00       	jmp    5 <__wrap_packet_id_write+0x5>
			1: R_X86_64_PLT32	hia_packet_id_write-0x4

Disassembly of section .text.__wrap_packet_id_read_epoch:

0000000000000000 <__wrap_packet_id_read_epoch>:
   0:	e9 00 00 00 00       	jmp    5 <__wrap_packet_id_read_epoch+0x5>
			1: R_X86_64_PLT32	hia_packet_id_read_epoch-0x4

Disassembly of section .text.__wrap_packet_id_write_epoch:

0000000000000000 <__wrap_packet_id_write_epoch>:
   0:	e9 00 00 00 00       	jmp    5 <__wrap_packet_id_write_epoch+0x5>
			1: R_X86_64_PLT32	hia_packet_id_write_epoch-0x4
