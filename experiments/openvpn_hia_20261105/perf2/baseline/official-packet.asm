
/workspace/scratch/2719a9027f80/packet-run-final4/upstream-packet-id.o:     file format elf64-x86-64


Disassembly of section .text.packet_id_init:

0000000000000000 <packet_id_init>:
   0:	55                   	push   rbp
   1:	41 57                	push   r15
   3:	41 56                	push   r14
   5:	41 54                	push   r12
   7:	53                   	push   rbx
   8:	45 89 c7             	mov    r15d,r8d
   b:	49 89 cc             	mov    r12,rcx
   e:	89 d5                	mov    ebp,edx
  10:	41 89 f6             	mov    r14d,esi
  13:	48 89 fb             	mov    rbx,rdi
  16:	48 8b 05 00 00 00 00 	mov    rax,QWORD PTR [rip+0x0]        # 1d <packet_id_init+0x1d>
			19: R_X86_64_REX_GOTPCRELX	x_debug_level-0x4
  1d:	83 38 07             	cmp    DWORD PTR [rax],0x7
  20:	72 26                	jb     48 <packet_id_init+0x48>
  22:	bf 87 00 00 46       	mov    edi,0x46000087
  27:	e8 00 00 00 00       	call   2c <packet_id_init+0x2c>
			28: R_X86_64_PLT32	dont_mute-0x4
  2c:	84 c0                	test   al,al
  2e:	74 18                	je     48 <packet_id_init+0x48>
  30:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 37 <packet_id_init+0x37>
			33: R_X86_64_PC32	.L.str-0x4
  37:	bf 87 00 00 46       	mov    edi,0x46000087
  3c:	44 89 f2             	mov    edx,r14d
  3f:	89 e9                	mov    ecx,ebp
  41:	31 c0                	xor    eax,eax
  43:	e8 00 00 00 00       	call   48 <packet_id_init+0x48>
			44: R_X86_64_PLT32	x_msg-0x4
  48:	48 85 db             	test   rbx,rbx
  4b:	0f 84 8e 00 00 00    	je     df <packet_id_init+0xdf>
  51:	0f 57 c0             	xorps  xmm0,xmm0
  54:	0f 11 43 50          	movups XMMWORD PTR [rbx+0x50],xmm0
  58:	0f 11 43 40          	movups XMMWORD PTR [rbx+0x40],xmm0
  5c:	0f 11 43 30          	movups XMMWORD PTR [rbx+0x30],xmm0
  60:	0f 11 43 20          	movups XMMWORD PTR [rbx+0x20],xmm0
  64:	0f 11 43 10          	movups XMMWORD PTR [rbx+0x10],xmm0
  68:	0f 11 03             	movups XMMWORD PTR [rbx],xmm0
  6b:	4c 89 63 50          	mov    QWORD PTR [rbx+0x50],r12
  6f:	44 89 7b 58          	mov    DWORD PTR [rbx+0x58],r15d
  73:	45 85 f6             	test   r14d,r14d
  76:	74 5a                	je     d2 <packet_id_init+0xd2>
  78:	41 81 fe 01 00 01 00 	cmp    r14d,0x10001
  7f:	73 76                	jae    f7 <packet_id_init+0xf7>
  81:	81 fd 59 02 00 00    	cmp    ebp,0x259
  87:	0f 83 82 00 00 00    	jae    10f <packet_id_init+0x10f>
  8d:	45 89 f4             	mov    r12d,r14d
  90:	46 8d 3c f5 10 00 00 	lea    r15d,[r14*8+0x10]
  97:	00 
  98:	4c 89 ff             	mov    rdi,r15
  9b:	e8 00 00 00 00       	call   a0 <packet_id_init+0xa0>
			9c: R_X86_64_PLT32	malloc-0x4
  a0:	48 89 43 48          	mov    QWORD PTR [rbx+0x48],rax
  a4:	48 85 c0             	test   rax,rax
  a7:	75 09                	jne    b2 <packet_id_init+0xb2>
  a9:	e8 00 00 00 00       	call   ae <packet_id_init+0xae>
			aa: R_X86_64_PLT32	out_of_memory-0x4
  ae:	48 8b 43 48          	mov    rax,QWORD PTR [rbx+0x48]
  b2:	48 89 c7             	mov    rdi,rax
  b5:	31 f6                	xor    esi,esi
  b7:	4c 89 fa             	mov    rdx,r15
  ba:	e8 00 00 00 00       	call   bf <packet_id_init+0xbf>
			bb: R_X86_64_PLT32	memset-0x4
  bf:	48 8b 43 48          	mov    rax,QWORD PTR [rbx+0x48]
  c3:	44 89 70 08          	mov    DWORD PTR [rax+0x8],r14d
  c7:	44 89 78 0c          	mov    DWORD PTR [rax+0xc],r15d
  cb:	4c 89 63 28          	mov    QWORD PTR [rbx+0x28],r12
  cf:	89 6b 30             	mov    DWORD PTR [rbx+0x30],ebp
  d2:	c6 43 40 01          	mov    BYTE PTR [rbx+0x40],0x1
  d6:	5b                   	pop    rbx
  d7:	41 5c                	pop    r12
  d9:	41 5e                	pop    r14
  db:	41 5f                	pop    r15
  dd:	5d                   	pop    rbp
  de:	c3                   	ret
  df:	48 8d 3d 00 00 00 00 	lea    rdi,[rip+0x0]        # e6 <packet_id_init+0xe6>
			e2: R_X86_64_PC32	.L.str.1-0x4
  e6:	48 8d 15 00 00 00 00 	lea    rdx,[rip+0x0]        # ed <packet_id_init+0xed>
			e9: R_X86_64_PC32	.L.str.2-0x4
  ed:	be 66 00 00 00       	mov    esi,0x66
  f2:	e8 00 00 00 00       	call   f7 <packet_id_init+0xf7>
			f3: R_X86_64_PLT32	assert_failed-0x4
  f7:	48 8d 3d 00 00 00 00 	lea    rdi,[rip+0x0]        # fe <packet_id_init+0xfe>
			fa: R_X86_64_PC32	.L.str.1-0x4
  fe:	48 8d 15 00 00 00 00 	lea    rdx,[rip+0x0]        # 105 <packet_id_init+0x105>
			101: R_X86_64_PC32	.L.str.25-0x4
 105:	be 57 00 00 00       	mov    esi,0x57
 10a:	e8 00 00 00 00       	call   10f <packet_id_init+0x10f>
			10b: R_X86_64_PLT32	assert_failed-0x4
 10f:	48 8d 3d 00 00 00 00 	lea    rdi,[rip+0x0]        # 116 <packet_id_init+0x116>
			112: R_X86_64_PC32	.L.str.1-0x4
 116:	48 8d 15 00 00 00 00 	lea    rdx,[rip+0x0]        # 11d <packet_id_init+0x11d>
			119: R_X86_64_PC32	.L.str.26-0x4
 11d:	be 58 00 00 00       	mov    esi,0x58
 122:	e8 00 00 00 00       	call   127 <.L.str.12+0x2>
			123: R_X86_64_PLT32	assert_failed-0x4

Disassembly of section .text.packet_id_move_recv:

0000000000000000 <packet_id_move_recv>:
   0:	55                   	push   rbp
   1:	41 57                	push   r15
   3:	41 56                	push   r14
   5:	41 54                	push   r12
   7:	53                   	push   rbx
   8:	48 85 f6             	test   rsi,rsi
   b:	0f 84 ff 00 00 00    	je     110 <packet_id_move_recv+0x110>
  11:	49 89 fe             	mov    r14,rdi
  14:	48 85 ff             	test   rdi,rdi
  17:	0f 84 0b 01 00 00    	je     128 <packet_id_move_recv+0x128>
  1d:	48 89 f3             	mov    rbx,rsi
  20:	49 8b 7e 38          	mov    rdi,QWORD PTR [r14+0x38]
  24:	e8 00 00 00 00       	call   29 <packet_id_move_recv+0x29>
			25: R_X86_64_PLT32	free-0x4
  29:	0f 57 c0             	xorps  xmm0,xmm0
  2c:	41 0f 11 46 40       	movups XMMWORD PTR [r14+0x40],xmm0
  31:	41 0f 11 46 30       	movups XMMWORD PTR [r14+0x30],xmm0
  36:	41 0f 11 46 20       	movups XMMWORD PTR [r14+0x20],xmm0
  3b:	41 0f 11 46 10       	movups XMMWORD PTR [r14+0x10],xmm0
  40:	41 0f 11 06          	movups XMMWORD PTR [r14],xmm0
  44:	0f 10 4b 40          	movups xmm1,XMMWORD PTR [rbx+0x40]
  48:	41 0f 11 4e 40       	movups XMMWORD PTR [r14+0x40],xmm1
  4d:	0f 10 0b             	movups xmm1,XMMWORD PTR [rbx]
  50:	0f 10 53 10          	movups xmm2,XMMWORD PTR [rbx+0x10]
  54:	0f 10 5b 20          	movups xmm3,XMMWORD PTR [rbx+0x20]
  58:	0f 10 63 30          	movups xmm4,XMMWORD PTR [rbx+0x30]
  5c:	41 0f 11 66 30       	movups XMMWORD PTR [r14+0x30],xmm4
  61:	41 0f 11 5e 20       	movups XMMWORD PTR [r14+0x20],xmm3
  66:	41 0f 11 56 10       	movups XMMWORD PTR [r14+0x10],xmm2
  6b:	41 0f 11 0e          	movups XMMWORD PTR [r14],xmm1
  6f:	0f 11 43 30          	movups XMMWORD PTR [rbx+0x30],xmm0
  73:	0f 11 43 20          	movups XMMWORD PTR [rbx+0x20],xmm0
  77:	0f 11 43 10          	movups XMMWORD PTR [rbx+0x10],xmm0
  7b:	0f 11 03             	movups XMMWORD PTR [rbx],xmm0
  7e:	0f 11 43 40          	movups XMMWORD PTR [rbx+0x40],xmm0
  82:	4d 8b 7e 18          	mov    r15,QWORD PTR [r14+0x18]
  86:	41 8b 6e 20          	mov    ebp,DWORD PTR [r14+0x20]
  8a:	49 8b 46 40          	mov    rax,QWORD PTR [r14+0x40]
  8e:	41 8b 4e 48          	mov    ecx,DWORD PTR [r14+0x48]
  92:	48 89 43 40          	mov    QWORD PTR [rbx+0x40],rax
  96:	89 4b 48             	mov    DWORD PTR [rbx+0x48],ecx
  99:	45 85 ff             	test   r15d,r15d
  9c:	74 65                	je     103 <packet_id_move_recv+0x103>
  9e:	41 81 ff 01 00 01 00 	cmp    r15d,0x10001
  a5:	0f 83 95 00 00 00    	jae    140 <packet_id_move_recv+0x140>
  ab:	81 fd 59 02 00 00    	cmp    ebp,0x259
  b1:	0f 83 a1 00 00 00    	jae    158 <packet_id_move_recv+0x158>
  b7:	45 89 fc             	mov    r12d,r15d
  ba:	41 81 e4 ff ff 01 00 	and    r12d,0x1ffff
  c1:	46 8d 34 fd 10 00 00 	lea    r14d,[r15*8+0x10]
  c8:	00 
  c9:	4c 89 f7             	mov    rdi,r14
  cc:	e8 00 00 00 00       	call   d1 <packet_id_move_recv+0xd1>
			cd: R_X86_64_PLT32	malloc-0x4
  d1:	48 89 43 38          	mov    QWORD PTR [rbx+0x38],rax
  d5:	48 85 c0             	test   rax,rax
  d8:	75 09                	jne    e3 <packet_id_move_recv+0xe3>
  da:	e8 00 00 00 00       	call   df <packet_id_move_recv+0xdf>
			db: R_X86_64_PLT32	out_of_memory-0x4
  df:	48 8b 43 38          	mov    rax,QWORD PTR [rbx+0x38]
  e3:	48 89 c7             	mov    rdi,rax
  e6:	31 f6                	xor    esi,esi
  e8:	4c 89 f2             	mov    rdx,r14
  eb:	e8 00 00 00 00       	call   f0 <packet_id_move_recv+0xf0>
			ec: R_X86_64_PLT32	memset-0x4
  f0:	48 8b 43 38          	mov    rax,QWORD PTR [rbx+0x38]
  f4:	44 89 78 08          	mov    DWORD PTR [rax+0x8],r15d
  f8:	44 89 70 0c          	mov    DWORD PTR [rax+0xc],r14d
  fc:	4c 89 63 18          	mov    QWORD PTR [rbx+0x18],r12
 100:	89 6b 20             	mov    DWORD PTR [rbx+0x20],ebp
 103:	c6 43 30 01          	mov    BYTE PTR [rbx+0x30],0x1
 107:	5b                   	pop    rbx
 108:	41 5c                	pop    r12
 10a:	41 5e                	pop    r14
 10c:	41 5f                	pop    r15
 10e:	5d                   	pop    rbp
 10f:	c3                   	ret
 110:	48 8d 3d 00 00 00 00 	lea    rdi,[rip+0x0]        # 117 <packet_id_move_recv+0x117>
			113: R_X86_64_PC32	.L.str.1-0x4
 117:	48 8d 15 00 00 00 00 	lea    rdx,[rip+0x0]        # 11e <packet_id_move_recv+0x11e>
			11a: R_X86_64_PC32	.L.str.3-0x4
 11e:	be 6f 00 00 00       	mov    esi,0x6f
 123:	e8 00 00 00 00       	call   128 <packet_id_move_recv+0x128>
			124: R_X86_64_PLT32	assert_failed-0x4
 128:	48 8d 3d 00 00 00 00 	lea    rdi,[rip+0x0]        # 12f <packet_id_move_recv+0x12f>
			12b: R_X86_64_PC32	.L.str.1-0x4
 12f:	48 8d 15 00 00 00 00 	lea    rdx,[rip+0x0]        # 136 <packet_id_move_recv+0x136>
			132: R_X86_64_PC32	.L.str.4-0x4
 136:	be 70 00 00 00       	mov    esi,0x70
 13b:	e8 00 00 00 00       	call   140 <packet_id_move_recv+0x140>
			13c: R_X86_64_PLT32	assert_failed-0x4
 140:	48 8d 3d 00 00 00 00 	lea    rdi,[rip+0x0]        # 147 <packet_id_move_recv+0x147>
			143: R_X86_64_PC32	.L.str.1-0x4
 147:	48 8d 15 00 00 00 00 	lea    rdx,[rip+0x0]        # 14e <packet_id_move_recv+0x14e>
			14a: R_X86_64_PC32	.L.str.25-0x4
 14e:	be 57 00 00 00       	mov    esi,0x57
 153:	e8 00 00 00 00       	call   158 <packet_id_move_recv+0x158>
			154: R_X86_64_PLT32	assert_failed-0x4
 158:	48 8d 3d 00 00 00 00 	lea    rdi,[rip+0x0]        # 15f <packet_id_move_recv+0x15f>
			15b: R_X86_64_PC32	.L.str.1-0x4
 15f:	48 8d 15 00 00 00 00 	lea    rdx,[rip+0x0]        # 166 <packet_id_move_recv+0x166>
			162: R_X86_64_PC32	.L.str.26-0x4
 166:	be 58 00 00 00       	mov    esi,0x58
 16b:	e8 00 00 00 00       	call   170 <.L.str.16+0x6>
			16c: R_X86_64_PLT32	assert_failed-0x4

Disassembly of section .text.packet_id_free:

0000000000000000 <packet_id_free>:
   0:	48 85 ff             	test   rdi,rdi
   3:	74 55                	je     5a <packet_id_free+0x5a>
   5:	53                   	push   rbx
   6:	48 89 fb             	mov    rbx,rdi
   9:	48 8b 05 00 00 00 00 	mov    rax,QWORD PTR [rip+0x0]        # 10 <packet_id_free+0x10>
			c: R_X86_64_REX_GOTPCRELX	x_debug_level-0x4
  10:	83 38 07             	cmp    DWORD PTR [rax],0x7
  13:	72 21                	jb     36 <packet_id_free+0x36>
  15:	bf 87 00 00 46       	mov    edi,0x46000087
  1a:	e8 00 00 00 00       	call   1f <packet_id_free+0x1f>
			1b: R_X86_64_PLT32	dont_mute-0x4
  1f:	84 c0                	test   al,al
  21:	74 13                	je     36 <packet_id_free+0x36>
  23:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 2a <packet_id_free+0x2a>
			26: R_X86_64_PC32	.L.str.5-0x4
  2a:	bf 87 00 00 46       	mov    edi,0x46000087
  2f:	31 c0                	xor    eax,eax
  31:	e8 00 00 00 00       	call   36 <packet_id_free+0x36>
			32: R_X86_64_PLT32	x_msg-0x4
  36:	48 8b 7b 48          	mov    rdi,QWORD PTR [rbx+0x48]
  3a:	e8 00 00 00 00       	call   3f <packet_id_free+0x3f>
			3b: R_X86_64_PLT32	free-0x4
  3f:	0f 57 c0             	xorps  xmm0,xmm0
  42:	0f 11 43 50          	movups XMMWORD PTR [rbx+0x50],xmm0
  46:	0f 11 43 40          	movups XMMWORD PTR [rbx+0x40],xmm0
  4a:	0f 11 43 30          	movups XMMWORD PTR [rbx+0x30],xmm0
  4e:	0f 11 43 20          	movups XMMWORD PTR [rbx+0x20],xmm0
  52:	0f 11 43 10          	movups XMMWORD PTR [rbx+0x10],xmm0
  56:	0f 11 03             	movups XMMWORD PTR [rbx],xmm0
  59:	5b                   	pop    rbx
  5a:	c3                   	ret

Disassembly of section .text.packet_id_add:

0000000000000000 <packet_id_add>:
   0:	41 56                	push   r14
   2:	53                   	push   rbx
   3:	50                   	push   rax
   4:	48 8b 47 38          	mov    rax,QWORD PTR [rdi+0x38]
   8:	48 85 c0             	test   rax,rax
   b:	74 31                	je     3e <packet_id_add+0x3e>
   d:	48 8b 0d 00 00 00 00 	mov    rcx,QWORD PTR [rip+0x0]        # 14 <packet_id_add+0x14>
			10: R_X86_64_REX_GOTPCRELX	now-0x4
  14:	48 8b 09             	mov    rcx,QWORD PTR [rcx]
  17:	8b 58 04             	mov    ebx,DWORD PTR [rax+0x4]
  1a:	4c 8b 46 08          	mov    r8,QWORD PTR [rsi+0x8]
  1e:	85 db                	test   ebx,ebx
  20:	74 32                	je     54 <packet_id_add+0x54>
  22:	48 8b 16             	mov    rdx,QWORD PTR [rsi]
  25:	4c 3b 47 08          	cmp    r8,QWORD PTR [rdi+0x8]
  29:	7f 2c                	jg     57 <packet_id_add+0x57>
  2b:	49 89 d1             	mov    r9,rdx
  2e:	4c 2b 4f 18          	sub    r9,QWORD PTR [rdi+0x18]
  32:	0f 83 0a 01 00 00    	jae    142 <packet_id_add+0x142>
  38:	4c 8b 77 10          	mov    r14,QWORD PTR [rdi+0x10]
  3c:	eb 40                	jmp    7e <packet_id_add+0x7e>
  3e:	f3 0f 6f 06          	movdqu xmm0,XMMWORD PTR [rsi]
  42:	66 0f 70 c0 4e       	pshufd xmm0,xmm0,0x4e
  47:	f3 0f 7f 47 08       	movdqu XMMWORD PTR [rdi+0x8],xmm0
  4c:	48 83 c4 08          	add    rsp,0x8
  50:	5b                   	pop    rbx
  51:	41 5e                	pop    r14
  53:	c3                   	ret
  54:	48 8b 16             	mov    rdx,QWORD PTR [rsi]
  57:	4c 89 47 08          	mov    QWORD PTR [rdi+0x8],r8
  5b:	48 c7 47 10 00 00 00 	mov    QWORD PTR [rdi+0x10],0x0
  62:	00 
  63:	31 db                	xor    ebx,ebx
  65:	49 89 d6             	mov    r14,rdx
  68:	4c 2b 77 18          	sub    r14,QWORD PTR [rdi+0x18]
  6c:	76 06                	jbe    74 <packet_id_add+0x74>
  6e:	4c 89 77 10          	mov    QWORD PTR [rdi+0x10],r14
  72:	eb 03                	jmp    77 <packet_id_add+0x77>
  74:	45 31 f6             	xor    r14d,r14d
  77:	48 c7 00 00 00 00 00 	mov    QWORD PTR [rax],0x0
  7e:	49 39 d6             	cmp    r14,rdx
  81:	73 5d                	jae    e0 <packet_id_add+0xe0>
  83:	44 8b 00             	mov    r8d,DWORD PTR [rax]
  86:	44 8b 48 08          	mov    r9d,DWORD PTR [rax+0x8]
  8a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
  90:	45 85 c0             	test   r8d,r8d
  93:	0f 88 bb 00 00 00    	js     154 <packet_id_add+0x154>
  99:	45 39 c8             	cmp    r8d,r9d
  9c:	0f 8d b2 00 00 00    	jge    154 <packet_id_add+0x154>
  a2:	41 83 e8 01          	sub    r8d,0x1
  a6:	ba 00 00 00 00       	mov    edx,0x0
  ab:	41 0f 42 d1          	cmovb  edx,r9d
  af:	41 01 d0             	add    r8d,edx
  b2:	44 89 00             	mov    DWORD PTR [rax],r8d
  b5:	49 63 d0             	movsxd rdx,r8d
  b8:	48 c7 44 d0 10 00 00 	mov    QWORD PTR [rax+rdx*8+0x10],0x0
  bf:	00 00 
  c1:	ff c3                	inc    ebx
  c3:	44 39 cb             	cmp    ebx,r9d
  c6:	41 0f 4d d9          	cmovge ebx,r9d
  ca:	89 58 04             	mov    DWORD PTR [rax+0x4],ebx
  cd:	4c 8b 77 10          	mov    r14,QWORD PTR [rdi+0x10]
  d1:	49 ff c6             	inc    r14
  d4:	4c 89 77 10          	mov    QWORD PTR [rdi+0x10],r14
  d8:	48 8b 16             	mov    rdx,QWORD PTR [rsi]
  db:	49 39 d6             	cmp    r14,rdx
  de:	72 b0                	jb     90 <packet_id_add+0x90>
  e0:	49 29 d6             	sub    r14,rdx
  e3:	48 63 d3             	movsxd rdx,ebx
  e6:	49 39 d6             	cmp    r14,rdx
  e9:	0f 9c c2             	setl   dl
  ec:	48 83 f9 02          	cmp    rcx,0x2
  f0:	40 0f 9d c6          	setge  sil
  f4:	40 20 d6             	and    sil,dl
  f7:	40 80 fe 01          	cmp    sil,0x1
  fb:	0f 85 4b ff ff ff    	jne    4c <packet_id_add+0x4c>
 101:	45 85 f6             	test   r14d,r14d
 104:	78 66                	js     16c <packet_id_add+0x16c>
 106:	44 39 f3             	cmp    ebx,r14d
 109:	7e 61                	jle    16c <packet_id_add+0x16c>
 10b:	8b 50 08             	mov    edx,DWORD PTR [rax+0x8]
 10e:	44 39 f2             	cmp    edx,r14d
 111:	7c 41                	jl     154 <packet_id_add+0x154>
 113:	8b 30                	mov    esi,DWORD PTR [rax]
 115:	85 f6                	test   esi,esi
 117:	78 3b                	js     154 <packet_id_add+0x154>
 119:	39 d6                	cmp    esi,edx
 11b:	7d 37                	jge    154 <packet_id_add+0x154>
 11d:	44 01 f6             	add    esi,r14d
 120:	31 ff                	xor    edi,edi
 122:	39 d6                	cmp    esi,edx
 124:	0f 43 fa             	cmovae edi,edx
 127:	29 fe                	sub    esi,edi
 129:	89 f7                	mov    edi,esi
 12b:	c1 ff 1f             	sar    edi,0x1f
 12e:	21 d7                	and    edi,edx
 130:	01 f7                	add    edi,esi
 132:	48 63 d7             	movsxd rdx,edi
 135:	48 89 4c d0 10       	mov    QWORD PTR [rax+rdx*8+0x10],rcx
 13a:	48 83 c4 08          	add    rsp,0x8
 13e:	5b                   	pop    rbx
 13f:	41 5e                	pop    r14
 141:	c3                   	ret
 142:	4c 8b 77 10          	mov    r14,QWORD PTR [rdi+0x10]
 146:	4d 39 f1             	cmp    r9,r14
 149:	0f 87 08 ff ff ff    	ja     57 <packet_id_add+0x57>
 14f:	e9 2a ff ff ff       	jmp    7e <packet_id_add+0x7e>
 154:	48 8d 3d 00 00 00 00 	lea    rdi,[rip+0x0]        # 15b <packet_id_add+0x15b>
			157: R_X86_64_PC32	.L.str.27-0x4
 15b:	48 8d 15 00 00 00 00 	lea    rdx,[rip+0x0]        # 162 <packet_id_add+0x162>
			15e: R_X86_64_PC32	.L.str.28-0x4
 162:	be bc 00 00 00       	mov    esi,0xbc
 167:	e8 00 00 00 00       	call   16c <packet_id_add+0x16c>
			168: R_X86_64_PLT32	assert_failed-0x4
 16c:	bf 10 00 00 00       	mov    edi,0x10
 171:	e8 00 00 00 00       	call   176 <packet_id_add+0x176>
			172: R_X86_64_PLT32	dont_mute-0x4
 176:	84 c0                	test   al,al
 178:	74 25                	je     19f <packet_id_add+0x19f>
 17a:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 181 <packet_id_add+0x181>
			17d: R_X86_64_PC32	.L.str.29-0x4
 181:	4c 8d 05 00 00 00 00 	lea    r8,[rip+0x0]        # 188 <packet_id_add+0x188>
			184: R_X86_64_PC32	.L.str.1-0x4
 188:	bf 10 00 00 00       	mov    edi,0x10
 18d:	44 89 f2             	mov    edx,r14d
 190:	89 d9                	mov    ecx,ebx
 192:	41 b9 ad 00 00 00    	mov    r9d,0xad
 198:	31 c0                	xor    eax,eax
 19a:	e8 00 00 00 00       	call   19f <packet_id_add+0x19f>
			19b: R_X86_64_PLT32	x_msg-0x4
 19f:	bf 01 00 00 00       	mov    edi,0x1
 1a4:	e8 00 00 00 00       	call   1a9 <.L.str.17+0xb>
			1a5: R_X86_64_PLT32	_exit-0x4

Disassembly of section .text.packet_id_reap:

0000000000000000 <packet_id_reap>:
   0:	55                   	push   rbp
   1:	41 57                	push   r15
   3:	41 56                	push   r14
   5:	41 55                	push   r13
   7:	41 54                	push   r12
   9:	53                   	push   rbx
   a:	50                   	push   rax
   b:	48 8b 05 00 00 00 00 	mov    rax,QWORD PTR [rip+0x0]        # 12 <packet_id_reap+0x12>
			e: R_X86_64_REX_GOTPCRELX	now-0x4
  12:	48 8b 00             	mov    rax,QWORD PTR [rax]
  15:	48 63 4f 20          	movsxd rcx,DWORD PTR [rdi+0x20]
  19:	48 85 c9             	test   rcx,rcx
  1c:	0f 84 b9 00 00 00    	je     db <packet_id_reap+0xdb>
  22:	48 8b 57 38          	mov    rdx,QWORD PTR [rdi+0x38]
  26:	8b 72 04             	mov    esi,DWORD PTR [rdx+0x4]
  29:	85 f6                	test   esi,esi
  2b:	0f 8e aa 00 00 00    	jle    db <packet_id_reap+0xdb>
  31:	44 8b 02             	mov    r8d,DWORD PTR [rdx]
  34:	44 8b 4a 08          	mov    r9d,DWORD PTR [rdx+0x8]
  38:	45 85 c0             	test   r8d,r8d
  3b:	41 0f 98 c2          	sets   r10b
  3f:	45 39 c8             	cmp    r8d,r9d
  42:	41 0f 9d c3          	setge  r11b
  46:	45 08 d3             	or     r11b,r10b
  49:	0f 85 9e 00 00 00    	jne    ed <packet_id_reap+0xed>
  4f:	45 85 c9             	test   r9d,r9d
  52:	41 ba ff ff ff ff    	mov    r10d,0xffffffff
  58:	45 0f 49 d1          	cmovns r10d,r9d
  5c:	41 f7 d2             	not    r10d
  5f:	f7 de                	neg    esi
  61:	45 31 db             	xor    r11d,r11d
  64:	bb 01 00 00 00       	mov    ebx,0x1
  69:	31 ed                	xor    ebp,ebp
  6b:	45 31 f6             	xor    r14d,r14d
  6e:	eb 09                	jmp    79 <packet_id_reap+0x79>
  70:	ff cd                	dec    ebp
  72:	41 ff c0             	inc    r8d
  75:	39 ee                	cmp    esi,ebp
  77:	74 62                	je     db <packet_id_reap+0xdb>
  79:	41 39 ea             	cmp    r10d,ebp
  7c:	74 6f                	je     ed <packet_id_reap+0xed>
  7e:	45 39 c8             	cmp    r8d,r9d
  81:	45 89 cf             	mov    r15d,r9d
  84:	45 0f 42 fb          	cmovb  r15d,r11d
  88:	45 89 c4             	mov    r12d,r8d
  8b:	45 29 fc             	sub    r12d,r15d
  8e:	41 c1 fc 1f          	sar    r12d,0x1f
  92:	45 21 cc             	and    r12d,r9d
  95:	45 29 fc             	sub    r12d,r15d
  98:	45 01 c4             	add    r12d,r8d
  9b:	4d 63 fc             	movsxd r15,r12d
  9e:	4e 8b 64 fa 10       	mov    r12,QWORD PTR [rdx+r15*8+0x10]
  a3:	49 83 fc 01          	cmp    r12,0x1
  a7:	74 32                	je     db <packet_id_reap+0xdb>
  a9:	4d 8d 2c 0c          	lea    r13,[r12+rcx*1]
  ad:	49 39 c5             	cmp    r13,rax
  b0:	45 0f b6 ee          	movzx  r13d,r14b
  b4:	45 89 ee             	mov    r14d,r13d
  b7:	44 0f 4c f3          	cmovl  r14d,ebx
  bb:	41 f6 c5 01          	test   r13b,0x1
  bf:	45 0f 45 f5          	cmovne r14d,r13d
  c3:	4d 85 e4             	test   r12,r12
  c6:	45 0f 44 f5          	cmove  r14d,r13d
  ca:	41 f6 c6 01          	test   r14b,0x1
  ce:	74 a0                	je     70 <packet_id_reap+0x70>
  d0:	4a c7 44 fa 10 01 00 	mov    QWORD PTR [rdx+r15*8+0x10],0x1
  d7:	00 00 
  d9:	eb 95                	jmp    70 <packet_id_reap+0x70>
  db:	48 89 07             	mov    QWORD PTR [rdi],rax
  de:	48 83 c4 08          	add    rsp,0x8
  e2:	5b                   	pop    rbx
  e3:	41 5c                	pop    r12
  e5:	41 5d                	pop    r13
  e7:	41 5e                	pop    r14
  e9:	41 5f                	pop    r15
  eb:	5d                   	pop    rbp
  ec:	c3                   	ret
  ed:	48 8d 3d 00 00 00 00 	lea    rdi,[rip+0x0]        # f4 <packet_id_reap+0xf4>
			f0: R_X86_64_PC32	.L.str.27-0x4
  f4:	48 8d 15 00 00 00 00 	lea    rdx,[rip+0x0]        # fb <packet_id_reap+0xfb>
			f7: R_X86_64_PC32	.L.str.28-0x4
  fb:	be bc 00 00 00       	mov    esi,0xbc
 100:	e8 00 00 00 00       	call   105 <.L.str.10+0x6>
			101: R_X86_64_PLT32	assert_failed-0x4

Disassembly of section .text.packet_id_test:

0000000000000000 <packet_id_test>:
   0:	41 57                	push   r15
   2:	41 56                	push   r14
   4:	41 55                	push   r13
   6:	41 54                	push   r12
   8:	53                   	push   rbx
   9:	4c 8b 2d 00 00 00 00 	mov    r13,QWORD PTR [rip+0x0]        # 10 <packet_id_test+0x10>
			c: R_X86_64_REX_GOTPCRELX	x_debug_level-0x4
  10:	41 83 7d 00 07       	cmp    DWORD PTR [r13+0x0],0x7
  15:	0f 83 48 01 00 00    	jae    163 <packet_id_test+0x163>
  1b:	80 7f 30 00          	cmp    BYTE PTR [rdi+0x30],0x0
  1f:	0f 84 6e 01 00 00    	je     193 <packet_id_test+0x193>
  25:	48 8b 06             	mov    rax,QWORD PTR [rsi]
  28:	48 85 c0             	test   rax,rax
  2b:	0f 84 b8 01 00 00    	je     1e9 <packet_id_test+0x1e9>
  31:	48 83 7f 18 00       	cmp    QWORD PTR [rdi+0x18],0x0
  36:	48 8b 4e 08          	mov    rcx,QWORD PTR [rsi+0x8]
  3a:	48 8b 57 08          	mov    rdx,QWORD PTR [rdi+0x8]
  3e:	0f 84 b8 00 00 00    	je     fc <packet_id_test+0xfc>
  44:	48 39 d1             	cmp    rcx,rdx
  47:	0f 85 ce 00 00 00    	jne    11b <packet_id_test+0x11b>
  4d:	4c 8b 77 10          	mov    r14,QWORD PTR [rdi+0x10]
  51:	b3 01                	mov    bl,0x1
  53:	49 29 c6             	sub    r14,rax
  56:	0f 82 8f 01 00 00    	jb     1eb <packet_id_test+0x1eb>
  5c:	4c 3b 77 28          	cmp    r14,QWORD PTR [rdi+0x28]
  60:	76 0f                	jbe    71 <packet_id_test+0x71>
  62:	4c 89 77 28          	mov    QWORD PTR [rdi+0x28],r14
  66:	41 83 7d 00 04       	cmp    DWORD PTR [r13+0x0],0x4
  6b:	0f 83 3a 01 00 00    	jae    1ab <packet_id_test+0x1ab>
  71:	48 8b 47 38          	mov    rax,QWORD PTR [rdi+0x38]
  75:	44 8b 78 04          	mov    r15d,DWORD PTR [rax+0x4]
  79:	4d 39 fe             	cmp    r14,r15
  7c:	0f 83 60 01 00 00    	jae    1e2 <packet_id_test+0x1e2>
  82:	45 85 f6             	test   r14d,r14d
  85:	0f 88 8b 01 00 00    	js     216 <packet_id_test+0x216>
  8b:	45 39 f7             	cmp    r15d,r14d
  8e:	0f 8e 82 01 00 00    	jle    216 <packet_id_test+0x216>
  94:	8b 48 08             	mov    ecx,DWORD PTR [rax+0x8]
  97:	44 39 f1             	cmp    ecx,r14d
  9a:	0f 8c b4 01 00 00    	jl     254 <packet_id_test+0x254>
  a0:	8b 10                	mov    edx,DWORD PTR [rax]
  a2:	85 d2                	test   edx,edx
  a4:	0f 88 aa 01 00 00    	js     254 <packet_id_test+0x254>
  aa:	39 ca                	cmp    edx,ecx
  ac:	0f 8d a2 01 00 00    	jge    254 <packet_id_test+0x254>
  b2:	44 01 f2             	add    edx,r14d
  b5:	45 31 c0             	xor    r8d,r8d
  b8:	39 ca                	cmp    edx,ecx
  ba:	44 0f 43 c1          	cmovae r8d,ecx
  be:	44 29 c2             	sub    edx,r8d
  c1:	41 89 d0             	mov    r8d,edx
  c4:	41 c1 f8 1f          	sar    r8d,0x1f
  c8:	41 21 c8             	and    r8d,ecx
  cb:	41 01 d0             	add    r8d,edx
  ce:	49 63 c8             	movsxd rcx,r8d
  d1:	48 83 7c c8 10 00    	cmp    QWORD PTR [rax+rcx*8+0x10],0x0
  d7:	0f 84 0e 01 00 00    	je     1eb <packet_id_test+0x1eb>
  dd:	41 83 7d 00 04       	cmp    DWORD PTR [r13+0x0],0x4
  e2:	0f 82 01 01 00 00    	jb     1e9 <packet_id_test+0x1e9>
  e8:	48 8d 0d 00 00 00 00 	lea    rcx,[rip+0x0]        # ef <packet_id_test+0xef>
			eb: R_X86_64_PC32	.L.str.10-0x4
  ef:	48 89 f8             	mov    rax,rdi
  f2:	bf 04 00 00 40       	mov    edi,0x40000004
  f7:	e9 0a 01 00 00       	jmp    206 <packet_id_test+0x206>
  fc:	48 39 d1             	cmp    rcx,rdx
  ff:	75 51                	jne    152 <packet_id_test+0x152>
 101:	48 8b 4f 10          	mov    rcx,QWORD PTR [rdi+0x10]
 105:	48 85 c9             	test   rcx,rcx
 108:	0f 94 c2             	sete   dl
 10b:	48 ff c1             	inc    rcx
 10e:	48 39 c8             	cmp    rax,rcx
 111:	0f 94 c3             	sete   bl
 114:	08 d3                	or     bl,dl
 116:	e9 d0 00 00 00       	jmp    1eb <packet_id_test+0x1eb>
 11b:	b3 01                	mov    bl,0x1
 11d:	0f 8d c8 00 00 00    	jge    1eb <packet_id_test+0x1eb>
 123:	41 83 7d 00 04       	cmp    DWORD PTR [r13+0x0],0x4
 128:	0f 82 bb 00 00 00    	jb     1e9 <packet_id_test+0x1e9>
 12e:	48 8d 0d 00 00 00 00 	lea    rcx,[rip+0x0]        # 135 <packet_id_test+0x135>
			131: R_X86_64_PC32	.L.str.11-0x4
 135:	31 db                	xor    ebx,ebx
 137:	48 89 f8             	mov    rax,rdi
 13a:	bf 04 00 00 3f       	mov    edi,0x3f000004
 13f:	48 89 f2             	mov    rdx,rsi
 142:	48 89 c6             	mov    rsi,rax
 145:	45 31 c0             	xor    r8d,r8d
 148:	e8 00 00 00 00       	call   14d <packet_id_test+0x14d>
			149: R_X86_64_PLT32	.text.packet_id_debug_print-0x4
 14d:	e9 99 00 00 00       	jmp    1eb <packet_id_test+0x1eb>
 152:	0f 9d c1             	setge  cl
 155:	48 83 f8 01          	cmp    rax,0x1
 159:	0f 94 c3             	sete   bl
 15c:	20 cb                	and    bl,cl
 15e:	e9 88 00 00 00       	jmp    1eb <packet_id_test+0x1eb>
 163:	48 8d 0d 00 00 00 00 	lea    rcx,[rip+0x0]        # 16a <packet_id_test+0x16a>
			166: R_X86_64_PC32	.L.str.6-0x4
 16a:	48 89 fb             	mov    rbx,rdi
 16d:	bf 87 00 00 46       	mov    edi,0x46000087
 172:	49 89 f6             	mov    r14,rsi
 175:	48 89 de             	mov    rsi,rbx
 178:	4c 89 f2             	mov    rdx,r14
 17b:	45 31 c0             	xor    r8d,r8d
 17e:	e8 00 00 00 00       	call   183 <packet_id_test+0x183>
			17f: R_X86_64_PLT32	.text.packet_id_debug_print-0x4
 183:	4c 89 f6             	mov    rsi,r14
 186:	48 89 df             	mov    rdi,rbx
 189:	80 7f 30 00          	cmp    BYTE PTR [rdi+0x30],0x0
 18d:	0f 85 92 fe ff ff    	jne    25 <packet_id_test+0x25>
 193:	48 8d 3d 00 00 00 00 	lea    rdi,[rip+0x0]        # 19a <packet_id_test+0x19a>
			196: R_X86_64_PC32	.L.str.1-0x4
 19a:	48 8d 15 00 00 00 00 	lea    rdx,[rip+0x0]        # 1a1 <packet_id_test+0x1a1>
			19d: R_X86_64_PC32	.L.str.7-0x4
 1a1:	be e2 00 00 00       	mov    esi,0xe2
 1a6:	e8 00 00 00 00       	call   1ab <packet_id_test+0x1ab>
			1a7: R_X86_64_PLT32	assert_failed-0x4
 1ab:	48 8d 0d 00 00 00 00 	lea    rcx,[rip+0x0]        # 1b2 <packet_id_test+0x1b2>
			1ae: R_X86_64_PC32	.L.str.8-0x4
 1b2:	49 89 ff             	mov    r15,rdi
 1b5:	bf 04 00 00 3f       	mov    edi,0x3f000004
 1ba:	49 89 f4             	mov    r12,rsi
 1bd:	4c 89 fe             	mov    rsi,r15
 1c0:	4c 89 e2             	mov    rdx,r12
 1c3:	4d 89 f0             	mov    r8,r14
 1c6:	e8 00 00 00 00       	call   1cb <packet_id_test+0x1cb>
			1c7: R_X86_64_PLT32	.text.packet_id_debug_print-0x4
 1cb:	4c 89 e6             	mov    rsi,r12
 1ce:	4c 89 ff             	mov    rdi,r15
 1d1:	48 8b 47 38          	mov    rax,QWORD PTR [rdi+0x38]
 1d5:	44 8b 78 04          	mov    r15d,DWORD PTR [rax+0x4]
 1d9:	4d 39 fe             	cmp    r14,r15
 1dc:	0f 82 a0 fe ff ff    	jb     82 <packet_id_test+0x82>
 1e2:	41 83 7d 00 04       	cmp    DWORD PTR [r13+0x0],0x4
 1e7:	73 0e                	jae    1f7 <packet_id_test+0x1f7>
 1e9:	31 db                	xor    ebx,ebx
 1eb:	89 d8                	mov    eax,ebx
 1ed:	5b                   	pop    rbx
 1ee:	41 5c                	pop    r12
 1f0:	41 5d                	pop    r13
 1f2:	41 5e                	pop    r14
 1f4:	41 5f                	pop    r15
 1f6:	c3                   	ret
 1f7:	48 8d 0d 00 00 00 00 	lea    rcx,[rip+0x0]        # 1fe <packet_id_test+0x1fe>
			1fa: R_X86_64_PC32	.L.str.9-0x4
 1fe:	48 89 f8             	mov    rax,rdi
 201:	bf 04 00 00 3f       	mov    edi,0x3f000004
 206:	48 89 f2             	mov    rdx,rsi
 209:	48 89 c6             	mov    rsi,rax
 20c:	4d 89 f0             	mov    r8,r14
 20f:	e8 00 00 00 00       	call   214 <packet_id_test+0x214>
			210: R_X86_64_PLT32	.text.packet_id_debug_print-0x4
 214:	eb d3                	jmp    1e9 <packet_id_test+0x1e9>
 216:	bf 10 00 00 00       	mov    edi,0x10
 21b:	e8 00 00 00 00       	call   220 <packet_id_test+0x220>
			21c: R_X86_64_PLT32	dont_mute-0x4
 220:	84 c0                	test   al,al
 222:	74 26                	je     24a <packet_id_test+0x24a>
 224:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 22b <packet_id_test+0x22b>
			227: R_X86_64_PC32	.L.str.29-0x4
 22b:	4c 8d 05 00 00 00 00 	lea    r8,[rip+0x0]        # 232 <packet_id_test+0x232>
			22e: R_X86_64_PC32	.L.str.1-0x4
 232:	bf 10 00 00 00       	mov    edi,0x10
 237:	44 89 f2             	mov    edx,r14d
 23a:	44 89 f9             	mov    ecx,r15d
 23d:	41 b9 0b 01 00 00    	mov    r9d,0x10b
 243:	31 c0                	xor    eax,eax
 245:	e8 00 00 00 00       	call   24a <packet_id_test+0x24a>
			246: R_X86_64_PLT32	x_msg-0x4
 24a:	bf 01 00 00 00       	mov    edi,0x1
 24f:	e8 00 00 00 00       	call   254 <packet_id_test+0x254>
			250: R_X86_64_PLT32	_exit-0x4
 254:	48 8d 3d 00 00 00 00 	lea    rdi,[rip+0x0]        # 25b <packet_id_test+0x25b>
			257: R_X86_64_PC32	.L.str.27-0x4
 25b:	48 8d 15 00 00 00 00 	lea    rdx,[rip+0x0]        # 262 <packet_id_test+0x262>
			25e: R_X86_64_PC32	.L.str.28-0x4
 262:	be bc 00 00 00       	mov    esi,0xbc
 267:	e8 00 00 00 00       	call   26c <.L.str.22+0xc>
			268: R_X86_64_PLT32	assert_failed-0x4

Disassembly of section .text.packet_id_read:

0000000000000000 <packet_id_read>:
   0:	0f 57 c0             	xorps  xmm0,xmm0
   3:	0f 11 07             	movups XMMWORD PTR [rdi],xmm0
   6:	8b 4e 08             	mov    ecx,DWORD PTR [rsi+0x8]
   9:	83 f9 04             	cmp    ecx,0x4
   c:	7c 1b                	jl     29 <packet_id_read+0x29>
   e:	4c 8b 46 10          	mov    r8,QWORD PTR [rsi+0x10]
  12:	4c 63 56 04          	movsxd r10,DWORD PTR [rsi+0x4]
  16:	4d 8d 4a 04          	lea    r9,[r10+0x4]
  1a:	44 89 4e 04          	mov    DWORD PTR [rsi+0x4],r9d
  1e:	8d 41 fc             	lea    eax,[rcx-0x4]
  21:	89 46 08             	mov    DWORD PTR [rsi+0x8],eax
  24:	4d 85 c0             	test   r8,r8
  27:	75 03                	jne    2c <packet_id_read+0x2c>
  29:	31 c0                	xor    eax,eax
  2b:	c3                   	ret
  2c:	43 8b 04 10          	mov    eax,DWORD PTR [r8+r10*1]
  30:	0f c8                	bswap  eax
  32:	48 89 07             	mov    QWORD PTR [rdi],rax
  35:	b0 01                	mov    al,0x1
  37:	84 d2                	test   dl,dl
  39:	74 f0                	je     2b <packet_id_read+0x2b>
  3b:	83 f9 08             	cmp    ecx,0x8
  3e:	72 e9                	jb     29 <packet_id_read+0x29>
  40:	41 83 c2 08          	add    r10d,0x8
  44:	44 89 56 04          	mov    DWORD PTR [rsi+0x4],r10d
  48:	83 c1 f8             	add    ecx,0xfffffff8
  4b:	89 4e 08             	mov    DWORD PTR [rsi+0x8],ecx
  4e:	43 8b 0c 08          	mov    ecx,DWORD PTR [r8+r9*1]
  52:	0f c9                	bswap  ecx
  54:	48 89 4f 08          	mov    QWORD PTR [rdi+0x8],rcx
  58:	c3                   	ret

Disassembly of section .text.packet_id_write:

0000000000000000 <packet_id_write>:
   0:	4c 8b 47 08          	mov    r8,QWORD PTR [rdi+0x8]
   4:	4d 85 c0             	test   r8,r8
   7:	74 45                	je     4e <packet_id_write+0x4e>
   9:	48 8b 07             	mov    rax,QWORD PTR [rdi]
   c:	41 b9 ff ff ff ff    	mov    r9d,0xffffffff
  12:	4c 39 c8             	cmp    rax,r9
  15:	75 53                	jne    6a <packet_id_write+0x6a>
  17:	84 d2                	test   dl,dl
  19:	0f 84 36 01 00 00    	je     155 <packet_id_write+0x155>
  1f:	48 8b 05 00 00 00 00 	mov    rax,QWORD PTR [rip+0x0]        # 26 <packet_id_write+0x26>
			22: R_X86_64_REX_GOTPCRELX	now-0x4
  26:	4c 8b 08             	mov    r9,QWORD PTR [rax]
  29:	4d 39 c1             	cmp    r9,r8
  2c:	0f 8e 23 01 00 00    	jle    155 <packet_id_write+0x155>
  32:	4c 89 4f 08          	mov    QWORD PTR [rdi+0x8],r9
  36:	48 c7 07 01 00 00 00 	mov    QWORD PTR [rdi],0x1
  3d:	41 0f c9             	bswap  r9d
  40:	b8 00 00 00 01       	mov    eax,0x1000000
  45:	45 89 c8             	mov    r8d,r9d
  48:	84 c9                	test   cl,cl
  4a:	75 35                	jne    81 <packet_id_write+0x81>
  4c:	eb 7e                	jmp    cc <packet_id_write+0xcc>
  4e:	48 8b 05 00 00 00 00 	mov    rax,QWORD PTR [rip+0x0]        # 55 <packet_id_write+0x55>
			51: R_X86_64_REX_GOTPCRELX	now-0x4
  55:	4c 8b 00             	mov    r8,QWORD PTR [rax]
  58:	4c 89 47 08          	mov    QWORD PTR [rdi+0x8],r8
  5c:	48 8b 07             	mov    rax,QWORD PTR [rdi]
  5f:	41 b9 ff ff ff ff    	mov    r9d,0xffffffff
  65:	4c 39 c8             	cmp    rax,r9
  68:	74 ad                	je     17 <packet_id_write+0x17>
  6a:	48 ff c0             	inc    rax
  6d:	48 89 07             	mov    QWORD PTR [rdi],rax
  70:	0f c8                	bswap  eax
  72:	41 0f c8             	bswap  r8d
  75:	84 c9                	test   cl,cl
  77:	74 53                	je     cc <packet_id_write+0xcc>
  79:	84 d2                	test   dl,dl
  7b:	0f 84 b7 00 00 00    	je     138 <packet_id_write+0x138>
  81:	48 85 f6             	test   rsi,rsi
  84:	0f 84 cb 00 00 00    	je     155 <packet_id_write+0x155>
  8a:	48 8b 4e 10          	mov    rcx,QWORD PTR [rsi+0x10]
  8e:	48 85 c9             	test   rcx,rcx
  91:	0f 84 be 00 00 00    	je     155 <packet_id_write+0x155>
  97:	8b 56 08             	mov    edx,DWORD PTR [rsi+0x8]
  9a:	85 d2                	test   edx,edx
  9c:	0f 88 b3 00 00 00    	js     155 <packet_id_write+0x155>
  a2:	8b 7e 04             	mov    edi,DWORD PTR [rsi+0x4]
  a5:	83 ff 04             	cmp    edi,0x4
  a8:	0f 8c a7 00 00 00    	jl     155 <packet_id_write+0x155>
  ae:	83 c7 fc             	add    edi,0xfffffffc
  b1:	89 7e 04             	mov    DWORD PTR [rsi+0x4],edi
  b4:	83 c2 04             	add    edx,0x4
  b7:	89 56 08             	mov    DWORD PTR [rsi+0x8],edx
  ba:	44 89 04 39          	mov    DWORD PTR [rcx+rdi*1],r8d
  be:	48 8b 4e 10          	mov    rcx,QWORD PTR [rsi+0x10]
  c2:	48 85 c9             	test   rcx,rcx
  c5:	75 7f                	jne    146 <packet_id_write+0x146>
  c7:	e9 89 00 00 00       	jmp    155 <packet_id_write+0x155>
  cc:	48 85 f6             	test   rsi,rsi
  cf:	0f 84 80 00 00 00    	je     155 <packet_id_write+0x155>
  d5:	48 8b 4e 10          	mov    rcx,QWORD PTR [rsi+0x10]
  d9:	48 85 c9             	test   rcx,rcx
  dc:	74 77                	je     155 <packet_id_write+0x155>
  de:	48 63 7e 08          	movsxd rdi,DWORD PTR [rsi+0x8]
  e2:	48 85 ff             	test   rdi,rdi
  e5:	78 6e                	js     155 <packet_id_write+0x155>
  e7:	4c 63 4e 04          	movsxd r9,DWORD PTR [rsi+0x4]
  eb:	45 8d 14 39          	lea    r10d,[r9+rdi*1]
  ef:	41 83 c2 04          	add    r10d,0x4
  f3:	44 3b 16             	cmp    r10d,DWORD PTR [rsi]
  f6:	7f 5d                	jg     155 <packet_id_write+0x155>
  f8:	44 8d 57 04          	lea    r10d,[rdi+0x4]
  fc:	44 89 56 08          	mov    DWORD PTR [rsi+0x8],r10d
 100:	4c 01 c9             	add    rcx,r9
 103:	89 04 0f             	mov    DWORD PTR [rdi+rcx*1],eax
 106:	b0 01                	mov    al,0x1
 108:	84 d2                	test   dl,dl
 10a:	74 5f                	je     16b <packet_id_write+0x16b>
 10c:	48 8b 4e 10          	mov    rcx,QWORD PTR [rsi+0x10]
 110:	48 85 c9             	test   rcx,rcx
 113:	74 40                	je     155 <packet_id_write+0x155>
 115:	8b 56 08             	mov    edx,DWORD PTR [rsi+0x8]
 118:	85 d2                	test   edx,edx
 11a:	78 39                	js     155 <packet_id_write+0x155>
 11c:	48 63 46 04          	movsxd rax,DWORD PTR [rsi+0x4]
 120:	8d 3c 10             	lea    edi,[rax+rdx*1]
 123:	83 c7 04             	add    edi,0x4
 126:	3b 3e                	cmp    edi,DWORD PTR [rsi]
 128:	7f 2b                	jg     155 <packet_id_write+0x155>
 12a:	8d 7a 04             	lea    edi,[rdx+0x4]
 12d:	89 7e 08             	mov    DWORD PTR [rsi+0x8],edi
 130:	48 01 c1             	add    rcx,rax
 133:	44 89 c0             	mov    eax,r8d
 136:	eb 2c                	jmp    164 <packet_id_write+0x164>
 138:	48 85 f6             	test   rsi,rsi
 13b:	74 18                	je     155 <packet_id_write+0x155>
 13d:	48 8b 4e 10          	mov    rcx,QWORD PTR [rsi+0x10]
 141:	48 85 c9             	test   rcx,rcx
 144:	74 0f                	je     155 <packet_id_write+0x155>
 146:	8b 7e 08             	mov    edi,DWORD PTR [rsi+0x8]
 149:	85 ff                	test   edi,edi
 14b:	78 08                	js     155 <packet_id_write+0x155>
 14d:	8b 56 04             	mov    edx,DWORD PTR [rsi+0x4]
 150:	83 fa 04             	cmp    edx,0x4
 153:	7d 03                	jge    158 <packet_id_write+0x158>
 155:	31 c0                	xor    eax,eax
 157:	c3                   	ret
 158:	83 c2 fc             	add    edx,0xfffffffc
 15b:	89 56 04             	mov    DWORD PTR [rsi+0x4],edx
 15e:	83 c7 04             	add    edi,0x4
 161:	89 7e 08             	mov    DWORD PTR [rsi+0x8],edi
 164:	89 d2                	mov    edx,edx
 166:	89 04 11             	mov    DWORD PTR [rcx+rdx*1],eax
 169:	b0 01                	mov    al,0x1
 16b:	c3                   	ret

Disassembly of section .text.packet_id_net_print:

0000000000000000 <packet_id_net_print>:
   0:	55                   	push   rbp
   1:	41 57                	push   r15
   3:	41 56                	push   r14
   5:	53                   	push   rbx
   6:	48 83 ec 18          	sub    rsp,0x18
   a:	48 89 d3             	mov    rbx,rdx
   d:	89 f5                	mov    ebp,esi
   f:	49 89 fe             	mov    r14,rdi
  12:	49 89 e7             	mov    r15,rsp
  15:	be 00 01 00 00       	mov    esi,0x100
  1a:	4c 89 ff             	mov    rdi,r15
  1d:	e8 00 00 00 00       	call   22 <packet_id_net_print+0x22>
			1e: R_X86_64_PLT32	alloc_buf_gc-0x4
  22:	49 8b 16             	mov    rdx,QWORD PTR [r14]
  25:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 2c <packet_id_net_print+0x2c>
			28: R_X86_64_PC32	.L.str.12-0x4
  2c:	4c 89 ff             	mov    rdi,r15
  2f:	31 c0                	xor    eax,eax
  31:	e8 00 00 00 00       	call   36 <packet_id_net_print+0x36>
			32: R_X86_64_PLT32	buf_printf-0x4
  36:	85 ed                	test   ebp,ebp
  38:	74 2f                	je     69 <packet_id_net_print+0x69>
  3a:	4d 8b 76 08          	mov    r14,QWORD PTR [r14+0x8]
  3e:	4d 85 f6             	test   r14,r14
  41:	74 26                	je     69 <packet_id_net_print+0x69>
  43:	4c 89 f7             	mov    rdi,r14
  46:	31 f6                	xor    esi,esi
  48:	31 d2                	xor    edx,edx
  4a:	48 89 d9             	mov    rcx,rbx
  4d:	e8 00 00 00 00       	call   52 <packet_id_net_print+0x52>
			4e: R_X86_64_PLT32	time_string-0x4
  52:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 59 <packet_id_net_print+0x59>
			55: R_X86_64_PC32	.L.str.13-0x4
  59:	48 89 e7             	mov    rdi,rsp
  5c:	4c 89 f2             	mov    rdx,r14
  5f:	48 89 c1             	mov    rcx,rax
  62:	31 c0                	xor    eax,eax
  64:	e8 00 00 00 00       	call   69 <packet_id_net_print+0x69>
			65: R_X86_64_PLT32	buf_printf-0x4
  69:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 70 <packet_id_net_print+0x70>
			6c: R_X86_64_PC32	.L.str.14-0x4
  70:	31 db                	xor    ebx,ebx
  72:	48 89 e7             	mov    rdi,rsp
  75:	31 c0                	xor    eax,eax
  77:	e8 00 00 00 00       	call   7c <packet_id_net_print+0x7c>
			78: R_X86_64_PLT32	buf_printf-0x4
  7c:	48 8b 44 24 10       	mov    rax,QWORD PTR [rsp+0x10]
  81:	48 63 4c 24 04       	movsxd rcx,DWORD PTR [rsp+0x4]
  86:	48 01 c1             	add    rcx,rax
  89:	83 7c 24 08 00       	cmp    DWORD PTR [rsp+0x8],0x0
  8e:	48 0f 49 d9          	cmovns rbx,rcx
  92:	48 85 c0             	test   rax,rax
  95:	48 0f 44 d8          	cmove  rbx,rax
  99:	48 89 d8             	mov    rax,rbx
  9c:	48 83 c4 18          	add    rsp,0x18
  a0:	5b                   	pop    rbx
  a1:	41 5e                	pop    r14
  a3:	41 5f                	pop    r15
  a5:	5d                   	pop    rbp
  a6:	c3                   	ret

Disassembly of section .text.packet_id_persist_init:

0000000000000000 <packet_id_persist_init>:
   0:	48 c7 07 00 00 00 00 	mov    QWORD PTR [rdi],0x0
   7:	c7 47 08 ff ff ff ff 	mov    DWORD PTR [rdi+0x8],0xffffffff
   e:	48 c7 47 20 00 00 00 	mov    QWORD PTR [rdi+0x20],0x0
  15:	00 
  16:	48 c7 47 10 00 00 00 	mov    QWORD PTR [rdi+0x10],0x0
  1d:	00 
  1e:	c7 47 28 00 00 00 00 	mov    DWORD PTR [rdi+0x28],0x0
  25:	c7 47 18 00 00 00 00 	mov    DWORD PTR [rdi+0x18],0x0
  2c:	c3                   	ret

Disassembly of section .text.packet_id_persist_close:

0000000000000000 <packet_id_persist_close>:
   0:	53                   	push   rbx
   1:	48 89 fb             	mov    rbx,rdi
   4:	8b 7f 08             	mov    edi,DWORD PTR [rdi+0x8]
   7:	85 ff                	test   edi,edi
   9:	78 65                	js     70 <packet_id_persist_close+0x70>
   b:	e8 00 00 00 00       	call   10 <packet_id_persist_close+0x10>
			c: R_X86_64_PLT32	close-0x4
  10:	85 c0                	test   eax,eax
  12:	74 30                	je     44 <packet_id_persist_close+0x44>
  14:	48 8b 05 00 00 00 00 	mov    rax,QWORD PTR [rip+0x0]        # 1b <packet_id_persist_close+0x1b>
			17: R_X86_64_REX_GOTPCRELX	x_debug_level-0x4
  1b:	83 38 00             	cmp    DWORD PTR [rax],0x0
  1e:	74 24                	je     44 <packet_id_persist_close+0x44>
  20:	bf 21 01 00 0c       	mov    edi,0xc000121
  25:	e8 00 00 00 00       	call   2a <packet_id_persist_close+0x2a>
			26: R_X86_64_PLT32	dont_mute-0x4
  2a:	84 c0                	test   al,al
  2c:	74 16                	je     44 <packet_id_persist_close+0x44>
  2e:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
  31:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 38 <packet_id_persist_close+0x38>
			34: R_X86_64_PC32	.L.str.15-0x4
  38:	bf 21 01 00 0c       	mov    edi,0xc000121
  3d:	31 c0                	xor    eax,eax
  3f:	e8 00 00 00 00       	call   44 <packet_id_persist_close+0x44>
			40: R_X86_64_PLT32	x_msg-0x4
  44:	48 c7 03 00 00 00 00 	mov    QWORD PTR [rbx],0x0
  4b:	c7 43 08 ff ff ff ff 	mov    DWORD PTR [rbx+0x8],0xffffffff
  52:	48 c7 43 20 00 00 00 	mov    QWORD PTR [rbx+0x20],0x0
  59:	00 
  5a:	48 c7 43 10 00 00 00 	mov    QWORD PTR [rbx+0x10],0x0
  61:	00 
  62:	c7 43 28 00 00 00 00 	mov    DWORD PTR [rbx+0x28],0x0
  69:	c7 43 18 00 00 00 00 	mov    DWORD PTR [rbx+0x18],0x0
  70:	5b                   	pop    rbx
  71:	c3                   	ret

Disassembly of section .text.packet_id_persist_load:

0000000000000000 <packet_id_persist_load>:
   0:	41 56                	push   r14
   2:	53                   	push   rbx
   3:	48 83 ec 28          	sub    rsp,0x28
   7:	0f 57 c0             	xorps  xmm0,xmm0
   a:	0f 29 04 24          	movaps XMMWORD PTR [rsp],xmm0
   e:	83 7f 08 00          	cmp    DWORD PTR [rdi+0x8],0x0
  12:	78 08                	js     1c <packet_id_persist_load+0x1c>
  14:	48 83 c4 28          	add    rsp,0x28
  18:	5b                   	pop    rbx
  19:	41 5e                	pop    r14
  1b:	c3                   	ret
  1c:	48 89 fb             	mov    rbx,rdi
  1f:	49 89 f6             	mov    r14,rsi
  22:	48 89 f7             	mov    rdi,rsi
  25:	be 42 00 00 00       	mov    esi,0x42
  2a:	ba 80 01 00 00       	mov    edx,0x180
  2f:	e8 00 00 00 00       	call   34 <packet_id_persist_load+0x34>
			30: R_X86_64_PLT32	platform_open-0x4
  34:	89 43 08             	mov    DWORD PTR [rbx+0x8],eax
  37:	83 f8 ff             	cmp    eax,0xffffffff
  3a:	0f 84 9f 00 00 00    	je     df <packet_id_persist_load+0xdf>
  40:	89 c7                	mov    edi,eax
  42:	be 06 00 00 00       	mov    esi,0x6
  47:	e8 00 00 00 00       	call   4c <packet_id_persist_load+0x4c>
			48: R_X86_64_PLT32	flock-0x4
  4c:	85 c0                	test   eax,eax
  4e:	0f 85 18 01 00 00    	jne    16c <packet_id_persist_load+0x16c>
  54:	4c 89 33             	mov    QWORD PTR [rbx],r14
  57:	8b 7b 08             	mov    edi,DWORD PTR [rbx+0x8]
  5a:	48 8d 74 24 18       	lea    rsi,[rsp+0x18]
  5f:	ba 10 00 00 00       	mov    edx,0x10
  64:	e8 00 00 00 00       	call   69 <packet_id_persist_load+0x69>
			65: R_X86_64_PLT32	read-0x4
  69:	48 83 f8 ff          	cmp    rax,0xffffffffffffffff
  6d:	0f 84 9e 00 00 00    	je     111 <packet_id_persist_load+0x111>
  73:	48 83 f8 10          	cmp    rax,0x10
  77:	0f 85 c4 00 00 00    	jne    141 <packet_id_persist_load+0x141>
  7d:	48 8b 44 24 18       	mov    rax,QWORD PTR [rsp+0x18]
  82:	48 89 43 20          	mov    QWORD PTR [rbx+0x20],rax
  86:	48 89 43 10          	mov    QWORD PTR [rbx+0x10],rax
  8a:	8b 44 24 20          	mov    eax,DWORD PTR [rsp+0x20]
  8e:	89 43 28             	mov    DWORD PTR [rbx+0x28],eax
  91:	89 43 18             	mov    DWORD PTR [rbx+0x18],eax
  94:	48 8b 05 00 00 00 00 	mov    rax,QWORD PTR [rip+0x0]        # 9b <packet_id_persist_load+0x9b>
			97: R_X86_64_REX_GOTPCRELX	x_debug_level-0x4
  9b:	83 38 09             	cmp    DWORD PTR [rax],0x9
  9e:	0f 82 9d 00 00 00    	jb     141 <packet_id_persist_load+0x141>
  a4:	bf 89 00 00 46       	mov    edi,0x46000089
  a9:	e8 00 00 00 00       	call   ae <packet_id_persist_load+0xae>
			aa: R_X86_64_PLT32	dont_mute-0x4
  ae:	84 c0                	test   al,al
  b0:	0f 84 8b 00 00 00    	je     141 <packet_id_persist_load+0x141>
  b6:	4c 8b 33             	mov    r14,QWORD PTR [rbx]
  b9:	48 89 e6             	mov    rsi,rsp
  bc:	48 89 df             	mov    rdi,rbx
  bf:	e8 00 00 00 00       	call   c4 <packet_id_persist_load+0xc4>
			c0: R_X86_64_PLT32	packet_id_persist_print-0x4
  c4:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # cb <packet_id_persist_load+0xcb>
			c7: R_X86_64_PC32	.L.str.18-0x4
  cb:	bf 89 00 00 46       	mov    edi,0x46000089
  d0:	4c 89 f2             	mov    rdx,r14
  d3:	48 89 c1             	mov    rcx,rax
  d6:	31 c0                	xor    eax,eax
  d8:	e8 00 00 00 00       	call   dd <packet_id_persist_load+0xdd>
			d9: R_X86_64_PLT32	x_msg-0x4
  dd:	eb 62                	jmp    141 <packet_id_persist_load+0x141>
  df:	48 8b 05 00 00 00 00 	mov    rax,QWORD PTR [rip+0x0]        # e6 <packet_id_persist_load+0xe6>
			e2: R_X86_64_REX_GOTPCRELX	x_debug_level-0x4
  e6:	83 38 00             	cmp    DWORD PTR [rax],0x0
  e9:	74 65                	je     150 <packet_id_persist_load+0x150>
  eb:	bf 21 01 00 0c       	mov    edi,0xc000121
  f0:	e8 00 00 00 00       	call   f5 <packet_id_persist_load+0xf5>
			f1: R_X86_64_PLT32	dont_mute-0x4
  f5:	84 c0                	test   al,al
  f7:	74 57                	je     150 <packet_id_persist_load+0x150>
  f9:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 100 <packet_id_persist_load+0x100>
			fc: R_X86_64_PC32	.L.str.16-0x4
 100:	bf 21 01 00 0c       	mov    edi,0xc000121
 105:	4c 89 f2             	mov    rdx,r14
 108:	31 c0                	xor    eax,eax
 10a:	e8 00 00 00 00       	call   10f <packet_id_persist_load+0x10f>
			10b: R_X86_64_PLT32	x_msg-0x4
 10f:	eb 3f                	jmp    150 <packet_id_persist_load+0x150>
 111:	48 8b 05 00 00 00 00 	mov    rax,QWORD PTR [rip+0x0]        # 118 <packet_id_persist_load+0x118>
			114: R_X86_64_REX_GOTPCRELX	x_debug_level-0x4
 118:	83 38 00             	cmp    DWORD PTR [rax],0x0
 11b:	74 24                	je     141 <packet_id_persist_load+0x141>
 11d:	bf 21 01 00 0c       	mov    edi,0xc000121
 122:	e8 00 00 00 00       	call   127 <packet_id_persist_load+0x127>
			123: R_X86_64_PLT32	dont_mute-0x4
 127:	84 c0                	test   al,al
 129:	74 16                	je     141 <packet_id_persist_load+0x141>
 12b:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
 12e:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 135 <packet_id_persist_load+0x135>
			131: R_X86_64_PC32	.L.str.19-0x4
 135:	bf 21 01 00 0c       	mov    edi,0xc000121
 13a:	31 c0                	xor    eax,eax
 13c:	e8 00 00 00 00       	call   141 <packet_id_persist_load+0x141>
			13d: R_X86_64_PLT32	x_msg-0x4
 141:	48 83 3c 24 00       	cmp    QWORD PTR [rsp],0x0
 146:	74 08                	je     150 <packet_id_persist_load+0x150>
 148:	48 89 e7             	mov    rdi,rsp
 14b:	e8 00 00 00 00       	call   150 <packet_id_persist_load+0x150>
			14c: R_X86_64_PLT32	x_gc_free-0x4
 150:	48 83 7c 24 08 00    	cmp    QWORD PTR [rsp+0x8],0x0
 156:	0f 84 b8 fe ff ff    	je     14 <packet_id_persist_load+0x14>
 15c:	48 89 e7             	mov    rdi,rsp
 15f:	e8 00 00 00 00       	call   164 <packet_id_persist_load+0x164>
			160: R_X86_64_PLT32	x_gc_freespecial-0x4
 164:	48 83 c4 28          	add    rsp,0x28
 168:	5b                   	pop    rbx
 169:	41 5e                	pop    r14
 16b:	c3                   	ret
 16c:	bf 10 01 00 00       	mov    edi,0x110
 171:	e8 00 00 00 00       	call   176 <packet_id_persist_load+0x176>
			172: R_X86_64_PLT32	dont_mute-0x4
 176:	84 c0                	test   al,al
 178:	74 16                	je     190 <packet_id_persist_load+0x190>
 17a:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 181 <packet_id_persist_load+0x181>
			17d: R_X86_64_PC32	.L.str.17-0x4
 181:	bf 10 01 00 00       	mov    edi,0x110
 186:	4c 89 f2             	mov    rdx,r14
 189:	31 c0                	xor    eax,eax
 18b:	e8 00 00 00 00       	call   190 <packet_id_persist_load+0x190>
			18c: R_X86_64_PLT32	x_msg-0x4
 190:	bf 01 00 00 00       	mov    edi,0x1
 195:	e8 00 00 00 00       	call   19a <.L.str.16+0x30>
			196: R_X86_64_PLT32	_exit-0x4

Disassembly of section .text.packet_id_persist_print:

0000000000000000 <packet_id_persist_print>:
   0:	41 57                	push   r15
   2:	41 56                	push   r14
   4:	53                   	push   rbx
   5:	48 83 ec 20          	sub    rsp,0x20
   9:	48 89 f3             	mov    rbx,rsi
   c:	49 89 fe             	mov    r14,rdi
   f:	4c 8d 7c 24 08       	lea    r15,[rsp+0x8]
  14:	be 00 01 00 00       	mov    esi,0x100
  19:	4c 89 ff             	mov    rdi,r15
  1c:	48 89 da             	mov    rdx,rbx
  1f:	e8 00 00 00 00       	call   24 <packet_id_persist_print+0x24>
			20: R_X86_64_PLT32	alloc_buf_gc-0x4
  24:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 2b <packet_id_persist_print+0x2b>
			27: R_X86_64_PC32	.L.str.23-0x4
  2b:	4c 89 ff             	mov    rdi,r15
  2e:	31 c0                	xor    eax,eax
  30:	e8 00 00 00 00       	call   35 <packet_id_persist_print+0x35>
			31: R_X86_64_PLT32	buf_printf-0x4
  35:	41 83 7e 08 00       	cmp    DWORD PTR [r14+0x8],0x0
  3a:	78 48                	js     84 <packet_id_persist_print+0x84>
  3c:	41 8b 56 18          	mov    edx,DWORD PTR [r14+0x18]
  40:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 47 <packet_id_persist_print+0x47>
			43: R_X86_64_PC32	.L.str.24-0x4
  47:	48 8d 7c 24 08       	lea    rdi,[rsp+0x8]
  4c:	31 c0                	xor    eax,eax
  4e:	e8 00 00 00 00       	call   53 <packet_id_persist_print+0x53>
			4f: R_X86_64_PLT32	buf_printf-0x4
  53:	4d 8b 76 10          	mov    r14,QWORD PTR [r14+0x10]
  57:	4d 85 f6             	test   r14,r14
  5a:	74 28                	je     84 <packet_id_persist_print+0x84>
  5c:	4c 89 f7             	mov    rdi,r14
  5f:	31 f6                	xor    esi,esi
  61:	31 d2                	xor    edx,edx
  63:	48 89 d9             	mov    rcx,rbx
  66:	e8 00 00 00 00       	call   6b <packet_id_persist_print+0x6b>
			67: R_X86_64_PLT32	time_string-0x4
  6b:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 72 <packet_id_persist_print+0x72>
			6e: R_X86_64_PC32	.L.str.13-0x4
  72:	48 8d 7c 24 08       	lea    rdi,[rsp+0x8]
  77:	4c 89 f2             	mov    rdx,r14
  7a:	48 89 c1             	mov    rcx,rax
  7d:	31 c0                	xor    eax,eax
  7f:	e8 00 00 00 00       	call   84 <packet_id_persist_print+0x84>
			80: R_X86_64_PLT32	buf_printf-0x4
  84:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 8b <packet_id_persist_print+0x8b>
			87: R_X86_64_PC32	.L.str.14-0x4
  8b:	48 8d 7c 24 08       	lea    rdi,[rsp+0x8]
  90:	31 c0                	xor    eax,eax
  92:	e8 00 00 00 00       	call   97 <packet_id_persist_print+0x97>
			93: R_X86_64_PLT32	buf_printf-0x4
  97:	48 8b 44 24 18       	mov    rax,QWORD PTR [rsp+0x18]
  9c:	48 83 c4 20          	add    rsp,0x20
  a0:	5b                   	pop    rbx
  a1:	41 5e                	pop    r14
  a3:	41 5f                	pop    r15
  a5:	c3                   	ret

Disassembly of section .text.packet_id_persist_save:

0000000000000000 <packet_id_persist_save>:
   0:	48 89 f8             	mov    rax,rdi
   3:	8b 7f 08             	mov    edi,DWORD PTR [rdi+0x8]
   6:	85 ff                	test   edi,edi
   8:	0f 88 3c 01 00 00    	js     14a <packet_id_persist_save+0x14a>
   e:	48 8b 48 10          	mov    rcx,QWORD PTR [rax+0x10]
  12:	48 85 c9             	test   rcx,rcx
  15:	0f 84 2f 01 00 00    	je     14a <packet_id_persist_save+0x14a>
  1b:	8b 50 18             	mov    edx,DWORD PTR [rax+0x18]
  1e:	48 3b 48 20          	cmp    rcx,QWORD PTR [rax+0x20]
  22:	75 09                	jne    2d <packet_id_persist_save+0x2d>
  24:	3b 50 28             	cmp    edx,DWORD PTR [rax+0x28]
  27:	0f 84 1d 01 00 00    	je     14a <packet_id_persist_save+0x14a>
  2d:	53                   	push   rbx
  2e:	48 83 ec 20          	sub    rsp,0x20
  32:	48 89 c3             	mov    rbx,rax
  35:	48 c7 44 24 18 00 00 	mov    QWORD PTR [rsp+0x18],0x0
  3c:	00 00 
  3e:	0f 57 c0             	xorps  xmm0,xmm0
  41:	0f 29 04 24          	movaps XMMWORD PTR [rsp],xmm0
  45:	48 89 4c 24 10       	mov    QWORD PTR [rsp+0x10],rcx
  4a:	89 54 24 18          	mov    DWORD PTR [rsp+0x18],edx
  4e:	31 f6                	xor    esi,esi
  50:	31 d2                	xor    edx,edx
  52:	e8 00 00 00 00       	call   57 <packet_id_persist_save+0x57>
			53: R_X86_64_PLT32	lseek-0x4
  57:	48 85 c0             	test   rax,rax
  5a:	74 31                	je     8d <packet_id_persist_save+0x8d>
  5c:	48 8b 05 00 00 00 00 	mov    rax,QWORD PTR [rip+0x0]        # 63 <packet_id_persist_save+0x63>
			5f: R_X86_64_REX_GOTPCRELX	x_debug_level-0x4
  63:	83 38 00             	cmp    DWORD PTR [rax],0x0
  66:	0f 84 ba 00 00 00    	je     126 <packet_id_persist_save+0x126>
  6c:	bf 21 01 00 0c       	mov    edi,0xc000121
  71:	e8 00 00 00 00       	call   76 <packet_id_persist_save+0x76>
			72: R_X86_64_PLT32	dont_mute-0x4
  76:	84 c0                	test   al,al
  78:	0f 84 a8 00 00 00    	je     126 <packet_id_persist_save+0x126>
  7e:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
  81:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 88 <packet_id_persist_save+0x88>
			84: R_X86_64_PC32	.L.str.22-0x4
  88:	e9 8d 00 00 00       	jmp    11a <packet_id_persist_save+0x11a>
  8d:	8b 7b 08             	mov    edi,DWORD PTR [rbx+0x8]
  90:	48 8d 74 24 10       	lea    rsi,[rsp+0x10]
  95:	ba 10 00 00 00       	mov    edx,0x10
  9a:	e8 00 00 00 00       	call   9f <packet_id_persist_save+0x9f>
			9b: R_X86_64_PLT32	write-0x4
  9f:	48 83 f8 10          	cmp    rax,0x10
  a3:	75 51                	jne    f6 <packet_id_persist_save+0xf6>
  a5:	48 8b 4b 10          	mov    rcx,QWORD PTR [rbx+0x10]
  a9:	48 89 4b 20          	mov    QWORD PTR [rbx+0x20],rcx
  ad:	8b 4b 18             	mov    ecx,DWORD PTR [rbx+0x18]
  b0:	89 4b 28             	mov    DWORD PTR [rbx+0x28],ecx
  b3:	48 8b 05 00 00 00 00 	mov    rax,QWORD PTR [rip+0x0]        # ba <packet_id_persist_save+0xba>
			b6: R_X86_64_REX_GOTPCRELX	x_debug_level-0x4
  ba:	83 38 09             	cmp    DWORD PTR [rax],0x9
  bd:	72 67                	jb     126 <packet_id_persist_save+0x126>
  bf:	bf 89 00 00 46       	mov    edi,0x46000089
  c4:	e8 00 00 00 00       	call   c9 <packet_id_persist_save+0xc9>
			c5: R_X86_64_PLT32	dont_mute-0x4
  c9:	84 c0                	test   al,al
  cb:	74 59                	je     126 <packet_id_persist_save+0x126>
  cd:	48 89 df             	mov    rdi,rbx
  d0:	48 8b 1b             	mov    rbx,QWORD PTR [rbx]
  d3:	48 89 e6             	mov    rsi,rsp
  d6:	e8 00 00 00 00       	call   db <packet_id_persist_save+0xdb>
			d7: R_X86_64_PLT32	packet_id_persist_print-0x4
  db:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # e2 <packet_id_persist_save+0xe2>
			de: R_X86_64_PC32	.L.str.20-0x4
  e2:	bf 89 00 00 46       	mov    edi,0x46000089
  e7:	48 89 da             	mov    rdx,rbx
  ea:	48 89 c1             	mov    rcx,rax
  ed:	31 c0                	xor    eax,eax
  ef:	e8 00 00 00 00       	call   f4 <packet_id_persist_save+0xf4>
			f0: R_X86_64_PLT32	x_msg-0x4
  f4:	eb 30                	jmp    126 <packet_id_persist_save+0x126>
  f6:	48 8b 05 00 00 00 00 	mov    rax,QWORD PTR [rip+0x0]        # fd <packet_id_persist_save+0xfd>
			f9: R_X86_64_REX_GOTPCRELX	x_debug_level-0x4
  fd:	83 38 00             	cmp    DWORD PTR [rax],0x0
 100:	74 24                	je     126 <packet_id_persist_save+0x126>
 102:	bf 21 01 00 0c       	mov    edi,0xc000121
 107:	e8 00 00 00 00       	call   10c <packet_id_persist_save+0x10c>
			108: R_X86_64_PLT32	dont_mute-0x4
 10c:	84 c0                	test   al,al
 10e:	74 16                	je     126 <packet_id_persist_save+0x126>
 110:	48 8b 13             	mov    rdx,QWORD PTR [rbx]
 113:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 11a <packet_id_persist_save+0x11a>
			116: R_X86_64_PC32	.L.str.21-0x4
 11a:	bf 21 01 00 0c       	mov    edi,0xc000121
 11f:	31 c0                	xor    eax,eax
 121:	e8 00 00 00 00       	call   126 <packet_id_persist_save+0x126>
			122: R_X86_64_PLT32	x_msg-0x4
 126:	48 83 3c 24 00       	cmp    QWORD PTR [rsp],0x0
 12b:	74 08                	je     135 <packet_id_persist_save+0x135>
 12d:	48 89 e7             	mov    rdi,rsp
 130:	e8 00 00 00 00       	call   135 <packet_id_persist_save+0x135>
			131: R_X86_64_PLT32	x_gc_free-0x4
 135:	48 83 7c 24 08 00    	cmp    QWORD PTR [rsp+0x8],0x0
 13b:	74 08                	je     145 <packet_id_persist_save+0x145>
 13d:	48 89 e7             	mov    rdi,rsp
 140:	e8 00 00 00 00       	call   145 <packet_id_persist_save+0x145>
			141: R_X86_64_PLT32	x_gc_freespecial-0x4
 145:	48 83 c4 20          	add    rsp,0x20
 149:	5b                   	pop    rbx
 14a:	c3                   	ret

Disassembly of section .text.packet_id_persist_load_obj:

0000000000000000 <packet_id_persist_load_obj>:
   0:	48 85 ff             	test   rdi,rdi
   3:	0f 94 c0             	sete   al
   6:	48 85 f6             	test   rsi,rsi
   9:	0f 94 c1             	sete   cl
   c:	08 c1                	or     cl,al
   e:	75 1a                	jne    2a <packet_id_persist_load_obj+0x2a>
  10:	83 7f 08 00          	cmp    DWORD PTR [rdi+0x8],0x0
  14:	78 14                	js     2a <packet_id_persist_load_obj+0x2a>
  16:	48 8b 47 10          	mov    rax,QWORD PTR [rdi+0x10]
  1a:	48 85 c0             	test   rax,rax
  1d:	74 0b                	je     2a <packet_id_persist_load_obj+0x2a>
  1f:	48 89 46 18          	mov    QWORD PTR [rsi+0x18],rax
  23:	8b 47 18             	mov    eax,DWORD PTR [rdi+0x18]
  26:	48 89 46 20          	mov    QWORD PTR [rsi+0x20],rax
  2a:	c3                   	ret

Disassembly of section .text.packet_id_read_epoch:

0000000000000000 <packet_id_read_epoch>:
   0:	8b 4e 08             	mov    ecx,DWORD PTR [rsi+0x8]
   3:	83 f9 08             	cmp    ecx,0x8
   6:	7c 1b                	jl     23 <packet_id_read_epoch+0x23>
   8:	48 8b 46 10          	mov    rax,QWORD PTR [rsi+0x10]
   c:	48 63 56 04          	movsxd rdx,DWORD PTR [rsi+0x4]
  10:	44 8d 42 08          	lea    r8d,[rdx+0x8]
  14:	44 89 46 04          	mov    DWORD PTR [rsi+0x4],r8d
  18:	83 c1 f8             	add    ecx,0xfffffff8
  1b:	89 4e 08             	mov    DWORD PTR [rsi+0x8],ecx
  1e:	48 85 c0             	test   rax,rax
  21:	75 03                	jne    26 <packet_id_read_epoch+0x26>
  23:	31 c0                	xor    eax,eax
  25:	c3                   	ret
  26:	48 8b 04 10          	mov    rax,QWORD PTR [rax+rdx*1]
  2a:	48 0f c8             	bswap  rax
  2d:	48 b9 ff ff ff ff ff 	movabs rcx,0xffffffffffff
  34:	ff 00 00 
  37:	48 21 c1             	and    rcx,rax
  3a:	48 c1 e8 30          	shr    rax,0x30
  3e:	48 89 0f             	mov    QWORD PTR [rdi],rcx
  41:	c3                   	ret

Disassembly of section .text.packet_id_write_epoch:

0000000000000000 <packet_id_write_epoch>:
   0:	48 83 7f 08 00       	cmp    QWORD PTR [rdi+0x8],0x0
   5:	74 14                	je     1b <packet_id_write_epoch+0x1b>
   7:	48 8b 07             	mov    rax,QWORD PTR [rdi]
   a:	48 b9 ff ff ff ff ff 	movabs rcx,0xffffffffffff
  11:	ff 00 00 
  14:	48 39 c8             	cmp    rax,rcx
  17:	75 22                	jne    3b <packet_id_write_epoch+0x3b>
  19:	eb 4e                	jmp    69 <packet_id_write_epoch+0x69>
  1b:	48 8b 05 00 00 00 00 	mov    rax,QWORD PTR [rip+0x0]        # 22 <packet_id_write_epoch+0x22>
			1e: R_X86_64_REX_GOTPCRELX	now-0x4
  22:	48 8b 00             	mov    rax,QWORD PTR [rax]
  25:	48 89 47 08          	mov    QWORD PTR [rdi+0x8],rax
  29:	48 8b 07             	mov    rax,QWORD PTR [rdi]
  2c:	48 b9 ff ff ff ff ff 	movabs rcx,0xffffffffffff
  33:	ff 00 00 
  36:	48 39 c8             	cmp    rax,rcx
  39:	74 2e                	je     69 <packet_id_write_epoch+0x69>
  3b:	48 ff c0             	inc    rax
  3e:	48 89 07             	mov    QWORD PTR [rdi],rax
  41:	48 85 d2             	test   rdx,rdx
  44:	74 23                	je     69 <packet_id_write_epoch+0x69>
  46:	48 8b 4a 10          	mov    rcx,QWORD PTR [rdx+0x10]
  4a:	48 85 c9             	test   rcx,rcx
  4d:	74 1a                	je     69 <packet_id_write_epoch+0x69>
  4f:	48 63 7a 08          	movsxd rdi,DWORD PTR [rdx+0x8]
  53:	48 85 ff             	test   rdi,rdi
  56:	78 11                	js     69 <packet_id_write_epoch+0x69>
  58:	4c 63 42 04          	movsxd r8,DWORD PTR [rdx+0x4]
  5c:	45 8d 0c 38          	lea    r9d,[r8+rdi*1]
  60:	41 83 c1 08          	add    r9d,0x8
  64:	44 3b 0a             	cmp    r9d,DWORD PTR [rdx]
  67:	7e 03                	jle    6c <packet_id_write_epoch+0x6c>
  69:	31 c0                	xor    eax,eax
  6b:	c3                   	ret
  6c:	0f b7 f6             	movzx  esi,si
  6f:	48 c1 e6 30          	shl    rsi,0x30
  73:	48 09 f0             	or     rax,rsi
  76:	48 0f c8             	bswap  rax
  79:	8d 77 08             	lea    esi,[rdi+0x8]
  7c:	89 72 08             	mov    DWORD PTR [rdx+0x8],esi
  7f:	4c 01 c1             	add    rcx,r8
  82:	48 89 04 0f          	mov    QWORD PTR [rdi+rcx*1],rax
  86:	b0 01                	mov    al,0x1
  88:	c3                   	ret

Disassembly of section .text.packet_id_debug_print:

0000000000000000 <packet_id_debug_print>:
   0:	55                   	push   rbp
   1:	41 57                	push   r15
   3:	41 56                	push   r14
   5:	41 55                	push   r13
   7:	41 54                	push   r12
   9:	53                   	push   rbx
   a:	48 83 ec 68          	sub    rsp,0x68
   e:	4d 89 c5             	mov    r13,r8
  11:	48 89 cb             	mov    rbx,rcx
  14:	48 89 54 24 48       	mov    QWORD PTR [rsp+0x48],rdx
  19:	49 89 f6             	mov    r14,rsi
  1c:	89 7c 24 0c          	mov    DWORD PTR [rsp+0xc],edi
  20:	0f 57 c0             	xorps  xmm0,xmm0
  23:	0f 29 44 24 10       	movaps XMMWORD PTR [rsp+0x10],xmm0
  28:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
  2d:	48 8d 54 24 10       	lea    rdx,[rsp+0x10]
  32:	be 00 01 00 00       	mov    esi,0x100
  37:	48 89 ef             	mov    rdi,rbp
  3a:	e8 00 00 00 00       	call   3f <packet_id_debug_print+0x3f>
			3b: R_X86_64_PLT32	alloc_buf_gc-0x4
  3f:	48 8b 05 00 00 00 00 	mov    rax,QWORD PTR [rip+0x0]        # 46 <packet_id_debug_print+0x46>
			42: R_X86_64_REX_GOTPCRELX	now-0x4
  46:	48 8b 00             	mov    rax,QWORD PTR [rax]
  49:	48 89 44 24 28       	mov    QWORD PTR [rsp+0x28],rax
  4e:	4d 8b 66 38          	mov    r12,QWORD PTR [r14+0x38]
  52:	0f 57 c0             	xorps  xmm0,xmm0
  55:	0f 29 44 24 50       	movaps XMMWORD PTR [rsp+0x50],xmm0
  5a:	48 8d 7c 24 50       	lea    rdi,[rsp+0x50]
  5f:	31 f6                	xor    esi,esi
  61:	e8 00 00 00 00       	call   66 <packet_id_debug_print+0x66>
			62: R_X86_64_PLT32	gettimeofday-0x4
  66:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 6d <packet_id_debug_print+0x6d>
			69: R_X86_64_PC32	.L.str.30-0x4
  6d:	48 89 ef             	mov    rdi,rbp
  70:	48 89 da             	mov    rdx,rbx
  73:	4c 89 e9             	mov    rcx,r13
  76:	31 c0                	xor    eax,eax
  78:	e8 00 00 00 00       	call   7d <packet_id_debug_print+0x7d>
			79: R_X86_64_PLT32	buf_printf-0x4
  7d:	49 8b 56 40          	mov    rdx,QWORD PTR [r14+0x40]
  81:	41 8b 4e 48          	mov    ecx,DWORD PTR [r14+0x48]
  85:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 8c <packet_id_debug_print+0x8c>
			88: R_X86_64_PC32	.L.str.31-0x4
  8c:	48 89 ef             	mov    rdi,rbp
  8f:	31 c0                	xor    eax,eax
  91:	e8 00 00 00 00       	call   96 <packet_id_debug_print+0x96>
			92: R_X86_64_PLT32	buf_printf-0x4
  96:	4d 85 e4             	test   r12,r12
  99:	0f 84 cd 00 00 00    	je     16c <packet_id_debug_print+0x16c>
  9f:	41 83 7c 24 04 00    	cmp    DWORD PTR [r12+0x4],0x0
  a5:	0f 8e c1 00 00 00    	jle    16c <packet_id_debug_print+0x16c>
  ab:	31 db                	xor    ebx,ebx
  ad:	4c 8d 2d 00 00 00 00 	lea    r13,[rip+0x0]        # b4 <packet_id_debug_print+0xb4>
			b0: R_X86_64_PC32	.L.str.32-0x4
  b4:	48 8d 6c 24 30       	lea    rbp,[rsp+0x30]
  b9:	45 31 ff             	xor    r15d,r15d
  bc:	eb 22                	jmp    e0 <packet_id_debug_print+0xe0>
  be:	66 90                	xchg   ax,ax
  c0:	ba 5f 00 00 00       	mov    edx,0x5f
  c5:	48 89 ef             	mov    rdi,rbp
  c8:	4c 89 ee             	mov    rsi,r13
  cb:	31 c0                	xor    eax,eax
  cd:	e8 00 00 00 00       	call   d2 <packet_id_debug_print+0xd2>
			ce: R_X86_64_PLT32	buf_printf-0x4
  d2:	41 ff c7             	inc    r15d
  d5:	45 3b 7c 24 04       	cmp    r15d,DWORD PTR [r12+0x4]
  da:	0f 8d 8c 00 00 00    	jge    16c <packet_id_debug_print+0x16c>
  e0:	41 8b 44 24 08       	mov    eax,DWORD PTR [r12+0x8]
  e5:	41 39 c7             	cmp    r15d,eax
  e8:	0f 8f bb 01 00 00    	jg     2a9 <packet_id_debug_print+0x2a9>
  ee:	41 8b 0c 24          	mov    ecx,DWORD PTR [r12]
  f2:	85 c9                	test   ecx,ecx
  f4:	0f 88 af 01 00 00    	js     2a9 <packet_id_debug_print+0x2a9>
  fa:	39 c1                	cmp    ecx,eax
  fc:	0f 8d a7 01 00 00    	jge    2a9 <packet_id_debug_print+0x2a9>
 102:	41 8d 14 0f          	lea    edx,[r15+rcx*1]
 106:	39 c2                	cmp    edx,eax
 108:	89 c2                	mov    edx,eax
 10a:	0f 42 d3             	cmovb  edx,ebx
 10d:	89 ce                	mov    esi,ecx
 10f:	29 d6                	sub    esi,edx
 111:	44 01 fe             	add    esi,r15d
 114:	c1 fe 1f             	sar    esi,0x1f
 117:	21 c6                	and    esi,eax
 119:	01 ce                	add    esi,ecx
 11b:	29 d6                	sub    esi,edx
 11d:	44 01 fe             	add    esi,r15d
 120:	48 63 c6             	movsxd rax,esi
 123:	49 8b 44 c4 10       	mov    rax,QWORD PTR [r12+rax*8+0x10]
 128:	48 85 c0             	test   rax,rax
 12b:	74 93                	je     c0 <packet_id_debug_print+0xc0>
 12d:	48 83 f8 01          	cmp    rax,0x1
 131:	75 0d                	jne    140 <packet_id_debug_print+0x140>
 133:	ba 45 00 00 00       	mov    edx,0x45
 138:	eb 8b                	jmp    c5 <packet_id_debug_print+0xc5>
 13a:	66 0f 1f 44 00 00    	nop    WORD PTR [rax+rax*1+0x0]
 140:	48 8b 4c 24 28       	mov    rcx,QWORD PTR [rsp+0x28]
 145:	89 ca                	mov    edx,ecx
 147:	29 c2                	sub    edx,eax
 149:	78 0f                	js     15a <packet_id_debug_print+0x15a>
 14b:	83 fa 0a             	cmp    edx,0xa
 14e:	72 14                	jb     164 <packet_id_debug_print+0x164>
 150:	ba 3e 00 00 00       	mov    edx,0x3e
 155:	e9 6b ff ff ff       	jmp    c5 <packet_id_debug_print+0xc5>
 15a:	ba 4e 00 00 00       	mov    edx,0x4e
 15f:	e9 61 ff ff ff       	jmp    c5 <packet_id_debug_print+0xc5>
 164:	83 c2 30             	add    edx,0x30
 167:	e9 59 ff ff ff       	jmp    c5 <packet_id_debug_print+0xc5>
 16c:	49 8b 56 08          	mov    rdx,QWORD PTR [r14+0x8]
 170:	49 8b 4e 10          	mov    rcx,QWORD PTR [r14+0x10]
 174:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 17b <packet_id_debug_print+0x17b>
			177: R_X86_64_PC32	.L.str.33-0x4
 17b:	48 8d 7c 24 30       	lea    rdi,[rsp+0x30]
 180:	31 c0                	xor    eax,eax
 182:	e8 00 00 00 00       	call   187 <packet_id_debug_print+0x187>
			183: R_X86_64_PLT32	buf_printf-0x4
 187:	48 8b 44 24 48       	mov    rax,QWORD PTR [rsp+0x48]
 18c:	48 85 c0             	test   rax,rax
 18f:	74 1a                	je     1ab <packet_id_debug_print+0x1ab>
 191:	48 8b 08             	mov    rcx,QWORD PTR [rax]
 194:	48 8b 50 08          	mov    rdx,QWORD PTR [rax+0x8]
 198:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 19f <packet_id_debug_print+0x19f>
			19b: R_X86_64_PC32	.L.str.34-0x4
 19f:	48 8d 7c 24 30       	lea    rdi,[rsp+0x30]
 1a4:	31 c0                	xor    eax,eax
 1a6:	e8 00 00 00 00       	call   1ab <packet_id_debug_print+0x1ab>
			1a7: R_X86_64_PLT32	buf_printf-0x4
 1ab:	8b 6c 24 50          	mov    ebp,DWORD PTR [rsp+0x50]
 1af:	48 8b 54 24 28       	mov    rdx,QWORD PTR [rsp+0x28]
 1b4:	89 d1                	mov    ecx,edx
 1b6:	29 e9                	sub    ecx,ebp
 1b8:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 1bf <packet_id_debug_print+0x1bf>
			1bb: R_X86_64_PC32	.L.str.35-0x4
 1bf:	48 8d 5c 24 30       	lea    rbx,[rsp+0x30]
 1c4:	48 89 df             	mov    rdi,rbx
 1c7:	31 c0                	xor    eax,eax
 1c9:	e8 00 00 00 00       	call   1ce <packet_id_debug_print+0x1ce>
			1ca: R_X86_64_PLT32	buf_printf-0x4
 1ce:	41 8b 16             	mov    edx,DWORD PTR [r14]
 1d1:	29 ea                	sub    edx,ebp
 1d3:	49 8b 4e 18          	mov    rcx,QWORD PTR [r14+0x18]
 1d7:	45 8b 46 20          	mov    r8d,DWORD PTR [r14+0x20]
 1db:	4d 8b 4e 28          	mov    r9,QWORD PTR [r14+0x28]
 1df:	41 0f b6 46 30       	movzx  eax,BYTE PTR [r14+0x30]
 1e4:	89 04 24             	mov    DWORD PTR [rsp],eax
 1e7:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 1ee <packet_id_debug_print+0x1ee>
			1ea: R_X86_64_PC32	.L.str.36-0x4
 1ee:	48 89 df             	mov    rdi,rbx
 1f1:	31 c0                	xor    eax,eax
 1f3:	e8 00 00 00 00       	call   1f8 <packet_id_debug_print+0x1f8>
			1f4: R_X86_64_PLT32	buf_printf-0x4
 1f8:	4d 85 e4             	test   r12,r12
 1fb:	74 26                	je     223 <packet_id_debug_print+0x223>
 1fd:	41 8b 14 24          	mov    edx,DWORD PTR [r12]
 201:	41 8b 4c 24 04       	mov    ecx,DWORD PTR [r12+0x4]
 206:	45 8b 44 24 08       	mov    r8d,DWORD PTR [r12+0x8]
 20b:	45 8b 4c 24 0c       	mov    r9d,DWORD PTR [r12+0xc]
 210:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 217 <packet_id_debug_print+0x217>
			213: R_X86_64_PC32	.L.str.37-0x4
 217:	48 8d 7c 24 30       	lea    rdi,[rsp+0x30]
 21c:	31 c0                	xor    eax,eax
 21e:	e8 00 00 00 00       	call   223 <packet_id_debug_print+0x223>
			21f: R_X86_64_PLT32	buf_printf-0x4
 223:	8b 5c 24 0c          	mov    ebx,DWORD PTR [rsp+0xc]
 227:	89 d8                	mov    eax,ebx
 229:	83 e0 0f             	and    eax,0xf
 22c:	48 8b 0d 00 00 00 00 	mov    rcx,QWORD PTR [rip+0x0]        # 233 <packet_id_debug_print+0x233>
			22f: R_X86_64_REX_GOTPCRELX	x_debug_level-0x4
 233:	3b 01                	cmp    eax,DWORD PTR [rcx]
 235:	77 3a                	ja     271 <packet_id_debug_print+0x271>
 237:	89 df                	mov    edi,ebx
 239:	e8 00 00 00 00       	call   23e <packet_id_debug_print+0x23e>
			23a: R_X86_64_PLT32	dont_mute-0x4
 23e:	84 c0                	test   al,al
 240:	74 2f                	je     271 <packet_id_debug_print+0x271>
 242:	48 8b 44 24 40       	mov    rax,QWORD PTR [rsp+0x40]
 247:	48 63 54 24 34       	movsxd rdx,DWORD PTR [rsp+0x34]
 24c:	48 01 c2             	add    rdx,rax
 24f:	31 c9                	xor    ecx,ecx
 251:	83 7c 24 38 00       	cmp    DWORD PTR [rsp+0x38],0x0
 256:	48 0f 48 d1          	cmovs  rdx,rcx
 25a:	48 85 c0             	test   rax,rax
 25d:	48 0f 44 d0          	cmove  rdx,rax
 261:	48 8d 35 00 00 00 00 	lea    rsi,[rip+0x0]        # 268 <packet_id_debug_print+0x268>
			264: R_X86_64_PC32	.L.str.38-0x4
 268:	89 df                	mov    edi,ebx
 26a:	31 c0                	xor    eax,eax
 26c:	e8 00 00 00 00       	call   271 <packet_id_debug_print+0x271>
			26d: R_X86_64_PLT32	x_msg-0x4
 271:	f6 c3 10             	test   bl,0x10
 274:	75 4b                	jne    2c1 <packet_id_debug_print+0x2c1>
 276:	48 83 7c 24 10 00    	cmp    QWORD PTR [rsp+0x10],0x0
 27c:	74 0a                	je     288 <packet_id_debug_print+0x288>
 27e:	48 8d 7c 24 10       	lea    rdi,[rsp+0x10]
 283:	e8 00 00 00 00       	call   288 <packet_id_debug_print+0x288>
			284: R_X86_64_PLT32	x_gc_free-0x4
 288:	48 83 7c 24 18 00    	cmp    QWORD PTR [rsp+0x18],0x0
 28e:	74 0a                	je     29a <packet_id_debug_print+0x29a>
 290:	48 8d 7c 24 10       	lea    rdi,[rsp+0x10]
 295:	e8 00 00 00 00       	call   29a <packet_id_debug_print+0x29a>
			296: R_X86_64_PLT32	x_gc_freespecial-0x4
 29a:	48 83 c4 68          	add    rsp,0x68
 29e:	5b                   	pop    rbx
 29f:	41 5c                	pop    r12
 2a1:	41 5d                	pop    r13
 2a3:	41 5e                	pop    r14
 2a5:	41 5f                	pop    r15
 2a7:	5d                   	pop    rbp
 2a8:	c3                   	ret
 2a9:	48 8d 3d 00 00 00 00 	lea    rdi,[rip+0x0]        # 2b0 <packet_id_debug_print+0x2b0>
			2ac: R_X86_64_PC32	.L.str.27-0x4
 2b0:	48 8d 15 00 00 00 00 	lea    rdx,[rip+0x0]        # 2b7 <packet_id_debug_print+0x2b7>
			2b3: R_X86_64_PC32	.L.str.28-0x4
 2b7:	be bc 00 00 00       	mov    esi,0xbc
 2bc:	e8 00 00 00 00       	call   2c1 <packet_id_debug_print+0x2c1>
			2bd: R_X86_64_PLT32	assert_failed-0x4
 2c1:	bf 01 00 00 00       	mov    edi,0x1
 2c6:	e8 00 00 00 00       	call   2cb <.L.str.25+0x2e>
			2c7: R_X86_64_PLT32	_exit-0x4
