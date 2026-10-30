
/workspace/scratch/5567a9db5cf4/hepta-work/experiments/hia_narrowing/round3_20261028/native01/narrowed.so:	file format elf64-x86-64

Disassembly of section .init:

0000000000001000 <_init>:
    1000:      	endbr64
    1004:      	subq	$0x8, %rsp
    1008:      	movq	0x2fc1(%rip), %rax      # 0x3fd0 <free@GLIBC_2.2.5+0x3fd0>
    100f:      	testq	%rax, %rax
    1012:      	je	0x1016 <_init+0x16>
    1014:      	callq	*%rax
    1016:      	addq	$0x8, %rsp
    101a:      	retq

Disassembly of section .plt:

0000000000001020 <.plt>:
    1020:      	pushq	0x2fca(%rip)            # 0x3ff0 <_GLOBAL_OFFSET_TABLE_+0x8>
    1026:      	jmpq	*0x2fcc(%rip)           # 0x3ff8 <_GLOBAL_OFFSET_TABLE_+0x10>
    102c:      	nopl	(%rax)

0000000000001030 <free@plt>:
    1030:      	jmpq	*0x2fca(%rip)           # 0x4000 <_GLOBAL_OFFSET_TABLE_+0x18>
    1036:      	pushq	$0x0
    103b:      	jmp	0x1020 <.plt>

0000000000001040 <abort@plt>:
    1040:      	jmpq	*0x2fc2(%rip)           # 0x4008 <_GLOBAL_OFFSET_TABLE_+0x20>
    1046:      	pushq	$0x1
    104b:      	jmp	0x1020 <.plt>

0000000000001050 <calloc@plt>:
    1050:      	jmpq	*0x2fba(%rip)           # 0x4010 <_GLOBAL_OFFSET_TABLE_+0x28>
    1056:      	pushq	$0x2
    105b:      	jmp	0x1020 <.plt>

Disassembly of section .plt.got:

0000000000001060 <__cxa_finalize@plt>:
    1060:      	jmpq	*0x2f7a(%rip)           # 0x3fe0 <free@GLIBC_2.2.5+0x3fe0>
    1066:      	nop

Disassembly of section .text:

0000000000001070 <deregister_tm_clones>:
    1070:      	leaq	0x2fa9(%rip), %rdi      # 0x4020 <completed.0>
    1077:      	leaq	0x2fa2(%rip), %rax      # 0x4020 <completed.0>
    107e:      	cmpq	%rdi, %rax
    1081:      	je	0x1098 <deregister_tm_clones+0x28>
    1083:      	movq	0x2f3e(%rip), %rax      # 0x3fc8 <free@GLIBC_2.2.5+0x3fc8>
    108a:      	testq	%rax, %rax
    108d:      	je	0x1098 <deregister_tm_clones+0x28>
    108f:      	jmpq	*%rax
    1091:      	nopl	(%rax)
    1098:      	retq
    1099:      	nopl	(%rax)

00000000000010a0 <register_tm_clones>:
    10a0:      	leaq	0x2f79(%rip), %rdi      # 0x4020 <completed.0>
    10a7:      	leaq	0x2f72(%rip), %rsi      # 0x4020 <completed.0>
    10ae:      	subq	%rdi, %rsi
    10b1:      	movq	%rsi, %rax
    10b4:      	shrq	$0x3f, %rsi
    10b8:      	sarq	$0x3, %rax
    10bc:      	addq	%rax, %rsi
    10bf:      	sarq	%rsi
    10c2:      	je	0x10d8 <register_tm_clones+0x38>
    10c4:      	movq	0x2f0d(%rip), %rax      # 0x3fd8 <free@GLIBC_2.2.5+0x3fd8>
    10cb:      	testq	%rax, %rax
    10ce:      	je	0x10d8 <register_tm_clones+0x38>
    10d0:      	jmpq	*%rax
    10d2:      	nopw	(%rax,%rax)
    10d8:      	retq
    10d9:      	nopl	(%rax)

00000000000010e0 <__do_global_dtors_aux>:
    10e0:      	endbr64
    10e4:      	cmpb	$0x0, 0x2f35(%rip)      # 0x4020 <completed.0>
    10eb:      	jne	0x1118 <__do_global_dtors_aux+0x38>
    10ed:      	pushq	%rbp
    10ee:      	cmpq	$0x0, 0x2eea(%rip)      # 0x3fe0 <free@GLIBC_2.2.5+0x3fe0>
    10f6:      	movq	%rsp, %rbp
    10f9:      	je	0x1107 <__do_global_dtors_aux+0x27>
    10fb:      	movq	0x2f16(%rip), %rdi      # 0x4018 <__dso_handle>
    1102:      	callq	0x1060 <__cxa_finalize@plt>
    1107:      	callq	0x1070 <deregister_tm_clones>
    110c:      	movb	$0x1, 0x2f0d(%rip)      # 0x4020 <completed.0>
    1113:      	popq	%rbp
    1114:      	retq
    1115:      	nopl	(%rax)
    1118:      	retq
    1119:      	nopl	(%rax)

0000000000001120 <frame_dummy>:
    1120:      	endbr64
    1124:      	jmp	0x10a0 <register_tm_clones>
    1129:      	nopl	(%rax)

0000000000001130 <full_lifecycle>:
    1130:      	pushq	%rbp
    1131:      	pushq	%r14
    1133:      	pushq	%rbx
    1134:      	movl	%esi, %ebp
    1136:      	movq	%rdi, %rbx
    1139:      	cmpq	$0x21, %rdi
    113d:      	jae	0x116f <full_lifecycle+0x3f>
    113f:      	testq	%rbx, %rbx
    1142:      	je	0x1278 <full_lifecycle+0x148>
    1148:      	movl	$0x1, %edi
    114d:      	movq	%rbx, %rsi
    1150:      	callq	0x1050 <calloc@plt>
    1155:      	testq	%rax, %rax
    1158:      	je	0x1280 <full_lifecycle+0x150>
    115e:      	cmpq	$0x3, %rbx
    1162:      	ja	0x128b <full_lifecycle+0x15b>
    1168:      	xorl	%ecx, %ecx
    116a:      	jmp	0x133f <full_lifecycle+0x20f>
    116f:      	testq	%rbx, %rbx
    1172:      	js	0x11a1 <full_lifecycle+0x71>
    1174:      	movl	$0x1, %edi
    1179:      	movq	%rbx, %rsi
    117c:      	callq	0x1050 <calloc@plt>
    1181:      	testq	%rax, %rax
    1184:      	je	0x11a1 <full_lifecycle+0x71>
    1186:      	movb	$0x1, %cl
    1188:      	testb	$0x1, %cl
    118b:      	jne	0x11aa <full_lifecycle+0x7a>
    118d:      	movl	$0x3e9, %r14d           # imm = 0x3E9
    1193:      	testq	%rax, %rax
    1196:      	jne	0x1435 <full_lifecycle+0x305>
    119c:      	jmp	0x143d <full_lifecycle+0x30d>
    11a1:      	xorl	%eax, %eax
    11a3:      	xorl	%ecx, %ecx
    11a5:      	testb	$0x1, %cl
    11a8:      	je	0x118d <full_lifecycle+0x5d>
    11aa:      	movq	%rbx, %rcx
    11ad:      	andq	$-0x10, %rcx
    11b1:      	movd	%ebp, %xmm0
    11b5:      	punpcklbw	%xmm0, %xmm0    # xmm0 = xmm0[0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7]
    11b9:      	pshuflw	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0,4,5,6,7]
    11be:      	pshufd	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0]
    11c3:      	movdqa	0xe35(%rip), %xmm1      # 0x2000 <free@GLIBC_2.2.5+0x2000>
    11cb:      	xorl	%edx, %edx
    11cd:      	movdqa	0xe3b(%rip), %xmm2      # 0x2010 <free@GLIBC_2.2.5+0x2010>
    11d5:      	nopw	%cs:(%rax,%rax)
    11e0:      	movdqa	%xmm1, %xmm3
    11e4:      	paddb	%xmm0, %xmm3
    11e8:      	movdqu	%xmm3, (%rax,%rdx)
    11ed:      	addq	$0x10, %rdx
    11f1:      	paddb	%xmm2, %xmm1
    11f5:      	cmpq	%rdx, %rcx
    11f8:      	jne	0x11e0 <full_lifecycle+0xb0>
    11fa:      	cmpq	%rcx, %rbx
    11fd:      	je	0x140f <full_lifecycle+0x2df>
    1203:      	testb	$0xc, %bl
    1206:      	je	0x13f1 <full_lifecycle+0x2c1>
    120c:      	movq	%rbx, %rdx
    120f:      	andq	$-0x4, %rdx
    1213:      	movd	%ecx, %xmm0
    1217:      	punpcklbw	%xmm0, %xmm0    # xmm0 = xmm0[0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7]
    121b:      	pshuflw	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0,4,5,6,7]
    1220:      	por	0xdf8(%rip), %xmm0      # 0x2020 <free@GLIBC_2.2.5+0x2020>
    1228:      	movzbl	%bpl, %esi
    122c:      	movd	%esi, %xmm1
    1230:      	punpcklbw	%xmm1, %xmm1    # xmm1 = xmm1[0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7]
    1234:      	pshuflw	$0x0, %xmm1, %xmm1      # xmm1 = xmm1[0,0,0,0,4,5,6,7]
    1239:      	movdqa	0xdef(%rip), %xmm2      # 0x2030 <free@GLIBC_2.2.5+0x2030>
    1241:      	nopw	%cs:(%rax,%rax)
    1250:      	movdqa	%xmm0, %xmm3
    1254:      	paddb	%xmm1, %xmm3
    1258:      	movd	%xmm3, (%rax,%rcx)
    125d:      	addq	$0x4, %rcx
    1261:      	paddb	%xmm2, %xmm0
    1265:      	cmpq	%rcx, %rdx
    1268:      	jne	0x1250 <full_lifecycle+0x120>
    126a:      	cmpq	%rdx, %rbx
    126d:      	jne	0x13f4 <full_lifecycle+0x2c4>
    1273:      	jmp	0x140f <full_lifecycle+0x2df>
    1278:      	xorl	%r14d, %r14d
    127b:      	jmp	0x143d <full_lifecycle+0x30d>
    1280:      	movl	$0x3e9, %r14d           # imm = 0x3E9
    1286:      	jmp	0x143d <full_lifecycle+0x30d>
    128b:      	movzbl	%bpl, %edx
    128f:      	cmpq	$0x10, %rbx
    1293:      	jae	0x1299 <full_lifecycle+0x169>
    1295:      	xorl	%ecx, %ecx
    1297:      	jmp	0x12e1 <full_lifecycle+0x1b1>
    1299:      	movl	%ebx, %ecx
    129b:      	andl	$0x30, %ecx
    129e:      	movd	%edx, %xmm0
    12a2:      	punpcklbw	%xmm0, %xmm0    # xmm0 = xmm0[0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7]
    12a6:      	pshuflw	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0,4,5,6,7]
    12ab:      	pshufd	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0]
    12b0:      	movdqa	0xd48(%rip), %xmm1      # 0x2000 <free@GLIBC_2.2.5+0x2000>
    12b8:      	paddb	%xmm0, %xmm1
    12bc:      	movdqu	%xmm1, (%rax)
    12c0:      	cmpq	$0x10, %rcx
    12c4:      	je	0x12d3 <full_lifecycle+0x1a3>
    12c6:      	paddb	0xd72(%rip), %xmm0      # 0x2040 <free@GLIBC_2.2.5+0x2040>
    12ce:      	movdqu	%xmm0, 0x10(%rax)
    12d3:      	cmpq	%rcx, %rbx
    12d6:      	je	0x135f <full_lifecycle+0x22f>
    12dc:      	testb	$0xc, %bl
    12df:      	je	0x133f <full_lifecycle+0x20f>
    12e1:      	movq	%rcx, %rsi
    12e4:      	movl	%ebx, %ecx
    12e6:      	andl	$0x3c, %ecx
    12e9:      	movd	%esi, %xmm0
    12ed:      	punpcklbw	%xmm0, %xmm0    # xmm0 = xmm0[0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7]
    12f1:      	pshuflw	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0,4,5,6,7]
    12f6:      	por	0xd22(%rip), %xmm0      # 0x2020 <free@GLIBC_2.2.5+0x2020>
    12fe:      	movd	%edx, %xmm1
    1302:      	punpcklbw	%xmm1, %xmm1    # xmm1 = xmm1[0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7]
    1306:      	pshuflw	$0x0, %xmm1, %xmm1      # xmm1 = xmm1[0,0,0,0,4,5,6,7]
    130b:      	movdqa	0xd1d(%rip), %xmm2      # 0x2030 <free@GLIBC_2.2.5+0x2030>
    1313:      	nopw	%cs:(%rax,%rax)
    1320:      	movdqa	%xmm0, %xmm3
    1324:      	paddb	%xmm1, %xmm3
    1328:      	movd	%xmm3, (%rax,%rsi)
    132d:      	addq	$0x4, %rsi
    1331:      	paddb	%xmm2, %xmm0
    1335:      	cmpq	%rsi, %rcx
    1338:      	jne	0x1320 <full_lifecycle+0x1f0>
    133a:      	cmpq	%rcx, %rbx
    133d:      	je	0x135f <full_lifecycle+0x22f>
    133f:      	movl	%ebp, %edx
    1341:      	nopw	%cs:(%rax,%rax)
    1350:      	leal	(%rdx,%rcx), %esi
    1353:      	movb	%sil, (%rax,%rcx)
    1357:      	incq	%rcx
    135a:      	cmpq	%rcx, %rbx
    135d:      	jne	0x1350 <full_lifecycle+0x220>
    135f:      	movl	%ebx, %ecx
    1361:      	andl	$0x7, %ecx
    1364:      	cmpq	$0x8, %rbx
    1368:      	jae	0x1371 <full_lifecycle+0x241>
    136a:      	xorl	%edx, %edx
    136c:      	xorl	%r14d, %r14d
    136f:      	jmp	0x13ca <full_lifecycle+0x29a>
    1371:      	andl	$0x38, %ebx
    1374:      	xorl	%edx, %edx
    1376:      	xorl	%r14d, %r14d
    1379:      	nopl	(%rax)
    1380:      	movzbl	(%rax,%rdx), %esi
    1384:      	addq	%r14, %rsi
    1387:      	movzbl	0x1(%rax,%rdx), %edi
    138c:      	movzbl	0x2(%rax,%rdx), %r8d
    1392:      	addq	%rdi, %r8
    1395:      	addq	%rsi, %r8
    1398:      	movzbl	0x3(%rax,%rdx), %esi
    139d:      	movzbl	0x4(%rax,%rdx), %edi
    13a2:      	addq	%rsi, %rdi
    13a5:      	movzbl	0x5(%rax,%rdx), %esi
    13aa:      	addq	%rdi, %rsi
    13ad:      	addq	%r8, %rsi
    13b0:      	movzbl	0x6(%rax,%rdx), %edi
    13b5:      	movzbl	0x7(%rax,%rdx), %r14d
    13bb:      	addq	%rdi, %r14
    13be:      	addq	%rsi, %r14
    13c1:      	addq	$0x8, %rdx
    13c5:      	cmpq	%rdx, %rbx
    13c8:      	jne	0x1380 <full_lifecycle+0x250>
    13ca:      	testq	%rcx, %rcx
    13cd:      	je	0x1435 <full_lifecycle+0x305>
    13cf:      	movq	%rax, %rsi
    13d2:      	addq	%rdx, %rsi
    13d5:      	xorl	%edx, %edx
    13d7:      	nopw	(%rax,%rax)
    13e0:      	movzbl	(%rsi,%rdx), %edi
    13e4:      	addq	%rdi, %r14
    13e7:      	incq	%rdx
    13ea:      	cmpq	%rdx, %rcx
    13ed:      	jne	0x13e0 <full_lifecycle+0x2b0>
    13ef:      	jmp	0x1435 <full_lifecycle+0x305>
    13f1:      	movq	%rcx, %rdx
    13f4:      	movl	%ebp, %ecx
    13f6:      	nopw	%cs:(%rax,%rax)
    1400:      	leal	(%rcx,%rdx), %esi
    1403:      	movb	%sil, (%rax,%rdx)
    1407:      	incq	%rdx
    140a:      	cmpq	%rdx, %rbx
    140d:      	jne	0x1400 <full_lifecycle+0x2d0>
    140f:      	xorl	%ecx, %ecx
    1411:      	xorl	%r14d, %r14d
    1414:      	nopw	%cs:(%rax,%rax)
    1420:      	movq	%r14, %rdx
    1423:      	movzbl	(%rax,%rcx), %r14d
    1428:      	addq	%rdx, %r14
    142b:      	jb	0x1445 <full_lifecycle+0x315>
    142d:      	incq	%rcx
    1430:      	cmpq	%rcx, %rbx
    1433:      	jne	0x1420 <full_lifecycle+0x2f0>
    1435:      	movq	%rax, %rdi
    1438:      	callq	0x1030 <free@plt>
    143d:      	movq	%r14, %rax
    1440:      	popq	%rbx
    1441:      	popq	%r14
    1443:      	popq	%rbp
    1444:      	retq
    1445:      	callq	0x1040 <abort@plt>
    144a:      	nopw	(%rax,%rax)

0000000000001450 <packet_xor>:
    1450:      	pushq	%r15
    1452:      	pushq	%r14
    1454:      	pushq	%rbx
    1455:      	movl	%esi, %r15d
    1458:      	movq	%rdi, %r14
    145b:      	cmpq	$0x21, %rdi
    145f:      	jae	0x1494 <packet_xor+0x44>
    1461:      	testq	%r14, %r14
    1464:      	je	0x15d8 <packet_xor+0x188>
    146a:      	movl	$0x1, %edi
    146f:      	movq	%r14, %rsi
    1472:      	callq	0x1050 <calloc@plt>
    1477:      	testq	%rax, %rax
    147a:      	je	0x15e0 <packet_xor+0x190>
    1480:      	movq	%rax, %rbx
    1483:      	cmpq	$0x3, %r14
    1487:      	ja	0x15eb <packet_xor+0x19b>
    148d:      	xorl	%eax, %eax
    148f:      	jmp	0x16bf <packet_xor+0x26f>
    1494:      	testq	%r14, %r14
    1497:      	js	0x14c8 <packet_xor+0x78>
    1499:      	movl	$0x1, %edi
    149e:      	movq	%r14, %rsi
    14a1:      	callq	0x1050 <calloc@plt>
    14a6:      	testq	%rax, %rax
    14a9:      	je	0x14c8 <packet_xor+0x78>
    14ab:      	movq	%rax, %rbx
    14ae:      	movb	$0x1, %al
    14b0:      	testb	$0x1, %al
    14b2:      	jne	0x14d0 <packet_xor+0x80>
    14b4:      	movl	$0x3e9, %r15d           # imm = 0x3E9
    14ba:      	testq	%rbx, %rbx
    14bd:      	jne	0x1a37 <packet_xor+0x5e7>
    14c3:      	jmp	0x1a3f <packet_xor+0x5ef>
    14c8:      	xorl	%ebx, %ebx
    14ca:      	xorl	%eax, %eax
    14cc:      	testb	$0x1, %al
    14ce:      	je	0x14b4 <packet_xor+0x64>
    14d0:      	movq	%r14, %rax
    14d3:      	andq	$-0x10, %rax
    14d7:      	movd	%r15d, %xmm0
    14dc:      	punpcklbw	%xmm0, %xmm0    # xmm0 = xmm0[0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7]
    14e0:      	pshuflw	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0,4,5,6,7]
    14e5:      	pshufd	$0x0, %xmm0, %xmm1      # xmm1 = xmm0[0,0,0,0]
    14ea:      	movdqa	0xb0e(%rip), %xmm2      # 0x2000 <free@GLIBC_2.2.5+0x2000>
    14f2:      	xorl	%ecx, %ecx
    14f4:      	movdqa	0xb54(%rip), %xmm3      # 0x2050 <free@GLIBC_2.2.5+0x2050>
    14fc:      	movdqa	0xb5c(%rip), %xmm0      # 0x2060 <free@GLIBC_2.2.5+0x2060>
    1504:      	movdqa	0xb04(%rip), %xmm6      # 0x2010 <free@GLIBC_2.2.5+0x2010>
    150c:      	nopl	(%rax)
    1510:      	movdqa	%xmm2, %xmm4
    1514:      	punpckhbw	%xmm4, %xmm4    # xmm4 = xmm4[8,8,9,9,10,10,11,11,12,12,13,13,14,14,15,15]
    1518:      	pmullw	%xmm3, %xmm4
    151c:      	pand	%xmm0, %xmm4
    1520:      	movdqa	%xmm2, %xmm5
    1524:      	punpcklbw	%xmm5, %xmm5    # xmm5 = xmm5[0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7]
    1528:      	pmullw	%xmm3, %xmm5
    152c:      	pand	%xmm0, %xmm5
    1530:      	packuswb	%xmm4, %xmm5
    1534:      	paddb	%xmm1, %xmm5
    1538:      	movdqu	%xmm5, (%rbx,%rcx)
    153d:      	addq	$0x10, %rcx
    1541:      	paddb	%xmm6, %xmm2
    1545:      	cmpq	%rcx, %rax
    1548:      	jne	0x1510 <packet_xor+0xc0>
    154a:      	cmpq	%rax, %r14
    154d:      	je	0x173d <packet_xor+0x2ed>
    1553:      	testb	$0xc, %r14b
    1557:      	je	0x1721 <packet_xor+0x2d1>
    155d:      	movq	%r14, %rcx
    1560:      	andq	$-0x4, %rcx
    1564:      	movd	%eax, %xmm1
    1568:      	punpcklbw	%xmm1, %xmm1    # xmm1 = xmm1[0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7]
    156c:      	pshuflw	$0x0, %xmm1, %xmm1      # xmm1 = xmm1[0,0,0,0,4,5,6,7]
    1571:      	por	0xaa7(%rip), %xmm1      # 0x2020 <free@GLIBC_2.2.5+0x2020>
    1579:      	movzbl	%r15b, %edx
    157d:      	movd	%edx, %xmm2
    1581:      	punpcklbw	%xmm2, %xmm2    # xmm2 = xmm2[0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7]
    1585:      	pshuflw	$0x0, %xmm2, %xmm2      # xmm2 = xmm2[0,0,0,0,4,5,6,7]
    158a:      	movdqa	0xade(%rip), %xmm3      # 0x2070 <free@GLIBC_2.2.5+0x2070>
    1592:      	movdqa	0xa96(%rip), %xmm4      # 0x2030 <free@GLIBC_2.2.5+0x2030>
    159a:      	nopw	(%rax,%rax)
    15a0:      	movdqa	%xmm1, %xmm5
    15a4:      	punpcklbw	%xmm5, %xmm5    # xmm5 = xmm5[0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7]
    15a8:      	pmullw	%xmm3, %xmm5
    15ac:      	pand	%xmm0, %xmm5
    15b0:      	packuswb	%xmm5, %xmm5
    15b4:      	paddb	%xmm2, %xmm5
    15b8:      	movd	%xmm5, (%rbx,%rax)
    15bd:      	addq	$0x4, %rax
    15c1:      	paddb	%xmm4, %xmm1
    15c5:      	cmpq	%rax, %rcx
    15c8:      	jne	0x15a0 <packet_xor+0x150>
    15ca:      	cmpq	%rcx, %r14
    15cd:      	jne	0x1724 <packet_xor+0x2d4>
    15d3:      	jmp	0x173d <packet_xor+0x2ed>
    15d8:      	xorl	%r15d, %r15d
    15db:      	jmp	0x1a3f <packet_xor+0x5ef>
    15e0:      	movl	$0x3e9, %r15d           # imm = 0x3E9
    15e6:      	jmp	0x1a3f <packet_xor+0x5ef>
    15eb:      	movzbl	%r15b, %ecx
    15ef:      	cmpq	$0x10, %r14
    15f3:      	jae	0x15f9 <packet_xor+0x1a9>
    15f5:      	xorl	%eax, %eax
    15f7:      	jmp	0x1643 <packet_xor+0x1f3>
    15f9:      	movl	%r14d, %eax
    15fc:      	andl	$0x30, %eax
    15ff:      	movd	%ecx, %xmm0
    1603:      	punpcklbw	%xmm0, %xmm0    # xmm0 = xmm0[0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7]
    1607:      	pshuflw	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0,4,5,6,7]
    160c:      	pshufd	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0]
    1611:      	movdqa	0xa67(%rip), %xmm1      # 0x2080 <free@GLIBC_2.2.5+0x2080>
    1619:      	paddb	%xmm0, %xmm1
    161d:      	movdqu	%xmm1, (%rbx)
    1621:      	cmpq	$0x10, %rax
    1625:      	je	0x1634 <packet_xor+0x1e4>
    1627:      	paddb	0xa61(%rip), %xmm0      # 0x2090 <free@GLIBC_2.2.5+0x2090>
    162f:      	movdqu	%xmm0, 0x10(%rbx)
    1634:      	cmpq	%rax, %r14
    1637:      	je	0x16de <packet_xor+0x28e>
    163d:      	testb	$0xc, %r14b
    1641:      	je	0x16bf <packet_xor+0x26f>
    1643:      	movq	%rax, %rdx
    1646:      	movl	%r14d, %eax
    1649:      	andl	$0x3c, %eax
    164c:      	movd	%edx, %xmm0
    1650:      	punpcklbw	%xmm0, %xmm0    # xmm0 = xmm0[0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7]
    1654:      	pshuflw	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0,4,5,6,7]
    1659:      	por	0x9bf(%rip), %xmm0      # 0x2020 <free@GLIBC_2.2.5+0x2020>
    1661:      	movd	%ecx, %xmm1
    1665:      	punpcklbw	%xmm1, %xmm1    # xmm1 = xmm1[0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7]
    1669:      	pshuflw	$0x0, %xmm1, %xmm1      # xmm1 = xmm1[0,0,0,0,4,5,6,7]
    166e:      	movdqa	0x9fa(%rip), %xmm2      # 0x2070 <free@GLIBC_2.2.5+0x2070>
    1676:      	movdqa	0x9e2(%rip), %xmm3      # 0x2060 <free@GLIBC_2.2.5+0x2060>
    167e:      	movdqa	0x9aa(%rip), %xmm4      # 0x2030 <free@GLIBC_2.2.5+0x2030>
    1686:      	nopw	%cs:(%rax,%rax)
    1690:      	movdqa	%xmm0, %xmm5
    1694:      	punpcklbw	%xmm5, %xmm5    # xmm5 = xmm5[0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7]
    1698:      	pmullw	%xmm2, %xmm5
    169c:      	pand	%xmm3, %xmm5
    16a0:      	packuswb	%xmm5, %xmm5
    16a4:      	paddb	%xmm1, %xmm5
    16a8:      	movd	%xmm5, (%rbx,%rdx)
    16ad:      	addq	$0x4, %rdx
    16b1:      	paddb	%xmm4, %xmm0
    16b5:      	cmpq	%rdx, %rax
    16b8:      	jne	0x1690 <packet_xor+0x240>
    16ba:      	cmpq	%rax, %r14
    16bd:      	je	0x16de <packet_xor+0x28e>
    16bf:      	leal	(%rax,%rax,2), %ecx
    16c2:      	leal	(%rax,%rcx,4), %ecx
    16c5:      	addb	%r15b, %cl
    16c8:      	nopl	(%rax,%rax)
    16d0:      	movb	%cl, (%rbx,%rax)
    16d3:      	incq	%rax
    16d6:      	addb	$0xd, %cl
    16d9:      	cmpq	%rax, %r14
    16dc:      	jne	0x16d0 <packet_xor+0x280>
    16de:      	movl	$0x1, %edi
    16e3:      	movq	%r14, %rsi
    16e6:      	callq	0x1050 <calloc@plt>
    16eb:      	testq	%rax, %rax
    16ee:      	je	0x1705 <packet_xor+0x2b5>
    16f0:      	xorb	$0x5a, %r15b
    16f4:      	movzbl	%r15b, %ecx
    16f8:      	cmpq	$0x3, %r14
    16fc:      	ja	0x1710 <packet_xor+0x2c0>
    16fe:      	xorl	%edx, %edx
    1700:      	jmp	0x1a48 <packet_xor+0x5f8>
    1705:      	movl	$0x3e9, %r15d           # imm = 0x3E9
    170b:      	jmp	0x1a37 <packet_xor+0x5e7>
    1710:      	cmpq	$0x10, %r14
    1714:      	jae	0x193f <packet_xor+0x4ef>
    171a:      	xorl	%edx, %edx
    171c:      	jmp	0x19a6 <packet_xor+0x556>
    1721:      	movq	%rax, %rcx
    1724:      	leal	(%rcx,%rcx,2), %eax
    1727:      	leal	(%rcx,%rax,4), %eax
    172a:      	addb	%r15b, %al
    172d:      	nopl	(%rax)
    1730:      	movb	%al, (%rbx,%rcx)
    1733:      	incq	%rcx
    1736:      	addb	$0xd, %al
    1738:      	cmpq	%rcx, %r14
    173b:      	jne	0x1730 <packet_xor+0x2e0>
    173d:      	testq	%r14, %r14
    1740:      	js	0x1758 <packet_xor+0x308>
    1742:      	movl	$0x1, %edi
    1747:      	movq	%r14, %rsi
    174a:      	callq	0x1050 <calloc@plt>
    174f:      	testq	%rax, %rax
    1752:      	je	0x1775 <packet_xor+0x325>
    1754:      	movb	$0x1, %cl
    1756:      	jmp	0x1779 <packet_xor+0x329>
    1758:      	xorl	%eax, %eax
    175a:      	xorl	%ecx, %ecx
    175c:      	testb	$0x1, %cl
    175f:      	jne	0x1786 <packet_xor+0x336>
    1761:      	movl	$0x3e9, %r15d           # imm = 0x3E9
    1767:      	testq	%rax, %rax
    176a:      	jne	0x1a2f <packet_xor+0x5df>
    1770:      	jmp	0x1a37 <packet_xor+0x5e7>
    1775:      	xorl	%eax, %eax
    1777:      	xorl	%ecx, %ecx
    1779:      	movdqa	0x88f(%rip), %xmm6      # 0x2010 <free@GLIBC_2.2.5+0x2010>
    1781:      	testb	$0x1, %cl
    1784:      	je	0x1761 <packet_xor+0x311>
    1786:      	xorb	$0x5a, %r15b
    178a:      	movq	%rax, %rcx
    178d:      	subq	%rbx, %rcx
    1790:      	cmpq	$0xf, %rcx
    1794:      	ja	0x1844 <packet_xor+0x3f4>
    179a:      	xorl	%edx, %edx
    179c:      	movq	%r14, %rsi
    179f:      	movq	%rdx, %rcx
    17a2:      	andq	$0x3, %rsi
    17a6:      	je	0x17c7 <packet_xor+0x377>
    17a8:      	leal	(%r15,%rdx), %edi
    17ac:      	movq	%rdx, %rcx
    17af:      	nop
    17b0:      	movzbl	(%rbx,%rcx), %r8d
    17b5:      	xorb	%dil, %r8b
    17b8:      	movb	%r8b, (%rax,%rcx)
    17bc:      	incq	%rcx
    17bf:      	incb	%dil
    17c2:      	decq	%rsi
    17c5:      	jne	0x17b0 <packet_xor+0x360>
    17c7:      	subq	%r14, %rdx
    17ca:      	cmpq	$-0x4, %rdx
    17ce:      	ja	0x18fc <packet_xor+0x4ac>
    17d4:      	movq	%rax, %rdx
    17d7:      	addq	$0x3, %rdx
    17db:      	movzbl	%r15b, %esi
    17df:      	leaq	0x3(%rbx), %rdi
    17e3:      	movq	%r14, %r8
    17e6:      	nopw	%cs:(%rax,%rax)
    17f0:      	leal	(%rcx,%rsi), %r9d
    17f4:      	movzbl	-0x3(%rdi,%rcx), %r10d
    17fa:      	xorb	%r9b, %r10b
    17fd:      	movb	%r10b, -0x3(%rdx,%rcx)
    1802:      	leal	0x1(%r9), %r10d
    1806:      	xorb	-0x2(%rdi,%rcx), %r10b
    180b:      	movb	%r10b, -0x2(%rdx,%rcx)
    1810:      	leal	0x2(%r9), %r10d
    1814:      	xorb	-0x1(%rdi,%rcx), %r10b
    1819:      	movb	%r10b, -0x1(%rdx,%rcx)
    181e:      	addb	$0x3, %r9b
    1822:      	xorb	(%rdi,%rcx), %r9b
    1826:      	movb	%r9b, (%rdx,%rcx)
    182a:      	addq	$-0x4, %r8
    182e:      	addq	$0x4, %rdx
    1832:      	addq	$0x4, %rsi
    1836:      	addq	$0x4, %rdi
    183a:      	cmpq	%r8, %rcx
    183d:      	jne	0x17f0 <packet_xor+0x3a0>
    183f:      	jmp	0x18fc <packet_xor+0x4ac>
    1844:      	movq	%r14, %rcx
    1847:      	andq	$-0x10, %rcx
    184b:      	movzbl	%r15b, %edx
    184f:      	movd	%edx, %xmm0
    1853:      	punpcklbw	%xmm0, %xmm0    # xmm0 = xmm0[0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7]
    1857:      	pshuflw	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0,4,5,6,7]
    185c:      	pshufd	$0x0, %xmm0, %xmm1      # xmm1 = xmm0[0,0,0,0]
    1861:      	movdqa	0x797(%rip), %xmm2      # 0x2000 <free@GLIBC_2.2.5+0x2000>
    1869:      	xorl	%edx, %edx
    186b:      	nopl	(%rax,%rax)
    1870:      	movdqu	(%rbx,%rdx), %xmm3
    1875:      	movdqa	%xmm1, %xmm4
    1879:      	paddb	%xmm2, %xmm4
    187d:      	pxor	%xmm3, %xmm4
    1881:      	movdqu	%xmm4, (%rax,%rdx)
    1886:      	addq	$0x10, %rdx
    188a:      	paddb	%xmm6, %xmm2
    188e:      	cmpq	%rdx, %rcx
    1891:      	jne	0x1870 <packet_xor+0x420>
    1893:      	cmpq	%rcx, %r14
    1896:      	je	0x18fc <packet_xor+0x4ac>
    1898:      	testb	$0xc, %r14b
    189c:      	je	0x1a05 <packet_xor+0x5b5>
    18a2:      	movq	%r14, %rdx
    18a5:      	andq	$-0x4, %rdx
    18a9:      	movd	%ecx, %xmm1
    18ad:      	punpcklbw	%xmm1, %xmm1    # xmm1 = xmm1[0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7]
    18b1:      	pshuflw	$0x0, %xmm1, %xmm1      # xmm1 = xmm1[0,0,0,0,4,5,6,7]
    18b6:      	por	0x762(%rip), %xmm1      # 0x2020 <free@GLIBC_2.2.5+0x2020>
    18be:      	movdqa	0x76a(%rip), %xmm2      # 0x2030 <free@GLIBC_2.2.5+0x2030>
    18c6:      	nopw	%cs:(%rax,%rax)
    18d0:      	movd	(%rbx,%rcx), %xmm3
    18d5:      	movdqa	%xmm0, %xmm4
    18d9:      	paddb	%xmm1, %xmm4
    18dd:      	pxor	%xmm3, %xmm4
    18e1:      	movd	%xmm4, (%rax,%rcx)
    18e6:      	addq	$0x4, %rcx
    18ea:      	paddb	%xmm2, %xmm1
    18ee:      	cmpq	%rcx, %rdx
    18f1:      	jne	0x18d0 <packet_xor+0x480>
    18f3:      	cmpq	%rdx, %r14
    18f6:      	jne	0x179c <packet_xor+0x34c>
    18fc:      	xorl	%ecx, %ecx
    18fe:      	xorl	%r15d, %r15d
    1901:      	nopw	%cs:(%rax,%rax)
    1910:      	movq	%r15, %rdx
    1913:      	movzbl	(%rax,%rcx), %r15d
    1918:      	addq	%rdx, %r15
    191b:      	jb	0x1a0d <packet_xor+0x5bd>
    1921:      	incq	%rcx
    1924:      	cmpq	%rcx, %r14
    1927:      	jne	0x1910 <packet_xor+0x4c0>
    1929:      	movq	%rax, %rdi
    192c:      	callq	0x1030 <free@plt>
    1931:      	testq	%rbx, %rbx
    1934:      	jne	0x1a37 <packet_xor+0x5e7>
    193a:      	jmp	0x1a3f <packet_xor+0x5ef>
    193f:      	movl	%r14d, %edx
    1942:      	andl	$0x30, %edx
    1945:      	movd	%ecx, %xmm0
    1949:      	punpcklbw	%xmm0, %xmm0    # xmm0 = xmm0[0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7]
    194d:      	pshuflw	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0,4,5,6,7]
    1952:      	pshufd	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0]
    1957:      	movdqa	0x6a1(%rip), %xmm1      # 0x2000 <free@GLIBC_2.2.5+0x2000>
    195f:      	xorl	%esi, %esi
    1961:      	movdqa	0x6a7(%rip), %xmm2      # 0x2010 <free@GLIBC_2.2.5+0x2010>
    1969:      	nopl	(%rax)
    1970:      	movdqu	(%rbx,%rsi), %xmm3
    1975:      	movdqa	%xmm0, %xmm4
    1979:      	paddb	%xmm1, %xmm4
    197d:      	pxor	%xmm3, %xmm4
    1981:      	movdqu	%xmm4, (%rax,%rsi)
    1986:      	addq	$0x10, %rsi
    198a:      	paddb	%xmm2, %xmm1
    198e:      	cmpq	%rsi, %rdx
    1991:      	jne	0x1970 <packet_xor+0x520>
    1993:      	cmpq	%rdx, %r14
    1996:      	je	0x1a5b <packet_xor+0x60b>
    199c:      	testb	$0xc, %r14b
    19a0:      	je	0x1a48 <packet_xor+0x5f8>
    19a6:      	movq	%rdx, %rsi
    19a9:      	movl	%r14d, %edx
    19ac:      	andl	$0x3c, %edx
    19af:      	movd	%esi, %xmm0
    19b3:      	punpcklbw	%xmm0, %xmm0    # xmm0 = xmm0[0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7]
    19b7:      	pshuflw	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0,4,5,6,7]
    19bc:      	por	0x65c(%rip), %xmm0      # 0x2020 <free@GLIBC_2.2.5+0x2020>
    19c4:      	movd	%ecx, %xmm1
    19c8:      	punpcklbw	%xmm1, %xmm1    # xmm1 = xmm1[0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7]
    19cc:      	pshuflw	$0x0, %xmm1, %xmm1      # xmm1 = xmm1[0,0,0,0,4,5,6,7]
    19d1:      	movdqa	0x657(%rip), %xmm2      # 0x2030 <free@GLIBC_2.2.5+0x2030>
    19d9:      	nopl	(%rax)
    19e0:      	movd	(%rbx,%rsi), %xmm3
    19e5:      	movdqa	%xmm1, %xmm4
    19e9:      	paddb	%xmm0, %xmm4
    19ed:      	pxor	%xmm3, %xmm4
    19f1:      	movd	%xmm4, (%rax,%rsi)
    19f6:      	addq	$0x4, %rsi
    19fa:      	paddb	%xmm2, %xmm0
    19fe:      	cmpq	%rsi, %rdx
    1a01:      	jne	0x19e0 <packet_xor+0x590>
    1a03:      	jmp	0x1a56 <packet_xor+0x606>
    1a05:      	movq	%rcx, %rdx
    1a08:      	jmp	0x179c <packet_xor+0x34c>
    1a0d:      	callq	0x1040 <abort@plt>
    1a12:      	testq	%rcx, %rcx
    1a15:      	je	0x1a2f <packet_xor+0x5df>
    1a17:      	movq	%rax, %rsi
    1a1a:      	addq	%rdx, %rsi
    1a1d:      	xorl	%edx, %edx
    1a1f:      	nop
    1a20:      	movzbl	(%rsi,%rdx), %edi
    1a24:      	addq	%rdi, %r15
    1a27:      	incq	%rdx
    1a2a:      	cmpq	%rdx, %rcx
    1a2d:      	jne	0x1a20 <packet_xor+0x5d0>
    1a2f:      	movq	%rax, %rdi
    1a32:      	callq	0x1030 <free@plt>
    1a37:      	movq	%rbx, %rdi
    1a3a:      	callq	0x1030 <free@plt>
    1a3f:      	movq	%r15, %rax
    1a42:      	popq	%rbx
    1a43:      	popq	%r14
    1a45:      	popq	%r15
    1a47:      	retq
    1a48:      	leal	(%rcx,%rdx), %esi
    1a4b:      	xorb	(%rbx,%rdx), %sil
    1a4f:      	movb	%sil, (%rax,%rdx)
    1a53:      	incq	%rdx
    1a56:      	cmpq	%rdx, %r14
    1a59:      	jne	0x1a48 <packet_xor+0x5f8>
    1a5b:      	leaq	-0x1(%r14), %rdx
    1a5f:      	movl	%r14d, %ecx
    1a62:      	andl	$0x7, %ecx
    1a65:      	cmpq	$0x7, %rdx
    1a69:      	jae	0x1a72 <packet_xor+0x622>
    1a6b:      	xorl	%edx, %edx
    1a6d:      	xorl	%r15d, %r15d
    1a70:      	jmp	0x1a12 <packet_xor+0x5c2>
    1a72:      	andl	$0x38, %r14d
    1a76:      	xorl	%edx, %edx
    1a78:      	xorl	%r15d, %r15d
    1a7b:      	nopl	(%rax,%rax)
    1a80:      	movzbl	(%rax,%rdx), %esi
    1a84:      	addq	%r15, %rsi
    1a87:      	movzbl	0x1(%rax,%rdx), %edi
    1a8c:      	movzbl	0x2(%rax,%rdx), %r8d
    1a92:      	addq	%rdi, %r8
    1a95:      	addq	%rsi, %r8
    1a98:      	movzbl	0x3(%rax,%rdx), %esi
    1a9d:      	movzbl	0x4(%rax,%rdx), %edi
    1aa2:      	addq	%rsi, %rdi
    1aa5:      	movzbl	0x5(%rax,%rdx), %esi
    1aaa:      	addq	%rdi, %rsi
    1aad:      	addq	%r8, %rsi
    1ab0:      	movzbl	0x6(%rax,%rdx), %edi
    1ab5:      	movzbl	0x7(%rax,%rdx), %r15d
    1abb:      	addq	%rdi, %r15
    1abe:      	addq	%rsi, %r15
    1ac1:      	addq	$0x8, %rdx
    1ac5:      	cmpq	%rdx, %r14
    1ac8:      	jne	0x1a80 <packet_xor+0x630>
    1aca:      	jmp	0x1a12 <packet_xor+0x5c2>

Disassembly of section .fini:

0000000000001ad0 <_fini>:
    1ad0:      	endbr64
    1ad4:      	subq	$0x8, %rsp
    1ad8:      	addq	$0x8, %rsp
    1adc:      	retq
