
/workspace/scratch/5567a9db5cf4/hepta-work/experiments/hia_narrowing/round3_20261028/native01/guarded.so:	file format elf64-x86-64

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
    1142:      	je	0x12c4 <full_lifecycle+0x194>
    1148:      	movl	$0x1, %edi
    114d:      	movq	%rbx, %rsi
    1150:      	callq	0x1050 <calloc@plt>
    1155:      	testq	%rax, %rax
    1158:      	je	0x12cc <full_lifecycle+0x19c>
    115e:      	cmpq	$0x3, %rbx
    1162:      	ja	0x12d7 <full_lifecycle+0x1a7>
    1168:      	xorl	%ecx, %ecx
    116a:      	jmp	0x13ab <full_lifecycle+0x27b>
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
    1196:      	jne	0x1495 <full_lifecycle+0x365>
    119c:      	jmp	0x149d <full_lifecycle+0x36d>
    11a1:      	xorl	%eax, %eax
    11a3:      	xorl	%ecx, %ecx
    11a5:      	testb	$0x1, %cl
    11a8:      	je	0x118d <full_lifecycle+0x5d>
    11aa:      	movq	%rbx, %rcx
    11ad:      	andq	$-0x10, %rcx
    11b1:      	movd	%ebp, %xmm0
    11b5:      	pshufd	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0]
    11ba:      	movdqa	0xe3e(%rip), %xmm2      # 0x2000 <free@GLIBC_2.2.5+0x2000>
    11c2:      	movdqa	0xe46(%rip), %xmm3      # 0x2010 <free@GLIBC_2.2.5+0x2010>
    11ca:      	movdqa	0xe4e(%rip), %xmm4      # 0x2020 <free@GLIBC_2.2.5+0x2020>
    11d2:      	movdqa	0xe56(%rip), %xmm5      # 0x2030 <free@GLIBC_2.2.5+0x2030>
    11da:      	xorl	%edx, %edx
    11dc:      	movdqa	0xe5c(%rip), %xmm1      # 0x2040 <free@GLIBC_2.2.5+0x2040>
    11e4:      	movdqa	0xe64(%rip), %xmm6      # 0x2050 <free@GLIBC_2.2.5+0x2050>
    11ec:      	nopl	(%rax)
    11f0:      	movdqa	%xmm0, %xmm7
    11f4:      	paddd	%xmm2, %xmm7
    11f8:      	movdqa	%xmm0, %xmm8
    11fd:      	paddd	%xmm3, %xmm8
    1202:      	movdqa	%xmm0, %xmm9
    1207:      	paddd	%xmm4, %xmm9
    120c:      	movdqa	%xmm0, %xmm10
    1211:      	paddd	%xmm5, %xmm10
    1216:      	pand	%xmm1, %xmm10
    121b:      	pand	%xmm1, %xmm9
    1220:      	packuswb	%xmm9, %xmm10
    1225:      	pand	%xmm1, %xmm8
    122a:      	pand	%xmm1, %xmm7
    122e:      	packuswb	%xmm7, %xmm8
    1233:      	packuswb	%xmm8, %xmm10
    1238:      	movdqu	%xmm10, (%rax,%rdx)
    123e:      	addq	$0x10, %rdx
    1242:      	paddd	%xmm6, %xmm5
    1246:      	paddd	%xmm6, %xmm4
    124a:      	paddd	%xmm6, %xmm3
    124e:      	paddd	%xmm6, %xmm2
    1252:      	cmpq	%rdx, %rcx
    1255:      	jne	0x11f0 <full_lifecycle+0xc0>
    1257:      	cmpq	%rcx, %rbx
    125a:      	je	0x146f <full_lifecycle+0x33f>
    1260:      	testb	$0xc, %bl
    1263:      	je	0x1451 <full_lifecycle+0x321>
    1269:      	movq	%rbx, %rdx
    126c:      	andq	$-0x4, %rdx
    1270:      	movd	%ecx, %xmm2
    1274:      	pshufd	$0x0, %xmm2, %xmm2      # xmm2 = xmm2[0,0,0,0]
    1279:      	por	0xdaf(%rip), %xmm2      # 0x2030 <free@GLIBC_2.2.5+0x2030>
    1281:      	movdqa	0xdd7(%rip), %xmm3      # 0x2060 <free@GLIBC_2.2.5+0x2060>
    1289:      	nopl	(%rax)
    1290:      	movdqa	%xmm0, %xmm4
    1294:      	paddd	%xmm2, %xmm4
    1298:      	pand	%xmm1, %xmm4
    129c:      	packuswb	%xmm4, %xmm4
    12a0:      	packuswb	%xmm4, %xmm4
    12a4:      	movd	%xmm4, (%rax,%rcx)
    12a9:      	addq	$0x4, %rcx
    12ad:      	paddd	%xmm3, %xmm2
    12b1:      	cmpq	%rcx, %rdx
    12b4:      	jne	0x1290 <full_lifecycle+0x160>
    12b6:      	cmpq	%rdx, %rbx
    12b9:      	jne	0x1454 <full_lifecycle+0x324>
    12bf:      	jmp	0x146f <full_lifecycle+0x33f>
    12c4:      	xorl	%r14d, %r14d
    12c7:      	jmp	0x149d <full_lifecycle+0x36d>
    12cc:      	movl	$0x3e9, %r14d           # imm = 0x3E9
    12d2:      	jmp	0x149d <full_lifecycle+0x36d>
    12d7:      	cmpq	$0x10, %rbx
    12db:      	jae	0x12e1 <full_lifecycle+0x1b1>
    12dd:      	xorl	%ecx, %ecx
    12df:      	jmp	0x1340 <full_lifecycle+0x210>
    12e1:      	movl	%ebx, %ecx
    12e3:      	andl	$0x30, %ecx
    12e6:      	movd	%ebp, %xmm0
    12ea:      	pshufd	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0]
    12ef:      	movdqa	0xd49(%rip), %xmm1      # 0x2040 <free@GLIBC_2.2.5+0x2040>
    12f7:      	pand	%xmm0, %xmm1
    12fb:      	packuswb	%xmm1, %xmm1
    12ff:      	packuswb	%xmm1, %xmm1
    1303:      	paddb	0xd65(%rip), %xmm1      # 0x2070 <free@GLIBC_2.2.5+0x2070>
    130b:      	movdqu	%xmm1, (%rax)
    130f:      	cmpq	$0x10, %rcx
    1313:      	je	0x1332 <full_lifecycle+0x202>
    1315:      	pand	0xd23(%rip), %xmm0      # 0x2040 <free@GLIBC_2.2.5+0x2040>
    131d:      	packuswb	%xmm0, %xmm0
    1321:      	packuswb	%xmm0, %xmm0
    1325:      	paddb	0xd53(%rip), %xmm0      # 0x2080 <free@GLIBC_2.2.5+0x2080>
    132d:      	movdqu	%xmm0, 0x10(%rax)
    1332:      	cmpq	%rcx, %rbx
    1335:      	je	0x13bf <full_lifecycle+0x28f>
    133b:      	testb	$0xc, %bl
    133e:      	je	0x13ab <full_lifecycle+0x27b>
    1340:      	movq	%rcx, %rdx
    1343:      	movl	%ebx, %ecx
    1345:      	andl	$0x3c, %ecx
    1348:      	movd	%edx, %xmm0
    134c:      	pshufd	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0]
    1351:      	por	0xcd7(%rip), %xmm0      # 0x2030 <free@GLIBC_2.2.5+0x2030>
    1359:      	movd	%ebp, %xmm1
    135d:      	pshufd	$0x0, %xmm1, %xmm1      # xmm1 = xmm1[0,0,0,0]
    1362:      	movdqa	0xcd6(%rip), %xmm2      # 0x2040 <free@GLIBC_2.2.5+0x2040>
    136a:      	movdqa	0xcee(%rip), %xmm3      # 0x2060 <free@GLIBC_2.2.5+0x2060>
    1372:      	nopw	%cs:(%rax,%rax)
    1380:      	movdqa	%xmm1, %xmm4
    1384:      	paddd	%xmm0, %xmm4
    1388:      	pand	%xmm2, %xmm4
    138c:      	packuswb	%xmm4, %xmm4
    1390:      	packuswb	%xmm4, %xmm4
    1394:      	movd	%xmm4, (%rax,%rdx)
    1399:      	addq	$0x4, %rdx
    139d:      	paddd	%xmm3, %xmm0
    13a1:      	cmpq	%rdx, %rcx
    13a4:      	jne	0x1380 <full_lifecycle+0x250>
    13a6:      	cmpq	%rcx, %rbx
    13a9:      	je	0x13bf <full_lifecycle+0x28f>
    13ab:      	movl	%ebp, %edx
    13ad:      	nopl	(%rax)
    13b0:      	leal	(%rdx,%rcx), %esi
    13b3:      	movb	%sil, (%rax,%rcx)
    13b7:      	incq	%rcx
    13ba:      	cmpq	%rcx, %rbx
    13bd:      	jne	0x13b0 <full_lifecycle+0x280>
    13bf:      	movl	%ebx, %ecx
    13c1:      	andl	$0x7, %ecx
    13c4:      	cmpq	$0x8, %rbx
    13c8:      	jae	0x13d1 <full_lifecycle+0x2a1>
    13ca:      	xorl	%edx, %edx
    13cc:      	xorl	%r14d, %r14d
    13cf:      	jmp	0x142a <full_lifecycle+0x2fa>
    13d1:      	andl	$0x38, %ebx
    13d4:      	xorl	%edx, %edx
    13d6:      	xorl	%r14d, %r14d
    13d9:      	nopl	(%rax)
    13e0:      	movzbl	(%rax,%rdx), %esi
    13e4:      	addq	%r14, %rsi
    13e7:      	movzbl	0x1(%rax,%rdx), %edi
    13ec:      	movzbl	0x2(%rax,%rdx), %r8d
    13f2:      	addq	%rdi, %r8
    13f5:      	addq	%rsi, %r8
    13f8:      	movzbl	0x3(%rax,%rdx), %esi
    13fd:      	movzbl	0x4(%rax,%rdx), %edi
    1402:      	addq	%rsi, %rdi
    1405:      	movzbl	0x5(%rax,%rdx), %esi
    140a:      	addq	%rdi, %rsi
    140d:      	addq	%r8, %rsi
    1410:      	movzbl	0x6(%rax,%rdx), %edi
    1415:      	movzbl	0x7(%rax,%rdx), %r14d
    141b:      	addq	%rdi, %r14
    141e:      	addq	%rsi, %r14
    1421:      	addq	$0x8, %rdx
    1425:      	cmpq	%rdx, %rbx
    1428:      	jne	0x13e0 <full_lifecycle+0x2b0>
    142a:      	testq	%rcx, %rcx
    142d:      	je	0x1495 <full_lifecycle+0x365>
    142f:      	movq	%rax, %rsi
    1432:      	addq	%rdx, %rsi
    1435:      	xorl	%edx, %edx
    1437:      	nopw	(%rax,%rax)
    1440:      	movzbl	(%rsi,%rdx), %edi
    1444:      	addq	%rdi, %r14
    1447:      	incq	%rdx
    144a:      	cmpq	%rdx, %rcx
    144d:      	jne	0x1440 <full_lifecycle+0x310>
    144f:      	jmp	0x1495 <full_lifecycle+0x365>
    1451:      	movq	%rcx, %rdx
    1454:      	movl	%ebp, %ecx
    1456:      	nopw	%cs:(%rax,%rax)
    1460:      	leal	(%rcx,%rdx), %esi
    1463:      	movb	%sil, (%rax,%rdx)
    1467:      	incq	%rdx
    146a:      	cmpq	%rdx, %rbx
    146d:      	jne	0x1460 <full_lifecycle+0x330>
    146f:      	xorl	%ecx, %ecx
    1471:      	xorl	%r14d, %r14d
    1474:      	nopw	%cs:(%rax,%rax)
    1480:      	movq	%r14, %rdx
    1483:      	movzbl	(%rax,%rcx), %r14d
    1488:      	addq	%rdx, %r14
    148b:      	jb	0x14a5 <full_lifecycle+0x375>
    148d:      	incq	%rcx
    1490:      	cmpq	%rcx, %rbx
    1493:      	jne	0x1480 <full_lifecycle+0x350>
    1495:      	movq	%rax, %rdi
    1498:      	callq	0x1030 <free@plt>
    149d:      	movq	%r14, %rax
    14a0:      	popq	%rbx
    14a1:      	popq	%r14
    14a3:      	popq	%rbp
    14a4:      	retq
    14a5:      	callq	0x1040 <abort@plt>
    14aa:      	nopw	(%rax,%rax)

00000000000014b0 <packet_xor>:
    14b0:      	pushq	%r15
    14b2:      	pushq	%r14
    14b4:      	pushq	%rbx
    14b5:      	movl	%esi, %r15d
    14b8:      	movq	%rdi, %r14
    14bb:      	cmpq	$0x21, %rdi
    14bf:      	jae	0x14f4 <packet_xor+0x44>
    14c1:      	testq	%r14, %r14
    14c4:      	je	0x16f0 <packet_xor+0x240>
    14ca:      	movl	$0x1, %edi
    14cf:      	movq	%r14, %rsi
    14d2:      	callq	0x1050 <calloc@plt>
    14d7:      	testq	%rax, %rax
    14da:      	je	0x16f8 <packet_xor+0x248>
    14e0:      	movq	%rax, %rbx
    14e3:      	cmpq	$0x3, %r14
    14e7:      	ja	0x1703 <packet_xor+0x253>
    14ed:      	xorl	%eax, %eax
    14ef:      	jmp	0x17f6 <packet_xor+0x346>
    14f4:      	testq	%r14, %r14
    14f7:      	js	0x1528 <packet_xor+0x78>
    14f9:      	movl	$0x1, %edi
    14fe:      	movq	%r14, %rsi
    1501:      	callq	0x1050 <calloc@plt>
    1506:      	testq	%rax, %rax
    1509:      	je	0x1528 <packet_xor+0x78>
    150b:      	movq	%rax, %rbx
    150e:      	movb	$0x1, %al
    1510:      	testb	$0x1, %al
    1512:      	jne	0x1530 <packet_xor+0x80>
    1514:      	movl	$0x3e9, %r15d           # imm = 0x3E9
    151a:      	testq	%rbx, %rbx
    151d:      	jne	0x1cd7 <packet_xor+0x827>
    1523:      	jmp	0x1cdf <packet_xor+0x82f>
    1528:      	xorl	%ebx, %ebx
    152a:      	xorl	%eax, %eax
    152c:      	testb	$0x1, %al
    152e:      	je	0x1514 <packet_xor+0x64>
    1530:      	movq	%r14, %rax
    1533:      	andq	$-0x10, %rax
    1537:      	movd	%r15d, %xmm0
    153c:      	pshufd	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0]
    1541:      	movdqa	0xab7(%rip), %xmm2      # 0x2000 <free@GLIBC_2.2.5+0x2000>
    1549:      	movdqa	0xabf(%rip), %xmm3      # 0x2010 <free@GLIBC_2.2.5+0x2010>
    1551:      	movdqa	0xac7(%rip), %xmm4      # 0x2020 <free@GLIBC_2.2.5+0x2020>
    1559:      	movdqa	0xacf(%rip), %xmm5      # 0x2030 <free@GLIBC_2.2.5+0x2030>
    1561:      	xorl	%ecx, %ecx
    1563:      	movdqa	0xb25(%rip), %xmm1      # 0x2090 <free@GLIBC_2.2.5+0x2090>
    156b:      	movdqa	0xacc(%rip), %xmm11     # 0x2040 <free@GLIBC_2.2.5+0x2040>
    1574:      	movdqa	0xad3(%rip), %xmm12     # 0x2050 <free@GLIBC_2.2.5+0x2050>
    157d:      	nopl	(%rax)
    1580:      	movdqa	%xmm5, %xmm6
    1584:      	pmuludq	%xmm1, %xmm6
    1588:      	pshufd	$0xe8, %xmm6, %xmm6     # xmm6 = xmm6[0,2,2,3]
    158d:      	pshufd	$0xf5, %xmm5, %xmm7     # xmm7 = xmm5[1,1,3,3]
    1592:      	pmuludq	%xmm1, %xmm7
    1596:      	pshufd	$0xe8, %xmm7, %xmm7     # xmm7 = xmm7[0,2,2,3]
    159b:      	punpckldq	%xmm7, %xmm6    # xmm6 = xmm6[0],xmm7[0],xmm6[1],xmm7[1]
    159f:      	movdqa	%xmm4, %xmm7
    15a3:      	pmuludq	%xmm1, %xmm7
    15a7:      	pshufd	$0xe8, %xmm7, %xmm7     # xmm7 = xmm7[0,2,2,3]
    15ac:      	pshufd	$0xf5, %xmm4, %xmm8     # xmm8 = xmm4[1,1,3,3]
    15b2:      	pmuludq	%xmm1, %xmm8
    15b7:      	pshufd	$0xe8, %xmm8, %xmm8     # xmm8 = xmm8[0,2,2,3]
    15bd:      	punpckldq	%xmm8, %xmm7    # xmm7 = xmm7[0],xmm8[0],xmm7[1],xmm8[1]
    15c2:      	movdqa	%xmm3, %xmm8
    15c7:      	pmuludq	%xmm1, %xmm8
    15cc:      	pshufd	$0xe8, %xmm8, %xmm8     # xmm8 = xmm8[0,2,2,3]
    15d2:      	pshufd	$0xf5, %xmm3, %xmm9     # xmm9 = xmm3[1,1,3,3]
    15d8:      	pmuludq	%xmm1, %xmm9
    15dd:      	pshufd	$0xe8, %xmm9, %xmm9     # xmm9 = xmm9[0,2,2,3]
    15e3:      	punpckldq	%xmm9, %xmm8    # xmm8 = xmm8[0],xmm9[0],xmm8[1],xmm9[1]
    15e8:      	movdqa	%xmm2, %xmm9
    15ed:      	pmuludq	%xmm1, %xmm9
    15f2:      	pshufd	$0xe8, %xmm9, %xmm9     # xmm9 = xmm9[0,2,2,3]
    15f8:      	pshufd	$0xf5, %xmm2, %xmm10    # xmm10 = xmm2[1,1,3,3]
    15fe:      	pmuludq	%xmm1, %xmm10
    1603:      	pshufd	$0xe8, %xmm10, %xmm10   # xmm10 = xmm10[0,2,2,3]
    1609:      	punpckldq	%xmm10, %xmm9   # xmm9 = xmm9[0],xmm10[0],xmm9[1],xmm10[1]
    160e:      	paddd	%xmm0, %xmm9
    1613:      	paddd	%xmm0, %xmm8
    1618:      	paddd	%xmm0, %xmm7
    161c:      	paddd	%xmm0, %xmm6
    1620:      	pand	%xmm11, %xmm6
    1625:      	pand	%xmm11, %xmm7
    162a:      	packuswb	%xmm7, %xmm6
    162e:      	pand	%xmm11, %xmm8
    1633:      	pand	%xmm11, %xmm9
    1638:      	packuswb	%xmm9, %xmm8
    163d:      	packuswb	%xmm8, %xmm6
    1642:      	movdqu	%xmm6, (%rbx,%rcx)
    1647:      	addq	$0x10, %rcx
    164b:      	paddd	%xmm12, %xmm5
    1650:      	paddd	%xmm12, %xmm4
    1655:      	paddd	%xmm12, %xmm3
    165a:      	paddd	%xmm12, %xmm2
    165f:      	cmpq	%rcx, %rax
    1662:      	jne	0x1580 <packet_xor+0xd0>
    1668:      	cmpq	%rax, %r14
    166b:      	je	0x186d <packet_xor+0x3bd>
    1671:      	testb	$0xc, %r14b
    1675:      	je	0x1852 <packet_xor+0x3a2>
    167b:      	movq	%r14, %rcx
    167e:      	andq	$-0x4, %rcx
    1682:      	movd	%eax, %xmm2
    1686:      	pshufd	$0x0, %xmm2, %xmm2      # xmm2 = xmm2[0,0,0,0]
    168b:      	por	0x99d(%rip), %xmm2      # 0x2030 <free@GLIBC_2.2.5+0x2030>
    1693:      	movdqa	0x9c5(%rip), %xmm3      # 0x2060 <free@GLIBC_2.2.5+0x2060>
    169b:      	nopl	(%rax,%rax)
    16a0:      	movdqa	%xmm2, %xmm4
    16a4:      	pmuludq	%xmm1, %xmm4
    16a8:      	pshufd	$0xe8, %xmm4, %xmm4     # xmm4 = xmm4[0,2,2,3]
    16ad:      	pshufd	$0xf5, %xmm2, %xmm5     # xmm5 = xmm2[1,1,3,3]
    16b2:      	pmuludq	%xmm1, %xmm5
    16b6:      	pshufd	$0xe8, %xmm5, %xmm5     # xmm5 = xmm5[0,2,2,3]
    16bb:      	punpckldq	%xmm5, %xmm4    # xmm4 = xmm4[0],xmm5[0],xmm4[1],xmm5[1]
    16bf:      	paddd	%xmm0, %xmm4
    16c3:      	pand	%xmm11, %xmm4
    16c8:      	packuswb	%xmm4, %xmm4
    16cc:      	packuswb	%xmm4, %xmm4
    16d0:      	movd	%xmm4, (%rbx,%rax)
    16d5:      	addq	$0x4, %rax
    16d9:      	paddd	%xmm3, %xmm2
    16dd:      	cmpq	%rax, %rcx
    16e0:      	jne	0x16a0 <packet_xor+0x1f0>
    16e2:      	cmpq	%rcx, %r14
    16e5:      	jne	0x1855 <packet_xor+0x3a5>
    16eb:      	jmp	0x186d <packet_xor+0x3bd>
    16f0:      	xorl	%r15d, %r15d
    16f3:      	jmp	0x1cdf <packet_xor+0x82f>
    16f8:      	movl	$0x3e9, %r15d           # imm = 0x3E9
    16fe:      	jmp	0x1cdf <packet_xor+0x82f>
    1703:      	cmpq	$0x10, %r14
    1707:      	jae	0x170d <packet_xor+0x25d>
    1709:      	xorl	%eax, %eax
    170b:      	jmp	0x1773 <packet_xor+0x2c3>
    170d:      	movl	%r14d, %eax
    1710:      	andl	$0x30, %eax
    1713:      	movd	%r15d, %xmm0
    1718:      	pshufd	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0]
    171d:      	movdqa	0x91b(%rip), %xmm1      # 0x2040 <free@GLIBC_2.2.5+0x2040>
    1725:      	pand	%xmm0, %xmm1
    1729:      	packuswb	%xmm1, %xmm1
    172d:      	packuswb	%xmm1, %xmm1
    1731:      	paddb	0x967(%rip), %xmm1      # 0x20a0 <free@GLIBC_2.2.5+0x20a0>
    1739:      	movdqu	%xmm1, (%rbx)
    173d:      	cmpq	$0x10, %rax
    1741:      	je	0x1760 <packet_xor+0x2b0>
    1743:      	pand	0x8f5(%rip), %xmm0      # 0x2040 <free@GLIBC_2.2.5+0x2040>
    174b:      	packuswb	%xmm0, %xmm0
    174f:      	packuswb	%xmm0, %xmm0
    1753:      	paddb	0x955(%rip), %xmm0      # 0x20b0 <free@GLIBC_2.2.5+0x20b0>
    175b:      	movdqu	%xmm0, 0x10(%rbx)
    1760:      	cmpq	%rax, %r14
    1763:      	je	0x180e <packet_xor+0x35e>
    1769:      	testb	$0xc, %r14b
    176d:      	je	0x17f6 <packet_xor+0x346>
    1773:      	movq	%rax, %rcx
    1776:      	movl	%r14d, %eax
    1779:      	andl	$0x3c, %eax
    177c:      	movd	%ecx, %xmm0
    1780:      	pshufd	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0]
    1785:      	por	0x8a3(%rip), %xmm0      # 0x2030 <free@GLIBC_2.2.5+0x2030>
    178d:      	movd	%r15d, %xmm1
    1792:      	pshufd	$0x0, %xmm1, %xmm1      # xmm1 = xmm1[0,0,0,0]
    1797:      	movdqa	0x8f1(%rip), %xmm2      # 0x2090 <free@GLIBC_2.2.5+0x2090>
    179f:      	movdqa	0x899(%rip), %xmm3      # 0x2040 <free@GLIBC_2.2.5+0x2040>
    17a7:      	movdqa	0x8b1(%rip), %xmm4      # 0x2060 <free@GLIBC_2.2.5+0x2060>
    17af:      	nop
    17b0:      	movdqa	%xmm0, %xmm5
    17b4:      	pmuludq	%xmm2, %xmm5
    17b8:      	pshufd	$0xe8, %xmm5, %xmm5     # xmm5 = xmm5[0,2,2,3]
    17bd:      	pshufd	$0xf5, %xmm0, %xmm6     # xmm6 = xmm0[1,1,3,3]
    17c2:      	pmuludq	%xmm2, %xmm6
    17c6:      	pshufd	$0xe8, %xmm6, %xmm6     # xmm6 = xmm6[0,2,2,3]
    17cb:      	punpckldq	%xmm6, %xmm5    # xmm5 = xmm5[0],xmm6[0],xmm5[1],xmm6[1]
    17cf:      	paddd	%xmm1, %xmm5
    17d3:      	pand	%xmm3, %xmm5
    17d7:      	packuswb	%xmm5, %xmm5
    17db:      	packuswb	%xmm5, %xmm5
    17df:      	movd	%xmm5, (%rbx,%rcx)
    17e4:      	addq	$0x4, %rcx
    17e8:      	paddd	%xmm4, %xmm0
    17ec:      	cmpq	%rcx, %rax
    17ef:      	jne	0x17b0 <packet_xor+0x300>
    17f1:      	cmpq	%rax, %r14
    17f4:      	je	0x180e <packet_xor+0x35e>
    17f6:      	leal	(%rax,%rax,2), %ecx
    17f9:      	leal	(%rax,%rcx,4), %ecx
    17fc:      	addl	%r15d, %ecx
    17ff:      	nop
    1800:      	movb	%cl, (%rbx,%rax)
    1803:      	incq	%rax
    1806:      	addb	$0xd, %cl
    1809:      	cmpq	%rax, %r14
    180c:      	jne	0x1800 <packet_xor+0x350>
    180e:      	movl	$0x1, %edi
    1813:      	movq	%r14, %rsi
    1816:      	callq	0x1050 <calloc@plt>
    181b:      	testq	%rax, %rax
    181e:      	je	0x1831 <packet_xor+0x381>
    1820:      	xorl	$0x5a, %r15d
    1824:      	cmpq	$0x3, %r14
    1828:      	ja	0x183c <packet_xor+0x38c>
    182a:      	xorl	%ecx, %ecx
    182c:      	jmp	0x1c14 <packet_xor+0x764>
    1831:      	movl	$0x3e9, %r15d           # imm = 0x3E9
    1837:      	jmp	0x1cd7 <packet_xor+0x827>
    183c:      	movd	%r15d, %xmm0
    1841:      	cmpq	$0x10, %r14
    1845:      	jae	0x1adf <packet_xor+0x62f>
    184b:      	xorl	%ecx, %ecx
    184d:      	jmp	0x1ba4 <packet_xor+0x6f4>
    1852:      	movq	%rax, %rcx
    1855:      	leal	(%rcx,%rcx,2), %eax
    1858:      	leal	(%rcx,%rax,4), %eax
    185b:      	addl	%r15d, %eax
    185e:      	nop
    1860:      	movb	%al, (%rbx,%rcx)
    1863:      	incq	%rcx
    1866:      	addb	$0xd, %al
    1868:      	cmpq	%rcx, %r14
    186b:      	jne	0x1860 <packet_xor+0x3b0>
    186d:      	testq	%r14, %r14
    1870:      	js	0x1888 <packet_xor+0x3d8>
    1872:      	movl	$0x1, %edi
    1877:      	movq	%r14, %rsi
    187a:      	callq	0x1050 <calloc@plt>
    187f:      	testq	%rax, %rax
    1882:      	je	0x18a5 <packet_xor+0x3f5>
    1884:      	movb	$0x1, %cl
    1886:      	jmp	0x18a9 <packet_xor+0x3f9>
    1888:      	xorl	%eax, %eax
    188a:      	xorl	%ecx, %ecx
    188c:      	testb	$0x1, %cl
    188f:      	jne	0x18c0 <packet_xor+0x410>
    1891:      	movl	$0x3e9, %r15d           # imm = 0x3E9
    1897:      	testq	%rax, %rax
    189a:      	jne	0x1ccf <packet_xor+0x81f>
    18a0:      	jmp	0x1cd7 <packet_xor+0x827>
    18a5:      	xorl	%eax, %eax
    18a7:      	xorl	%ecx, %ecx
    18a9:      	movdqa	0x78e(%rip), %xmm11     # 0x2040 <free@GLIBC_2.2.5+0x2040>
    18b2:      	movdqa	0x795(%rip), %xmm12     # 0x2050 <free@GLIBC_2.2.5+0x2050>
    18bb:      	testb	$0x1, %cl
    18be:      	je	0x1891 <packet_xor+0x3e1>
    18c0:      	xorl	$0x5a, %r15d
    18c4:      	movq	%rax, %rcx
    18c7:      	subq	%rbx, %rcx
    18ca:      	cmpq	$0xf, %rcx
    18ce:      	ja	0x1984 <packet_xor+0x4d4>
    18d4:      	xorl	%edx, %edx
    18d6:      	movq	%r14, %rsi
    18d9:      	movq	%rdx, %rcx
    18dc:      	andq	$0x3, %rsi
    18e0:      	je	0x1907 <packet_xor+0x457>
    18e2:      	leal	(%r15,%rdx), %edi
    18e6:      	movq	%rdx, %rcx
    18e9:      	nopl	(%rax)
    18f0:      	movzbl	(%rbx,%rcx), %r8d
    18f5:      	xorb	%dil, %r8b
    18f8:      	movb	%r8b, (%rax,%rcx)
    18fc:      	incq	%rcx
    18ff:      	incb	%dil
    1902:      	decq	%rsi
    1905:      	jne	0x18f0 <packet_xor+0x440>
    1907:      	subq	%r14, %rdx
    190a:      	cmpq	$-0x4, %rdx
    190e:      	ja	0x1aa9 <packet_xor+0x5f9>
    1914:      	movq	%rax, %rdx
    1917:      	addq	$0x3, %rdx
    191b:      	movl	%r15d, %esi
    191e:      	leaq	0x3(%rbx), %rdi
    1922:      	movq	%r14, %r8
    1925:      	nopw	%cs:(%rax,%rax)
    1930:      	leal	(%rcx,%rsi), %r9d
    1934:      	movzbl	-0x3(%rdi,%rcx), %r10d
    193a:      	xorb	%r9b, %r10b
    193d:      	movb	%r10b, -0x3(%rdx,%rcx)
    1942:      	leal	0x1(%r9), %r10d
    1946:      	xorb	-0x2(%rdi,%rcx), %r10b
    194b:      	movb	%r10b, -0x2(%rdx,%rcx)
    1950:      	leal	0x2(%r9), %r10d
    1954:      	xorb	-0x1(%rdi,%rcx), %r10b
    1959:      	movb	%r10b, -0x1(%rdx,%rcx)
    195e:      	addb	$0x3, %r9b
    1962:      	xorb	(%rdi,%rcx), %r9b
    1966:      	movb	%r9b, (%rdx,%rcx)
    196a:      	addq	$-0x4, %r8
    196e:      	addq	$0x4, %rdx
    1972:      	addq	$0x4, %rsi
    1976:      	addq	$0x4, %rdi
    197a:      	cmpq	%r8, %rcx
    197d:      	jne	0x1930 <packet_xor+0x480>
    197f:      	jmp	0x1aa9 <packet_xor+0x5f9>
    1984:      	movq	%r14, %rcx
    1987:      	andq	$-0x10, %rcx
    198b:      	movd	%r15d, %xmm0
    1990:      	pshufd	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0]
    1995:      	movdqa	0x663(%rip), %xmm1      # 0x2000 <free@GLIBC_2.2.5+0x2000>
    199d:      	movdqa	0x66b(%rip), %xmm2      # 0x2010 <free@GLIBC_2.2.5+0x2010>
    19a5:      	movdqa	0x673(%rip), %xmm3      # 0x2020 <free@GLIBC_2.2.5+0x2020>
    19ad:      	movdqa	0x67b(%rip), %xmm4      # 0x2030 <free@GLIBC_2.2.5+0x2030>
    19b5:      	xorl	%edx, %edx
    19b7:      	nopw	(%rax,%rax)
    19c0:      	movdqu	(%rbx,%rdx), %xmm5
    19c5:      	movdqa	%xmm0, %xmm6
    19c9:      	paddd	%xmm1, %xmm6
    19cd:      	movdqa	%xmm0, %xmm7
    19d1:      	paddd	%xmm2, %xmm7
    19d5:      	movdqa	%xmm0, %xmm8
    19da:      	paddd	%xmm3, %xmm8
    19df:      	movdqa	%xmm0, %xmm9
    19e4:      	paddd	%xmm4, %xmm9
    19e9:      	pand	%xmm11, %xmm9
    19ee:      	pand	%xmm11, %xmm8
    19f3:      	packuswb	%xmm8, %xmm9
    19f8:      	pand	%xmm11, %xmm7
    19fd:      	pand	%xmm11, %xmm6
    1a02:      	packuswb	%xmm6, %xmm7
    1a06:      	packuswb	%xmm7, %xmm9
    1a0b:      	pxor	%xmm5, %xmm9
    1a10:      	movdqu	%xmm9, (%rax,%rdx)
    1a16:      	addq	$0x10, %rdx
    1a1a:      	paddd	%xmm12, %xmm4
    1a1f:      	paddd	%xmm12, %xmm3
    1a24:      	paddd	%xmm12, %xmm2
    1a29:      	paddd	%xmm12, %xmm1
    1a2e:      	cmpq	%rdx, %rcx
    1a31:      	jne	0x19c0 <packet_xor+0x510>
    1a33:      	cmpq	%rcx, %r14
    1a36:      	je	0x1aa9 <packet_xor+0x5f9>
    1a38:      	testb	$0xc, %r14b
    1a3c:      	je	0x1ce8 <packet_xor+0x838>
    1a42:      	movq	%r14, %rdx
    1a45:      	andq	$-0x4, %rdx
    1a49:      	movd	%ecx, %xmm1
    1a4d:      	pshufd	$0x0, %xmm1, %xmm1      # xmm1 = xmm1[0,0,0,0]
    1a52:      	por	0x5d6(%rip), %xmm1      # 0x2030 <free@GLIBC_2.2.5+0x2030>
    1a5a:      	movdqa	0x5fe(%rip), %xmm2      # 0x2060 <free@GLIBC_2.2.5+0x2060>
    1a62:      	nopw	%cs:(%rax,%rax)
    1a70:      	movd	(%rbx,%rcx), %xmm3
    1a75:      	movdqa	%xmm0, %xmm4
    1a79:      	paddd	%xmm1, %xmm4
    1a7d:      	pand	%xmm11, %xmm4
    1a82:      	packuswb	%xmm4, %xmm4
    1a86:      	packuswb	%xmm4, %xmm4
    1a8a:      	pxor	%xmm3, %xmm4
    1a8e:      	movd	%xmm4, (%rax,%rcx)
    1a93:      	addq	$0x4, %rcx
    1a97:      	paddd	%xmm2, %xmm1
    1a9b:      	cmpq	%rcx, %rdx
    1a9e:      	jne	0x1a70 <packet_xor+0x5c0>
    1aa0:      	cmpq	%rdx, %r14
    1aa3:      	jne	0x18d6 <packet_xor+0x426>
    1aa9:      	xorl	%ecx, %ecx
    1aab:      	xorl	%r15d, %r15d
    1aae:      	nop
    1ab0:      	movq	%r15, %rdx
    1ab3:      	movzbl	(%rax,%rcx), %r15d
    1ab8:      	addq	%rdx, %r15
    1abb:      	jb	0x1cf0 <packet_xor+0x840>
    1ac1:      	incq	%rcx
    1ac4:      	cmpq	%rcx, %r14
    1ac7:      	jne	0x1ab0 <packet_xor+0x600>
    1ac9:      	movq	%rax, %rdi
    1acc:      	callq	0x1030 <free@plt>
    1ad1:      	testq	%rbx, %rbx
    1ad4:      	jne	0x1cd7 <packet_xor+0x827>
    1ada:      	jmp	0x1cdf <packet_xor+0x82f>
    1adf:      	movl	%r14d, %ecx
    1ae2:      	andl	$0x30, %ecx
    1ae5:      	pshufd	$0x0, %xmm0, %xmm1      # xmm1 = xmm0[0,0,0,0]
    1aea:      	movdqa	0x50e(%rip), %xmm2      # 0x2000 <free@GLIBC_2.2.5+0x2000>
    1af2:      	movdqa	0x516(%rip), %xmm3      # 0x2010 <free@GLIBC_2.2.5+0x2010>
    1afa:      	movdqa	0x51e(%rip), %xmm4      # 0x2020 <free@GLIBC_2.2.5+0x2020>
    1b02:      	movdqa	0x526(%rip), %xmm5      # 0x2030 <free@GLIBC_2.2.5+0x2030>
    1b0a:      	xorl	%edx, %edx
    1b0c:      	movdqa	0x52c(%rip), %xmm6      # 0x2040 <free@GLIBC_2.2.5+0x2040>
    1b14:      	movdqa	0x534(%rip), %xmm7      # 0x2050 <free@GLIBC_2.2.5+0x2050>
    1b1c:      	nopl	(%rax)
    1b20:      	movdqu	(%rbx,%rdx), %xmm8
    1b26:      	movdqa	%xmm1, %xmm9
    1b2b:      	paddd	%xmm2, %xmm9
    1b30:      	movdqa	%xmm1, %xmm10
    1b35:      	paddd	%xmm3, %xmm10
    1b3a:      	movdqa	%xmm1, %xmm11
    1b3f:      	paddd	%xmm4, %xmm11
    1b44:      	movdqa	%xmm1, %xmm12
    1b49:      	paddd	%xmm5, %xmm12
    1b4e:      	pand	%xmm6, %xmm12
    1b53:      	pand	%xmm6, %xmm11
    1b58:      	packuswb	%xmm11, %xmm12
    1b5d:      	pand	%xmm6, %xmm10
    1b62:      	pand	%xmm6, %xmm9
    1b67:      	packuswb	%xmm9, %xmm10
    1b6c:      	packuswb	%xmm10, %xmm12
    1b71:      	pxor	%xmm8, %xmm12
    1b76:      	movdqu	%xmm12, (%rax,%rdx)
    1b7c:      	addq	$0x10, %rdx
    1b80:      	paddd	%xmm7, %xmm5
    1b84:      	paddd	%xmm7, %xmm4
    1b88:      	paddd	%xmm7, %xmm3
    1b8c:      	paddd	%xmm7, %xmm2
    1b90:      	cmpq	%rdx, %rcx
    1b93:      	jne	0x1b20 <packet_xor+0x670>
    1b95:      	cmpq	%rcx, %r14
    1b98:      	je	0x1c33 <packet_xor+0x783>
    1b9e:      	testb	$0xc, %r14b
    1ba2:      	je	0x1c14 <packet_xor+0x764>
    1ba4:      	movq	%rcx, %rdx
    1ba7:      	movl	%r14d, %ecx
    1baa:      	movd	%edx, %xmm1
    1bae:      	pshufd	$0x0, %xmm1, %xmm1      # xmm1 = xmm1[0,0,0,0]
    1bb3:      	por	0x475(%rip), %xmm1      # 0x2030 <free@GLIBC_2.2.5+0x2030>
    1bbb:      	andl	$0x3c, %ecx
    1bbe:      	pshufd	$0x0, %xmm0, %xmm0      # xmm0 = xmm0[0,0,0,0]
    1bc3:      	movdqa	0x475(%rip), %xmm2      # 0x2040 <free@GLIBC_2.2.5+0x2040>
    1bcb:      	movdqa	0x48d(%rip), %xmm3      # 0x2060 <free@GLIBC_2.2.5+0x2060>
    1bd3:      	nopw	%cs:(%rax,%rax)
    1be0:      	movd	(%rbx,%rdx), %xmm4
    1be5:      	movdqa	%xmm0, %xmm5
    1be9:      	paddd	%xmm1, %xmm5
    1bed:      	pand	%xmm2, %xmm5
    1bf1:      	packuswb	%xmm5, %xmm5
    1bf5:      	packuswb	%xmm5, %xmm5
    1bf9:      	pxor	%xmm4, %xmm5
    1bfd:      	movd	%xmm5, (%rax,%rdx)
    1c02:      	addq	$0x4, %rdx
    1c06:      	paddd	%xmm3, %xmm1
    1c0a:      	cmpq	%rdx, %rcx
    1c0d:      	jne	0x1be0 <packet_xor+0x730>
    1c0f:      	cmpq	%rcx, %r14
    1c12:      	je	0x1c33 <packet_xor+0x783>
    1c14:      	movl	%r15d, %edx
    1c17:      	nopw	(%rax,%rax)
    1c20:      	leal	(%rdx,%rcx), %esi
    1c23:      	xorb	(%rbx,%rcx), %sil
    1c27:      	movb	%sil, (%rax,%rcx)
    1c2b:      	incq	%rcx
    1c2e:      	cmpq	%rcx, %r14
    1c31:      	jne	0x1c20 <packet_xor+0x770>
    1c33:      	leaq	-0x1(%r14), %rdx
    1c37:      	movl	%r14d, %ecx
    1c3a:      	andl	$0x7, %ecx
    1c3d:      	cmpq	$0x7, %rdx
    1c41:      	jae	0x1c4a <packet_xor+0x79a>
    1c43:      	xorl	%edx, %edx
    1c45:      	xorl	%r15d, %r15d
    1c48:      	jmp	0x1caa <packet_xor+0x7fa>
    1c4a:      	andl	$0x38, %r14d
    1c4e:      	xorl	%edx, %edx
    1c50:      	xorl	%r15d, %r15d
    1c53:      	nopw	%cs:(%rax,%rax)
    1c60:      	movzbl	(%rax,%rdx), %esi
    1c64:      	addq	%r15, %rsi
    1c67:      	movzbl	0x1(%rax,%rdx), %edi
    1c6c:      	movzbl	0x2(%rax,%rdx), %r8d
    1c72:      	addq	%rdi, %r8
    1c75:      	addq	%rsi, %r8
    1c78:      	movzbl	0x3(%rax,%rdx), %esi
    1c7d:      	movzbl	0x4(%rax,%rdx), %edi
    1c82:      	addq	%rsi, %rdi
    1c85:      	movzbl	0x5(%rax,%rdx), %esi
    1c8a:      	addq	%rdi, %rsi
    1c8d:      	addq	%r8, %rsi
    1c90:      	movzbl	0x6(%rax,%rdx), %edi
    1c95:      	movzbl	0x7(%rax,%rdx), %r15d
    1c9b:      	addq	%rdi, %r15
    1c9e:      	addq	%rsi, %r15
    1ca1:      	addq	$0x8, %rdx
    1ca5:      	cmpq	%rdx, %r14
    1ca8:      	jne	0x1c60 <packet_xor+0x7b0>
    1caa:      	testq	%rcx, %rcx
    1cad:      	je	0x1ccf <packet_xor+0x81f>
    1caf:      	movq	%rax, %rsi
    1cb2:      	addq	%rdx, %rsi
    1cb5:      	xorl	%edx, %edx
    1cb7:      	nopw	(%rax,%rax)
    1cc0:      	movzbl	(%rsi,%rdx), %edi
    1cc4:      	addq	%rdi, %r15
    1cc7:      	incq	%rdx
    1cca:      	cmpq	%rdx, %rcx
    1ccd:      	jne	0x1cc0 <packet_xor+0x810>
    1ccf:      	movq	%rax, %rdi
    1cd2:      	callq	0x1030 <free@plt>
    1cd7:      	movq	%rbx, %rdi
    1cda:      	callq	0x1030 <free@plt>
    1cdf:      	movq	%r15, %rax
    1ce2:      	popq	%rbx
    1ce3:      	popq	%r14
    1ce5:      	popq	%r15
    1ce7:      	retq
    1ce8:      	movq	%rcx, %rdx
    1ceb:      	jmp	0x18d6 <packet_xor+0x426>
    1cf0:      	callq	0x1040 <abort@plt>

Disassembly of section .fini:

0000000000001cf8 <_fini>:
    1cf8:      	endbr64
    1cfc:      	subq	$0x8, %rsp
    1d00:      	addq	$0x8, %rsp
    1d04:      	retq
