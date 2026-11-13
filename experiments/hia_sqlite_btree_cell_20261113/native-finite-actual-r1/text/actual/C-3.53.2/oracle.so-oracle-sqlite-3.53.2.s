	.file	"oracle-sqlite-3.53.2.c"
	.text
	.p2align 4
	.type	btreeParseCellAdjustSizeForOverflow.isra.0, @function
btreeParseCellAdjustSizeForOverflow.isra.0:
.LFB15:
	.cfi_startproc
	movzwl	%di, %r9d
	movl	16(%r8), %eax
	movq	%rcx, %rdi
	movl	56(%rdx), %ecx
	movzwl	%si, %r10d
	xorl	%edx, %edx
	subl	%r10d, %eax
	subl	$4, %ecx
	divl	%ecx
	addl	%r10d, %edx
	cmpl	%edx, %r9d
	cmovge	%edx, %esi
	movw	%si, 20(%r8)
	movzwl	%si, %esi
	addq	8(%r8), %rsi
	subq	%rdi, %rsi
	addl	$4, %esi
	movw	%si, 22(%r8)
	ret
	.cfi_endproc
.LFE15:
	.size	btreeParseCellAdjustSizeForOverflow.isra.0, .-btreeParseCellAdjustSizeForOverflow.isra.0
	.p2align 4
	.globl	hia_oracle_3532_GetVarint
	.type	hia_oracle_3532_GetVarint, @function
hia_oracle_3532_GetVarint:
.LFB8:
	.cfi_startproc
	endbr64
	movsbq	(%rdi), %rax
	movl	$1, %edx
	testb	%al, %al
	jns	.L6
	movsbl	1(%rdi), %edx
	movzbl	%al, %eax
	testb	%dl, %dl
	jns	.L14
	movzbl	2(%rdi), %ecx
	sall	$14, %eax
	orl	%ecx, %eax
	andl	$128, %ecx
	je	.L15
	movzbl	3(%rdi), %ecx
	movzbl	%dl, %edx
	sall	$14, %edx
	orl	%ecx, %edx
	movl	%edx, %ecx
	andl	$2080895, %ecx
	andl	$128, %edx
	je	.L16
	movl	%eax, %edx
	movzbl	4(%rdi), %r9d
	sall	$14, %edx
	andl	$-266354688, %edx
	movl	%r9d, %r8d
	orl	%r9d, %edx
	andl	$128, %r9d
	je	.L17
	sall	$7, %eax
	movzbl	5(%rdi), %r9d
	andl	$266354560, %eax
	orl	%ecx, %eax
	sall	$14, %ecx
	orl	%r9d, %ecx
	andl	$128, %r9d
	je	.L18
	movzbl	6(%rdi), %r9d
	sall	$14, %edx
	orl	%r9d, %edx
	andl	$128, %r9d
	je	.L19
	movzbl	7(%rdi), %r9d
	sall	$14, %ecx
	andl	$2080895, %edx
	orl	%r9d, %ecx
	andl	$128, %r9d
	je	.L20
	sall	$4, %eax
	andl	$127, %r8d
	sall	$8, %ecx
	shrl	$3, %r8d
	sall	$15, %edx
	andl	$532709120, %ecx
	orl	%eax, %r8d
	movzbl	8(%rdi), %eax
	orl	%ecx, %edx
	salq	$32, %r8
	orl	%edx, %eax
	movl	$9, %edx
	orq	%r8, %rax
.L6:
	movq	%rax, (%rsi)
	movl	%edx, %eax
	ret
	.p2align 4,,10
	.p2align 3
.L14:
	sall	$7, %eax
	andl	$16256, %eax
	orl	%edx, %eax
	movl	$2, %edx
	movq	%rax, (%rsi)
	movl	%edx, %eax
	ret
	.p2align 4,,10
	.p2align 3
.L17:
	shrl	$18, %eax
	sall	$7, %ecx
	andl	$7, %eax
	orl	%edx, %ecx
	movl	$5, %edx
	salq	$32, %rax
	orq	%rcx, %rax
	jmp	.L6
	.p2align 4,,10
	.p2align 3
.L15:
	andl	$127, %edx
	andl	$2080895, %eax
	sall	$7, %edx
	orl	%eax, %edx
	movl	%edx, %eax
	movl	$3, %edx
	jmp	.L6
	.p2align 4,,10
	.p2align 3
.L16:
	sall	$7, %eax
	movl	$4, %edx
	andl	$266354560, %eax
	orl	%ecx, %eax
	jmp	.L6
	.p2align 4,,10
	.p2align 3
.L18:
	sall	$7, %edx
	shrl	$18, %eax
	andl	$266354560, %edx
	salq	$32, %rax
	orl	%ecx, %edx
	orq	%rdx, %rax
	movl	$6, %edx
	jmp	.L6
	.p2align 4,,10
	.p2align 3
.L20:
	sall	$7, %edx
	shrl	$4, %eax
	andl	$-266354561, %ecx
	orl	%edx, %ecx
	salq	$32, %rax
	movl	$8, %edx
	orq	%rcx, %rax
	jmp	.L6
	.p2align 4,,10
	.p2align 3
.L19:
	sall	$7, %ecx
	andl	$-266354561, %edx
	shrl	$11, %eax
	andl	$266354560, %ecx
	salq	$32, %rax
	orl	%edx, %ecx
	movl	$7, %edx
	orq	%rcx, %rax
	jmp	.L6
	.cfi_endproc
.LFE8:
	.size	hia_oracle_3532_GetVarint, .-hia_oracle_3532_GetVarint
	.section	.rodata.str1.8,"aMS",@progbits,1
	.align 8
.LC0:
	.string	"/home/qq/hia-rewrite-20261113-e26e-r1/sqlite-btree-cell-native-r1/candidate/reference/native-oracle/oracle-sqlite-3.53.2.c"
	.section	.rodata.str1.1,"aMS",@progbits,1
.LC1:
	.string	"(p[0] & 0x80)!=0"
.LC2:
	.string	"n>3 && n<=9"
	.section	.text.unlikely,"ax",@progbits
.LCOLDB3:
	.text
.LHOTB3:
	.p2align 4
	.globl	hia_oracle_3532_GetVarint32
	.type	hia_oracle_3532_GetVarint32, @function
hia_oracle_3532_GetVarint32:
.LFB9:
	.cfi_startproc
	endbr64
	subq	$40, %rsp
	.cfi_def_cfa_offset 48
	movq	%fs:40, %rax
	movq	%rax, 24(%rsp)
	xorl	%eax, %eax
	movzbl	(%rdi), %eax
	testb	%al, %al
	jns	.L29
	movzbl	1(%rdi), %ecx
	movq	%rsi, %r8
	testb	%cl, %cl
	jns	.L33
	movzbl	2(%rdi), %esi
	testb	%sil, %sil
	jns	.L34
	leaq	16(%rsp), %rsi
	movq	%r8, 8(%rsp)
	call	hia_oracle_3532_GetVarint@PLT
	leal	-4(%rax), %edx
	cmpb	$5, %dl
	ja	.L30
	movq	16(%rsp), %rdx
	movl	$4294967295, %ecx
	movq	8(%rsp), %r8
	cmpq	%rdx, %rcx
	movl	$-1, %ecx
	cmovb	%ecx, %edx
.L24:
	movl	%edx, (%r8)
	movq	24(%rsp), %rdx
	subq	%fs:40, %rdx
	jne	.L35
	addq	$40, %rsp
	.cfi_remember_state
	.cfi_def_cfa_offset 8
	ret
	.p2align 4,,10
	.p2align 3
.L34:
	.cfi_restore_state
	movl	%eax, %edx
	sall	$7, %ecx
	movl	$3, %eax
	sall	$14, %edx
	andl	$16256, %ecx
	andl	$2080768, %edx
	orl	%ecx, %edx
	orl	%esi, %edx
	jmp	.L24
	.p2align 4,,10
	.p2align 3
.L33:
	movl	%eax, %edx
	movl	$2, %eax
	sall	$7, %edx
	andl	$16256, %edx
	orl	%ecx, %edx
	jmp	.L24
.L35:
	call	__stack_chk_fail@PLT
	.cfi_endproc
	.section	.text.unlikely
	.cfi_startproc
	.type	hia_oracle_3532_GetVarint32.cold, @function
hia_oracle_3532_GetVarint32.cold:
.LFSB9:
.L29:
	.cfi_def_cfa_offset 48
	leaq	__PRETTY_FUNCTION__.3(%rip), %rcx
	movl	$357, %edx
	leaq	.LC0(%rip), %rsi
	leaq	.LC1(%rip), %rdi
	call	__assert_fail@PLT
.L30:
	leaq	__PRETTY_FUNCTION__.3(%rip), %rcx
	movl	$371, %edx
	leaq	.LC0(%rip), %rsi
	leaq	.LC2(%rip), %rdi
	call	__assert_fail@PLT
	.cfi_endproc
.LFE9:
	.text
	.size	hia_oracle_3532_GetVarint32, .-hia_oracle_3532_GetVarint32
	.section	.text.unlikely
	.size	hia_oracle_3532_GetVarint32.cold, .-hia_oracle_3532_GetVarint32.cold
.LCOLDE3:
	.text
.LHOTE3:
	.section	.rodata.str1.1
.LC5:
	.string	"pPage->leaf==0"
.LC6:
	.string	"pPage->childPtrSize==0"
	.section	.text.unlikely
.LCOLDB8:
	.text
.LHOTB8:
	.p2align 4
	.globl	oracle_cell
	.type	oracle_cell, @function
oracle_cell:
.LFB14:
	.cfi_startproc
	endbr64
	pushq	%r15
	.cfi_def_cfa_offset 16
	.cfi_offset 15, -16
	movq	%rsi, %r10
	movq	%rdx, %rsi
	movq	%rdi, %r11
	pushq	%r14
	.cfi_def_cfa_offset 24
	.cfi_offset 14, -24
	movq	%rcx, %r14
	pushq	%r12
	.cfi_def_cfa_offset 32
	.cfi_offset 12, -32
	pushq	%rbp
	.cfi_def_cfa_offset 40
	.cfi_offset 6, -40
	pushq	%rbx
	.cfi_def_cfa_offset 48
	.cfi_offset 3, -48
	movq	%rcx, %rbx
	movl	$19, %ecx
	subq	$224, %rsp
	.cfi_def_cfa_offset 272
	movq	%fs:40, %rax
	movq	%rax, 216(%rsp)
	xorl	%eax, %eax
	leaq	64(%rsp), %rdx
	movq	%rdx, %rdi
	rep stosq
	testq	%r11, %r11
	je	.L76
	testq	%r9, %r9
	je	.L76
	leaq	-512(%r10), %rax
	cmpq	$65024, %rax
	ja	.L76
	leaq	-1(%r10), %rax
	testq	%r10, %rax
	jne	.L76
	cmpq	$479, %rsi
	jbe	.L76
	cmpq	%rsi, %r10
	jb	.L76
	movq	%r10, %rax
	subq	%rsi, %rax
	cmpq	$255, %rax
	ja	.L76
	andq	$-9, %rbx
	movq	%rbx, %rcx
	cmpq	$5, %rbx
	je	.L80
	movl	$1, %eax
	cmpq	$2, %rbx
	jne	.L36
.L80:
	leaq	-4(%rsi), %rax
	cmpq	%r8, %rax
	jb	.L76
	leal	-12(%rsi), %eax
	movl	$2155905153, %ebx
	movl	%esi, 120(%rsp)
	movl	%eax, %edi
	sall	$5, %eax
	movl	%r10d, 116(%rsp)
	sall	$6, %edi
	imulq	%rbx, %rax
	imulq	%rbx, %rdi
	leal	-35(%rsi), %ebx
	movw	%bx, 110(%rsp)
	movl	%ebx, %r15d
	shrq	$39, %rax
	shrq	$39, %rdi
	subl	$23, %eax
	subl	$23, %edi
	cmpq	$10, %r14
	movw	%ax, 108(%rsp)
	movl	%eax, %ebp
	movw	%ax, 112(%rsp)
	sete	%al
	cmpq	$13, %r14
	sete	%sil
	movw	%di, 106(%rsp)
	orl	%eax, %esi
	movl	%esi, %eax
	xorl	$1, %eax
	cmpq	$5, %rcx
	jne	.L39
	movl	$-1515870811, %edi
	movd	%edi, %xmm0
	movabsq	$-6510615555426900571, %rdi
	pshufd	$0, %xmm0, %xmm0
	movq	%rdi, 48(%rsp)
	movaps	%xmm0, 32(%rsp)
	cmpq	$5, %r14
	je	.L99
	leaq	(%r11,%r8), %rdi
	testb	%al, %al
	jne	.L94
	movzbl	(%rdi), %esi
	movq	%rsi, %rax
	testb	%sil, %sil
	js	.L47
	movzbl	1(%rdi), %ecx
	movq	%rcx, %rbx
	cmpq	$127, %rcx
	ja	.L77
	leaq	2(%rdi), %r8
	movq	%rcx, 32(%rsp)
	movl	%esi, 48(%rsp)
	movq	%r8, 40(%rsp)
.L49:
	subq	%rdi, %r8
	movl	$4, %edx
	movw	%si, 52(%rsp)
	leal	(%rsi,%r8), %eax
	cmpw	%dx, %ax
	cmovb	%edx, %eax
	movw	%ax, 54(%rsp)
	.p2align 4
	.p2align 3
.L45:
	movq	32(%rsp), %rax
	movq	%rax, (%r9)
	xorl	%eax, %eax
	cmpq	$0, 40(%rsp)
	sete	%al
	movq	%rax, 8(%r9)
	movq	40(%rsp), %rdx
	testq	%rdx, %rdx
	je	.L66
	movq	$-1, 16(%r9)
	movl	48(%rsp), %eax
	movq	%rax, 24(%r9)
	movzwl	52(%rsp), %eax
	movq	%rax, 32(%r9)
	movzwl	54(%rsp), %eax
	movq	%rax, 40(%r9)
	movq	%r10, %rax
	notq	%rax
	cmpq	%rdx, %rax
	cmova	%rdx, %rax
	cmpq	%r11, %rax
	movl	$2, %eax
	jb	.L36
	addq	%r11, %r10
	cmpq	%rdx, %r10
	jb	.L36
	subq	%r11, %rdx
	xorl	%eax, %eax
	movq	%rdx, 16(%r9)
	jmp	.L36
	.p2align 4,,10
	.p2align 3
.L76:
	movl	$1, %eax
.L36:
	movq	216(%rsp), %rdx
	subq	%fs:40, %rdx
	jne	.L100
	addq	$224, %rsp
	.cfi_remember_state
	.cfi_def_cfa_offset 48
	popq	%rbx
	.cfi_def_cfa_offset 40
	popq	%rbp
	.cfi_def_cfa_offset 32
	popq	%r12
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	ret
	.p2align 4,,10
	.p2align 3
.L39:
	.cfi_restore_state
	sall	$2, %eax
	leaq	(%r11,%r8), %rbx
	movl	$-1515870811, %ecx
	movzbl	%al, %eax
	movd	%ecx, %xmm0
	movq	%rbx, %r15
	movabsq	$-6510615555426900571, %rcx
	addq	%rbx, %rax
	movq	%rcx, 48(%rsp)
	pshufd	$0, %xmm0, %xmm0
	movaps	%xmm0, 32(%rsp)
	movzbl	(%rax), %ecx
	movq	%rcx, %r8
	testb	%cl, %cl
	jns	.L101
	leaq	8(%rax), %rbx
	andl	$127, %ecx
	jmp	.L61
	.p2align 6
	.p2align 4,,10
	.p2align 3
.L102:
	cmpq	%rbx, %rax
	jnb	.L63
.L61:
	movq	%rax, %r14
	movzbl	1(%rax), %r8d
	sall	$7, %ecx
	addq	$1, %rax
	movl	%r8d, %esi
	andl	$127, %esi
	orl	%esi, %ecx
	testb	%r8b, %r8b
	js	.L102
.L63:
	leaq	2(%r14), %rsi
	movl	%ecx, %r8d
.L64:
	movzwl	%di, %eax
	movq	%r8, 32(%rsp)
	movl	%ecx, 48(%rsp)
	movq	%rsi, 40(%rsp)
	cmpl	%ecx, %eax
	jb	.L65
	subq	%r15, %rsi
	movl	$4, %eax
	movw	%cx, 52(%rsp)
	addl	%ecx, %esi
	cmpw	%ax, %si
	cmovb	%eax, %esi
	movw	%si, 54(%rsp)
	jmp	.L45
	.p2align 4,,10
	.p2align 3
.L66:
	movq	$0, 16(%r9)
	movl	48(%rsp), %eax
	movq	%rax, 24(%r9)
	movzwl	52(%rsp), %eax
	movq	%rax, 32(%r9)
	movzwl	54(%rsp), %eax
	movq	%rax, 40(%r9)
	xorl	%eax, %eax
	jmp	.L36
	.p2align 4,,10
	.p2align 3
.L101:
	leaq	1(%rax), %rsi
	jmp	.L64
	.p2align 4,,10
	.p2align 3
.L99:
	testb	%sil, %sil
	jne	.L93
	leaq	4(%r11,%r8), %rdi
	leaq	32(%rsp), %rsi
	movq	%r9, 24(%rsp)
	movq	%r10, 16(%rsp)
	movq	%r11, 8(%rsp)
	call	hia_oracle_3532_GetVarint@PLT
	movq	8(%rsp), %r11
	movq	16(%rsp), %r10
	movl	$0, 48(%rsp)
	movzbl	%al, %eax
	movq	24(%rsp), %r9
	movq	$0, 40(%rsp)
	addl	$4, %eax
	movw	%ax, 54(%rsp)
	xorl	%eax, %eax
	movw	%ax, 52(%rsp)
	jmp	.L45
	.p2align 4,,10
	.p2align 3
.L65:
	leaq	32(%rsp), %r8
	movq	%r15, %rcx
	movl	%ebp, %esi
	movq	%r9, 16(%rsp)
	movq	%r10, 8(%rsp)
	call	btreeParseCellAdjustSizeForOverflow.isra.0
	movq	16(%rsp), %r9
	movq	8(%rsp), %r10
	jmp	.L45
.L47:
	leaq	8(%rdi), %rbx
	andl	$127, %eax
	movq	%rdi, %rcx
	jmp	.L50
	.p2align 6
	.p2align 4,,10
	.p2align 3
.L103:
	cmpq	%rbx, %rcx
	jnb	.L81
.L50:
	movq	%rcx, %r14
	movzbl	1(%rcx), %r8d
	salq	$7, %rax
	addq	$1, %rcx
	movq	%r8, %rsi
	andl	$127, %esi
	orq	%rsi, %rax
	testb	%r8b, %r8b
	js	.L103
.L81:
	movzbl	1(%rcx), %ebx
	movl	%eax, %esi
	cmpq	$127, %rbx
	ja	.L48
	leaq	3(%r14), %r8
	movq	%rbx, %r14
.L52:
	movl	%eax, 48(%rsp)
	movzwl	%r15w, %eax
	movq	%r14, 32(%rsp)
	movq	%r8, 40(%rsp)
	cmpq	%rsi, %rax
	jnb	.L49
	movq	%rdi, %rcx
	leaq	32(%rsp), %r8
	movl	%ebp, %esi
	movl	%r15d, %edi
	movq	%r9, 16(%rsp)
	movq	%r10, 8(%rsp)
	call	btreeParseCellAdjustSizeForOverflow.isra.0
	movq	8(%rsp), %r10
	movq	16(%rsp), %r9
	jmp	.L45
.L77:
	movq	%rdi, %rcx
.L48:
	movzbl	2(%rcx), %r8d
	salq	$7, %rbx
	xorq	%r8, %rbx
	leaq	3(%rcx), %r8
	movq	%rbx, %r14
	xorq	$16384, %r14
	cmpb	$0, 2(%rcx)
	jns	.L52
	movzbl	3(%rcx), %r8d
	salq	$7, %rbx
	xorq	%r8, %rbx
	leaq	4(%rcx), %r8
	movq	%rbx, %r14
	xorq	$2113536, %r14
	cmpb	$0, 3(%rcx)
	jns	.L52
	movzbl	4(%rcx), %r8d
	salq	$7, %rbx
	xorq	%r8, %rbx
	leaq	5(%rcx), %r8
	xorq	$270548992, %rbx
	movq	%rbx, %r14
	cmpb	$0, 4(%rcx)
	jns	.L52
	movzbl	5(%rcx), %r8d
	salq	$7, %rbx
	xorq	%rbx, %r8
	movq	%r8, %rbx
	xorb	$64, %bh
	cmpb	$0, 5(%rcx)
	js	.L104
	leaq	6(%rcx), %r8
	movq	%rbx, %r14
	jmp	.L52
.L100:
	call	__stack_chk_fail@PLT
.L104:
	movzbl	6(%rcx), %r8d
	salq	$7, %rbx
	xorq	%rbx, %r8
	movq	%r8, %rbx
	xorb	$64, %bh
	cmpb	$0, 6(%rcx)
	js	.L105
	leaq	7(%rcx), %r8
	movq	%rbx, %r14
	jmp	.L52
.L105:
	movzbl	7(%rcx), %r8d
	salq	$7, %rbx
	xorq	%rbx, %r8
	movq	%r8, %rbx
	xorb	$64, %bh
	cmpb	$0, 7(%rcx)
	js	.L106
	leaq	8(%rcx), %r8
	movq	%rbx, %r14
	jmp	.L52
.L106:
	movzbl	8(%rcx), %r8d
	salq	$7, %rbx
	xorq	%rbx, %r8
	movq	%r8, %rbx
	xorb	$64, %bh
	cmpb	$0, 8(%rcx)
	js	.L107
	leaq	9(%rcx), %r8
	movq	%rbx, %r14
	jmp	.L52
.L107:
	leaq	10(%rcx), %r8
	movzbl	9(%rcx), %ecx
	salq	$8, %rbx
	xorq	%rbx, %rcx
	xorb	$-128, %ch
	movq	%rcx, %r14
	jmp	.L52
	.cfi_endproc
	.section	.text.unlikely
	.cfi_startproc
	.type	oracle_cell.cold, @function
oracle_cell.cold:
.LFSB14:
.L94:
	.cfi_def_cfa_offset 272
	.cfi_offset 3, -48
	.cfi_offset 6, -40
	.cfi_offset 12, -32
	.cfi_offset 14, -24
	.cfi_offset 15, -16
	leaq	__PRETTY_FUNCTION__.1(%rip), %rcx
	movl	$443, %edx
	leaq	.LC0(%rip), %rsi
	leaq	.LC6(%rip), %rdi
	call	__assert_fail@PLT
.L93:
	leaq	__PRETTY_FUNCTION__.2(%rip), %rcx
	movl	$419, %edx
	leaq	.LC0(%rip), %rsi
	leaq	.LC5(%rip), %rdi
	call	__assert_fail@PLT
	.cfi_endproc
.LFE14:
	.text
	.size	oracle_cell, .-oracle_cell
	.section	.text.unlikely
	.size	oracle_cell.cold, .-oracle_cell.cold
.LCOLDE8:
	.text
.LHOTE8:
	.section	.rodata
	.align 16
	.type	__PRETTY_FUNCTION__.1, @object
	.size	__PRETTY_FUNCTION__.1, 18
__PRETTY_FUNCTION__.1:
	.string	"btreeParseCellPtr"
	.align 16
	.type	__PRETTY_FUNCTION__.2, @object
	.size	__PRETTY_FUNCTION__.2, 27
__PRETTY_FUNCTION__.2:
	.string	"btreeParseCellPtrNoPayload"
	.align 16
	.type	__PRETTY_FUNCTION__.3, @object
	.size	__PRETTY_FUNCTION__.3, 28
__PRETTY_FUNCTION__.3:
	.string	"hia_oracle_3532_GetVarint32"
	.ident	"GCC: (Ubuntu 15.2.0-16ubuntu1) 15.2.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	1f - 0f
	.long	4f - 1f
	.long	5
0:
	.string	"GNU"
1:
	.align 8
	.long	0xc0000002
	.long	3f - 2f
2:
	.long	0x3
3:
	.align 8
4:
