; Standalone HIA: verified core -> LLVM. No source AST or Rust safety gate.
target triple = "x86_64-unknown-linux-gnu"
%hia.buffer = type { ptr, i64 }
%hia.alloc = type { %hia.buffer, i1 }
declare void @abort() noreturn
declare noalias ptr @calloc(i64, i64) "no-builtins"
declare noalias ptr @malloc(i64) "no-builtins"
declare void @free(ptr) "no-builtins"
declare { i64, i1 } @llvm.uadd.with.overflow.i64(i64, i64)

; A failed allocation is an empty, valid owner plus false. Zero length succeeds.
; The independent verifier still requires every resulting owner to be consumed.
define internal %hia.alloc @__hia_allocate(i64 %length, i1 %zero_bytes) {
entry:
  %zero = icmp eq i64 %length, 0
  br i1 %zero, label %empty, label %nonempty
empty:
  %empty_result = insertvalue %hia.alloc zeroinitializer, i1 true, 1
  ret %hia.alloc %empty_result
nonempty:
  %valid = icmp ule i64 %length, 9223372036854775807
  br i1 %valid, label %allocate, label %failed
allocate:
  br i1 %zero_bytes, label %zeroed, label %unread
zeroed:
  %zero_pointer = call ptr @calloc(i64 1, i64 %length) nobuiltin
  br label %allocated
unread:
  %unread_pointer = call ptr @malloc(i64 %length) nobuiltin
  br label %allocated
allocated:
  %pointer = phi ptr [ %zero_pointer, %zeroed ], [ %unread_pointer, %unread ]
  %success = icmp ne ptr %pointer, null
  br i1 %success, label %ready, label %failed
ready:
  %b0 = insertvalue %hia.buffer zeroinitializer, ptr %pointer, 0
  %b1 = insertvalue %hia.buffer %b0, i64 %length, 1
  %r0 = insertvalue %hia.alloc zeroinitializer, %hia.buffer %b1, 0
  %r1 = insertvalue %hia.alloc %r0, i1 true, 1
  ret %hia.alloc %r1
failed:
  ret %hia.alloc zeroinitializer
}

define internal i64 @__hia_fn_0(i64 %p_0_0, i32 %p_0_1) {
b0:
  %t1 = icmp ule i64 %p_0_0, 32
  br i1 %t1, label %edge_0, label %edge_1
b1:
  %p_1_0 = phi i64 [ %p_0_0, %edge_0 ]
  %p_1_1 = phi i32 [ %p_0_1, %edge_0 ]
  %t2 = call %hia.alloc @__hia_allocate(i64 %p_1_0, i1 true)
  %t3 = extractvalue %hia.alloc %t2, 0
  %t4 = extractvalue %hia.alloc %t2, 1
  %t5 = select i1 %t4, i64 %p_1_0, i64 0
  %t6 = insertvalue %hia.buffer %t3, i64 %t5, 1
  br i1 %t4, label %edge_2, label %edge_3
b2:
  %p_2_0 = phi i64 [ %p_1_0, %edge_2 ]
  %p_2_1 = phi i32 [ %p_1_1, %edge_2 ]
  %p_2_2 = phi i1 [ %t4, %edge_2 ]
  %p_2_3 = phi %hia.buffer [ %t6, %edge_2 ]
  %p_2_4 = phi i8 [ 1, %edge_2 ]
  br label %edge_4
b3:
  %p_3_0 = phi i64 [ %p_1_0, %edge_3 ]
  %p_3_1 = phi i32 [ %p_1_1, %edge_3 ]
  %p_3_2 = phi i1 [ %t4, %edge_3 ]
  %p_3_3 = phi %hia.buffer [ %t6, %edge_3 ]
  %p_3_4 = phi i8 [ 1, %edge_3 ]
  %t7 = extractvalue %hia.buffer %p_3_3, 0
  %t8 = icmp ne ptr %t7, null
  br i1 %t8, label %drop_nonnull_9, label %drop_after_9
drop_nonnull_9:
  call void @free(ptr %t7) nobuiltin
  br label %drop_after_9
drop_after_9:
  %t10 = zext i8 %p_3_4 to i64
  %t11 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 1000, i64 %t10)
  %t12 = extractvalue { i64, i1 } %t11, 0
  %t13 = extractvalue { i64, i1 } %t11, 1
  %t14 = xor i1 %t13, true
  br i1 %t14, label %ok_15, label %trap_15
trap_15:
  call void @abort()
  unreachable
ok_15:
  ret i64 %t12
b4:
  %p_4_0 = phi i64 [ %p_2_0, %edge_4 ], [ %p_5_0, %edge_7 ]
  %p_4_1 = phi i32 [ %p_2_1, %edge_4 ], [ %p_5_1, %edge_7 ]
  %p_4_2 = phi %hia.buffer [ %p_2_3, %edge_4 ], [ %p_5_2, %edge_7 ]
  %p_4_3 = phi i64 [ %p_2_0, %edge_4 ], [ %p_5_3, %edge_7 ]
  %p_4_4 = phi i64 [ 0, %edge_4 ], [ %t26, %edge_7 ]
  %t16 = icmp ult i64 %p_4_4, %p_4_3
  br i1 %t16, label %edge_5, label %edge_6
b5:
  %p_5_0 = phi i64 [ %p_4_0, %edge_5 ]
  %p_5_1 = phi i32 [ %p_4_1, %edge_5 ]
  %p_5_2 = phi %hia.buffer [ %p_4_2, %edge_5 ]
  %p_5_3 = phi i64 [ %p_4_3, %edge_5 ]
  %p_5_4 = phi i64 [ %p_4_4, %edge_5 ]
  %t17 = trunc i64 %p_5_4 to i32
  %t18 = add i32 %t17, %p_5_1
  %t19 = trunc i32 %t18 to i8
  %t20 = extractvalue %hia.buffer %p_5_2, 0
  %t21 = extractvalue %hia.buffer %p_5_2, 1
  %t22 = icmp ult i64 %p_5_4, %t21
  br i1 %t22, label %ok_23, label %trap_23
trap_23:
  call void @abort()
  unreachable
ok_23:
  %t24 = getelementptr i8, ptr %t20, i64 %p_5_4
  store i8 %t19, ptr %t24, align 1
  %t25 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_5_4, i64 1)
  %t26 = extractvalue { i64, i1 } %t25, 0
  %t27 = extractvalue { i64, i1 } %t25, 1
  %t28 = xor i1 %t27, true
  br i1 %t28, label %ok_29, label %trap_29
trap_29:
  call void @abort()
  unreachable
ok_29:
  br label %edge_7
b6:
  %p_6_0 = phi i64 [ %p_4_0, %edge_6 ]
  %p_6_1 = phi i32 [ %p_4_1, %edge_6 ]
  %p_6_2 = phi %hia.buffer [ %p_4_2, %edge_6 ]
  %p_6_3 = phi i64 [ %p_4_3, %edge_6 ]
  %p_6_4 = phi i64 [ %p_4_4, %edge_6 ]
  br label %edge_8
b7:
  %p_7_0 = phi i64 [ %p_6_0, %edge_8 ], [ %p_8_0, %edge_11 ]
  %p_7_1 = phi i32 [ %p_6_1, %edge_8 ], [ %p_8_1, %edge_11 ]
  %p_7_2 = phi %hia.buffer [ %p_6_2, %edge_8 ], [ %p_8_2, %edge_11 ]
  %p_7_3 = phi i64 [ 0, %edge_8 ], [ %t38, %edge_11 ]
  %p_7_4 = phi i64 [ %p_6_0, %edge_8 ], [ %p_8_4, %edge_11 ]
  %p_7_5 = phi i64 [ 0, %edge_8 ], [ %t40, %edge_11 ]
  %t30 = icmp ult i64 %p_7_5, %p_7_4
  br i1 %t30, label %edge_9, label %edge_10
b8:
  %p_8_0 = phi i64 [ %p_7_0, %edge_9 ]
  %p_8_1 = phi i32 [ %p_7_1, %edge_9 ]
  %p_8_2 = phi %hia.buffer [ %p_7_2, %edge_9 ]
  %p_8_3 = phi i64 [ %p_7_3, %edge_9 ]
  %p_8_4 = phi i64 [ %p_7_4, %edge_9 ]
  %p_8_5 = phi i64 [ %p_7_5, %edge_9 ]
  %t31 = extractvalue %hia.buffer %p_8_2, 0
  %t32 = extractvalue %hia.buffer %p_8_2, 1
  %t33 = icmp ult i64 %p_8_5, %t32
  br i1 %t33, label %ok_34, label %trap_34
trap_34:
  call void @abort()
  unreachable
ok_34:
  %t35 = getelementptr i8, ptr %t31, i64 %p_8_5
  %t36 = load i8, ptr %t35, align 1
  %t37 = zext i8 %t36 to i64
  %t38 = add i64 %p_8_3, %t37
  %t39 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_8_5, i64 1)
  %t40 = extractvalue { i64, i1 } %t39, 0
  %t41 = extractvalue { i64, i1 } %t39, 1
  %t42 = xor i1 %t41, true
  br i1 %t42, label %ok_43, label %trap_43
trap_43:
  call void @abort()
  unreachable
ok_43:
  br label %edge_11
b9:
  %p_9_0 = phi i64 [ %p_7_0, %edge_10 ]
  %p_9_1 = phi i32 [ %p_7_1, %edge_10 ]
  %p_9_2 = phi %hia.buffer [ %p_7_2, %edge_10 ]
  %p_9_3 = phi i64 [ %p_7_3, %edge_10 ]
  %p_9_4 = phi i64 [ %p_7_4, %edge_10 ]
  %p_9_5 = phi i64 [ %p_7_5, %edge_10 ]
  %t44 = extractvalue %hia.buffer %p_9_2, 0
  %t45 = icmp ne ptr %t44, null
  br i1 %t45, label %drop_nonnull_46, label %drop_after_46
drop_nonnull_46:
  call void @free(ptr %t44) nobuiltin
  br label %drop_after_46
drop_after_46:
  ret i64 %p_9_3
b10:
  %p_10_0 = phi i64 [ %p_0_0, %edge_1 ]
  %p_10_1 = phi i32 [ %p_0_1, %edge_1 ]
  %t47 = call %hia.alloc @__hia_allocate(i64 %p_10_0, i1 true)
  %t48 = extractvalue %hia.alloc %t47, 0
  %t49 = extractvalue %hia.alloc %t47, 1
  %t50 = select i1 %t49, i64 %p_10_0, i64 0
  %t51 = insertvalue %hia.buffer %t48, i64 %t50, 1
  br i1 %t49, label %edge_12, label %edge_13
b11:
  %p_11_0 = phi i64 [ %p_10_0, %edge_12 ]
  %p_11_1 = phi i32 [ %p_10_1, %edge_12 ]
  %p_11_2 = phi i1 [ %t49, %edge_12 ]
  %p_11_3 = phi %hia.buffer [ %t51, %edge_12 ]
  %p_11_4 = phi i8 [ 1, %edge_12 ]
  br label %edge_14
b12:
  %p_12_0 = phi i64 [ %p_10_0, %edge_13 ]
  %p_12_1 = phi i32 [ %p_10_1, %edge_13 ]
  %p_12_2 = phi i1 [ %t49, %edge_13 ]
  %p_12_3 = phi %hia.buffer [ %t51, %edge_13 ]
  %p_12_4 = phi i8 [ 1, %edge_13 ]
  %t52 = extractvalue %hia.buffer %p_12_3, 0
  %t53 = icmp ne ptr %t52, null
  br i1 %t53, label %drop_nonnull_54, label %drop_after_54
drop_nonnull_54:
  call void @free(ptr %t52) nobuiltin
  br label %drop_after_54
drop_after_54:
  %t55 = zext i8 %p_12_4 to i64
  %t56 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 1000, i64 %t55)
  %t57 = extractvalue { i64, i1 } %t56, 0
  %t58 = extractvalue { i64, i1 } %t56, 1
  %t59 = xor i1 %t58, true
  br i1 %t59, label %ok_60, label %trap_60
trap_60:
  call void @abort()
  unreachable
ok_60:
  ret i64 %t57
b13:
  %p_13_0 = phi i64 [ %p_11_0, %edge_14 ], [ %p_14_0, %edge_17 ]
  %p_13_1 = phi i32 [ %p_11_1, %edge_14 ], [ %p_14_1, %edge_17 ]
  %p_13_2 = phi %hia.buffer [ %p_11_3, %edge_14 ], [ %p_14_2, %edge_17 ]
  %p_13_3 = phi i64 [ %p_11_0, %edge_14 ], [ %p_14_3, %edge_17 ]
  %p_13_4 = phi i64 [ 0, %edge_14 ], [ %t71, %edge_17 ]
  %t61 = icmp ult i64 %p_13_4, %p_13_3
  br i1 %t61, label %edge_15, label %edge_16
b14:
  %p_14_0 = phi i64 [ %p_13_0, %edge_15 ]
  %p_14_1 = phi i32 [ %p_13_1, %edge_15 ]
  %p_14_2 = phi %hia.buffer [ %p_13_2, %edge_15 ]
  %p_14_3 = phi i64 [ %p_13_3, %edge_15 ]
  %p_14_4 = phi i64 [ %p_13_4, %edge_15 ]
  %t62 = trunc i64 %p_14_4 to i32
  %t63 = add i32 %t62, %p_14_1
  %t64 = trunc i32 %t63 to i8
  %t65 = extractvalue %hia.buffer %p_14_2, 0
  %t66 = extractvalue %hia.buffer %p_14_2, 1
  %t67 = icmp ult i64 %p_14_4, %t66
  br i1 %t67, label %ok_68, label %trap_68
trap_68:
  call void @abort()
  unreachable
ok_68:
  %t69 = getelementptr i8, ptr %t65, i64 %p_14_4
  store i8 %t64, ptr %t69, align 1
  %t70 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_14_4, i64 1)
  %t71 = extractvalue { i64, i1 } %t70, 0
  %t72 = extractvalue { i64, i1 } %t70, 1
  %t73 = xor i1 %t72, true
  br i1 %t73, label %ok_74, label %trap_74
trap_74:
  call void @abort()
  unreachable
ok_74:
  br label %edge_17
b15:
  %p_15_0 = phi i64 [ %p_13_0, %edge_16 ]
  %p_15_1 = phi i32 [ %p_13_1, %edge_16 ]
  %p_15_2 = phi %hia.buffer [ %p_13_2, %edge_16 ]
  %p_15_3 = phi i64 [ %p_13_3, %edge_16 ]
  %p_15_4 = phi i64 [ %p_13_4, %edge_16 ]
  br label %edge_18
b16:
  %p_16_0 = phi i64 [ %p_15_0, %edge_18 ], [ %p_17_0, %edge_21 ]
  %p_16_1 = phi i32 [ %p_15_1, %edge_18 ], [ %p_17_1, %edge_21 ]
  %p_16_2 = phi %hia.buffer [ %p_15_2, %edge_18 ], [ %p_17_2, %edge_21 ]
  %p_16_3 = phi i64 [ 0, %edge_18 ], [ %t84, %edge_21 ]
  %p_16_4 = phi i64 [ %p_15_0, %edge_18 ], [ %p_17_4, %edge_21 ]
  %p_16_5 = phi i64 [ 0, %edge_18 ], [ %t89, %edge_21 ]
  %t75 = icmp ult i64 %p_16_5, %p_16_4
  br i1 %t75, label %edge_19, label %edge_20
b17:
  %p_17_0 = phi i64 [ %p_16_0, %edge_19 ]
  %p_17_1 = phi i32 [ %p_16_1, %edge_19 ]
  %p_17_2 = phi %hia.buffer [ %p_16_2, %edge_19 ]
  %p_17_3 = phi i64 [ %p_16_3, %edge_19 ]
  %p_17_4 = phi i64 [ %p_16_4, %edge_19 ]
  %p_17_5 = phi i64 [ %p_16_5, %edge_19 ]
  %t76 = extractvalue %hia.buffer %p_17_2, 0
  %t77 = extractvalue %hia.buffer %p_17_2, 1
  %t78 = icmp ult i64 %p_17_5, %t77
  br i1 %t78, label %ok_79, label %trap_79
trap_79:
  call void @abort()
  unreachable
ok_79:
  %t80 = getelementptr i8, ptr %t76, i64 %p_17_5
  %t81 = load i8, ptr %t80, align 1
  %t82 = zext i8 %t81 to i64
  %t83 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_17_3, i64 %t82)
  %t84 = extractvalue { i64, i1 } %t83, 0
  %t85 = extractvalue { i64, i1 } %t83, 1
  %t86 = xor i1 %t85, true
  br i1 %t86, label %ok_87, label %trap_87
trap_87:
  call void @abort()
  unreachable
ok_87:
  %t88 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_17_5, i64 1)
  %t89 = extractvalue { i64, i1 } %t88, 0
  %t90 = extractvalue { i64, i1 } %t88, 1
  %t91 = xor i1 %t90, true
  br i1 %t91, label %ok_92, label %trap_92
trap_92:
  call void @abort()
  unreachable
ok_92:
  br label %edge_21
b18:
  %p_18_0 = phi i64 [ %p_16_0, %edge_20 ]
  %p_18_1 = phi i32 [ %p_16_1, %edge_20 ]
  %p_18_2 = phi %hia.buffer [ %p_16_2, %edge_20 ]
  %p_18_3 = phi i64 [ %p_16_3, %edge_20 ]
  %p_18_4 = phi i64 [ %p_16_4, %edge_20 ]
  %p_18_5 = phi i64 [ %p_16_5, %edge_20 ]
  %t93 = extractvalue %hia.buffer %p_18_2, 0
  %t94 = icmp ne ptr %t93, null
  br i1 %t94, label %drop_nonnull_95, label %drop_after_95
drop_nonnull_95:
  call void @free(ptr %t93) nobuiltin
  br label %drop_after_95
drop_after_95:
  ret i64 %p_18_3
edge_0:
  br label %b1
edge_1:
  br label %b10
edge_2:
  br label %b2
edge_3:
  br label %b3
edge_4:
  br label %b4
edge_5:
  br label %b5
edge_6:
  br label %b6
edge_7:
  br label %b4
edge_8:
  br label %b7
edge_9:
  br label %b8
edge_10:
  br label %b9
edge_11:
  br label %b7
edge_12:
  br label %b11
edge_13:
  br label %b12
edge_14:
  br label %b13
edge_15:
  br label %b14
edge_16:
  br label %b15
edge_17:
  br label %b13
edge_18:
  br label %b16
edge_19:
  br label %b17
edge_20:
  br label %b18
edge_21:
  br label %b16
}

define internal i64 @__hia_fn_1(i64 %p_0_0, i32 %p_0_1) {
b0:
  %t1 = icmp ule i64 %p_0_0, 32
  br i1 %t1, label %edge_0, label %edge_1
b1:
  %p_1_0 = phi i64 [ %p_0_0, %edge_0 ]
  %p_1_1 = phi i32 [ %p_0_1, %edge_0 ]
  %t2 = call %hia.alloc @__hia_allocate(i64 %p_1_0, i1 true)
  %t3 = extractvalue %hia.alloc %t2, 0
  %t4 = extractvalue %hia.alloc %t2, 1
  %t5 = select i1 %t4, i64 %p_1_0, i64 0
  %t6 = insertvalue %hia.buffer %t3, i64 %t5, 1
  br i1 %t4, label %edge_2, label %edge_3
b2:
  %p_2_0 = phi i64 [ %p_1_0, %edge_2 ]
  %p_2_1 = phi i32 [ %p_1_1, %edge_2 ]
  %p_2_2 = phi i1 [ %t4, %edge_2 ]
  %p_2_3 = phi %hia.buffer [ %t6, %edge_2 ]
  %p_2_4 = phi i8 [ 1, %edge_2 ]
  br label %edge_4
b3:
  %p_3_0 = phi i64 [ %p_1_0, %edge_3 ]
  %p_3_1 = phi i32 [ %p_1_1, %edge_3 ]
  %p_3_2 = phi i1 [ %t4, %edge_3 ]
  %p_3_3 = phi %hia.buffer [ %t6, %edge_3 ]
  %p_3_4 = phi i8 [ 1, %edge_3 ]
  %t7 = extractvalue %hia.buffer %p_3_3, 0
  %t8 = icmp ne ptr %t7, null
  br i1 %t8, label %drop_nonnull_9, label %drop_after_9
drop_nonnull_9:
  call void @free(ptr %t7) nobuiltin
  br label %drop_after_9
drop_after_9:
  %t10 = zext i8 %p_3_4 to i64
  %t11 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 1000, i64 %t10)
  %t12 = extractvalue { i64, i1 } %t11, 0
  %t13 = extractvalue { i64, i1 } %t11, 1
  %t14 = xor i1 %t13, true
  br i1 %t14, label %ok_15, label %trap_15
trap_15:
  call void @abort()
  unreachable
ok_15:
  ret i64 %t12
b4:
  %p_4_0 = phi i64 [ %p_2_0, %edge_4 ], [ %p_5_0, %edge_7 ]
  %p_4_1 = phi i32 [ %p_2_1, %edge_4 ], [ %p_5_1, %edge_7 ]
  %p_4_2 = phi %hia.buffer [ %p_2_3, %edge_4 ], [ %p_5_2, %edge_7 ]
  %p_4_3 = phi i64 [ %p_2_0, %edge_4 ], [ %p_5_3, %edge_7 ]
  %p_4_4 = phi i64 [ 0, %edge_4 ], [ %t27, %edge_7 ]
  %t16 = icmp ult i64 %p_4_4, %p_4_3
  br i1 %t16, label %edge_5, label %edge_6
b5:
  %p_5_0 = phi i64 [ %p_4_0, %edge_5 ]
  %p_5_1 = phi i32 [ %p_4_1, %edge_5 ]
  %p_5_2 = phi %hia.buffer [ %p_4_2, %edge_5 ]
  %p_5_3 = phi i64 [ %p_4_3, %edge_5 ]
  %p_5_4 = phi i64 [ %p_4_4, %edge_5 ]
  %t17 = trunc i64 %p_5_4 to i32
  %t18 = mul i32 %t17, 13
  %t19 = add i32 %t18, %p_5_1
  %t20 = trunc i32 %t19 to i8
  %t21 = extractvalue %hia.buffer %p_5_2, 0
  %t22 = extractvalue %hia.buffer %p_5_2, 1
  %t23 = icmp ult i64 %p_5_4, %t22
  br i1 %t23, label %ok_24, label %trap_24
trap_24:
  call void @abort()
  unreachable
ok_24:
  %t25 = getelementptr i8, ptr %t21, i64 %p_5_4
  store i8 %t20, ptr %t25, align 1
  %t26 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_5_4, i64 1)
  %t27 = extractvalue { i64, i1 } %t26, 0
  %t28 = extractvalue { i64, i1 } %t26, 1
  %t29 = xor i1 %t28, true
  br i1 %t29, label %ok_30, label %trap_30
trap_30:
  call void @abort()
  unreachable
ok_30:
  br label %edge_7
b6:
  %p_6_0 = phi i64 [ %p_4_0, %edge_6 ]
  %p_6_1 = phi i32 [ %p_4_1, %edge_6 ]
  %p_6_2 = phi %hia.buffer [ %p_4_2, %edge_6 ]
  %p_6_3 = phi i64 [ %p_4_3, %edge_6 ]
  %p_6_4 = phi i64 [ %p_4_4, %edge_6 ]
  %t31 = call %hia.alloc @__hia_allocate(i64 %p_6_0, i1 true)
  %t32 = extractvalue %hia.alloc %t31, 0
  %t33 = extractvalue %hia.alloc %t31, 1
  %t34 = select i1 %t33, i64 %p_6_0, i64 0
  %t35 = insertvalue %hia.buffer %t32, i64 %t34, 1
  br i1 %t33, label %edge_8, label %edge_9
b7:
  %p_7_0 = phi i64 [ %p_6_0, %edge_8 ]
  %p_7_1 = phi i32 [ %p_6_1, %edge_8 ]
  %p_7_2 = phi %hia.buffer [ %p_6_2, %edge_8 ]
  %p_7_3 = phi i1 [ %t33, %edge_8 ]
  %p_7_4 = phi %hia.buffer [ %t35, %edge_8 ]
  %p_7_5 = phi i8 [ 1, %edge_8 ]
  br label %edge_10
b8:
  %p_8_0 = phi i64 [ %p_6_0, %edge_9 ]
  %p_8_1 = phi i32 [ %p_6_1, %edge_9 ]
  %p_8_2 = phi %hia.buffer [ %p_6_2, %edge_9 ]
  %p_8_3 = phi i1 [ %t33, %edge_9 ]
  %p_8_4 = phi %hia.buffer [ %t35, %edge_9 ]
  %p_8_5 = phi i8 [ 1, %edge_9 ]
  %t36 = extractvalue %hia.buffer %p_8_4, 0
  %t37 = icmp ne ptr %t36, null
  br i1 %t37, label %drop_nonnull_38, label %drop_after_38
drop_nonnull_38:
  call void @free(ptr %t36) nobuiltin
  br label %drop_after_38
drop_after_38:
  %t39 = extractvalue %hia.buffer %p_8_2, 0
  %t40 = icmp ne ptr %t39, null
  br i1 %t40, label %drop_nonnull_41, label %drop_after_41
drop_nonnull_41:
  call void @free(ptr %t39) nobuiltin
  br label %drop_after_41
drop_after_41:
  %t42 = zext i8 %p_8_5 to i64
  %t43 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 1000, i64 %t42)
  %t44 = extractvalue { i64, i1 } %t43, 0
  %t45 = extractvalue { i64, i1 } %t43, 1
  %t46 = xor i1 %t45, true
  br i1 %t46, label %ok_47, label %trap_47
trap_47:
  call void @abort()
  unreachable
ok_47:
  ret i64 %t44
b9:
  %p_9_0 = phi i64 [ %p_7_0, %edge_10 ], [ %p_10_0, %edge_13 ]
  %p_9_1 = phi i32 [ %p_7_1, %edge_10 ], [ %p_10_1, %edge_13 ]
  %p_9_2 = phi %hia.buffer [ %p_7_2, %edge_10 ], [ %p_10_2, %edge_13 ]
  %p_9_3 = phi %hia.buffer [ %p_7_4, %edge_10 ], [ %p_10_3, %edge_13 ]
  %p_9_4 = phi i64 [ %p_7_0, %edge_10 ], [ %p_10_4, %edge_13 ]
  %p_9_5 = phi i64 [ 0, %edge_10 ], [ %t66, %edge_13 ]
  %t48 = icmp ult i64 %p_9_5, %p_9_4
  br i1 %t48, label %edge_11, label %edge_12
b10:
  %p_10_0 = phi i64 [ %p_9_0, %edge_11 ]
  %p_10_1 = phi i32 [ %p_9_1, %edge_11 ]
  %p_10_2 = phi %hia.buffer [ %p_9_2, %edge_11 ]
  %p_10_3 = phi %hia.buffer [ %p_9_3, %edge_11 ]
  %p_10_4 = phi i64 [ %p_9_4, %edge_11 ]
  %p_10_5 = phi i64 [ %p_9_5, %edge_11 ]
  %t49 = extractvalue %hia.buffer %p_10_2, 0
  %t50 = extractvalue %hia.buffer %p_10_2, 1
  %t51 = icmp ult i64 %p_10_5, %t50
  br i1 %t51, label %ok_52, label %trap_52
trap_52:
  call void @abort()
  unreachable
ok_52:
  %t53 = getelementptr i8, ptr %t49, i64 %p_10_5
  %t54 = load i8, ptr %t53, align 1
  %t55 = trunc i64 %p_10_5 to i32
  %t56 = xor i32 %p_10_1, 90
  %t57 = add i32 %t55, %t56
  %t58 = trunc i32 %t57 to i8
  %t59 = xor i8 %t54, %t58
  %t60 = extractvalue %hia.buffer %p_10_3, 0
  %t61 = extractvalue %hia.buffer %p_10_3, 1
  %t62 = icmp ult i64 %p_10_5, %t61
  br i1 %t62, label %ok_63, label %trap_63
trap_63:
  call void @abort()
  unreachable
ok_63:
  %t64 = getelementptr i8, ptr %t60, i64 %p_10_5
  store i8 %t59, ptr %t64, align 1
  %t65 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_10_5, i64 1)
  %t66 = extractvalue { i64, i1 } %t65, 0
  %t67 = extractvalue { i64, i1 } %t65, 1
  %t68 = xor i1 %t67, true
  br i1 %t68, label %ok_69, label %trap_69
trap_69:
  call void @abort()
  unreachable
ok_69:
  br label %edge_13
b11:
  %p_11_0 = phi i64 [ %p_9_0, %edge_12 ]
  %p_11_1 = phi i32 [ %p_9_1, %edge_12 ]
  %p_11_2 = phi %hia.buffer [ %p_9_2, %edge_12 ]
  %p_11_3 = phi %hia.buffer [ %p_9_3, %edge_12 ]
  %p_11_4 = phi i64 [ %p_9_4, %edge_12 ]
  %p_11_5 = phi i64 [ %p_9_5, %edge_12 ]
  br label %edge_14
b12:
  %p_12_0 = phi i64 [ %p_11_0, %edge_14 ], [ %p_13_0, %edge_17 ]
  %p_12_1 = phi i32 [ %p_11_1, %edge_14 ], [ %p_13_1, %edge_17 ]
  %p_12_2 = phi %hia.buffer [ %p_11_2, %edge_14 ], [ %p_13_2, %edge_17 ]
  %p_12_3 = phi %hia.buffer [ %p_11_3, %edge_14 ], [ %p_13_3, %edge_17 ]
  %p_12_4 = phi i64 [ 0, %edge_14 ], [ %t78, %edge_17 ]
  %p_12_5 = phi i64 [ %p_11_0, %edge_14 ], [ %p_13_5, %edge_17 ]
  %p_12_6 = phi i64 [ 0, %edge_14 ], [ %t80, %edge_17 ]
  %t70 = icmp ult i64 %p_12_6, %p_12_5
  br i1 %t70, label %edge_15, label %edge_16
b13:
  %p_13_0 = phi i64 [ %p_12_0, %edge_15 ]
  %p_13_1 = phi i32 [ %p_12_1, %edge_15 ]
  %p_13_2 = phi %hia.buffer [ %p_12_2, %edge_15 ]
  %p_13_3 = phi %hia.buffer [ %p_12_3, %edge_15 ]
  %p_13_4 = phi i64 [ %p_12_4, %edge_15 ]
  %p_13_5 = phi i64 [ %p_12_5, %edge_15 ]
  %p_13_6 = phi i64 [ %p_12_6, %edge_15 ]
  %t71 = extractvalue %hia.buffer %p_13_3, 0
  %t72 = extractvalue %hia.buffer %p_13_3, 1
  %t73 = icmp ult i64 %p_13_6, %t72
  br i1 %t73, label %ok_74, label %trap_74
trap_74:
  call void @abort()
  unreachable
ok_74:
  %t75 = getelementptr i8, ptr %t71, i64 %p_13_6
  %t76 = load i8, ptr %t75, align 1
  %t77 = zext i8 %t76 to i64
  %t78 = add i64 %p_13_4, %t77
  %t79 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_13_6, i64 1)
  %t80 = extractvalue { i64, i1 } %t79, 0
  %t81 = extractvalue { i64, i1 } %t79, 1
  %t82 = xor i1 %t81, true
  br i1 %t82, label %ok_83, label %trap_83
trap_83:
  call void @abort()
  unreachable
ok_83:
  br label %edge_17
b14:
  %p_14_0 = phi i64 [ %p_12_0, %edge_16 ]
  %p_14_1 = phi i32 [ %p_12_1, %edge_16 ]
  %p_14_2 = phi %hia.buffer [ %p_12_2, %edge_16 ]
  %p_14_3 = phi %hia.buffer [ %p_12_3, %edge_16 ]
  %p_14_4 = phi i64 [ %p_12_4, %edge_16 ]
  %p_14_5 = phi i64 [ %p_12_5, %edge_16 ]
  %p_14_6 = phi i64 [ %p_12_6, %edge_16 ]
  %t84 = extractvalue %hia.buffer %p_14_3, 0
  %t85 = icmp ne ptr %t84, null
  br i1 %t85, label %drop_nonnull_86, label %drop_after_86
drop_nonnull_86:
  call void @free(ptr %t84) nobuiltin
  br label %drop_after_86
drop_after_86:
  %t87 = extractvalue %hia.buffer %p_14_2, 0
  %t88 = icmp ne ptr %t87, null
  br i1 %t88, label %drop_nonnull_89, label %drop_after_89
drop_nonnull_89:
  call void @free(ptr %t87) nobuiltin
  br label %drop_after_89
drop_after_89:
  ret i64 %p_14_4
b15:
  %p_15_0 = phi i64 [ %p_0_0, %edge_1 ]
  %p_15_1 = phi i32 [ %p_0_1, %edge_1 ]
  %t90 = call %hia.alloc @__hia_allocate(i64 %p_15_0, i1 true)
  %t91 = extractvalue %hia.alloc %t90, 0
  %t92 = extractvalue %hia.alloc %t90, 1
  %t93 = select i1 %t92, i64 %p_15_0, i64 0
  %t94 = insertvalue %hia.buffer %t91, i64 %t93, 1
  br i1 %t92, label %edge_18, label %edge_19
b16:
  %p_16_0 = phi i64 [ %p_15_0, %edge_18 ]
  %p_16_1 = phi i32 [ %p_15_1, %edge_18 ]
  %p_16_2 = phi i1 [ %t92, %edge_18 ]
  %p_16_3 = phi %hia.buffer [ %t94, %edge_18 ]
  %p_16_4 = phi i8 [ 1, %edge_18 ]
  br label %edge_20
b17:
  %p_17_0 = phi i64 [ %p_15_0, %edge_19 ]
  %p_17_1 = phi i32 [ %p_15_1, %edge_19 ]
  %p_17_2 = phi i1 [ %t92, %edge_19 ]
  %p_17_3 = phi %hia.buffer [ %t94, %edge_19 ]
  %p_17_4 = phi i8 [ 1, %edge_19 ]
  %t95 = extractvalue %hia.buffer %p_17_3, 0
  %t96 = icmp ne ptr %t95, null
  br i1 %t96, label %drop_nonnull_97, label %drop_after_97
drop_nonnull_97:
  call void @free(ptr %t95) nobuiltin
  br label %drop_after_97
drop_after_97:
  %t98 = zext i8 %p_17_4 to i64
  %t99 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 1000, i64 %t98)
  %t100 = extractvalue { i64, i1 } %t99, 0
  %t101 = extractvalue { i64, i1 } %t99, 1
  %t102 = xor i1 %t101, true
  br i1 %t102, label %ok_103, label %trap_103
trap_103:
  call void @abort()
  unreachable
ok_103:
  ret i64 %t100
b18:
  %p_18_0 = phi i64 [ %p_16_0, %edge_20 ], [ %p_19_0, %edge_23 ]
  %p_18_1 = phi i32 [ %p_16_1, %edge_20 ], [ %p_19_1, %edge_23 ]
  %p_18_2 = phi %hia.buffer [ %p_16_3, %edge_20 ], [ %p_19_2, %edge_23 ]
  %p_18_3 = phi i64 [ %p_16_0, %edge_20 ], [ %p_19_3, %edge_23 ]
  %p_18_4 = phi i64 [ 0, %edge_20 ], [ %t115, %edge_23 ]
  %t104 = icmp ult i64 %p_18_4, %p_18_3
  br i1 %t104, label %edge_21, label %edge_22
b19:
  %p_19_0 = phi i64 [ %p_18_0, %edge_21 ]
  %p_19_1 = phi i32 [ %p_18_1, %edge_21 ]
  %p_19_2 = phi %hia.buffer [ %p_18_2, %edge_21 ]
  %p_19_3 = phi i64 [ %p_18_3, %edge_21 ]
  %p_19_4 = phi i64 [ %p_18_4, %edge_21 ]
  %t105 = trunc i64 %p_19_4 to i32
  %t106 = mul i32 %t105, 13
  %t107 = add i32 %t106, %p_19_1
  %t108 = trunc i32 %t107 to i8
  %t109 = extractvalue %hia.buffer %p_19_2, 0
  %t110 = extractvalue %hia.buffer %p_19_2, 1
  %t111 = icmp ult i64 %p_19_4, %t110
  br i1 %t111, label %ok_112, label %trap_112
trap_112:
  call void @abort()
  unreachable
ok_112:
  %t113 = getelementptr i8, ptr %t109, i64 %p_19_4
  store i8 %t108, ptr %t113, align 1
  %t114 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_19_4, i64 1)
  %t115 = extractvalue { i64, i1 } %t114, 0
  %t116 = extractvalue { i64, i1 } %t114, 1
  %t117 = xor i1 %t116, true
  br i1 %t117, label %ok_118, label %trap_118
trap_118:
  call void @abort()
  unreachable
ok_118:
  br label %edge_23
b20:
  %p_20_0 = phi i64 [ %p_18_0, %edge_22 ]
  %p_20_1 = phi i32 [ %p_18_1, %edge_22 ]
  %p_20_2 = phi %hia.buffer [ %p_18_2, %edge_22 ]
  %p_20_3 = phi i64 [ %p_18_3, %edge_22 ]
  %p_20_4 = phi i64 [ %p_18_4, %edge_22 ]
  %t119 = call %hia.alloc @__hia_allocate(i64 %p_20_0, i1 true)
  %t120 = extractvalue %hia.alloc %t119, 0
  %t121 = extractvalue %hia.alloc %t119, 1
  %t122 = select i1 %t121, i64 %p_20_0, i64 0
  %t123 = insertvalue %hia.buffer %t120, i64 %t122, 1
  br i1 %t121, label %edge_24, label %edge_25
b21:
  %p_21_0 = phi i64 [ %p_20_0, %edge_24 ]
  %p_21_1 = phi i32 [ %p_20_1, %edge_24 ]
  %p_21_2 = phi %hia.buffer [ %p_20_2, %edge_24 ]
  %p_21_3 = phi i1 [ %t121, %edge_24 ]
  %p_21_4 = phi %hia.buffer [ %t123, %edge_24 ]
  %p_21_5 = phi i8 [ 1, %edge_24 ]
  br label %edge_26
b22:
  %p_22_0 = phi i64 [ %p_20_0, %edge_25 ]
  %p_22_1 = phi i32 [ %p_20_1, %edge_25 ]
  %p_22_2 = phi %hia.buffer [ %p_20_2, %edge_25 ]
  %p_22_3 = phi i1 [ %t121, %edge_25 ]
  %p_22_4 = phi %hia.buffer [ %t123, %edge_25 ]
  %p_22_5 = phi i8 [ 1, %edge_25 ]
  %t124 = extractvalue %hia.buffer %p_22_4, 0
  %t125 = icmp ne ptr %t124, null
  br i1 %t125, label %drop_nonnull_126, label %drop_after_126
drop_nonnull_126:
  call void @free(ptr %t124) nobuiltin
  br label %drop_after_126
drop_after_126:
  %t127 = extractvalue %hia.buffer %p_22_2, 0
  %t128 = icmp ne ptr %t127, null
  br i1 %t128, label %drop_nonnull_129, label %drop_after_129
drop_nonnull_129:
  call void @free(ptr %t127) nobuiltin
  br label %drop_after_129
drop_after_129:
  %t130 = zext i8 %p_22_5 to i64
  %t131 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 1000, i64 %t130)
  %t132 = extractvalue { i64, i1 } %t131, 0
  %t133 = extractvalue { i64, i1 } %t131, 1
  %t134 = xor i1 %t133, true
  br i1 %t134, label %ok_135, label %trap_135
trap_135:
  call void @abort()
  unreachable
ok_135:
  ret i64 %t132
b23:
  %p_23_0 = phi i64 [ %p_21_0, %edge_26 ], [ %p_24_0, %edge_29 ]
  %p_23_1 = phi i32 [ %p_21_1, %edge_26 ], [ %p_24_1, %edge_29 ]
  %p_23_2 = phi %hia.buffer [ %p_21_2, %edge_26 ], [ %p_24_2, %edge_29 ]
  %p_23_3 = phi %hia.buffer [ %p_21_4, %edge_26 ], [ %p_24_3, %edge_29 ]
  %p_23_4 = phi i64 [ %p_21_0, %edge_26 ], [ %p_24_4, %edge_29 ]
  %p_23_5 = phi i64 [ 0, %edge_26 ], [ %t154, %edge_29 ]
  %t136 = icmp ult i64 %p_23_5, %p_23_4
  br i1 %t136, label %edge_27, label %edge_28
b24:
  %p_24_0 = phi i64 [ %p_23_0, %edge_27 ]
  %p_24_1 = phi i32 [ %p_23_1, %edge_27 ]
  %p_24_2 = phi %hia.buffer [ %p_23_2, %edge_27 ]
  %p_24_3 = phi %hia.buffer [ %p_23_3, %edge_27 ]
  %p_24_4 = phi i64 [ %p_23_4, %edge_27 ]
  %p_24_5 = phi i64 [ %p_23_5, %edge_27 ]
  %t137 = extractvalue %hia.buffer %p_24_2, 0
  %t138 = extractvalue %hia.buffer %p_24_2, 1
  %t139 = icmp ult i64 %p_24_5, %t138
  br i1 %t139, label %ok_140, label %trap_140
trap_140:
  call void @abort()
  unreachable
ok_140:
  %t141 = getelementptr i8, ptr %t137, i64 %p_24_5
  %t142 = load i8, ptr %t141, align 1
  %t143 = trunc i64 %p_24_5 to i32
  %t144 = xor i32 %p_24_1, 90
  %t145 = add i32 %t143, %t144
  %t146 = trunc i32 %t145 to i8
  %t147 = xor i8 %t142, %t146
  %t148 = extractvalue %hia.buffer %p_24_3, 0
  %t149 = extractvalue %hia.buffer %p_24_3, 1
  %t150 = icmp ult i64 %p_24_5, %t149
  br i1 %t150, label %ok_151, label %trap_151
trap_151:
  call void @abort()
  unreachable
ok_151:
  %t152 = getelementptr i8, ptr %t148, i64 %p_24_5
  store i8 %t147, ptr %t152, align 1
  %t153 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_24_5, i64 1)
  %t154 = extractvalue { i64, i1 } %t153, 0
  %t155 = extractvalue { i64, i1 } %t153, 1
  %t156 = xor i1 %t155, true
  br i1 %t156, label %ok_157, label %trap_157
trap_157:
  call void @abort()
  unreachable
ok_157:
  br label %edge_29
b25:
  %p_25_0 = phi i64 [ %p_23_0, %edge_28 ]
  %p_25_1 = phi i32 [ %p_23_1, %edge_28 ]
  %p_25_2 = phi %hia.buffer [ %p_23_2, %edge_28 ]
  %p_25_3 = phi %hia.buffer [ %p_23_3, %edge_28 ]
  %p_25_4 = phi i64 [ %p_23_4, %edge_28 ]
  %p_25_5 = phi i64 [ %p_23_5, %edge_28 ]
  br label %edge_30
b26:
  %p_26_0 = phi i64 [ %p_25_0, %edge_30 ], [ %p_27_0, %edge_33 ]
  %p_26_1 = phi i32 [ %p_25_1, %edge_30 ], [ %p_27_1, %edge_33 ]
  %p_26_2 = phi %hia.buffer [ %p_25_2, %edge_30 ], [ %p_27_2, %edge_33 ]
  %p_26_3 = phi %hia.buffer [ %p_25_3, %edge_30 ], [ %p_27_3, %edge_33 ]
  %p_26_4 = phi i64 [ 0, %edge_30 ], [ %t167, %edge_33 ]
  %p_26_5 = phi i64 [ %p_25_0, %edge_30 ], [ %p_27_5, %edge_33 ]
  %p_26_6 = phi i64 [ 0, %edge_30 ], [ %t172, %edge_33 ]
  %t158 = icmp ult i64 %p_26_6, %p_26_5
  br i1 %t158, label %edge_31, label %edge_32
b27:
  %p_27_0 = phi i64 [ %p_26_0, %edge_31 ]
  %p_27_1 = phi i32 [ %p_26_1, %edge_31 ]
  %p_27_2 = phi %hia.buffer [ %p_26_2, %edge_31 ]
  %p_27_3 = phi %hia.buffer [ %p_26_3, %edge_31 ]
  %p_27_4 = phi i64 [ %p_26_4, %edge_31 ]
  %p_27_5 = phi i64 [ %p_26_5, %edge_31 ]
  %p_27_6 = phi i64 [ %p_26_6, %edge_31 ]
  %t159 = extractvalue %hia.buffer %p_27_3, 0
  %t160 = extractvalue %hia.buffer %p_27_3, 1
  %t161 = icmp ult i64 %p_27_6, %t160
  br i1 %t161, label %ok_162, label %trap_162
trap_162:
  call void @abort()
  unreachable
ok_162:
  %t163 = getelementptr i8, ptr %t159, i64 %p_27_6
  %t164 = load i8, ptr %t163, align 1
  %t165 = zext i8 %t164 to i64
  %t166 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_27_4, i64 %t165)
  %t167 = extractvalue { i64, i1 } %t166, 0
  %t168 = extractvalue { i64, i1 } %t166, 1
  %t169 = xor i1 %t168, true
  br i1 %t169, label %ok_170, label %trap_170
trap_170:
  call void @abort()
  unreachable
ok_170:
  %t171 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_27_6, i64 1)
  %t172 = extractvalue { i64, i1 } %t171, 0
  %t173 = extractvalue { i64, i1 } %t171, 1
  %t174 = xor i1 %t173, true
  br i1 %t174, label %ok_175, label %trap_175
trap_175:
  call void @abort()
  unreachable
ok_175:
  br label %edge_33
b28:
  %p_28_0 = phi i64 [ %p_26_0, %edge_32 ]
  %p_28_1 = phi i32 [ %p_26_1, %edge_32 ]
  %p_28_2 = phi %hia.buffer [ %p_26_2, %edge_32 ]
  %p_28_3 = phi %hia.buffer [ %p_26_3, %edge_32 ]
  %p_28_4 = phi i64 [ %p_26_4, %edge_32 ]
  %p_28_5 = phi i64 [ %p_26_5, %edge_32 ]
  %p_28_6 = phi i64 [ %p_26_6, %edge_32 ]
  %t176 = extractvalue %hia.buffer %p_28_3, 0
  %t177 = icmp ne ptr %t176, null
  br i1 %t177, label %drop_nonnull_178, label %drop_after_178
drop_nonnull_178:
  call void @free(ptr %t176) nobuiltin
  br label %drop_after_178
drop_after_178:
  %t179 = extractvalue %hia.buffer %p_28_2, 0
  %t180 = icmp ne ptr %t179, null
  br i1 %t180, label %drop_nonnull_181, label %drop_after_181
drop_nonnull_181:
  call void @free(ptr %t179) nobuiltin
  br label %drop_after_181
drop_after_181:
  ret i64 %p_28_4
edge_0:
  br label %b1
edge_1:
  br label %b15
edge_2:
  br label %b2
edge_3:
  br label %b3
edge_4:
  br label %b4
edge_5:
  br label %b5
edge_6:
  br label %b6
edge_7:
  br label %b4
edge_8:
  br label %b7
edge_9:
  br label %b8
edge_10:
  br label %b9
edge_11:
  br label %b10
edge_12:
  br label %b11
edge_13:
  br label %b9
edge_14:
  br label %b12
edge_15:
  br label %b13
edge_16:
  br label %b14
edge_17:
  br label %b12
edge_18:
  br label %b16
edge_19:
  br label %b17
edge_20:
  br label %b18
edge_21:
  br label %b19
edge_22:
  br label %b20
edge_23:
  br label %b18
edge_24:
  br label %b21
edge_25:
  br label %b22
edge_26:
  br label %b23
edge_27:
  br label %b24
edge_28:
  br label %b25
edge_29:
  br label %b23
edge_30:
  br label %b26
edge_31:
  br label %b27
edge_32:
  br label %b28
edge_33:
  br label %b26
}

define i64 @full_lifecycle(i64 %a0, i32 %a1) {
entry:
  %result = call i64 @__hia_fn_0(i64 %a0, i32 %a1)
  ret i64 %result
}

define i64 @packet_xor(i64 %a0, i32 %a1) {
entry:
  %result = call i64 @__hia_fn_1(i64 %a0, i32 %a1)
  ret i64 %result
}
