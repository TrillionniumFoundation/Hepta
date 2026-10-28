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
  %p_4_4 = phi i64 [ 0, %edge_4 ], [ %t28, %edge_7 ]
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
  %t19 = trunc i64 %p_5_4 to i8
  %t20 = trunc i32 %p_5_1 to i8
  %t21 = add i8 %t19, %t20
  %t22 = extractvalue %hia.buffer %p_5_2, 0
  %t23 = extractvalue %hia.buffer %p_5_2, 1
  %t24 = icmp ult i64 %p_5_4, %t23
  br i1 %t24, label %ok_25, label %trap_25
trap_25:
  call void @abort()
  unreachable
ok_25:
  %t26 = getelementptr i8, ptr %t22, i64 %p_5_4
  store i8 %t21, ptr %t26, align 1
  %t27 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_5_4, i64 1)
  %t28 = extractvalue { i64, i1 } %t27, 0
  %t29 = extractvalue { i64, i1 } %t27, 1
  %t30 = xor i1 %t29, true
  br i1 %t30, label %ok_31, label %trap_31
trap_31:
  call void @abort()
  unreachable
ok_31:
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
  %p_7_3 = phi i64 [ 0, %edge_8 ], [ %t40, %edge_11 ]
  %p_7_4 = phi i64 [ %p_6_0, %edge_8 ], [ %p_8_4, %edge_11 ]
  %p_7_5 = phi i64 [ 0, %edge_8 ], [ %t42, %edge_11 ]
  %t32 = icmp ult i64 %p_7_5, %p_7_4
  br i1 %t32, label %edge_9, label %edge_10
b8:
  %p_8_0 = phi i64 [ %p_7_0, %edge_9 ]
  %p_8_1 = phi i32 [ %p_7_1, %edge_9 ]
  %p_8_2 = phi %hia.buffer [ %p_7_2, %edge_9 ]
  %p_8_3 = phi i64 [ %p_7_3, %edge_9 ]
  %p_8_4 = phi i64 [ %p_7_4, %edge_9 ]
  %p_8_5 = phi i64 [ %p_7_5, %edge_9 ]
  %t33 = extractvalue %hia.buffer %p_8_2, 0
  %t34 = extractvalue %hia.buffer %p_8_2, 1
  %t35 = icmp ult i64 %p_8_5, %t34
  br i1 %t35, label %ok_36, label %trap_36
trap_36:
  call void @abort()
  unreachable
ok_36:
  %t37 = getelementptr i8, ptr %t33, i64 %p_8_5
  %t38 = load i8, ptr %t37, align 1
  %t39 = zext i8 %t38 to i64
  %t40 = add i64 %p_8_3, %t39
  %t41 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_8_5, i64 1)
  %t42 = extractvalue { i64, i1 } %t41, 0
  %t43 = extractvalue { i64, i1 } %t41, 1
  %t44 = xor i1 %t43, true
  br i1 %t44, label %ok_45, label %trap_45
trap_45:
  call void @abort()
  unreachable
ok_45:
  br label %edge_11
b9:
  %p_9_0 = phi i64 [ %p_7_0, %edge_10 ]
  %p_9_1 = phi i32 [ %p_7_1, %edge_10 ]
  %p_9_2 = phi %hia.buffer [ %p_7_2, %edge_10 ]
  %p_9_3 = phi i64 [ %p_7_3, %edge_10 ]
  %p_9_4 = phi i64 [ %p_7_4, %edge_10 ]
  %p_9_5 = phi i64 [ %p_7_5, %edge_10 ]
  %t46 = extractvalue %hia.buffer %p_9_2, 0
  %t47 = icmp ne ptr %t46, null
  br i1 %t47, label %drop_nonnull_48, label %drop_after_48
drop_nonnull_48:
  call void @free(ptr %t46) nobuiltin
  br label %drop_after_48
drop_after_48:
  ret i64 %p_9_3
b10:
  %p_10_0 = phi i64 [ %p_0_0, %edge_1 ]
  %p_10_1 = phi i32 [ %p_0_1, %edge_1 ]
  %t49 = call %hia.alloc @__hia_allocate(i64 %p_10_0, i1 true)
  %t50 = extractvalue %hia.alloc %t49, 0
  %t51 = extractvalue %hia.alloc %t49, 1
  %t52 = select i1 %t51, i64 %p_10_0, i64 0
  %t53 = insertvalue %hia.buffer %t50, i64 %t52, 1
  br i1 %t51, label %edge_12, label %edge_13
b11:
  %p_11_0 = phi i64 [ %p_10_0, %edge_12 ]
  %p_11_1 = phi i32 [ %p_10_1, %edge_12 ]
  %p_11_2 = phi i1 [ %t51, %edge_12 ]
  %p_11_3 = phi %hia.buffer [ %t53, %edge_12 ]
  %p_11_4 = phi i8 [ 1, %edge_12 ]
  br label %edge_14
b12:
  %p_12_0 = phi i64 [ %p_10_0, %edge_13 ]
  %p_12_1 = phi i32 [ %p_10_1, %edge_13 ]
  %p_12_2 = phi i1 [ %t51, %edge_13 ]
  %p_12_3 = phi %hia.buffer [ %t53, %edge_13 ]
  %p_12_4 = phi i8 [ 1, %edge_13 ]
  %t54 = extractvalue %hia.buffer %p_12_3, 0
  %t55 = icmp ne ptr %t54, null
  br i1 %t55, label %drop_nonnull_56, label %drop_after_56
drop_nonnull_56:
  call void @free(ptr %t54) nobuiltin
  br label %drop_after_56
drop_after_56:
  %t57 = zext i8 %p_12_4 to i64
  %t58 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 1000, i64 %t57)
  %t59 = extractvalue { i64, i1 } %t58, 0
  %t60 = extractvalue { i64, i1 } %t58, 1
  %t61 = xor i1 %t60, true
  br i1 %t61, label %ok_62, label %trap_62
trap_62:
  call void @abort()
  unreachable
ok_62:
  ret i64 %t59
b13:
  %p_13_0 = phi i64 [ %p_11_0, %edge_14 ], [ %p_14_0, %edge_17 ]
  %p_13_1 = phi i32 [ %p_11_1, %edge_14 ], [ %p_14_1, %edge_17 ]
  %p_13_2 = phi %hia.buffer [ %p_11_3, %edge_14 ], [ %p_14_2, %edge_17 ]
  %p_13_3 = phi i64 [ %p_11_0, %edge_14 ], [ %p_14_3, %edge_17 ]
  %p_13_4 = phi i64 [ 0, %edge_14 ], [ %t75, %edge_17 ]
  %t63 = icmp ult i64 %p_13_4, %p_13_3
  br i1 %t63, label %edge_15, label %edge_16
b14:
  %p_14_0 = phi i64 [ %p_13_0, %edge_15 ]
  %p_14_1 = phi i32 [ %p_13_1, %edge_15 ]
  %p_14_2 = phi %hia.buffer [ %p_13_2, %edge_15 ]
  %p_14_3 = phi i64 [ %p_13_3, %edge_15 ]
  %p_14_4 = phi i64 [ %p_13_4, %edge_15 ]
  %t64 = trunc i64 %p_14_4 to i32
  %t65 = add i32 %t64, %p_14_1
  %t66 = trunc i64 %p_14_4 to i8
  %t67 = trunc i32 %p_14_1 to i8
  %t68 = add i8 %t66, %t67
  %t69 = extractvalue %hia.buffer %p_14_2, 0
  %t70 = extractvalue %hia.buffer %p_14_2, 1
  %t71 = icmp ult i64 %p_14_4, %t70
  br i1 %t71, label %ok_72, label %trap_72
trap_72:
  call void @abort()
  unreachable
ok_72:
  %t73 = getelementptr i8, ptr %t69, i64 %p_14_4
  store i8 %t68, ptr %t73, align 1
  %t74 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_14_4, i64 1)
  %t75 = extractvalue { i64, i1 } %t74, 0
  %t76 = extractvalue { i64, i1 } %t74, 1
  %t77 = xor i1 %t76, true
  br i1 %t77, label %ok_78, label %trap_78
trap_78:
  call void @abort()
  unreachable
ok_78:
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
  %p_16_3 = phi i64 [ 0, %edge_18 ], [ %t88, %edge_21 ]
  %p_16_4 = phi i64 [ %p_15_0, %edge_18 ], [ %p_17_4, %edge_21 ]
  %p_16_5 = phi i64 [ 0, %edge_18 ], [ %t93, %edge_21 ]
  %t79 = icmp ult i64 %p_16_5, %p_16_4
  br i1 %t79, label %edge_19, label %edge_20
b17:
  %p_17_0 = phi i64 [ %p_16_0, %edge_19 ]
  %p_17_1 = phi i32 [ %p_16_1, %edge_19 ]
  %p_17_2 = phi %hia.buffer [ %p_16_2, %edge_19 ]
  %p_17_3 = phi i64 [ %p_16_3, %edge_19 ]
  %p_17_4 = phi i64 [ %p_16_4, %edge_19 ]
  %p_17_5 = phi i64 [ %p_16_5, %edge_19 ]
  %t80 = extractvalue %hia.buffer %p_17_2, 0
  %t81 = extractvalue %hia.buffer %p_17_2, 1
  %t82 = icmp ult i64 %p_17_5, %t81
  br i1 %t82, label %ok_83, label %trap_83
trap_83:
  call void @abort()
  unreachable
ok_83:
  %t84 = getelementptr i8, ptr %t80, i64 %p_17_5
  %t85 = load i8, ptr %t84, align 1
  %t86 = zext i8 %t85 to i64
  %t87 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_17_3, i64 %t86)
  %t88 = extractvalue { i64, i1 } %t87, 0
  %t89 = extractvalue { i64, i1 } %t87, 1
  %t90 = xor i1 %t89, true
  br i1 %t90, label %ok_91, label %trap_91
trap_91:
  call void @abort()
  unreachable
ok_91:
  %t92 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_17_5, i64 1)
  %t93 = extractvalue { i64, i1 } %t92, 0
  %t94 = extractvalue { i64, i1 } %t92, 1
  %t95 = xor i1 %t94, true
  br i1 %t95, label %ok_96, label %trap_96
trap_96:
  call void @abort()
  unreachable
ok_96:
  br label %edge_21
b18:
  %p_18_0 = phi i64 [ %p_16_0, %edge_20 ]
  %p_18_1 = phi i32 [ %p_16_1, %edge_20 ]
  %p_18_2 = phi %hia.buffer [ %p_16_2, %edge_20 ]
  %p_18_3 = phi i64 [ %p_16_3, %edge_20 ]
  %p_18_4 = phi i64 [ %p_16_4, %edge_20 ]
  %p_18_5 = phi i64 [ %p_16_5, %edge_20 ]
  %t97 = extractvalue %hia.buffer %p_18_2, 0
  %t98 = icmp ne ptr %t97, null
  br i1 %t98, label %drop_nonnull_99, label %drop_after_99
drop_nonnull_99:
  call void @free(ptr %t97) nobuiltin
  br label %drop_after_99
drop_after_99:
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
  %p_4_4 = phi i64 [ 0, %edge_4 ], [ %t30, %edge_7 ]
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
  %t20 = trunc i64 %p_5_4 to i8
  %t21 = mul i8 %t20, 13
  %t22 = trunc i32 %p_5_1 to i8
  %t23 = add i8 %t21, %t22
  %t24 = extractvalue %hia.buffer %p_5_2, 0
  %t25 = extractvalue %hia.buffer %p_5_2, 1
  %t26 = icmp ult i64 %p_5_4, %t25
  br i1 %t26, label %ok_27, label %trap_27
trap_27:
  call void @abort()
  unreachable
ok_27:
  %t28 = getelementptr i8, ptr %t24, i64 %p_5_4
  store i8 %t23, ptr %t28, align 1
  %t29 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_5_4, i64 1)
  %t30 = extractvalue { i64, i1 } %t29, 0
  %t31 = extractvalue { i64, i1 } %t29, 1
  %t32 = xor i1 %t31, true
  br i1 %t32, label %ok_33, label %trap_33
trap_33:
  call void @abort()
  unreachable
ok_33:
  br label %edge_7
b6:
  %p_6_0 = phi i64 [ %p_4_0, %edge_6 ]
  %p_6_1 = phi i32 [ %p_4_1, %edge_6 ]
  %p_6_2 = phi %hia.buffer [ %p_4_2, %edge_6 ]
  %p_6_3 = phi i64 [ %p_4_3, %edge_6 ]
  %p_6_4 = phi i64 [ %p_4_4, %edge_6 ]
  %t34 = call %hia.alloc @__hia_allocate(i64 %p_6_0, i1 true)
  %t35 = extractvalue %hia.alloc %t34, 0
  %t36 = extractvalue %hia.alloc %t34, 1
  %t37 = select i1 %t36, i64 %p_6_0, i64 0
  %t38 = insertvalue %hia.buffer %t35, i64 %t37, 1
  br i1 %t36, label %edge_8, label %edge_9
b7:
  %p_7_0 = phi i64 [ %p_6_0, %edge_8 ]
  %p_7_1 = phi i32 [ %p_6_1, %edge_8 ]
  %p_7_2 = phi %hia.buffer [ %p_6_2, %edge_8 ]
  %p_7_3 = phi i1 [ %t36, %edge_8 ]
  %p_7_4 = phi %hia.buffer [ %t38, %edge_8 ]
  %p_7_5 = phi i8 [ 1, %edge_8 ]
  br label %edge_10
b8:
  %p_8_0 = phi i64 [ %p_6_0, %edge_9 ]
  %p_8_1 = phi i32 [ %p_6_1, %edge_9 ]
  %p_8_2 = phi %hia.buffer [ %p_6_2, %edge_9 ]
  %p_8_3 = phi i1 [ %t36, %edge_9 ]
  %p_8_4 = phi %hia.buffer [ %t38, %edge_9 ]
  %p_8_5 = phi i8 [ 1, %edge_9 ]
  %t39 = extractvalue %hia.buffer %p_8_4, 0
  %t40 = icmp ne ptr %t39, null
  br i1 %t40, label %drop_nonnull_41, label %drop_after_41
drop_nonnull_41:
  call void @free(ptr %t39) nobuiltin
  br label %drop_after_41
drop_after_41:
  %t42 = extractvalue %hia.buffer %p_8_2, 0
  %t43 = icmp ne ptr %t42, null
  br i1 %t43, label %drop_nonnull_44, label %drop_after_44
drop_nonnull_44:
  call void @free(ptr %t42) nobuiltin
  br label %drop_after_44
drop_after_44:
  %t45 = zext i8 %p_8_5 to i64
  %t46 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 1000, i64 %t45)
  %t47 = extractvalue { i64, i1 } %t46, 0
  %t48 = extractvalue { i64, i1 } %t46, 1
  %t49 = xor i1 %t48, true
  br i1 %t49, label %ok_50, label %trap_50
trap_50:
  call void @abort()
  unreachable
ok_50:
  ret i64 %t47
b9:
  %p_9_0 = phi i64 [ %p_7_0, %edge_10 ], [ %p_10_0, %edge_13 ]
  %p_9_1 = phi i32 [ %p_7_1, %edge_10 ], [ %p_10_1, %edge_13 ]
  %p_9_2 = phi %hia.buffer [ %p_7_2, %edge_10 ], [ %p_10_2, %edge_13 ]
  %p_9_3 = phi %hia.buffer [ %p_7_4, %edge_10 ], [ %p_10_3, %edge_13 ]
  %p_9_4 = phi i64 [ %p_7_0, %edge_10 ], [ %p_10_4, %edge_13 ]
  %p_9_5 = phi i64 [ 0, %edge_10 ], [ %t72, %edge_13 ]
  %t51 = icmp ult i64 %p_9_5, %p_9_4
  br i1 %t51, label %edge_11, label %edge_12
b10:
  %p_10_0 = phi i64 [ %p_9_0, %edge_11 ]
  %p_10_1 = phi i32 [ %p_9_1, %edge_11 ]
  %p_10_2 = phi %hia.buffer [ %p_9_2, %edge_11 ]
  %p_10_3 = phi %hia.buffer [ %p_9_3, %edge_11 ]
  %p_10_4 = phi i64 [ %p_9_4, %edge_11 ]
  %p_10_5 = phi i64 [ %p_9_5, %edge_11 ]
  %t52 = extractvalue %hia.buffer %p_10_2, 0
  %t53 = extractvalue %hia.buffer %p_10_2, 1
  %t54 = icmp ult i64 %p_10_5, %t53
  br i1 %t54, label %ok_55, label %trap_55
trap_55:
  call void @abort()
  unreachable
ok_55:
  %t56 = getelementptr i8, ptr %t52, i64 %p_10_5
  %t57 = load i8, ptr %t56, align 1
  %t58 = trunc i64 %p_10_5 to i32
  %t59 = xor i32 %p_10_1, 90
  %t60 = add i32 %t58, %t59
  %t61 = trunc i64 %p_10_5 to i8
  %t62 = trunc i32 %p_10_1 to i8
  %t63 = xor i8 %t62, 90
  %t64 = add i8 %t61, %t63
  %t65 = xor i8 %t57, %t64
  %t66 = extractvalue %hia.buffer %p_10_3, 0
  %t67 = extractvalue %hia.buffer %p_10_3, 1
  %t68 = icmp ult i64 %p_10_5, %t67
  br i1 %t68, label %ok_69, label %trap_69
trap_69:
  call void @abort()
  unreachable
ok_69:
  %t70 = getelementptr i8, ptr %t66, i64 %p_10_5
  store i8 %t65, ptr %t70, align 1
  %t71 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_10_5, i64 1)
  %t72 = extractvalue { i64, i1 } %t71, 0
  %t73 = extractvalue { i64, i1 } %t71, 1
  %t74 = xor i1 %t73, true
  br i1 %t74, label %ok_75, label %trap_75
trap_75:
  call void @abort()
  unreachable
ok_75:
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
  %p_12_4 = phi i64 [ 0, %edge_14 ], [ %t84, %edge_17 ]
  %p_12_5 = phi i64 [ %p_11_0, %edge_14 ], [ %p_13_5, %edge_17 ]
  %p_12_6 = phi i64 [ 0, %edge_14 ], [ %t86, %edge_17 ]
  %t76 = icmp ult i64 %p_12_6, %p_12_5
  br i1 %t76, label %edge_15, label %edge_16
b13:
  %p_13_0 = phi i64 [ %p_12_0, %edge_15 ]
  %p_13_1 = phi i32 [ %p_12_1, %edge_15 ]
  %p_13_2 = phi %hia.buffer [ %p_12_2, %edge_15 ]
  %p_13_3 = phi %hia.buffer [ %p_12_3, %edge_15 ]
  %p_13_4 = phi i64 [ %p_12_4, %edge_15 ]
  %p_13_5 = phi i64 [ %p_12_5, %edge_15 ]
  %p_13_6 = phi i64 [ %p_12_6, %edge_15 ]
  %t77 = extractvalue %hia.buffer %p_13_3, 0
  %t78 = extractvalue %hia.buffer %p_13_3, 1
  %t79 = icmp ult i64 %p_13_6, %t78
  br i1 %t79, label %ok_80, label %trap_80
trap_80:
  call void @abort()
  unreachable
ok_80:
  %t81 = getelementptr i8, ptr %t77, i64 %p_13_6
  %t82 = load i8, ptr %t81, align 1
  %t83 = zext i8 %t82 to i64
  %t84 = add i64 %p_13_4, %t83
  %t85 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_13_6, i64 1)
  %t86 = extractvalue { i64, i1 } %t85, 0
  %t87 = extractvalue { i64, i1 } %t85, 1
  %t88 = xor i1 %t87, true
  br i1 %t88, label %ok_89, label %trap_89
trap_89:
  call void @abort()
  unreachable
ok_89:
  br label %edge_17
b14:
  %p_14_0 = phi i64 [ %p_12_0, %edge_16 ]
  %p_14_1 = phi i32 [ %p_12_1, %edge_16 ]
  %p_14_2 = phi %hia.buffer [ %p_12_2, %edge_16 ]
  %p_14_3 = phi %hia.buffer [ %p_12_3, %edge_16 ]
  %p_14_4 = phi i64 [ %p_12_4, %edge_16 ]
  %p_14_5 = phi i64 [ %p_12_5, %edge_16 ]
  %p_14_6 = phi i64 [ %p_12_6, %edge_16 ]
  %t90 = extractvalue %hia.buffer %p_14_3, 0
  %t91 = icmp ne ptr %t90, null
  br i1 %t91, label %drop_nonnull_92, label %drop_after_92
drop_nonnull_92:
  call void @free(ptr %t90) nobuiltin
  br label %drop_after_92
drop_after_92:
  %t93 = extractvalue %hia.buffer %p_14_2, 0
  %t94 = icmp ne ptr %t93, null
  br i1 %t94, label %drop_nonnull_95, label %drop_after_95
drop_nonnull_95:
  call void @free(ptr %t93) nobuiltin
  br label %drop_after_95
drop_after_95:
  ret i64 %p_14_4
b15:
  %p_15_0 = phi i64 [ %p_0_0, %edge_1 ]
  %p_15_1 = phi i32 [ %p_0_1, %edge_1 ]
  %t96 = call %hia.alloc @__hia_allocate(i64 %p_15_0, i1 true)
  %t97 = extractvalue %hia.alloc %t96, 0
  %t98 = extractvalue %hia.alloc %t96, 1
  %t99 = select i1 %t98, i64 %p_15_0, i64 0
  %t100 = insertvalue %hia.buffer %t97, i64 %t99, 1
  br i1 %t98, label %edge_18, label %edge_19
b16:
  %p_16_0 = phi i64 [ %p_15_0, %edge_18 ]
  %p_16_1 = phi i32 [ %p_15_1, %edge_18 ]
  %p_16_2 = phi i1 [ %t98, %edge_18 ]
  %p_16_3 = phi %hia.buffer [ %t100, %edge_18 ]
  %p_16_4 = phi i8 [ 1, %edge_18 ]
  br label %edge_20
b17:
  %p_17_0 = phi i64 [ %p_15_0, %edge_19 ]
  %p_17_1 = phi i32 [ %p_15_1, %edge_19 ]
  %p_17_2 = phi i1 [ %t98, %edge_19 ]
  %p_17_3 = phi %hia.buffer [ %t100, %edge_19 ]
  %p_17_4 = phi i8 [ 1, %edge_19 ]
  %t101 = extractvalue %hia.buffer %p_17_3, 0
  %t102 = icmp ne ptr %t101, null
  br i1 %t102, label %drop_nonnull_103, label %drop_after_103
drop_nonnull_103:
  call void @free(ptr %t101) nobuiltin
  br label %drop_after_103
drop_after_103:
  %t104 = zext i8 %p_17_4 to i64
  %t105 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 1000, i64 %t104)
  %t106 = extractvalue { i64, i1 } %t105, 0
  %t107 = extractvalue { i64, i1 } %t105, 1
  %t108 = xor i1 %t107, true
  br i1 %t108, label %ok_109, label %trap_109
trap_109:
  call void @abort()
  unreachable
ok_109:
  ret i64 %t106
b18:
  %p_18_0 = phi i64 [ %p_16_0, %edge_20 ], [ %p_19_0, %edge_23 ]
  %p_18_1 = phi i32 [ %p_16_1, %edge_20 ], [ %p_19_1, %edge_23 ]
  %p_18_2 = phi %hia.buffer [ %p_16_3, %edge_20 ], [ %p_19_2, %edge_23 ]
  %p_18_3 = phi i64 [ %p_16_0, %edge_20 ], [ %p_19_3, %edge_23 ]
  %p_18_4 = phi i64 [ 0, %edge_20 ], [ %t124, %edge_23 ]
  %t110 = icmp ult i64 %p_18_4, %p_18_3
  br i1 %t110, label %edge_21, label %edge_22
b19:
  %p_19_0 = phi i64 [ %p_18_0, %edge_21 ]
  %p_19_1 = phi i32 [ %p_18_1, %edge_21 ]
  %p_19_2 = phi %hia.buffer [ %p_18_2, %edge_21 ]
  %p_19_3 = phi i64 [ %p_18_3, %edge_21 ]
  %p_19_4 = phi i64 [ %p_18_4, %edge_21 ]
  %t111 = trunc i64 %p_19_4 to i32
  %t112 = mul i32 %t111, 13
  %t113 = add i32 %t112, %p_19_1
  %t114 = trunc i64 %p_19_4 to i8
  %t115 = mul i8 %t114, 13
  %t116 = trunc i32 %p_19_1 to i8
  %t117 = add i8 %t115, %t116
  %t118 = extractvalue %hia.buffer %p_19_2, 0
  %t119 = extractvalue %hia.buffer %p_19_2, 1
  %t120 = icmp ult i64 %p_19_4, %t119
  br i1 %t120, label %ok_121, label %trap_121
trap_121:
  call void @abort()
  unreachable
ok_121:
  %t122 = getelementptr i8, ptr %t118, i64 %p_19_4
  store i8 %t117, ptr %t122, align 1
  %t123 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_19_4, i64 1)
  %t124 = extractvalue { i64, i1 } %t123, 0
  %t125 = extractvalue { i64, i1 } %t123, 1
  %t126 = xor i1 %t125, true
  br i1 %t126, label %ok_127, label %trap_127
trap_127:
  call void @abort()
  unreachable
ok_127:
  br label %edge_23
b20:
  %p_20_0 = phi i64 [ %p_18_0, %edge_22 ]
  %p_20_1 = phi i32 [ %p_18_1, %edge_22 ]
  %p_20_2 = phi %hia.buffer [ %p_18_2, %edge_22 ]
  %p_20_3 = phi i64 [ %p_18_3, %edge_22 ]
  %p_20_4 = phi i64 [ %p_18_4, %edge_22 ]
  %t128 = call %hia.alloc @__hia_allocate(i64 %p_20_0, i1 true)
  %t129 = extractvalue %hia.alloc %t128, 0
  %t130 = extractvalue %hia.alloc %t128, 1
  %t131 = select i1 %t130, i64 %p_20_0, i64 0
  %t132 = insertvalue %hia.buffer %t129, i64 %t131, 1
  br i1 %t130, label %edge_24, label %edge_25
b21:
  %p_21_0 = phi i64 [ %p_20_0, %edge_24 ]
  %p_21_1 = phi i32 [ %p_20_1, %edge_24 ]
  %p_21_2 = phi %hia.buffer [ %p_20_2, %edge_24 ]
  %p_21_3 = phi i1 [ %t130, %edge_24 ]
  %p_21_4 = phi %hia.buffer [ %t132, %edge_24 ]
  %p_21_5 = phi i8 [ 1, %edge_24 ]
  br label %edge_26
b22:
  %p_22_0 = phi i64 [ %p_20_0, %edge_25 ]
  %p_22_1 = phi i32 [ %p_20_1, %edge_25 ]
  %p_22_2 = phi %hia.buffer [ %p_20_2, %edge_25 ]
  %p_22_3 = phi i1 [ %t130, %edge_25 ]
  %p_22_4 = phi %hia.buffer [ %t132, %edge_25 ]
  %p_22_5 = phi i8 [ 1, %edge_25 ]
  %t133 = extractvalue %hia.buffer %p_22_4, 0
  %t134 = icmp ne ptr %t133, null
  br i1 %t134, label %drop_nonnull_135, label %drop_after_135
drop_nonnull_135:
  call void @free(ptr %t133) nobuiltin
  br label %drop_after_135
drop_after_135:
  %t136 = extractvalue %hia.buffer %p_22_2, 0
  %t137 = icmp ne ptr %t136, null
  br i1 %t137, label %drop_nonnull_138, label %drop_after_138
drop_nonnull_138:
  call void @free(ptr %t136) nobuiltin
  br label %drop_after_138
drop_after_138:
  %t139 = zext i8 %p_22_5 to i64
  %t140 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 1000, i64 %t139)
  %t141 = extractvalue { i64, i1 } %t140, 0
  %t142 = extractvalue { i64, i1 } %t140, 1
  %t143 = xor i1 %t142, true
  br i1 %t143, label %ok_144, label %trap_144
trap_144:
  call void @abort()
  unreachable
ok_144:
  ret i64 %t141
b23:
  %p_23_0 = phi i64 [ %p_21_0, %edge_26 ], [ %p_24_0, %edge_29 ]
  %p_23_1 = phi i32 [ %p_21_1, %edge_26 ], [ %p_24_1, %edge_29 ]
  %p_23_2 = phi %hia.buffer [ %p_21_2, %edge_26 ], [ %p_24_2, %edge_29 ]
  %p_23_3 = phi %hia.buffer [ %p_21_4, %edge_26 ], [ %p_24_3, %edge_29 ]
  %p_23_4 = phi i64 [ %p_21_0, %edge_26 ], [ %p_24_4, %edge_29 ]
  %p_23_5 = phi i64 [ 0, %edge_26 ], [ %t166, %edge_29 ]
  %t145 = icmp ult i64 %p_23_5, %p_23_4
  br i1 %t145, label %edge_27, label %edge_28
b24:
  %p_24_0 = phi i64 [ %p_23_0, %edge_27 ]
  %p_24_1 = phi i32 [ %p_23_1, %edge_27 ]
  %p_24_2 = phi %hia.buffer [ %p_23_2, %edge_27 ]
  %p_24_3 = phi %hia.buffer [ %p_23_3, %edge_27 ]
  %p_24_4 = phi i64 [ %p_23_4, %edge_27 ]
  %p_24_5 = phi i64 [ %p_23_5, %edge_27 ]
  %t146 = extractvalue %hia.buffer %p_24_2, 0
  %t147 = extractvalue %hia.buffer %p_24_2, 1
  %t148 = icmp ult i64 %p_24_5, %t147
  br i1 %t148, label %ok_149, label %trap_149
trap_149:
  call void @abort()
  unreachable
ok_149:
  %t150 = getelementptr i8, ptr %t146, i64 %p_24_5
  %t151 = load i8, ptr %t150, align 1
  %t152 = trunc i64 %p_24_5 to i32
  %t153 = xor i32 %p_24_1, 90
  %t154 = add i32 %t152, %t153
  %t155 = trunc i64 %p_24_5 to i8
  %t156 = trunc i32 %p_24_1 to i8
  %t157 = xor i8 %t156, 90
  %t158 = add i8 %t155, %t157
  %t159 = xor i8 %t151, %t158
  %t160 = extractvalue %hia.buffer %p_24_3, 0
  %t161 = extractvalue %hia.buffer %p_24_3, 1
  %t162 = icmp ult i64 %p_24_5, %t161
  br i1 %t162, label %ok_163, label %trap_163
trap_163:
  call void @abort()
  unreachable
ok_163:
  %t164 = getelementptr i8, ptr %t160, i64 %p_24_5
  store i8 %t159, ptr %t164, align 1
  %t165 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_24_5, i64 1)
  %t166 = extractvalue { i64, i1 } %t165, 0
  %t167 = extractvalue { i64, i1 } %t165, 1
  %t168 = xor i1 %t167, true
  br i1 %t168, label %ok_169, label %trap_169
trap_169:
  call void @abort()
  unreachable
ok_169:
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
  %p_26_4 = phi i64 [ 0, %edge_30 ], [ %t179, %edge_33 ]
  %p_26_5 = phi i64 [ %p_25_0, %edge_30 ], [ %p_27_5, %edge_33 ]
  %p_26_6 = phi i64 [ 0, %edge_30 ], [ %t184, %edge_33 ]
  %t170 = icmp ult i64 %p_26_6, %p_26_5
  br i1 %t170, label %edge_31, label %edge_32
b27:
  %p_27_0 = phi i64 [ %p_26_0, %edge_31 ]
  %p_27_1 = phi i32 [ %p_26_1, %edge_31 ]
  %p_27_2 = phi %hia.buffer [ %p_26_2, %edge_31 ]
  %p_27_3 = phi %hia.buffer [ %p_26_3, %edge_31 ]
  %p_27_4 = phi i64 [ %p_26_4, %edge_31 ]
  %p_27_5 = phi i64 [ %p_26_5, %edge_31 ]
  %p_27_6 = phi i64 [ %p_26_6, %edge_31 ]
  %t171 = extractvalue %hia.buffer %p_27_3, 0
  %t172 = extractvalue %hia.buffer %p_27_3, 1
  %t173 = icmp ult i64 %p_27_6, %t172
  br i1 %t173, label %ok_174, label %trap_174
trap_174:
  call void @abort()
  unreachable
ok_174:
  %t175 = getelementptr i8, ptr %t171, i64 %p_27_6
  %t176 = load i8, ptr %t175, align 1
  %t177 = zext i8 %t176 to i64
  %t178 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_27_4, i64 %t177)
  %t179 = extractvalue { i64, i1 } %t178, 0
  %t180 = extractvalue { i64, i1 } %t178, 1
  %t181 = xor i1 %t180, true
  br i1 %t181, label %ok_182, label %trap_182
trap_182:
  call void @abort()
  unreachable
ok_182:
  %t183 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_27_6, i64 1)
  %t184 = extractvalue { i64, i1 } %t183, 0
  %t185 = extractvalue { i64, i1 } %t183, 1
  %t186 = xor i1 %t185, true
  br i1 %t186, label %ok_187, label %trap_187
trap_187:
  call void @abort()
  unreachable
ok_187:
  br label %edge_33
b28:
  %p_28_0 = phi i64 [ %p_26_0, %edge_32 ]
  %p_28_1 = phi i32 [ %p_26_1, %edge_32 ]
  %p_28_2 = phi %hia.buffer [ %p_26_2, %edge_32 ]
  %p_28_3 = phi %hia.buffer [ %p_26_3, %edge_32 ]
  %p_28_4 = phi i64 [ %p_26_4, %edge_32 ]
  %p_28_5 = phi i64 [ %p_26_5, %edge_32 ]
  %p_28_6 = phi i64 [ %p_26_6, %edge_32 ]
  %t188 = extractvalue %hia.buffer %p_28_3, 0
  %t189 = icmp ne ptr %t188, null
  br i1 %t189, label %drop_nonnull_190, label %drop_after_190
drop_nonnull_190:
  call void @free(ptr %t188) nobuiltin
  br label %drop_after_190
drop_after_190:
  %t191 = extractvalue %hia.buffer %p_28_2, 0
  %t192 = icmp ne ptr %t191, null
  br i1 %t192, label %drop_nonnull_193, label %drop_after_193
drop_nonnull_193:
  call void @free(ptr %t191) nobuiltin
  br label %drop_after_193
drop_after_193:
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
