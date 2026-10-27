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
  %t1 = call %hia.alloc @__hia_allocate(i64 %p_0_0, i1 true)
  %t2 = extractvalue %hia.alloc %t1, 0
  %t3 = extractvalue %hia.alloc %t1, 1
  %t4 = select i1 %t3, i64 %p_0_0, i64 0
  %t5 = insertvalue %hia.buffer %t2, i64 %t4, 1
  br i1 %t3, label %edge_0, label %edge_1
b1:
  %p_1_0 = phi i64 [ %p_0_0, %edge_0 ]
  %p_1_1 = phi i32 [ %p_0_1, %edge_0 ]
  %p_1_2 = phi i1 [ %t3, %edge_0 ]
  %p_1_3 = phi %hia.buffer [ %t5, %edge_0 ]
  %p_1_4 = phi i8 [ 1, %edge_0 ]
  br label %edge_2
b2:
  %p_2_0 = phi i64 [ %p_0_0, %edge_1 ]
  %p_2_1 = phi i32 [ %p_0_1, %edge_1 ]
  %p_2_2 = phi i1 [ %t3, %edge_1 ]
  %p_2_3 = phi %hia.buffer [ %t5, %edge_1 ]
  %p_2_4 = phi i8 [ 1, %edge_1 ]
  %t6 = extractvalue %hia.buffer %p_2_3, 0
  %t7 = icmp ne ptr %t6, null
  br i1 %t7, label %drop_nonnull_8, label %drop_after_8
drop_nonnull_8:
  call void @free(ptr %t6) nobuiltin
  br label %drop_after_8
drop_after_8:
  %t9 = zext i8 %p_2_4 to i64
  %t10 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 1000, i64 %t9)
  %t11 = extractvalue { i64, i1 } %t10, 0
  %t12 = extractvalue { i64, i1 } %t10, 1
  %t13 = xor i1 %t12, true
  br i1 %t13, label %ok_14, label %trap_14
trap_14:
  call void @abort()
  unreachable
ok_14:
  ret i64 %t11
b3:
  %p_3_0 = phi i64 [ %p_1_0, %edge_2 ], [ %p_4_0, %edge_5 ]
  %p_3_1 = phi i32 [ %p_1_1, %edge_2 ], [ %p_4_1, %edge_5 ]
  %p_3_2 = phi %hia.buffer [ %p_1_3, %edge_2 ], [ %p_4_2, %edge_5 ]
  %p_3_3 = phi i64 [ %p_1_0, %edge_2 ], [ %p_4_3, %edge_5 ]
  %p_3_4 = phi i64 [ 0, %edge_2 ], [ %t25, %edge_5 ]
  %t15 = icmp ult i64 %p_3_4, %p_3_3
  br i1 %t15, label %edge_3, label %edge_4
b4:
  %p_4_0 = phi i64 [ %p_3_0, %edge_3 ]
  %p_4_1 = phi i32 [ %p_3_1, %edge_3 ]
  %p_4_2 = phi %hia.buffer [ %p_3_2, %edge_3 ]
  %p_4_3 = phi i64 [ %p_3_3, %edge_3 ]
  %p_4_4 = phi i64 [ %p_3_4, %edge_3 ]
  %t16 = trunc i64 %p_4_4 to i32
  %t17 = add i32 %t16, %p_4_1
  %t18 = trunc i32 %t17 to i8
  %t19 = extractvalue %hia.buffer %p_4_2, 0
  %t20 = extractvalue %hia.buffer %p_4_2, 1
  %t21 = icmp ult i64 %p_4_4, %t20
  br i1 %t21, label %ok_22, label %trap_22
trap_22:
  call void @abort()
  unreachable
ok_22:
  %t23 = getelementptr i8, ptr %t19, i64 %p_4_4
  store i8 %t18, ptr %t23, align 1
  %t24 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_4_4, i64 1)
  %t25 = extractvalue { i64, i1 } %t24, 0
  %t26 = extractvalue { i64, i1 } %t24, 1
  %t27 = xor i1 %t26, true
  br i1 %t27, label %ok_28, label %trap_28
trap_28:
  call void @abort()
  unreachable
ok_28:
  br label %edge_5
b5:
  %p_5_0 = phi i64 [ %p_3_0, %edge_4 ]
  %p_5_1 = phi i32 [ %p_3_1, %edge_4 ]
  %p_5_2 = phi %hia.buffer [ %p_3_2, %edge_4 ]
  %p_5_3 = phi i64 [ %p_3_3, %edge_4 ]
  %p_5_4 = phi i64 [ %p_3_4, %edge_4 ]
  br label %edge_6
b6:
  %p_6_0 = phi i64 [ %p_5_0, %edge_6 ], [ %p_7_0, %edge_9 ]
  %p_6_1 = phi i32 [ %p_5_1, %edge_6 ], [ %p_7_1, %edge_9 ]
  %p_6_2 = phi %hia.buffer [ %p_5_2, %edge_6 ], [ %p_7_2, %edge_9 ]
  %p_6_3 = phi i64 [ 0, %edge_6 ], [ %t38, %edge_9 ]
  %p_6_4 = phi i64 [ %p_5_0, %edge_6 ], [ %p_7_4, %edge_9 ]
  %p_6_5 = phi i64 [ 0, %edge_6 ], [ %t43, %edge_9 ]
  %t29 = icmp ult i64 %p_6_5, %p_6_4
  br i1 %t29, label %edge_7, label %edge_8
b7:
  %p_7_0 = phi i64 [ %p_6_0, %edge_7 ]
  %p_7_1 = phi i32 [ %p_6_1, %edge_7 ]
  %p_7_2 = phi %hia.buffer [ %p_6_2, %edge_7 ]
  %p_7_3 = phi i64 [ %p_6_3, %edge_7 ]
  %p_7_4 = phi i64 [ %p_6_4, %edge_7 ]
  %p_7_5 = phi i64 [ %p_6_5, %edge_7 ]
  %t30 = extractvalue %hia.buffer %p_7_2, 0
  %t31 = extractvalue %hia.buffer %p_7_2, 1
  %t32 = icmp ult i64 %p_7_5, %t31
  br i1 %t32, label %ok_33, label %trap_33
trap_33:
  call void @abort()
  unreachable
ok_33:
  %t34 = getelementptr i8, ptr %t30, i64 %p_7_5
  %t35 = load i8, ptr %t34, align 1
  %t36 = zext i8 %t35 to i64
  %t37 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_7_3, i64 %t36)
  %t38 = extractvalue { i64, i1 } %t37, 0
  %t39 = extractvalue { i64, i1 } %t37, 1
  %t40 = xor i1 %t39, true
  br i1 %t40, label %ok_41, label %trap_41
trap_41:
  call void @abort()
  unreachable
ok_41:
  %t42 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_7_5, i64 1)
  %t43 = extractvalue { i64, i1 } %t42, 0
  %t44 = extractvalue { i64, i1 } %t42, 1
  %t45 = xor i1 %t44, true
  br i1 %t45, label %ok_46, label %trap_46
trap_46:
  call void @abort()
  unreachable
ok_46:
  br label %edge_9
b8:
  %p_8_0 = phi i64 [ %p_6_0, %edge_8 ]
  %p_8_1 = phi i32 [ %p_6_1, %edge_8 ]
  %p_8_2 = phi %hia.buffer [ %p_6_2, %edge_8 ]
  %p_8_3 = phi i64 [ %p_6_3, %edge_8 ]
  %p_8_4 = phi i64 [ %p_6_4, %edge_8 ]
  %p_8_5 = phi i64 [ %p_6_5, %edge_8 ]
  %t47 = extractvalue %hia.buffer %p_8_2, 0
  %t48 = icmp ne ptr %t47, null
  br i1 %t48, label %drop_nonnull_49, label %drop_after_49
drop_nonnull_49:
  call void @free(ptr %t47) nobuiltin
  br label %drop_after_49
drop_after_49:
  ret i64 %p_8_3
edge_0:
  br label %b1
edge_1:
  br label %b2
edge_2:
  br label %b3
edge_3:
  br label %b4
edge_4:
  br label %b5
edge_5:
  br label %b3
edge_6:
  br label %b6
edge_7:
  br label %b7
edge_8:
  br label %b8
edge_9:
  br label %b6
}

define internal i64 @__hia_fn_1(i64 %p_0_0, i32 %p_0_1) {
b0:
  %t1 = call %hia.alloc @__hia_allocate(i64 %p_0_0, i1 true)
  %t2 = extractvalue %hia.alloc %t1, 0
  %t3 = extractvalue %hia.alloc %t1, 1
  %t4 = select i1 %t3, i64 %p_0_0, i64 0
  %t5 = insertvalue %hia.buffer %t2, i64 %t4, 1
  br i1 %t3, label %edge_0, label %edge_1
b1:
  %p_1_0 = phi i64 [ %p_0_0, %edge_0 ]
  %p_1_1 = phi i32 [ %p_0_1, %edge_0 ]
  %p_1_2 = phi i1 [ %t3, %edge_0 ]
  %p_1_3 = phi %hia.buffer [ %t5, %edge_0 ]
  %p_1_4 = phi i8 [ 1, %edge_0 ]
  br label %edge_2
b2:
  %p_2_0 = phi i64 [ %p_0_0, %edge_1 ]
  %p_2_1 = phi i32 [ %p_0_1, %edge_1 ]
  %p_2_2 = phi i1 [ %t3, %edge_1 ]
  %p_2_3 = phi %hia.buffer [ %t5, %edge_1 ]
  %p_2_4 = phi i8 [ 1, %edge_1 ]
  %t6 = extractvalue %hia.buffer %p_2_3, 0
  %t7 = icmp ne ptr %t6, null
  br i1 %t7, label %drop_nonnull_8, label %drop_after_8
drop_nonnull_8:
  call void @free(ptr %t6) nobuiltin
  br label %drop_after_8
drop_after_8:
  %t9 = zext i8 %p_2_4 to i64
  %t10 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 1000, i64 %t9)
  %t11 = extractvalue { i64, i1 } %t10, 0
  %t12 = extractvalue { i64, i1 } %t10, 1
  %t13 = xor i1 %t12, true
  br i1 %t13, label %ok_14, label %trap_14
trap_14:
  call void @abort()
  unreachable
ok_14:
  ret i64 %t11
b3:
  %p_3_0 = phi i64 [ %p_1_0, %edge_2 ], [ %p_4_0, %edge_5 ]
  %p_3_1 = phi i32 [ %p_1_1, %edge_2 ], [ %p_4_1, %edge_5 ]
  %p_3_2 = phi %hia.buffer [ %p_1_3, %edge_2 ], [ %p_4_2, %edge_5 ]
  %p_3_3 = phi i64 [ %p_1_0, %edge_2 ], [ %p_4_3, %edge_5 ]
  %p_3_4 = phi i64 [ 0, %edge_2 ], [ %t26, %edge_5 ]
  %t15 = icmp ult i64 %p_3_4, %p_3_3
  br i1 %t15, label %edge_3, label %edge_4
b4:
  %p_4_0 = phi i64 [ %p_3_0, %edge_3 ]
  %p_4_1 = phi i32 [ %p_3_1, %edge_3 ]
  %p_4_2 = phi %hia.buffer [ %p_3_2, %edge_3 ]
  %p_4_3 = phi i64 [ %p_3_3, %edge_3 ]
  %p_4_4 = phi i64 [ %p_3_4, %edge_3 ]
  %t16 = trunc i64 %p_4_4 to i32
  %t17 = mul i32 %t16, 13
  %t18 = add i32 %t17, %p_4_1
  %t19 = trunc i32 %t18 to i8
  %t20 = extractvalue %hia.buffer %p_4_2, 0
  %t21 = extractvalue %hia.buffer %p_4_2, 1
  %t22 = icmp ult i64 %p_4_4, %t21
  br i1 %t22, label %ok_23, label %trap_23
trap_23:
  call void @abort()
  unreachable
ok_23:
  %t24 = getelementptr i8, ptr %t20, i64 %p_4_4
  store i8 %t19, ptr %t24, align 1
  %t25 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_4_4, i64 1)
  %t26 = extractvalue { i64, i1 } %t25, 0
  %t27 = extractvalue { i64, i1 } %t25, 1
  %t28 = xor i1 %t27, true
  br i1 %t28, label %ok_29, label %trap_29
trap_29:
  call void @abort()
  unreachable
ok_29:
  br label %edge_5
b5:
  %p_5_0 = phi i64 [ %p_3_0, %edge_4 ]
  %p_5_1 = phi i32 [ %p_3_1, %edge_4 ]
  %p_5_2 = phi %hia.buffer [ %p_3_2, %edge_4 ]
  %p_5_3 = phi i64 [ %p_3_3, %edge_4 ]
  %p_5_4 = phi i64 [ %p_3_4, %edge_4 ]
  %t30 = call %hia.alloc @__hia_allocate(i64 %p_5_0, i1 true)
  %t31 = extractvalue %hia.alloc %t30, 0
  %t32 = extractvalue %hia.alloc %t30, 1
  %t33 = select i1 %t32, i64 %p_5_0, i64 0
  %t34 = insertvalue %hia.buffer %t31, i64 %t33, 1
  br i1 %t32, label %edge_6, label %edge_7
b6:
  %p_6_0 = phi i64 [ %p_5_0, %edge_6 ]
  %p_6_1 = phi i32 [ %p_5_1, %edge_6 ]
  %p_6_2 = phi %hia.buffer [ %p_5_2, %edge_6 ]
  %p_6_3 = phi i1 [ %t32, %edge_6 ]
  %p_6_4 = phi %hia.buffer [ %t34, %edge_6 ]
  %p_6_5 = phi i8 [ 1, %edge_6 ]
  br label %edge_8
b7:
  %p_7_0 = phi i64 [ %p_5_0, %edge_7 ]
  %p_7_1 = phi i32 [ %p_5_1, %edge_7 ]
  %p_7_2 = phi %hia.buffer [ %p_5_2, %edge_7 ]
  %p_7_3 = phi i1 [ %t32, %edge_7 ]
  %p_7_4 = phi %hia.buffer [ %t34, %edge_7 ]
  %p_7_5 = phi i8 [ 1, %edge_7 ]
  %t35 = extractvalue %hia.buffer %p_7_4, 0
  %t36 = icmp ne ptr %t35, null
  br i1 %t36, label %drop_nonnull_37, label %drop_after_37
drop_nonnull_37:
  call void @free(ptr %t35) nobuiltin
  br label %drop_after_37
drop_after_37:
  %t38 = extractvalue %hia.buffer %p_7_2, 0
  %t39 = icmp ne ptr %t38, null
  br i1 %t39, label %drop_nonnull_40, label %drop_after_40
drop_nonnull_40:
  call void @free(ptr %t38) nobuiltin
  br label %drop_after_40
drop_after_40:
  %t41 = zext i8 %p_7_5 to i64
  %t42 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 1000, i64 %t41)
  %t43 = extractvalue { i64, i1 } %t42, 0
  %t44 = extractvalue { i64, i1 } %t42, 1
  %t45 = xor i1 %t44, true
  br i1 %t45, label %ok_46, label %trap_46
trap_46:
  call void @abort()
  unreachable
ok_46:
  ret i64 %t43
b8:
  %p_8_0 = phi i64 [ %p_6_0, %edge_8 ], [ %p_9_0, %edge_11 ]
  %p_8_1 = phi i32 [ %p_6_1, %edge_8 ], [ %p_9_1, %edge_11 ]
  %p_8_2 = phi %hia.buffer [ %p_6_2, %edge_8 ], [ %p_9_2, %edge_11 ]
  %p_8_3 = phi %hia.buffer [ %p_6_4, %edge_8 ], [ %p_9_3, %edge_11 ]
  %p_8_4 = phi i64 [ %p_6_0, %edge_8 ], [ %p_9_4, %edge_11 ]
  %p_8_5 = phi i64 [ 0, %edge_8 ], [ %t65, %edge_11 ]
  %t47 = icmp ult i64 %p_8_5, %p_8_4
  br i1 %t47, label %edge_9, label %edge_10
b9:
  %p_9_0 = phi i64 [ %p_8_0, %edge_9 ]
  %p_9_1 = phi i32 [ %p_8_1, %edge_9 ]
  %p_9_2 = phi %hia.buffer [ %p_8_2, %edge_9 ]
  %p_9_3 = phi %hia.buffer [ %p_8_3, %edge_9 ]
  %p_9_4 = phi i64 [ %p_8_4, %edge_9 ]
  %p_9_5 = phi i64 [ %p_8_5, %edge_9 ]
  %t48 = extractvalue %hia.buffer %p_9_2, 0
  %t49 = extractvalue %hia.buffer %p_9_2, 1
  %t50 = icmp ult i64 %p_9_5, %t49
  br i1 %t50, label %ok_51, label %trap_51
trap_51:
  call void @abort()
  unreachable
ok_51:
  %t52 = getelementptr i8, ptr %t48, i64 %p_9_5
  %t53 = load i8, ptr %t52, align 1
  %t54 = trunc i64 %p_9_5 to i32
  %t55 = xor i32 %p_9_1, 90
  %t56 = add i32 %t54, %t55
  %t57 = trunc i32 %t56 to i8
  %t58 = xor i8 %t53, %t57
  %t59 = extractvalue %hia.buffer %p_9_3, 0
  %t60 = extractvalue %hia.buffer %p_9_3, 1
  %t61 = icmp ult i64 %p_9_5, %t60
  br i1 %t61, label %ok_62, label %trap_62
trap_62:
  call void @abort()
  unreachable
ok_62:
  %t63 = getelementptr i8, ptr %t59, i64 %p_9_5
  store i8 %t58, ptr %t63, align 1
  %t64 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_9_5, i64 1)
  %t65 = extractvalue { i64, i1 } %t64, 0
  %t66 = extractvalue { i64, i1 } %t64, 1
  %t67 = xor i1 %t66, true
  br i1 %t67, label %ok_68, label %trap_68
trap_68:
  call void @abort()
  unreachable
ok_68:
  br label %edge_11
b10:
  %p_10_0 = phi i64 [ %p_8_0, %edge_10 ]
  %p_10_1 = phi i32 [ %p_8_1, %edge_10 ]
  %p_10_2 = phi %hia.buffer [ %p_8_2, %edge_10 ]
  %p_10_3 = phi %hia.buffer [ %p_8_3, %edge_10 ]
  %p_10_4 = phi i64 [ %p_8_4, %edge_10 ]
  %p_10_5 = phi i64 [ %p_8_5, %edge_10 ]
  br label %edge_12
b11:
  %p_11_0 = phi i64 [ %p_10_0, %edge_12 ], [ %p_12_0, %edge_15 ]
  %p_11_1 = phi i32 [ %p_10_1, %edge_12 ], [ %p_12_1, %edge_15 ]
  %p_11_2 = phi %hia.buffer [ %p_10_2, %edge_12 ], [ %p_12_2, %edge_15 ]
  %p_11_3 = phi %hia.buffer [ %p_10_3, %edge_12 ], [ %p_12_3, %edge_15 ]
  %p_11_4 = phi i64 [ 0, %edge_12 ], [ %t78, %edge_15 ]
  %p_11_5 = phi i64 [ %p_10_0, %edge_12 ], [ %p_12_5, %edge_15 ]
  %p_11_6 = phi i64 [ 0, %edge_12 ], [ %t83, %edge_15 ]
  %t69 = icmp ult i64 %p_11_6, %p_11_5
  br i1 %t69, label %edge_13, label %edge_14
b12:
  %p_12_0 = phi i64 [ %p_11_0, %edge_13 ]
  %p_12_1 = phi i32 [ %p_11_1, %edge_13 ]
  %p_12_2 = phi %hia.buffer [ %p_11_2, %edge_13 ]
  %p_12_3 = phi %hia.buffer [ %p_11_3, %edge_13 ]
  %p_12_4 = phi i64 [ %p_11_4, %edge_13 ]
  %p_12_5 = phi i64 [ %p_11_5, %edge_13 ]
  %p_12_6 = phi i64 [ %p_11_6, %edge_13 ]
  %t70 = extractvalue %hia.buffer %p_12_3, 0
  %t71 = extractvalue %hia.buffer %p_12_3, 1
  %t72 = icmp ult i64 %p_12_6, %t71
  br i1 %t72, label %ok_73, label %trap_73
trap_73:
  call void @abort()
  unreachable
ok_73:
  %t74 = getelementptr i8, ptr %t70, i64 %p_12_6
  %t75 = load i8, ptr %t74, align 1
  %t76 = zext i8 %t75 to i64
  %t77 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_12_4, i64 %t76)
  %t78 = extractvalue { i64, i1 } %t77, 0
  %t79 = extractvalue { i64, i1 } %t77, 1
  %t80 = xor i1 %t79, true
  br i1 %t80, label %ok_81, label %trap_81
trap_81:
  call void @abort()
  unreachable
ok_81:
  %t82 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_12_6, i64 1)
  %t83 = extractvalue { i64, i1 } %t82, 0
  %t84 = extractvalue { i64, i1 } %t82, 1
  %t85 = xor i1 %t84, true
  br i1 %t85, label %ok_86, label %trap_86
trap_86:
  call void @abort()
  unreachable
ok_86:
  br label %edge_15
b13:
  %p_13_0 = phi i64 [ %p_11_0, %edge_14 ]
  %p_13_1 = phi i32 [ %p_11_1, %edge_14 ]
  %p_13_2 = phi %hia.buffer [ %p_11_2, %edge_14 ]
  %p_13_3 = phi %hia.buffer [ %p_11_3, %edge_14 ]
  %p_13_4 = phi i64 [ %p_11_4, %edge_14 ]
  %p_13_5 = phi i64 [ %p_11_5, %edge_14 ]
  %p_13_6 = phi i64 [ %p_11_6, %edge_14 ]
  %t87 = extractvalue %hia.buffer %p_13_3, 0
  %t88 = icmp ne ptr %t87, null
  br i1 %t88, label %drop_nonnull_89, label %drop_after_89
drop_nonnull_89:
  call void @free(ptr %t87) nobuiltin
  br label %drop_after_89
drop_after_89:
  %t90 = extractvalue %hia.buffer %p_13_2, 0
  %t91 = icmp ne ptr %t90, null
  br i1 %t91, label %drop_nonnull_92, label %drop_after_92
drop_nonnull_92:
  call void @free(ptr %t90) nobuiltin
  br label %drop_after_92
drop_after_92:
  ret i64 %p_13_4
edge_0:
  br label %b1
edge_1:
  br label %b2
edge_2:
  br label %b3
edge_3:
  br label %b4
edge_4:
  br label %b5
edge_5:
  br label %b3
edge_6:
  br label %b6
edge_7:
  br label %b7
edge_8:
  br label %b8
edge_9:
  br label %b9
edge_10:
  br label %b10
edge_11:
  br label %b8
edge_12:
  br label %b11
edge_13:
  br label %b12
edge_14:
  br label %b13
edge_15:
  br label %b11
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
