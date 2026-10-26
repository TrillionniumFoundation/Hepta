; Standalone HIA: verified core -> LLVM. No source AST or Rust safety gate.
target triple = "x86_64-unknown-linux-gnu"
%hia.buffer = type { ptr, i64 }
%hia.alloc = type { %hia.buffer, i1 }
declare void @abort() noreturn
declare ptr @calloc(i64, i64) "no-builtins"
declare ptr @malloc(i64) "no-builtins"
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

define internal %hia.buffer @__hia_fn_0(%hia.buffer %p_0_0) {
b0:
  ret %hia.buffer %p_0_0
}

define internal i64 @__hia_fn_1(i64 %p_0_0, i32 %p_0_1) {
b0:
  %t1 = call %hia.alloc @__hia_allocate(i64 %p_0_0, i1 true)
  %t2 = extractvalue %hia.alloc %t1, 0
  %t3 = extractvalue %hia.alloc %t1, 1
  br i1 %t3, label %edge_0, label %edge_1
b1:
  %p_1_0 = phi i64 [ %p_0_0, %edge_0 ]
  %p_1_1 = phi i32 [ %p_0_1, %edge_0 ]
  %p_1_2 = phi i1 [ %t3, %edge_0 ]
  %p_1_3 = phi %hia.buffer [ %t2, %edge_0 ]
  %p_1_4 = phi i8 [ 1, %edge_0 ]
  br label %edge_2
b2:
  %p_2_0 = phi i64 [ %p_0_0, %edge_1 ]
  %p_2_1 = phi i32 [ %p_0_1, %edge_1 ]
  %p_2_2 = phi i1 [ %t3, %edge_1 ]
  %p_2_3 = phi %hia.buffer [ %t2, %edge_1 ]
  %p_2_4 = phi i8 [ 1, %edge_1 ]
  %t4 = extractvalue %hia.buffer %p_2_3, 0
  call void @free(ptr %t4) nobuiltin
  %t5 = zext i8 %p_2_4 to i64
  %t6 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 1000, i64 %t5)
  %t7 = extractvalue { i64, i1 } %t6, 0
  %t8 = extractvalue { i64, i1 } %t6, 1
  %t9 = xor i1 %t8, true
  br i1 %t9, label %ok_10, label %trap_10
trap_10:
  call void @abort()
  unreachable
ok_10:
  ret i64 %t7
b3:
  %p_3_0 = phi i64 [ %p_1_0, %edge_2 ], [ %p_4_0, %edge_5 ]
  %p_3_1 = phi i32 [ %p_1_1, %edge_2 ], [ %p_4_1, %edge_5 ]
  %p_3_2 = phi %hia.buffer [ %p_1_3, %edge_2 ], [ %p_4_2, %edge_5 ]
  %p_3_3 = phi i64 [ %p_1_0, %edge_2 ], [ %p_4_3, %edge_5 ]
  %p_3_4 = phi i64 [ 0, %edge_2 ], [ %t21, %edge_5 ]
  %t11 = icmp ult i64 %p_3_4, %p_3_3
  br i1 %t11, label %edge_3, label %edge_4
b4:
  %p_4_0 = phi i64 [ %p_3_0, %edge_3 ]
  %p_4_1 = phi i32 [ %p_3_1, %edge_3 ]
  %p_4_2 = phi %hia.buffer [ %p_3_2, %edge_3 ]
  %p_4_3 = phi i64 [ %p_3_3, %edge_3 ]
  %p_4_4 = phi i64 [ %p_3_4, %edge_3 ]
  %t12 = trunc i64 %p_4_4 to i32
  %t13 = add i32 %t12, %p_4_1
  %t14 = trunc i32 %t13 to i8
  %t15 = extractvalue %hia.buffer %p_4_2, 0
  %t16 = extractvalue %hia.buffer %p_4_2, 1
  %t17 = icmp ult i64 %p_4_4, %t16
  br i1 %t17, label %ok_18, label %trap_18
trap_18:
  call void @abort()
  unreachable
ok_18:
  %t19 = getelementptr i8, ptr %t15, i64 %p_4_4
  store i8 %t14, ptr %t19, align 1
  %t20 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_4_4, i64 1)
  %t21 = extractvalue { i64, i1 } %t20, 0
  %t22 = extractvalue { i64, i1 } %t20, 1
  %t23 = xor i1 %t22, true
  br i1 %t23, label %ok_24, label %trap_24
trap_24:
  call void @abort()
  unreachable
ok_24:
  br label %edge_5
b5:
  %p_5_0 = phi i64 [ %p_3_0, %edge_4 ]
  %p_5_1 = phi i32 [ %p_3_1, %edge_4 ]
  %p_5_2 = phi %hia.buffer [ %p_3_2, %edge_4 ]
  %p_5_3 = phi i64 [ %p_3_3, %edge_4 ]
  %p_5_4 = phi i64 [ %p_3_4, %edge_4 ]
  %t25 = call %hia.buffer @__hia_fn_0(%hia.buffer %p_5_2)
  br label %edge_6
b6:
  %p_6_0 = phi i64 [ %p_5_0, %edge_6 ], [ %p_7_0, %edge_9 ]
  %p_6_1 = phi i32 [ %p_5_1, %edge_6 ], [ %p_7_1, %edge_9 ]
  %p_6_2 = phi %hia.buffer [ %t25, %edge_6 ], [ %p_7_2, %edge_9 ]
  %p_6_3 = phi i64 [ 0, %edge_6 ], [ %t35, %edge_9 ]
  %p_6_4 = phi i64 [ %p_5_0, %edge_6 ], [ %p_7_4, %edge_9 ]
  %p_6_5 = phi i64 [ 0, %edge_6 ], [ %t40, %edge_9 ]
  %t26 = icmp ult i64 %p_6_5, %p_6_4
  br i1 %t26, label %edge_7, label %edge_8
b7:
  %p_7_0 = phi i64 [ %p_6_0, %edge_7 ]
  %p_7_1 = phi i32 [ %p_6_1, %edge_7 ]
  %p_7_2 = phi %hia.buffer [ %p_6_2, %edge_7 ]
  %p_7_3 = phi i64 [ %p_6_3, %edge_7 ]
  %p_7_4 = phi i64 [ %p_6_4, %edge_7 ]
  %p_7_5 = phi i64 [ %p_6_5, %edge_7 ]
  %t27 = extractvalue %hia.buffer %p_7_2, 0
  %t28 = extractvalue %hia.buffer %p_7_2, 1
  %t29 = icmp ult i64 %p_7_5, %t28
  br i1 %t29, label %ok_30, label %trap_30
trap_30:
  call void @abort()
  unreachable
ok_30:
  %t31 = getelementptr i8, ptr %t27, i64 %p_7_5
  %t32 = load i8, ptr %t31, align 1
  %t33 = zext i8 %t32 to i64
  %t34 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_7_3, i64 %t33)
  %t35 = extractvalue { i64, i1 } %t34, 0
  %t36 = extractvalue { i64, i1 } %t34, 1
  %t37 = xor i1 %t36, true
  br i1 %t37, label %ok_38, label %trap_38
trap_38:
  call void @abort()
  unreachable
ok_38:
  %t39 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_7_5, i64 1)
  %t40 = extractvalue { i64, i1 } %t39, 0
  %t41 = extractvalue { i64, i1 } %t39, 1
  %t42 = xor i1 %t41, true
  br i1 %t42, label %ok_43, label %trap_43
trap_43:
  call void @abort()
  unreachable
ok_43:
  br label %edge_9
b8:
  %p_8_0 = phi i64 [ %p_6_0, %edge_8 ]
  %p_8_1 = phi i32 [ %p_6_1, %edge_8 ]
  %p_8_2 = phi %hia.buffer [ %p_6_2, %edge_8 ]
  %p_8_3 = phi i64 [ %p_6_3, %edge_8 ]
  %p_8_4 = phi i64 [ %p_6_4, %edge_8 ]
  %p_8_5 = phi i64 [ %p_6_5, %edge_8 ]
  %t44 = extractvalue %hia.buffer %p_8_2, 0
  call void @free(ptr %t44) nobuiltin
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

define internal i64 @__hia_fn_2(i64 %p_0_0, i32 %p_0_1) {
b0:
  %t1 = call %hia.alloc @__hia_allocate(i64 %p_0_0, i1 false)
  %t2 = extractvalue %hia.alloc %t1, 0
  %t3 = extractvalue %hia.alloc %t1, 1
  br i1 %t3, label %edge_0, label %edge_1
b1:
  %p_1_0 = phi i64 [ %p_0_0, %edge_0 ]
  %p_1_1 = phi i32 [ %p_0_1, %edge_0 ]
  %p_1_2 = phi i1 [ %t3, %edge_0 ]
  %p_1_3 = phi %hia.buffer [ %t2, %edge_0 ]
  %p_1_4 = phi i8 [ 1, %edge_0 ]
  %t4 = extractvalue %hia.buffer %p_1_3, 0
  call void @free(ptr %t4) nobuiltin
  %t5 = zext i32 %p_1_1 to i64
  %t6 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 1002, i64 %t5)
  %t7 = extractvalue { i64, i1 } %t6, 0
  %t8 = extractvalue { i64, i1 } %t6, 1
  %t9 = xor i1 %t8, true
  br i1 %t9, label %ok_10, label %trap_10
trap_10:
  call void @abort()
  unreachable
ok_10:
  ret i64 %t7
b2:
  %p_2_0 = phi i64 [ %p_0_0, %edge_1 ]
  %p_2_1 = phi i32 [ %p_0_1, %edge_1 ]
  %p_2_2 = phi i1 [ %t3, %edge_1 ]
  %p_2_3 = phi %hia.buffer [ %t2, %edge_1 ]
  %p_2_4 = phi i8 [ 1, %edge_1 ]
  %t11 = extractvalue %hia.buffer %p_2_3, 0
  call void @free(ptr %t11) nobuiltin
  %t12 = zext i8 %p_2_4 to i64
  %t13 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 1000, i64 %t12)
  %t14 = extractvalue { i64, i1 } %t13, 0
  %t15 = extractvalue { i64, i1 } %t13, 1
  %t16 = xor i1 %t15, true
  br i1 %t16, label %ok_17, label %trap_17
trap_17:
  call void @abort()
  unreachable
ok_17:
  %t18 = zext i32 %p_2_1 to i64
  %t19 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %t14, i64 %t18)
  %t20 = extractvalue { i64, i1 } %t19, 0
  %t21 = extractvalue { i64, i1 } %t19, 1
  %t22 = xor i1 %t21, true
  br i1 %t22, label %ok_23, label %trap_23
trap_23:
  call void @abort()
  unreachable
ok_23:
  ret i64 %t20
edge_0:
  br label %b1
edge_1:
  br label %b2
}

define internal i64 @__hia_fn_3(i64 %p_0_0, i32 %p_0_1) {
b0:
  %t1 = call %hia.alloc @__hia_allocate(i64 %p_0_0, i1 true)
  %t2 = extractvalue %hia.alloc %t1, 0
  %t3 = extractvalue %hia.alloc %t1, 1
  br i1 %t3, label %edge_0, label %edge_1
b1:
  %p_1_0 = phi i64 [ %p_0_0, %edge_0 ]
  %p_1_1 = phi i32 [ %p_0_1, %edge_0 ]
  %p_1_2 = phi i1 [ %t3, %edge_0 ]
  %p_1_3 = phi %hia.buffer [ %t2, %edge_0 ]
  %p_1_4 = phi i8 [ 1, %edge_0 ]
  br label %edge_2
b2:
  %p_2_0 = phi i64 [ %p_0_0, %edge_1 ]
  %p_2_1 = phi i32 [ %p_0_1, %edge_1 ]
  %p_2_2 = phi i1 [ %t3, %edge_1 ]
  %p_2_3 = phi %hia.buffer [ %t2, %edge_1 ]
  %p_2_4 = phi i8 [ 1, %edge_1 ]
  %t4 = extractvalue %hia.buffer %p_2_3, 0
  call void @free(ptr %t4) nobuiltin
  %t5 = zext i8 %p_2_4 to i64
  %t6 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 1000, i64 %t5)
  %t7 = extractvalue { i64, i1 } %t6, 0
  %t8 = extractvalue { i64, i1 } %t6, 1
  %t9 = xor i1 %t8, true
  br i1 %t9, label %ok_10, label %trap_10
trap_10:
  call void @abort()
  unreachable
ok_10:
  ret i64 %t7
b3:
  %p_3_0 = phi i64 [ %p_1_0, %edge_2 ], [ %p_4_0, %edge_5 ]
  %p_3_1 = phi i32 [ %p_1_1, %edge_2 ], [ %p_4_1, %edge_5 ]
  %p_3_2 = phi %hia.buffer [ %p_1_3, %edge_2 ], [ %p_4_2, %edge_5 ]
  %p_3_3 = phi i64 [ %p_1_0, %edge_2 ], [ %p_4_3, %edge_5 ]
  %p_3_4 = phi i64 [ 0, %edge_2 ], [ %t19, %edge_5 ]
  %t11 = icmp ult i64 %p_3_4, %p_3_3
  br i1 %t11, label %edge_3, label %edge_4
b4:
  %p_4_0 = phi i64 [ %p_3_0, %edge_3 ]
  %p_4_1 = phi i32 [ %p_3_1, %edge_3 ]
  %p_4_2 = phi %hia.buffer [ %p_3_2, %edge_3 ]
  %p_4_3 = phi i64 [ %p_3_3, %edge_3 ]
  %p_4_4 = phi i64 [ %p_3_4, %edge_3 ]
  %t12 = trunc i32 %p_4_1 to i8
  %t13 = extractvalue %hia.buffer %p_4_2, 0
  %t14 = extractvalue %hia.buffer %p_4_2, 1
  %t15 = icmp ult i64 %p_4_4, %t14
  br i1 %t15, label %ok_16, label %trap_16
trap_16:
  call void @abort()
  unreachable
ok_16:
  %t17 = getelementptr i8, ptr %t13, i64 %p_4_4
  store i8 %t12, ptr %t17, align 1
  %t18 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_4_4, i64 1)
  %t19 = extractvalue { i64, i1 } %t18, 0
  %t20 = extractvalue { i64, i1 } %t18, 1
  %t21 = xor i1 %t20, true
  br i1 %t21, label %ok_22, label %trap_22
trap_22:
  call void @abort()
  unreachable
ok_22:
  br label %edge_5
b5:
  %p_5_0 = phi i64 [ %p_3_0, %edge_4 ]
  %p_5_1 = phi i32 [ %p_3_1, %edge_4 ]
  %p_5_2 = phi %hia.buffer [ %p_3_2, %edge_4 ]
  %p_5_3 = phi i64 [ %p_3_3, %edge_4 ]
  %p_5_4 = phi i64 [ %p_3_4, %edge_4 ]
  %t23 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_5_0, i64 17)
  %t24 = extractvalue { i64, i1 } %t23, 0
  %t25 = extractvalue { i64, i1 } %t23, 1
  %t26 = xor i1 %t25, true
  br i1 %t26, label %ok_27, label %trap_27
trap_27:
  call void @abort()
  unreachable
ok_27:
  %t28 = call %hia.alloc @__hia_allocate(i64 %t24, i1 true)
  %t29 = extractvalue %hia.alloc %t28, 0
  %t30 = extractvalue %hia.alloc %t28, 1
  br i1 %t30, label %edge_6, label %edge_7
b6:
  %p_6_0 = phi i64 [ %p_5_0, %edge_6 ]
  %p_6_1 = phi i32 [ %p_5_1, %edge_6 ]
  %p_6_2 = phi %hia.buffer [ %p_5_2, %edge_6 ]
  %p_6_3 = phi i1 [ %t30, %edge_6 ]
  %p_6_4 = phi %hia.buffer [ %t29, %edge_6 ]
  %p_6_5 = phi i8 [ 1, %edge_6 ]
  br label %edge_8
b7:
  %p_7_0 = phi i64 [ %p_5_0, %edge_7 ]
  %p_7_1 = phi i32 [ %p_5_1, %edge_7 ]
  %p_7_2 = phi %hia.buffer [ %p_5_2, %edge_7 ]
  %p_7_3 = phi i1 [ %t30, %edge_7 ]
  %p_7_4 = phi %hia.buffer [ %t29, %edge_7 ]
  %p_7_5 = phi i8 [ 1, %edge_7 ]
  %t31 = extractvalue %hia.buffer %p_7_4, 0
  call void @free(ptr %t31) nobuiltin
  %t32 = extractvalue %hia.buffer %p_7_2, 0
  call void @free(ptr %t32) nobuiltin
  %t33 = zext i8 %p_7_5 to i64
  %t34 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 1000, i64 %t33)
  %t35 = extractvalue { i64, i1 } %t34, 0
  %t36 = extractvalue { i64, i1 } %t34, 1
  %t37 = xor i1 %t36, true
  br i1 %t37, label %ok_38, label %trap_38
trap_38:
  call void @abort()
  unreachable
ok_38:
  ret i64 %t35
b8:
  %p_8_0 = phi i64 [ %p_6_0, %edge_8 ], [ %p_9_0, %edge_11 ]
  %p_8_1 = phi i32 [ %p_6_1, %edge_8 ], [ %p_9_1, %edge_11 ]
  %p_8_2 = phi %hia.buffer [ %p_6_2, %edge_8 ], [ %p_9_2, %edge_11 ]
  %p_8_3 = phi %hia.buffer [ %p_6_4, %edge_8 ], [ %p_9_3, %edge_11 ]
  %p_8_4 = phi i64 [ %p_6_0, %edge_8 ], [ %p_9_4, %edge_11 ]
  %p_8_5 = phi i64 [ 0, %edge_8 ], [ %t53, %edge_11 ]
  %t39 = icmp ult i64 %p_8_5, %p_8_4
  br i1 %t39, label %edge_9, label %edge_10
b9:
  %p_9_0 = phi i64 [ %p_8_0, %edge_9 ]
  %p_9_1 = phi i32 [ %p_8_1, %edge_9 ]
  %p_9_2 = phi %hia.buffer [ %p_8_2, %edge_9 ]
  %p_9_3 = phi %hia.buffer [ %p_8_3, %edge_9 ]
  %p_9_4 = phi i64 [ %p_8_4, %edge_9 ]
  %p_9_5 = phi i64 [ %p_8_5, %edge_9 ]
  %t40 = extractvalue %hia.buffer %p_9_2, 0
  %t41 = extractvalue %hia.buffer %p_9_2, 1
  %t42 = icmp ult i64 %p_9_5, %t41
  br i1 %t42, label %ok_43, label %trap_43
trap_43:
  call void @abort()
  unreachable
ok_43:
  %t44 = getelementptr i8, ptr %t40, i64 %p_9_5
  %t45 = load i8, ptr %t44, align 1
  %t46 = xor i8 %t45, 90
  %t47 = extractvalue %hia.buffer %p_9_3, 0
  %t48 = extractvalue %hia.buffer %p_9_3, 1
  %t49 = icmp ult i64 %p_9_5, %t48
  br i1 %t49, label %ok_50, label %trap_50
trap_50:
  call void @abort()
  unreachable
ok_50:
  %t51 = getelementptr i8, ptr %t47, i64 %p_9_5
  store i8 %t46, ptr %t51, align 1
  %t52 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_9_5, i64 1)
  %t53 = extractvalue { i64, i1 } %t52, 0
  %t54 = extractvalue { i64, i1 } %t52, 1
  %t55 = xor i1 %t54, true
  br i1 %t55, label %ok_56, label %trap_56
trap_56:
  call void @abort()
  unreachable
ok_56:
  br label %edge_11
b10:
  %p_10_0 = phi i64 [ %p_8_0, %edge_10 ]
  %p_10_1 = phi i32 [ %p_8_1, %edge_10 ]
  %p_10_2 = phi %hia.buffer [ %p_8_2, %edge_10 ]
  %p_10_3 = phi %hia.buffer [ %p_8_3, %edge_10 ]
  %p_10_4 = phi i64 [ %p_8_4, %edge_10 ]
  %p_10_5 = phi i64 [ %p_8_5, %edge_10 ]
  %t57 = extractvalue %hia.buffer %p_10_3, 1
  br label %edge_12
b11:
  %p_11_0 = phi i64 [ %p_10_0, %edge_12 ], [ %p_12_0, %edge_15 ]
  %p_11_1 = phi i32 [ %p_10_1, %edge_12 ], [ %p_12_1, %edge_15 ]
  %p_11_2 = phi %hia.buffer [ %p_10_2, %edge_12 ], [ %p_12_2, %edge_15 ]
  %p_11_3 = phi %hia.buffer [ %p_10_3, %edge_12 ], [ %p_12_3, %edge_15 ]
  %p_11_4 = phi i64 [ 0, %edge_12 ], [ %t67, %edge_15 ]
  %p_11_5 = phi i64 [ %t57, %edge_12 ], [ %p_12_5, %edge_15 ]
  %p_11_6 = phi i64 [ 0, %edge_12 ], [ %t72, %edge_15 ]
  %t58 = icmp ult i64 %p_11_6, %p_11_5
  br i1 %t58, label %edge_13, label %edge_14
b12:
  %p_12_0 = phi i64 [ %p_11_0, %edge_13 ]
  %p_12_1 = phi i32 [ %p_11_1, %edge_13 ]
  %p_12_2 = phi %hia.buffer [ %p_11_2, %edge_13 ]
  %p_12_3 = phi %hia.buffer [ %p_11_3, %edge_13 ]
  %p_12_4 = phi i64 [ %p_11_4, %edge_13 ]
  %p_12_5 = phi i64 [ %p_11_5, %edge_13 ]
  %p_12_6 = phi i64 [ %p_11_6, %edge_13 ]
  %t59 = extractvalue %hia.buffer %p_12_3, 0
  %t60 = extractvalue %hia.buffer %p_12_3, 1
  %t61 = icmp ult i64 %p_12_6, %t60
  br i1 %t61, label %ok_62, label %trap_62
trap_62:
  call void @abort()
  unreachable
ok_62:
  %t63 = getelementptr i8, ptr %t59, i64 %p_12_6
  %t64 = load i8, ptr %t63, align 1
  %t65 = zext i8 %t64 to i64
  %t66 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_12_4, i64 %t65)
  %t67 = extractvalue { i64, i1 } %t66, 0
  %t68 = extractvalue { i64, i1 } %t66, 1
  %t69 = xor i1 %t68, true
  br i1 %t69, label %ok_70, label %trap_70
trap_70:
  call void @abort()
  unreachable
ok_70:
  %t71 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_12_6, i64 1)
  %t72 = extractvalue { i64, i1 } %t71, 0
  %t73 = extractvalue { i64, i1 } %t71, 1
  %t74 = xor i1 %t73, true
  br i1 %t74, label %ok_75, label %trap_75
trap_75:
  call void @abort()
  unreachable
ok_75:
  br label %edge_15
b13:
  %p_13_0 = phi i64 [ %p_11_0, %edge_14 ]
  %p_13_1 = phi i32 [ %p_11_1, %edge_14 ]
  %p_13_2 = phi %hia.buffer [ %p_11_2, %edge_14 ]
  %p_13_3 = phi %hia.buffer [ %p_11_3, %edge_14 ]
  %p_13_4 = phi i64 [ %p_11_4, %edge_14 ]
  %p_13_5 = phi i64 [ %p_11_5, %edge_14 ]
  %p_13_6 = phi i64 [ %p_11_6, %edge_14 ]
  %t76 = extractvalue %hia.buffer %p_13_3, 0
  call void @free(ptr %t76) nobuiltin
  %t77 = extractvalue %hia.buffer %p_13_2, 0
  call void @free(ptr %t77) nobuiltin
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

define internal i64 @__hia_fn_4(i64 %p_0_0, i32 %p_0_1) {
b0:
  %t1 = call %hia.alloc @__hia_allocate(i64 7, i1 true)
  %t2 = extractvalue %hia.alloc %t1, 0
  %t3 = extractvalue %hia.alloc %t1, 1
  br i1 %t3, label %edge_0, label %edge_1
b1:
  %p_1_0 = phi i64 [ %p_0_0, %edge_0 ]
  %p_1_1 = phi i32 [ %p_0_1, %edge_0 ]
  %p_1_2 = phi i1 [ %t3, %edge_0 ]
  %p_1_3 = phi %hia.buffer [ %t2, %edge_0 ]
  %p_1_4 = phi i8 [ 1, %edge_0 ]
  %t4 = extractvalue %hia.buffer %p_1_3, 0
  %t5 = extractvalue %hia.buffer %p_1_3, 1
  %t6 = icmp ult i64 0, %t5
  br i1 %t6, label %ok_7, label %trap_7
trap_7:
  call void @abort()
  unreachable
ok_7:
  %t8 = getelementptr i8, ptr %t4, i64 0
  store i8 19, ptr %t8, align 1
  %t9 = call %hia.alloc @__hia_allocate(i64 %p_1_0, i1 true)
  %t10 = extractvalue %hia.alloc %t9, 0
  %t11 = extractvalue %hia.alloc %t9, 1
  br i1 %t11, label %edge_2, label %edge_3
b2:
  %p_2_0 = phi i64 [ %p_0_0, %edge_1 ]
  %p_2_1 = phi i32 [ %p_0_1, %edge_1 ]
  %p_2_2 = phi i1 [ %t3, %edge_1 ]
  %p_2_3 = phi %hia.buffer [ %t2, %edge_1 ]
  %p_2_4 = phi i8 [ 1, %edge_1 ]
  %t12 = extractvalue %hia.buffer %p_2_3, 0
  call void @free(ptr %t12) nobuiltin
  %t13 = zext i8 %p_2_4 to i64
  %t14 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 100, i64 %t13)
  %t15 = extractvalue { i64, i1 } %t14, 0
  %t16 = extractvalue { i64, i1 } %t14, 1
  %t17 = xor i1 %t16, true
  br i1 %t17, label %ok_18, label %trap_18
trap_18:
  call void @abort()
  unreachable
ok_18:
  ret i64 %t15
b3:
  %p_3_0 = phi i64 [ %p_1_0, %edge_2 ]
  %p_3_1 = phi i32 [ %p_1_1, %edge_2 ]
  %p_3_2 = phi %hia.buffer [ %p_1_3, %edge_2 ]
  %p_3_3 = phi i1 [ %t11, %edge_2 ]
  %p_3_4 = phi %hia.buffer [ %t10, %edge_2 ]
  %p_3_5 = phi i8 [ 1, %edge_2 ]
  %t19 = call %hia.buffer @__hia_fn_0(%hia.buffer %p_3_4)
  %t20 = icmp ne i32 %p_3_1, 0
  br i1 %t20, label %edge_4, label %edge_5
b4:
  %p_4_0 = phi i64 [ %p_1_0, %edge_3 ]
  %p_4_1 = phi i32 [ %p_1_1, %edge_3 ]
  %p_4_2 = phi %hia.buffer [ %p_1_3, %edge_3 ]
  %p_4_3 = phi i1 [ %t11, %edge_3 ]
  %p_4_4 = phi %hia.buffer [ %t10, %edge_3 ]
  %p_4_5 = phi i8 [ 1, %edge_3 ]
  %t21 = extractvalue %hia.buffer %p_4_4, 0
  call void @free(ptr %t21) nobuiltin
  %t22 = extractvalue %hia.buffer %p_4_2, 0
  call void @free(ptr %t22) nobuiltin
  %t23 = zext i8 %p_4_5 to i64
  ret i64 %t23
b5:
  %p_5_0 = phi i64 [ %p_3_0, %edge_4 ]
  %p_5_1 = phi i32 [ %p_3_1, %edge_4 ]
  %p_5_2 = phi %hia.buffer [ %p_3_2, %edge_4 ]
  %p_5_3 = phi %hia.buffer [ %t19, %edge_4 ]
  %t24 = extractvalue %hia.buffer %p_5_3, 0
  call void @free(ptr %t24) nobuiltin
  %t25 = extractvalue %hia.buffer %p_5_2, 0
  call void @free(ptr %t25) nobuiltin
  ret i64 2
b6:
  %p_6_0 = phi i64 [ %p_3_0, %edge_5 ]
  %p_6_1 = phi i32 [ %p_3_1, %edge_5 ]
  %p_6_2 = phi %hia.buffer [ %p_3_2, %edge_5 ]
  %p_6_3 = phi %hia.buffer [ %t19, %edge_5 ]
  %t26 = extractvalue %hia.buffer %p_6_3, 1
  %t27 = extractvalue %hia.buffer %p_6_2, 0
  %t28 = extractvalue %hia.buffer %p_6_2, 1
  %t29 = icmp ult i64 0, %t28
  br i1 %t29, label %ok_30, label %trap_30
trap_30:
  call void @abort()
  unreachable
ok_30:
  %t31 = getelementptr i8, ptr %t27, i64 0
  %t32 = load i8, ptr %t31, align 1
  %t33 = zext i8 %t32 to i64
  %t34 = call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %t26, i64 %t33)
  %t35 = extractvalue { i64, i1 } %t34, 0
  %t36 = extractvalue { i64, i1 } %t34, 1
  %t37 = xor i1 %t36, true
  br i1 %t37, label %ok_38, label %trap_38
trap_38:
  call void @abort()
  unreachable
ok_38:
  %t39 = extractvalue %hia.buffer %p_6_3, 0
  call void @free(ptr %t39) nobuiltin
  %t40 = extractvalue %hia.buffer %p_6_2, 0
  call void @free(ptr %t40) nobuiltin
  ret i64 %t35
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
  br label %b6
}

define i64 @full_lifecycle(i64 %a0, i32 %a1) {
entry:
  %result = call i64 @__hia_fn_1(i64 %a0, i32 %a1)
  ret i64 %result
}

define i64 @constructor_error(i64 %a0, i32 %a1) {
entry:
  %result = call i64 @__hia_fn_2(i64 %a0, i32 %a1)
  ret i64 %result
}

define i64 @two_stage(i64 %a0, i32 %a1) {
entry:
  %result = call i64 @__hia_fn_3(i64 %a0, i32 %a1)
  ret i64 %result
}

define i64 @two_alloc(i64 %a0, i32 %a1) {
entry:
  %result = call i64 @__hia_fn_4(i64 %a0, i32 %a1)
  ret i64 %result
}
