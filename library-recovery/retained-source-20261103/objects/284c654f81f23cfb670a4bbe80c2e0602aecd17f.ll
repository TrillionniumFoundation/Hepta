; Standalone HIA: verified core -> LLVM. No source AST or Rust safety gate.
target triple = "x86_64-unknown-linux-gnu"
%hia.buffer = type { ptr, i64 }
%hia.alloc = type { %hia.buffer, i1 }
declare void @abort() noreturn
declare noalias ptr @calloc(i64, i64) "no-builtins"
declare noalias ptr @malloc(i64) "no-builtins"
declare void @free(ptr) "no-builtins"

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

define internal i32 @__hia_fn_0(i32 %p_0_0, i8 %p_0_1, i32 %p_0_2) {
b0:
  %t1 = zext i8 %p_0_1 to i32
  %t2 = xor i32 %p_0_0, %t1
  %t3 = trunc i64 0 to i32
  br label %edge_0
b1:
  %p_1_0 = phi i32 [ %p_0_0, %edge_0 ], [ %p_6_0, %edge_7 ]
  %p_1_1 = phi i8 [ %p_0_1, %edge_0 ], [ %p_6_1, %edge_7 ]
  %p_1_2 = phi i32 [ %p_0_2, %edge_0 ], [ %p_6_2, %edge_7 ]
  %p_1_3 = phi i32 [ %p_0_0, %edge_0 ], [ %p_6_3, %edge_7 ]
  %p_1_4 = phi i8 [ %p_0_1, %edge_0 ], [ %p_6_4, %edge_7 ]
  %p_1_5 = phi i32 [ %p_0_2, %edge_0 ], [ %p_6_5, %edge_7 ]
  %p_1_6 = phi i32 [ %t2, %edge_0 ], [ %p_6_6, %edge_7 ]
  %p_1_7 = phi i32 [ %t3, %edge_0 ], [ %t20, %edge_7 ]
  %t4 = trunc i64 8 to i32
  %t5 = icmp ult i32 %p_1_7, %t4
  br i1 %t5, label %edge_1, label %edge_2
b2:
  %p_2_0 = phi i32 [ %p_1_0, %edge_1 ]
  %p_2_1 = phi i8 [ %p_1_1, %edge_1 ]
  %p_2_2 = phi i32 [ %p_1_2, %edge_1 ]
  %p_2_3 = phi i32 [ %p_1_3, %edge_1 ]
  %p_2_4 = phi i8 [ %p_1_4, %edge_1 ]
  %p_2_5 = phi i32 [ %p_1_5, %edge_1 ]
  %p_2_6 = phi i32 [ %p_1_6, %edge_1 ]
  %p_2_7 = phi i32 [ %p_1_7, %edge_1 ]
  %t6 = trunc i64 1 to i32
  %t7 = and i32 %p_2_6, %t6
  %t8 = trunc i64 0 to i32
  %t9 = icmp ne i32 %t7, %t8
  br i1 %t9, label %edge_3, label %edge_4
b3:
  %p_3_0 = phi i32 [ %p_1_0, %edge_2 ]
  %p_3_1 = phi i8 [ %p_1_1, %edge_2 ]
  %p_3_2 = phi i32 [ %p_1_2, %edge_2 ]
  %p_3_3 = phi i32 [ %p_1_3, %edge_2 ]
  %p_3_4 = phi i8 [ %p_1_4, %edge_2 ]
  %p_3_5 = phi i32 [ %p_1_5, %edge_2 ]
  %p_3_6 = phi i32 [ %p_1_6, %edge_2 ]
  %p_3_7 = phi i32 [ %p_1_7, %edge_2 ]
  ret i32 %p_3_6
b4:
  %p_4_0 = phi i32 [ %p_2_0, %edge_3 ]
  %p_4_1 = phi i8 [ %p_2_1, %edge_3 ]
  %p_4_2 = phi i32 [ %p_2_2, %edge_3 ]
  %p_4_3 = phi i32 [ %p_2_3, %edge_3 ]
  %p_4_4 = phi i8 [ %p_2_4, %edge_3 ]
  %p_4_5 = phi i32 [ %p_2_5, %edge_3 ]
  %p_4_6 = phi i32 [ %p_2_6, %edge_3 ]
  %p_4_7 = phi i32 [ %p_2_7, %edge_3 ]
  %t10 = trunc i64 1 to i32
  %t11 = icmp ult i32 %t10, 32
  br i1 %t11, label %ok_12, label %trap_12
trap_12:
  call void @abort()
  unreachable
ok_12:
  %t13 = lshr i32 %p_4_6, %t10
  %t14 = xor i32 %t13, %p_4_5
  br label %edge_5
b5:
  %p_5_0 = phi i32 [ %p_2_0, %edge_4 ]
  %p_5_1 = phi i8 [ %p_2_1, %edge_4 ]
  %p_5_2 = phi i32 [ %p_2_2, %edge_4 ]
  %p_5_3 = phi i32 [ %p_2_3, %edge_4 ]
  %p_5_4 = phi i8 [ %p_2_4, %edge_4 ]
  %p_5_5 = phi i32 [ %p_2_5, %edge_4 ]
  %p_5_6 = phi i32 [ %p_2_6, %edge_4 ]
  %p_5_7 = phi i32 [ %p_2_7, %edge_4 ]
  %t15 = trunc i64 1 to i32
  %t16 = icmp ult i32 %t15, 32
  br i1 %t16, label %ok_17, label %trap_17
trap_17:
  call void @abort()
  unreachable
ok_17:
  %t18 = lshr i32 %p_5_6, %t15
  br label %edge_6
b6:
  %p_6_0 = phi i32 [ %p_4_0, %edge_5 ], [ %p_5_0, %edge_6 ]
  %p_6_1 = phi i8 [ %p_4_1, %edge_5 ], [ %p_5_1, %edge_6 ]
  %p_6_2 = phi i32 [ %p_4_2, %edge_5 ], [ %p_5_2, %edge_6 ]
  %p_6_3 = phi i32 [ %p_4_3, %edge_5 ], [ %p_5_3, %edge_6 ]
  %p_6_4 = phi i8 [ %p_4_4, %edge_5 ], [ %p_5_4, %edge_6 ]
  %p_6_5 = phi i32 [ %p_4_5, %edge_5 ], [ %p_5_5, %edge_6 ]
  %p_6_6 = phi i32 [ %t14, %edge_5 ], [ %t18, %edge_6 ]
  %p_6_7 = phi i32 [ %p_4_7, %edge_5 ], [ %p_5_7, %edge_6 ]
  %t19 = trunc i64 1 to i32
  %t20 = add i32 %p_6_7, %t19
  br label %edge_7
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
edge_6:
  br label %b6
edge_7:
  br label %b1
}

define internal i64 @__hia_fn_1(i64 %p_0_0, i64 %p_0_1, i32 %p_0_2, i32 %p_0_3) {
b0:
  %t1 = trunc i64 0 to i32
  %t2 = sext i32 %t1 to i64
  %t3 = icmp eq i64 %p_0_0, %t2
  br i1 %t3, label %edge_0, label %edge_1
b1:
  %p_1_0 = phi i64 [ %p_0_0, %edge_0 ]
  %p_1_1 = phi i64 [ %p_0_1, %edge_0 ]
  %p_1_2 = phi i32 [ %p_0_2, %edge_0 ]
  %p_1_3 = phi i32 [ %p_0_3, %edge_0 ]
  %p_1_4 = phi i64 [ %p_0_0, %edge_0 ]
  %p_1_5 = phi i64 [ %p_0_1, %edge_0 ]
  %p_1_6 = phi i32 [ %p_0_2, %edge_0 ]
  %p_1_7 = phi i32 [ %p_0_3, %edge_0 ]
  %t4 = zext i32 %p_1_6 to i64
  ret i64 %t4
b2:
  %p_2_0 = phi i64 [ %p_0_0, %edge_1 ]
  %p_2_1 = phi i64 [ %p_0_1, %edge_1 ]
  %p_2_2 = phi i32 [ %p_0_2, %edge_1 ]
  %p_2_3 = phi i32 [ %p_0_3, %edge_1 ]
  %p_2_4 = phi i64 [ %p_0_0, %edge_1 ]
  %p_2_5 = phi i64 [ %p_0_1, %edge_1 ]
  %p_2_6 = phi i32 [ %p_0_2, %edge_1 ]
  %p_2_7 = phi i32 [ %p_0_3, %edge_1 ]
  %t5 = trunc i64 8 to i32
  %t6 = sext i32 %t5 to i64
  %t7 = icmp ugt i64 %p_2_4, %t6
  br i1 %t7, label %edge_2, label %edge_3
b3:
  %p_3_0 = phi i64 [ %p_2_0, %edge_2 ]
  %p_3_1 = phi i64 [ %p_2_1, %edge_2 ]
  %p_3_2 = phi i32 [ %p_2_2, %edge_2 ]
  %p_3_3 = phi i32 [ %p_2_3, %edge_2 ]
  %p_3_4 = phi i64 [ %p_2_4, %edge_2 ]
  %p_3_5 = phi i64 [ %p_2_5, %edge_2 ]
  %p_3_6 = phi i32 [ %p_2_6, %edge_2 ]
  %p_3_7 = phi i32 [ %p_2_7, %edge_2 ]
  ret i64 4294967296
b4:
  %p_4_0 = phi i64 [ %p_2_0, %edge_3 ]
  %p_4_1 = phi i64 [ %p_2_1, %edge_3 ]
  %p_4_2 = phi i32 [ %p_2_2, %edge_3 ]
  %p_4_3 = phi i32 [ %p_2_3, %edge_3 ]
  %p_4_4 = phi i64 [ %p_2_4, %edge_3 ]
  %p_4_5 = phi i64 [ %p_2_5, %edge_3 ]
  %p_4_6 = phi i32 [ %p_2_6, %edge_3 ]
  %p_4_7 = phi i32 [ %p_2_7, %edge_3 ]
  %t8 = call %hia.alloc @__hia_allocate(i64 %p_4_4, i1 true)
  %t9 = extractvalue %hia.alloc %t8, 0
  %t10 = extractvalue %hia.alloc %t8, 1
  %t11 = select i1 %t10, i64 %p_4_4, i64 0
  %t12 = insertvalue %hia.buffer %t9, i64 %t11, 1
  br i1 %t10, label %edge_4, label %edge_5
b5:
  %p_5_0 = phi i64 [ %p_4_0, %edge_4 ]
  %p_5_1 = phi i64 [ %p_4_1, %edge_4 ]
  %p_5_2 = phi i32 [ %p_4_2, %edge_4 ]
  %p_5_3 = phi i32 [ %p_4_3, %edge_4 ]
  %p_5_4 = phi i64 [ %p_4_4, %edge_4 ]
  %p_5_5 = phi i64 [ %p_4_5, %edge_4 ]
  %p_5_6 = phi i32 [ %p_4_6, %edge_4 ]
  %p_5_7 = phi i32 [ %p_4_7, %edge_4 ]
  %p_5_8 = phi i1 [ %t10, %edge_4 ]
  %p_5_9 = phi %hia.buffer [ %t12, %edge_4 ]
  %p_5_10 = phi i8 [ 1, %edge_4 ]
  %t13 = trunc i64 0 to i32
  %t14 = sext i32 %t13 to i64
  br label %edge_6
b6:
  %p_6_0 = phi i64 [ %p_4_0, %edge_5 ]
  %p_6_1 = phi i64 [ %p_4_1, %edge_5 ]
  %p_6_2 = phi i32 [ %p_4_2, %edge_5 ]
  %p_6_3 = phi i32 [ %p_4_3, %edge_5 ]
  %p_6_4 = phi i64 [ %p_4_4, %edge_5 ]
  %p_6_5 = phi i64 [ %p_4_5, %edge_5 ]
  %p_6_6 = phi i32 [ %p_4_6, %edge_5 ]
  %p_6_7 = phi i32 [ %p_4_7, %edge_5 ]
  %p_6_8 = phi i1 [ %t10, %edge_5 ]
  %p_6_9 = phi %hia.buffer [ %t12, %edge_5 ]
  %p_6_10 = phi i8 [ 1, %edge_5 ]
  %t15 = extractvalue %hia.buffer %p_6_9, 0
  %t16 = icmp ne ptr %t15, null
  br i1 %t16, label %drop_nonnull_17, label %drop_after_17
drop_nonnull_17:
  call void @free(ptr %t15) nobuiltin
  br label %drop_after_17
drop_after_17:
  ret i64 8589934592
b7:
  %p_7_0 = phi i64 [ %p_5_0, %edge_6 ], [ %p_8_0, %edge_9 ]
  %p_7_1 = phi i64 [ %p_5_1, %edge_6 ], [ %p_8_1, %edge_9 ]
  %p_7_2 = phi i32 [ %p_5_2, %edge_6 ], [ %p_8_2, %edge_9 ]
  %p_7_3 = phi i32 [ %p_5_3, %edge_6 ], [ %p_8_3, %edge_9 ]
  %p_7_4 = phi i64 [ %p_5_4, %edge_6 ], [ %p_8_4, %edge_9 ]
  %p_7_5 = phi i64 [ %p_5_5, %edge_6 ], [ %p_8_5, %edge_9 ]
  %p_7_6 = phi i32 [ %p_5_6, %edge_6 ], [ %p_8_6, %edge_9 ]
  %p_7_7 = phi i32 [ %p_5_7, %edge_6 ], [ %p_8_7, %edge_9 ]
  %p_7_8 = phi %hia.buffer [ %p_5_9, %edge_6 ], [ %p_8_8, %edge_9 ]
  %p_7_9 = phi i64 [ %t14, %edge_6 ], [ %t29, %edge_9 ]
  %t18 = icmp ult i64 %p_7_9, %p_7_4
  br i1 %t18, label %edge_7, label %edge_8
b8:
  %p_8_0 = phi i64 [ %p_7_0, %edge_7 ]
  %p_8_1 = phi i64 [ %p_7_1, %edge_7 ]
  %p_8_2 = phi i32 [ %p_7_2, %edge_7 ]
  %p_8_3 = phi i32 [ %p_7_3, %edge_7 ]
  %p_8_4 = phi i64 [ %p_7_4, %edge_7 ]
  %p_8_5 = phi i64 [ %p_7_5, %edge_7 ]
  %p_8_6 = phi i32 [ %p_7_6, %edge_7 ]
  %p_8_7 = phi i32 [ %p_7_7, %edge_7 ]
  %p_8_8 = phi %hia.buffer [ %p_7_8, %edge_7 ]
  %p_8_9 = phi i64 [ %p_7_9, %edge_7 ]
  %t19 = mul i64 %p_8_9, 8
  %t20 = icmp ult i64 %t19, 64
  br i1 %t20, label %ok_21, label %trap_21
trap_21:
  call void @abort()
  unreachable
ok_21:
  %t22 = lshr i64 %p_8_5, %t19
  %t23 = trunc i64 %t22 to i8
  %t24 = extractvalue %hia.buffer %p_8_8, 0
  %t25 = extractvalue %hia.buffer %p_8_8, 1
  %t26 = icmp ult i64 %p_8_9, %t25
  br i1 %t26, label %ok_27, label %trap_27
trap_27:
  call void @abort()
  unreachable
ok_27:
  %t28 = getelementptr i8, ptr %t24, i64 %p_8_9
  store i8 %t23, ptr %t28, align 1
  %t29 = add i64 %p_8_9, 1
  br label %edge_9
b9:
  %p_9_0 = phi i64 [ %p_7_0, %edge_8 ]
  %p_9_1 = phi i64 [ %p_7_1, %edge_8 ]
  %p_9_2 = phi i32 [ %p_7_2, %edge_8 ]
  %p_9_3 = phi i32 [ %p_7_3, %edge_8 ]
  %p_9_4 = phi i64 [ %p_7_4, %edge_8 ]
  %p_9_5 = phi i64 [ %p_7_5, %edge_8 ]
  %p_9_6 = phi i32 [ %p_7_6, %edge_8 ]
  %p_9_7 = phi i32 [ %p_7_7, %edge_8 ]
  %p_9_8 = phi %hia.buffer [ %p_7_8, %edge_8 ]
  %p_9_9 = phi i64 [ %p_7_9, %edge_8 ]
  %t30 = trunc i64 0 to i32
  %t31 = sext i32 %t30 to i64
  br label %edge_10
b10:
  %p_10_0 = phi i64 [ %p_9_0, %edge_10 ], [ %p_11_0, %edge_13 ]
  %p_10_1 = phi i64 [ %p_9_1, %edge_10 ], [ %p_11_1, %edge_13 ]
  %p_10_2 = phi i32 [ %p_9_2, %edge_10 ], [ %p_11_2, %edge_13 ]
  %p_10_3 = phi i32 [ %p_9_3, %edge_10 ], [ %p_11_3, %edge_13 ]
  %p_10_4 = phi i64 [ %p_9_4, %edge_10 ], [ %p_11_4, %edge_13 ]
  %p_10_5 = phi i64 [ %p_9_5, %edge_10 ], [ %p_11_5, %edge_13 ]
  %p_10_6 = phi i32 [ %p_9_6, %edge_10 ], [ %p_11_6, %edge_13 ]
  %p_10_7 = phi i32 [ %p_9_7, %edge_10 ], [ %p_11_7, %edge_13 ]
  %p_10_8 = phi %hia.buffer [ %p_9_8, %edge_10 ], [ %p_11_8, %edge_13 ]
  %p_10_9 = phi i64 [ %p_9_9, %edge_10 ], [ %p_11_9, %edge_13 ]
  %p_10_10 = phi i32 [ %p_9_6, %edge_10 ], [ %t39, %edge_13 ]
  %p_10_11 = phi i64 [ %t31, %edge_10 ], [ %t40, %edge_13 ]
  %t32 = icmp ult i64 %p_10_11, %p_10_4
  br i1 %t32, label %edge_11, label %edge_12
b11:
  %p_11_0 = phi i64 [ %p_10_0, %edge_11 ]
  %p_11_1 = phi i64 [ %p_10_1, %edge_11 ]
  %p_11_2 = phi i32 [ %p_10_2, %edge_11 ]
  %p_11_3 = phi i32 [ %p_10_3, %edge_11 ]
  %p_11_4 = phi i64 [ %p_10_4, %edge_11 ]
  %p_11_5 = phi i64 [ %p_10_5, %edge_11 ]
  %p_11_6 = phi i32 [ %p_10_6, %edge_11 ]
  %p_11_7 = phi i32 [ %p_10_7, %edge_11 ]
  %p_11_8 = phi %hia.buffer [ %p_10_8, %edge_11 ]
  %p_11_9 = phi i64 [ %p_10_9, %edge_11 ]
  %p_11_10 = phi i32 [ %p_10_10, %edge_11 ]
  %p_11_11 = phi i64 [ %p_10_11, %edge_11 ]
  %t33 = extractvalue %hia.buffer %p_11_8, 0
  %t34 = extractvalue %hia.buffer %p_11_8, 1
  %t35 = icmp ult i64 %p_11_11, %t34
  br i1 %t35, label %ok_36, label %trap_36
trap_36:
  call void @abort()
  unreachable
ok_36:
  %t37 = getelementptr i8, ptr %t33, i64 %p_11_11
  %t38 = load i8, ptr %t37, align 1
  %t39 = call i32 @__hia_fn_0(i32 %p_11_10, i8 %t38, i32 %p_11_7)
  %t40 = add i64 %p_11_11, 1
  br label %edge_13
b12:
  %p_12_0 = phi i64 [ %p_10_0, %edge_12 ]
  %p_12_1 = phi i64 [ %p_10_1, %edge_12 ]
  %p_12_2 = phi i32 [ %p_10_2, %edge_12 ]
  %p_12_3 = phi i32 [ %p_10_3, %edge_12 ]
  %p_12_4 = phi i64 [ %p_10_4, %edge_12 ]
  %p_12_5 = phi i64 [ %p_10_5, %edge_12 ]
  %p_12_6 = phi i32 [ %p_10_6, %edge_12 ]
  %p_12_7 = phi i32 [ %p_10_7, %edge_12 ]
  %p_12_8 = phi %hia.buffer [ %p_10_8, %edge_12 ]
  %p_12_9 = phi i64 [ %p_10_9, %edge_12 ]
  %p_12_10 = phi i32 [ %p_10_10, %edge_12 ]
  %p_12_11 = phi i64 [ %p_10_11, %edge_12 ]
  %t41 = extractvalue %hia.buffer %p_12_8, 0
  %t42 = icmp ne ptr %t41, null
  br i1 %t42, label %drop_nonnull_43, label %drop_after_43
drop_nonnull_43:
  call void @free(ptr %t41) nobuiltin
  br label %drop_after_43
drop_after_43:
  %t44 = zext i32 %p_12_10 to i64
  ret i64 %t44
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
edge_6:
  br label %b7
edge_7:
  br label %b8
edge_8:
  br label %b9
edge_9:
  br label %b7
edge_10:
  br label %b10
edge_11:
  br label %b11
edge_12:
  br label %b12
edge_13:
  br label %b10
}

define internal i64 @__hia_fn_2(i64 %p_0_0, i64 %p_0_1, i32 %p_0_2, i32 %p_0_3) {
b0:
  %t1 = trunc i64 1 to i32
  %t2 = icmp eq i32 %p_0_3, %t1
  br i1 %t2, label %edge_0, label %edge_1
b1:
  %p_1_0 = phi i64 [ %p_0_0, %edge_0 ]
  %p_1_1 = phi i64 [ %p_0_1, %edge_0 ]
  %p_1_2 = phi i32 [ %p_0_2, %edge_0 ]
  %p_1_3 = phi i32 [ %p_0_3, %edge_0 ]
  %p_1_4 = phi i64 [ %p_0_0, %edge_0 ]
  %p_1_5 = phi i64 [ %p_0_1, %edge_0 ]
  %p_1_6 = phi i32 [ %p_0_2, %edge_0 ]
  %p_1_7 = phi i32 [ %p_0_3, %edge_0 ]
  %t3 = trunc i64 3988292384 to i32
  %t4 = call i64 @__hia_fn_1(i64 %p_1_4, i64 %p_1_5, i32 %p_1_6, i32 %t3)
  ret i64 %t4
b2:
  %p_2_0 = phi i64 [ %p_0_0, %edge_1 ]
  %p_2_1 = phi i64 [ %p_0_1, %edge_1 ]
  %p_2_2 = phi i32 [ %p_0_2, %edge_1 ]
  %p_2_3 = phi i32 [ %p_0_3, %edge_1 ]
  %p_2_4 = phi i64 [ %p_0_0, %edge_1 ]
  %p_2_5 = phi i64 [ %p_0_1, %edge_1 ]
  %p_2_6 = phi i32 [ %p_0_2, %edge_1 ]
  %p_2_7 = phi i32 [ %p_0_3, %edge_1 ]
  %t5 = trunc i64 2 to i32
  %t6 = icmp eq i32 %p_2_7, %t5
  br i1 %t6, label %edge_2, label %edge_3
b3:
  %p_3_0 = phi i64 [ %p_2_0, %edge_2 ]
  %p_3_1 = phi i64 [ %p_2_1, %edge_2 ]
  %p_3_2 = phi i32 [ %p_2_2, %edge_2 ]
  %p_3_3 = phi i32 [ %p_2_3, %edge_2 ]
  %p_3_4 = phi i64 [ %p_2_4, %edge_2 ]
  %p_3_5 = phi i64 [ %p_2_5, %edge_2 ]
  %p_3_6 = phi i32 [ %p_2_6, %edge_2 ]
  %p_3_7 = phi i32 [ %p_2_7, %edge_2 ]
  %t7 = trunc i64 2197175160 to i32
  %t8 = call i64 @__hia_fn_1(i64 %p_3_4, i64 %p_3_5, i32 %p_3_6, i32 %t7)
  ret i64 %t8
b4:
  %p_4_0 = phi i64 [ %p_2_0, %edge_3 ]
  %p_4_1 = phi i64 [ %p_2_1, %edge_3 ]
  %p_4_2 = phi i32 [ %p_2_2, %edge_3 ]
  %p_4_3 = phi i32 [ %p_2_3, %edge_3 ]
  %p_4_4 = phi i64 [ %p_2_4, %edge_3 ]
  %p_4_5 = phi i64 [ %p_2_5, %edge_3 ]
  %p_4_6 = phi i32 [ %p_2_6, %edge_3 ]
  %p_4_7 = phi i32 [ %p_2_7, %edge_3 ]
  ret i64 12884901888
edge_0:
  br label %b1
edge_1:
  br label %b2
edge_2:
  br label %b3
edge_3:
  br label %b4
}

define i32 @c_checksum_byte(i32 %a0, i8 zeroext %a1, i32 %a2) {
entry:
  %result = call i32 @__hia_fn_0(i32 %a0, i8 %a1, i32 %a2)
  ret i32 %result
}

define i64 @c_checksum_chunk(i64 %a0, i64 %a1, i32 %a2, i32 %a3) {
entry:
  %result = call i64 @__hia_fn_1(i64 %a0, i64 %a1, i32 %a2, i32 %a3)
  ret i64 %result
}

define i64 @c_checksum_chunk_v2(i64 %a0, i64 %a1, i32 %a2, i32 %a3) {
entry:
  %result = call i64 @__hia_fn_2(i64 %a0, i64 %a1, i32 %a2, i32 %a3)
  ret i64 %result
}
