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

define internal i32 @__hia_fn_0(i32 %p_0_0, i32 %p_0_1) {
b0:
  %t1 = icmp ugt i32 %p_0_0, %p_0_1
  br i1 %t1, label %edge_0, label %edge_1
b1:
  %p_1_0 = phi i32 [ %p_0_0, %edge_0 ]
  br label %edge_2
b2:
  %p_2_0 = phi i32 [ %p_0_1, %edge_1 ]
  br label %edge_3
b3:
  %p_3_0 = phi i32 [ %p_1_0, %edge_2 ], [ %p_2_0, %edge_3 ]
  ret i32 %p_3_0
edge_0:
  br label %b1
edge_1:
  br label %b2
edge_2:
  br label %b3
edge_3:
  br label %b3
}

define i32 @selected(i32 %a0, i32 %a1) {
entry:
  %result = call i32 @__hia_fn_0(i32 %a0, i32 %a1)
  ret i32 %result
}
