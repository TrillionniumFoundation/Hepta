; Module graph fixture for the systems codec. Opaque pointers express the
; recursive node through a self-referencing global, not an unsized by-value type.
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"
%node = type { i32, ptr }
%record = type { %node, [3 x i8] }
$fixture = comdat any
@head = global %node { i32 7, ptr @head }, comdat($fixture), align 8
@record = internal global %record zeroinitializer, align 8
@head_alias = alias %node, ptr @head
@head_next_address = global ptr getelementptr inbounds (%node, ptr @head, i64 0, i32 1), align 8
@head_integer_address = global i64 ptrtoint (ptr @head to i64), align 8
@binary_bytes = private unnamed_addr constant [8 x i8] c"\00\01\7F\80\FE\FFhi", align 1
@other_space = addrspace(1) global i32 5, align 4
@choice = ifunc i32 (), ptr @resolver

declare void @take_node(ptr byval(%node) align 8) nounwind
declare void @give_node(ptr sret(%node) align 8) nounwind
declare range(i32 0, 16) i32 @bounded(i32 range(i32 0, 8)) nounwind
declare void @initialize(ptr initializes((0, 4), (8, 12))) nounwind

define internal ptr @resolver() {
entry:
  ret ptr @implementation
}
define internal i32 @implementation() {
entry:
  ret i32 7
}

define i32 @typed_attributes(ptr %out, ptr %input, i32 %n) #0 {
entry:
  call void @take_node(ptr byval(%node) align 8 %input)
  call void @give_node(ptr sret(%node) align 8 %out)
  call void @initialize(ptr initializes((0, 4), (8, 12)) %out)
  %value = call range(i32 0, 16) i32 @bounded(i32 range(i32 0, 8) %n)
  ret i32 %value
}

define i32 @alias_metadata(ptr %left, ptr %right) {
entry:
  %a = load i32, ptr %left, align 4, !alias.scope !0, !noalias !3, !range !5
  %b = load i32, ptr %right, align 4, !alias.scope !3, !noalias !0
  %sum = add i32 %a, %b
  ret i32 %sum
}

define i32 @loop_metadata(i32 %count) {
entry:
  br label %loop
loop:
  %n = phi i32 [0, %entry], [%next, %loop]
  %next = add i32 %n, 1
  %done = icmp uge i32 %next, %count
  br i1 %done, label %exit, label %loop, !llvm.loop !6
exit:
  ret i32 %next
}

attributes #0 = { nounwind memory(argmem: readwrite) "hia.fixture"="byte-string" }
!hia.fixture = !{!1, !4}
!0 = !{!1}
!1 = distinct !{!1, !2, !"left scope"}
!2 = distinct !{!2, !"alias domain"}
!3 = !{!4}
!4 = distinct !{!4, !2, !"right scope"}
!5 = !{i32 0, i32 16}
!6 = distinct !{!6, !7}
!7 = !{!"llvm.loop.unroll.disable"}
