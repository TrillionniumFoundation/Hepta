target triple = "x86_64-unknown-linux-gnu"
declare ptr @calloc(i64, i64)
declare void @free(ptr)
declare void @abort() noreturn

define zeroext i8 @swap_bytes(i64 %length, i64 %left, i64 %right, i64 %probe) {
entry:
  %five = icmp eq i64 %length, 5
  br i1 %five, label %alloc, label %abort_block
alloc:
  %buffer = call ptr @calloc(i64 1, i64 %length)
  %nonnull = icmp ne ptr %buffer, null
  br i1 %nonnull, label %init, label %abort_block
init:
  %p0 = getelementptr i8, ptr %buffer, i64 0
  %p1 = getelementptr i8, ptr %buffer, i64 1
  %p2 = getelementptr i8, ptr %buffer, i64 2
  %p3 = getelementptr i8, ptr %buffer, i64 3
  %p4 = getelementptr i8, ptr %buffer, i64 4
  store i8 11, ptr %p0, align 1
  store i8 22, ptr %p1, align 1
  store i8 33, ptr %p2, align 1
  store i8 44, ptr %p3, align 1
  store i8 55, ptr %p4, align 1
  %left_ok = icmp ult i64 %left, %length
  br i1 %left_ok, label %guard_right, label %abort_block
guard_right:
  %right_ok = icmp ult i64 %right, %length
  br i1 %right_ok, label %checked, label %abort_block
checked:
  %pl = getelementptr i8, ptr %buffer, i64 %left
  %pr = getelementptr i8, ptr %buffer, i64 %right
  %old_l = load i8, ptr %pl, align 1
  %old_r = load i8, ptr %pr, align 1
  store i8 %old_r, ptr %pl, align 1
  store i8 %old_l, ptr %pr, align 1
  %probe_ok = icmp ult i64 %probe, %length
  br i1 %probe_ok, label %return_byte, label %abort_block
return_byte:
  %pp = getelementptr i8, ptr %buffer, i64 %probe
  %answer = load i8, ptr %pp, align 1
  call void @free(ptr %buffer)
  ret i8 %answer
abort_block:
  call void @abort()
  unreachable
}
