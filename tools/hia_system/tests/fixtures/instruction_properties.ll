; Typed systems instruction coverage; not executed as an application.
; Every executable LLVM20 opcode except callbr is present. callbr is generated
; from asm_goto.c so inline-assembly constraints come from the pinned frontend.
target triple = "x86_64-unknown-linux-gnu"
@data = global i64 9, align 16
@destinations = constant [2 x ptr] [ptr blockaddress(@indirect, %left), ptr blockaddress(@indirect, %right)]

declare i32 @called(i32)
declare fastcc signext i32 @fast_called(i32 signext) nounwind
declare void @may_throw()
declare i32 @__gxx_personality_v0(...)
declare i32 @__CxxFrameHandler3(...)

define i64 @integer_ops(i64 %a, i64 %b) {
entry:
  %add = add nuw nsw i64 %a, %b
  %sub = sub nuw nsw i64 %a, %b
  %mul = mul nuw nsw i64 %a, %b
  %udiv = udiv exact i64 %a, %b
  %sdiv = sdiv exact i64 %a, %b
  %urem = urem i64 %a, %b
  %srem = srem i64 %a, %b
  %shl = shl nuw nsw i64 %a, 1
  %lshr = lshr exact i64 %a, 1
  %ashr = ashr exact i64 %a, 1
  %and = and i64 %a, %b
  %or = or disjoint i64 %a, %b
  %xor = xor i64 %a, %b
  %compare = icmp samesign sgt i64 %a, %b
  %choose = select i1 %compare, i64 %add, i64 %sub
  %frozen = freeze i64 %choose
  ret i64 %frozen
}

define double @float_ops(double %a, double %b) {
entry:
  %neg = fneg fast double %a
  %add = fadd reassoc nnan ninf nsz arcp contract afn double %a, %b
  %sub = fsub double %a, %b
  %mul = fmul double %a, %b
  %div = fdiv double %a, %b
  %rem = frem double %a, %b
  %cmp = fcmp nnan olt double %a, %b
  %select = select fast i1 %cmp, double %add, double %sub
  ret double %select
}

define i64 @cast_ops(i64 %a, i32 %b, float %f, double %d, ptr %p, ptr addrspace(1) %q) {
entry:
  %trunc = trunc nuw nsw i64 %a to i32
  %zext = zext nneg i32 %b to i64
  %sext = sext i32 %b to i64
  %fptoui = fptoui double %d to i64
  %fptosi = fptosi double %d to i64
  %uitofp = uitofp nneg i64 %a to double
  %sitofp = sitofp i64 %a to double
  %fptrunc = fptrunc double %d to float
  %fpext = fpext float %f to double
  %ptrtoint = ptrtoint ptr %p to i64
  %inttoptr = inttoptr i64 %a to ptr
  %bitcast = bitcast double %d to i64
  %addrspacecast = addrspacecast ptr addrspace(1) %q to ptr
  ret i64 %bitcast
}

define i64 @memory_ops(ptr %p, i64 %value) {
entry:
  %allocation = alloca i64, i64 2, align 16
  %ordinary = load volatile i64, ptr %p, align 8
  store volatile i64 %ordinary, ptr %allocation, align 16
  %acquired = load atomic volatile i64, ptr %p syncscope("singlethread") acquire, align 8
  store atomic volatile i64 %value, ptr %p syncscope("singlethread") release, align 8
  fence syncscope("singlethread") seq_cst
  %pair = cmpxchg weak volatile ptr %p, i64 %acquired, i64 %value syncscope("singlethread") acq_rel acquire, align 8
  %old = atomicrmw volatile add ptr %p, i64 %value syncscope("singlethread") monotonic, align 8
  %element = getelementptr inbounds i64, ptr %allocation, i64 1
  %other_element = getelementptr nusw nuw i64, ptr %p, i64 1
  %extracted = extractvalue {i64, i1} %pair, 0
  ret i64 %extracted
}

define i32 @control_flow(i32 %count) {
entry:
  switch i32 %count, label %loop [i32 0, label %zero i32 1, label %one]
loop:
  %i = phi i32 [0, %entry], [%next, %loop]
  %next = add i32 %i, 1
  %done = icmp uge i32 %next, %count
  br i1 %done, label %exit, label %loop
zero:
  ret i32 0
one:
  ret i32 1
exit:
  ret i32 %next
}

define i32 @indirect(i1 %choose) {
entry:
  %address = select i1 %choose, ptr blockaddress(@indirect, %left), ptr blockaddress(@indirect, %right)
  indirectbr ptr %address, [label %left, label %right]
left:
  ret i32 3
right:
  ret i32 7
}

define i32 @call_ops(ptr %function, i32 %a) {
entry:
  %ordinary = call i32 @called(i32 %a) [ "deopt"(i32 %a) ]
  %fast = call fastcc signext i32 @fast_called(i32 signext %ordinary) nounwind
  %indirect = notail call i32 %function(i32 %fast)
  %tail = tail call i32 @called(i32 %indirect)
  ret i32 %tail
}

define i32 @vector_ops(<4 x i32> %a, <4 x i32> %b, i32 %value) {
entry:
  %insert = insertelement <4 x i32> %a, i32 %value, i32 2
  %shuffle = shufflevector <4 x i32> %insert, <4 x i32> %b, <4 x i32> <i32 0, i32 5, i32 poison, i32 3>
  %extract = extractelement <4 x i32> %shuffle, i32 1
  %aggregate = insertvalue {i32, [2 x i32]} poison, i32 %extract, 1, 0
  %aggregate_value = extractvalue {i32, [2 x i32]} %aggregate, 1, 0
  ret i32 %aggregate_value
}

define i32 @varargs(ptr %arguments) {
entry:
  %value = va_arg ptr %arguments, i32
  ret i32 %value
}

define void @unreachable_path() {
entry:
  unreachable
}

define void @landing() personality ptr @__gxx_personality_v0 {
entry:
  invoke void @may_throw() to label %normal unwind label %exception
normal:
  ret void
exception:
  %landing = landingpad {ptr, i32} cleanup catch ptr null
  resume {ptr, i32} %landing
}

define void @catching() personality ptr @__CxxFrameHandler3 {
entry:
  invoke void @may_throw() to label %normal unwind label %dispatch
dispatch:
  %switch = catchswitch within none [label %handler] unwind to caller
handler:
  %pad = catchpad within %switch [ptr null, i32 64, ptr null]
  catchret from %pad to label %normal
normal:
  ret void
}

define void @cleaning() personality ptr @__CxxFrameHandler3 {
entry:
  invoke void @may_throw() to label %normal unwind label %exception
exception:
  %pad = cleanuppad within none []
  cleanupret from %pad unwind to caller
normal:
  ret void
}
