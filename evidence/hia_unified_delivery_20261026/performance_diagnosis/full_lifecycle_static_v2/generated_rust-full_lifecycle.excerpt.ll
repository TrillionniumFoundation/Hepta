define noundef i64 @full_lifecycle(i64 noundef %h_size, i32 noundef %h_seed) unnamed_addr #1 personality ptr @rust_eh_personality {
start:
  %_19.i.i.i = alloca [24 x i8], align 8
  %self5.i.i.i = alloca [24 x i8], align 8
  %_5.i.not.i = icmp eq i64 %h_size, 0
  br i1 %_5.i.not.i, label %bb9, label %bb1.i.i

bb1.i.i:                                          ; preds = %start
  %_27.i.i.i.i = icmp slt i64 %h_size, 0
  br i1 %_27.i.i.i.i, label %bb9, label %"_ZN5alloc7raw_vec20RawVecInner$LT$A$GT$14current_memory17h7133a2a81fc56a81E.exit.i.i.i", !prof !5

"_ZN5alloc7raw_vec20RawVecInner$LT$A$GT$14current_memory17h7133a2a81fc56a81E.exit.i.i.i": ; preds = %bb1.i.i
  call void @llvm.lifetime.start.p0(i64 24, ptr nonnull %self5.i.i.i), !noalias !6
  call void @llvm.lifetime.start.p0(i64 24, ptr nonnull %_19.i.i.i), !noalias !6
  %0 = getelementptr inbounds nuw i8, ptr %_19.i.i.i, i64 8
  store i64 0, ptr %0, align 8, !alias.scope !13, !noalias !6
; call alloc::raw_vec::finish_grow
  call fastcc void @_ZN5alloc7raw_vec11finish_grow17h7bea7c01440f6ee8E(ptr noalias nocapture noundef align 8 dereferenceable(24) %self5.i.i.i, i64 noundef 1, i64 noundef range(i64 1, 0) %h_size, ptr noalias nocapture noundef readonly align 8 dereferenceable(24) %_19.i.i.i) #12, !noalias !6
  call void @llvm.lifetime.end.p0(i64 24, ptr nonnull %_19.i.i.i), !noalias !6
  %_45.i.i.i = load i64, ptr %self5.i.i.i, align 8, !range !16, !noalias !6, !noundef !4
  %1 = trunc nuw i64 %_45.i.i.i to i1
  br i1 %1, label %bb15.i.i.i, label %bb1.i3.i

bb15.i.i.i:                                       ; preds = %"_ZN5alloc7raw_vec20RawVecInner$LT$A$GT$14current_memory17h7133a2a81fc56a81E.exit.i.i.i"
  call void @llvm.lifetime.end.p0(i64 24, ptr nonnull %self5.i.i.i), !noalias !6
  br label %bb9

bb1.i3.i:                                         ; preds = %"_ZN5alloc7raw_vec20RawVecInner$LT$A$GT$14current_memory17h7133a2a81fc56a81E.exit.i.i.i"
  %2 = getelementptr inbounds nuw i8, ptr %self5.i.i.i, i64 8
  %v.011.i.i.i = load ptr, ptr %2, align 8, !noalias !6, !nonnull !4, !noundef !4
  call void @llvm.lifetime.end.p0(i64 24, ptr nonnull %self5.i.i.i), !noalias !6
  %_276.i.i.not.i = icmp eq i64 %h_size, 1
  br i1 %_276.i.i.not.i, label %iter.check, label %bb14.thread.i.i.i

bb14.thread.i.i.i:                                ; preds = %bb1.i3.i
  %3 = add nsw i64 %h_size, -1
  tail call void @llvm.memset.p0.i64(ptr nonnull align 1 %v.011.i.i.i, i8 0, i64 %3, i1 false), !noalias !17
  %scevgep.i.i.i = getelementptr i8, ptr %v.011.i.i.i, i64 %3
  br label %iter.check

iter.check:                                       ; preds = %bb14.thread.i.i.i, %bb1.i3.i
  %ptr.sroa.0.0.lcssa16.i.i.i = phi ptr [ %scevgep.i.i.i, %bb14.thread.i.i.i ], [ %v.011.i.i.i, %bb1.i3.i ]
  store i8 0, ptr %ptr.sroa.0.0.lcssa16.i.i.i, align 1, !noalias !17
  %min.iters.check = icmp ult i64 %h_size, 4
  br i1 %min.iters.check, label %bb12.preheader, label %vector.main.loop.iter.check

bb12.preheader:                                   ; preds = %vec.epilog.iter.check, %vec.epilog.middle.block, %iter.check
  %iter.sroa.0.020.ph = phi i64 [ %n.vec, %vec.epilog.iter.check ], [ 0, %iter.check ], [ %n.vec38, %vec.epilog.middle.block ]
  br label %bb12

vector.main.loop.iter.check:                      ; preds = %iter.check
  %min.iters.check36 = icmp ult i64 %h_size, 16
  br i1 %min.iters.check36, label %vec.epilog.ph, label %vector.ph

vector.ph:                                        ; preds = %vector.main.loop.iter.check
  %n.vec = and i64 %h_size, 9223372036854775792
  %broadcast.splatinsert = insertelement <16 x i32> poison, i32 %h_seed, i64 0
  %broadcast.splat = shufflevector <16 x i32> %broadcast.splatinsert, <16 x i32> poison, <16 x i32> zeroinitializer
  br label %vector.body

vector.body:                                      ; preds = %vector.body, %vector.ph
  %index = phi i64 [ 0, %vector.ph ], [ %index.next, %vector.body ]
  %vec.ind = phi <16 x i32> [ <i32 0, i32 1, i32 2, i32 3, i32 4, i32 5, i32 6, i32 7, i32 8, i32 9, i32 10, i32 11, i32 12, i32 13, i32 14, i32 15>, %vector.ph ], [ %vec.ind.next, %vector.body ]
  %4 = add <16 x i32> %broadcast.splat, %vec.ind
  %5 = getelementptr inbounds nuw i8, ptr %v.011.i.i.i, i64 %index
  %6 = trunc <16 x i32> %4 to <16 x i8>
  store <16 x i8> %6, ptr %5, align 1
  %index.next = add nuw i64 %index, 16
  %vec.ind.next = add <16 x i32> %vec.ind, splat (i32 16)
  %7 = icmp eq i64 %index.next, %n.vec
  br i1 %7, label %middle.block, label %vector.body, !llvm.loop !22

middle.block:                                     ; preds = %vector.body
  %cmp.n = icmp eq i64 %h_size, %n.vec
  br i1 %cmp.n, label %bb13.preheader, label %vec.epilog.iter.check

bb13.preheader:                                   ; preds = %bb12, %vec.epilog.middle.block, %middle.block
  br label %bb13

vec.epilog.iter.check:                            ; preds = %middle.block
  %n.vec.remaining = and i64 %h_size, 12
  %min.epilog.iters.check = icmp eq i64 %n.vec.remaining, 0
  br i1 %min.epilog.iters.check, label %bb12.preheader, label %vec.epilog.ph

vec.epilog.ph:                                    ; preds = %vec.epilog.iter.check, %vector.main.loop.iter.check
  %bc.resume.val = phi i64 [ %n.vec, %vec.epilog.iter.check ], [ 0, %vector.main.loop.iter.check ]
  %n.vec38 = and i64 %h_size, 9223372036854775804
  %8 = trunc i64 %bc.resume.val to i32
  %.splatinsert = insertelement <4 x i32> poison, i32 %8, i64 0
  %.splat = shufflevector <4 x i32> %.splatinsert, <4 x i32> poison, <4 x i32> zeroinitializer
  %induction = or disjoint <4 x i32> %.splat, <i32 0, i32 1, i32 2, i32 3>
  %broadcast.splatinsert42 = insertelement <4 x i32> poison, i32 %h_seed, i64 0
  %broadcast.splat43 = shufflevector <4 x i32> %broadcast.splatinsert42, <4 x i32> poison, <4 x i32> zeroinitializer
  br label %vec.epilog.vector.body

vec.epilog.vector.body:                           ; preds = %vec.epilog.vector.body, %vec.epilog.ph
  %index39 = phi i64 [ %bc.resume.val, %vec.epilog.ph ], [ %index.next44, %vec.epilog.vector.body ]
  %vec.ind40 = phi <4 x i32> [ %induction, %vec.epilog.ph ], [ %vec.ind.next41, %vec.epilog.vector.body ]
  %9 = add <4 x i32> %broadcast.splat43, %vec.ind40
  %10 = getelementptr inbounds nuw i8, ptr %v.011.i.i.i, i64 %index39
  %11 = trunc <4 x i32> %9 to <4 x i8>
  store <4 x i8> %11, ptr %10, align 1
  %index.next44 = add nuw i64 %index39, 4
  %vec.ind.next41 = add <4 x i32> %vec.ind40, splat (i32 4)
  %12 = icmp eq i64 %index.next44, %n.vec38
  br i1 %12, label %vec.epilog.middle.block, label %vec.epilog.vector.body, !llvm.loop !25

vec.epilog.middle.block:                          ; preds = %vec.epilog.vector.body
  %cmp.n45 = icmp eq i64 %h_size, %n.vec38
  br i1 %cmp.n45, label %bb13.preheader, label %bb12.preheader

"_ZN63_$LT$alloc..alloc..Global$u20$as$u20$core..alloc..Allocator$GT$10deallocate17h2c52237e5ef43dfdE.exit.i.i.i.i": ; preds = %bb8
; call __rustc::__rust_dealloc
  tail call void @_RNvCsj4CZ6flxxfE_7___rustc14___rust_dealloc(ptr noundef nonnull %v.011.i.i.i, i64 noundef %h_size, i64 noundef range(i64 1, -9223372036854775807) 1) #12
  br label %bb9

bb13:                                             ; preds = %bb13.preheader, %bb8
  %iter1.sroa.0.023 = phi i64 [ %_35, %bb8 ], [ 0, %bb13.preheader ]
  %h_total.sroa.0.022 = phi i64 [ %_21.0, %bb8 ], [ 0, %bb13.preheader ]
  %_20 = getelementptr inbounds nuw i8, ptr %v.011.i.i.i, i64 %iter1.sroa.0.023
  %_19 = load i8, ptr %_20, align 1, !noundef !4
  %_18 = zext i8 %_19 to i64
  %13 = tail call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %h_total.sroa.0.022, i64 %_18)
  %_21.1 = extractvalue { i64, i1 } %13, 1
  br i1 %_21.1, label %panic2, label %bb8

bb9:                                              ; preds = %start, %bb1.i.i, %bb15.i.i.i, %"_ZN63_$LT$alloc..alloc..Global$u20$as$u20$core..alloc..Allocator$GT$10deallocate17h2c52237e5ef43dfdE.exit.i.i.i.i"
  %_0.sroa.0.0 = phi i64 [ %_21.0, %"_ZN63_$LT$alloc..alloc..Global$u20$as$u20$core..alloc..Allocator$GT$10deallocate17h2c52237e5ef43dfdE.exit.i.i.i.i" ], [ 1001, %bb15.i.i.i ], [ 1001, %bb1.i.i ], [ 0, %start ]
  ret i64 %_0.sroa.0.0

bb8:                                              ; preds = %bb13
  %_35 = add nuw i64 %iter1.sroa.0.023, 1
  %_21.0 = extractvalue { i64, i1 } %13, 0
  %exitcond24.not = icmp eq i64 %_35, %h_size
  br i1 %exitcond24.not, label %"_ZN63_$LT$alloc..alloc..Global$u20$as$u20$core..alloc..Allocator$GT$10deallocate17h2c52237e5ef43dfdE.exit.i.i.i.i", label %bb13

panic2:                                           ; preds = %bb13
; call core::panicking::panic_const::panic_const_add_overflow
  tail call void @_ZN4core9panicking11panic_const24panic_const_add_overflow17h3253708af8a8c611E(ptr noalias noundef nonnull readonly align 8 dereferenceable(24) @alloc_fecb0f2b1ceea185b5addeaa7cf6fd27) #13
  unreachable

bb12:                                             ; preds = %bb12.preheader, %bb12
  %iter.sroa.0.020 = phi i64 [ %_25, %bb12 ], [ %iter.sroa.0.020.ph, %bb12.preheader ]
  %_12 = trunc i64 %iter.sroa.0.020 to i32
  %_11 = add i32 %h_seed, %_12
  %_25 = add nuw i64 %iter.sroa.0.020, 1
  %_13 = getelementptr inbounds nuw i8, ptr %v.011.i.i.i, i64 %iter.sroa.0.020
  %14 = trunc i32 %_11 to i8
  store i8 %14, ptr %_13, align 1
  %exitcond.not = icmp eq i64 %_25, %h_size
  br i1 %exitcond.not, label %bb13.preheader, label %bb12, !llvm.loop !26
}
