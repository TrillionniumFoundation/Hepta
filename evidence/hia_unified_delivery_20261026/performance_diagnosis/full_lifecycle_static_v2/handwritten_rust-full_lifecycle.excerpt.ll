define noundef i64 @full_lifecycle(i64 noundef %size, i32 noundef %seed) unnamed_addr #1 personality ptr @rust_eh_personality {
start:
  %_19.i.i.i.i = alloca [24 x i8], align 8
  %self5.i.i.i.i = alloca [24 x i8], align 8
  %_5.i.not.i.i = icmp eq i64 %size, 0
  br i1 %_5.i.not.i.i, label %bb10, label %bb1.i.i.i

bb1.i.i.i:                                        ; preds = %start
  %_27.i.i.i.i.i = icmp slt i64 %size, 0
  br i1 %_27.i.i.i.i.i, label %bb10, label %"_ZN5alloc7raw_vec20RawVecInner$LT$A$GT$14current_memory17h7133a2a81fc56a81E.exit.i.i.i.i", !prof !5

"_ZN5alloc7raw_vec20RawVecInner$LT$A$GT$14current_memory17h7133a2a81fc56a81E.exit.i.i.i.i": ; preds = %bb1.i.i.i
  call void @llvm.lifetime.start.p0(i64 24, ptr nonnull %self5.i.i.i.i), !noalias !6
  call void @llvm.lifetime.start.p0(i64 24, ptr nonnull %_19.i.i.i.i), !noalias !6
  %0 = getelementptr inbounds nuw i8, ptr %_19.i.i.i.i, i64 8
  store i64 0, ptr %0, align 8, !alias.scope !15, !noalias !6
; call alloc::raw_vec::finish_grow
  call fastcc void @_ZN5alloc7raw_vec11finish_grow17h7bea7c01440f6ee8E(ptr noalias nocapture noundef align 8 dereferenceable(24) %self5.i.i.i.i, i64 noundef 1, i64 noundef range(i64 1, 0) %size, ptr noalias nocapture noundef readonly align 8 dereferenceable(24) %_19.i.i.i.i) #10, !noalias !6
  call void @llvm.lifetime.end.p0(i64 24, ptr nonnull %_19.i.i.i.i), !noalias !6
  %_45.i.i.i.i = load i64, ptr %self5.i.i.i.i, align 8, !range !18, !noalias !6, !noundef !4
  %1 = trunc nuw i64 %_45.i.i.i.i to i1
  br i1 %1, label %bb15.i.i.i.i, label %bb1.i3.i.i

bb15.i.i.i.i:                                     ; preds = %"_ZN5alloc7raw_vec20RawVecInner$LT$A$GT$14current_memory17h7133a2a81fc56a81E.exit.i.i.i.i"
  call void @llvm.lifetime.end.p0(i64 24, ptr nonnull %self5.i.i.i.i), !noalias !6
  br label %bb10

bb1.i3.i.i:                                       ; preds = %"_ZN5alloc7raw_vec20RawVecInner$LT$A$GT$14current_memory17h7133a2a81fc56a81E.exit.i.i.i.i"
  %2 = getelementptr inbounds nuw i8, ptr %self5.i.i.i.i, i64 8
  %v.011.i.i.i.i = load ptr, ptr %2, align 8, !noalias !6, !nonnull !4, !noundef !4
  call void @llvm.lifetime.end.p0(i64 24, ptr nonnull %self5.i.i.i.i), !noalias !6
  %_276.i.i.not.i.i = icmp eq i64 %size, 1
  br i1 %_276.i.i.not.i.i, label %iter.check, label %bb14.thread.i.i.i.i

bb14.thread.i.i.i.i:                              ; preds = %bb1.i3.i.i
  %3 = add nsw i64 %size, -1
  tail call void @llvm.memset.p0.i64(ptr nonnull align 1 %v.011.i.i.i.i, i8 0, i64 %3, i1 false), !noalias !19
  %scevgep.i.i.i.i = getelementptr i8, ptr %v.011.i.i.i.i, i64 %3
  br label %iter.check

iter.check:                                       ; preds = %bb14.thread.i.i.i.i, %bb1.i3.i.i
  %ptr.sroa.0.0.lcssa16.i.i.i.i = phi ptr [ %scevgep.i.i.i.i, %bb14.thread.i.i.i.i ], [ %v.011.i.i.i.i, %bb1.i3.i.i ]
  store i8 0, ptr %ptr.sroa.0.0.lcssa16.i.i.i.i, align 1, !noalias !19
  %_28 = getelementptr inbounds nuw i8, ptr %v.011.i.i.i.i, i64 %size
  %min.iters.check = icmp ult i64 %size, 4
  br i1 %min.iters.check, label %bb8.preheader, label %vector.main.loop.iter.check

vector.main.loop.iter.check:                      ; preds = %iter.check
  %min.iters.check30 = icmp ult i64 %size, 16
  br i1 %min.iters.check30, label %vec.epilog.ph, label %vector.ph

vector.ph:                                        ; preds = %vector.main.loop.iter.check
  %n.vec = and i64 %size, 9223372036854775792
  %broadcast.splatinsert = insertelement <16 x i32> poison, i32 %seed, i64 0
  %broadcast.splat = shufflevector <16 x i32> %broadcast.splatinsert, <16 x i32> poison, <16 x i32> zeroinitializer
  br label %vector.body

vector.body:                                      ; preds = %vector.body, %vector.ph
  %index = phi i64 [ 0, %vector.ph ], [ %index.next, %vector.body ]
  %vec.ind = phi <16 x i32> [ <i32 0, i32 1, i32 2, i32 3, i32 4, i32 5, i32 6, i32 7, i32 8, i32 9, i32 10, i32 11, i32 12, i32 13, i32 14, i32 15>, %vector.ph ], [ %vec.ind.next, %vector.body ]
  %next.gep = getelementptr i8, ptr %v.011.i.i.i.i, i64 %index
  %4 = add <16 x i32> %broadcast.splat, %vec.ind
  %5 = trunc <16 x i32> %4 to <16 x i8>
  store <16 x i8> %5, ptr %next.gep, align 1
  %index.next = add nuw i64 %index, 16
  %vec.ind.next = add <16 x i32> %vec.ind, splat (i32 16)
  %6 = icmp eq i64 %index.next, %n.vec
  br i1 %6, label %middle.block, label %vector.body, !llvm.loop !24

middle.block:                                     ; preds = %vector.body
  %cmp.n = icmp eq i64 %size, %n.vec
  br i1 %cmp.n, label %bb10.i.preheader, label %vec.epilog.iter.check

vec.epilog.iter.check:                            ; preds = %middle.block
  %ind.end = getelementptr i8, ptr %v.011.i.i.i.i, i64 %n.vec
  %n.vec.remaining = and i64 %size, 12
  %min.epilog.iters.check = icmp eq i64 %n.vec.remaining, 0
  br i1 %min.epilog.iters.check, label %bb8.preheader, label %vec.epilog.ph

vec.epilog.ph:                                    ; preds = %vec.epilog.iter.check, %vector.main.loop.iter.check
  %bc.resume.val = phi i64 [ %n.vec, %vec.epilog.iter.check ], [ 0, %vector.main.loop.iter.check ]
  %n.vec32 = and i64 %size, 9223372036854775804
  %7 = getelementptr i8, ptr %v.011.i.i.i.i, i64 %n.vec32
  %8 = trunc i64 %bc.resume.val to i32
  %.splatinsert = insertelement <4 x i32> poison, i32 %8, i64 0
  %.splat = shufflevector <4 x i32> %.splatinsert, <4 x i32> poison, <4 x i32> zeroinitializer
  %induction = or disjoint <4 x i32> %.splat, <i32 0, i32 1, i32 2, i32 3>
  %broadcast.splatinsert37 = insertelement <4 x i32> poison, i32 %seed, i64 0
  %broadcast.splat38 = shufflevector <4 x i32> %broadcast.splatinsert37, <4 x i32> poison, <4 x i32> zeroinitializer
  br label %vec.epilog.vector.body

vec.epilog.vector.body:                           ; preds = %vec.epilog.vector.body, %vec.epilog.ph
  %index33 = phi i64 [ %bc.resume.val, %vec.epilog.ph ], [ %index.next39, %vec.epilog.vector.body ]
  %vec.ind34 = phi <4 x i32> [ %induction, %vec.epilog.ph ], [ %vec.ind.next35, %vec.epilog.vector.body ]
  %next.gep36 = getelementptr i8, ptr %v.011.i.i.i.i, i64 %index33
  %9 = add <4 x i32> %broadcast.splat38, %vec.ind34
  %10 = trunc <4 x i32> %9 to <4 x i8>
  store <4 x i8> %10, ptr %next.gep36, align 1
  %index.next39 = add nuw i64 %index33, 4
  %vec.ind.next35 = add <4 x i32> %vec.ind34, splat (i32 4)
  %11 = icmp eq i64 %index.next39, %n.vec32
  br i1 %11, label %vec.epilog.middle.block, label %vec.epilog.vector.body, !llvm.loop !27

vec.epilog.middle.block:                          ; preds = %vec.epilog.vector.body
  %cmp.n40 = icmp eq i64 %size, %n.vec32
  br i1 %cmp.n40, label %bb10.i.preheader, label %bb8.preheader

bb8.preheader:                                    ; preds = %vec.epilog.iter.check, %vec.epilog.middle.block, %iter.check
  %iter.sroa.7.022.ph = phi i64 [ %n.vec, %vec.epilog.iter.check ], [ 0, %iter.check ], [ %n.vec32, %vec.epilog.middle.block ]
  %iter.sroa.0.021.ph = phi ptr [ %ind.end, %vec.epilog.iter.check ], [ %v.011.i.i.i.i, %iter.check ], [ %7, %vec.epilog.middle.block ]
  br label %bb8

bb8:                                              ; preds = %bb8.preheader, %bb8
  %iter.sroa.7.022 = phi i64 [ %12, %bb8 ], [ %iter.sroa.7.022.ph, %bb8.preheader ]
  %iter.sroa.0.021 = phi ptr [ %_19.i.i, %bb8 ], [ %iter.sroa.0.021.ph, %bb8.preheader ]
  %_19.i.i = getelementptr inbounds nuw i8, ptr %iter.sroa.0.021, i64 1
  %12 = add nuw i64 %iter.sroa.7.022, 1
  %_19 = trunc i64 %iter.sroa.7.022 to i32
  %_18 = add i32 %seed, %_19
  %13 = trunc i32 %_18 to i8
  store i8 %13, ptr %iter.sroa.0.021, align 1
  %_7.i.i = icmp eq ptr %_19.i.i, %_28
  br i1 %_7.i.i, label %bb10.i.preheader, label %bb8, !llvm.loop !28

bb10.i.preheader:                                 ; preds = %bb8, %middle.block, %vec.epilog.middle.block
  br label %bb10.i

bb10.i:                                           ; preds = %bb10.i.preheader, %"_ZN4core4iter8adapters3map8map_fold28_$u7b$$u7b$closure$u7d$$u7d$17hafeda09588f1058eE.exit.i"
  %acc.sroa.0.0.i = phi i64 [ %_4.0.i.i.i, %"_ZN4core4iter8adapters3map8map_fold28_$u7b$$u7b$closure$u7d$$u7d$17hafeda09588f1058eE.exit.i" ], [ 0, %bb10.i.preheader ]
  %i.sroa.0.0.i = phi i64 [ %_28.i, %"_ZN4core4iter8adapters3map8map_fold28_$u7b$$u7b$closure$u7d$$u7d$17hafeda09588f1058eE.exit.i" ], [ 0, %bb10.i.preheader ]
  %_38.i = getelementptr inbounds nuw i8, ptr %v.011.i.i.i.i, i64 %i.sroa.0.0.i
  %_38.val.i = load i8, ptr %_38.i, align 1, !noundef !4
  %_0.i.i.i = zext i8 %_38.val.i to i64
  %14 = tail call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %acc.sroa.0.0.i, i64 range(i64 0, 256) %_0.i.i.i)
  %_4.1.i.i.i = extractvalue { i64, i1 } %14, 1
  br i1 %_4.1.i.i.i, label %panic.i.i.i, label %"_ZN4core4iter8adapters3map8map_fold28_$u7b$$u7b$closure$u7d$$u7d$17hafeda09588f1058eE.exit.i"

panic.i.i.i:                                      ; preds = %bb10.i
; call core::panicking::panic_const::panic_const_add_overflow
  tail call void @_ZN4core9panicking11panic_const24panic_const_add_overflow17h3253708af8a8c611E(ptr noalias noundef nonnull readonly align 8 dereferenceable(24) @alloc_ab72be71d6e2840b2811c519be7c049b) #11
  unreachable

"_ZN4core4iter8adapters3map8map_fold28_$u7b$$u7b$closure$u7d$$u7d$17hafeda09588f1058eE.exit.i": ; preds = %bb10.i
  %_4.0.i.i.i = extractvalue { i64, i1 } %14, 0
  %_28.i = add nuw i64 %i.sroa.0.0.i, 1
  %_30.i = icmp eq i64 %_28.i, %size
  br i1 %_30.i, label %"_ZN63_$LT$alloc..alloc..Global$u20$as$u20$core..alloc..Allocator$GT$10deallocate17h2c52237e5ef43dfdE.exit.i.i.i.i.i", label %bb10.i

"_ZN63_$LT$alloc..alloc..Global$u20$as$u20$core..alloc..Allocator$GT$10deallocate17h2c52237e5ef43dfdE.exit.i.i.i.i.i": ; preds = %"_ZN4core4iter8adapters3map8map_fold28_$u7b$$u7b$closure$u7d$$u7d$17hafeda09588f1058eE.exit.i"
; call __rustc::__rust_dealloc
  tail call void @_RNvCsj4CZ6flxxfE_7___rustc14___rust_dealloc(ptr noundef nonnull %v.011.i.i.i.i, i64 noundef %size, i64 noundef range(i64 1, -9223372036854775807) 1) #10
  br label %bb10

bb10:                                             ; preds = %start, %bb1.i.i.i, %bb15.i.i.i.i, %"_ZN63_$LT$alloc..alloc..Global$u20$as$u20$core..alloc..Allocator$GT$10deallocate17h2c52237e5ef43dfdE.exit.i.i.i.i.i"
  %_0.sroa.0.0 = phi i64 [ %_4.0.i.i.i, %"_ZN63_$LT$alloc..alloc..Global$u20$as$u20$core..alloc..Allocator$GT$10deallocate17h2c52237e5ef43dfdE.exit.i.i.i.i.i" ], [ 1001, %bb15.i.i.i.i ], [ 1001, %bb1.i.i.i ], [ 0, %start ]
  ret i64 %_0.sroa.0.0
}
