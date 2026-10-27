define i64 @full_lifecycle(i64 %a0, i32 %a1) local_unnamed_addr {
entry:
  %zero.i.i = icmp eq i64 %a0, 0
  br i1 %zero.i.i, label %__hia_fn_1.exit, label %nonempty.i.i

nonempty.i.i:                                     ; preds = %entry
  %valid.i.i = icmp sgt i64 %a0, -1
  br i1 %valid.i.i, label %allocate.i.i, label %__hia_allocate.exit.i

allocate.i.i:                                     ; preds = %nonempty.i.i
  %zero_pointer.i.i = tail call ptr @calloc(i64 1, i64 %a0) #4
  %success.not.i.i = icmp eq ptr %zero_pointer.i.i, null
  br i1 %success.not.i.i, label %__hia_allocate.exit.i, label %ready.i.i

ready.i.i:                                        ; preds = %allocate.i.i
  %b0.i.i = insertvalue %hia.buffer zeroinitializer, ptr %zero_pointer.i.i, 0
  %b1.i.i = insertvalue %hia.buffer %b0.i.i, i64 %a0, 1
  %r0.i.i = insertvalue %hia.alloc zeroinitializer, %hia.buffer %b1.i.i, 0
  %r1.i.i = insertvalue %hia.alloc %r0.i.i, i1 true, 1
  br label %__hia_allocate.exit.i

__hia_allocate.exit.i:                            ; preds = %ready.i.i, %allocate.i.i, %nonempty.i.i
  %common.ret.op.i.i = phi %hia.alloc [ %r1.i.i, %ready.i.i ], [ zeroinitializer, %allocate.i.i ], [ zeroinitializer, %nonempty.i.i ]
  %t2.i = extractvalue %hia.alloc %common.ret.op.i.i, 0
  %t3.i = extractvalue %hia.alloc %common.ret.op.i.i, 1
  br i1 %t3.i, label %b3.preheader.i, label %edge_1.i

b3.preheader.i:                                   ; preds = %__hia_allocate.exit.i
  %t16.i = extractvalue %hia.buffer %t2.i, 1
  %t15.i = extractvalue %hia.buffer %t2.i, 0
  %0 = add i64 %a0, -1
  %umin = tail call i64 @llvm.umin.i64(i64 %t16.i, i64 %0)
  %1 = add i64 %umin, 1
  %min.iters.check = icmp ult i64 %1, 17
  br i1 %min.iters.check, label %edge_3.i.preheader, label %vector.ph

edge_3.i.preheader:                               ; preds = %vector.body, %b3.preheader.i
  %p_3_47.i.ph = phi i64 [ 0, %b3.preheader.i ], [ %n.vec, %vector.body ]
  br label %edge_3.i

vector.ph:                                        ; preds = %b3.preheader.i
  %n.mod.vf = and i64 %1, 15
  %2 = icmp eq i64 %n.mod.vf, 0
  %3 = select i1 %2, i64 16, i64 %n.mod.vf
  %n.vec = sub i64 %1, %3
  %broadcast.splatinsert = insertelement <16 x i32> poison, i32 %a1, i64 0
  %broadcast.splat = shufflevector <16 x i32> %broadcast.splatinsert, <16 x i32> poison, <16 x i32> zeroinitializer
  br label %vector.body

vector.body:                                      ; preds = %vector.body, %vector.ph
  %index = phi i64 [ 0, %vector.ph ], [ %index.next, %vector.body ]
  %vec.ind = phi <16 x i32> [ <i32 0, i32 1, i32 2, i32 3, i32 4, i32 5, i32 6, i32 7, i32 8, i32 9, i32 10, i32 11, i32 12, i32 13, i32 14, i32 15>, %vector.ph ], [ %vec.ind.next, %vector.body ]
  %4 = add <16 x i32> %broadcast.splat, %vec.ind
  %5 = trunc <16 x i32> %4 to <16 x i8>
  %6 = getelementptr i8, ptr %t15.i, i64 %index
  store <16 x i8> %5, ptr %6, align 1
  %index.next = add nuw i64 %index, 16
  %vec.ind.next = add <16 x i32> %vec.ind, splat (i32 16)
  %7 = icmp eq i64 %index.next, %n.vec
  br i1 %7, label %edge_3.i.preheader, label %vector.body, !llvm.loop !0

trap_18.i:                                        ; preds = %edge_3.i
  tail call void @abort()
  unreachable

ok_18.i:                                          ; preds = %edge_3.i
  %t12.i = trunc i64 %p_3_47.i to i32
  %t13.i = add i32 %a1, %t12.i
  %t14.i = trunc i32 %t13.i to i8
  %t19.i = getelementptr i8, ptr %t15.i, i64 %p_3_47.i
  store i8 %t14.i, ptr %t19.i, align 1
  %t202.i = add nuw i64 %p_3_47.i, 1
  %exitcond11.not.i = icmp eq i64 %t202.i, %a0
  br i1 %exitcond11.not.i, label %edge_7.i, label %edge_3.i, !llvm.loop !3

trap_30.i:                                        ; preds = %edge_7.i
  tail call void @abort()
  unreachable

ok_30.i:                                          ; preds = %edge_7.i
  %t31.i = getelementptr i8, ptr %t15.i, i64 %p_6_510.i
  %t32.i = load i8, ptr %t31.i, align 1
  %t33.i = zext i8 %t32.i to i64
  %t34.i = tail call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_6_39.i, i64 %t33.i)
  %t36.i = extractvalue { i64, i1 } %t34.i, 1
  br i1 %t36.i, label %trap_38.i, label %ok_38.i

trap_38.i:                                        ; preds = %ok_30.i
  tail call void @abort()
  unreachable

ok_38.i:                                          ; preds = %ok_30.i
  %t35.i = extractvalue { i64, i1 } %t34.i, 0
  %t393.i = add nuw i64 %p_6_510.i, 1
  %exitcond13.not.i = icmp eq i64 %t393.i, %a0
  br i1 %exitcond13.not.i, label %__hia_fn_1.exit, label %edge_7.i

edge_1.i:                                         ; preds = %__hia_allocate.exit.i
  %t4.i = extractvalue %hia.buffer %t2.i, 0
  br label %__hia_fn_1.exit

edge_3.i:                                         ; preds = %edge_3.i.preheader, %ok_18.i
  %p_3_47.i = phi i64 [ %t202.i, %ok_18.i ], [ %p_3_47.i.ph, %edge_3.i.preheader ]
  %exitcond.not.i = icmp eq i64 %p_3_47.i, %t16.i
  br i1 %exitcond.not.i, label %trap_18.i, label %ok_18.i

edge_7.i:                                         ; preds = %ok_18.i, %ok_38.i
  %p_6_510.i = phi i64 [ %t393.i, %ok_38.i ], [ 0, %ok_18.i ]
  %p_6_39.i = phi i64 [ %t35.i, %ok_38.i ], [ 0, %ok_18.i ]
  %exitcond12.not.i = icmp eq i64 %p_6_510.i, %t16.i
  br i1 %exitcond12.not.i, label %trap_30.i, label %ok_30.i

__hia_fn_1.exit:                                  ; preds = %ok_38.i, %entry, %edge_1.i
  %t4.sink.i = phi ptr [ %t4.i, %edge_1.i ], [ null, %entry ], [ %t15.i, %ok_38.i ]
  %common.ret.op.i = phi i64 [ 1001, %edge_1.i ], [ 0, %entry ], [ %t35.i, %ok_38.i ]
  tail call void @free(ptr %t4.sink.i) #4
  ret i64 %common.ret.op.i
}
