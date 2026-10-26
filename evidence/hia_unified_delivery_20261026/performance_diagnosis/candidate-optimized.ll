; ModuleID = '/tmp/hia-perf-diagnosis-9fe/candidate.ll'
source_filename = "/tmp/hia-perf-diagnosis-9fe/candidate.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%hia.buffer = type { ptr, i64 }
%hia.alloc = type { %hia.buffer, i1 }

; Function Attrs: cold nofree noreturn
declare void @abort() local_unnamed_addr #0

declare ptr @calloc(i64, i64) local_unnamed_addr #1

declare ptr @malloc(i64) local_unnamed_addr #1

declare void @free(ptr) local_unnamed_addr #1

; Function Attrs: mustprogress nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare { i64, i1 } @llvm.uadd.with.overflow.i64(i64, i64) #2

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

define range(i64 1001, 4294968298) i64 @constructor_error(i64 %a0, i32 %a1) local_unnamed_addr {
entry:
  %zero.i.i = icmp eq i64 %a0, 0
  br i1 %zero.i.i, label %__hia_fn_2.exit, label %nonempty.i.i

nonempty.i.i:                                     ; preds = %entry
  %valid.i.i = icmp sgt i64 %a0, -1
  br i1 %valid.i.i, label %allocate.i.i, label %__hia_fn_2.exit

allocate.i.i:                                     ; preds = %nonempty.i.i
  %unread_pointer.i.i = tail call ptr @malloc(i64 %a0) #4
  %success.not.i.i = icmp eq ptr %unread_pointer.i.i, null
  br i1 %success.not.i.i, label %__hia_fn_2.exit, label %ready.i.i

ready.i.i:                                        ; preds = %allocate.i.i
  %b0.i.i = insertvalue %hia.buffer zeroinitializer, ptr %unread_pointer.i.i, 0
  %b1.i.i = insertvalue %hia.buffer %b0.i.i, i64 %a0, 1
  %r0.i.i = insertvalue %hia.alloc zeroinitializer, %hia.buffer %b1.i.i, 0
  %r1.i.i = insertvalue %hia.alloc %r0.i.i, i1 true, 1
  br label %__hia_fn_2.exit

__hia_fn_2.exit:                                  ; preds = %entry, %nonempty.i.i, %allocate.i.i, %ready.i.i
  %common.ret.op.i.i = phi %hia.alloc [ %r1.i.i, %ready.i.i ], [ zeroinitializer, %allocate.i.i ], [ zeroinitializer, %nonempty.i.i ], [ { %hia.buffer zeroinitializer, i1 true }, %entry ]
  %t2.i = extractvalue %hia.alloc %common.ret.op.i.i, 0
  %t3.i = extractvalue %hia.alloc %common.ret.op.i.i, 1
  %t4.i = extractvalue %hia.buffer %t2.i, 0
  tail call void @free(ptr %t4.i) #4
  %t5.i = zext i32 %a1 to i64
  %spec.select.i = select i1 %t3.i, i64 1002, i64 1001
  %t6.i = add nuw nsw i64 %spec.select.i, %t5.i
  ret i64 %t6.i
}

define i64 @two_stage(i64 %a0, i32 %a1) local_unnamed_addr {
entry:
  %zero.i.i = icmp eq i64 %a0, 0
  br i1 %zero.i.i, label %edge_4.i, label %nonempty.i.i

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
  br i1 %t3.i, label %b3.preheader.i, label %__hia_fn_3.exit

b3.preheader.i:                                   ; preds = %__hia_allocate.exit.i
  %t14.i = extractvalue %hia.buffer %t2.i, 1
  %t13.i = extractvalue %hia.buffer %t2.i, 0
  %t12.i = trunc i32 %a1 to i8
  %0 = add i64 %a0, -1
  %umin = tail call i64 @llvm.umin.i64(i64 %t14.i, i64 %0)
  %1 = add i64 %umin, 1
  %min.iters.check = icmp ult i64 %1, 33
  br i1 %min.iters.check, label %edge_3.i.preheader, label %vector.ph

edge_3.i.preheader:                               ; preds = %vector.body, %b3.preheader.i
  %p_3_419.i.ph = phi i64 [ 0, %b3.preheader.i ], [ %n.vec, %vector.body ]
  br label %edge_3.i

vector.ph:                                        ; preds = %b3.preheader.i
  %n.mod.vf = and i64 %1, 31
  %2 = icmp eq i64 %n.mod.vf, 0
  %3 = select i1 %2, i64 32, i64 %n.mod.vf
  %n.vec = sub i64 %1, %3
  %broadcast.splatinsert = insertelement <16 x i8> poison, i8 %t12.i, i64 0
  %broadcast.splat = shufflevector <16 x i8> %broadcast.splatinsert, <16 x i8> poison, <16 x i32> zeroinitializer
  br label %vector.body

vector.body:                                      ; preds = %vector.body, %vector.ph
  %index = phi i64 [ 0, %vector.ph ], [ %index.next, %vector.body ]
  %4 = getelementptr i8, ptr %t13.i, i64 %index
  %5 = getelementptr i8, ptr %4, i64 16
  store <16 x i8> %broadcast.splat, ptr %4, align 1
  store <16 x i8> %broadcast.splat, ptr %5, align 1
  %index.next = add nuw i64 %index, 32
  %6 = icmp eq i64 %index.next, %n.vec
  br i1 %6, label %edge_3.i.preheader, label %vector.body, !llvm.loop !4

common.ret.sink.split.i:                          ; preds = %ok_70.i, %edge_10.i, %edge_7.i
  %t31.sink.i = phi ptr [ %t31.i, %edge_7.i ], [ %.pre30.i.pre-phi, %edge_10.i ], [ %.pre30.i.pre-phi, %ok_70.i ]
  %common.ret.op.ph.i = phi i64 [ 1001, %edge_7.i ], [ 0, %edge_10.i ], [ %t67.i, %ok_70.i ]
  tail call void @free(ptr %t31.sink.i) #4
  br label %__hia_fn_3.exit

trap_16.i:                                        ; preds = %edge_3.i
  tail call void @abort()
  unreachable

ok_16.i:                                          ; preds = %edge_3.i
  %t17.i = getelementptr i8, ptr %t13.i, i64 %p_3_419.i
  store i8 %t12.i, ptr %t17.i, align 1
  %t1814.i = add nuw i64 %p_3_419.i, 1
  %exitcond25.not.i = icmp eq i64 %t1814.i, %a0
  br i1 %exitcond25.not.i, label %edge_4.i, label %edge_3.i, !llvm.loop !5

trap_27.i:                                        ; preds = %edge_4.i
  tail call void @abort()
  unreachable

ok_27.i:                                          ; preds = %edge_4.i
  %t24.i = extractvalue { i64, i1 } %t23.i, 0
  %valid.i3.i = icmp sgt i64 %t24.i, -1
  br i1 %valid.i3.i, label %allocate.i5.i, label %__hia_allocate.exit13.i

allocate.i5.i:                                    ; preds = %ok_27.i
  %zero_pointer.i6.i = tail call ptr @calloc(i64 1, i64 %t24.i) #4
  %success.not.i7.i = icmp eq ptr %zero_pointer.i6.i, null
  br i1 %success.not.i7.i, label %__hia_allocate.exit13.i, label %ready.i8.i

ready.i8.i:                                       ; preds = %allocate.i5.i
  %b0.i9.i = insertvalue %hia.buffer zeroinitializer, ptr %zero_pointer.i6.i, 0
  %b1.i10.i = insertvalue %hia.buffer %b0.i9.i, i64 %t24.i, 1
  %r0.i11.i = insertvalue %hia.alloc zeroinitializer, %hia.buffer %b1.i10.i, 0
  %r1.i12.i = insertvalue %hia.alloc %r0.i11.i, i1 true, 1
  br label %__hia_allocate.exit13.i

__hia_allocate.exit13.i:                          ; preds = %ready.i8.i, %allocate.i5.i, %ok_27.i
  %common.ret.op.i4.i = phi %hia.alloc [ %r1.i12.i, %ready.i8.i ], [ zeroinitializer, %allocate.i5.i ], [ zeroinitializer, %ok_27.i ]
  %t29.i = extractvalue %hia.alloc %common.ret.op.i4.i, 0
  %t30.i = extractvalue %hia.alloc %common.ret.op.i4.i, 1
  br i1 %t30.i, label %b8.preheader.i, label %edge_7.i

b8.preheader.i:                                   ; preds = %__hia_allocate.exit13.i
  br i1 %zero.i.i, label %b8.preheader.edge_10_crit_edge.i, label %edge_9.lr.ph.i

b8.preheader.edge_10_crit_edge.i:                 ; preds = %b8.preheader.i
  %.pre.i = extractvalue %hia.buffer %t29.i, 1
  %.pre = extractvalue %hia.buffer %t29.i, 0
  br label %edge_10.i

edge_9.lr.ph.i:                                   ; preds = %b8.preheader.i
  %t41.i = extractvalue %hia.buffer %t23537.i, 1
  %t48.i = extractvalue %hia.buffer %t29.i, 1
  %t47.i = extractvalue %hia.buffer %t29.i, 0
  %t40.i = extractvalue %hia.buffer %t23537.i, 0
  %7 = add i64 %a0, -1
  %umin3 = tail call i64 @llvm.umin.i64(i64 %t48.i, i64 %7)
  %8 = freeze i64 %umin3
  %umin4 = tail call i64 @llvm.umin.i64(i64 %8, i64 %t41.i)
  %9 = add i64 %umin4, 1
  %min.iters.check7 = icmp ult i64 %9, 33
  %t40.i2 = ptrtoint ptr %t40.i to i64
  %t47.i1 = ptrtoint ptr %t47.i to i64
  %10 = sub i64 %t47.i1, %t40.i2
  %diff.check = icmp ult i64 %10, 32
  %or.cond = select i1 %min.iters.check7, i1 true, i1 %diff.check
  br i1 %or.cond, label %edge_9.i.preheader, label %vector.ph8

edge_9.i.preheader:                               ; preds = %vector.body11, %edge_9.lr.ph.i
  %p_8_521.i.ph = phi i64 [ 0, %edge_9.lr.ph.i ], [ %n.vec10, %vector.body11 ]
  br label %edge_9.i

vector.ph8:                                       ; preds = %edge_9.lr.ph.i
  %n.mod.vf9 = and i64 %9, 31
  %11 = icmp eq i64 %n.mod.vf9, 0
  %12 = select i1 %11, i64 32, i64 %n.mod.vf9
  %n.vec10 = sub i64 %9, %12
  br label %vector.body11

vector.body11:                                    ; preds = %vector.body11, %vector.ph8
  %index12 = phi i64 [ 0, %vector.ph8 ], [ %index.next14, %vector.body11 ]
  %13 = getelementptr i8, ptr %t40.i, i64 %index12
  %14 = getelementptr i8, ptr %13, i64 16
  %wide.load = load <16 x i8>, ptr %13, align 1
  %wide.load13 = load <16 x i8>, ptr %14, align 1
  %15 = xor <16 x i8> %wide.load, splat (i8 90)
  %16 = xor <16 x i8> %wide.load13, splat (i8 90)
  %17 = getelementptr i8, ptr %t47.i, i64 %index12
  %18 = getelementptr i8, ptr %17, i64 16
  store <16 x i8> %15, ptr %17, align 1
  store <16 x i8> %16, ptr %18, align 1
  %index.next14 = add nuw i64 %index12, 32
  %19 = icmp eq i64 %index.next14, %n.vec10
  br i1 %19, label %edge_9.i.preheader, label %vector.body11, !llvm.loop !6

trap_43.i:                                        ; preds = %edge_9.i
  tail call void @abort()
  unreachable

ok_43.i:                                          ; preds = %edge_9.i
  %exitcond27.not.i = icmp eq i64 %p_8_521.i, %t48.i
  br i1 %exitcond27.not.i, label %trap_50.i, label %ok_50.i

trap_50.i:                                        ; preds = %ok_43.i
  tail call void @abort()
  unreachable

ok_50.i:                                          ; preds = %ok_43.i
  %t44.i = getelementptr i8, ptr %t40.i, i64 %p_8_521.i
  %t45.i = load i8, ptr %t44.i, align 1
  %t46.i = xor i8 %t45.i, 90
  %t51.i = getelementptr i8, ptr %t47.i, i64 %p_8_521.i
  store i8 %t46.i, ptr %t51.i, align 1
  %t5215.i = add nuw i64 %p_8_521.i, 1
  %exitcond28.not.i = icmp eq i64 %t5215.i, %a0
  br i1 %exitcond28.not.i, label %edge_10.i, label %edge_9.i, !llvm.loop !7

trap_70.i:                                        ; preds = %edge_13.i
  tail call void @abort()
  unreachable

ok_70.i:                                          ; preds = %edge_13.i
  %t67.i = extractvalue { i64, i1 } %t66.i, 0
  %t7116.i = add nuw i64 %p_11_624.i, 1
  %exitcond29.not.i = icmp eq i64 %t7116.i, %t57.pre-phi.i
  br i1 %exitcond29.not.i, label %common.ret.sink.split.i, label %edge_13.i

edge_3.i:                                         ; preds = %edge_3.i.preheader, %ok_16.i
  %p_3_419.i = phi i64 [ %t1814.i, %ok_16.i ], [ %p_3_419.i.ph, %edge_3.i.preheader ]
  %exitcond.not.i = icmp eq i64 %p_3_419.i, %t14.i
  br i1 %exitcond.not.i, label %trap_16.i, label %ok_16.i

edge_4.i:                                         ; preds = %ok_16.i, %entry
  %t23537.i = phi %hia.buffer [ zeroinitializer, %entry ], [ %t2.i, %ok_16.i ]
  %t23.i = tail call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %a0, i64 17)
  %t25.i = extractvalue { i64, i1 } %t23.i, 1
  br i1 %t25.i, label %trap_27.i, label %ok_27.i

edge_7.i:                                         ; preds = %__hia_allocate.exit13.i
  %t31.i = extractvalue %hia.buffer %t29.i, 0
  br label %common.ret.sink.split.i

edge_9.i:                                         ; preds = %edge_9.i.preheader, %ok_50.i
  %p_8_521.i = phi i64 [ %t5215.i, %ok_50.i ], [ %p_8_521.i.ph, %edge_9.i.preheader ]
  %exitcond26.not.i = icmp eq i64 %p_8_521.i, %t41.i
  br i1 %exitcond26.not.i, label %trap_43.i, label %ok_43.i

edge_10.i:                                        ; preds = %ok_50.i, %b8.preheader.edge_10_crit_edge.i
  %.pre30.i.pre-phi = phi ptr [ %.pre, %b8.preheader.edge_10_crit_edge.i ], [ %t47.i, %ok_50.i ]
  %t57.pre-phi.i = phi i64 [ %.pre.i, %b8.preheader.edge_10_crit_edge.i ], [ %t48.i, %ok_50.i ]
  %t5822.not.i = icmp eq i64 %t57.pre-phi.i, 0
  br i1 %t5822.not.i, label %common.ret.sink.split.i, label %edge_13.i

edge_13.i:                                        ; preds = %edge_10.i, %ok_70.i
  %p_11_624.i = phi i64 [ %t7116.i, %ok_70.i ], [ 0, %edge_10.i ]
  %p_11_423.i = phi i64 [ %t67.i, %ok_70.i ], [ 0, %edge_10.i ]
  %t63.i = getelementptr i8, ptr %.pre30.i.pre-phi, i64 %p_11_624.i
  %t64.i = load i8, ptr %t63.i, align 1
  %t65.i = zext i8 %t64.i to i64
  %t66.i = tail call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %p_11_423.i, i64 %t65.i)
  %t68.i = extractvalue { i64, i1 } %t66.i, 1
  br i1 %t68.i, label %trap_70.i, label %ok_70.i

__hia_fn_3.exit:                                  ; preds = %__hia_allocate.exit.i, %common.ret.sink.split.i
  %t23537.sink.i = phi %hia.buffer [ %t2.i, %__hia_allocate.exit.i ], [ %t23537.i, %common.ret.sink.split.i ]
  %common.ret.op.i = phi i64 [ 1001, %__hia_allocate.exit.i ], [ %common.ret.op.ph.i, %common.ret.sink.split.i ]
  %t32.i = extractvalue %hia.buffer %t23537.sink.i, 0
  tail call void @free(ptr %t32.i) #4
  ret i64 %common.ret.op.i
}

define i64 @two_alloc(i64 %a0, i32 %a1) local_unnamed_addr {
entry:
  %zero_pointer.i.i = tail call ptr @calloc(i64 1, i64 7) #4
  %success.not.i.not.i = icmp eq ptr %zero_pointer.i.i, null
  br i1 %success.not.i.not.i, label %__hia_fn_4.exit, label %edge_0.i

nonempty.i.i:                                     ; preds = %edge_0.i
  %valid.i.i = icmp sgt i64 %a0, -1
  br i1 %valid.i.i, label %allocate.i.i, label %__hia_allocate.exit9.i

allocate.i.i:                                     ; preds = %nonempty.i.i
  %zero_pointer.i2.i = tail call ptr @calloc(i64 1, i64 %a0) #4
  %success.not.i3.i = icmp eq ptr %zero_pointer.i2.i, null
  br i1 %success.not.i3.i, label %__hia_allocate.exit9.i, label %ready.i4.i

ready.i4.i:                                       ; preds = %allocate.i.i
  %b0.i5.i = insertvalue %hia.buffer zeroinitializer, ptr %zero_pointer.i2.i, 0
  %b1.i6.i = insertvalue %hia.buffer %b0.i5.i, i64 %a0, 1
  %r0.i7.i = insertvalue %hia.alloc zeroinitializer, %hia.buffer %b1.i6.i, 0
  %r1.i8.i = insertvalue %hia.alloc %r0.i7.i, i1 true, 1
  br label %__hia_allocate.exit9.i

__hia_allocate.exit9.i:                           ; preds = %edge_0.i, %ready.i4.i, %allocate.i.i, %nonempty.i.i
  %common.ret.op.i1.i = phi %hia.alloc [ %r1.i8.i, %ready.i4.i ], [ zeroinitializer, %allocate.i.i ], [ zeroinitializer, %nonempty.i.i ], [ { %hia.buffer zeroinitializer, i1 true }, %edge_0.i ]
  %t10.i = extractvalue %hia.alloc %common.ret.op.i1.i, 0
  %t11.i = extractvalue %hia.alloc %common.ret.op.i1.i, 1
  br i1 %t11.i, label %edge_2.i, label %common.ret.sink.split.i

common.ret.sink.split.i:                          ; preds = %edge_2.i, %ok_38.i, %__hia_allocate.exit9.i
  %common.ret.op.ph.i = phi i64 [ %t35.i, %ok_38.i ], [ 1, %__hia_allocate.exit9.i ], [ 2, %edge_2.i ]
  %t39.i = extractvalue %hia.buffer %t10.i, 0
  tail call void @free(ptr %t39.i) #4
  br label %__hia_fn_4.exit

trap_38.i:                                        ; preds = %edge_5.i
  tail call void @abort()
  unreachable

ok_38.i:                                          ; preds = %edge_5.i
  %t35.i = extractvalue { i64, i1 } %t34.i, 0
  br label %common.ret.sink.split.i

edge_0.i:                                         ; preds = %entry
  store i8 19, ptr %zero_pointer.i.i, align 1
  %zero.i.i = icmp eq i64 %a0, 0
  br i1 %zero.i.i, label %__hia_allocate.exit9.i, label %nonempty.i.i

edge_2.i:                                         ; preds = %__hia_allocate.exit9.i
  %t20.not.i = icmp eq i32 %a1, 0
  br i1 %t20.not.i, label %edge_5.i, label %common.ret.sink.split.i

edge_5.i:                                         ; preds = %edge_2.i
  %t26.i = extractvalue %hia.buffer %t10.i, 1
  %t32.i = load i8, ptr %zero_pointer.i.i, align 1
  %t33.i = zext i8 %t32.i to i64
  %t34.i = tail call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %t26.i, i64 %t33.i)
  %t36.i = extractvalue { i64, i1 } %t34.i, 1
  br i1 %t36.i, label %trap_38.i, label %ok_38.i

__hia_fn_4.exit:                                  ; preds = %entry, %common.ret.sink.split.i
  %common.ret.op.i = phi i64 [ 101, %entry ], [ %common.ret.op.ph.i, %common.ret.sink.split.i ]
  tail call void @free(ptr %zero_pointer.i.i) #4
  ret i64 %common.ret.op.i
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare i64 @llvm.umin.i64(i64, i64) #3

attributes #0 = { cold nofree noreturn }
attributes #1 = { "no-builtins" }
attributes #2 = { mustprogress nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #3 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #4 = { nobuiltin }

!0 = distinct !{!0, !1, !2}
!1 = !{!"llvm.loop.isvectorized", i32 1}
!2 = !{!"llvm.loop.unroll.runtime.disable"}
!3 = distinct !{!3, !2, !1}
!4 = distinct !{!4, !1, !2}
!5 = distinct !{!5, !2, !1}
!6 = distinct !{!6, !1, !2}
!7 = distinct !{!7, !1}
