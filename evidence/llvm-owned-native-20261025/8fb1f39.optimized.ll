; ModuleID = '/tmp/hepta-owned-fields.ll'
source_filename = "/tmp/hepta-owned-fields.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

declare noalias ptr @malloc(i64) local_unnamed_addr #0

; Function Attrs: mustprogress nounwind willreturn allockind("free") memory(argmem: readwrite, inaccessiblemem: readwrite)
declare void @free(ptr allocptr nocapture noundef) local_unnamed_addr #1

; Function Attrs: cold nofree noreturn
declare void @abort() local_unnamed_addr #2

; Function Attrs: mustprogress nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly, i8, i64, i1 immarg) #3

; Function Attrs: mustprogress nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare { i64, i1 } @llvm.uadd.with.overflow.i64(i64, i64) #4

; Function Attrs: noinline optnone
define internal fastcc noalias ptr @__hepta_owned_allocate(i64 range(i64 1, -9223372036854775808) %size) unnamed_addr #5 {
entry:
  %data = call ptr @malloc(i64 %size) #6
  ret ptr %data
}

define i64 @full_lifecycle(i64 %arg0, i32 %arg1) local_unnamed_addr {
entry:
  %oversized.i.i = icmp slt i64 %arg0, 0
  br i1 %oversized.i.i, label %common.ret, label %check_zero.i.i

check_zero.i.i:                                   ; preds = %entry
  %zero.i.i = icmp eq i64 %arg0, 0
  br i1 %zero.i.i, label %common.ret, label %allocate.i.i

allocate.i.i:                                     ; preds = %check_zero.i.i
  %data.i.i = tail call fastcc ptr @__hepta_owned_allocate(i64 %arg0), !noalias !0
  %failed.i.i = icmp eq ptr %data.i.i, null
  br i1 %failed.i.i, label %common.ret, label %iter.check

common.ret:                                       ; preds = %check_zero.i.i, %entry, %allocate.i.i, %release.i.i.i
  %common.ret.op = phi i64 [ %v57, %release.i.i.i ], [ 1001, %allocate.i.i ], [ 1001, %entry ], [ 0, %check_zero.i.i ]
  ret i64 %common.ret.op

iter.check:                                       ; preds = %allocate.i.i
  tail call void @llvm.memset.p0.i64(ptr nonnull align 1 %data.i.i, i8 0, i64 %arg0, i1 false), !noalias !0
  %min.iters.check = icmp ult i64 %arg0, 4
  br i1 %min.iters.check, label %checked10.preheader, label %vector.main.loop.iter.check

vector.main.loop.iter.check:                      ; preds = %iter.check
  %min.iters.check38 = icmp ult i64 %arg0, 16
  br i1 %min.iters.check38, label %vec.epilog.ph, label %vector.ph

vector.ph:                                        ; preds = %vector.main.loop.iter.check
  %n.vec = and i64 %arg0, 9223372036854775792
  %broadcast.splatinsert = insertelement <16 x i32> poison, i32 %arg1, i64 0
  %broadcast.splat = shufflevector <16 x i32> %broadcast.splatinsert, <16 x i32> poison, <16 x i32> zeroinitializer
  br label %vector.body

vector.body:                                      ; preds = %vector.body, %vector.ph
  %index = phi i64 [ 0, %vector.ph ], [ %index.next, %vector.body ]
  %vec.ind = phi <16 x i32> [ <i32 0, i32 1, i32 2, i32 3, i32 4, i32 5, i32 6, i32 7, i32 8, i32 9, i32 10, i32 11, i32 12, i32 13, i32 14, i32 15>, %vector.ph ], [ %vec.ind.next, %vector.body ]
  %0 = add <16 x i32> %broadcast.splat, %vec.ind
  %1 = trunc <16 x i32> %0 to <16 x i8>
  %2 = getelementptr i8, ptr %data.i.i, i64 %index
  store <16 x i8> %1, ptr %2, align 1
  %index.next = add nuw i64 %index, 16
  %vec.ind.next = add <16 x i32> %vec.ind, splat (i32 16)
  %3 = icmp eq i64 %index.next, %n.vec
  br i1 %3, label %middle.block, label %vector.body, !llvm.loop !5

middle.block:                                     ; preds = %vector.body
  %cmp.n = icmp eq i64 %arg0, %n.vec
  br i1 %cmp.n, label %checked15.preheader, label %vec.epilog.iter.check

vec.epilog.iter.check:                            ; preds = %middle.block
  %n.vec.remaining = and i64 %arg0, 12
  %min.epilog.iters.check = icmp eq i64 %n.vec.remaining, 0
  br i1 %min.epilog.iters.check, label %checked10.preheader, label %vec.epilog.ph

vec.epilog.ph:                                    ; preds = %vec.epilog.iter.check, %vector.main.loop.iter.check
  %bc.resume.val = phi i64 [ %n.vec, %vec.epilog.iter.check ], [ 0, %vector.main.loop.iter.check ]
  %n.vec40 = and i64 %arg0, 9223372036854775804
  %4 = trunc i64 %bc.resume.val to i32
  %.splatinsert = insertelement <4 x i32> poison, i32 %4, i64 0
  %.splat = shufflevector <4 x i32> %.splatinsert, <4 x i32> poison, <4 x i32> zeroinitializer
  %induction = or disjoint <4 x i32> %.splat, <i32 0, i32 1, i32 2, i32 3>
  %broadcast.splatinsert44 = insertelement <4 x i32> poison, i32 %arg1, i64 0
  %broadcast.splat45 = shufflevector <4 x i32> %broadcast.splatinsert44, <4 x i32> poison, <4 x i32> zeroinitializer
  br label %vec.epilog.vector.body

vec.epilog.vector.body:                           ; preds = %vec.epilog.vector.body, %vec.epilog.ph
  %index41 = phi i64 [ %bc.resume.val, %vec.epilog.ph ], [ %index.next46, %vec.epilog.vector.body ]
  %vec.ind42 = phi <4 x i32> [ %induction, %vec.epilog.ph ], [ %vec.ind.next43, %vec.epilog.vector.body ]
  %5 = add <4 x i32> %broadcast.splat45, %vec.ind42
  %6 = trunc <4 x i32> %5 to <4 x i8>
  %7 = getelementptr i8, ptr %data.i.i, i64 %index41
  store <4 x i8> %6, ptr %7, align 1
  %index.next46 = add nuw i64 %index41, 4
  %vec.ind.next43 = add <4 x i32> %vec.ind42, splat (i32 4)
  %8 = icmp eq i64 %index.next46, %n.vec40
  br i1 %8, label %vec.epilog.middle.block, label %vec.epilog.vector.body, !llvm.loop !8

vec.epilog.middle.block:                          ; preds = %vec.epilog.vector.body
  %cmp.n47 = icmp eq i64 %arg0, %n.vec40
  br i1 %cmp.n47, label %checked15.preheader, label %checked10.preheader

checked10.preheader:                              ; preds = %vec.epilog.iter.check, %vec.epilog.middle.block, %iter.check
  %v20.026.ph = phi i64 [ %n.vec, %vec.epilog.iter.check ], [ 0, %iter.check ], [ %n.vec40, %vec.epilog.middle.block ]
  br label %checked10

checked10:                                        ; preds = %checked10.preheader, %checked10
  %v20.026 = phi i64 [ %v36, %checked10 ], [ %v20.026.ph, %checked10.preheader ]
  %v24 = trunc i64 %v20.026 to i32
  %v26 = add i32 %arg1, %v24
  %v27 = trunc i32 %v26 to i8
  %v34 = getelementptr i8, ptr %data.i.i, i64 %v20.026
  store i8 %v27, ptr %v34, align 1
  %v36 = add nuw i64 %v20.026, 1
  %exitcond.not = icmp eq i64 %v36, %arg0
  br i1 %exitcond.not, label %checked15.preheader, label %checked10, !llvm.loop !9

checked15.preheader:                              ; preds = %checked10, %vec.epilog.middle.block, %middle.block
  br label %checked15

checked15:                                        ; preds = %checked15.preheader, %checked17
  %v43.029 = phi i64 [ %v61, %checked17 ], [ 0, %checked15.preheader ]
  %v41.028 = phi i64 [ %v57, %checked17 ], [ 0, %checked15.preheader ]
  %v53 = getelementptr i8, ptr %data.i.i, i64 %v43.029
  %v54 = load i8, ptr %v53, align 1
  %v55 = zext i8 %v54 to i64
  %v56 = tail call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %v41.028, i64 %v55)
  %v58 = extractvalue { i64, i1 } %v56, 1
  br i1 %v58, label %abort18, label %checked17

abort18:                                          ; preds = %checked15
  tail call void @abort()
  unreachable

checked17:                                        ; preds = %checked15
  %v57 = extractvalue { i64, i1 } %v56, 0
  %v61 = add nuw i64 %v43.029, 1
  %exitcond30.not = icmp eq i64 %v61, %arg0
  br i1 %exitcond30.not, label %release.i.i.i, label %checked15

release.i.i.i:                                    ; preds = %checked17
  tail call void @free(ptr nonnull %data.i.i)
  br label %common.ret
}

define range(i64 1001, 4294968298) i64 @constructor_error(i64 %arg0, i32 %arg1) local_unnamed_addr {
entry:
  %oversized.i.i = icmp slt i64 %arg0, 0
  br i1 %oversized.i.i, label %common.ret, label %check_zero.i.i

check_zero.i.i:                                   ; preds = %entry
  %zero.i.i = icmp eq i64 %arg0, 0
  br i1 %zero.i.i, label %common.ret, label %allocate.i.i

allocate.i.i:                                     ; preds = %check_zero.i.i
  %data.i.i = tail call fastcc ptr @__hepta_owned_allocate(i64 %arg0), !noalias !10
  %failed.i.i = icmp eq ptr %data.i.i, null
  br i1 %failed.i.i, label %common.ret, label %variant1.i

variant1.i:                                       ; preds = %allocate.i.i
  tail call void @free(ptr nonnull %data.i.i), !noalias !15
  br label %common.ret

common.ret:                                       ; preds = %variant1.i, %check_zero.i.i, %entry, %allocate.i.i
  %v4.sroa.7.0 = phi i64 [ 1001, %allocate.i.i ], [ 1001, %entry ], [ 1002, %check_zero.i.i ], [ 1002, %variant1.i ]
  %v16 = zext i32 %arg1 to i64
  %v17 = add nuw nsw i64 %v4.sroa.7.0, %v16
  ret i64 %v17
}

define i64 @two_stage(i64 %arg0, i32 %arg1) local_unnamed_addr {
entry:
  %oversized.i.i = icmp slt i64 %arg0, 0
  br i1 %oversized.i.i, label %common.ret, label %check_zero.i.i

check_zero.i.i:                                   ; preds = %entry
  %zero.i.i = icmp eq i64 %arg0, 0
  br i1 %zero.i.i, label %allocate.i, label %allocate.i.i

allocate.i.i:                                     ; preds = %check_zero.i.i
  %data.i.i = tail call fastcc ptr @__hepta_owned_allocate(i64 %arg0), !noalias !16
  %failed.i.i = icmp eq ptr %data.i.i, null
  br i1 %failed.i.i, label %common.ret, label %iter.check

common.ret.sink.split:                            ; preds = %__hepta_owned_drop0.exit, %variant10, %checked7
  %v4.sroa.3.0.ph415761.sink = phi ptr [ %v4.sroa.3.0.ph4156, %variant10 ], [ %data.i.i, %checked7 ], [ %v4.sroa.3.0.ph4156, %__hepta_owned_drop0.exit ]
  %common.ret.op.ph = phi i64 [ 1001, %variant10 ], [ 1001, %checked7 ], [ %v74, %__hepta_owned_drop0.exit ]
  tail call void @free(ptr nonnull %v4.sroa.3.0.ph415761.sink)
  br label %common.ret

common.ret:                                       ; preds = %common.ret.sink.split, %variant10, %entry, %allocate.i.i, %__hepta_owned_drop0.exit
  %common.ret.op = phi i64 [ %v74, %__hepta_owned_drop0.exit ], [ 1001, %allocate.i.i ], [ 1001, %entry ], [ 1001, %variant10 ], [ %common.ret.op.ph, %common.ret.sink.split ]
  ret i64 %common.ret.op

iter.check:                                       ; preds = %allocate.i.i
  tail call void @llvm.memset.p0.i64(ptr nonnull align 1 %data.i.i, i8 0, i64 %arg0, i1 false), !noalias !16
  %v20 = trunc i32 %arg1 to i8
  %min.iters.check = icmp ult i64 %arg0, 4
  br i1 %min.iters.check, label %checked4.i.preheader, label %vector.main.loop.iter.check

vector.main.loop.iter.check:                      ; preds = %iter.check
  %min.iters.check62 = icmp ult i64 %arg0, 32
  br i1 %min.iters.check62, label %vec.epilog.ph, label %vector.ph

vector.ph:                                        ; preds = %vector.main.loop.iter.check
  %n.vec = and i64 %arg0, 9223372036854775776
  %broadcast.splatinsert = insertelement <16 x i8> poison, i8 %v20, i64 0
  %broadcast.splat = shufflevector <16 x i8> %broadcast.splatinsert, <16 x i8> poison, <16 x i32> zeroinitializer
  br label %vector.body

vector.body:                                      ; preds = %vector.body, %vector.ph
  %index = phi i64 [ 0, %vector.ph ], [ %index.next, %vector.body ]
  %0 = getelementptr i8, ptr %data.i.i, i64 %index
  %1 = getelementptr i8, ptr %0, i64 16
  store <16 x i8> %broadcast.splat, ptr %0, align 1
  store <16 x i8> %broadcast.splat, ptr %1, align 1
  %index.next = add nuw i64 %index, 32
  %2 = icmp eq i64 %index.next, %n.vec
  br i1 %2, label %middle.block, label %vector.body, !llvm.loop !21

middle.block:                                     ; preds = %vector.body
  %cmp.n = icmp eq i64 %arg0, %n.vec
  br i1 %cmp.n, label %checked7, label %vec.epilog.iter.check

vec.epilog.iter.check:                            ; preds = %middle.block
  %n.vec.remaining = and i64 %arg0, 28
  %min.epilog.iters.check = icmp eq i64 %n.vec.remaining, 0
  br i1 %min.epilog.iters.check, label %checked4.i.preheader, label %vec.epilog.ph

vec.epilog.ph:                                    ; preds = %vec.epilog.iter.check, %vector.main.loop.iter.check
  %vec.epilog.resume.val = phi i64 [ %n.vec, %vec.epilog.iter.check ], [ 0, %vector.main.loop.iter.check ]
  %n.vec64 = and i64 %arg0, 9223372036854775804
  %broadcast.splatinsert66 = insertelement <4 x i8> poison, i8 %v20, i64 0
  %broadcast.splat67 = shufflevector <4 x i8> %broadcast.splatinsert66, <4 x i8> poison, <4 x i32> zeroinitializer
  br label %vec.epilog.vector.body

vec.epilog.vector.body:                           ; preds = %vec.epilog.vector.body, %vec.epilog.ph
  %index65 = phi i64 [ %vec.epilog.resume.val, %vec.epilog.ph ], [ %index.next68, %vec.epilog.vector.body ]
  %3 = getelementptr i8, ptr %data.i.i, i64 %index65
  store <4 x i8> %broadcast.splat67, ptr %3, align 1
  %index.next68 = add nuw i64 %index65, 4
  %4 = icmp eq i64 %index.next68, %n.vec64
  br i1 %4, label %vec.epilog.middle.block, label %vec.epilog.vector.body, !llvm.loop !22

vec.epilog.middle.block:                          ; preds = %vec.epilog.vector.body
  %cmp.n69 = icmp eq i64 %arg0, %n.vec64
  br i1 %cmp.n69, label %checked7, label %checked4.i.preheader

checked4.i.preheader:                             ; preds = %vec.epilog.iter.check, %vec.epilog.middle.block, %iter.check
  %v6.010.i.ph = phi i64 [ %n.vec, %vec.epilog.iter.check ], [ 0, %iter.check ], [ %n.vec64, %vec.epilog.middle.block ]
  br label %checked4.i

checked4.i:                                       ; preds = %checked4.i.preheader, %checked4.i
  %v6.010.i = phi i64 [ %v18.i, %checked4.i ], [ %v6.010.i.ph, %checked4.i.preheader ]
  %v16.i = getelementptr i8, ptr %data.i.i, i64 %v6.010.i
  store i8 %v20, ptr %v16.i, align 1
  %v18.i = add nuw nsw i64 %v6.010.i, 1
  %exitcond.not.i = icmp eq i64 %v18.i, %arg0
  br i1 %exitcond.not.i, label %checked7, label %checked4.i, !llvm.loop !23

checked7:                                         ; preds = %checked4.i, %vec.epilog.middle.block, %middle.block
  %v22 = add nuw i64 %arg0, 17
  %oversized.i = icmp slt i64 %v22, 0
  br i1 %oversized.i, label %common.ret.sink.split, label %allocate.i

allocate.i:                                       ; preds = %check_zero.i.i, %checked7
  %v2258 = phi i64 [ %v22, %checked7 ], [ 17, %check_zero.i.i ]
  %v4.sroa.3.0.ph4156 = phi ptr [ %data.i.i, %checked7 ], [ null, %check_zero.i.i ]
  %data.i = tail call fastcc ptr @__hepta_owned_allocate(i64 %v2258), !noalias !24
  %failed.i = icmp eq ptr %data.i, null
  br i1 %failed.i, label %variant10, label %variant9

variant10:                                        ; preds = %allocate.i
  %allocated.not.i.i.i = icmp eq ptr %v4.sroa.3.0.ph4156, null
  br i1 %allocated.not.i.i.i, label %common.ret, label %common.ret.sink.split

variant9:                                         ; preds = %allocate.i
  tail call void @llvm.memset.p0.i64(ptr noundef nonnull align 1 dereferenceable(1) %data.i, i8 0, i64 %v2258, i1 false), !noalias !24
  br i1 %zero.i.i, label %checked23.preheader, label %iter.check73

iter.check73:                                     ; preds = %variant9
  %min.iters.check71 = icmp ult i64 %arg0, 4
  br i1 %min.iters.check71, label %checked18.preheader, label %vector.main.loop.iter.check75

vector.main.loop.iter.check75:                    ; preds = %iter.check73
  %min.iters.check74 = icmp ult i64 %arg0, 32
  br i1 %min.iters.check74, label %vec.epilog.ph87, label %vector.ph76

vector.ph76:                                      ; preds = %vector.main.loop.iter.check75
  %n.vec78 = and i64 %arg0, 9223372036854775776
  br label %vector.body79

vector.body79:                                    ; preds = %vector.body79, %vector.ph76
  %index80 = phi i64 [ 0, %vector.ph76 ], [ %index.next82, %vector.body79 ]
  %5 = getelementptr i8, ptr %v4.sroa.3.0.ph4156, i64 %index80
  %6 = getelementptr i8, ptr %5, i64 16
  %wide.load = load <16 x i8>, ptr %5, align 1
  %wide.load81 = load <16 x i8>, ptr %6, align 1
  %7 = xor <16 x i8> %wide.load, splat (i8 90)
  %8 = xor <16 x i8> %wide.load81, splat (i8 90)
  %9 = getelementptr i8, ptr %data.i, i64 %index80
  %10 = getelementptr i8, ptr %9, i64 16
  store <16 x i8> %7, ptr %9, align 1
  store <16 x i8> %8, ptr %10, align 1
  %index.next82 = add nuw i64 %index80, 32
  %11 = icmp eq i64 %index.next82, %n.vec78
  br i1 %11, label %middle.block70, label %vector.body79, !llvm.loop !27

middle.block70:                                   ; preds = %vector.body79
  %cmp.n83 = icmp eq i64 %arg0, %n.vec78
  br i1 %cmp.n83, label %checked23.preheader, label %vec.epilog.iter.check88

vec.epilog.iter.check88:                          ; preds = %middle.block70
  %n.vec.remaining89 = and i64 %arg0, 28
  %min.epilog.iters.check90 = icmp eq i64 %n.vec.remaining89, 0
  br i1 %min.epilog.iters.check90, label %checked18.preheader, label %vec.epilog.ph87

vec.epilog.ph87:                                  ; preds = %vec.epilog.iter.check88, %vector.main.loop.iter.check75
  %vec.epilog.resume.val84 = phi i64 [ %n.vec78, %vec.epilog.iter.check88 ], [ 0, %vector.main.loop.iter.check75 ]
  %n.vec92 = and i64 %arg0, 9223372036854775804
  br label %vec.epilog.vector.body93

vec.epilog.vector.body93:                         ; preds = %vec.epilog.vector.body93, %vec.epilog.ph87
  %index94 = phi i64 [ %vec.epilog.resume.val84, %vec.epilog.ph87 ], [ %index.next96, %vec.epilog.vector.body93 ]
  %12 = getelementptr i8, ptr %v4.sroa.3.0.ph4156, i64 %index94
  %wide.load95 = load <4 x i8>, ptr %12, align 1
  %13 = xor <4 x i8> %wide.load95, splat (i8 90)
  %14 = getelementptr i8, ptr %data.i, i64 %index94
  store <4 x i8> %13, ptr %14, align 1
  %index.next96 = add nuw i64 %index94, 4
  %15 = icmp eq i64 %index.next96, %n.vec92
  br i1 %15, label %vec.epilog.middle.block85, label %vec.epilog.vector.body93, !llvm.loop !28

vec.epilog.middle.block85:                        ; preds = %vec.epilog.vector.body93
  %cmp.n97 = icmp eq i64 %arg0, %n.vec92
  br i1 %cmp.n97, label %checked23.preheader, label %checked18.preheader

checked18.preheader:                              ; preds = %vec.epilog.iter.check88, %vec.epilog.middle.block85, %iter.check73
  %v43.049.ph = phi i64 [ %n.vec78, %vec.epilog.iter.check88 ], [ 0, %iter.check73 ], [ %n.vec92, %vec.epilog.middle.block85 ]
  br label %checked18

checked18:                                        ; preds = %checked18.preheader, %checked18
  %v43.049 = phi i64 [ %v56, %checked18 ], [ %v43.049.ph, %checked18.preheader ]
  %v8.i = getelementptr i8, ptr %v4.sroa.3.0.ph4156, i64 %v43.049
  %v9.i = load i8, ptr %v8.i, align 1
  %v48 = xor i8 %v9.i, 90
  %v54 = getelementptr i8, ptr %data.i, i64 %v43.049
  store i8 %v48, ptr %v54, align 1
  %v56 = add nuw i64 %v43.049, 1
  %exitcond.not = icmp eq i64 %v56, %arg0
  br i1 %exitcond.not, label %checked23.preheader, label %checked18, !llvm.loop !29

checked23.preheader:                              ; preds = %checked18, %middle.block70, %vec.epilog.middle.block85, %variant9
  br label %checked23

checked23:                                        ; preds = %checked23.preheader, %checked25
  %v61.051 = phi i64 [ %v78, %checked25 ], [ 0, %checked23.preheader ]
  %v57.050 = phi i64 [ %v74, %checked25 ], [ 0, %checked23.preheader ]
  %v70 = getelementptr i8, ptr %data.i, i64 %v61.051
  %v71 = load i8, ptr %v70, align 1
  %v72 = zext i8 %v71 to i64
  %v73 = tail call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %v57.050, i64 %v72)
  %v75 = extractvalue { i64, i1 } %v73, 1
  br i1 %v75, label %abort26, label %checked25

abort26:                                          ; preds = %checked23
  tail call void @abort()
  unreachable

checked25:                                        ; preds = %checked23
  %v74 = extractvalue { i64, i1 } %v73, 0
  %v78 = add nuw i64 %v61.051, 1
  %exitcond52.not = icmp eq i64 %v78, %v2258
  br i1 %exitcond52.not, label %__hepta_owned_drop0.exit, label %checked23

__hepta_owned_drop0.exit:                         ; preds = %checked25
  tail call void @free(ptr nonnull %data.i)
  %allocated.not.i.i.i23 = icmp eq ptr %v4.sroa.3.0.ph4156, null
  br i1 %allocated.not.i.i.i23, label %common.ret, label %common.ret.sink.split
}

define range(i64 1, -9223372036854775789) i64 @two_alloc(i64 %arg0, i32 %arg1) local_unnamed_addr {
entry:
  %data.i = tail call fastcc ptr @__hepta_owned_allocate(i64 7), !noalias !30
  %failed.i = icmp eq ptr %data.i, null
  br i1 %failed.i, label %common.ret, label %checked7

common.ret.sink.split:                            ; preds = %variant9.thread, %variant9, %checked7, %allocate.i
  %common.ret.op.ph = phi i64 [ 1, %allocate.i ], [ 1, %checked7 ], [ %spec.select, %variant9.thread ], [ %common.ret.op.ph.ph, %variant9 ]
  tail call void @free(ptr nonnull %data.i)
  br label %common.ret

common.ret:                                       ; preds = %common.ret.sink.split, %entry
  %common.ret.op = phi i64 [ 101, %entry ], [ %common.ret.op.ph, %common.ret.sink.split ]
  ret i64 %common.ret.op

checked7:                                         ; preds = %entry
  %oversized.i = icmp slt i64 %arg0, 0
  br i1 %oversized.i, label %common.ret.sink.split, label %check_zero.i

check_zero.i:                                     ; preds = %checked7
  %zero.i = icmp eq i64 %arg0, 0
  br i1 %zero.i, label %variant9.thread, label %allocate.i

allocate.i:                                       ; preds = %check_zero.i
  %data.i16 = tail call fastcc ptr @__hepta_owned_allocate(i64 %arg0), !noalias !33
  %failed.i17 = icmp eq ptr %data.i16, null
  br i1 %failed.i17, label %common.ret.sink.split, label %variant9

variant9:                                         ; preds = %allocate.i
  %v39.not = icmp eq i32 %arg1, 0
  %v5274 = add nuw i64 %arg0, 19
  %common.ret.op.ph.ph = select i1 %v39.not, i64 %v5274, i64 2
  tail call void @free(ptr nonnull %data.i16)
  br label %common.ret.sink.split

variant9.thread:                                  ; preds = %check_zero.i
  %v39.not54 = icmp eq i32 %arg1, 0
  %spec.select = select i1 %v39.not54, i64 19, i64 2
  br label %common.ret.sink.split
}

attributes #0 = { "no-builtins" }
attributes #1 = { mustprogress nounwind willreturn allockind("free") memory(argmem: readwrite, inaccessiblemem: readwrite) "alloc-family"="malloc" }
attributes #2 = { cold nofree noreturn }
attributes #3 = { mustprogress nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #4 = { mustprogress nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #5 = { noinline optnone }
attributes #6 = { nobuiltin }

!0 = !{!1, !3}
!1 = distinct !{!1, !2, !"__hepta_owned_try_buffer: %out"}
!2 = distinct !{!2, !"__hepta_owned_try_buffer"}
!3 = distinct !{!3, !4, !"__hepta_owned_fn0: %out"}
!4 = distinct !{!4, !"__hepta_owned_fn0"}
!5 = distinct !{!5, !6, !7}
!6 = !{!"llvm.loop.isvectorized", i32 1}
!7 = !{!"llvm.loop.unroll.runtime.disable"}
!8 = distinct !{!8, !6, !7}
!9 = distinct !{!9, !7, !6}
!10 = !{!11, !13}
!11 = distinct !{!11, !12, !"__hepta_owned_try_buffer: %out"}
!12 = distinct !{!12, !"__hepta_owned_try_buffer"}
!13 = distinct !{!13, !14, !"__hepta_owned_fn0: %out"}
!14 = distinct !{!14, !"__hepta_owned_fn0"}
!15 = !{!13}
!16 = !{!17, !19}
!17 = distinct !{!17, !18, !"__hepta_owned_try_buffer: %out"}
!18 = distinct !{!18, !"__hepta_owned_try_buffer"}
!19 = distinct !{!19, !20, !"__hepta_owned_fn0: %out"}
!20 = distinct !{!20, !"__hepta_owned_fn0"}
!21 = distinct !{!21, !6, !7}
!22 = distinct !{!22, !6, !7}
!23 = distinct !{!23, !7, !6}
!24 = !{!25}
!25 = distinct !{!25, !26, !"__hepta_owned_try_buffer: %out"}
!26 = distinct !{!26, !"__hepta_owned_try_buffer"}
!27 = distinct !{!27, !6, !7}
!28 = distinct !{!28, !6, !7}
!29 = distinct !{!29, !7, !6}
!30 = !{!31}
!31 = distinct !{!31, !32, !"__hepta_owned_try_buffer: %out"}
!32 = distinct !{!32, !"__hepta_owned_try_buffer"}
!33 = !{!34}
!34 = distinct !{!34, !35, !"__hepta_owned_try_buffer: %out"}
!35 = distinct !{!35, !"__hepta_owned_try_buffer"}
