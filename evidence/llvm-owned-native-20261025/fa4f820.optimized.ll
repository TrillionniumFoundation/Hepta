; ModuleID = '/tmp/hepta-owned-first.ll'
source_filename = "/tmp/hepta-owned-first.ll"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-unknown-linux-gnu"

%hepta.bytes = type { ptr, i64 }
%hepta.type1 = type { i32, { %hepta.bytes }, { i8 } }
%hepta.type2 = type { i32, { %hepta.type0 }, { i8 } }
%hepta.type0 = type { %hepta.bytes }

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
  %data = call ptr @malloc(i64 %size) #7
  ret ptr %data
}

define i64 @full_lifecycle(i64 %arg0, i32 %arg1) local_unnamed_addr {
entry:
  %oversized.i.i = icmp slt i64 %arg0, 0
  br i1 %oversized.i.i, label %__hepta_owned_try_buffer.exit.i, label %check_zero.i.i

check_zero.i.i:                                   ; preds = %entry
  %zero.i.i = icmp eq i64 %arg0, 0
  br i1 %zero.i.i, label %__hepta_owned_try_buffer.exit.i, label %allocate.i.i

allocate.i.i:                                     ; preds = %check_zero.i.i
  %data.i.i = tail call fastcc ptr @__hepta_owned_allocate(i64 %arg0)
  %failed.i.i = icmp eq ptr %data.i.i, null
  br i1 %failed.i.i, label %__hepta_owned_try_buffer.exit.i, label %success.i.i

success.i.i:                                      ; preds = %allocate.i.i
  tail call void @llvm.memset.p0.i64(ptr nonnull align 1 %data.i.i, i8 0, i64 %arg0, i1 false)
  %with_data.i.i = insertvalue %hepta.bytes zeroinitializer, ptr %data.i.i, 0
  %buffer.i.i = insertvalue %hepta.bytes %with_data.i.i, i64 %arg0, 1
  %ok.i.i = insertvalue %hepta.type1 zeroinitializer, %hepta.bytes %buffer.i.i, 1, 0
  br label %__hepta_owned_try_buffer.exit.i

__hepta_owned_try_buffer.exit.i:                  ; preds = %success.i.i, %allocate.i.i, %check_zero.i.i, %entry
  %common.ret.op.i.i = phi %hepta.type1 [ %ok.i.i, %success.i.i ], [ zeroinitializer, %check_zero.i.i ], [ { i32 1, { %hepta.bytes } zeroinitializer, { i8 } { i8 1 } }, %allocate.i.i ], [ { i32 1, { %hepta.bytes } zeroinitializer, { i8 } { i8 1 } }, %entry ]
  %v5.i = extractvalue %hepta.type1 %common.ret.op.i.i, 0
  switch i32 %v5.i, label %invalid3.i [
    i32 0, label %variant1.i
    i32 1, label %variant2.i
  ]

invalid3.i:                                       ; preds = %__hepta_owned_try_buffer.exit.i
  tail call void @abort()
  unreachable

variant2.i:                                       ; preds = %__hepta_owned_try_buffer.exit.i
  %v6.i = extractvalue %hepta.type1 %common.ret.op.i.i, 2, 0
  %v10.i = insertvalue %hepta.type2 { i32 1, { %hepta.type0 } zeroinitializer, { i8 } zeroinitializer }, i8 %v6.i, 2, 0
  br label %__hepta_owned_fn0.exit

variant1.i:                                       ; preds = %__hepta_owned_try_buffer.exit.i
  %v11.i = extractvalue %hepta.type1 %common.ret.op.i.i, 1, 0
  %v18.i = insertvalue %hepta.type0 zeroinitializer, %hepta.bytes %v11.i, 0
  %v20.i = insertvalue %hepta.type2 zeroinitializer, %hepta.type0 %v18.i, 1, 0
  br label %__hepta_owned_fn0.exit

__hepta_owned_fn0.exit:                           ; preds = %variant2.i, %variant1.i
  %common.ret.op.i = phi %hepta.type2 [ %v10.i, %variant2.i ], [ %v20.i, %variant1.i ]
  %v5 = extractvalue %hepta.type2 %common.ret.op.i, 0
  switch i32 %v5, label %invalid3 [
    i32 0, label %variant1
    i32 1, label %variant2
  ]

invalid3:                                         ; preds = %__hepta_owned_fn0.exit
  tail call void @abort()
  unreachable

variant2:                                         ; preds = %__hepta_owned_fn0.exit
  %v6 = extractvalue %hepta.type2 %common.ret.op.i, 2, 0
  %v9 = zext i8 %v6 to i64
  %v10 = add nuw nsw i64 %v9, 1000
  br label %common.ret

common.ret:                                       ; preds = %variant2, %exit14
  %common.ret.op = phi i64 [ %v39.0.lcssa, %exit14 ], [ %v10, %variant2 ]
  ret i64 %common.ret.op

variant1:                                         ; preds = %__hepta_owned_fn0.exit
  %v14 = extractvalue %hepta.type2 %common.ret.op.i, 1, 0
  %v14.fca.0.0.extract = extractvalue %hepta.type0 %v14, 0, 0
  %v14.fca.0.1.extract = extractvalue %hepta.type0 %v14, 0, 1
  %v2120.not = icmp eq i64 %arg0, 0
  br i1 %v2120.not, label %exit14, label %body8.preheader

body8.preheader:                                  ; preds = %variant1
  %0 = add i64 %arg0, -1
  %umin = tail call i64 @llvm.umin.i64(i64 %v14.fca.0.1.extract, i64 %0)
  %1 = add i64 %umin, 1
  %min.iters.check = icmp ult i64 %1, 17
  br i1 %min.iters.check, label %body8.preheader28, label %vector.ph

vector.ph:                                        ; preds = %body8.preheader
  %n.mod.vf = and i64 %1, 15
  %2 = icmp eq i64 %n.mod.vf, 0
  %3 = select i1 %2, i64 16, i64 %n.mod.vf
  %n.vec = sub i64 %1, %3
  %broadcast.splatinsert = insertelement <16 x i32> poison, i32 %arg1, i64 0
  %broadcast.splat = shufflevector <16 x i32> %broadcast.splatinsert, <16 x i32> poison, <16 x i32> zeroinitializer
  br label %vector.body

vector.body:                                      ; preds = %vector.body, %vector.ph
  %index = phi i64 [ 0, %vector.ph ], [ %index.next, %vector.body ]
  %vec.ind = phi <16 x i32> [ <i32 0, i32 1, i32 2, i32 3, i32 4, i32 5, i32 6, i32 7, i32 8, i32 9, i32 10, i32 11, i32 12, i32 13, i32 14, i32 15>, %vector.ph ], [ %vec.ind.next, %vector.body ]
  %4 = add <16 x i32> %broadcast.splat, %vec.ind
  %5 = trunc <16 x i32> %4 to <16 x i8>
  %6 = getelementptr i8, ptr %v14.fca.0.0.extract, i64 %index
  store <16 x i8> %5, ptr %6, align 1
  %index.next = add nuw i64 %index, 16
  %vec.ind.next = add <16 x i32> %vec.ind, splat (i32 16)
  %7 = icmp eq i64 %index.next, %n.vec
  br i1 %7, label %body8.preheader28, label %vector.body, !llvm.loop !0

body8.preheader28:                                ; preds = %vector.body, %body8.preheader
  %v19.021.ph = phi i64 [ 0, %body8.preheader ], [ %n.vec, %vector.body ]
  br label %body8

body8:                                            ; preds = %body8.preheader28, %checked10
  %v19.021 = phi i64 [ %v35, %checked10 ], [ %v19.021.ph, %body8.preheader28 ]
  %exitcond.not = icmp eq i64 %v19.021, %v14.fca.0.1.extract
  br i1 %exitcond.not, label %abort11, label %checked10

abort11:                                          ; preds = %body8
  tail call void @abort()
  unreachable

checked10:                                        ; preds = %body8
  %v23 = trunc i64 %v19.021 to i32
  %v25 = add i32 %arg1, %v23
  %v26 = trunc i32 %v25 to i8
  %v33 = getelementptr i8, ptr %v14.fca.0.0.extract, i64 %v19.021
  store i8 %v26, ptr %v33, align 1
  %v35 = add nuw i64 %v19.021, 1
  %exitcond25.not = icmp eq i64 %v35, %arg0
  br i1 %exitcond25.not, label %body13, label %body8, !llvm.loop !3

body13:                                           ; preds = %checked10, %checked17
  %v41.024 = phi i64 [ %v58, %checked17 ], [ 0, %checked10 ]
  %v39.023 = phi i64 [ %v54, %checked17 ], [ 0, %checked10 ]
  %exitcond26.not = icmp eq i64 %v41.024, %v14.fca.0.1.extract
  br i1 %exitcond26.not, label %abort16, label %checked15

abort16:                                          ; preds = %body13
  tail call void @abort()
  unreachable

checked15:                                        ; preds = %body13
  %v50 = getelementptr i8, ptr %v14.fca.0.0.extract, i64 %v41.024
  %v51 = load i8, ptr %v50, align 1
  %v52 = zext i8 %v51 to i64
  %v53 = tail call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %v39.023, i64 %v52)
  %v55 = extractvalue { i64, i1 } %v53, 1
  br i1 %v55, label %abort18, label %checked17

abort18:                                          ; preds = %checked15
  tail call void @abort()
  unreachable

checked17:                                        ; preds = %checked15
  %v54 = extractvalue { i64, i1 } %v53, 0
  %v58 = add nuw i64 %v41.024, 1
  %exitcond27.not = icmp eq i64 %v58, %arg0
  br i1 %exitcond27.not, label %exit14, label %body13

exit14:                                           ; preds = %checked17, %variant1
  %v39.0.lcssa = phi i64 [ 0, %variant1 ], [ %v54, %checked17 ]
  %child1.i.i = extractvalue %hepta.type0 %v14, 0
  %data.i.i.i = extractvalue %hepta.bytes %child1.i.i, 0
  tail call void @free(ptr %data.i.i.i)
  br label %common.ret
}

define range(i64 1000, 4294968551) i64 @constructor_error(i64 %arg0, i32 %arg1) local_unnamed_addr {
entry:
  %oversized.i.i = icmp slt i64 %arg0, 0
  br i1 %oversized.i.i, label %__hepta_owned_try_buffer.exit.i, label %check_zero.i.i

check_zero.i.i:                                   ; preds = %entry
  %zero.i.i = icmp eq i64 %arg0, 0
  br i1 %zero.i.i, label %__hepta_owned_try_buffer.exit.i, label %allocate.i.i

allocate.i.i:                                     ; preds = %check_zero.i.i
  %data.i.i = tail call fastcc ptr @__hepta_owned_allocate(i64 %arg0)
  %failed.i.i = icmp eq ptr %data.i.i, null
  br i1 %failed.i.i, label %__hepta_owned_try_buffer.exit.i, label %success.i.i

success.i.i:                                      ; preds = %allocate.i.i
  tail call void @llvm.memset.p0.i64(ptr nonnull align 1 %data.i.i, i8 0, i64 %arg0, i1 false)
  %with_data.i.i = insertvalue %hepta.bytes zeroinitializer, ptr %data.i.i, 0
  %buffer.i.i = insertvalue %hepta.bytes %with_data.i.i, i64 %arg0, 1
  %ok.i.i = insertvalue %hepta.type1 zeroinitializer, %hepta.bytes %buffer.i.i, 1, 0
  br label %__hepta_owned_try_buffer.exit.i

__hepta_owned_try_buffer.exit.i:                  ; preds = %success.i.i, %allocate.i.i, %check_zero.i.i, %entry
  %common.ret.op.i.i = phi %hepta.type1 [ %ok.i.i, %success.i.i ], [ zeroinitializer, %check_zero.i.i ], [ { i32 1, { %hepta.bytes } zeroinitializer, { i8 } { i8 1 } }, %allocate.i.i ], [ { i32 1, { %hepta.bytes } zeroinitializer, { i8 } { i8 1 } }, %entry ]
  %v5.i = extractvalue %hepta.type1 %common.ret.op.i.i, 0
  switch i32 %v5.i, label %invalid3.i [
    i32 0, label %variant1.i
    i32 1, label %variant2.i
  ]

invalid3.i:                                       ; preds = %__hepta_owned_try_buffer.exit.i
  tail call void @abort()
  unreachable

variant2.i:                                       ; preds = %__hepta_owned_try_buffer.exit.i
  %v6.i = extractvalue %hepta.type1 %common.ret.op.i.i, 2, 0
  %v10.i = insertvalue %hepta.type2 { i32 1, { %hepta.type0 } zeroinitializer, { i8 } zeroinitializer }, i8 %v6.i, 2, 0
  br label %__hepta_owned_fn0.exit

variant1.i:                                       ; preds = %__hepta_owned_try_buffer.exit.i
  %v11.i = extractvalue %hepta.type1 %common.ret.op.i.i, 1, 0
  %data.i4.i = extractvalue %hepta.bytes %v11.i, 0
  tail call void @free(ptr %data.i4.i)
  br label %__hepta_owned_fn0.exit

__hepta_owned_fn0.exit:                           ; preds = %variant2.i, %variant1.i
  %common.ret.op.i = phi %hepta.type2 [ %v10.i, %variant2.i ], [ { i32 1, { %hepta.type0 } zeroinitializer, { i8 } { i8 2 } }, %variant1.i ]
  %v5 = extractvalue %hepta.type2 %common.ret.op.i, 0
  switch i32 %v5, label %invalid3 [
    i32 0, label %variant1
    i32 1, label %checked5
  ]

invalid3:                                         ; preds = %__hepta_owned_fn0.exit
  tail call void @abort()
  unreachable

checked5:                                         ; preds = %__hepta_owned_fn0.exit
  %v6 = extractvalue %hepta.type2 %common.ret.op.i, 2, 0
  %v9 = zext i8 %v6 to i64
  %v15 = zext i32 %arg1 to i64
  %v10 = add nuw nsw i64 %v15, 1000
  %v16 = add nuw nsw i64 %v10, %v9
  br label %common.ret

common.ret:                                       ; preds = %checked5, %variant1
  %common.ret.op = phi i64 [ 9000, %variant1 ], [ %v16, %checked5 ]
  ret i64 %common.ret.op

variant1:                                         ; preds = %__hepta_owned_fn0.exit
  %v20 = extractvalue %hepta.type2 %common.ret.op.i, 1, 0
  %child1.i.i = extractvalue %hepta.type0 %v20, 0
  %data.i.i.i = extractvalue %hepta.bytes %child1.i.i, 0
  tail call void @free(ptr %data.i.i.i)
  br label %common.ret
}

define i64 @two_stage(i64 %arg0, i32 %arg1) local_unnamed_addr {
entry:
  %oversized.i.i = icmp slt i64 %arg0, 0
  br i1 %oversized.i.i, label %__hepta_owned_try_buffer.exit.i, label %check_zero.i.i

check_zero.i.i:                                   ; preds = %entry
  %zero.i.i = icmp eq i64 %arg0, 0
  br i1 %zero.i.i, label %__hepta_owned_try_buffer.exit.i, label %allocate.i.i

allocate.i.i:                                     ; preds = %check_zero.i.i
  %data.i.i = tail call fastcc ptr @__hepta_owned_allocate(i64 %arg0)
  %failed.i.i = icmp eq ptr %data.i.i, null
  br i1 %failed.i.i, label %__hepta_owned_try_buffer.exit.i, label %success.i.i

success.i.i:                                      ; preds = %allocate.i.i
  tail call void @llvm.memset.p0.i64(ptr nonnull align 1 %data.i.i, i8 0, i64 %arg0, i1 false)
  %with_data.i.i = insertvalue %hepta.bytes zeroinitializer, ptr %data.i.i, 0
  %buffer.i.i = insertvalue %hepta.bytes %with_data.i.i, i64 %arg0, 1
  %ok.i.i = insertvalue %hepta.type1 zeroinitializer, %hepta.bytes %buffer.i.i, 1, 0
  br label %__hepta_owned_try_buffer.exit.i

__hepta_owned_try_buffer.exit.i:                  ; preds = %success.i.i, %allocate.i.i, %check_zero.i.i, %entry
  %common.ret.op.i.i = phi %hepta.type1 [ %ok.i.i, %success.i.i ], [ zeroinitializer, %check_zero.i.i ], [ { i32 1, { %hepta.bytes } zeroinitializer, { i8 } { i8 1 } }, %allocate.i.i ], [ { i32 1, { %hepta.bytes } zeroinitializer, { i8 } { i8 1 } }, %entry ]
  %v5.i = extractvalue %hepta.type1 %common.ret.op.i.i, 0
  switch i32 %v5.i, label %invalid3.i [
    i32 0, label %variant1.i
    i32 1, label %variant2.i
  ]

invalid3.i:                                       ; preds = %__hepta_owned_try_buffer.exit.i
  tail call void @abort()
  unreachable

variant2.i:                                       ; preds = %__hepta_owned_try_buffer.exit.i
  %v6.i = extractvalue %hepta.type1 %common.ret.op.i.i, 2, 0
  %v10.i = insertvalue %hepta.type2 { i32 1, { %hepta.type0 } zeroinitializer, { i8 } zeroinitializer }, i8 %v6.i, 2, 0
  br label %__hepta_owned_fn0.exit

variant1.i:                                       ; preds = %__hepta_owned_try_buffer.exit.i
  %v11.i = extractvalue %hepta.type1 %common.ret.op.i.i, 1, 0
  %v18.i = insertvalue %hepta.type0 zeroinitializer, %hepta.bytes %v11.i, 0
  %v20.i = insertvalue %hepta.type2 zeroinitializer, %hepta.type0 %v18.i, 1, 0
  br label %__hepta_owned_fn0.exit

__hepta_owned_fn0.exit:                           ; preds = %variant2.i, %variant1.i
  %common.ret.op.i = phi %hepta.type2 [ %v10.i, %variant2.i ], [ %v20.i, %variant1.i ]
  %v5 = extractvalue %hepta.type2 %common.ret.op.i, 0
  switch i32 %v5, label %invalid3 [
    i32 0, label %variant1
    i32 1, label %variant2
  ]

invalid3:                                         ; preds = %__hepta_owned_fn0.exit
  tail call void @abort()
  unreachable

variant2:                                         ; preds = %__hepta_owned_fn0.exit
  %v6 = extractvalue %hepta.type2 %common.ret.op.i, 2, 0
  %v9 = zext i8 %v6 to i64
  %v10 = add nuw nsw i64 %v9, 1000
  br label %common.ret

common.ret:                                       ; preds = %variant10, %variant2, %exit22
  %common.ret.op = phi i64 [ %v55.0.lcssa, %exit22 ], [ %v10, %variant2 ], [ %v32, %variant10 ]
  ret i64 %common.ret.op

variant1:                                         ; preds = %__hepta_owned_fn0.exit
  %v14 = extractvalue %hepta.type2 %common.ret.op.i, 1, 0
  %v14.fca.0.0.extract = extractvalue %hepta.type0 %v14, 0, 0
  %v14.fca.0.0.extract46 = ptrtoint ptr %v14.fca.0.0.extract to i64
  %v14.fca.0.1.extract = extractvalue %hepta.type0 %v14, 0, 1
  %v19 = trunc i32 %arg1 to i8
  %v89.not.i = icmp eq i64 %v14.fca.0.1.extract, 0
  br i1 %v89.not.i, label %__hepta_owned_fn5.exit, label %iter.check

iter.check:                                       ; preds = %variant1
  %min.iters.check = icmp ult i64 %v14.fca.0.1.extract, 4
  br i1 %min.iters.check, label %checked4.i.preheader, label %vector.main.loop.iter.check

vector.main.loop.iter.check:                      ; preds = %iter.check
  %min.iters.check37 = icmp ult i64 %v14.fca.0.1.extract, 32
  br i1 %min.iters.check37, label %vec.epilog.ph, label %vector.ph

vector.ph:                                        ; preds = %vector.main.loop.iter.check
  %n.vec = and i64 %v14.fca.0.1.extract, -32
  %broadcast.splatinsert = insertelement <16 x i8> poison, i8 %v19, i64 0
  %broadcast.splat = shufflevector <16 x i8> %broadcast.splatinsert, <16 x i8> poison, <16 x i32> zeroinitializer
  br label %vector.body

vector.body:                                      ; preds = %vector.body, %vector.ph
  %index = phi i64 [ 0, %vector.ph ], [ %index.next, %vector.body ]
  %0 = getelementptr i8, ptr %v14.fca.0.0.extract, i64 %index
  %1 = getelementptr i8, ptr %0, i64 16
  store <16 x i8> %broadcast.splat, ptr %0, align 1
  store <16 x i8> %broadcast.splat, ptr %1, align 1
  %index.next = add nuw i64 %index, 32
  %2 = icmp eq i64 %index.next, %n.vec
  br i1 %2, label %middle.block, label %vector.body, !llvm.loop !4

middle.block:                                     ; preds = %vector.body
  %cmp.n = icmp eq i64 %v14.fca.0.1.extract, %n.vec
  br i1 %cmp.n, label %__hepta_owned_fn5.exit, label %vec.epilog.iter.check

vec.epilog.iter.check:                            ; preds = %middle.block
  %n.vec.remaining = and i64 %v14.fca.0.1.extract, 28
  %min.epilog.iters.check = icmp eq i64 %n.vec.remaining, 0
  br i1 %min.epilog.iters.check, label %checked4.i.preheader, label %vec.epilog.ph

vec.epilog.ph:                                    ; preds = %vec.epilog.iter.check, %vector.main.loop.iter.check
  %vec.epilog.resume.val = phi i64 [ %n.vec, %vec.epilog.iter.check ], [ 0, %vector.main.loop.iter.check ]
  %n.vec39 = and i64 %v14.fca.0.1.extract, -4
  %broadcast.splatinsert41 = insertelement <4 x i8> poison, i8 %v19, i64 0
  %broadcast.splat42 = shufflevector <4 x i8> %broadcast.splatinsert41, <4 x i8> poison, <4 x i32> zeroinitializer
  br label %vec.epilog.vector.body

vec.epilog.vector.body:                           ; preds = %vec.epilog.vector.body, %vec.epilog.ph
  %index40 = phi i64 [ %vec.epilog.resume.val, %vec.epilog.ph ], [ %index.next43, %vec.epilog.vector.body ]
  %3 = getelementptr i8, ptr %v14.fca.0.0.extract, i64 %index40
  store <4 x i8> %broadcast.splat42, ptr %3, align 1
  %index.next43 = add nuw i64 %index40, 4
  %4 = icmp eq i64 %index.next43, %n.vec39
  br i1 %4, label %vec.epilog.middle.block, label %vec.epilog.vector.body, !llvm.loop !5

vec.epilog.middle.block:                          ; preds = %vec.epilog.vector.body
  %cmp.n44 = icmp eq i64 %v14.fca.0.1.extract, %n.vec39
  br i1 %cmp.n44, label %__hepta_owned_fn5.exit, label %checked4.i.preheader

checked4.i.preheader:                             ; preds = %vec.epilog.iter.check, %vec.epilog.middle.block, %iter.check
  %v6.010.i.ph = phi i64 [ %n.vec, %vec.epilog.iter.check ], [ 0, %iter.check ], [ %n.vec39, %vec.epilog.middle.block ]
  br label %checked4.i

checked4.i:                                       ; preds = %checked4.i.preheader, %checked4.i
  %v6.010.i = phi i64 [ %v18.i19, %checked4.i ], [ %v6.010.i.ph, %checked4.i.preheader ]
  %v16.i = getelementptr i8, ptr %v14.fca.0.0.extract, i64 %v6.010.i
  store i8 %v19, ptr %v16.i, align 1
  %v18.i19 = add nuw i64 %v6.010.i, 1
  %exitcond.not.i = icmp eq i64 %v18.i19, %v14.fca.0.1.extract
  br i1 %exitcond.not.i, label %__hepta_owned_fn5.exit, label %checked4.i, !llvm.loop !6

__hepta_owned_fn5.exit:                           ; preds = %checked4.i, %middle.block, %vec.epilog.middle.block, %variant1
  %v21 = tail call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %arg0, i64 17)
  %v23 = extractvalue { i64, i1 } %v21, 1
  br i1 %v23, label %abort8, label %checked7

abort8:                                           ; preds = %__hepta_owned_fn5.exit
  tail call void @abort()
  unreachable

checked7:                                         ; preds = %__hepta_owned_fn5.exit
  %v22 = extractvalue { i64, i1 } %v21, 0
  %oversized.i = icmp slt i64 %v22, 0
  br i1 %oversized.i, label %__hepta_owned_try_buffer.exit, label %allocate.i

allocate.i:                                       ; preds = %checked7
  %data.i = tail call fastcc ptr @__hepta_owned_allocate(i64 %v22)
  %failed.i = icmp eq ptr %data.i, null
  br i1 %failed.i, label %__hepta_owned_try_buffer.exit, label %success.i

success.i:                                        ; preds = %allocate.i
  tail call void @llvm.memset.p0.i64(ptr nonnull align 1 %data.i, i8 0, i64 %v22, i1 false)
  %with_data.i = insertvalue %hepta.bytes zeroinitializer, ptr %data.i, 0
  %buffer.i = insertvalue %hepta.bytes %with_data.i, i64 %v22, 1
  %ok.i = insertvalue %hepta.type1 zeroinitializer, %hepta.bytes %buffer.i, 1, 0
  br label %__hepta_owned_try_buffer.exit

__hepta_owned_try_buffer.exit:                    ; preds = %checked7, %allocate.i, %success.i
  %common.ret.op.i20 = phi %hepta.type1 [ %ok.i, %success.i ], [ { i32 1, { %hepta.bytes } zeroinitializer, { i8 } { i8 1 } }, %allocate.i ], [ { i32 1, { %hepta.bytes } zeroinitializer, { i8 } { i8 1 } }, %checked7 ]
  %v26 = extractvalue %hepta.type1 %common.ret.op.i20, 0
  switch i32 %v26, label %invalid11 [
    i32 0, label %variant9
    i32 1, label %variant10
  ]

invalid11:                                        ; preds = %__hepta_owned_try_buffer.exit
  tail call void @abort()
  unreachable

variant10:                                        ; preds = %__hepta_owned_try_buffer.exit
  %v27 = extractvalue %hepta.type1 %common.ret.op.i20, 2, 0
  %child1.i.i = extractvalue %hepta.type0 %v14, 0
  %data.i.i.i = extractvalue %hepta.bytes %child1.i.i, 0
  tail call void @free(ptr %data.i.i.i)
  %v31 = zext i8 %v27 to i64
  %v32 = add nuw nsw i64 %v31, 1000
  br label %common.ret

variant9:                                         ; preds = %__hepta_owned_try_buffer.exit
  %v36 = extractvalue %hepta.type1 %common.ret.op.i20, 1, 0
  %v36.fca.0.extract = extractvalue %hepta.bytes %v36, 0
  %v36.fca.1.extract = extractvalue %hepta.bytes %v36, 1
  %v4329.not = icmp eq i64 %arg0, 0
  br i1 %v4329.not, label %loop20.preheader, label %body16.preheader

body16.preheader:                                 ; preds = %variant9
  %v36.fca.0.extract45 = ptrtoint ptr %v36.fca.0.extract to i64
  %5 = add i64 %arg0, -1
  %umin = tail call i64 @llvm.umin.i64(i64 %v36.fca.1.extract, i64 %5)
  %6 = freeze i64 %umin
  %umin47 = tail call i64 @llvm.umin.i64(i64 %6, i64 %v14.fca.0.1.extract)
  %7 = add i64 %umin47, 1
  %min.iters.check49 = icmp ult i64 %7, 33
  %8 = sub i64 %v36.fca.0.extract45, %v14.fca.0.0.extract46
  %diff.check = icmp ult i64 %8, 32
  %or.cond = select i1 %min.iters.check49, i1 true, i1 %diff.check
  br i1 %or.cond, label %body16.preheader58, label %vector.ph50

body16.preheader58:                               ; preds = %vector.body53, %body16.preheader
  %v41.030.ph = phi i64 [ 0, %body16.preheader ], [ %n.vec52, %vector.body53 ]
  br label %body16

vector.ph50:                                      ; preds = %body16.preheader
  %n.mod.vf51 = and i64 %7, 31
  %9 = icmp eq i64 %n.mod.vf51, 0
  %10 = select i1 %9, i64 32, i64 %n.mod.vf51
  %n.vec52 = sub i64 %7, %10
  br label %vector.body53

vector.body53:                                    ; preds = %vector.body53, %vector.ph50
  %index54 = phi i64 [ 0, %vector.ph50 ], [ %index.next56, %vector.body53 ]
  %11 = getelementptr i8, ptr %v14.fca.0.0.extract, i64 %index54
  %12 = getelementptr i8, ptr %11, i64 16
  %wide.load = load <16 x i8>, ptr %11, align 1
  %wide.load55 = load <16 x i8>, ptr %12, align 1
  %13 = xor <16 x i8> %wide.load, splat (i8 90)
  %14 = xor <16 x i8> %wide.load55, splat (i8 90)
  %15 = getelementptr i8, ptr %v36.fca.0.extract, i64 %index54
  %16 = getelementptr i8, ptr %15, i64 16
  store <16 x i8> %13, ptr %15, align 1
  store <16 x i8> %14, ptr %16, align 1
  %index.next56 = add nuw i64 %index54, 32
  %17 = icmp eq i64 %index.next56, %n.vec52
  br i1 %17, label %body16.preheader58, label %vector.body53, !llvm.loop !7

loop20.preheader:                                 ; preds = %checked18, %variant9
  %v6131.not = icmp eq i64 %v36.fca.1.extract, 0
  br i1 %v6131.not, label %exit22, label %checked23

body16:                                           ; preds = %body16.preheader58, %checked18
  %v41.030 = phi i64 [ %v54, %checked18 ], [ %v41.030.ph, %body16.preheader58 ]
  %exitcond.not = icmp eq i64 %v41.030, %v14.fca.0.1.extract
  br i1 %exitcond.not, label %abort2.i, label %__hepta_owned_fn6.exit

abort2.i:                                         ; preds = %body16
  tail call void @abort()
  unreachable

__hepta_owned_fn6.exit:                           ; preds = %body16
  %exitcond34.not = icmp eq i64 %v41.030, %v36.fca.1.extract
  br i1 %exitcond34.not, label %abort19, label %checked18

abort19:                                          ; preds = %__hepta_owned_fn6.exit
  tail call void @abort()
  unreachable

checked18:                                        ; preds = %__hepta_owned_fn6.exit
  %v8.i = getelementptr i8, ptr %v14.fca.0.0.extract, i64 %v41.030
  %v9.i = load i8, ptr %v8.i, align 1
  %v46 = xor i8 %v9.i, 90
  %v52 = getelementptr i8, ptr %v36.fca.0.extract, i64 %v41.030
  store i8 %v46, ptr %v52, align 1
  %v54 = add nuw i64 %v41.030, 1
  %exitcond35.not = icmp eq i64 %v54, %arg0
  br i1 %exitcond35.not, label %loop20.preheader, label %body16, !llvm.loop !8

checked23:                                        ; preds = %loop20.preheader, %checked25
  %v59.033 = phi i64 [ %v76, %checked25 ], [ 0, %loop20.preheader ]
  %v55.032 = phi i64 [ %v72, %checked25 ], [ 0, %loop20.preheader ]
  %v68 = getelementptr i8, ptr %v36.fca.0.extract, i64 %v59.033
  %v69 = load i8, ptr %v68, align 1
  %v70 = zext i8 %v69 to i64
  %v71 = tail call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %v55.032, i64 %v70)
  %v73 = extractvalue { i64, i1 } %v71, 1
  br i1 %v73, label %abort26, label %checked25

abort26:                                          ; preds = %checked23
  tail call void @abort()
  unreachable

checked25:                                        ; preds = %checked23
  %v72 = extractvalue { i64, i1 } %v71, 0
  %v76 = add nuw i64 %v59.033, 1
  %exitcond36.not = icmp eq i64 %v76, %v36.fca.1.extract
  br i1 %exitcond36.not, label %exit22, label %checked23

exit22:                                           ; preds = %checked25, %loop20.preheader
  %v55.0.lcssa = phi i64 [ 0, %loop20.preheader ], [ %v72, %checked25 ]
  tail call void @free(ptr %v36.fca.0.extract)
  %child1.i.i22 = extractvalue %hepta.type0 %v14, 0
  %data.i.i.i23 = extractvalue %hepta.bytes %child1.i.i22, 0
  tail call void @free(ptr %data.i.i.i23)
  br label %common.ret
}

define i64 @two_alloc(i64 %arg0, i32 %arg1) local_unnamed_addr {
entry:
  %data.i = tail call fastcc ptr @__hepta_owned_allocate(i64 7)
  %failed.i = icmp eq ptr %data.i, null
  br i1 %failed.i, label %__hepta_owned_try_buffer.exit, label %success.i

success.i:                                        ; preds = %entry
  tail call void @llvm.memset.p0.i64(ptr noundef nonnull align 1 dereferenceable(7) %data.i, i8 0, i64 7, i1 false)
  %with_data.i = insertvalue %hepta.bytes zeroinitializer, ptr %data.i, 0
  %buffer.i = insertvalue %hepta.bytes %with_data.i, i64 7, 1
  %ok.i = insertvalue %hepta.type1 zeroinitializer, %hepta.bytes %buffer.i, 1, 0
  br label %__hepta_owned_try_buffer.exit

__hepta_owned_try_buffer.exit:                    ; preds = %entry, %success.i
  %common.ret.op.i = phi %hepta.type1 [ %ok.i, %success.i ], [ { i32 1, { %hepta.bytes } zeroinitializer, { i8 } { i8 1 } }, %entry ]
  %v4 = extractvalue %hepta.type1 %common.ret.op.i, 0
  switch i32 %v4, label %invalid3 [
    i32 0, label %variant1
    i32 1, label %variant2
  ]

invalid3:                                         ; preds = %__hepta_owned_try_buffer.exit
  tail call void @abort()
  unreachable

variant2:                                         ; preds = %__hepta_owned_try_buffer.exit
  %v5 = extractvalue %hepta.type1 %common.ret.op.i, 2, 0
  %v8 = zext i8 %v5 to i64
  %v9 = add nuw nsw i64 %v8, 100
  br label %common.ret

common.ret:                                       ; preds = %variant2, %checked18, %then13, %variant10
  %common.ret.op = phi i64 [ %v29, %variant10 ], [ 2, %then13 ], [ %v50, %checked18 ], [ %v9, %variant2 ]
  ret i64 %common.ret.op

variant1:                                         ; preds = %__hepta_owned_try_buffer.exit
  %v13 = extractvalue %hepta.type1 %common.ret.op.i, 1, 0
  %v13.fca.0.extract = extractvalue %hepta.bytes %v13, 0
  %v13.fca.1.extract = extractvalue %hepta.bytes %v13, 1
  %v20.not = icmp eq i64 %v13.fca.1.extract, 0
  br i1 %v20.not, label %abort8, label %checked7

abort8:                                           ; preds = %variant1
  tail call void @abort()
  unreachable

checked7:                                         ; preds = %variant1
  store i8 19, ptr %v13.fca.0.extract, align 1
  %oversized.i = icmp slt i64 %arg0, 0
  br i1 %oversized.i, label %__hepta_owned_try_buffer.exit20, label %check_zero.i

check_zero.i:                                     ; preds = %checked7
  %zero.i = icmp eq i64 %arg0, 0
  br i1 %zero.i, label %__hepta_owned_try_buffer.exit20, label %allocate.i

allocate.i:                                       ; preds = %check_zero.i
  %data.i13 = tail call fastcc ptr @__hepta_owned_allocate(i64 %arg0)
  %failed.i14 = icmp eq ptr %data.i13, null
  br i1 %failed.i14, label %__hepta_owned_try_buffer.exit20, label %success.i15

success.i15:                                      ; preds = %allocate.i
  tail call void @llvm.memset.p0.i64(ptr nonnull align 1 %data.i13, i8 0, i64 %arg0, i1 false)
  %with_data.i16 = insertvalue %hepta.bytes zeroinitializer, ptr %data.i13, 0
  %buffer.i17 = insertvalue %hepta.bytes %with_data.i16, i64 %arg0, 1
  %ok.i18 = insertvalue %hepta.type1 zeroinitializer, %hepta.bytes %buffer.i17, 1, 0
  br label %__hepta_owned_try_buffer.exit20

__hepta_owned_try_buffer.exit20:                  ; preds = %checked7, %check_zero.i, %allocate.i, %success.i15
  %common.ret.op.i19 = phi %hepta.type1 [ %ok.i18, %success.i15 ], [ zeroinitializer, %check_zero.i ], [ { i32 1, { %hepta.bytes } zeroinitializer, { i8 } { i8 1 } }, %allocate.i ], [ { i32 1, { %hepta.bytes } zeroinitializer, { i8 } { i8 1 } }, %checked7 ]
  %v24 = extractvalue %hepta.type1 %common.ret.op.i19, 0
  switch i32 %v24, label %invalid11 [
    i32 0, label %variant9
    i32 1, label %variant10
  ]

invalid11:                                        ; preds = %__hepta_owned_try_buffer.exit20
  tail call void @abort()
  unreachable

variant10:                                        ; preds = %__hepta_owned_try_buffer.exit20
  %v25 = extractvalue %hepta.type1 %common.ret.op.i19, 2, 0
  tail call void @free(ptr nonnull %v13.fca.0.extract)
  %v29 = zext i8 %v25 to i64
  br label %common.ret

variant9:                                         ; preds = %__hepta_owned_try_buffer.exit20
  %v30 = extractvalue %hepta.type1 %common.ret.op.i19, 1, 0
  %v36.not = icmp eq i32 %arg1, 0
  br i1 %v36.not, label %checked16, label %then13

then13:                                           ; preds = %variant9
  %data.i22 = extractvalue %hepta.bytes %v30, 0
  tail call void @free(ptr %data.i22)
  tail call void @free(ptr nonnull %v13.fca.0.extract)
  br label %common.ret

checked16:                                        ; preds = %variant9
  %v33.fca.1.extract = extractvalue %hepta.bytes %v30, 1
  %v47 = load i8, ptr %v13.fca.0.extract, align 1
  %v48 = zext i8 %v47 to i64
  %v49 = tail call { i64, i1 } @llvm.uadd.with.overflow.i64(i64 %v33.fca.1.extract, i64 %v48)
  %v51 = extractvalue { i64, i1 } %v49, 1
  br i1 %v51, label %abort19, label %checked18

abort19:                                          ; preds = %checked16
  tail call void @abort()
  unreachable

checked18:                                        ; preds = %checked16
  %v50 = extractvalue { i64, i1 } %v49, 0
  %data.i24 = extractvalue %hepta.bytes %v30, 0
  tail call void @free(ptr %data.i24)
  tail call void @free(ptr nonnull %v13.fca.0.extract)
  br label %common.ret
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare i64 @llvm.umin.i64(i64, i64) #6

attributes #0 = { "no-builtins" }
attributes #1 = { mustprogress nounwind willreturn allockind("free") memory(argmem: readwrite, inaccessiblemem: readwrite) "alloc-family"="malloc" }
attributes #2 = { cold nofree noreturn }
attributes #3 = { mustprogress nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #4 = { mustprogress nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #5 = { noinline optnone }
attributes #6 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #7 = { nobuiltin }

!0 = distinct !{!0, !1, !2}
!1 = !{!"llvm.loop.isvectorized", i32 1}
!2 = !{!"llvm.loop.unroll.runtime.disable"}
!3 = distinct !{!3, !2, !1}
!4 = distinct !{!4, !1, !2}
!5 = distinct !{!5, !1, !2}
!6 = distinct !{!6, !2, !1}
!7 = distinct !{!7, !1, !2}
!8 = distinct !{!8, !1}
