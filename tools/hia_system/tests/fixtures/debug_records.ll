; All LLVM20 non-instruction debug record forms remain typed HIA data.
; Record order, duplicate entries, poison locations and DIArgList are deliberate.
source_filename = "hia-debug-records.c"
target triple = "x86_64-unknown-linux-gnu"

define i32 @debug_record_fixture(i32 %x) !dbg !4 {
entry:
  %slot = alloca i32, align 4
    #dbg_declare(ptr %slot, !7, !DIExpression(), !9)
    #dbg_label(!12, !9)
  store i32 %x, ptr %slot, align 4, !dbg !9, !DIAssignID !14
    #dbg_assign(i32 %x, !7, !DIExpression(), !14, ptr %slot, !DIExpression(), !9)
    #dbg_value(i32 %x, !7, !DIExpression(), !9)
    #dbg_value(i32 %x, !7, !DIExpression(), !9)
    #dbg_value(!DIArgList(i32 %x, i32 1), !7, !DIExpression(DW_OP_LLVM_arg, 0, DW_OP_LLVM_arg, 1, DW_OP_plus, DW_OP_stack_value), !9)
    #dbg_value(i32 poison, !7, !DIExpression(), !9)
  %value = load i32, ptr %slot, align 4, !dbg !9
  ret i32 %value, !dbg !9
}

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!2, !3, !16}

!0 = distinct !DICompileUnit(language: DW_LANG_C11, file: !1, producer: "hia-system-debug-fixture", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug)
!1 = !DIFile(filename: "hia-debug-records.c", directory: "/")
!2 = !{i32 7, !"Dwarf Version", i32 4}
!3 = !{i32 2, !"Debug Info Version", i32 3}
!4 = distinct !DISubprogram(name: "debug_record_fixture", scope: !1, file: !1, line: 1, type: !5, scopeLine: 1, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !8)
!5 = !DISubroutineType(types: !6)
!6 = !{!10, !10}
!7 = !DILocalVariable(name: "x", arg: 1, scope: !4, file: !1, line: 1, type: !10)
!8 = !{!7, !12}
!9 = !DILocation(line: 2, column: 1, scope: !4)
!10 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!12 = !DILabel(scope: !4, name: "checkpoint", file: !1, line: 2)
!14 = distinct !DIAssignID()
!16 = !{i32 7, !"debug-info-assignment-tracking", i1 true}
