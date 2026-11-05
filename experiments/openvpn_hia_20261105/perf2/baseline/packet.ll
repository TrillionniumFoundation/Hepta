; Standalone HIA: verified core -> LLVM. No source AST or Rust safety gate.
target triple = "x86_64-unknown-linux-gnu"
%hia.buffer = type { ptr, i64 }
%hia.alloc = type { %hia.buffer, i1 }
declare void @abort() noreturn
declare noalias ptr @calloc(i64, i64) "no-builtins"
declare noalias ptr @malloc(i64) "no-builtins"
declare void @free(ptr) "no-builtins"

; A failed allocation is an empty, valid owner plus false. Zero length succeeds.
; The independent verifier still requires every resulting owner to be consumed.
define internal %hia.alloc @__hia_allocate(i64 %length, i1 %zero_bytes) {
entry:
  %zero = icmp eq i64 %length, 0
  br i1 %zero, label %empty, label %nonempty
empty:
  %empty_result = insertvalue %hia.alloc zeroinitializer, i1 true, 1
  ret %hia.alloc %empty_result
nonempty:
  %valid = icmp ule i64 %length, 9223372036854775807
  br i1 %valid, label %allocate, label %failed
allocate:
  br i1 %zero_bytes, label %zeroed, label %unread
zeroed:
  %zero_pointer = call ptr @calloc(i64 1, i64 %length) nobuiltin
  br label %allocated
unread:
  %unread_pointer = call ptr @malloc(i64 %length) nobuiltin
  br label %allocated
allocated:
  %pointer = phi ptr [ %zero_pointer, %zeroed ], [ %unread_pointer, %unread ]
  %success = icmp ne ptr %pointer, null
  br i1 %success, label %ready, label %failed
ready:
  %b0 = insertvalue %hia.buffer zeroinitializer, ptr %pointer, 0
  %b1 = insertvalue %hia.buffer %b0, i64 %length, 1
  %r0 = insertvalue %hia.alloc zeroinitializer, %hia.buffer %b1, 0
  %r1 = insertvalue %hia.alloc %r0, i1 true, 1
  ret %hia.alloc %r1
failed:
  ret %hia.alloc zeroinitializer
}

define internal i32 @__hia_fn_0(%hia.buffer %p_0_0, %hia.buffer %p_0_1, i32 %p_0_2) {
b0:
  %t1 = extractvalue %hia.buffer %p_0_1, 1
  %t2 = icmp eq i64 %t1, 32
  %t3 = icmp ule i32 %p_0_2, 1
  %t4 = and i1 %t2, %t3
  br i1 %t4, label %edge_0, label %edge_1
b1:
  %p_1_0 = phi %hia.buffer [ %p_0_0, %edge_0 ]
  %p_1_1 = phi %hia.buffer [ %p_0_1, %edge_0 ]
  %p_1_2 = phi i32 [ %p_0_2, %edge_0 ]
  %t5 = add i64 0, 0
  %t6 = extractvalue %hia.buffer %p_1_1, 0
  %t7 = extractvalue %hia.buffer %p_1_1, 1
  %t8 = icmp ult i64 %t5, %t7
  br i1 %t8, label %ok_9, label %trap_9
trap_9:
  call void @abort()
  unreachable
ok_9:
  %t10 = getelementptr i8, ptr %t6, i64 %t5
  %t11 = load i8, ptr %t10, align 1
  %t12 = zext i8 %t11 to i64
  %t13 = icmp ult i64 0, 64
  br i1 %t13, label %ok_14, label %trap_14
trap_14:
  call void @abort()
  unreachable
ok_14:
  %t15 = shl i64 %t12, 0
  %t16 = or i64 0, %t15
  %t17 = add i64 0, 1
  %t18 = extractvalue %hia.buffer %p_1_1, 0
  %t19 = extractvalue %hia.buffer %p_1_1, 1
  %t20 = icmp ult i64 %t17, %t19
  br i1 %t20, label %ok_21, label %trap_21
trap_21:
  call void @abort()
  unreachable
ok_21:
  %t22 = getelementptr i8, ptr %t18, i64 %t17
  %t23 = load i8, ptr %t22, align 1
  %t24 = zext i8 %t23 to i64
  %t25 = icmp ult i64 8, 64
  br i1 %t25, label %ok_26, label %trap_26
trap_26:
  call void @abort()
  unreachable
ok_26:
  %t27 = shl i64 %t24, 8
  %t28 = or i64 %t16, %t27
  %t29 = add i64 0, 2
  %t30 = extractvalue %hia.buffer %p_1_1, 0
  %t31 = extractvalue %hia.buffer %p_1_1, 1
  %t32 = icmp ult i64 %t29, %t31
  br i1 %t32, label %ok_33, label %trap_33
trap_33:
  call void @abort()
  unreachable
ok_33:
  %t34 = getelementptr i8, ptr %t30, i64 %t29
  %t35 = load i8, ptr %t34, align 1
  %t36 = zext i8 %t35 to i64
  %t37 = icmp ult i64 16, 64
  br i1 %t37, label %ok_38, label %trap_38
trap_38:
  call void @abort()
  unreachable
ok_38:
  %t39 = shl i64 %t36, 16
  %t40 = or i64 %t28, %t39
  %t41 = add i64 0, 3
  %t42 = extractvalue %hia.buffer %p_1_1, 0
  %t43 = extractvalue %hia.buffer %p_1_1, 1
  %t44 = icmp ult i64 %t41, %t43
  br i1 %t44, label %ok_45, label %trap_45
trap_45:
  call void @abort()
  unreachable
ok_45:
  %t46 = getelementptr i8, ptr %t42, i64 %t41
  %t47 = load i8, ptr %t46, align 1
  %t48 = zext i8 %t47 to i64
  %t49 = icmp ult i64 24, 64
  br i1 %t49, label %ok_50, label %trap_50
trap_50:
  call void @abort()
  unreachable
ok_50:
  %t51 = shl i64 %t48, 24
  %t52 = or i64 %t40, %t51
  %t53 = add i64 0, 4
  %t54 = extractvalue %hia.buffer %p_1_1, 0
  %t55 = extractvalue %hia.buffer %p_1_1, 1
  %t56 = icmp ult i64 %t53, %t55
  br i1 %t56, label %ok_57, label %trap_57
trap_57:
  call void @abort()
  unreachable
ok_57:
  %t58 = getelementptr i8, ptr %t54, i64 %t53
  %t59 = load i8, ptr %t58, align 1
  %t60 = zext i8 %t59 to i64
  %t61 = icmp ult i64 32, 64
  br i1 %t61, label %ok_62, label %trap_62
trap_62:
  call void @abort()
  unreachable
ok_62:
  %t63 = shl i64 %t60, 32
  %t64 = or i64 %t52, %t63
  %t65 = add i64 0, 5
  %t66 = extractvalue %hia.buffer %p_1_1, 0
  %t67 = extractvalue %hia.buffer %p_1_1, 1
  %t68 = icmp ult i64 %t65, %t67
  br i1 %t68, label %ok_69, label %trap_69
trap_69:
  call void @abort()
  unreachable
ok_69:
  %t70 = getelementptr i8, ptr %t66, i64 %t65
  %t71 = load i8, ptr %t70, align 1
  %t72 = zext i8 %t71 to i64
  %t73 = icmp ult i64 40, 64
  br i1 %t73, label %ok_74, label %trap_74
trap_74:
  call void @abort()
  unreachable
ok_74:
  %t75 = shl i64 %t72, 40
  %t76 = or i64 %t64, %t75
  %t77 = add i64 0, 6
  %t78 = extractvalue %hia.buffer %p_1_1, 0
  %t79 = extractvalue %hia.buffer %p_1_1, 1
  %t80 = icmp ult i64 %t77, %t79
  br i1 %t80, label %ok_81, label %trap_81
trap_81:
  call void @abort()
  unreachable
ok_81:
  %t82 = getelementptr i8, ptr %t78, i64 %t77
  %t83 = load i8, ptr %t82, align 1
  %t84 = zext i8 %t83 to i64
  %t85 = icmp ult i64 48, 64
  br i1 %t85, label %ok_86, label %trap_86
trap_86:
  call void @abort()
  unreachable
ok_86:
  %t87 = shl i64 %t84, 48
  %t88 = or i64 %t76, %t87
  %t89 = add i64 0, 7
  %t90 = extractvalue %hia.buffer %p_1_1, 0
  %t91 = extractvalue %hia.buffer %p_1_1, 1
  %t92 = icmp ult i64 %t89, %t91
  br i1 %t92, label %ok_93, label %trap_93
trap_93:
  call void @abort()
  unreachable
ok_93:
  %t94 = getelementptr i8, ptr %t90, i64 %t89
  %t95 = load i8, ptr %t94, align 1
  %t96 = zext i8 %t95 to i64
  %t97 = icmp ult i64 56, 64
  br i1 %t97, label %ok_98, label %trap_98
trap_98:
  call void @abort()
  unreachable
ok_98:
  %t99 = shl i64 %t96, 56
  %t100 = or i64 %t88, %t99
  %t101 = add i64 8, 0
  %t102 = extractvalue %hia.buffer %p_1_1, 0
  %t103 = extractvalue %hia.buffer %p_1_1, 1
  %t104 = icmp ult i64 %t101, %t103
  br i1 %t104, label %ok_105, label %trap_105
trap_105:
  call void @abort()
  unreachable
ok_105:
  %t106 = getelementptr i8, ptr %t102, i64 %t101
  %t107 = load i8, ptr %t106, align 1
  %t108 = zext i8 %t107 to i64
  %t109 = icmp ult i64 0, 64
  br i1 %t109, label %ok_110, label %trap_110
trap_110:
  call void @abort()
  unreachable
ok_110:
  %t111 = shl i64 %t108, 0
  %t112 = or i64 0, %t111
  %t113 = add i64 8, 1
  %t114 = extractvalue %hia.buffer %p_1_1, 0
  %t115 = extractvalue %hia.buffer %p_1_1, 1
  %t116 = icmp ult i64 %t113, %t115
  br i1 %t116, label %ok_117, label %trap_117
trap_117:
  call void @abort()
  unreachable
ok_117:
  %t118 = getelementptr i8, ptr %t114, i64 %t113
  %t119 = load i8, ptr %t118, align 1
  %t120 = zext i8 %t119 to i64
  %t121 = icmp ult i64 8, 64
  br i1 %t121, label %ok_122, label %trap_122
trap_122:
  call void @abort()
  unreachable
ok_122:
  %t123 = shl i64 %t120, 8
  %t124 = or i64 %t112, %t123
  %t125 = add i64 8, 2
  %t126 = extractvalue %hia.buffer %p_1_1, 0
  %t127 = extractvalue %hia.buffer %p_1_1, 1
  %t128 = icmp ult i64 %t125, %t127
  br i1 %t128, label %ok_129, label %trap_129
trap_129:
  call void @abort()
  unreachable
ok_129:
  %t130 = getelementptr i8, ptr %t126, i64 %t125
  %t131 = load i8, ptr %t130, align 1
  %t132 = zext i8 %t131 to i64
  %t133 = icmp ult i64 16, 64
  br i1 %t133, label %ok_134, label %trap_134
trap_134:
  call void @abort()
  unreachable
ok_134:
  %t135 = shl i64 %t132, 16
  %t136 = or i64 %t124, %t135
  %t137 = add i64 8, 3
  %t138 = extractvalue %hia.buffer %p_1_1, 0
  %t139 = extractvalue %hia.buffer %p_1_1, 1
  %t140 = icmp ult i64 %t137, %t139
  br i1 %t140, label %ok_141, label %trap_141
trap_141:
  call void @abort()
  unreachable
ok_141:
  %t142 = getelementptr i8, ptr %t138, i64 %t137
  %t143 = load i8, ptr %t142, align 1
  %t144 = zext i8 %t143 to i64
  %t145 = icmp ult i64 24, 64
  br i1 %t145, label %ok_146, label %trap_146
trap_146:
  call void @abort()
  unreachable
ok_146:
  %t147 = shl i64 %t144, 24
  %t148 = or i64 %t136, %t147
  %t149 = add i64 8, 4
  %t150 = extractvalue %hia.buffer %p_1_1, 0
  %t151 = extractvalue %hia.buffer %p_1_1, 1
  %t152 = icmp ult i64 %t149, %t151
  br i1 %t152, label %ok_153, label %trap_153
trap_153:
  call void @abort()
  unreachable
ok_153:
  %t154 = getelementptr i8, ptr %t150, i64 %t149
  %t155 = load i8, ptr %t154, align 1
  %t156 = zext i8 %t155 to i64
  %t157 = icmp ult i64 32, 64
  br i1 %t157, label %ok_158, label %trap_158
trap_158:
  call void @abort()
  unreachable
ok_158:
  %t159 = shl i64 %t156, 32
  %t160 = or i64 %t148, %t159
  %t161 = add i64 8, 5
  %t162 = extractvalue %hia.buffer %p_1_1, 0
  %t163 = extractvalue %hia.buffer %p_1_1, 1
  %t164 = icmp ult i64 %t161, %t163
  br i1 %t164, label %ok_165, label %trap_165
trap_165:
  call void @abort()
  unreachable
ok_165:
  %t166 = getelementptr i8, ptr %t162, i64 %t161
  %t167 = load i8, ptr %t166, align 1
  %t168 = zext i8 %t167 to i64
  %t169 = icmp ult i64 40, 64
  br i1 %t169, label %ok_170, label %trap_170
trap_170:
  call void @abort()
  unreachable
ok_170:
  %t171 = shl i64 %t168, 40
  %t172 = or i64 %t160, %t171
  %t173 = add i64 8, 6
  %t174 = extractvalue %hia.buffer %p_1_1, 0
  %t175 = extractvalue %hia.buffer %p_1_1, 1
  %t176 = icmp ult i64 %t173, %t175
  br i1 %t176, label %ok_177, label %trap_177
trap_177:
  call void @abort()
  unreachable
ok_177:
  %t178 = getelementptr i8, ptr %t174, i64 %t173
  %t179 = load i8, ptr %t178, align 1
  %t180 = zext i8 %t179 to i64
  %t181 = icmp ult i64 48, 64
  br i1 %t181, label %ok_182, label %trap_182
trap_182:
  call void @abort()
  unreachable
ok_182:
  %t183 = shl i64 %t180, 48
  %t184 = or i64 %t172, %t183
  %t185 = add i64 8, 7
  %t186 = extractvalue %hia.buffer %p_1_1, 0
  %t187 = extractvalue %hia.buffer %p_1_1, 1
  %t188 = icmp ult i64 %t185, %t187
  br i1 %t188, label %ok_189, label %trap_189
trap_189:
  call void @abort()
  unreachable
ok_189:
  %t190 = getelementptr i8, ptr %t186, i64 %t185
  %t191 = load i8, ptr %t190, align 1
  %t192 = zext i8 %t191 to i64
  %t193 = icmp ult i64 56, 64
  br i1 %t193, label %ok_194, label %trap_194
trap_194:
  call void @abort()
  unreachable
ok_194:
  %t195 = shl i64 %t192, 56
  %t196 = or i64 %t184, %t195
  %t197 = add i64 16, 0
  %t198 = extractvalue %hia.buffer %p_1_1, 0
  %t199 = extractvalue %hia.buffer %p_1_1, 1
  %t200 = icmp ult i64 %t197, %t199
  br i1 %t200, label %ok_201, label %trap_201
trap_201:
  call void @abort()
  unreachable
ok_201:
  %t202 = getelementptr i8, ptr %t198, i64 %t197
  %t203 = load i8, ptr %t202, align 1
  %t204 = zext i8 %t203 to i64
  %t205 = icmp ult i64 0, 64
  br i1 %t205, label %ok_206, label %trap_206
trap_206:
  call void @abort()
  unreachable
ok_206:
  %t207 = shl i64 %t204, 0
  %t208 = or i64 0, %t207
  %t209 = add i64 16, 1
  %t210 = extractvalue %hia.buffer %p_1_1, 0
  %t211 = extractvalue %hia.buffer %p_1_1, 1
  %t212 = icmp ult i64 %t209, %t211
  br i1 %t212, label %ok_213, label %trap_213
trap_213:
  call void @abort()
  unreachable
ok_213:
  %t214 = getelementptr i8, ptr %t210, i64 %t209
  %t215 = load i8, ptr %t214, align 1
  %t216 = zext i8 %t215 to i64
  %t217 = icmp ult i64 8, 64
  br i1 %t217, label %ok_218, label %trap_218
trap_218:
  call void @abort()
  unreachable
ok_218:
  %t219 = shl i64 %t216, 8
  %t220 = or i64 %t208, %t219
  %t221 = add i64 16, 2
  %t222 = extractvalue %hia.buffer %p_1_1, 0
  %t223 = extractvalue %hia.buffer %p_1_1, 1
  %t224 = icmp ult i64 %t221, %t223
  br i1 %t224, label %ok_225, label %trap_225
trap_225:
  call void @abort()
  unreachable
ok_225:
  %t226 = getelementptr i8, ptr %t222, i64 %t221
  %t227 = load i8, ptr %t226, align 1
  %t228 = zext i8 %t227 to i64
  %t229 = icmp ult i64 16, 64
  br i1 %t229, label %ok_230, label %trap_230
trap_230:
  call void @abort()
  unreachable
ok_230:
  %t231 = shl i64 %t228, 16
  %t232 = or i64 %t220, %t231
  %t233 = add i64 16, 3
  %t234 = extractvalue %hia.buffer %p_1_1, 0
  %t235 = extractvalue %hia.buffer %p_1_1, 1
  %t236 = icmp ult i64 %t233, %t235
  br i1 %t236, label %ok_237, label %trap_237
trap_237:
  call void @abort()
  unreachable
ok_237:
  %t238 = getelementptr i8, ptr %t234, i64 %t233
  %t239 = load i8, ptr %t238, align 1
  %t240 = zext i8 %t239 to i64
  %t241 = icmp ult i64 24, 64
  br i1 %t241, label %ok_242, label %trap_242
trap_242:
  call void @abort()
  unreachable
ok_242:
  %t243 = shl i64 %t240, 24
  %t244 = or i64 %t232, %t243
  %t245 = add i64 16, 4
  %t246 = extractvalue %hia.buffer %p_1_1, 0
  %t247 = extractvalue %hia.buffer %p_1_1, 1
  %t248 = icmp ult i64 %t245, %t247
  br i1 %t248, label %ok_249, label %trap_249
trap_249:
  call void @abort()
  unreachable
ok_249:
  %t250 = getelementptr i8, ptr %t246, i64 %t245
  %t251 = load i8, ptr %t250, align 1
  %t252 = zext i8 %t251 to i64
  %t253 = icmp ult i64 32, 64
  br i1 %t253, label %ok_254, label %trap_254
trap_254:
  call void @abort()
  unreachable
ok_254:
  %t255 = shl i64 %t252, 32
  %t256 = or i64 %t244, %t255
  %t257 = add i64 16, 5
  %t258 = extractvalue %hia.buffer %p_1_1, 0
  %t259 = extractvalue %hia.buffer %p_1_1, 1
  %t260 = icmp ult i64 %t257, %t259
  br i1 %t260, label %ok_261, label %trap_261
trap_261:
  call void @abort()
  unreachable
ok_261:
  %t262 = getelementptr i8, ptr %t258, i64 %t257
  %t263 = load i8, ptr %t262, align 1
  %t264 = zext i8 %t263 to i64
  %t265 = icmp ult i64 40, 64
  br i1 %t265, label %ok_266, label %trap_266
trap_266:
  call void @abort()
  unreachable
ok_266:
  %t267 = shl i64 %t264, 40
  %t268 = or i64 %t256, %t267
  %t269 = add i64 16, 6
  %t270 = extractvalue %hia.buffer %p_1_1, 0
  %t271 = extractvalue %hia.buffer %p_1_1, 1
  %t272 = icmp ult i64 %t269, %t271
  br i1 %t272, label %ok_273, label %trap_273
trap_273:
  call void @abort()
  unreachable
ok_273:
  %t274 = getelementptr i8, ptr %t270, i64 %t269
  %t275 = load i8, ptr %t274, align 1
  %t276 = zext i8 %t275 to i64
  %t277 = icmp ult i64 48, 64
  br i1 %t277, label %ok_278, label %trap_278
trap_278:
  call void @abort()
  unreachable
ok_278:
  %t279 = shl i64 %t276, 48
  %t280 = or i64 %t268, %t279
  %t281 = add i64 16, 7
  %t282 = extractvalue %hia.buffer %p_1_1, 0
  %t283 = extractvalue %hia.buffer %p_1_1, 1
  %t284 = icmp ult i64 %t281, %t283
  br i1 %t284, label %ok_285, label %trap_285
trap_285:
  call void @abort()
  unreachable
ok_285:
  %t286 = getelementptr i8, ptr %t282, i64 %t281
  %t287 = load i8, ptr %t286, align 1
  %t288 = zext i8 %t287 to i64
  %t289 = icmp ult i64 56, 64
  br i1 %t289, label %ok_290, label %trap_290
trap_290:
  call void @abort()
  unreachable
ok_290:
  %t291 = shl i64 %t288, 56
  %t292 = or i64 %t280, %t291
  %t293 = add i64 24, 0
  %t294 = extractvalue %hia.buffer %p_1_1, 0
  %t295 = extractvalue %hia.buffer %p_1_1, 1
  %t296 = icmp ult i64 %t293, %t295
  br i1 %t296, label %ok_297, label %trap_297
trap_297:
  call void @abort()
  unreachable
ok_297:
  %t298 = getelementptr i8, ptr %t294, i64 %t293
  %t299 = load i8, ptr %t298, align 1
  %t300 = zext i8 %t299 to i64
  %t301 = icmp ult i64 0, 64
  br i1 %t301, label %ok_302, label %trap_302
trap_302:
  call void @abort()
  unreachable
ok_302:
  %t303 = shl i64 %t300, 0
  %t304 = or i64 0, %t303
  %t305 = add i64 24, 1
  %t306 = extractvalue %hia.buffer %p_1_1, 0
  %t307 = extractvalue %hia.buffer %p_1_1, 1
  %t308 = icmp ult i64 %t305, %t307
  br i1 %t308, label %ok_309, label %trap_309
trap_309:
  call void @abort()
  unreachable
ok_309:
  %t310 = getelementptr i8, ptr %t306, i64 %t305
  %t311 = load i8, ptr %t310, align 1
  %t312 = zext i8 %t311 to i64
  %t313 = icmp ult i64 8, 64
  br i1 %t313, label %ok_314, label %trap_314
trap_314:
  call void @abort()
  unreachable
ok_314:
  %t315 = shl i64 %t312, 8
  %t316 = or i64 %t304, %t315
  %t317 = add i64 24, 2
  %t318 = extractvalue %hia.buffer %p_1_1, 0
  %t319 = extractvalue %hia.buffer %p_1_1, 1
  %t320 = icmp ult i64 %t317, %t319
  br i1 %t320, label %ok_321, label %trap_321
trap_321:
  call void @abort()
  unreachable
ok_321:
  %t322 = getelementptr i8, ptr %t318, i64 %t317
  %t323 = load i8, ptr %t322, align 1
  %t324 = zext i8 %t323 to i64
  %t325 = icmp ult i64 16, 64
  br i1 %t325, label %ok_326, label %trap_326
trap_326:
  call void @abort()
  unreachable
ok_326:
  %t327 = shl i64 %t324, 16
  %t328 = or i64 %t316, %t327
  %t329 = add i64 24, 3
  %t330 = extractvalue %hia.buffer %p_1_1, 0
  %t331 = extractvalue %hia.buffer %p_1_1, 1
  %t332 = icmp ult i64 %t329, %t331
  br i1 %t332, label %ok_333, label %trap_333
trap_333:
  call void @abort()
  unreachable
ok_333:
  %t334 = getelementptr i8, ptr %t330, i64 %t329
  %t335 = load i8, ptr %t334, align 1
  %t336 = zext i8 %t335 to i64
  %t337 = icmp ult i64 24, 64
  br i1 %t337, label %ok_338, label %trap_338
trap_338:
  call void @abort()
  unreachable
ok_338:
  %t339 = shl i64 %t336, 24
  %t340 = or i64 %t328, %t339
  %t341 = add i64 24, 4
  %t342 = extractvalue %hia.buffer %p_1_1, 0
  %t343 = extractvalue %hia.buffer %p_1_1, 1
  %t344 = icmp ult i64 %t341, %t343
  br i1 %t344, label %ok_345, label %trap_345
trap_345:
  call void @abort()
  unreachable
ok_345:
  %t346 = getelementptr i8, ptr %t342, i64 %t341
  %t347 = load i8, ptr %t346, align 1
  %t348 = zext i8 %t347 to i64
  %t349 = icmp ult i64 32, 64
  br i1 %t349, label %ok_350, label %trap_350
trap_350:
  call void @abort()
  unreachable
ok_350:
  %t351 = shl i64 %t348, 32
  %t352 = or i64 %t340, %t351
  %t353 = add i64 24, 5
  %t354 = extractvalue %hia.buffer %p_1_1, 0
  %t355 = extractvalue %hia.buffer %p_1_1, 1
  %t356 = icmp ult i64 %t353, %t355
  br i1 %t356, label %ok_357, label %trap_357
trap_357:
  call void @abort()
  unreachable
ok_357:
  %t358 = getelementptr i8, ptr %t354, i64 %t353
  %t359 = load i8, ptr %t358, align 1
  %t360 = zext i8 %t359 to i64
  %t361 = icmp ult i64 40, 64
  br i1 %t361, label %ok_362, label %trap_362
trap_362:
  call void @abort()
  unreachable
ok_362:
  %t363 = shl i64 %t360, 40
  %t364 = or i64 %t352, %t363
  %t365 = add i64 24, 6
  %t366 = extractvalue %hia.buffer %p_1_1, 0
  %t367 = extractvalue %hia.buffer %p_1_1, 1
  %t368 = icmp ult i64 %t365, %t367
  br i1 %t368, label %ok_369, label %trap_369
trap_369:
  call void @abort()
  unreachable
ok_369:
  %t370 = getelementptr i8, ptr %t366, i64 %t365
  %t371 = load i8, ptr %t370, align 1
  %t372 = zext i8 %t371 to i64
  %t373 = icmp ult i64 48, 64
  br i1 %t373, label %ok_374, label %trap_374
trap_374:
  call void @abort()
  unreachable
ok_374:
  %t375 = shl i64 %t372, 48
  %t376 = or i64 %t364, %t375
  %t377 = add i64 24, 7
  %t378 = extractvalue %hia.buffer %p_1_1, 0
  %t379 = extractvalue %hia.buffer %p_1_1, 1
  %t380 = icmp ult i64 %t377, %t379
  br i1 %t380, label %ok_381, label %trap_381
trap_381:
  call void @abort()
  unreachable
ok_381:
  %t382 = getelementptr i8, ptr %t378, i64 %t377
  %t383 = load i8, ptr %t382, align 1
  %t384 = zext i8 %t383 to i64
  %t385 = icmp ult i64 56, 64
  br i1 %t385, label %ok_386, label %trap_386
trap_386:
  call void @abort()
  unreachable
ok_386:
  %t387 = shl i64 %t384, 56
  %t388 = or i64 %t376, %t387
  %t389 = extractvalue %hia.buffer %p_1_0, 1
  %t390 = icmp ule i64 %t292, %t389
  %t391 = sub i64 %t389, %t292
  %t392 = icmp ule i64 %t388, %t391
  %t393 = and i1 %t390, %t392
  br i1 %t393, label %edge_2, label %edge_3
b2:
  ret i32 4294836225
b3:
  ret i32 0
b4:
  ret i32 1
b5:
  %p_5_0 = phi %hia.buffer [ %p_1_0, %edge_2 ]
  %p_5_1 = phi %hia.buffer [ %p_1_1, %edge_2 ]
  %p_5_2 = phi i64 [ %t100, %edge_2 ]
  %p_5_3 = phi i64 [ %t196, %edge_2 ]
  %p_5_4 = phi i64 [ %t292, %edge_2 ]
  %p_5_5 = phi i64 [ %t388, %edge_2 ]
  %p_5_6 = phi i64 [ %t389, %edge_2 ]
  %p_5_7 = phi i32 [ %p_1_2, %edge_2 ]
  %t394 = icmp ult i64 0, 64
  br i1 %t394, label %ok_395, label %trap_395
trap_395:
  call void @abort()
  unreachable
ok_395:
  %t396 = lshr i64 0, 0
  %t397 = trunc i64 %t396 to i8
  %t398 = add i64 0, 0
  %t399 = extractvalue %hia.buffer %p_5_1, 0
  %t400 = extractvalue %hia.buffer %p_5_1, 1
  %t401 = icmp ult i64 %t398, %t400
  br i1 %t401, label %ok_402, label %trap_402
trap_402:
  call void @abort()
  unreachable
ok_402:
  %t403 = getelementptr i8, ptr %t399, i64 %t398
  store i8 %t397, ptr %t403, align 1
  %t404 = icmp ult i64 8, 64
  br i1 %t404, label %ok_405, label %trap_405
trap_405:
  call void @abort()
  unreachable
ok_405:
  %t406 = lshr i64 0, 8
  %t407 = trunc i64 %t406 to i8
  %t408 = add i64 0, 1
  %t409 = extractvalue %hia.buffer %p_5_1, 0
  %t410 = extractvalue %hia.buffer %p_5_1, 1
  %t411 = icmp ult i64 %t408, %t410
  br i1 %t411, label %ok_412, label %trap_412
trap_412:
  call void @abort()
  unreachable
ok_412:
  %t413 = getelementptr i8, ptr %t409, i64 %t408
  store i8 %t407, ptr %t413, align 1
  %t414 = icmp ult i64 16, 64
  br i1 %t414, label %ok_415, label %trap_415
trap_415:
  call void @abort()
  unreachable
ok_415:
  %t416 = lshr i64 0, 16
  %t417 = trunc i64 %t416 to i8
  %t418 = add i64 0, 2
  %t419 = extractvalue %hia.buffer %p_5_1, 0
  %t420 = extractvalue %hia.buffer %p_5_1, 1
  %t421 = icmp ult i64 %t418, %t420
  br i1 %t421, label %ok_422, label %trap_422
trap_422:
  call void @abort()
  unreachable
ok_422:
  %t423 = getelementptr i8, ptr %t419, i64 %t418
  store i8 %t417, ptr %t423, align 1
  %t424 = icmp ult i64 24, 64
  br i1 %t424, label %ok_425, label %trap_425
trap_425:
  call void @abort()
  unreachable
ok_425:
  %t426 = lshr i64 0, 24
  %t427 = trunc i64 %t426 to i8
  %t428 = add i64 0, 3
  %t429 = extractvalue %hia.buffer %p_5_1, 0
  %t430 = extractvalue %hia.buffer %p_5_1, 1
  %t431 = icmp ult i64 %t428, %t430
  br i1 %t431, label %ok_432, label %trap_432
trap_432:
  call void @abort()
  unreachable
ok_432:
  %t433 = getelementptr i8, ptr %t429, i64 %t428
  store i8 %t427, ptr %t433, align 1
  %t434 = icmp ult i64 32, 64
  br i1 %t434, label %ok_435, label %trap_435
trap_435:
  call void @abort()
  unreachable
ok_435:
  %t436 = lshr i64 0, 32
  %t437 = trunc i64 %t436 to i8
  %t438 = add i64 0, 4
  %t439 = extractvalue %hia.buffer %p_5_1, 0
  %t440 = extractvalue %hia.buffer %p_5_1, 1
  %t441 = icmp ult i64 %t438, %t440
  br i1 %t441, label %ok_442, label %trap_442
trap_442:
  call void @abort()
  unreachable
ok_442:
  %t443 = getelementptr i8, ptr %t439, i64 %t438
  store i8 %t437, ptr %t443, align 1
  %t444 = icmp ult i64 40, 64
  br i1 %t444, label %ok_445, label %trap_445
trap_445:
  call void @abort()
  unreachable
ok_445:
  %t446 = lshr i64 0, 40
  %t447 = trunc i64 %t446 to i8
  %t448 = add i64 0, 5
  %t449 = extractvalue %hia.buffer %p_5_1, 0
  %t450 = extractvalue %hia.buffer %p_5_1, 1
  %t451 = icmp ult i64 %t448, %t450
  br i1 %t451, label %ok_452, label %trap_452
trap_452:
  call void @abort()
  unreachable
ok_452:
  %t453 = getelementptr i8, ptr %t449, i64 %t448
  store i8 %t447, ptr %t453, align 1
  %t454 = icmp ult i64 48, 64
  br i1 %t454, label %ok_455, label %trap_455
trap_455:
  call void @abort()
  unreachable
ok_455:
  %t456 = lshr i64 0, 48
  %t457 = trunc i64 %t456 to i8
  %t458 = add i64 0, 6
  %t459 = extractvalue %hia.buffer %p_5_1, 0
  %t460 = extractvalue %hia.buffer %p_5_1, 1
  %t461 = icmp ult i64 %t458, %t460
  br i1 %t461, label %ok_462, label %trap_462
trap_462:
  call void @abort()
  unreachable
ok_462:
  %t463 = getelementptr i8, ptr %t459, i64 %t458
  store i8 %t457, ptr %t463, align 1
  %t464 = icmp ult i64 56, 64
  br i1 %t464, label %ok_465, label %trap_465
trap_465:
  call void @abort()
  unreachable
ok_465:
  %t466 = lshr i64 0, 56
  %t467 = trunc i64 %t466 to i8
  %t468 = add i64 0, 7
  %t469 = extractvalue %hia.buffer %p_5_1, 0
  %t470 = extractvalue %hia.buffer %p_5_1, 1
  %t471 = icmp ult i64 %t468, %t470
  br i1 %t471, label %ok_472, label %trap_472
trap_472:
  call void @abort()
  unreachable
ok_472:
  %t473 = getelementptr i8, ptr %t469, i64 %t468
  store i8 %t467, ptr %t473, align 1
  %t474 = icmp ult i64 0, 64
  br i1 %t474, label %ok_475, label %trap_475
trap_475:
  call void @abort()
  unreachable
ok_475:
  %t476 = lshr i64 0, 0
  %t477 = trunc i64 %t476 to i8
  %t478 = add i64 8, 0
  %t479 = extractvalue %hia.buffer %p_5_1, 0
  %t480 = extractvalue %hia.buffer %p_5_1, 1
  %t481 = icmp ult i64 %t478, %t480
  br i1 %t481, label %ok_482, label %trap_482
trap_482:
  call void @abort()
  unreachable
ok_482:
  %t483 = getelementptr i8, ptr %t479, i64 %t478
  store i8 %t477, ptr %t483, align 1
  %t484 = icmp ult i64 8, 64
  br i1 %t484, label %ok_485, label %trap_485
trap_485:
  call void @abort()
  unreachable
ok_485:
  %t486 = lshr i64 0, 8
  %t487 = trunc i64 %t486 to i8
  %t488 = add i64 8, 1
  %t489 = extractvalue %hia.buffer %p_5_1, 0
  %t490 = extractvalue %hia.buffer %p_5_1, 1
  %t491 = icmp ult i64 %t488, %t490
  br i1 %t491, label %ok_492, label %trap_492
trap_492:
  call void @abort()
  unreachable
ok_492:
  %t493 = getelementptr i8, ptr %t489, i64 %t488
  store i8 %t487, ptr %t493, align 1
  %t494 = icmp ult i64 16, 64
  br i1 %t494, label %ok_495, label %trap_495
trap_495:
  call void @abort()
  unreachable
ok_495:
  %t496 = lshr i64 0, 16
  %t497 = trunc i64 %t496 to i8
  %t498 = add i64 8, 2
  %t499 = extractvalue %hia.buffer %p_5_1, 0
  %t500 = extractvalue %hia.buffer %p_5_1, 1
  %t501 = icmp ult i64 %t498, %t500
  br i1 %t501, label %ok_502, label %trap_502
trap_502:
  call void @abort()
  unreachable
ok_502:
  %t503 = getelementptr i8, ptr %t499, i64 %t498
  store i8 %t497, ptr %t503, align 1
  %t504 = icmp ult i64 24, 64
  br i1 %t504, label %ok_505, label %trap_505
trap_505:
  call void @abort()
  unreachable
ok_505:
  %t506 = lshr i64 0, 24
  %t507 = trunc i64 %t506 to i8
  %t508 = add i64 8, 3
  %t509 = extractvalue %hia.buffer %p_5_1, 0
  %t510 = extractvalue %hia.buffer %p_5_1, 1
  %t511 = icmp ult i64 %t508, %t510
  br i1 %t511, label %ok_512, label %trap_512
trap_512:
  call void @abort()
  unreachable
ok_512:
  %t513 = getelementptr i8, ptr %t509, i64 %t508
  store i8 %t507, ptr %t513, align 1
  %t514 = icmp ult i64 32, 64
  br i1 %t514, label %ok_515, label %trap_515
trap_515:
  call void @abort()
  unreachable
ok_515:
  %t516 = lshr i64 0, 32
  %t517 = trunc i64 %t516 to i8
  %t518 = add i64 8, 4
  %t519 = extractvalue %hia.buffer %p_5_1, 0
  %t520 = extractvalue %hia.buffer %p_5_1, 1
  %t521 = icmp ult i64 %t518, %t520
  br i1 %t521, label %ok_522, label %trap_522
trap_522:
  call void @abort()
  unreachable
ok_522:
  %t523 = getelementptr i8, ptr %t519, i64 %t518
  store i8 %t517, ptr %t523, align 1
  %t524 = icmp ult i64 40, 64
  br i1 %t524, label %ok_525, label %trap_525
trap_525:
  call void @abort()
  unreachable
ok_525:
  %t526 = lshr i64 0, 40
  %t527 = trunc i64 %t526 to i8
  %t528 = add i64 8, 5
  %t529 = extractvalue %hia.buffer %p_5_1, 0
  %t530 = extractvalue %hia.buffer %p_5_1, 1
  %t531 = icmp ult i64 %t528, %t530
  br i1 %t531, label %ok_532, label %trap_532
trap_532:
  call void @abort()
  unreachable
ok_532:
  %t533 = getelementptr i8, ptr %t529, i64 %t528
  store i8 %t527, ptr %t533, align 1
  %t534 = icmp ult i64 48, 64
  br i1 %t534, label %ok_535, label %trap_535
trap_535:
  call void @abort()
  unreachable
ok_535:
  %t536 = lshr i64 0, 48
  %t537 = trunc i64 %t536 to i8
  %t538 = add i64 8, 6
  %t539 = extractvalue %hia.buffer %p_5_1, 0
  %t540 = extractvalue %hia.buffer %p_5_1, 1
  %t541 = icmp ult i64 %t538, %t540
  br i1 %t541, label %ok_542, label %trap_542
trap_542:
  call void @abort()
  unreachable
ok_542:
  %t543 = getelementptr i8, ptr %t539, i64 %t538
  store i8 %t537, ptr %t543, align 1
  %t544 = icmp ult i64 56, 64
  br i1 %t544, label %ok_545, label %trap_545
trap_545:
  call void @abort()
  unreachable
ok_545:
  %t546 = lshr i64 0, 56
  %t547 = trunc i64 %t546 to i8
  %t548 = add i64 8, 7
  %t549 = extractvalue %hia.buffer %p_5_1, 0
  %t550 = extractvalue %hia.buffer %p_5_1, 1
  %t551 = icmp ult i64 %t548, %t550
  br i1 %t551, label %ok_552, label %trap_552
trap_552:
  call void @abort()
  unreachable
ok_552:
  %t553 = getelementptr i8, ptr %t549, i64 %t548
  store i8 %t547, ptr %t553, align 1
  %t554 = icmp uge i64 %p_5_5, 4
  br i1 %t554, label %edge_4, label %edge_5
b6:
  %p_6_0 = phi %hia.buffer [ %p_5_0, %edge_4 ]
  %p_6_1 = phi %hia.buffer [ %p_5_1, %edge_4 ]
  %p_6_2 = phi i64 [ %p_5_2, %edge_4 ]
  %p_6_3 = phi i64 [ %p_5_3, %edge_4 ]
  %p_6_4 = phi i64 [ %p_5_4, %edge_4 ]
  %p_6_5 = phi i64 [ %p_5_5, %edge_4 ]
  %p_6_6 = phi i64 [ %p_5_6, %edge_4 ]
  %p_6_7 = phi i32 [ %p_5_7, %edge_4 ]
  %t555 = add i64 %p_6_4, 0
  %t556 = extractvalue %hia.buffer %p_6_0, 0
  %t557 = extractvalue %hia.buffer %p_6_0, 1
  %t558 = icmp ult i64 %t555, %t557
  br i1 %t558, label %ok_559, label %trap_559
trap_559:
  call void @abort()
  unreachable
ok_559:
  %t560 = getelementptr i8, ptr %t556, i64 %t555
  %t561 = load i8, ptr %t560, align 1
  %t562 = zext i8 %t561 to i64
  %t563 = icmp ult i64 24, 64
  br i1 %t563, label %ok_564, label %trap_564
trap_564:
  call void @abort()
  unreachable
ok_564:
  %t565 = shl i64 %t562, 24
  %t566 = or i64 0, %t565
  %t567 = add i64 %p_6_4, 1
  %t568 = extractvalue %hia.buffer %p_6_0, 0
  %t569 = extractvalue %hia.buffer %p_6_0, 1
  %t570 = icmp ult i64 %t567, %t569
  br i1 %t570, label %ok_571, label %trap_571
trap_571:
  call void @abort()
  unreachable
ok_571:
  %t572 = getelementptr i8, ptr %t568, i64 %t567
  %t573 = load i8, ptr %t572, align 1
  %t574 = zext i8 %t573 to i64
  %t575 = icmp ult i64 16, 64
  br i1 %t575, label %ok_576, label %trap_576
trap_576:
  call void @abort()
  unreachable
ok_576:
  %t577 = shl i64 %t574, 16
  %t578 = or i64 %t566, %t577
  %t579 = add i64 %p_6_4, 2
  %t580 = extractvalue %hia.buffer %p_6_0, 0
  %t581 = extractvalue %hia.buffer %p_6_0, 1
  %t582 = icmp ult i64 %t579, %t581
  br i1 %t582, label %ok_583, label %trap_583
trap_583:
  call void @abort()
  unreachable
ok_583:
  %t584 = getelementptr i8, ptr %t580, i64 %t579
  %t585 = load i8, ptr %t584, align 1
  %t586 = zext i8 %t585 to i64
  %t587 = icmp ult i64 8, 64
  br i1 %t587, label %ok_588, label %trap_588
trap_588:
  call void @abort()
  unreachable
ok_588:
  %t589 = shl i64 %t586, 8
  %t590 = or i64 %t578, %t589
  %t591 = add i64 %p_6_4, 3
  %t592 = extractvalue %hia.buffer %p_6_0, 0
  %t593 = extractvalue %hia.buffer %p_6_0, 1
  %t594 = icmp ult i64 %t591, %t593
  br i1 %t594, label %ok_595, label %trap_595
trap_595:
  call void @abort()
  unreachable
ok_595:
  %t596 = getelementptr i8, ptr %t592, i64 %t591
  %t597 = load i8, ptr %t596, align 1
  %t598 = zext i8 %t597 to i64
  %t599 = icmp ult i64 0, 64
  br i1 %t599, label %ok_600, label %trap_600
trap_600:
  call void @abort()
  unreachable
ok_600:
  %t601 = shl i64 %t598, 0
  %t602 = or i64 %t590, %t601
  %t603 = icmp ult i64 0, 64
  br i1 %t603, label %ok_604, label %trap_604
trap_604:
  call void @abort()
  unreachable
ok_604:
  %t605 = lshr i64 %t602, 0
  %t606 = trunc i64 %t605 to i8
  %t607 = add i64 0, 0
  %t608 = extractvalue %hia.buffer %p_6_1, 0
  %t609 = extractvalue %hia.buffer %p_6_1, 1
  %t610 = icmp ult i64 %t607, %t609
  br i1 %t610, label %ok_611, label %trap_611
trap_611:
  call void @abort()
  unreachable
ok_611:
  %t612 = getelementptr i8, ptr %t608, i64 %t607
  store i8 %t606, ptr %t612, align 1
  %t613 = icmp ult i64 8, 64
  br i1 %t613, label %ok_614, label %trap_614
trap_614:
  call void @abort()
  unreachable
ok_614:
  %t615 = lshr i64 %t602, 8
  %t616 = trunc i64 %t615 to i8
  %t617 = add i64 0, 1
  %t618 = extractvalue %hia.buffer %p_6_1, 0
  %t619 = extractvalue %hia.buffer %p_6_1, 1
  %t620 = icmp ult i64 %t617, %t619
  br i1 %t620, label %ok_621, label %trap_621
trap_621:
  call void @abort()
  unreachable
ok_621:
  %t622 = getelementptr i8, ptr %t618, i64 %t617
  store i8 %t616, ptr %t622, align 1
  %t623 = icmp ult i64 16, 64
  br i1 %t623, label %ok_624, label %trap_624
trap_624:
  call void @abort()
  unreachable
ok_624:
  %t625 = lshr i64 %t602, 16
  %t626 = trunc i64 %t625 to i8
  %t627 = add i64 0, 2
  %t628 = extractvalue %hia.buffer %p_6_1, 0
  %t629 = extractvalue %hia.buffer %p_6_1, 1
  %t630 = icmp ult i64 %t627, %t629
  br i1 %t630, label %ok_631, label %trap_631
trap_631:
  call void @abort()
  unreachable
ok_631:
  %t632 = getelementptr i8, ptr %t628, i64 %t627
  store i8 %t626, ptr %t632, align 1
  %t633 = icmp ult i64 24, 64
  br i1 %t633, label %ok_634, label %trap_634
trap_634:
  call void @abort()
  unreachable
ok_634:
  %t635 = lshr i64 %t602, 24
  %t636 = trunc i64 %t635 to i8
  %t637 = add i64 0, 3
  %t638 = extractvalue %hia.buffer %p_6_1, 0
  %t639 = extractvalue %hia.buffer %p_6_1, 1
  %t640 = icmp ult i64 %t637, %t639
  br i1 %t640, label %ok_641, label %trap_641
trap_641:
  call void @abort()
  unreachable
ok_641:
  %t642 = getelementptr i8, ptr %t638, i64 %t637
  store i8 %t636, ptr %t642, align 1
  %t643 = icmp ult i64 32, 64
  br i1 %t643, label %ok_644, label %trap_644
trap_644:
  call void @abort()
  unreachable
ok_644:
  %t645 = lshr i64 %t602, 32
  %t646 = trunc i64 %t645 to i8
  %t647 = add i64 0, 4
  %t648 = extractvalue %hia.buffer %p_6_1, 0
  %t649 = extractvalue %hia.buffer %p_6_1, 1
  %t650 = icmp ult i64 %t647, %t649
  br i1 %t650, label %ok_651, label %trap_651
trap_651:
  call void @abort()
  unreachable
ok_651:
  %t652 = getelementptr i8, ptr %t648, i64 %t647
  store i8 %t646, ptr %t652, align 1
  %t653 = icmp ult i64 40, 64
  br i1 %t653, label %ok_654, label %trap_654
trap_654:
  call void @abort()
  unreachable
ok_654:
  %t655 = lshr i64 %t602, 40
  %t656 = trunc i64 %t655 to i8
  %t657 = add i64 0, 5
  %t658 = extractvalue %hia.buffer %p_6_1, 0
  %t659 = extractvalue %hia.buffer %p_6_1, 1
  %t660 = icmp ult i64 %t657, %t659
  br i1 %t660, label %ok_661, label %trap_661
trap_661:
  call void @abort()
  unreachable
ok_661:
  %t662 = getelementptr i8, ptr %t658, i64 %t657
  store i8 %t656, ptr %t662, align 1
  %t663 = icmp ult i64 48, 64
  br i1 %t663, label %ok_664, label %trap_664
trap_664:
  call void @abort()
  unreachable
ok_664:
  %t665 = lshr i64 %t602, 48
  %t666 = trunc i64 %t665 to i8
  %t667 = add i64 0, 6
  %t668 = extractvalue %hia.buffer %p_6_1, 0
  %t669 = extractvalue %hia.buffer %p_6_1, 1
  %t670 = icmp ult i64 %t667, %t669
  br i1 %t670, label %ok_671, label %trap_671
trap_671:
  call void @abort()
  unreachable
ok_671:
  %t672 = getelementptr i8, ptr %t668, i64 %t667
  store i8 %t666, ptr %t672, align 1
  %t673 = icmp ult i64 56, 64
  br i1 %t673, label %ok_674, label %trap_674
trap_674:
  call void @abort()
  unreachable
ok_674:
  %t675 = lshr i64 %t602, 56
  %t676 = trunc i64 %t675 to i8
  %t677 = add i64 0, 7
  %t678 = extractvalue %hia.buffer %p_6_1, 0
  %t679 = extractvalue %hia.buffer %p_6_1, 1
  %t680 = icmp ult i64 %t677, %t679
  br i1 %t680, label %ok_681, label %trap_681
trap_681:
  call void @abort()
  unreachable
ok_681:
  %t682 = getelementptr i8, ptr %t678, i64 %t677
  store i8 %t676, ptr %t682, align 1
  %t683 = add i64 %p_6_4, 4
  %t684 = sub i64 %p_6_5, 4
  %t685 = icmp ult i64 0, 64
  br i1 %t685, label %ok_686, label %trap_686
trap_686:
  call void @abort()
  unreachable
ok_686:
  %t687 = lshr i64 %t683, 0
  %t688 = trunc i64 %t687 to i8
  %t689 = add i64 16, 0
  %t690 = extractvalue %hia.buffer %p_6_1, 0
  %t691 = extractvalue %hia.buffer %p_6_1, 1
  %t692 = icmp ult i64 %t689, %t691
  br i1 %t692, label %ok_693, label %trap_693
trap_693:
  call void @abort()
  unreachable
ok_693:
  %t694 = getelementptr i8, ptr %t690, i64 %t689
  store i8 %t688, ptr %t694, align 1
  %t695 = icmp ult i64 8, 64
  br i1 %t695, label %ok_696, label %trap_696
trap_696:
  call void @abort()
  unreachable
ok_696:
  %t697 = lshr i64 %t683, 8
  %t698 = trunc i64 %t697 to i8
  %t699 = add i64 16, 1
  %t700 = extractvalue %hia.buffer %p_6_1, 0
  %t701 = extractvalue %hia.buffer %p_6_1, 1
  %t702 = icmp ult i64 %t699, %t701
  br i1 %t702, label %ok_703, label %trap_703
trap_703:
  call void @abort()
  unreachable
ok_703:
  %t704 = getelementptr i8, ptr %t700, i64 %t699
  store i8 %t698, ptr %t704, align 1
  %t705 = icmp ult i64 16, 64
  br i1 %t705, label %ok_706, label %trap_706
trap_706:
  call void @abort()
  unreachable
ok_706:
  %t707 = lshr i64 %t683, 16
  %t708 = trunc i64 %t707 to i8
  %t709 = add i64 16, 2
  %t710 = extractvalue %hia.buffer %p_6_1, 0
  %t711 = extractvalue %hia.buffer %p_6_1, 1
  %t712 = icmp ult i64 %t709, %t711
  br i1 %t712, label %ok_713, label %trap_713
trap_713:
  call void @abort()
  unreachable
ok_713:
  %t714 = getelementptr i8, ptr %t710, i64 %t709
  store i8 %t708, ptr %t714, align 1
  %t715 = icmp ult i64 24, 64
  br i1 %t715, label %ok_716, label %trap_716
trap_716:
  call void @abort()
  unreachable
ok_716:
  %t717 = lshr i64 %t683, 24
  %t718 = trunc i64 %t717 to i8
  %t719 = add i64 16, 3
  %t720 = extractvalue %hia.buffer %p_6_1, 0
  %t721 = extractvalue %hia.buffer %p_6_1, 1
  %t722 = icmp ult i64 %t719, %t721
  br i1 %t722, label %ok_723, label %trap_723
trap_723:
  call void @abort()
  unreachable
ok_723:
  %t724 = getelementptr i8, ptr %t720, i64 %t719
  store i8 %t718, ptr %t724, align 1
  %t725 = icmp ult i64 32, 64
  br i1 %t725, label %ok_726, label %trap_726
trap_726:
  call void @abort()
  unreachable
ok_726:
  %t727 = lshr i64 %t683, 32
  %t728 = trunc i64 %t727 to i8
  %t729 = add i64 16, 4
  %t730 = extractvalue %hia.buffer %p_6_1, 0
  %t731 = extractvalue %hia.buffer %p_6_1, 1
  %t732 = icmp ult i64 %t729, %t731
  br i1 %t732, label %ok_733, label %trap_733
trap_733:
  call void @abort()
  unreachable
ok_733:
  %t734 = getelementptr i8, ptr %t730, i64 %t729
  store i8 %t728, ptr %t734, align 1
  %t735 = icmp ult i64 40, 64
  br i1 %t735, label %ok_736, label %trap_736
trap_736:
  call void @abort()
  unreachable
ok_736:
  %t737 = lshr i64 %t683, 40
  %t738 = trunc i64 %t737 to i8
  %t739 = add i64 16, 5
  %t740 = extractvalue %hia.buffer %p_6_1, 0
  %t741 = extractvalue %hia.buffer %p_6_1, 1
  %t742 = icmp ult i64 %t739, %t741
  br i1 %t742, label %ok_743, label %trap_743
trap_743:
  call void @abort()
  unreachable
ok_743:
  %t744 = getelementptr i8, ptr %t740, i64 %t739
  store i8 %t738, ptr %t744, align 1
  %t745 = icmp ult i64 48, 64
  br i1 %t745, label %ok_746, label %trap_746
trap_746:
  call void @abort()
  unreachable
ok_746:
  %t747 = lshr i64 %t683, 48
  %t748 = trunc i64 %t747 to i8
  %t749 = add i64 16, 6
  %t750 = extractvalue %hia.buffer %p_6_1, 0
  %t751 = extractvalue %hia.buffer %p_6_1, 1
  %t752 = icmp ult i64 %t749, %t751
  br i1 %t752, label %ok_753, label %trap_753
trap_753:
  call void @abort()
  unreachable
ok_753:
  %t754 = getelementptr i8, ptr %t750, i64 %t749
  store i8 %t748, ptr %t754, align 1
  %t755 = icmp ult i64 56, 64
  br i1 %t755, label %ok_756, label %trap_756
trap_756:
  call void @abort()
  unreachable
ok_756:
  %t757 = lshr i64 %t683, 56
  %t758 = trunc i64 %t757 to i8
  %t759 = add i64 16, 7
  %t760 = extractvalue %hia.buffer %p_6_1, 0
  %t761 = extractvalue %hia.buffer %p_6_1, 1
  %t762 = icmp ult i64 %t759, %t761
  br i1 %t762, label %ok_763, label %trap_763
trap_763:
  call void @abort()
  unreachable
ok_763:
  %t764 = getelementptr i8, ptr %t760, i64 %t759
  store i8 %t758, ptr %t764, align 1
  %t765 = icmp ult i64 0, 64
  br i1 %t765, label %ok_766, label %trap_766
trap_766:
  call void @abort()
  unreachable
ok_766:
  %t767 = lshr i64 %t684, 0
  %t768 = trunc i64 %t767 to i8
  %t769 = add i64 24, 0
  %t770 = extractvalue %hia.buffer %p_6_1, 0
  %t771 = extractvalue %hia.buffer %p_6_1, 1
  %t772 = icmp ult i64 %t769, %t771
  br i1 %t772, label %ok_773, label %trap_773
trap_773:
  call void @abort()
  unreachable
ok_773:
  %t774 = getelementptr i8, ptr %t770, i64 %t769
  store i8 %t768, ptr %t774, align 1
  %t775 = icmp ult i64 8, 64
  br i1 %t775, label %ok_776, label %trap_776
trap_776:
  call void @abort()
  unreachable
ok_776:
  %t777 = lshr i64 %t684, 8
  %t778 = trunc i64 %t777 to i8
  %t779 = add i64 24, 1
  %t780 = extractvalue %hia.buffer %p_6_1, 0
  %t781 = extractvalue %hia.buffer %p_6_1, 1
  %t782 = icmp ult i64 %t779, %t781
  br i1 %t782, label %ok_783, label %trap_783
trap_783:
  call void @abort()
  unreachable
ok_783:
  %t784 = getelementptr i8, ptr %t780, i64 %t779
  store i8 %t778, ptr %t784, align 1
  %t785 = icmp ult i64 16, 64
  br i1 %t785, label %ok_786, label %trap_786
trap_786:
  call void @abort()
  unreachable
ok_786:
  %t787 = lshr i64 %t684, 16
  %t788 = trunc i64 %t787 to i8
  %t789 = add i64 24, 2
  %t790 = extractvalue %hia.buffer %p_6_1, 0
  %t791 = extractvalue %hia.buffer %p_6_1, 1
  %t792 = icmp ult i64 %t789, %t791
  br i1 %t792, label %ok_793, label %trap_793
trap_793:
  call void @abort()
  unreachable
ok_793:
  %t794 = getelementptr i8, ptr %t790, i64 %t789
  store i8 %t788, ptr %t794, align 1
  %t795 = icmp ult i64 24, 64
  br i1 %t795, label %ok_796, label %trap_796
trap_796:
  call void @abort()
  unreachable
ok_796:
  %t797 = lshr i64 %t684, 24
  %t798 = trunc i64 %t797 to i8
  %t799 = add i64 24, 3
  %t800 = extractvalue %hia.buffer %p_6_1, 0
  %t801 = extractvalue %hia.buffer %p_6_1, 1
  %t802 = icmp ult i64 %t799, %t801
  br i1 %t802, label %ok_803, label %trap_803
trap_803:
  call void @abort()
  unreachable
ok_803:
  %t804 = getelementptr i8, ptr %t800, i64 %t799
  store i8 %t798, ptr %t804, align 1
  %t805 = icmp ult i64 32, 64
  br i1 %t805, label %ok_806, label %trap_806
trap_806:
  call void @abort()
  unreachable
ok_806:
  %t807 = lshr i64 %t684, 32
  %t808 = trunc i64 %t807 to i8
  %t809 = add i64 24, 4
  %t810 = extractvalue %hia.buffer %p_6_1, 0
  %t811 = extractvalue %hia.buffer %p_6_1, 1
  %t812 = icmp ult i64 %t809, %t811
  br i1 %t812, label %ok_813, label %trap_813
trap_813:
  call void @abort()
  unreachable
ok_813:
  %t814 = getelementptr i8, ptr %t810, i64 %t809
  store i8 %t808, ptr %t814, align 1
  %t815 = icmp ult i64 40, 64
  br i1 %t815, label %ok_816, label %trap_816
trap_816:
  call void @abort()
  unreachable
ok_816:
  %t817 = lshr i64 %t684, 40
  %t818 = trunc i64 %t817 to i8
  %t819 = add i64 24, 5
  %t820 = extractvalue %hia.buffer %p_6_1, 0
  %t821 = extractvalue %hia.buffer %p_6_1, 1
  %t822 = icmp ult i64 %t819, %t821
  br i1 %t822, label %ok_823, label %trap_823
trap_823:
  call void @abort()
  unreachable
ok_823:
  %t824 = getelementptr i8, ptr %t820, i64 %t819
  store i8 %t818, ptr %t824, align 1
  %t825 = icmp ult i64 48, 64
  br i1 %t825, label %ok_826, label %trap_826
trap_826:
  call void @abort()
  unreachable
ok_826:
  %t827 = lshr i64 %t684, 48
  %t828 = trunc i64 %t827 to i8
  %t829 = add i64 24, 6
  %t830 = extractvalue %hia.buffer %p_6_1, 0
  %t831 = extractvalue %hia.buffer %p_6_1, 1
  %t832 = icmp ult i64 %t829, %t831
  br i1 %t832, label %ok_833, label %trap_833
trap_833:
  call void @abort()
  unreachable
ok_833:
  %t834 = getelementptr i8, ptr %t830, i64 %t829
  store i8 %t828, ptr %t834, align 1
  %t835 = icmp ult i64 56, 64
  br i1 %t835, label %ok_836, label %trap_836
trap_836:
  call void @abort()
  unreachable
ok_836:
  %t837 = lshr i64 %t684, 56
  %t838 = trunc i64 %t837 to i8
  %t839 = add i64 24, 7
  %t840 = extractvalue %hia.buffer %p_6_1, 0
  %t841 = extractvalue %hia.buffer %p_6_1, 1
  %t842 = icmp ult i64 %t839, %t841
  br i1 %t842, label %ok_843, label %trap_843
trap_843:
  call void @abort()
  unreachable
ok_843:
  %t844 = getelementptr i8, ptr %t840, i64 %t839
  store i8 %t838, ptr %t844, align 1
  %t845 = icmp ne i32 %p_6_7, 0
  br i1 %t845, label %edge_6, label %edge_7
b7:
  %p_7_0 = phi %hia.buffer [ %p_6_0, %edge_6 ]
  %p_7_1 = phi %hia.buffer [ %p_6_1, %edge_6 ]
  %p_7_2 = phi i64 [ %p_6_2, %edge_6 ]
  %p_7_3 = phi i64 [ %p_6_3, %edge_6 ]
  %p_7_4 = phi i64 [ %t683, %edge_6 ]
  %p_7_5 = phi i64 [ %t684, %edge_6 ]
  %p_7_6 = phi i64 [ %p_6_6, %edge_6 ]
  %p_7_7 = phi i32 [ %p_6_7, %edge_6 ]
  %t846 = icmp uge i64 %p_7_5, 4
  br i1 %t846, label %edge_8, label %edge_9
b8:
  %p_8_0 = phi %hia.buffer [ %p_7_0, %edge_8 ]
  %p_8_1 = phi %hia.buffer [ %p_7_1, %edge_8 ]
  %p_8_2 = phi i64 [ %p_7_2, %edge_8 ]
  %p_8_3 = phi i64 [ %p_7_3, %edge_8 ]
  %p_8_4 = phi i64 [ %p_7_4, %edge_8 ]
  %p_8_5 = phi i64 [ %p_7_5, %edge_8 ]
  %p_8_6 = phi i64 [ %p_7_6, %edge_8 ]
  %p_8_7 = phi i32 [ %p_7_7, %edge_8 ]
  %t847 = add i64 %p_8_4, 0
  %t848 = extractvalue %hia.buffer %p_8_0, 0
  %t849 = extractvalue %hia.buffer %p_8_0, 1
  %t850 = icmp ult i64 %t847, %t849
  br i1 %t850, label %ok_851, label %trap_851
trap_851:
  call void @abort()
  unreachable
ok_851:
  %t852 = getelementptr i8, ptr %t848, i64 %t847
  %t853 = load i8, ptr %t852, align 1
  %t854 = zext i8 %t853 to i64
  %t855 = icmp ult i64 24, 64
  br i1 %t855, label %ok_856, label %trap_856
trap_856:
  call void @abort()
  unreachable
ok_856:
  %t857 = shl i64 %t854, 24
  %t858 = or i64 0, %t857
  %t859 = add i64 %p_8_4, 1
  %t860 = extractvalue %hia.buffer %p_8_0, 0
  %t861 = extractvalue %hia.buffer %p_8_0, 1
  %t862 = icmp ult i64 %t859, %t861
  br i1 %t862, label %ok_863, label %trap_863
trap_863:
  call void @abort()
  unreachable
ok_863:
  %t864 = getelementptr i8, ptr %t860, i64 %t859
  %t865 = load i8, ptr %t864, align 1
  %t866 = zext i8 %t865 to i64
  %t867 = icmp ult i64 16, 64
  br i1 %t867, label %ok_868, label %trap_868
trap_868:
  call void @abort()
  unreachable
ok_868:
  %t869 = shl i64 %t866, 16
  %t870 = or i64 %t858, %t869
  %t871 = add i64 %p_8_4, 2
  %t872 = extractvalue %hia.buffer %p_8_0, 0
  %t873 = extractvalue %hia.buffer %p_8_0, 1
  %t874 = icmp ult i64 %t871, %t873
  br i1 %t874, label %ok_875, label %trap_875
trap_875:
  call void @abort()
  unreachable
ok_875:
  %t876 = getelementptr i8, ptr %t872, i64 %t871
  %t877 = load i8, ptr %t876, align 1
  %t878 = zext i8 %t877 to i64
  %t879 = icmp ult i64 8, 64
  br i1 %t879, label %ok_880, label %trap_880
trap_880:
  call void @abort()
  unreachable
ok_880:
  %t881 = shl i64 %t878, 8
  %t882 = or i64 %t870, %t881
  %t883 = add i64 %p_8_4, 3
  %t884 = extractvalue %hia.buffer %p_8_0, 0
  %t885 = extractvalue %hia.buffer %p_8_0, 1
  %t886 = icmp ult i64 %t883, %t885
  br i1 %t886, label %ok_887, label %trap_887
trap_887:
  call void @abort()
  unreachable
ok_887:
  %t888 = getelementptr i8, ptr %t884, i64 %t883
  %t889 = load i8, ptr %t888, align 1
  %t890 = zext i8 %t889 to i64
  %t891 = icmp ult i64 0, 64
  br i1 %t891, label %ok_892, label %trap_892
trap_892:
  call void @abort()
  unreachable
ok_892:
  %t893 = shl i64 %t890, 0
  %t894 = or i64 %t882, %t893
  %t895 = icmp ult i64 0, 64
  br i1 %t895, label %ok_896, label %trap_896
trap_896:
  call void @abort()
  unreachable
ok_896:
  %t897 = lshr i64 %t894, 0
  %t898 = trunc i64 %t897 to i8
  %t899 = add i64 8, 0
  %t900 = extractvalue %hia.buffer %p_8_1, 0
  %t901 = extractvalue %hia.buffer %p_8_1, 1
  %t902 = icmp ult i64 %t899, %t901
  br i1 %t902, label %ok_903, label %trap_903
trap_903:
  call void @abort()
  unreachable
ok_903:
  %t904 = getelementptr i8, ptr %t900, i64 %t899
  store i8 %t898, ptr %t904, align 1
  %t905 = icmp ult i64 8, 64
  br i1 %t905, label %ok_906, label %trap_906
trap_906:
  call void @abort()
  unreachable
ok_906:
  %t907 = lshr i64 %t894, 8
  %t908 = trunc i64 %t907 to i8
  %t909 = add i64 8, 1
  %t910 = extractvalue %hia.buffer %p_8_1, 0
  %t911 = extractvalue %hia.buffer %p_8_1, 1
  %t912 = icmp ult i64 %t909, %t911
  br i1 %t912, label %ok_913, label %trap_913
trap_913:
  call void @abort()
  unreachable
ok_913:
  %t914 = getelementptr i8, ptr %t910, i64 %t909
  store i8 %t908, ptr %t914, align 1
  %t915 = icmp ult i64 16, 64
  br i1 %t915, label %ok_916, label %trap_916
trap_916:
  call void @abort()
  unreachable
ok_916:
  %t917 = lshr i64 %t894, 16
  %t918 = trunc i64 %t917 to i8
  %t919 = add i64 8, 2
  %t920 = extractvalue %hia.buffer %p_8_1, 0
  %t921 = extractvalue %hia.buffer %p_8_1, 1
  %t922 = icmp ult i64 %t919, %t921
  br i1 %t922, label %ok_923, label %trap_923
trap_923:
  call void @abort()
  unreachable
ok_923:
  %t924 = getelementptr i8, ptr %t920, i64 %t919
  store i8 %t918, ptr %t924, align 1
  %t925 = icmp ult i64 24, 64
  br i1 %t925, label %ok_926, label %trap_926
trap_926:
  call void @abort()
  unreachable
ok_926:
  %t927 = lshr i64 %t894, 24
  %t928 = trunc i64 %t927 to i8
  %t929 = add i64 8, 3
  %t930 = extractvalue %hia.buffer %p_8_1, 0
  %t931 = extractvalue %hia.buffer %p_8_1, 1
  %t932 = icmp ult i64 %t929, %t931
  br i1 %t932, label %ok_933, label %trap_933
trap_933:
  call void @abort()
  unreachable
ok_933:
  %t934 = getelementptr i8, ptr %t930, i64 %t929
  store i8 %t928, ptr %t934, align 1
  %t935 = icmp ult i64 32, 64
  br i1 %t935, label %ok_936, label %trap_936
trap_936:
  call void @abort()
  unreachable
ok_936:
  %t937 = lshr i64 %t894, 32
  %t938 = trunc i64 %t937 to i8
  %t939 = add i64 8, 4
  %t940 = extractvalue %hia.buffer %p_8_1, 0
  %t941 = extractvalue %hia.buffer %p_8_1, 1
  %t942 = icmp ult i64 %t939, %t941
  br i1 %t942, label %ok_943, label %trap_943
trap_943:
  call void @abort()
  unreachable
ok_943:
  %t944 = getelementptr i8, ptr %t940, i64 %t939
  store i8 %t938, ptr %t944, align 1
  %t945 = icmp ult i64 40, 64
  br i1 %t945, label %ok_946, label %trap_946
trap_946:
  call void @abort()
  unreachable
ok_946:
  %t947 = lshr i64 %t894, 40
  %t948 = trunc i64 %t947 to i8
  %t949 = add i64 8, 5
  %t950 = extractvalue %hia.buffer %p_8_1, 0
  %t951 = extractvalue %hia.buffer %p_8_1, 1
  %t952 = icmp ult i64 %t949, %t951
  br i1 %t952, label %ok_953, label %trap_953
trap_953:
  call void @abort()
  unreachable
ok_953:
  %t954 = getelementptr i8, ptr %t950, i64 %t949
  store i8 %t948, ptr %t954, align 1
  %t955 = icmp ult i64 48, 64
  br i1 %t955, label %ok_956, label %trap_956
trap_956:
  call void @abort()
  unreachable
ok_956:
  %t957 = lshr i64 %t894, 48
  %t958 = trunc i64 %t957 to i8
  %t959 = add i64 8, 6
  %t960 = extractvalue %hia.buffer %p_8_1, 0
  %t961 = extractvalue %hia.buffer %p_8_1, 1
  %t962 = icmp ult i64 %t959, %t961
  br i1 %t962, label %ok_963, label %trap_963
trap_963:
  call void @abort()
  unreachable
ok_963:
  %t964 = getelementptr i8, ptr %t960, i64 %t959
  store i8 %t958, ptr %t964, align 1
  %t965 = icmp ult i64 56, 64
  br i1 %t965, label %ok_966, label %trap_966
trap_966:
  call void @abort()
  unreachable
ok_966:
  %t967 = lshr i64 %t894, 56
  %t968 = trunc i64 %t967 to i8
  %t969 = add i64 8, 7
  %t970 = extractvalue %hia.buffer %p_8_1, 0
  %t971 = extractvalue %hia.buffer %p_8_1, 1
  %t972 = icmp ult i64 %t969, %t971
  br i1 %t972, label %ok_973, label %trap_973
trap_973:
  call void @abort()
  unreachable
ok_973:
  %t974 = getelementptr i8, ptr %t970, i64 %t969
  store i8 %t968, ptr %t974, align 1
  %t975 = add i64 %p_8_4, 4
  %t976 = sub i64 %p_8_5, 4
  %t977 = icmp ult i64 0, 64
  br i1 %t977, label %ok_978, label %trap_978
trap_978:
  call void @abort()
  unreachable
ok_978:
  %t979 = lshr i64 %t975, 0
  %t980 = trunc i64 %t979 to i8
  %t981 = add i64 16, 0
  %t982 = extractvalue %hia.buffer %p_8_1, 0
  %t983 = extractvalue %hia.buffer %p_8_1, 1
  %t984 = icmp ult i64 %t981, %t983
  br i1 %t984, label %ok_985, label %trap_985
trap_985:
  call void @abort()
  unreachable
ok_985:
  %t986 = getelementptr i8, ptr %t982, i64 %t981
  store i8 %t980, ptr %t986, align 1
  %t987 = icmp ult i64 8, 64
  br i1 %t987, label %ok_988, label %trap_988
trap_988:
  call void @abort()
  unreachable
ok_988:
  %t989 = lshr i64 %t975, 8
  %t990 = trunc i64 %t989 to i8
  %t991 = add i64 16, 1
  %t992 = extractvalue %hia.buffer %p_8_1, 0
  %t993 = extractvalue %hia.buffer %p_8_1, 1
  %t994 = icmp ult i64 %t991, %t993
  br i1 %t994, label %ok_995, label %trap_995
trap_995:
  call void @abort()
  unreachable
ok_995:
  %t996 = getelementptr i8, ptr %t992, i64 %t991
  store i8 %t990, ptr %t996, align 1
  %t997 = icmp ult i64 16, 64
  br i1 %t997, label %ok_998, label %trap_998
trap_998:
  call void @abort()
  unreachable
ok_998:
  %t999 = lshr i64 %t975, 16
  %t1000 = trunc i64 %t999 to i8
  %t1001 = add i64 16, 2
  %t1002 = extractvalue %hia.buffer %p_8_1, 0
  %t1003 = extractvalue %hia.buffer %p_8_1, 1
  %t1004 = icmp ult i64 %t1001, %t1003
  br i1 %t1004, label %ok_1005, label %trap_1005
trap_1005:
  call void @abort()
  unreachable
ok_1005:
  %t1006 = getelementptr i8, ptr %t1002, i64 %t1001
  store i8 %t1000, ptr %t1006, align 1
  %t1007 = icmp ult i64 24, 64
  br i1 %t1007, label %ok_1008, label %trap_1008
trap_1008:
  call void @abort()
  unreachable
ok_1008:
  %t1009 = lshr i64 %t975, 24
  %t1010 = trunc i64 %t1009 to i8
  %t1011 = add i64 16, 3
  %t1012 = extractvalue %hia.buffer %p_8_1, 0
  %t1013 = extractvalue %hia.buffer %p_8_1, 1
  %t1014 = icmp ult i64 %t1011, %t1013
  br i1 %t1014, label %ok_1015, label %trap_1015
trap_1015:
  call void @abort()
  unreachable
ok_1015:
  %t1016 = getelementptr i8, ptr %t1012, i64 %t1011
  store i8 %t1010, ptr %t1016, align 1
  %t1017 = icmp ult i64 32, 64
  br i1 %t1017, label %ok_1018, label %trap_1018
trap_1018:
  call void @abort()
  unreachable
ok_1018:
  %t1019 = lshr i64 %t975, 32
  %t1020 = trunc i64 %t1019 to i8
  %t1021 = add i64 16, 4
  %t1022 = extractvalue %hia.buffer %p_8_1, 0
  %t1023 = extractvalue %hia.buffer %p_8_1, 1
  %t1024 = icmp ult i64 %t1021, %t1023
  br i1 %t1024, label %ok_1025, label %trap_1025
trap_1025:
  call void @abort()
  unreachable
ok_1025:
  %t1026 = getelementptr i8, ptr %t1022, i64 %t1021
  store i8 %t1020, ptr %t1026, align 1
  %t1027 = icmp ult i64 40, 64
  br i1 %t1027, label %ok_1028, label %trap_1028
trap_1028:
  call void @abort()
  unreachable
ok_1028:
  %t1029 = lshr i64 %t975, 40
  %t1030 = trunc i64 %t1029 to i8
  %t1031 = add i64 16, 5
  %t1032 = extractvalue %hia.buffer %p_8_1, 0
  %t1033 = extractvalue %hia.buffer %p_8_1, 1
  %t1034 = icmp ult i64 %t1031, %t1033
  br i1 %t1034, label %ok_1035, label %trap_1035
trap_1035:
  call void @abort()
  unreachable
ok_1035:
  %t1036 = getelementptr i8, ptr %t1032, i64 %t1031
  store i8 %t1030, ptr %t1036, align 1
  %t1037 = icmp ult i64 48, 64
  br i1 %t1037, label %ok_1038, label %trap_1038
trap_1038:
  call void @abort()
  unreachable
ok_1038:
  %t1039 = lshr i64 %t975, 48
  %t1040 = trunc i64 %t1039 to i8
  %t1041 = add i64 16, 6
  %t1042 = extractvalue %hia.buffer %p_8_1, 0
  %t1043 = extractvalue %hia.buffer %p_8_1, 1
  %t1044 = icmp ult i64 %t1041, %t1043
  br i1 %t1044, label %ok_1045, label %trap_1045
trap_1045:
  call void @abort()
  unreachable
ok_1045:
  %t1046 = getelementptr i8, ptr %t1042, i64 %t1041
  store i8 %t1040, ptr %t1046, align 1
  %t1047 = icmp ult i64 56, 64
  br i1 %t1047, label %ok_1048, label %trap_1048
trap_1048:
  call void @abort()
  unreachable
ok_1048:
  %t1049 = lshr i64 %t975, 56
  %t1050 = trunc i64 %t1049 to i8
  %t1051 = add i64 16, 7
  %t1052 = extractvalue %hia.buffer %p_8_1, 0
  %t1053 = extractvalue %hia.buffer %p_8_1, 1
  %t1054 = icmp ult i64 %t1051, %t1053
  br i1 %t1054, label %ok_1055, label %trap_1055
trap_1055:
  call void @abort()
  unreachable
ok_1055:
  %t1056 = getelementptr i8, ptr %t1052, i64 %t1051
  store i8 %t1050, ptr %t1056, align 1
  %t1057 = icmp ult i64 0, 64
  br i1 %t1057, label %ok_1058, label %trap_1058
trap_1058:
  call void @abort()
  unreachable
ok_1058:
  %t1059 = lshr i64 %t976, 0
  %t1060 = trunc i64 %t1059 to i8
  %t1061 = add i64 24, 0
  %t1062 = extractvalue %hia.buffer %p_8_1, 0
  %t1063 = extractvalue %hia.buffer %p_8_1, 1
  %t1064 = icmp ult i64 %t1061, %t1063
  br i1 %t1064, label %ok_1065, label %trap_1065
trap_1065:
  call void @abort()
  unreachable
ok_1065:
  %t1066 = getelementptr i8, ptr %t1062, i64 %t1061
  store i8 %t1060, ptr %t1066, align 1
  %t1067 = icmp ult i64 8, 64
  br i1 %t1067, label %ok_1068, label %trap_1068
trap_1068:
  call void @abort()
  unreachable
ok_1068:
  %t1069 = lshr i64 %t976, 8
  %t1070 = trunc i64 %t1069 to i8
  %t1071 = add i64 24, 1
  %t1072 = extractvalue %hia.buffer %p_8_1, 0
  %t1073 = extractvalue %hia.buffer %p_8_1, 1
  %t1074 = icmp ult i64 %t1071, %t1073
  br i1 %t1074, label %ok_1075, label %trap_1075
trap_1075:
  call void @abort()
  unreachable
ok_1075:
  %t1076 = getelementptr i8, ptr %t1072, i64 %t1071
  store i8 %t1070, ptr %t1076, align 1
  %t1077 = icmp ult i64 16, 64
  br i1 %t1077, label %ok_1078, label %trap_1078
trap_1078:
  call void @abort()
  unreachable
ok_1078:
  %t1079 = lshr i64 %t976, 16
  %t1080 = trunc i64 %t1079 to i8
  %t1081 = add i64 24, 2
  %t1082 = extractvalue %hia.buffer %p_8_1, 0
  %t1083 = extractvalue %hia.buffer %p_8_1, 1
  %t1084 = icmp ult i64 %t1081, %t1083
  br i1 %t1084, label %ok_1085, label %trap_1085
trap_1085:
  call void @abort()
  unreachable
ok_1085:
  %t1086 = getelementptr i8, ptr %t1082, i64 %t1081
  store i8 %t1080, ptr %t1086, align 1
  %t1087 = icmp ult i64 24, 64
  br i1 %t1087, label %ok_1088, label %trap_1088
trap_1088:
  call void @abort()
  unreachable
ok_1088:
  %t1089 = lshr i64 %t976, 24
  %t1090 = trunc i64 %t1089 to i8
  %t1091 = add i64 24, 3
  %t1092 = extractvalue %hia.buffer %p_8_1, 0
  %t1093 = extractvalue %hia.buffer %p_8_1, 1
  %t1094 = icmp ult i64 %t1091, %t1093
  br i1 %t1094, label %ok_1095, label %trap_1095
trap_1095:
  call void @abort()
  unreachable
ok_1095:
  %t1096 = getelementptr i8, ptr %t1092, i64 %t1091
  store i8 %t1090, ptr %t1096, align 1
  %t1097 = icmp ult i64 32, 64
  br i1 %t1097, label %ok_1098, label %trap_1098
trap_1098:
  call void @abort()
  unreachable
ok_1098:
  %t1099 = lshr i64 %t976, 32
  %t1100 = trunc i64 %t1099 to i8
  %t1101 = add i64 24, 4
  %t1102 = extractvalue %hia.buffer %p_8_1, 0
  %t1103 = extractvalue %hia.buffer %p_8_1, 1
  %t1104 = icmp ult i64 %t1101, %t1103
  br i1 %t1104, label %ok_1105, label %trap_1105
trap_1105:
  call void @abort()
  unreachable
ok_1105:
  %t1106 = getelementptr i8, ptr %t1102, i64 %t1101
  store i8 %t1100, ptr %t1106, align 1
  %t1107 = icmp ult i64 40, 64
  br i1 %t1107, label %ok_1108, label %trap_1108
trap_1108:
  call void @abort()
  unreachable
ok_1108:
  %t1109 = lshr i64 %t976, 40
  %t1110 = trunc i64 %t1109 to i8
  %t1111 = add i64 24, 5
  %t1112 = extractvalue %hia.buffer %p_8_1, 0
  %t1113 = extractvalue %hia.buffer %p_8_1, 1
  %t1114 = icmp ult i64 %t1111, %t1113
  br i1 %t1114, label %ok_1115, label %trap_1115
trap_1115:
  call void @abort()
  unreachable
ok_1115:
  %t1116 = getelementptr i8, ptr %t1112, i64 %t1111
  store i8 %t1110, ptr %t1116, align 1
  %t1117 = icmp ult i64 48, 64
  br i1 %t1117, label %ok_1118, label %trap_1118
trap_1118:
  call void @abort()
  unreachable
ok_1118:
  %t1119 = lshr i64 %t976, 48
  %t1120 = trunc i64 %t1119 to i8
  %t1121 = add i64 24, 6
  %t1122 = extractvalue %hia.buffer %p_8_1, 0
  %t1123 = extractvalue %hia.buffer %p_8_1, 1
  %t1124 = icmp ult i64 %t1121, %t1123
  br i1 %t1124, label %ok_1125, label %trap_1125
trap_1125:
  call void @abort()
  unreachable
ok_1125:
  %t1126 = getelementptr i8, ptr %t1122, i64 %t1121
  store i8 %t1120, ptr %t1126, align 1
  %t1127 = icmp ult i64 56, 64
  br i1 %t1127, label %ok_1128, label %trap_1128
trap_1128:
  call void @abort()
  unreachable
ok_1128:
  %t1129 = lshr i64 %t976, 56
  %t1130 = trunc i64 %t1129 to i8
  %t1131 = add i64 24, 7
  %t1132 = extractvalue %hia.buffer %p_8_1, 0
  %t1133 = extractvalue %hia.buffer %p_8_1, 1
  %t1134 = icmp ult i64 %t1131, %t1133
  br i1 %t1134, label %ok_1135, label %trap_1135
trap_1135:
  call void @abort()
  unreachable
ok_1135:
  %t1136 = getelementptr i8, ptr %t1132, i64 %t1131
  store i8 %t1130, ptr %t1136, align 1
  br label %edge_10
edge_0:
  br label %b1
edge_1:
  br label %b2
edge_2:
  br label %b5
edge_3:
  br label %b2
edge_4:
  br label %b6
edge_5:
  br label %b3
edge_6:
  br label %b7
edge_7:
  br label %b4
edge_8:
  br label %b8
edge_9:
  br label %b3
edge_10:
  br label %b4
}

define internal i32 @__hia_fn_1(%hia.buffer %p_0_0, %hia.buffer %p_0_1, i64 %p_0_2, i32 %p_0_3, i32 %p_0_4) {
b0:
  %t1 = extractvalue %hia.buffer %p_0_1, 1
  %t2 = icmp eq i64 %t1, 32
  %t3 = icmp ule i32 %p_0_3, 1
  %t4 = and i1 %t2, %t3
  %t5 = icmp ule i32 %p_0_4, 1
  %t6 = and i1 %t4, %t5
  br i1 %t6, label %edge_0, label %edge_1
b1:
  %p_1_0 = phi %hia.buffer [ %p_0_0, %edge_0 ]
  %p_1_1 = phi %hia.buffer [ %p_0_1, %edge_0 ]
  %p_1_2 = phi i64 [ %p_0_2, %edge_0 ]
  %p_1_3 = phi i32 [ %p_0_3, %edge_0 ]
  %p_1_4 = phi i32 [ %p_0_4, %edge_0 ]
  %t7 = add i64 0, 0
  %t8 = extractvalue %hia.buffer %p_1_1, 0
  %t9 = extractvalue %hia.buffer %p_1_1, 1
  %t10 = icmp ult i64 %t7, %t9
  br i1 %t10, label %ok_11, label %trap_11
trap_11:
  call void @abort()
  unreachable
ok_11:
  %t12 = getelementptr i8, ptr %t8, i64 %t7
  %t13 = load i8, ptr %t12, align 1
  %t14 = zext i8 %t13 to i64
  %t15 = icmp ult i64 0, 64
  br i1 %t15, label %ok_16, label %trap_16
trap_16:
  call void @abort()
  unreachable
ok_16:
  %t17 = shl i64 %t14, 0
  %t18 = or i64 0, %t17
  %t19 = add i64 0, 1
  %t20 = extractvalue %hia.buffer %p_1_1, 0
  %t21 = extractvalue %hia.buffer %p_1_1, 1
  %t22 = icmp ult i64 %t19, %t21
  br i1 %t22, label %ok_23, label %trap_23
trap_23:
  call void @abort()
  unreachable
ok_23:
  %t24 = getelementptr i8, ptr %t20, i64 %t19
  %t25 = load i8, ptr %t24, align 1
  %t26 = zext i8 %t25 to i64
  %t27 = icmp ult i64 8, 64
  br i1 %t27, label %ok_28, label %trap_28
trap_28:
  call void @abort()
  unreachable
ok_28:
  %t29 = shl i64 %t26, 8
  %t30 = or i64 %t18, %t29
  %t31 = add i64 0, 2
  %t32 = extractvalue %hia.buffer %p_1_1, 0
  %t33 = extractvalue %hia.buffer %p_1_1, 1
  %t34 = icmp ult i64 %t31, %t33
  br i1 %t34, label %ok_35, label %trap_35
trap_35:
  call void @abort()
  unreachable
ok_35:
  %t36 = getelementptr i8, ptr %t32, i64 %t31
  %t37 = load i8, ptr %t36, align 1
  %t38 = zext i8 %t37 to i64
  %t39 = icmp ult i64 16, 64
  br i1 %t39, label %ok_40, label %trap_40
trap_40:
  call void @abort()
  unreachable
ok_40:
  %t41 = shl i64 %t38, 16
  %t42 = or i64 %t30, %t41
  %t43 = add i64 0, 3
  %t44 = extractvalue %hia.buffer %p_1_1, 0
  %t45 = extractvalue %hia.buffer %p_1_1, 1
  %t46 = icmp ult i64 %t43, %t45
  br i1 %t46, label %ok_47, label %trap_47
trap_47:
  call void @abort()
  unreachable
ok_47:
  %t48 = getelementptr i8, ptr %t44, i64 %t43
  %t49 = load i8, ptr %t48, align 1
  %t50 = zext i8 %t49 to i64
  %t51 = icmp ult i64 24, 64
  br i1 %t51, label %ok_52, label %trap_52
trap_52:
  call void @abort()
  unreachable
ok_52:
  %t53 = shl i64 %t50, 24
  %t54 = or i64 %t42, %t53
  %t55 = add i64 0, 4
  %t56 = extractvalue %hia.buffer %p_1_1, 0
  %t57 = extractvalue %hia.buffer %p_1_1, 1
  %t58 = icmp ult i64 %t55, %t57
  br i1 %t58, label %ok_59, label %trap_59
trap_59:
  call void @abort()
  unreachable
ok_59:
  %t60 = getelementptr i8, ptr %t56, i64 %t55
  %t61 = load i8, ptr %t60, align 1
  %t62 = zext i8 %t61 to i64
  %t63 = icmp ult i64 32, 64
  br i1 %t63, label %ok_64, label %trap_64
trap_64:
  call void @abort()
  unreachable
ok_64:
  %t65 = shl i64 %t62, 32
  %t66 = or i64 %t54, %t65
  %t67 = add i64 0, 5
  %t68 = extractvalue %hia.buffer %p_1_1, 0
  %t69 = extractvalue %hia.buffer %p_1_1, 1
  %t70 = icmp ult i64 %t67, %t69
  br i1 %t70, label %ok_71, label %trap_71
trap_71:
  call void @abort()
  unreachable
ok_71:
  %t72 = getelementptr i8, ptr %t68, i64 %t67
  %t73 = load i8, ptr %t72, align 1
  %t74 = zext i8 %t73 to i64
  %t75 = icmp ult i64 40, 64
  br i1 %t75, label %ok_76, label %trap_76
trap_76:
  call void @abort()
  unreachable
ok_76:
  %t77 = shl i64 %t74, 40
  %t78 = or i64 %t66, %t77
  %t79 = add i64 0, 6
  %t80 = extractvalue %hia.buffer %p_1_1, 0
  %t81 = extractvalue %hia.buffer %p_1_1, 1
  %t82 = icmp ult i64 %t79, %t81
  br i1 %t82, label %ok_83, label %trap_83
trap_83:
  call void @abort()
  unreachable
ok_83:
  %t84 = getelementptr i8, ptr %t80, i64 %t79
  %t85 = load i8, ptr %t84, align 1
  %t86 = zext i8 %t85 to i64
  %t87 = icmp ult i64 48, 64
  br i1 %t87, label %ok_88, label %trap_88
trap_88:
  call void @abort()
  unreachable
ok_88:
  %t89 = shl i64 %t86, 48
  %t90 = or i64 %t78, %t89
  %t91 = add i64 0, 7
  %t92 = extractvalue %hia.buffer %p_1_1, 0
  %t93 = extractvalue %hia.buffer %p_1_1, 1
  %t94 = icmp ult i64 %t91, %t93
  br i1 %t94, label %ok_95, label %trap_95
trap_95:
  call void @abort()
  unreachable
ok_95:
  %t96 = getelementptr i8, ptr %t92, i64 %t91
  %t97 = load i8, ptr %t96, align 1
  %t98 = zext i8 %t97 to i64
  %t99 = icmp ult i64 56, 64
  br i1 %t99, label %ok_100, label %trap_100
trap_100:
  call void @abort()
  unreachable
ok_100:
  %t101 = shl i64 %t98, 56
  %t102 = or i64 %t90, %t101
  %t103 = add i64 8, 0
  %t104 = extractvalue %hia.buffer %p_1_1, 0
  %t105 = extractvalue %hia.buffer %p_1_1, 1
  %t106 = icmp ult i64 %t103, %t105
  br i1 %t106, label %ok_107, label %trap_107
trap_107:
  call void @abort()
  unreachable
ok_107:
  %t108 = getelementptr i8, ptr %t104, i64 %t103
  %t109 = load i8, ptr %t108, align 1
  %t110 = zext i8 %t109 to i64
  %t111 = icmp ult i64 0, 64
  br i1 %t111, label %ok_112, label %trap_112
trap_112:
  call void @abort()
  unreachable
ok_112:
  %t113 = shl i64 %t110, 0
  %t114 = or i64 0, %t113
  %t115 = add i64 8, 1
  %t116 = extractvalue %hia.buffer %p_1_1, 0
  %t117 = extractvalue %hia.buffer %p_1_1, 1
  %t118 = icmp ult i64 %t115, %t117
  br i1 %t118, label %ok_119, label %trap_119
trap_119:
  call void @abort()
  unreachable
ok_119:
  %t120 = getelementptr i8, ptr %t116, i64 %t115
  %t121 = load i8, ptr %t120, align 1
  %t122 = zext i8 %t121 to i64
  %t123 = icmp ult i64 8, 64
  br i1 %t123, label %ok_124, label %trap_124
trap_124:
  call void @abort()
  unreachable
ok_124:
  %t125 = shl i64 %t122, 8
  %t126 = or i64 %t114, %t125
  %t127 = add i64 8, 2
  %t128 = extractvalue %hia.buffer %p_1_1, 0
  %t129 = extractvalue %hia.buffer %p_1_1, 1
  %t130 = icmp ult i64 %t127, %t129
  br i1 %t130, label %ok_131, label %trap_131
trap_131:
  call void @abort()
  unreachable
ok_131:
  %t132 = getelementptr i8, ptr %t128, i64 %t127
  %t133 = load i8, ptr %t132, align 1
  %t134 = zext i8 %t133 to i64
  %t135 = icmp ult i64 16, 64
  br i1 %t135, label %ok_136, label %trap_136
trap_136:
  call void @abort()
  unreachable
ok_136:
  %t137 = shl i64 %t134, 16
  %t138 = or i64 %t126, %t137
  %t139 = add i64 8, 3
  %t140 = extractvalue %hia.buffer %p_1_1, 0
  %t141 = extractvalue %hia.buffer %p_1_1, 1
  %t142 = icmp ult i64 %t139, %t141
  br i1 %t142, label %ok_143, label %trap_143
trap_143:
  call void @abort()
  unreachable
ok_143:
  %t144 = getelementptr i8, ptr %t140, i64 %t139
  %t145 = load i8, ptr %t144, align 1
  %t146 = zext i8 %t145 to i64
  %t147 = icmp ult i64 24, 64
  br i1 %t147, label %ok_148, label %trap_148
trap_148:
  call void @abort()
  unreachable
ok_148:
  %t149 = shl i64 %t146, 24
  %t150 = or i64 %t138, %t149
  %t151 = add i64 8, 4
  %t152 = extractvalue %hia.buffer %p_1_1, 0
  %t153 = extractvalue %hia.buffer %p_1_1, 1
  %t154 = icmp ult i64 %t151, %t153
  br i1 %t154, label %ok_155, label %trap_155
trap_155:
  call void @abort()
  unreachable
ok_155:
  %t156 = getelementptr i8, ptr %t152, i64 %t151
  %t157 = load i8, ptr %t156, align 1
  %t158 = zext i8 %t157 to i64
  %t159 = icmp ult i64 32, 64
  br i1 %t159, label %ok_160, label %trap_160
trap_160:
  call void @abort()
  unreachable
ok_160:
  %t161 = shl i64 %t158, 32
  %t162 = or i64 %t150, %t161
  %t163 = add i64 8, 5
  %t164 = extractvalue %hia.buffer %p_1_1, 0
  %t165 = extractvalue %hia.buffer %p_1_1, 1
  %t166 = icmp ult i64 %t163, %t165
  br i1 %t166, label %ok_167, label %trap_167
trap_167:
  call void @abort()
  unreachable
ok_167:
  %t168 = getelementptr i8, ptr %t164, i64 %t163
  %t169 = load i8, ptr %t168, align 1
  %t170 = zext i8 %t169 to i64
  %t171 = icmp ult i64 40, 64
  br i1 %t171, label %ok_172, label %trap_172
trap_172:
  call void @abort()
  unreachable
ok_172:
  %t173 = shl i64 %t170, 40
  %t174 = or i64 %t162, %t173
  %t175 = add i64 8, 6
  %t176 = extractvalue %hia.buffer %p_1_1, 0
  %t177 = extractvalue %hia.buffer %p_1_1, 1
  %t178 = icmp ult i64 %t175, %t177
  br i1 %t178, label %ok_179, label %trap_179
trap_179:
  call void @abort()
  unreachable
ok_179:
  %t180 = getelementptr i8, ptr %t176, i64 %t175
  %t181 = load i8, ptr %t180, align 1
  %t182 = zext i8 %t181 to i64
  %t183 = icmp ult i64 48, 64
  br i1 %t183, label %ok_184, label %trap_184
trap_184:
  call void @abort()
  unreachable
ok_184:
  %t185 = shl i64 %t182, 48
  %t186 = or i64 %t174, %t185
  %t187 = add i64 8, 7
  %t188 = extractvalue %hia.buffer %p_1_1, 0
  %t189 = extractvalue %hia.buffer %p_1_1, 1
  %t190 = icmp ult i64 %t187, %t189
  br i1 %t190, label %ok_191, label %trap_191
trap_191:
  call void @abort()
  unreachable
ok_191:
  %t192 = getelementptr i8, ptr %t188, i64 %t187
  %t193 = load i8, ptr %t192, align 1
  %t194 = zext i8 %t193 to i64
  %t195 = icmp ult i64 56, 64
  br i1 %t195, label %ok_196, label %trap_196
trap_196:
  call void @abort()
  unreachable
ok_196:
  %t197 = shl i64 %t194, 56
  %t198 = or i64 %t186, %t197
  %t199 = add i64 16, 0
  %t200 = extractvalue %hia.buffer %p_1_1, 0
  %t201 = extractvalue %hia.buffer %p_1_1, 1
  %t202 = icmp ult i64 %t199, %t201
  br i1 %t202, label %ok_203, label %trap_203
trap_203:
  call void @abort()
  unreachable
ok_203:
  %t204 = getelementptr i8, ptr %t200, i64 %t199
  %t205 = load i8, ptr %t204, align 1
  %t206 = zext i8 %t205 to i64
  %t207 = icmp ult i64 0, 64
  br i1 %t207, label %ok_208, label %trap_208
trap_208:
  call void @abort()
  unreachable
ok_208:
  %t209 = shl i64 %t206, 0
  %t210 = or i64 0, %t209
  %t211 = add i64 16, 1
  %t212 = extractvalue %hia.buffer %p_1_1, 0
  %t213 = extractvalue %hia.buffer %p_1_1, 1
  %t214 = icmp ult i64 %t211, %t213
  br i1 %t214, label %ok_215, label %trap_215
trap_215:
  call void @abort()
  unreachable
ok_215:
  %t216 = getelementptr i8, ptr %t212, i64 %t211
  %t217 = load i8, ptr %t216, align 1
  %t218 = zext i8 %t217 to i64
  %t219 = icmp ult i64 8, 64
  br i1 %t219, label %ok_220, label %trap_220
trap_220:
  call void @abort()
  unreachable
ok_220:
  %t221 = shl i64 %t218, 8
  %t222 = or i64 %t210, %t221
  %t223 = add i64 16, 2
  %t224 = extractvalue %hia.buffer %p_1_1, 0
  %t225 = extractvalue %hia.buffer %p_1_1, 1
  %t226 = icmp ult i64 %t223, %t225
  br i1 %t226, label %ok_227, label %trap_227
trap_227:
  call void @abort()
  unreachable
ok_227:
  %t228 = getelementptr i8, ptr %t224, i64 %t223
  %t229 = load i8, ptr %t228, align 1
  %t230 = zext i8 %t229 to i64
  %t231 = icmp ult i64 16, 64
  br i1 %t231, label %ok_232, label %trap_232
trap_232:
  call void @abort()
  unreachable
ok_232:
  %t233 = shl i64 %t230, 16
  %t234 = or i64 %t222, %t233
  %t235 = add i64 16, 3
  %t236 = extractvalue %hia.buffer %p_1_1, 0
  %t237 = extractvalue %hia.buffer %p_1_1, 1
  %t238 = icmp ult i64 %t235, %t237
  br i1 %t238, label %ok_239, label %trap_239
trap_239:
  call void @abort()
  unreachable
ok_239:
  %t240 = getelementptr i8, ptr %t236, i64 %t235
  %t241 = load i8, ptr %t240, align 1
  %t242 = zext i8 %t241 to i64
  %t243 = icmp ult i64 24, 64
  br i1 %t243, label %ok_244, label %trap_244
trap_244:
  call void @abort()
  unreachable
ok_244:
  %t245 = shl i64 %t242, 24
  %t246 = or i64 %t234, %t245
  %t247 = add i64 16, 4
  %t248 = extractvalue %hia.buffer %p_1_1, 0
  %t249 = extractvalue %hia.buffer %p_1_1, 1
  %t250 = icmp ult i64 %t247, %t249
  br i1 %t250, label %ok_251, label %trap_251
trap_251:
  call void @abort()
  unreachable
ok_251:
  %t252 = getelementptr i8, ptr %t248, i64 %t247
  %t253 = load i8, ptr %t252, align 1
  %t254 = zext i8 %t253 to i64
  %t255 = icmp ult i64 32, 64
  br i1 %t255, label %ok_256, label %trap_256
trap_256:
  call void @abort()
  unreachable
ok_256:
  %t257 = shl i64 %t254, 32
  %t258 = or i64 %t246, %t257
  %t259 = add i64 16, 5
  %t260 = extractvalue %hia.buffer %p_1_1, 0
  %t261 = extractvalue %hia.buffer %p_1_1, 1
  %t262 = icmp ult i64 %t259, %t261
  br i1 %t262, label %ok_263, label %trap_263
trap_263:
  call void @abort()
  unreachable
ok_263:
  %t264 = getelementptr i8, ptr %t260, i64 %t259
  %t265 = load i8, ptr %t264, align 1
  %t266 = zext i8 %t265 to i64
  %t267 = icmp ult i64 40, 64
  br i1 %t267, label %ok_268, label %trap_268
trap_268:
  call void @abort()
  unreachable
ok_268:
  %t269 = shl i64 %t266, 40
  %t270 = or i64 %t258, %t269
  %t271 = add i64 16, 6
  %t272 = extractvalue %hia.buffer %p_1_1, 0
  %t273 = extractvalue %hia.buffer %p_1_1, 1
  %t274 = icmp ult i64 %t271, %t273
  br i1 %t274, label %ok_275, label %trap_275
trap_275:
  call void @abort()
  unreachable
ok_275:
  %t276 = getelementptr i8, ptr %t272, i64 %t271
  %t277 = load i8, ptr %t276, align 1
  %t278 = zext i8 %t277 to i64
  %t279 = icmp ult i64 48, 64
  br i1 %t279, label %ok_280, label %trap_280
trap_280:
  call void @abort()
  unreachable
ok_280:
  %t281 = shl i64 %t278, 48
  %t282 = or i64 %t270, %t281
  %t283 = add i64 16, 7
  %t284 = extractvalue %hia.buffer %p_1_1, 0
  %t285 = extractvalue %hia.buffer %p_1_1, 1
  %t286 = icmp ult i64 %t283, %t285
  br i1 %t286, label %ok_287, label %trap_287
trap_287:
  call void @abort()
  unreachable
ok_287:
  %t288 = getelementptr i8, ptr %t284, i64 %t283
  %t289 = load i8, ptr %t288, align 1
  %t290 = zext i8 %t289 to i64
  %t291 = icmp ult i64 56, 64
  br i1 %t291, label %ok_292, label %trap_292
trap_292:
  call void @abort()
  unreachable
ok_292:
  %t293 = shl i64 %t290, 56
  %t294 = or i64 %t282, %t293
  %t295 = add i64 24, 0
  %t296 = extractvalue %hia.buffer %p_1_1, 0
  %t297 = extractvalue %hia.buffer %p_1_1, 1
  %t298 = icmp ult i64 %t295, %t297
  br i1 %t298, label %ok_299, label %trap_299
trap_299:
  call void @abort()
  unreachable
ok_299:
  %t300 = getelementptr i8, ptr %t296, i64 %t295
  %t301 = load i8, ptr %t300, align 1
  %t302 = zext i8 %t301 to i64
  %t303 = icmp ult i64 0, 64
  br i1 %t303, label %ok_304, label %trap_304
trap_304:
  call void @abort()
  unreachable
ok_304:
  %t305 = shl i64 %t302, 0
  %t306 = or i64 0, %t305
  %t307 = add i64 24, 1
  %t308 = extractvalue %hia.buffer %p_1_1, 0
  %t309 = extractvalue %hia.buffer %p_1_1, 1
  %t310 = icmp ult i64 %t307, %t309
  br i1 %t310, label %ok_311, label %trap_311
trap_311:
  call void @abort()
  unreachable
ok_311:
  %t312 = getelementptr i8, ptr %t308, i64 %t307
  %t313 = load i8, ptr %t312, align 1
  %t314 = zext i8 %t313 to i64
  %t315 = icmp ult i64 8, 64
  br i1 %t315, label %ok_316, label %trap_316
trap_316:
  call void @abort()
  unreachable
ok_316:
  %t317 = shl i64 %t314, 8
  %t318 = or i64 %t306, %t317
  %t319 = add i64 24, 2
  %t320 = extractvalue %hia.buffer %p_1_1, 0
  %t321 = extractvalue %hia.buffer %p_1_1, 1
  %t322 = icmp ult i64 %t319, %t321
  br i1 %t322, label %ok_323, label %trap_323
trap_323:
  call void @abort()
  unreachable
ok_323:
  %t324 = getelementptr i8, ptr %t320, i64 %t319
  %t325 = load i8, ptr %t324, align 1
  %t326 = zext i8 %t325 to i64
  %t327 = icmp ult i64 16, 64
  br i1 %t327, label %ok_328, label %trap_328
trap_328:
  call void @abort()
  unreachable
ok_328:
  %t329 = shl i64 %t326, 16
  %t330 = or i64 %t318, %t329
  %t331 = add i64 24, 3
  %t332 = extractvalue %hia.buffer %p_1_1, 0
  %t333 = extractvalue %hia.buffer %p_1_1, 1
  %t334 = icmp ult i64 %t331, %t333
  br i1 %t334, label %ok_335, label %trap_335
trap_335:
  call void @abort()
  unreachable
ok_335:
  %t336 = getelementptr i8, ptr %t332, i64 %t331
  %t337 = load i8, ptr %t336, align 1
  %t338 = zext i8 %t337 to i64
  %t339 = icmp ult i64 24, 64
  br i1 %t339, label %ok_340, label %trap_340
trap_340:
  call void @abort()
  unreachable
ok_340:
  %t341 = shl i64 %t338, 24
  %t342 = or i64 %t330, %t341
  %t343 = add i64 24, 4
  %t344 = extractvalue %hia.buffer %p_1_1, 0
  %t345 = extractvalue %hia.buffer %p_1_1, 1
  %t346 = icmp ult i64 %t343, %t345
  br i1 %t346, label %ok_347, label %trap_347
trap_347:
  call void @abort()
  unreachable
ok_347:
  %t348 = getelementptr i8, ptr %t344, i64 %t343
  %t349 = load i8, ptr %t348, align 1
  %t350 = zext i8 %t349 to i64
  %t351 = icmp ult i64 32, 64
  br i1 %t351, label %ok_352, label %trap_352
trap_352:
  call void @abort()
  unreachable
ok_352:
  %t353 = shl i64 %t350, 32
  %t354 = or i64 %t342, %t353
  %t355 = add i64 24, 5
  %t356 = extractvalue %hia.buffer %p_1_1, 0
  %t357 = extractvalue %hia.buffer %p_1_1, 1
  %t358 = icmp ult i64 %t355, %t357
  br i1 %t358, label %ok_359, label %trap_359
trap_359:
  call void @abort()
  unreachable
ok_359:
  %t360 = getelementptr i8, ptr %t356, i64 %t355
  %t361 = load i8, ptr %t360, align 1
  %t362 = zext i8 %t361 to i64
  %t363 = icmp ult i64 40, 64
  br i1 %t363, label %ok_364, label %trap_364
trap_364:
  call void @abort()
  unreachable
ok_364:
  %t365 = shl i64 %t362, 40
  %t366 = or i64 %t354, %t365
  %t367 = add i64 24, 6
  %t368 = extractvalue %hia.buffer %p_1_1, 0
  %t369 = extractvalue %hia.buffer %p_1_1, 1
  %t370 = icmp ult i64 %t367, %t369
  br i1 %t370, label %ok_371, label %trap_371
trap_371:
  call void @abort()
  unreachable
ok_371:
  %t372 = getelementptr i8, ptr %t368, i64 %t367
  %t373 = load i8, ptr %t372, align 1
  %t374 = zext i8 %t373 to i64
  %t375 = icmp ult i64 48, 64
  br i1 %t375, label %ok_376, label %trap_376
trap_376:
  call void @abort()
  unreachable
ok_376:
  %t377 = shl i64 %t374, 48
  %t378 = or i64 %t366, %t377
  %t379 = add i64 24, 7
  %t380 = extractvalue %hia.buffer %p_1_1, 0
  %t381 = extractvalue %hia.buffer %p_1_1, 1
  %t382 = icmp ult i64 %t379, %t381
  br i1 %t382, label %ok_383, label %trap_383
trap_383:
  call void @abort()
  unreachable
ok_383:
  %t384 = getelementptr i8, ptr %t380, i64 %t379
  %t385 = load i8, ptr %t384, align 1
  %t386 = zext i8 %t385 to i64
  %t387 = icmp ult i64 56, 64
  br i1 %t387, label %ok_388, label %trap_388
trap_388:
  call void @abort()
  unreachable
ok_388:
  %t389 = shl i64 %t386, 56
  %t390 = or i64 %t378, %t389
  %t391 = extractvalue %hia.buffer %p_1_0, 1
  %t392 = icmp ule i64 %t294, %t391
  %t393 = sub i64 %t391, %t294
  %t394 = icmp ule i64 %t390, %t393
  %t395 = and i1 %t392, %t394
  br i1 %t395, label %edge_2, label %edge_3
b2:
  ret i32 4294836225
b3:
  ret i32 0
b4:
  ret i32 1
b5:
  %p_5_0 = phi %hia.buffer [ %p_1_0, %edge_2 ]
  %p_5_1 = phi %hia.buffer [ %p_1_1, %edge_2 ]
  %p_5_2 = phi i64 [ %t102, %edge_2 ]
  %p_5_3 = phi i64 [ %t198, %edge_2 ]
  %p_5_4 = phi i64 [ %t294, %edge_2 ]
  %p_5_5 = phi i64 [ %t390, %edge_2 ]
  %p_5_6 = phi i64 [ %t391, %edge_2 ]
  %p_5_7 = phi i64 [ %p_1_2, %edge_2 ]
  %p_5_8 = phi i32 [ %p_1_3, %edge_2 ]
  %p_5_9 = phi i32 [ %p_1_4, %edge_2 ]
  %t396 = icmp eq i64 %p_5_3, 0
  %t397 = select i1 %t396, i64 %p_5_7, i64 %p_5_3
  %t398 = icmp ult i64 0, 64
  br i1 %t398, label %ok_399, label %trap_399
trap_399:
  call void @abort()
  unreachable
ok_399:
  %t400 = lshr i64 %t397, 0
  %t401 = trunc i64 %t400 to i8
  %t402 = add i64 8, 0
  %t403 = extractvalue %hia.buffer %p_5_1, 0
  %t404 = extractvalue %hia.buffer %p_5_1, 1
  %t405 = icmp ult i64 %t402, %t404
  br i1 %t405, label %ok_406, label %trap_406
trap_406:
  call void @abort()
  unreachable
ok_406:
  %t407 = getelementptr i8, ptr %t403, i64 %t402
  store i8 %t401, ptr %t407, align 1
  %t408 = icmp ult i64 8, 64
  br i1 %t408, label %ok_409, label %trap_409
trap_409:
  call void @abort()
  unreachable
ok_409:
  %t410 = lshr i64 %t397, 8
  %t411 = trunc i64 %t410 to i8
  %t412 = add i64 8, 1
  %t413 = extractvalue %hia.buffer %p_5_1, 0
  %t414 = extractvalue %hia.buffer %p_5_1, 1
  %t415 = icmp ult i64 %t412, %t414
  br i1 %t415, label %ok_416, label %trap_416
trap_416:
  call void @abort()
  unreachable
ok_416:
  %t417 = getelementptr i8, ptr %t413, i64 %t412
  store i8 %t411, ptr %t417, align 1
  %t418 = icmp ult i64 16, 64
  br i1 %t418, label %ok_419, label %trap_419
trap_419:
  call void @abort()
  unreachable
ok_419:
  %t420 = lshr i64 %t397, 16
  %t421 = trunc i64 %t420 to i8
  %t422 = add i64 8, 2
  %t423 = extractvalue %hia.buffer %p_5_1, 0
  %t424 = extractvalue %hia.buffer %p_5_1, 1
  %t425 = icmp ult i64 %t422, %t424
  br i1 %t425, label %ok_426, label %trap_426
trap_426:
  call void @abort()
  unreachable
ok_426:
  %t427 = getelementptr i8, ptr %t423, i64 %t422
  store i8 %t421, ptr %t427, align 1
  %t428 = icmp ult i64 24, 64
  br i1 %t428, label %ok_429, label %trap_429
trap_429:
  call void @abort()
  unreachable
ok_429:
  %t430 = lshr i64 %t397, 24
  %t431 = trunc i64 %t430 to i8
  %t432 = add i64 8, 3
  %t433 = extractvalue %hia.buffer %p_5_1, 0
  %t434 = extractvalue %hia.buffer %p_5_1, 1
  %t435 = icmp ult i64 %t432, %t434
  br i1 %t435, label %ok_436, label %trap_436
trap_436:
  call void @abort()
  unreachable
ok_436:
  %t437 = getelementptr i8, ptr %t433, i64 %t432
  store i8 %t431, ptr %t437, align 1
  %t438 = icmp ult i64 32, 64
  br i1 %t438, label %ok_439, label %trap_439
trap_439:
  call void @abort()
  unreachable
ok_439:
  %t440 = lshr i64 %t397, 32
  %t441 = trunc i64 %t440 to i8
  %t442 = add i64 8, 4
  %t443 = extractvalue %hia.buffer %p_5_1, 0
  %t444 = extractvalue %hia.buffer %p_5_1, 1
  %t445 = icmp ult i64 %t442, %t444
  br i1 %t445, label %ok_446, label %trap_446
trap_446:
  call void @abort()
  unreachable
ok_446:
  %t447 = getelementptr i8, ptr %t443, i64 %t442
  store i8 %t441, ptr %t447, align 1
  %t448 = icmp ult i64 40, 64
  br i1 %t448, label %ok_449, label %trap_449
trap_449:
  call void @abort()
  unreachable
ok_449:
  %t450 = lshr i64 %t397, 40
  %t451 = trunc i64 %t450 to i8
  %t452 = add i64 8, 5
  %t453 = extractvalue %hia.buffer %p_5_1, 0
  %t454 = extractvalue %hia.buffer %p_5_1, 1
  %t455 = icmp ult i64 %t452, %t454
  br i1 %t455, label %ok_456, label %trap_456
trap_456:
  call void @abort()
  unreachable
ok_456:
  %t457 = getelementptr i8, ptr %t453, i64 %t452
  store i8 %t451, ptr %t457, align 1
  %t458 = icmp ult i64 48, 64
  br i1 %t458, label %ok_459, label %trap_459
trap_459:
  call void @abort()
  unreachable
ok_459:
  %t460 = lshr i64 %t397, 48
  %t461 = trunc i64 %t460 to i8
  %t462 = add i64 8, 6
  %t463 = extractvalue %hia.buffer %p_5_1, 0
  %t464 = extractvalue %hia.buffer %p_5_1, 1
  %t465 = icmp ult i64 %t462, %t464
  br i1 %t465, label %ok_466, label %trap_466
trap_466:
  call void @abort()
  unreachable
ok_466:
  %t467 = getelementptr i8, ptr %t463, i64 %t462
  store i8 %t461, ptr %t467, align 1
  %t468 = icmp ult i64 56, 64
  br i1 %t468, label %ok_469, label %trap_469
trap_469:
  call void @abort()
  unreachable
ok_469:
  %t470 = lshr i64 %t397, 56
  %t471 = trunc i64 %t470 to i8
  %t472 = add i64 8, 7
  %t473 = extractvalue %hia.buffer %p_5_1, 0
  %t474 = extractvalue %hia.buffer %p_5_1, 1
  %t475 = icmp ult i64 %t472, %t474
  br i1 %t475, label %ok_476, label %trap_476
trap_476:
  call void @abort()
  unreachable
ok_476:
  %t477 = getelementptr i8, ptr %t473, i64 %t472
  store i8 %t471, ptr %t477, align 1
  %t478 = icmp eq i64 %p_5_2, 4294967295
  %t479 = icmp ne i32 %p_5_8, 0
  %t480 = icmp sgt i64 %p_5_7, %t397
  %t481 = and i1 %t479, %t480
  %t482 = xor i1 %t478, true
  %t483 = or i1 %t482, %t481
  %t484 = select i1 %t478, i64 0, i64 %p_5_2
  %t485 = select i1 %t478, i64 %p_5_7, i64 %t397
  br i1 %t483, label %edge_4, label %edge_5
b6:
  %p_6_0 = phi %hia.buffer [ %p_5_0, %edge_4 ]
  %p_6_1 = phi %hia.buffer [ %p_5_1, %edge_4 ]
  %p_6_2 = phi i64 [ %t484, %edge_4 ]
  %p_6_3 = phi i64 [ %t485, %edge_4 ]
  %p_6_4 = phi i64 [ %p_5_4, %edge_4 ]
  %p_6_5 = phi i64 [ %p_5_5, %edge_4 ]
  %p_6_6 = phi i64 [ %p_5_6, %edge_4 ]
  %p_6_7 = phi i64 [ %p_5_7, %edge_4 ]
  %p_6_8 = phi i32 [ %p_5_8, %edge_4 ]
  %p_6_9 = phi i32 [ %p_5_9, %edge_4 ]
  %t486 = add i64 %p_6_2, 1
  %t487 = icmp ult i64 0, 64
  br i1 %t487, label %ok_488, label %trap_488
trap_488:
  call void @abort()
  unreachable
ok_488:
  %t489 = lshr i64 %t486, 0
  %t490 = trunc i64 %t489 to i8
  %t491 = add i64 0, 0
  %t492 = extractvalue %hia.buffer %p_6_1, 0
  %t493 = extractvalue %hia.buffer %p_6_1, 1
  %t494 = icmp ult i64 %t491, %t493
  br i1 %t494, label %ok_495, label %trap_495
trap_495:
  call void @abort()
  unreachable
ok_495:
  %t496 = getelementptr i8, ptr %t492, i64 %t491
  store i8 %t490, ptr %t496, align 1
  %t497 = icmp ult i64 8, 64
  br i1 %t497, label %ok_498, label %trap_498
trap_498:
  call void @abort()
  unreachable
ok_498:
  %t499 = lshr i64 %t486, 8
  %t500 = trunc i64 %t499 to i8
  %t501 = add i64 0, 1
  %t502 = extractvalue %hia.buffer %p_6_1, 0
  %t503 = extractvalue %hia.buffer %p_6_1, 1
  %t504 = icmp ult i64 %t501, %t503
  br i1 %t504, label %ok_505, label %trap_505
trap_505:
  call void @abort()
  unreachable
ok_505:
  %t506 = getelementptr i8, ptr %t502, i64 %t501
  store i8 %t500, ptr %t506, align 1
  %t507 = icmp ult i64 16, 64
  br i1 %t507, label %ok_508, label %trap_508
trap_508:
  call void @abort()
  unreachable
ok_508:
  %t509 = lshr i64 %t486, 16
  %t510 = trunc i64 %t509 to i8
  %t511 = add i64 0, 2
  %t512 = extractvalue %hia.buffer %p_6_1, 0
  %t513 = extractvalue %hia.buffer %p_6_1, 1
  %t514 = icmp ult i64 %t511, %t513
  br i1 %t514, label %ok_515, label %trap_515
trap_515:
  call void @abort()
  unreachable
ok_515:
  %t516 = getelementptr i8, ptr %t512, i64 %t511
  store i8 %t510, ptr %t516, align 1
  %t517 = icmp ult i64 24, 64
  br i1 %t517, label %ok_518, label %trap_518
trap_518:
  call void @abort()
  unreachable
ok_518:
  %t519 = lshr i64 %t486, 24
  %t520 = trunc i64 %t519 to i8
  %t521 = add i64 0, 3
  %t522 = extractvalue %hia.buffer %p_6_1, 0
  %t523 = extractvalue %hia.buffer %p_6_1, 1
  %t524 = icmp ult i64 %t521, %t523
  br i1 %t524, label %ok_525, label %trap_525
trap_525:
  call void @abort()
  unreachable
ok_525:
  %t526 = getelementptr i8, ptr %t522, i64 %t521
  store i8 %t520, ptr %t526, align 1
  %t527 = icmp ult i64 32, 64
  br i1 %t527, label %ok_528, label %trap_528
trap_528:
  call void @abort()
  unreachable
ok_528:
  %t529 = lshr i64 %t486, 32
  %t530 = trunc i64 %t529 to i8
  %t531 = add i64 0, 4
  %t532 = extractvalue %hia.buffer %p_6_1, 0
  %t533 = extractvalue %hia.buffer %p_6_1, 1
  %t534 = icmp ult i64 %t531, %t533
  br i1 %t534, label %ok_535, label %trap_535
trap_535:
  call void @abort()
  unreachable
ok_535:
  %t536 = getelementptr i8, ptr %t532, i64 %t531
  store i8 %t530, ptr %t536, align 1
  %t537 = icmp ult i64 40, 64
  br i1 %t537, label %ok_538, label %trap_538
trap_538:
  call void @abort()
  unreachable
ok_538:
  %t539 = lshr i64 %t486, 40
  %t540 = trunc i64 %t539 to i8
  %t541 = add i64 0, 5
  %t542 = extractvalue %hia.buffer %p_6_1, 0
  %t543 = extractvalue %hia.buffer %p_6_1, 1
  %t544 = icmp ult i64 %t541, %t543
  br i1 %t544, label %ok_545, label %trap_545
trap_545:
  call void @abort()
  unreachable
ok_545:
  %t546 = getelementptr i8, ptr %t542, i64 %t541
  store i8 %t540, ptr %t546, align 1
  %t547 = icmp ult i64 48, 64
  br i1 %t547, label %ok_548, label %trap_548
trap_548:
  call void @abort()
  unreachable
ok_548:
  %t549 = lshr i64 %t486, 48
  %t550 = trunc i64 %t549 to i8
  %t551 = add i64 0, 6
  %t552 = extractvalue %hia.buffer %p_6_1, 0
  %t553 = extractvalue %hia.buffer %p_6_1, 1
  %t554 = icmp ult i64 %t551, %t553
  br i1 %t554, label %ok_555, label %trap_555
trap_555:
  call void @abort()
  unreachable
ok_555:
  %t556 = getelementptr i8, ptr %t552, i64 %t551
  store i8 %t550, ptr %t556, align 1
  %t557 = icmp ult i64 56, 64
  br i1 %t557, label %ok_558, label %trap_558
trap_558:
  call void @abort()
  unreachable
ok_558:
  %t559 = lshr i64 %t486, 56
  %t560 = trunc i64 %t559 to i8
  %t561 = add i64 0, 7
  %t562 = extractvalue %hia.buffer %p_6_1, 0
  %t563 = extractvalue %hia.buffer %p_6_1, 1
  %t564 = icmp ult i64 %t561, %t563
  br i1 %t564, label %ok_565, label %trap_565
trap_565:
  call void @abort()
  unreachable
ok_565:
  %t566 = getelementptr i8, ptr %t562, i64 %t561
  store i8 %t560, ptr %t566, align 1
  %t567 = icmp ult i64 0, 64
  br i1 %t567, label %ok_568, label %trap_568
trap_568:
  call void @abort()
  unreachable
ok_568:
  %t569 = lshr i64 %p_6_3, 0
  %t570 = trunc i64 %t569 to i8
  %t571 = add i64 8, 0
  %t572 = extractvalue %hia.buffer %p_6_1, 0
  %t573 = extractvalue %hia.buffer %p_6_1, 1
  %t574 = icmp ult i64 %t571, %t573
  br i1 %t574, label %ok_575, label %trap_575
trap_575:
  call void @abort()
  unreachable
ok_575:
  %t576 = getelementptr i8, ptr %t572, i64 %t571
  store i8 %t570, ptr %t576, align 1
  %t577 = icmp ult i64 8, 64
  br i1 %t577, label %ok_578, label %trap_578
trap_578:
  call void @abort()
  unreachable
ok_578:
  %t579 = lshr i64 %p_6_3, 8
  %t580 = trunc i64 %t579 to i8
  %t581 = add i64 8, 1
  %t582 = extractvalue %hia.buffer %p_6_1, 0
  %t583 = extractvalue %hia.buffer %p_6_1, 1
  %t584 = icmp ult i64 %t581, %t583
  br i1 %t584, label %ok_585, label %trap_585
trap_585:
  call void @abort()
  unreachable
ok_585:
  %t586 = getelementptr i8, ptr %t582, i64 %t581
  store i8 %t580, ptr %t586, align 1
  %t587 = icmp ult i64 16, 64
  br i1 %t587, label %ok_588, label %trap_588
trap_588:
  call void @abort()
  unreachable
ok_588:
  %t589 = lshr i64 %p_6_3, 16
  %t590 = trunc i64 %t589 to i8
  %t591 = add i64 8, 2
  %t592 = extractvalue %hia.buffer %p_6_1, 0
  %t593 = extractvalue %hia.buffer %p_6_1, 1
  %t594 = icmp ult i64 %t591, %t593
  br i1 %t594, label %ok_595, label %trap_595
trap_595:
  call void @abort()
  unreachable
ok_595:
  %t596 = getelementptr i8, ptr %t592, i64 %t591
  store i8 %t590, ptr %t596, align 1
  %t597 = icmp ult i64 24, 64
  br i1 %t597, label %ok_598, label %trap_598
trap_598:
  call void @abort()
  unreachable
ok_598:
  %t599 = lshr i64 %p_6_3, 24
  %t600 = trunc i64 %t599 to i8
  %t601 = add i64 8, 3
  %t602 = extractvalue %hia.buffer %p_6_1, 0
  %t603 = extractvalue %hia.buffer %p_6_1, 1
  %t604 = icmp ult i64 %t601, %t603
  br i1 %t604, label %ok_605, label %trap_605
trap_605:
  call void @abort()
  unreachable
ok_605:
  %t606 = getelementptr i8, ptr %t602, i64 %t601
  store i8 %t600, ptr %t606, align 1
  %t607 = icmp ult i64 32, 64
  br i1 %t607, label %ok_608, label %trap_608
trap_608:
  call void @abort()
  unreachable
ok_608:
  %t609 = lshr i64 %p_6_3, 32
  %t610 = trunc i64 %t609 to i8
  %t611 = add i64 8, 4
  %t612 = extractvalue %hia.buffer %p_6_1, 0
  %t613 = extractvalue %hia.buffer %p_6_1, 1
  %t614 = icmp ult i64 %t611, %t613
  br i1 %t614, label %ok_615, label %trap_615
trap_615:
  call void @abort()
  unreachable
ok_615:
  %t616 = getelementptr i8, ptr %t612, i64 %t611
  store i8 %t610, ptr %t616, align 1
  %t617 = icmp ult i64 40, 64
  br i1 %t617, label %ok_618, label %trap_618
trap_618:
  call void @abort()
  unreachable
ok_618:
  %t619 = lshr i64 %p_6_3, 40
  %t620 = trunc i64 %t619 to i8
  %t621 = add i64 8, 5
  %t622 = extractvalue %hia.buffer %p_6_1, 0
  %t623 = extractvalue %hia.buffer %p_6_1, 1
  %t624 = icmp ult i64 %t621, %t623
  br i1 %t624, label %ok_625, label %trap_625
trap_625:
  call void @abort()
  unreachable
ok_625:
  %t626 = getelementptr i8, ptr %t622, i64 %t621
  store i8 %t620, ptr %t626, align 1
  %t627 = icmp ult i64 48, 64
  br i1 %t627, label %ok_628, label %trap_628
trap_628:
  call void @abort()
  unreachable
ok_628:
  %t629 = lshr i64 %p_6_3, 48
  %t630 = trunc i64 %t629 to i8
  %t631 = add i64 8, 6
  %t632 = extractvalue %hia.buffer %p_6_1, 0
  %t633 = extractvalue %hia.buffer %p_6_1, 1
  %t634 = icmp ult i64 %t631, %t633
  br i1 %t634, label %ok_635, label %trap_635
trap_635:
  call void @abort()
  unreachable
ok_635:
  %t636 = getelementptr i8, ptr %t632, i64 %t631
  store i8 %t630, ptr %t636, align 1
  %t637 = icmp ult i64 56, 64
  br i1 %t637, label %ok_638, label %trap_638
trap_638:
  call void @abort()
  unreachable
ok_638:
  %t639 = lshr i64 %p_6_3, 56
  %t640 = trunc i64 %t639 to i8
  %t641 = add i64 8, 7
  %t642 = extractvalue %hia.buffer %p_6_1, 0
  %t643 = extractvalue %hia.buffer %p_6_1, 1
  %t644 = icmp ult i64 %t641, %t643
  br i1 %t644, label %ok_645, label %trap_645
trap_645:
  call void @abort()
  unreachable
ok_645:
  %t646 = getelementptr i8, ptr %t642, i64 %t641
  store i8 %t640, ptr %t646, align 1
  %t647 = icmp ne i32 %p_6_9, 0
  br i1 %t647, label %edge_6, label %edge_7
b7:
  %p_7_0 = phi %hia.buffer [ %p_6_0, %edge_7 ]
  %p_7_1 = phi %hia.buffer [ %p_6_1, %edge_7 ]
  %p_7_2 = phi i64 [ %t486, %edge_7 ]
  %p_7_3 = phi i64 [ %p_6_3, %edge_7 ]
  %p_7_4 = phi i64 [ %p_6_4, %edge_7 ]
  %p_7_5 = phi i64 [ %p_6_5, %edge_7 ]
  %p_7_6 = phi i64 [ %p_6_6, %edge_7 ]
  %p_7_7 = phi i64 [ %p_6_7, %edge_7 ]
  %p_7_8 = phi i32 [ %p_6_8, %edge_7 ]
  %p_7_9 = phi i32 [ %p_6_9, %edge_7 ]
  %t648 = add i64 %p_7_4, %p_7_5
  %t649 = sub i64 %p_7_6, %t648
  %t650 = icmp uge i64 %t649, 4
  br i1 %t650, label %edge_8, label %edge_9
b8:
  %p_8_0 = phi %hia.buffer [ %p_7_0, %edge_8 ]
  %p_8_1 = phi %hia.buffer [ %p_7_1, %edge_8 ]
  %p_8_2 = phi i64 [ %p_7_2, %edge_8 ]
  %p_8_3 = phi i64 [ %p_7_3, %edge_8 ]
  %p_8_4 = phi i64 [ %p_7_4, %edge_8 ]
  %p_8_5 = phi i64 [ %p_7_5, %edge_8 ]
  %p_8_6 = phi i64 [ %p_7_6, %edge_8 ]
  %p_8_7 = phi i64 [ %p_7_7, %edge_8 ]
  %p_8_8 = phi i32 [ %p_7_8, %edge_8 ]
  %p_8_9 = phi i32 [ %p_7_9, %edge_8 ]
  %t651 = add i64 %p_8_4, %p_8_5
  %t652 = icmp ult i64 24, 64
  br i1 %t652, label %ok_653, label %trap_653
trap_653:
  call void @abort()
  unreachable
ok_653:
  %t654 = lshr i64 %p_8_2, 24
  %t655 = trunc i64 %t654 to i8
  %t656 = add i64 %t651, 0
  %t657 = extractvalue %hia.buffer %p_8_0, 0
  %t658 = extractvalue %hia.buffer %p_8_0, 1
  %t659 = icmp ult i64 %t656, %t658
  br i1 %t659, label %ok_660, label %trap_660
trap_660:
  call void @abort()
  unreachable
ok_660:
  %t661 = getelementptr i8, ptr %t657, i64 %t656
  store i8 %t655, ptr %t661, align 1
  %t662 = icmp ult i64 16, 64
  br i1 %t662, label %ok_663, label %trap_663
trap_663:
  call void @abort()
  unreachable
ok_663:
  %t664 = lshr i64 %p_8_2, 16
  %t665 = trunc i64 %t664 to i8
  %t666 = add i64 %t651, 1
  %t667 = extractvalue %hia.buffer %p_8_0, 0
  %t668 = extractvalue %hia.buffer %p_8_0, 1
  %t669 = icmp ult i64 %t666, %t668
  br i1 %t669, label %ok_670, label %trap_670
trap_670:
  call void @abort()
  unreachable
ok_670:
  %t671 = getelementptr i8, ptr %t667, i64 %t666
  store i8 %t665, ptr %t671, align 1
  %t672 = icmp ult i64 8, 64
  br i1 %t672, label %ok_673, label %trap_673
trap_673:
  call void @abort()
  unreachable
ok_673:
  %t674 = lshr i64 %p_8_2, 8
  %t675 = trunc i64 %t674 to i8
  %t676 = add i64 %t651, 2
  %t677 = extractvalue %hia.buffer %p_8_0, 0
  %t678 = extractvalue %hia.buffer %p_8_0, 1
  %t679 = icmp ult i64 %t676, %t678
  br i1 %t679, label %ok_680, label %trap_680
trap_680:
  call void @abort()
  unreachable
ok_680:
  %t681 = getelementptr i8, ptr %t677, i64 %t676
  store i8 %t675, ptr %t681, align 1
  %t682 = icmp ult i64 0, 64
  br i1 %t682, label %ok_683, label %trap_683
trap_683:
  call void @abort()
  unreachable
ok_683:
  %t684 = lshr i64 %p_8_2, 0
  %t685 = trunc i64 %t684 to i8
  %t686 = add i64 %t651, 3
  %t687 = extractvalue %hia.buffer %p_8_0, 0
  %t688 = extractvalue %hia.buffer %p_8_0, 1
  %t689 = icmp ult i64 %t686, %t688
  br i1 %t689, label %ok_690, label %trap_690
trap_690:
  call void @abort()
  unreachable
ok_690:
  %t691 = getelementptr i8, ptr %t687, i64 %t686
  store i8 %t685, ptr %t691, align 1
  %t692 = add i64 %p_8_5, 4
  %t693 = icmp ult i64 0, 64
  br i1 %t693, label %ok_694, label %trap_694
trap_694:
  call void @abort()
  unreachable
ok_694:
  %t695 = lshr i64 %t692, 0
  %t696 = trunc i64 %t695 to i8
  %t697 = add i64 24, 0
  %t698 = extractvalue %hia.buffer %p_8_1, 0
  %t699 = extractvalue %hia.buffer %p_8_1, 1
  %t700 = icmp ult i64 %t697, %t699
  br i1 %t700, label %ok_701, label %trap_701
trap_701:
  call void @abort()
  unreachable
ok_701:
  %t702 = getelementptr i8, ptr %t698, i64 %t697
  store i8 %t696, ptr %t702, align 1
  %t703 = icmp ult i64 8, 64
  br i1 %t703, label %ok_704, label %trap_704
trap_704:
  call void @abort()
  unreachable
ok_704:
  %t705 = lshr i64 %t692, 8
  %t706 = trunc i64 %t705 to i8
  %t707 = add i64 24, 1
  %t708 = extractvalue %hia.buffer %p_8_1, 0
  %t709 = extractvalue %hia.buffer %p_8_1, 1
  %t710 = icmp ult i64 %t707, %t709
  br i1 %t710, label %ok_711, label %trap_711
trap_711:
  call void @abort()
  unreachable
ok_711:
  %t712 = getelementptr i8, ptr %t708, i64 %t707
  store i8 %t706, ptr %t712, align 1
  %t713 = icmp ult i64 16, 64
  br i1 %t713, label %ok_714, label %trap_714
trap_714:
  call void @abort()
  unreachable
ok_714:
  %t715 = lshr i64 %t692, 16
  %t716 = trunc i64 %t715 to i8
  %t717 = add i64 24, 2
  %t718 = extractvalue %hia.buffer %p_8_1, 0
  %t719 = extractvalue %hia.buffer %p_8_1, 1
  %t720 = icmp ult i64 %t717, %t719
  br i1 %t720, label %ok_721, label %trap_721
trap_721:
  call void @abort()
  unreachable
ok_721:
  %t722 = getelementptr i8, ptr %t718, i64 %t717
  store i8 %t716, ptr %t722, align 1
  %t723 = icmp ult i64 24, 64
  br i1 %t723, label %ok_724, label %trap_724
trap_724:
  call void @abort()
  unreachable
ok_724:
  %t725 = lshr i64 %t692, 24
  %t726 = trunc i64 %t725 to i8
  %t727 = add i64 24, 3
  %t728 = extractvalue %hia.buffer %p_8_1, 0
  %t729 = extractvalue %hia.buffer %p_8_1, 1
  %t730 = icmp ult i64 %t727, %t729
  br i1 %t730, label %ok_731, label %trap_731
trap_731:
  call void @abort()
  unreachable
ok_731:
  %t732 = getelementptr i8, ptr %t728, i64 %t727
  store i8 %t726, ptr %t732, align 1
  %t733 = icmp ult i64 32, 64
  br i1 %t733, label %ok_734, label %trap_734
trap_734:
  call void @abort()
  unreachable
ok_734:
  %t735 = lshr i64 %t692, 32
  %t736 = trunc i64 %t735 to i8
  %t737 = add i64 24, 4
  %t738 = extractvalue %hia.buffer %p_8_1, 0
  %t739 = extractvalue %hia.buffer %p_8_1, 1
  %t740 = icmp ult i64 %t737, %t739
  br i1 %t740, label %ok_741, label %trap_741
trap_741:
  call void @abort()
  unreachable
ok_741:
  %t742 = getelementptr i8, ptr %t738, i64 %t737
  store i8 %t736, ptr %t742, align 1
  %t743 = icmp ult i64 40, 64
  br i1 %t743, label %ok_744, label %trap_744
trap_744:
  call void @abort()
  unreachable
ok_744:
  %t745 = lshr i64 %t692, 40
  %t746 = trunc i64 %t745 to i8
  %t747 = add i64 24, 5
  %t748 = extractvalue %hia.buffer %p_8_1, 0
  %t749 = extractvalue %hia.buffer %p_8_1, 1
  %t750 = icmp ult i64 %t747, %t749
  br i1 %t750, label %ok_751, label %trap_751
trap_751:
  call void @abort()
  unreachable
ok_751:
  %t752 = getelementptr i8, ptr %t748, i64 %t747
  store i8 %t746, ptr %t752, align 1
  %t753 = icmp ult i64 48, 64
  br i1 %t753, label %ok_754, label %trap_754
trap_754:
  call void @abort()
  unreachable
ok_754:
  %t755 = lshr i64 %t692, 48
  %t756 = trunc i64 %t755 to i8
  %t757 = add i64 24, 6
  %t758 = extractvalue %hia.buffer %p_8_1, 0
  %t759 = extractvalue %hia.buffer %p_8_1, 1
  %t760 = icmp ult i64 %t757, %t759
  br i1 %t760, label %ok_761, label %trap_761
trap_761:
  call void @abort()
  unreachable
ok_761:
  %t762 = getelementptr i8, ptr %t758, i64 %t757
  store i8 %t756, ptr %t762, align 1
  %t763 = icmp ult i64 56, 64
  br i1 %t763, label %ok_764, label %trap_764
trap_764:
  call void @abort()
  unreachable
ok_764:
  %t765 = lshr i64 %t692, 56
  %t766 = trunc i64 %t765 to i8
  %t767 = add i64 24, 7
  %t768 = extractvalue %hia.buffer %p_8_1, 0
  %t769 = extractvalue %hia.buffer %p_8_1, 1
  %t770 = icmp ult i64 %t767, %t769
  br i1 %t770, label %ok_771, label %trap_771
trap_771:
  call void @abort()
  unreachable
ok_771:
  %t772 = getelementptr i8, ptr %t768, i64 %t767
  store i8 %t766, ptr %t772, align 1
  %t773 = icmp ne i32 %p_8_8, 0
  br i1 %t773, label %edge_10, label %edge_11
b9:
  %p_9_0 = phi %hia.buffer [ %p_8_0, %edge_10 ]
  %p_9_1 = phi %hia.buffer [ %p_8_1, %edge_10 ]
  %p_9_2 = phi i64 [ %p_8_2, %edge_10 ]
  %p_9_3 = phi i64 [ %p_8_3, %edge_10 ]
  %p_9_4 = phi i64 [ %p_8_4, %edge_10 ]
  %p_9_5 = phi i64 [ %t692, %edge_10 ]
  %p_9_6 = phi i64 [ %p_8_6, %edge_10 ]
  %p_9_7 = phi i64 [ %p_8_7, %edge_10 ]
  %p_9_8 = phi i32 [ %p_8_8, %edge_10 ]
  %p_9_9 = phi i32 [ %p_8_9, %edge_10 ]
  %t774 = add i64 %p_9_4, %p_9_5
  %t775 = sub i64 %p_9_6, %t774
  %t776 = icmp uge i64 %t775, 4
  br i1 %t776, label %edge_12, label %edge_13
b10:
  %p_10_0 = phi %hia.buffer [ %p_9_0, %edge_12 ]
  %p_10_1 = phi %hia.buffer [ %p_9_1, %edge_12 ]
  %p_10_2 = phi i64 [ %p_9_2, %edge_12 ]
  %p_10_3 = phi i64 [ %p_9_3, %edge_12 ]
  %p_10_4 = phi i64 [ %p_9_4, %edge_12 ]
  %p_10_5 = phi i64 [ %p_9_5, %edge_12 ]
  %p_10_6 = phi i64 [ %p_9_6, %edge_12 ]
  %p_10_7 = phi i64 [ %p_9_7, %edge_12 ]
  %p_10_8 = phi i32 [ %p_9_8, %edge_12 ]
  %p_10_9 = phi i32 [ %p_9_9, %edge_12 ]
  %t777 = add i64 %p_10_4, %p_10_5
  %t778 = icmp ult i64 24, 64
  br i1 %t778, label %ok_779, label %trap_779
trap_779:
  call void @abort()
  unreachable
ok_779:
  %t780 = lshr i64 %p_10_3, 24
  %t781 = trunc i64 %t780 to i8
  %t782 = add i64 %t777, 0
  %t783 = extractvalue %hia.buffer %p_10_0, 0
  %t784 = extractvalue %hia.buffer %p_10_0, 1
  %t785 = icmp ult i64 %t782, %t784
  br i1 %t785, label %ok_786, label %trap_786
trap_786:
  call void @abort()
  unreachable
ok_786:
  %t787 = getelementptr i8, ptr %t783, i64 %t782
  store i8 %t781, ptr %t787, align 1
  %t788 = icmp ult i64 16, 64
  br i1 %t788, label %ok_789, label %trap_789
trap_789:
  call void @abort()
  unreachable
ok_789:
  %t790 = lshr i64 %p_10_3, 16
  %t791 = trunc i64 %t790 to i8
  %t792 = add i64 %t777, 1
  %t793 = extractvalue %hia.buffer %p_10_0, 0
  %t794 = extractvalue %hia.buffer %p_10_0, 1
  %t795 = icmp ult i64 %t792, %t794
  br i1 %t795, label %ok_796, label %trap_796
trap_796:
  call void @abort()
  unreachable
ok_796:
  %t797 = getelementptr i8, ptr %t793, i64 %t792
  store i8 %t791, ptr %t797, align 1
  %t798 = icmp ult i64 8, 64
  br i1 %t798, label %ok_799, label %trap_799
trap_799:
  call void @abort()
  unreachable
ok_799:
  %t800 = lshr i64 %p_10_3, 8
  %t801 = trunc i64 %t800 to i8
  %t802 = add i64 %t777, 2
  %t803 = extractvalue %hia.buffer %p_10_0, 0
  %t804 = extractvalue %hia.buffer %p_10_0, 1
  %t805 = icmp ult i64 %t802, %t804
  br i1 %t805, label %ok_806, label %trap_806
trap_806:
  call void @abort()
  unreachable
ok_806:
  %t807 = getelementptr i8, ptr %t803, i64 %t802
  store i8 %t801, ptr %t807, align 1
  %t808 = icmp ult i64 0, 64
  br i1 %t808, label %ok_809, label %trap_809
trap_809:
  call void @abort()
  unreachable
ok_809:
  %t810 = lshr i64 %p_10_3, 0
  %t811 = trunc i64 %t810 to i8
  %t812 = add i64 %t777, 3
  %t813 = extractvalue %hia.buffer %p_10_0, 0
  %t814 = extractvalue %hia.buffer %p_10_0, 1
  %t815 = icmp ult i64 %t812, %t814
  br i1 %t815, label %ok_816, label %trap_816
trap_816:
  call void @abort()
  unreachable
ok_816:
  %t817 = getelementptr i8, ptr %t813, i64 %t812
  store i8 %t811, ptr %t817, align 1
  %t818 = add i64 %p_10_5, 4
  %t819 = icmp ult i64 0, 64
  br i1 %t819, label %ok_820, label %trap_820
trap_820:
  call void @abort()
  unreachable
ok_820:
  %t821 = lshr i64 %t818, 0
  %t822 = trunc i64 %t821 to i8
  %t823 = add i64 24, 0
  %t824 = extractvalue %hia.buffer %p_10_1, 0
  %t825 = extractvalue %hia.buffer %p_10_1, 1
  %t826 = icmp ult i64 %t823, %t825
  br i1 %t826, label %ok_827, label %trap_827
trap_827:
  call void @abort()
  unreachable
ok_827:
  %t828 = getelementptr i8, ptr %t824, i64 %t823
  store i8 %t822, ptr %t828, align 1
  %t829 = icmp ult i64 8, 64
  br i1 %t829, label %ok_830, label %trap_830
trap_830:
  call void @abort()
  unreachable
ok_830:
  %t831 = lshr i64 %t818, 8
  %t832 = trunc i64 %t831 to i8
  %t833 = add i64 24, 1
  %t834 = extractvalue %hia.buffer %p_10_1, 0
  %t835 = extractvalue %hia.buffer %p_10_1, 1
  %t836 = icmp ult i64 %t833, %t835
  br i1 %t836, label %ok_837, label %trap_837
trap_837:
  call void @abort()
  unreachable
ok_837:
  %t838 = getelementptr i8, ptr %t834, i64 %t833
  store i8 %t832, ptr %t838, align 1
  %t839 = icmp ult i64 16, 64
  br i1 %t839, label %ok_840, label %trap_840
trap_840:
  call void @abort()
  unreachable
ok_840:
  %t841 = lshr i64 %t818, 16
  %t842 = trunc i64 %t841 to i8
  %t843 = add i64 24, 2
  %t844 = extractvalue %hia.buffer %p_10_1, 0
  %t845 = extractvalue %hia.buffer %p_10_1, 1
  %t846 = icmp ult i64 %t843, %t845
  br i1 %t846, label %ok_847, label %trap_847
trap_847:
  call void @abort()
  unreachable
ok_847:
  %t848 = getelementptr i8, ptr %t844, i64 %t843
  store i8 %t842, ptr %t848, align 1
  %t849 = icmp ult i64 24, 64
  br i1 %t849, label %ok_850, label %trap_850
trap_850:
  call void @abort()
  unreachable
ok_850:
  %t851 = lshr i64 %t818, 24
  %t852 = trunc i64 %t851 to i8
  %t853 = add i64 24, 3
  %t854 = extractvalue %hia.buffer %p_10_1, 0
  %t855 = extractvalue %hia.buffer %p_10_1, 1
  %t856 = icmp ult i64 %t853, %t855
  br i1 %t856, label %ok_857, label %trap_857
trap_857:
  call void @abort()
  unreachable
ok_857:
  %t858 = getelementptr i8, ptr %t854, i64 %t853
  store i8 %t852, ptr %t858, align 1
  %t859 = icmp ult i64 32, 64
  br i1 %t859, label %ok_860, label %trap_860
trap_860:
  call void @abort()
  unreachable
ok_860:
  %t861 = lshr i64 %t818, 32
  %t862 = trunc i64 %t861 to i8
  %t863 = add i64 24, 4
  %t864 = extractvalue %hia.buffer %p_10_1, 0
  %t865 = extractvalue %hia.buffer %p_10_1, 1
  %t866 = icmp ult i64 %t863, %t865
  br i1 %t866, label %ok_867, label %trap_867
trap_867:
  call void @abort()
  unreachable
ok_867:
  %t868 = getelementptr i8, ptr %t864, i64 %t863
  store i8 %t862, ptr %t868, align 1
  %t869 = icmp ult i64 40, 64
  br i1 %t869, label %ok_870, label %trap_870
trap_870:
  call void @abort()
  unreachable
ok_870:
  %t871 = lshr i64 %t818, 40
  %t872 = trunc i64 %t871 to i8
  %t873 = add i64 24, 5
  %t874 = extractvalue %hia.buffer %p_10_1, 0
  %t875 = extractvalue %hia.buffer %p_10_1, 1
  %t876 = icmp ult i64 %t873, %t875
  br i1 %t876, label %ok_877, label %trap_877
trap_877:
  call void @abort()
  unreachable
ok_877:
  %t878 = getelementptr i8, ptr %t874, i64 %t873
  store i8 %t872, ptr %t878, align 1
  %t879 = icmp ult i64 48, 64
  br i1 %t879, label %ok_880, label %trap_880
trap_880:
  call void @abort()
  unreachable
ok_880:
  %t881 = lshr i64 %t818, 48
  %t882 = trunc i64 %t881 to i8
  %t883 = add i64 24, 6
  %t884 = extractvalue %hia.buffer %p_10_1, 0
  %t885 = extractvalue %hia.buffer %p_10_1, 1
  %t886 = icmp ult i64 %t883, %t885
  br i1 %t886, label %ok_887, label %trap_887
trap_887:
  call void @abort()
  unreachable
ok_887:
  %t888 = getelementptr i8, ptr %t884, i64 %t883
  store i8 %t882, ptr %t888, align 1
  %t889 = icmp ult i64 56, 64
  br i1 %t889, label %ok_890, label %trap_890
trap_890:
  call void @abort()
  unreachable
ok_890:
  %t891 = lshr i64 %t818, 56
  %t892 = trunc i64 %t891 to i8
  %t893 = add i64 24, 7
  %t894 = extractvalue %hia.buffer %p_10_1, 0
  %t895 = extractvalue %hia.buffer %p_10_1, 1
  %t896 = icmp ult i64 %t893, %t895
  br i1 %t896, label %ok_897, label %trap_897
trap_897:
  call void @abort()
  unreachable
ok_897:
  %t898 = getelementptr i8, ptr %t894, i64 %t893
  store i8 %t892, ptr %t898, align 1
  br label %edge_14
b11:
  %p_11_0 = phi %hia.buffer [ %p_6_0, %edge_6 ]
  %p_11_1 = phi %hia.buffer [ %p_6_1, %edge_6 ]
  %p_11_2 = phi i64 [ %t486, %edge_6 ]
  %p_11_3 = phi i64 [ %p_6_3, %edge_6 ]
  %p_11_4 = phi i64 [ %p_6_4, %edge_6 ]
  %p_11_5 = phi i64 [ %p_6_5, %edge_6 ]
  %p_11_6 = phi i64 [ %p_6_6, %edge_6 ]
  %p_11_7 = phi i64 [ %p_6_7, %edge_6 ]
  %p_11_8 = phi i32 [ %p_6_8, %edge_6 ]
  %p_11_9 = phi i32 [ %p_6_9, %edge_6 ]
  %t899 = icmp ne i32 %p_11_8, 0
  br i1 %t899, label %edge_15, label %edge_16
b12:
  %p_12_0 = phi %hia.buffer [ %p_11_0, %edge_15 ]
  %p_12_1 = phi %hia.buffer [ %p_11_1, %edge_15 ]
  %p_12_2 = phi i64 [ %p_11_2, %edge_15 ]
  %p_12_3 = phi i64 [ %p_11_3, %edge_15 ]
  %p_12_4 = phi i64 [ %p_11_4, %edge_15 ]
  %p_12_5 = phi i64 [ %p_11_5, %edge_15 ]
  %p_12_6 = phi i64 [ %p_11_6, %edge_15 ]
  %p_12_7 = phi i64 [ %p_11_7, %edge_15 ]
  %p_12_8 = phi i32 [ %p_11_8, %edge_15 ]
  %p_12_9 = phi i32 [ %p_11_9, %edge_15 ]
  %t900 = icmp uge i64 %p_12_4, 4
  br i1 %t900, label %edge_17, label %edge_18
b13:
  %p_13_0 = phi %hia.buffer [ %p_12_0, %edge_17 ]
  %p_13_1 = phi %hia.buffer [ %p_12_1, %edge_17 ]
  %p_13_2 = phi i64 [ %p_12_2, %edge_17 ]
  %p_13_3 = phi i64 [ %p_12_3, %edge_17 ]
  %p_13_4 = phi i64 [ %p_12_4, %edge_17 ]
  %p_13_5 = phi i64 [ %p_12_5, %edge_17 ]
  %p_13_6 = phi i64 [ %p_12_6, %edge_17 ]
  %p_13_7 = phi i64 [ %p_12_7, %edge_17 ]
  %p_13_8 = phi i32 [ %p_12_8, %edge_17 ]
  %p_13_9 = phi i32 [ %p_12_9, %edge_17 ]
  %t901 = sub i64 %p_13_4, 4
  %t902 = add i64 %p_13_5, 4
  %t903 = icmp ult i64 24, 64
  br i1 %t903, label %ok_904, label %trap_904
trap_904:
  call void @abort()
  unreachable
ok_904:
  %t905 = lshr i64 %p_13_3, 24
  %t906 = trunc i64 %t905 to i8
  %t907 = add i64 %t901, 0
  %t908 = extractvalue %hia.buffer %p_13_0, 0
  %t909 = extractvalue %hia.buffer %p_13_0, 1
  %t910 = icmp ult i64 %t907, %t909
  br i1 %t910, label %ok_911, label %trap_911
trap_911:
  call void @abort()
  unreachable
ok_911:
  %t912 = getelementptr i8, ptr %t908, i64 %t907
  store i8 %t906, ptr %t912, align 1
  %t913 = icmp ult i64 16, 64
  br i1 %t913, label %ok_914, label %trap_914
trap_914:
  call void @abort()
  unreachable
ok_914:
  %t915 = lshr i64 %p_13_3, 16
  %t916 = trunc i64 %t915 to i8
  %t917 = add i64 %t901, 1
  %t918 = extractvalue %hia.buffer %p_13_0, 0
  %t919 = extractvalue %hia.buffer %p_13_0, 1
  %t920 = icmp ult i64 %t917, %t919
  br i1 %t920, label %ok_921, label %trap_921
trap_921:
  call void @abort()
  unreachable
ok_921:
  %t922 = getelementptr i8, ptr %t918, i64 %t917
  store i8 %t916, ptr %t922, align 1
  %t923 = icmp ult i64 8, 64
  br i1 %t923, label %ok_924, label %trap_924
trap_924:
  call void @abort()
  unreachable
ok_924:
  %t925 = lshr i64 %p_13_3, 8
  %t926 = trunc i64 %t925 to i8
  %t927 = add i64 %t901, 2
  %t928 = extractvalue %hia.buffer %p_13_0, 0
  %t929 = extractvalue %hia.buffer %p_13_0, 1
  %t930 = icmp ult i64 %t927, %t929
  br i1 %t930, label %ok_931, label %trap_931
trap_931:
  call void @abort()
  unreachable
ok_931:
  %t932 = getelementptr i8, ptr %t928, i64 %t927
  store i8 %t926, ptr %t932, align 1
  %t933 = icmp ult i64 0, 64
  br i1 %t933, label %ok_934, label %trap_934
trap_934:
  call void @abort()
  unreachable
ok_934:
  %t935 = lshr i64 %p_13_3, 0
  %t936 = trunc i64 %t935 to i8
  %t937 = add i64 %t901, 3
  %t938 = extractvalue %hia.buffer %p_13_0, 0
  %t939 = extractvalue %hia.buffer %p_13_0, 1
  %t940 = icmp ult i64 %t937, %t939
  br i1 %t940, label %ok_941, label %trap_941
trap_941:
  call void @abort()
  unreachable
ok_941:
  %t942 = getelementptr i8, ptr %t938, i64 %t937
  store i8 %t936, ptr %t942, align 1
  %t943 = icmp ult i64 0, 64
  br i1 %t943, label %ok_944, label %trap_944
trap_944:
  call void @abort()
  unreachable
ok_944:
  %t945 = lshr i64 %t901, 0
  %t946 = trunc i64 %t945 to i8
  %t947 = add i64 16, 0
  %t948 = extractvalue %hia.buffer %p_13_1, 0
  %t949 = extractvalue %hia.buffer %p_13_1, 1
  %t950 = icmp ult i64 %t947, %t949
  br i1 %t950, label %ok_951, label %trap_951
trap_951:
  call void @abort()
  unreachable
ok_951:
  %t952 = getelementptr i8, ptr %t948, i64 %t947
  store i8 %t946, ptr %t952, align 1
  %t953 = icmp ult i64 8, 64
  br i1 %t953, label %ok_954, label %trap_954
trap_954:
  call void @abort()
  unreachable
ok_954:
  %t955 = lshr i64 %t901, 8
  %t956 = trunc i64 %t955 to i8
  %t957 = add i64 16, 1
  %t958 = extractvalue %hia.buffer %p_13_1, 0
  %t959 = extractvalue %hia.buffer %p_13_1, 1
  %t960 = icmp ult i64 %t957, %t959
  br i1 %t960, label %ok_961, label %trap_961
trap_961:
  call void @abort()
  unreachable
ok_961:
  %t962 = getelementptr i8, ptr %t958, i64 %t957
  store i8 %t956, ptr %t962, align 1
  %t963 = icmp ult i64 16, 64
  br i1 %t963, label %ok_964, label %trap_964
trap_964:
  call void @abort()
  unreachable
ok_964:
  %t965 = lshr i64 %t901, 16
  %t966 = trunc i64 %t965 to i8
  %t967 = add i64 16, 2
  %t968 = extractvalue %hia.buffer %p_13_1, 0
  %t969 = extractvalue %hia.buffer %p_13_1, 1
  %t970 = icmp ult i64 %t967, %t969
  br i1 %t970, label %ok_971, label %trap_971
trap_971:
  call void @abort()
  unreachable
ok_971:
  %t972 = getelementptr i8, ptr %t968, i64 %t967
  store i8 %t966, ptr %t972, align 1
  %t973 = icmp ult i64 24, 64
  br i1 %t973, label %ok_974, label %trap_974
trap_974:
  call void @abort()
  unreachable
ok_974:
  %t975 = lshr i64 %t901, 24
  %t976 = trunc i64 %t975 to i8
  %t977 = add i64 16, 3
  %t978 = extractvalue %hia.buffer %p_13_1, 0
  %t979 = extractvalue %hia.buffer %p_13_1, 1
  %t980 = icmp ult i64 %t977, %t979
  br i1 %t980, label %ok_981, label %trap_981
trap_981:
  call void @abort()
  unreachable
ok_981:
  %t982 = getelementptr i8, ptr %t978, i64 %t977
  store i8 %t976, ptr %t982, align 1
  %t983 = icmp ult i64 32, 64
  br i1 %t983, label %ok_984, label %trap_984
trap_984:
  call void @abort()
  unreachable
ok_984:
  %t985 = lshr i64 %t901, 32
  %t986 = trunc i64 %t985 to i8
  %t987 = add i64 16, 4
  %t988 = extractvalue %hia.buffer %p_13_1, 0
  %t989 = extractvalue %hia.buffer %p_13_1, 1
  %t990 = icmp ult i64 %t987, %t989
  br i1 %t990, label %ok_991, label %trap_991
trap_991:
  call void @abort()
  unreachable
ok_991:
  %t992 = getelementptr i8, ptr %t988, i64 %t987
  store i8 %t986, ptr %t992, align 1
  %t993 = icmp ult i64 40, 64
  br i1 %t993, label %ok_994, label %trap_994
trap_994:
  call void @abort()
  unreachable
ok_994:
  %t995 = lshr i64 %t901, 40
  %t996 = trunc i64 %t995 to i8
  %t997 = add i64 16, 5
  %t998 = extractvalue %hia.buffer %p_13_1, 0
  %t999 = extractvalue %hia.buffer %p_13_1, 1
  %t1000 = icmp ult i64 %t997, %t999
  br i1 %t1000, label %ok_1001, label %trap_1001
trap_1001:
  call void @abort()
  unreachable
ok_1001:
  %t1002 = getelementptr i8, ptr %t998, i64 %t997
  store i8 %t996, ptr %t1002, align 1
  %t1003 = icmp ult i64 48, 64
  br i1 %t1003, label %ok_1004, label %trap_1004
trap_1004:
  call void @abort()
  unreachable
ok_1004:
  %t1005 = lshr i64 %t901, 48
  %t1006 = trunc i64 %t1005 to i8
  %t1007 = add i64 16, 6
  %t1008 = extractvalue %hia.buffer %p_13_1, 0
  %t1009 = extractvalue %hia.buffer %p_13_1, 1
  %t1010 = icmp ult i64 %t1007, %t1009
  br i1 %t1010, label %ok_1011, label %trap_1011
trap_1011:
  call void @abort()
  unreachable
ok_1011:
  %t1012 = getelementptr i8, ptr %t1008, i64 %t1007
  store i8 %t1006, ptr %t1012, align 1
  %t1013 = icmp ult i64 56, 64
  br i1 %t1013, label %ok_1014, label %trap_1014
trap_1014:
  call void @abort()
  unreachable
ok_1014:
  %t1015 = lshr i64 %t901, 56
  %t1016 = trunc i64 %t1015 to i8
  %t1017 = add i64 16, 7
  %t1018 = extractvalue %hia.buffer %p_13_1, 0
  %t1019 = extractvalue %hia.buffer %p_13_1, 1
  %t1020 = icmp ult i64 %t1017, %t1019
  br i1 %t1020, label %ok_1021, label %trap_1021
trap_1021:
  call void @abort()
  unreachable
ok_1021:
  %t1022 = getelementptr i8, ptr %t1018, i64 %t1017
  store i8 %t1016, ptr %t1022, align 1
  %t1023 = icmp ult i64 0, 64
  br i1 %t1023, label %ok_1024, label %trap_1024
trap_1024:
  call void @abort()
  unreachable
ok_1024:
  %t1025 = lshr i64 %t902, 0
  %t1026 = trunc i64 %t1025 to i8
  %t1027 = add i64 24, 0
  %t1028 = extractvalue %hia.buffer %p_13_1, 0
  %t1029 = extractvalue %hia.buffer %p_13_1, 1
  %t1030 = icmp ult i64 %t1027, %t1029
  br i1 %t1030, label %ok_1031, label %trap_1031
trap_1031:
  call void @abort()
  unreachable
ok_1031:
  %t1032 = getelementptr i8, ptr %t1028, i64 %t1027
  store i8 %t1026, ptr %t1032, align 1
  %t1033 = icmp ult i64 8, 64
  br i1 %t1033, label %ok_1034, label %trap_1034
trap_1034:
  call void @abort()
  unreachable
ok_1034:
  %t1035 = lshr i64 %t902, 8
  %t1036 = trunc i64 %t1035 to i8
  %t1037 = add i64 24, 1
  %t1038 = extractvalue %hia.buffer %p_13_1, 0
  %t1039 = extractvalue %hia.buffer %p_13_1, 1
  %t1040 = icmp ult i64 %t1037, %t1039
  br i1 %t1040, label %ok_1041, label %trap_1041
trap_1041:
  call void @abort()
  unreachable
ok_1041:
  %t1042 = getelementptr i8, ptr %t1038, i64 %t1037
  store i8 %t1036, ptr %t1042, align 1
  %t1043 = icmp ult i64 16, 64
  br i1 %t1043, label %ok_1044, label %trap_1044
trap_1044:
  call void @abort()
  unreachable
ok_1044:
  %t1045 = lshr i64 %t902, 16
  %t1046 = trunc i64 %t1045 to i8
  %t1047 = add i64 24, 2
  %t1048 = extractvalue %hia.buffer %p_13_1, 0
  %t1049 = extractvalue %hia.buffer %p_13_1, 1
  %t1050 = icmp ult i64 %t1047, %t1049
  br i1 %t1050, label %ok_1051, label %trap_1051
trap_1051:
  call void @abort()
  unreachable
ok_1051:
  %t1052 = getelementptr i8, ptr %t1048, i64 %t1047
  store i8 %t1046, ptr %t1052, align 1
  %t1053 = icmp ult i64 24, 64
  br i1 %t1053, label %ok_1054, label %trap_1054
trap_1054:
  call void @abort()
  unreachable
ok_1054:
  %t1055 = lshr i64 %t902, 24
  %t1056 = trunc i64 %t1055 to i8
  %t1057 = add i64 24, 3
  %t1058 = extractvalue %hia.buffer %p_13_1, 0
  %t1059 = extractvalue %hia.buffer %p_13_1, 1
  %t1060 = icmp ult i64 %t1057, %t1059
  br i1 %t1060, label %ok_1061, label %trap_1061
trap_1061:
  call void @abort()
  unreachable
ok_1061:
  %t1062 = getelementptr i8, ptr %t1058, i64 %t1057
  store i8 %t1056, ptr %t1062, align 1
  %t1063 = icmp ult i64 32, 64
  br i1 %t1063, label %ok_1064, label %trap_1064
trap_1064:
  call void @abort()
  unreachable
ok_1064:
  %t1065 = lshr i64 %t902, 32
  %t1066 = trunc i64 %t1065 to i8
  %t1067 = add i64 24, 4
  %t1068 = extractvalue %hia.buffer %p_13_1, 0
  %t1069 = extractvalue %hia.buffer %p_13_1, 1
  %t1070 = icmp ult i64 %t1067, %t1069
  br i1 %t1070, label %ok_1071, label %trap_1071
trap_1071:
  call void @abort()
  unreachable
ok_1071:
  %t1072 = getelementptr i8, ptr %t1068, i64 %t1067
  store i8 %t1066, ptr %t1072, align 1
  %t1073 = icmp ult i64 40, 64
  br i1 %t1073, label %ok_1074, label %trap_1074
trap_1074:
  call void @abort()
  unreachable
ok_1074:
  %t1075 = lshr i64 %t902, 40
  %t1076 = trunc i64 %t1075 to i8
  %t1077 = add i64 24, 5
  %t1078 = extractvalue %hia.buffer %p_13_1, 0
  %t1079 = extractvalue %hia.buffer %p_13_1, 1
  %t1080 = icmp ult i64 %t1077, %t1079
  br i1 %t1080, label %ok_1081, label %trap_1081
trap_1081:
  call void @abort()
  unreachable
ok_1081:
  %t1082 = getelementptr i8, ptr %t1078, i64 %t1077
  store i8 %t1076, ptr %t1082, align 1
  %t1083 = icmp ult i64 48, 64
  br i1 %t1083, label %ok_1084, label %trap_1084
trap_1084:
  call void @abort()
  unreachable
ok_1084:
  %t1085 = lshr i64 %t902, 48
  %t1086 = trunc i64 %t1085 to i8
  %t1087 = add i64 24, 6
  %t1088 = extractvalue %hia.buffer %p_13_1, 0
  %t1089 = extractvalue %hia.buffer %p_13_1, 1
  %t1090 = icmp ult i64 %t1087, %t1089
  br i1 %t1090, label %ok_1091, label %trap_1091
trap_1091:
  call void @abort()
  unreachable
ok_1091:
  %t1092 = getelementptr i8, ptr %t1088, i64 %t1087
  store i8 %t1086, ptr %t1092, align 1
  %t1093 = icmp ult i64 56, 64
  br i1 %t1093, label %ok_1094, label %trap_1094
trap_1094:
  call void @abort()
  unreachable
ok_1094:
  %t1095 = lshr i64 %t902, 56
  %t1096 = trunc i64 %t1095 to i8
  %t1097 = add i64 24, 7
  %t1098 = extractvalue %hia.buffer %p_13_1, 0
  %t1099 = extractvalue %hia.buffer %p_13_1, 1
  %t1100 = icmp ult i64 %t1097, %t1099
  br i1 %t1100, label %ok_1101, label %trap_1101
trap_1101:
  call void @abort()
  unreachable
ok_1101:
  %t1102 = getelementptr i8, ptr %t1098, i64 %t1097
  store i8 %t1096, ptr %t1102, align 1
  br label %edge_19
b14:
  %p_14_0 = phi %hia.buffer [ %p_11_0, %edge_16 ], [ %p_13_0, %edge_19 ]
  %p_14_1 = phi %hia.buffer [ %p_11_1, %edge_16 ], [ %p_13_1, %edge_19 ]
  %p_14_2 = phi i64 [ %p_11_2, %edge_16 ], [ %p_13_2, %edge_19 ]
  %p_14_3 = phi i64 [ %p_11_3, %edge_16 ], [ %p_13_3, %edge_19 ]
  %p_14_4 = phi i64 [ %p_11_4, %edge_16 ], [ %t901, %edge_19 ]
  %p_14_5 = phi i64 [ %p_11_5, %edge_16 ], [ %t902, %edge_19 ]
  %p_14_6 = phi i64 [ %p_11_6, %edge_16 ], [ %p_13_6, %edge_19 ]
  %p_14_7 = phi i64 [ %p_11_7, %edge_16 ], [ %p_13_7, %edge_19 ]
  %p_14_8 = phi i32 [ %p_11_8, %edge_16 ], [ %p_13_8, %edge_19 ]
  %p_14_9 = phi i32 [ %p_11_9, %edge_16 ], [ %p_13_9, %edge_19 ]
  %t1103 = icmp uge i64 %p_14_4, 4
  br i1 %t1103, label %edge_20, label %edge_21
b15:
  %p_15_0 = phi %hia.buffer [ %p_14_0, %edge_20 ]
  %p_15_1 = phi %hia.buffer [ %p_14_1, %edge_20 ]
  %p_15_2 = phi i64 [ %p_14_2, %edge_20 ]
  %p_15_3 = phi i64 [ %p_14_3, %edge_20 ]
  %p_15_4 = phi i64 [ %p_14_4, %edge_20 ]
  %p_15_5 = phi i64 [ %p_14_5, %edge_20 ]
  %p_15_6 = phi i64 [ %p_14_6, %edge_20 ]
  %p_15_7 = phi i64 [ %p_14_7, %edge_20 ]
  %p_15_8 = phi i32 [ %p_14_8, %edge_20 ]
  %p_15_9 = phi i32 [ %p_14_9, %edge_20 ]
  %t1104 = sub i64 %p_15_4, 4
  %t1105 = add i64 %p_15_5, 4
  %t1106 = icmp ult i64 24, 64
  br i1 %t1106, label %ok_1107, label %trap_1107
trap_1107:
  call void @abort()
  unreachable
ok_1107:
  %t1108 = lshr i64 %p_15_2, 24
  %t1109 = trunc i64 %t1108 to i8
  %t1110 = add i64 %t1104, 0
  %t1111 = extractvalue %hia.buffer %p_15_0, 0
  %t1112 = extractvalue %hia.buffer %p_15_0, 1
  %t1113 = icmp ult i64 %t1110, %t1112
  br i1 %t1113, label %ok_1114, label %trap_1114
trap_1114:
  call void @abort()
  unreachable
ok_1114:
  %t1115 = getelementptr i8, ptr %t1111, i64 %t1110
  store i8 %t1109, ptr %t1115, align 1
  %t1116 = icmp ult i64 16, 64
  br i1 %t1116, label %ok_1117, label %trap_1117
trap_1117:
  call void @abort()
  unreachable
ok_1117:
  %t1118 = lshr i64 %p_15_2, 16
  %t1119 = trunc i64 %t1118 to i8
  %t1120 = add i64 %t1104, 1
  %t1121 = extractvalue %hia.buffer %p_15_0, 0
  %t1122 = extractvalue %hia.buffer %p_15_0, 1
  %t1123 = icmp ult i64 %t1120, %t1122
  br i1 %t1123, label %ok_1124, label %trap_1124
trap_1124:
  call void @abort()
  unreachable
ok_1124:
  %t1125 = getelementptr i8, ptr %t1121, i64 %t1120
  store i8 %t1119, ptr %t1125, align 1
  %t1126 = icmp ult i64 8, 64
  br i1 %t1126, label %ok_1127, label %trap_1127
trap_1127:
  call void @abort()
  unreachable
ok_1127:
  %t1128 = lshr i64 %p_15_2, 8
  %t1129 = trunc i64 %t1128 to i8
  %t1130 = add i64 %t1104, 2
  %t1131 = extractvalue %hia.buffer %p_15_0, 0
  %t1132 = extractvalue %hia.buffer %p_15_0, 1
  %t1133 = icmp ult i64 %t1130, %t1132
  br i1 %t1133, label %ok_1134, label %trap_1134
trap_1134:
  call void @abort()
  unreachable
ok_1134:
  %t1135 = getelementptr i8, ptr %t1131, i64 %t1130
  store i8 %t1129, ptr %t1135, align 1
  %t1136 = icmp ult i64 0, 64
  br i1 %t1136, label %ok_1137, label %trap_1137
trap_1137:
  call void @abort()
  unreachable
ok_1137:
  %t1138 = lshr i64 %p_15_2, 0
  %t1139 = trunc i64 %t1138 to i8
  %t1140 = add i64 %t1104, 3
  %t1141 = extractvalue %hia.buffer %p_15_0, 0
  %t1142 = extractvalue %hia.buffer %p_15_0, 1
  %t1143 = icmp ult i64 %t1140, %t1142
  br i1 %t1143, label %ok_1144, label %trap_1144
trap_1144:
  call void @abort()
  unreachable
ok_1144:
  %t1145 = getelementptr i8, ptr %t1141, i64 %t1140
  store i8 %t1139, ptr %t1145, align 1
  %t1146 = icmp ult i64 0, 64
  br i1 %t1146, label %ok_1147, label %trap_1147
trap_1147:
  call void @abort()
  unreachable
ok_1147:
  %t1148 = lshr i64 %t1104, 0
  %t1149 = trunc i64 %t1148 to i8
  %t1150 = add i64 16, 0
  %t1151 = extractvalue %hia.buffer %p_15_1, 0
  %t1152 = extractvalue %hia.buffer %p_15_1, 1
  %t1153 = icmp ult i64 %t1150, %t1152
  br i1 %t1153, label %ok_1154, label %trap_1154
trap_1154:
  call void @abort()
  unreachable
ok_1154:
  %t1155 = getelementptr i8, ptr %t1151, i64 %t1150
  store i8 %t1149, ptr %t1155, align 1
  %t1156 = icmp ult i64 8, 64
  br i1 %t1156, label %ok_1157, label %trap_1157
trap_1157:
  call void @abort()
  unreachable
ok_1157:
  %t1158 = lshr i64 %t1104, 8
  %t1159 = trunc i64 %t1158 to i8
  %t1160 = add i64 16, 1
  %t1161 = extractvalue %hia.buffer %p_15_1, 0
  %t1162 = extractvalue %hia.buffer %p_15_1, 1
  %t1163 = icmp ult i64 %t1160, %t1162
  br i1 %t1163, label %ok_1164, label %trap_1164
trap_1164:
  call void @abort()
  unreachable
ok_1164:
  %t1165 = getelementptr i8, ptr %t1161, i64 %t1160
  store i8 %t1159, ptr %t1165, align 1
  %t1166 = icmp ult i64 16, 64
  br i1 %t1166, label %ok_1167, label %trap_1167
trap_1167:
  call void @abort()
  unreachable
ok_1167:
  %t1168 = lshr i64 %t1104, 16
  %t1169 = trunc i64 %t1168 to i8
  %t1170 = add i64 16, 2
  %t1171 = extractvalue %hia.buffer %p_15_1, 0
  %t1172 = extractvalue %hia.buffer %p_15_1, 1
  %t1173 = icmp ult i64 %t1170, %t1172
  br i1 %t1173, label %ok_1174, label %trap_1174
trap_1174:
  call void @abort()
  unreachable
ok_1174:
  %t1175 = getelementptr i8, ptr %t1171, i64 %t1170
  store i8 %t1169, ptr %t1175, align 1
  %t1176 = icmp ult i64 24, 64
  br i1 %t1176, label %ok_1177, label %trap_1177
trap_1177:
  call void @abort()
  unreachable
ok_1177:
  %t1178 = lshr i64 %t1104, 24
  %t1179 = trunc i64 %t1178 to i8
  %t1180 = add i64 16, 3
  %t1181 = extractvalue %hia.buffer %p_15_1, 0
  %t1182 = extractvalue %hia.buffer %p_15_1, 1
  %t1183 = icmp ult i64 %t1180, %t1182
  br i1 %t1183, label %ok_1184, label %trap_1184
trap_1184:
  call void @abort()
  unreachable
ok_1184:
  %t1185 = getelementptr i8, ptr %t1181, i64 %t1180
  store i8 %t1179, ptr %t1185, align 1
  %t1186 = icmp ult i64 32, 64
  br i1 %t1186, label %ok_1187, label %trap_1187
trap_1187:
  call void @abort()
  unreachable
ok_1187:
  %t1188 = lshr i64 %t1104, 32
  %t1189 = trunc i64 %t1188 to i8
  %t1190 = add i64 16, 4
  %t1191 = extractvalue %hia.buffer %p_15_1, 0
  %t1192 = extractvalue %hia.buffer %p_15_1, 1
  %t1193 = icmp ult i64 %t1190, %t1192
  br i1 %t1193, label %ok_1194, label %trap_1194
trap_1194:
  call void @abort()
  unreachable
ok_1194:
  %t1195 = getelementptr i8, ptr %t1191, i64 %t1190
  store i8 %t1189, ptr %t1195, align 1
  %t1196 = icmp ult i64 40, 64
  br i1 %t1196, label %ok_1197, label %trap_1197
trap_1197:
  call void @abort()
  unreachable
ok_1197:
  %t1198 = lshr i64 %t1104, 40
  %t1199 = trunc i64 %t1198 to i8
  %t1200 = add i64 16, 5
  %t1201 = extractvalue %hia.buffer %p_15_1, 0
  %t1202 = extractvalue %hia.buffer %p_15_1, 1
  %t1203 = icmp ult i64 %t1200, %t1202
  br i1 %t1203, label %ok_1204, label %trap_1204
trap_1204:
  call void @abort()
  unreachable
ok_1204:
  %t1205 = getelementptr i8, ptr %t1201, i64 %t1200
  store i8 %t1199, ptr %t1205, align 1
  %t1206 = icmp ult i64 48, 64
  br i1 %t1206, label %ok_1207, label %trap_1207
trap_1207:
  call void @abort()
  unreachable
ok_1207:
  %t1208 = lshr i64 %t1104, 48
  %t1209 = trunc i64 %t1208 to i8
  %t1210 = add i64 16, 6
  %t1211 = extractvalue %hia.buffer %p_15_1, 0
  %t1212 = extractvalue %hia.buffer %p_15_1, 1
  %t1213 = icmp ult i64 %t1210, %t1212
  br i1 %t1213, label %ok_1214, label %trap_1214
trap_1214:
  call void @abort()
  unreachable
ok_1214:
  %t1215 = getelementptr i8, ptr %t1211, i64 %t1210
  store i8 %t1209, ptr %t1215, align 1
  %t1216 = icmp ult i64 56, 64
  br i1 %t1216, label %ok_1217, label %trap_1217
trap_1217:
  call void @abort()
  unreachable
ok_1217:
  %t1218 = lshr i64 %t1104, 56
  %t1219 = trunc i64 %t1218 to i8
  %t1220 = add i64 16, 7
  %t1221 = extractvalue %hia.buffer %p_15_1, 0
  %t1222 = extractvalue %hia.buffer %p_15_1, 1
  %t1223 = icmp ult i64 %t1220, %t1222
  br i1 %t1223, label %ok_1224, label %trap_1224
trap_1224:
  call void @abort()
  unreachable
ok_1224:
  %t1225 = getelementptr i8, ptr %t1221, i64 %t1220
  store i8 %t1219, ptr %t1225, align 1
  %t1226 = icmp ult i64 0, 64
  br i1 %t1226, label %ok_1227, label %trap_1227
trap_1227:
  call void @abort()
  unreachable
ok_1227:
  %t1228 = lshr i64 %t1105, 0
  %t1229 = trunc i64 %t1228 to i8
  %t1230 = add i64 24, 0
  %t1231 = extractvalue %hia.buffer %p_15_1, 0
  %t1232 = extractvalue %hia.buffer %p_15_1, 1
  %t1233 = icmp ult i64 %t1230, %t1232
  br i1 %t1233, label %ok_1234, label %trap_1234
trap_1234:
  call void @abort()
  unreachable
ok_1234:
  %t1235 = getelementptr i8, ptr %t1231, i64 %t1230
  store i8 %t1229, ptr %t1235, align 1
  %t1236 = icmp ult i64 8, 64
  br i1 %t1236, label %ok_1237, label %trap_1237
trap_1237:
  call void @abort()
  unreachable
ok_1237:
  %t1238 = lshr i64 %t1105, 8
  %t1239 = trunc i64 %t1238 to i8
  %t1240 = add i64 24, 1
  %t1241 = extractvalue %hia.buffer %p_15_1, 0
  %t1242 = extractvalue %hia.buffer %p_15_1, 1
  %t1243 = icmp ult i64 %t1240, %t1242
  br i1 %t1243, label %ok_1244, label %trap_1244
trap_1244:
  call void @abort()
  unreachable
ok_1244:
  %t1245 = getelementptr i8, ptr %t1241, i64 %t1240
  store i8 %t1239, ptr %t1245, align 1
  %t1246 = icmp ult i64 16, 64
  br i1 %t1246, label %ok_1247, label %trap_1247
trap_1247:
  call void @abort()
  unreachable
ok_1247:
  %t1248 = lshr i64 %t1105, 16
  %t1249 = trunc i64 %t1248 to i8
  %t1250 = add i64 24, 2
  %t1251 = extractvalue %hia.buffer %p_15_1, 0
  %t1252 = extractvalue %hia.buffer %p_15_1, 1
  %t1253 = icmp ult i64 %t1250, %t1252
  br i1 %t1253, label %ok_1254, label %trap_1254
trap_1254:
  call void @abort()
  unreachable
ok_1254:
  %t1255 = getelementptr i8, ptr %t1251, i64 %t1250
  store i8 %t1249, ptr %t1255, align 1
  %t1256 = icmp ult i64 24, 64
  br i1 %t1256, label %ok_1257, label %trap_1257
trap_1257:
  call void @abort()
  unreachable
ok_1257:
  %t1258 = lshr i64 %t1105, 24
  %t1259 = trunc i64 %t1258 to i8
  %t1260 = add i64 24, 3
  %t1261 = extractvalue %hia.buffer %p_15_1, 0
  %t1262 = extractvalue %hia.buffer %p_15_1, 1
  %t1263 = icmp ult i64 %t1260, %t1262
  br i1 %t1263, label %ok_1264, label %trap_1264
trap_1264:
  call void @abort()
  unreachable
ok_1264:
  %t1265 = getelementptr i8, ptr %t1261, i64 %t1260
  store i8 %t1259, ptr %t1265, align 1
  %t1266 = icmp ult i64 32, 64
  br i1 %t1266, label %ok_1267, label %trap_1267
trap_1267:
  call void @abort()
  unreachable
ok_1267:
  %t1268 = lshr i64 %t1105, 32
  %t1269 = trunc i64 %t1268 to i8
  %t1270 = add i64 24, 4
  %t1271 = extractvalue %hia.buffer %p_15_1, 0
  %t1272 = extractvalue %hia.buffer %p_15_1, 1
  %t1273 = icmp ult i64 %t1270, %t1272
  br i1 %t1273, label %ok_1274, label %trap_1274
trap_1274:
  call void @abort()
  unreachable
ok_1274:
  %t1275 = getelementptr i8, ptr %t1271, i64 %t1270
  store i8 %t1269, ptr %t1275, align 1
  %t1276 = icmp ult i64 40, 64
  br i1 %t1276, label %ok_1277, label %trap_1277
trap_1277:
  call void @abort()
  unreachable
ok_1277:
  %t1278 = lshr i64 %t1105, 40
  %t1279 = trunc i64 %t1278 to i8
  %t1280 = add i64 24, 5
  %t1281 = extractvalue %hia.buffer %p_15_1, 0
  %t1282 = extractvalue %hia.buffer %p_15_1, 1
  %t1283 = icmp ult i64 %t1280, %t1282
  br i1 %t1283, label %ok_1284, label %trap_1284
trap_1284:
  call void @abort()
  unreachable
ok_1284:
  %t1285 = getelementptr i8, ptr %t1281, i64 %t1280
  store i8 %t1279, ptr %t1285, align 1
  %t1286 = icmp ult i64 48, 64
  br i1 %t1286, label %ok_1287, label %trap_1287
trap_1287:
  call void @abort()
  unreachable
ok_1287:
  %t1288 = lshr i64 %t1105, 48
  %t1289 = trunc i64 %t1288 to i8
  %t1290 = add i64 24, 6
  %t1291 = extractvalue %hia.buffer %p_15_1, 0
  %t1292 = extractvalue %hia.buffer %p_15_1, 1
  %t1293 = icmp ult i64 %t1290, %t1292
  br i1 %t1293, label %ok_1294, label %trap_1294
trap_1294:
  call void @abort()
  unreachable
ok_1294:
  %t1295 = getelementptr i8, ptr %t1291, i64 %t1290
  store i8 %t1289, ptr %t1295, align 1
  %t1296 = icmp ult i64 56, 64
  br i1 %t1296, label %ok_1297, label %trap_1297
trap_1297:
  call void @abort()
  unreachable
ok_1297:
  %t1298 = lshr i64 %t1105, 56
  %t1299 = trunc i64 %t1298 to i8
  %t1300 = add i64 24, 7
  %t1301 = extractvalue %hia.buffer %p_15_1, 0
  %t1302 = extractvalue %hia.buffer %p_15_1, 1
  %t1303 = icmp ult i64 %t1300, %t1302
  br i1 %t1303, label %ok_1304, label %trap_1304
trap_1304:
  call void @abort()
  unreachable
ok_1304:
  %t1305 = getelementptr i8, ptr %t1301, i64 %t1300
  store i8 %t1299, ptr %t1305, align 1
  br label %edge_22
edge_0:
  br label %b1
edge_1:
  br label %b2
edge_2:
  br label %b5
edge_3:
  br label %b2
edge_4:
  br label %b6
edge_5:
  br label %b3
edge_6:
  br label %b11
edge_7:
  br label %b7
edge_8:
  br label %b8
edge_9:
  br label %b3
edge_10:
  br label %b9
edge_11:
  br label %b4
edge_12:
  br label %b10
edge_13:
  br label %b3
edge_14:
  br label %b4
edge_15:
  br label %b12
edge_16:
  br label %b14
edge_17:
  br label %b13
edge_18:
  br label %b3
edge_19:
  br label %b14
edge_20:
  br label %b15
edge_21:
  br label %b3
edge_22:
  br label %b4
}

define internal i32 @__hia_fn_2(%hia.buffer %p_0_0, %hia.buffer %p_0_1) {
b0:
  %t1 = extractvalue %hia.buffer %p_0_1, 1
  %t2 = icmp eq i64 %t1, 32
  br i1 %t2, label %edge_0, label %edge_1
b1:
  %p_1_0 = phi %hia.buffer [ %p_0_0, %edge_0 ]
  %p_1_1 = phi %hia.buffer [ %p_0_1, %edge_0 ]
  %t3 = add i64 0, 0
  %t4 = extractvalue %hia.buffer %p_1_1, 0
  %t5 = extractvalue %hia.buffer %p_1_1, 1
  %t6 = icmp ult i64 %t3, %t5
  br i1 %t6, label %ok_7, label %trap_7
trap_7:
  call void @abort()
  unreachable
ok_7:
  %t8 = getelementptr i8, ptr %t4, i64 %t3
  %t9 = load i8, ptr %t8, align 1
  %t10 = zext i8 %t9 to i64
  %t11 = icmp ult i64 0, 64
  br i1 %t11, label %ok_12, label %trap_12
trap_12:
  call void @abort()
  unreachable
ok_12:
  %t13 = shl i64 %t10, 0
  %t14 = or i64 0, %t13
  %t15 = add i64 0, 1
  %t16 = extractvalue %hia.buffer %p_1_1, 0
  %t17 = extractvalue %hia.buffer %p_1_1, 1
  %t18 = icmp ult i64 %t15, %t17
  br i1 %t18, label %ok_19, label %trap_19
trap_19:
  call void @abort()
  unreachable
ok_19:
  %t20 = getelementptr i8, ptr %t16, i64 %t15
  %t21 = load i8, ptr %t20, align 1
  %t22 = zext i8 %t21 to i64
  %t23 = icmp ult i64 8, 64
  br i1 %t23, label %ok_24, label %trap_24
trap_24:
  call void @abort()
  unreachable
ok_24:
  %t25 = shl i64 %t22, 8
  %t26 = or i64 %t14, %t25
  %t27 = add i64 0, 2
  %t28 = extractvalue %hia.buffer %p_1_1, 0
  %t29 = extractvalue %hia.buffer %p_1_1, 1
  %t30 = icmp ult i64 %t27, %t29
  br i1 %t30, label %ok_31, label %trap_31
trap_31:
  call void @abort()
  unreachable
ok_31:
  %t32 = getelementptr i8, ptr %t28, i64 %t27
  %t33 = load i8, ptr %t32, align 1
  %t34 = zext i8 %t33 to i64
  %t35 = icmp ult i64 16, 64
  br i1 %t35, label %ok_36, label %trap_36
trap_36:
  call void @abort()
  unreachable
ok_36:
  %t37 = shl i64 %t34, 16
  %t38 = or i64 %t26, %t37
  %t39 = add i64 0, 3
  %t40 = extractvalue %hia.buffer %p_1_1, 0
  %t41 = extractvalue %hia.buffer %p_1_1, 1
  %t42 = icmp ult i64 %t39, %t41
  br i1 %t42, label %ok_43, label %trap_43
trap_43:
  call void @abort()
  unreachable
ok_43:
  %t44 = getelementptr i8, ptr %t40, i64 %t39
  %t45 = load i8, ptr %t44, align 1
  %t46 = zext i8 %t45 to i64
  %t47 = icmp ult i64 24, 64
  br i1 %t47, label %ok_48, label %trap_48
trap_48:
  call void @abort()
  unreachable
ok_48:
  %t49 = shl i64 %t46, 24
  %t50 = or i64 %t38, %t49
  %t51 = add i64 0, 4
  %t52 = extractvalue %hia.buffer %p_1_1, 0
  %t53 = extractvalue %hia.buffer %p_1_1, 1
  %t54 = icmp ult i64 %t51, %t53
  br i1 %t54, label %ok_55, label %trap_55
trap_55:
  call void @abort()
  unreachable
ok_55:
  %t56 = getelementptr i8, ptr %t52, i64 %t51
  %t57 = load i8, ptr %t56, align 1
  %t58 = zext i8 %t57 to i64
  %t59 = icmp ult i64 32, 64
  br i1 %t59, label %ok_60, label %trap_60
trap_60:
  call void @abort()
  unreachable
ok_60:
  %t61 = shl i64 %t58, 32
  %t62 = or i64 %t50, %t61
  %t63 = add i64 0, 5
  %t64 = extractvalue %hia.buffer %p_1_1, 0
  %t65 = extractvalue %hia.buffer %p_1_1, 1
  %t66 = icmp ult i64 %t63, %t65
  br i1 %t66, label %ok_67, label %trap_67
trap_67:
  call void @abort()
  unreachable
ok_67:
  %t68 = getelementptr i8, ptr %t64, i64 %t63
  %t69 = load i8, ptr %t68, align 1
  %t70 = zext i8 %t69 to i64
  %t71 = icmp ult i64 40, 64
  br i1 %t71, label %ok_72, label %trap_72
trap_72:
  call void @abort()
  unreachable
ok_72:
  %t73 = shl i64 %t70, 40
  %t74 = or i64 %t62, %t73
  %t75 = add i64 0, 6
  %t76 = extractvalue %hia.buffer %p_1_1, 0
  %t77 = extractvalue %hia.buffer %p_1_1, 1
  %t78 = icmp ult i64 %t75, %t77
  br i1 %t78, label %ok_79, label %trap_79
trap_79:
  call void @abort()
  unreachable
ok_79:
  %t80 = getelementptr i8, ptr %t76, i64 %t75
  %t81 = load i8, ptr %t80, align 1
  %t82 = zext i8 %t81 to i64
  %t83 = icmp ult i64 48, 64
  br i1 %t83, label %ok_84, label %trap_84
trap_84:
  call void @abort()
  unreachable
ok_84:
  %t85 = shl i64 %t82, 48
  %t86 = or i64 %t74, %t85
  %t87 = add i64 0, 7
  %t88 = extractvalue %hia.buffer %p_1_1, 0
  %t89 = extractvalue %hia.buffer %p_1_1, 1
  %t90 = icmp ult i64 %t87, %t89
  br i1 %t90, label %ok_91, label %trap_91
trap_91:
  call void @abort()
  unreachable
ok_91:
  %t92 = getelementptr i8, ptr %t88, i64 %t87
  %t93 = load i8, ptr %t92, align 1
  %t94 = zext i8 %t93 to i64
  %t95 = icmp ult i64 56, 64
  br i1 %t95, label %ok_96, label %trap_96
trap_96:
  call void @abort()
  unreachable
ok_96:
  %t97 = shl i64 %t94, 56
  %t98 = or i64 %t86, %t97
  %t99 = add i64 8, 0
  %t100 = extractvalue %hia.buffer %p_1_1, 0
  %t101 = extractvalue %hia.buffer %p_1_1, 1
  %t102 = icmp ult i64 %t99, %t101
  br i1 %t102, label %ok_103, label %trap_103
trap_103:
  call void @abort()
  unreachable
ok_103:
  %t104 = getelementptr i8, ptr %t100, i64 %t99
  %t105 = load i8, ptr %t104, align 1
  %t106 = zext i8 %t105 to i64
  %t107 = icmp ult i64 0, 64
  br i1 %t107, label %ok_108, label %trap_108
trap_108:
  call void @abort()
  unreachable
ok_108:
  %t109 = shl i64 %t106, 0
  %t110 = or i64 0, %t109
  %t111 = add i64 8, 1
  %t112 = extractvalue %hia.buffer %p_1_1, 0
  %t113 = extractvalue %hia.buffer %p_1_1, 1
  %t114 = icmp ult i64 %t111, %t113
  br i1 %t114, label %ok_115, label %trap_115
trap_115:
  call void @abort()
  unreachable
ok_115:
  %t116 = getelementptr i8, ptr %t112, i64 %t111
  %t117 = load i8, ptr %t116, align 1
  %t118 = zext i8 %t117 to i64
  %t119 = icmp ult i64 8, 64
  br i1 %t119, label %ok_120, label %trap_120
trap_120:
  call void @abort()
  unreachable
ok_120:
  %t121 = shl i64 %t118, 8
  %t122 = or i64 %t110, %t121
  %t123 = add i64 8, 2
  %t124 = extractvalue %hia.buffer %p_1_1, 0
  %t125 = extractvalue %hia.buffer %p_1_1, 1
  %t126 = icmp ult i64 %t123, %t125
  br i1 %t126, label %ok_127, label %trap_127
trap_127:
  call void @abort()
  unreachable
ok_127:
  %t128 = getelementptr i8, ptr %t124, i64 %t123
  %t129 = load i8, ptr %t128, align 1
  %t130 = zext i8 %t129 to i64
  %t131 = icmp ult i64 16, 64
  br i1 %t131, label %ok_132, label %trap_132
trap_132:
  call void @abort()
  unreachable
ok_132:
  %t133 = shl i64 %t130, 16
  %t134 = or i64 %t122, %t133
  %t135 = add i64 8, 3
  %t136 = extractvalue %hia.buffer %p_1_1, 0
  %t137 = extractvalue %hia.buffer %p_1_1, 1
  %t138 = icmp ult i64 %t135, %t137
  br i1 %t138, label %ok_139, label %trap_139
trap_139:
  call void @abort()
  unreachable
ok_139:
  %t140 = getelementptr i8, ptr %t136, i64 %t135
  %t141 = load i8, ptr %t140, align 1
  %t142 = zext i8 %t141 to i64
  %t143 = icmp ult i64 24, 64
  br i1 %t143, label %ok_144, label %trap_144
trap_144:
  call void @abort()
  unreachable
ok_144:
  %t145 = shl i64 %t142, 24
  %t146 = or i64 %t134, %t145
  %t147 = add i64 8, 4
  %t148 = extractvalue %hia.buffer %p_1_1, 0
  %t149 = extractvalue %hia.buffer %p_1_1, 1
  %t150 = icmp ult i64 %t147, %t149
  br i1 %t150, label %ok_151, label %trap_151
trap_151:
  call void @abort()
  unreachable
ok_151:
  %t152 = getelementptr i8, ptr %t148, i64 %t147
  %t153 = load i8, ptr %t152, align 1
  %t154 = zext i8 %t153 to i64
  %t155 = icmp ult i64 32, 64
  br i1 %t155, label %ok_156, label %trap_156
trap_156:
  call void @abort()
  unreachable
ok_156:
  %t157 = shl i64 %t154, 32
  %t158 = or i64 %t146, %t157
  %t159 = add i64 8, 5
  %t160 = extractvalue %hia.buffer %p_1_1, 0
  %t161 = extractvalue %hia.buffer %p_1_1, 1
  %t162 = icmp ult i64 %t159, %t161
  br i1 %t162, label %ok_163, label %trap_163
trap_163:
  call void @abort()
  unreachable
ok_163:
  %t164 = getelementptr i8, ptr %t160, i64 %t159
  %t165 = load i8, ptr %t164, align 1
  %t166 = zext i8 %t165 to i64
  %t167 = icmp ult i64 40, 64
  br i1 %t167, label %ok_168, label %trap_168
trap_168:
  call void @abort()
  unreachable
ok_168:
  %t169 = shl i64 %t166, 40
  %t170 = or i64 %t158, %t169
  %t171 = add i64 8, 6
  %t172 = extractvalue %hia.buffer %p_1_1, 0
  %t173 = extractvalue %hia.buffer %p_1_1, 1
  %t174 = icmp ult i64 %t171, %t173
  br i1 %t174, label %ok_175, label %trap_175
trap_175:
  call void @abort()
  unreachable
ok_175:
  %t176 = getelementptr i8, ptr %t172, i64 %t171
  %t177 = load i8, ptr %t176, align 1
  %t178 = zext i8 %t177 to i64
  %t179 = icmp ult i64 48, 64
  br i1 %t179, label %ok_180, label %trap_180
trap_180:
  call void @abort()
  unreachable
ok_180:
  %t181 = shl i64 %t178, 48
  %t182 = or i64 %t170, %t181
  %t183 = add i64 8, 7
  %t184 = extractvalue %hia.buffer %p_1_1, 0
  %t185 = extractvalue %hia.buffer %p_1_1, 1
  %t186 = icmp ult i64 %t183, %t185
  br i1 %t186, label %ok_187, label %trap_187
trap_187:
  call void @abort()
  unreachable
ok_187:
  %t188 = getelementptr i8, ptr %t184, i64 %t183
  %t189 = load i8, ptr %t188, align 1
  %t190 = zext i8 %t189 to i64
  %t191 = icmp ult i64 56, 64
  br i1 %t191, label %ok_192, label %trap_192
trap_192:
  call void @abort()
  unreachable
ok_192:
  %t193 = shl i64 %t190, 56
  %t194 = or i64 %t182, %t193
  %t195 = add i64 16, 0
  %t196 = extractvalue %hia.buffer %p_1_1, 0
  %t197 = extractvalue %hia.buffer %p_1_1, 1
  %t198 = icmp ult i64 %t195, %t197
  br i1 %t198, label %ok_199, label %trap_199
trap_199:
  call void @abort()
  unreachable
ok_199:
  %t200 = getelementptr i8, ptr %t196, i64 %t195
  %t201 = load i8, ptr %t200, align 1
  %t202 = zext i8 %t201 to i64
  %t203 = icmp ult i64 0, 64
  br i1 %t203, label %ok_204, label %trap_204
trap_204:
  call void @abort()
  unreachable
ok_204:
  %t205 = shl i64 %t202, 0
  %t206 = or i64 0, %t205
  %t207 = add i64 16, 1
  %t208 = extractvalue %hia.buffer %p_1_1, 0
  %t209 = extractvalue %hia.buffer %p_1_1, 1
  %t210 = icmp ult i64 %t207, %t209
  br i1 %t210, label %ok_211, label %trap_211
trap_211:
  call void @abort()
  unreachable
ok_211:
  %t212 = getelementptr i8, ptr %t208, i64 %t207
  %t213 = load i8, ptr %t212, align 1
  %t214 = zext i8 %t213 to i64
  %t215 = icmp ult i64 8, 64
  br i1 %t215, label %ok_216, label %trap_216
trap_216:
  call void @abort()
  unreachable
ok_216:
  %t217 = shl i64 %t214, 8
  %t218 = or i64 %t206, %t217
  %t219 = add i64 16, 2
  %t220 = extractvalue %hia.buffer %p_1_1, 0
  %t221 = extractvalue %hia.buffer %p_1_1, 1
  %t222 = icmp ult i64 %t219, %t221
  br i1 %t222, label %ok_223, label %trap_223
trap_223:
  call void @abort()
  unreachable
ok_223:
  %t224 = getelementptr i8, ptr %t220, i64 %t219
  %t225 = load i8, ptr %t224, align 1
  %t226 = zext i8 %t225 to i64
  %t227 = icmp ult i64 16, 64
  br i1 %t227, label %ok_228, label %trap_228
trap_228:
  call void @abort()
  unreachable
ok_228:
  %t229 = shl i64 %t226, 16
  %t230 = or i64 %t218, %t229
  %t231 = add i64 16, 3
  %t232 = extractvalue %hia.buffer %p_1_1, 0
  %t233 = extractvalue %hia.buffer %p_1_1, 1
  %t234 = icmp ult i64 %t231, %t233
  br i1 %t234, label %ok_235, label %trap_235
trap_235:
  call void @abort()
  unreachable
ok_235:
  %t236 = getelementptr i8, ptr %t232, i64 %t231
  %t237 = load i8, ptr %t236, align 1
  %t238 = zext i8 %t237 to i64
  %t239 = icmp ult i64 24, 64
  br i1 %t239, label %ok_240, label %trap_240
trap_240:
  call void @abort()
  unreachable
ok_240:
  %t241 = shl i64 %t238, 24
  %t242 = or i64 %t230, %t241
  %t243 = add i64 16, 4
  %t244 = extractvalue %hia.buffer %p_1_1, 0
  %t245 = extractvalue %hia.buffer %p_1_1, 1
  %t246 = icmp ult i64 %t243, %t245
  br i1 %t246, label %ok_247, label %trap_247
trap_247:
  call void @abort()
  unreachable
ok_247:
  %t248 = getelementptr i8, ptr %t244, i64 %t243
  %t249 = load i8, ptr %t248, align 1
  %t250 = zext i8 %t249 to i64
  %t251 = icmp ult i64 32, 64
  br i1 %t251, label %ok_252, label %trap_252
trap_252:
  call void @abort()
  unreachable
ok_252:
  %t253 = shl i64 %t250, 32
  %t254 = or i64 %t242, %t253
  %t255 = add i64 16, 5
  %t256 = extractvalue %hia.buffer %p_1_1, 0
  %t257 = extractvalue %hia.buffer %p_1_1, 1
  %t258 = icmp ult i64 %t255, %t257
  br i1 %t258, label %ok_259, label %trap_259
trap_259:
  call void @abort()
  unreachable
ok_259:
  %t260 = getelementptr i8, ptr %t256, i64 %t255
  %t261 = load i8, ptr %t260, align 1
  %t262 = zext i8 %t261 to i64
  %t263 = icmp ult i64 40, 64
  br i1 %t263, label %ok_264, label %trap_264
trap_264:
  call void @abort()
  unreachable
ok_264:
  %t265 = shl i64 %t262, 40
  %t266 = or i64 %t254, %t265
  %t267 = add i64 16, 6
  %t268 = extractvalue %hia.buffer %p_1_1, 0
  %t269 = extractvalue %hia.buffer %p_1_1, 1
  %t270 = icmp ult i64 %t267, %t269
  br i1 %t270, label %ok_271, label %trap_271
trap_271:
  call void @abort()
  unreachable
ok_271:
  %t272 = getelementptr i8, ptr %t268, i64 %t267
  %t273 = load i8, ptr %t272, align 1
  %t274 = zext i8 %t273 to i64
  %t275 = icmp ult i64 48, 64
  br i1 %t275, label %ok_276, label %trap_276
trap_276:
  call void @abort()
  unreachable
ok_276:
  %t277 = shl i64 %t274, 48
  %t278 = or i64 %t266, %t277
  %t279 = add i64 16, 7
  %t280 = extractvalue %hia.buffer %p_1_1, 0
  %t281 = extractvalue %hia.buffer %p_1_1, 1
  %t282 = icmp ult i64 %t279, %t281
  br i1 %t282, label %ok_283, label %trap_283
trap_283:
  call void @abort()
  unreachable
ok_283:
  %t284 = getelementptr i8, ptr %t280, i64 %t279
  %t285 = load i8, ptr %t284, align 1
  %t286 = zext i8 %t285 to i64
  %t287 = icmp ult i64 56, 64
  br i1 %t287, label %ok_288, label %trap_288
trap_288:
  call void @abort()
  unreachable
ok_288:
  %t289 = shl i64 %t286, 56
  %t290 = or i64 %t278, %t289
  %t291 = add i64 24, 0
  %t292 = extractvalue %hia.buffer %p_1_1, 0
  %t293 = extractvalue %hia.buffer %p_1_1, 1
  %t294 = icmp ult i64 %t291, %t293
  br i1 %t294, label %ok_295, label %trap_295
trap_295:
  call void @abort()
  unreachable
ok_295:
  %t296 = getelementptr i8, ptr %t292, i64 %t291
  %t297 = load i8, ptr %t296, align 1
  %t298 = zext i8 %t297 to i64
  %t299 = icmp ult i64 0, 64
  br i1 %t299, label %ok_300, label %trap_300
trap_300:
  call void @abort()
  unreachable
ok_300:
  %t301 = shl i64 %t298, 0
  %t302 = or i64 0, %t301
  %t303 = add i64 24, 1
  %t304 = extractvalue %hia.buffer %p_1_1, 0
  %t305 = extractvalue %hia.buffer %p_1_1, 1
  %t306 = icmp ult i64 %t303, %t305
  br i1 %t306, label %ok_307, label %trap_307
trap_307:
  call void @abort()
  unreachable
ok_307:
  %t308 = getelementptr i8, ptr %t304, i64 %t303
  %t309 = load i8, ptr %t308, align 1
  %t310 = zext i8 %t309 to i64
  %t311 = icmp ult i64 8, 64
  br i1 %t311, label %ok_312, label %trap_312
trap_312:
  call void @abort()
  unreachable
ok_312:
  %t313 = shl i64 %t310, 8
  %t314 = or i64 %t302, %t313
  %t315 = add i64 24, 2
  %t316 = extractvalue %hia.buffer %p_1_1, 0
  %t317 = extractvalue %hia.buffer %p_1_1, 1
  %t318 = icmp ult i64 %t315, %t317
  br i1 %t318, label %ok_319, label %trap_319
trap_319:
  call void @abort()
  unreachable
ok_319:
  %t320 = getelementptr i8, ptr %t316, i64 %t315
  %t321 = load i8, ptr %t320, align 1
  %t322 = zext i8 %t321 to i64
  %t323 = icmp ult i64 16, 64
  br i1 %t323, label %ok_324, label %trap_324
trap_324:
  call void @abort()
  unreachable
ok_324:
  %t325 = shl i64 %t322, 16
  %t326 = or i64 %t314, %t325
  %t327 = add i64 24, 3
  %t328 = extractvalue %hia.buffer %p_1_1, 0
  %t329 = extractvalue %hia.buffer %p_1_1, 1
  %t330 = icmp ult i64 %t327, %t329
  br i1 %t330, label %ok_331, label %trap_331
trap_331:
  call void @abort()
  unreachable
ok_331:
  %t332 = getelementptr i8, ptr %t328, i64 %t327
  %t333 = load i8, ptr %t332, align 1
  %t334 = zext i8 %t333 to i64
  %t335 = icmp ult i64 24, 64
  br i1 %t335, label %ok_336, label %trap_336
trap_336:
  call void @abort()
  unreachable
ok_336:
  %t337 = shl i64 %t334, 24
  %t338 = or i64 %t326, %t337
  %t339 = add i64 24, 4
  %t340 = extractvalue %hia.buffer %p_1_1, 0
  %t341 = extractvalue %hia.buffer %p_1_1, 1
  %t342 = icmp ult i64 %t339, %t341
  br i1 %t342, label %ok_343, label %trap_343
trap_343:
  call void @abort()
  unreachable
ok_343:
  %t344 = getelementptr i8, ptr %t340, i64 %t339
  %t345 = load i8, ptr %t344, align 1
  %t346 = zext i8 %t345 to i64
  %t347 = icmp ult i64 32, 64
  br i1 %t347, label %ok_348, label %trap_348
trap_348:
  call void @abort()
  unreachable
ok_348:
  %t349 = shl i64 %t346, 32
  %t350 = or i64 %t338, %t349
  %t351 = add i64 24, 5
  %t352 = extractvalue %hia.buffer %p_1_1, 0
  %t353 = extractvalue %hia.buffer %p_1_1, 1
  %t354 = icmp ult i64 %t351, %t353
  br i1 %t354, label %ok_355, label %trap_355
trap_355:
  call void @abort()
  unreachable
ok_355:
  %t356 = getelementptr i8, ptr %t352, i64 %t351
  %t357 = load i8, ptr %t356, align 1
  %t358 = zext i8 %t357 to i64
  %t359 = icmp ult i64 40, 64
  br i1 %t359, label %ok_360, label %trap_360
trap_360:
  call void @abort()
  unreachable
ok_360:
  %t361 = shl i64 %t358, 40
  %t362 = or i64 %t350, %t361
  %t363 = add i64 24, 6
  %t364 = extractvalue %hia.buffer %p_1_1, 0
  %t365 = extractvalue %hia.buffer %p_1_1, 1
  %t366 = icmp ult i64 %t363, %t365
  br i1 %t366, label %ok_367, label %trap_367
trap_367:
  call void @abort()
  unreachable
ok_367:
  %t368 = getelementptr i8, ptr %t364, i64 %t363
  %t369 = load i8, ptr %t368, align 1
  %t370 = zext i8 %t369 to i64
  %t371 = icmp ult i64 48, 64
  br i1 %t371, label %ok_372, label %trap_372
trap_372:
  call void @abort()
  unreachable
ok_372:
  %t373 = shl i64 %t370, 48
  %t374 = or i64 %t362, %t373
  %t375 = add i64 24, 7
  %t376 = extractvalue %hia.buffer %p_1_1, 0
  %t377 = extractvalue %hia.buffer %p_1_1, 1
  %t378 = icmp ult i64 %t375, %t377
  br i1 %t378, label %ok_379, label %trap_379
trap_379:
  call void @abort()
  unreachable
ok_379:
  %t380 = getelementptr i8, ptr %t376, i64 %t375
  %t381 = load i8, ptr %t380, align 1
  %t382 = zext i8 %t381 to i64
  %t383 = icmp ult i64 56, 64
  br i1 %t383, label %ok_384, label %trap_384
trap_384:
  call void @abort()
  unreachable
ok_384:
  %t385 = shl i64 %t382, 56
  %t386 = or i64 %t374, %t385
  %t387 = extractvalue %hia.buffer %p_1_0, 1
  %t388 = icmp ule i64 %t290, %t387
  %t389 = sub i64 %t387, %t290
  %t390 = icmp ule i64 %t386, %t389
  %t391 = and i1 %t388, %t390
  br i1 %t391, label %edge_2, label %edge_3
b2:
  ret i32 4294836225
b3:
  ret i32 0
b4:
  %p_4_0 = phi %hia.buffer [ %p_1_0, %edge_2 ]
  %p_4_1 = phi %hia.buffer [ %p_1_1, %edge_2 ]
  %p_4_2 = phi i64 [ %t98, %edge_2 ]
  %p_4_3 = phi i64 [ %t194, %edge_2 ]
  %p_4_4 = phi i64 [ %t290, %edge_2 ]
  %p_4_5 = phi i64 [ %t386, %edge_2 ]
  %p_4_6 = phi i64 [ %t387, %edge_2 ]
  %t392 = icmp uge i64 %p_4_5, 8
  br i1 %t392, label %edge_4, label %edge_5
b5:
  %p_5_0 = phi %hia.buffer [ %p_4_0, %edge_4 ]
  %p_5_1 = phi %hia.buffer [ %p_4_1, %edge_4 ]
  %p_5_2 = phi i64 [ %p_4_2, %edge_4 ]
  %p_5_3 = phi i64 [ %p_4_3, %edge_4 ]
  %p_5_4 = phi i64 [ %p_4_4, %edge_4 ]
  %p_5_5 = phi i64 [ %p_4_5, %edge_4 ]
  %p_5_6 = phi i64 [ %p_4_6, %edge_4 ]
  %t393 = add i64 %p_5_4, 0
  %t394 = extractvalue %hia.buffer %p_5_0, 0
  %t395 = extractvalue %hia.buffer %p_5_0, 1
  %t396 = icmp ult i64 %t393, %t395
  br i1 %t396, label %ok_397, label %trap_397
trap_397:
  call void @abort()
  unreachable
ok_397:
  %t398 = getelementptr i8, ptr %t394, i64 %t393
  %t399 = load i8, ptr %t398, align 1
  %t400 = zext i8 %t399 to i64
  %t401 = icmp ult i64 56, 64
  br i1 %t401, label %ok_402, label %trap_402
trap_402:
  call void @abort()
  unreachable
ok_402:
  %t403 = shl i64 %t400, 56
  %t404 = or i64 0, %t403
  %t405 = add i64 %p_5_4, 1
  %t406 = extractvalue %hia.buffer %p_5_0, 0
  %t407 = extractvalue %hia.buffer %p_5_0, 1
  %t408 = icmp ult i64 %t405, %t407
  br i1 %t408, label %ok_409, label %trap_409
trap_409:
  call void @abort()
  unreachable
ok_409:
  %t410 = getelementptr i8, ptr %t406, i64 %t405
  %t411 = load i8, ptr %t410, align 1
  %t412 = zext i8 %t411 to i64
  %t413 = icmp ult i64 48, 64
  br i1 %t413, label %ok_414, label %trap_414
trap_414:
  call void @abort()
  unreachable
ok_414:
  %t415 = shl i64 %t412, 48
  %t416 = or i64 %t404, %t415
  %t417 = add i64 %p_5_4, 2
  %t418 = extractvalue %hia.buffer %p_5_0, 0
  %t419 = extractvalue %hia.buffer %p_5_0, 1
  %t420 = icmp ult i64 %t417, %t419
  br i1 %t420, label %ok_421, label %trap_421
trap_421:
  call void @abort()
  unreachable
ok_421:
  %t422 = getelementptr i8, ptr %t418, i64 %t417
  %t423 = load i8, ptr %t422, align 1
  %t424 = zext i8 %t423 to i64
  %t425 = icmp ult i64 40, 64
  br i1 %t425, label %ok_426, label %trap_426
trap_426:
  call void @abort()
  unreachable
ok_426:
  %t427 = shl i64 %t424, 40
  %t428 = or i64 %t416, %t427
  %t429 = add i64 %p_5_4, 3
  %t430 = extractvalue %hia.buffer %p_5_0, 0
  %t431 = extractvalue %hia.buffer %p_5_0, 1
  %t432 = icmp ult i64 %t429, %t431
  br i1 %t432, label %ok_433, label %trap_433
trap_433:
  call void @abort()
  unreachable
ok_433:
  %t434 = getelementptr i8, ptr %t430, i64 %t429
  %t435 = load i8, ptr %t434, align 1
  %t436 = zext i8 %t435 to i64
  %t437 = icmp ult i64 32, 64
  br i1 %t437, label %ok_438, label %trap_438
trap_438:
  call void @abort()
  unreachable
ok_438:
  %t439 = shl i64 %t436, 32
  %t440 = or i64 %t428, %t439
  %t441 = add i64 %p_5_4, 4
  %t442 = extractvalue %hia.buffer %p_5_0, 0
  %t443 = extractvalue %hia.buffer %p_5_0, 1
  %t444 = icmp ult i64 %t441, %t443
  br i1 %t444, label %ok_445, label %trap_445
trap_445:
  call void @abort()
  unreachable
ok_445:
  %t446 = getelementptr i8, ptr %t442, i64 %t441
  %t447 = load i8, ptr %t446, align 1
  %t448 = zext i8 %t447 to i64
  %t449 = icmp ult i64 24, 64
  br i1 %t449, label %ok_450, label %trap_450
trap_450:
  call void @abort()
  unreachable
ok_450:
  %t451 = shl i64 %t448, 24
  %t452 = or i64 %t440, %t451
  %t453 = add i64 %p_5_4, 5
  %t454 = extractvalue %hia.buffer %p_5_0, 0
  %t455 = extractvalue %hia.buffer %p_5_0, 1
  %t456 = icmp ult i64 %t453, %t455
  br i1 %t456, label %ok_457, label %trap_457
trap_457:
  call void @abort()
  unreachable
ok_457:
  %t458 = getelementptr i8, ptr %t454, i64 %t453
  %t459 = load i8, ptr %t458, align 1
  %t460 = zext i8 %t459 to i64
  %t461 = icmp ult i64 16, 64
  br i1 %t461, label %ok_462, label %trap_462
trap_462:
  call void @abort()
  unreachable
ok_462:
  %t463 = shl i64 %t460, 16
  %t464 = or i64 %t452, %t463
  %t465 = add i64 %p_5_4, 6
  %t466 = extractvalue %hia.buffer %p_5_0, 0
  %t467 = extractvalue %hia.buffer %p_5_0, 1
  %t468 = icmp ult i64 %t465, %t467
  br i1 %t468, label %ok_469, label %trap_469
trap_469:
  call void @abort()
  unreachable
ok_469:
  %t470 = getelementptr i8, ptr %t466, i64 %t465
  %t471 = load i8, ptr %t470, align 1
  %t472 = zext i8 %t471 to i64
  %t473 = icmp ult i64 8, 64
  br i1 %t473, label %ok_474, label %trap_474
trap_474:
  call void @abort()
  unreachable
ok_474:
  %t475 = shl i64 %t472, 8
  %t476 = or i64 %t464, %t475
  %t477 = add i64 %p_5_4, 7
  %t478 = extractvalue %hia.buffer %p_5_0, 0
  %t479 = extractvalue %hia.buffer %p_5_0, 1
  %t480 = icmp ult i64 %t477, %t479
  br i1 %t480, label %ok_481, label %trap_481
trap_481:
  call void @abort()
  unreachable
ok_481:
  %t482 = getelementptr i8, ptr %t478, i64 %t477
  %t483 = load i8, ptr %t482, align 1
  %t484 = zext i8 %t483 to i64
  %t485 = icmp ult i64 0, 64
  br i1 %t485, label %ok_486, label %trap_486
trap_486:
  call void @abort()
  unreachable
ok_486:
  %t487 = shl i64 %t484, 0
  %t488 = or i64 %t476, %t487
  %t489 = and i64 %t488, 281474976710655
  %t490 = icmp ult i64 0, 64
  br i1 %t490, label %ok_491, label %trap_491
trap_491:
  call void @abort()
  unreachable
ok_491:
  %t492 = lshr i64 %t489, 0
  %t493 = trunc i64 %t492 to i8
  %t494 = add i64 0, 0
  %t495 = extractvalue %hia.buffer %p_5_1, 0
  %t496 = extractvalue %hia.buffer %p_5_1, 1
  %t497 = icmp ult i64 %t494, %t496
  br i1 %t497, label %ok_498, label %trap_498
trap_498:
  call void @abort()
  unreachable
ok_498:
  %t499 = getelementptr i8, ptr %t495, i64 %t494
  store i8 %t493, ptr %t499, align 1
  %t500 = icmp ult i64 8, 64
  br i1 %t500, label %ok_501, label %trap_501
trap_501:
  call void @abort()
  unreachable
ok_501:
  %t502 = lshr i64 %t489, 8
  %t503 = trunc i64 %t502 to i8
  %t504 = add i64 0, 1
  %t505 = extractvalue %hia.buffer %p_5_1, 0
  %t506 = extractvalue %hia.buffer %p_5_1, 1
  %t507 = icmp ult i64 %t504, %t506
  br i1 %t507, label %ok_508, label %trap_508
trap_508:
  call void @abort()
  unreachable
ok_508:
  %t509 = getelementptr i8, ptr %t505, i64 %t504
  store i8 %t503, ptr %t509, align 1
  %t510 = icmp ult i64 16, 64
  br i1 %t510, label %ok_511, label %trap_511
trap_511:
  call void @abort()
  unreachable
ok_511:
  %t512 = lshr i64 %t489, 16
  %t513 = trunc i64 %t512 to i8
  %t514 = add i64 0, 2
  %t515 = extractvalue %hia.buffer %p_5_1, 0
  %t516 = extractvalue %hia.buffer %p_5_1, 1
  %t517 = icmp ult i64 %t514, %t516
  br i1 %t517, label %ok_518, label %trap_518
trap_518:
  call void @abort()
  unreachable
ok_518:
  %t519 = getelementptr i8, ptr %t515, i64 %t514
  store i8 %t513, ptr %t519, align 1
  %t520 = icmp ult i64 24, 64
  br i1 %t520, label %ok_521, label %trap_521
trap_521:
  call void @abort()
  unreachable
ok_521:
  %t522 = lshr i64 %t489, 24
  %t523 = trunc i64 %t522 to i8
  %t524 = add i64 0, 3
  %t525 = extractvalue %hia.buffer %p_5_1, 0
  %t526 = extractvalue %hia.buffer %p_5_1, 1
  %t527 = icmp ult i64 %t524, %t526
  br i1 %t527, label %ok_528, label %trap_528
trap_528:
  call void @abort()
  unreachable
ok_528:
  %t529 = getelementptr i8, ptr %t525, i64 %t524
  store i8 %t523, ptr %t529, align 1
  %t530 = icmp ult i64 32, 64
  br i1 %t530, label %ok_531, label %trap_531
trap_531:
  call void @abort()
  unreachable
ok_531:
  %t532 = lshr i64 %t489, 32
  %t533 = trunc i64 %t532 to i8
  %t534 = add i64 0, 4
  %t535 = extractvalue %hia.buffer %p_5_1, 0
  %t536 = extractvalue %hia.buffer %p_5_1, 1
  %t537 = icmp ult i64 %t534, %t536
  br i1 %t537, label %ok_538, label %trap_538
trap_538:
  call void @abort()
  unreachable
ok_538:
  %t539 = getelementptr i8, ptr %t535, i64 %t534
  store i8 %t533, ptr %t539, align 1
  %t540 = icmp ult i64 40, 64
  br i1 %t540, label %ok_541, label %trap_541
trap_541:
  call void @abort()
  unreachable
ok_541:
  %t542 = lshr i64 %t489, 40
  %t543 = trunc i64 %t542 to i8
  %t544 = add i64 0, 5
  %t545 = extractvalue %hia.buffer %p_5_1, 0
  %t546 = extractvalue %hia.buffer %p_5_1, 1
  %t547 = icmp ult i64 %t544, %t546
  br i1 %t547, label %ok_548, label %trap_548
trap_548:
  call void @abort()
  unreachable
ok_548:
  %t549 = getelementptr i8, ptr %t545, i64 %t544
  store i8 %t543, ptr %t549, align 1
  %t550 = icmp ult i64 48, 64
  br i1 %t550, label %ok_551, label %trap_551
trap_551:
  call void @abort()
  unreachable
ok_551:
  %t552 = lshr i64 %t489, 48
  %t553 = trunc i64 %t552 to i8
  %t554 = add i64 0, 6
  %t555 = extractvalue %hia.buffer %p_5_1, 0
  %t556 = extractvalue %hia.buffer %p_5_1, 1
  %t557 = icmp ult i64 %t554, %t556
  br i1 %t557, label %ok_558, label %trap_558
trap_558:
  call void @abort()
  unreachable
ok_558:
  %t559 = getelementptr i8, ptr %t555, i64 %t554
  store i8 %t553, ptr %t559, align 1
  %t560 = icmp ult i64 56, 64
  br i1 %t560, label %ok_561, label %trap_561
trap_561:
  call void @abort()
  unreachable
ok_561:
  %t562 = lshr i64 %t489, 56
  %t563 = trunc i64 %t562 to i8
  %t564 = add i64 0, 7
  %t565 = extractvalue %hia.buffer %p_5_1, 0
  %t566 = extractvalue %hia.buffer %p_5_1, 1
  %t567 = icmp ult i64 %t564, %t566
  br i1 %t567, label %ok_568, label %trap_568
trap_568:
  call void @abort()
  unreachable
ok_568:
  %t569 = getelementptr i8, ptr %t565, i64 %t564
  store i8 %t563, ptr %t569, align 1
  %t570 = add i64 %p_5_4, 8
  %t571 = sub i64 %p_5_5, 8
  %t572 = icmp ult i64 0, 64
  br i1 %t572, label %ok_573, label %trap_573
trap_573:
  call void @abort()
  unreachable
ok_573:
  %t574 = lshr i64 %t570, 0
  %t575 = trunc i64 %t574 to i8
  %t576 = add i64 16, 0
  %t577 = extractvalue %hia.buffer %p_5_1, 0
  %t578 = extractvalue %hia.buffer %p_5_1, 1
  %t579 = icmp ult i64 %t576, %t578
  br i1 %t579, label %ok_580, label %trap_580
trap_580:
  call void @abort()
  unreachable
ok_580:
  %t581 = getelementptr i8, ptr %t577, i64 %t576
  store i8 %t575, ptr %t581, align 1
  %t582 = icmp ult i64 8, 64
  br i1 %t582, label %ok_583, label %trap_583
trap_583:
  call void @abort()
  unreachable
ok_583:
  %t584 = lshr i64 %t570, 8
  %t585 = trunc i64 %t584 to i8
  %t586 = add i64 16, 1
  %t587 = extractvalue %hia.buffer %p_5_1, 0
  %t588 = extractvalue %hia.buffer %p_5_1, 1
  %t589 = icmp ult i64 %t586, %t588
  br i1 %t589, label %ok_590, label %trap_590
trap_590:
  call void @abort()
  unreachable
ok_590:
  %t591 = getelementptr i8, ptr %t587, i64 %t586
  store i8 %t585, ptr %t591, align 1
  %t592 = icmp ult i64 16, 64
  br i1 %t592, label %ok_593, label %trap_593
trap_593:
  call void @abort()
  unreachable
ok_593:
  %t594 = lshr i64 %t570, 16
  %t595 = trunc i64 %t594 to i8
  %t596 = add i64 16, 2
  %t597 = extractvalue %hia.buffer %p_5_1, 0
  %t598 = extractvalue %hia.buffer %p_5_1, 1
  %t599 = icmp ult i64 %t596, %t598
  br i1 %t599, label %ok_600, label %trap_600
trap_600:
  call void @abort()
  unreachable
ok_600:
  %t601 = getelementptr i8, ptr %t597, i64 %t596
  store i8 %t595, ptr %t601, align 1
  %t602 = icmp ult i64 24, 64
  br i1 %t602, label %ok_603, label %trap_603
trap_603:
  call void @abort()
  unreachable
ok_603:
  %t604 = lshr i64 %t570, 24
  %t605 = trunc i64 %t604 to i8
  %t606 = add i64 16, 3
  %t607 = extractvalue %hia.buffer %p_5_1, 0
  %t608 = extractvalue %hia.buffer %p_5_1, 1
  %t609 = icmp ult i64 %t606, %t608
  br i1 %t609, label %ok_610, label %trap_610
trap_610:
  call void @abort()
  unreachable
ok_610:
  %t611 = getelementptr i8, ptr %t607, i64 %t606
  store i8 %t605, ptr %t611, align 1
  %t612 = icmp ult i64 32, 64
  br i1 %t612, label %ok_613, label %trap_613
trap_613:
  call void @abort()
  unreachable
ok_613:
  %t614 = lshr i64 %t570, 32
  %t615 = trunc i64 %t614 to i8
  %t616 = add i64 16, 4
  %t617 = extractvalue %hia.buffer %p_5_1, 0
  %t618 = extractvalue %hia.buffer %p_5_1, 1
  %t619 = icmp ult i64 %t616, %t618
  br i1 %t619, label %ok_620, label %trap_620
trap_620:
  call void @abort()
  unreachable
ok_620:
  %t621 = getelementptr i8, ptr %t617, i64 %t616
  store i8 %t615, ptr %t621, align 1
  %t622 = icmp ult i64 40, 64
  br i1 %t622, label %ok_623, label %trap_623
trap_623:
  call void @abort()
  unreachable
ok_623:
  %t624 = lshr i64 %t570, 40
  %t625 = trunc i64 %t624 to i8
  %t626 = add i64 16, 5
  %t627 = extractvalue %hia.buffer %p_5_1, 0
  %t628 = extractvalue %hia.buffer %p_5_1, 1
  %t629 = icmp ult i64 %t626, %t628
  br i1 %t629, label %ok_630, label %trap_630
trap_630:
  call void @abort()
  unreachable
ok_630:
  %t631 = getelementptr i8, ptr %t627, i64 %t626
  store i8 %t625, ptr %t631, align 1
  %t632 = icmp ult i64 48, 64
  br i1 %t632, label %ok_633, label %trap_633
trap_633:
  call void @abort()
  unreachable
ok_633:
  %t634 = lshr i64 %t570, 48
  %t635 = trunc i64 %t634 to i8
  %t636 = add i64 16, 6
  %t637 = extractvalue %hia.buffer %p_5_1, 0
  %t638 = extractvalue %hia.buffer %p_5_1, 1
  %t639 = icmp ult i64 %t636, %t638
  br i1 %t639, label %ok_640, label %trap_640
trap_640:
  call void @abort()
  unreachable
ok_640:
  %t641 = getelementptr i8, ptr %t637, i64 %t636
  store i8 %t635, ptr %t641, align 1
  %t642 = icmp ult i64 56, 64
  br i1 %t642, label %ok_643, label %trap_643
trap_643:
  call void @abort()
  unreachable
ok_643:
  %t644 = lshr i64 %t570, 56
  %t645 = trunc i64 %t644 to i8
  %t646 = add i64 16, 7
  %t647 = extractvalue %hia.buffer %p_5_1, 0
  %t648 = extractvalue %hia.buffer %p_5_1, 1
  %t649 = icmp ult i64 %t646, %t648
  br i1 %t649, label %ok_650, label %trap_650
trap_650:
  call void @abort()
  unreachable
ok_650:
  %t651 = getelementptr i8, ptr %t647, i64 %t646
  store i8 %t645, ptr %t651, align 1
  %t652 = icmp ult i64 0, 64
  br i1 %t652, label %ok_653, label %trap_653
trap_653:
  call void @abort()
  unreachable
ok_653:
  %t654 = lshr i64 %t571, 0
  %t655 = trunc i64 %t654 to i8
  %t656 = add i64 24, 0
  %t657 = extractvalue %hia.buffer %p_5_1, 0
  %t658 = extractvalue %hia.buffer %p_5_1, 1
  %t659 = icmp ult i64 %t656, %t658
  br i1 %t659, label %ok_660, label %trap_660
trap_660:
  call void @abort()
  unreachable
ok_660:
  %t661 = getelementptr i8, ptr %t657, i64 %t656
  store i8 %t655, ptr %t661, align 1
  %t662 = icmp ult i64 8, 64
  br i1 %t662, label %ok_663, label %trap_663
trap_663:
  call void @abort()
  unreachable
ok_663:
  %t664 = lshr i64 %t571, 8
  %t665 = trunc i64 %t664 to i8
  %t666 = add i64 24, 1
  %t667 = extractvalue %hia.buffer %p_5_1, 0
  %t668 = extractvalue %hia.buffer %p_5_1, 1
  %t669 = icmp ult i64 %t666, %t668
  br i1 %t669, label %ok_670, label %trap_670
trap_670:
  call void @abort()
  unreachable
ok_670:
  %t671 = getelementptr i8, ptr %t667, i64 %t666
  store i8 %t665, ptr %t671, align 1
  %t672 = icmp ult i64 16, 64
  br i1 %t672, label %ok_673, label %trap_673
trap_673:
  call void @abort()
  unreachable
ok_673:
  %t674 = lshr i64 %t571, 16
  %t675 = trunc i64 %t674 to i8
  %t676 = add i64 24, 2
  %t677 = extractvalue %hia.buffer %p_5_1, 0
  %t678 = extractvalue %hia.buffer %p_5_1, 1
  %t679 = icmp ult i64 %t676, %t678
  br i1 %t679, label %ok_680, label %trap_680
trap_680:
  call void @abort()
  unreachable
ok_680:
  %t681 = getelementptr i8, ptr %t677, i64 %t676
  store i8 %t675, ptr %t681, align 1
  %t682 = icmp ult i64 24, 64
  br i1 %t682, label %ok_683, label %trap_683
trap_683:
  call void @abort()
  unreachable
ok_683:
  %t684 = lshr i64 %t571, 24
  %t685 = trunc i64 %t684 to i8
  %t686 = add i64 24, 3
  %t687 = extractvalue %hia.buffer %p_5_1, 0
  %t688 = extractvalue %hia.buffer %p_5_1, 1
  %t689 = icmp ult i64 %t686, %t688
  br i1 %t689, label %ok_690, label %trap_690
trap_690:
  call void @abort()
  unreachable
ok_690:
  %t691 = getelementptr i8, ptr %t687, i64 %t686
  store i8 %t685, ptr %t691, align 1
  %t692 = icmp ult i64 32, 64
  br i1 %t692, label %ok_693, label %trap_693
trap_693:
  call void @abort()
  unreachable
ok_693:
  %t694 = lshr i64 %t571, 32
  %t695 = trunc i64 %t694 to i8
  %t696 = add i64 24, 4
  %t697 = extractvalue %hia.buffer %p_5_1, 0
  %t698 = extractvalue %hia.buffer %p_5_1, 1
  %t699 = icmp ult i64 %t696, %t698
  br i1 %t699, label %ok_700, label %trap_700
trap_700:
  call void @abort()
  unreachable
ok_700:
  %t701 = getelementptr i8, ptr %t697, i64 %t696
  store i8 %t695, ptr %t701, align 1
  %t702 = icmp ult i64 40, 64
  br i1 %t702, label %ok_703, label %trap_703
trap_703:
  call void @abort()
  unreachable
ok_703:
  %t704 = lshr i64 %t571, 40
  %t705 = trunc i64 %t704 to i8
  %t706 = add i64 24, 5
  %t707 = extractvalue %hia.buffer %p_5_1, 0
  %t708 = extractvalue %hia.buffer %p_5_1, 1
  %t709 = icmp ult i64 %t706, %t708
  br i1 %t709, label %ok_710, label %trap_710
trap_710:
  call void @abort()
  unreachable
ok_710:
  %t711 = getelementptr i8, ptr %t707, i64 %t706
  store i8 %t705, ptr %t711, align 1
  %t712 = icmp ult i64 48, 64
  br i1 %t712, label %ok_713, label %trap_713
trap_713:
  call void @abort()
  unreachable
ok_713:
  %t714 = lshr i64 %t571, 48
  %t715 = trunc i64 %t714 to i8
  %t716 = add i64 24, 6
  %t717 = extractvalue %hia.buffer %p_5_1, 0
  %t718 = extractvalue %hia.buffer %p_5_1, 1
  %t719 = icmp ult i64 %t716, %t718
  br i1 %t719, label %ok_720, label %trap_720
trap_720:
  call void @abort()
  unreachable
ok_720:
  %t721 = getelementptr i8, ptr %t717, i64 %t716
  store i8 %t715, ptr %t721, align 1
  %t722 = icmp ult i64 56, 64
  br i1 %t722, label %ok_723, label %trap_723
trap_723:
  call void @abort()
  unreachable
ok_723:
  %t724 = lshr i64 %t571, 56
  %t725 = trunc i64 %t724 to i8
  %t726 = add i64 24, 7
  %t727 = extractvalue %hia.buffer %p_5_1, 0
  %t728 = extractvalue %hia.buffer %p_5_1, 1
  %t729 = icmp ult i64 %t726, %t728
  br i1 %t729, label %ok_730, label %trap_730
trap_730:
  call void @abort()
  unreachable
ok_730:
  %t731 = getelementptr i8, ptr %t727, i64 %t726
  store i8 %t725, ptr %t731, align 1
  %t732 = icmp ult i64 48, 64
  br i1 %t732, label %ok_733, label %trap_733
trap_733:
  call void @abort()
  unreachable
ok_733:
  %t734 = lshr i64 %t488, 48
  %t735 = trunc i64 %t734 to i32
  ret i32 %t735
edge_0:
  br label %b1
edge_1:
  br label %b2
edge_2:
  br label %b4
edge_3:
  br label %b2
edge_4:
  br label %b5
edge_5:
  br label %b3
}

define internal i32 @__hia_fn_3(%hia.buffer %p_0_0, %hia.buffer %p_0_1, i64 %p_0_2, i16 %p_0_3) {
b0:
  %t1 = extractvalue %hia.buffer %p_0_1, 1
  %t2 = icmp eq i64 %t1, 32
  br i1 %t2, label %edge_0, label %edge_1
b1:
  %p_1_0 = phi %hia.buffer [ %p_0_0, %edge_0 ]
  %p_1_1 = phi %hia.buffer [ %p_0_1, %edge_0 ]
  %p_1_2 = phi i64 [ %p_0_2, %edge_0 ]
  %p_1_3 = phi i16 [ %p_0_3, %edge_0 ]
  %t3 = add i64 0, 0
  %t4 = extractvalue %hia.buffer %p_1_1, 0
  %t5 = extractvalue %hia.buffer %p_1_1, 1
  %t6 = icmp ult i64 %t3, %t5
  br i1 %t6, label %ok_7, label %trap_7
trap_7:
  call void @abort()
  unreachable
ok_7:
  %t8 = getelementptr i8, ptr %t4, i64 %t3
  %t9 = load i8, ptr %t8, align 1
  %t10 = zext i8 %t9 to i64
  %t11 = icmp ult i64 0, 64
  br i1 %t11, label %ok_12, label %trap_12
trap_12:
  call void @abort()
  unreachable
ok_12:
  %t13 = shl i64 %t10, 0
  %t14 = or i64 0, %t13
  %t15 = add i64 0, 1
  %t16 = extractvalue %hia.buffer %p_1_1, 0
  %t17 = extractvalue %hia.buffer %p_1_1, 1
  %t18 = icmp ult i64 %t15, %t17
  br i1 %t18, label %ok_19, label %trap_19
trap_19:
  call void @abort()
  unreachable
ok_19:
  %t20 = getelementptr i8, ptr %t16, i64 %t15
  %t21 = load i8, ptr %t20, align 1
  %t22 = zext i8 %t21 to i64
  %t23 = icmp ult i64 8, 64
  br i1 %t23, label %ok_24, label %trap_24
trap_24:
  call void @abort()
  unreachable
ok_24:
  %t25 = shl i64 %t22, 8
  %t26 = or i64 %t14, %t25
  %t27 = add i64 0, 2
  %t28 = extractvalue %hia.buffer %p_1_1, 0
  %t29 = extractvalue %hia.buffer %p_1_1, 1
  %t30 = icmp ult i64 %t27, %t29
  br i1 %t30, label %ok_31, label %trap_31
trap_31:
  call void @abort()
  unreachable
ok_31:
  %t32 = getelementptr i8, ptr %t28, i64 %t27
  %t33 = load i8, ptr %t32, align 1
  %t34 = zext i8 %t33 to i64
  %t35 = icmp ult i64 16, 64
  br i1 %t35, label %ok_36, label %trap_36
trap_36:
  call void @abort()
  unreachable
ok_36:
  %t37 = shl i64 %t34, 16
  %t38 = or i64 %t26, %t37
  %t39 = add i64 0, 3
  %t40 = extractvalue %hia.buffer %p_1_1, 0
  %t41 = extractvalue %hia.buffer %p_1_1, 1
  %t42 = icmp ult i64 %t39, %t41
  br i1 %t42, label %ok_43, label %trap_43
trap_43:
  call void @abort()
  unreachable
ok_43:
  %t44 = getelementptr i8, ptr %t40, i64 %t39
  %t45 = load i8, ptr %t44, align 1
  %t46 = zext i8 %t45 to i64
  %t47 = icmp ult i64 24, 64
  br i1 %t47, label %ok_48, label %trap_48
trap_48:
  call void @abort()
  unreachable
ok_48:
  %t49 = shl i64 %t46, 24
  %t50 = or i64 %t38, %t49
  %t51 = add i64 0, 4
  %t52 = extractvalue %hia.buffer %p_1_1, 0
  %t53 = extractvalue %hia.buffer %p_1_1, 1
  %t54 = icmp ult i64 %t51, %t53
  br i1 %t54, label %ok_55, label %trap_55
trap_55:
  call void @abort()
  unreachable
ok_55:
  %t56 = getelementptr i8, ptr %t52, i64 %t51
  %t57 = load i8, ptr %t56, align 1
  %t58 = zext i8 %t57 to i64
  %t59 = icmp ult i64 32, 64
  br i1 %t59, label %ok_60, label %trap_60
trap_60:
  call void @abort()
  unreachable
ok_60:
  %t61 = shl i64 %t58, 32
  %t62 = or i64 %t50, %t61
  %t63 = add i64 0, 5
  %t64 = extractvalue %hia.buffer %p_1_1, 0
  %t65 = extractvalue %hia.buffer %p_1_1, 1
  %t66 = icmp ult i64 %t63, %t65
  br i1 %t66, label %ok_67, label %trap_67
trap_67:
  call void @abort()
  unreachable
ok_67:
  %t68 = getelementptr i8, ptr %t64, i64 %t63
  %t69 = load i8, ptr %t68, align 1
  %t70 = zext i8 %t69 to i64
  %t71 = icmp ult i64 40, 64
  br i1 %t71, label %ok_72, label %trap_72
trap_72:
  call void @abort()
  unreachable
ok_72:
  %t73 = shl i64 %t70, 40
  %t74 = or i64 %t62, %t73
  %t75 = add i64 0, 6
  %t76 = extractvalue %hia.buffer %p_1_1, 0
  %t77 = extractvalue %hia.buffer %p_1_1, 1
  %t78 = icmp ult i64 %t75, %t77
  br i1 %t78, label %ok_79, label %trap_79
trap_79:
  call void @abort()
  unreachable
ok_79:
  %t80 = getelementptr i8, ptr %t76, i64 %t75
  %t81 = load i8, ptr %t80, align 1
  %t82 = zext i8 %t81 to i64
  %t83 = icmp ult i64 48, 64
  br i1 %t83, label %ok_84, label %trap_84
trap_84:
  call void @abort()
  unreachable
ok_84:
  %t85 = shl i64 %t82, 48
  %t86 = or i64 %t74, %t85
  %t87 = add i64 0, 7
  %t88 = extractvalue %hia.buffer %p_1_1, 0
  %t89 = extractvalue %hia.buffer %p_1_1, 1
  %t90 = icmp ult i64 %t87, %t89
  br i1 %t90, label %ok_91, label %trap_91
trap_91:
  call void @abort()
  unreachable
ok_91:
  %t92 = getelementptr i8, ptr %t88, i64 %t87
  %t93 = load i8, ptr %t92, align 1
  %t94 = zext i8 %t93 to i64
  %t95 = icmp ult i64 56, 64
  br i1 %t95, label %ok_96, label %trap_96
trap_96:
  call void @abort()
  unreachable
ok_96:
  %t97 = shl i64 %t94, 56
  %t98 = or i64 %t86, %t97
  %t99 = add i64 8, 0
  %t100 = extractvalue %hia.buffer %p_1_1, 0
  %t101 = extractvalue %hia.buffer %p_1_1, 1
  %t102 = icmp ult i64 %t99, %t101
  br i1 %t102, label %ok_103, label %trap_103
trap_103:
  call void @abort()
  unreachable
ok_103:
  %t104 = getelementptr i8, ptr %t100, i64 %t99
  %t105 = load i8, ptr %t104, align 1
  %t106 = zext i8 %t105 to i64
  %t107 = icmp ult i64 0, 64
  br i1 %t107, label %ok_108, label %trap_108
trap_108:
  call void @abort()
  unreachable
ok_108:
  %t109 = shl i64 %t106, 0
  %t110 = or i64 0, %t109
  %t111 = add i64 8, 1
  %t112 = extractvalue %hia.buffer %p_1_1, 0
  %t113 = extractvalue %hia.buffer %p_1_1, 1
  %t114 = icmp ult i64 %t111, %t113
  br i1 %t114, label %ok_115, label %trap_115
trap_115:
  call void @abort()
  unreachable
ok_115:
  %t116 = getelementptr i8, ptr %t112, i64 %t111
  %t117 = load i8, ptr %t116, align 1
  %t118 = zext i8 %t117 to i64
  %t119 = icmp ult i64 8, 64
  br i1 %t119, label %ok_120, label %trap_120
trap_120:
  call void @abort()
  unreachable
ok_120:
  %t121 = shl i64 %t118, 8
  %t122 = or i64 %t110, %t121
  %t123 = add i64 8, 2
  %t124 = extractvalue %hia.buffer %p_1_1, 0
  %t125 = extractvalue %hia.buffer %p_1_1, 1
  %t126 = icmp ult i64 %t123, %t125
  br i1 %t126, label %ok_127, label %trap_127
trap_127:
  call void @abort()
  unreachable
ok_127:
  %t128 = getelementptr i8, ptr %t124, i64 %t123
  %t129 = load i8, ptr %t128, align 1
  %t130 = zext i8 %t129 to i64
  %t131 = icmp ult i64 16, 64
  br i1 %t131, label %ok_132, label %trap_132
trap_132:
  call void @abort()
  unreachable
ok_132:
  %t133 = shl i64 %t130, 16
  %t134 = or i64 %t122, %t133
  %t135 = add i64 8, 3
  %t136 = extractvalue %hia.buffer %p_1_1, 0
  %t137 = extractvalue %hia.buffer %p_1_1, 1
  %t138 = icmp ult i64 %t135, %t137
  br i1 %t138, label %ok_139, label %trap_139
trap_139:
  call void @abort()
  unreachable
ok_139:
  %t140 = getelementptr i8, ptr %t136, i64 %t135
  %t141 = load i8, ptr %t140, align 1
  %t142 = zext i8 %t141 to i64
  %t143 = icmp ult i64 24, 64
  br i1 %t143, label %ok_144, label %trap_144
trap_144:
  call void @abort()
  unreachable
ok_144:
  %t145 = shl i64 %t142, 24
  %t146 = or i64 %t134, %t145
  %t147 = add i64 8, 4
  %t148 = extractvalue %hia.buffer %p_1_1, 0
  %t149 = extractvalue %hia.buffer %p_1_1, 1
  %t150 = icmp ult i64 %t147, %t149
  br i1 %t150, label %ok_151, label %trap_151
trap_151:
  call void @abort()
  unreachable
ok_151:
  %t152 = getelementptr i8, ptr %t148, i64 %t147
  %t153 = load i8, ptr %t152, align 1
  %t154 = zext i8 %t153 to i64
  %t155 = icmp ult i64 32, 64
  br i1 %t155, label %ok_156, label %trap_156
trap_156:
  call void @abort()
  unreachable
ok_156:
  %t157 = shl i64 %t154, 32
  %t158 = or i64 %t146, %t157
  %t159 = add i64 8, 5
  %t160 = extractvalue %hia.buffer %p_1_1, 0
  %t161 = extractvalue %hia.buffer %p_1_1, 1
  %t162 = icmp ult i64 %t159, %t161
  br i1 %t162, label %ok_163, label %trap_163
trap_163:
  call void @abort()
  unreachable
ok_163:
  %t164 = getelementptr i8, ptr %t160, i64 %t159
  %t165 = load i8, ptr %t164, align 1
  %t166 = zext i8 %t165 to i64
  %t167 = icmp ult i64 40, 64
  br i1 %t167, label %ok_168, label %trap_168
trap_168:
  call void @abort()
  unreachable
ok_168:
  %t169 = shl i64 %t166, 40
  %t170 = or i64 %t158, %t169
  %t171 = add i64 8, 6
  %t172 = extractvalue %hia.buffer %p_1_1, 0
  %t173 = extractvalue %hia.buffer %p_1_1, 1
  %t174 = icmp ult i64 %t171, %t173
  br i1 %t174, label %ok_175, label %trap_175
trap_175:
  call void @abort()
  unreachable
ok_175:
  %t176 = getelementptr i8, ptr %t172, i64 %t171
  %t177 = load i8, ptr %t176, align 1
  %t178 = zext i8 %t177 to i64
  %t179 = icmp ult i64 48, 64
  br i1 %t179, label %ok_180, label %trap_180
trap_180:
  call void @abort()
  unreachable
ok_180:
  %t181 = shl i64 %t178, 48
  %t182 = or i64 %t170, %t181
  %t183 = add i64 8, 7
  %t184 = extractvalue %hia.buffer %p_1_1, 0
  %t185 = extractvalue %hia.buffer %p_1_1, 1
  %t186 = icmp ult i64 %t183, %t185
  br i1 %t186, label %ok_187, label %trap_187
trap_187:
  call void @abort()
  unreachable
ok_187:
  %t188 = getelementptr i8, ptr %t184, i64 %t183
  %t189 = load i8, ptr %t188, align 1
  %t190 = zext i8 %t189 to i64
  %t191 = icmp ult i64 56, 64
  br i1 %t191, label %ok_192, label %trap_192
trap_192:
  call void @abort()
  unreachable
ok_192:
  %t193 = shl i64 %t190, 56
  %t194 = or i64 %t182, %t193
  %t195 = add i64 16, 0
  %t196 = extractvalue %hia.buffer %p_1_1, 0
  %t197 = extractvalue %hia.buffer %p_1_1, 1
  %t198 = icmp ult i64 %t195, %t197
  br i1 %t198, label %ok_199, label %trap_199
trap_199:
  call void @abort()
  unreachable
ok_199:
  %t200 = getelementptr i8, ptr %t196, i64 %t195
  %t201 = load i8, ptr %t200, align 1
  %t202 = zext i8 %t201 to i64
  %t203 = icmp ult i64 0, 64
  br i1 %t203, label %ok_204, label %trap_204
trap_204:
  call void @abort()
  unreachable
ok_204:
  %t205 = shl i64 %t202, 0
  %t206 = or i64 0, %t205
  %t207 = add i64 16, 1
  %t208 = extractvalue %hia.buffer %p_1_1, 0
  %t209 = extractvalue %hia.buffer %p_1_1, 1
  %t210 = icmp ult i64 %t207, %t209
  br i1 %t210, label %ok_211, label %trap_211
trap_211:
  call void @abort()
  unreachable
ok_211:
  %t212 = getelementptr i8, ptr %t208, i64 %t207
  %t213 = load i8, ptr %t212, align 1
  %t214 = zext i8 %t213 to i64
  %t215 = icmp ult i64 8, 64
  br i1 %t215, label %ok_216, label %trap_216
trap_216:
  call void @abort()
  unreachable
ok_216:
  %t217 = shl i64 %t214, 8
  %t218 = or i64 %t206, %t217
  %t219 = add i64 16, 2
  %t220 = extractvalue %hia.buffer %p_1_1, 0
  %t221 = extractvalue %hia.buffer %p_1_1, 1
  %t222 = icmp ult i64 %t219, %t221
  br i1 %t222, label %ok_223, label %trap_223
trap_223:
  call void @abort()
  unreachable
ok_223:
  %t224 = getelementptr i8, ptr %t220, i64 %t219
  %t225 = load i8, ptr %t224, align 1
  %t226 = zext i8 %t225 to i64
  %t227 = icmp ult i64 16, 64
  br i1 %t227, label %ok_228, label %trap_228
trap_228:
  call void @abort()
  unreachable
ok_228:
  %t229 = shl i64 %t226, 16
  %t230 = or i64 %t218, %t229
  %t231 = add i64 16, 3
  %t232 = extractvalue %hia.buffer %p_1_1, 0
  %t233 = extractvalue %hia.buffer %p_1_1, 1
  %t234 = icmp ult i64 %t231, %t233
  br i1 %t234, label %ok_235, label %trap_235
trap_235:
  call void @abort()
  unreachable
ok_235:
  %t236 = getelementptr i8, ptr %t232, i64 %t231
  %t237 = load i8, ptr %t236, align 1
  %t238 = zext i8 %t237 to i64
  %t239 = icmp ult i64 24, 64
  br i1 %t239, label %ok_240, label %trap_240
trap_240:
  call void @abort()
  unreachable
ok_240:
  %t241 = shl i64 %t238, 24
  %t242 = or i64 %t230, %t241
  %t243 = add i64 16, 4
  %t244 = extractvalue %hia.buffer %p_1_1, 0
  %t245 = extractvalue %hia.buffer %p_1_1, 1
  %t246 = icmp ult i64 %t243, %t245
  br i1 %t246, label %ok_247, label %trap_247
trap_247:
  call void @abort()
  unreachable
ok_247:
  %t248 = getelementptr i8, ptr %t244, i64 %t243
  %t249 = load i8, ptr %t248, align 1
  %t250 = zext i8 %t249 to i64
  %t251 = icmp ult i64 32, 64
  br i1 %t251, label %ok_252, label %trap_252
trap_252:
  call void @abort()
  unreachable
ok_252:
  %t253 = shl i64 %t250, 32
  %t254 = or i64 %t242, %t253
  %t255 = add i64 16, 5
  %t256 = extractvalue %hia.buffer %p_1_1, 0
  %t257 = extractvalue %hia.buffer %p_1_1, 1
  %t258 = icmp ult i64 %t255, %t257
  br i1 %t258, label %ok_259, label %trap_259
trap_259:
  call void @abort()
  unreachable
ok_259:
  %t260 = getelementptr i8, ptr %t256, i64 %t255
  %t261 = load i8, ptr %t260, align 1
  %t262 = zext i8 %t261 to i64
  %t263 = icmp ult i64 40, 64
  br i1 %t263, label %ok_264, label %trap_264
trap_264:
  call void @abort()
  unreachable
ok_264:
  %t265 = shl i64 %t262, 40
  %t266 = or i64 %t254, %t265
  %t267 = add i64 16, 6
  %t268 = extractvalue %hia.buffer %p_1_1, 0
  %t269 = extractvalue %hia.buffer %p_1_1, 1
  %t270 = icmp ult i64 %t267, %t269
  br i1 %t270, label %ok_271, label %trap_271
trap_271:
  call void @abort()
  unreachable
ok_271:
  %t272 = getelementptr i8, ptr %t268, i64 %t267
  %t273 = load i8, ptr %t272, align 1
  %t274 = zext i8 %t273 to i64
  %t275 = icmp ult i64 48, 64
  br i1 %t275, label %ok_276, label %trap_276
trap_276:
  call void @abort()
  unreachable
ok_276:
  %t277 = shl i64 %t274, 48
  %t278 = or i64 %t266, %t277
  %t279 = add i64 16, 7
  %t280 = extractvalue %hia.buffer %p_1_1, 0
  %t281 = extractvalue %hia.buffer %p_1_1, 1
  %t282 = icmp ult i64 %t279, %t281
  br i1 %t282, label %ok_283, label %trap_283
trap_283:
  call void @abort()
  unreachable
ok_283:
  %t284 = getelementptr i8, ptr %t280, i64 %t279
  %t285 = load i8, ptr %t284, align 1
  %t286 = zext i8 %t285 to i64
  %t287 = icmp ult i64 56, 64
  br i1 %t287, label %ok_288, label %trap_288
trap_288:
  call void @abort()
  unreachable
ok_288:
  %t289 = shl i64 %t286, 56
  %t290 = or i64 %t278, %t289
  %t291 = add i64 24, 0
  %t292 = extractvalue %hia.buffer %p_1_1, 0
  %t293 = extractvalue %hia.buffer %p_1_1, 1
  %t294 = icmp ult i64 %t291, %t293
  br i1 %t294, label %ok_295, label %trap_295
trap_295:
  call void @abort()
  unreachable
ok_295:
  %t296 = getelementptr i8, ptr %t292, i64 %t291
  %t297 = load i8, ptr %t296, align 1
  %t298 = zext i8 %t297 to i64
  %t299 = icmp ult i64 0, 64
  br i1 %t299, label %ok_300, label %trap_300
trap_300:
  call void @abort()
  unreachable
ok_300:
  %t301 = shl i64 %t298, 0
  %t302 = or i64 0, %t301
  %t303 = add i64 24, 1
  %t304 = extractvalue %hia.buffer %p_1_1, 0
  %t305 = extractvalue %hia.buffer %p_1_1, 1
  %t306 = icmp ult i64 %t303, %t305
  br i1 %t306, label %ok_307, label %trap_307
trap_307:
  call void @abort()
  unreachable
ok_307:
  %t308 = getelementptr i8, ptr %t304, i64 %t303
  %t309 = load i8, ptr %t308, align 1
  %t310 = zext i8 %t309 to i64
  %t311 = icmp ult i64 8, 64
  br i1 %t311, label %ok_312, label %trap_312
trap_312:
  call void @abort()
  unreachable
ok_312:
  %t313 = shl i64 %t310, 8
  %t314 = or i64 %t302, %t313
  %t315 = add i64 24, 2
  %t316 = extractvalue %hia.buffer %p_1_1, 0
  %t317 = extractvalue %hia.buffer %p_1_1, 1
  %t318 = icmp ult i64 %t315, %t317
  br i1 %t318, label %ok_319, label %trap_319
trap_319:
  call void @abort()
  unreachable
ok_319:
  %t320 = getelementptr i8, ptr %t316, i64 %t315
  %t321 = load i8, ptr %t320, align 1
  %t322 = zext i8 %t321 to i64
  %t323 = icmp ult i64 16, 64
  br i1 %t323, label %ok_324, label %trap_324
trap_324:
  call void @abort()
  unreachable
ok_324:
  %t325 = shl i64 %t322, 16
  %t326 = or i64 %t314, %t325
  %t327 = add i64 24, 3
  %t328 = extractvalue %hia.buffer %p_1_1, 0
  %t329 = extractvalue %hia.buffer %p_1_1, 1
  %t330 = icmp ult i64 %t327, %t329
  br i1 %t330, label %ok_331, label %trap_331
trap_331:
  call void @abort()
  unreachable
ok_331:
  %t332 = getelementptr i8, ptr %t328, i64 %t327
  %t333 = load i8, ptr %t332, align 1
  %t334 = zext i8 %t333 to i64
  %t335 = icmp ult i64 24, 64
  br i1 %t335, label %ok_336, label %trap_336
trap_336:
  call void @abort()
  unreachable
ok_336:
  %t337 = shl i64 %t334, 24
  %t338 = or i64 %t326, %t337
  %t339 = add i64 24, 4
  %t340 = extractvalue %hia.buffer %p_1_1, 0
  %t341 = extractvalue %hia.buffer %p_1_1, 1
  %t342 = icmp ult i64 %t339, %t341
  br i1 %t342, label %ok_343, label %trap_343
trap_343:
  call void @abort()
  unreachable
ok_343:
  %t344 = getelementptr i8, ptr %t340, i64 %t339
  %t345 = load i8, ptr %t344, align 1
  %t346 = zext i8 %t345 to i64
  %t347 = icmp ult i64 32, 64
  br i1 %t347, label %ok_348, label %trap_348
trap_348:
  call void @abort()
  unreachable
ok_348:
  %t349 = shl i64 %t346, 32
  %t350 = or i64 %t338, %t349
  %t351 = add i64 24, 5
  %t352 = extractvalue %hia.buffer %p_1_1, 0
  %t353 = extractvalue %hia.buffer %p_1_1, 1
  %t354 = icmp ult i64 %t351, %t353
  br i1 %t354, label %ok_355, label %trap_355
trap_355:
  call void @abort()
  unreachable
ok_355:
  %t356 = getelementptr i8, ptr %t352, i64 %t351
  %t357 = load i8, ptr %t356, align 1
  %t358 = zext i8 %t357 to i64
  %t359 = icmp ult i64 40, 64
  br i1 %t359, label %ok_360, label %trap_360
trap_360:
  call void @abort()
  unreachable
ok_360:
  %t361 = shl i64 %t358, 40
  %t362 = or i64 %t350, %t361
  %t363 = add i64 24, 6
  %t364 = extractvalue %hia.buffer %p_1_1, 0
  %t365 = extractvalue %hia.buffer %p_1_1, 1
  %t366 = icmp ult i64 %t363, %t365
  br i1 %t366, label %ok_367, label %trap_367
trap_367:
  call void @abort()
  unreachable
ok_367:
  %t368 = getelementptr i8, ptr %t364, i64 %t363
  %t369 = load i8, ptr %t368, align 1
  %t370 = zext i8 %t369 to i64
  %t371 = icmp ult i64 48, 64
  br i1 %t371, label %ok_372, label %trap_372
trap_372:
  call void @abort()
  unreachable
ok_372:
  %t373 = shl i64 %t370, 48
  %t374 = or i64 %t362, %t373
  %t375 = add i64 24, 7
  %t376 = extractvalue %hia.buffer %p_1_1, 0
  %t377 = extractvalue %hia.buffer %p_1_1, 1
  %t378 = icmp ult i64 %t375, %t377
  br i1 %t378, label %ok_379, label %trap_379
trap_379:
  call void @abort()
  unreachable
ok_379:
  %t380 = getelementptr i8, ptr %t376, i64 %t375
  %t381 = load i8, ptr %t380, align 1
  %t382 = zext i8 %t381 to i64
  %t383 = icmp ult i64 56, 64
  br i1 %t383, label %ok_384, label %trap_384
trap_384:
  call void @abort()
  unreachable
ok_384:
  %t385 = shl i64 %t382, 56
  %t386 = or i64 %t374, %t385
  %t387 = extractvalue %hia.buffer %p_1_0, 1
  %t388 = icmp ule i64 %t290, %t387
  %t389 = sub i64 %t387, %t290
  %t390 = icmp ule i64 %t386, %t389
  %t391 = and i1 %t388, %t390
  br i1 %t391, label %edge_2, label %edge_3
b2:
  ret i32 4294836225
b3:
  ret i32 0
b4:
  ret i32 1
b5:
  %p_5_0 = phi %hia.buffer [ %p_1_0, %edge_2 ]
  %p_5_1 = phi %hia.buffer [ %p_1_1, %edge_2 ]
  %p_5_2 = phi i64 [ %t98, %edge_2 ]
  %p_5_3 = phi i64 [ %t194, %edge_2 ]
  %p_5_4 = phi i64 [ %t290, %edge_2 ]
  %p_5_5 = phi i64 [ %t386, %edge_2 ]
  %p_5_6 = phi i64 [ %t387, %edge_2 ]
  %p_5_7 = phi i64 [ %p_1_2, %edge_2 ]
  %p_5_8 = phi i16 [ %p_1_3, %edge_2 ]
  %t392 = icmp eq i64 %p_5_3, 0
  %t393 = select i1 %t392, i64 %p_5_7, i64 %p_5_3
  %t394 = icmp ult i64 0, 64
  br i1 %t394, label %ok_395, label %trap_395
trap_395:
  call void @abort()
  unreachable
ok_395:
  %t396 = lshr i64 %t393, 0
  %t397 = trunc i64 %t396 to i8
  %t398 = add i64 8, 0
  %t399 = extractvalue %hia.buffer %p_5_1, 0
  %t400 = extractvalue %hia.buffer %p_5_1, 1
  %t401 = icmp ult i64 %t398, %t400
  br i1 %t401, label %ok_402, label %trap_402
trap_402:
  call void @abort()
  unreachable
ok_402:
  %t403 = getelementptr i8, ptr %t399, i64 %t398
  store i8 %t397, ptr %t403, align 1
  %t404 = icmp ult i64 8, 64
  br i1 %t404, label %ok_405, label %trap_405
trap_405:
  call void @abort()
  unreachable
ok_405:
  %t406 = lshr i64 %t393, 8
  %t407 = trunc i64 %t406 to i8
  %t408 = add i64 8, 1
  %t409 = extractvalue %hia.buffer %p_5_1, 0
  %t410 = extractvalue %hia.buffer %p_5_1, 1
  %t411 = icmp ult i64 %t408, %t410
  br i1 %t411, label %ok_412, label %trap_412
trap_412:
  call void @abort()
  unreachable
ok_412:
  %t413 = getelementptr i8, ptr %t409, i64 %t408
  store i8 %t407, ptr %t413, align 1
  %t414 = icmp ult i64 16, 64
  br i1 %t414, label %ok_415, label %trap_415
trap_415:
  call void @abort()
  unreachable
ok_415:
  %t416 = lshr i64 %t393, 16
  %t417 = trunc i64 %t416 to i8
  %t418 = add i64 8, 2
  %t419 = extractvalue %hia.buffer %p_5_1, 0
  %t420 = extractvalue %hia.buffer %p_5_1, 1
  %t421 = icmp ult i64 %t418, %t420
  br i1 %t421, label %ok_422, label %trap_422
trap_422:
  call void @abort()
  unreachable
ok_422:
  %t423 = getelementptr i8, ptr %t419, i64 %t418
  store i8 %t417, ptr %t423, align 1
  %t424 = icmp ult i64 24, 64
  br i1 %t424, label %ok_425, label %trap_425
trap_425:
  call void @abort()
  unreachable
ok_425:
  %t426 = lshr i64 %t393, 24
  %t427 = trunc i64 %t426 to i8
  %t428 = add i64 8, 3
  %t429 = extractvalue %hia.buffer %p_5_1, 0
  %t430 = extractvalue %hia.buffer %p_5_1, 1
  %t431 = icmp ult i64 %t428, %t430
  br i1 %t431, label %ok_432, label %trap_432
trap_432:
  call void @abort()
  unreachable
ok_432:
  %t433 = getelementptr i8, ptr %t429, i64 %t428
  store i8 %t427, ptr %t433, align 1
  %t434 = icmp ult i64 32, 64
  br i1 %t434, label %ok_435, label %trap_435
trap_435:
  call void @abort()
  unreachable
ok_435:
  %t436 = lshr i64 %t393, 32
  %t437 = trunc i64 %t436 to i8
  %t438 = add i64 8, 4
  %t439 = extractvalue %hia.buffer %p_5_1, 0
  %t440 = extractvalue %hia.buffer %p_5_1, 1
  %t441 = icmp ult i64 %t438, %t440
  br i1 %t441, label %ok_442, label %trap_442
trap_442:
  call void @abort()
  unreachable
ok_442:
  %t443 = getelementptr i8, ptr %t439, i64 %t438
  store i8 %t437, ptr %t443, align 1
  %t444 = icmp ult i64 40, 64
  br i1 %t444, label %ok_445, label %trap_445
trap_445:
  call void @abort()
  unreachable
ok_445:
  %t446 = lshr i64 %t393, 40
  %t447 = trunc i64 %t446 to i8
  %t448 = add i64 8, 5
  %t449 = extractvalue %hia.buffer %p_5_1, 0
  %t450 = extractvalue %hia.buffer %p_5_1, 1
  %t451 = icmp ult i64 %t448, %t450
  br i1 %t451, label %ok_452, label %trap_452
trap_452:
  call void @abort()
  unreachable
ok_452:
  %t453 = getelementptr i8, ptr %t449, i64 %t448
  store i8 %t447, ptr %t453, align 1
  %t454 = icmp ult i64 48, 64
  br i1 %t454, label %ok_455, label %trap_455
trap_455:
  call void @abort()
  unreachable
ok_455:
  %t456 = lshr i64 %t393, 48
  %t457 = trunc i64 %t456 to i8
  %t458 = add i64 8, 6
  %t459 = extractvalue %hia.buffer %p_5_1, 0
  %t460 = extractvalue %hia.buffer %p_5_1, 1
  %t461 = icmp ult i64 %t458, %t460
  br i1 %t461, label %ok_462, label %trap_462
trap_462:
  call void @abort()
  unreachable
ok_462:
  %t463 = getelementptr i8, ptr %t459, i64 %t458
  store i8 %t457, ptr %t463, align 1
  %t464 = icmp ult i64 56, 64
  br i1 %t464, label %ok_465, label %trap_465
trap_465:
  call void @abort()
  unreachable
ok_465:
  %t466 = lshr i64 %t393, 56
  %t467 = trunc i64 %t466 to i8
  %t468 = add i64 8, 7
  %t469 = extractvalue %hia.buffer %p_5_1, 0
  %t470 = extractvalue %hia.buffer %p_5_1, 1
  %t471 = icmp ult i64 %t468, %t470
  br i1 %t471, label %ok_472, label %trap_472
trap_472:
  call void @abort()
  unreachable
ok_472:
  %t473 = getelementptr i8, ptr %t469, i64 %t468
  store i8 %t467, ptr %t473, align 1
  %t474 = icmp eq i64 %p_5_2, 281474976710655
  br i1 %t474, label %edge_4, label %edge_5
b6:
  %p_6_0 = phi %hia.buffer [ %p_5_0, %edge_5 ]
  %p_6_1 = phi %hia.buffer [ %p_5_1, %edge_5 ]
  %p_6_2 = phi i64 [ %p_5_2, %edge_5 ]
  %p_6_3 = phi i64 [ %t393, %edge_5 ]
  %p_6_4 = phi i64 [ %p_5_4, %edge_5 ]
  %p_6_5 = phi i64 [ %p_5_5, %edge_5 ]
  %p_6_6 = phi i64 [ %p_5_6, %edge_5 ]
  %p_6_7 = phi i64 [ %p_5_7, %edge_5 ]
  %p_6_8 = phi i16 [ %p_5_8, %edge_5 ]
  %t475 = add i64 %p_6_2, 1
  %t476 = icmp ult i64 0, 64
  br i1 %t476, label %ok_477, label %trap_477
trap_477:
  call void @abort()
  unreachable
ok_477:
  %t478 = lshr i64 %t475, 0
  %t479 = trunc i64 %t478 to i8
  %t480 = add i64 0, 0
  %t481 = extractvalue %hia.buffer %p_6_1, 0
  %t482 = extractvalue %hia.buffer %p_6_1, 1
  %t483 = icmp ult i64 %t480, %t482
  br i1 %t483, label %ok_484, label %trap_484
trap_484:
  call void @abort()
  unreachable
ok_484:
  %t485 = getelementptr i8, ptr %t481, i64 %t480
  store i8 %t479, ptr %t485, align 1
  %t486 = icmp ult i64 8, 64
  br i1 %t486, label %ok_487, label %trap_487
trap_487:
  call void @abort()
  unreachable
ok_487:
  %t488 = lshr i64 %t475, 8
  %t489 = trunc i64 %t488 to i8
  %t490 = add i64 0, 1
  %t491 = extractvalue %hia.buffer %p_6_1, 0
  %t492 = extractvalue %hia.buffer %p_6_1, 1
  %t493 = icmp ult i64 %t490, %t492
  br i1 %t493, label %ok_494, label %trap_494
trap_494:
  call void @abort()
  unreachable
ok_494:
  %t495 = getelementptr i8, ptr %t491, i64 %t490
  store i8 %t489, ptr %t495, align 1
  %t496 = icmp ult i64 16, 64
  br i1 %t496, label %ok_497, label %trap_497
trap_497:
  call void @abort()
  unreachable
ok_497:
  %t498 = lshr i64 %t475, 16
  %t499 = trunc i64 %t498 to i8
  %t500 = add i64 0, 2
  %t501 = extractvalue %hia.buffer %p_6_1, 0
  %t502 = extractvalue %hia.buffer %p_6_1, 1
  %t503 = icmp ult i64 %t500, %t502
  br i1 %t503, label %ok_504, label %trap_504
trap_504:
  call void @abort()
  unreachable
ok_504:
  %t505 = getelementptr i8, ptr %t501, i64 %t500
  store i8 %t499, ptr %t505, align 1
  %t506 = icmp ult i64 24, 64
  br i1 %t506, label %ok_507, label %trap_507
trap_507:
  call void @abort()
  unreachable
ok_507:
  %t508 = lshr i64 %t475, 24
  %t509 = trunc i64 %t508 to i8
  %t510 = add i64 0, 3
  %t511 = extractvalue %hia.buffer %p_6_1, 0
  %t512 = extractvalue %hia.buffer %p_6_1, 1
  %t513 = icmp ult i64 %t510, %t512
  br i1 %t513, label %ok_514, label %trap_514
trap_514:
  call void @abort()
  unreachable
ok_514:
  %t515 = getelementptr i8, ptr %t511, i64 %t510
  store i8 %t509, ptr %t515, align 1
  %t516 = icmp ult i64 32, 64
  br i1 %t516, label %ok_517, label %trap_517
trap_517:
  call void @abort()
  unreachable
ok_517:
  %t518 = lshr i64 %t475, 32
  %t519 = trunc i64 %t518 to i8
  %t520 = add i64 0, 4
  %t521 = extractvalue %hia.buffer %p_6_1, 0
  %t522 = extractvalue %hia.buffer %p_6_1, 1
  %t523 = icmp ult i64 %t520, %t522
  br i1 %t523, label %ok_524, label %trap_524
trap_524:
  call void @abort()
  unreachable
ok_524:
  %t525 = getelementptr i8, ptr %t521, i64 %t520
  store i8 %t519, ptr %t525, align 1
  %t526 = icmp ult i64 40, 64
  br i1 %t526, label %ok_527, label %trap_527
trap_527:
  call void @abort()
  unreachable
ok_527:
  %t528 = lshr i64 %t475, 40
  %t529 = trunc i64 %t528 to i8
  %t530 = add i64 0, 5
  %t531 = extractvalue %hia.buffer %p_6_1, 0
  %t532 = extractvalue %hia.buffer %p_6_1, 1
  %t533 = icmp ult i64 %t530, %t532
  br i1 %t533, label %ok_534, label %trap_534
trap_534:
  call void @abort()
  unreachable
ok_534:
  %t535 = getelementptr i8, ptr %t531, i64 %t530
  store i8 %t529, ptr %t535, align 1
  %t536 = icmp ult i64 48, 64
  br i1 %t536, label %ok_537, label %trap_537
trap_537:
  call void @abort()
  unreachable
ok_537:
  %t538 = lshr i64 %t475, 48
  %t539 = trunc i64 %t538 to i8
  %t540 = add i64 0, 6
  %t541 = extractvalue %hia.buffer %p_6_1, 0
  %t542 = extractvalue %hia.buffer %p_6_1, 1
  %t543 = icmp ult i64 %t540, %t542
  br i1 %t543, label %ok_544, label %trap_544
trap_544:
  call void @abort()
  unreachable
ok_544:
  %t545 = getelementptr i8, ptr %t541, i64 %t540
  store i8 %t539, ptr %t545, align 1
  %t546 = icmp ult i64 56, 64
  br i1 %t546, label %ok_547, label %trap_547
trap_547:
  call void @abort()
  unreachable
ok_547:
  %t548 = lshr i64 %t475, 56
  %t549 = trunc i64 %t548 to i8
  %t550 = add i64 0, 7
  %t551 = extractvalue %hia.buffer %p_6_1, 0
  %t552 = extractvalue %hia.buffer %p_6_1, 1
  %t553 = icmp ult i64 %t550, %t552
  br i1 %t553, label %ok_554, label %trap_554
trap_554:
  call void @abort()
  unreachable
ok_554:
  %t555 = getelementptr i8, ptr %t551, i64 %t550
  store i8 %t549, ptr %t555, align 1
  %t556 = icmp ult i64 0, 64
  br i1 %t556, label %ok_557, label %trap_557
trap_557:
  call void @abort()
  unreachable
ok_557:
  %t558 = lshr i64 %p_6_3, 0
  %t559 = trunc i64 %t558 to i8
  %t560 = add i64 8, 0
  %t561 = extractvalue %hia.buffer %p_6_1, 0
  %t562 = extractvalue %hia.buffer %p_6_1, 1
  %t563 = icmp ult i64 %t560, %t562
  br i1 %t563, label %ok_564, label %trap_564
trap_564:
  call void @abort()
  unreachable
ok_564:
  %t565 = getelementptr i8, ptr %t561, i64 %t560
  store i8 %t559, ptr %t565, align 1
  %t566 = icmp ult i64 8, 64
  br i1 %t566, label %ok_567, label %trap_567
trap_567:
  call void @abort()
  unreachable
ok_567:
  %t568 = lshr i64 %p_6_3, 8
  %t569 = trunc i64 %t568 to i8
  %t570 = add i64 8, 1
  %t571 = extractvalue %hia.buffer %p_6_1, 0
  %t572 = extractvalue %hia.buffer %p_6_1, 1
  %t573 = icmp ult i64 %t570, %t572
  br i1 %t573, label %ok_574, label %trap_574
trap_574:
  call void @abort()
  unreachable
ok_574:
  %t575 = getelementptr i8, ptr %t571, i64 %t570
  store i8 %t569, ptr %t575, align 1
  %t576 = icmp ult i64 16, 64
  br i1 %t576, label %ok_577, label %trap_577
trap_577:
  call void @abort()
  unreachable
ok_577:
  %t578 = lshr i64 %p_6_3, 16
  %t579 = trunc i64 %t578 to i8
  %t580 = add i64 8, 2
  %t581 = extractvalue %hia.buffer %p_6_1, 0
  %t582 = extractvalue %hia.buffer %p_6_1, 1
  %t583 = icmp ult i64 %t580, %t582
  br i1 %t583, label %ok_584, label %trap_584
trap_584:
  call void @abort()
  unreachable
ok_584:
  %t585 = getelementptr i8, ptr %t581, i64 %t580
  store i8 %t579, ptr %t585, align 1
  %t586 = icmp ult i64 24, 64
  br i1 %t586, label %ok_587, label %trap_587
trap_587:
  call void @abort()
  unreachable
ok_587:
  %t588 = lshr i64 %p_6_3, 24
  %t589 = trunc i64 %t588 to i8
  %t590 = add i64 8, 3
  %t591 = extractvalue %hia.buffer %p_6_1, 0
  %t592 = extractvalue %hia.buffer %p_6_1, 1
  %t593 = icmp ult i64 %t590, %t592
  br i1 %t593, label %ok_594, label %trap_594
trap_594:
  call void @abort()
  unreachable
ok_594:
  %t595 = getelementptr i8, ptr %t591, i64 %t590
  store i8 %t589, ptr %t595, align 1
  %t596 = icmp ult i64 32, 64
  br i1 %t596, label %ok_597, label %trap_597
trap_597:
  call void @abort()
  unreachable
ok_597:
  %t598 = lshr i64 %p_6_3, 32
  %t599 = trunc i64 %t598 to i8
  %t600 = add i64 8, 4
  %t601 = extractvalue %hia.buffer %p_6_1, 0
  %t602 = extractvalue %hia.buffer %p_6_1, 1
  %t603 = icmp ult i64 %t600, %t602
  br i1 %t603, label %ok_604, label %trap_604
trap_604:
  call void @abort()
  unreachable
ok_604:
  %t605 = getelementptr i8, ptr %t601, i64 %t600
  store i8 %t599, ptr %t605, align 1
  %t606 = icmp ult i64 40, 64
  br i1 %t606, label %ok_607, label %trap_607
trap_607:
  call void @abort()
  unreachable
ok_607:
  %t608 = lshr i64 %p_6_3, 40
  %t609 = trunc i64 %t608 to i8
  %t610 = add i64 8, 5
  %t611 = extractvalue %hia.buffer %p_6_1, 0
  %t612 = extractvalue %hia.buffer %p_6_1, 1
  %t613 = icmp ult i64 %t610, %t612
  br i1 %t613, label %ok_614, label %trap_614
trap_614:
  call void @abort()
  unreachable
ok_614:
  %t615 = getelementptr i8, ptr %t611, i64 %t610
  store i8 %t609, ptr %t615, align 1
  %t616 = icmp ult i64 48, 64
  br i1 %t616, label %ok_617, label %trap_617
trap_617:
  call void @abort()
  unreachable
ok_617:
  %t618 = lshr i64 %p_6_3, 48
  %t619 = trunc i64 %t618 to i8
  %t620 = add i64 8, 6
  %t621 = extractvalue %hia.buffer %p_6_1, 0
  %t622 = extractvalue %hia.buffer %p_6_1, 1
  %t623 = icmp ult i64 %t620, %t622
  br i1 %t623, label %ok_624, label %trap_624
trap_624:
  call void @abort()
  unreachable
ok_624:
  %t625 = getelementptr i8, ptr %t621, i64 %t620
  store i8 %t619, ptr %t625, align 1
  %t626 = icmp ult i64 56, 64
  br i1 %t626, label %ok_627, label %trap_627
trap_627:
  call void @abort()
  unreachable
ok_627:
  %t628 = lshr i64 %p_6_3, 56
  %t629 = trunc i64 %t628 to i8
  %t630 = add i64 8, 7
  %t631 = extractvalue %hia.buffer %p_6_1, 0
  %t632 = extractvalue %hia.buffer %p_6_1, 1
  %t633 = icmp ult i64 %t630, %t632
  br i1 %t633, label %ok_634, label %trap_634
trap_634:
  call void @abort()
  unreachable
ok_634:
  %t635 = getelementptr i8, ptr %t631, i64 %t630
  store i8 %t629, ptr %t635, align 1
  br label %edge_6
b7:
  %p_7_0 = phi %hia.buffer [ %p_6_0, %edge_6 ]
  %p_7_1 = phi %hia.buffer [ %p_6_1, %edge_6 ]
  %p_7_2 = phi i64 [ %t475, %edge_6 ]
  %p_7_3 = phi i64 [ %p_6_3, %edge_6 ]
  %p_7_4 = phi i64 [ %p_6_4, %edge_6 ]
  %p_7_5 = phi i64 [ %p_6_5, %edge_6 ]
  %p_7_6 = phi i64 [ %p_6_6, %edge_6 ]
  %p_7_7 = phi i64 [ %p_6_7, %edge_6 ]
  %p_7_8 = phi i16 [ %p_6_8, %edge_6 ]
  %t636 = add i64 %p_7_4, %p_7_5
  %t637 = sub i64 %p_7_6, %t636
  %t638 = icmp uge i64 %t637, 8
  br i1 %t638, label %edge_7, label %edge_8
b8:
  %p_8_0 = phi %hia.buffer [ %p_7_0, %edge_7 ]
  %p_8_1 = phi %hia.buffer [ %p_7_1, %edge_7 ]
  %p_8_2 = phi i64 [ %p_7_2, %edge_7 ]
  %p_8_3 = phi i64 [ %p_7_3, %edge_7 ]
  %p_8_4 = phi i64 [ %p_7_4, %edge_7 ]
  %p_8_5 = phi i64 [ %p_7_5, %edge_7 ]
  %p_8_6 = phi i64 [ %p_7_6, %edge_7 ]
  %p_8_7 = phi i64 [ %p_7_7, %edge_7 ]
  %p_8_8 = phi i16 [ %p_7_8, %edge_7 ]
  %t639 = add i64 %p_8_4, %p_8_5
  %t640 = zext i16 %p_8_8 to i64
  %t641 = icmp ult i64 48, 64
  br i1 %t641, label %ok_642, label %trap_642
trap_642:
  call void @abort()
  unreachable
ok_642:
  %t643 = shl i64 %t640, 48
  %t644 = or i64 %t643, %p_8_2
  %t645 = icmp ult i64 56, 64
  br i1 %t645, label %ok_646, label %trap_646
trap_646:
  call void @abort()
  unreachable
ok_646:
  %t647 = lshr i64 %t644, 56
  %t648 = trunc i64 %t647 to i8
  %t649 = add i64 %t639, 0
  %t650 = extractvalue %hia.buffer %p_8_0, 0
  %t651 = extractvalue %hia.buffer %p_8_0, 1
  %t652 = icmp ult i64 %t649, %t651
  br i1 %t652, label %ok_653, label %trap_653
trap_653:
  call void @abort()
  unreachable
ok_653:
  %t654 = getelementptr i8, ptr %t650, i64 %t649
  store i8 %t648, ptr %t654, align 1
  %t655 = icmp ult i64 48, 64
  br i1 %t655, label %ok_656, label %trap_656
trap_656:
  call void @abort()
  unreachable
ok_656:
  %t657 = lshr i64 %t644, 48
  %t658 = trunc i64 %t657 to i8
  %t659 = add i64 %t639, 1
  %t660 = extractvalue %hia.buffer %p_8_0, 0
  %t661 = extractvalue %hia.buffer %p_8_0, 1
  %t662 = icmp ult i64 %t659, %t661
  br i1 %t662, label %ok_663, label %trap_663
trap_663:
  call void @abort()
  unreachable
ok_663:
  %t664 = getelementptr i8, ptr %t660, i64 %t659
  store i8 %t658, ptr %t664, align 1
  %t665 = icmp ult i64 40, 64
  br i1 %t665, label %ok_666, label %trap_666
trap_666:
  call void @abort()
  unreachable
ok_666:
  %t667 = lshr i64 %t644, 40
  %t668 = trunc i64 %t667 to i8
  %t669 = add i64 %t639, 2
  %t670 = extractvalue %hia.buffer %p_8_0, 0
  %t671 = extractvalue %hia.buffer %p_8_0, 1
  %t672 = icmp ult i64 %t669, %t671
  br i1 %t672, label %ok_673, label %trap_673
trap_673:
  call void @abort()
  unreachable
ok_673:
  %t674 = getelementptr i8, ptr %t670, i64 %t669
  store i8 %t668, ptr %t674, align 1
  %t675 = icmp ult i64 32, 64
  br i1 %t675, label %ok_676, label %trap_676
trap_676:
  call void @abort()
  unreachable
ok_676:
  %t677 = lshr i64 %t644, 32
  %t678 = trunc i64 %t677 to i8
  %t679 = add i64 %t639, 3
  %t680 = extractvalue %hia.buffer %p_8_0, 0
  %t681 = extractvalue %hia.buffer %p_8_0, 1
  %t682 = icmp ult i64 %t679, %t681
  br i1 %t682, label %ok_683, label %trap_683
trap_683:
  call void @abort()
  unreachable
ok_683:
  %t684 = getelementptr i8, ptr %t680, i64 %t679
  store i8 %t678, ptr %t684, align 1
  %t685 = icmp ult i64 24, 64
  br i1 %t685, label %ok_686, label %trap_686
trap_686:
  call void @abort()
  unreachable
ok_686:
  %t687 = lshr i64 %t644, 24
  %t688 = trunc i64 %t687 to i8
  %t689 = add i64 %t639, 4
  %t690 = extractvalue %hia.buffer %p_8_0, 0
  %t691 = extractvalue %hia.buffer %p_8_0, 1
  %t692 = icmp ult i64 %t689, %t691
  br i1 %t692, label %ok_693, label %trap_693
trap_693:
  call void @abort()
  unreachable
ok_693:
  %t694 = getelementptr i8, ptr %t690, i64 %t689
  store i8 %t688, ptr %t694, align 1
  %t695 = icmp ult i64 16, 64
  br i1 %t695, label %ok_696, label %trap_696
trap_696:
  call void @abort()
  unreachable
ok_696:
  %t697 = lshr i64 %t644, 16
  %t698 = trunc i64 %t697 to i8
  %t699 = add i64 %t639, 5
  %t700 = extractvalue %hia.buffer %p_8_0, 0
  %t701 = extractvalue %hia.buffer %p_8_0, 1
  %t702 = icmp ult i64 %t699, %t701
  br i1 %t702, label %ok_703, label %trap_703
trap_703:
  call void @abort()
  unreachable
ok_703:
  %t704 = getelementptr i8, ptr %t700, i64 %t699
  store i8 %t698, ptr %t704, align 1
  %t705 = icmp ult i64 8, 64
  br i1 %t705, label %ok_706, label %trap_706
trap_706:
  call void @abort()
  unreachable
ok_706:
  %t707 = lshr i64 %t644, 8
  %t708 = trunc i64 %t707 to i8
  %t709 = add i64 %t639, 6
  %t710 = extractvalue %hia.buffer %p_8_0, 0
  %t711 = extractvalue %hia.buffer %p_8_0, 1
  %t712 = icmp ult i64 %t709, %t711
  br i1 %t712, label %ok_713, label %trap_713
trap_713:
  call void @abort()
  unreachable
ok_713:
  %t714 = getelementptr i8, ptr %t710, i64 %t709
  store i8 %t708, ptr %t714, align 1
  %t715 = icmp ult i64 0, 64
  br i1 %t715, label %ok_716, label %trap_716
trap_716:
  call void @abort()
  unreachable
ok_716:
  %t717 = lshr i64 %t644, 0
  %t718 = trunc i64 %t717 to i8
  %t719 = add i64 %t639, 7
  %t720 = extractvalue %hia.buffer %p_8_0, 0
  %t721 = extractvalue %hia.buffer %p_8_0, 1
  %t722 = icmp ult i64 %t719, %t721
  br i1 %t722, label %ok_723, label %trap_723
trap_723:
  call void @abort()
  unreachable
ok_723:
  %t724 = getelementptr i8, ptr %t720, i64 %t719
  store i8 %t718, ptr %t724, align 1
  %t725 = add i64 %p_8_5, 8
  %t726 = icmp ult i64 0, 64
  br i1 %t726, label %ok_727, label %trap_727
trap_727:
  call void @abort()
  unreachable
ok_727:
  %t728 = lshr i64 %t725, 0
  %t729 = trunc i64 %t728 to i8
  %t730 = add i64 24, 0
  %t731 = extractvalue %hia.buffer %p_8_1, 0
  %t732 = extractvalue %hia.buffer %p_8_1, 1
  %t733 = icmp ult i64 %t730, %t732
  br i1 %t733, label %ok_734, label %trap_734
trap_734:
  call void @abort()
  unreachable
ok_734:
  %t735 = getelementptr i8, ptr %t731, i64 %t730
  store i8 %t729, ptr %t735, align 1
  %t736 = icmp ult i64 8, 64
  br i1 %t736, label %ok_737, label %trap_737
trap_737:
  call void @abort()
  unreachable
ok_737:
  %t738 = lshr i64 %t725, 8
  %t739 = trunc i64 %t738 to i8
  %t740 = add i64 24, 1
  %t741 = extractvalue %hia.buffer %p_8_1, 0
  %t742 = extractvalue %hia.buffer %p_8_1, 1
  %t743 = icmp ult i64 %t740, %t742
  br i1 %t743, label %ok_744, label %trap_744
trap_744:
  call void @abort()
  unreachable
ok_744:
  %t745 = getelementptr i8, ptr %t741, i64 %t740
  store i8 %t739, ptr %t745, align 1
  %t746 = icmp ult i64 16, 64
  br i1 %t746, label %ok_747, label %trap_747
trap_747:
  call void @abort()
  unreachable
ok_747:
  %t748 = lshr i64 %t725, 16
  %t749 = trunc i64 %t748 to i8
  %t750 = add i64 24, 2
  %t751 = extractvalue %hia.buffer %p_8_1, 0
  %t752 = extractvalue %hia.buffer %p_8_1, 1
  %t753 = icmp ult i64 %t750, %t752
  br i1 %t753, label %ok_754, label %trap_754
trap_754:
  call void @abort()
  unreachable
ok_754:
  %t755 = getelementptr i8, ptr %t751, i64 %t750
  store i8 %t749, ptr %t755, align 1
  %t756 = icmp ult i64 24, 64
  br i1 %t756, label %ok_757, label %trap_757
trap_757:
  call void @abort()
  unreachable
ok_757:
  %t758 = lshr i64 %t725, 24
  %t759 = trunc i64 %t758 to i8
  %t760 = add i64 24, 3
  %t761 = extractvalue %hia.buffer %p_8_1, 0
  %t762 = extractvalue %hia.buffer %p_8_1, 1
  %t763 = icmp ult i64 %t760, %t762
  br i1 %t763, label %ok_764, label %trap_764
trap_764:
  call void @abort()
  unreachable
ok_764:
  %t765 = getelementptr i8, ptr %t761, i64 %t760
  store i8 %t759, ptr %t765, align 1
  %t766 = icmp ult i64 32, 64
  br i1 %t766, label %ok_767, label %trap_767
trap_767:
  call void @abort()
  unreachable
ok_767:
  %t768 = lshr i64 %t725, 32
  %t769 = trunc i64 %t768 to i8
  %t770 = add i64 24, 4
  %t771 = extractvalue %hia.buffer %p_8_1, 0
  %t772 = extractvalue %hia.buffer %p_8_1, 1
  %t773 = icmp ult i64 %t770, %t772
  br i1 %t773, label %ok_774, label %trap_774
trap_774:
  call void @abort()
  unreachable
ok_774:
  %t775 = getelementptr i8, ptr %t771, i64 %t770
  store i8 %t769, ptr %t775, align 1
  %t776 = icmp ult i64 40, 64
  br i1 %t776, label %ok_777, label %trap_777
trap_777:
  call void @abort()
  unreachable
ok_777:
  %t778 = lshr i64 %t725, 40
  %t779 = trunc i64 %t778 to i8
  %t780 = add i64 24, 5
  %t781 = extractvalue %hia.buffer %p_8_1, 0
  %t782 = extractvalue %hia.buffer %p_8_1, 1
  %t783 = icmp ult i64 %t780, %t782
  br i1 %t783, label %ok_784, label %trap_784
trap_784:
  call void @abort()
  unreachable
ok_784:
  %t785 = getelementptr i8, ptr %t781, i64 %t780
  store i8 %t779, ptr %t785, align 1
  %t786 = icmp ult i64 48, 64
  br i1 %t786, label %ok_787, label %trap_787
trap_787:
  call void @abort()
  unreachable
ok_787:
  %t788 = lshr i64 %t725, 48
  %t789 = trunc i64 %t788 to i8
  %t790 = add i64 24, 6
  %t791 = extractvalue %hia.buffer %p_8_1, 0
  %t792 = extractvalue %hia.buffer %p_8_1, 1
  %t793 = icmp ult i64 %t790, %t792
  br i1 %t793, label %ok_794, label %trap_794
trap_794:
  call void @abort()
  unreachable
ok_794:
  %t795 = getelementptr i8, ptr %t791, i64 %t790
  store i8 %t789, ptr %t795, align 1
  %t796 = icmp ult i64 56, 64
  br i1 %t796, label %ok_797, label %trap_797
trap_797:
  call void @abort()
  unreachable
ok_797:
  %t798 = lshr i64 %t725, 56
  %t799 = trunc i64 %t798 to i8
  %t800 = add i64 24, 7
  %t801 = extractvalue %hia.buffer %p_8_1, 0
  %t802 = extractvalue %hia.buffer %p_8_1, 1
  %t803 = icmp ult i64 %t800, %t802
  br i1 %t803, label %ok_804, label %trap_804
trap_804:
  call void @abort()
  unreachable
ok_804:
  %t805 = getelementptr i8, ptr %t801, i64 %t800
  store i8 %t799, ptr %t805, align 1
  br label %edge_9
edge_0:
  br label %b1
edge_1:
  br label %b2
edge_2:
  br label %b5
edge_3:
  br label %b2
edge_4:
  br label %b3
edge_5:
  br label %b6
edge_6:
  br label %b7
edge_7:
  br label %b8
edge_8:
  br label %b3
edge_9:
  br label %b4
}

define i64 @ovpn_hia_packet_id_read(ptr %a0_data, i64 %a0_len, ptr %a1_data, i64 %a1_len, i32 %a2) {
entry:
  %fb1 = icmp ule i64 %a0_len, 65536
  br i1 %fb1, label %fb_ok_2, label %fb_reject_2
fb_reject_2:
  ret i64 4294967296
fb_ok_2:
  %fb3 = icmp eq i64 %a0_len, 0
  %fb4 = icmp ne ptr %a0_data, null
  %fb5 = or i1 %fb3, %fb4
  br i1 %fb5, label %fb_ok_6, label %fb_reject_6
fb_reject_6:
  ret i64 8589934592
fb_ok_6:
  %fb7 = ptrtoint ptr %a0_data to i64
  %fb8 = add i64 %fb7, %a0_len
  %fb9 = icmp uge i64 %fb8, %fb7
  br i1 %fb9, label %fb_ok_10, label %fb_reject_10
fb_reject_10:
  ret i64 12884901888
fb_ok_10:
  %fb11 = icmp ule i64 %a1_len, 65536
  br i1 %fb11, label %fb_ok_12, label %fb_reject_12
fb_reject_12:
  ret i64 4294967296
fb_ok_12:
  %fb13 = icmp eq i64 %a1_len, 0
  %fb14 = icmp ne ptr %a1_data, null
  %fb15 = or i1 %fb13, %fb14
  br i1 %fb15, label %fb_ok_16, label %fb_reject_16
fb_reject_16:
  ret i64 8589934592
fb_ok_16:
  %fb17 = ptrtoint ptr %a1_data to i64
  %fb18 = add i64 %fb17, %a1_len
  %fb19 = icmp uge i64 %fb18, %fb17
  br i1 %fb19, label %fb_ok_20, label %fb_reject_20
fb_reject_20:
  ret i64 12884901888
fb_ok_20:
  %fb21 = icmp ule i64 %fb8, %fb17
  %fb22 = icmp ule i64 %fb18, %fb7
  %fb23 = or i1 %fb21, %fb22
  %fb24 = or i1 %fb3, %fb13
  %fb25 = or i1 %fb23, %fb24
  br i1 %fb25, label %fb_ok_26, label %fb_reject_26
fb_reject_26:
  ret i64 17179869184
fb_ok_26:
  %fb27 = insertvalue %hia.buffer zeroinitializer, ptr %a0_data, 0
  %fb28 = insertvalue %hia.buffer %fb27, i64 %a0_len, 1
  %fb29 = insertvalue %hia.buffer zeroinitializer, ptr %a1_data, 0
  %fb30 = insertvalue %hia.buffer %fb29, i64 %a1_len, 1
  %fb31 = call i32 @__hia_fn_0(%hia.buffer %fb28, %hia.buffer %fb30, i32 %a2)
  %fb32 = zext i32 %fb31 to i64
  ret i64 %fb32
}

define i64 @ovpn_hia_packet_id_write(ptr %a0_data, i64 %a0_len, ptr %a1_data, i64 %a1_len, i64 %a2, i32 %a3, i32 %a4) {
entry:
  %fb1 = icmp ule i64 %a0_len, 65536
  br i1 %fb1, label %fb_ok_2, label %fb_reject_2
fb_reject_2:
  ret i64 4294967296
fb_ok_2:
  %fb3 = icmp eq i64 %a0_len, 0
  %fb4 = icmp ne ptr %a0_data, null
  %fb5 = or i1 %fb3, %fb4
  br i1 %fb5, label %fb_ok_6, label %fb_reject_6
fb_reject_6:
  ret i64 8589934592
fb_ok_6:
  %fb7 = ptrtoint ptr %a0_data to i64
  %fb8 = add i64 %fb7, %a0_len
  %fb9 = icmp uge i64 %fb8, %fb7
  br i1 %fb9, label %fb_ok_10, label %fb_reject_10
fb_reject_10:
  ret i64 12884901888
fb_ok_10:
  %fb11 = icmp ule i64 %a1_len, 65536
  br i1 %fb11, label %fb_ok_12, label %fb_reject_12
fb_reject_12:
  ret i64 4294967296
fb_ok_12:
  %fb13 = icmp eq i64 %a1_len, 0
  %fb14 = icmp ne ptr %a1_data, null
  %fb15 = or i1 %fb13, %fb14
  br i1 %fb15, label %fb_ok_16, label %fb_reject_16
fb_reject_16:
  ret i64 8589934592
fb_ok_16:
  %fb17 = ptrtoint ptr %a1_data to i64
  %fb18 = add i64 %fb17, %a1_len
  %fb19 = icmp uge i64 %fb18, %fb17
  br i1 %fb19, label %fb_ok_20, label %fb_reject_20
fb_reject_20:
  ret i64 12884901888
fb_ok_20:
  %fb21 = icmp ule i64 %fb8, %fb17
  %fb22 = icmp ule i64 %fb18, %fb7
  %fb23 = or i1 %fb21, %fb22
  %fb24 = or i1 %fb3, %fb13
  %fb25 = or i1 %fb23, %fb24
  br i1 %fb25, label %fb_ok_26, label %fb_reject_26
fb_reject_26:
  ret i64 17179869184
fb_ok_26:
  %fb27 = insertvalue %hia.buffer zeroinitializer, ptr %a0_data, 0
  %fb28 = insertvalue %hia.buffer %fb27, i64 %a0_len, 1
  %fb29 = insertvalue %hia.buffer zeroinitializer, ptr %a1_data, 0
  %fb30 = insertvalue %hia.buffer %fb29, i64 %a1_len, 1
  %fb31 = call i32 @__hia_fn_1(%hia.buffer %fb28, %hia.buffer %fb30, i64 %a2, i32 %a3, i32 %a4)
  %fb32 = zext i32 %fb31 to i64
  ret i64 %fb32
}

define i64 @ovpn_hia_packet_id_read_epoch(ptr %a0_data, i64 %a0_len, ptr %a1_data, i64 %a1_len) {
entry:
  %fb1 = icmp ule i64 %a0_len, 65536
  br i1 %fb1, label %fb_ok_2, label %fb_reject_2
fb_reject_2:
  ret i64 4294967296
fb_ok_2:
  %fb3 = icmp eq i64 %a0_len, 0
  %fb4 = icmp ne ptr %a0_data, null
  %fb5 = or i1 %fb3, %fb4
  br i1 %fb5, label %fb_ok_6, label %fb_reject_6
fb_reject_6:
  ret i64 8589934592
fb_ok_6:
  %fb7 = ptrtoint ptr %a0_data to i64
  %fb8 = add i64 %fb7, %a0_len
  %fb9 = icmp uge i64 %fb8, %fb7
  br i1 %fb9, label %fb_ok_10, label %fb_reject_10
fb_reject_10:
  ret i64 12884901888
fb_ok_10:
  %fb11 = icmp ule i64 %a1_len, 65536
  br i1 %fb11, label %fb_ok_12, label %fb_reject_12
fb_reject_12:
  ret i64 4294967296
fb_ok_12:
  %fb13 = icmp eq i64 %a1_len, 0
  %fb14 = icmp ne ptr %a1_data, null
  %fb15 = or i1 %fb13, %fb14
  br i1 %fb15, label %fb_ok_16, label %fb_reject_16
fb_reject_16:
  ret i64 8589934592
fb_ok_16:
  %fb17 = ptrtoint ptr %a1_data to i64
  %fb18 = add i64 %fb17, %a1_len
  %fb19 = icmp uge i64 %fb18, %fb17
  br i1 %fb19, label %fb_ok_20, label %fb_reject_20
fb_reject_20:
  ret i64 12884901888
fb_ok_20:
  %fb21 = icmp ule i64 %fb8, %fb17
  %fb22 = icmp ule i64 %fb18, %fb7
  %fb23 = or i1 %fb21, %fb22
  %fb24 = or i1 %fb3, %fb13
  %fb25 = or i1 %fb23, %fb24
  br i1 %fb25, label %fb_ok_26, label %fb_reject_26
fb_reject_26:
  ret i64 17179869184
fb_ok_26:
  %fb27 = insertvalue %hia.buffer zeroinitializer, ptr %a0_data, 0
  %fb28 = insertvalue %hia.buffer %fb27, i64 %a0_len, 1
  %fb29 = insertvalue %hia.buffer zeroinitializer, ptr %a1_data, 0
  %fb30 = insertvalue %hia.buffer %fb29, i64 %a1_len, 1
  %fb31 = call i32 @__hia_fn_2(%hia.buffer %fb28, %hia.buffer %fb30)
  %fb32 = zext i32 %fb31 to i64
  ret i64 %fb32
}

define i64 @ovpn_hia_packet_id_write_epoch(ptr %a0_data, i64 %a0_len, ptr %a1_data, i64 %a1_len, i64 %a2, i16 zeroext %a3) {
entry:
  %fb1 = icmp ule i64 %a0_len, 65536
  br i1 %fb1, label %fb_ok_2, label %fb_reject_2
fb_reject_2:
  ret i64 4294967296
fb_ok_2:
  %fb3 = icmp eq i64 %a0_len, 0
  %fb4 = icmp ne ptr %a0_data, null
  %fb5 = or i1 %fb3, %fb4
  br i1 %fb5, label %fb_ok_6, label %fb_reject_6
fb_reject_6:
  ret i64 8589934592
fb_ok_6:
  %fb7 = ptrtoint ptr %a0_data to i64
  %fb8 = add i64 %fb7, %a0_len
  %fb9 = icmp uge i64 %fb8, %fb7
  br i1 %fb9, label %fb_ok_10, label %fb_reject_10
fb_reject_10:
  ret i64 12884901888
fb_ok_10:
  %fb11 = icmp ule i64 %a1_len, 65536
  br i1 %fb11, label %fb_ok_12, label %fb_reject_12
fb_reject_12:
  ret i64 4294967296
fb_ok_12:
  %fb13 = icmp eq i64 %a1_len, 0
  %fb14 = icmp ne ptr %a1_data, null
  %fb15 = or i1 %fb13, %fb14
  br i1 %fb15, label %fb_ok_16, label %fb_reject_16
fb_reject_16:
  ret i64 8589934592
fb_ok_16:
  %fb17 = ptrtoint ptr %a1_data to i64
  %fb18 = add i64 %fb17, %a1_len
  %fb19 = icmp uge i64 %fb18, %fb17
  br i1 %fb19, label %fb_ok_20, label %fb_reject_20
fb_reject_20:
  ret i64 12884901888
fb_ok_20:
  %fb21 = icmp ule i64 %fb8, %fb17
  %fb22 = icmp ule i64 %fb18, %fb7
  %fb23 = or i1 %fb21, %fb22
  %fb24 = or i1 %fb3, %fb13
  %fb25 = or i1 %fb23, %fb24
  br i1 %fb25, label %fb_ok_26, label %fb_reject_26
fb_reject_26:
  ret i64 17179869184
fb_ok_26:
  %fb27 = insertvalue %hia.buffer zeroinitializer, ptr %a0_data, 0
  %fb28 = insertvalue %hia.buffer %fb27, i64 %a0_len, 1
  %fb29 = insertvalue %hia.buffer zeroinitializer, ptr %a1_data, 0
  %fb30 = insertvalue %hia.buffer %fb29, i64 %a1_len, 1
  %fb31 = call i32 @__hia_fn_3(%hia.buffer %fb28, %hia.buffer %fb30, i64 %a2, i16 %a3)
  %fb32 = zext i32 %fb31 to i64
  ret i64 %fb32
}
