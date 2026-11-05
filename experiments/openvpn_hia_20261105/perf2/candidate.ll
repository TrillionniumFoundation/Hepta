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

define internal i32 @__hia_fn_0(%hia.buffer %p_0_0, %hia.buffer %p_0_1, i32 %p_0_2) alwaysinline {
b0:
  %t1 = extractvalue %hia.buffer %p_0_1, 1
  %t2 = icmp eq i64 %t1, 32
  %t3 = extractvalue %hia.buffer %p_0_0, 1
  %t4 = icmp ule i64 %t3, 65536
  %t5 = and i1 %t2, %t4
  %t6 = icmp ule i32 %p_0_2, 1
  %t7 = and i1 %t5, %t6
  br i1 %t7, label %edge_0, label %edge_1
b1:
  %p_1_0 = phi %hia.buffer [ %p_0_0, %edge_0 ]
  %p_1_1 = phi %hia.buffer [ %p_0_1, %edge_0 ]
  %p_1_2 = phi i32 [ %p_0_2, %edge_0 ]
  %t8 = trunc i64 0 to i32
  %t9 = zext i32 %t8 to i64
  %t10 = add i64 %t9, 7
  %t11 = extractvalue %hia.buffer %p_1_1, 0
  %t12 = extractvalue %hia.buffer %p_1_1, 1
  %t13 = icmp ult i64 %t10, %t12
  br i1 %t13, label %ok_14, label %trap_14
trap_14:
  call void @abort()
  unreachable
ok_14:
  %t15 = getelementptr i8, ptr %t11, i64 %t10
  %t16 = load i8, ptr %t15, align 1
  %t17 = zext i8 %t16 to i64
  %t18 = icmp ult i64 56, 64
  br i1 %t18, label %ok_19, label %trap_19
trap_19:
  call void @abort()
  unreachable
ok_19:
  %t20 = shl i64 %t17, 56
  %t21 = or i64 0, %t20
  %t22 = add i64 %t9, 6
  %t23 = extractvalue %hia.buffer %p_1_1, 0
  %t24 = extractvalue %hia.buffer %p_1_1, 1
  %t25 = icmp ult i64 %t22, %t24
  br i1 %t25, label %ok_26, label %trap_26
trap_26:
  call void @abort()
  unreachable
ok_26:
  %t27 = getelementptr i8, ptr %t23, i64 %t22
  %t28 = load i8, ptr %t27, align 1
  %t29 = zext i8 %t28 to i64
  %t30 = icmp ult i64 48, 64
  br i1 %t30, label %ok_31, label %trap_31
trap_31:
  call void @abort()
  unreachable
ok_31:
  %t32 = shl i64 %t29, 48
  %t33 = or i64 %t21, %t32
  %t34 = add i64 %t9, 5
  %t35 = extractvalue %hia.buffer %p_1_1, 0
  %t36 = extractvalue %hia.buffer %p_1_1, 1
  %t37 = icmp ult i64 %t34, %t36
  br i1 %t37, label %ok_38, label %trap_38
trap_38:
  call void @abort()
  unreachable
ok_38:
  %t39 = getelementptr i8, ptr %t35, i64 %t34
  %t40 = load i8, ptr %t39, align 1
  %t41 = zext i8 %t40 to i64
  %t42 = icmp ult i64 40, 64
  br i1 %t42, label %ok_43, label %trap_43
trap_43:
  call void @abort()
  unreachable
ok_43:
  %t44 = shl i64 %t41, 40
  %t45 = or i64 %t33, %t44
  %t46 = add i64 %t9, 4
  %t47 = extractvalue %hia.buffer %p_1_1, 0
  %t48 = extractvalue %hia.buffer %p_1_1, 1
  %t49 = icmp ult i64 %t46, %t48
  br i1 %t49, label %ok_50, label %trap_50
trap_50:
  call void @abort()
  unreachable
ok_50:
  %t51 = getelementptr i8, ptr %t47, i64 %t46
  %t52 = load i8, ptr %t51, align 1
  %t53 = zext i8 %t52 to i64
  %t54 = icmp ult i64 32, 64
  br i1 %t54, label %ok_55, label %trap_55
trap_55:
  call void @abort()
  unreachable
ok_55:
  %t56 = shl i64 %t53, 32
  %t57 = or i64 %t45, %t56
  %t58 = add i64 %t9, 3
  %t59 = extractvalue %hia.buffer %p_1_1, 0
  %t60 = extractvalue %hia.buffer %p_1_1, 1
  %t61 = icmp ult i64 %t58, %t60
  br i1 %t61, label %ok_62, label %trap_62
trap_62:
  call void @abort()
  unreachable
ok_62:
  %t63 = getelementptr i8, ptr %t59, i64 %t58
  %t64 = load i8, ptr %t63, align 1
  %t65 = zext i8 %t64 to i64
  %t66 = icmp ult i64 24, 64
  br i1 %t66, label %ok_67, label %trap_67
trap_67:
  call void @abort()
  unreachable
ok_67:
  %t68 = shl i64 %t65, 24
  %t69 = or i64 %t57, %t68
  %t70 = add i64 %t9, 2
  %t71 = extractvalue %hia.buffer %p_1_1, 0
  %t72 = extractvalue %hia.buffer %p_1_1, 1
  %t73 = icmp ult i64 %t70, %t72
  br i1 %t73, label %ok_74, label %trap_74
trap_74:
  call void @abort()
  unreachable
ok_74:
  %t75 = getelementptr i8, ptr %t71, i64 %t70
  %t76 = load i8, ptr %t75, align 1
  %t77 = zext i8 %t76 to i64
  %t78 = icmp ult i64 16, 64
  br i1 %t78, label %ok_79, label %trap_79
trap_79:
  call void @abort()
  unreachable
ok_79:
  %t80 = shl i64 %t77, 16
  %t81 = or i64 %t69, %t80
  %t82 = add i64 %t9, 1
  %t83 = extractvalue %hia.buffer %p_1_1, 0
  %t84 = extractvalue %hia.buffer %p_1_1, 1
  %t85 = icmp ult i64 %t82, %t84
  br i1 %t85, label %ok_86, label %trap_86
trap_86:
  call void @abort()
  unreachable
ok_86:
  %t87 = getelementptr i8, ptr %t83, i64 %t82
  %t88 = load i8, ptr %t87, align 1
  %t89 = zext i8 %t88 to i64
  %t90 = icmp ult i64 8, 64
  br i1 %t90, label %ok_91, label %trap_91
trap_91:
  call void @abort()
  unreachable
ok_91:
  %t92 = shl i64 %t89, 8
  %t93 = or i64 %t81, %t92
  %t94 = add i64 %t9, 0
  %t95 = extractvalue %hia.buffer %p_1_1, 0
  %t96 = extractvalue %hia.buffer %p_1_1, 1
  %t97 = icmp ult i64 %t94, %t96
  br i1 %t97, label %ok_98, label %trap_98
trap_98:
  call void @abort()
  unreachable
ok_98:
  %t99 = getelementptr i8, ptr %t95, i64 %t94
  %t100 = load i8, ptr %t99, align 1
  %t101 = zext i8 %t100 to i64
  %t102 = icmp ult i64 0, 64
  br i1 %t102, label %ok_103, label %trap_103
trap_103:
  call void @abort()
  unreachable
ok_103:
  %t104 = shl i64 %t101, 0
  %t105 = or i64 %t93, %t104
  %t106 = trunc i64 8 to i32
  %t107 = zext i32 %t106 to i64
  %t108 = add i64 %t107, 7
  %t109 = extractvalue %hia.buffer %p_1_1, 0
  %t110 = extractvalue %hia.buffer %p_1_1, 1
  %t111 = icmp ult i64 %t108, %t110
  br i1 %t111, label %ok_112, label %trap_112
trap_112:
  call void @abort()
  unreachable
ok_112:
  %t113 = getelementptr i8, ptr %t109, i64 %t108
  %t114 = load i8, ptr %t113, align 1
  %t115 = zext i8 %t114 to i64
  %t116 = icmp ult i64 56, 64
  br i1 %t116, label %ok_117, label %trap_117
trap_117:
  call void @abort()
  unreachable
ok_117:
  %t118 = shl i64 %t115, 56
  %t119 = or i64 0, %t118
  %t120 = add i64 %t107, 6
  %t121 = extractvalue %hia.buffer %p_1_1, 0
  %t122 = extractvalue %hia.buffer %p_1_1, 1
  %t123 = icmp ult i64 %t120, %t122
  br i1 %t123, label %ok_124, label %trap_124
trap_124:
  call void @abort()
  unreachable
ok_124:
  %t125 = getelementptr i8, ptr %t121, i64 %t120
  %t126 = load i8, ptr %t125, align 1
  %t127 = zext i8 %t126 to i64
  %t128 = icmp ult i64 48, 64
  br i1 %t128, label %ok_129, label %trap_129
trap_129:
  call void @abort()
  unreachable
ok_129:
  %t130 = shl i64 %t127, 48
  %t131 = or i64 %t119, %t130
  %t132 = add i64 %t107, 5
  %t133 = extractvalue %hia.buffer %p_1_1, 0
  %t134 = extractvalue %hia.buffer %p_1_1, 1
  %t135 = icmp ult i64 %t132, %t134
  br i1 %t135, label %ok_136, label %trap_136
trap_136:
  call void @abort()
  unreachable
ok_136:
  %t137 = getelementptr i8, ptr %t133, i64 %t132
  %t138 = load i8, ptr %t137, align 1
  %t139 = zext i8 %t138 to i64
  %t140 = icmp ult i64 40, 64
  br i1 %t140, label %ok_141, label %trap_141
trap_141:
  call void @abort()
  unreachable
ok_141:
  %t142 = shl i64 %t139, 40
  %t143 = or i64 %t131, %t142
  %t144 = add i64 %t107, 4
  %t145 = extractvalue %hia.buffer %p_1_1, 0
  %t146 = extractvalue %hia.buffer %p_1_1, 1
  %t147 = icmp ult i64 %t144, %t146
  br i1 %t147, label %ok_148, label %trap_148
trap_148:
  call void @abort()
  unreachable
ok_148:
  %t149 = getelementptr i8, ptr %t145, i64 %t144
  %t150 = load i8, ptr %t149, align 1
  %t151 = zext i8 %t150 to i64
  %t152 = icmp ult i64 32, 64
  br i1 %t152, label %ok_153, label %trap_153
trap_153:
  call void @abort()
  unreachable
ok_153:
  %t154 = shl i64 %t151, 32
  %t155 = or i64 %t143, %t154
  %t156 = add i64 %t107, 3
  %t157 = extractvalue %hia.buffer %p_1_1, 0
  %t158 = extractvalue %hia.buffer %p_1_1, 1
  %t159 = icmp ult i64 %t156, %t158
  br i1 %t159, label %ok_160, label %trap_160
trap_160:
  call void @abort()
  unreachable
ok_160:
  %t161 = getelementptr i8, ptr %t157, i64 %t156
  %t162 = load i8, ptr %t161, align 1
  %t163 = zext i8 %t162 to i64
  %t164 = icmp ult i64 24, 64
  br i1 %t164, label %ok_165, label %trap_165
trap_165:
  call void @abort()
  unreachable
ok_165:
  %t166 = shl i64 %t163, 24
  %t167 = or i64 %t155, %t166
  %t168 = add i64 %t107, 2
  %t169 = extractvalue %hia.buffer %p_1_1, 0
  %t170 = extractvalue %hia.buffer %p_1_1, 1
  %t171 = icmp ult i64 %t168, %t170
  br i1 %t171, label %ok_172, label %trap_172
trap_172:
  call void @abort()
  unreachable
ok_172:
  %t173 = getelementptr i8, ptr %t169, i64 %t168
  %t174 = load i8, ptr %t173, align 1
  %t175 = zext i8 %t174 to i64
  %t176 = icmp ult i64 16, 64
  br i1 %t176, label %ok_177, label %trap_177
trap_177:
  call void @abort()
  unreachable
ok_177:
  %t178 = shl i64 %t175, 16
  %t179 = or i64 %t167, %t178
  %t180 = add i64 %t107, 1
  %t181 = extractvalue %hia.buffer %p_1_1, 0
  %t182 = extractvalue %hia.buffer %p_1_1, 1
  %t183 = icmp ult i64 %t180, %t182
  br i1 %t183, label %ok_184, label %trap_184
trap_184:
  call void @abort()
  unreachable
ok_184:
  %t185 = getelementptr i8, ptr %t181, i64 %t180
  %t186 = load i8, ptr %t185, align 1
  %t187 = zext i8 %t186 to i64
  %t188 = icmp ult i64 8, 64
  br i1 %t188, label %ok_189, label %trap_189
trap_189:
  call void @abort()
  unreachable
ok_189:
  %t190 = shl i64 %t187, 8
  %t191 = or i64 %t179, %t190
  %t192 = add i64 %t107, 0
  %t193 = extractvalue %hia.buffer %p_1_1, 0
  %t194 = extractvalue %hia.buffer %p_1_1, 1
  %t195 = icmp ult i64 %t192, %t194
  br i1 %t195, label %ok_196, label %trap_196
trap_196:
  call void @abort()
  unreachable
ok_196:
  %t197 = getelementptr i8, ptr %t193, i64 %t192
  %t198 = load i8, ptr %t197, align 1
  %t199 = zext i8 %t198 to i64
  %t200 = icmp ult i64 0, 64
  br i1 %t200, label %ok_201, label %trap_201
trap_201:
  call void @abort()
  unreachable
ok_201:
  %t202 = shl i64 %t199, 0
  %t203 = or i64 %t191, %t202
  %t204 = trunc i64 16 to i32
  %t205 = zext i32 %t204 to i64
  %t206 = add i64 %t205, 7
  %t207 = extractvalue %hia.buffer %p_1_1, 0
  %t208 = extractvalue %hia.buffer %p_1_1, 1
  %t209 = icmp ult i64 %t206, %t208
  br i1 %t209, label %ok_210, label %trap_210
trap_210:
  call void @abort()
  unreachable
ok_210:
  %t211 = getelementptr i8, ptr %t207, i64 %t206
  %t212 = load i8, ptr %t211, align 1
  %t213 = zext i8 %t212 to i64
  %t214 = icmp ult i64 56, 64
  br i1 %t214, label %ok_215, label %trap_215
trap_215:
  call void @abort()
  unreachable
ok_215:
  %t216 = shl i64 %t213, 56
  %t217 = or i64 0, %t216
  %t218 = add i64 %t205, 6
  %t219 = extractvalue %hia.buffer %p_1_1, 0
  %t220 = extractvalue %hia.buffer %p_1_1, 1
  %t221 = icmp ult i64 %t218, %t220
  br i1 %t221, label %ok_222, label %trap_222
trap_222:
  call void @abort()
  unreachable
ok_222:
  %t223 = getelementptr i8, ptr %t219, i64 %t218
  %t224 = load i8, ptr %t223, align 1
  %t225 = zext i8 %t224 to i64
  %t226 = icmp ult i64 48, 64
  br i1 %t226, label %ok_227, label %trap_227
trap_227:
  call void @abort()
  unreachable
ok_227:
  %t228 = shl i64 %t225, 48
  %t229 = or i64 %t217, %t228
  %t230 = add i64 %t205, 5
  %t231 = extractvalue %hia.buffer %p_1_1, 0
  %t232 = extractvalue %hia.buffer %p_1_1, 1
  %t233 = icmp ult i64 %t230, %t232
  br i1 %t233, label %ok_234, label %trap_234
trap_234:
  call void @abort()
  unreachable
ok_234:
  %t235 = getelementptr i8, ptr %t231, i64 %t230
  %t236 = load i8, ptr %t235, align 1
  %t237 = zext i8 %t236 to i64
  %t238 = icmp ult i64 40, 64
  br i1 %t238, label %ok_239, label %trap_239
trap_239:
  call void @abort()
  unreachable
ok_239:
  %t240 = shl i64 %t237, 40
  %t241 = or i64 %t229, %t240
  %t242 = add i64 %t205, 4
  %t243 = extractvalue %hia.buffer %p_1_1, 0
  %t244 = extractvalue %hia.buffer %p_1_1, 1
  %t245 = icmp ult i64 %t242, %t244
  br i1 %t245, label %ok_246, label %trap_246
trap_246:
  call void @abort()
  unreachable
ok_246:
  %t247 = getelementptr i8, ptr %t243, i64 %t242
  %t248 = load i8, ptr %t247, align 1
  %t249 = zext i8 %t248 to i64
  %t250 = icmp ult i64 32, 64
  br i1 %t250, label %ok_251, label %trap_251
trap_251:
  call void @abort()
  unreachable
ok_251:
  %t252 = shl i64 %t249, 32
  %t253 = or i64 %t241, %t252
  %t254 = add i64 %t205, 3
  %t255 = extractvalue %hia.buffer %p_1_1, 0
  %t256 = extractvalue %hia.buffer %p_1_1, 1
  %t257 = icmp ult i64 %t254, %t256
  br i1 %t257, label %ok_258, label %trap_258
trap_258:
  call void @abort()
  unreachable
ok_258:
  %t259 = getelementptr i8, ptr %t255, i64 %t254
  %t260 = load i8, ptr %t259, align 1
  %t261 = zext i8 %t260 to i64
  %t262 = icmp ult i64 24, 64
  br i1 %t262, label %ok_263, label %trap_263
trap_263:
  call void @abort()
  unreachable
ok_263:
  %t264 = shl i64 %t261, 24
  %t265 = or i64 %t253, %t264
  %t266 = add i64 %t205, 2
  %t267 = extractvalue %hia.buffer %p_1_1, 0
  %t268 = extractvalue %hia.buffer %p_1_1, 1
  %t269 = icmp ult i64 %t266, %t268
  br i1 %t269, label %ok_270, label %trap_270
trap_270:
  call void @abort()
  unreachable
ok_270:
  %t271 = getelementptr i8, ptr %t267, i64 %t266
  %t272 = load i8, ptr %t271, align 1
  %t273 = zext i8 %t272 to i64
  %t274 = icmp ult i64 16, 64
  br i1 %t274, label %ok_275, label %trap_275
trap_275:
  call void @abort()
  unreachable
ok_275:
  %t276 = shl i64 %t273, 16
  %t277 = or i64 %t265, %t276
  %t278 = add i64 %t205, 1
  %t279 = extractvalue %hia.buffer %p_1_1, 0
  %t280 = extractvalue %hia.buffer %p_1_1, 1
  %t281 = icmp ult i64 %t278, %t280
  br i1 %t281, label %ok_282, label %trap_282
trap_282:
  call void @abort()
  unreachable
ok_282:
  %t283 = getelementptr i8, ptr %t279, i64 %t278
  %t284 = load i8, ptr %t283, align 1
  %t285 = zext i8 %t284 to i64
  %t286 = icmp ult i64 8, 64
  br i1 %t286, label %ok_287, label %trap_287
trap_287:
  call void @abort()
  unreachable
ok_287:
  %t288 = shl i64 %t285, 8
  %t289 = or i64 %t277, %t288
  %t290 = add i64 %t205, 0
  %t291 = extractvalue %hia.buffer %p_1_1, 0
  %t292 = extractvalue %hia.buffer %p_1_1, 1
  %t293 = icmp ult i64 %t290, %t292
  br i1 %t293, label %ok_294, label %trap_294
trap_294:
  call void @abort()
  unreachable
ok_294:
  %t295 = getelementptr i8, ptr %t291, i64 %t290
  %t296 = load i8, ptr %t295, align 1
  %t297 = zext i8 %t296 to i64
  %t298 = icmp ult i64 0, 64
  br i1 %t298, label %ok_299, label %trap_299
trap_299:
  call void @abort()
  unreachable
ok_299:
  %t300 = shl i64 %t297, 0
  %t301 = or i64 %t289, %t300
  %t302 = trunc i64 24 to i32
  %t303 = zext i32 %t302 to i64
  %t304 = add i64 %t303, 7
  %t305 = extractvalue %hia.buffer %p_1_1, 0
  %t306 = extractvalue %hia.buffer %p_1_1, 1
  %t307 = icmp ult i64 %t304, %t306
  br i1 %t307, label %ok_308, label %trap_308
trap_308:
  call void @abort()
  unreachable
ok_308:
  %t309 = getelementptr i8, ptr %t305, i64 %t304
  %t310 = load i8, ptr %t309, align 1
  %t311 = zext i8 %t310 to i64
  %t312 = icmp ult i64 56, 64
  br i1 %t312, label %ok_313, label %trap_313
trap_313:
  call void @abort()
  unreachable
ok_313:
  %t314 = shl i64 %t311, 56
  %t315 = or i64 0, %t314
  %t316 = add i64 %t303, 6
  %t317 = extractvalue %hia.buffer %p_1_1, 0
  %t318 = extractvalue %hia.buffer %p_1_1, 1
  %t319 = icmp ult i64 %t316, %t318
  br i1 %t319, label %ok_320, label %trap_320
trap_320:
  call void @abort()
  unreachable
ok_320:
  %t321 = getelementptr i8, ptr %t317, i64 %t316
  %t322 = load i8, ptr %t321, align 1
  %t323 = zext i8 %t322 to i64
  %t324 = icmp ult i64 48, 64
  br i1 %t324, label %ok_325, label %trap_325
trap_325:
  call void @abort()
  unreachable
ok_325:
  %t326 = shl i64 %t323, 48
  %t327 = or i64 %t315, %t326
  %t328 = add i64 %t303, 5
  %t329 = extractvalue %hia.buffer %p_1_1, 0
  %t330 = extractvalue %hia.buffer %p_1_1, 1
  %t331 = icmp ult i64 %t328, %t330
  br i1 %t331, label %ok_332, label %trap_332
trap_332:
  call void @abort()
  unreachable
ok_332:
  %t333 = getelementptr i8, ptr %t329, i64 %t328
  %t334 = load i8, ptr %t333, align 1
  %t335 = zext i8 %t334 to i64
  %t336 = icmp ult i64 40, 64
  br i1 %t336, label %ok_337, label %trap_337
trap_337:
  call void @abort()
  unreachable
ok_337:
  %t338 = shl i64 %t335, 40
  %t339 = or i64 %t327, %t338
  %t340 = add i64 %t303, 4
  %t341 = extractvalue %hia.buffer %p_1_1, 0
  %t342 = extractvalue %hia.buffer %p_1_1, 1
  %t343 = icmp ult i64 %t340, %t342
  br i1 %t343, label %ok_344, label %trap_344
trap_344:
  call void @abort()
  unreachable
ok_344:
  %t345 = getelementptr i8, ptr %t341, i64 %t340
  %t346 = load i8, ptr %t345, align 1
  %t347 = zext i8 %t346 to i64
  %t348 = icmp ult i64 32, 64
  br i1 %t348, label %ok_349, label %trap_349
trap_349:
  call void @abort()
  unreachable
ok_349:
  %t350 = shl i64 %t347, 32
  %t351 = or i64 %t339, %t350
  %t352 = add i64 %t303, 3
  %t353 = extractvalue %hia.buffer %p_1_1, 0
  %t354 = extractvalue %hia.buffer %p_1_1, 1
  %t355 = icmp ult i64 %t352, %t354
  br i1 %t355, label %ok_356, label %trap_356
trap_356:
  call void @abort()
  unreachable
ok_356:
  %t357 = getelementptr i8, ptr %t353, i64 %t352
  %t358 = load i8, ptr %t357, align 1
  %t359 = zext i8 %t358 to i64
  %t360 = icmp ult i64 24, 64
  br i1 %t360, label %ok_361, label %trap_361
trap_361:
  call void @abort()
  unreachable
ok_361:
  %t362 = shl i64 %t359, 24
  %t363 = or i64 %t351, %t362
  %t364 = add i64 %t303, 2
  %t365 = extractvalue %hia.buffer %p_1_1, 0
  %t366 = extractvalue %hia.buffer %p_1_1, 1
  %t367 = icmp ult i64 %t364, %t366
  br i1 %t367, label %ok_368, label %trap_368
trap_368:
  call void @abort()
  unreachable
ok_368:
  %t369 = getelementptr i8, ptr %t365, i64 %t364
  %t370 = load i8, ptr %t369, align 1
  %t371 = zext i8 %t370 to i64
  %t372 = icmp ult i64 16, 64
  br i1 %t372, label %ok_373, label %trap_373
trap_373:
  call void @abort()
  unreachable
ok_373:
  %t374 = shl i64 %t371, 16
  %t375 = or i64 %t363, %t374
  %t376 = add i64 %t303, 1
  %t377 = extractvalue %hia.buffer %p_1_1, 0
  %t378 = extractvalue %hia.buffer %p_1_1, 1
  %t379 = icmp ult i64 %t376, %t378
  br i1 %t379, label %ok_380, label %trap_380
trap_380:
  call void @abort()
  unreachable
ok_380:
  %t381 = getelementptr i8, ptr %t377, i64 %t376
  %t382 = load i8, ptr %t381, align 1
  %t383 = zext i8 %t382 to i64
  %t384 = icmp ult i64 8, 64
  br i1 %t384, label %ok_385, label %trap_385
trap_385:
  call void @abort()
  unreachable
ok_385:
  %t386 = shl i64 %t383, 8
  %t387 = or i64 %t375, %t386
  %t388 = add i64 %t303, 0
  %t389 = extractvalue %hia.buffer %p_1_1, 0
  %t390 = extractvalue %hia.buffer %p_1_1, 1
  %t391 = icmp ult i64 %t388, %t390
  br i1 %t391, label %ok_392, label %trap_392
trap_392:
  call void @abort()
  unreachable
ok_392:
  %t393 = getelementptr i8, ptr %t389, i64 %t388
  %t394 = load i8, ptr %t393, align 1
  %t395 = zext i8 %t394 to i64
  %t396 = icmp ult i64 0, 64
  br i1 %t396, label %ok_397, label %trap_397
trap_397:
  call void @abort()
  unreachable
ok_397:
  %t398 = shl i64 %t395, 0
  %t399 = or i64 %t387, %t398
  %t400 = extractvalue %hia.buffer %p_1_0, 1
  %t401 = icmp ule i64 %t301, %t400
  %t402 = sub i64 %t400, %t301
  %t403 = icmp ule i64 %t399, %t402
  %t404 = and i1 %t401, %t403
  br i1 %t404, label %edge_2, label %edge_3
b2:
  ret i32 4294836225
b3:
  ret i32 0
b4:
  ret i32 1
b5:
  %p_5_0 = phi %hia.buffer [ %p_1_0, %edge_2 ]
  %p_5_1 = phi %hia.buffer [ %p_1_1, %edge_2 ]
  %p_5_2 = phi i64 [ %t105, %edge_2 ]
  %p_5_3 = phi i64 [ %t203, %edge_2 ]
  %p_5_4 = phi i64 [ %t301, %edge_2 ]
  %p_5_5 = phi i64 [ %t399, %edge_2 ]
  %p_5_6 = phi i64 [ %t400, %edge_2 ]
  %p_5_7 = phi i32 [ %p_1_2, %edge_2 ]
  %t405 = trunc i64 0 to i32
  %t406 = zext i32 %t405 to i64
  %t407 = icmp ult i64 56, 64
  br i1 %t407, label %ok_408, label %trap_408
trap_408:
  call void @abort()
  unreachable
ok_408:
  %t409 = lshr i64 0, 56
  %t410 = trunc i64 %t409 to i8
  %t411 = add i64 %t406, 7
  %t412 = extractvalue %hia.buffer %p_5_1, 0
  %t413 = extractvalue %hia.buffer %p_5_1, 1
  %t414 = icmp ult i64 %t411, %t413
  br i1 %t414, label %ok_415, label %trap_415
trap_415:
  call void @abort()
  unreachable
ok_415:
  %t416 = getelementptr i8, ptr %t412, i64 %t411
  store i8 %t410, ptr %t416, align 1
  %t417 = icmp ult i64 48, 64
  br i1 %t417, label %ok_418, label %trap_418
trap_418:
  call void @abort()
  unreachable
ok_418:
  %t419 = lshr i64 0, 48
  %t420 = trunc i64 %t419 to i8
  %t421 = add i64 %t406, 6
  %t422 = extractvalue %hia.buffer %p_5_1, 0
  %t423 = extractvalue %hia.buffer %p_5_1, 1
  %t424 = icmp ult i64 %t421, %t423
  br i1 %t424, label %ok_425, label %trap_425
trap_425:
  call void @abort()
  unreachable
ok_425:
  %t426 = getelementptr i8, ptr %t422, i64 %t421
  store i8 %t420, ptr %t426, align 1
  %t427 = icmp ult i64 40, 64
  br i1 %t427, label %ok_428, label %trap_428
trap_428:
  call void @abort()
  unreachable
ok_428:
  %t429 = lshr i64 0, 40
  %t430 = trunc i64 %t429 to i8
  %t431 = add i64 %t406, 5
  %t432 = extractvalue %hia.buffer %p_5_1, 0
  %t433 = extractvalue %hia.buffer %p_5_1, 1
  %t434 = icmp ult i64 %t431, %t433
  br i1 %t434, label %ok_435, label %trap_435
trap_435:
  call void @abort()
  unreachable
ok_435:
  %t436 = getelementptr i8, ptr %t432, i64 %t431
  store i8 %t430, ptr %t436, align 1
  %t437 = icmp ult i64 32, 64
  br i1 %t437, label %ok_438, label %trap_438
trap_438:
  call void @abort()
  unreachable
ok_438:
  %t439 = lshr i64 0, 32
  %t440 = trunc i64 %t439 to i8
  %t441 = add i64 %t406, 4
  %t442 = extractvalue %hia.buffer %p_5_1, 0
  %t443 = extractvalue %hia.buffer %p_5_1, 1
  %t444 = icmp ult i64 %t441, %t443
  br i1 %t444, label %ok_445, label %trap_445
trap_445:
  call void @abort()
  unreachable
ok_445:
  %t446 = getelementptr i8, ptr %t442, i64 %t441
  store i8 %t440, ptr %t446, align 1
  %t447 = icmp ult i64 24, 64
  br i1 %t447, label %ok_448, label %trap_448
trap_448:
  call void @abort()
  unreachable
ok_448:
  %t449 = lshr i64 0, 24
  %t450 = trunc i64 %t449 to i8
  %t451 = add i64 %t406, 3
  %t452 = extractvalue %hia.buffer %p_5_1, 0
  %t453 = extractvalue %hia.buffer %p_5_1, 1
  %t454 = icmp ult i64 %t451, %t453
  br i1 %t454, label %ok_455, label %trap_455
trap_455:
  call void @abort()
  unreachable
ok_455:
  %t456 = getelementptr i8, ptr %t452, i64 %t451
  store i8 %t450, ptr %t456, align 1
  %t457 = icmp ult i64 16, 64
  br i1 %t457, label %ok_458, label %trap_458
trap_458:
  call void @abort()
  unreachable
ok_458:
  %t459 = lshr i64 0, 16
  %t460 = trunc i64 %t459 to i8
  %t461 = add i64 %t406, 2
  %t462 = extractvalue %hia.buffer %p_5_1, 0
  %t463 = extractvalue %hia.buffer %p_5_1, 1
  %t464 = icmp ult i64 %t461, %t463
  br i1 %t464, label %ok_465, label %trap_465
trap_465:
  call void @abort()
  unreachable
ok_465:
  %t466 = getelementptr i8, ptr %t462, i64 %t461
  store i8 %t460, ptr %t466, align 1
  %t467 = icmp ult i64 8, 64
  br i1 %t467, label %ok_468, label %trap_468
trap_468:
  call void @abort()
  unreachable
ok_468:
  %t469 = lshr i64 0, 8
  %t470 = trunc i64 %t469 to i8
  %t471 = add i64 %t406, 1
  %t472 = extractvalue %hia.buffer %p_5_1, 0
  %t473 = extractvalue %hia.buffer %p_5_1, 1
  %t474 = icmp ult i64 %t471, %t473
  br i1 %t474, label %ok_475, label %trap_475
trap_475:
  call void @abort()
  unreachable
ok_475:
  %t476 = getelementptr i8, ptr %t472, i64 %t471
  store i8 %t470, ptr %t476, align 1
  %t477 = icmp ult i64 0, 64
  br i1 %t477, label %ok_478, label %trap_478
trap_478:
  call void @abort()
  unreachable
ok_478:
  %t479 = lshr i64 0, 0
  %t480 = trunc i64 %t479 to i8
  %t481 = add i64 %t406, 0
  %t482 = extractvalue %hia.buffer %p_5_1, 0
  %t483 = extractvalue %hia.buffer %p_5_1, 1
  %t484 = icmp ult i64 %t481, %t483
  br i1 %t484, label %ok_485, label %trap_485
trap_485:
  call void @abort()
  unreachable
ok_485:
  %t486 = getelementptr i8, ptr %t482, i64 %t481
  store i8 %t480, ptr %t486, align 1
  %t487 = trunc i64 8 to i32
  %t488 = zext i32 %t487 to i64
  %t489 = icmp ult i64 56, 64
  br i1 %t489, label %ok_490, label %trap_490
trap_490:
  call void @abort()
  unreachable
ok_490:
  %t491 = lshr i64 0, 56
  %t492 = trunc i64 %t491 to i8
  %t493 = add i64 %t488, 7
  %t494 = extractvalue %hia.buffer %p_5_1, 0
  %t495 = extractvalue %hia.buffer %p_5_1, 1
  %t496 = icmp ult i64 %t493, %t495
  br i1 %t496, label %ok_497, label %trap_497
trap_497:
  call void @abort()
  unreachable
ok_497:
  %t498 = getelementptr i8, ptr %t494, i64 %t493
  store i8 %t492, ptr %t498, align 1
  %t499 = icmp ult i64 48, 64
  br i1 %t499, label %ok_500, label %trap_500
trap_500:
  call void @abort()
  unreachable
ok_500:
  %t501 = lshr i64 0, 48
  %t502 = trunc i64 %t501 to i8
  %t503 = add i64 %t488, 6
  %t504 = extractvalue %hia.buffer %p_5_1, 0
  %t505 = extractvalue %hia.buffer %p_5_1, 1
  %t506 = icmp ult i64 %t503, %t505
  br i1 %t506, label %ok_507, label %trap_507
trap_507:
  call void @abort()
  unreachable
ok_507:
  %t508 = getelementptr i8, ptr %t504, i64 %t503
  store i8 %t502, ptr %t508, align 1
  %t509 = icmp ult i64 40, 64
  br i1 %t509, label %ok_510, label %trap_510
trap_510:
  call void @abort()
  unreachable
ok_510:
  %t511 = lshr i64 0, 40
  %t512 = trunc i64 %t511 to i8
  %t513 = add i64 %t488, 5
  %t514 = extractvalue %hia.buffer %p_5_1, 0
  %t515 = extractvalue %hia.buffer %p_5_1, 1
  %t516 = icmp ult i64 %t513, %t515
  br i1 %t516, label %ok_517, label %trap_517
trap_517:
  call void @abort()
  unreachable
ok_517:
  %t518 = getelementptr i8, ptr %t514, i64 %t513
  store i8 %t512, ptr %t518, align 1
  %t519 = icmp ult i64 32, 64
  br i1 %t519, label %ok_520, label %trap_520
trap_520:
  call void @abort()
  unreachable
ok_520:
  %t521 = lshr i64 0, 32
  %t522 = trunc i64 %t521 to i8
  %t523 = add i64 %t488, 4
  %t524 = extractvalue %hia.buffer %p_5_1, 0
  %t525 = extractvalue %hia.buffer %p_5_1, 1
  %t526 = icmp ult i64 %t523, %t525
  br i1 %t526, label %ok_527, label %trap_527
trap_527:
  call void @abort()
  unreachable
ok_527:
  %t528 = getelementptr i8, ptr %t524, i64 %t523
  store i8 %t522, ptr %t528, align 1
  %t529 = icmp ult i64 24, 64
  br i1 %t529, label %ok_530, label %trap_530
trap_530:
  call void @abort()
  unreachable
ok_530:
  %t531 = lshr i64 0, 24
  %t532 = trunc i64 %t531 to i8
  %t533 = add i64 %t488, 3
  %t534 = extractvalue %hia.buffer %p_5_1, 0
  %t535 = extractvalue %hia.buffer %p_5_1, 1
  %t536 = icmp ult i64 %t533, %t535
  br i1 %t536, label %ok_537, label %trap_537
trap_537:
  call void @abort()
  unreachable
ok_537:
  %t538 = getelementptr i8, ptr %t534, i64 %t533
  store i8 %t532, ptr %t538, align 1
  %t539 = icmp ult i64 16, 64
  br i1 %t539, label %ok_540, label %trap_540
trap_540:
  call void @abort()
  unreachable
ok_540:
  %t541 = lshr i64 0, 16
  %t542 = trunc i64 %t541 to i8
  %t543 = add i64 %t488, 2
  %t544 = extractvalue %hia.buffer %p_5_1, 0
  %t545 = extractvalue %hia.buffer %p_5_1, 1
  %t546 = icmp ult i64 %t543, %t545
  br i1 %t546, label %ok_547, label %trap_547
trap_547:
  call void @abort()
  unreachable
ok_547:
  %t548 = getelementptr i8, ptr %t544, i64 %t543
  store i8 %t542, ptr %t548, align 1
  %t549 = icmp ult i64 8, 64
  br i1 %t549, label %ok_550, label %trap_550
trap_550:
  call void @abort()
  unreachable
ok_550:
  %t551 = lshr i64 0, 8
  %t552 = trunc i64 %t551 to i8
  %t553 = add i64 %t488, 1
  %t554 = extractvalue %hia.buffer %p_5_1, 0
  %t555 = extractvalue %hia.buffer %p_5_1, 1
  %t556 = icmp ult i64 %t553, %t555
  br i1 %t556, label %ok_557, label %trap_557
trap_557:
  call void @abort()
  unreachable
ok_557:
  %t558 = getelementptr i8, ptr %t554, i64 %t553
  store i8 %t552, ptr %t558, align 1
  %t559 = icmp ult i64 0, 64
  br i1 %t559, label %ok_560, label %trap_560
trap_560:
  call void @abort()
  unreachable
ok_560:
  %t561 = lshr i64 0, 0
  %t562 = trunc i64 %t561 to i8
  %t563 = add i64 %t488, 0
  %t564 = extractvalue %hia.buffer %p_5_1, 0
  %t565 = extractvalue %hia.buffer %p_5_1, 1
  %t566 = icmp ult i64 %t563, %t565
  br i1 %t566, label %ok_567, label %trap_567
trap_567:
  call void @abort()
  unreachable
ok_567:
  %t568 = getelementptr i8, ptr %t564, i64 %t563
  store i8 %t562, ptr %t568, align 1
  %t569 = icmp uge i64 %p_5_5, 4
  br i1 %t569, label %edge_4, label %edge_5
b6:
  %p_6_0 = phi %hia.buffer [ %p_5_0, %edge_4 ]
  %p_6_1 = phi %hia.buffer [ %p_5_1, %edge_4 ]
  %p_6_2 = phi i64 [ %p_5_2, %edge_4 ]
  %p_6_3 = phi i64 [ %p_5_3, %edge_4 ]
  %p_6_4 = phi i64 [ %p_5_4, %edge_4 ]
  %p_6_5 = phi i64 [ %p_5_5, %edge_4 ]
  %p_6_6 = phi i64 [ %p_5_6, %edge_4 ]
  %p_6_7 = phi i32 [ %p_5_7, %edge_4 ]
  %t570 = trunc i64 %p_6_4 to i32
  %t571 = zext i32 %t570 to i64
  %t572 = add i64 %t571, 3
  %t573 = extractvalue %hia.buffer %p_6_0, 0
  %t574 = extractvalue %hia.buffer %p_6_0, 1
  %t575 = icmp ult i64 %t572, %t574
  br i1 %t575, label %ok_576, label %trap_576
trap_576:
  call void @abort()
  unreachable
ok_576:
  %t577 = getelementptr i8, ptr %t573, i64 %t572
  %t578 = load i8, ptr %t577, align 1
  %t579 = zext i8 %t578 to i64
  %t580 = icmp ult i64 0, 64
  br i1 %t580, label %ok_581, label %trap_581
trap_581:
  call void @abort()
  unreachable
ok_581:
  %t582 = shl i64 %t579, 0
  %t583 = or i64 0, %t582
  %t584 = add i64 %t571, 2
  %t585 = extractvalue %hia.buffer %p_6_0, 0
  %t586 = extractvalue %hia.buffer %p_6_0, 1
  %t587 = icmp ult i64 %t584, %t586
  br i1 %t587, label %ok_588, label %trap_588
trap_588:
  call void @abort()
  unreachable
ok_588:
  %t589 = getelementptr i8, ptr %t585, i64 %t584
  %t590 = load i8, ptr %t589, align 1
  %t591 = zext i8 %t590 to i64
  %t592 = icmp ult i64 8, 64
  br i1 %t592, label %ok_593, label %trap_593
trap_593:
  call void @abort()
  unreachable
ok_593:
  %t594 = shl i64 %t591, 8
  %t595 = or i64 %t583, %t594
  %t596 = add i64 %t571, 1
  %t597 = extractvalue %hia.buffer %p_6_0, 0
  %t598 = extractvalue %hia.buffer %p_6_0, 1
  %t599 = icmp ult i64 %t596, %t598
  br i1 %t599, label %ok_600, label %trap_600
trap_600:
  call void @abort()
  unreachable
ok_600:
  %t601 = getelementptr i8, ptr %t597, i64 %t596
  %t602 = load i8, ptr %t601, align 1
  %t603 = zext i8 %t602 to i64
  %t604 = icmp ult i64 16, 64
  br i1 %t604, label %ok_605, label %trap_605
trap_605:
  call void @abort()
  unreachable
ok_605:
  %t606 = shl i64 %t603, 16
  %t607 = or i64 %t595, %t606
  %t608 = add i64 %t571, 0
  %t609 = extractvalue %hia.buffer %p_6_0, 0
  %t610 = extractvalue %hia.buffer %p_6_0, 1
  %t611 = icmp ult i64 %t608, %t610
  br i1 %t611, label %ok_612, label %trap_612
trap_612:
  call void @abort()
  unreachable
ok_612:
  %t613 = getelementptr i8, ptr %t609, i64 %t608
  %t614 = load i8, ptr %t613, align 1
  %t615 = zext i8 %t614 to i64
  %t616 = icmp ult i64 24, 64
  br i1 %t616, label %ok_617, label %trap_617
trap_617:
  call void @abort()
  unreachable
ok_617:
  %t618 = shl i64 %t615, 24
  %t619 = or i64 %t607, %t618
  %t620 = trunc i64 0 to i32
  %t621 = zext i32 %t620 to i64
  %t622 = icmp ult i64 56, 64
  br i1 %t622, label %ok_623, label %trap_623
trap_623:
  call void @abort()
  unreachable
ok_623:
  %t624 = lshr i64 %t619, 56
  %t625 = trunc i64 %t624 to i8
  %t626 = add i64 %t621, 7
  %t627 = extractvalue %hia.buffer %p_6_1, 0
  %t628 = extractvalue %hia.buffer %p_6_1, 1
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
  %t634 = lshr i64 %t619, 48
  %t635 = trunc i64 %t634 to i8
  %t636 = add i64 %t621, 6
  %t637 = extractvalue %hia.buffer %p_6_1, 0
  %t638 = extractvalue %hia.buffer %p_6_1, 1
  %t639 = icmp ult i64 %t636, %t638
  br i1 %t639, label %ok_640, label %trap_640
trap_640:
  call void @abort()
  unreachable
ok_640:
  %t641 = getelementptr i8, ptr %t637, i64 %t636
  store i8 %t635, ptr %t641, align 1
  %t642 = icmp ult i64 40, 64
  br i1 %t642, label %ok_643, label %trap_643
trap_643:
  call void @abort()
  unreachable
ok_643:
  %t644 = lshr i64 %t619, 40
  %t645 = trunc i64 %t644 to i8
  %t646 = add i64 %t621, 5
  %t647 = extractvalue %hia.buffer %p_6_1, 0
  %t648 = extractvalue %hia.buffer %p_6_1, 1
  %t649 = icmp ult i64 %t646, %t648
  br i1 %t649, label %ok_650, label %trap_650
trap_650:
  call void @abort()
  unreachable
ok_650:
  %t651 = getelementptr i8, ptr %t647, i64 %t646
  store i8 %t645, ptr %t651, align 1
  %t652 = icmp ult i64 32, 64
  br i1 %t652, label %ok_653, label %trap_653
trap_653:
  call void @abort()
  unreachable
ok_653:
  %t654 = lshr i64 %t619, 32
  %t655 = trunc i64 %t654 to i8
  %t656 = add i64 %t621, 4
  %t657 = extractvalue %hia.buffer %p_6_1, 0
  %t658 = extractvalue %hia.buffer %p_6_1, 1
  %t659 = icmp ult i64 %t656, %t658
  br i1 %t659, label %ok_660, label %trap_660
trap_660:
  call void @abort()
  unreachable
ok_660:
  %t661 = getelementptr i8, ptr %t657, i64 %t656
  store i8 %t655, ptr %t661, align 1
  %t662 = icmp ult i64 24, 64
  br i1 %t662, label %ok_663, label %trap_663
trap_663:
  call void @abort()
  unreachable
ok_663:
  %t664 = lshr i64 %t619, 24
  %t665 = trunc i64 %t664 to i8
  %t666 = add i64 %t621, 3
  %t667 = extractvalue %hia.buffer %p_6_1, 0
  %t668 = extractvalue %hia.buffer %p_6_1, 1
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
  %t674 = lshr i64 %t619, 16
  %t675 = trunc i64 %t674 to i8
  %t676 = add i64 %t621, 2
  %t677 = extractvalue %hia.buffer %p_6_1, 0
  %t678 = extractvalue %hia.buffer %p_6_1, 1
  %t679 = icmp ult i64 %t676, %t678
  br i1 %t679, label %ok_680, label %trap_680
trap_680:
  call void @abort()
  unreachable
ok_680:
  %t681 = getelementptr i8, ptr %t677, i64 %t676
  store i8 %t675, ptr %t681, align 1
  %t682 = icmp ult i64 8, 64
  br i1 %t682, label %ok_683, label %trap_683
trap_683:
  call void @abort()
  unreachable
ok_683:
  %t684 = lshr i64 %t619, 8
  %t685 = trunc i64 %t684 to i8
  %t686 = add i64 %t621, 1
  %t687 = extractvalue %hia.buffer %p_6_1, 0
  %t688 = extractvalue %hia.buffer %p_6_1, 1
  %t689 = icmp ult i64 %t686, %t688
  br i1 %t689, label %ok_690, label %trap_690
trap_690:
  call void @abort()
  unreachable
ok_690:
  %t691 = getelementptr i8, ptr %t687, i64 %t686
  store i8 %t685, ptr %t691, align 1
  %t692 = icmp ult i64 0, 64
  br i1 %t692, label %ok_693, label %trap_693
trap_693:
  call void @abort()
  unreachable
ok_693:
  %t694 = lshr i64 %t619, 0
  %t695 = trunc i64 %t694 to i8
  %t696 = add i64 %t621, 0
  %t697 = extractvalue %hia.buffer %p_6_1, 0
  %t698 = extractvalue %hia.buffer %p_6_1, 1
  %t699 = icmp ult i64 %t696, %t698
  br i1 %t699, label %ok_700, label %trap_700
trap_700:
  call void @abort()
  unreachable
ok_700:
  %t701 = getelementptr i8, ptr %t697, i64 %t696
  store i8 %t695, ptr %t701, align 1
  %t702 = add i64 %p_6_4, 4
  %t703 = sub i64 %p_6_5, 4
  %t704 = trunc i64 16 to i32
  %t705 = zext i32 %t704 to i64
  %t706 = icmp ult i64 56, 64
  br i1 %t706, label %ok_707, label %trap_707
trap_707:
  call void @abort()
  unreachable
ok_707:
  %t708 = lshr i64 %t702, 56
  %t709 = trunc i64 %t708 to i8
  %t710 = add i64 %t705, 7
  %t711 = extractvalue %hia.buffer %p_6_1, 0
  %t712 = extractvalue %hia.buffer %p_6_1, 1
  %t713 = icmp ult i64 %t710, %t712
  br i1 %t713, label %ok_714, label %trap_714
trap_714:
  call void @abort()
  unreachable
ok_714:
  %t715 = getelementptr i8, ptr %t711, i64 %t710
  store i8 %t709, ptr %t715, align 1
  %t716 = icmp ult i64 48, 64
  br i1 %t716, label %ok_717, label %trap_717
trap_717:
  call void @abort()
  unreachable
ok_717:
  %t718 = lshr i64 %t702, 48
  %t719 = trunc i64 %t718 to i8
  %t720 = add i64 %t705, 6
  %t721 = extractvalue %hia.buffer %p_6_1, 0
  %t722 = extractvalue %hia.buffer %p_6_1, 1
  %t723 = icmp ult i64 %t720, %t722
  br i1 %t723, label %ok_724, label %trap_724
trap_724:
  call void @abort()
  unreachable
ok_724:
  %t725 = getelementptr i8, ptr %t721, i64 %t720
  store i8 %t719, ptr %t725, align 1
  %t726 = icmp ult i64 40, 64
  br i1 %t726, label %ok_727, label %trap_727
trap_727:
  call void @abort()
  unreachable
ok_727:
  %t728 = lshr i64 %t702, 40
  %t729 = trunc i64 %t728 to i8
  %t730 = add i64 %t705, 5
  %t731 = extractvalue %hia.buffer %p_6_1, 0
  %t732 = extractvalue %hia.buffer %p_6_1, 1
  %t733 = icmp ult i64 %t730, %t732
  br i1 %t733, label %ok_734, label %trap_734
trap_734:
  call void @abort()
  unreachable
ok_734:
  %t735 = getelementptr i8, ptr %t731, i64 %t730
  store i8 %t729, ptr %t735, align 1
  %t736 = icmp ult i64 32, 64
  br i1 %t736, label %ok_737, label %trap_737
trap_737:
  call void @abort()
  unreachable
ok_737:
  %t738 = lshr i64 %t702, 32
  %t739 = trunc i64 %t738 to i8
  %t740 = add i64 %t705, 4
  %t741 = extractvalue %hia.buffer %p_6_1, 0
  %t742 = extractvalue %hia.buffer %p_6_1, 1
  %t743 = icmp ult i64 %t740, %t742
  br i1 %t743, label %ok_744, label %trap_744
trap_744:
  call void @abort()
  unreachable
ok_744:
  %t745 = getelementptr i8, ptr %t741, i64 %t740
  store i8 %t739, ptr %t745, align 1
  %t746 = icmp ult i64 24, 64
  br i1 %t746, label %ok_747, label %trap_747
trap_747:
  call void @abort()
  unreachable
ok_747:
  %t748 = lshr i64 %t702, 24
  %t749 = trunc i64 %t748 to i8
  %t750 = add i64 %t705, 3
  %t751 = extractvalue %hia.buffer %p_6_1, 0
  %t752 = extractvalue %hia.buffer %p_6_1, 1
  %t753 = icmp ult i64 %t750, %t752
  br i1 %t753, label %ok_754, label %trap_754
trap_754:
  call void @abort()
  unreachable
ok_754:
  %t755 = getelementptr i8, ptr %t751, i64 %t750
  store i8 %t749, ptr %t755, align 1
  %t756 = icmp ult i64 16, 64
  br i1 %t756, label %ok_757, label %trap_757
trap_757:
  call void @abort()
  unreachable
ok_757:
  %t758 = lshr i64 %t702, 16
  %t759 = trunc i64 %t758 to i8
  %t760 = add i64 %t705, 2
  %t761 = extractvalue %hia.buffer %p_6_1, 0
  %t762 = extractvalue %hia.buffer %p_6_1, 1
  %t763 = icmp ult i64 %t760, %t762
  br i1 %t763, label %ok_764, label %trap_764
trap_764:
  call void @abort()
  unreachable
ok_764:
  %t765 = getelementptr i8, ptr %t761, i64 %t760
  store i8 %t759, ptr %t765, align 1
  %t766 = icmp ult i64 8, 64
  br i1 %t766, label %ok_767, label %trap_767
trap_767:
  call void @abort()
  unreachable
ok_767:
  %t768 = lshr i64 %t702, 8
  %t769 = trunc i64 %t768 to i8
  %t770 = add i64 %t705, 1
  %t771 = extractvalue %hia.buffer %p_6_1, 0
  %t772 = extractvalue %hia.buffer %p_6_1, 1
  %t773 = icmp ult i64 %t770, %t772
  br i1 %t773, label %ok_774, label %trap_774
trap_774:
  call void @abort()
  unreachable
ok_774:
  %t775 = getelementptr i8, ptr %t771, i64 %t770
  store i8 %t769, ptr %t775, align 1
  %t776 = icmp ult i64 0, 64
  br i1 %t776, label %ok_777, label %trap_777
trap_777:
  call void @abort()
  unreachable
ok_777:
  %t778 = lshr i64 %t702, 0
  %t779 = trunc i64 %t778 to i8
  %t780 = add i64 %t705, 0
  %t781 = extractvalue %hia.buffer %p_6_1, 0
  %t782 = extractvalue %hia.buffer %p_6_1, 1
  %t783 = icmp ult i64 %t780, %t782
  br i1 %t783, label %ok_784, label %trap_784
trap_784:
  call void @abort()
  unreachable
ok_784:
  %t785 = getelementptr i8, ptr %t781, i64 %t780
  store i8 %t779, ptr %t785, align 1
  %t786 = trunc i64 24 to i32
  %t787 = zext i32 %t786 to i64
  %t788 = icmp ult i64 56, 64
  br i1 %t788, label %ok_789, label %trap_789
trap_789:
  call void @abort()
  unreachable
ok_789:
  %t790 = lshr i64 %t703, 56
  %t791 = trunc i64 %t790 to i8
  %t792 = add i64 %t787, 7
  %t793 = extractvalue %hia.buffer %p_6_1, 0
  %t794 = extractvalue %hia.buffer %p_6_1, 1
  %t795 = icmp ult i64 %t792, %t794
  br i1 %t795, label %ok_796, label %trap_796
trap_796:
  call void @abort()
  unreachable
ok_796:
  %t797 = getelementptr i8, ptr %t793, i64 %t792
  store i8 %t791, ptr %t797, align 1
  %t798 = icmp ult i64 48, 64
  br i1 %t798, label %ok_799, label %trap_799
trap_799:
  call void @abort()
  unreachable
ok_799:
  %t800 = lshr i64 %t703, 48
  %t801 = trunc i64 %t800 to i8
  %t802 = add i64 %t787, 6
  %t803 = extractvalue %hia.buffer %p_6_1, 0
  %t804 = extractvalue %hia.buffer %p_6_1, 1
  %t805 = icmp ult i64 %t802, %t804
  br i1 %t805, label %ok_806, label %trap_806
trap_806:
  call void @abort()
  unreachable
ok_806:
  %t807 = getelementptr i8, ptr %t803, i64 %t802
  store i8 %t801, ptr %t807, align 1
  %t808 = icmp ult i64 40, 64
  br i1 %t808, label %ok_809, label %trap_809
trap_809:
  call void @abort()
  unreachable
ok_809:
  %t810 = lshr i64 %t703, 40
  %t811 = trunc i64 %t810 to i8
  %t812 = add i64 %t787, 5
  %t813 = extractvalue %hia.buffer %p_6_1, 0
  %t814 = extractvalue %hia.buffer %p_6_1, 1
  %t815 = icmp ult i64 %t812, %t814
  br i1 %t815, label %ok_816, label %trap_816
trap_816:
  call void @abort()
  unreachable
ok_816:
  %t817 = getelementptr i8, ptr %t813, i64 %t812
  store i8 %t811, ptr %t817, align 1
  %t818 = icmp ult i64 32, 64
  br i1 %t818, label %ok_819, label %trap_819
trap_819:
  call void @abort()
  unreachable
ok_819:
  %t820 = lshr i64 %t703, 32
  %t821 = trunc i64 %t820 to i8
  %t822 = add i64 %t787, 4
  %t823 = extractvalue %hia.buffer %p_6_1, 0
  %t824 = extractvalue %hia.buffer %p_6_1, 1
  %t825 = icmp ult i64 %t822, %t824
  br i1 %t825, label %ok_826, label %trap_826
trap_826:
  call void @abort()
  unreachable
ok_826:
  %t827 = getelementptr i8, ptr %t823, i64 %t822
  store i8 %t821, ptr %t827, align 1
  %t828 = icmp ult i64 24, 64
  br i1 %t828, label %ok_829, label %trap_829
trap_829:
  call void @abort()
  unreachable
ok_829:
  %t830 = lshr i64 %t703, 24
  %t831 = trunc i64 %t830 to i8
  %t832 = add i64 %t787, 3
  %t833 = extractvalue %hia.buffer %p_6_1, 0
  %t834 = extractvalue %hia.buffer %p_6_1, 1
  %t835 = icmp ult i64 %t832, %t834
  br i1 %t835, label %ok_836, label %trap_836
trap_836:
  call void @abort()
  unreachable
ok_836:
  %t837 = getelementptr i8, ptr %t833, i64 %t832
  store i8 %t831, ptr %t837, align 1
  %t838 = icmp ult i64 16, 64
  br i1 %t838, label %ok_839, label %trap_839
trap_839:
  call void @abort()
  unreachable
ok_839:
  %t840 = lshr i64 %t703, 16
  %t841 = trunc i64 %t840 to i8
  %t842 = add i64 %t787, 2
  %t843 = extractvalue %hia.buffer %p_6_1, 0
  %t844 = extractvalue %hia.buffer %p_6_1, 1
  %t845 = icmp ult i64 %t842, %t844
  br i1 %t845, label %ok_846, label %trap_846
trap_846:
  call void @abort()
  unreachable
ok_846:
  %t847 = getelementptr i8, ptr %t843, i64 %t842
  store i8 %t841, ptr %t847, align 1
  %t848 = icmp ult i64 8, 64
  br i1 %t848, label %ok_849, label %trap_849
trap_849:
  call void @abort()
  unreachable
ok_849:
  %t850 = lshr i64 %t703, 8
  %t851 = trunc i64 %t850 to i8
  %t852 = add i64 %t787, 1
  %t853 = extractvalue %hia.buffer %p_6_1, 0
  %t854 = extractvalue %hia.buffer %p_6_1, 1
  %t855 = icmp ult i64 %t852, %t854
  br i1 %t855, label %ok_856, label %trap_856
trap_856:
  call void @abort()
  unreachable
ok_856:
  %t857 = getelementptr i8, ptr %t853, i64 %t852
  store i8 %t851, ptr %t857, align 1
  %t858 = icmp ult i64 0, 64
  br i1 %t858, label %ok_859, label %trap_859
trap_859:
  call void @abort()
  unreachable
ok_859:
  %t860 = lshr i64 %t703, 0
  %t861 = trunc i64 %t860 to i8
  %t862 = add i64 %t787, 0
  %t863 = extractvalue %hia.buffer %p_6_1, 0
  %t864 = extractvalue %hia.buffer %p_6_1, 1
  %t865 = icmp ult i64 %t862, %t864
  br i1 %t865, label %ok_866, label %trap_866
trap_866:
  call void @abort()
  unreachable
ok_866:
  %t867 = getelementptr i8, ptr %t863, i64 %t862
  store i8 %t861, ptr %t867, align 1
  %t868 = icmp ne i32 %p_6_7, 0
  br i1 %t868, label %edge_6, label %edge_7
b7:
  %p_7_0 = phi %hia.buffer [ %p_6_0, %edge_6 ]
  %p_7_1 = phi %hia.buffer [ %p_6_1, %edge_6 ]
  %p_7_2 = phi i64 [ %p_6_2, %edge_6 ]
  %p_7_3 = phi i64 [ %p_6_3, %edge_6 ]
  %p_7_4 = phi i64 [ %t702, %edge_6 ]
  %p_7_5 = phi i64 [ %t703, %edge_6 ]
  %p_7_6 = phi i64 [ %p_6_6, %edge_6 ]
  %p_7_7 = phi i32 [ %p_6_7, %edge_6 ]
  %t869 = icmp uge i64 %p_7_5, 4
  br i1 %t869, label %edge_8, label %edge_9
b8:
  %p_8_0 = phi %hia.buffer [ %p_7_0, %edge_8 ]
  %p_8_1 = phi %hia.buffer [ %p_7_1, %edge_8 ]
  %p_8_2 = phi i64 [ %p_7_2, %edge_8 ]
  %p_8_3 = phi i64 [ %p_7_3, %edge_8 ]
  %p_8_4 = phi i64 [ %p_7_4, %edge_8 ]
  %p_8_5 = phi i64 [ %p_7_5, %edge_8 ]
  %p_8_6 = phi i64 [ %p_7_6, %edge_8 ]
  %p_8_7 = phi i32 [ %p_7_7, %edge_8 ]
  %t870 = trunc i64 %p_8_4 to i32
  %t871 = zext i32 %t870 to i64
  %t872 = add i64 %t871, 3
  %t873 = extractvalue %hia.buffer %p_8_0, 0
  %t874 = extractvalue %hia.buffer %p_8_0, 1
  %t875 = icmp ult i64 %t872, %t874
  br i1 %t875, label %ok_876, label %trap_876
trap_876:
  call void @abort()
  unreachable
ok_876:
  %t877 = getelementptr i8, ptr %t873, i64 %t872
  %t878 = load i8, ptr %t877, align 1
  %t879 = zext i8 %t878 to i64
  %t880 = icmp ult i64 0, 64
  br i1 %t880, label %ok_881, label %trap_881
trap_881:
  call void @abort()
  unreachable
ok_881:
  %t882 = shl i64 %t879, 0
  %t883 = or i64 0, %t882
  %t884 = add i64 %t871, 2
  %t885 = extractvalue %hia.buffer %p_8_0, 0
  %t886 = extractvalue %hia.buffer %p_8_0, 1
  %t887 = icmp ult i64 %t884, %t886
  br i1 %t887, label %ok_888, label %trap_888
trap_888:
  call void @abort()
  unreachable
ok_888:
  %t889 = getelementptr i8, ptr %t885, i64 %t884
  %t890 = load i8, ptr %t889, align 1
  %t891 = zext i8 %t890 to i64
  %t892 = icmp ult i64 8, 64
  br i1 %t892, label %ok_893, label %trap_893
trap_893:
  call void @abort()
  unreachable
ok_893:
  %t894 = shl i64 %t891, 8
  %t895 = or i64 %t883, %t894
  %t896 = add i64 %t871, 1
  %t897 = extractvalue %hia.buffer %p_8_0, 0
  %t898 = extractvalue %hia.buffer %p_8_0, 1
  %t899 = icmp ult i64 %t896, %t898
  br i1 %t899, label %ok_900, label %trap_900
trap_900:
  call void @abort()
  unreachable
ok_900:
  %t901 = getelementptr i8, ptr %t897, i64 %t896
  %t902 = load i8, ptr %t901, align 1
  %t903 = zext i8 %t902 to i64
  %t904 = icmp ult i64 16, 64
  br i1 %t904, label %ok_905, label %trap_905
trap_905:
  call void @abort()
  unreachable
ok_905:
  %t906 = shl i64 %t903, 16
  %t907 = or i64 %t895, %t906
  %t908 = add i64 %t871, 0
  %t909 = extractvalue %hia.buffer %p_8_0, 0
  %t910 = extractvalue %hia.buffer %p_8_0, 1
  %t911 = icmp ult i64 %t908, %t910
  br i1 %t911, label %ok_912, label %trap_912
trap_912:
  call void @abort()
  unreachable
ok_912:
  %t913 = getelementptr i8, ptr %t909, i64 %t908
  %t914 = load i8, ptr %t913, align 1
  %t915 = zext i8 %t914 to i64
  %t916 = icmp ult i64 24, 64
  br i1 %t916, label %ok_917, label %trap_917
trap_917:
  call void @abort()
  unreachable
ok_917:
  %t918 = shl i64 %t915, 24
  %t919 = or i64 %t907, %t918
  %t920 = trunc i64 8 to i32
  %t921 = zext i32 %t920 to i64
  %t922 = icmp ult i64 56, 64
  br i1 %t922, label %ok_923, label %trap_923
trap_923:
  call void @abort()
  unreachable
ok_923:
  %t924 = lshr i64 %t919, 56
  %t925 = trunc i64 %t924 to i8
  %t926 = add i64 %t921, 7
  %t927 = extractvalue %hia.buffer %p_8_1, 0
  %t928 = extractvalue %hia.buffer %p_8_1, 1
  %t929 = icmp ult i64 %t926, %t928
  br i1 %t929, label %ok_930, label %trap_930
trap_930:
  call void @abort()
  unreachable
ok_930:
  %t931 = getelementptr i8, ptr %t927, i64 %t926
  store i8 %t925, ptr %t931, align 1
  %t932 = icmp ult i64 48, 64
  br i1 %t932, label %ok_933, label %trap_933
trap_933:
  call void @abort()
  unreachable
ok_933:
  %t934 = lshr i64 %t919, 48
  %t935 = trunc i64 %t934 to i8
  %t936 = add i64 %t921, 6
  %t937 = extractvalue %hia.buffer %p_8_1, 0
  %t938 = extractvalue %hia.buffer %p_8_1, 1
  %t939 = icmp ult i64 %t936, %t938
  br i1 %t939, label %ok_940, label %trap_940
trap_940:
  call void @abort()
  unreachable
ok_940:
  %t941 = getelementptr i8, ptr %t937, i64 %t936
  store i8 %t935, ptr %t941, align 1
  %t942 = icmp ult i64 40, 64
  br i1 %t942, label %ok_943, label %trap_943
trap_943:
  call void @abort()
  unreachable
ok_943:
  %t944 = lshr i64 %t919, 40
  %t945 = trunc i64 %t944 to i8
  %t946 = add i64 %t921, 5
  %t947 = extractvalue %hia.buffer %p_8_1, 0
  %t948 = extractvalue %hia.buffer %p_8_1, 1
  %t949 = icmp ult i64 %t946, %t948
  br i1 %t949, label %ok_950, label %trap_950
trap_950:
  call void @abort()
  unreachable
ok_950:
  %t951 = getelementptr i8, ptr %t947, i64 %t946
  store i8 %t945, ptr %t951, align 1
  %t952 = icmp ult i64 32, 64
  br i1 %t952, label %ok_953, label %trap_953
trap_953:
  call void @abort()
  unreachable
ok_953:
  %t954 = lshr i64 %t919, 32
  %t955 = trunc i64 %t954 to i8
  %t956 = add i64 %t921, 4
  %t957 = extractvalue %hia.buffer %p_8_1, 0
  %t958 = extractvalue %hia.buffer %p_8_1, 1
  %t959 = icmp ult i64 %t956, %t958
  br i1 %t959, label %ok_960, label %trap_960
trap_960:
  call void @abort()
  unreachable
ok_960:
  %t961 = getelementptr i8, ptr %t957, i64 %t956
  store i8 %t955, ptr %t961, align 1
  %t962 = icmp ult i64 24, 64
  br i1 %t962, label %ok_963, label %trap_963
trap_963:
  call void @abort()
  unreachable
ok_963:
  %t964 = lshr i64 %t919, 24
  %t965 = trunc i64 %t964 to i8
  %t966 = add i64 %t921, 3
  %t967 = extractvalue %hia.buffer %p_8_1, 0
  %t968 = extractvalue %hia.buffer %p_8_1, 1
  %t969 = icmp ult i64 %t966, %t968
  br i1 %t969, label %ok_970, label %trap_970
trap_970:
  call void @abort()
  unreachable
ok_970:
  %t971 = getelementptr i8, ptr %t967, i64 %t966
  store i8 %t965, ptr %t971, align 1
  %t972 = icmp ult i64 16, 64
  br i1 %t972, label %ok_973, label %trap_973
trap_973:
  call void @abort()
  unreachable
ok_973:
  %t974 = lshr i64 %t919, 16
  %t975 = trunc i64 %t974 to i8
  %t976 = add i64 %t921, 2
  %t977 = extractvalue %hia.buffer %p_8_1, 0
  %t978 = extractvalue %hia.buffer %p_8_1, 1
  %t979 = icmp ult i64 %t976, %t978
  br i1 %t979, label %ok_980, label %trap_980
trap_980:
  call void @abort()
  unreachable
ok_980:
  %t981 = getelementptr i8, ptr %t977, i64 %t976
  store i8 %t975, ptr %t981, align 1
  %t982 = icmp ult i64 8, 64
  br i1 %t982, label %ok_983, label %trap_983
trap_983:
  call void @abort()
  unreachable
ok_983:
  %t984 = lshr i64 %t919, 8
  %t985 = trunc i64 %t984 to i8
  %t986 = add i64 %t921, 1
  %t987 = extractvalue %hia.buffer %p_8_1, 0
  %t988 = extractvalue %hia.buffer %p_8_1, 1
  %t989 = icmp ult i64 %t986, %t988
  br i1 %t989, label %ok_990, label %trap_990
trap_990:
  call void @abort()
  unreachable
ok_990:
  %t991 = getelementptr i8, ptr %t987, i64 %t986
  store i8 %t985, ptr %t991, align 1
  %t992 = icmp ult i64 0, 64
  br i1 %t992, label %ok_993, label %trap_993
trap_993:
  call void @abort()
  unreachable
ok_993:
  %t994 = lshr i64 %t919, 0
  %t995 = trunc i64 %t994 to i8
  %t996 = add i64 %t921, 0
  %t997 = extractvalue %hia.buffer %p_8_1, 0
  %t998 = extractvalue %hia.buffer %p_8_1, 1
  %t999 = icmp ult i64 %t996, %t998
  br i1 %t999, label %ok_1000, label %trap_1000
trap_1000:
  call void @abort()
  unreachable
ok_1000:
  %t1001 = getelementptr i8, ptr %t997, i64 %t996
  store i8 %t995, ptr %t1001, align 1
  %t1002 = add i64 %p_8_4, 4
  %t1003 = sub i64 %p_8_5, 4
  %t1004 = trunc i64 16 to i32
  %t1005 = zext i32 %t1004 to i64
  %t1006 = icmp ult i64 56, 64
  br i1 %t1006, label %ok_1007, label %trap_1007
trap_1007:
  call void @abort()
  unreachable
ok_1007:
  %t1008 = lshr i64 %t1002, 56
  %t1009 = trunc i64 %t1008 to i8
  %t1010 = add i64 %t1005, 7
  %t1011 = extractvalue %hia.buffer %p_8_1, 0
  %t1012 = extractvalue %hia.buffer %p_8_1, 1
  %t1013 = icmp ult i64 %t1010, %t1012
  br i1 %t1013, label %ok_1014, label %trap_1014
trap_1014:
  call void @abort()
  unreachable
ok_1014:
  %t1015 = getelementptr i8, ptr %t1011, i64 %t1010
  store i8 %t1009, ptr %t1015, align 1
  %t1016 = icmp ult i64 48, 64
  br i1 %t1016, label %ok_1017, label %trap_1017
trap_1017:
  call void @abort()
  unreachable
ok_1017:
  %t1018 = lshr i64 %t1002, 48
  %t1019 = trunc i64 %t1018 to i8
  %t1020 = add i64 %t1005, 6
  %t1021 = extractvalue %hia.buffer %p_8_1, 0
  %t1022 = extractvalue %hia.buffer %p_8_1, 1
  %t1023 = icmp ult i64 %t1020, %t1022
  br i1 %t1023, label %ok_1024, label %trap_1024
trap_1024:
  call void @abort()
  unreachable
ok_1024:
  %t1025 = getelementptr i8, ptr %t1021, i64 %t1020
  store i8 %t1019, ptr %t1025, align 1
  %t1026 = icmp ult i64 40, 64
  br i1 %t1026, label %ok_1027, label %trap_1027
trap_1027:
  call void @abort()
  unreachable
ok_1027:
  %t1028 = lshr i64 %t1002, 40
  %t1029 = trunc i64 %t1028 to i8
  %t1030 = add i64 %t1005, 5
  %t1031 = extractvalue %hia.buffer %p_8_1, 0
  %t1032 = extractvalue %hia.buffer %p_8_1, 1
  %t1033 = icmp ult i64 %t1030, %t1032
  br i1 %t1033, label %ok_1034, label %trap_1034
trap_1034:
  call void @abort()
  unreachable
ok_1034:
  %t1035 = getelementptr i8, ptr %t1031, i64 %t1030
  store i8 %t1029, ptr %t1035, align 1
  %t1036 = icmp ult i64 32, 64
  br i1 %t1036, label %ok_1037, label %trap_1037
trap_1037:
  call void @abort()
  unreachable
ok_1037:
  %t1038 = lshr i64 %t1002, 32
  %t1039 = trunc i64 %t1038 to i8
  %t1040 = add i64 %t1005, 4
  %t1041 = extractvalue %hia.buffer %p_8_1, 0
  %t1042 = extractvalue %hia.buffer %p_8_1, 1
  %t1043 = icmp ult i64 %t1040, %t1042
  br i1 %t1043, label %ok_1044, label %trap_1044
trap_1044:
  call void @abort()
  unreachable
ok_1044:
  %t1045 = getelementptr i8, ptr %t1041, i64 %t1040
  store i8 %t1039, ptr %t1045, align 1
  %t1046 = icmp ult i64 24, 64
  br i1 %t1046, label %ok_1047, label %trap_1047
trap_1047:
  call void @abort()
  unreachable
ok_1047:
  %t1048 = lshr i64 %t1002, 24
  %t1049 = trunc i64 %t1048 to i8
  %t1050 = add i64 %t1005, 3
  %t1051 = extractvalue %hia.buffer %p_8_1, 0
  %t1052 = extractvalue %hia.buffer %p_8_1, 1
  %t1053 = icmp ult i64 %t1050, %t1052
  br i1 %t1053, label %ok_1054, label %trap_1054
trap_1054:
  call void @abort()
  unreachable
ok_1054:
  %t1055 = getelementptr i8, ptr %t1051, i64 %t1050
  store i8 %t1049, ptr %t1055, align 1
  %t1056 = icmp ult i64 16, 64
  br i1 %t1056, label %ok_1057, label %trap_1057
trap_1057:
  call void @abort()
  unreachable
ok_1057:
  %t1058 = lshr i64 %t1002, 16
  %t1059 = trunc i64 %t1058 to i8
  %t1060 = add i64 %t1005, 2
  %t1061 = extractvalue %hia.buffer %p_8_1, 0
  %t1062 = extractvalue %hia.buffer %p_8_1, 1
  %t1063 = icmp ult i64 %t1060, %t1062
  br i1 %t1063, label %ok_1064, label %trap_1064
trap_1064:
  call void @abort()
  unreachable
ok_1064:
  %t1065 = getelementptr i8, ptr %t1061, i64 %t1060
  store i8 %t1059, ptr %t1065, align 1
  %t1066 = icmp ult i64 8, 64
  br i1 %t1066, label %ok_1067, label %trap_1067
trap_1067:
  call void @abort()
  unreachable
ok_1067:
  %t1068 = lshr i64 %t1002, 8
  %t1069 = trunc i64 %t1068 to i8
  %t1070 = add i64 %t1005, 1
  %t1071 = extractvalue %hia.buffer %p_8_1, 0
  %t1072 = extractvalue %hia.buffer %p_8_1, 1
  %t1073 = icmp ult i64 %t1070, %t1072
  br i1 %t1073, label %ok_1074, label %trap_1074
trap_1074:
  call void @abort()
  unreachable
ok_1074:
  %t1075 = getelementptr i8, ptr %t1071, i64 %t1070
  store i8 %t1069, ptr %t1075, align 1
  %t1076 = icmp ult i64 0, 64
  br i1 %t1076, label %ok_1077, label %trap_1077
trap_1077:
  call void @abort()
  unreachable
ok_1077:
  %t1078 = lshr i64 %t1002, 0
  %t1079 = trunc i64 %t1078 to i8
  %t1080 = add i64 %t1005, 0
  %t1081 = extractvalue %hia.buffer %p_8_1, 0
  %t1082 = extractvalue %hia.buffer %p_8_1, 1
  %t1083 = icmp ult i64 %t1080, %t1082
  br i1 %t1083, label %ok_1084, label %trap_1084
trap_1084:
  call void @abort()
  unreachable
ok_1084:
  %t1085 = getelementptr i8, ptr %t1081, i64 %t1080
  store i8 %t1079, ptr %t1085, align 1
  %t1086 = trunc i64 24 to i32
  %t1087 = zext i32 %t1086 to i64
  %t1088 = icmp ult i64 56, 64
  br i1 %t1088, label %ok_1089, label %trap_1089
trap_1089:
  call void @abort()
  unreachable
ok_1089:
  %t1090 = lshr i64 %t1003, 56
  %t1091 = trunc i64 %t1090 to i8
  %t1092 = add i64 %t1087, 7
  %t1093 = extractvalue %hia.buffer %p_8_1, 0
  %t1094 = extractvalue %hia.buffer %p_8_1, 1
  %t1095 = icmp ult i64 %t1092, %t1094
  br i1 %t1095, label %ok_1096, label %trap_1096
trap_1096:
  call void @abort()
  unreachable
ok_1096:
  %t1097 = getelementptr i8, ptr %t1093, i64 %t1092
  store i8 %t1091, ptr %t1097, align 1
  %t1098 = icmp ult i64 48, 64
  br i1 %t1098, label %ok_1099, label %trap_1099
trap_1099:
  call void @abort()
  unreachable
ok_1099:
  %t1100 = lshr i64 %t1003, 48
  %t1101 = trunc i64 %t1100 to i8
  %t1102 = add i64 %t1087, 6
  %t1103 = extractvalue %hia.buffer %p_8_1, 0
  %t1104 = extractvalue %hia.buffer %p_8_1, 1
  %t1105 = icmp ult i64 %t1102, %t1104
  br i1 %t1105, label %ok_1106, label %trap_1106
trap_1106:
  call void @abort()
  unreachable
ok_1106:
  %t1107 = getelementptr i8, ptr %t1103, i64 %t1102
  store i8 %t1101, ptr %t1107, align 1
  %t1108 = icmp ult i64 40, 64
  br i1 %t1108, label %ok_1109, label %trap_1109
trap_1109:
  call void @abort()
  unreachable
ok_1109:
  %t1110 = lshr i64 %t1003, 40
  %t1111 = trunc i64 %t1110 to i8
  %t1112 = add i64 %t1087, 5
  %t1113 = extractvalue %hia.buffer %p_8_1, 0
  %t1114 = extractvalue %hia.buffer %p_8_1, 1
  %t1115 = icmp ult i64 %t1112, %t1114
  br i1 %t1115, label %ok_1116, label %trap_1116
trap_1116:
  call void @abort()
  unreachable
ok_1116:
  %t1117 = getelementptr i8, ptr %t1113, i64 %t1112
  store i8 %t1111, ptr %t1117, align 1
  %t1118 = icmp ult i64 32, 64
  br i1 %t1118, label %ok_1119, label %trap_1119
trap_1119:
  call void @abort()
  unreachable
ok_1119:
  %t1120 = lshr i64 %t1003, 32
  %t1121 = trunc i64 %t1120 to i8
  %t1122 = add i64 %t1087, 4
  %t1123 = extractvalue %hia.buffer %p_8_1, 0
  %t1124 = extractvalue %hia.buffer %p_8_1, 1
  %t1125 = icmp ult i64 %t1122, %t1124
  br i1 %t1125, label %ok_1126, label %trap_1126
trap_1126:
  call void @abort()
  unreachable
ok_1126:
  %t1127 = getelementptr i8, ptr %t1123, i64 %t1122
  store i8 %t1121, ptr %t1127, align 1
  %t1128 = icmp ult i64 24, 64
  br i1 %t1128, label %ok_1129, label %trap_1129
trap_1129:
  call void @abort()
  unreachable
ok_1129:
  %t1130 = lshr i64 %t1003, 24
  %t1131 = trunc i64 %t1130 to i8
  %t1132 = add i64 %t1087, 3
  %t1133 = extractvalue %hia.buffer %p_8_1, 0
  %t1134 = extractvalue %hia.buffer %p_8_1, 1
  %t1135 = icmp ult i64 %t1132, %t1134
  br i1 %t1135, label %ok_1136, label %trap_1136
trap_1136:
  call void @abort()
  unreachable
ok_1136:
  %t1137 = getelementptr i8, ptr %t1133, i64 %t1132
  store i8 %t1131, ptr %t1137, align 1
  %t1138 = icmp ult i64 16, 64
  br i1 %t1138, label %ok_1139, label %trap_1139
trap_1139:
  call void @abort()
  unreachable
ok_1139:
  %t1140 = lshr i64 %t1003, 16
  %t1141 = trunc i64 %t1140 to i8
  %t1142 = add i64 %t1087, 2
  %t1143 = extractvalue %hia.buffer %p_8_1, 0
  %t1144 = extractvalue %hia.buffer %p_8_1, 1
  %t1145 = icmp ult i64 %t1142, %t1144
  br i1 %t1145, label %ok_1146, label %trap_1146
trap_1146:
  call void @abort()
  unreachable
ok_1146:
  %t1147 = getelementptr i8, ptr %t1143, i64 %t1142
  store i8 %t1141, ptr %t1147, align 1
  %t1148 = icmp ult i64 8, 64
  br i1 %t1148, label %ok_1149, label %trap_1149
trap_1149:
  call void @abort()
  unreachable
ok_1149:
  %t1150 = lshr i64 %t1003, 8
  %t1151 = trunc i64 %t1150 to i8
  %t1152 = add i64 %t1087, 1
  %t1153 = extractvalue %hia.buffer %p_8_1, 0
  %t1154 = extractvalue %hia.buffer %p_8_1, 1
  %t1155 = icmp ult i64 %t1152, %t1154
  br i1 %t1155, label %ok_1156, label %trap_1156
trap_1156:
  call void @abort()
  unreachable
ok_1156:
  %t1157 = getelementptr i8, ptr %t1153, i64 %t1152
  store i8 %t1151, ptr %t1157, align 1
  %t1158 = icmp ult i64 0, 64
  br i1 %t1158, label %ok_1159, label %trap_1159
trap_1159:
  call void @abort()
  unreachable
ok_1159:
  %t1160 = lshr i64 %t1003, 0
  %t1161 = trunc i64 %t1160 to i8
  %t1162 = add i64 %t1087, 0
  %t1163 = extractvalue %hia.buffer %p_8_1, 0
  %t1164 = extractvalue %hia.buffer %p_8_1, 1
  %t1165 = icmp ult i64 %t1162, %t1164
  br i1 %t1165, label %ok_1166, label %trap_1166
trap_1166:
  call void @abort()
  unreachable
ok_1166:
  %t1167 = getelementptr i8, ptr %t1163, i64 %t1162
  store i8 %t1161, ptr %t1167, align 1
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

define internal i32 @__hia_fn_1(%hia.buffer %p_0_0, %hia.buffer %p_0_1, i64 %p_0_2, i32 %p_0_3, i32 %p_0_4) alwaysinline {
b0:
  %t1 = extractvalue %hia.buffer %p_0_1, 1
  %t2 = icmp eq i64 %t1, 32
  %t3 = extractvalue %hia.buffer %p_0_0, 1
  %t4 = icmp ule i64 %t3, 65536
  %t5 = and i1 %t2, %t4
  %t6 = icmp ule i32 %p_0_3, 1
  %t7 = and i1 %t5, %t6
  %t8 = icmp ule i32 %p_0_4, 1
  %t9 = and i1 %t7, %t8
  br i1 %t9, label %edge_0, label %edge_1
b1:
  %p_1_0 = phi %hia.buffer [ %p_0_0, %edge_0 ]
  %p_1_1 = phi %hia.buffer [ %p_0_1, %edge_0 ]
  %p_1_2 = phi i64 [ %p_0_2, %edge_0 ]
  %p_1_3 = phi i32 [ %p_0_3, %edge_0 ]
  %p_1_4 = phi i32 [ %p_0_4, %edge_0 ]
  %t10 = trunc i64 0 to i32
  %t11 = zext i32 %t10 to i64
  %t12 = add i64 %t11, 7
  %t13 = extractvalue %hia.buffer %p_1_1, 0
  %t14 = extractvalue %hia.buffer %p_1_1, 1
  %t15 = icmp ult i64 %t12, %t14
  br i1 %t15, label %ok_16, label %trap_16
trap_16:
  call void @abort()
  unreachable
ok_16:
  %t17 = getelementptr i8, ptr %t13, i64 %t12
  %t18 = load i8, ptr %t17, align 1
  %t19 = zext i8 %t18 to i64
  %t20 = icmp ult i64 56, 64
  br i1 %t20, label %ok_21, label %trap_21
trap_21:
  call void @abort()
  unreachable
ok_21:
  %t22 = shl i64 %t19, 56
  %t23 = or i64 0, %t22
  %t24 = add i64 %t11, 6
  %t25 = extractvalue %hia.buffer %p_1_1, 0
  %t26 = extractvalue %hia.buffer %p_1_1, 1
  %t27 = icmp ult i64 %t24, %t26
  br i1 %t27, label %ok_28, label %trap_28
trap_28:
  call void @abort()
  unreachable
ok_28:
  %t29 = getelementptr i8, ptr %t25, i64 %t24
  %t30 = load i8, ptr %t29, align 1
  %t31 = zext i8 %t30 to i64
  %t32 = icmp ult i64 48, 64
  br i1 %t32, label %ok_33, label %trap_33
trap_33:
  call void @abort()
  unreachable
ok_33:
  %t34 = shl i64 %t31, 48
  %t35 = or i64 %t23, %t34
  %t36 = add i64 %t11, 5
  %t37 = extractvalue %hia.buffer %p_1_1, 0
  %t38 = extractvalue %hia.buffer %p_1_1, 1
  %t39 = icmp ult i64 %t36, %t38
  br i1 %t39, label %ok_40, label %trap_40
trap_40:
  call void @abort()
  unreachable
ok_40:
  %t41 = getelementptr i8, ptr %t37, i64 %t36
  %t42 = load i8, ptr %t41, align 1
  %t43 = zext i8 %t42 to i64
  %t44 = icmp ult i64 40, 64
  br i1 %t44, label %ok_45, label %trap_45
trap_45:
  call void @abort()
  unreachable
ok_45:
  %t46 = shl i64 %t43, 40
  %t47 = or i64 %t35, %t46
  %t48 = add i64 %t11, 4
  %t49 = extractvalue %hia.buffer %p_1_1, 0
  %t50 = extractvalue %hia.buffer %p_1_1, 1
  %t51 = icmp ult i64 %t48, %t50
  br i1 %t51, label %ok_52, label %trap_52
trap_52:
  call void @abort()
  unreachable
ok_52:
  %t53 = getelementptr i8, ptr %t49, i64 %t48
  %t54 = load i8, ptr %t53, align 1
  %t55 = zext i8 %t54 to i64
  %t56 = icmp ult i64 32, 64
  br i1 %t56, label %ok_57, label %trap_57
trap_57:
  call void @abort()
  unreachable
ok_57:
  %t58 = shl i64 %t55, 32
  %t59 = or i64 %t47, %t58
  %t60 = add i64 %t11, 3
  %t61 = extractvalue %hia.buffer %p_1_1, 0
  %t62 = extractvalue %hia.buffer %p_1_1, 1
  %t63 = icmp ult i64 %t60, %t62
  br i1 %t63, label %ok_64, label %trap_64
trap_64:
  call void @abort()
  unreachable
ok_64:
  %t65 = getelementptr i8, ptr %t61, i64 %t60
  %t66 = load i8, ptr %t65, align 1
  %t67 = zext i8 %t66 to i64
  %t68 = icmp ult i64 24, 64
  br i1 %t68, label %ok_69, label %trap_69
trap_69:
  call void @abort()
  unreachable
ok_69:
  %t70 = shl i64 %t67, 24
  %t71 = or i64 %t59, %t70
  %t72 = add i64 %t11, 2
  %t73 = extractvalue %hia.buffer %p_1_1, 0
  %t74 = extractvalue %hia.buffer %p_1_1, 1
  %t75 = icmp ult i64 %t72, %t74
  br i1 %t75, label %ok_76, label %trap_76
trap_76:
  call void @abort()
  unreachable
ok_76:
  %t77 = getelementptr i8, ptr %t73, i64 %t72
  %t78 = load i8, ptr %t77, align 1
  %t79 = zext i8 %t78 to i64
  %t80 = icmp ult i64 16, 64
  br i1 %t80, label %ok_81, label %trap_81
trap_81:
  call void @abort()
  unreachable
ok_81:
  %t82 = shl i64 %t79, 16
  %t83 = or i64 %t71, %t82
  %t84 = add i64 %t11, 1
  %t85 = extractvalue %hia.buffer %p_1_1, 0
  %t86 = extractvalue %hia.buffer %p_1_1, 1
  %t87 = icmp ult i64 %t84, %t86
  br i1 %t87, label %ok_88, label %trap_88
trap_88:
  call void @abort()
  unreachable
ok_88:
  %t89 = getelementptr i8, ptr %t85, i64 %t84
  %t90 = load i8, ptr %t89, align 1
  %t91 = zext i8 %t90 to i64
  %t92 = icmp ult i64 8, 64
  br i1 %t92, label %ok_93, label %trap_93
trap_93:
  call void @abort()
  unreachable
ok_93:
  %t94 = shl i64 %t91, 8
  %t95 = or i64 %t83, %t94
  %t96 = add i64 %t11, 0
  %t97 = extractvalue %hia.buffer %p_1_1, 0
  %t98 = extractvalue %hia.buffer %p_1_1, 1
  %t99 = icmp ult i64 %t96, %t98
  br i1 %t99, label %ok_100, label %trap_100
trap_100:
  call void @abort()
  unreachable
ok_100:
  %t101 = getelementptr i8, ptr %t97, i64 %t96
  %t102 = load i8, ptr %t101, align 1
  %t103 = zext i8 %t102 to i64
  %t104 = icmp ult i64 0, 64
  br i1 %t104, label %ok_105, label %trap_105
trap_105:
  call void @abort()
  unreachable
ok_105:
  %t106 = shl i64 %t103, 0
  %t107 = or i64 %t95, %t106
  %t108 = trunc i64 8 to i32
  %t109 = zext i32 %t108 to i64
  %t110 = add i64 %t109, 7
  %t111 = extractvalue %hia.buffer %p_1_1, 0
  %t112 = extractvalue %hia.buffer %p_1_1, 1
  %t113 = icmp ult i64 %t110, %t112
  br i1 %t113, label %ok_114, label %trap_114
trap_114:
  call void @abort()
  unreachable
ok_114:
  %t115 = getelementptr i8, ptr %t111, i64 %t110
  %t116 = load i8, ptr %t115, align 1
  %t117 = zext i8 %t116 to i64
  %t118 = icmp ult i64 56, 64
  br i1 %t118, label %ok_119, label %trap_119
trap_119:
  call void @abort()
  unreachable
ok_119:
  %t120 = shl i64 %t117, 56
  %t121 = or i64 0, %t120
  %t122 = add i64 %t109, 6
  %t123 = extractvalue %hia.buffer %p_1_1, 0
  %t124 = extractvalue %hia.buffer %p_1_1, 1
  %t125 = icmp ult i64 %t122, %t124
  br i1 %t125, label %ok_126, label %trap_126
trap_126:
  call void @abort()
  unreachable
ok_126:
  %t127 = getelementptr i8, ptr %t123, i64 %t122
  %t128 = load i8, ptr %t127, align 1
  %t129 = zext i8 %t128 to i64
  %t130 = icmp ult i64 48, 64
  br i1 %t130, label %ok_131, label %trap_131
trap_131:
  call void @abort()
  unreachable
ok_131:
  %t132 = shl i64 %t129, 48
  %t133 = or i64 %t121, %t132
  %t134 = add i64 %t109, 5
  %t135 = extractvalue %hia.buffer %p_1_1, 0
  %t136 = extractvalue %hia.buffer %p_1_1, 1
  %t137 = icmp ult i64 %t134, %t136
  br i1 %t137, label %ok_138, label %trap_138
trap_138:
  call void @abort()
  unreachable
ok_138:
  %t139 = getelementptr i8, ptr %t135, i64 %t134
  %t140 = load i8, ptr %t139, align 1
  %t141 = zext i8 %t140 to i64
  %t142 = icmp ult i64 40, 64
  br i1 %t142, label %ok_143, label %trap_143
trap_143:
  call void @abort()
  unreachable
ok_143:
  %t144 = shl i64 %t141, 40
  %t145 = or i64 %t133, %t144
  %t146 = add i64 %t109, 4
  %t147 = extractvalue %hia.buffer %p_1_1, 0
  %t148 = extractvalue %hia.buffer %p_1_1, 1
  %t149 = icmp ult i64 %t146, %t148
  br i1 %t149, label %ok_150, label %trap_150
trap_150:
  call void @abort()
  unreachable
ok_150:
  %t151 = getelementptr i8, ptr %t147, i64 %t146
  %t152 = load i8, ptr %t151, align 1
  %t153 = zext i8 %t152 to i64
  %t154 = icmp ult i64 32, 64
  br i1 %t154, label %ok_155, label %trap_155
trap_155:
  call void @abort()
  unreachable
ok_155:
  %t156 = shl i64 %t153, 32
  %t157 = or i64 %t145, %t156
  %t158 = add i64 %t109, 3
  %t159 = extractvalue %hia.buffer %p_1_1, 0
  %t160 = extractvalue %hia.buffer %p_1_1, 1
  %t161 = icmp ult i64 %t158, %t160
  br i1 %t161, label %ok_162, label %trap_162
trap_162:
  call void @abort()
  unreachable
ok_162:
  %t163 = getelementptr i8, ptr %t159, i64 %t158
  %t164 = load i8, ptr %t163, align 1
  %t165 = zext i8 %t164 to i64
  %t166 = icmp ult i64 24, 64
  br i1 %t166, label %ok_167, label %trap_167
trap_167:
  call void @abort()
  unreachable
ok_167:
  %t168 = shl i64 %t165, 24
  %t169 = or i64 %t157, %t168
  %t170 = add i64 %t109, 2
  %t171 = extractvalue %hia.buffer %p_1_1, 0
  %t172 = extractvalue %hia.buffer %p_1_1, 1
  %t173 = icmp ult i64 %t170, %t172
  br i1 %t173, label %ok_174, label %trap_174
trap_174:
  call void @abort()
  unreachable
ok_174:
  %t175 = getelementptr i8, ptr %t171, i64 %t170
  %t176 = load i8, ptr %t175, align 1
  %t177 = zext i8 %t176 to i64
  %t178 = icmp ult i64 16, 64
  br i1 %t178, label %ok_179, label %trap_179
trap_179:
  call void @abort()
  unreachable
ok_179:
  %t180 = shl i64 %t177, 16
  %t181 = or i64 %t169, %t180
  %t182 = add i64 %t109, 1
  %t183 = extractvalue %hia.buffer %p_1_1, 0
  %t184 = extractvalue %hia.buffer %p_1_1, 1
  %t185 = icmp ult i64 %t182, %t184
  br i1 %t185, label %ok_186, label %trap_186
trap_186:
  call void @abort()
  unreachable
ok_186:
  %t187 = getelementptr i8, ptr %t183, i64 %t182
  %t188 = load i8, ptr %t187, align 1
  %t189 = zext i8 %t188 to i64
  %t190 = icmp ult i64 8, 64
  br i1 %t190, label %ok_191, label %trap_191
trap_191:
  call void @abort()
  unreachable
ok_191:
  %t192 = shl i64 %t189, 8
  %t193 = or i64 %t181, %t192
  %t194 = add i64 %t109, 0
  %t195 = extractvalue %hia.buffer %p_1_1, 0
  %t196 = extractvalue %hia.buffer %p_1_1, 1
  %t197 = icmp ult i64 %t194, %t196
  br i1 %t197, label %ok_198, label %trap_198
trap_198:
  call void @abort()
  unreachable
ok_198:
  %t199 = getelementptr i8, ptr %t195, i64 %t194
  %t200 = load i8, ptr %t199, align 1
  %t201 = zext i8 %t200 to i64
  %t202 = icmp ult i64 0, 64
  br i1 %t202, label %ok_203, label %trap_203
trap_203:
  call void @abort()
  unreachable
ok_203:
  %t204 = shl i64 %t201, 0
  %t205 = or i64 %t193, %t204
  %t206 = trunc i64 16 to i32
  %t207 = zext i32 %t206 to i64
  %t208 = add i64 %t207, 7
  %t209 = extractvalue %hia.buffer %p_1_1, 0
  %t210 = extractvalue %hia.buffer %p_1_1, 1
  %t211 = icmp ult i64 %t208, %t210
  br i1 %t211, label %ok_212, label %trap_212
trap_212:
  call void @abort()
  unreachable
ok_212:
  %t213 = getelementptr i8, ptr %t209, i64 %t208
  %t214 = load i8, ptr %t213, align 1
  %t215 = zext i8 %t214 to i64
  %t216 = icmp ult i64 56, 64
  br i1 %t216, label %ok_217, label %trap_217
trap_217:
  call void @abort()
  unreachable
ok_217:
  %t218 = shl i64 %t215, 56
  %t219 = or i64 0, %t218
  %t220 = add i64 %t207, 6
  %t221 = extractvalue %hia.buffer %p_1_1, 0
  %t222 = extractvalue %hia.buffer %p_1_1, 1
  %t223 = icmp ult i64 %t220, %t222
  br i1 %t223, label %ok_224, label %trap_224
trap_224:
  call void @abort()
  unreachable
ok_224:
  %t225 = getelementptr i8, ptr %t221, i64 %t220
  %t226 = load i8, ptr %t225, align 1
  %t227 = zext i8 %t226 to i64
  %t228 = icmp ult i64 48, 64
  br i1 %t228, label %ok_229, label %trap_229
trap_229:
  call void @abort()
  unreachable
ok_229:
  %t230 = shl i64 %t227, 48
  %t231 = or i64 %t219, %t230
  %t232 = add i64 %t207, 5
  %t233 = extractvalue %hia.buffer %p_1_1, 0
  %t234 = extractvalue %hia.buffer %p_1_1, 1
  %t235 = icmp ult i64 %t232, %t234
  br i1 %t235, label %ok_236, label %trap_236
trap_236:
  call void @abort()
  unreachable
ok_236:
  %t237 = getelementptr i8, ptr %t233, i64 %t232
  %t238 = load i8, ptr %t237, align 1
  %t239 = zext i8 %t238 to i64
  %t240 = icmp ult i64 40, 64
  br i1 %t240, label %ok_241, label %trap_241
trap_241:
  call void @abort()
  unreachable
ok_241:
  %t242 = shl i64 %t239, 40
  %t243 = or i64 %t231, %t242
  %t244 = add i64 %t207, 4
  %t245 = extractvalue %hia.buffer %p_1_1, 0
  %t246 = extractvalue %hia.buffer %p_1_1, 1
  %t247 = icmp ult i64 %t244, %t246
  br i1 %t247, label %ok_248, label %trap_248
trap_248:
  call void @abort()
  unreachable
ok_248:
  %t249 = getelementptr i8, ptr %t245, i64 %t244
  %t250 = load i8, ptr %t249, align 1
  %t251 = zext i8 %t250 to i64
  %t252 = icmp ult i64 32, 64
  br i1 %t252, label %ok_253, label %trap_253
trap_253:
  call void @abort()
  unreachable
ok_253:
  %t254 = shl i64 %t251, 32
  %t255 = or i64 %t243, %t254
  %t256 = add i64 %t207, 3
  %t257 = extractvalue %hia.buffer %p_1_1, 0
  %t258 = extractvalue %hia.buffer %p_1_1, 1
  %t259 = icmp ult i64 %t256, %t258
  br i1 %t259, label %ok_260, label %trap_260
trap_260:
  call void @abort()
  unreachable
ok_260:
  %t261 = getelementptr i8, ptr %t257, i64 %t256
  %t262 = load i8, ptr %t261, align 1
  %t263 = zext i8 %t262 to i64
  %t264 = icmp ult i64 24, 64
  br i1 %t264, label %ok_265, label %trap_265
trap_265:
  call void @abort()
  unreachable
ok_265:
  %t266 = shl i64 %t263, 24
  %t267 = or i64 %t255, %t266
  %t268 = add i64 %t207, 2
  %t269 = extractvalue %hia.buffer %p_1_1, 0
  %t270 = extractvalue %hia.buffer %p_1_1, 1
  %t271 = icmp ult i64 %t268, %t270
  br i1 %t271, label %ok_272, label %trap_272
trap_272:
  call void @abort()
  unreachable
ok_272:
  %t273 = getelementptr i8, ptr %t269, i64 %t268
  %t274 = load i8, ptr %t273, align 1
  %t275 = zext i8 %t274 to i64
  %t276 = icmp ult i64 16, 64
  br i1 %t276, label %ok_277, label %trap_277
trap_277:
  call void @abort()
  unreachable
ok_277:
  %t278 = shl i64 %t275, 16
  %t279 = or i64 %t267, %t278
  %t280 = add i64 %t207, 1
  %t281 = extractvalue %hia.buffer %p_1_1, 0
  %t282 = extractvalue %hia.buffer %p_1_1, 1
  %t283 = icmp ult i64 %t280, %t282
  br i1 %t283, label %ok_284, label %trap_284
trap_284:
  call void @abort()
  unreachable
ok_284:
  %t285 = getelementptr i8, ptr %t281, i64 %t280
  %t286 = load i8, ptr %t285, align 1
  %t287 = zext i8 %t286 to i64
  %t288 = icmp ult i64 8, 64
  br i1 %t288, label %ok_289, label %trap_289
trap_289:
  call void @abort()
  unreachable
ok_289:
  %t290 = shl i64 %t287, 8
  %t291 = or i64 %t279, %t290
  %t292 = add i64 %t207, 0
  %t293 = extractvalue %hia.buffer %p_1_1, 0
  %t294 = extractvalue %hia.buffer %p_1_1, 1
  %t295 = icmp ult i64 %t292, %t294
  br i1 %t295, label %ok_296, label %trap_296
trap_296:
  call void @abort()
  unreachable
ok_296:
  %t297 = getelementptr i8, ptr %t293, i64 %t292
  %t298 = load i8, ptr %t297, align 1
  %t299 = zext i8 %t298 to i64
  %t300 = icmp ult i64 0, 64
  br i1 %t300, label %ok_301, label %trap_301
trap_301:
  call void @abort()
  unreachable
ok_301:
  %t302 = shl i64 %t299, 0
  %t303 = or i64 %t291, %t302
  %t304 = trunc i64 24 to i32
  %t305 = zext i32 %t304 to i64
  %t306 = add i64 %t305, 7
  %t307 = extractvalue %hia.buffer %p_1_1, 0
  %t308 = extractvalue %hia.buffer %p_1_1, 1
  %t309 = icmp ult i64 %t306, %t308
  br i1 %t309, label %ok_310, label %trap_310
trap_310:
  call void @abort()
  unreachable
ok_310:
  %t311 = getelementptr i8, ptr %t307, i64 %t306
  %t312 = load i8, ptr %t311, align 1
  %t313 = zext i8 %t312 to i64
  %t314 = icmp ult i64 56, 64
  br i1 %t314, label %ok_315, label %trap_315
trap_315:
  call void @abort()
  unreachable
ok_315:
  %t316 = shl i64 %t313, 56
  %t317 = or i64 0, %t316
  %t318 = add i64 %t305, 6
  %t319 = extractvalue %hia.buffer %p_1_1, 0
  %t320 = extractvalue %hia.buffer %p_1_1, 1
  %t321 = icmp ult i64 %t318, %t320
  br i1 %t321, label %ok_322, label %trap_322
trap_322:
  call void @abort()
  unreachable
ok_322:
  %t323 = getelementptr i8, ptr %t319, i64 %t318
  %t324 = load i8, ptr %t323, align 1
  %t325 = zext i8 %t324 to i64
  %t326 = icmp ult i64 48, 64
  br i1 %t326, label %ok_327, label %trap_327
trap_327:
  call void @abort()
  unreachable
ok_327:
  %t328 = shl i64 %t325, 48
  %t329 = or i64 %t317, %t328
  %t330 = add i64 %t305, 5
  %t331 = extractvalue %hia.buffer %p_1_1, 0
  %t332 = extractvalue %hia.buffer %p_1_1, 1
  %t333 = icmp ult i64 %t330, %t332
  br i1 %t333, label %ok_334, label %trap_334
trap_334:
  call void @abort()
  unreachable
ok_334:
  %t335 = getelementptr i8, ptr %t331, i64 %t330
  %t336 = load i8, ptr %t335, align 1
  %t337 = zext i8 %t336 to i64
  %t338 = icmp ult i64 40, 64
  br i1 %t338, label %ok_339, label %trap_339
trap_339:
  call void @abort()
  unreachable
ok_339:
  %t340 = shl i64 %t337, 40
  %t341 = or i64 %t329, %t340
  %t342 = add i64 %t305, 4
  %t343 = extractvalue %hia.buffer %p_1_1, 0
  %t344 = extractvalue %hia.buffer %p_1_1, 1
  %t345 = icmp ult i64 %t342, %t344
  br i1 %t345, label %ok_346, label %trap_346
trap_346:
  call void @abort()
  unreachable
ok_346:
  %t347 = getelementptr i8, ptr %t343, i64 %t342
  %t348 = load i8, ptr %t347, align 1
  %t349 = zext i8 %t348 to i64
  %t350 = icmp ult i64 32, 64
  br i1 %t350, label %ok_351, label %trap_351
trap_351:
  call void @abort()
  unreachable
ok_351:
  %t352 = shl i64 %t349, 32
  %t353 = or i64 %t341, %t352
  %t354 = add i64 %t305, 3
  %t355 = extractvalue %hia.buffer %p_1_1, 0
  %t356 = extractvalue %hia.buffer %p_1_1, 1
  %t357 = icmp ult i64 %t354, %t356
  br i1 %t357, label %ok_358, label %trap_358
trap_358:
  call void @abort()
  unreachable
ok_358:
  %t359 = getelementptr i8, ptr %t355, i64 %t354
  %t360 = load i8, ptr %t359, align 1
  %t361 = zext i8 %t360 to i64
  %t362 = icmp ult i64 24, 64
  br i1 %t362, label %ok_363, label %trap_363
trap_363:
  call void @abort()
  unreachable
ok_363:
  %t364 = shl i64 %t361, 24
  %t365 = or i64 %t353, %t364
  %t366 = add i64 %t305, 2
  %t367 = extractvalue %hia.buffer %p_1_1, 0
  %t368 = extractvalue %hia.buffer %p_1_1, 1
  %t369 = icmp ult i64 %t366, %t368
  br i1 %t369, label %ok_370, label %trap_370
trap_370:
  call void @abort()
  unreachable
ok_370:
  %t371 = getelementptr i8, ptr %t367, i64 %t366
  %t372 = load i8, ptr %t371, align 1
  %t373 = zext i8 %t372 to i64
  %t374 = icmp ult i64 16, 64
  br i1 %t374, label %ok_375, label %trap_375
trap_375:
  call void @abort()
  unreachable
ok_375:
  %t376 = shl i64 %t373, 16
  %t377 = or i64 %t365, %t376
  %t378 = add i64 %t305, 1
  %t379 = extractvalue %hia.buffer %p_1_1, 0
  %t380 = extractvalue %hia.buffer %p_1_1, 1
  %t381 = icmp ult i64 %t378, %t380
  br i1 %t381, label %ok_382, label %trap_382
trap_382:
  call void @abort()
  unreachable
ok_382:
  %t383 = getelementptr i8, ptr %t379, i64 %t378
  %t384 = load i8, ptr %t383, align 1
  %t385 = zext i8 %t384 to i64
  %t386 = icmp ult i64 8, 64
  br i1 %t386, label %ok_387, label %trap_387
trap_387:
  call void @abort()
  unreachable
ok_387:
  %t388 = shl i64 %t385, 8
  %t389 = or i64 %t377, %t388
  %t390 = add i64 %t305, 0
  %t391 = extractvalue %hia.buffer %p_1_1, 0
  %t392 = extractvalue %hia.buffer %p_1_1, 1
  %t393 = icmp ult i64 %t390, %t392
  br i1 %t393, label %ok_394, label %trap_394
trap_394:
  call void @abort()
  unreachable
ok_394:
  %t395 = getelementptr i8, ptr %t391, i64 %t390
  %t396 = load i8, ptr %t395, align 1
  %t397 = zext i8 %t396 to i64
  %t398 = icmp ult i64 0, 64
  br i1 %t398, label %ok_399, label %trap_399
trap_399:
  call void @abort()
  unreachable
ok_399:
  %t400 = shl i64 %t397, 0
  %t401 = or i64 %t389, %t400
  %t402 = extractvalue %hia.buffer %p_1_0, 1
  %t403 = icmp ule i64 %t303, %t402
  %t404 = sub i64 %t402, %t303
  %t405 = icmp ule i64 %t401, %t404
  %t406 = and i1 %t403, %t405
  br i1 %t406, label %edge_2, label %edge_3
b2:
  ret i32 4294836225
b3:
  ret i32 0
b4:
  ret i32 1
b5:
  %p_5_0 = phi %hia.buffer [ %p_1_0, %edge_2 ]
  %p_5_1 = phi %hia.buffer [ %p_1_1, %edge_2 ]
  %p_5_2 = phi i64 [ %t107, %edge_2 ]
  %p_5_3 = phi i64 [ %t205, %edge_2 ]
  %p_5_4 = phi i64 [ %t303, %edge_2 ]
  %p_5_5 = phi i64 [ %t401, %edge_2 ]
  %p_5_6 = phi i64 [ %t402, %edge_2 ]
  %p_5_7 = phi i64 [ %p_1_2, %edge_2 ]
  %p_5_8 = phi i32 [ %p_1_3, %edge_2 ]
  %p_5_9 = phi i32 [ %p_1_4, %edge_2 ]
  %t407 = icmp eq i64 %p_5_3, 0
  %t408 = select i1 %t407, i64 %p_5_7, i64 %p_5_3
  %t409 = trunc i64 8 to i32
  %t410 = zext i32 %t409 to i64
  %t411 = icmp ult i64 56, 64
  br i1 %t411, label %ok_412, label %trap_412
trap_412:
  call void @abort()
  unreachable
ok_412:
  %t413 = lshr i64 %t408, 56
  %t414 = trunc i64 %t413 to i8
  %t415 = add i64 %t410, 7
  %t416 = extractvalue %hia.buffer %p_5_1, 0
  %t417 = extractvalue %hia.buffer %p_5_1, 1
  %t418 = icmp ult i64 %t415, %t417
  br i1 %t418, label %ok_419, label %trap_419
trap_419:
  call void @abort()
  unreachable
ok_419:
  %t420 = getelementptr i8, ptr %t416, i64 %t415
  store i8 %t414, ptr %t420, align 1
  %t421 = icmp ult i64 48, 64
  br i1 %t421, label %ok_422, label %trap_422
trap_422:
  call void @abort()
  unreachable
ok_422:
  %t423 = lshr i64 %t408, 48
  %t424 = trunc i64 %t423 to i8
  %t425 = add i64 %t410, 6
  %t426 = extractvalue %hia.buffer %p_5_1, 0
  %t427 = extractvalue %hia.buffer %p_5_1, 1
  %t428 = icmp ult i64 %t425, %t427
  br i1 %t428, label %ok_429, label %trap_429
trap_429:
  call void @abort()
  unreachable
ok_429:
  %t430 = getelementptr i8, ptr %t426, i64 %t425
  store i8 %t424, ptr %t430, align 1
  %t431 = icmp ult i64 40, 64
  br i1 %t431, label %ok_432, label %trap_432
trap_432:
  call void @abort()
  unreachable
ok_432:
  %t433 = lshr i64 %t408, 40
  %t434 = trunc i64 %t433 to i8
  %t435 = add i64 %t410, 5
  %t436 = extractvalue %hia.buffer %p_5_1, 0
  %t437 = extractvalue %hia.buffer %p_5_1, 1
  %t438 = icmp ult i64 %t435, %t437
  br i1 %t438, label %ok_439, label %trap_439
trap_439:
  call void @abort()
  unreachable
ok_439:
  %t440 = getelementptr i8, ptr %t436, i64 %t435
  store i8 %t434, ptr %t440, align 1
  %t441 = icmp ult i64 32, 64
  br i1 %t441, label %ok_442, label %trap_442
trap_442:
  call void @abort()
  unreachable
ok_442:
  %t443 = lshr i64 %t408, 32
  %t444 = trunc i64 %t443 to i8
  %t445 = add i64 %t410, 4
  %t446 = extractvalue %hia.buffer %p_5_1, 0
  %t447 = extractvalue %hia.buffer %p_5_1, 1
  %t448 = icmp ult i64 %t445, %t447
  br i1 %t448, label %ok_449, label %trap_449
trap_449:
  call void @abort()
  unreachable
ok_449:
  %t450 = getelementptr i8, ptr %t446, i64 %t445
  store i8 %t444, ptr %t450, align 1
  %t451 = icmp ult i64 24, 64
  br i1 %t451, label %ok_452, label %trap_452
trap_452:
  call void @abort()
  unreachable
ok_452:
  %t453 = lshr i64 %t408, 24
  %t454 = trunc i64 %t453 to i8
  %t455 = add i64 %t410, 3
  %t456 = extractvalue %hia.buffer %p_5_1, 0
  %t457 = extractvalue %hia.buffer %p_5_1, 1
  %t458 = icmp ult i64 %t455, %t457
  br i1 %t458, label %ok_459, label %trap_459
trap_459:
  call void @abort()
  unreachable
ok_459:
  %t460 = getelementptr i8, ptr %t456, i64 %t455
  store i8 %t454, ptr %t460, align 1
  %t461 = icmp ult i64 16, 64
  br i1 %t461, label %ok_462, label %trap_462
trap_462:
  call void @abort()
  unreachable
ok_462:
  %t463 = lshr i64 %t408, 16
  %t464 = trunc i64 %t463 to i8
  %t465 = add i64 %t410, 2
  %t466 = extractvalue %hia.buffer %p_5_1, 0
  %t467 = extractvalue %hia.buffer %p_5_1, 1
  %t468 = icmp ult i64 %t465, %t467
  br i1 %t468, label %ok_469, label %trap_469
trap_469:
  call void @abort()
  unreachable
ok_469:
  %t470 = getelementptr i8, ptr %t466, i64 %t465
  store i8 %t464, ptr %t470, align 1
  %t471 = icmp ult i64 8, 64
  br i1 %t471, label %ok_472, label %trap_472
trap_472:
  call void @abort()
  unreachable
ok_472:
  %t473 = lshr i64 %t408, 8
  %t474 = trunc i64 %t473 to i8
  %t475 = add i64 %t410, 1
  %t476 = extractvalue %hia.buffer %p_5_1, 0
  %t477 = extractvalue %hia.buffer %p_5_1, 1
  %t478 = icmp ult i64 %t475, %t477
  br i1 %t478, label %ok_479, label %trap_479
trap_479:
  call void @abort()
  unreachable
ok_479:
  %t480 = getelementptr i8, ptr %t476, i64 %t475
  store i8 %t474, ptr %t480, align 1
  %t481 = icmp ult i64 0, 64
  br i1 %t481, label %ok_482, label %trap_482
trap_482:
  call void @abort()
  unreachable
ok_482:
  %t483 = lshr i64 %t408, 0
  %t484 = trunc i64 %t483 to i8
  %t485 = add i64 %t410, 0
  %t486 = extractvalue %hia.buffer %p_5_1, 0
  %t487 = extractvalue %hia.buffer %p_5_1, 1
  %t488 = icmp ult i64 %t485, %t487
  br i1 %t488, label %ok_489, label %trap_489
trap_489:
  call void @abort()
  unreachable
ok_489:
  %t490 = getelementptr i8, ptr %t486, i64 %t485
  store i8 %t484, ptr %t490, align 1
  %t491 = icmp eq i64 %p_5_2, 4294967295
  %t492 = icmp ne i32 %p_5_8, 0
  %t493 = icmp sgt i64 %p_5_7, %t408
  %t494 = and i1 %t492, %t493
  %t495 = xor i1 %t491, true
  %t496 = or i1 %t495, %t494
  %t497 = select i1 %t491, i64 0, i64 %p_5_2
  %t498 = select i1 %t491, i64 %p_5_7, i64 %t408
  br i1 %t496, label %edge_4, label %edge_5
b6:
  %p_6_0 = phi %hia.buffer [ %p_5_0, %edge_4 ]
  %p_6_1 = phi %hia.buffer [ %p_5_1, %edge_4 ]
  %p_6_2 = phi i64 [ %t497, %edge_4 ]
  %p_6_3 = phi i64 [ %t498, %edge_4 ]
  %p_6_4 = phi i64 [ %p_5_4, %edge_4 ]
  %p_6_5 = phi i64 [ %p_5_5, %edge_4 ]
  %p_6_6 = phi i64 [ %p_5_6, %edge_4 ]
  %p_6_7 = phi i64 [ %p_5_7, %edge_4 ]
  %p_6_8 = phi i32 [ %p_5_8, %edge_4 ]
  %p_6_9 = phi i32 [ %p_5_9, %edge_4 ]
  %t499 = add i64 %p_6_2, 1
  %t500 = trunc i64 0 to i32
  %t501 = zext i32 %t500 to i64
  %t502 = icmp ult i64 56, 64
  br i1 %t502, label %ok_503, label %trap_503
trap_503:
  call void @abort()
  unreachable
ok_503:
  %t504 = lshr i64 %t499, 56
  %t505 = trunc i64 %t504 to i8
  %t506 = add i64 %t501, 7
  %t507 = extractvalue %hia.buffer %p_6_1, 0
  %t508 = extractvalue %hia.buffer %p_6_1, 1
  %t509 = icmp ult i64 %t506, %t508
  br i1 %t509, label %ok_510, label %trap_510
trap_510:
  call void @abort()
  unreachable
ok_510:
  %t511 = getelementptr i8, ptr %t507, i64 %t506
  store i8 %t505, ptr %t511, align 1
  %t512 = icmp ult i64 48, 64
  br i1 %t512, label %ok_513, label %trap_513
trap_513:
  call void @abort()
  unreachable
ok_513:
  %t514 = lshr i64 %t499, 48
  %t515 = trunc i64 %t514 to i8
  %t516 = add i64 %t501, 6
  %t517 = extractvalue %hia.buffer %p_6_1, 0
  %t518 = extractvalue %hia.buffer %p_6_1, 1
  %t519 = icmp ult i64 %t516, %t518
  br i1 %t519, label %ok_520, label %trap_520
trap_520:
  call void @abort()
  unreachable
ok_520:
  %t521 = getelementptr i8, ptr %t517, i64 %t516
  store i8 %t515, ptr %t521, align 1
  %t522 = icmp ult i64 40, 64
  br i1 %t522, label %ok_523, label %trap_523
trap_523:
  call void @abort()
  unreachable
ok_523:
  %t524 = lshr i64 %t499, 40
  %t525 = trunc i64 %t524 to i8
  %t526 = add i64 %t501, 5
  %t527 = extractvalue %hia.buffer %p_6_1, 0
  %t528 = extractvalue %hia.buffer %p_6_1, 1
  %t529 = icmp ult i64 %t526, %t528
  br i1 %t529, label %ok_530, label %trap_530
trap_530:
  call void @abort()
  unreachable
ok_530:
  %t531 = getelementptr i8, ptr %t527, i64 %t526
  store i8 %t525, ptr %t531, align 1
  %t532 = icmp ult i64 32, 64
  br i1 %t532, label %ok_533, label %trap_533
trap_533:
  call void @abort()
  unreachable
ok_533:
  %t534 = lshr i64 %t499, 32
  %t535 = trunc i64 %t534 to i8
  %t536 = add i64 %t501, 4
  %t537 = extractvalue %hia.buffer %p_6_1, 0
  %t538 = extractvalue %hia.buffer %p_6_1, 1
  %t539 = icmp ult i64 %t536, %t538
  br i1 %t539, label %ok_540, label %trap_540
trap_540:
  call void @abort()
  unreachable
ok_540:
  %t541 = getelementptr i8, ptr %t537, i64 %t536
  store i8 %t535, ptr %t541, align 1
  %t542 = icmp ult i64 24, 64
  br i1 %t542, label %ok_543, label %trap_543
trap_543:
  call void @abort()
  unreachable
ok_543:
  %t544 = lshr i64 %t499, 24
  %t545 = trunc i64 %t544 to i8
  %t546 = add i64 %t501, 3
  %t547 = extractvalue %hia.buffer %p_6_1, 0
  %t548 = extractvalue %hia.buffer %p_6_1, 1
  %t549 = icmp ult i64 %t546, %t548
  br i1 %t549, label %ok_550, label %trap_550
trap_550:
  call void @abort()
  unreachable
ok_550:
  %t551 = getelementptr i8, ptr %t547, i64 %t546
  store i8 %t545, ptr %t551, align 1
  %t552 = icmp ult i64 16, 64
  br i1 %t552, label %ok_553, label %trap_553
trap_553:
  call void @abort()
  unreachable
ok_553:
  %t554 = lshr i64 %t499, 16
  %t555 = trunc i64 %t554 to i8
  %t556 = add i64 %t501, 2
  %t557 = extractvalue %hia.buffer %p_6_1, 0
  %t558 = extractvalue %hia.buffer %p_6_1, 1
  %t559 = icmp ult i64 %t556, %t558
  br i1 %t559, label %ok_560, label %trap_560
trap_560:
  call void @abort()
  unreachable
ok_560:
  %t561 = getelementptr i8, ptr %t557, i64 %t556
  store i8 %t555, ptr %t561, align 1
  %t562 = icmp ult i64 8, 64
  br i1 %t562, label %ok_563, label %trap_563
trap_563:
  call void @abort()
  unreachable
ok_563:
  %t564 = lshr i64 %t499, 8
  %t565 = trunc i64 %t564 to i8
  %t566 = add i64 %t501, 1
  %t567 = extractvalue %hia.buffer %p_6_1, 0
  %t568 = extractvalue %hia.buffer %p_6_1, 1
  %t569 = icmp ult i64 %t566, %t568
  br i1 %t569, label %ok_570, label %trap_570
trap_570:
  call void @abort()
  unreachable
ok_570:
  %t571 = getelementptr i8, ptr %t567, i64 %t566
  store i8 %t565, ptr %t571, align 1
  %t572 = icmp ult i64 0, 64
  br i1 %t572, label %ok_573, label %trap_573
trap_573:
  call void @abort()
  unreachable
ok_573:
  %t574 = lshr i64 %t499, 0
  %t575 = trunc i64 %t574 to i8
  %t576 = add i64 %t501, 0
  %t577 = extractvalue %hia.buffer %p_6_1, 0
  %t578 = extractvalue %hia.buffer %p_6_1, 1
  %t579 = icmp ult i64 %t576, %t578
  br i1 %t579, label %ok_580, label %trap_580
trap_580:
  call void @abort()
  unreachable
ok_580:
  %t581 = getelementptr i8, ptr %t577, i64 %t576
  store i8 %t575, ptr %t581, align 1
  %t582 = trunc i64 8 to i32
  %t583 = zext i32 %t582 to i64
  %t584 = icmp ult i64 56, 64
  br i1 %t584, label %ok_585, label %trap_585
trap_585:
  call void @abort()
  unreachable
ok_585:
  %t586 = lshr i64 %p_6_3, 56
  %t587 = trunc i64 %t586 to i8
  %t588 = add i64 %t583, 7
  %t589 = extractvalue %hia.buffer %p_6_1, 0
  %t590 = extractvalue %hia.buffer %p_6_1, 1
  %t591 = icmp ult i64 %t588, %t590
  br i1 %t591, label %ok_592, label %trap_592
trap_592:
  call void @abort()
  unreachable
ok_592:
  %t593 = getelementptr i8, ptr %t589, i64 %t588
  store i8 %t587, ptr %t593, align 1
  %t594 = icmp ult i64 48, 64
  br i1 %t594, label %ok_595, label %trap_595
trap_595:
  call void @abort()
  unreachable
ok_595:
  %t596 = lshr i64 %p_6_3, 48
  %t597 = trunc i64 %t596 to i8
  %t598 = add i64 %t583, 6
  %t599 = extractvalue %hia.buffer %p_6_1, 0
  %t600 = extractvalue %hia.buffer %p_6_1, 1
  %t601 = icmp ult i64 %t598, %t600
  br i1 %t601, label %ok_602, label %trap_602
trap_602:
  call void @abort()
  unreachable
ok_602:
  %t603 = getelementptr i8, ptr %t599, i64 %t598
  store i8 %t597, ptr %t603, align 1
  %t604 = icmp ult i64 40, 64
  br i1 %t604, label %ok_605, label %trap_605
trap_605:
  call void @abort()
  unreachable
ok_605:
  %t606 = lshr i64 %p_6_3, 40
  %t607 = trunc i64 %t606 to i8
  %t608 = add i64 %t583, 5
  %t609 = extractvalue %hia.buffer %p_6_1, 0
  %t610 = extractvalue %hia.buffer %p_6_1, 1
  %t611 = icmp ult i64 %t608, %t610
  br i1 %t611, label %ok_612, label %trap_612
trap_612:
  call void @abort()
  unreachable
ok_612:
  %t613 = getelementptr i8, ptr %t609, i64 %t608
  store i8 %t607, ptr %t613, align 1
  %t614 = icmp ult i64 32, 64
  br i1 %t614, label %ok_615, label %trap_615
trap_615:
  call void @abort()
  unreachable
ok_615:
  %t616 = lshr i64 %p_6_3, 32
  %t617 = trunc i64 %t616 to i8
  %t618 = add i64 %t583, 4
  %t619 = extractvalue %hia.buffer %p_6_1, 0
  %t620 = extractvalue %hia.buffer %p_6_1, 1
  %t621 = icmp ult i64 %t618, %t620
  br i1 %t621, label %ok_622, label %trap_622
trap_622:
  call void @abort()
  unreachable
ok_622:
  %t623 = getelementptr i8, ptr %t619, i64 %t618
  store i8 %t617, ptr %t623, align 1
  %t624 = icmp ult i64 24, 64
  br i1 %t624, label %ok_625, label %trap_625
trap_625:
  call void @abort()
  unreachable
ok_625:
  %t626 = lshr i64 %p_6_3, 24
  %t627 = trunc i64 %t626 to i8
  %t628 = add i64 %t583, 3
  %t629 = extractvalue %hia.buffer %p_6_1, 0
  %t630 = extractvalue %hia.buffer %p_6_1, 1
  %t631 = icmp ult i64 %t628, %t630
  br i1 %t631, label %ok_632, label %trap_632
trap_632:
  call void @abort()
  unreachable
ok_632:
  %t633 = getelementptr i8, ptr %t629, i64 %t628
  store i8 %t627, ptr %t633, align 1
  %t634 = icmp ult i64 16, 64
  br i1 %t634, label %ok_635, label %trap_635
trap_635:
  call void @abort()
  unreachable
ok_635:
  %t636 = lshr i64 %p_6_3, 16
  %t637 = trunc i64 %t636 to i8
  %t638 = add i64 %t583, 2
  %t639 = extractvalue %hia.buffer %p_6_1, 0
  %t640 = extractvalue %hia.buffer %p_6_1, 1
  %t641 = icmp ult i64 %t638, %t640
  br i1 %t641, label %ok_642, label %trap_642
trap_642:
  call void @abort()
  unreachable
ok_642:
  %t643 = getelementptr i8, ptr %t639, i64 %t638
  store i8 %t637, ptr %t643, align 1
  %t644 = icmp ult i64 8, 64
  br i1 %t644, label %ok_645, label %trap_645
trap_645:
  call void @abort()
  unreachable
ok_645:
  %t646 = lshr i64 %p_6_3, 8
  %t647 = trunc i64 %t646 to i8
  %t648 = add i64 %t583, 1
  %t649 = extractvalue %hia.buffer %p_6_1, 0
  %t650 = extractvalue %hia.buffer %p_6_1, 1
  %t651 = icmp ult i64 %t648, %t650
  br i1 %t651, label %ok_652, label %trap_652
trap_652:
  call void @abort()
  unreachable
ok_652:
  %t653 = getelementptr i8, ptr %t649, i64 %t648
  store i8 %t647, ptr %t653, align 1
  %t654 = icmp ult i64 0, 64
  br i1 %t654, label %ok_655, label %trap_655
trap_655:
  call void @abort()
  unreachable
ok_655:
  %t656 = lshr i64 %p_6_3, 0
  %t657 = trunc i64 %t656 to i8
  %t658 = add i64 %t583, 0
  %t659 = extractvalue %hia.buffer %p_6_1, 0
  %t660 = extractvalue %hia.buffer %p_6_1, 1
  %t661 = icmp ult i64 %t658, %t660
  br i1 %t661, label %ok_662, label %trap_662
trap_662:
  call void @abort()
  unreachable
ok_662:
  %t663 = getelementptr i8, ptr %t659, i64 %t658
  store i8 %t657, ptr %t663, align 1
  %t664 = icmp ne i32 %p_6_9, 0
  br i1 %t664, label %edge_6, label %edge_7
b7:
  %p_7_0 = phi %hia.buffer [ %p_6_0, %edge_7 ]
  %p_7_1 = phi %hia.buffer [ %p_6_1, %edge_7 ]
  %p_7_2 = phi i64 [ %t499, %edge_7 ]
  %p_7_3 = phi i64 [ %p_6_3, %edge_7 ]
  %p_7_4 = phi i64 [ %p_6_4, %edge_7 ]
  %p_7_5 = phi i64 [ %p_6_5, %edge_7 ]
  %p_7_6 = phi i64 [ %p_6_6, %edge_7 ]
  %p_7_7 = phi i64 [ %p_6_7, %edge_7 ]
  %p_7_8 = phi i32 [ %p_6_8, %edge_7 ]
  %p_7_9 = phi i32 [ %p_6_9, %edge_7 ]
  %t665 = add i64 %p_7_4, %p_7_5
  %t666 = sub i64 %p_7_6, %t665
  %t667 = icmp uge i64 %t666, 4
  br i1 %t667, label %edge_8, label %edge_9
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
  %t668 = add i64 %p_8_4, %p_8_5
  %t669 = trunc i64 %t668 to i32
  %t670 = zext i32 %t669 to i64
  %t671 = icmp ult i64 0, 64
  br i1 %t671, label %ok_672, label %trap_672
trap_672:
  call void @abort()
  unreachable
ok_672:
  %t673 = lshr i64 %p_8_2, 0
  %t674 = trunc i64 %t673 to i8
  %t675 = add i64 %t670, 3
  %t676 = extractvalue %hia.buffer %p_8_0, 0
  %t677 = extractvalue %hia.buffer %p_8_0, 1
  %t678 = icmp ult i64 %t675, %t677
  br i1 %t678, label %ok_679, label %trap_679
trap_679:
  call void @abort()
  unreachable
ok_679:
  %t680 = getelementptr i8, ptr %t676, i64 %t675
  store i8 %t674, ptr %t680, align 1
  %t681 = icmp ult i64 8, 64
  br i1 %t681, label %ok_682, label %trap_682
trap_682:
  call void @abort()
  unreachable
ok_682:
  %t683 = lshr i64 %p_8_2, 8
  %t684 = trunc i64 %t683 to i8
  %t685 = add i64 %t670, 2
  %t686 = extractvalue %hia.buffer %p_8_0, 0
  %t687 = extractvalue %hia.buffer %p_8_0, 1
  %t688 = icmp ult i64 %t685, %t687
  br i1 %t688, label %ok_689, label %trap_689
trap_689:
  call void @abort()
  unreachable
ok_689:
  %t690 = getelementptr i8, ptr %t686, i64 %t685
  store i8 %t684, ptr %t690, align 1
  %t691 = icmp ult i64 16, 64
  br i1 %t691, label %ok_692, label %trap_692
trap_692:
  call void @abort()
  unreachable
ok_692:
  %t693 = lshr i64 %p_8_2, 16
  %t694 = trunc i64 %t693 to i8
  %t695 = add i64 %t670, 1
  %t696 = extractvalue %hia.buffer %p_8_0, 0
  %t697 = extractvalue %hia.buffer %p_8_0, 1
  %t698 = icmp ult i64 %t695, %t697
  br i1 %t698, label %ok_699, label %trap_699
trap_699:
  call void @abort()
  unreachable
ok_699:
  %t700 = getelementptr i8, ptr %t696, i64 %t695
  store i8 %t694, ptr %t700, align 1
  %t701 = icmp ult i64 24, 64
  br i1 %t701, label %ok_702, label %trap_702
trap_702:
  call void @abort()
  unreachable
ok_702:
  %t703 = lshr i64 %p_8_2, 24
  %t704 = trunc i64 %t703 to i8
  %t705 = add i64 %t670, 0
  %t706 = extractvalue %hia.buffer %p_8_0, 0
  %t707 = extractvalue %hia.buffer %p_8_0, 1
  %t708 = icmp ult i64 %t705, %t707
  br i1 %t708, label %ok_709, label %trap_709
trap_709:
  call void @abort()
  unreachable
ok_709:
  %t710 = getelementptr i8, ptr %t706, i64 %t705
  store i8 %t704, ptr %t710, align 1
  %t711 = add i64 %p_8_5, 4
  %t712 = trunc i64 24 to i32
  %t713 = zext i32 %t712 to i64
  %t714 = icmp ult i64 56, 64
  br i1 %t714, label %ok_715, label %trap_715
trap_715:
  call void @abort()
  unreachable
ok_715:
  %t716 = lshr i64 %t711, 56
  %t717 = trunc i64 %t716 to i8
  %t718 = add i64 %t713, 7
  %t719 = extractvalue %hia.buffer %p_8_1, 0
  %t720 = extractvalue %hia.buffer %p_8_1, 1
  %t721 = icmp ult i64 %t718, %t720
  br i1 %t721, label %ok_722, label %trap_722
trap_722:
  call void @abort()
  unreachable
ok_722:
  %t723 = getelementptr i8, ptr %t719, i64 %t718
  store i8 %t717, ptr %t723, align 1
  %t724 = icmp ult i64 48, 64
  br i1 %t724, label %ok_725, label %trap_725
trap_725:
  call void @abort()
  unreachable
ok_725:
  %t726 = lshr i64 %t711, 48
  %t727 = trunc i64 %t726 to i8
  %t728 = add i64 %t713, 6
  %t729 = extractvalue %hia.buffer %p_8_1, 0
  %t730 = extractvalue %hia.buffer %p_8_1, 1
  %t731 = icmp ult i64 %t728, %t730
  br i1 %t731, label %ok_732, label %trap_732
trap_732:
  call void @abort()
  unreachable
ok_732:
  %t733 = getelementptr i8, ptr %t729, i64 %t728
  store i8 %t727, ptr %t733, align 1
  %t734 = icmp ult i64 40, 64
  br i1 %t734, label %ok_735, label %trap_735
trap_735:
  call void @abort()
  unreachable
ok_735:
  %t736 = lshr i64 %t711, 40
  %t737 = trunc i64 %t736 to i8
  %t738 = add i64 %t713, 5
  %t739 = extractvalue %hia.buffer %p_8_1, 0
  %t740 = extractvalue %hia.buffer %p_8_1, 1
  %t741 = icmp ult i64 %t738, %t740
  br i1 %t741, label %ok_742, label %trap_742
trap_742:
  call void @abort()
  unreachable
ok_742:
  %t743 = getelementptr i8, ptr %t739, i64 %t738
  store i8 %t737, ptr %t743, align 1
  %t744 = icmp ult i64 32, 64
  br i1 %t744, label %ok_745, label %trap_745
trap_745:
  call void @abort()
  unreachable
ok_745:
  %t746 = lshr i64 %t711, 32
  %t747 = trunc i64 %t746 to i8
  %t748 = add i64 %t713, 4
  %t749 = extractvalue %hia.buffer %p_8_1, 0
  %t750 = extractvalue %hia.buffer %p_8_1, 1
  %t751 = icmp ult i64 %t748, %t750
  br i1 %t751, label %ok_752, label %trap_752
trap_752:
  call void @abort()
  unreachable
ok_752:
  %t753 = getelementptr i8, ptr %t749, i64 %t748
  store i8 %t747, ptr %t753, align 1
  %t754 = icmp ult i64 24, 64
  br i1 %t754, label %ok_755, label %trap_755
trap_755:
  call void @abort()
  unreachable
ok_755:
  %t756 = lshr i64 %t711, 24
  %t757 = trunc i64 %t756 to i8
  %t758 = add i64 %t713, 3
  %t759 = extractvalue %hia.buffer %p_8_1, 0
  %t760 = extractvalue %hia.buffer %p_8_1, 1
  %t761 = icmp ult i64 %t758, %t760
  br i1 %t761, label %ok_762, label %trap_762
trap_762:
  call void @abort()
  unreachable
ok_762:
  %t763 = getelementptr i8, ptr %t759, i64 %t758
  store i8 %t757, ptr %t763, align 1
  %t764 = icmp ult i64 16, 64
  br i1 %t764, label %ok_765, label %trap_765
trap_765:
  call void @abort()
  unreachable
ok_765:
  %t766 = lshr i64 %t711, 16
  %t767 = trunc i64 %t766 to i8
  %t768 = add i64 %t713, 2
  %t769 = extractvalue %hia.buffer %p_8_1, 0
  %t770 = extractvalue %hia.buffer %p_8_1, 1
  %t771 = icmp ult i64 %t768, %t770
  br i1 %t771, label %ok_772, label %trap_772
trap_772:
  call void @abort()
  unreachable
ok_772:
  %t773 = getelementptr i8, ptr %t769, i64 %t768
  store i8 %t767, ptr %t773, align 1
  %t774 = icmp ult i64 8, 64
  br i1 %t774, label %ok_775, label %trap_775
trap_775:
  call void @abort()
  unreachable
ok_775:
  %t776 = lshr i64 %t711, 8
  %t777 = trunc i64 %t776 to i8
  %t778 = add i64 %t713, 1
  %t779 = extractvalue %hia.buffer %p_8_1, 0
  %t780 = extractvalue %hia.buffer %p_8_1, 1
  %t781 = icmp ult i64 %t778, %t780
  br i1 %t781, label %ok_782, label %trap_782
trap_782:
  call void @abort()
  unreachable
ok_782:
  %t783 = getelementptr i8, ptr %t779, i64 %t778
  store i8 %t777, ptr %t783, align 1
  %t784 = icmp ult i64 0, 64
  br i1 %t784, label %ok_785, label %trap_785
trap_785:
  call void @abort()
  unreachable
ok_785:
  %t786 = lshr i64 %t711, 0
  %t787 = trunc i64 %t786 to i8
  %t788 = add i64 %t713, 0
  %t789 = extractvalue %hia.buffer %p_8_1, 0
  %t790 = extractvalue %hia.buffer %p_8_1, 1
  %t791 = icmp ult i64 %t788, %t790
  br i1 %t791, label %ok_792, label %trap_792
trap_792:
  call void @abort()
  unreachable
ok_792:
  %t793 = getelementptr i8, ptr %t789, i64 %t788
  store i8 %t787, ptr %t793, align 1
  %t794 = icmp ne i32 %p_8_8, 0
  br i1 %t794, label %edge_10, label %edge_11
b9:
  %p_9_0 = phi %hia.buffer [ %p_8_0, %edge_10 ]
  %p_9_1 = phi %hia.buffer [ %p_8_1, %edge_10 ]
  %p_9_2 = phi i64 [ %p_8_2, %edge_10 ]
  %p_9_3 = phi i64 [ %p_8_3, %edge_10 ]
  %p_9_4 = phi i64 [ %p_8_4, %edge_10 ]
  %p_9_5 = phi i64 [ %t711, %edge_10 ]
  %p_9_6 = phi i64 [ %p_8_6, %edge_10 ]
  %p_9_7 = phi i64 [ %p_8_7, %edge_10 ]
  %p_9_8 = phi i32 [ %p_8_8, %edge_10 ]
  %p_9_9 = phi i32 [ %p_8_9, %edge_10 ]
  %t795 = add i64 %p_9_4, %p_9_5
  %t796 = sub i64 %p_9_6, %t795
  %t797 = icmp uge i64 %t796, 4
  br i1 %t797, label %edge_12, label %edge_13
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
  %t798 = add i64 %p_10_4, %p_10_5
  %t799 = trunc i64 %t798 to i32
  %t800 = zext i32 %t799 to i64
  %t801 = icmp ult i64 0, 64
  br i1 %t801, label %ok_802, label %trap_802
trap_802:
  call void @abort()
  unreachable
ok_802:
  %t803 = lshr i64 %p_10_3, 0
  %t804 = trunc i64 %t803 to i8
  %t805 = add i64 %t800, 3
  %t806 = extractvalue %hia.buffer %p_10_0, 0
  %t807 = extractvalue %hia.buffer %p_10_0, 1
  %t808 = icmp ult i64 %t805, %t807
  br i1 %t808, label %ok_809, label %trap_809
trap_809:
  call void @abort()
  unreachable
ok_809:
  %t810 = getelementptr i8, ptr %t806, i64 %t805
  store i8 %t804, ptr %t810, align 1
  %t811 = icmp ult i64 8, 64
  br i1 %t811, label %ok_812, label %trap_812
trap_812:
  call void @abort()
  unreachable
ok_812:
  %t813 = lshr i64 %p_10_3, 8
  %t814 = trunc i64 %t813 to i8
  %t815 = add i64 %t800, 2
  %t816 = extractvalue %hia.buffer %p_10_0, 0
  %t817 = extractvalue %hia.buffer %p_10_0, 1
  %t818 = icmp ult i64 %t815, %t817
  br i1 %t818, label %ok_819, label %trap_819
trap_819:
  call void @abort()
  unreachable
ok_819:
  %t820 = getelementptr i8, ptr %t816, i64 %t815
  store i8 %t814, ptr %t820, align 1
  %t821 = icmp ult i64 16, 64
  br i1 %t821, label %ok_822, label %trap_822
trap_822:
  call void @abort()
  unreachable
ok_822:
  %t823 = lshr i64 %p_10_3, 16
  %t824 = trunc i64 %t823 to i8
  %t825 = add i64 %t800, 1
  %t826 = extractvalue %hia.buffer %p_10_0, 0
  %t827 = extractvalue %hia.buffer %p_10_0, 1
  %t828 = icmp ult i64 %t825, %t827
  br i1 %t828, label %ok_829, label %trap_829
trap_829:
  call void @abort()
  unreachable
ok_829:
  %t830 = getelementptr i8, ptr %t826, i64 %t825
  store i8 %t824, ptr %t830, align 1
  %t831 = icmp ult i64 24, 64
  br i1 %t831, label %ok_832, label %trap_832
trap_832:
  call void @abort()
  unreachable
ok_832:
  %t833 = lshr i64 %p_10_3, 24
  %t834 = trunc i64 %t833 to i8
  %t835 = add i64 %t800, 0
  %t836 = extractvalue %hia.buffer %p_10_0, 0
  %t837 = extractvalue %hia.buffer %p_10_0, 1
  %t838 = icmp ult i64 %t835, %t837
  br i1 %t838, label %ok_839, label %trap_839
trap_839:
  call void @abort()
  unreachable
ok_839:
  %t840 = getelementptr i8, ptr %t836, i64 %t835
  store i8 %t834, ptr %t840, align 1
  %t841 = add i64 %p_10_5, 4
  %t842 = trunc i64 24 to i32
  %t843 = zext i32 %t842 to i64
  %t844 = icmp ult i64 56, 64
  br i1 %t844, label %ok_845, label %trap_845
trap_845:
  call void @abort()
  unreachable
ok_845:
  %t846 = lshr i64 %t841, 56
  %t847 = trunc i64 %t846 to i8
  %t848 = add i64 %t843, 7
  %t849 = extractvalue %hia.buffer %p_10_1, 0
  %t850 = extractvalue %hia.buffer %p_10_1, 1
  %t851 = icmp ult i64 %t848, %t850
  br i1 %t851, label %ok_852, label %trap_852
trap_852:
  call void @abort()
  unreachable
ok_852:
  %t853 = getelementptr i8, ptr %t849, i64 %t848
  store i8 %t847, ptr %t853, align 1
  %t854 = icmp ult i64 48, 64
  br i1 %t854, label %ok_855, label %trap_855
trap_855:
  call void @abort()
  unreachable
ok_855:
  %t856 = lshr i64 %t841, 48
  %t857 = trunc i64 %t856 to i8
  %t858 = add i64 %t843, 6
  %t859 = extractvalue %hia.buffer %p_10_1, 0
  %t860 = extractvalue %hia.buffer %p_10_1, 1
  %t861 = icmp ult i64 %t858, %t860
  br i1 %t861, label %ok_862, label %trap_862
trap_862:
  call void @abort()
  unreachable
ok_862:
  %t863 = getelementptr i8, ptr %t859, i64 %t858
  store i8 %t857, ptr %t863, align 1
  %t864 = icmp ult i64 40, 64
  br i1 %t864, label %ok_865, label %trap_865
trap_865:
  call void @abort()
  unreachable
ok_865:
  %t866 = lshr i64 %t841, 40
  %t867 = trunc i64 %t866 to i8
  %t868 = add i64 %t843, 5
  %t869 = extractvalue %hia.buffer %p_10_1, 0
  %t870 = extractvalue %hia.buffer %p_10_1, 1
  %t871 = icmp ult i64 %t868, %t870
  br i1 %t871, label %ok_872, label %trap_872
trap_872:
  call void @abort()
  unreachable
ok_872:
  %t873 = getelementptr i8, ptr %t869, i64 %t868
  store i8 %t867, ptr %t873, align 1
  %t874 = icmp ult i64 32, 64
  br i1 %t874, label %ok_875, label %trap_875
trap_875:
  call void @abort()
  unreachable
ok_875:
  %t876 = lshr i64 %t841, 32
  %t877 = trunc i64 %t876 to i8
  %t878 = add i64 %t843, 4
  %t879 = extractvalue %hia.buffer %p_10_1, 0
  %t880 = extractvalue %hia.buffer %p_10_1, 1
  %t881 = icmp ult i64 %t878, %t880
  br i1 %t881, label %ok_882, label %trap_882
trap_882:
  call void @abort()
  unreachable
ok_882:
  %t883 = getelementptr i8, ptr %t879, i64 %t878
  store i8 %t877, ptr %t883, align 1
  %t884 = icmp ult i64 24, 64
  br i1 %t884, label %ok_885, label %trap_885
trap_885:
  call void @abort()
  unreachable
ok_885:
  %t886 = lshr i64 %t841, 24
  %t887 = trunc i64 %t886 to i8
  %t888 = add i64 %t843, 3
  %t889 = extractvalue %hia.buffer %p_10_1, 0
  %t890 = extractvalue %hia.buffer %p_10_1, 1
  %t891 = icmp ult i64 %t888, %t890
  br i1 %t891, label %ok_892, label %trap_892
trap_892:
  call void @abort()
  unreachable
ok_892:
  %t893 = getelementptr i8, ptr %t889, i64 %t888
  store i8 %t887, ptr %t893, align 1
  %t894 = icmp ult i64 16, 64
  br i1 %t894, label %ok_895, label %trap_895
trap_895:
  call void @abort()
  unreachable
ok_895:
  %t896 = lshr i64 %t841, 16
  %t897 = trunc i64 %t896 to i8
  %t898 = add i64 %t843, 2
  %t899 = extractvalue %hia.buffer %p_10_1, 0
  %t900 = extractvalue %hia.buffer %p_10_1, 1
  %t901 = icmp ult i64 %t898, %t900
  br i1 %t901, label %ok_902, label %trap_902
trap_902:
  call void @abort()
  unreachable
ok_902:
  %t903 = getelementptr i8, ptr %t899, i64 %t898
  store i8 %t897, ptr %t903, align 1
  %t904 = icmp ult i64 8, 64
  br i1 %t904, label %ok_905, label %trap_905
trap_905:
  call void @abort()
  unreachable
ok_905:
  %t906 = lshr i64 %t841, 8
  %t907 = trunc i64 %t906 to i8
  %t908 = add i64 %t843, 1
  %t909 = extractvalue %hia.buffer %p_10_1, 0
  %t910 = extractvalue %hia.buffer %p_10_1, 1
  %t911 = icmp ult i64 %t908, %t910
  br i1 %t911, label %ok_912, label %trap_912
trap_912:
  call void @abort()
  unreachable
ok_912:
  %t913 = getelementptr i8, ptr %t909, i64 %t908
  store i8 %t907, ptr %t913, align 1
  %t914 = icmp ult i64 0, 64
  br i1 %t914, label %ok_915, label %trap_915
trap_915:
  call void @abort()
  unreachable
ok_915:
  %t916 = lshr i64 %t841, 0
  %t917 = trunc i64 %t916 to i8
  %t918 = add i64 %t843, 0
  %t919 = extractvalue %hia.buffer %p_10_1, 0
  %t920 = extractvalue %hia.buffer %p_10_1, 1
  %t921 = icmp ult i64 %t918, %t920
  br i1 %t921, label %ok_922, label %trap_922
trap_922:
  call void @abort()
  unreachable
ok_922:
  %t923 = getelementptr i8, ptr %t919, i64 %t918
  store i8 %t917, ptr %t923, align 1
  br label %edge_14
b11:
  %p_11_0 = phi %hia.buffer [ %p_6_0, %edge_6 ]
  %p_11_1 = phi %hia.buffer [ %p_6_1, %edge_6 ]
  %p_11_2 = phi i64 [ %t499, %edge_6 ]
  %p_11_3 = phi i64 [ %p_6_3, %edge_6 ]
  %p_11_4 = phi i64 [ %p_6_4, %edge_6 ]
  %p_11_5 = phi i64 [ %p_6_5, %edge_6 ]
  %p_11_6 = phi i64 [ %p_6_6, %edge_6 ]
  %p_11_7 = phi i64 [ %p_6_7, %edge_6 ]
  %p_11_8 = phi i32 [ %p_6_8, %edge_6 ]
  %p_11_9 = phi i32 [ %p_6_9, %edge_6 ]
  %t924 = icmp ne i32 %p_11_8, 0
  br i1 %t924, label %edge_15, label %edge_16
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
  %t925 = icmp uge i64 %p_12_4, 4
  br i1 %t925, label %edge_17, label %edge_18
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
  %t926 = sub i64 %p_13_4, 4
  %t927 = add i64 %p_13_5, 4
  %t928 = trunc i64 %t926 to i32
  %t929 = zext i32 %t928 to i64
  %t930 = icmp ult i64 0, 64
  br i1 %t930, label %ok_931, label %trap_931
trap_931:
  call void @abort()
  unreachable
ok_931:
  %t932 = lshr i64 %p_13_3, 0
  %t933 = trunc i64 %t932 to i8
  %t934 = add i64 %t929, 3
  %t935 = extractvalue %hia.buffer %p_13_0, 0
  %t936 = extractvalue %hia.buffer %p_13_0, 1
  %t937 = icmp ult i64 %t934, %t936
  br i1 %t937, label %ok_938, label %trap_938
trap_938:
  call void @abort()
  unreachable
ok_938:
  %t939 = getelementptr i8, ptr %t935, i64 %t934
  store i8 %t933, ptr %t939, align 1
  %t940 = icmp ult i64 8, 64
  br i1 %t940, label %ok_941, label %trap_941
trap_941:
  call void @abort()
  unreachable
ok_941:
  %t942 = lshr i64 %p_13_3, 8
  %t943 = trunc i64 %t942 to i8
  %t944 = add i64 %t929, 2
  %t945 = extractvalue %hia.buffer %p_13_0, 0
  %t946 = extractvalue %hia.buffer %p_13_0, 1
  %t947 = icmp ult i64 %t944, %t946
  br i1 %t947, label %ok_948, label %trap_948
trap_948:
  call void @abort()
  unreachable
ok_948:
  %t949 = getelementptr i8, ptr %t945, i64 %t944
  store i8 %t943, ptr %t949, align 1
  %t950 = icmp ult i64 16, 64
  br i1 %t950, label %ok_951, label %trap_951
trap_951:
  call void @abort()
  unreachable
ok_951:
  %t952 = lshr i64 %p_13_3, 16
  %t953 = trunc i64 %t952 to i8
  %t954 = add i64 %t929, 1
  %t955 = extractvalue %hia.buffer %p_13_0, 0
  %t956 = extractvalue %hia.buffer %p_13_0, 1
  %t957 = icmp ult i64 %t954, %t956
  br i1 %t957, label %ok_958, label %trap_958
trap_958:
  call void @abort()
  unreachable
ok_958:
  %t959 = getelementptr i8, ptr %t955, i64 %t954
  store i8 %t953, ptr %t959, align 1
  %t960 = icmp ult i64 24, 64
  br i1 %t960, label %ok_961, label %trap_961
trap_961:
  call void @abort()
  unreachable
ok_961:
  %t962 = lshr i64 %p_13_3, 24
  %t963 = trunc i64 %t962 to i8
  %t964 = add i64 %t929, 0
  %t965 = extractvalue %hia.buffer %p_13_0, 0
  %t966 = extractvalue %hia.buffer %p_13_0, 1
  %t967 = icmp ult i64 %t964, %t966
  br i1 %t967, label %ok_968, label %trap_968
trap_968:
  call void @abort()
  unreachable
ok_968:
  %t969 = getelementptr i8, ptr %t965, i64 %t964
  store i8 %t963, ptr %t969, align 1
  %t970 = trunc i64 16 to i32
  %t971 = zext i32 %t970 to i64
  %t972 = icmp ult i64 56, 64
  br i1 %t972, label %ok_973, label %trap_973
trap_973:
  call void @abort()
  unreachable
ok_973:
  %t974 = lshr i64 %t926, 56
  %t975 = trunc i64 %t974 to i8
  %t976 = add i64 %t971, 7
  %t977 = extractvalue %hia.buffer %p_13_1, 0
  %t978 = extractvalue %hia.buffer %p_13_1, 1
  %t979 = icmp ult i64 %t976, %t978
  br i1 %t979, label %ok_980, label %trap_980
trap_980:
  call void @abort()
  unreachable
ok_980:
  %t981 = getelementptr i8, ptr %t977, i64 %t976
  store i8 %t975, ptr %t981, align 1
  %t982 = icmp ult i64 48, 64
  br i1 %t982, label %ok_983, label %trap_983
trap_983:
  call void @abort()
  unreachable
ok_983:
  %t984 = lshr i64 %t926, 48
  %t985 = trunc i64 %t984 to i8
  %t986 = add i64 %t971, 6
  %t987 = extractvalue %hia.buffer %p_13_1, 0
  %t988 = extractvalue %hia.buffer %p_13_1, 1
  %t989 = icmp ult i64 %t986, %t988
  br i1 %t989, label %ok_990, label %trap_990
trap_990:
  call void @abort()
  unreachable
ok_990:
  %t991 = getelementptr i8, ptr %t987, i64 %t986
  store i8 %t985, ptr %t991, align 1
  %t992 = icmp ult i64 40, 64
  br i1 %t992, label %ok_993, label %trap_993
trap_993:
  call void @abort()
  unreachable
ok_993:
  %t994 = lshr i64 %t926, 40
  %t995 = trunc i64 %t994 to i8
  %t996 = add i64 %t971, 5
  %t997 = extractvalue %hia.buffer %p_13_1, 0
  %t998 = extractvalue %hia.buffer %p_13_1, 1
  %t999 = icmp ult i64 %t996, %t998
  br i1 %t999, label %ok_1000, label %trap_1000
trap_1000:
  call void @abort()
  unreachable
ok_1000:
  %t1001 = getelementptr i8, ptr %t997, i64 %t996
  store i8 %t995, ptr %t1001, align 1
  %t1002 = icmp ult i64 32, 64
  br i1 %t1002, label %ok_1003, label %trap_1003
trap_1003:
  call void @abort()
  unreachable
ok_1003:
  %t1004 = lshr i64 %t926, 32
  %t1005 = trunc i64 %t1004 to i8
  %t1006 = add i64 %t971, 4
  %t1007 = extractvalue %hia.buffer %p_13_1, 0
  %t1008 = extractvalue %hia.buffer %p_13_1, 1
  %t1009 = icmp ult i64 %t1006, %t1008
  br i1 %t1009, label %ok_1010, label %trap_1010
trap_1010:
  call void @abort()
  unreachable
ok_1010:
  %t1011 = getelementptr i8, ptr %t1007, i64 %t1006
  store i8 %t1005, ptr %t1011, align 1
  %t1012 = icmp ult i64 24, 64
  br i1 %t1012, label %ok_1013, label %trap_1013
trap_1013:
  call void @abort()
  unreachable
ok_1013:
  %t1014 = lshr i64 %t926, 24
  %t1015 = trunc i64 %t1014 to i8
  %t1016 = add i64 %t971, 3
  %t1017 = extractvalue %hia.buffer %p_13_1, 0
  %t1018 = extractvalue %hia.buffer %p_13_1, 1
  %t1019 = icmp ult i64 %t1016, %t1018
  br i1 %t1019, label %ok_1020, label %trap_1020
trap_1020:
  call void @abort()
  unreachable
ok_1020:
  %t1021 = getelementptr i8, ptr %t1017, i64 %t1016
  store i8 %t1015, ptr %t1021, align 1
  %t1022 = icmp ult i64 16, 64
  br i1 %t1022, label %ok_1023, label %trap_1023
trap_1023:
  call void @abort()
  unreachable
ok_1023:
  %t1024 = lshr i64 %t926, 16
  %t1025 = trunc i64 %t1024 to i8
  %t1026 = add i64 %t971, 2
  %t1027 = extractvalue %hia.buffer %p_13_1, 0
  %t1028 = extractvalue %hia.buffer %p_13_1, 1
  %t1029 = icmp ult i64 %t1026, %t1028
  br i1 %t1029, label %ok_1030, label %trap_1030
trap_1030:
  call void @abort()
  unreachable
ok_1030:
  %t1031 = getelementptr i8, ptr %t1027, i64 %t1026
  store i8 %t1025, ptr %t1031, align 1
  %t1032 = icmp ult i64 8, 64
  br i1 %t1032, label %ok_1033, label %trap_1033
trap_1033:
  call void @abort()
  unreachable
ok_1033:
  %t1034 = lshr i64 %t926, 8
  %t1035 = trunc i64 %t1034 to i8
  %t1036 = add i64 %t971, 1
  %t1037 = extractvalue %hia.buffer %p_13_1, 0
  %t1038 = extractvalue %hia.buffer %p_13_1, 1
  %t1039 = icmp ult i64 %t1036, %t1038
  br i1 %t1039, label %ok_1040, label %trap_1040
trap_1040:
  call void @abort()
  unreachable
ok_1040:
  %t1041 = getelementptr i8, ptr %t1037, i64 %t1036
  store i8 %t1035, ptr %t1041, align 1
  %t1042 = icmp ult i64 0, 64
  br i1 %t1042, label %ok_1043, label %trap_1043
trap_1043:
  call void @abort()
  unreachable
ok_1043:
  %t1044 = lshr i64 %t926, 0
  %t1045 = trunc i64 %t1044 to i8
  %t1046 = add i64 %t971, 0
  %t1047 = extractvalue %hia.buffer %p_13_1, 0
  %t1048 = extractvalue %hia.buffer %p_13_1, 1
  %t1049 = icmp ult i64 %t1046, %t1048
  br i1 %t1049, label %ok_1050, label %trap_1050
trap_1050:
  call void @abort()
  unreachable
ok_1050:
  %t1051 = getelementptr i8, ptr %t1047, i64 %t1046
  store i8 %t1045, ptr %t1051, align 1
  %t1052 = trunc i64 24 to i32
  %t1053 = zext i32 %t1052 to i64
  %t1054 = icmp ult i64 56, 64
  br i1 %t1054, label %ok_1055, label %trap_1055
trap_1055:
  call void @abort()
  unreachable
ok_1055:
  %t1056 = lshr i64 %t927, 56
  %t1057 = trunc i64 %t1056 to i8
  %t1058 = add i64 %t1053, 7
  %t1059 = extractvalue %hia.buffer %p_13_1, 0
  %t1060 = extractvalue %hia.buffer %p_13_1, 1
  %t1061 = icmp ult i64 %t1058, %t1060
  br i1 %t1061, label %ok_1062, label %trap_1062
trap_1062:
  call void @abort()
  unreachable
ok_1062:
  %t1063 = getelementptr i8, ptr %t1059, i64 %t1058
  store i8 %t1057, ptr %t1063, align 1
  %t1064 = icmp ult i64 48, 64
  br i1 %t1064, label %ok_1065, label %trap_1065
trap_1065:
  call void @abort()
  unreachable
ok_1065:
  %t1066 = lshr i64 %t927, 48
  %t1067 = trunc i64 %t1066 to i8
  %t1068 = add i64 %t1053, 6
  %t1069 = extractvalue %hia.buffer %p_13_1, 0
  %t1070 = extractvalue %hia.buffer %p_13_1, 1
  %t1071 = icmp ult i64 %t1068, %t1070
  br i1 %t1071, label %ok_1072, label %trap_1072
trap_1072:
  call void @abort()
  unreachable
ok_1072:
  %t1073 = getelementptr i8, ptr %t1069, i64 %t1068
  store i8 %t1067, ptr %t1073, align 1
  %t1074 = icmp ult i64 40, 64
  br i1 %t1074, label %ok_1075, label %trap_1075
trap_1075:
  call void @abort()
  unreachable
ok_1075:
  %t1076 = lshr i64 %t927, 40
  %t1077 = trunc i64 %t1076 to i8
  %t1078 = add i64 %t1053, 5
  %t1079 = extractvalue %hia.buffer %p_13_1, 0
  %t1080 = extractvalue %hia.buffer %p_13_1, 1
  %t1081 = icmp ult i64 %t1078, %t1080
  br i1 %t1081, label %ok_1082, label %trap_1082
trap_1082:
  call void @abort()
  unreachable
ok_1082:
  %t1083 = getelementptr i8, ptr %t1079, i64 %t1078
  store i8 %t1077, ptr %t1083, align 1
  %t1084 = icmp ult i64 32, 64
  br i1 %t1084, label %ok_1085, label %trap_1085
trap_1085:
  call void @abort()
  unreachable
ok_1085:
  %t1086 = lshr i64 %t927, 32
  %t1087 = trunc i64 %t1086 to i8
  %t1088 = add i64 %t1053, 4
  %t1089 = extractvalue %hia.buffer %p_13_1, 0
  %t1090 = extractvalue %hia.buffer %p_13_1, 1
  %t1091 = icmp ult i64 %t1088, %t1090
  br i1 %t1091, label %ok_1092, label %trap_1092
trap_1092:
  call void @abort()
  unreachable
ok_1092:
  %t1093 = getelementptr i8, ptr %t1089, i64 %t1088
  store i8 %t1087, ptr %t1093, align 1
  %t1094 = icmp ult i64 24, 64
  br i1 %t1094, label %ok_1095, label %trap_1095
trap_1095:
  call void @abort()
  unreachable
ok_1095:
  %t1096 = lshr i64 %t927, 24
  %t1097 = trunc i64 %t1096 to i8
  %t1098 = add i64 %t1053, 3
  %t1099 = extractvalue %hia.buffer %p_13_1, 0
  %t1100 = extractvalue %hia.buffer %p_13_1, 1
  %t1101 = icmp ult i64 %t1098, %t1100
  br i1 %t1101, label %ok_1102, label %trap_1102
trap_1102:
  call void @abort()
  unreachable
ok_1102:
  %t1103 = getelementptr i8, ptr %t1099, i64 %t1098
  store i8 %t1097, ptr %t1103, align 1
  %t1104 = icmp ult i64 16, 64
  br i1 %t1104, label %ok_1105, label %trap_1105
trap_1105:
  call void @abort()
  unreachable
ok_1105:
  %t1106 = lshr i64 %t927, 16
  %t1107 = trunc i64 %t1106 to i8
  %t1108 = add i64 %t1053, 2
  %t1109 = extractvalue %hia.buffer %p_13_1, 0
  %t1110 = extractvalue %hia.buffer %p_13_1, 1
  %t1111 = icmp ult i64 %t1108, %t1110
  br i1 %t1111, label %ok_1112, label %trap_1112
trap_1112:
  call void @abort()
  unreachable
ok_1112:
  %t1113 = getelementptr i8, ptr %t1109, i64 %t1108
  store i8 %t1107, ptr %t1113, align 1
  %t1114 = icmp ult i64 8, 64
  br i1 %t1114, label %ok_1115, label %trap_1115
trap_1115:
  call void @abort()
  unreachable
ok_1115:
  %t1116 = lshr i64 %t927, 8
  %t1117 = trunc i64 %t1116 to i8
  %t1118 = add i64 %t1053, 1
  %t1119 = extractvalue %hia.buffer %p_13_1, 0
  %t1120 = extractvalue %hia.buffer %p_13_1, 1
  %t1121 = icmp ult i64 %t1118, %t1120
  br i1 %t1121, label %ok_1122, label %trap_1122
trap_1122:
  call void @abort()
  unreachable
ok_1122:
  %t1123 = getelementptr i8, ptr %t1119, i64 %t1118
  store i8 %t1117, ptr %t1123, align 1
  %t1124 = icmp ult i64 0, 64
  br i1 %t1124, label %ok_1125, label %trap_1125
trap_1125:
  call void @abort()
  unreachable
ok_1125:
  %t1126 = lshr i64 %t927, 0
  %t1127 = trunc i64 %t1126 to i8
  %t1128 = add i64 %t1053, 0
  %t1129 = extractvalue %hia.buffer %p_13_1, 0
  %t1130 = extractvalue %hia.buffer %p_13_1, 1
  %t1131 = icmp ult i64 %t1128, %t1130
  br i1 %t1131, label %ok_1132, label %trap_1132
trap_1132:
  call void @abort()
  unreachable
ok_1132:
  %t1133 = getelementptr i8, ptr %t1129, i64 %t1128
  store i8 %t1127, ptr %t1133, align 1
  br label %edge_19
b14:
  %p_14_0 = phi %hia.buffer [ %p_11_0, %edge_16 ], [ %p_13_0, %edge_19 ]
  %p_14_1 = phi %hia.buffer [ %p_11_1, %edge_16 ], [ %p_13_1, %edge_19 ]
  %p_14_2 = phi i64 [ %p_11_2, %edge_16 ], [ %p_13_2, %edge_19 ]
  %p_14_3 = phi i64 [ %p_11_3, %edge_16 ], [ %p_13_3, %edge_19 ]
  %p_14_4 = phi i64 [ %p_11_4, %edge_16 ], [ %t926, %edge_19 ]
  %p_14_5 = phi i64 [ %p_11_5, %edge_16 ], [ %t927, %edge_19 ]
  %p_14_6 = phi i64 [ %p_11_6, %edge_16 ], [ %p_13_6, %edge_19 ]
  %p_14_7 = phi i64 [ %p_11_7, %edge_16 ], [ %p_13_7, %edge_19 ]
  %p_14_8 = phi i32 [ %p_11_8, %edge_16 ], [ %p_13_8, %edge_19 ]
  %p_14_9 = phi i32 [ %p_11_9, %edge_16 ], [ %p_13_9, %edge_19 ]
  %t1134 = icmp uge i64 %p_14_4, 4
  br i1 %t1134, label %edge_20, label %edge_21
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
  %t1135 = sub i64 %p_15_4, 4
  %t1136 = add i64 %p_15_5, 4
  %t1137 = trunc i64 %t1135 to i32
  %t1138 = zext i32 %t1137 to i64
  %t1139 = icmp ult i64 0, 64
  br i1 %t1139, label %ok_1140, label %trap_1140
trap_1140:
  call void @abort()
  unreachable
ok_1140:
  %t1141 = lshr i64 %p_15_2, 0
  %t1142 = trunc i64 %t1141 to i8
  %t1143 = add i64 %t1138, 3
  %t1144 = extractvalue %hia.buffer %p_15_0, 0
  %t1145 = extractvalue %hia.buffer %p_15_0, 1
  %t1146 = icmp ult i64 %t1143, %t1145
  br i1 %t1146, label %ok_1147, label %trap_1147
trap_1147:
  call void @abort()
  unreachable
ok_1147:
  %t1148 = getelementptr i8, ptr %t1144, i64 %t1143
  store i8 %t1142, ptr %t1148, align 1
  %t1149 = icmp ult i64 8, 64
  br i1 %t1149, label %ok_1150, label %trap_1150
trap_1150:
  call void @abort()
  unreachable
ok_1150:
  %t1151 = lshr i64 %p_15_2, 8
  %t1152 = trunc i64 %t1151 to i8
  %t1153 = add i64 %t1138, 2
  %t1154 = extractvalue %hia.buffer %p_15_0, 0
  %t1155 = extractvalue %hia.buffer %p_15_0, 1
  %t1156 = icmp ult i64 %t1153, %t1155
  br i1 %t1156, label %ok_1157, label %trap_1157
trap_1157:
  call void @abort()
  unreachable
ok_1157:
  %t1158 = getelementptr i8, ptr %t1154, i64 %t1153
  store i8 %t1152, ptr %t1158, align 1
  %t1159 = icmp ult i64 16, 64
  br i1 %t1159, label %ok_1160, label %trap_1160
trap_1160:
  call void @abort()
  unreachable
ok_1160:
  %t1161 = lshr i64 %p_15_2, 16
  %t1162 = trunc i64 %t1161 to i8
  %t1163 = add i64 %t1138, 1
  %t1164 = extractvalue %hia.buffer %p_15_0, 0
  %t1165 = extractvalue %hia.buffer %p_15_0, 1
  %t1166 = icmp ult i64 %t1163, %t1165
  br i1 %t1166, label %ok_1167, label %trap_1167
trap_1167:
  call void @abort()
  unreachable
ok_1167:
  %t1168 = getelementptr i8, ptr %t1164, i64 %t1163
  store i8 %t1162, ptr %t1168, align 1
  %t1169 = icmp ult i64 24, 64
  br i1 %t1169, label %ok_1170, label %trap_1170
trap_1170:
  call void @abort()
  unreachable
ok_1170:
  %t1171 = lshr i64 %p_15_2, 24
  %t1172 = trunc i64 %t1171 to i8
  %t1173 = add i64 %t1138, 0
  %t1174 = extractvalue %hia.buffer %p_15_0, 0
  %t1175 = extractvalue %hia.buffer %p_15_0, 1
  %t1176 = icmp ult i64 %t1173, %t1175
  br i1 %t1176, label %ok_1177, label %trap_1177
trap_1177:
  call void @abort()
  unreachable
ok_1177:
  %t1178 = getelementptr i8, ptr %t1174, i64 %t1173
  store i8 %t1172, ptr %t1178, align 1
  %t1179 = trunc i64 16 to i32
  %t1180 = zext i32 %t1179 to i64
  %t1181 = icmp ult i64 56, 64
  br i1 %t1181, label %ok_1182, label %trap_1182
trap_1182:
  call void @abort()
  unreachable
ok_1182:
  %t1183 = lshr i64 %t1135, 56
  %t1184 = trunc i64 %t1183 to i8
  %t1185 = add i64 %t1180, 7
  %t1186 = extractvalue %hia.buffer %p_15_1, 0
  %t1187 = extractvalue %hia.buffer %p_15_1, 1
  %t1188 = icmp ult i64 %t1185, %t1187
  br i1 %t1188, label %ok_1189, label %trap_1189
trap_1189:
  call void @abort()
  unreachable
ok_1189:
  %t1190 = getelementptr i8, ptr %t1186, i64 %t1185
  store i8 %t1184, ptr %t1190, align 1
  %t1191 = icmp ult i64 48, 64
  br i1 %t1191, label %ok_1192, label %trap_1192
trap_1192:
  call void @abort()
  unreachable
ok_1192:
  %t1193 = lshr i64 %t1135, 48
  %t1194 = trunc i64 %t1193 to i8
  %t1195 = add i64 %t1180, 6
  %t1196 = extractvalue %hia.buffer %p_15_1, 0
  %t1197 = extractvalue %hia.buffer %p_15_1, 1
  %t1198 = icmp ult i64 %t1195, %t1197
  br i1 %t1198, label %ok_1199, label %trap_1199
trap_1199:
  call void @abort()
  unreachable
ok_1199:
  %t1200 = getelementptr i8, ptr %t1196, i64 %t1195
  store i8 %t1194, ptr %t1200, align 1
  %t1201 = icmp ult i64 40, 64
  br i1 %t1201, label %ok_1202, label %trap_1202
trap_1202:
  call void @abort()
  unreachable
ok_1202:
  %t1203 = lshr i64 %t1135, 40
  %t1204 = trunc i64 %t1203 to i8
  %t1205 = add i64 %t1180, 5
  %t1206 = extractvalue %hia.buffer %p_15_1, 0
  %t1207 = extractvalue %hia.buffer %p_15_1, 1
  %t1208 = icmp ult i64 %t1205, %t1207
  br i1 %t1208, label %ok_1209, label %trap_1209
trap_1209:
  call void @abort()
  unreachable
ok_1209:
  %t1210 = getelementptr i8, ptr %t1206, i64 %t1205
  store i8 %t1204, ptr %t1210, align 1
  %t1211 = icmp ult i64 32, 64
  br i1 %t1211, label %ok_1212, label %trap_1212
trap_1212:
  call void @abort()
  unreachable
ok_1212:
  %t1213 = lshr i64 %t1135, 32
  %t1214 = trunc i64 %t1213 to i8
  %t1215 = add i64 %t1180, 4
  %t1216 = extractvalue %hia.buffer %p_15_1, 0
  %t1217 = extractvalue %hia.buffer %p_15_1, 1
  %t1218 = icmp ult i64 %t1215, %t1217
  br i1 %t1218, label %ok_1219, label %trap_1219
trap_1219:
  call void @abort()
  unreachable
ok_1219:
  %t1220 = getelementptr i8, ptr %t1216, i64 %t1215
  store i8 %t1214, ptr %t1220, align 1
  %t1221 = icmp ult i64 24, 64
  br i1 %t1221, label %ok_1222, label %trap_1222
trap_1222:
  call void @abort()
  unreachable
ok_1222:
  %t1223 = lshr i64 %t1135, 24
  %t1224 = trunc i64 %t1223 to i8
  %t1225 = add i64 %t1180, 3
  %t1226 = extractvalue %hia.buffer %p_15_1, 0
  %t1227 = extractvalue %hia.buffer %p_15_1, 1
  %t1228 = icmp ult i64 %t1225, %t1227
  br i1 %t1228, label %ok_1229, label %trap_1229
trap_1229:
  call void @abort()
  unreachable
ok_1229:
  %t1230 = getelementptr i8, ptr %t1226, i64 %t1225
  store i8 %t1224, ptr %t1230, align 1
  %t1231 = icmp ult i64 16, 64
  br i1 %t1231, label %ok_1232, label %trap_1232
trap_1232:
  call void @abort()
  unreachable
ok_1232:
  %t1233 = lshr i64 %t1135, 16
  %t1234 = trunc i64 %t1233 to i8
  %t1235 = add i64 %t1180, 2
  %t1236 = extractvalue %hia.buffer %p_15_1, 0
  %t1237 = extractvalue %hia.buffer %p_15_1, 1
  %t1238 = icmp ult i64 %t1235, %t1237
  br i1 %t1238, label %ok_1239, label %trap_1239
trap_1239:
  call void @abort()
  unreachable
ok_1239:
  %t1240 = getelementptr i8, ptr %t1236, i64 %t1235
  store i8 %t1234, ptr %t1240, align 1
  %t1241 = icmp ult i64 8, 64
  br i1 %t1241, label %ok_1242, label %trap_1242
trap_1242:
  call void @abort()
  unreachable
ok_1242:
  %t1243 = lshr i64 %t1135, 8
  %t1244 = trunc i64 %t1243 to i8
  %t1245 = add i64 %t1180, 1
  %t1246 = extractvalue %hia.buffer %p_15_1, 0
  %t1247 = extractvalue %hia.buffer %p_15_1, 1
  %t1248 = icmp ult i64 %t1245, %t1247
  br i1 %t1248, label %ok_1249, label %trap_1249
trap_1249:
  call void @abort()
  unreachable
ok_1249:
  %t1250 = getelementptr i8, ptr %t1246, i64 %t1245
  store i8 %t1244, ptr %t1250, align 1
  %t1251 = icmp ult i64 0, 64
  br i1 %t1251, label %ok_1252, label %trap_1252
trap_1252:
  call void @abort()
  unreachable
ok_1252:
  %t1253 = lshr i64 %t1135, 0
  %t1254 = trunc i64 %t1253 to i8
  %t1255 = add i64 %t1180, 0
  %t1256 = extractvalue %hia.buffer %p_15_1, 0
  %t1257 = extractvalue %hia.buffer %p_15_1, 1
  %t1258 = icmp ult i64 %t1255, %t1257
  br i1 %t1258, label %ok_1259, label %trap_1259
trap_1259:
  call void @abort()
  unreachable
ok_1259:
  %t1260 = getelementptr i8, ptr %t1256, i64 %t1255
  store i8 %t1254, ptr %t1260, align 1
  %t1261 = trunc i64 24 to i32
  %t1262 = zext i32 %t1261 to i64
  %t1263 = icmp ult i64 56, 64
  br i1 %t1263, label %ok_1264, label %trap_1264
trap_1264:
  call void @abort()
  unreachable
ok_1264:
  %t1265 = lshr i64 %t1136, 56
  %t1266 = trunc i64 %t1265 to i8
  %t1267 = add i64 %t1262, 7
  %t1268 = extractvalue %hia.buffer %p_15_1, 0
  %t1269 = extractvalue %hia.buffer %p_15_1, 1
  %t1270 = icmp ult i64 %t1267, %t1269
  br i1 %t1270, label %ok_1271, label %trap_1271
trap_1271:
  call void @abort()
  unreachable
ok_1271:
  %t1272 = getelementptr i8, ptr %t1268, i64 %t1267
  store i8 %t1266, ptr %t1272, align 1
  %t1273 = icmp ult i64 48, 64
  br i1 %t1273, label %ok_1274, label %trap_1274
trap_1274:
  call void @abort()
  unreachable
ok_1274:
  %t1275 = lshr i64 %t1136, 48
  %t1276 = trunc i64 %t1275 to i8
  %t1277 = add i64 %t1262, 6
  %t1278 = extractvalue %hia.buffer %p_15_1, 0
  %t1279 = extractvalue %hia.buffer %p_15_1, 1
  %t1280 = icmp ult i64 %t1277, %t1279
  br i1 %t1280, label %ok_1281, label %trap_1281
trap_1281:
  call void @abort()
  unreachable
ok_1281:
  %t1282 = getelementptr i8, ptr %t1278, i64 %t1277
  store i8 %t1276, ptr %t1282, align 1
  %t1283 = icmp ult i64 40, 64
  br i1 %t1283, label %ok_1284, label %trap_1284
trap_1284:
  call void @abort()
  unreachable
ok_1284:
  %t1285 = lshr i64 %t1136, 40
  %t1286 = trunc i64 %t1285 to i8
  %t1287 = add i64 %t1262, 5
  %t1288 = extractvalue %hia.buffer %p_15_1, 0
  %t1289 = extractvalue %hia.buffer %p_15_1, 1
  %t1290 = icmp ult i64 %t1287, %t1289
  br i1 %t1290, label %ok_1291, label %trap_1291
trap_1291:
  call void @abort()
  unreachable
ok_1291:
  %t1292 = getelementptr i8, ptr %t1288, i64 %t1287
  store i8 %t1286, ptr %t1292, align 1
  %t1293 = icmp ult i64 32, 64
  br i1 %t1293, label %ok_1294, label %trap_1294
trap_1294:
  call void @abort()
  unreachable
ok_1294:
  %t1295 = lshr i64 %t1136, 32
  %t1296 = trunc i64 %t1295 to i8
  %t1297 = add i64 %t1262, 4
  %t1298 = extractvalue %hia.buffer %p_15_1, 0
  %t1299 = extractvalue %hia.buffer %p_15_1, 1
  %t1300 = icmp ult i64 %t1297, %t1299
  br i1 %t1300, label %ok_1301, label %trap_1301
trap_1301:
  call void @abort()
  unreachable
ok_1301:
  %t1302 = getelementptr i8, ptr %t1298, i64 %t1297
  store i8 %t1296, ptr %t1302, align 1
  %t1303 = icmp ult i64 24, 64
  br i1 %t1303, label %ok_1304, label %trap_1304
trap_1304:
  call void @abort()
  unreachable
ok_1304:
  %t1305 = lshr i64 %t1136, 24
  %t1306 = trunc i64 %t1305 to i8
  %t1307 = add i64 %t1262, 3
  %t1308 = extractvalue %hia.buffer %p_15_1, 0
  %t1309 = extractvalue %hia.buffer %p_15_1, 1
  %t1310 = icmp ult i64 %t1307, %t1309
  br i1 %t1310, label %ok_1311, label %trap_1311
trap_1311:
  call void @abort()
  unreachable
ok_1311:
  %t1312 = getelementptr i8, ptr %t1308, i64 %t1307
  store i8 %t1306, ptr %t1312, align 1
  %t1313 = icmp ult i64 16, 64
  br i1 %t1313, label %ok_1314, label %trap_1314
trap_1314:
  call void @abort()
  unreachable
ok_1314:
  %t1315 = lshr i64 %t1136, 16
  %t1316 = trunc i64 %t1315 to i8
  %t1317 = add i64 %t1262, 2
  %t1318 = extractvalue %hia.buffer %p_15_1, 0
  %t1319 = extractvalue %hia.buffer %p_15_1, 1
  %t1320 = icmp ult i64 %t1317, %t1319
  br i1 %t1320, label %ok_1321, label %trap_1321
trap_1321:
  call void @abort()
  unreachable
ok_1321:
  %t1322 = getelementptr i8, ptr %t1318, i64 %t1317
  store i8 %t1316, ptr %t1322, align 1
  %t1323 = icmp ult i64 8, 64
  br i1 %t1323, label %ok_1324, label %trap_1324
trap_1324:
  call void @abort()
  unreachable
ok_1324:
  %t1325 = lshr i64 %t1136, 8
  %t1326 = trunc i64 %t1325 to i8
  %t1327 = add i64 %t1262, 1
  %t1328 = extractvalue %hia.buffer %p_15_1, 0
  %t1329 = extractvalue %hia.buffer %p_15_1, 1
  %t1330 = icmp ult i64 %t1327, %t1329
  br i1 %t1330, label %ok_1331, label %trap_1331
trap_1331:
  call void @abort()
  unreachable
ok_1331:
  %t1332 = getelementptr i8, ptr %t1328, i64 %t1327
  store i8 %t1326, ptr %t1332, align 1
  %t1333 = icmp ult i64 0, 64
  br i1 %t1333, label %ok_1334, label %trap_1334
trap_1334:
  call void @abort()
  unreachable
ok_1334:
  %t1335 = lshr i64 %t1136, 0
  %t1336 = trunc i64 %t1335 to i8
  %t1337 = add i64 %t1262, 0
  %t1338 = extractvalue %hia.buffer %p_15_1, 0
  %t1339 = extractvalue %hia.buffer %p_15_1, 1
  %t1340 = icmp ult i64 %t1337, %t1339
  br i1 %t1340, label %ok_1341, label %trap_1341
trap_1341:
  call void @abort()
  unreachable
ok_1341:
  %t1342 = getelementptr i8, ptr %t1338, i64 %t1337
  store i8 %t1336, ptr %t1342, align 1
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

define internal i32 @__hia_fn_2(%hia.buffer %p_0_0, %hia.buffer %p_0_1) alwaysinline {
b0:
  %t1 = extractvalue %hia.buffer %p_0_1, 1
  %t2 = icmp eq i64 %t1, 32
  %t3 = extractvalue %hia.buffer %p_0_0, 1
  %t4 = icmp ule i64 %t3, 65536
  %t5 = and i1 %t2, %t4
  br i1 %t5, label %edge_0, label %edge_1
b1:
  %p_1_0 = phi %hia.buffer [ %p_0_0, %edge_0 ]
  %p_1_1 = phi %hia.buffer [ %p_0_1, %edge_0 ]
  %t6 = trunc i64 0 to i32
  %t7 = zext i32 %t6 to i64
  %t8 = add i64 %t7, 7
  %t9 = extractvalue %hia.buffer %p_1_1, 0
  %t10 = extractvalue %hia.buffer %p_1_1, 1
  %t11 = icmp ult i64 %t8, %t10
  br i1 %t11, label %ok_12, label %trap_12
trap_12:
  call void @abort()
  unreachable
ok_12:
  %t13 = getelementptr i8, ptr %t9, i64 %t8
  %t14 = load i8, ptr %t13, align 1
  %t15 = zext i8 %t14 to i64
  %t16 = icmp ult i64 56, 64
  br i1 %t16, label %ok_17, label %trap_17
trap_17:
  call void @abort()
  unreachable
ok_17:
  %t18 = shl i64 %t15, 56
  %t19 = or i64 0, %t18
  %t20 = add i64 %t7, 6
  %t21 = extractvalue %hia.buffer %p_1_1, 0
  %t22 = extractvalue %hia.buffer %p_1_1, 1
  %t23 = icmp ult i64 %t20, %t22
  br i1 %t23, label %ok_24, label %trap_24
trap_24:
  call void @abort()
  unreachable
ok_24:
  %t25 = getelementptr i8, ptr %t21, i64 %t20
  %t26 = load i8, ptr %t25, align 1
  %t27 = zext i8 %t26 to i64
  %t28 = icmp ult i64 48, 64
  br i1 %t28, label %ok_29, label %trap_29
trap_29:
  call void @abort()
  unreachable
ok_29:
  %t30 = shl i64 %t27, 48
  %t31 = or i64 %t19, %t30
  %t32 = add i64 %t7, 5
  %t33 = extractvalue %hia.buffer %p_1_1, 0
  %t34 = extractvalue %hia.buffer %p_1_1, 1
  %t35 = icmp ult i64 %t32, %t34
  br i1 %t35, label %ok_36, label %trap_36
trap_36:
  call void @abort()
  unreachable
ok_36:
  %t37 = getelementptr i8, ptr %t33, i64 %t32
  %t38 = load i8, ptr %t37, align 1
  %t39 = zext i8 %t38 to i64
  %t40 = icmp ult i64 40, 64
  br i1 %t40, label %ok_41, label %trap_41
trap_41:
  call void @abort()
  unreachable
ok_41:
  %t42 = shl i64 %t39, 40
  %t43 = or i64 %t31, %t42
  %t44 = add i64 %t7, 4
  %t45 = extractvalue %hia.buffer %p_1_1, 0
  %t46 = extractvalue %hia.buffer %p_1_1, 1
  %t47 = icmp ult i64 %t44, %t46
  br i1 %t47, label %ok_48, label %trap_48
trap_48:
  call void @abort()
  unreachable
ok_48:
  %t49 = getelementptr i8, ptr %t45, i64 %t44
  %t50 = load i8, ptr %t49, align 1
  %t51 = zext i8 %t50 to i64
  %t52 = icmp ult i64 32, 64
  br i1 %t52, label %ok_53, label %trap_53
trap_53:
  call void @abort()
  unreachable
ok_53:
  %t54 = shl i64 %t51, 32
  %t55 = or i64 %t43, %t54
  %t56 = add i64 %t7, 3
  %t57 = extractvalue %hia.buffer %p_1_1, 0
  %t58 = extractvalue %hia.buffer %p_1_1, 1
  %t59 = icmp ult i64 %t56, %t58
  br i1 %t59, label %ok_60, label %trap_60
trap_60:
  call void @abort()
  unreachable
ok_60:
  %t61 = getelementptr i8, ptr %t57, i64 %t56
  %t62 = load i8, ptr %t61, align 1
  %t63 = zext i8 %t62 to i64
  %t64 = icmp ult i64 24, 64
  br i1 %t64, label %ok_65, label %trap_65
trap_65:
  call void @abort()
  unreachable
ok_65:
  %t66 = shl i64 %t63, 24
  %t67 = or i64 %t55, %t66
  %t68 = add i64 %t7, 2
  %t69 = extractvalue %hia.buffer %p_1_1, 0
  %t70 = extractvalue %hia.buffer %p_1_1, 1
  %t71 = icmp ult i64 %t68, %t70
  br i1 %t71, label %ok_72, label %trap_72
trap_72:
  call void @abort()
  unreachable
ok_72:
  %t73 = getelementptr i8, ptr %t69, i64 %t68
  %t74 = load i8, ptr %t73, align 1
  %t75 = zext i8 %t74 to i64
  %t76 = icmp ult i64 16, 64
  br i1 %t76, label %ok_77, label %trap_77
trap_77:
  call void @abort()
  unreachable
ok_77:
  %t78 = shl i64 %t75, 16
  %t79 = or i64 %t67, %t78
  %t80 = add i64 %t7, 1
  %t81 = extractvalue %hia.buffer %p_1_1, 0
  %t82 = extractvalue %hia.buffer %p_1_1, 1
  %t83 = icmp ult i64 %t80, %t82
  br i1 %t83, label %ok_84, label %trap_84
trap_84:
  call void @abort()
  unreachable
ok_84:
  %t85 = getelementptr i8, ptr %t81, i64 %t80
  %t86 = load i8, ptr %t85, align 1
  %t87 = zext i8 %t86 to i64
  %t88 = icmp ult i64 8, 64
  br i1 %t88, label %ok_89, label %trap_89
trap_89:
  call void @abort()
  unreachable
ok_89:
  %t90 = shl i64 %t87, 8
  %t91 = or i64 %t79, %t90
  %t92 = add i64 %t7, 0
  %t93 = extractvalue %hia.buffer %p_1_1, 0
  %t94 = extractvalue %hia.buffer %p_1_1, 1
  %t95 = icmp ult i64 %t92, %t94
  br i1 %t95, label %ok_96, label %trap_96
trap_96:
  call void @abort()
  unreachable
ok_96:
  %t97 = getelementptr i8, ptr %t93, i64 %t92
  %t98 = load i8, ptr %t97, align 1
  %t99 = zext i8 %t98 to i64
  %t100 = icmp ult i64 0, 64
  br i1 %t100, label %ok_101, label %trap_101
trap_101:
  call void @abort()
  unreachable
ok_101:
  %t102 = shl i64 %t99, 0
  %t103 = or i64 %t91, %t102
  %t104 = trunc i64 8 to i32
  %t105 = zext i32 %t104 to i64
  %t106 = add i64 %t105, 7
  %t107 = extractvalue %hia.buffer %p_1_1, 0
  %t108 = extractvalue %hia.buffer %p_1_1, 1
  %t109 = icmp ult i64 %t106, %t108
  br i1 %t109, label %ok_110, label %trap_110
trap_110:
  call void @abort()
  unreachable
ok_110:
  %t111 = getelementptr i8, ptr %t107, i64 %t106
  %t112 = load i8, ptr %t111, align 1
  %t113 = zext i8 %t112 to i64
  %t114 = icmp ult i64 56, 64
  br i1 %t114, label %ok_115, label %trap_115
trap_115:
  call void @abort()
  unreachable
ok_115:
  %t116 = shl i64 %t113, 56
  %t117 = or i64 0, %t116
  %t118 = add i64 %t105, 6
  %t119 = extractvalue %hia.buffer %p_1_1, 0
  %t120 = extractvalue %hia.buffer %p_1_1, 1
  %t121 = icmp ult i64 %t118, %t120
  br i1 %t121, label %ok_122, label %trap_122
trap_122:
  call void @abort()
  unreachable
ok_122:
  %t123 = getelementptr i8, ptr %t119, i64 %t118
  %t124 = load i8, ptr %t123, align 1
  %t125 = zext i8 %t124 to i64
  %t126 = icmp ult i64 48, 64
  br i1 %t126, label %ok_127, label %trap_127
trap_127:
  call void @abort()
  unreachable
ok_127:
  %t128 = shl i64 %t125, 48
  %t129 = or i64 %t117, %t128
  %t130 = add i64 %t105, 5
  %t131 = extractvalue %hia.buffer %p_1_1, 0
  %t132 = extractvalue %hia.buffer %p_1_1, 1
  %t133 = icmp ult i64 %t130, %t132
  br i1 %t133, label %ok_134, label %trap_134
trap_134:
  call void @abort()
  unreachable
ok_134:
  %t135 = getelementptr i8, ptr %t131, i64 %t130
  %t136 = load i8, ptr %t135, align 1
  %t137 = zext i8 %t136 to i64
  %t138 = icmp ult i64 40, 64
  br i1 %t138, label %ok_139, label %trap_139
trap_139:
  call void @abort()
  unreachable
ok_139:
  %t140 = shl i64 %t137, 40
  %t141 = or i64 %t129, %t140
  %t142 = add i64 %t105, 4
  %t143 = extractvalue %hia.buffer %p_1_1, 0
  %t144 = extractvalue %hia.buffer %p_1_1, 1
  %t145 = icmp ult i64 %t142, %t144
  br i1 %t145, label %ok_146, label %trap_146
trap_146:
  call void @abort()
  unreachable
ok_146:
  %t147 = getelementptr i8, ptr %t143, i64 %t142
  %t148 = load i8, ptr %t147, align 1
  %t149 = zext i8 %t148 to i64
  %t150 = icmp ult i64 32, 64
  br i1 %t150, label %ok_151, label %trap_151
trap_151:
  call void @abort()
  unreachable
ok_151:
  %t152 = shl i64 %t149, 32
  %t153 = or i64 %t141, %t152
  %t154 = add i64 %t105, 3
  %t155 = extractvalue %hia.buffer %p_1_1, 0
  %t156 = extractvalue %hia.buffer %p_1_1, 1
  %t157 = icmp ult i64 %t154, %t156
  br i1 %t157, label %ok_158, label %trap_158
trap_158:
  call void @abort()
  unreachable
ok_158:
  %t159 = getelementptr i8, ptr %t155, i64 %t154
  %t160 = load i8, ptr %t159, align 1
  %t161 = zext i8 %t160 to i64
  %t162 = icmp ult i64 24, 64
  br i1 %t162, label %ok_163, label %trap_163
trap_163:
  call void @abort()
  unreachable
ok_163:
  %t164 = shl i64 %t161, 24
  %t165 = or i64 %t153, %t164
  %t166 = add i64 %t105, 2
  %t167 = extractvalue %hia.buffer %p_1_1, 0
  %t168 = extractvalue %hia.buffer %p_1_1, 1
  %t169 = icmp ult i64 %t166, %t168
  br i1 %t169, label %ok_170, label %trap_170
trap_170:
  call void @abort()
  unreachable
ok_170:
  %t171 = getelementptr i8, ptr %t167, i64 %t166
  %t172 = load i8, ptr %t171, align 1
  %t173 = zext i8 %t172 to i64
  %t174 = icmp ult i64 16, 64
  br i1 %t174, label %ok_175, label %trap_175
trap_175:
  call void @abort()
  unreachable
ok_175:
  %t176 = shl i64 %t173, 16
  %t177 = or i64 %t165, %t176
  %t178 = add i64 %t105, 1
  %t179 = extractvalue %hia.buffer %p_1_1, 0
  %t180 = extractvalue %hia.buffer %p_1_1, 1
  %t181 = icmp ult i64 %t178, %t180
  br i1 %t181, label %ok_182, label %trap_182
trap_182:
  call void @abort()
  unreachable
ok_182:
  %t183 = getelementptr i8, ptr %t179, i64 %t178
  %t184 = load i8, ptr %t183, align 1
  %t185 = zext i8 %t184 to i64
  %t186 = icmp ult i64 8, 64
  br i1 %t186, label %ok_187, label %trap_187
trap_187:
  call void @abort()
  unreachable
ok_187:
  %t188 = shl i64 %t185, 8
  %t189 = or i64 %t177, %t188
  %t190 = add i64 %t105, 0
  %t191 = extractvalue %hia.buffer %p_1_1, 0
  %t192 = extractvalue %hia.buffer %p_1_1, 1
  %t193 = icmp ult i64 %t190, %t192
  br i1 %t193, label %ok_194, label %trap_194
trap_194:
  call void @abort()
  unreachable
ok_194:
  %t195 = getelementptr i8, ptr %t191, i64 %t190
  %t196 = load i8, ptr %t195, align 1
  %t197 = zext i8 %t196 to i64
  %t198 = icmp ult i64 0, 64
  br i1 %t198, label %ok_199, label %trap_199
trap_199:
  call void @abort()
  unreachable
ok_199:
  %t200 = shl i64 %t197, 0
  %t201 = or i64 %t189, %t200
  %t202 = trunc i64 16 to i32
  %t203 = zext i32 %t202 to i64
  %t204 = add i64 %t203, 7
  %t205 = extractvalue %hia.buffer %p_1_1, 0
  %t206 = extractvalue %hia.buffer %p_1_1, 1
  %t207 = icmp ult i64 %t204, %t206
  br i1 %t207, label %ok_208, label %trap_208
trap_208:
  call void @abort()
  unreachable
ok_208:
  %t209 = getelementptr i8, ptr %t205, i64 %t204
  %t210 = load i8, ptr %t209, align 1
  %t211 = zext i8 %t210 to i64
  %t212 = icmp ult i64 56, 64
  br i1 %t212, label %ok_213, label %trap_213
trap_213:
  call void @abort()
  unreachable
ok_213:
  %t214 = shl i64 %t211, 56
  %t215 = or i64 0, %t214
  %t216 = add i64 %t203, 6
  %t217 = extractvalue %hia.buffer %p_1_1, 0
  %t218 = extractvalue %hia.buffer %p_1_1, 1
  %t219 = icmp ult i64 %t216, %t218
  br i1 %t219, label %ok_220, label %trap_220
trap_220:
  call void @abort()
  unreachable
ok_220:
  %t221 = getelementptr i8, ptr %t217, i64 %t216
  %t222 = load i8, ptr %t221, align 1
  %t223 = zext i8 %t222 to i64
  %t224 = icmp ult i64 48, 64
  br i1 %t224, label %ok_225, label %trap_225
trap_225:
  call void @abort()
  unreachable
ok_225:
  %t226 = shl i64 %t223, 48
  %t227 = or i64 %t215, %t226
  %t228 = add i64 %t203, 5
  %t229 = extractvalue %hia.buffer %p_1_1, 0
  %t230 = extractvalue %hia.buffer %p_1_1, 1
  %t231 = icmp ult i64 %t228, %t230
  br i1 %t231, label %ok_232, label %trap_232
trap_232:
  call void @abort()
  unreachable
ok_232:
  %t233 = getelementptr i8, ptr %t229, i64 %t228
  %t234 = load i8, ptr %t233, align 1
  %t235 = zext i8 %t234 to i64
  %t236 = icmp ult i64 40, 64
  br i1 %t236, label %ok_237, label %trap_237
trap_237:
  call void @abort()
  unreachable
ok_237:
  %t238 = shl i64 %t235, 40
  %t239 = or i64 %t227, %t238
  %t240 = add i64 %t203, 4
  %t241 = extractvalue %hia.buffer %p_1_1, 0
  %t242 = extractvalue %hia.buffer %p_1_1, 1
  %t243 = icmp ult i64 %t240, %t242
  br i1 %t243, label %ok_244, label %trap_244
trap_244:
  call void @abort()
  unreachable
ok_244:
  %t245 = getelementptr i8, ptr %t241, i64 %t240
  %t246 = load i8, ptr %t245, align 1
  %t247 = zext i8 %t246 to i64
  %t248 = icmp ult i64 32, 64
  br i1 %t248, label %ok_249, label %trap_249
trap_249:
  call void @abort()
  unreachable
ok_249:
  %t250 = shl i64 %t247, 32
  %t251 = or i64 %t239, %t250
  %t252 = add i64 %t203, 3
  %t253 = extractvalue %hia.buffer %p_1_1, 0
  %t254 = extractvalue %hia.buffer %p_1_1, 1
  %t255 = icmp ult i64 %t252, %t254
  br i1 %t255, label %ok_256, label %trap_256
trap_256:
  call void @abort()
  unreachable
ok_256:
  %t257 = getelementptr i8, ptr %t253, i64 %t252
  %t258 = load i8, ptr %t257, align 1
  %t259 = zext i8 %t258 to i64
  %t260 = icmp ult i64 24, 64
  br i1 %t260, label %ok_261, label %trap_261
trap_261:
  call void @abort()
  unreachable
ok_261:
  %t262 = shl i64 %t259, 24
  %t263 = or i64 %t251, %t262
  %t264 = add i64 %t203, 2
  %t265 = extractvalue %hia.buffer %p_1_1, 0
  %t266 = extractvalue %hia.buffer %p_1_1, 1
  %t267 = icmp ult i64 %t264, %t266
  br i1 %t267, label %ok_268, label %trap_268
trap_268:
  call void @abort()
  unreachable
ok_268:
  %t269 = getelementptr i8, ptr %t265, i64 %t264
  %t270 = load i8, ptr %t269, align 1
  %t271 = zext i8 %t270 to i64
  %t272 = icmp ult i64 16, 64
  br i1 %t272, label %ok_273, label %trap_273
trap_273:
  call void @abort()
  unreachable
ok_273:
  %t274 = shl i64 %t271, 16
  %t275 = or i64 %t263, %t274
  %t276 = add i64 %t203, 1
  %t277 = extractvalue %hia.buffer %p_1_1, 0
  %t278 = extractvalue %hia.buffer %p_1_1, 1
  %t279 = icmp ult i64 %t276, %t278
  br i1 %t279, label %ok_280, label %trap_280
trap_280:
  call void @abort()
  unreachable
ok_280:
  %t281 = getelementptr i8, ptr %t277, i64 %t276
  %t282 = load i8, ptr %t281, align 1
  %t283 = zext i8 %t282 to i64
  %t284 = icmp ult i64 8, 64
  br i1 %t284, label %ok_285, label %trap_285
trap_285:
  call void @abort()
  unreachable
ok_285:
  %t286 = shl i64 %t283, 8
  %t287 = or i64 %t275, %t286
  %t288 = add i64 %t203, 0
  %t289 = extractvalue %hia.buffer %p_1_1, 0
  %t290 = extractvalue %hia.buffer %p_1_1, 1
  %t291 = icmp ult i64 %t288, %t290
  br i1 %t291, label %ok_292, label %trap_292
trap_292:
  call void @abort()
  unreachable
ok_292:
  %t293 = getelementptr i8, ptr %t289, i64 %t288
  %t294 = load i8, ptr %t293, align 1
  %t295 = zext i8 %t294 to i64
  %t296 = icmp ult i64 0, 64
  br i1 %t296, label %ok_297, label %trap_297
trap_297:
  call void @abort()
  unreachable
ok_297:
  %t298 = shl i64 %t295, 0
  %t299 = or i64 %t287, %t298
  %t300 = trunc i64 24 to i32
  %t301 = zext i32 %t300 to i64
  %t302 = add i64 %t301, 7
  %t303 = extractvalue %hia.buffer %p_1_1, 0
  %t304 = extractvalue %hia.buffer %p_1_1, 1
  %t305 = icmp ult i64 %t302, %t304
  br i1 %t305, label %ok_306, label %trap_306
trap_306:
  call void @abort()
  unreachable
ok_306:
  %t307 = getelementptr i8, ptr %t303, i64 %t302
  %t308 = load i8, ptr %t307, align 1
  %t309 = zext i8 %t308 to i64
  %t310 = icmp ult i64 56, 64
  br i1 %t310, label %ok_311, label %trap_311
trap_311:
  call void @abort()
  unreachable
ok_311:
  %t312 = shl i64 %t309, 56
  %t313 = or i64 0, %t312
  %t314 = add i64 %t301, 6
  %t315 = extractvalue %hia.buffer %p_1_1, 0
  %t316 = extractvalue %hia.buffer %p_1_1, 1
  %t317 = icmp ult i64 %t314, %t316
  br i1 %t317, label %ok_318, label %trap_318
trap_318:
  call void @abort()
  unreachable
ok_318:
  %t319 = getelementptr i8, ptr %t315, i64 %t314
  %t320 = load i8, ptr %t319, align 1
  %t321 = zext i8 %t320 to i64
  %t322 = icmp ult i64 48, 64
  br i1 %t322, label %ok_323, label %trap_323
trap_323:
  call void @abort()
  unreachable
ok_323:
  %t324 = shl i64 %t321, 48
  %t325 = or i64 %t313, %t324
  %t326 = add i64 %t301, 5
  %t327 = extractvalue %hia.buffer %p_1_1, 0
  %t328 = extractvalue %hia.buffer %p_1_1, 1
  %t329 = icmp ult i64 %t326, %t328
  br i1 %t329, label %ok_330, label %trap_330
trap_330:
  call void @abort()
  unreachable
ok_330:
  %t331 = getelementptr i8, ptr %t327, i64 %t326
  %t332 = load i8, ptr %t331, align 1
  %t333 = zext i8 %t332 to i64
  %t334 = icmp ult i64 40, 64
  br i1 %t334, label %ok_335, label %trap_335
trap_335:
  call void @abort()
  unreachable
ok_335:
  %t336 = shl i64 %t333, 40
  %t337 = or i64 %t325, %t336
  %t338 = add i64 %t301, 4
  %t339 = extractvalue %hia.buffer %p_1_1, 0
  %t340 = extractvalue %hia.buffer %p_1_1, 1
  %t341 = icmp ult i64 %t338, %t340
  br i1 %t341, label %ok_342, label %trap_342
trap_342:
  call void @abort()
  unreachable
ok_342:
  %t343 = getelementptr i8, ptr %t339, i64 %t338
  %t344 = load i8, ptr %t343, align 1
  %t345 = zext i8 %t344 to i64
  %t346 = icmp ult i64 32, 64
  br i1 %t346, label %ok_347, label %trap_347
trap_347:
  call void @abort()
  unreachable
ok_347:
  %t348 = shl i64 %t345, 32
  %t349 = or i64 %t337, %t348
  %t350 = add i64 %t301, 3
  %t351 = extractvalue %hia.buffer %p_1_1, 0
  %t352 = extractvalue %hia.buffer %p_1_1, 1
  %t353 = icmp ult i64 %t350, %t352
  br i1 %t353, label %ok_354, label %trap_354
trap_354:
  call void @abort()
  unreachable
ok_354:
  %t355 = getelementptr i8, ptr %t351, i64 %t350
  %t356 = load i8, ptr %t355, align 1
  %t357 = zext i8 %t356 to i64
  %t358 = icmp ult i64 24, 64
  br i1 %t358, label %ok_359, label %trap_359
trap_359:
  call void @abort()
  unreachable
ok_359:
  %t360 = shl i64 %t357, 24
  %t361 = or i64 %t349, %t360
  %t362 = add i64 %t301, 2
  %t363 = extractvalue %hia.buffer %p_1_1, 0
  %t364 = extractvalue %hia.buffer %p_1_1, 1
  %t365 = icmp ult i64 %t362, %t364
  br i1 %t365, label %ok_366, label %trap_366
trap_366:
  call void @abort()
  unreachable
ok_366:
  %t367 = getelementptr i8, ptr %t363, i64 %t362
  %t368 = load i8, ptr %t367, align 1
  %t369 = zext i8 %t368 to i64
  %t370 = icmp ult i64 16, 64
  br i1 %t370, label %ok_371, label %trap_371
trap_371:
  call void @abort()
  unreachable
ok_371:
  %t372 = shl i64 %t369, 16
  %t373 = or i64 %t361, %t372
  %t374 = add i64 %t301, 1
  %t375 = extractvalue %hia.buffer %p_1_1, 0
  %t376 = extractvalue %hia.buffer %p_1_1, 1
  %t377 = icmp ult i64 %t374, %t376
  br i1 %t377, label %ok_378, label %trap_378
trap_378:
  call void @abort()
  unreachable
ok_378:
  %t379 = getelementptr i8, ptr %t375, i64 %t374
  %t380 = load i8, ptr %t379, align 1
  %t381 = zext i8 %t380 to i64
  %t382 = icmp ult i64 8, 64
  br i1 %t382, label %ok_383, label %trap_383
trap_383:
  call void @abort()
  unreachable
ok_383:
  %t384 = shl i64 %t381, 8
  %t385 = or i64 %t373, %t384
  %t386 = add i64 %t301, 0
  %t387 = extractvalue %hia.buffer %p_1_1, 0
  %t388 = extractvalue %hia.buffer %p_1_1, 1
  %t389 = icmp ult i64 %t386, %t388
  br i1 %t389, label %ok_390, label %trap_390
trap_390:
  call void @abort()
  unreachable
ok_390:
  %t391 = getelementptr i8, ptr %t387, i64 %t386
  %t392 = load i8, ptr %t391, align 1
  %t393 = zext i8 %t392 to i64
  %t394 = icmp ult i64 0, 64
  br i1 %t394, label %ok_395, label %trap_395
trap_395:
  call void @abort()
  unreachable
ok_395:
  %t396 = shl i64 %t393, 0
  %t397 = or i64 %t385, %t396
  %t398 = extractvalue %hia.buffer %p_1_0, 1
  %t399 = icmp ule i64 %t299, %t398
  %t400 = sub i64 %t398, %t299
  %t401 = icmp ule i64 %t397, %t400
  %t402 = and i1 %t399, %t401
  br i1 %t402, label %edge_2, label %edge_3
b2:
  ret i32 4294836225
b3:
  ret i32 0
b4:
  %p_4_0 = phi %hia.buffer [ %p_1_0, %edge_2 ]
  %p_4_1 = phi %hia.buffer [ %p_1_1, %edge_2 ]
  %p_4_2 = phi i64 [ %t103, %edge_2 ]
  %p_4_3 = phi i64 [ %t201, %edge_2 ]
  %p_4_4 = phi i64 [ %t299, %edge_2 ]
  %p_4_5 = phi i64 [ %t397, %edge_2 ]
  %p_4_6 = phi i64 [ %t398, %edge_2 ]
  %t403 = icmp uge i64 %p_4_5, 8
  br i1 %t403, label %edge_4, label %edge_5
b5:
  %p_5_0 = phi %hia.buffer [ %p_4_0, %edge_4 ]
  %p_5_1 = phi %hia.buffer [ %p_4_1, %edge_4 ]
  %p_5_2 = phi i64 [ %p_4_2, %edge_4 ]
  %p_5_3 = phi i64 [ %p_4_3, %edge_4 ]
  %p_5_4 = phi i64 [ %p_4_4, %edge_4 ]
  %p_5_5 = phi i64 [ %p_4_5, %edge_4 ]
  %p_5_6 = phi i64 [ %p_4_6, %edge_4 ]
  %t404 = trunc i64 %p_5_4 to i32
  %t405 = zext i32 %t404 to i64
  %t406 = add i64 %t405, 7
  %t407 = extractvalue %hia.buffer %p_5_0, 0
  %t408 = extractvalue %hia.buffer %p_5_0, 1
  %t409 = icmp ult i64 %t406, %t408
  br i1 %t409, label %ok_410, label %trap_410
trap_410:
  call void @abort()
  unreachable
ok_410:
  %t411 = getelementptr i8, ptr %t407, i64 %t406
  %t412 = load i8, ptr %t411, align 1
  %t413 = zext i8 %t412 to i64
  %t414 = icmp ult i64 0, 64
  br i1 %t414, label %ok_415, label %trap_415
trap_415:
  call void @abort()
  unreachable
ok_415:
  %t416 = shl i64 %t413, 0
  %t417 = or i64 0, %t416
  %t418 = add i64 %t405, 6
  %t419 = extractvalue %hia.buffer %p_5_0, 0
  %t420 = extractvalue %hia.buffer %p_5_0, 1
  %t421 = icmp ult i64 %t418, %t420
  br i1 %t421, label %ok_422, label %trap_422
trap_422:
  call void @abort()
  unreachable
ok_422:
  %t423 = getelementptr i8, ptr %t419, i64 %t418
  %t424 = load i8, ptr %t423, align 1
  %t425 = zext i8 %t424 to i64
  %t426 = icmp ult i64 8, 64
  br i1 %t426, label %ok_427, label %trap_427
trap_427:
  call void @abort()
  unreachable
ok_427:
  %t428 = shl i64 %t425, 8
  %t429 = or i64 %t417, %t428
  %t430 = add i64 %t405, 5
  %t431 = extractvalue %hia.buffer %p_5_0, 0
  %t432 = extractvalue %hia.buffer %p_5_0, 1
  %t433 = icmp ult i64 %t430, %t432
  br i1 %t433, label %ok_434, label %trap_434
trap_434:
  call void @abort()
  unreachable
ok_434:
  %t435 = getelementptr i8, ptr %t431, i64 %t430
  %t436 = load i8, ptr %t435, align 1
  %t437 = zext i8 %t436 to i64
  %t438 = icmp ult i64 16, 64
  br i1 %t438, label %ok_439, label %trap_439
trap_439:
  call void @abort()
  unreachable
ok_439:
  %t440 = shl i64 %t437, 16
  %t441 = or i64 %t429, %t440
  %t442 = add i64 %t405, 4
  %t443 = extractvalue %hia.buffer %p_5_0, 0
  %t444 = extractvalue %hia.buffer %p_5_0, 1
  %t445 = icmp ult i64 %t442, %t444
  br i1 %t445, label %ok_446, label %trap_446
trap_446:
  call void @abort()
  unreachable
ok_446:
  %t447 = getelementptr i8, ptr %t443, i64 %t442
  %t448 = load i8, ptr %t447, align 1
  %t449 = zext i8 %t448 to i64
  %t450 = icmp ult i64 24, 64
  br i1 %t450, label %ok_451, label %trap_451
trap_451:
  call void @abort()
  unreachable
ok_451:
  %t452 = shl i64 %t449, 24
  %t453 = or i64 %t441, %t452
  %t454 = add i64 %t405, 3
  %t455 = extractvalue %hia.buffer %p_5_0, 0
  %t456 = extractvalue %hia.buffer %p_5_0, 1
  %t457 = icmp ult i64 %t454, %t456
  br i1 %t457, label %ok_458, label %trap_458
trap_458:
  call void @abort()
  unreachable
ok_458:
  %t459 = getelementptr i8, ptr %t455, i64 %t454
  %t460 = load i8, ptr %t459, align 1
  %t461 = zext i8 %t460 to i64
  %t462 = icmp ult i64 32, 64
  br i1 %t462, label %ok_463, label %trap_463
trap_463:
  call void @abort()
  unreachable
ok_463:
  %t464 = shl i64 %t461, 32
  %t465 = or i64 %t453, %t464
  %t466 = add i64 %t405, 2
  %t467 = extractvalue %hia.buffer %p_5_0, 0
  %t468 = extractvalue %hia.buffer %p_5_0, 1
  %t469 = icmp ult i64 %t466, %t468
  br i1 %t469, label %ok_470, label %trap_470
trap_470:
  call void @abort()
  unreachable
ok_470:
  %t471 = getelementptr i8, ptr %t467, i64 %t466
  %t472 = load i8, ptr %t471, align 1
  %t473 = zext i8 %t472 to i64
  %t474 = icmp ult i64 40, 64
  br i1 %t474, label %ok_475, label %trap_475
trap_475:
  call void @abort()
  unreachable
ok_475:
  %t476 = shl i64 %t473, 40
  %t477 = or i64 %t465, %t476
  %t478 = add i64 %t405, 1
  %t479 = extractvalue %hia.buffer %p_5_0, 0
  %t480 = extractvalue %hia.buffer %p_5_0, 1
  %t481 = icmp ult i64 %t478, %t480
  br i1 %t481, label %ok_482, label %trap_482
trap_482:
  call void @abort()
  unreachable
ok_482:
  %t483 = getelementptr i8, ptr %t479, i64 %t478
  %t484 = load i8, ptr %t483, align 1
  %t485 = zext i8 %t484 to i64
  %t486 = icmp ult i64 48, 64
  br i1 %t486, label %ok_487, label %trap_487
trap_487:
  call void @abort()
  unreachable
ok_487:
  %t488 = shl i64 %t485, 48
  %t489 = or i64 %t477, %t488
  %t490 = add i64 %t405, 0
  %t491 = extractvalue %hia.buffer %p_5_0, 0
  %t492 = extractvalue %hia.buffer %p_5_0, 1
  %t493 = icmp ult i64 %t490, %t492
  br i1 %t493, label %ok_494, label %trap_494
trap_494:
  call void @abort()
  unreachable
ok_494:
  %t495 = getelementptr i8, ptr %t491, i64 %t490
  %t496 = load i8, ptr %t495, align 1
  %t497 = zext i8 %t496 to i64
  %t498 = icmp ult i64 56, 64
  br i1 %t498, label %ok_499, label %trap_499
trap_499:
  call void @abort()
  unreachable
ok_499:
  %t500 = shl i64 %t497, 56
  %t501 = or i64 %t489, %t500
  %t502 = and i64 %t501, 281474976710655
  %t503 = trunc i64 0 to i32
  %t504 = zext i32 %t503 to i64
  %t505 = icmp ult i64 56, 64
  br i1 %t505, label %ok_506, label %trap_506
trap_506:
  call void @abort()
  unreachable
ok_506:
  %t507 = lshr i64 %t502, 56
  %t508 = trunc i64 %t507 to i8
  %t509 = add i64 %t504, 7
  %t510 = extractvalue %hia.buffer %p_5_1, 0
  %t511 = extractvalue %hia.buffer %p_5_1, 1
  %t512 = icmp ult i64 %t509, %t511
  br i1 %t512, label %ok_513, label %trap_513
trap_513:
  call void @abort()
  unreachable
ok_513:
  %t514 = getelementptr i8, ptr %t510, i64 %t509
  store i8 %t508, ptr %t514, align 1
  %t515 = icmp ult i64 48, 64
  br i1 %t515, label %ok_516, label %trap_516
trap_516:
  call void @abort()
  unreachable
ok_516:
  %t517 = lshr i64 %t502, 48
  %t518 = trunc i64 %t517 to i8
  %t519 = add i64 %t504, 6
  %t520 = extractvalue %hia.buffer %p_5_1, 0
  %t521 = extractvalue %hia.buffer %p_5_1, 1
  %t522 = icmp ult i64 %t519, %t521
  br i1 %t522, label %ok_523, label %trap_523
trap_523:
  call void @abort()
  unreachable
ok_523:
  %t524 = getelementptr i8, ptr %t520, i64 %t519
  store i8 %t518, ptr %t524, align 1
  %t525 = icmp ult i64 40, 64
  br i1 %t525, label %ok_526, label %trap_526
trap_526:
  call void @abort()
  unreachable
ok_526:
  %t527 = lshr i64 %t502, 40
  %t528 = trunc i64 %t527 to i8
  %t529 = add i64 %t504, 5
  %t530 = extractvalue %hia.buffer %p_5_1, 0
  %t531 = extractvalue %hia.buffer %p_5_1, 1
  %t532 = icmp ult i64 %t529, %t531
  br i1 %t532, label %ok_533, label %trap_533
trap_533:
  call void @abort()
  unreachable
ok_533:
  %t534 = getelementptr i8, ptr %t530, i64 %t529
  store i8 %t528, ptr %t534, align 1
  %t535 = icmp ult i64 32, 64
  br i1 %t535, label %ok_536, label %trap_536
trap_536:
  call void @abort()
  unreachable
ok_536:
  %t537 = lshr i64 %t502, 32
  %t538 = trunc i64 %t537 to i8
  %t539 = add i64 %t504, 4
  %t540 = extractvalue %hia.buffer %p_5_1, 0
  %t541 = extractvalue %hia.buffer %p_5_1, 1
  %t542 = icmp ult i64 %t539, %t541
  br i1 %t542, label %ok_543, label %trap_543
trap_543:
  call void @abort()
  unreachable
ok_543:
  %t544 = getelementptr i8, ptr %t540, i64 %t539
  store i8 %t538, ptr %t544, align 1
  %t545 = icmp ult i64 24, 64
  br i1 %t545, label %ok_546, label %trap_546
trap_546:
  call void @abort()
  unreachable
ok_546:
  %t547 = lshr i64 %t502, 24
  %t548 = trunc i64 %t547 to i8
  %t549 = add i64 %t504, 3
  %t550 = extractvalue %hia.buffer %p_5_1, 0
  %t551 = extractvalue %hia.buffer %p_5_1, 1
  %t552 = icmp ult i64 %t549, %t551
  br i1 %t552, label %ok_553, label %trap_553
trap_553:
  call void @abort()
  unreachable
ok_553:
  %t554 = getelementptr i8, ptr %t550, i64 %t549
  store i8 %t548, ptr %t554, align 1
  %t555 = icmp ult i64 16, 64
  br i1 %t555, label %ok_556, label %trap_556
trap_556:
  call void @abort()
  unreachable
ok_556:
  %t557 = lshr i64 %t502, 16
  %t558 = trunc i64 %t557 to i8
  %t559 = add i64 %t504, 2
  %t560 = extractvalue %hia.buffer %p_5_1, 0
  %t561 = extractvalue %hia.buffer %p_5_1, 1
  %t562 = icmp ult i64 %t559, %t561
  br i1 %t562, label %ok_563, label %trap_563
trap_563:
  call void @abort()
  unreachable
ok_563:
  %t564 = getelementptr i8, ptr %t560, i64 %t559
  store i8 %t558, ptr %t564, align 1
  %t565 = icmp ult i64 8, 64
  br i1 %t565, label %ok_566, label %trap_566
trap_566:
  call void @abort()
  unreachable
ok_566:
  %t567 = lshr i64 %t502, 8
  %t568 = trunc i64 %t567 to i8
  %t569 = add i64 %t504, 1
  %t570 = extractvalue %hia.buffer %p_5_1, 0
  %t571 = extractvalue %hia.buffer %p_5_1, 1
  %t572 = icmp ult i64 %t569, %t571
  br i1 %t572, label %ok_573, label %trap_573
trap_573:
  call void @abort()
  unreachable
ok_573:
  %t574 = getelementptr i8, ptr %t570, i64 %t569
  store i8 %t568, ptr %t574, align 1
  %t575 = icmp ult i64 0, 64
  br i1 %t575, label %ok_576, label %trap_576
trap_576:
  call void @abort()
  unreachable
ok_576:
  %t577 = lshr i64 %t502, 0
  %t578 = trunc i64 %t577 to i8
  %t579 = add i64 %t504, 0
  %t580 = extractvalue %hia.buffer %p_5_1, 0
  %t581 = extractvalue %hia.buffer %p_5_1, 1
  %t582 = icmp ult i64 %t579, %t581
  br i1 %t582, label %ok_583, label %trap_583
trap_583:
  call void @abort()
  unreachable
ok_583:
  %t584 = getelementptr i8, ptr %t580, i64 %t579
  store i8 %t578, ptr %t584, align 1
  %t585 = add i64 %p_5_4, 8
  %t586 = sub i64 %p_5_5, 8
  %t587 = trunc i64 16 to i32
  %t588 = zext i32 %t587 to i64
  %t589 = icmp ult i64 56, 64
  br i1 %t589, label %ok_590, label %trap_590
trap_590:
  call void @abort()
  unreachable
ok_590:
  %t591 = lshr i64 %t585, 56
  %t592 = trunc i64 %t591 to i8
  %t593 = add i64 %t588, 7
  %t594 = extractvalue %hia.buffer %p_5_1, 0
  %t595 = extractvalue %hia.buffer %p_5_1, 1
  %t596 = icmp ult i64 %t593, %t595
  br i1 %t596, label %ok_597, label %trap_597
trap_597:
  call void @abort()
  unreachable
ok_597:
  %t598 = getelementptr i8, ptr %t594, i64 %t593
  store i8 %t592, ptr %t598, align 1
  %t599 = icmp ult i64 48, 64
  br i1 %t599, label %ok_600, label %trap_600
trap_600:
  call void @abort()
  unreachable
ok_600:
  %t601 = lshr i64 %t585, 48
  %t602 = trunc i64 %t601 to i8
  %t603 = add i64 %t588, 6
  %t604 = extractvalue %hia.buffer %p_5_1, 0
  %t605 = extractvalue %hia.buffer %p_5_1, 1
  %t606 = icmp ult i64 %t603, %t605
  br i1 %t606, label %ok_607, label %trap_607
trap_607:
  call void @abort()
  unreachable
ok_607:
  %t608 = getelementptr i8, ptr %t604, i64 %t603
  store i8 %t602, ptr %t608, align 1
  %t609 = icmp ult i64 40, 64
  br i1 %t609, label %ok_610, label %trap_610
trap_610:
  call void @abort()
  unreachable
ok_610:
  %t611 = lshr i64 %t585, 40
  %t612 = trunc i64 %t611 to i8
  %t613 = add i64 %t588, 5
  %t614 = extractvalue %hia.buffer %p_5_1, 0
  %t615 = extractvalue %hia.buffer %p_5_1, 1
  %t616 = icmp ult i64 %t613, %t615
  br i1 %t616, label %ok_617, label %trap_617
trap_617:
  call void @abort()
  unreachable
ok_617:
  %t618 = getelementptr i8, ptr %t614, i64 %t613
  store i8 %t612, ptr %t618, align 1
  %t619 = icmp ult i64 32, 64
  br i1 %t619, label %ok_620, label %trap_620
trap_620:
  call void @abort()
  unreachable
ok_620:
  %t621 = lshr i64 %t585, 32
  %t622 = trunc i64 %t621 to i8
  %t623 = add i64 %t588, 4
  %t624 = extractvalue %hia.buffer %p_5_1, 0
  %t625 = extractvalue %hia.buffer %p_5_1, 1
  %t626 = icmp ult i64 %t623, %t625
  br i1 %t626, label %ok_627, label %trap_627
trap_627:
  call void @abort()
  unreachable
ok_627:
  %t628 = getelementptr i8, ptr %t624, i64 %t623
  store i8 %t622, ptr %t628, align 1
  %t629 = icmp ult i64 24, 64
  br i1 %t629, label %ok_630, label %trap_630
trap_630:
  call void @abort()
  unreachable
ok_630:
  %t631 = lshr i64 %t585, 24
  %t632 = trunc i64 %t631 to i8
  %t633 = add i64 %t588, 3
  %t634 = extractvalue %hia.buffer %p_5_1, 0
  %t635 = extractvalue %hia.buffer %p_5_1, 1
  %t636 = icmp ult i64 %t633, %t635
  br i1 %t636, label %ok_637, label %trap_637
trap_637:
  call void @abort()
  unreachable
ok_637:
  %t638 = getelementptr i8, ptr %t634, i64 %t633
  store i8 %t632, ptr %t638, align 1
  %t639 = icmp ult i64 16, 64
  br i1 %t639, label %ok_640, label %trap_640
trap_640:
  call void @abort()
  unreachable
ok_640:
  %t641 = lshr i64 %t585, 16
  %t642 = trunc i64 %t641 to i8
  %t643 = add i64 %t588, 2
  %t644 = extractvalue %hia.buffer %p_5_1, 0
  %t645 = extractvalue %hia.buffer %p_5_1, 1
  %t646 = icmp ult i64 %t643, %t645
  br i1 %t646, label %ok_647, label %trap_647
trap_647:
  call void @abort()
  unreachable
ok_647:
  %t648 = getelementptr i8, ptr %t644, i64 %t643
  store i8 %t642, ptr %t648, align 1
  %t649 = icmp ult i64 8, 64
  br i1 %t649, label %ok_650, label %trap_650
trap_650:
  call void @abort()
  unreachable
ok_650:
  %t651 = lshr i64 %t585, 8
  %t652 = trunc i64 %t651 to i8
  %t653 = add i64 %t588, 1
  %t654 = extractvalue %hia.buffer %p_5_1, 0
  %t655 = extractvalue %hia.buffer %p_5_1, 1
  %t656 = icmp ult i64 %t653, %t655
  br i1 %t656, label %ok_657, label %trap_657
trap_657:
  call void @abort()
  unreachable
ok_657:
  %t658 = getelementptr i8, ptr %t654, i64 %t653
  store i8 %t652, ptr %t658, align 1
  %t659 = icmp ult i64 0, 64
  br i1 %t659, label %ok_660, label %trap_660
trap_660:
  call void @abort()
  unreachable
ok_660:
  %t661 = lshr i64 %t585, 0
  %t662 = trunc i64 %t661 to i8
  %t663 = add i64 %t588, 0
  %t664 = extractvalue %hia.buffer %p_5_1, 0
  %t665 = extractvalue %hia.buffer %p_5_1, 1
  %t666 = icmp ult i64 %t663, %t665
  br i1 %t666, label %ok_667, label %trap_667
trap_667:
  call void @abort()
  unreachable
ok_667:
  %t668 = getelementptr i8, ptr %t664, i64 %t663
  store i8 %t662, ptr %t668, align 1
  %t669 = trunc i64 24 to i32
  %t670 = zext i32 %t669 to i64
  %t671 = icmp ult i64 56, 64
  br i1 %t671, label %ok_672, label %trap_672
trap_672:
  call void @abort()
  unreachable
ok_672:
  %t673 = lshr i64 %t586, 56
  %t674 = trunc i64 %t673 to i8
  %t675 = add i64 %t670, 7
  %t676 = extractvalue %hia.buffer %p_5_1, 0
  %t677 = extractvalue %hia.buffer %p_5_1, 1
  %t678 = icmp ult i64 %t675, %t677
  br i1 %t678, label %ok_679, label %trap_679
trap_679:
  call void @abort()
  unreachable
ok_679:
  %t680 = getelementptr i8, ptr %t676, i64 %t675
  store i8 %t674, ptr %t680, align 1
  %t681 = icmp ult i64 48, 64
  br i1 %t681, label %ok_682, label %trap_682
trap_682:
  call void @abort()
  unreachable
ok_682:
  %t683 = lshr i64 %t586, 48
  %t684 = trunc i64 %t683 to i8
  %t685 = add i64 %t670, 6
  %t686 = extractvalue %hia.buffer %p_5_1, 0
  %t687 = extractvalue %hia.buffer %p_5_1, 1
  %t688 = icmp ult i64 %t685, %t687
  br i1 %t688, label %ok_689, label %trap_689
trap_689:
  call void @abort()
  unreachable
ok_689:
  %t690 = getelementptr i8, ptr %t686, i64 %t685
  store i8 %t684, ptr %t690, align 1
  %t691 = icmp ult i64 40, 64
  br i1 %t691, label %ok_692, label %trap_692
trap_692:
  call void @abort()
  unreachable
ok_692:
  %t693 = lshr i64 %t586, 40
  %t694 = trunc i64 %t693 to i8
  %t695 = add i64 %t670, 5
  %t696 = extractvalue %hia.buffer %p_5_1, 0
  %t697 = extractvalue %hia.buffer %p_5_1, 1
  %t698 = icmp ult i64 %t695, %t697
  br i1 %t698, label %ok_699, label %trap_699
trap_699:
  call void @abort()
  unreachable
ok_699:
  %t700 = getelementptr i8, ptr %t696, i64 %t695
  store i8 %t694, ptr %t700, align 1
  %t701 = icmp ult i64 32, 64
  br i1 %t701, label %ok_702, label %trap_702
trap_702:
  call void @abort()
  unreachable
ok_702:
  %t703 = lshr i64 %t586, 32
  %t704 = trunc i64 %t703 to i8
  %t705 = add i64 %t670, 4
  %t706 = extractvalue %hia.buffer %p_5_1, 0
  %t707 = extractvalue %hia.buffer %p_5_1, 1
  %t708 = icmp ult i64 %t705, %t707
  br i1 %t708, label %ok_709, label %trap_709
trap_709:
  call void @abort()
  unreachable
ok_709:
  %t710 = getelementptr i8, ptr %t706, i64 %t705
  store i8 %t704, ptr %t710, align 1
  %t711 = icmp ult i64 24, 64
  br i1 %t711, label %ok_712, label %trap_712
trap_712:
  call void @abort()
  unreachable
ok_712:
  %t713 = lshr i64 %t586, 24
  %t714 = trunc i64 %t713 to i8
  %t715 = add i64 %t670, 3
  %t716 = extractvalue %hia.buffer %p_5_1, 0
  %t717 = extractvalue %hia.buffer %p_5_1, 1
  %t718 = icmp ult i64 %t715, %t717
  br i1 %t718, label %ok_719, label %trap_719
trap_719:
  call void @abort()
  unreachable
ok_719:
  %t720 = getelementptr i8, ptr %t716, i64 %t715
  store i8 %t714, ptr %t720, align 1
  %t721 = icmp ult i64 16, 64
  br i1 %t721, label %ok_722, label %trap_722
trap_722:
  call void @abort()
  unreachable
ok_722:
  %t723 = lshr i64 %t586, 16
  %t724 = trunc i64 %t723 to i8
  %t725 = add i64 %t670, 2
  %t726 = extractvalue %hia.buffer %p_5_1, 0
  %t727 = extractvalue %hia.buffer %p_5_1, 1
  %t728 = icmp ult i64 %t725, %t727
  br i1 %t728, label %ok_729, label %trap_729
trap_729:
  call void @abort()
  unreachable
ok_729:
  %t730 = getelementptr i8, ptr %t726, i64 %t725
  store i8 %t724, ptr %t730, align 1
  %t731 = icmp ult i64 8, 64
  br i1 %t731, label %ok_732, label %trap_732
trap_732:
  call void @abort()
  unreachable
ok_732:
  %t733 = lshr i64 %t586, 8
  %t734 = trunc i64 %t733 to i8
  %t735 = add i64 %t670, 1
  %t736 = extractvalue %hia.buffer %p_5_1, 0
  %t737 = extractvalue %hia.buffer %p_5_1, 1
  %t738 = icmp ult i64 %t735, %t737
  br i1 %t738, label %ok_739, label %trap_739
trap_739:
  call void @abort()
  unreachable
ok_739:
  %t740 = getelementptr i8, ptr %t736, i64 %t735
  store i8 %t734, ptr %t740, align 1
  %t741 = icmp ult i64 0, 64
  br i1 %t741, label %ok_742, label %trap_742
trap_742:
  call void @abort()
  unreachable
ok_742:
  %t743 = lshr i64 %t586, 0
  %t744 = trunc i64 %t743 to i8
  %t745 = add i64 %t670, 0
  %t746 = extractvalue %hia.buffer %p_5_1, 0
  %t747 = extractvalue %hia.buffer %p_5_1, 1
  %t748 = icmp ult i64 %t745, %t747
  br i1 %t748, label %ok_749, label %trap_749
trap_749:
  call void @abort()
  unreachable
ok_749:
  %t750 = getelementptr i8, ptr %t746, i64 %t745
  store i8 %t744, ptr %t750, align 1
  %t751 = icmp ult i64 48, 64
  br i1 %t751, label %ok_752, label %trap_752
trap_752:
  call void @abort()
  unreachable
ok_752:
  %t753 = lshr i64 %t501, 48
  %t754 = trunc i64 %t753 to i32
  ret i32 %t754
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

define internal i32 @__hia_fn_3(%hia.buffer %p_0_0, %hia.buffer %p_0_1, i64 %p_0_2, i16 %p_0_3) alwaysinline {
b0:
  %t1 = extractvalue %hia.buffer %p_0_1, 1
  %t2 = icmp eq i64 %t1, 32
  %t3 = extractvalue %hia.buffer %p_0_0, 1
  %t4 = icmp ule i64 %t3, 65536
  %t5 = and i1 %t2, %t4
  br i1 %t5, label %edge_0, label %edge_1
b1:
  %p_1_0 = phi %hia.buffer [ %p_0_0, %edge_0 ]
  %p_1_1 = phi %hia.buffer [ %p_0_1, %edge_0 ]
  %p_1_2 = phi i64 [ %p_0_2, %edge_0 ]
  %p_1_3 = phi i16 [ %p_0_3, %edge_0 ]
  %t6 = trunc i64 0 to i32
  %t7 = zext i32 %t6 to i64
  %t8 = add i64 %t7, 7
  %t9 = extractvalue %hia.buffer %p_1_1, 0
  %t10 = extractvalue %hia.buffer %p_1_1, 1
  %t11 = icmp ult i64 %t8, %t10
  br i1 %t11, label %ok_12, label %trap_12
trap_12:
  call void @abort()
  unreachable
ok_12:
  %t13 = getelementptr i8, ptr %t9, i64 %t8
  %t14 = load i8, ptr %t13, align 1
  %t15 = zext i8 %t14 to i64
  %t16 = icmp ult i64 56, 64
  br i1 %t16, label %ok_17, label %trap_17
trap_17:
  call void @abort()
  unreachable
ok_17:
  %t18 = shl i64 %t15, 56
  %t19 = or i64 0, %t18
  %t20 = add i64 %t7, 6
  %t21 = extractvalue %hia.buffer %p_1_1, 0
  %t22 = extractvalue %hia.buffer %p_1_1, 1
  %t23 = icmp ult i64 %t20, %t22
  br i1 %t23, label %ok_24, label %trap_24
trap_24:
  call void @abort()
  unreachable
ok_24:
  %t25 = getelementptr i8, ptr %t21, i64 %t20
  %t26 = load i8, ptr %t25, align 1
  %t27 = zext i8 %t26 to i64
  %t28 = icmp ult i64 48, 64
  br i1 %t28, label %ok_29, label %trap_29
trap_29:
  call void @abort()
  unreachable
ok_29:
  %t30 = shl i64 %t27, 48
  %t31 = or i64 %t19, %t30
  %t32 = add i64 %t7, 5
  %t33 = extractvalue %hia.buffer %p_1_1, 0
  %t34 = extractvalue %hia.buffer %p_1_1, 1
  %t35 = icmp ult i64 %t32, %t34
  br i1 %t35, label %ok_36, label %trap_36
trap_36:
  call void @abort()
  unreachable
ok_36:
  %t37 = getelementptr i8, ptr %t33, i64 %t32
  %t38 = load i8, ptr %t37, align 1
  %t39 = zext i8 %t38 to i64
  %t40 = icmp ult i64 40, 64
  br i1 %t40, label %ok_41, label %trap_41
trap_41:
  call void @abort()
  unreachable
ok_41:
  %t42 = shl i64 %t39, 40
  %t43 = or i64 %t31, %t42
  %t44 = add i64 %t7, 4
  %t45 = extractvalue %hia.buffer %p_1_1, 0
  %t46 = extractvalue %hia.buffer %p_1_1, 1
  %t47 = icmp ult i64 %t44, %t46
  br i1 %t47, label %ok_48, label %trap_48
trap_48:
  call void @abort()
  unreachable
ok_48:
  %t49 = getelementptr i8, ptr %t45, i64 %t44
  %t50 = load i8, ptr %t49, align 1
  %t51 = zext i8 %t50 to i64
  %t52 = icmp ult i64 32, 64
  br i1 %t52, label %ok_53, label %trap_53
trap_53:
  call void @abort()
  unreachable
ok_53:
  %t54 = shl i64 %t51, 32
  %t55 = or i64 %t43, %t54
  %t56 = add i64 %t7, 3
  %t57 = extractvalue %hia.buffer %p_1_1, 0
  %t58 = extractvalue %hia.buffer %p_1_1, 1
  %t59 = icmp ult i64 %t56, %t58
  br i1 %t59, label %ok_60, label %trap_60
trap_60:
  call void @abort()
  unreachable
ok_60:
  %t61 = getelementptr i8, ptr %t57, i64 %t56
  %t62 = load i8, ptr %t61, align 1
  %t63 = zext i8 %t62 to i64
  %t64 = icmp ult i64 24, 64
  br i1 %t64, label %ok_65, label %trap_65
trap_65:
  call void @abort()
  unreachable
ok_65:
  %t66 = shl i64 %t63, 24
  %t67 = or i64 %t55, %t66
  %t68 = add i64 %t7, 2
  %t69 = extractvalue %hia.buffer %p_1_1, 0
  %t70 = extractvalue %hia.buffer %p_1_1, 1
  %t71 = icmp ult i64 %t68, %t70
  br i1 %t71, label %ok_72, label %trap_72
trap_72:
  call void @abort()
  unreachable
ok_72:
  %t73 = getelementptr i8, ptr %t69, i64 %t68
  %t74 = load i8, ptr %t73, align 1
  %t75 = zext i8 %t74 to i64
  %t76 = icmp ult i64 16, 64
  br i1 %t76, label %ok_77, label %trap_77
trap_77:
  call void @abort()
  unreachable
ok_77:
  %t78 = shl i64 %t75, 16
  %t79 = or i64 %t67, %t78
  %t80 = add i64 %t7, 1
  %t81 = extractvalue %hia.buffer %p_1_1, 0
  %t82 = extractvalue %hia.buffer %p_1_1, 1
  %t83 = icmp ult i64 %t80, %t82
  br i1 %t83, label %ok_84, label %trap_84
trap_84:
  call void @abort()
  unreachable
ok_84:
  %t85 = getelementptr i8, ptr %t81, i64 %t80
  %t86 = load i8, ptr %t85, align 1
  %t87 = zext i8 %t86 to i64
  %t88 = icmp ult i64 8, 64
  br i1 %t88, label %ok_89, label %trap_89
trap_89:
  call void @abort()
  unreachable
ok_89:
  %t90 = shl i64 %t87, 8
  %t91 = or i64 %t79, %t90
  %t92 = add i64 %t7, 0
  %t93 = extractvalue %hia.buffer %p_1_1, 0
  %t94 = extractvalue %hia.buffer %p_1_1, 1
  %t95 = icmp ult i64 %t92, %t94
  br i1 %t95, label %ok_96, label %trap_96
trap_96:
  call void @abort()
  unreachable
ok_96:
  %t97 = getelementptr i8, ptr %t93, i64 %t92
  %t98 = load i8, ptr %t97, align 1
  %t99 = zext i8 %t98 to i64
  %t100 = icmp ult i64 0, 64
  br i1 %t100, label %ok_101, label %trap_101
trap_101:
  call void @abort()
  unreachable
ok_101:
  %t102 = shl i64 %t99, 0
  %t103 = or i64 %t91, %t102
  %t104 = trunc i64 8 to i32
  %t105 = zext i32 %t104 to i64
  %t106 = add i64 %t105, 7
  %t107 = extractvalue %hia.buffer %p_1_1, 0
  %t108 = extractvalue %hia.buffer %p_1_1, 1
  %t109 = icmp ult i64 %t106, %t108
  br i1 %t109, label %ok_110, label %trap_110
trap_110:
  call void @abort()
  unreachable
ok_110:
  %t111 = getelementptr i8, ptr %t107, i64 %t106
  %t112 = load i8, ptr %t111, align 1
  %t113 = zext i8 %t112 to i64
  %t114 = icmp ult i64 56, 64
  br i1 %t114, label %ok_115, label %trap_115
trap_115:
  call void @abort()
  unreachable
ok_115:
  %t116 = shl i64 %t113, 56
  %t117 = or i64 0, %t116
  %t118 = add i64 %t105, 6
  %t119 = extractvalue %hia.buffer %p_1_1, 0
  %t120 = extractvalue %hia.buffer %p_1_1, 1
  %t121 = icmp ult i64 %t118, %t120
  br i1 %t121, label %ok_122, label %trap_122
trap_122:
  call void @abort()
  unreachable
ok_122:
  %t123 = getelementptr i8, ptr %t119, i64 %t118
  %t124 = load i8, ptr %t123, align 1
  %t125 = zext i8 %t124 to i64
  %t126 = icmp ult i64 48, 64
  br i1 %t126, label %ok_127, label %trap_127
trap_127:
  call void @abort()
  unreachable
ok_127:
  %t128 = shl i64 %t125, 48
  %t129 = or i64 %t117, %t128
  %t130 = add i64 %t105, 5
  %t131 = extractvalue %hia.buffer %p_1_1, 0
  %t132 = extractvalue %hia.buffer %p_1_1, 1
  %t133 = icmp ult i64 %t130, %t132
  br i1 %t133, label %ok_134, label %trap_134
trap_134:
  call void @abort()
  unreachable
ok_134:
  %t135 = getelementptr i8, ptr %t131, i64 %t130
  %t136 = load i8, ptr %t135, align 1
  %t137 = zext i8 %t136 to i64
  %t138 = icmp ult i64 40, 64
  br i1 %t138, label %ok_139, label %trap_139
trap_139:
  call void @abort()
  unreachable
ok_139:
  %t140 = shl i64 %t137, 40
  %t141 = or i64 %t129, %t140
  %t142 = add i64 %t105, 4
  %t143 = extractvalue %hia.buffer %p_1_1, 0
  %t144 = extractvalue %hia.buffer %p_1_1, 1
  %t145 = icmp ult i64 %t142, %t144
  br i1 %t145, label %ok_146, label %trap_146
trap_146:
  call void @abort()
  unreachable
ok_146:
  %t147 = getelementptr i8, ptr %t143, i64 %t142
  %t148 = load i8, ptr %t147, align 1
  %t149 = zext i8 %t148 to i64
  %t150 = icmp ult i64 32, 64
  br i1 %t150, label %ok_151, label %trap_151
trap_151:
  call void @abort()
  unreachable
ok_151:
  %t152 = shl i64 %t149, 32
  %t153 = or i64 %t141, %t152
  %t154 = add i64 %t105, 3
  %t155 = extractvalue %hia.buffer %p_1_1, 0
  %t156 = extractvalue %hia.buffer %p_1_1, 1
  %t157 = icmp ult i64 %t154, %t156
  br i1 %t157, label %ok_158, label %trap_158
trap_158:
  call void @abort()
  unreachable
ok_158:
  %t159 = getelementptr i8, ptr %t155, i64 %t154
  %t160 = load i8, ptr %t159, align 1
  %t161 = zext i8 %t160 to i64
  %t162 = icmp ult i64 24, 64
  br i1 %t162, label %ok_163, label %trap_163
trap_163:
  call void @abort()
  unreachable
ok_163:
  %t164 = shl i64 %t161, 24
  %t165 = or i64 %t153, %t164
  %t166 = add i64 %t105, 2
  %t167 = extractvalue %hia.buffer %p_1_1, 0
  %t168 = extractvalue %hia.buffer %p_1_1, 1
  %t169 = icmp ult i64 %t166, %t168
  br i1 %t169, label %ok_170, label %trap_170
trap_170:
  call void @abort()
  unreachable
ok_170:
  %t171 = getelementptr i8, ptr %t167, i64 %t166
  %t172 = load i8, ptr %t171, align 1
  %t173 = zext i8 %t172 to i64
  %t174 = icmp ult i64 16, 64
  br i1 %t174, label %ok_175, label %trap_175
trap_175:
  call void @abort()
  unreachable
ok_175:
  %t176 = shl i64 %t173, 16
  %t177 = or i64 %t165, %t176
  %t178 = add i64 %t105, 1
  %t179 = extractvalue %hia.buffer %p_1_1, 0
  %t180 = extractvalue %hia.buffer %p_1_1, 1
  %t181 = icmp ult i64 %t178, %t180
  br i1 %t181, label %ok_182, label %trap_182
trap_182:
  call void @abort()
  unreachable
ok_182:
  %t183 = getelementptr i8, ptr %t179, i64 %t178
  %t184 = load i8, ptr %t183, align 1
  %t185 = zext i8 %t184 to i64
  %t186 = icmp ult i64 8, 64
  br i1 %t186, label %ok_187, label %trap_187
trap_187:
  call void @abort()
  unreachable
ok_187:
  %t188 = shl i64 %t185, 8
  %t189 = or i64 %t177, %t188
  %t190 = add i64 %t105, 0
  %t191 = extractvalue %hia.buffer %p_1_1, 0
  %t192 = extractvalue %hia.buffer %p_1_1, 1
  %t193 = icmp ult i64 %t190, %t192
  br i1 %t193, label %ok_194, label %trap_194
trap_194:
  call void @abort()
  unreachable
ok_194:
  %t195 = getelementptr i8, ptr %t191, i64 %t190
  %t196 = load i8, ptr %t195, align 1
  %t197 = zext i8 %t196 to i64
  %t198 = icmp ult i64 0, 64
  br i1 %t198, label %ok_199, label %trap_199
trap_199:
  call void @abort()
  unreachable
ok_199:
  %t200 = shl i64 %t197, 0
  %t201 = or i64 %t189, %t200
  %t202 = trunc i64 16 to i32
  %t203 = zext i32 %t202 to i64
  %t204 = add i64 %t203, 7
  %t205 = extractvalue %hia.buffer %p_1_1, 0
  %t206 = extractvalue %hia.buffer %p_1_1, 1
  %t207 = icmp ult i64 %t204, %t206
  br i1 %t207, label %ok_208, label %trap_208
trap_208:
  call void @abort()
  unreachable
ok_208:
  %t209 = getelementptr i8, ptr %t205, i64 %t204
  %t210 = load i8, ptr %t209, align 1
  %t211 = zext i8 %t210 to i64
  %t212 = icmp ult i64 56, 64
  br i1 %t212, label %ok_213, label %trap_213
trap_213:
  call void @abort()
  unreachable
ok_213:
  %t214 = shl i64 %t211, 56
  %t215 = or i64 0, %t214
  %t216 = add i64 %t203, 6
  %t217 = extractvalue %hia.buffer %p_1_1, 0
  %t218 = extractvalue %hia.buffer %p_1_1, 1
  %t219 = icmp ult i64 %t216, %t218
  br i1 %t219, label %ok_220, label %trap_220
trap_220:
  call void @abort()
  unreachable
ok_220:
  %t221 = getelementptr i8, ptr %t217, i64 %t216
  %t222 = load i8, ptr %t221, align 1
  %t223 = zext i8 %t222 to i64
  %t224 = icmp ult i64 48, 64
  br i1 %t224, label %ok_225, label %trap_225
trap_225:
  call void @abort()
  unreachable
ok_225:
  %t226 = shl i64 %t223, 48
  %t227 = or i64 %t215, %t226
  %t228 = add i64 %t203, 5
  %t229 = extractvalue %hia.buffer %p_1_1, 0
  %t230 = extractvalue %hia.buffer %p_1_1, 1
  %t231 = icmp ult i64 %t228, %t230
  br i1 %t231, label %ok_232, label %trap_232
trap_232:
  call void @abort()
  unreachable
ok_232:
  %t233 = getelementptr i8, ptr %t229, i64 %t228
  %t234 = load i8, ptr %t233, align 1
  %t235 = zext i8 %t234 to i64
  %t236 = icmp ult i64 40, 64
  br i1 %t236, label %ok_237, label %trap_237
trap_237:
  call void @abort()
  unreachable
ok_237:
  %t238 = shl i64 %t235, 40
  %t239 = or i64 %t227, %t238
  %t240 = add i64 %t203, 4
  %t241 = extractvalue %hia.buffer %p_1_1, 0
  %t242 = extractvalue %hia.buffer %p_1_1, 1
  %t243 = icmp ult i64 %t240, %t242
  br i1 %t243, label %ok_244, label %trap_244
trap_244:
  call void @abort()
  unreachable
ok_244:
  %t245 = getelementptr i8, ptr %t241, i64 %t240
  %t246 = load i8, ptr %t245, align 1
  %t247 = zext i8 %t246 to i64
  %t248 = icmp ult i64 32, 64
  br i1 %t248, label %ok_249, label %trap_249
trap_249:
  call void @abort()
  unreachable
ok_249:
  %t250 = shl i64 %t247, 32
  %t251 = or i64 %t239, %t250
  %t252 = add i64 %t203, 3
  %t253 = extractvalue %hia.buffer %p_1_1, 0
  %t254 = extractvalue %hia.buffer %p_1_1, 1
  %t255 = icmp ult i64 %t252, %t254
  br i1 %t255, label %ok_256, label %trap_256
trap_256:
  call void @abort()
  unreachable
ok_256:
  %t257 = getelementptr i8, ptr %t253, i64 %t252
  %t258 = load i8, ptr %t257, align 1
  %t259 = zext i8 %t258 to i64
  %t260 = icmp ult i64 24, 64
  br i1 %t260, label %ok_261, label %trap_261
trap_261:
  call void @abort()
  unreachable
ok_261:
  %t262 = shl i64 %t259, 24
  %t263 = or i64 %t251, %t262
  %t264 = add i64 %t203, 2
  %t265 = extractvalue %hia.buffer %p_1_1, 0
  %t266 = extractvalue %hia.buffer %p_1_1, 1
  %t267 = icmp ult i64 %t264, %t266
  br i1 %t267, label %ok_268, label %trap_268
trap_268:
  call void @abort()
  unreachable
ok_268:
  %t269 = getelementptr i8, ptr %t265, i64 %t264
  %t270 = load i8, ptr %t269, align 1
  %t271 = zext i8 %t270 to i64
  %t272 = icmp ult i64 16, 64
  br i1 %t272, label %ok_273, label %trap_273
trap_273:
  call void @abort()
  unreachable
ok_273:
  %t274 = shl i64 %t271, 16
  %t275 = or i64 %t263, %t274
  %t276 = add i64 %t203, 1
  %t277 = extractvalue %hia.buffer %p_1_1, 0
  %t278 = extractvalue %hia.buffer %p_1_1, 1
  %t279 = icmp ult i64 %t276, %t278
  br i1 %t279, label %ok_280, label %trap_280
trap_280:
  call void @abort()
  unreachable
ok_280:
  %t281 = getelementptr i8, ptr %t277, i64 %t276
  %t282 = load i8, ptr %t281, align 1
  %t283 = zext i8 %t282 to i64
  %t284 = icmp ult i64 8, 64
  br i1 %t284, label %ok_285, label %trap_285
trap_285:
  call void @abort()
  unreachable
ok_285:
  %t286 = shl i64 %t283, 8
  %t287 = or i64 %t275, %t286
  %t288 = add i64 %t203, 0
  %t289 = extractvalue %hia.buffer %p_1_1, 0
  %t290 = extractvalue %hia.buffer %p_1_1, 1
  %t291 = icmp ult i64 %t288, %t290
  br i1 %t291, label %ok_292, label %trap_292
trap_292:
  call void @abort()
  unreachable
ok_292:
  %t293 = getelementptr i8, ptr %t289, i64 %t288
  %t294 = load i8, ptr %t293, align 1
  %t295 = zext i8 %t294 to i64
  %t296 = icmp ult i64 0, 64
  br i1 %t296, label %ok_297, label %trap_297
trap_297:
  call void @abort()
  unreachable
ok_297:
  %t298 = shl i64 %t295, 0
  %t299 = or i64 %t287, %t298
  %t300 = trunc i64 24 to i32
  %t301 = zext i32 %t300 to i64
  %t302 = add i64 %t301, 7
  %t303 = extractvalue %hia.buffer %p_1_1, 0
  %t304 = extractvalue %hia.buffer %p_1_1, 1
  %t305 = icmp ult i64 %t302, %t304
  br i1 %t305, label %ok_306, label %trap_306
trap_306:
  call void @abort()
  unreachable
ok_306:
  %t307 = getelementptr i8, ptr %t303, i64 %t302
  %t308 = load i8, ptr %t307, align 1
  %t309 = zext i8 %t308 to i64
  %t310 = icmp ult i64 56, 64
  br i1 %t310, label %ok_311, label %trap_311
trap_311:
  call void @abort()
  unreachable
ok_311:
  %t312 = shl i64 %t309, 56
  %t313 = or i64 0, %t312
  %t314 = add i64 %t301, 6
  %t315 = extractvalue %hia.buffer %p_1_1, 0
  %t316 = extractvalue %hia.buffer %p_1_1, 1
  %t317 = icmp ult i64 %t314, %t316
  br i1 %t317, label %ok_318, label %trap_318
trap_318:
  call void @abort()
  unreachable
ok_318:
  %t319 = getelementptr i8, ptr %t315, i64 %t314
  %t320 = load i8, ptr %t319, align 1
  %t321 = zext i8 %t320 to i64
  %t322 = icmp ult i64 48, 64
  br i1 %t322, label %ok_323, label %trap_323
trap_323:
  call void @abort()
  unreachable
ok_323:
  %t324 = shl i64 %t321, 48
  %t325 = or i64 %t313, %t324
  %t326 = add i64 %t301, 5
  %t327 = extractvalue %hia.buffer %p_1_1, 0
  %t328 = extractvalue %hia.buffer %p_1_1, 1
  %t329 = icmp ult i64 %t326, %t328
  br i1 %t329, label %ok_330, label %trap_330
trap_330:
  call void @abort()
  unreachable
ok_330:
  %t331 = getelementptr i8, ptr %t327, i64 %t326
  %t332 = load i8, ptr %t331, align 1
  %t333 = zext i8 %t332 to i64
  %t334 = icmp ult i64 40, 64
  br i1 %t334, label %ok_335, label %trap_335
trap_335:
  call void @abort()
  unreachable
ok_335:
  %t336 = shl i64 %t333, 40
  %t337 = or i64 %t325, %t336
  %t338 = add i64 %t301, 4
  %t339 = extractvalue %hia.buffer %p_1_1, 0
  %t340 = extractvalue %hia.buffer %p_1_1, 1
  %t341 = icmp ult i64 %t338, %t340
  br i1 %t341, label %ok_342, label %trap_342
trap_342:
  call void @abort()
  unreachable
ok_342:
  %t343 = getelementptr i8, ptr %t339, i64 %t338
  %t344 = load i8, ptr %t343, align 1
  %t345 = zext i8 %t344 to i64
  %t346 = icmp ult i64 32, 64
  br i1 %t346, label %ok_347, label %trap_347
trap_347:
  call void @abort()
  unreachable
ok_347:
  %t348 = shl i64 %t345, 32
  %t349 = or i64 %t337, %t348
  %t350 = add i64 %t301, 3
  %t351 = extractvalue %hia.buffer %p_1_1, 0
  %t352 = extractvalue %hia.buffer %p_1_1, 1
  %t353 = icmp ult i64 %t350, %t352
  br i1 %t353, label %ok_354, label %trap_354
trap_354:
  call void @abort()
  unreachable
ok_354:
  %t355 = getelementptr i8, ptr %t351, i64 %t350
  %t356 = load i8, ptr %t355, align 1
  %t357 = zext i8 %t356 to i64
  %t358 = icmp ult i64 24, 64
  br i1 %t358, label %ok_359, label %trap_359
trap_359:
  call void @abort()
  unreachable
ok_359:
  %t360 = shl i64 %t357, 24
  %t361 = or i64 %t349, %t360
  %t362 = add i64 %t301, 2
  %t363 = extractvalue %hia.buffer %p_1_1, 0
  %t364 = extractvalue %hia.buffer %p_1_1, 1
  %t365 = icmp ult i64 %t362, %t364
  br i1 %t365, label %ok_366, label %trap_366
trap_366:
  call void @abort()
  unreachable
ok_366:
  %t367 = getelementptr i8, ptr %t363, i64 %t362
  %t368 = load i8, ptr %t367, align 1
  %t369 = zext i8 %t368 to i64
  %t370 = icmp ult i64 16, 64
  br i1 %t370, label %ok_371, label %trap_371
trap_371:
  call void @abort()
  unreachable
ok_371:
  %t372 = shl i64 %t369, 16
  %t373 = or i64 %t361, %t372
  %t374 = add i64 %t301, 1
  %t375 = extractvalue %hia.buffer %p_1_1, 0
  %t376 = extractvalue %hia.buffer %p_1_1, 1
  %t377 = icmp ult i64 %t374, %t376
  br i1 %t377, label %ok_378, label %trap_378
trap_378:
  call void @abort()
  unreachable
ok_378:
  %t379 = getelementptr i8, ptr %t375, i64 %t374
  %t380 = load i8, ptr %t379, align 1
  %t381 = zext i8 %t380 to i64
  %t382 = icmp ult i64 8, 64
  br i1 %t382, label %ok_383, label %trap_383
trap_383:
  call void @abort()
  unreachable
ok_383:
  %t384 = shl i64 %t381, 8
  %t385 = or i64 %t373, %t384
  %t386 = add i64 %t301, 0
  %t387 = extractvalue %hia.buffer %p_1_1, 0
  %t388 = extractvalue %hia.buffer %p_1_1, 1
  %t389 = icmp ult i64 %t386, %t388
  br i1 %t389, label %ok_390, label %trap_390
trap_390:
  call void @abort()
  unreachable
ok_390:
  %t391 = getelementptr i8, ptr %t387, i64 %t386
  %t392 = load i8, ptr %t391, align 1
  %t393 = zext i8 %t392 to i64
  %t394 = icmp ult i64 0, 64
  br i1 %t394, label %ok_395, label %trap_395
trap_395:
  call void @abort()
  unreachable
ok_395:
  %t396 = shl i64 %t393, 0
  %t397 = or i64 %t385, %t396
  %t398 = extractvalue %hia.buffer %p_1_0, 1
  %t399 = icmp ule i64 %t299, %t398
  %t400 = sub i64 %t398, %t299
  %t401 = icmp ule i64 %t397, %t400
  %t402 = and i1 %t399, %t401
  br i1 %t402, label %edge_2, label %edge_3
b2:
  ret i32 4294836225
b3:
  ret i32 0
b4:
  ret i32 1
b5:
  %p_5_0 = phi %hia.buffer [ %p_1_0, %edge_2 ]
  %p_5_1 = phi %hia.buffer [ %p_1_1, %edge_2 ]
  %p_5_2 = phi i64 [ %t103, %edge_2 ]
  %p_5_3 = phi i64 [ %t201, %edge_2 ]
  %p_5_4 = phi i64 [ %t299, %edge_2 ]
  %p_5_5 = phi i64 [ %t397, %edge_2 ]
  %p_5_6 = phi i64 [ %t398, %edge_2 ]
  %p_5_7 = phi i64 [ %p_1_2, %edge_2 ]
  %p_5_8 = phi i16 [ %p_1_3, %edge_2 ]
  %t403 = icmp eq i64 %p_5_3, 0
  %t404 = select i1 %t403, i64 %p_5_7, i64 %p_5_3
  %t405 = trunc i64 8 to i32
  %t406 = zext i32 %t405 to i64
  %t407 = icmp ult i64 56, 64
  br i1 %t407, label %ok_408, label %trap_408
trap_408:
  call void @abort()
  unreachable
ok_408:
  %t409 = lshr i64 %t404, 56
  %t410 = trunc i64 %t409 to i8
  %t411 = add i64 %t406, 7
  %t412 = extractvalue %hia.buffer %p_5_1, 0
  %t413 = extractvalue %hia.buffer %p_5_1, 1
  %t414 = icmp ult i64 %t411, %t413
  br i1 %t414, label %ok_415, label %trap_415
trap_415:
  call void @abort()
  unreachable
ok_415:
  %t416 = getelementptr i8, ptr %t412, i64 %t411
  store i8 %t410, ptr %t416, align 1
  %t417 = icmp ult i64 48, 64
  br i1 %t417, label %ok_418, label %trap_418
trap_418:
  call void @abort()
  unreachable
ok_418:
  %t419 = lshr i64 %t404, 48
  %t420 = trunc i64 %t419 to i8
  %t421 = add i64 %t406, 6
  %t422 = extractvalue %hia.buffer %p_5_1, 0
  %t423 = extractvalue %hia.buffer %p_5_1, 1
  %t424 = icmp ult i64 %t421, %t423
  br i1 %t424, label %ok_425, label %trap_425
trap_425:
  call void @abort()
  unreachable
ok_425:
  %t426 = getelementptr i8, ptr %t422, i64 %t421
  store i8 %t420, ptr %t426, align 1
  %t427 = icmp ult i64 40, 64
  br i1 %t427, label %ok_428, label %trap_428
trap_428:
  call void @abort()
  unreachable
ok_428:
  %t429 = lshr i64 %t404, 40
  %t430 = trunc i64 %t429 to i8
  %t431 = add i64 %t406, 5
  %t432 = extractvalue %hia.buffer %p_5_1, 0
  %t433 = extractvalue %hia.buffer %p_5_1, 1
  %t434 = icmp ult i64 %t431, %t433
  br i1 %t434, label %ok_435, label %trap_435
trap_435:
  call void @abort()
  unreachable
ok_435:
  %t436 = getelementptr i8, ptr %t432, i64 %t431
  store i8 %t430, ptr %t436, align 1
  %t437 = icmp ult i64 32, 64
  br i1 %t437, label %ok_438, label %trap_438
trap_438:
  call void @abort()
  unreachable
ok_438:
  %t439 = lshr i64 %t404, 32
  %t440 = trunc i64 %t439 to i8
  %t441 = add i64 %t406, 4
  %t442 = extractvalue %hia.buffer %p_5_1, 0
  %t443 = extractvalue %hia.buffer %p_5_1, 1
  %t444 = icmp ult i64 %t441, %t443
  br i1 %t444, label %ok_445, label %trap_445
trap_445:
  call void @abort()
  unreachable
ok_445:
  %t446 = getelementptr i8, ptr %t442, i64 %t441
  store i8 %t440, ptr %t446, align 1
  %t447 = icmp ult i64 24, 64
  br i1 %t447, label %ok_448, label %trap_448
trap_448:
  call void @abort()
  unreachable
ok_448:
  %t449 = lshr i64 %t404, 24
  %t450 = trunc i64 %t449 to i8
  %t451 = add i64 %t406, 3
  %t452 = extractvalue %hia.buffer %p_5_1, 0
  %t453 = extractvalue %hia.buffer %p_5_1, 1
  %t454 = icmp ult i64 %t451, %t453
  br i1 %t454, label %ok_455, label %trap_455
trap_455:
  call void @abort()
  unreachable
ok_455:
  %t456 = getelementptr i8, ptr %t452, i64 %t451
  store i8 %t450, ptr %t456, align 1
  %t457 = icmp ult i64 16, 64
  br i1 %t457, label %ok_458, label %trap_458
trap_458:
  call void @abort()
  unreachable
ok_458:
  %t459 = lshr i64 %t404, 16
  %t460 = trunc i64 %t459 to i8
  %t461 = add i64 %t406, 2
  %t462 = extractvalue %hia.buffer %p_5_1, 0
  %t463 = extractvalue %hia.buffer %p_5_1, 1
  %t464 = icmp ult i64 %t461, %t463
  br i1 %t464, label %ok_465, label %trap_465
trap_465:
  call void @abort()
  unreachable
ok_465:
  %t466 = getelementptr i8, ptr %t462, i64 %t461
  store i8 %t460, ptr %t466, align 1
  %t467 = icmp ult i64 8, 64
  br i1 %t467, label %ok_468, label %trap_468
trap_468:
  call void @abort()
  unreachable
ok_468:
  %t469 = lshr i64 %t404, 8
  %t470 = trunc i64 %t469 to i8
  %t471 = add i64 %t406, 1
  %t472 = extractvalue %hia.buffer %p_5_1, 0
  %t473 = extractvalue %hia.buffer %p_5_1, 1
  %t474 = icmp ult i64 %t471, %t473
  br i1 %t474, label %ok_475, label %trap_475
trap_475:
  call void @abort()
  unreachable
ok_475:
  %t476 = getelementptr i8, ptr %t472, i64 %t471
  store i8 %t470, ptr %t476, align 1
  %t477 = icmp ult i64 0, 64
  br i1 %t477, label %ok_478, label %trap_478
trap_478:
  call void @abort()
  unreachable
ok_478:
  %t479 = lshr i64 %t404, 0
  %t480 = trunc i64 %t479 to i8
  %t481 = add i64 %t406, 0
  %t482 = extractvalue %hia.buffer %p_5_1, 0
  %t483 = extractvalue %hia.buffer %p_5_1, 1
  %t484 = icmp ult i64 %t481, %t483
  br i1 %t484, label %ok_485, label %trap_485
trap_485:
  call void @abort()
  unreachable
ok_485:
  %t486 = getelementptr i8, ptr %t482, i64 %t481
  store i8 %t480, ptr %t486, align 1
  %t487 = icmp eq i64 %p_5_2, 281474976710655
  br i1 %t487, label %edge_4, label %edge_5
b6:
  %p_6_0 = phi %hia.buffer [ %p_5_0, %edge_5 ]
  %p_6_1 = phi %hia.buffer [ %p_5_1, %edge_5 ]
  %p_6_2 = phi i64 [ %p_5_2, %edge_5 ]
  %p_6_3 = phi i64 [ %t404, %edge_5 ]
  %p_6_4 = phi i64 [ %p_5_4, %edge_5 ]
  %p_6_5 = phi i64 [ %p_5_5, %edge_5 ]
  %p_6_6 = phi i64 [ %p_5_6, %edge_5 ]
  %p_6_7 = phi i64 [ %p_5_7, %edge_5 ]
  %p_6_8 = phi i16 [ %p_5_8, %edge_5 ]
  %t488 = add i64 %p_6_2, 1
  %t489 = trunc i64 0 to i32
  %t490 = zext i32 %t489 to i64
  %t491 = icmp ult i64 56, 64
  br i1 %t491, label %ok_492, label %trap_492
trap_492:
  call void @abort()
  unreachable
ok_492:
  %t493 = lshr i64 %t488, 56
  %t494 = trunc i64 %t493 to i8
  %t495 = add i64 %t490, 7
  %t496 = extractvalue %hia.buffer %p_6_1, 0
  %t497 = extractvalue %hia.buffer %p_6_1, 1
  %t498 = icmp ult i64 %t495, %t497
  br i1 %t498, label %ok_499, label %trap_499
trap_499:
  call void @abort()
  unreachable
ok_499:
  %t500 = getelementptr i8, ptr %t496, i64 %t495
  store i8 %t494, ptr %t500, align 1
  %t501 = icmp ult i64 48, 64
  br i1 %t501, label %ok_502, label %trap_502
trap_502:
  call void @abort()
  unreachable
ok_502:
  %t503 = lshr i64 %t488, 48
  %t504 = trunc i64 %t503 to i8
  %t505 = add i64 %t490, 6
  %t506 = extractvalue %hia.buffer %p_6_1, 0
  %t507 = extractvalue %hia.buffer %p_6_1, 1
  %t508 = icmp ult i64 %t505, %t507
  br i1 %t508, label %ok_509, label %trap_509
trap_509:
  call void @abort()
  unreachable
ok_509:
  %t510 = getelementptr i8, ptr %t506, i64 %t505
  store i8 %t504, ptr %t510, align 1
  %t511 = icmp ult i64 40, 64
  br i1 %t511, label %ok_512, label %trap_512
trap_512:
  call void @abort()
  unreachable
ok_512:
  %t513 = lshr i64 %t488, 40
  %t514 = trunc i64 %t513 to i8
  %t515 = add i64 %t490, 5
  %t516 = extractvalue %hia.buffer %p_6_1, 0
  %t517 = extractvalue %hia.buffer %p_6_1, 1
  %t518 = icmp ult i64 %t515, %t517
  br i1 %t518, label %ok_519, label %trap_519
trap_519:
  call void @abort()
  unreachable
ok_519:
  %t520 = getelementptr i8, ptr %t516, i64 %t515
  store i8 %t514, ptr %t520, align 1
  %t521 = icmp ult i64 32, 64
  br i1 %t521, label %ok_522, label %trap_522
trap_522:
  call void @abort()
  unreachable
ok_522:
  %t523 = lshr i64 %t488, 32
  %t524 = trunc i64 %t523 to i8
  %t525 = add i64 %t490, 4
  %t526 = extractvalue %hia.buffer %p_6_1, 0
  %t527 = extractvalue %hia.buffer %p_6_1, 1
  %t528 = icmp ult i64 %t525, %t527
  br i1 %t528, label %ok_529, label %trap_529
trap_529:
  call void @abort()
  unreachable
ok_529:
  %t530 = getelementptr i8, ptr %t526, i64 %t525
  store i8 %t524, ptr %t530, align 1
  %t531 = icmp ult i64 24, 64
  br i1 %t531, label %ok_532, label %trap_532
trap_532:
  call void @abort()
  unreachable
ok_532:
  %t533 = lshr i64 %t488, 24
  %t534 = trunc i64 %t533 to i8
  %t535 = add i64 %t490, 3
  %t536 = extractvalue %hia.buffer %p_6_1, 0
  %t537 = extractvalue %hia.buffer %p_6_1, 1
  %t538 = icmp ult i64 %t535, %t537
  br i1 %t538, label %ok_539, label %trap_539
trap_539:
  call void @abort()
  unreachable
ok_539:
  %t540 = getelementptr i8, ptr %t536, i64 %t535
  store i8 %t534, ptr %t540, align 1
  %t541 = icmp ult i64 16, 64
  br i1 %t541, label %ok_542, label %trap_542
trap_542:
  call void @abort()
  unreachable
ok_542:
  %t543 = lshr i64 %t488, 16
  %t544 = trunc i64 %t543 to i8
  %t545 = add i64 %t490, 2
  %t546 = extractvalue %hia.buffer %p_6_1, 0
  %t547 = extractvalue %hia.buffer %p_6_1, 1
  %t548 = icmp ult i64 %t545, %t547
  br i1 %t548, label %ok_549, label %trap_549
trap_549:
  call void @abort()
  unreachable
ok_549:
  %t550 = getelementptr i8, ptr %t546, i64 %t545
  store i8 %t544, ptr %t550, align 1
  %t551 = icmp ult i64 8, 64
  br i1 %t551, label %ok_552, label %trap_552
trap_552:
  call void @abort()
  unreachable
ok_552:
  %t553 = lshr i64 %t488, 8
  %t554 = trunc i64 %t553 to i8
  %t555 = add i64 %t490, 1
  %t556 = extractvalue %hia.buffer %p_6_1, 0
  %t557 = extractvalue %hia.buffer %p_6_1, 1
  %t558 = icmp ult i64 %t555, %t557
  br i1 %t558, label %ok_559, label %trap_559
trap_559:
  call void @abort()
  unreachable
ok_559:
  %t560 = getelementptr i8, ptr %t556, i64 %t555
  store i8 %t554, ptr %t560, align 1
  %t561 = icmp ult i64 0, 64
  br i1 %t561, label %ok_562, label %trap_562
trap_562:
  call void @abort()
  unreachable
ok_562:
  %t563 = lshr i64 %t488, 0
  %t564 = trunc i64 %t563 to i8
  %t565 = add i64 %t490, 0
  %t566 = extractvalue %hia.buffer %p_6_1, 0
  %t567 = extractvalue %hia.buffer %p_6_1, 1
  %t568 = icmp ult i64 %t565, %t567
  br i1 %t568, label %ok_569, label %trap_569
trap_569:
  call void @abort()
  unreachable
ok_569:
  %t570 = getelementptr i8, ptr %t566, i64 %t565
  store i8 %t564, ptr %t570, align 1
  %t571 = trunc i64 8 to i32
  %t572 = zext i32 %t571 to i64
  %t573 = icmp ult i64 56, 64
  br i1 %t573, label %ok_574, label %trap_574
trap_574:
  call void @abort()
  unreachable
ok_574:
  %t575 = lshr i64 %p_6_3, 56
  %t576 = trunc i64 %t575 to i8
  %t577 = add i64 %t572, 7
  %t578 = extractvalue %hia.buffer %p_6_1, 0
  %t579 = extractvalue %hia.buffer %p_6_1, 1
  %t580 = icmp ult i64 %t577, %t579
  br i1 %t580, label %ok_581, label %trap_581
trap_581:
  call void @abort()
  unreachable
ok_581:
  %t582 = getelementptr i8, ptr %t578, i64 %t577
  store i8 %t576, ptr %t582, align 1
  %t583 = icmp ult i64 48, 64
  br i1 %t583, label %ok_584, label %trap_584
trap_584:
  call void @abort()
  unreachable
ok_584:
  %t585 = lshr i64 %p_6_3, 48
  %t586 = trunc i64 %t585 to i8
  %t587 = add i64 %t572, 6
  %t588 = extractvalue %hia.buffer %p_6_1, 0
  %t589 = extractvalue %hia.buffer %p_6_1, 1
  %t590 = icmp ult i64 %t587, %t589
  br i1 %t590, label %ok_591, label %trap_591
trap_591:
  call void @abort()
  unreachable
ok_591:
  %t592 = getelementptr i8, ptr %t588, i64 %t587
  store i8 %t586, ptr %t592, align 1
  %t593 = icmp ult i64 40, 64
  br i1 %t593, label %ok_594, label %trap_594
trap_594:
  call void @abort()
  unreachable
ok_594:
  %t595 = lshr i64 %p_6_3, 40
  %t596 = trunc i64 %t595 to i8
  %t597 = add i64 %t572, 5
  %t598 = extractvalue %hia.buffer %p_6_1, 0
  %t599 = extractvalue %hia.buffer %p_6_1, 1
  %t600 = icmp ult i64 %t597, %t599
  br i1 %t600, label %ok_601, label %trap_601
trap_601:
  call void @abort()
  unreachable
ok_601:
  %t602 = getelementptr i8, ptr %t598, i64 %t597
  store i8 %t596, ptr %t602, align 1
  %t603 = icmp ult i64 32, 64
  br i1 %t603, label %ok_604, label %trap_604
trap_604:
  call void @abort()
  unreachable
ok_604:
  %t605 = lshr i64 %p_6_3, 32
  %t606 = trunc i64 %t605 to i8
  %t607 = add i64 %t572, 4
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
  %t613 = icmp ult i64 24, 64
  br i1 %t613, label %ok_614, label %trap_614
trap_614:
  call void @abort()
  unreachable
ok_614:
  %t615 = lshr i64 %p_6_3, 24
  %t616 = trunc i64 %t615 to i8
  %t617 = add i64 %t572, 3
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
  %t625 = lshr i64 %p_6_3, 16
  %t626 = trunc i64 %t625 to i8
  %t627 = add i64 %t572, 2
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
  %t633 = icmp ult i64 8, 64
  br i1 %t633, label %ok_634, label %trap_634
trap_634:
  call void @abort()
  unreachable
ok_634:
  %t635 = lshr i64 %p_6_3, 8
  %t636 = trunc i64 %t635 to i8
  %t637 = add i64 %t572, 1
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
  %t643 = icmp ult i64 0, 64
  br i1 %t643, label %ok_644, label %trap_644
trap_644:
  call void @abort()
  unreachable
ok_644:
  %t645 = lshr i64 %p_6_3, 0
  %t646 = trunc i64 %t645 to i8
  %t647 = add i64 %t572, 0
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
  br label %edge_6
b7:
  %p_7_0 = phi %hia.buffer [ %p_6_0, %edge_6 ]
  %p_7_1 = phi %hia.buffer [ %p_6_1, %edge_6 ]
  %p_7_2 = phi i64 [ %t488, %edge_6 ]
  %p_7_3 = phi i64 [ %p_6_3, %edge_6 ]
  %p_7_4 = phi i64 [ %p_6_4, %edge_6 ]
  %p_7_5 = phi i64 [ %p_6_5, %edge_6 ]
  %p_7_6 = phi i64 [ %p_6_6, %edge_6 ]
  %p_7_7 = phi i64 [ %p_6_7, %edge_6 ]
  %p_7_8 = phi i16 [ %p_6_8, %edge_6 ]
  %t653 = add i64 %p_7_4, %p_7_5
  %t654 = sub i64 %p_7_6, %t653
  %t655 = icmp uge i64 %t654, 8
  br i1 %t655, label %edge_7, label %edge_8
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
  %t656 = add i64 %p_8_4, %p_8_5
  %t657 = zext i16 %p_8_8 to i64
  %t658 = icmp ult i64 48, 64
  br i1 %t658, label %ok_659, label %trap_659
trap_659:
  call void @abort()
  unreachable
ok_659:
  %t660 = shl i64 %t657, 48
  %t661 = or i64 %t660, %p_8_2
  %t662 = trunc i64 %t656 to i32
  %t663 = zext i32 %t662 to i64
  %t664 = icmp ult i64 0, 64
  br i1 %t664, label %ok_665, label %trap_665
trap_665:
  call void @abort()
  unreachable
ok_665:
  %t666 = lshr i64 %t661, 0
  %t667 = trunc i64 %t666 to i8
  %t668 = add i64 %t663, 7
  %t669 = extractvalue %hia.buffer %p_8_0, 0
  %t670 = extractvalue %hia.buffer %p_8_0, 1
  %t671 = icmp ult i64 %t668, %t670
  br i1 %t671, label %ok_672, label %trap_672
trap_672:
  call void @abort()
  unreachable
ok_672:
  %t673 = getelementptr i8, ptr %t669, i64 %t668
  store i8 %t667, ptr %t673, align 1
  %t674 = icmp ult i64 8, 64
  br i1 %t674, label %ok_675, label %trap_675
trap_675:
  call void @abort()
  unreachable
ok_675:
  %t676 = lshr i64 %t661, 8
  %t677 = trunc i64 %t676 to i8
  %t678 = add i64 %t663, 6
  %t679 = extractvalue %hia.buffer %p_8_0, 0
  %t680 = extractvalue %hia.buffer %p_8_0, 1
  %t681 = icmp ult i64 %t678, %t680
  br i1 %t681, label %ok_682, label %trap_682
trap_682:
  call void @abort()
  unreachable
ok_682:
  %t683 = getelementptr i8, ptr %t679, i64 %t678
  store i8 %t677, ptr %t683, align 1
  %t684 = icmp ult i64 16, 64
  br i1 %t684, label %ok_685, label %trap_685
trap_685:
  call void @abort()
  unreachable
ok_685:
  %t686 = lshr i64 %t661, 16
  %t687 = trunc i64 %t686 to i8
  %t688 = add i64 %t663, 5
  %t689 = extractvalue %hia.buffer %p_8_0, 0
  %t690 = extractvalue %hia.buffer %p_8_0, 1
  %t691 = icmp ult i64 %t688, %t690
  br i1 %t691, label %ok_692, label %trap_692
trap_692:
  call void @abort()
  unreachable
ok_692:
  %t693 = getelementptr i8, ptr %t689, i64 %t688
  store i8 %t687, ptr %t693, align 1
  %t694 = icmp ult i64 24, 64
  br i1 %t694, label %ok_695, label %trap_695
trap_695:
  call void @abort()
  unreachable
ok_695:
  %t696 = lshr i64 %t661, 24
  %t697 = trunc i64 %t696 to i8
  %t698 = add i64 %t663, 4
  %t699 = extractvalue %hia.buffer %p_8_0, 0
  %t700 = extractvalue %hia.buffer %p_8_0, 1
  %t701 = icmp ult i64 %t698, %t700
  br i1 %t701, label %ok_702, label %trap_702
trap_702:
  call void @abort()
  unreachable
ok_702:
  %t703 = getelementptr i8, ptr %t699, i64 %t698
  store i8 %t697, ptr %t703, align 1
  %t704 = icmp ult i64 32, 64
  br i1 %t704, label %ok_705, label %trap_705
trap_705:
  call void @abort()
  unreachable
ok_705:
  %t706 = lshr i64 %t661, 32
  %t707 = trunc i64 %t706 to i8
  %t708 = add i64 %t663, 3
  %t709 = extractvalue %hia.buffer %p_8_0, 0
  %t710 = extractvalue %hia.buffer %p_8_0, 1
  %t711 = icmp ult i64 %t708, %t710
  br i1 %t711, label %ok_712, label %trap_712
trap_712:
  call void @abort()
  unreachable
ok_712:
  %t713 = getelementptr i8, ptr %t709, i64 %t708
  store i8 %t707, ptr %t713, align 1
  %t714 = icmp ult i64 40, 64
  br i1 %t714, label %ok_715, label %trap_715
trap_715:
  call void @abort()
  unreachable
ok_715:
  %t716 = lshr i64 %t661, 40
  %t717 = trunc i64 %t716 to i8
  %t718 = add i64 %t663, 2
  %t719 = extractvalue %hia.buffer %p_8_0, 0
  %t720 = extractvalue %hia.buffer %p_8_0, 1
  %t721 = icmp ult i64 %t718, %t720
  br i1 %t721, label %ok_722, label %trap_722
trap_722:
  call void @abort()
  unreachable
ok_722:
  %t723 = getelementptr i8, ptr %t719, i64 %t718
  store i8 %t717, ptr %t723, align 1
  %t724 = icmp ult i64 48, 64
  br i1 %t724, label %ok_725, label %trap_725
trap_725:
  call void @abort()
  unreachable
ok_725:
  %t726 = lshr i64 %t661, 48
  %t727 = trunc i64 %t726 to i8
  %t728 = add i64 %t663, 1
  %t729 = extractvalue %hia.buffer %p_8_0, 0
  %t730 = extractvalue %hia.buffer %p_8_0, 1
  %t731 = icmp ult i64 %t728, %t730
  br i1 %t731, label %ok_732, label %trap_732
trap_732:
  call void @abort()
  unreachable
ok_732:
  %t733 = getelementptr i8, ptr %t729, i64 %t728
  store i8 %t727, ptr %t733, align 1
  %t734 = icmp ult i64 56, 64
  br i1 %t734, label %ok_735, label %trap_735
trap_735:
  call void @abort()
  unreachable
ok_735:
  %t736 = lshr i64 %t661, 56
  %t737 = trunc i64 %t736 to i8
  %t738 = add i64 %t663, 0
  %t739 = extractvalue %hia.buffer %p_8_0, 0
  %t740 = extractvalue %hia.buffer %p_8_0, 1
  %t741 = icmp ult i64 %t738, %t740
  br i1 %t741, label %ok_742, label %trap_742
trap_742:
  call void @abort()
  unreachable
ok_742:
  %t743 = getelementptr i8, ptr %t739, i64 %t738
  store i8 %t737, ptr %t743, align 1
  %t744 = add i64 %p_8_5, 8
  %t745 = trunc i64 24 to i32
  %t746 = zext i32 %t745 to i64
  %t747 = icmp ult i64 56, 64
  br i1 %t747, label %ok_748, label %trap_748
trap_748:
  call void @abort()
  unreachable
ok_748:
  %t749 = lshr i64 %t744, 56
  %t750 = trunc i64 %t749 to i8
  %t751 = add i64 %t746, 7
  %t752 = extractvalue %hia.buffer %p_8_1, 0
  %t753 = extractvalue %hia.buffer %p_8_1, 1
  %t754 = icmp ult i64 %t751, %t753
  br i1 %t754, label %ok_755, label %trap_755
trap_755:
  call void @abort()
  unreachable
ok_755:
  %t756 = getelementptr i8, ptr %t752, i64 %t751
  store i8 %t750, ptr %t756, align 1
  %t757 = icmp ult i64 48, 64
  br i1 %t757, label %ok_758, label %trap_758
trap_758:
  call void @abort()
  unreachable
ok_758:
  %t759 = lshr i64 %t744, 48
  %t760 = trunc i64 %t759 to i8
  %t761 = add i64 %t746, 6
  %t762 = extractvalue %hia.buffer %p_8_1, 0
  %t763 = extractvalue %hia.buffer %p_8_1, 1
  %t764 = icmp ult i64 %t761, %t763
  br i1 %t764, label %ok_765, label %trap_765
trap_765:
  call void @abort()
  unreachable
ok_765:
  %t766 = getelementptr i8, ptr %t762, i64 %t761
  store i8 %t760, ptr %t766, align 1
  %t767 = icmp ult i64 40, 64
  br i1 %t767, label %ok_768, label %trap_768
trap_768:
  call void @abort()
  unreachable
ok_768:
  %t769 = lshr i64 %t744, 40
  %t770 = trunc i64 %t769 to i8
  %t771 = add i64 %t746, 5
  %t772 = extractvalue %hia.buffer %p_8_1, 0
  %t773 = extractvalue %hia.buffer %p_8_1, 1
  %t774 = icmp ult i64 %t771, %t773
  br i1 %t774, label %ok_775, label %trap_775
trap_775:
  call void @abort()
  unreachable
ok_775:
  %t776 = getelementptr i8, ptr %t772, i64 %t771
  store i8 %t770, ptr %t776, align 1
  %t777 = icmp ult i64 32, 64
  br i1 %t777, label %ok_778, label %trap_778
trap_778:
  call void @abort()
  unreachable
ok_778:
  %t779 = lshr i64 %t744, 32
  %t780 = trunc i64 %t779 to i8
  %t781 = add i64 %t746, 4
  %t782 = extractvalue %hia.buffer %p_8_1, 0
  %t783 = extractvalue %hia.buffer %p_8_1, 1
  %t784 = icmp ult i64 %t781, %t783
  br i1 %t784, label %ok_785, label %trap_785
trap_785:
  call void @abort()
  unreachable
ok_785:
  %t786 = getelementptr i8, ptr %t782, i64 %t781
  store i8 %t780, ptr %t786, align 1
  %t787 = icmp ult i64 24, 64
  br i1 %t787, label %ok_788, label %trap_788
trap_788:
  call void @abort()
  unreachable
ok_788:
  %t789 = lshr i64 %t744, 24
  %t790 = trunc i64 %t789 to i8
  %t791 = add i64 %t746, 3
  %t792 = extractvalue %hia.buffer %p_8_1, 0
  %t793 = extractvalue %hia.buffer %p_8_1, 1
  %t794 = icmp ult i64 %t791, %t793
  br i1 %t794, label %ok_795, label %trap_795
trap_795:
  call void @abort()
  unreachable
ok_795:
  %t796 = getelementptr i8, ptr %t792, i64 %t791
  store i8 %t790, ptr %t796, align 1
  %t797 = icmp ult i64 16, 64
  br i1 %t797, label %ok_798, label %trap_798
trap_798:
  call void @abort()
  unreachable
ok_798:
  %t799 = lshr i64 %t744, 16
  %t800 = trunc i64 %t799 to i8
  %t801 = add i64 %t746, 2
  %t802 = extractvalue %hia.buffer %p_8_1, 0
  %t803 = extractvalue %hia.buffer %p_8_1, 1
  %t804 = icmp ult i64 %t801, %t803
  br i1 %t804, label %ok_805, label %trap_805
trap_805:
  call void @abort()
  unreachable
ok_805:
  %t806 = getelementptr i8, ptr %t802, i64 %t801
  store i8 %t800, ptr %t806, align 1
  %t807 = icmp ult i64 8, 64
  br i1 %t807, label %ok_808, label %trap_808
trap_808:
  call void @abort()
  unreachable
ok_808:
  %t809 = lshr i64 %t744, 8
  %t810 = trunc i64 %t809 to i8
  %t811 = add i64 %t746, 1
  %t812 = extractvalue %hia.buffer %p_8_1, 0
  %t813 = extractvalue %hia.buffer %p_8_1, 1
  %t814 = icmp ult i64 %t811, %t813
  br i1 %t814, label %ok_815, label %trap_815
trap_815:
  call void @abort()
  unreachable
ok_815:
  %t816 = getelementptr i8, ptr %t812, i64 %t811
  store i8 %t810, ptr %t816, align 1
  %t817 = icmp ult i64 0, 64
  br i1 %t817, label %ok_818, label %trap_818
trap_818:
  call void @abort()
  unreachable
ok_818:
  %t819 = lshr i64 %t744, 0
  %t820 = trunc i64 %t819 to i8
  %t821 = add i64 %t746, 0
  %t822 = extractvalue %hia.buffer %p_8_1, 0
  %t823 = extractvalue %hia.buffer %p_8_1, 1
  %t824 = icmp ult i64 %t821, %t823
  br i1 %t824, label %ok_825, label %trap_825
trap_825:
  call void @abort()
  unreachable
ok_825:
  %t826 = getelementptr i8, ptr %t822, i64 %t821
  store i8 %t820, ptr %t826, align 1
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
