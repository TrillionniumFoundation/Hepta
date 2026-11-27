(() => {
 const range=(a,b)=>Array.from({length:b-a},(_,i)=>i+a);
 const U64="18446744073709551615";
 const groups={};
 const put=(group,rows)=>{if(groups[group])throw Error("duplicate group");groups[group]=rows.map(x=>typeof x==="string"?{id:x,pairs:1}:x);};
 const rows=(names,pairs)=>names.map((id,i)=>({id,pairs:typeof pairs==="function"?pairs(i):pairs}));
 put("head-genesis-commit",rows([0,1,7].map(x=>"generation-"+x),25));
 put("head-partial-eintr",[{id:"all-positive-partials",pairs:41},...rows([1,2,4,5,6,8,9].map(x=>"eintr-retry-"+x),27)]);
 put("head-replay-conflict",[{id:"exact-entire-target-replay",pairs:13},{id:"other-writer-conflict",pairs:9},{id:"foreign-store-read",pairs:5}]);
 put("head-lost-ack",range(1,13).map(a=>({id:"lost-ack-"+a,pairs:2*a+3})));
 put("head-eintr-refusals",[3,7,10,11,12].map(a=>({id:"eintr-no-retry-"+a,pairs:2*a+2})));
 put("head-effect-errors",[
 ...[[1,1],[3,2147483648],[4,0],[4,257],[5,1],[7,1],[8,1],[10,1],[11,1],[12,1]].map(([a,v])=>({id:"effect-"+a+"-"+v,pairs:2*a+1})),
 ...[2,6,9].map(a=>({id:"read-zero-"+a,pairs:2*a+1})),
 {id:"actual-negative-errno",pairs:15},{id:"payload-on-nonread",pairs:7}]);
 put("head-protocol-errors",[
 ...rows(["wrong-nonce","wrong-serial","wrong-action","ack-without-claim"],2),
 {id:"duplicate-claim",pairs:3},
 ...rows(["unknown-event","malformed-lost-response","serial-exhaustion"],2)]);
 put("head-sha-format",[
 ...[0,7,8,16,32,40,80,112,128,160,168,223,224,255].map(a=>"corrupt-"+a),
 ...[8,16,40,160,168].map(a=>"well-hashed-invalid-"+a),
 ...[2,6,9].map(a=>({id:"bad-read-hash-"+a,pairs:2*a+1}))]);
 put("head-generation-boundaries",["generation-exhaustion",{id:"last-generation",pairs:25},"transaction-reuse","zero-transaction"]);
 put("head-abi-extents",[
 ...[0,127,128,463,465].map(x=>"source-"+x),...[0,1151].map(x=>"output-"+x),
 ...[0,2047,2049].map(x=>"workspace-"+x),...[0,40,95,112,127].map(x=>"header-"+x),
 ...[16,24,32].map(x=>"init-word-"+x),"zero-nonce"]);
 put("head-dirty-seal",[
 ...[0,247,248,1104,2047].map(x=>"dirty-init-"+x),
 ...rows([0,8,24,96,144,248,256,512,768,1104,2047].map(x=>"corrupt-private-state-"+x),2),
 {id:"well-sealed-invalid-reserved",pairs:2}]);
 put("head-terminal-observe",[{id:"confirmed-terminal-observe",pairs:31},{id:"conflict-terminal-observe",pairs:10}]);
 put("catalog-genesis-empty-pages",["genesis-ten-families",...range(1,11).map(x=>"empty-"+x)]);
 put("catalog-ten-single-transitions",range(1,11).map(x=>"table-"+x));
 put("catalog-joint-transaction",["request-slot-version-budget"]);
 put("catalog-all-table-transition",["one-generation-ten-updates","validate-complete-new-root"]);
 put("catalog-uuid-generation",["different-store","wrong-generation","max-generation-valid-read","max-generation-no-wrap","zero-uuid"]);
 put("catalog-header-selector",[
 ...[0,56,63,64,111,120,127].map(x=>"header-"+x),
 ...[[8,4],[8,U64],[16,1],[24,1],[48,1]].map(([a,v])=>"header-word-"+a+"-"+v),
 ...[0,11,U64].map(x=>"empty-selector-"+x)]);
 put("catalog-extents",[
 ...[[2,128],[0,704],[1,1104]].flatMap(([op,n])=>Array.from(new Set([0,127,n-1,n+1])).map(x=>"source-"+op+"-"+x)),
 ...[0,1151].map(x=>"output-"+x),...[0,2047,2049].map(x=>"workspace-"+x)]);
 put("catalog-table-order",[...range(1,11).map(x=>"missing-or-duplicate-"+x),"reordered-first-two","table-count-nine"]);
 put("catalog-root-bindings",[...range(1,11).flatMap(x=>["zero-root-"+x,"wrong-table-empty-root-"+x]),"wrong-store-empty-root"]);
 put("catalog-sha-corruption",[
 ...[0,7,8,16,32,40,48,63,64,79,80,543,544,575].map(x=>"corrupt-"+x),
 ...[0,8,48,63].map(x=>"well-hashed-malformed-"+x)]);
 put("catalog-change-mask",[...[0,1024,U64].map(x=>"bad-mask-"+x),"zero-selected-digest","selected-unchanged-pair","nonzero-unselected-update","wrong-empty-selected-pair"]);
 put("catalog-dirty-scratch",[90,165,255].flatMap(x=>["dirty-genesis-"+x,"dirty-validate-"+x,"dirty-error-"+x]));
 put("catalog-count-boundaries",["max-u64-count","nonempty-to-exact-empty","last-valid-generation"]);
 for(const [group,rs] of Object.entries(groups))if(new Set(rs.map(r=>r.id)).size!==rs.length)throw Error("duplicate ID "+group);
 return {basis:"Manual transcription of every reachable branch/loop literal in both fixed Python control texts, and independent arithmetic of call sites; no Python, HIA or native execution.",
 stages:["compile-head","compile-catalog",...Object.keys(groups)],
 groups,case_count:Object.values(groups).reduce((n,rs)=>n+rs.length,0),pairs:Object.values(groups).flat().reduce((n,r)=>n+r.pairs,0)};
})()
