function inverseController(newText) {
function one(t,a,b){if(t.split(a).length!==2)throw Error('inverse cardinality');return t.replace(a,b);}
let s=newText;
s=one(s,'def copy_small_originals(root, public, custody, policy, *, failure):','def copy_small_originals(root, public, custody, policy):');
s=one(s,"    require(type(failure) is bool, 'exact source failure selection flag required')\n    if failure:\n        priority = ['actual/error.txt']\n        priority += ['actual/' + label + '.error.txt' for label, _ in policy['components']]\n        priority += ['guardian/child.stderr.log', 'guardian.stderr.log',\n                     'actual/REPORT.json', 'guardian/guardian.json']\n        order = priority + [name for name in order if name not in priority]\n","");
s=one(s,"            'failure_originals_prioritized': failure,\n","");
s=one(s,"selection = copy_small_originals(\n                root, public, custody, policy,\n                failure=bool(final['errors'] or custody['errors']\n                             or final['source_acceptance'] is None))","selection = copy_small_originals(root, public, custody, policy)");
return s;
}

function inversePolicy(newValue) {
 const p=JSON.parse(JSON.stringify(newValue));
 p.controls["controller.py"]={"bytes":56324,"sha256":"14951d857c6a6ed1a5e28f362b5e486af940bb597baa868e2f7848b9250db163","git_blob":"c2a08d0e23d061a428d45da456fed93b750a220b"};
 p.runtime.provider="actions/setup-python@v5";
 delete p.runtime.actions_commits;
 delete p.custody.failure_originals_priority;
 return JSON.stringify(p,null,2)+"\n";
}
function inverseWorkflowTemplate(newText) {
 function one(t,a,b){if(t.split(a).length!==2)throw Error("workflow inverse cardinality");return t.replace(a,b);}
 let t=newText;
 t=one(t,"b2a17727804f9ae80f5a8757363a11e33c485fa2a1fd32f48546ac01cc727241","14951d857c6a6ed1a5e28f362b5e486af940bb597baa868e2f7848b9250db163");
 t=one(t,"8e66871a71e0ecdb8cca704133d96ec604156aa17d94b5c81f204be3d06950a6","f2301664398b417ee8db99fb41cf094ffe99de06178cd034c708bb8dcf23f7a4");
 t=one(t,"uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262","uses: actions/checkout@v4");
 t=one(t,"uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1","uses: actions/setup-python@v5");
 t=one(t,"uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02","uses: actions/upload-artifact@v4");
 return t;
}
