"""HIA source shared by consumers of nominal public JSON artifact and Context references.

The bounded JSON decoder already owns duplicate-key and UTF-8 admission.
Members may appear in any order and escaped spellings decode to the same text.
"""
import ast

BODY = '''
def nominal(o:mutbuf,w:mutbuf,row:u64,dst:u64,artifact:bool) -> bool:
    if row == 18446744073709551615 or get(o,row)!=6 or get(o,row+32) != choose(artifact,3,2):
        return False
    id = 18446744073709551615
    sha = id
    uri = id
    i = get(o,row+24)
    while i != 18446744073709551615:
        k = 64+72*i
        if get(o,k) != 4:
            return False
        p = get(o,k+40)
        n = get(o,k+48)
        if n == 2 and match_word(o,p,n) == ID_KEY:
            id = k
        elif n == 6 and match_word(o,p,n) == SHA_KEY:
            sha = k
        elif n == 3 and match_word(o,p,n) == URI_KEY:
            uri = k
        else:
            return False
        i = get(o,k+16)
    if id == 18446744073709551615 or sha == 18446744073709551615 or (artifact and uri == 18446744073709551615):
        return False
    n = choose(artifact,34,36)
    if get(o,id+32) != n or get(o,sha+32) != 64:
        return False
    if artifact:
        if get(o,uri+32)!=48:
            return False
    a = get(o,id+24)
    b = get(o,sha+24)
    if artifact:
        if match_word(o,a,2) != ART_ID or nominal_hex(o,a+2,32) == False:
            return False
    elif match_word(o,a,4) != CTX_ID or nominal_hex(o,a+4,32) == False:
        return False
    if nominal_hex(o,b,64) == False:
        return False
    p = ref_id_prefix(w,dst)
    p = arena_copy(o,w,a,p,n)
    p = ref_sha_separator(w,p)
    p = arena_copy(o,w,b,p,64)
    if artifact:
        a = get(o,uri+24)
        if match_word(o,a,8)!=ART_URI_LEFT or match_word(o,a+8,8)!=ART_URI_RIGHT or nominal_hex(o,a+16,32)==False:
            return False
        p = ref_uri_separator(w,p)
        p = arena_copy(o,w,a,p,48)
    store(w,p,34)
    store(w,p+1,125)
    return True

def nominal_hex(o:mutbuf,a:u64,n:u64) -> bool:
    i = 0
    while i < n:
        ch = widen(byte(o,a+i))
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return False
        i = i+1
    return True

def arena_copy(o:mutbuf,w:mutbuf,a:u64,p:u64,n:u64) -> u64:
    i = 0
    while i < n:
        store(w,p+i,byte(o,a+i))
        i = i+1
    return p+n

def nominal_matches(s:readbuf,w:mutbuf,a:u64,p:u64,n:u64) -> bool:
    i = 0
    while i < n:
        if byte(s,a+i) != byte(w,p+i):
            return False
        i = i+1
    return True
'''

def source(*, context_only=False):
    def literal(name,payload):
        lines=[f'def {name}(w:mutbuf,p:u64) -> u64:']
        for i in range(0,len(payload),8):
            b=payload[i:i+8]
            if len(b)==8:
                lines.append(f'    put(w,p+{i},{int.from_bytes(b,"little")})')
            else:
                lines.extend(f'    store(w,p+{i+j},{v})' for j,v in enumerate(b))
        return '\n'.join((*lines,f'    return p+{len(payload)}'))
    tokens = {'ID_KEY': b'id', 'SHA_KEY': b'sha256', 'URI_KEY': b'uri', 'ART_ID': b'a-', 'CTX_ID': b'ctx-', 'ART_URI_LEFT': b'hia://ar', 'ART_URI_RIGHT': b'tifacts/'}
    text = BODY
    for name, payload in tokens.items():
        text = text.replace(name, str(int.from_bytes(payload, 'little')))
    if context_only:
        class Context(ast.NodeTransformer):
            def visit_Name(self, node):
                return ast.Constant(False) if node.id == 'artifact' else node
            def visit_Call(self, node):
                self.generic_visit(node)
                if isinstance(node.func, ast.Name) and node.func.id == 'choose' and isinstance(node.args[0],ast.Constant):
                    return node.args[1] if node.args[0].value else node.args[2]
                return node
            def visit_If(self,node):
                self.generic_visit(node)
                if isinstance(node.test, ast.Constant):
                    return node.body if node.test.value else node.orelse
                return node
        text=ast.unparse(ast.fix_missing_locations(Context().visit(ast.parse(text))))
    return '\n'.join((text,literal('ref_id_prefix',b'{"id":"'),
                      literal('ref_sha_separator',b'","sha256":"'),literal('ref_uri_separator',b'","uri":"')))
