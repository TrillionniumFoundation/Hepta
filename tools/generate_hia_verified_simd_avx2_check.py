"""Author an independent AVX2 machine decoder and closed control-flow grammar."""
from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_elf_linker import SOURCE as ELF
from tools.generate_hia_shared_linker import document
from tools.generate_hia_verified_simd_sse2_check import OPS as BASE_OPS, POLICY as BASE

MODULE = 'verified_simd_avx2_check'
OPS = BASE_OPS + ('vclear','vor','vsad','vadd','vorm','vsadm','vload','vstore','half','vout','vin','vshift',
                  'upper','wordread','wordwrite')
OP = {name:i + 1 for i,name in enumerate(OPS)}
LABELS = ('admitted','bulk','vector','merge','fold','short','narrow','horizontal','tail','word16',
          'word8','word4','word2','word1','cleanup','done','abort')


def schedule(shape):
    """Describe the legal induction and dataflow in decoded register/address operands."""
    rows = []
    def take(op, *args):
        assert len(args) <= 3
        rows.append((OP[op], *args, *([0] * (3 - len(args)))))
    def mark(label): take('mark',LABELS.index(label))
    def branch(condition,label): take('branch',condition,LABELS.index(label))
    def jump(label): take('jump',LABELS.index(label))
    def consume(count):
        take('addi',7,count)
        if shape == 3: take('addi',2,count)
        take('subi',10,count)
    def reg(op,width,dest,src,other):
        take(op,width,dest * 16 + src,other)
    def chunk(width,offset,acc):
        if shape == 1:
            take('vsadm',width,18,7 + 16*offset)
            reg('vadd',width,acc,acc,1)
        else:
            take('vorm',width,acc*17,7 + 16*offset)
    def combine(width,acc,other):
        reg('vadd' if shape == 1 else 'vor',width,acc,acc,other)
    def cleanup():
        mark('cleanup')
        take('upper')
    copy = shape == 3
    if copy:
        take('mov',0,8)
        for cap in (6,1):
            take('cmp',8,cap)
            branch(7,'abort')
        take('test',8,8)
        branch(4,'done')
        for ptr,end in [(7,9),(2,10)]:
            take('test',ptr,ptr)
            branch(4,'abort')
            take('mov',end,ptr)
            take('add',end,8)
            branch(2,'abort')
        take('cmp',9,2)
        branch(6,'admitted')
        take('cmp',10,7)
        branch(7,'abort')
        mark('admitted')
        take('mov',10,8)
    else:
        take('imm',0,0)
        take('cmp',2,6)
        branch(7,'abort')
        take('test',2,2)
        branch(4,'done')
        take('test',7,7)
        branch(4,'abort')
        take('mov',9,7)
        take('add',9,2)
        branch(2,'abort')
        take('mov',10,2)
        take('cmpi',10,32)
        branch(2,'short')
        for acc in (0,2,3,4,5):
            reg('vclear',32,acc,acc,acc)
    for loop,n,next_ in [('bulk',128,'vector' if copy else 'merge'),('vector',32,'tail' if copy else 'fold')]:
        mark(loop)
        take('cmpi',10,n)
        branch(2,next_)
        if copy:
            for op,base in [('vload',2),('vstore',7)]:
                for i in range(n//32):
                    take(op,32,(i+1)*16,base + 16*i)
        else:
            for i,acc in enumerate((0,3,4,5)[:n//32]):
                chunk(32,i,acc)
        consume(n)
        jump(loop)
        if loop == 'bulk' and not copy:
            mark('merge')
            for acc in (3,4,5):
                combine(32,0,acc)
    if copy:
        mark('tail')
        take('test',10,10)
        branch(4,'cleanup')
        take('cmpi',10,1)
        branch(4,'word1')
        for size in (16,8,4,2):
            mark('word'+str(size))
            take('cmpi',10,size)
            branch(2,'word'+str(size//2))
            def transfer(store,idx):
                if size == 16:
                    take('vstore' if store else 'vload',size,idx*16,7 if store else 2)
                else:
                    take('wordwrite' if store else 'wordread',size,9 if idx == 1 else 11,7 if store else 2)
            transfer(False,1)
            take('subi',10,size)
            take('add',2,10)
            transfer(False,2)
            transfer(True,1)
            take('add',7,10)
            transfer(True,2)
            jump('cleanup')
        mark('word1')
        take('wordread',1,9,2)
        take('wordwrite',1,9,7)
        cleanup()
    else:
        mark('fold')
        take('half',1,0,1)
        combine(16,0,1)
        jump('narrow')
        mark('short')
        for reg_ in (0,2): reg('vclear',16,reg_,reg_,reg_)
        mark('narrow')
        take('cmpi',10,16)
        branch(2,'horizontal')
        chunk(16,0,0)
        consume(16)
        jump('narrow')
        mark('horizontal')
        take('vout',0,0)
        take('vshift',0,0,8)
        take('vout',9,0)
        scalar = 'add' if shape == 1 else 'or'
        take(scalar,0,9)
        for size in (8,4,2):
            mark('word'+str(size))
            take('cmpi',10,size)
            branch(2,'word'+str(size//2))
            take('wordread',size,9,7)
            if shape == 1:
                take('vin',1,9)
                reg('vsad',16,1,2,1)
                take('vout',9,1)
            take(scalar,0,9)
            consume(size)
        mark('word1')
        take('test',10,10)
        branch(4,'cleanup')
        take('wordread',1,9,7)
        take(scalar,0,9)
        cleanup()
    mark('done')
    if shape == 2:
        take('test',0,0)
        take('imm',0,0)
        take('sete',0)
    take('ret')
    mark('abort')
    take('subi',4,8)
    take('call')
    take('ud2')
    return rows


EXTENSION = '''
def wide_decode(s:readbuf, w:mutbuf, p:u64, end:u64) -> u64:
    if end - p < 3:
        return 0
    first = byte(s, p)
    prefix = byte(s, p + 1)
    if first == 196:
        if end - p < 5:
            return 0
        sel = byte(s, p + 2)
        op = byte(s, p + 3)
        modrm = byte(s, p + 4)
        if modrm < 192:
            return 0
        dst = (modrm >> 3) & 7
        rm = modrm & 7
        if prefix == 227 and sel == 125 and op == 57 and end - p >= 6:
            put(w, 0, p + 6)
            return token(OP_HALF, rm, dst, byte(s, p + 5))
        if (prefix != 225 and prefix != 193) or sel != 249 or (op != 126 and op != 110):
            return 0
        gpr = rm + choose(prefix == 193, 8, 0)
        put(w, 0, p + 5)
        if op == 126:
            return token(OP_VOUT, gpr, dst, 0)
        return token(OP_VIN, dst, gpr, 0)
    opcode = byte(s, p + 2)
    if prefix == 248 and opcode == 119:
        put(w, 0, p + 3)
        return OP_UPPER
    if end - p < 4 or prefix < 128:
        return 0
    width = choose((prefix & 4) == 0, 16, 32)
    src = 15 - ((prefix >> 3) & 15)
    if src >= 8:
        return 0
    selector = prefix & 3
    addr = byte(s, p + 3)
    mode = addr >> 6
    reg = (addr >> 3) & 7
    base = addr & 7
    put(w, 0, p + 4)
    if mode == 3:
        if selector != 1:
            return 0
        if opcode == 115:
            if width != 16 or reg != 3 or end - p < 5:
                return 0
            put(w, 0, p + 5)
            return token(OP_VSHIFT, src, base, byte(s, p + 4))
        op = choose(opcode == 239, OP_VCLEAR, choose(opcode == 246, OP_VSAD, choose(opcode == 235, OP_VOR, choose(opcode == 212, OP_VADD, 0))))
        if op == 0:
            return 0
        return token(op, width, reg * 16 + src, base)
    if mode > 1 or (base != 2 and base != 7):
        return 0
    index = 0
    if mode == 1:
        if end - p < 5:
            return 0
        disp = byte(s, p + 4)
        if disp != width and disp != 2 * width and disp != 3 * width:
            return 0
        index = choose(disp == width, 1, choose(disp == 2 * width, 2, 3))
        put(w, 0, p + 5)
    if (opcode == 111 or opcode == 127) and selector == 2 and src == 0:
        return token(choose(opcode == 111, OP_VLOAD, OP_VSTORE), width, reg * 16, base + 16 * index)
    if selector != 1 or (opcode != 246 and opcode != 235):
        return 0
    return token(choose(opcode == 246, OP_VSADM, OP_VORM), width, reg * 16 + src, base + 16 * index)

def word_decode(s:readbuf, w:mutbuf, p:u64, end:u64) -> u64:
    at = p
    if byte(s, p) == 102:
        at = p + 1
    if end - at < 3:
        return 0
    rex = byte(s, at)
    op = byte(s, at + 1)
    if rex != 68 and rex != 76:
        return 0
    pos = at + 2
    n = choose(rex == 76, 8, 4)
    read = 0
    if op == 15:
        if at != p or rex != 76 or end - at < 4:
            return 0
        ext = byte(s, pos)
        if ext != 182 and ext != 183:
            return 0
        n = choose(ext == 182, 1, 2)
        pos = pos + 1
        read = 1
    elif op == 139:
        if at != p:
            return 0
        read = 1
    elif op == 136:
        if rex != 68 or at != p:
            return 0
        n = 1
    elif op == 137:
        if at != p:
            if rex != 68:
                return 0
            n = 2
    else:
        return 0
    rm = byte(s, pos)
    if rm >= 64:
        return 0
    base = rm & 7
    reg = 8 + ((rm >> 3) & 7)
    if (base != 2 and base != 7) or (reg != 9 and reg != 11):
        return 0
    put(w, 0, pos + 1)
    return token(choose(read == 1, OP_WORDREAD, OP_WORDWRITE), n, reg, base)
'''


def source_program():
    text = BASE.replace('192 +','320 +').replace('200 +','328 +')
    text = text.replace('    put(o, 16, 1)','    put(o, 16, 2)')
    start = text.index('    if first == 102 or first == 243:')
    end = text.index('    if first < 64',start)
    text = text[:start] + '''    if first == 196 or first == 197:
        return wide_decode(s, w, p, end)
    if first == 102 or first == 68 or first == 76:
        word = word_decode(s, w, p, end)
        if word != 0 or first == 102:
            return word
''' + text[end:]
    start = text.index('    if second == 131:')
    end = text.index('        op = choose(src',start)
    text = text[:start] + '''    if second == 131 or second == 129:
        if (first & 4) != 0 or end - p < choose(second == 131, 4, 7):
            return 0
        if second == 131:
            imm = byte(s, p + 3)
            if imm >= 128:
                return 0
            put(w, 0, p + 4)
        else:
            imm = uint(s, p + 3, 4)
            if imm < 128 or imm > 255:
                return 0
            put(w, 0, p + 7)
''' + text[end:]
    start = text.index('def packed_op(')
    end = text.index('def relative(',start)
    text = text[:start] + EXTENSION + '\n' + text[end:]
    enums = {'OP_'+key.upper():value for key,value in OP.items()}
    enums.update(BIND_REPLY=int.from_bytes(b'HIAEBNR1','little'),SUCCESS=int.from_bytes(b'HIASIMV1','little'))
    text = re.sub(r'\b[A-Z][A-Z0-9_]+\b',lambda m:str(enums[m[0]]),text)
    text += '\ndef specification(w:mutbuf, shape:u64) -> u64:\n'
    for shape in (1,2):
        text += f'    if shape == {shape}:\n        return grammar{shape}(w)\n'
    text += '    return grammar3(w)\n'
    for shape in (1,2,3):
        rows = schedule(shape)
        edge_count = sum(row[0] in (OP['jump'], OP['branch']) for row in rows)
        assert 320 + 16 * edge_count <= 1024 and 1024 + len(rows) * 4 + 8 <= 2048
        data = bytes(v for row in rows for v in row)
        text += f'\ndef grammar{shape}(w:mutbuf) -> u64:\n'
        for i in range(0,len(data),8):
            text += f'    put(w, {1024+i}, {int.from_bytes(data[i:i+8],"little")})\n'
        text += f'    return {len(rows)}\n'
    return text


if __name__ == '__main__':
    helpers = ELF[ELF.index('def uint('):ELF.index('def copy_bytes(')]
    target = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap' / (MODULE + '.hepta')
    target.write_text(render_assembly(document(source_program() + helpers,MODULE)))
