"""Independent definition of the checked forward-byte Core recurrences.

The encoder walks this specification at authoring time. Identifiers beginning
with $ name SSA slots and @ names block slots. Each namespace is bijective.
"""

def value(name, typ):
    return {'name': '$' + name, 'type': typ}


def op(code, args, result=None, **attrs):
    return {'op': code, 'args': ['$' + x for x in args.split()], 'attrs': attrs,
            'out': [value(*result)] if result else []}


def edge(target, names):
    return {'target': '@' + target, 'args': ['$' + x for x in names]}


def recurrence(kind):
    copy = kind == 'copy_u8'
    signature = ([('dst', 'mutbuf')] if copy else []) + [('src', 'readbuf'), ('n', 'usize')]
    carried = signature + [('idx', 'usize')] + ([] if copy else [('acc', 'u64')])
    def params(prefix, spec):
        return [value(prefix + name, typ) for name, typ in spec]
    def names(prefix, spec):
        return [prefix + name for name, _ in spec]
    def block(role, parameters, ops, term):
        return {'id':'@' + role, 'params':parameters, 'ops':ops, 'term':term}
    def branch(condition, yes, no):
        return {'op':'branch','cond':'$' + condition,'then':yes,'else':no}
    initial = [op('buffer.len', 'src', ('extent','usize')),
               op('compare.le', 'n extent', ('read_ok','bool'))]
    if copy:
        initial += [op('buffer.len', 'dst', ('dst_extent','usize')),
                    op('compare.le', 'n dst_extent', ('write_ok','bool')),
                    op('bool.and', 'read_ok write_ok', ('ok','bool'))]
    initial += [op('const','', ('origin','usize'), value=0)]
    if not copy:
        initial += [op('const','', ('init','u64'), value=0)]
    body = [op('buffer.load', 'b_src b_idx', ('byte','u8'))]
    if copy:
        body += [op('buffer.store','b_dst b_idx byte')]
    else:
        body += [op('int.cast','byte',('wide','u64'),mode='wrap'),
                 op('int.add.wrap' if kind == 'sum_u8' else 'bit.or','b_acc wide',('next_acc','u64'))]
    body += [op('const','',('one','usize'),value=1),
             op('int.add.wrap','b_idx one',('next_idx','usize'))]
    result = []
    answer = 'd_acc'
    if copy:
        result = [op('int.cast','d_n',('answer','u64'),mode='wrap')]
        answer = 'answer'
    if kind == 'all_zero_u8':
        result = [op('const','',('no','u64'),value=0), op('const','',('yes','u64'),value=1),
                  op('compare.eq','d_acc no',('clear','bool')),
                  op('select','clear yes no',('answer','u64'))]
        answer = 'answer'
    blocks = [block('entry', params('',signature), initial,
                    branch('ok' if copy else 'read_ok',
                           edge('loop', names('',signature) + ['origin'] + ([] if copy else ['init'])),
                           edge('bad', []))),
              block('loop', params('l_',carried),
                    [op('compare.lt','l_idx l_n',('more','bool'))],
                    branch('more',edge('body',names('l_',carried)),edge('done',names('l_',carried)))),
              block('body', params('b_',carried), body,
                    {'op':'jump', **edge('loop', names('b_',signature) + ['next_idx'] + ([] if copy else ['next_acc']))}),
              block('done', params('d_',carried), result, {'op':'ret','values':['$' + answer]}),
              block('bad', [], [], {'op':'trap','code':'bounds'})]
    return {'schema':'hepta.hia.program.v8','module':'%module','functions':[
        {'name':'%export','params':params('', signature), 'returns':['u64'],
         'effects':['read','trap'] + (['write'] if copy else []),
         'entry':'@entry', 'blocks':blocks}]}
