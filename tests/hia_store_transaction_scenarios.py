"""Finite inputs fixed from the original Python transaction protocol only."""
from copy import deepcopy

ERRORS = ('ValueError', 'AttributeError', 'OSError', 'KeyboardInterrupt',
          'SystemExit', 'GeneratorExit', 'StopIteration', 'StopAsyncIteration')


def cases():
    result = []
    def add(name, actions=None, **options):
        result.append({'id': name, 'actions': deepcopy(actions if actions is not None else [{'op':'with'}]),
                       **deepcopy(options)})
    add('factory-is-lazy', [{'op':'inspect'}])
    add('close-unstarted', [{'op':'close'}, {'op':'close'}, {'op':'inspect'}])
    add('normal-with')
    add('normal-with-outer-active', outer_exception=True)
    add('manual-enter-exit', [{'op':'enter'}, {'op':'exit'}, {'op':'inspect'}])
    add('manual-enter-enter-exit', [{'op':'enter'}, {'op':'enter'}, {'op':'exit'}])
    add('manual-exit-before-enter', [{'op':'exit'}, {'op':'inspect'}])
    add('manual-error-exit-before-enter', [{'op':'exit','error':'body'}, {'op':'inspect'}])
    add('manual-exit-twice', [{'op':'enter'}, {'op':'exit'}, {'op':'exit'}])
    add('manual-error-exit-twice', [{'op':'enter'}, {'op':'exit','error':'body'}, {'op':'exit','error':'body'}])
    for value in [None, 0, False, 'sent-through-unused-yield']:
        add('raw-send-after-yield-'+repr(value), [{'op':'next'}, {'op':'send','value':value}, {'op':'inspect'}])
    add('raw-next-completes', [{'op':'next'}, {'op':'next'}, {'op':'next'}])
    add('raw-send-non-None-before-start', [{'op':'send','value':7}, {'op':'next'}, {'op':'close'}])
    add('raw-close-suspended', [{'op':'next'}, {'op':'close'}, {'op':'close'}])
    add('raw-send-closed', [{'op':'close'}, {'op':'send','value':None}, {'op':'send','value':7}])
    for lock in ['none', 'missing_enter', 'missing_exit']:
        add('lock-protocol-'+lock, lock_kind=lock)
    for special in ['enter','exit']:
        add('lock-noncallable-'+special, noncallable_special=special)
    add('db-noncallable-execute', noncallable_execute=True)
    add('db-none-before-BEGIN', [{'op':'mutate','action':'db_none'}, {'op':'with'}])
    # Separate provider call and after-effect failures. No SQL outcome is
    # inferred by this observer; both phases are actual declared fake effects.
    phases = [('store.lock.get',1,None), ('lock0.exit.lookup',1,None),
              ('lock0.enter.lookup',1,None), ('lock0.enter.call',1,None),
              ('store.db.get',1,None), ('db0.execute.lookup',1,None),
              ('db0.execute.call',1,None), ('db0.execute.after',1,None)]
    for body in [None, 'body']:
        phases.extend((name,2,body) for name in ['store.db.get','db0.execute.lookup','db0.execute.call','db0.execute.after'])
    phases.extend([('lock0.exit.call',1,None), ('lock0.exit.call',1,'body')])
    for event, occurrence, body in phases:
        for error in ERRORS:
            action = {'op':'with', **({'error':body} if body else {})}
            add(f'fault-{event}-{occurrence}-{body}-{error}', [action],
                faults=[{'event':event,'occurrence':occurrence,'error':error}])
    for event in ['store.db.get','db0.execute.call','db0.execute.after']:
        for error in ['ValueError','StopIteration','KeyboardInterrupt']:
            for exit_value in [True,'token_true']:
                add(f'suppressed-BEGIN-{event}-{error}-{exit_value}', exit=exit_value,
                    faults=[{'event':event,'error':error}])
    for body in [None,'ValueError','KeyboardInterrupt','StopIteration','GeneratorExit']:
        for exit_value in [False,True,'token_false','token_true','token_bad']:
            add(f'exit-policy-{body}-{exit_value}', [{'op':'with',**({'error':body} if body else {})}], exit=exit_value)
    for error in ERRORS:
        add('exit-bool-fault-'+error, [{'op':'with','error':'body'}], exit='token_true',
            faults=[{'event':'lock0.exit.result.bool','error':error}])
    for error in ERRORS:
        for style in ['instance','class','two','three']:
            for entered in [False,True]:
                add(f'raw-throw-{error}-{style}-started{entered}',
                    ([{'op':'next'}] if entered else []) + [{'op':'throw','error':error,'style':style},{'op':'inspect'}])
        add('CM-exit-none-instance-'+error, [{'op':'enter'},{'op':'exit_none_value','type':error}])
    for style in ['invalid','bad_traceback','bad_value']:
        for entered in [False,True]:
            add(f'raw-throw-invalid-{style}-started{entered}',
                ([{'op':'next'}] if entered else [])+[{'op':'throw','style':style},{'op':'inspect'}])
    for matcher in ['builtin','fallback','Exception','ValueError','KeyError','tuple','empty_tuple','invalid','mixed_tuple']:
        add('dynamic-matcher-not-read-on-commit-'+matcher,
            [{'op':'enter'},{'op':'mutate','action':'matcher:'+matcher},{'op':'exit'}])
        for error in ['ValueError','KeyError','KeyboardInterrupt','StopIteration','GeneratorExit']:
            for raw in [False,True]:
                add(f'dynamic-matcher-{matcher}-{error}-raw{raw}',
                    [{'op':'next' if raw else 'enter'}, {'op':'mutate','action':'matcher:'+matcher},
                     {'op':'throw' if raw else 'exit','error':error}])
    for mutation in ['db1','db_none','lock1']:
        for error in [None,'body']:
            add(f'body-mutation-{mutation}-{error}',
                [{'op':'with','mutations':[mutation],**({'error':error} if error else {})}])
    for event,mutation in [('store.lock.get','lock1'), ('lock0.exit.lookup','lock1'),
                           ('lock0.enter.lookup','lock1'), ('lock0.enter.call','db1'),
                           ('store.db.get','db1'), ('db0.execute.lookup','db1'),
                           ('db0.execute.call','db1'), ('db0.execute.after','db1')]:
        for error in [None,'body']:
            add(f'capture-{event}-{mutation}-{error}', [{'op':'with',**({'error':error} if error else {})}],
                callbacks=[{'event':event,'action':mutation}])
    for error in [None,'body','StopIteration']:
        add('all-temporary-release-'+str(error), [{'op':'with',**({'error':error} if error else {})}],
            enter_token=True, sql_return_token=True, exit='token_true' if error else 'token_bad',
            release_bindings=True, ephemeral_lock=True)
    add('enter-result-release-before-BEGIN', enter_token=True, enter_delete_action='db1')
    add('BEGIN-result-release-before-body', sql_return_token=True, sql_delete_actions={'BEGIN IMMEDIATE':'db1'})
    for sql,error in [('COMMIT',None),('ROLLBACK','body')]:
        add('terminal-SQL-result-release-'+sql,[{'op':'with',**({'error':error} if error else {})}],
            sql_return_token=True,sql_delete_actions={sql:'lock1'})
    for event in ['lock0.enter.result.delete','db0.BEGIN IMMEDIATE.result.delete',
                  'db0.COMMIT.result.delete','lock0.exit.result.delete']:
        add('unraisable-temporary-release-'+event, enter_token=True, sql_return_token=True, exit='token_bad',
            faults=[{'event':event,'error':'ValueError'}])
    for event in ['store.lock.get','lock0.enter.lookup','lock0.exit.lookup','lock0.enter.call',
                  'db0.execute.call','db0.execute.after','lock0.exit.call']:
        for operation in ['next','send','throw','close']:
            add(f'reenter-gi_running-{event}-{operation}', callbacks=[{'event':event,'action':'reenter:'+operation}])
    for outer in [False,True]:
        for error in [None,'body']:
            add(f'Context-switch-outer{outer}-{error}',
                [{'op':'enter','context':'entry-context'},
                 {'op':'exit','context':'exit-context',**({'error':error} if error else {})}], outer_exception=outer)
    for lock in ['fake','rlock']:
        add('thread-resume-enter-main-exit-worker-'+lock,
            [{'op':'enter'},{'op':'exit','thread':True},{'op':'inspect'}],lock_kind=lock)
        add('thread-resume-enter-worker-exit-main-'+lock,
            [{'op':'enter','thread':True},{'op':'exit'},{'op':'inspect'}],lock_kind=lock)
        add('thread-throw-enter-main-exit-worker-'+lock,
            [{'op':'enter'},{'op':'exit','error':'body','thread':True}],lock_kind=lock)
    add('concurrent-gi_running-before-first-yield', [{'op':'concurrent'},{'op':'exit'}],block_event='db0.execute.call')
    add('fork-unstarted-independent-both-sides',[{'op':'fork','action':{'op':'with'}},{'op':'with'}])
    for lock in ['fake','rlock']:
        add('fork-suspended-normal-both-sides-'+lock,
            [{'op':'enter'},{'op':'fork','action':{'op':'exit'}},{'op':'exit'}],lock_kind=lock)
        add('fork-suspended-throw-child-parent-normal-'+lock,
            [{'op':'enter'},{'op':'fork','action':{'op':'exit','error':'body'}},{'op':'exit'}],lock_kind=lock)
    # Bounded final additions: original language protocol, never candidate graph.
    # Same object re-raised by a cleanup provider must not become a replacement.
    for error in ['ValueError', 'StopIteration']:
        for raw in [False, True]:
            for event, occurrence in [('db0.execute.after', 2),
                                      ('lock0.exit.call', 1),
                                      ('lock0.exit.result.bool', 1)]:
                add(f'same-error-cleanup-{error}-raw{raw}-{event}',
                    [{'op':'next' if raw else 'enter'},
                     {'op':'throw' if raw else 'exit','error':error}],
                    exit='token_true', outer_exception=True,
                    faults=[{'event':event,'occurrence':occurrence,'error':error}])
    # This records temporary lifetimes during each distinct failure cleanup lane.
    lifetime_faults = [('enter-lookup','lock0.enter.lookup',1,None),
                       ('exit-lookup','lock0.exit.lookup',1,None),
                       ('enter-call','lock0.enter.call',1,None),
                       ('BEGIN','db0.execute.after',1,None),
                       ('COMMIT','db0.execute.after',2,None),
                       ('ROLLBACK','db0.execute.after',2,'body'),
                       ('exit-call','lock0.exit.call',1,'body'),
                       ('exit-truth','lock0.exit.result.bool',1,'body')]
    for name, event, occurrence, body in lifetime_faults:
        for outer in [False, True]:
            add(f'temporary-release-failure-{name}-outer{outer}',
                [{'op':'with',**({'error':body} if body else {})}],
                release_bindings=True,ephemeral_lock=True,enter_token=True,
                sql_return_token=True,exit='token_false',outer_exception=outer,
                faults=[{'event':event,'occurrence':occurrence,'error':'ValueError'}])
    # close() creates its own GeneratorExit; throw(instance) must preserve the
    # supplied object and differs when an inner lock suppresses termination.
    for exit_value in [False, True, 'token_false', 'token_true']:
        for outer in [False, True]:
            for operation in ['throw', 'close']:
                add(f'GeneratorExit-{operation}-{exit_value}-outer{outer}',
                    [{'op':'next'},
                     {'op':operation,**({'error':'GeneratorExit'} if operation=='throw' else {})},
                     {'op':'inspect'}], exit=exit_value,outer_exception=outer,
                    release_bindings=True,ephemeral_lock=True,enter_token=True,
                    sql_return_token=True)
    # These cases explicitly separate terminal observations from later
    # traceback-cycle finalization instead of erasing the distinction.
    for error in ['ValueError', 'StopAsyncIteration']:
        add('explicit-GC-exit-truth-'+error,
            [{'op':'with','error':'body'}],exit='token_true',explicit_gc=True,
            release_bindings=True,ephemeral_lock=True,enter_token=True,
            sql_return_token=True,
            faults=[{'event':'lock0.exit.result.bool','error':error}])
    add('explicit-GC-COMMIT-failure',explicit_gc=True,exit='token_false',
        release_bindings=True,ephemeral_lock=True,enter_token=True,
        sql_return_token=True,
        faults=[{'event':'db0.execute.after','occurrence':2,'error':'ValueError'}])
    assert len({item['id'] for item in result}) == len(result)
    return result
