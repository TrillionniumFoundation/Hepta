"""Finite original-only supplemental inputs. This module runs no original code."""
def inputs():
    bodies = []
    def add(name, **changes):
        row = {'id': name, 'cursor': True, 'limit': 2, 'store_lifetime': 'temporary',
               'persistent_db': False, 'execute_callable': 'method',
               'fetchone_callable': 'method', 'cursor_retains_db': True, 'store_cycle': False}
        row.update(changes)
        bodies.append(row)
    add('sql.select-and-insert')
    add('sql.insert-only', cursor=False)
    add('sql.select-only', limit=6)
    add('sql.no-cursor-no-insert', cursor=False, limit=6)
    add('lifetime.persistent-store', store_lifetime='persistent')
    add('lifetime.temporary-store-persistent-db', persistent_db=True)
    add('lifetime.temporary-db-no-cursor-retention', cursor_retains_db=False)
    for mode in ('bound', 'detached'):
        add('lifetime.execute-' + mode, execute_callable=mode)
        add('lifetime.fetchone-' + mode, fetchone_callable=mode)
    for stage, point, occurrence in [('select','args.get.cursor',1), ('insert','ref.get.id',2)]:
        add('cycle.gc-in-' + stage + '-tuple', store_cycle=True,
            action={'point':point,'occurrence':occurrence,'kind':'gc'})
        for kind in ('rebind-service', 'rebind-db'):
            add('tuple.' + stage + '.' + kind, store_lifetime='persistent',
                action={'point':point,'occurrence':occurrence,'kind':kind})
    for point in ('sql.select.store.lookup','store.select.db.lookup','db.select.execute.lookup',
                  'cursor.select.fetchone.lookup','sql.insert.store.lookup',
                  'store.insert.db.lookup','db.insert.execute.lookup','args.get.cursor'):
        add('lookup-AttributeError.' + point, fault={'point':point,'type':'AttributeError'})
    for point in ('db.select.execute.before','db.select.execute.after',
                  'cursor.select.fetchone.before','db.insert.execute.before','db.insert.execute.after'):
        for kind in ('ValueError','StopIteration','KeyboardInterrupt'):
            add('provider.' + point + '.' + kind, fault={'point':point,'type':kind})
    for point, occurrence in [('ref.get.id',2),('ref.get.sha256',2),('offset.add',4)]:
        add('insert-tuple.' + point, fault={'point':point,'occurrence':occurrence,'type':'ValueError'})
    cases = [{**row, 'id':row['id'] + '.outer' + str(int(outer)), 'outer':outer}
             for row in bodies for outer in (False, True)]
    assert len({c['id'] for c in cases}) == len(cases)
    return {'schema':'hia.service-read-sql-original-inputs.v1', 'cases':cases,
            'scope':'FINITE_FAKE_SQL_EXPRESSION_ORIGINAL_ONLY',
            'execution_history':'one complete case in each fresh process; no hidden warmup',
            'existing_86_and_6286_inputs_modified':False,
            'candidate_graph_consulted_to_generate_expectations':False,
            'native_vm_real_sql_or_resource_ack_controls_included':False}
