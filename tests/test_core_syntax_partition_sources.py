"""Exact source partition controls. These tests never invoke Lean."""
from copy import deepcopy
from dataclasses import replace, FrozenInstanceError
import re
from types import MappingProxyType
from unittest import TestCase, mock

from tools import core_syntax_partition_sources as part
from tools import core_syntax_structured_stages as original


class PartitionSourceTests(TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = original.build_inputs()
        cls.value = part.build_partition_sources(cls.base)

    def changed(self, index=None, source=None, stages=None, manifest=None, **fields):
        value = dict(self.value)
        ss = list(value['stages'] if stages is None else stages)
        if index is not None:
            ss[index] = replace(ss[index], **({'source':source} if source is not None else fields))
        value['stages'] = tuple(ss)
        value['sources'] = MappingProxyType({s.module_name:s.source for s in ss})
        m = deepcopy(value['manifest'] if manifest is None else manifest)
        m['stages'] = [s.manifest() for s in ss]
        m['proof_input_bytes'] = sum(s.source_bytes for s in ss)
        value['manifest'] = m
        value['manifest_json'] = part.encode(m)
        value['manifest_sha256'] = part.digest(value['manifest_json'].encode())
        return value

    def reject(self, value):
        with self.assertRaises((ValueError, TypeError, KeyError)):
            part.validate_bindings(value)

    def test_all_complete_inputs_exact_inverse_and_counts(self):
        stats = part.validate_bindings(self.value)
        self.assertEqual(stats['stage_count'],11)
        self.assertEqual(stats['source_bytes'],2400382)
        restored=[]
        for i,s in enumerate(self.value['stages'][2:8]):
            imports,rows,prints=part._parse(s.source)
            restored.extend(rows)
            self.assertEqual(len(prints),part.PART_COUNTS[i])
            self.assertEqual(sum(r[1]=='def' for r in rows),part.DEF_COUNTS[i])
        expected,inputs=part._stream(self.base)
        self.assertEqual(tuple(restored),expected)
        self.assertEqual(sum(r[1]=='theorem' for r in restored),4215)
        self.assertEqual(sum(r[1]=='def' for r in restored),7685)
        self.assertEqual(len(self.value['expected_theorems']),66)
        self.assertEqual(len(self.value['negatives']),10)
        for name,location in self.value['manifest']['negative_declaration_locations'].items():
            source=self.value['sources'][location['module']]
            local=self.value['negatives'][name]['certificate'].rsplit('.',1)[1]
            self.assertTrue(source.splitlines()[location['line']-1].startswith('theorem '+local+' :'))
        self.assertEqual(self.value['manifest']['preserved_negative_coordinates'],'original-O')
        for key,m in self.value['manifest']['inputs'].items():
            self.assertEqual(sum(m['theorem_counts'].values()),843)
            self.assertEqual(m['root_owner'],part.PREFIX+'.'+part.ROOT_OWNERS[key])
            self.assertEqual(m['original_input_binding'],self.base['manifest']['inputs'][key])

    def test_exact_dag_and_immutable_stages(self):
        self.assertEqual(tuple(s.name for s in self.value['stages']),part.NAMES)
        self.assertEqual(self.value['stages'][:2],self.base['stages'][:2])
        for index,owner in ((8,'CertPart06'),(9,'CertPart02'),(10,'CertPart03')):
            s=self.value['stages'][index]
            self.assertEqual(s.parents,(part.PREFIX+'.'+owner,))
            self.assertNotIn('Connections',s.source.splitlines()[0])
        with self.assertRaises(TypeError):self.value['sources']['extra']='bad'
        with self.assertRaises(FrozenInstanceError):self.value['stages'][2].source='bad'

    def test_full_old_validator_called_on_original_only(self):
        from tools import check_core_syntax_staged as runner
        with mock.patch.object(runner,'validate_plan',wraps=runner.validate_plan) as checked:
            part.validate_bindings(self.value)
            self.assertEqual(checked.call_count,1)
            self.assertIs(checked.call_args.args[0],self.base)

    def test_rehashed_declaration_omission_duplication_swap(self):
        source=self.value['stages'][2].source
        lines=source.splitlines(keepends=True)
        at=next(i for i,l in enumerate(lines) if l.startswith('def '))
        for changed in (lines[:at]+lines[at+1:],lines[:at]+[lines[at]]+lines[at:],
                        lines[:at]+[lines[at+1],lines[at]]+lines[at+2:]):
            with self.subTest(change=len(changed)):
                self.reject(self.changed(2,''.join(changed)))

    def test_rehashed_definition_bytes_root_alias_and_proof(self):
        source=self.value['stages'][2].source
        changed=source.replace(':= [123]',':= [124]',1)
        self.assertNotEqual(changed,source)
        self.reject(self.changed(2,changed))
        source=self.value['stages'][3].source
        self.reject(self.changed(3,source.replace('def linearRaw : Raw := linear_r0','def linearRaw : Raw := linear_r1',1)))
        source=self.value['stages'][2].source
        self.reject(self.changed(2,source.replace(':= by decide +kernel',':= by rfl',1)))

    def test_same_count_cross_cut_move_and_namespaces(self):
        ss=list(self.value['stages'])
        a,b=ss[2].source,ss[3].source
        # Swap two complete one-line facts across a fixed cut, preserving counts.
        x=re.search(r'^theorem linear_s1 .*\n',a,re.M).group()
        y=re.search(r'^theorem linear_p146 .*\n',b,re.M).group()
        ss[2]=replace(ss[2],source=a.replace(x,y))
        ss[3]=replace(ss[3],source=b.replace(y,x))
        self.reject(self.changed(stages=ss))
        self.reject(self.changed(2,a.replace('namespace HiaCoreSyntaxSlice\n','namespace HiaCoreSyntaxSlice.WrongPhi\n',1)))

    def test_multiline_split_and_unknown_commands(self):
        source=self.value['stages'][2].source
        self.assertIn('  simpa only [',source)
        self.reject(self.changed(2,source.replace('  simpa only [','simpa only [',1)))
        for command in ('noncomputable section\n','set_option maxHeartbeats 0\n','axiom evil : True\n'):
            self.reject(self.changed(2,command+source))

    def test_wrong_import_self_forward_and_extractor_shortcut(self):
        for index,parent in ((2,'CertPart01'),(2,'CertPart06'),(10,'Connections')):
            s=self.value['stages'][index]
            parent=part.PREFIX+'.'+parent
            source=re.sub(r'^import [^\n]+','import '+parent,s.source,count=1)
            ss=list(self.value['stages'])
            ss[index]=replace(s,source=source,parents=(parent,),explicit_imports=(parent,),direct_imports=('Init',parent))
            self.reject(self.changed(stages=ss))

    def test_inventory_print_omission_duplication_and_foreign_target(self):
        source=self.value['stages'][2].source
        line=re.search(r'^#print axioms .+\n',source,re.M).group()
        for changed in (source.replace(line,'',1),source+line,source.replace(line,'#print axioms HiaCoreSyntaxSlice.linear_transport\n',1)):
            self.reject(self.changed(2,changed))
        s=self.value['stages'][2]
        self.reject(self.changed(2,expected_theorems=frozenset(list(s.expected_theorems)[1:])))

    def test_counts_float_aliases_root_owner_and_input_binding(self):
        for key,value in (('transport_theorem_count',4215.0),('transport_definition_count',7685.0),('cuts',[703.0,*part.CUTS[1:]])):
            m=deepcopy(self.value['manifest']);m[key]=value
            self.reject(self.changed(manifest=m))
        for line in (1, 1.0):
            m=deepcopy(self.value['manifest'])
            m['negative_declaration_locations']['wrong_phi']['line']=line
            self.reject(self.changed(manifest=m))
        m=deepcopy(self.value['manifest'])
        location=m['negative_declaration_locations']['wrong_phi']
        location['line']=float(location['line'])
        self.reject(self.changed(manifest=m))
        m=deepcopy(self.value['manifest']);m['inputs']['linear']['root_owner']=part.PREFIX+'.CertPart01'
        self.reject(self.changed(manifest=m))
        m=deepcopy(self.value['manifest']);m['inputs']['wrong_phi']['original_input_binding']=m['inputs']['linear']['original_input_binding']
        self.reject(self.changed(manifest=m))
        v=self.changed();v['manifest']['stages'][2]['source_bytes']=float(v['manifest']['stages'][2]['source_bytes'])
        v['manifest_json']=part.encode(v['manifest']);v['manifest_sha256']=part.digest(v['manifest_json'].encode())
        self.reject(v)

    def test_old_protocol_no_recursion_and_no_fallback(self):
        for mutation in ('protocol','nested','self','stages'):
            v=dict(self.value);base=dict(self.base);v['original_prepared']=base
            if mutation=='protocol':base['manifest']={**base['manifest'],'protocol':part.PROTOCOL}
            elif mutation=='nested':base['original_prepared']=self.base
            elif mutation=='self':base['original_prepared']=base
            else:base['stages']=v['stages']
            self.reject(v)
        self.reject(self.changed(stages=self.value['stages'][:-1]))
        self.reject(self.changed(stages=self.value['stages']+(self.value['stages'][-1],)))

    def test_unchanged_consumers_baseline_and_full_negative(self):
        for index in (0,1,8,9,10):
            source=self.value['stages'][index].source
            self.reject(self.changed(index,source+'\n'))
        v=dict(self.value);v['negatives']=dict(v['negatives']);v['negatives'].pop('wrong_arm_implementation')
        self.reject(v)

    def test_manifest_hashes_source_map_and_budget_boundaries(self):
        v=dict(self.value);v['manifest_sha256']='0'*64;self.reject(v)
        v=dict(self.value);v['sources']={};self.reject(v)
        self.reject(self.changed(2,self.value['stages'][2].source+' '*(part.MAX_SOURCE+1)))
        with mock.patch.object(part,'MAX_SOURCE',max(part.SOURCE_SIZES)),mock.patch.object(part,'MAX_TOTAL_SOURCE',2400382):
            part.validate_bindings(self.value)
        with mock.patch.object(part,'MAX_TOTAL_SOURCE',2400381):self.reject(self.value)
        with mock.patch.object(part,'MAX_SOURCE',max(part.SOURCE_SIZES)-1):self.reject(self.value)

    def test_canonical_metadata_extra_keys_and_stale_identity(self):
        m=deepcopy(self.value['manifest']);m['unexpected']=True;self.reject(self.changed(manifest=m))
        m=deepcopy(self.value['manifest']);m['original_manifest_sha256']='0'*64;self.reject(self.changed(manifest=m))
        v=dict(self.value);v['manifest_json']+=' ';self.reject(v)

    def test_recomputed_manifest_cannot_weaken_root_or_rewrite_proof(self):
        source=self.value['stages'][3].source
        old=re.search(r'^theorem linear_bounds .*$',source,re.M).group()
        changed=source.replace(old,'theorem linear_bounds : True := by trivial')
        value=self.changed(3,changed)
        _,inputs=part._stream(self.base)
        # Recompute all proposal metadata, not merely its outer SHA.
        value['manifest']=part._manifest(value['stages'],self.base,inputs)
        value['manifest_json']=part.encode(value['manifest'])
        value['manifest_sha256']=part.digest(value['manifest_json'].encode())
        self.reject(value)

    def test_original_float_metadata_and_changed_canonical_input(self):
        value=dict(self.value);base=dict(self.base)
        m=deepcopy(base['manifest'])
        m['stages'][2]['source_bytes']=float(m['stages'][2]['source_bytes'])
        base['manifest']=m;base['manifest_json']=part.encode(m)
        base['manifest_sha256']=part.digest(base['manifest_json'].encode())
        value['original_prepared']=base
        self.reject(value)
        value=dict(self.value);value['canonical_bytes']=value['canonical_bytes'][:-1]+b']'
        self.reject(value)
