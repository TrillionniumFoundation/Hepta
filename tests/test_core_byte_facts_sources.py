"""Source-only byte-fact adversaries; none invoke Lean or confer acceptance."""
from copy import deepcopy
from dataclasses import replace
import json
import re
import unittest
from unittest.mock import patch

from tools import core_byte_facts_sources as facts
from tools import core_syntax_partition_sources as original
from tools import check_core_syntax_staged as acceptance
from tools import core_syntax_partition_diagnostic_sources as previous_diagnostic


class ByteFactsSourcesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = original.build_inputs()
        cls.proposal = facts.build_sources(cls.prepared)

    def validate(self, proposal, real_original=False):
        if real_original:
            return facts.validate_sources(self.prepared,proposal)
        # The original fixture was fully validated at construction and is not
        # changed by these derivative tamper tests. The independent DAG and all
        # inverse/template checks still execute for every candidate.
        def authenticated(value):
            self.assertIs(value,self.prepared)
        with patch.object(facts,'_original',side_effect=authenticated):
            return facts.validate_sources(self.prepared,proposal)

    def changed(self,index=None,source=None,manifest=None,stages=None):
        ss = list(self.proposal.stages if stages is None else stages)
        if index is not None:
            ss[index] = replace(ss[index],source=source)
        return facts.ByteFactsSources(self.proposal.original_stages,tuple(ss),
            facts.encode(self.proposal.manifest if manifest is None else manifest))

    def reject(self,proposal):
        with self.assertRaises((ValueError,TypeError,KeyError)):
            self.validate(proposal)

    def test_complete_real_validation_and_budget_accounting(self):
        stats = self.validate(self.proposal,real_original=True)
        self.assertFalse(stats['acceptance_eligible'])
        self.assertEqual(stats['authority'],'DENY_ALL')
        self.assertEqual(stats['stage_counts'],(56,35,703,1298,1298,1297,1297,1297,70,5,1))
        self.assertLessEqual(stats['manifest_bytes'],32768)
        m=self.proposal.manifest
        self.assertEqual(len(m['obligations']),12)
        for key,value in facts.DENY.items(): self.assertEqual(m[key],value)
        self.assertEqual(m['original_source_bytes'],2400382)
        self.assertEqual(m['transformed_source_bytes'],3121095)
        self.assertEqual(m['retained_source_bytes'],sum(len(s.encode()) for s in self.proposal.retained_sources.values()))
        self.assertEqual(m['diagnostic_retained_source_upper_bound'],6056005)
        self.assertLess(m['diagnostic_retained_source_upper_bound'],8*1024*1024)
        self.assertLessEqual(max(s.source_bytes for s in self.proposal.stages),2*1024*1024)
        self.assertEqual(len(self.prepared['expected_theorems']),66)
        self.assertEqual(len(self.prepared['negatives']),10)

    def test_full_inverse_all_five_data_and_old_declarations(self):
        for old,new in zip(self.prepared['stages'],self.proposal.stages):
            self.assertEqual(facts.inverse_source(new.source,old.source,
                self.proposal.manifest['edits'][old.name]),old.source.encode())
            self.assertEqual(re.findall(r'^def .+$',new.source,re.M),
                re.findall(r'^def .+$',old.source,re.M) if old.name!='SyntaxData' else
                re.findall(r'^def .+$',old.source,re.M)+['def facts (xs : List Nat) (n : Nat) : Prop :='])
            old_statements = re.findall(r'^theorem (.+?) := ',old.source,re.M)
            new_statements = re.findall(r'^theorem (.+?) := ',new.source,re.M)
            for statement in old_statements:
                self.assertEqual(new_statements.count(statement),1)
            self.assertTrue(old.expected_theorems <= new.expected_theorems)
        self.assertEqual(self.proposal.stages[0],self.prepared['stages'][0])
        self.assertEqual(self.proposal.stages[2],self.prepared['stages'][2])
        self.assertEqual(self.proposal.stages[8:],self.prepared['stages'][8:])

    def test_exact_helper_contracts_and_inventory(self):
        helper=facts.helper_source()
        self.assertEqual(re.findall(r'^def (\w+)',helper,re.M),['facts'])
        self.assertEqual(re.findall(r'^theorem (\w+)',helper,re.M),['nil','cons','append'])
        self.assertIn('(byteBound : b ≤ 255) (child : facts xs n) : facts (b :: xs) (n + 1)',helper)
        self.assertIn('(left : facts xs n) (right : facts ys m) : facts (xs ++ ys) (n + m)',helper)
        self.assertNotRegex(helper,r'(?m)^\s*(import|axiom|unsafe|opaque|set_option)\b|\bsorry\b|\bnative_decide\b')

    def test_each_new_inventory_printed_once_in_exact_namespace(self):
        for old,new in zip(self.prepared['stages'],self.proposal.stages):
            for name in new.expected_theorems-old.expected_theorems:
                self.assertEqual(new.source.count('#print axioms '+name+'\n'),1)
        for key,item in self.proposal.manifest['inputs'].items():
            stage=next(s for s in self.proposal.stages if s.name==item['owner'])
            names={item['namespace']+'.'+item['stem']+'_bf%04d'%i for i in range(595)}
            self.assertTrue(names<=stage.expected_theorems)
            self.assertEqual(item['fact_count'],595)
            self.assertEqual(item['root'],item['stem']+'Bytes')

    def test_original_acceptance_and_marker_protocol_reject_derivative(self):
        changed=dict(self.prepared,stages=self.proposal.stages)
        with self.assertRaises(ValueError): acceptance.validate_plan(changed)
        with self.assertRaises(ValueError): previous_diagnostic.build_diagnostic_sources(changed)

    def test_root_propositions_and_small_final_numerical_proof(self):
        for key,item in self.proposal.manifest['inputs'].items():
            stage=next(s for s in self.proposal.stages if s.name==item['owner'])
            stem=item['stem'];cert=self.prepared['structured_certificates'][key]['manifest']['cert']
            self.assertIn('theorem '+cert+'_length : '+stem+'Bytes.length ≤ transportByteLimit := by\n  rw [('+stem+'_bf0594).1]\n  decide +kernel',stage.source)
            self.assertIn('theorem '+cert+'_byte_range : '+stem+'Bytes.all (fun byte => decide (byte ≤ 255)) = true := by exact ('+stem+'_bf0594).2',stage.source)
            self.assertIn('theorem '+stem+'_bf0594 : '+facts.HELPER+'facts '+stem+'Bytes '+str(item['bytes_length']),stage.source)

    def test_rehashed_changed_fact_length_proof_and_root_reference(self):
        for before,after in (('facts linear_g0 1','facts linear_g0 2'),
                             ('by decide +kernel','by sorry'),
                             ('rw [(linear_bf0594).1]','rw [(linear_bf0593).1]')):
            source=self.proposal.stages[3].source
            altered=source.replace(before,after,1)
            self.assertNotEqual(source,altered)
            m=self.proposal.manifest
            # Update every affected interval's hash and offset/size when equal
            # length; different-size candidates still must fail exact inversion.
            delta=len(altered.encode())-len(source.encode())
            m['stages'][3]['source_sha256']=facts.digest(altered.encode())
            m['stages'][3]['source_bytes']=len(altered.encode())
            if delta==0:
                for edit in m['edits']['CertPart02']:
                    a,b=edit['transformed_start'],edit['transformed_end']
                    edit['transformed_sha256']=facts.digest(altered.encode()[a:b])
            self.reject(self.changed(3,altered,m))

    def test_inverse_alone_does_not_validate_inserted_theorem(self):
        source=self.proposal.stages[3].source
        altered=source.replace('facts linear_g0 1','facts linear_g0 2',1)
        self.assertEqual(len(source),len(altered))
        m=self.proposal.manifest
        for edit in m['edits']['CertPart02']:
            a,b=edit['transformed_start'],edit['transformed_end']
            edit['transformed_sha256']=facts.digest(altered.encode()[a:b])
        self.assertEqual(facts.inverse_source(altered,self.prepared['stages'][3].source,
                         m['edits']['CertPart02']),self.prepared['stages'][3].source.encode())
        self.reject(self.changed(3,altered,m))

    def test_rehashed_added_print_missing_or_wrong(self):
        source=self.proposal.stages[3].source
        before='#print axioms HiaCoreSyntaxSlice.linear_bf0594\n'
        altered=source.replace(before,before.replace('0594','9999'))
        m=self.proposal.manifest
        edit=m['edits']['CertPart02'][-1]
        edit['transformed_sha256']=facts.digest(altered.encode()[edit['transformed_start']:edit['transformed_end']])
        self.assertEqual(facts.inverse_source(altered,self.prepared['stages'][3].source,m['edits']['CertPart02']),self.prepared['stages'][3].source.encode())
        self.reject(self.changed(3,altered,m))

    def test_edit_overlap_offsets_namespace_and_schema(self):
        for kind in ('overlap','offset','namespace','extra','boolean'):
            m=self.proposal.manifest; e=m['edits']['CertPart02'][0]
            if kind=='overlap': m['edits']['CertPart02'][1]=deepcopy(e)
            if kind=='offset': e['transformed_start']+=1
            if kind=='namespace': e['namespace']='HiaCoreSyntaxSlice.WrongPhi'
            if kind=='extra': e['extra']=True
            if kind=='boolean': e['original_start']=True
            self.reject(self.changed(manifest=m))

    def test_missing_extra_old_or_auxiliary_inventory(self):
        stages=list(self.proposal.stages)
        for names in (stages[3].expected_theorems-{'HiaCoreSyntaxSlice.linear_transport'},
                      stages[3].expected_theorems-{'HiaCoreSyntaxSlice.linear_bf0594'},
                      stages[3].expected_theorems|{'HiaCoreSyntaxSlice.extra'}):
            ss=list(stages);ss[3]=replace(ss[3],expected_theorems=frozenset(names))
            self.reject(self.changed(stages=ss))

    def test_changed_import_namespace_data_or_unrelated_old_proof(self):
        source=self.proposal.stages[3].source
        for altered in (source.replace('import HiaSyntaxResearch.CertPart01','import HiaSyntaxResearch.Baseline',1),
                        source.replace('namespace HiaCoreSyntaxSlice','namespace HiaCoreSyntaxSlice.WrongPhi',1),
                        source.replace('linear_r0','linear_r1',1),
                        source.replace('theorem linear_p146','theorem linear_p999',1)):
            self.assertNotEqual(source,altered)
            self.reject(self.changed(3,altered))

    def test_manifest_forgery_is_not_acceptance_or_byte_evidence(self):
        for key,value in (('source_only',False),('acceptance_eligible',True),
                          ('authority','ALLOW'),('retained_source_bytes',0),
                          ('auxiliary_theorem_count',2974)):
            m=self.proposal.manifest;m[key]=value
            self.reject(self.changed(manifest=m))
        m=self.proposal.manifest;m['inputs']['linear']['bytes_sha256']='0'*64
        self.reject(self.changed(manifest=m))

    def test_proposal_and_retained_sources_are_immutable(self):
        with self.assertRaises(TypeError):self.proposal.retained_sources['new']='bad'
        with self.assertRaises(TypeError):self.proposal.sources['new']='bad'
        with self.assertRaises(Exception):self.proposal.stages[3].source='bad'

    def test_original_byte_substitution_fails_before_source_generation(self):
        stages=list(self.prepared['stages'])
        stages[3]=replace(stages[3],source=stages[3].source.replace('def linearBytes : List Nat := linear_b0',
                                                                'def linearBytes : List Nat := linear_t0'))
        self.assertNotEqual(stages[3].source,self.prepared['stages'][3].source)
        with self.assertRaises(ValueError):facts.build_sources(dict(self.prepared,stages=tuple(stages)))

    def test_original_manifest_source_caps_and_helper_pin_fail_closed(self):
        with patch.object(facts,'MAX_MANIFEST',1),self.assertRaises(ValueError):facts._derive(self.prepared)
        with patch.object(facts,'MAX_TOTAL_SOURCE',1),self.assertRaises(ValueError):facts._derive(self.prepared)
        with patch.object(facts,'HELPER_SHA256','0'*64),self.assertRaises(ValueError):facts.helper_source()

    def test_independent_validator_rejects_fault_in_shared_emitter(self):
        real = facts._proof
        def faulty(ast, known):
            length, proof = real(ast,known)
            if ast[0] == 'ref' and proof.endswith('0001'):
                return length, proof[:-4]+'0000'
            return length, proof
        with patch.object(facts,'_proof',side_effect=faulty):
            bad = facts._derive(self.prepared)
            self.assertNotEqual(bad.stages,self.proposal.stages)
            # Re-deriving with the same faulty emitter produces the same bad
            # proposal. An independent inserted-source checker must reject it.
            self.reject(bad)

    def test_explicit_edit_byte_counts_are_not_boolean_or_forged(self):
        for key,value in (('original_bytes',True),('transformed_bytes',0)):
            m=self.proposal.manifest;m['edits']['CertPart02'][0][key]=value
            self.reject(self.changed(manifest=m))

    def test_independent_validator_rejects_faulty_helper_and_root_emitter(self):
        helper=facts.helper_source()
        altered=helper.replace('(byteBound : b ≤ 255)','(byteBound : b ≤ 256)',1)
        self.assertNotEqual(helper,altered)
        with patch.object(facts,'helper_source',return_value=altered):
            bad=facts._derive(self.prepared)
            self.reject(bad)
        real=facts._facts
        def wrong_root(plan,stem):
            block,names,(length,root)=real(plan,stem)
            return block,names,(length,stem+'_bf0593')
        with patch.object(facts,'_facts',side_effect=wrong_root):
            bad=facts._derive(self.prepared)
            self.reject(bad)
