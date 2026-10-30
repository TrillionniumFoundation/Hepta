"""Development-only persistent transport controls; no model endpoint invoked."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

from tools.hia_agent_v8b_transport import (AppServerDialogue, DialogueRejected,
    usage_delta, usage_record)

FAKE = r'''
import json,sys,time
mode=sys.argv[1];count=0
def emit(x):print(json.dumps(x),flush=True)
for line in sys.stdin:
 r=json.loads(line);m=r["method"]
 if m=="initialize":emit({"id":r["id"],"result":{"userAgent":"fixture-no-model"}})
 elif m=="initialized":pass
 elif m=="thread/start":emit({"id":r["id"],"result":{"thread":{"id":"fixture-thread","turns":[]},"model":"fixture-only","sandbox":{"type":"readOnly"}}})
 elif m=="turn/start":
  count+=1;tid="turn-"+str(count)
  emit({"id":r["id"],"result":{"turn":{"id":tid,"status":"inProgress","items":[]}}})
  if mode=="timeout":time.sleep(5);continue
  if mode=="overflow":print("x"*131072,flush=True);continue
  if mode=="server-request":
   emit({"id":"request-1","method":"item/commandExecution/requestApproval","params":{"threadId":"fixture-thread","turnId":tid}});continue
  if mode=="tool":
   emit({"method":"item/started","params":{"threadId":"fixture-thread","turnId":tid,"item":{"id":"bad","type":"commandExecution"}}});continue
  emit({"method":"hook/started","params":{"threadId":"fixture-thread","turnId":tid}})
  usage={"inputTokens":10,"cachedInputTokens":3,"cacheWriteInputTokens":0,"outputTokens":2,"reasoningOutputTokens":1,"totalTokens":12}
  if mode=="missing-optional":usage.pop("cacheWriteInputTokens")
  total={k:v*count for k,v in usage.items()}
  if mode=="usage-mismatch":usage["inputTokens"]=9
  if mode=="decrease" and count==2:total["inputTokens"]=0
  emit({"method":"item/completed","params":{"threadId":"fixture-thread","turnId":tid,"item":{"id":"answer-"+str(count),"type":"agentMessage","text":json.dumps({"action":"catalog"})}}})
  if mode in ("metadata","metadata-thread","metadata-turn","metadata-id","metadata-missing"):
   params={"threadId":"wrong-thread" if mode=="metadata-thread" else "fixture-thread","turnId":"wrong-turn" if mode=="metadata-turn" else tid,"metadata":{"approval":"opaque data, not authority","fixture":True}}
   if mode=="metadata-missing":params.pop("metadata")
   notice={"method":"turn/moderationMetadata","params":params}
   if mode=="metadata-id":notice["id"]="server-request-cannot-be-metadata"
   emit(notice)
  if mode!="missing-usage":
   emit({"method":"thread/tokenUsage/updated","params":{"threadId":"wrong-thread" if mode=="cross-thread" else "fixture-thread","turnId":tid,"tokenUsage":{"last":usage,"total":total,"modelContextWindow":100000}}})
  finished={"method":"turn/completed","params":{"threadId":"fixture-thread","turn":{"id":tid,"status":"completed","items":[],"error":None}}}
  if mode in ("late-tool","late-usage"):
   late={"method":"item/started","params":{"threadId":"fixture-thread","turnId":tid,"item":{"id":"late","type":"commandExecution"}}}
   if mode=="late-usage":late={"method":"thread/tokenUsage/updated","params":{"threadId":"fixture-thread","turnId":tid,"tokenUsage":{"last":usage,"total":{k:v*2 for k,v in total.items()}}}}
   sys.stdout.write(json.dumps(finished)+"\n"+json.dumps(late)+"\n");sys.stdout.flush()
  else:emit(finished)
'''
CFG={"max_turns_per_cell":6,"max_turn_wall_seconds":2,
     "max_provider_total_tokens_per_cell":1000,"max_provider_input_tokens_per_turn":1000,
     "max_provider_output_tokens_per_turn":1000,
     "stream_limits":{"stdout_bytes_per_cell":262144,"stderr_bytes_per_cell":65536,"line_bytes":262144}}


class PersistentTransportTests(unittest.TestCase):
    def dialogue(self, root, mode="good", cfg=None):
        return AppServerDialogue(executable="unused",cwd=root,output=Path(root)/"transport",
            cfg=deepcopy(CFG if cfg is None else cfg),deadline=time.monotonic()+10,
            argv=[sys.executable,"-u","-c",FAKE,mode])

    def test_registered_metadata_is_passive_and_bound_without_reply(self):
        with tempfile.TemporaryDirectory() as td:
            d=self.dialogue(td,"metadata")
            try:
                d.start_thread("fixture-only")
                record=d.turn("new-cohort public fixture")
                self.assertTrue(record["usage_complete"])
                self.assertEqual(len(record["passive_moderation_notifications"]),1)
                note=record["passive_moderation_notifications"][0]
                self.assertFalse(note["authority_granted"])
                self.assertFalse(note["response_sent"])
                self.assertFalse(note["moderation_or_hooks_disabled"])
            finally:d.close()
            self.assertEqual(d.record["status"],"closed")
            self.assertEqual(len(d.record["final_stream_audit"]["passive_moderation_notifications"]),1)
            sent=[json.loads(line) for line in (Path(td)/"transport/stdin.raw").read_text().splitlines()]
            self.assertEqual([row["method"] for row in sent],["initialize","initialized","thread/start","turn/start"])
            self.assertNotIn("opaque data",(Path(td)/"transport/stdin.raw").read_text())

    def test_metadata_wrong_thread_turn_id_or_missing_field_still_refused(self):
        for mode in ("metadata-thread","metadata-turn","metadata-id","metadata-missing"):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as td:
                d=self.dialogue(td,mode)
                try:
                    d.start_thread("fixture-only")
                    with self.assertRaises(DialogueRejected):d.turn("public fixture")
                    with self.assertRaises(DialogueRejected):d.turn("retry forbidden")
                finally:d.close()
                self.assertEqual(d.record["status"],"failed_closed")
                self.assertTrue(d.record["cleanup_confirmed"])

    def test_cumulative_usage_is_not_sum_of_cumulative_events(self):
        with tempfile.TemporaryDirectory() as td:
            d=self.dialogue(td)
            try:
                d.start_thread("fixture-only")
                first=d.turn("public development prompt")
                second=d.turn("public development feedback")
                self.assertEqual(first["usage_delta"]["totalTokens"],12)
                self.assertEqual(second["usage_delta"]["totalTokens"],12)
                self.assertEqual(second["cumulative_usage"]["totalTokens"],24)
                self.assertTrue(second["last_equals_cumulative_delta"])
                self.assertEqual(d.record["generation_turns_started"],2)
            finally:d.close()
            self.assertTrue(d.record["cleanup_confirmed"])
            self.assertTrue(d.record["streams_drained"])
            raw=(Path(td)/"transport/stdin.raw").read_text()
            self.assertEqual(raw.count("public development prompt"),1)
            self.assertEqual(raw.count("public development feedback"),1)

    def test_invalid_coverage_usage_tools_and_thread_are_terminal(self):
        for mode in ("tool","server-request","usage-mismatch","missing-usage","cross-thread","decrease"):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as td:
                d=self.dialogue(td,mode)
                try:
                    d.start_thread("fixture-only")
                    if mode=="decrease":d.turn("first public prompt")
                    with self.assertRaises(DialogueRejected):d.turn("public input")
                    self.assertTrue(d.failed)
                    with self.assertRaises(DialogueRejected):d.turn("retry prohibited")
                finally:d.close()
                self.assertTrue(d.record["cleanup_confirmed"])
                self.assertEqual(d.record["status"],"failed_closed")

    def test_timeout_cleans_owned_group_without_retry(self):
        with tempfile.TemporaryDirectory() as td:
            cfg=deepcopy(CFG);cfg["max_turn_wall_seconds"]=0.1
            d=self.dialogue(td,"timeout",cfg)
            try:
                d.start_thread("fixture-only")
                with self.assertRaises(TimeoutError):d.turn("public input")
            finally:d.close()
            self.assertTrue(d.record["cleanup_confirmed"])
            self.assertTrue(d.record["signal_delivered_before_reap"])
            self.assertFalse(d.record["replay_permitted"])

    def test_retained_raw_bytes_never_exceed_registered_cap(self):
        with tempfile.TemporaryDirectory() as td:
            cfg=deepcopy(CFG);cfg["stream_limits"]["stdout_bytes_per_cell"]=2048
            d=self.dialogue(td,"overflow",cfg)
            try:
                d.start_thread("fixture-only")
                with self.assertRaises(DialogueRejected):d.turn("public input")
            finally:d.close()
            self.assertLessEqual((Path(td)/"transport/stdout.raw").stat().st_size,2048)
            self.assertTrue(d.record["raw_stream_truncated_at_registered_cap"])
            self.assertTrue(d.record["cleanup_confirmed"])

    def test_tail_tool_after_completed_contaminates_entire_cell(self):
        with tempfile.TemporaryDirectory() as td:
            d=self.dialogue(td,"late-tool")
            try:
                d.start_thread("fixture-only")
                self.assertEqual(d.turn("public input")["status"],"completed")
            finally:d.close()
            self.assertTrue(d.record["cleanup_confirmed"])
            self.assertFalse(d.record["final_stream_audit"]["eligible"])
            self.assertEqual(d.record["status"],"failed_closed")
            self.assertEqual(d.record["final_stream_audit"]["forbidden_activity"][0]["item_type"],"commandExecution")

    def test_queued_tail_usage_cannot_escape_completed_turn_accounting(self):
        from tools.qualify_hia_agent_v8b_continuation import terminal_usage_admission
        with tempfile.TemporaryDirectory() as td:
            d=self.dialogue(td,"late-usage")
            try:
                d.start_thread("fixture-only")
                record=d.turn("public input")
            finally:d.close()
            result=terminal_usage_admission([record],d.record,d.usage_total,CFG)
            self.assertTrue(d.record["final_stream_audit"]["eligible"])
            self.assertEqual(result["provider_observed_cumulative_usage"]["totalTokens"],24)
            self.assertFalse(result["terminal_raw_usage_matches_completed_turns"])
            self.assertFalse(result["provider_usage_complete"])
            self.assertIsNone(result["provider_cumulative_usage"]["totalTokens"])

    def test_optional_cache_write_unknown_keeps_provider_total_comparable(self):
        with tempfile.TemporaryDirectory() as td:
            d=self.dialogue(td,"missing-optional")
            try:
                d.start_thread("fixture-only")
                record=d.turn("public input")
                self.assertTrue(record["usage_complete"])
                self.assertFalse(record["all_raw_usage_categories_known"])
                self.assertIsNone(record["cumulative_usage"]["cacheWriteInputTokens"])
                self.assertEqual(record["cumulative_usage"]["totalTokens"],12)
            finally:d.close()

    def test_usage_does_not_invent_cache_write_or_reasoning_overlap(self):
        data={"inputTokens":10,"cachedInputTokens":4,"outputTokens":8,
              "reasoningOutputTokens":9,"totalTokens":18}
        actual=usage_record(data)
        self.assertIsNone(actual["cacheWriteInputTokens"])
        self.assertEqual(actual["reasoningOutputTokens"],9)
        self.assertEqual(actual["totalTokens"],18)
        with self.assertRaises(DialogueRejected):usage_record({**data,"inputTokens":None})
        with self.assertRaises(DialogueRejected):
            usage_delta({"inputTokens":10},{"inputTokens":9})


if __name__=="__main__":
    unittest.main()
