//! Test-only observer: all policy calls resolve to the original production module.
use super::*;
use std::io::BufWriter;
use std::os::unix::fs::OpenOptionsExt;

fn packed(entry: &Entry) -> Vec<u8> {
    let record = &entry.record;
    let mut raw = vec![0u8; 384];
    raw[..64].copy_from_slice(record.request_id.as_bytes());
    raw[64..128].copy_from_slice(record.owner.as_bytes());
    raw[128..128 + record.tool_name.len()].copy_from_slice(record.tool_name.as_bytes());
    let state = match record.state { DurableState::Unknown => 0u64, DurableState::Completed => 1, DurableState::Failed => 2 };
    let words = [(192, record.tool_name.len() as u64), (200, state),
        (208, record.accepted_unix_ms as u64), (216, (record.accepted_unix_ms >> 64) as u64),
        (224, record.elapsed_ms.is_some() as u64), (232, record.elapsed_ms.unwrap_or(0)),
        (240, entry.stamp.device), (248, entry.stamp.inode), (256, entry.stamp.links),
        (288, entry.stamp.length), (328, entry.stamp.modified.0 as u64),
        (336, entry.stamp.modified.1 as u64), (344, entry.stamp.changed.0 as u64),
        (352, entry.stamp.changed.1 as u64)];
    for (at, value) in words { raw[at..at+8].copy_from_slice(&value.to_le_bytes()); }
    raw[264..268].copy_from_slice(&entry.stamp.mode.to_le_bytes());
    raw[268..272].copy_from_slice(&entry.stamp.uid.to_le_bytes());
    raw
}
fn hex(raw: &[u8]) -> String { raw.iter().map(|v| format!("{v:02x}")).collect() }
fn version(v: Option<super::super::super::namespace_version::Version>) -> [u64; 3] {
    match v {
        Some(super::super::super::namespace_version::Version::Watch(a,b)) => [1,a,b],
        None => [0,0,0],
        _ => panic!("this actual Linux observer requires its original content watch"),
    }
}
fn state_words(state: &State) -> Vec<u64> {
    let mut words = vec![state.pending.len() as u64, state.generation, state.applied,
        state.database.is_some() as u64, state.failed as u64, state.retired as u64,
        state.busy as u64, state.large_archive as u64, state.requested as u64];
    words.extend(version(state.version)); words
}
struct Observer { out: BufWriter<File>, count: u64 }
impl Observer {
    fn emit(&mut self, label: &str, actions: Value, slot: &Slot, status: Option<u64>, extra: Value) {
        let state = slot.state.lock().unwrap();
        let row = json!({"case":label,"actions":actions,"state_words":state_words(&state),"status":status,"extra":extra});
        serde_json::to_writer(&mut self.out,&row).unwrap();self.out.write_all(b"\n").unwrap();self.count+=1;
    }
    fn raw(&mut self, row: Value) { serde_json::to_writer(&mut self.out,&row).unwrap();self.out.write_all(b"\n").unwrap();self.count+=1; }
}
fn record(n: u64) -> Record {
    Record { request_id:format!("{n:064x}"), owner:"a".repeat(64), tool_name:"file_info".into(),
        accepted_unix_ms:(1u128<<100)+u128::from(n), state:DurableState::Unknown, elapsed_ms:None }
}
fn fixture_state(slot: &Slot, database: &Arc<Database>, large: bool, observer: &mut Observer, label: &str) {
    let mut state=slot.state.lock().unwrap();
    state.database=Some(database.clone());state.worker=false;state.busy=false;state.failed=false;
    state.retired=false;state.pending.clear();state.requested=false;state.query_flushed=false;
    state.large_archive=large;state.version=content_version(&slot.archive).unwrap();
    state.generation=0;state.applied=0;state.last_publication=Instant::now();
    let words=state_words(&state);drop(state);
    observer.emit(label,json!([{"fixture":words}]),slot,None,Value::Null);
}
fn publish(slot: &Slot, original: &Path, observer: &mut Observer, label: &str, record: &Record) -> Entry {
    let guard=store_lock().unwrap();
    let before=version(content_version(&slot.archive).unwrap());
    publication_before(slot,&slot.archive);
    let path=original.join(format!("{}.json",record.request_id));
    let mut file=std::fs::OpenOptions::new().create(true).truncate(true).write(true).mode(0o600).open(path).unwrap();
    file.write_all(&serde_json::to_vec(record).unwrap()).unwrap();drop(file);
    let entry=Entry { record:record.clone(), stamp:stamp(&slot.archive,&format!("{}.json",record.request_id)).unwrap() };
    publication_after(slot,&slot.archive,&[record],true);
    let after=version(content_version(&slot.archive).unwrap());drop(guard);
    observer.emit(label,json!([
        {"op":1,"args":before}, {"op":2,"args":[],"data_hex":hex(&packed(&entry))},
        {"op":3,"args":[1,after[0],after[1],after[2],0,0,1]}
    ]),slot,None,Value::Null);entry
}
fn query(slot: &Slot, observer: &mut Observer, label: &str, allow_pending: bool) {
    let current=version(content_version(&slot.archive).unwrap());
    let state=slot.state.lock().unwrap();
    let result=query_database_for_read(&state,&slot.archive,allow_pending);
    let status=result.is_ok() as u64;let error=result.err().map(|e|e.to_string());drop(state);
    observer.emit(label,json!([{"op":6,"args":[allow_pending as u64,current[0],current[1],current[2]]}]),slot,Some(status),json!({"error":error}));
}
fn claimed(slot: &Slot, observer: &mut Observer, label: &str) -> (BTreeMap<Id,Entry>,u64) {
    let current=version(content_version(&slot.archive).unwrap());
    let (pending,generation)=claim_pending(slot).unwrap();
    observer.emit(label,json!([{"op":4,"args":[1,current[0],current[1],current[2]]}]),slot,Some(1),json!({"claimed":pending.len(),"generation":generation}));
    (pending,generation)
}
fn entries(slot: &Slot, observer: &mut Observer, label: &str, pending: &BTreeMap<Id,Entry>, claimed: bool) {
    for (position,entry) in pending.values().enumerate() {
        observer.emit(&format!("{label}-{position}"),json!([{"op":9,"args":[claimed as u64,position]}]),slot,None,json!({"entry_hex":hex(&packed(entry))}));
    }
}
fn drain(slot: &Slot, observer: &mut Observer, label: &str) {
    let guard=store_lock().unwrap();let current=version(content_version(&slot.archive).unwrap());
    let result=drain_for_query(slot,Instant::now()+QUERY_BUDGET,&mut SteadyTrace::new("observer",Some(false)));
    let status=match &result {Ok(false)=>1,Ok(true)=>2,Err(_)=>0};drop(guard);
    observer.emit(label,json!([{"op":7,"args":current}]),slot,Some(status),json!({"error":result.err().map(|e|e.to_string())}));
}

#[test]
fn hia_index_policy_observation() {
    let output=std::env::var_os("HIA_INDEX_ORACLE_OUTPUT").unwrap();
    let mut observer=Observer {out:BufWriter::new(File::create(output).unwrap()),count:0};
    let (root,_owner)=tests::fixture();let archive=open_archive(root.path()).unwrap();
    let slot={let _guard=store_lock().unwrap();try_slot_at(root.path(),&archive).unwrap()};
    let original=root.path().join(ARCHIVE_NAME);
    let cache=std::fs::OpenOptions::new().read(true).write(true).create_new(true).mode(0o600).open(root.path().join("policy-observer.redb")).unwrap();
    let database=Arc::new(open_database(cache,Instant::now()+Duration::from_secs(30)).unwrap().0);
    fixture_state(&slot,&database,false,&mut observer,"small-fixture");
    let mut all=BTreeMap::new();
    for n in 0..8192 {let r=record(n);let e=publish(&slot,&original,&mut observer,&format!("fill-{n}"),&r);all.insert(id(&r.request_id).unwrap(),e);}
    let mut replacement=record(4096);replacement.state=DurableState::Completed;replacement.elapsed_ms=Some(7);
    let e=publish(&slot,&original,&mut observer,"replace-at-capacity",&replacement);all.insert(id(&replacement.request_id).unwrap(),e);
    let (first,_generation)=claimed(&slot,&mut observer,"claim-8192");
    entries(&slot,&mut observer,"claimed-before-new-writes",&first,true);
    query(&slot,&mut observer,"claimed-empty-cannot-be-read",true);
    for n in 100000..108192 {let r=record(n);let e=publish(&slot,&original,&mut observer,&format!("during-claim-{n}"),&r);all.insert(id(&r.request_id).unwrap(),e);}
    {let pending=slot.state.lock().unwrap().pending.clone();entries(&slot,&mut observer,"second-complete-cohort",&pending,false);}
    entries(&slot,&mut observer,"claimed-after-new-writes",&first,true);
    let overflow=record(999999);let e=publish(&slot,&original,&mut observer,"overflow-invalidates-unclaimed",&overflow);all.insert(id(&overflow.request_id).unwrap(),e);
    entries(&slot,&mut observer,"claimed-after-invalidation",&first,true);
    query(&slot,&mut observer,"invalidated-query-refusal",true);
    drop(first);
    // The fixture creates the real original redb image with the original apply;
    // this observes state policy, not the original cold-loader qualification.
    for chunk in all.values().cloned().collect::<Vec<_>>().chunks(BUILD_CHUNK) {apply(&database,chunk.iter().cloned(),None,false).unwrap();}
    assert!(large_archive(&database).unwrap());assert_eq!(all.len(),16385);
    fixture_state(&slot,&database,true,&mut observer,"actual-16385-row-large-fixture");
    for n in (0..384).rev() {let r=record(n);publish(&slot,&original,&mut observer,&format!("large-{n}"),&r);}
    let (pending,generation)=claimed(&slot,&mut observer,"claim-256-leave-128");
    entries(&slot,&mut observer,"large-claimed-prefix",&pending,true);
    {let tail=slot.state.lock().unwrap().pending.clone();entries(&slot,&mut observer,"large-pending-tail",&tail,false);}
    apply(&database,pending.into_values(),None,false).unwrap();
    let large=large_archive(&database).unwrap();
    {let mut state=slot.state.lock().unwrap();original_completion(&mut state,generation,large).unwrap();}
    observer.emit("complete-256",json!([{"op":5,"args":[1,16385]}]),&slot,Some(1),Value::Null);
    query(&slot,&mut observer,"watched-128-tail",true);query(&slot,&mut observer,"complete-read-refuses-tail",false);
    drain(&slot,&mut observer,"readonly-tail-requests-maintenance");
    let next=record(1001);publish(&slot,&original,&mut observer,"129th-pending",&next);
    query(&slot,&mut observer,"129-tail-refused",true);drain(&slot,&mut observer,"129-yields-for-worker");
    let (pending,generation)=claimed(&slot,&mut observer,"claim-requested-remainder");
    apply(&database,pending.into_values(),None,false).unwrap();
    let large=large_archive(&database).unwrap();
    {let mut state=slot.state.lock().unwrap();original_completion(&mut state,generation,large).unwrap();}
    observer.emit("complete-requested-remainder",json!([{"op":5,"args":[1,16385]}]),&slot,Some(1),Value::Null);
    query(&slot,&mut observer,"complete-after-drain",true);
    // Actual external publication changes the original content watch.
    std::fs::write(original.join(format!("{:064x}.json",1001)),serde_json::to_vec(&record(1001)).unwrap()).unwrap();
    let current=version(content_version(&slot.archive).unwrap());
    let error=claim_pending(&slot).err().unwrap().to_string();
    observer.emit("changed-watch-claim-refused",json!([{"op":4,"args":[1,current[0],current[1],current[2]]}]),&slot,Some(0),json!({"error":error}));
    publication_before(&slot,&slot.archive);
    observer.emit("changed-watch-publication-before",json!([{"op":1,"args":current}]),&slot,None,Value::Null);

    let old=all.get(&id(&replacement.request_id).unwrap()).unwrap().clone();
    for kind in 0..9 {
        let mut new=old.clone();let label=match kind {
            0=>"identical",
            1=>{new.record.state=DurableState::Unknown;new.record.elapsed_ms=None;"older-unknown"},
            2=>{new.record.owner="b".repeat(64);"owner-change"},
            3=>{new.record.tool_name="host_list".into();"tool-change"},
            4=>{new.record.accepted_unix_ms+=1;"u128-accepted-change"},
            5=>{new.record.state=DurableState::Failed;"terminal-change"},
            6=>{new.record.elapsed_ms=Some(8);"elapsed-change"},
            7=>{new.stamp.changed.1+=1;"stamp-change"},
            _=>{new.stamp.length+=1;"length-change"},
        };
        let pending=BTreeMap::from([(id(&new.record.request_id).unwrap(),new.clone())]);
        let result=PendingView::new(&database,&pending,Instant::now()+QUERY_BUDGET);
        let status=match &result {Ok(view)=>u64::from(!view.entries.is_empty()),Err(error)=>match error.downcast_ref::<OriginalRecordConflict>() {Some(OriginalRecordConflict::Identity)=>2,Some(OriginalRecordConflict::Terminal)=>3,_=>panic!("unexpected original error {error}")}};
        let data=[packed(&old),packed(&new)].concat();
        observer.raw(json!({"case":format!("transition-{label}"),"actions":[{"op":8,"args":[],"data_hex":hex(&data)}],"status":status,"extra":{"error":result.err().map(|e|e.to_string())}}));
    }
    observer.out.flush().unwrap();println!("ORIGINAL_OBSERVATIONS {}",observer.count);
}

fn original_completion(state: &mut State, generation: u64, large: bool) -> Result<()> {
		if state.failed {
			bail!("archive index invalidated during flush");
		}
		state.applied = generation;
		state.large_archive = large;
		state.requested =
			state.requested && (state.generation != generation || !state.pending.is_empty());
		state.busy = false;
Ok(())
}

