		if state.failed {
			bail!("archive index invalidated during flush");
		}
		state.applied = generation;
		state.large_archive = large;
		state.requested =
			state.requested && (state.generation != generation || !state.pending.is_empty());
		state.busy = false;