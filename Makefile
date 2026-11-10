.PHONY: check source cold
source:
	python -B tools/check_hia_core_only.py
	python -B tools/generate_hia_selfhost_contract.py --check
check: source
	python -B -m unittest tests.test_hia_core_only tests.test_hia_agent_entry tests.test_hia_edit_query tests.test_hia_edit_batch -v
cold:
	python -B tools/replay_hia_selfhost_cold.py --output $(OUTPUT)
