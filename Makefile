.PHONY: test build fixture-test fixture-decode fixture-decode-write capture-clienthello live-smoke

test:
	cargo test

build:
	cargo build

live-smoke:
	bash scripts/live_reality_smoke/run-live-smoke.sh

fixture-test:
	cargo test --test reality_fixture -- --nocapture

fixture-decode:
	cargo run --bin decode_reality_fixture -- tests/fixtures/reality/basic-xray

fixture-decode-write:
	cargo run --bin decode_reality_fixture -- tests/fixtures/reality/basic-xray --write-expected --force

capture-clienthello:
	python3 scripts/capture_reality_clienthello.py --listen 127.0.0.1:24443 --out /tmp/client_hello.bin
