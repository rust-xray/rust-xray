.PHONY: test build fixture-test fixture-decode fixture-decode-write capture-clienthello

test:
	cargo test

build:
	cargo build

fixture-test:
	cargo test --test reality_fixture -- --nocapture

fixture-decode:
	cargo run --bin decode_reality_fixture -- tests/fixtures/reality/basic-xray

fixture-decode-write:
	cargo run --bin decode_reality_fixture -- tests/fixtures/reality/basic-xray --write-expected --force

capture-clienthello:
	python3 scripts/capture_reality_clienthello.py --listen 127.0.0.1:24443 --out /tmp/client_hello.bin
