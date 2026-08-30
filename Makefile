.PHONY: test build build-debug build-musl build-linux-x86_64-gnu build-linux-x86_64-gnu-debug fixture-test fixture-decode fixture-decode-write capture-clienthello live-smoke
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc
CC_x86_64_unknown_linux_musl=musl-gcc

test:
	cargo test

build:
	cargo build --release

build-debug:
	cargo build

build-musl:
	cargo build --target x86_64-unknown-linux-musl

build-musl-release:
	cargo build --release --target x86_64-unknown-linux-musl

build-linux-x86_64-gnu:
	bash scripts/build-linux-x86_64-gnu.sh

build-linux-x86_64-gnu-debug:
	bash scripts/build-linux-x86_64-gnu.sh --debug

live-smoke:
	bash scripts/live_reality_smoke/run-live-smoke.sh
	bash scripts/live_xhttp_smoke/run-live-xhttp-smoke.sh

fixture-test:
	cargo test --test reality_fixture -- --nocapture

fixture-decode:
	cargo run --bin decode_reality_fixture -- tests/fixtures/reality/basic-xray

fixture-decode-write:
	cargo run --bin decode_reality_fixture -- tests/fixtures/reality/basic-xray --write-expected --force

capture-clienthello:
	python3 scripts/capture_reality_clienthello.py --listen 127.0.0.1:24443 --out /tmp/client_hello.bin
