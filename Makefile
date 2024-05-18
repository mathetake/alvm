TESTS_MANIFEST := --manifest-path tvisor-tests/Cargo.toml

.PHONY: check build test all

check:
	@cargo fmt --all -- --check
	@cargo clippy --all -- -D warnings

build:
	@cargo build --message-format=json | jq -r 'select(.executable != null) | .executable' | xargs -Iexecutable_path codesign --entitlements entitlements.xml -s "Takeshi Yoneda" executable_path;
	@cargo build --release  --message-format=json | jq -r 'select(.executable != null) | .executable' | xargs -Iexecutable_path codesign --entitlements entitlements.xml -s "Takeshi Yoneda" executable_path;

test: build
	@for executable_path in `cargo test --no-run --message-format=json | jq -r 'select(.executable != null) | .executable' | grep "deps"`; do \
		echo "Signing test: $$executable_path"; \
		codesign --entitlements entitlements.xml -s "Takeshi Yoneda" $$executable_path; \
		echo "Running test: $$executable_path"; \
		$$executable_path --test-threads=1; \
		if [ $$? -ne 0 ]; then \
			exit 1; \
		fi; \
	done

name := ""
test.integration:
	@cargo test --no-run --message-format=json | \
		jq -r 'select(.executable != null) | .executable' | grep "deps/integration-" | \
		xargs -I {} sh -c 'codesign --entitlements entitlements.xml -s "Takeshi Yoned" {}; {} --exact $$name --nocapture --test-threads=1'; \
	if [ $$? -ne 0 ]; then \
		exit 1; \
	fi

all: check build test
