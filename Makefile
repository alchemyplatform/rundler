# Heavily inspired by Reth: https://github.com/paradigmxyz/reth/blob/a3952f12811ac33d23b021f33a7e0afaa247ec7d/Makefile

##@ Test

UNIT_TEST_ARGS := --locked --workspace --all-features

.PHONY: build
build: ## Build the project.
	cargo build --all --all-features

.PHONY: clean
clean: ## Clean the project.
	cargo clean

## Run all tests.
.PHONY: test
test: test-unit test-spec-integrated test-spec-modular

.PHONY: test-unit
test-unit: ## Run unit tests.
	cargo install cargo-nextest --locked
	cargo nextest run $(UNIT_TEST_ARGS)

.PHONY: test-spec-integrated
test-spec-integrated: ## Run spec tests in integrated mode
	test/spec-tests/local/run-spec-tests.sh

.PHONY: test-spec-modular
test-spec-modular: ## Run spec tests in modular mode
	test/spec-tests/remote/run-spec-tests.sh
	
.PHONY: fmt
fmt: ## format code with nightly rust
	cargo +nightly fmt

