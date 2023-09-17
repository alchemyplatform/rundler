# Heavily inspired by Reth: https://github.com/paradigmxyz/reth/blob/a3952f12811ac33d23b021f33a7e0afaa247ec7d/Makefile

##@ Test

UNIT_TEST_ARGS := --locked --workspace --all-features

.PHONY: test
test: test-unit ## Run all tests.

.PHONY: test-unit
test-unit: ## Run unit tests.
	cargo install cargo-nextest --locked
	cargo nextest run $(UNIT_TEST_ARGS)
