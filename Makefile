# Heavily inspired by Reth: https://github.com/paradigmxyz/reth/blob/a3952f12811ac33d23b021f33a7e0afaa247ec7d/Makefile

##@ Test

UNIT_TEST_ARGS := --locked --workspace --all-features
PROFILE ?= release
DOCKER_IMAGE_NAME ?= alchemyplatform/rundler
BIN_DIR = "dist/bin"
BUILD_PATH = "target"
GIT_TAG ?= $(shell git describe --tags --abbrev=0)

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
	$(MAKE) test-spec-integrated-v0_6
	$(MAKE) test-spec-integrated-v0_7

.PHONY: test-spec-integrated-v0_6
test-spec-integrated-v0_6: ## Run v0.6 spec tests in integrated mode
	test/spec-tests/local/run-spec-tests-v0_6.sh

.PHONY: test-spec-integrated-v0_7
test-spec-integrated-v0_7: ## Run v0.7 spec tests in integrated mode
	test/spec-tests/local/run-spec-tests-v0_7.sh

.PHONY: test-spec-modular
test-spec-modular: ## Run spec tests in modular mode
	$(MAKE) test-spec-modular-v0_6
	$(MAKE) test-spec-modular-v0_7

.PHONY: test-spec-modular-v0_6
test-spec-modular-v0_6: ## Run v0.6 spec tests in modular mode
	test/spec-tests/remote/run-spec-tests-v0_6.sh

.PHONY: test-spec-modular-v0_7
test-spec-modular-v0_7: ## Run v0.7 spec tests in modular mode
	test/spec-tests/remote/run-spec-tests-v0_7.sh

.PHONY: submodule-update
submodule-update: ## Update git submodules
	git submodule update

build-%:
	cross build --target $* --profile "$(PROFILE)"
	
.PHONY: fmt
fmt: ## format code with nightly rust
	cargo +nightly fmt

# Note: This requires a buildx builder with emulation support. For example:
#
# `docker run --privileged --rm tonistiigi/binfmt --install amd64,arm64`
# `docker buildx create --use --driver docker-container --name cross-builder`
.PHONY: docker-build-latest
docker-build-latest: ## Build and push a cross-arch Docker image tagged with the latest git tag and `latest`.
	$(call build_docker_image,$(GIT_TAG),latest)

.PHONY: docker-build
docker-build: ## Build and push a cross-arch Docker image 
	$(call build_docker_image,$(GIT_TAG))

# Create a cross-arch Docker image with the given tags and push it
define build_docker_image
	$(MAKE) build-aarch64-unknown-linux-gnu
	mkdir -p $(BIN_DIR)/arm64
	cp $(BUILD_PATH)/aarch64-unknown-linux-gnu/$(PROFILE)/rundler $(BIN_DIR)/arm64/rundler

	$(MAKE) build-x86_64-unknown-linux-gnu
	mkdir -p $(BIN_DIR)/amd64
	cp $(BUILD_PATH)/x86_64-unknown-linux-gnu/$(PROFILE)/rundler $(BIN_DIR)/amd64/rundler

	docker buildx build --file ./Dockerfile.cross . \
		--platform linux/arm64,linux/amd64 \
		--tag $(DOCKER_IMAGE_NAME):$(1) \
		$(if $(2),--tag $(DOCKER_IMAGE_NAME):$(2)) \
		--provenance=false --push
endef

