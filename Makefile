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

# Note: The additional rustc compiler flags are for intrinsics needed by MDBX.
# See: https://github.com/cross-rs/cross/wiki/FAQ#undefined-reference-with-build-std
build-%:
	cross build --bin rundler --target $* --profile "$(PROFILE)"
	
# Note: This requires a buildx builder with emulation support. For example:
.PHONY: docker-build-latest
docker-build-latest: ## Build and push a cross-arch Docker image tagged with the latest git tag and `latest`.
	$(call build_docker_image,$(GIT_TAG),latest)

# Create a cross-arch Docker image with the given tags and push it
define build_docker_image
	$(MAKE) build-x86_64-unknown-linux-gnu
	mkdir -p $(BIN_DIR)/amd64
	cp $(BUILD_PATH)/x86_64-unknown-linux-gnu/$(PROFILE)/rundler $(BIN_DIR)/amd64/rundler

	$(MAKE) build-aarch64-unknown-linux-gnu
	mkdir -p $(BIN_DIR)/arm64
	cp $(BUILD_PATH)/aarch64-unknown-linux-gnu/$(PROFILE)/rundler $(BIN_DIR)/arm64/rundler

	docker buildx build --file ./Dockerfile.cross . \
		--platform linux/amd64,linux/arm64 \
		--tag $(DOCKER_IMAGE_NAME):$(1) \
		--tag $(DOCKER_IMAGE_NAME):$(2) \
		--provenance=false 
endef



# docker buildx build --file ./Dockerfile.cross . \
# 	--platform linux/amd64,linux/arm64 \
# 	--tag $(DOCKER_IMAGE_NAME):$(1) \
# 	--tag $(DOCKER_IMAGE_NAME):$(2) \
# 	--provenance=false \
# 	--push
