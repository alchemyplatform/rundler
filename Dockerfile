# Adapted from https://github.com/paradigmxyz/reth/blob/main/Dockerfile
# syntax=docker/dockerfile:1.4

FROM --platform=$TARGETPLATFORM rust:1.75.0 AS chef-builder

# Install system dependencies
RUN apt-get update && apt-get -y upgrade && apt-get install -y libclang-dev pkg-config protobuf-compiler rsync unzip
RUN curl -fsSL https://bun.sh/install | BUN_INSTALL=/usr bash 
SHELL ["/bin/bash", "-c"]
RUN curl -L https://foundry.paradigm.xyz | bash
ENV PATH="/root/.foundry/bin:${PATH}"
RUN foundryup

RUN cargo install cargo-chef --locked

WORKDIR /app

# Builds a cargo-chef plan
FROM chef-builder AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef-builder AS builder
COPY --from=planner /app/recipe.json recipe.json

# Set the build profile to be release
ARG BUILD_PROFILE=release
ENV BUILD_PROFILE $BUILD_PROFILE

# Builds dependencies
RUN cargo chef cook --profile $BUILD_PROFILE --recipe-path recipe.json

# Undo the source file changes made by cargo-chef.
# rsync invalidates the cargo cache for the changed files only, by updating their timestamps.
# This makes sure the fake empty binaries created by cargo-chef are rebuilt.
COPY --from=planner /app recipe-original
RUN rsync --recursive --checksum --itemize-changes --verbose recipe-original/ .
RUN rm -r recipe-original

RUN cargo build --profile $BUILD_PROFILE --locked --bin rundler

# Use Ubuntu as the release image
FROM ubuntu AS runtime
WORKDIR /app
# Install system dependencies for the runtime
# install curl for healthcheck
RUN apt-get -y update; apt-get -y install curl

# Copy rundler over from the build stage
COPY --from=builder /app/target/release/rundler /usr/local/bin

EXPOSE 3000 8080
ENTRYPOINT ["/usr/local/bin/rundler"]
