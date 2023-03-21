# Adapted from https://github.com/paradigmxyz/reth/blob/main/Dockerfile
# syntax=docker/dockerfile:1.4

FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

# Builds a cargo-chef plan
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json

# Set the build profile to be release
ARG BUILD_PROFILE=release
ENV BUILD_PROFILE $BUILD_PROFILE

# Install system dependencies
RUN curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | apt-key add - && echo "deb https://dl.yarnpkg.com/debian/ stable main" | tee /etc/apt/sources.list.d/yarn.list
RUN apt-get update && apt-get -y upgrade && apt-get install -y libclang-dev pkg-config protobuf-compiler nodejs yarn
RUN cargo install --git https://github.com/foundry-rs/foundry --profile local --locked foundry-cli

# Builds dependencies
RUN cargo chef cook --profile $BUILD_PROFILE --recipe-path recipe.json

# Build application
COPY . .
RUN cargo build --profile $BUILD_PROFILE --locked --bin alchemy-bundler

# Use Ubuntu as the release image
FROM ubuntu AS runtime
WORKDIR /app

# Copy reth over from the build stage
COPY --from=builder /app/target/release/alchemy-bundler /usr/local/bin

EXPOSE 3000 8080
CMD ["/usr/local/bin/alchemy-bundler", "bundler"]
