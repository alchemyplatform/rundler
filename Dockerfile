# syntax=docker/dockerfile:1.3
FROM rust:1.67.0 AS builder

ARG TARGETPLATFORM

# Set the build profile to be release
ARG BUILD_PROFILE=release
ENV BUILD_PROFILE $BUILD_PROFILE

WORKDIR /root

# Update and install dependencies
RUN apt-get update && apt-get -y upgrade && apt-get install -y protobuf-compiler

RUN --mount=type=cache,target=/usr/local/cargo/registry,id=${TARGETPLATFORM} \
    cargo install cargo-strip

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry,id=${TARGETPLATFORM} --mount=type=cache,target=/root/target,id=${TARGETPLATFORM} \
    cargo build --release && \
    cargo strip && \
    mv /root/target/release/alchemy-bundler /root

# Use alpine as the release image
FROM frolvlad/alpine-glibc

RUN apk add --no-cache linux-headers

COPY --from=builder /root/alchemy-bundler /

ENTRYPOINT ["./alchemy-bundler"]
