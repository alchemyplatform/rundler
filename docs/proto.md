# Rundler Protocol Buffers

Rundler utilizes gRPC for communication between modules while running in distributed mode. Refer to this document for best practices when utilizing protocol buffers in gRPC.

## Building

Rundler builds on [Tonic](https://github.com/hyperium/tonic) to power lightning quick gRPC interfaces between internal components. To re-compile changes to the protocol buffers:

1. Make sure `protoc` is installed locally. On Macs one can run `brew install protobuf`. Otherwise see the official [protobuf docs](https://grpc.io/docs/protoc-installation/) for installation instructions.
2. Run `cargo build` to recompile the protocol buffers as part of the overall binary build. This is configured in `build.rs` in the `generate_protos` function. Adding schemas in new files will require a change to `build.rs`.

## Protocol Buffer to Memory Representation Translation

## Style Guide

Rundler largely relies on the canonical [protobuf style guide](https://protobuf.dev/programming-guides/style/). There are a few minor differences captured in `buf.yaml` to support Tonic best practices. Rundler uses [buf](https://buf.build/) to lint the `.proto` files. To use `buf` run `buf lint protos/.`. To install `buf` on Macs, run `brew install bufbuild/buf/buf`.
