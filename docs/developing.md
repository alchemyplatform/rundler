# Developing

## Setup

1. Clone the repo and checkout submodules

```
git clone https://github.com/alchemyplatform/rundler
cd rundler
git submodule update --init --recursive
```

2. Install prerequisites

* [Rust/Cargo](https://www.rust-lang.org/tools/install): 1.72 or higher with nightly 
* [Cocogitto](https://github.com/cocogitto/cocogitto): Commit linting
* [Docker](https://docs.docker.com/engine/install/): Run spec tests
* [PDM](https://pdm.fming.dev/latest/#installation): Run spec tests
* [Protoc](https://grpc.io/docs/protoc-installation/): Compile protobuf
* [Buf](https://buf.build/docs/installation): Protobuf linting
* [Foundry](https://book.getfoundry.sh/getting-started/installation): Compile contracts

## Build & Test

Rundler contains a `Makefile` to simplify common build/test commands

```
# build rundler
$ make build 

# run unit tests
$ make test-unit

# run all tests
$ make test

```

## Running Locally

Rundler requires an RPC end that supports `debug_traceCall` to be running. A simple way to do that is to use docker compose to run Geth with the following configuration:

```
version: "3.8"

services:
  geth:
    image: ethereum/client-go:v1.10.26
    ports:
      - "8545:8545"
      - "8546:8546"
    command:
      - --miner.gaslimit=12000000
      - --http
      - --http.api=personal,eth,net,web3,debug
      - --http.vhosts=*
      - --http.addr=0.0.0.0
      - --ws
      - --ws.api=personal,eth,net,web3,debug
      - --ws.addr=0.0.0.0
      - --ignore-legacy-receipts
      - --allow-insecure-unlock
      - --rpc.allow-unprotected-txs
      - --dev
      - --verbosity=2
      - --nodiscover
      - --maxpeers=0
      - --mine
      - --miner.threads=1
      - --networkid=1337

```

Create a `.env` file and fill in any required [configs](./cli.md).

Then:

```
cargo run node
```

will run a full Rundler node locally.
