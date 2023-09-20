# Rundler

## Development

### Build & Test

Prerequisites:

* [Rust & Cargo](https://rustup.rs/)
    * Nightly rust required for `rustfmt`:
```
rustup toolchain add nightly
```
* [Cocogitto](https://github.com/cocogitto/cocogitto)
    * `cargo install --locked cocogitto`
* [Docker](https://docs.docker.com/engine/install/)

Run tests:
```
git clone https://github.com/OMGWINNING/rundler
cd rundler
cargo test --all
```

### Run locally:

Running locally requires access to an Ethereum RPC node on the network the Rundler is running on. For testing it is recommended to run a local devlopment node.

Steps to run `Geth` in dev mode locally:

1. `cd test`
2. `docker compose up` (use `-d`) to run in background.

Steps to run `Rundler` locally:

1. Copy the default .env file. By default, this will be pointing at the local `Geth` node.
```
cp test/.env.default .env
```

2. (Optional) Fund and deploy contracts. Contracts are deployed from the [account-abstraction](https://github.com/eth-infinitism/account-abstraction) repo. This does the following: 
    * Creates an account for the bundler to use.
    * Deploys the `EntryPoint`.
    * Deploys a `SimpleAccountFactory`.
    * Deploys a `VerifyingPaymaster`.
    * Deploys a `SimpleAccount`.
    * Funds each of the accounts.
```
cargo run --bin deploy_dev_contracts
```

3. (Optional) Modify the `BUNDLER_PRIVATE_KEY` field if using a different account than was funded in #2.

4. Start the Rundler
```
cargo run node
```

### Documentation

- [configuration](docs/config.md)
- [transactions](docs/transactions.md)
- [contributing](docs/CONTRIBUTING.md)
- [architecture](docs/architecture.md)

### Goals

- Implement P2P mempool
- Implement persistant mempool
- Keep our spec test fork in like with origin 
- Deploy public docker image
- Cross platform compilation

### Resources

- [EIP-4337](https://eips.ethereum.org/EIPS/eip-4337)

### Communication:
- [Telegram](https://t.me/+F_xS9IVOdJZmZjQx)