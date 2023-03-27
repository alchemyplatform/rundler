# Alchemy Bundler (working name)

## Development

### Getting started

Make sure nightly Rust is installed to get nightly rustfmt:
```
rustup toolchain add nightly
```
Enable githooks to automatically run rustfmt on commit. Or don't, but then
you'll need to run `cargo +nightly fmt` yourself before you can merge.
```
git config core.hooksPath .githooks
```

### Build & Test

Prerequisites:

* [Rust & Cargo](https://rustup.rs/)

```
git clone https://github.com/OMGWINNING/alchemy-bundler
cd alchemy-bundler
cargo test --all
```
