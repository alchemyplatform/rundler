# Rundler

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
* [Cocogitto](https://github.com/cocogitto/cocogitto)
    * `cargo install --locked cocogitto`

```
git clone https://github.com/OMGWINNING/rundler
cd rundler
cargo test --all
```

### Contributing:

* Commit messages must follow [conventional commits sytle](https://www.conventionalcommits.org/en/v1.0.0/).
