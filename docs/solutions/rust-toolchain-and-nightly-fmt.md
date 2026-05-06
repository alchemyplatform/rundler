---
title: Rust Toolchain and Nightly Fmt
date: 2026-05-06
tags:
  - solutions
  - tooling
area: tooling
---

# Rust Toolchain and Nightly Fmt

## Problem

An agent may read `docs/developing.md`, see the older "Rust 1.85 or higher"
guidance, and run checks with a different compiler than CI.

## Root Cause

The authoritative toolchain lives in `rust-toolchain.toml` and root
`Cargo.toml`. CI also installs `dtolnay/rust-toolchain@1.92.0`. Formatting is a
separate nightly rustfmt path via `make fmt` and CI's `cargo +nightly fmt
--all --check`.

## Solution

Use Rust `1.92.0` for builds, clippy, and tests. Use nightly only for rustfmt.
When documentation and toolchain files disagree, trust `rust-toolchain.toml`,
`Cargo.toml`, and `.github/workflows/ci.yaml`.
