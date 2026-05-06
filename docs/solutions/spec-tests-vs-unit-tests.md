---
title: Spec Tests vs Unit Tests
date: 2026-05-06
tags:
  - solutions
  - testing
  - compliance
area: testing
---

# Spec Tests vs Unit Tests

## Problem

A change can pass Rust unit tests while breaking ERC-4337 conformance or
distributed mode.

## Root Cause

Rundler has multiple test layers. `make test-unit` runs `cargo nextest` across
the Rust workspace. `make test-spec-integrated` runs local single-process spec
tests. `make test-spec-modular` runs remote/distributed mode. CI compliance also
builds a Docker image and runs the external bundler test executor for v0.6,
v0.7, and v0.8.

## Solution

Use unit tests for local Rust behavior. Add spec tests for changes to RPC
interfaces, EntryPoint routing, simulation, mempool acceptance, or builder
submission. Choose integrated mode for node behavior and modular mode for
pool/builder/RPC service boundaries.
