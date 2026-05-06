---
title: EntryPoint ABI Versions
date: 2026-05-06
tags:
  - solutions
  - rpc
  - entrypoint
area: rpc
---

# EntryPoint ABI Versions

## Problem

It is easy to assume each supported EntryPoint version has a separate ABI and
user operation type.

## Root Cause

`EntryPointVersion` includes v0.6, v0.7, v0.8, and v0.9, but
`EntryPointAbiVersion` has only v0.6 and v0.7. v0.7, v0.8, and v0.9 share the
v0.7 ABI route. `EntryPointRouter` still routes by concrete EntryPoint address
and validates that the user operation variant matches the route ABI.

## Solution

When adding RPC, simulation, or conversion behavior, distinguish version from
ABI. Use `EntryPointVersion::abi_version()`, `ChainSpec::entry_point_address`,
and `EntryPointRouter` rather than ad hoc address or schema checks.

