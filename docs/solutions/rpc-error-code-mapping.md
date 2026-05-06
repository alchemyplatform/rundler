---
title: RPC Error Code Mapping
date: 2026-05-06
tags:
  - solutions
  - rpc
  - errors
area: rpc
---

# RPC Error Code Mapping

## Problem

New validation or simulation errors can accidentally become generic internal
JSON-RPC failures, which breaks wallet and bundler clients that parse ERC-4337
error codes.

## Root Cause

`EthRpcError` maps to `ErrorObjectOwned` in `crates/rpc/src/eth/error.rs`.
Many variants intentionally map to ERC-4337 custom codes such as
EntryPoint validation rejected, paymaster rejected, opcode violation, and
signature check failed. Some variants also include structured data.

## Solution

When adding client-visible errors, update both the domain-to-`EthRpcError`
conversion and `impl From<EthRpcError> for ErrorObjectOwned`. Use
`rpc_err_with_data` for structured payloads and avoid `INTERNAL_ERROR_CODE`
unless the failure is truly internal.

