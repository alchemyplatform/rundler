# Rundler PR Review Instructions

You are reviewing a PR for Rundler, a public Rust ERC-4337 bundler workspace
that ships a `rundler` binary and modular pool, builder, RPC, provider, signer,
simulation, contract, and task crates.

## How to review

1. Read `AGENTS.md` for the skill catalog and directory-to-skill mapping.
2. Read `.agents/skills/*/rules/*.md` for the relevant skills based on which
   files changed in the diff.
3. Review the PR against those rules.

Every finding must appear as both a summary bullet and an inline file
annotation. There are two types of findings:

**Rule violations** — cite the specific rule in the comment body:

- Name the rule, for example `rpc-errors/core`: preserve ERC-4337 error codes.
- Quote the violating code.
- Show the correct pattern or reference where to find it.

**Security issues, bugs, and logic errors** — no rule citation needed:

- Describe the issue directly.
- Explain the impact.
- Suggest a fix.

If no issues are found, say so explicitly in the summary.

## Self-verification before posting any comment

Before submitting any comment, verify:

1. What rule is violated, if this is a rule violation.
2. What the code actually does, quoting the relevant code.
3. What should change.
4. Why the current code is wrong.

Drop the comment if the evidence does not support it.

## Security, always flag as blocking

Clearly state "this should be fixed before merge" for:

- Hardcoded private keys, mnemonics, API tokens, relay auth headers, KMS
  credentials, or database/service credentials.
- Secrets logged through tracing, metrics labels, errors, or RPC responses.
- User-supplied hex, addresses, signatures, authorization tuples, or calldata
  used without validation at an RPC or proto boundary.
- New privileged RPC methods exposed by default without explicit gating.
- Sender, signer, or KMS/Redis leasing changes that can cause nonce collisions,
  stuck signer leases, or unauthorized sponsored delegation.
- Public workflow changes that expose secrets to untrusted fork PR code.

## Code quality, flag as notes

Mention these when they materially affect reliability:

- Missing error handling for provider, gRPC, sender, or AWS calls.
- External calls without timeout or retry behavior where surrounding code uses
  provider layers or `connect_with_retries`.
- Missing metrics or tracing in new hot paths, background tasks, or sender
  state transitions.
- `tokio::spawn` in library code where `TaskSpawnerExt` would preserve task
  supervision.
- Tests that cover only unit behavior when the change affects EntryPoint,
  simulation, mempool, RPC, or distributed-mode spec behavior.

## What not to flag

- Style and formatting that `cargo +nightly fmt`, clippy, or cargo-sort handles.
- Missing spec tests on docs-only changes.
- Missing database guidance; Rundler has no SQL/ORM persistence layer.
- Vendored submodule internals unless the PR intentionally changes them.
- Public repository workflow limitations if the PR did not modify workflows.

## Calibration

Security findings and correctness bugs are blocking. Rule violations are notes
unless they can break runtime behavior, client compatibility, or CI. Quality
issues are notes unless they create a plausible production failure mode.

