---
name: Run Spec Tests
description: Prepare and run Rundler ERC-4337 spec tests in integrated or modular mode.
argument-hint: [mode] [version]
---

## How It Works

1. Choose integrated or modular mode.
2. Choose one EntryPoint spec version or all versions.
3. Ensure submodules and external tools are ready.
4. Run the matching Makefile target.
5. Summarize logs, failures, and skipped coverage.

## Instructions

### Validate Arguments

- `$1` — **mode**: Required, `integrated`, `modular`, or `all`.
  - **Suggest:** Use `integrated` for local single-process behavior and
    `modular` for distributed pool/builder/RPC behavior.
- `$2` — **version**: Optional, `v0_6`, `v0_7`, `v0_8`, or `all`.
  - **Suggest:** Choose versions affected by the changed EntryPoint behavior.

### 1. Prepare

Run `git submodule update --init --recursive` if the spec-test submodules are
missing. Make sure Docker, PDM, Node, and Foundry are available before starting
long spec runs.

### 2. Run

Use the Makefile target matching the requested mode and version:

| Mode       | Version | Command                          |
| ---------- | ------- | -------------------------------- |
| integrated | all     | `make test-spec-integrated`      |
| integrated | `v0_6`  | `make test-spec-integrated-v0_6` |
| integrated | `v0_7`  | `make test-spec-integrated-v0_7` |
| integrated | `v0_8`  | `make test-spec-integrated-v0_8` |
| modular    | all     | `make test-spec-modular`         |
| modular    | `v0_6`  | `make test-spec-modular-v0_6`    |
| modular    | `v0_7`  | `make test-spec-modular-v0_7`    |
| modular    | `v0_8`  | `make test-spec-modular-v0_8`    |

### 3. Report

Include the command, version, mode, exit code, and the first actionable failure
summary. Do not rerun the same failing spec target twice without a new
hypothesis.
