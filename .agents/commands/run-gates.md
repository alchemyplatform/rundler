---
name: Run Gates
description: Run the appropriate local verification gates for the current Rundler diff.
argument-hint: "[scope]"
---

## How It Works

1. Inspect the diff and classify changed areas.
2. Pick the smallest safe gate set from the table below.
3. Run gates in order and stop on the first failure.
4. Report commands, exit codes, and remaining risk.

## Instructions

### Validate Arguments

- `$1` — **scope**: Optional area hint such as `unit`, `rpc`, `proto`,
  `contracts`, `spec-integrated`, `spec-modular`, or `all`.
  - **Suggest:** If omitted, inspect changed paths with `git status --short`
    and `git diff --name-only`.

### 1. Classify the Diff

Use the first matching rules:

| Changed paths                                                           | Required gates                                                                                  |
| ----------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `Cargo.toml`, `Cargo.lock`, `.cargo/`, `Makefile`, `.github/workflows/` | `make fmt`, `make lint`, `make test-unit`                                                       |
| `crates/rpc/`, `crates/types/src/user_operation/`                       | `make fmt`, `make lint`, `make test-unit`, targeted spec tests if behavior changed              |
| `crates/{pool,builder}/proto/`                                          | `buf lint`, `cargo build --all --all-features`, `make test-unit`                                |
| `crates/contracts/`, `.gitmodules`                                      | `git submodule update --init --recursive`, `cargo build --all --all-features`, `make test-unit` |
| `crates/sim/tracer/`                                                    | `yarn build` from `crates/sim/tracer`, then `cargo build --all --all-features`                  |
| EntryPoint, simulation, mempool, or builder behavior                    | `make test-unit`, then `make test-spec-integrated` or `make test-spec-modular` as appropriate   |
| Docs-only                                                               | Run codespell against changed `.md` and `.mdc` files if codespell is installed                   |

For docs-only changes, collect changed docs first so nested guidance files
under `.agents/`, `.cursor/rules/`, and `docs/solutions/` are covered:

```bash
changed_docs=$(git diff --name-only -- '*.md' '*.mdc')
[ -z "$changed_docs" ] || codespell --toml .github/workflows/codespell.toml $changed_docs
```

### 2. Run Commands

Run commands from the repository root unless a row specifies another directory.
Do not dispatch GitHub workflows or releases.

### 3. Report

Use this structure:

    **Gates run:**
    - `<command>` → <passed/failed/skipped with reason>

    **Result:** <summary>
    **Remaining risk:** <anything not covered locally>
