---
name: Add Chain Spec
description: Add or update a Rundler hardcoded chain spec and verify config resolution behavior.
argument-hint: [network_name]
---

## How It Works

1. Inspect the existing hardcoded chain specs.
2. Add or update the TOML file.
3. Register the network in `chain_spec.rs`.
4. Verify config precedence and required fields.
5. Update docs when user-facing behavior changes.

## Instructions

### Validate Arguments

- `$1` — **network_name**: Required snake_case hardcoded network name.
  - **Suggest:** List `bin/rundler/chain_specs/*.toml`.

### 1. Load Context

Read `.agents/skills/configuration-observability/SKILL.md`.

### 2. Edit the Chain Spec

Add or update `bin/rundler/chain_specs/<network_name>.toml`. Prefer inheriting
from a `base` spec when a network mostly matches an existing family. Ensure
`id` is non-zero.

### 3. Register the Spec

Update `define_hardcoded_chain_specs!` in
`bin/rundler/src/cli/chain_spec.rs`. Remember the resolution order:

1. `CHAIN_*` env vars
2. `--chain_spec` file
3. `--network` hardcoded spec
4. base spec
5. defaults

### 4. Verify

Run:

```bash
make fmt
make lint
make test-unit
```

If chain behavior affects gas estimation, EntryPoint support, DA gas, or senders,
run targeted spec tests or document why local spec coverage is not practical.

