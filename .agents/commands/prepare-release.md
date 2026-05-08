---
name: Prepare Release
description: Prepare Rundler release inputs and checks without dispatching production-affecting workflows.
argument-hint: "[version]"
---

## How It Works

1. Validate the release version input.
2. Inspect release and Docker release workflow requirements.
3. Run local gates.
4. Produce a release checklist and workflow-dispatch plan.
5. Ask for explicit confirmation before any workflow dispatch.

## Instructions

### Validate Arguments

- `$1` — **version**: Required version tag, for example `v0.11.0`.
  - **Suggest:** Inspect `Cargo.toml` workspace version and recent git tags.

### 1. Inspect Workflows

Read:

- `.github/workflows/release.yaml`
- `.github/workflows/docker-release.yaml`
- `docs/release.md`
- `Makefile`

Confirm target platforms, signing requirements, Docker Hub secret expectations,
and whether the workflow will trigger from tag push or manual dispatch.

### 2. Run Local Gates

Run:

```bash
make fmt
make lint
make test-unit
```

If release changes affect spec behavior, run targeted spec tests.

### 3. Produce the Checklist

Report:

    **Version:** <version>
    **Local gates:** <commands and status>
    **Workflow inputs:** <release.yaml and docker-release.yaml inputs>
    **Required secrets:** <names only, never values>
    **Manual confirmation needed:** yes

Do not create tags, dispatch workflows, or publish Docker images without
explicit user confirmation.
