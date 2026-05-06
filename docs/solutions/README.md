---
title: Rundler Solution Notes
date: 2026-05-06
tags:
  - ai-guidance
  - solutions
area: agent-docs
---

# Rundler Solution Notes

These docs capture gotchas discovered while auditing or changing Rundler. They
are reference material, not authoritative rules. If a solution doc contradicts
the current code, trust the code.

## Format

Each note should include frontmatter:

```yaml
---
title: Short descriptive title
date: YYYY-MM-DD
tags:
  - solutions
  - relevant-area
area: crate-or-workflow
---
```

Use these sections:

- `## Problem`
- `## Root Cause`
- `## Solution`

Prefer notes for issues that are easy for agents to miss: stale docs, generated
boundaries, workflow behavior that differs from local commands, or versioned
protocol details.

