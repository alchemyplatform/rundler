# Spawn Through `rundler-task`

## Rule

Use `TaskSpawnerExt` from `crates/task/src/lib.rs` for long-running library
tasks instead of untracked `tokio::spawn`.

## Why

Critical servers and loops should be supervised by Reth's task manager so the
binary can observe failure and shut down cleanly.

## Examples

- Good: accept `impl TaskSpawnerExt` and call `spawn_critical` for servers or
  loops that must not silently die.
- Bad: start a background loop with `tokio::spawn` from a library crate and
  drop the handle.

## Exceptions

Short test-only tasks may use Tokio directly inside test modules.
