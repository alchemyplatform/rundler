# Respect Recursive Submodules

## Rule

Initialize and account for recursive submodules before working with contracts,
FastLZ, or spec tests.

## Why

CI checks out submodules recursively. Contract sources, account-abstraction
versions, OpenZeppelin versions, FastLZ, and spec tests live under submodules.

## Examples

- Good: run `git submodule update --init --recursive` before contract or spec
  work.
- Bad: assume missing vendored files mean the repo no longer uses them.

## Exceptions

Do not audit vendored submodule internals unless the change explicitly targets
those sources.
