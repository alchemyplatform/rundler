#!/bin/bash
# Pre-commit checks hook for rundler
# Runs cargo fmt and clippy before allowing git commit

set -e

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

# Only run checks if this is a git commit command
if ! echo "$COMMAND" | grep -q "git commit"; then
  exit 0
fi

PROJECT_DIR=$(echo "$INPUT" | jq -r '.cwd // empty')
cd "$PROJECT_DIR"

echo "Running cargo +nightly fmt --all..." >&2
if ! cargo +nightly fmt --all; then
  echo "BLOCKED: formatting failed" >&2
  exit 2
fi

echo "Running cargo clippy..." >&2
if ! cargo clippy --all --all-features --tests -- -D warnings; then
  echo "BLOCKED: clippy check failed" >&2
  exit 2
fi

exit 0
