#!/bin/bash
set -x
cd "$(dirname "$0")"

# ASSUMES THAT YOU'VE INSTALLED THE DEPENDENCIES FOR THE SPEC TESTS
# (cd bundler-spec-tests && pdm install && pdm run update-deps)

cargo build

./launcher.sh stop # kill already running processes if any
export ENABLED_ENTRY_POINTS="v0.8"
./launcher.sh start v0_8

echo "Running v0.8 spec tests"
(cd ../v0_8/bundler-spec-tests && pdm run pytest tests/single --tb=short -rA -W ignore::DeprecationWarning --url http://localhost:3000/rpc --entry-point 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108 --ethereum-node http://127.0.0.1:8545/ "$@")

./launcher.sh stop
