#!/bin/bash
set -x
cd "$(dirname "$0")"

# ASSUMES THAT YOU'VE INSTALLED THE DEPENDENCIES FOR THE SPEC TESTS
# (cd bundler-spec-tests && pdm install && pdm run update-deps)

cargo build

./launcher.sh stop # kill already running processes if any
export DISABLE_ENTRY_POINT_V0_7=true
./launcher.sh start v0_6

echo "Running v0.6 spec tests"
(cd ../v0_6/bundler-spec-tests && pdm run pytest -rA -W ignore::DeprecationWarning --url http://localhost:3000 --entry-point 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789 --ethereum-node http://localhost:8545 $@)

./launcher.sh stop
