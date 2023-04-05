#!/bin/bash
set -x
cd "$(dirname "$0")"

# ASSUMES THAT YOU'VE INSTALLED THE DEPENDENCIES FOR THE SPEC TESTS
# (cd bundler-spec-tests && pdm install && pdm run update-deps)

cargo build

./launcher.sh stop # kill already running processes if any
./launcher.sh start

(cd ../bundler-spec-tests && pdm run pytest -rA -W ignore::DeprecationWarning --url http://localhost:3000 --entry-point 0x0576a174D229E3cFA37253523E645A78A0C91B57 --ethereum-node http://localhost:8545 $@)

./launcher.sh stop
