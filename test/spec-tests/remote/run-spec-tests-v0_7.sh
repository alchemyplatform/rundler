#!/bin/bash
set -x
cd "$(dirname "$0")"

# ASSUMES THAT YOU'VE INSTALLED THE DEPENDENCIES FOR THE SPEC TESTS
# (cd bundler-spec-tests && pdm install && pdm run update-deps)

docker build ../../.. -t alchemy-platform/rundler:latest

./launcher.sh stop
./launcher.sh start v0_7

(cd ../v0_7/bundler-spec-tests && pdm run pytest -rA -W ignore::DeprecationWarning --url http://localhost:3000 --entry-point 0x0000000071727De22E5E9d8BAf0edAc6f37da032 --ethereum-node http://localhost:8545 $@)

./launcher.sh stop
