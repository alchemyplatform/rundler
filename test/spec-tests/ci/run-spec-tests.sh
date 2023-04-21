#!/bin/bash
set -x
cd "$(dirname "$0")"

cd ../bundler-spec-tests
pdm install && pdm run update-deps
pdm run test --launcher-script=../ci/rundler-launcher.sh
