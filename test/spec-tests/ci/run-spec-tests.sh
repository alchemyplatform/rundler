#!/bin/bash
set -x
cd "$(dirname "$0")"

(cd bundler-spec-tests && pdm install && pdm run update-deps)

docker build ../../.. -t alchemy-platform/alchemy-bundler:latest

(cd ../bundler-spec-tests && pdm run test --launcher-script=../launchers/alchemy-bundler-launcher/alchemy-bundler-launcher.sh $@)

../launchers/alchemy-bundler-launcher/alchemy-bundler-launcher.sh stop
