#!/bin/bash
set -x
cd "$(dirname "$0")"

(cd ../bundler-spec-tests && ls -la && pdm install && pdm run update-deps)

docker build ../../.. -t alchemy-platform/rundler:latest

(cd ../bundler-spec-tests && pdm run test --launcher-script=../launchers/rundler-launcher/rundler-launcher.sh $@)

../launchers/rundler-launcher/rundler-launcher.sh stop
