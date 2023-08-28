#!/bin/bash
set -e
cd "$(dirname "$0")"

(cd ../bundler-spec-tests && pdm install && pdm run update-deps)

(cd ../bundler-spec-tests && pdm run test --launcher-script=../launchers/rundler-launcher/rundler-launcher.sh $@)

../launchers/rundler-launcher/rundler-launcher.sh stop
