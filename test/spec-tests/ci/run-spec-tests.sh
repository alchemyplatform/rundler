#!/bin/bash
set -e
cd "$(dirname "$0")"

(cd ../bundler-spec-tests && pdm install && pdm run update-deps)


docker buildx create --use
docker buildx build --load --cache-from type=local,src=/tmp/.buildx-cache --cache-to type=local,mode=max,dest=/tmp/.buildx-cache-new -t alchemy-platform/rundler:latest ../../..

(cd ../bundler-spec-tests && pdm run test --url http://127.0.0.1:3000 --launcher-script=../launchers/rundler-launcher/rundler-launcher.sh $@)

../launchers/rundler-launcher/rundler-launcher.sh stop
