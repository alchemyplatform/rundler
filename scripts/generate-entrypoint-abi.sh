#!/usr/bin/env bash

set -e

PROJECT_DIR=$(git rev-parse --show-toplevel)

if [[ -z $PROJECT_DIR ]]
then
  echo "Could not locate Git root."
  exit 1
fi

OUT_DIR=$PROJECT_DIR/abis
OUT=$OUT_DIR/EntryPoint.json

cd $PROJECT_DIR/submodules/account-abstraction
yarn
yarn compile
mkdir -p $OUT_DIR
rm -f $OUT
cp artifacts/contracts/core/EntryPoint.sol/EntryPoint.json $OUT
echo "Generated EntryPoint ABI."

