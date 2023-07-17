#!/usr/bin/env bash

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

vault server -dev -dev-root-token-id=root -dev-plugin-dir=$SCRIPT_DIR/../build/bin
