#!/bin/bash
# SPDX-License-Identifier: MIT

ROOT=$(realpath $(dirname "$0"))
BUILD=$ROOT/build

sudo -E $BUILD/dks/dks \
     --cmd analyze \
     "$@"

sudo chown -R $USER: $BUILD/vis 2>/dev/null
