#!/usr/bin/env bash

# Copyright 2023 The OpenVEX Authors
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

: "${GIT_HASH:?Environment variable empty or not defined.}"
: "${GIT_VERSION:?Environment variable empty or not defined.}"

if [[ ! -f vexImagerefs ]]; then
    echo "vexImagerefs not found"
    exit 1
fi

echo "Signing images with Keyless..."
cosign sign --yes -a GIT_HASH="$GIT_HASH" -a GIT_VERSION="$GIT_VERSION" $(cat vexImagerefs)
