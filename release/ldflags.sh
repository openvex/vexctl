#!/usr/bin/env bash

# Copyright 2023 The OpenVEX Authors
# SPDX-License-Identifier: Apache-2.0

# Copyright 2023 The OpenVEX Authors
#
# Licensed under the Apache License, Version 2.0 (the "License"";
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

# Output LDFlAGS for a given environment. LDFLAGS are applied to all go binary
# builds.
#
# Args: env
function ldflags() {
  local GIT_VERSION=$(git describe --tags --always --dirty)
  local GIT_COMMIT=$(git rev-parse HEAD)

  local GIT_TREESTATE="clean"
  if [[ $(git diff --stat) != '' ]]; then
    GIT_TREESTATE="dirty"
  fi

  local DATE_FMT="+%Y-%m-%dT%H:%M:%SZ"
  local BUILD_DATE=$(date "$DATE_FMT")
  local SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
  if [ $SOURCE_DATE_EPOCH ]
  then
      local BUILD_DATE=$(date -u -d "@$SOURCE_DATE_EPOCH" "$DATE_FMT" 2>/dev/null || date -u -r "$SOURCE_DATE_EPOCH" "$DATE_FMT" 2>/dev/null || date -u "$DATE_FMT")
  fi

  echo "-buildid= -X sigs.k8s.io/release-utils/version.gitVersion=$GIT_VERSION \
        -X sigs.k8s.io/release-utils/version.gitCommit=$GIT_COMMIT \
        -X sigs.k8s.io/release-utils/version.gitTreeState=$GIT_TREESTATE \
        -X sigs.k8s.io/release-utils/version.buildDate=$BUILD_DATE"
}
