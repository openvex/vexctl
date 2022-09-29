# Copyright 2022 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0

binary: # build the binaries
	go build -o vexctl ./main.go

default:
	binary