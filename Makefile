# Copyright 2022 Chainguard, Inc.
# SPDX-License-Identifier: Apache-2.0
# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Set version variables for LDFLAGS
GIT_VERSION ?= $(shell git describe --tags --always --dirty)

LDFLAGS=-buildid= -X sigs.k8s.io/release-utils/version.gitVersion=$(GIT_VERSION)

## Build

.PHONY: vex
vex: # build the binaries
	go build -trimpath -ldflags "$(LDFLAGS)" -o vexctl ./main.go

.PHONY: default
default:
	binary

## Tests

.PHONY: test
test:
	go test -v ./...

## Release

.PHONY: release
release:
	LDFLAGS="$(LDFLAGS)" goreleaser release --rm-dist --timeout 120m

.PHONY: snapshot
snapshot:
	LDFLAGS="$(LDFLAGS)" goreleaser release --rm-dist --snapshot --skip-sign --skip-publish --timeout 120m
