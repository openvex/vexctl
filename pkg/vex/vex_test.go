/*
Copyright 2021 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/
package vex

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadYAML(t *testing.T) {
	vexDoc, err := OpenYAML("testdata/vex.yaml")
	require.NoError(t, err)

	require.Equal(t, "as", vexDoc)
	require.Len(t, vexDoc.Statements, 2)
}
