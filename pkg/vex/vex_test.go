/*
Copyright 2022 Chainguard, Inc.
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

func TestLoadCSAF(t *testing.T) {
	vexDoc, err := OpenCSAF("testdata/csaf.json", []string{})
	require.NoError(t, err)
	require.Len(t, vexDoc.Statements, 1)
	require.Equal(t, vexDoc.Statements[0].Vulnerability, "CVE-2009-4487")
	require.Equal(t, vexDoc.Statements[0].Status, StatusNotAffected)
	require.Equal(t, vexDoc.Metadata.ID, "2022-EVD-UC-01-NA-001")
}
