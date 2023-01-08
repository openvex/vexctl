/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package vex

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoadYAML(t *testing.T) {
	vexDoc, err := OpenYAML("testdata/vex.yaml")
	require.NoError(t, err)

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

func TestCanonicalHash(t *testing.T) {
	goldenHash := `461bb1de8d85c7a6af96edf24d0e0672726d248500e63c5413f89db0c6710fa0`
	ts, err := time.Parse(time.RFC3339, "2022-12-22T16:36:43-05:00")
	require.NoError(t, err)
	otherTS, err := time.Parse(time.RFC3339, "2019-01-22T16:36:43-05:00")
	require.NoError(t, err)

	testDoc := func() VEX {
		return VEX{
			Metadata: Metadata{
				Author:     "John Doe",
				AuthorRole: "VEX Writer Extraordinaire",
				Timestamp:  &ts,
				Version:    "1",
				Tooling:    "OpenVEX",
				Supplier:   "Chainguard Inc",
			},
			Statements: []Statement{
				{
					Vulnerability:   "CVE-1234-5678",
					VulnDescription: "",
					Products:        []string{"pkg:apk/wolfi/bash@1.0.0"},
					Status:          "under_investigation",
				},
			},
		}
	}

	for i, tc := range []struct {
		prepare   func(*VEX)
		expected  string
		shouldErr bool
	}{
		// Default Expected
		{func(v *VEX) {}, goldenHash, false},
		// Adding a statement changes the hash
		{
			func(v *VEX) {
				v.Statements = append(v.Statements, Statement{
					Vulnerability: "CVE-2010-543231",
					Products:      []string{"pkg:apk/wolfi/git@2.0.0"},
					Status:        "affected",
				})
			},
			"cf392111c8dfee8f6a115780de1eabf292fcd36aafb6eca75952ea7e2d648e21",
			false,
		},
		// Changing metadata should not change hash
		{
			func(v *VEX) {
				v.Author = "123"
				v.AuthorRole = "abc"
				v.ID = "298347" // Mmhh...
				v.Supplier = "Mr Supplier"
				v.Tooling = "Fake Tool 1.0"
			},
			goldenHash,
			false,
		},
		// Changing other statement metadata should not change the hash
		{
			func(v *VEX) {
				v.Statements[0].ActionStatement = "Action!"
				v.Statements[0].VulnDescription = "It is very bad"
				v.Statements[0].StatusNotes = "Let's note somthn here"
				v.Statements[0].ImpactStatement = "We evaded this CVE by a hair"
				v.Statements[0].ActionStatementTimestamp = &otherTS
			},
			goldenHash,
			false,
		},
		// Changing products changes the hash
		{
			func(v *VEX) {
				v.Statements[0].Products[0] = "cool router, bro"
			},
			"3ba778366d70b4fc656f9c1338a6be26fab55a7d011db4ceddf2f4840080ab3b",
			false,
		},
		// Changing document time changes the hash
		{
			func(v *VEX) {
				v.Timestamp = &otherTS
			},
			"c69a58b923d83f2c0952a508572aec6529801950e9dcac520dfbcbb953fffe52",
			false,
		},
		// Same timestamp in statement as doc should not change the hash
		{
			func(v *VEX) {
				v.Statements[0].Timestamp = v.Timestamp
			},
			goldenHash,
			false,
		},
	} {
		doc := testDoc()
		tc.prepare(&doc)
		hashString, err := doc.CanonicalHash()
		if tc.shouldErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
		require.Equal(t, tc.expected, hashString, fmt.Sprintf("Testcase #%d %s", i, doc.Statements[0].Products[0]))
	}
}
