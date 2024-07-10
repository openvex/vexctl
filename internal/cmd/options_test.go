/*
Copyright 2022 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/stretchr/testify/require"
)

func TestVexDocOptionsValidate(t *testing.T) {
	for s, tc := range map[string]struct {
		sut     vexDocOptions
		mustErr bool
	}{
		"no author": {
			vexDocOptions{Author: ""}, true,
		},
		"ok": {
			vexDocOptions{Author: "Test Author"}, false,
		},
	} {
		err := tc.sut.Validate()
		if tc.mustErr {
			require.Error(t, err, s)
		}
	}
}

func TestVexStatementOptionsValidate(t *testing.T) {
	for s, tc := range map[string]struct {
		sut     vexStatementOptions
		mustErr bool
	}{
		"no statement on affected": {
			vexStatementOptions{
				Status:          string(vex.StatusNotAffected),
				ActionStatement: "",
			}, true,
		},
		"action statement on non-affected": {
			vexStatementOptions{
				Status:          string(vex.StatusUnderInvestigation),
				ActionStatement: "Action statement",
			}, true,
		},
		"empty product": {
			vexStatementOptions{
				Status:   string(vex.StatusUnderInvestigation),
				Products: []string{},
			}, true,
		},
		"empty vulnerability": {
			vexStatementOptions{
				Status:        string(vex.StatusUnderInvestigation),
				Products:      []string{"pkg:golang/fmt"},
				Vulnerability: "",
			}, true,
		},
		"empty status": {
			vexStatementOptions{
				Status:        "",
				Products:      []string{"pkg:golang/fmt"},
				Vulnerability: "CVE-2014-12345678",
			}, true,
		},
		"invalid status": {
			vexStatementOptions{
				Status:        "cheese",
				Products:      []string{"pkg:golang/fmt"},
				Vulnerability: "CVE-2014-12345678",
			}, true,
		},
		"justification on non-not-affected": {
			vexStatementOptions{
				Status:        string(vex.StatusUnderInvestigation),
				Products:      []string{"pkg:golang/fmt"},
				Vulnerability: "CVE-2014-12345678",
				Justification: "justification goes here",
			}, true,
		},
		"impact statement on non-not-affected": {
			vexStatementOptions{
				Status:          string(vex.StatusUnderInvestigation),
				Products:        []string{"pkg:golang/fmt"},
				Vulnerability:   "CVE-2014-12345678",
				ImpactStatement: "buffer underrun is never run under",
			}, true,
		},
		"can't associate a subcomponent when multiple products are defined": {
			vexStatementOptions{
				Status:        string(vex.StatusNotAffected),
				Products:      []string{"pkg:oci/alpine@sha256:124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126", "pkg:oci/busybox@sha256:c6ab5a1a2bc330f3f9616b20c7fba7716cadd941514cf80f8d7c3da8af6b0946"},
				Subcomponents: []string{"pkg:golang/fmt"},
				Vulnerability: "CVE-2014-12345678",
			}, true,
		},
		"ok": {
			vexStatementOptions{
				Status:        string(vex.StatusUnderInvestigation),
				Products:      []string{"pkg:golang/fmt"},
				Vulnerability: "CVE-2014-12345678",
			}, false,
		},
	} {
		err := tc.sut.Validate()
		if tc.mustErr {
			require.Error(t, err, s)
		}
	}
}

func TestAddOptionsValidate(t *testing.T) {
	stubOpts := vexStatementOptions{
		Status:        "fixed",
		Vulnerability: "CVE-2014-1234678",
		Products:      []string{"pkg:generic/test@1.00"},
	}

	// create a test directory and a file in it
	d, err := os.MkdirTemp("", "vexctl-testaddoptions-*")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(d, "openvex.test"), []byte("BLANK FILE"), os.FileMode(0o644)))
	defer os.RemoveAll(d)

	for _, tc := range []struct {
		name    string
		prepare func(*addOptions)
		sut     *addOptions
		mustErr bool
	}{
		{
			name:    "no-error",
			prepare: func(_ *addOptions) {},
			sut: &addOptions{
				vexStatementOptions: stubOpts,
				documentPath:        filepath.Join(d, "openvex.test"),
				inPlace:             false,
			},
			mustErr: false,
		},
		{
			name:    "inplace-and-outfile",
			prepare: func(_ *addOptions) {},
			sut: &addOptions{
				vexStatementOptions: stubOpts,
				outFileOption: outFileOption{
					outFilePath: "test.txt",
				},
				documentPath: filepath.Join(d, "openvex.test"),
				inPlace:      true,
			},
			mustErr: true,
		},
		{
			name: "non-existent-sourcedoc",
			prepare: func(ao *addOptions) {
				b := make([]byte, 15)
				if _, err := rand.Read(b); err != nil {
					require.NoError(t, err)
				}
				ao.documentPath = filepath.Join("/", fmt.Sprintf("%X", b), fmt.Sprintf("%X", b)+"-please-dont-create-this.openvex.json")
			},
			sut: &addOptions{
				vexStatementOptions: stubOpts,
				inPlace:             true,
			},
			mustErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.prepare(tc.sut)
			err := tc.sut.Validate()
			if tc.mustErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
