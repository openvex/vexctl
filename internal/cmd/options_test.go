/*
Copyright 2022 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
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
				Status:  string(vex.StatusUnderInvestigation),
				Product: "",
			}, true,
		},
		"empty vulnerability": {
			vexStatementOptions{
				Status:        string(vex.StatusUnderInvestigation),
				Product:       "pkg:golang/fmt",
				Vulnerability: "",
			}, true,
		},
		"empty status": {
			vexStatementOptions{
				Status:        "",
				Product:       "pkg:golang/fmt",
				Vulnerability: "CVE-2014-12345678",
			}, true,
		},
		"invalid status": {
			vexStatementOptions{
				Status:        "cheese",
				Product:       "pkg:golang/fmt",
				Vulnerability: "CVE-2014-12345678",
			}, true,
		},
		"justification on non-not-affected": {
			vexStatementOptions{
				Status:        string(vex.StatusUnderInvestigation),
				Product:       "pkg:golang/fmt",
				Vulnerability: "CVE-2014-12345678",
				Justification: "justification goes here",
			}, true,
		},
		"impact statement on non-not-affected": {
			vexStatementOptions{
				Status:          string(vex.StatusUnderInvestigation),
				Product:         "pkg:golang/fmt",
				Vulnerability:   "CVE-2014-12345678",
				ImpactStatement: "buffer underrun is never run under",
			}, true,
		},
		"ok": {
			vexStatementOptions{
				Status:        string(vex.StatusUnderInvestigation),
				Product:       "pkg:golang/fmt",
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
