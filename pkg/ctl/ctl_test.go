/*
Copyright 2022 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package ctl

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openvex/go-vex/pkg/sarif"
	"github.com/openvex/go-vex/pkg/vex"
)

const (
	sarifSampleVEX    = "testdata/sarif/sample.openvex.json"
	sarifNginxGrype   = "testdata/sarif/nginx-grype.sarif.json"
	sarifNginxTrivy   = "testdata/sarif/nginx-trivy.sarif.json"
	sarifNginxSnyk    = "testdata/sarif/nginx-snyk.sarif.json"
	sarifSampleHist   = "testdata/sarif/sample-history.json"
	sarifSample2Vulns = "testdata/sarif/sample-2vulns.json"
)

func TestVexReport(t *testing.T) {
	impl := defaultVexCtlImplementation{}
	for _, tc := range []struct {
		vexDoc         string
		lenStatements  int
		sarifDoc       string
		lenRuns        int
		lenResults     int
		lenAfterFilter int
	}{
		// One OpenVEX statement, filters one vuln
		{sarifSampleVEX, 1, sarifNginxGrype, 1, 99, 98},
		{sarifSampleVEX, 1, sarifNginxTrivy, 1, 99, 98},
		{sarifSampleVEX, 1, sarifNginxSnyk, 2, 65, 64},

		// Two OpenVEX statements, filters one vuln
		{sarifSampleHist, 2, sarifNginxGrype, 1, 99, 98},
		{sarifSampleHist, 2, sarifNginxTrivy, 1, 99, 98},
		{sarifSampleHist, 2, sarifNginxSnyk, 2, 65, 64},

		// Two OpenVEX statements, filters two vuln
		{sarifSample2Vulns, 2, sarifNginxGrype, 1, 99, 96},
		{sarifSample2Vulns, 2, sarifNginxTrivy, 1, 99, 96},
		{sarifSample2Vulns, 2, sarifNginxSnyk, 2, 65, 63},
	} {
		vexDoc, err := vex.Open(tc.vexDoc)
		require.NoError(t, err)
		require.NotNil(t, vexDoc)
		require.Len(t, vexDoc.Statements, tc.lenStatements)

		report, err := sarif.Open(tc.sarifDoc)
		require.NoError(t, err)
		require.NotNil(t, report)
		require.Len(t, report.Runs, tc.lenRuns)
		require.Len(t, report.Runs[0].Results, tc.lenResults)

		newReport, err := impl.ApplySingleVEX(report, vexDoc)
		require.NoError(t, err)
		require.Len(t, newReport.Runs, tc.lenRuns)
		require.Len(t, newReport.Runs[0].Results, tc.lenAfterFilter)
	}
}
