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
		{"testdata/sarif/sample.openvex.json", 1, "testdata/sarif/nginx-grype.sarif.json", 1, 99, 98},
		{"testdata/sarif/sample.openvex.json", 1, "testdata/sarif/nginx-trivy.sarif.json", 1, 99, 98},
		{"testdata/sarif/sample.openvex.json", 1, "testdata/sarif/nginx-snyk.sarif.json", 2, 65, 64},

		// Two OpenVEX statements, filters one vuln
		{"testdata/sarif/sample-history.json", 2, "testdata/sarif/nginx-grype.sarif.json", 1, 99, 98},
		{"testdata/sarif/sample-history.json", 2, "testdata/sarif/nginx-trivy.sarif.json", 1, 99, 98},
		{"testdata/sarif/sample-history.json", 2, "testdata/sarif/nginx-snyk.sarif.json", 2, 65, 64},

		// Two OpenVEX statements, filters two vuln
		{"testdata/sarif/sample-2vulns.json", 2, "testdata/sarif/nginx-grype.sarif.json", 1, 99, 96},
		{"testdata/sarif/sample-2vulns.json", 2, "testdata/sarif/nginx-trivy.sarif.json", 1, 99, 96},
		{"testdata/sarif/sample-2vulns.json", 2, "testdata/sarif/nginx-snyk.sarif.json", 2, 65, 63},
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
