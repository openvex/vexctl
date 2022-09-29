package ctl

import (
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/vex/pkg/sarif"
	"chainguard.dev/vex/pkg/vex"
)

func TestVexReport(t *testing.T) {
	vexDoc, err := vex.OpenJSON("testdata/test.vex.json")
	require.NoError(t, err)
	require.NotNil(t, vexDoc)
	require.Len(t, vexDoc.Statements, 2)

	report, err := sarif.Open("testdata/nginx.sarif.json")
	require.NoError(t, err)
	require.NotNil(t, report)
	require.Len(t, report.Runs, 1)
	require.Len(t, report.Runs[0].Results, 123)

	impl := defaultVexCtlImplementation{}
	newReport, err := impl.ApplySingleVEX(report, vexDoc)
	require.NoError(t, err)
	require.Len(t, newReport.Runs, 1)
	require.Len(t, newReport.Runs[0].Results, 122)
}
