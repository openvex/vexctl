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

func TestMerge(t *testing.T) {
	doc1, err := vex.Load("testdata/document1.vex.json")
	require.NoError(t, err)
	doc2, err := vex.Load("testdata/document1.vex.json")
	require.NoError(t, err)

	impl := defaultVexCtlImplementation{}
	for _, tc := range []struct {
		opts        MergeOptions
		docs        []*vex.VEX
		expectedDoc *vex.VEX
		shouldErr   bool
	}{
		// CeZero docs should fail
		{
			opts:        MergeOptions{},
			docs:        []*vex.VEX{},
			expectedDoc: &vex.VEX{},
			shouldErr:   true,
		},
		// One doc results in the same doc
		{
			opts:        MergeOptions{},
			docs:        []*vex.VEX{doc1},
			expectedDoc: doc1,
			shouldErr:   false,
		},
		// Two docs, as they are
		{
			opts: MergeOptions{},
			docs: []*vex.VEX{doc1, doc2},
			expectedDoc: &vex.VEX{
				Metadata: vex.Metadata{},
				Statements: []vex.Statement{
					doc1.Statements[0],
					doc2.Statements[0],
				},
			},
			shouldErr: false,
		},
	} {
		doc, err := impl.Merge(tc.opts, tc.docs)
		if tc.shouldErr {
			require.Error(t, err)
			continue
		}

		// Check doc
		require.Len(t, doc.Statements, len(tc.expectedDoc.Statements))
		require.Equal(t, doc.Statements, tc.expectedDoc.Statements)
	}
}
