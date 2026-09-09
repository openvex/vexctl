/*
Copyright 2022 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package ctl

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseAttachMethod(t *testing.T) {
	for _, tc := range []struct {
		in       string
		expected AttachMethod
		mustErr  bool
	}{
		{"", AttachMethodReferrers, false},
		{"referrers", AttachMethodReferrers, false},
		{"REFERRERS", AttachMethodReferrers, false},
		{"legacy", AttachMethodLegacy, false},
		{"cosign", "", true},
	} {
		m, err := ParseAttachMethod(tc.in)
		if tc.mustErr {
			require.Error(t, err, tc.in)
			continue
		}
		require.NoError(t, err, tc.in)
		require.Equal(t, tc.expected, m, tc.in)
	}
}

func TestImageRepository(t *testing.T) {
	for _, method := range []AttachMethod{AttachMethodReferrers, AttachMethodLegacy} {
		repo, err := imageRepository("localhost:5000/test/image:latest", method)
		require.NoError(t, err, method)
		require.NotNil(t, repo, method)
	}

	_, err := imageRepository("not a reference", AttachMethodReferrers)
	require.Error(t, err)

	_, err = imageRepository("localhost:5000/test/image:latest", AttachMethod("cosign"))
	require.Error(t, err)
}
