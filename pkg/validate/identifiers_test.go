/*
Copyright 2026 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package validate

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSplitCPE(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		cpe  string
		want []string
	}{
		{name: "empty", cpe: "", want: []string{""}},
		{name: "one component", cpe: "a", want: []string{"a"}},
		{name: "two components", cpe: "a:b", want: []string{"a", "b"}},
		{name: "a trailing separator leaves an empty component", cpe: "a:", want: []string{"a", ""}},
		{
			name: "a CPE 2.3 splits into thirteen components",
			cpe:  "cpe:2.3:a:apache:log4j:2.4:*:*:*:*:*:*:*",
			want: []string{"cpe", "2.3", "a", "apache", "log4j", "2.4", "*", "*", "*", "*", "*", "*", "*"},
		},
		{
			name: "an escaped colon does not separate",
			cpe:  `a:pro\:duct:b`,
			want: []string{"a", `pro\:duct`, "b"},
		},
		{
			name: "an escaped backslash before a separator",
			cpe:  `a:b\\:c`,
			want: []string{"a", `b\\`, "c"},
		},
		{
			name: "a trailing backslash escapes nothing",
			cpe:  `a:b\`,
			want: []string{"a", `b\`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, splitCPE(tc.cpe))
		})
	}
}

// TestSplitCPEEscapedColons checks that a CPE 2.3 whose components contain
// escaped colons still counts as thirteen components.
func TestSplitCPEEscapedColons(t *testing.T) {
	t.Parallel()

	cpe := `cpe:2.3:a:vendor:pro\:duct:1\:0:*:*:*:*:*:*:*`
	require.Len(t, splitCPE(cpe), cpe23Components)

	res := &Result{}
	res.checkCPE23(cpe, "p")
	require.Empty(t, res.Findings, "findings were:\n%s", render(res))
}

func TestPurlType(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		purl string
		want string
	}{
		{purl: "pkg:apk/wolfi/git@2.39.0-r1", want: "apk"},
		{purl: "pkg:APK/wolfi/git@2.39.0-r1", want: "APK"},
		{purl: "pkg://oci/nginx", want: "oci"},
		{purl: "pkg:maven", want: "maven"},
		{purl: "pkg:", want: ""},
		{purl: "pkg:oci/nginx@sha256%3Aabc", want: "oci"},
	} {
		t.Run(tc.purl, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, purlType(tc.purl))
		})
	}
}

// TestCheckCPEDispatch checks that a CPE given as a component @id is checked
// as the flavor of CPE it announces itself to be.
func TestCheckCPEDispatch(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		cpe       string
		wantCount int
	}{
		{name: "a CPE 2.3 with every component", cpe: "cpe:2.3:a:apache:log4j:2.4:*:*:*:*:*:*:*"},
		{name: "a CPE 2.2", cpe: "cpe:/a:apache:log4j:2.4"},
		{name: "a short CPE 2.3", cpe: "cpe:2.3:a:apache", wantCount: 1},
		{name: "an overlong CPE 2.2", cpe: "cpe:/a:b:c:d:e:f:g:h", wantCount: 1},
		{name: "neither flavor", cpe: "cpe:apache:log4j", wantCount: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			res := &Result{}
			res.checkCPE(tc.cpe, "p")
			require.Len(t, res.Findings, tc.wantCount, "findings were:\n%s", render(res))
		})
	}
}

func TestKnownAlgorithms(t *testing.T) {
	t.Parallel()

	names := knownAlgorithms()
	require.Len(t, names, len(hashLengths))
	require.Equal(t, "blake2b-256", names[0], "the names should come back sorted")
	require.Contains(t, names, "sha-256")
}

func TestIsHex(t *testing.T) {
	t.Parallel()

	require.True(t, isHex(""))
	require.True(t, isHex("0123456789abcdef"))
	require.True(t, isHex("ABCDEF"))
	require.False(t, isHex("g"))
	require.False(t, isHex("ab cd"))
	require.False(t, isHex("0x1234"))
}
