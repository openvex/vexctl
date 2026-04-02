/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const sampleDoc = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/test/vex-test",
  "author": "Test Author",
  "timestamp": "2023-08-16T19:55:22.076684217-06:00",
  "version": 1,
  "statements": [
    {
      "vulnerability": {"name": "CVE-2023-12345"},
      "products": [{"@id": "pkg:apk/wolfi/git@2.39.0"}],
      "status": "fixed"
    }
  ]
}`

// TestAddNoProductFlag tests that add does not error when no product is
// specified via flags (regression test for openvex/vexctl#321).
func TestAddNoProductFlag(t *testing.T) {
	dir := t.TempDir()

	docPath := filepath.Join(dir, "test.openvex.json")
	require.NoError(t, os.WriteFile(docPath, []byte(sampleDoc), 0o600))

	outPath := filepath.Join(dir, "out.openvex.json")

	rootCmd.SetArgs([]string{
		"add",
		"--file", outPath,
		docPath,
		"pkg:apk/wolfi/git@2.41.0",
		"CVE-2023-99999",
		"fixed",
	})

	err := rootCmd.Execute()
	require.NoError(t, err, "add should not fail when product is provided only as a positional argument")
}
