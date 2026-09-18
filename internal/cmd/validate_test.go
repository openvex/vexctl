/*
Copyright 2026 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/openvex/go-vex/pkg/validate"
)

// warningDoc parses and asserts something, but its @id is not an IRI, so
// validating it produces a warning and no errors.
const warningDoc = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "merged-vex-abc123",
  "author": "Test Author",
  "timestamp": "2023-08-16T19:55:22Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {"name": "CVE-2023-12345"},
      "products": [{"@id": "pkg:apk/wolfi/git@2.39.0"}],
      "status": "fixed"
    }
  ]
}`

// invalidDoc has a statement with a status of "affected" and no action
// statement, which the spec requires.
const invalidDoc = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/test/vex-test",
  "author": "Test Author",
  "timestamp": "2023-08-16T19:55:22Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {"name": "CVE-2023-12345"},
      "products": [{"@id": "pkg:apk/wolfi/git@2.39.0"}],
      "status": "affected"
    }
  ]
}`

// runValidate runs the validate subcommand and returns what it printed. Each
// run builds its own command, so runs share no flag state and can go in
// parallel.
func runValidate(t *testing.T, args ...string) (string, error) {
	t.Helper()

	out := &bytes.Buffer{}
	root := &cobra.Command{Use: appname}
	root.SetOut(out)
	root.SetErr(out)
	addValidate(root)

	root.SetArgs(append([]string{"validate"}, args...))
	err := root.Execute()

	return out.String(), err
}

func writeDoc(t *testing.T, dir, name, content string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestValidateCommand(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	valid := writeDoc(t, dir, "valid.openvex.json", sampleDoc)
	warns := writeDoc(t, dir, "warns.openvex.json", warningDoc)
	invalid := writeDoc(t, dir, "invalid.openvex.json", invalidDoc)

	t.Run("a valid document passes", func(t *testing.T) {
		t.Parallel()
		out, err := runValidate(t, valid)
		require.NoError(t, err)
		require.Contains(t, out, "1 document checked, 1 valid, 0 invalid")
	})

	t.Run("an invalid document fails", func(t *testing.T) {
		t.Parallel()
		out, err := runValidate(t, invalid)
		require.Error(t, err)
		require.Contains(t, err.Error(), "1 document is invalid")
		require.Contains(t, out, "action statement must be set")
	})

	t.Run("warnings alone do not fail", func(t *testing.T) {
		t.Parallel()
		out, err := runValidate(t, warns)
		require.NoError(t, err)
		require.Contains(t, out, "is not an IRI")
		require.Contains(t, out, "1 document checked, 1 valid, 0 invalid")
	})

	t.Run("strict turns warnings into a failure", func(t *testing.T) {
		t.Parallel()
		_, err := runValidate(t, "--strict", warns)
		require.Error(t, err)
		require.Contains(t, err.Error(), "--strict")
	})

	t.Run("strict passes a document with no findings", func(t *testing.T) {
		t.Parallel()
		_, err := runValidate(t, "--strict", valid)
		require.NoError(t, err)
	})

	t.Run("every file is checked, not just the first", func(t *testing.T) {
		t.Parallel()
		out, err := runValidate(t, invalid, valid, warns)
		require.Error(t, err)
		require.Contains(t, out, "3 documents checked, 2 valid, 1 invalid")
		for _, path := range []string{invalid, valid, warns} {
			require.Contains(t, out, path)
		}
	})

	t.Run("a missing file is a finding, not a crash", func(t *testing.T) {
		t.Parallel()
		out, err := runValidate(t, filepath.Join(dir, "absent.json"))
		require.Error(t, err)
		require.Contains(t, out, "reading document")
	})

	t.Run("no arguments is a usage error", func(t *testing.T) {
		t.Parallel()
		_, err := runValidate(t)
		require.Error(t, err)
	})

	t.Run("an unknown format is rejected", func(t *testing.T) {
		t.Parallel()
		_, err := runValidate(t, "--format=yaml", valid)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid output format")
	})

	t.Run("the json report holds every finding", func(t *testing.T) {
		t.Parallel()
		out, err := runValidate(t, "--format=json", invalid, valid)
		require.Error(t, err)

		report := jsonReport{}
		require.NoError(t, json.Unmarshal([]byte(out), &report))

		require.False(t, report.Valid)
		require.Equal(t, 2, report.Summary.Files)
		require.Equal(t, 1, report.Summary.Invalid)
		require.Equal(t, 1, report.Summary.Errors)
		require.Len(t, report.Files, 2)
		require.Equal(t, invalid, report.Files[0].File)
		require.Equal(t, validate.CheckStatus, report.Files[0].Findings[0].Check)
		require.Empty(t, report.Files[1].Findings)
	})
}

func TestWriteTextReport(t *testing.T) {
	t.Parallel()

	results := []*validate.Result{
		{File: "clean.json", Findings: []validate.Finding{}},
		{File: "dirty.json", Findings: []validate.Finding{
			{Severity: validate.SeverityError, Check: validate.CheckPurl, Path: "statements[0]", Message: "bad purl"},
			{Severity: validate.SeverityWarning, Check: validate.CheckIRI, Path: "@id", Message: "not an IRI"},
		}},
	}

	out := &bytes.Buffer{}
	require.NoError(t, writeTextReport(out, results))

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	require.Equal(t, []string{
		"clean.json: ok",
		"dirty.json: 1 error, 1 warning",
		"  error [purl] statements[0]: bad purl",
		"  warning [iri] @id: not an IRI",
		"",
		"2 documents checked, 1 valid, 1 invalid (1 error, 1 warning)",
	}, lines)
}

func TestValidationError(t *testing.T) {
	t.Parallel()

	clean := &validate.Result{File: "a.json"}

	warned := &validate.Result{File: "b.json", Findings: []validate.Finding{
		{Severity: validate.SeverityWarning, Check: validate.CheckIRI, Message: "not an IRI"},
	}}

	failed := &validate.Result{File: "c.json", Findings: []validate.Finding{
		{Severity: validate.SeverityError, Check: validate.CheckPurl, Message: "bad purl"},
	}}

	for _, tc := range []struct {
		name    string
		results []*validate.Result
		strict  bool
		wantErr string
	}{
		{name: "nothing to report", results: []*validate.Result{clean}},
		{name: "warnings are tolerated", results: []*validate.Result{warned}},
		{
			name: "warnings fail under strict", results: []*validate.Result{warned}, strict: true,
			wantErr: "1 warning was reported and --strict is set",
		},
		{
			name: "errors always fail", results: []*validate.Result{failed},
			wantErr: "1 document is invalid (1 error, 0 warnings)",
		},
		{
			name: "several invalid documents are counted", results: []*validate.Result{failed, failed, clean},
			wantErr: "2 documents are invalid (2 errors, 0 warnings)",
		},
		{
			name: "strict does not mask errors", results: []*validate.Result{failed, warned}, strict: true,
			wantErr: "1 document is invalid (1 error, 1 warning)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := validationError(tc.results, tc.strict)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tc.wantErr)
		})
	}
}

func TestPluralize(t *testing.T) {
	t.Parallel()

	require.Equal(t, "0 errors", pluralize(0, "error", "errors"))
	require.Equal(t, "1 error", pluralize(1, "error", "errors"))
	require.Equal(t, "2 errors", pluralize(2, "error", "errors"))
}
