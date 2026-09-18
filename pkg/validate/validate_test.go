/*
Copyright 2026 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package validate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openvex/go-vex/pkg/vex"
)

// validDocument is the document every test case starts from: the smallest
// OpenVEX document that produces no findings at all.
func validDocument() string {
	return fmt.Sprintf(`{
  "@context": %q,
  "@id": "https://openvex.dev/docs/public/vex-test",
  "author": "Wolfi J Inkinson",
  "role": "Document Creator",
  "timestamp": "2023-12-04T21:55:19Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {"name": "CVE-2014-123456"},
      "products": [{"@id": "pkg:apk/distro/git@2.39.0-r1?arch=x86_64"}],
      "status": "fixed"
    }
  ]
}`, vex.ContextLocator())
}

// The paths the tables below point at over and over.
const (
	stmt0        = "statements[0]"
	stmt0Product = stmt0 + ".products[0]"
	stmt0Vuln    = stmt0 + ".vulnerability"
)

// expected is a finding a test case requires, matched on everything but its
// message so that rewording a message does not break the tests.
type expected struct {
	severity Severity
	check    string
	path     string
}

func requireFindings(t *testing.T, res *Result, want []expected) {
	t.Helper()

	got := make([]expected, 0, len(res.Findings))
	for i := range res.Findings {
		got = append(got, expected{
			severity: res.Findings[i].Severity,
			check:    res.Findings[i].Check,
			path:     res.Findings[i].Path,
		})
	}

	require.Equal(t, want, got, "findings were:\n%s", render(res))

	// Every finding must say something, whatever it says.
	for i := range res.Findings {
		require.NotEmpty(t, res.Findings[i].Message, "finding %d has no message", i)
	}
}

func render(res *Result) string {
	lines := make([]string, 0, len(res.Findings))
	for i := range res.Findings {
		lines = append(lines, "  "+res.Findings[i].String())
	}
	return strings.Join(lines, "\n")
}

func TestDocumentValid(t *testing.T) {
	t.Parallel()

	res := Document([]byte(validDocument()))
	requireFindings(t, res, []expected{})
	require.True(t, res.Valid())
	require.Equal(t, 0, res.Errors())
	require.Equal(t, 0, res.Warnings())
}

func TestDocumentJSON(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		doc  string
		want []expected
	}{
		{
			name: "empty file",
			doc:  "   \n  ",
			want: []expected{{SeverityError, CheckJSON, ""}},
		},
		{
			name: "syntax error",
			doc:  `{"@context": "x",}`,
			want: []expected{{SeverityError, CheckJSON, ""}},
		},
		{
			name: "not an object",
			doc:  `["a", "b"]`,
			want: []expected{{SeverityError, CheckJSON, ""}},
		},
		{
			name: "trailing document",
			doc:  validDocument() + "\n{}",
			want: []expected{
				{SeverityError, CheckJSON, ""},
				{SeverityWarning, CheckJSON, ""},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			requireFindings(t, Document([]byte(tc.doc)), tc.want)
		})
	}
}

func TestDocumentContext(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		doc  string
		want []expected
	}{
		{
			name: "current version validates fully",
			doc:  validDocument(),
			want: []expected{},
		},
		{
			name: "older spec version stops the run",
			doc:  `{"@context": "https://openvex.dev/ns/v0.0.1", "vulnerability": "nonsense"}`,
			want: []expected{{SeverityWarning, CheckContext, fieldContext}},
		},
		{
			name: "unversioned context is the first spec version",
			doc:  `{"@context": "https://openvex.dev/ns"}`,
			want: []expected{{SeverityWarning, CheckContext, fieldContext}},
		},
		{
			name: "a foreign context is not OpenVEX",
			doc:  `{"@context": "https://example.com/ns/v1"}`,
			want: []expected{{SeverityError, CheckContext, fieldContext}},
		},
		{
			name: "a context of the wrong type",
			doc:  `{"@context": 12}`,
			want: []expected{{SeverityError, CheckFieldType, fieldContext}},
		},
		{
			name: "CSAF is reported as such",
			doc:  `{"document": {"csaf_version": "2.0"}}`,
			want: []expected{{SeverityError, CheckContext, ""}},
		},
		{
			name: "a missing context does not stop the run",
			doc:  `{"@id": "https://example.com/v", "author": "A", "timestamp": "2023-12-04T21:55:19Z", "version": 1, "statements": []}`,
			want: []expected{
				{SeverityError, CheckRequired, fieldContext},
				{SeverityWarning, CheckStatements, fieldStatements},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			requireFindings(t, Document([]byte(tc.doc)), tc.want)
		})
	}
}

func TestDocumentSchema(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		doc  string
		want []expected
	}{
		{
			name: "required document fields are reported once each",
			doc:  fmt.Sprintf(`{"@context": %q}`, vex.ContextLocator()),
			want: []expected{
				{SeverityError, CheckRequired, fieldID},
				{SeverityError, CheckRequired, "author"},
				{SeverityError, CheckRequired, fieldTimestamp},
				{SeverityError, CheckRequired, fieldVersion},
				{SeverityError, CheckRequired, fieldStatements},
			},
		},
		{
			name: "an empty required field is not a present one",
			doc:  replace(t, `"author": "Wolfi J Inkinson"`, `"author": ""`),
			want: []expected{{SeverityError, CheckRequired, "author"}},
		},
		{
			name: "misspelled fields are reported, not dropped",
			doc:  replace(t, `"status": "fixed"`, `"status": "fixed", "justifcation": "component_not_present"`),
			want: []expected{{SeverityWarning, CheckUnknownField, stmt0 + ".justifcation"}},
		},
		{
			name: "unknown document fields",
			doc:  replace(t, `"version": 1`, `"version": 1, "statments": []`),
			want: []expected{{SeverityWarning, CheckUnknownField, "statments"}},
		},
		{
			name: "a string where a number belongs",
			doc:  replace(t, `"version": 1`, `"version": "1"`),
			want: []expected{
				{SeverityError, CheckFieldType, fieldVersion},
				{SeverityWarning, CheckJSON, ""},
			},
		},
		{
			name: "a fractional version",
			doc:  replace(t, `"version": 1`, `"version": 1.5`),
			want: []expected{
				{SeverityError, CheckFieldType, fieldVersion},
				{SeverityWarning, CheckJSON, ""},
			},
		},
		{
			name: "a timestamp that is not RFC3339",
			doc:  replace(t, `"timestamp": "2023-12-04T21:55:19Z"`, `"timestamp": "4 December 2023"`),
			want: []expected{
				{SeverityError, CheckFieldType, fieldTimestamp},
				{SeverityWarning, CheckJSON, ""},
			},
		},
		{
			name: "statements must be a list",
			doc: strings.Replace(
				validDocument(),
				`"statements": [`, `"statements": {"first": [`, 1,
			) + "}",
			want: []expected{
				{SeverityError, CheckFieldType, fieldStatements},
				{SeverityWarning, CheckJSON, ""},
			},
		},
		{
			name: "products hold objects, not strings",
			doc:  replace(t, `"products": [{"@id": "pkg:apk/distro/git@2.39.0-r1?arch=x86_64"}]`, `"products": ["pkg:apk/distro/git@2.39.0-r1"]`),
			want: []expected{
				{SeverityError, CheckFieldType, stmt0Product},
				{SeverityWarning, CheckJSON, ""},
			},
		},
		{
			name: "aliases hold strings",
			doc:  replace(t, `"name": "CVE-2014-123456"`, `"name": "CVE-2014-123456", "aliases": [12]`),
			want: []expected{
				{SeverityError, CheckFieldType, stmt0Vuln + ".aliases[0]"},
				{SeverityWarning, CheckJSON, ""},
			},
		},
		{
			name: "identifiers hold strings",
			doc:  replace(t, `"@id": "pkg:apk/distro/git@2.39.0-r1?arch=x86_64"`, `"@id": "pkg:apk/distro/git@2.39.0-r1?arch=x86_64", "identifiers": {"purl": ["a"]}`),
			want: []expected{
				{SeverityError, CheckFieldType, stmt0Product + ".identifiers.purl"},
				{SeverityWarning, CheckJSON, ""},
			},
		},
		{
			name: "spec fields vexctl drops are warned about",
			doc:  replace(t, `"status": "fixed"`, `"status": "fixed", "supplier": "ACME", "version": 2`),
			want: []expected{
				{SeverityWarning, CheckDroppedField, stmt0 + ".supplier"},
				{SeverityWarning, CheckDroppedField, stmt0 + ".version"},
			},
		},
		{
			name: "document supplier was removed from the spec",
			doc:  replace(t, `"version": 1`, `"version": 1, "supplier": "ACME"`),
			want: []expected{{SeverityWarning, CheckDroppedField, "supplier"}},
		},
		{
			name: "subcomponents cannot nest",
			doc: replace(t,
				`{"@id": "pkg:apk/distro/git@2.39.0-r1?arch=x86_64"}`,
				`{"@id": "pkg:apk/distro/git@2.39.0-r1", "subcomponents": [{"@id": "pkg:generic/zlib@1.0", "subcomponents": []}]}`,
			),
			want: []expected{{SeverityWarning, CheckUnknownField, stmt0Product + ".subcomponents[0].subcomponents"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			requireFindings(t, Document([]byte(tc.doc)), tc.want)
		})
	}
}

func TestDocumentMetadata(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		doc  string
		want []expected
	}{
		{
			name: "a document id that is not an IRI",
			doc:  replace(t, `"@id": "https://openvex.dev/docs/public/vex-test"`, `"@id": "merged-vex-abc123"`),
			want: []expected{{SeverityWarning, CheckIRI, fieldID}},
		},
		{
			name: "a purl is a valid document id",
			doc:  replace(t, `"@id": "https://openvex.dev/docs/public/vex-test"`, `"@id": "pkg:apk/distro/git@2.39.0-r1"`),
			want: []expected{},
		},
		{
			name: "documents start at version 1",
			doc:  replace(t, `"version": 1`, `"version": 0`),
			want: []expected{{SeverityError, CheckVersion, fieldVersion}},
		},
		{
			name: "last_updated cannot precede the timestamp",
			doc:  replace(t, `"version": 1`, `"version": 1, "last_updated": "2022-01-01T00:00:00Z"`),
			want: []expected{{SeverityError, CheckTimestamp, "last_updated"}},
		},
		{
			name: "a document with no statements says nothing",
			doc:  replace(t, `"statements": [`, `"statements": [] , "unused": [`),
			want: []expected{
				{SeverityWarning, CheckUnknownField, "unused"},
				{SeverityWarning, CheckStatements, fieldStatements},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			requireFindings(t, Document([]byte(tc.doc)), tc.want)
		})
	}
}

func TestDocumentStatements(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		doc  string
		want []expected
	}{
		{
			name: "not_affected needs a justification or an impact statement",
			doc:  replace(t, `"status": "fixed"`, `"status": "not_affected"`),
			want: []expected{{SeverityError, CheckStatus, stmt0}},
		},
		{
			name: "an impact statement stands in for a justification",
			doc:  replace(t, `"status": "fixed"`, `"status": "not_affected", "impact_statement": "the code is never reached"`),
			want: []expected{},
		},
		{
			name: "affected needs an action statement",
			doc:  replace(t, `"status": "fixed"`, `"status": "affected"`),
			want: []expected{{SeverityError, CheckStatus, stmt0}},
		},
		{
			name: "an unknown status",
			doc:  replace(t, `"status": "fixed"`, `"status": "not_afected"`),
			want: []expected{{SeverityError, CheckStatus, stmt0}},
		},
		{
			name: "a justification that does not belong to a fixed statement",
			doc:  replace(t, `"status": "fixed"`, `"status": "fixed", "justification": "component_not_present"`),
			want: []expected{{SeverityError, CheckStatus, stmt0}},
		},
		{
			name: "an invalid justification label is caught whatever the status",
			doc:  replace(t, `"status": "fixed"`, `"status": "not_affected", "justification": "i_said_so"`),
			want: []expected{
				{SeverityError, CheckStatus, stmt0},
				{SeverityError, CheckJustification, stmt0 + ".justification"},
			},
		},
		{
			name: "a statement without a vulnerability",
			doc:  replace(t, `"vulnerability": {"name": "CVE-2014-123456"}`, `"vulnerability": {"description": "something bad"}`),
			want: []expected{
				{SeverityError, CheckRequired, stmt0Vuln + ".name"},
				{SeverityError, CheckVulnerability, stmt0Vuln + ".name"},
			},
		},
		{
			name: "a vulnerability id that is not an IRI",
			doc:  replace(t, `"name": "CVE-2014-123456"`, `"@id": "CVE-2014-123456", "name": "CVE-2014-123456"`),
			want: []expected{{SeverityWarning, CheckIRI, stmt0Vuln + ".@id"}},
		},
		{
			name: "aliases that repeat",
			doc: replace(t, `"name": "CVE-2014-123456"`,
				`"name": "CVE-2014-123456", "aliases": ["CVE-2014-123456", "GHSA-1", "GHSA-1", ""]`),
			want: []expected{
				{SeverityWarning, CheckVulnerability, stmt0Vuln + ".aliases[0]"},
				{SeverityWarning, CheckVulnerability, stmt0Vuln + ".aliases[2]"},
				{SeverityError, CheckVulnerability, stmt0Vuln + ".aliases[3]"},
			},
		},
		{
			name: "a statement with no products",
			doc:  replace(t, `"products": [{"@id": "pkg:apk/distro/git@2.39.0-r1?arch=x86_64"}]`, `"products": []`),
			want: []expected{{SeverityError, CheckProduct, stmt0 + ".products"}},
		},
		{
			name: "a statement that cannot be placed in time",
			doc: strings.NewReplacer(
				`"timestamp": "2023-12-04T21:55:19Z",`, "",
				`"role": "Document Creator",`, "",
			).Replace(validDocument()),
			want: []expected{
				{SeverityError, CheckRequired, fieldTimestamp},
				{SeverityError, CheckTimestamp, stmt0 + ".timestamp"},
			},
		},
		{
			name: "a statement inherits the document timestamp",
			doc:  replace(t, `"status": "fixed"`, `"status": "fixed", "last_updated": "2024-01-01T00:00:00Z"`),
			want: []expected{},
		},
		{
			name: "a statement last updated before it was made",
			doc: replace(t, `"status": "fixed"`,
				`"status": "fixed", "timestamp": "2024-01-01T00:00:00Z", "last_updated": "2023-01-01T00:00:00Z"`),
			want: []expected{{SeverityError, CheckTimestamp, stmt0 + ".last_updated"}},
		},
		{
			name: "last_updated is compared against the inherited timestamp",
			doc:  replace(t, `"status": "fixed"`, `"status": "fixed", "last_updated": "2022-01-01T00:00:00Z"`),
			want: []expected{{SeverityError, CheckTimestamp, stmt0 + ".last_updated"}},
		},
		{
			name: "an action statement timestamp with no action statement",
			doc:  replace(t, `"status": "fixed"`, `"status": "fixed", "action_statement_timestamp": "2024-01-01T00:00:00Z"`),
			want: []expected{{SeverityWarning, CheckTimestamp, stmt0 + ".action_statement_timestamp"}},
		},
		{
			name: "statement ids must be unique",
			doc: replace(t, `"vulnerability": {"name": "CVE-2014-123456"}`,
				`"@id": "https://example.com/s/1", "vulnerability": {"name": "CVE-2014-123456"}`),
			want: []expected{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			requireFindings(t, Document([]byte(tc.doc)), tc.want)
		})
	}
}

func TestDocumentRepeatedStatementID(t *testing.T) {
	t.Parallel()

	doc := fmt.Sprintf(`{
  "@context": %q,
  "@id": "https://openvex.dev/docs/public/vex-test",
  "author": "Wolfi J Inkinson",
  "timestamp": "2023-12-04T21:55:19Z",
  "version": 1,
  "statements": [
    {
      "@id": "https://example.com/statements/1",
      "vulnerability": {"name": "CVE-2014-123456"},
      "products": [{"@id": "pkg:apk/distro/git@2.39.0-r1"}],
      "status": "fixed"
    },
    {
      "@id": "https://example.com/statements/1",
      "vulnerability": {"name": "CVE-2014-999999"},
      "products": [{"@id": "pkg:apk/distro/git@2.39.0-r1"}],
      "status": "fixed"
    }
  ]
}`, vex.ContextLocator())

	requireFindings(t, Document([]byte(doc)), []expected{
		{SeverityError, CheckStatements, "statements[1].@id"},
	})
}

func TestDocumentComponents(t *testing.T) {
	t.Parallel()

	// product replaces the single product of the valid document.
	product := func(t *testing.T, body string) string {
		t.Helper()
		return replace(t, `{"@id": "pkg:apk/distro/git@2.39.0-r1?arch=x86_64"}`, body)
	}

	for _, tc := range []struct {
		name string
		doc  string
		want []expected
	}{
		{
			name: "a product with no way to address it",
			doc:  product(t, `{"supplier": "ACME"}`),
			want: []expected{{SeverityError, CheckProduct, stmt0Product}},
		},
		{
			name: "hashes alone can address a product",
			doc:  product(t, `{"hashes": {"sha-256": "`+strings.Repeat("a", 64)+`"}}`),
			want: []expected{},
		},
		{
			name: "a malformed package url",
			doc:  product(t, `{"@id": "pkg:not a purl"}`),
			want: []expected{{SeverityError, CheckPurl, stmt0Product + ".@id"}},
		},
		{
			name: "a package url type in uppercase",
			doc:  product(t, `{"@id": "pkg:APK/distro/git@2.39.0-r1"}`),
			want: []expected{{SeverityWarning, CheckPurl, stmt0Product + ".@id"}},
		},
		{
			name: "a product id that is neither an identifier nor an IRI",
			doc:  product(t, `{"@id": "my-product"}`),
			want: []expected{{SeverityWarning, CheckIRI, stmt0Product + ".@id"}},
		},
		{
			name: "a malformed purl identifier",
			doc:  product(t, `{"identifiers": {"purl": "git@2.39.0"}}`),
			want: []expected{{SeverityError, CheckPurl, stmt0Product + ".identifiers.purl"}},
		},
		{
			name: "an identifier type OpenVEX does not define",
			doc:  product(t, `{"identifiers": {"swid": "acme.com/git"}}`),
			want: []expected{{SeverityWarning, CheckIdentifier, stmt0Product + ".identifiers.swid"}},
		},
		{
			name: "an empty identifier",
			doc:  product(t, `{"identifiers": {"purl": ""}}`),
			want: []expected{{SeverityError, CheckIdentifier, stmt0Product + ".identifiers.purl"}},
		},
		{
			name: "a short CPE 2.3",
			doc:  product(t, `{"identifiers": {"cpe23": "cpe:2.3:a:apache:log4j"}}`),
			want: []expected{{SeverityError, CheckCPE, stmt0Product + ".identifiers.cpe23"}},
		},
		{
			name: "a complete CPE 2.3",
			doc:  product(t, `{"identifiers": {"cpe23": "cpe:2.3:a:apache:log4j:2.4:*:*:*:*:*:*:*"}}`),
			want: []expected{},
		},
		{
			name: "a CPE 2.2 in a CPE 2.3 field",
			doc:  product(t, `{"identifiers": {"cpe23": "cpe:/a:apache:log4j:2.4"}}`),
			want: []expected{{SeverityError, CheckCPE, stmt0Product + ".identifiers.cpe23"}},
		},
		{
			name: "a CPE 2.2",
			doc:  product(t, `{"identifiers": {"cpe22": "cpe:/a:apache:log4j:2.4"}}`),
			want: []expected{},
		},
		{
			name: "an overlong CPE 2.2",
			doc:  product(t, `{"identifiers": {"cpe22": "cpe:/a:b:c:d:e:f:g:h"}}`),
			want: []expected{{SeverityError, CheckCPE, stmt0Product + ".identifiers.cpe22"}},
		},
		{
			name: "a CPE as the product id",
			doc:  product(t, `{"@id": "cpe:2.3:a:apache:log4j"}`),
			want: []expected{{SeverityError, CheckCPE, stmt0Product + ".@id"}},
		},
		{
			name: "a hash of the wrong length",
			doc:  product(t, `{"hashes": {"sha-256": "abc123"}}`),
			want: []expected{{SeverityError, CheckHash, stmt0Product + ".hashes.sha-256"}},
		},
		{
			name: "a hash that is not hexadecimal",
			doc:  product(t, `{"hashes": {"sha-256": "`+strings.Repeat("z", 64)+`"}}`),
			want: []expected{{SeverityError, CheckHash, stmt0Product + ".hashes.sha-256"}},
		},
		{
			name: "an empty hash",
			doc:  product(t, `{"hashes": {"sha-512": ""}}`),
			want: []expected{{SeverityError, CheckHash, stmt0Product + ".hashes.sha-512"}},
		},
		{
			name: "an algorithm OpenVEX does not name",
			doc:  product(t, `{"hashes": {"sha-9000": "abcdef"}}`),
			want: []expected{{SeverityWarning, CheckHash, stmt0Product + ".hashes.sha-9000"}},
		},
		{
			name: "subcomponents are checked like products",
			doc: product(t, `{
				"@id": "pkg:apk/distro/git@2.39.0-r1",
				"subcomponents": [{"@id": "pkg:bad purl"}, {}]
			}`),
			want: []expected{
				{SeverityError, CheckPurl, stmt0Product + ".subcomponents[0].@id"},
				{SeverityError, CheckProduct, stmt0Product + ".subcomponents[1]"},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			requireFindings(t, Document([]byte(tc.doc)), tc.want)
		})
	}
}

// TestFindingOrder checks that findings of the same statement stay together
// and that statements are reported in the order they appear.
func TestFindingOrder(t *testing.T) {
	t.Parallel()

	statements := make([]string, 0, 12)
	for i := 0; i < 12; i++ {
		statements = append(statements, fmt.Sprintf(`{
      "vulnerability": {"name": "CVE-2014-%06d"},
      "products": [{"@id": "pkg:bad purl"}],
      "status": "fixed",
      "typo": true
    }`, i))
	}

	doc := fmt.Sprintf(`{
  "@context": %q,
  "@id": "merged-vex-abc",
  "author": "Wolfi J Inkinson",
  "timestamp": "2023-12-04T21:55:19Z",
  "version": 1,
  "statements": [%s]
}`, vex.ContextLocator(), strings.Join(statements, ","))

	res := Document([]byte(doc))

	paths := make([]string, 0, len(res.Findings))
	for i := range res.Findings {
		paths = append(paths, res.Findings[i].Path)
	}

	want := []string{"@id"}
	for i := 0; i < 12; i++ {
		want = append(want,
			fmt.Sprintf("statements[%d].products[0].@id", i),
			fmt.Sprintf("statements[%d].typo", i),
		)
	}
	require.Equal(t, want, paths, "findings were:\n%s", render(res))
}

func TestFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	path := filepath.Join(dir, "valid.openvex.json")
	require.NoError(t, os.WriteFile(path, []byte(validDocument()), 0o600))

	res := File(path)
	require.Equal(t, path, res.File)
	require.True(t, res.Valid())
	require.Empty(t, res.Findings)

	missing := File(filepath.Join(dir, "nope.json"))
	require.False(t, missing.Valid())
	requireFindings(t, missing, []expected{{SeverityError, CheckFile, ""}})
}

func TestResultCounts(t *testing.T) {
	t.Parallel()

	res := &Result{}
	require.True(t, res.Valid(), "a result with no findings is valid")

	res.warnf(CheckIRI, "@id", "a warning")
	require.True(t, res.Valid(), "warnings do not invalidate a document")
	require.Equal(t, 1, res.Warnings())

	res.errorf(CheckStatus, stmt0, "an error")
	require.False(t, res.Valid())
	require.Equal(t, 1, res.Errors())
	require.Equal(t, 1, res.Warnings())
}

func TestFindingString(t *testing.T) {
	t.Parallel()

	withPath := Finding{Severity: SeverityError, Check: CheckPurl, Path: stmt0, Message: "bad purl"}
	require.Equal(t, "error [purl] statements[0]: bad purl", withPath.String())

	withoutPath := Finding{Severity: SeverityWarning, Check: CheckJSON, Message: "odd file"}
	require.Equal(t, "warning [json]: odd file", withoutPath.String())
}

func TestPosition(t *testing.T) {
	t.Parallel()

	data := []byte("{\n  \"a\": 1,\n  \"b\"\n}")
	for _, tc := range []struct {
		offset     int64
		line, col  int
		nameOfCase string
	}{
		{offset: 0, line: 1, col: 1, nameOfCase: "start of file"},
		{offset: 1, line: 1, col: 2, nameOfCase: "before the first newline"},
		{offset: 2, line: 2, col: 1, nameOfCase: "start of the second line"},
		{offset: 11, line: 2, col: 10, nameOfCase: "end of the second line"},
		{offset: 9999, line: 4, col: 2, nameOfCase: "past the end of the file"},
	} {
		t.Run(tc.nameOfCase, func(t *testing.T) {
			t.Parallel()
			line, col := position(data, tc.offset)
			require.Equal(t, tc.line, line)
			require.Equal(t, tc.col, col)
		})
	}
}

// replace rewrites a fragment of the valid document, failing the test when the
// fragment is not there so that a reworded fixture cannot silently pass.
func replace(t *testing.T, old, updated string) string {
	t.Helper()

	doc := validDocument()
	require.Contains(t, doc, old, "the test fixture does not contain %q", old)
	return strings.Replace(doc, old, updated, 1)
}
