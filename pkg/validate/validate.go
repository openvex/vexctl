/*
Copyright 2026 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

// Package validate implements the checks behind the `vexctl validate`
// subcommand, a linter for hand written or hand edited OpenVEX documents.
//
// The validator reports two kinds of findings. Errors mark documents that
// break the OpenVEX specification and that VEX consumers may reject or read
// incorrectly. Warnings mark data that parses but is suspicious: fields vexctl
// silently drops, identifiers that are not canonical or metadata the spec no
// longer defines.
//
// Findings are reported for the whole document instead of failing on the first
// problem, so that a single run tells the author everything that needs fixing.
package validate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openvex/go-vex/pkg/vex"
)

// Severity qualifies how serious a Finding is.
type Severity string

const (
	// SeverityError marks a finding that makes a document invalid.
	SeverityError Severity = "error"

	// SeverityWarning marks a finding that does not break the document but
	// signals data that is missing, ignored or likely to be a mistake.
	SeverityWarning Severity = "warning"
)

// The check names reported in Finding.Check. They group findings by the kind
// of problem they describe so that output can be filtered or counted.
const (
	CheckFile          = "file"
	CheckJSON          = "json"
	CheckContext       = "context"
	CheckRequired      = "required"
	CheckFieldType     = "field-type"
	CheckUnknownField  = "unknown-field"
	CheckDroppedField  = "dropped-field"
	CheckIRI           = "iri"
	CheckVersion       = "version"
	CheckTimestamp     = "timestamp"
	CheckStatements    = "statements"
	CheckStatus        = "status"
	CheckJustification = "justification"
	CheckVulnerability = "vulnerability"
	CheckProduct       = "product"
	CheckIdentifier    = "identifier"
	CheckPurl          = "purl"
	CheckCPE           = "cpe"
	CheckHash          = "hash"
)

// Finding is a single problem found while validating a document.
type Finding struct {
	// Severity tells whether the finding invalidates the document.
	Severity Severity `json:"severity"`

	// Check names the kind of problem, one of the Check constants.
	Check string `json:"check"`

	// Path locates the offending value in the document, for example
	// "statements[0].products[1].@id". It is empty for findings about the
	// document as a whole, such as a JSON syntax error.
	Path string `json:"path,omitempty"`

	// Message describes the problem in a way an author can act on.
	Message string `json:"message"`
}

// String renders a finding as a single line of text.
func (f *Finding) String() string {
	if f.Path == "" {
		return fmt.Sprintf("%s [%s]: %s", f.Severity, f.Check, f.Message)
	}
	return fmt.Sprintf("%s [%s] %s: %s", f.Severity, f.Check, f.Path, f.Message)
}

// Result captures every finding produced while validating one document.
type Result struct {
	// File is the path the document was read from. It is empty when the
	// document was validated from memory.
	File string `json:"file,omitempty"`

	// Findings lists the problems found, in document order.
	Findings []Finding `json:"findings"`
}

// Errors returns the number of findings that invalidate the document.
func (r *Result) Errors() int {
	return r.count(SeverityError)
}

// Warnings returns the number of findings that do not invalidate the document.
func (r *Result) Warnings() int {
	return r.count(SeverityWarning)
}

func (r *Result) count(s Severity) int {
	total := 0
	for i := range r.Findings {
		if r.Findings[i].Severity == s {
			total++
		}
	}
	return total
}

// Valid returns true when the document produced no error findings. A valid
// document may still have warnings.
func (r *Result) Valid() bool {
	return r.Errors() == 0
}

func (r *Result) errorf(check, path, format string, args ...any) {
	r.addf(SeverityError, check, path, format, args...)
}

func (r *Result) warnf(check, path, format string, args ...any) {
	r.addf(SeverityWarning, check, path, format, args...)
}

func (r *Result) addf(severity Severity, check, path, format string, args ...any) {
	r.Findings = append(r.Findings, Finding{
		Severity: severity,
		Check:    check,
		Path:     path,
		Message:  fmt.Sprintf(format, args...),
	})
}

// File reads the document at path and validates it. Problems reading the file
// are reported as findings too, so that validating a list of paths never stops
// early.
func File(path string) *Result {
	res := &Result{File: path, Findings: []Finding{}}

	data, err := os.ReadFile(path)
	if err != nil {
		res.errorf(CheckFile, "", "reading document: %v", err)
		return res
	}

	res.validate(data)
	return res
}

// Document validates an OpenVEX document held in memory.
func Document(data []byte) *Result {
	res := &Result{Findings: []Finding{}}
	res.validate(data)
	return res
}

// validate runs every check against the raw bytes of a document. Each stage
// stops the run when it leaves nothing meaningful for the next one to look at.
func (r *Result) validate(data []byte) {
	raw, ok := r.parse(data)
	if !ok {
		return
	}

	if openVEX := r.checkContext(raw); !openVEX {
		return
	}

	r.checkSchema(raw)

	doc, ok := r.decode(data)
	if !ok {
		return
	}

	r.checkMetadata(doc, raw)
	r.checkStatements(doc)

	// Only a complete run needs reordering. The passes that stop early report
	// in the order a reader meets the problems anyway.
	r.sortFindings()
}

// indexed matches the array subscript of a finding path.
var indexed = regexp.MustCompile(`\[(\d+)]`)

// sortFindings reorders the findings the way a reader walks the document:
// first the ones about the file as a whole, then the document's own fields,
// then each statement in turn. The checks run in passes, so without this the
// findings of one statement would be spread across the report.
func (r *Result) sortFindings() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		return sortKey(r.Findings[i].Path) < sortKey(r.Findings[j].Path)
	})
}

func sortKey(path string) string {
	switch {
	case path == "":
		return "0"
	case strings.HasPrefix(path, fieldStatements):
		// Subscripts are padded so that statements[10] sorts after
		// statements[2] instead of before it.
		return "2" + indexed.ReplaceAllStringFunc(path, func(subscript string) string {
			index, err := strconv.Atoi(strings.Trim(subscript, "[]"))
			if err != nil {
				return subscript
			}
			return fmt.Sprintf("[%09d]", index)
		})
	default:
		return "1" + path
	}
}

// parse decodes the document into a generic tree. The tree is what the schema
// checks walk: it preserves the fields vexctl's own structs would drop.
func (r *Result) parse(data []byte) (map[string]any, bool) {
	if len(bytes.TrimSpace(data)) == 0 {
		r.errorf(CheckJSON, "", "the document is empty")
		return nil, false
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var top any
	if err := dec.Decode(&top); err != nil {
		var syntaxErr *json.SyntaxError
		if errors.As(err, &syntaxErr) {
			line, col := position(data, syntaxErr.Offset)
			r.errorf(CheckJSON, "", "invalid JSON at line %d, column %d: %v", line, col, err)
		} else {
			r.errorf(CheckJSON, "", "invalid JSON: %v", err)
		}
		return nil, false
	}

	obj, ok := top.(map[string]any)
	if !ok {
		r.errorf(CheckJSON, "", "an OpenVEX document must be a JSON object, this document is %s", jsonTypeName(top))
		return nil, false
	}

	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		r.errorf(CheckJSON, "", "the document is followed by more data; a VEX file holds a single JSON document")
	}

	return obj, true
}

// checkContext reads @context and reports whether the rest of the checks apply
// to the document. They only do for the OpenVEX version vexctl implements.
func (r *Result) checkContext(raw map[string]any) bool {
	value, found := raw[fieldContext]
	if !found || value == nil {
		if looksLikeCSAF(raw) {
			r.errorf(
				CheckContext, "",
				"this is a CSAF document and validate only checks OpenVEX documents; `vexctl merge` reads CSAF data and writes it back out as OpenVEX",
			)
			return false
		}

		r.errorf(
			CheckRequired, fieldContext,
			"required field \"@context\" is missing; OpenVEX documents declare their spec version in it (%q)",
			vex.ContextLocator(),
		)
		// Nothing says the document is not OpenVEX, so keep checking it
		// against the version vexctl implements.
		return true
	}

	locator, ok := value.(string)
	if !ok {
		r.typeErrorf(fieldContext, "a string", value)
		return false
	}

	if locator == vex.ContextLocator() {
		return true
	}

	if !strings.HasPrefix(locator, vex.Context) {
		r.errorf(
			CheckContext, fieldContext,
			"%q is not an OpenVEX context; OpenVEX documents declare %q. Only OpenVEX documents can be validated",
			locator, vex.ContextLocator(),
		)
		return false
	}

	// An OpenVEX document, but not one written against the spec version this
	// build knows. Its field names may differ, so checking it here would only
	// produce noise.
	version := strings.TrimPrefix(strings.TrimPrefix(locator, vex.Context), "/")
	if version == "" {
		// The spec defaults an unversioned context to the first release.
		version = "v0.0.1"
	}
	r.warnf(
		CheckContext, fieldContext,
		"the document declares OpenVEX %s but vexctl validates documents against v%s, so no further checks ran; `vexctl merge` rewrites a document in the current version",
		version, vex.SpecVersion,
	)
	return false
}

// looksLikeCSAF reports whether a document without an OpenVEX context is a
// CSAF advisory, which carries VEX data in a shape of its own.
func looksLikeCSAF(raw map[string]any) bool {
	document, ok := raw["document"].(map[string]any)
	if !ok {
		return false
	}
	_, ok = document["csaf_version"]
	return ok
}

// decode parses the document into vexctl's own structs, which the semantic
// checks read. Decoding errors the schema pass already explained are not
// repeated.
func (r *Result) decode(data []byte) (*vex.VEX, bool) {
	doc := &vex.VEX{}
	if err := json.Unmarshal(data, doc); err != nil {
		if r.Errors() == 0 {
			r.errorf(CheckJSON, "", "the document cannot be decoded as OpenVEX: %v", err)
		} else {
			r.warnf(
				CheckJSON, "",
				"the statements were left unchecked because the document does not decode; fix the errors above and validate it again",
			)
		}
		return nil, false
	}
	return doc, true
}

// checkMetadata checks the values of the document level fields. Their presence
// and types are already covered by the schema pass, which raw is consulted for
// so that a missing field is not reported twice.
func (r *Result) checkMetadata(doc *vex.VEX, raw map[string]any) {
	if doc.ID != "" {
		r.checkIRI(doc.ID, fieldID, "document")
	}

	if _, versioned := raw[fieldVersion]; versioned && doc.Version < 1 {
		r.errorf(CheckVersion, fieldVersion, "document version must be 1 or greater, it is %d", doc.Version)
	}

	if doc.Timestamp != nil && doc.LastUpdated != nil && doc.LastUpdated.Before(*doc.Timestamp) {
		r.errorf(
			CheckTimestamp, "last_updated",
			"last_updated (%s) is before the document timestamp (%s)",
			doc.LastUpdated.Format(time.RFC3339), doc.Timestamp.Format(time.RFC3339),
		)
	}

	// A missing statements field is already reported as a missing required
	// field, only an empty list is worth pointing out here.
	if _, listed := raw[fieldStatements]; listed && len(doc.Statements) == 0 {
		r.warnf(CheckStatements, fieldStatements, "the document has no statements, so it asserts nothing")
	}
}

// checkStatements checks each statement and the relationships between them.
func (r *Result) checkStatements(doc *vex.VEX) {
	seen := map[string]int{}

	for i := range doc.Statements {
		stmt := &doc.Statements[i]
		path := fmt.Sprintf("statements[%d]", i)

		if stmt.ID != "" {
			if first, repeated := seen[stmt.ID]; repeated {
				r.errorf(
					CheckStatements, path+".@id",
					"statement @id %q is already used by statements[%d]; statement identifiers must be unique within a document",
					stmt.ID, first,
				)
			} else {
				seen[stmt.ID] = i
			}
			r.checkIRI(stmt.ID, path+".@id", "statement")
		}

		r.checkStatement(stmt, doc, path)
	}
}

// checkStatement checks that a statement carries the four data points the spec
// requires: a vulnerability, a status, at least one product and a timestamp.
func (r *Result) checkStatement(stmt *vex.Statement, doc *vex.VEX, path string) {
	r.checkVulnerability(&stmt.Vulnerability, path+".vulnerability")

	// go-vex knows the rules tying status, justification, impact statement and
	// action statement together.
	if stmt.Status != "" {
		if err := stmt.Validate(); err != nil {
			r.errorf(CheckStatus, path, "%s", err)
		}
	}

	// go-vex only looks at the justification value for not_affected
	// statements, so an invalid label elsewhere would go unreported.
	if stmt.Justification != "" && !stmt.Justification.Valid() {
		r.errorf(
			CheckJustification, path+".justification",
			"invalid justification %q, must be one of [%s]",
			stmt.Justification, strings.Join(vex.Justifications(), ", "),
		)
	}

	r.checkStatementDates(stmt, doc, path)

	if len(stmt.Products) == 0 {
		r.errorf(CheckProduct, path+".products", "the statement lists no products; a statement must name the software it is about")
		return
	}

	for i := range stmt.Products {
		productPath := fmt.Sprintf("%s.products[%d]", path, i)
		r.checkComponent(&stmt.Products[i].Component, productPath, "product")

		for j := range stmt.Products[i].Subcomponents {
			r.checkComponent(
				&stmt.Products[i].Subcomponents[j].Component,
				fmt.Sprintf("%s.subcomponents[%d]", productPath, j),
				"subcomponent",
			)
		}
	}
}

// checkStatementDates checks the timestamps of a statement, including the one
// it inherits from the document.
func (r *Result) checkStatementDates(stmt *vex.Statement, doc *vex.VEX, path string) {
	// A statement without a timestamp of its own inherits the document's.
	issued := stmt.Timestamp
	if issued == nil {
		issued = doc.Timestamp
	}

	if issued == nil {
		r.errorf(
			CheckTimestamp, path+".timestamp",
			"the statement has no timestamp and the document defines none to inherit; a statement cannot be placed in time without one",
		)
	}

	if issued != nil && stmt.LastUpdated != nil && stmt.LastUpdated.Before(*issued) {
		r.errorf(
			CheckTimestamp, path+".last_updated",
			"last_updated (%s) is before the statement timestamp (%s)",
			stmt.LastUpdated.Format(time.RFC3339), issued.Format(time.RFC3339),
		)
	}

	if stmt.ActionStatementTimestamp != nil && stmt.ActionStatement == "" {
		r.warnf(
			CheckTimestamp, path+".action_statement_timestamp",
			"action_statement_timestamp is set but the statement has no action_statement",
		)
	}
}

// checkVulnerability checks the struct naming the vulnerability a statement
// is about.
func (r *Result) checkVulnerability(v *vex.Vulnerability, path string) {
	if v.Name == "" {
		r.errorf(CheckVulnerability, path+".name", "the statement does not name a vulnerability")
	}

	if v.ID != "" {
		r.checkIRI(v.ID, path+".@id", "vulnerability")
	}

	seen := map[vex.VulnerabilityID]bool{}
	for i, alias := range v.Aliases {
		aliasPath := fmt.Sprintf("%s.aliases[%d]", path, i)
		switch {
		case alias == "":
			r.errorf(CheckVulnerability, aliasPath, "the alias is empty")
		case seen[alias]:
			r.warnf(CheckVulnerability, aliasPath, "alias %q is listed more than once", alias)
		case alias == v.Name:
			r.warnf(CheckVulnerability, aliasPath, "alias %q repeats the vulnerability name", alias)
		}
		seen[alias] = true
	}
}

// checkComponent checks that a product or subcomponent can be addressed and
// that every identifier it carries is well formed. kind names the struct in
// the messages, either "product" or "subcomponent".
func (r *Result) checkComponent(c *vex.Component, path, kind string) {
	if c.ID == "" && len(c.Identifiers) == 0 && len(c.Hashes) == 0 {
		r.errorf(
			CheckProduct, path,
			"the %s cannot be addressed; identify it with @id, identifiers or hashes",
			kind,
		)
		return
	}

	if c.ID != "" {
		r.checkComponentID(c.ID, path+".@id", kind)
	}

	for _, idType := range slices.Sorted(maps.Keys(c.Identifiers)) {
		r.checkIdentifier(idType, c.Identifiers[idType], fmt.Sprintf("%s.identifiers.%s", path, idType))
	}

	for _, algo := range slices.Sorted(maps.Keys(c.Hashes)) {
		r.checkHash(algo, c.Hashes[algo], fmt.Sprintf("%s.hashes.%s", path, algo))
	}
}

// checkComponentID checks a component's @id. The spec wants an IRI there and
// notes that package URLs are valid IRIs, so purls and CPEs get checked as the
// identifiers they are.
func (r *Result) checkComponentID(id, path, kind string) {
	switch {
	case strings.HasPrefix(id, purlScheme):
		r.checkPurl(id, path)
	case strings.HasPrefix(id, cpe23Prefix) || strings.HasPrefix(id, cpe22Prefix):
		r.checkCPE(id, path)
	default:
		r.checkIRI(id, path, kind)
	}
}

// checkIRI warns when an identifier cannot serve as an IRI. OpenVEX uses @id
// fields to address things beyond the document, which needs an identifier that
// is unique outside of it, such as a URL or a package URL.
func (r *Result) checkIRI(id, path, kind string) {
	parsed, err := url.Parse(id)
	if err != nil || parsed.Scheme == "" {
		r.warnf(
			CheckIRI, path,
			"the %s @id %q is not an IRI; @id fields should be globally unique identifiers such as a URL or a package URL",
			kind, id,
		)
	}
}

// position turns a byte offset into the line and column a reader can find it
// at, both counted from 1.
func position(data []byte, offset int64) (line, column int) {
	line, column = 1, 1
	for i := int64(0); i < offset && i < int64(len(data)); i++ {
		if data[i] == '\n' {
			line++
			column = 1
			continue
		}
		column++
	}
	return line, column
}
