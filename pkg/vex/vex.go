/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package vex

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"chainguard.dev/vex/pkg/csaf"
)

const (
	// TypeURI is the type used to describe VEX documents, e.g. within [in-toto
	// statements].
	//
	// [in-toto statements]: https://github.com/in-toto/attestation/blob/main/spec/README.md#statement
	TypeURI = "text/vex"

	// DefaultAuthor is the default value for a document's Author field.
	DefaultAuthor = "Unknown Author"

	// DefaultRole is the default value for a document's AuthorRole field.
	DefaultRole = "Document Creator"

	// Context is the URL of the json-ld context definition
	Context = "https://openvex.dev/ns"
)

// The VEX type represents a VEX document and all of its contained information.
type VEX struct {
	Metadata
	Statements []Statement `json:"statements"`
}

// The Metadata type represents the metadata associated with a VEX document.
type Metadata struct {
	// Context is the URL pointing to the jsonld context definition
	Context string `json:"@context"`

	// ID is the identifying string for the VEX document. This should be unique per
	// document.
	ID string `json:"@id"`

	// Author is the identifier for the author of the VEX statement, ideally a common
	// name, may be a URI. [author] is an individual or organization. [author]
	// identity SHOULD be cryptographically associated with the signature of the VEX
	// statement or document or transport.
	Author string `json:"author"`

	// AuthorRole describes the role of the document Author.
	AuthorRole string `json:"role"`

	// Timestamp defines the time at which the document was issued.
	Timestamp *time.Time `json:"timestamp"`

	// Version is the document version. It must be incremented when any content
	// within the VEX document changes, including any VEX statements included within
	// the VEX document.
	Version string `json:"version"`

	// Tooling expresses how the VEX document and contained VEX statements were
	// generated. It's optional. It may specify tools or automated processes used in
	// the document or statement generation.
	Tooling string `json:"tooling,omitempty"`

	// Supplier is an optional field.
	Supplier string `json:"supplier,omitempty"`
}

// New returns a new, initialized VEX document.
func New() VEX {
	now := time.Now()
	t, err := DateFromEnv()
	if err != nil {
		logrus.Warn(err)
	}
	if t != nil {
		now = *t
	}
	return VEX{
		Metadata: Metadata{
			Context:    Context,
			Author:     DefaultAuthor,
			AuthorRole: DefaultRole,
			Version:    "1",
			Timestamp:  &now,
		},
		Statements: []Statement{},
	}
}

// Load reads the VEX document file at the given path and returns a decoded VEX
// object. If Load is unable to read the file or decode the document, it returns
// an error.
func Load(path string) (*VEX, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("loading VEX file: %w", err)
	}

	vexDoc := &VEX{}
	if err := json.Unmarshal(data, vexDoc); err != nil {
		return nil, fmt.Errorf("unmarshaling VEX document: %w", err)
	}
	return vexDoc, nil
}

// OpenYAML opens a VEX file in YAML format.
func OpenYAML(path string) (*VEX, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening YAML file: %w", err)
	}
	vexDoc := New()
	if err := yaml.Unmarshal(data, &vexDoc); err != nil {
		return nil, fmt.Errorf("unmarshalling VEX data: %w", err)
	}
	return &vexDoc, nil
}

// OpenJSON opens a VEX file in JSON format.
func OpenJSON(path string) (*VEX, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening JSON file: %w", err)
	}
	vexDoc := New()
	if err := json.Unmarshal(data, &vexDoc); err != nil {
		return nil, fmt.Errorf("unmarshalling VEX data: %w", err)
	}
	return &vexDoc, nil
}

// ToJSON serializes the VEX document to JSON and writes it to the passed writer.
func (vexDoc *VEX) ToJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	if err := enc.Encode(vexDoc); err != nil {
		return fmt.Errorf("encoding vex document: %w", err)
	}
	return nil
}

// StatementFromID returns a statement for a given vulnerability if there is one.
func (vexDoc *VEX) StatementFromID(id string) *Statement {
	for _, statement := range vexDoc.Statements { //nolint:gocritic // turning off for rule rangeValCopy
		if statement.Vulnerability == id {
			logrus.Infof("VEX doc contains statement for CVE %s", id)
			return &statement
		}
	}
	return nil
}

// SortDocuments sorts and returns a slice of documents based on their date.
// VEXes should be applied sequentially in chronological order as they capture
// knowledge about an artifact as it changes over time.
func SortDocuments(docs []*VEX) []*VEX {
	sort.Slice(docs, func(i, j int) bool {
		if docs[j].Timestamp == nil {
			return true
		}
		if docs[i].Timestamp == nil {
			return false
		}
		return docs[i].Timestamp.Before(*(docs[j].Timestamp))
	})
	return docs
}

// OpenCSAF opens a CSAF document and builds a VEX object from it.
func OpenCSAF(path string, products []string) (*VEX, error) {
	csafDoc, err := csaf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening csaf doc: %w", err)
	}

	productDict := map[string]string{}
	for _, pid := range products {
		productDict[pid] = pid
	}

	// If no products were specified, we use the first one
	if len(products) == 0 {
		p := csafDoc.FirstProductName()
		if p == "" {
			// Error? I think so.
			return nil, errors.New("unable to find a product ID in CSAF document")
		}
		productDict[p] = p
	}

	// Create the vex doc
	v := &VEX{
		Metadata: Metadata{
			ID:         csafDoc.Document.Tracking.ID,
			Author:     "",
			AuthorRole: "",
			Timestamp:  &time.Time{},
		},
		Statements: []Statement{},
	}

	// Cycle the CSAF vulns list and get those that apply
	for _, c := range csafDoc.Vulnerabilities {
		for status, docProducts := range c.ProductStatus {
			for _, productID := range docProducts {
				if _, ok := productDict[productID]; ok {
					// Check we have a valid status
					if StatusFromCSAF(status) == "" {
						return nil, fmt.Errorf("invalid status for product %s", productID)
					}

					// TODO search the threats struct for justification, etc
					just := ""
					for _, t := range c.Threats {
						// Search the threats for a justification
						for _, p := range t.ProductIDs {
							if p == productID {
								just = t.Details
							}
						}
					}

					v.Statements = append(v.Statements, Statement{
						Vulnerability:   c.CVE,
						Status:          StatusFromCSAF(status),
						Justification:   "", // Justifications are not machine readable in csaf, it seems
						ActionStatement: just,
						Products:        products,
					})
				}
			}
		}
	}

	return v, nil
}

// CanonicalHash returns a hash representing the state of impact statements
// expressed in it. This hash should be constant as long as the impact
// statements are not modified. Changes in extra information and metadata
// will not alter the hash.
func (vexDoc *VEX) CanonicalHash() (string, error) {
	// Here's the algo:

	// 1. Start with the document date. In unixtime to avoid format variance.
	cString := fmt.Sprintf("%d", vexDoc.Timestamp.Unix())

	// 2. Document version
	cString += fmt.Sprintf(":%s", vexDoc.Version)

	// 3. Sort the statements
	stmts := vexDoc.Statements
	SortStatements(stmts, *vexDoc.Timestamp)

	// 4. Now add the data from each statement
	//nolint:gocritic
	for _, s := range stmts {
		// 4a. Vulnerability
		cString += fmt.Sprintf(":%s", s.Vulnerability)
		// 4b. Status + Justification
		cString += fmt.Sprintf(":%s:%s", s.Status, s.Justification)
		// 4c. Statement time, in unixtime. If it exists, if not the doc's
		if s.Timestamp != nil {
			cString += fmt.Sprintf(":%d", s.Timestamp.Unix())
		} else {
			cString += fmt.Sprintf(":%d", vexDoc.Timestamp.Unix())
		}
		// 4d. Sorted products
		prods := s.Products
		sort.Strings(prods)
		cString += fmt.Sprintf(":%s", strings.Join(prods, ":"))
	}

	// 5. Hash the string in sha256 and return
	h := sha256.New()
	if _, err := h.Write([]byte(cString)); err != nil {
		return "", fmt.Errorf("hashing canonicalization string: %w", err)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// GenerateCanonicalID generates an ID for the document. The ID will be
// based on the canonicalization hash. This means that documents
// with the same impact statements will always get the same ID.
// Trying to generate the id of a doc with an existing ID will
// not do anything.
func (vexDoc *VEX) GenerateCanonicalID() (string, error) {
	if vexDoc.ID != "" {
		return vexDoc.ID, nil
	}
	cHash, err := vexDoc.CanonicalHash()
	if err != nil {
		return "", fmt.Errorf("getting canonical hash: %w", err)
	}

	vexDoc.ID = fmt.Sprintf("VEX-%s", cHash)
	return vexDoc.ID, nil
}

func DateFromEnv() (*time.Time, error) {
	// Support envvar for reproducible vexing
	d := os.Getenv("SOURCE_DATE_EPOCH")
	if d == "" {
		return nil, nil
	}

	var t time.Time
	sec, err := strconv.ParseInt(d, 10, 64)
	if err == nil {
		t = time.Unix(sec, 0)
	} else {
		t, err = time.Parse(time.RFC3339, d)
		if err != nil {
			return nil, fmt.Errorf("failed to parse envvar SOURCE_DATE_EPOCH: %w", err)
		}
	}
	return &t, nil
}
