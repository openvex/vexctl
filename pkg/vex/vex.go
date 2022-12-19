/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/
package vex

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"chainguard.dev/vex/pkg/csaf"
)

const (
	// This is the format identifier for
	formatIdentifier = "text/vex+json"

	// MIME type to record in the attestations
	MimeType = "text/vex"
)

type Status string

const (
	// StatusNotAffected means no remediation or mitigation is required.
	StatusNotAffected Status = "not_affected"

	// StatusAffected means actions are recommended to remediate or mitigate.
	StatusAffected Status = "affected"

	// StatusFixed means the listed products or components have been remediated (by including fixes).
	StatusFixed Status = "fixed"

	// StatusUnderInvestigation means the author of the VEX statement is investigating.
	StatusUnderInvestigation Status = "under_investigation"
)

type Justification string

// Valid returns a bool indicating whether the Justification value is equal to one of the enumerated allowed values for Justification.
func (j Justification) Valid() bool {
	switch j {
	case ComponentNotPresent,
		VulnerableCodeNotPresent,
		VulnerableCodeNotInExecutePath,
		VulnerableCodeCannotBeControlledByAdversary,
		InlineMitigationsAlreadyExist:

		return true

	default:

		return false
	}
}

const (
	// ComponentNotPresent means the vulnerable component is not included in the artifact.
	//
	// ComponentNotPresent is a strong justification that the artifact is not affected.
	ComponentNotPresent Justification = "component_not_present"

	// VulnerableCodeNotPresent means the vulnerable component is included in
	// artifact, but the vulnerable code is not present. Typically, this case occurs
	// when source code is configured or built in a way that excluded the vulnerable
	// code.
	//
	// VulnerableCodeNotPresent is a strong justification that the artifact is not affected.
	VulnerableCodeNotPresent Justification = "vulnerable_code_not_present"

	// VulnerableCodeNotInExecutePath means the vulnerable code (likely in
	// [subcomponent_id]) can not be executed as it is used by [product_id].
	// Typically, this case occurs when [product_id] includes the vulnerable
	// [subcomponent_id] and the vulnerable code but does not call or use the
	// vulnerable code.
	VulnerableCodeNotInExecutePath Justification = "vulnerable_code_not_in_execute_path"

	// VulnerableCodeCannotBeControlledByAdversary means the vulnerable code cannot
	// be controlled by an attacker to exploit the vulnerability.
	//
	// This justification could be difficult to prove conclusively.
	VulnerableCodeCannotBeControlledByAdversary Justification = "vulnerable_code_cannot_be_controlled_by_adversary"

	// InlineMitigationsAlreadyExist means [product_id] includes built-in protections
	// or features that prevent exploitation of the vulnerability. These built-in
	// protections cannot be subverted by the attacker and cannot be configured or
	// disabled by the user. These mitigations completely prevent exploitation based
	// on known attack vectors.
	//
	// This justification could be difficult to prove conclusively. History is littered with examples of mitigation bypasses, typically involving minor modifications of existing exploit code.
	InlineMitigationsAlreadyExist Justification = "inline_mitigations_already_exist"
)

// StatusFromCSAF returns a vex status from the CSAF status
func StatusFromCSAF(csafStatus string) Status {
	switch csafStatus {
	case "known_not_affected":
		return StatusNotAffected
	case "fixed":
		return StatusFixed
	case "under_investigation":
		return StatusUnderInvestigation
	case "known_affected":
		return StatusAffected
	default:
		return ""
	}
}

type VEX struct {
	Metadata
	Statements []Statement `json:"statements"`
}

type Metadata struct {
	ID                 string    `json:"id"`                // Identifier string for the VEX document
	Format             string    `json:"format"`            // VEX Format Identifier
	Author             string    `json:"author"`            // Document author
	AuthorRole         string    `json:"role"`              // Role of author
	ProductIdentifiers []string  `json:"product,omitempty"` // For spec completeness
	Timestamp          time.Time `json:"timestamp"`
}

// A Statement is a declaration conveying a single [status] for a single [vul_id] for one or more [product_id]s. A VEX Statement exists within a VEX Document.
type Statement struct {
	Vulnerability string `json:"vulnerability"`

	// A VEX statement MUST provide Status of the vulnerabilities with respect to the
	// products and components listed in the statement. Status MUST be one of the
	// Status const values, some of which have further options and requirements.
	Status Status `json:"status"`

	// For ”Not affected” status, a VEX statement MAY include a status Justification
	// that further explains the status.
	Justification Justification `json:"justification,omitempty"`

	// For status “Affected”, a VEX statement MUST include an ActionStatement that
	// SHOULD describe actions to remediate or mitigate [vul_id].
	ActionStatement string `json:"action_statement,omitempty"` // Required if status = AFFECTED

	// For status “Not affected”, a VEX statement MUST include an ImpactStatement
	// that contains a description why the vulnerability cannot be exploited.
	ImpactStatement string `json:"impact_statement,omitempty"`

	References []VulnerabilityReference `json:"references,omitempty"` // Optional list
}

// VulnerabilityReference captures other identifier assigned to the CVE
type VulnerabilityReference struct {
	RefType   string `json:"type"` // URL, OSV, FEDORA, etc
	Reference string `reference:"ref"`
}

func New() VEX {
	return VEX{
		Metadata: Metadata{
			Format:             formatIdentifier,
			ProductIdentifiers: []string{},
			Timestamp:          time.Now(),
		},
		Statements: []Statement{},
	}
}

func OpenYAML(path string) (*VEX, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening yaml file: %w", err)
	}
	vexDoc := New()
	if err := yaml.Unmarshal(data, &vexDoc); err != nil {
		return nil, fmt.Errorf("unmarshalling vex data: %w", err)
	}
	return &vexDoc, nil
}

// OpenJSON opens a vex file in json format
func OpenJSON(path string) (*VEX, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening yaml file: %w", err)
	}
	vexDoc := New()
	if err := json.Unmarshal(data, &vexDoc); err != nil {
		return nil, fmt.Errorf("unmarshalling vex data: %w", err)
	}
	return &vexDoc, nil
}

// ToJSON serializes the VEX document to JSON and writes it to the passed writer
func (vexDoc *VEX) ToJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	if err := enc.Encode(vexDoc); err != nil {
		return fmt.Errorf("encoding vex document: %w", err)
	}
	return nil
}

// StatementFromID Returns a statement for a given vulnerability if there is one
func (vexDoc *VEX) StatementFromID(id string) *Statement {
	for _, statement := range vexDoc.Statements {
		if statement.Vulnerability == id {
			logrus.Infof("VEX doc contains statement for CVE %s", id)
			return &statement
		}
	}
	return nil
}

// Sort sorts a bunch of documents based on their date. VEXes should
// be applied sequentially in chronogical order as they capture knowledge about an
// artifact as it changes over time.
func Sort(docs []*VEX) []*VEX {
	sort.Slice(docs, func(i, j int) bool {
		return docs[i].Timestamp.Before(docs[j].Timestamp)
	})
	return docs
}

// OpenCSAF opens a CSAF document and builds a vex object from it
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
			ID:                 csafDoc.Document.Tracking.ID,
			Author:             "",
			AuthorRole:         "",
			ProductIdentifiers: products,
			Timestamp:          time.Time{},
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
						References:      []VulnerabilityReference{},
					})
				}
			}
		}
	}

	return v, nil
}
