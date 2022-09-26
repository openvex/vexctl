/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/
package vex

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

type Status string
type Justification string

const (

	// This is the format identifier for
	formatIdentifier = "vex_attestation"

	// Impact Statement constants
	StatusNotAffected        Status = "not_affected"
	StatusAffected           Status = "affected"
	StatusFixed              Status = "fixed"
	StatusUnderInvestigation Status = "under_investigation"

	// Justification constants
	ComponentNotPresent                         Justification = "component_not_present"
	VulnerableCodeNotPresent                    Justification = "vulnerable_code_not_present"
	VulnerableCodeNotInExecutePath              Justification = "vulnerable_code_not_in_execute_path"
	VulnerableCodeCannotBeControlledByAdversary Justification = "vulnerable_code_cannot_be_controlled_by_adversary"
	InlineMitigationsAlreadyExist               Justification = "inline_mitigations_already_exist"
)

type VEX struct {
	Metadata
	Statements []Statement `json:"statements"`
}

type Metadata struct {
	Format             string    // VEX Format Identifier
	ID                 string    // Identifier string for the VEX document
	Author             string    `json:"author"`            // Document author
	AuthorRole         string    `json:"role"`              // Role of author
	ProductIdentifiers []string  `json:"product,omitempty"` // For spec completeness
	Timestamp          time.Time `json:"timestamp"`
}

// Statement
type Statement struct {
	Vulnerability   string                   `json:"vulnerability"`
	Status          Status                   `json:"impact"`
	Justification   Justification            `json:"justification,omitempty"`
	ActionStatement string                   `json:"action_statement,omitempty"` // Required if status = AFFECTED
	References      []VulnerabilityReference `json:"references,omitempty"`       // Optional list
}

// VulnerabilityReference captures other identifier assinged to the CVE
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
