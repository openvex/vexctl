/*
Copyright 2021 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/
package vex

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

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
	Vulnerabilities []Statement `json:"vulnerabilities"`
}

type Metadata struct {
	Format             string    // VEX Format Identifier
	ID                 string    // Identifier string for the VEX document
	Author             string    `json:"author"`            // Document author
	AuthorRole         string    `json:"role"`              // Role of author
	ProductIdentifiers []string  `json:"product,omitempty"` // For spec completeness
	Timestamp          time.Time `json:"timestamp"`
}

// TypeStatement
type Statement struct {
	Vulnerability   string                   `json:"vulnerability"`
	Status          Status                   `json:"impact"`
	Justification   Justification            `json:"justification,omitempty"`
	ActionStatement string                   `json:"action_statement,omitempty"` // Required if status = AFFECTED
	References      []VulnerabilityReference `json:"references,omitempty"`       // Optional list
}

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
		Vulnerabilities: []Statement{},
	}
}

// Load loads a VEX document from disk
func Load(path string) (*VEX, error) {
	if filepath.Ext("path") == ".yaml" {
		return LoadYAML(path)
	}
	return nil, errors.New("file format not recognized")
}

func LoadYAML(path string) (*VEX, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening yaml file: %w", err)
	}
	vexDoc := New()
	if err := yaml.Unmarshal(data, vexDoc); err != nil {
		return nil, fmt.Errorf("unmarshalling vex data: %w", err)
	}
	return &vexDoc, nil
}

func (v *VEX) ToJSON() ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("encoding vex document: %w", err)
	}
	return b.Bytes(), nil
}
