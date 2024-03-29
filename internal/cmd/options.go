/*
Copyright 2022 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/spf13/cobra"
)

type vexDocOptions struct {
	DocumentID string
	Author     string
	AuthorRole string
}

const (
	productLongFlag = "product"
	vulnLongFlag    = "vuln"
)

// Validate checks that the document options are valid
func (do *vexDocOptions) Validate() error {
	if do.Author == "" {
		return fmt.Errorf("document author cannot be blank")
	}
	return nil
}

func (do *vexDocOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(
		&do.DocumentID,
		"id",
		"",
		"ID string for the new VEX document (autogenerated by default)",
	)

	cmd.PersistentFlags().StringVar(
		&do.Author,
		"author",
		vex.DefaultAuthor,
		"author to record in the new document",
	)

	cmd.PersistentFlags().StringVar(
		&do.AuthorRole,
		"author-role",
		vex.DefaultRole,
		"optional author role to record in the new document",
	)
}

type vexStatementOptions struct {
	Status          string
	StatusNotes     string
	Justification   string
	ImpactStatement string
	Vulnerability   string
	ActionStatement string
	Product         string
	Subcomponents   []string
}

// Validate checks that the statement options are coherent
func (so *vexStatementOptions) Validate() error {
	if so.Status != string(vex.StatusAffected) &&
		(so.ActionStatement != vex.NoActionStatementMsg && so.ActionStatement != "") {
		return errors.New("action statement can only be set when status = \"affected\" ")
	}

	if so.Status != string(vex.StatusAffected) {
		so.ActionStatement = ""
	}

	if so.Product == "" {
		return errors.New("a required product id is needed to generate a valid VEX statement")
	}

	if so.Vulnerability == "" {
		return errors.New("a vulnerability ID is required to generate a valid VEX statement")
	}

	if so.Status == "" || !vex.Status(so.Status).Valid() {
		return fmt.Errorf(
			"a valid impact status is required, one of %s",
			strings.Join(vex.Statuses(), ", "),
		)
	}

	if so.Justification != "" && so.Status != string(vex.StatusNotAffected) {
		return fmt.Errorf("justification should only be set when status is %q", vex.StatusNotAffected)
	}

	if so.ImpactStatement != "" && so.Status != string(vex.StatusNotAffected) {
		return fmt.Errorf("--impact-statement can be set only when status is \"not_affected\" (status was %q)", so.Status)
	}

	return nil
}

func (so *vexStatementOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVarP(
		&so.Vulnerability,
		"vuln",
		"v",
		"",
		"vulnerability to add to the statement (eg CVE-2023-12345)",
	)

	cmd.PersistentFlags().StringVarP(
		&so.Product,
		productLongFlag,
		"p",
		"",
		"main identifier of the product, a package URL or another IRI",
	)

	cmd.PersistentFlags().StringVarP(
		&so.Status,
		"status",
		"s",
		"",
		"impact status of the product vs the vulnerability",
	)

	cmd.PersistentFlags().StringVar(
		&so.StatusNotes,
		"status-note",
		"",
		"statement on how status was determined",
	)

	cmd.PersistentFlags().StringSliceVar(
		&so.Subcomponents,
		"subcomponents",
		[]string{},
		"list of subcomponents to add to the statement, package URLs or other IRIs",
	)

	cmd.PersistentFlags().StringVarP(
		&so.Justification,
		"justification",
		"j",
		"",
		"justification for \"not_affected\" status (see vexctl list justification)",
	)

	cmd.PersistentFlags().StringVarP(
		&so.ActionStatement,
		"action-statement",
		"a",
		vex.NoActionStatementMsg,
		"action statement for \"affected\" status (only when status=affected)",
	)

	cmd.PersistentFlags().StringVar(
		&so.ImpactStatement,
		"impact-statement",
		"",
		"text explaining why a vulnerability cannot be exploited (only when status=not_affected)",
	)
}

// ToStatement returns a new vex.Statement based on the configured options
func (so *vexStatementOptions) ToStatement() vex.Statement {
	t := time.Now()

	s := vex.Statement{
		Vulnerability: vex.Vulnerability{
			Name: vex.VulnerabilityID(so.Vulnerability),
		},
		Timestamp:   &t,
		LastUpdated: nil,
		Products: []vex.Product{
			{
				Component: vex.Component{
					ID: so.Product,
				},
				Subcomponents: []vex.Subcomponent{},
			},
		},
		Status:                   vex.Status(so.Status),
		StatusNotes:              so.StatusNotes,
		Justification:            vex.Justification(so.Justification),
		ImpactStatement:          so.ImpactStatement,
		ActionStatement:          so.ActionStatement,
		ActionStatementTimestamp: nil,
	}

	if so.ActionStatement != "" {
		s.ActionStatementTimestamp = &t
	}

	for _, sc := range so.Subcomponents {
		s.Products[0].Subcomponents = append(s.Products[0].Subcomponents, vex.Subcomponent{
			Component: vex.Component{ID: sc},
		})
	}

	// Honor the epoch date envvar
	if os.Getenv("SOURCE_DATE_EPOCH") != "" {
		d, err := vex.DateFromEnv()
		if err == nil && d != nil {
			s.Timestamp = d
			if so.ActionStatement != "" {
				s.ActionStatementTimestamp = d
			}
		}
	}
	return s
}

type productsListOption struct {
	Products []string
}

func (pl *productsListOption) Validate() error {
	return nil
}

func (pl *productsListOption) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringSliceVar(
		&pl.Products,
		productLongFlag,
		[]string{},
		"list of products purls or other IRIs",
	)
}

type vulnerabilityListOption struct {
	Vulnerabilities []string
}

func (vl *vulnerabilityListOption) Validate() error {
	return nil
}

func (vl *vulnerabilityListOption) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringSliceVar(
		&vl.Vulnerabilities,
		vulnLongFlag,
		[]string{},
		"list of vulnerability identifiers",
	)
}

type outFileOption struct {
	outFilePath string
}

func (of *outFileOption) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(
		&of.outFilePath,
		"file",
		"",
		"file to write the document to (default is STDOUT)",
	)
}

func (of *outFileOption) Validate() error {
	return nil
}

func timeFromEnv() (time.Time, error) {
	t := time.Now()
	nt, err := vex.DateFromEnv()
	if err != nil {
		return t, fmt.Errorf("reading SOURCE_DATE_EPOCH from env: %w", err)
	}

	if nt != nil {
		t = *nt
	}
	return t, nil
}

func writeDocument(doc *vex.VEX, filepath string) error {
	out := os.Stdout
	if filepath != "" {
		f, err := os.Create(filepath)
		if err != nil {
			return fmt.Errorf("opening VEX file to write document: %w", err)
		}
		out = f
		defer f.Close()
	}

	if err := doc.ToJSON(out); err != nil {
		return fmt.Errorf("writing new VEX document: %w", err)
	}

	if filepath != "" {
		fmt.Fprintf(os.Stderr, " > VEX document written to %s\n", filepath)
	}
	return nil
}
