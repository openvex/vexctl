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

	"github.com/spf13/cobra"

	"github.com/openvex/go-vex/pkg/vex"
)

type createOptions struct {
	vexDocOptions
	vexStatementOptions
	outFilePath string
}

// Validates the options in context with arguments
func (o *createOptions) Validate(args []string) error {
	if o.Status != string(vex.StatusAffected) && o.ActionStatement == vex.NoActionStatementMsg {
		o.ActionStatement = ""
	}
	if o.Product == "" {
		return errors.New("a required product id is needed to generate a valid VEX statement")
	}

	if len(args) < 2 && o.Vulnerability == "" {
		return errors.New("a vulnerability ID is required to generate a valid VEX statement")
	}

	if len(args) < 3 && o.Status == "" {
		return fmt.Errorf("a valid impact status is required, one of %s", strings.Join(vex.Statuses(), ", "))
	}

	if len(args) >= 2 && o.Vulnerability != "" && args[1] != o.Vulnerability {
		return errors.New("vulnerability can only be specified once")
	}
	if len(args) >= 3 && o.Status != "" && args[2] != o.Status {
		return errors.New("status can only be specified once")
	}

	if o.ImpactStatement != "" && o.Status != string(vex.StatusNotAffected) {
		return fmt.Errorf("--impact-statement can be set only when status is \"not_affected\" (status was %q)", o.Status)
	}

	return nil
}

func addCreate(parentCmd *cobra.Command) {
	opts := createOptions{}
	createCmd := &cobra.Command{
		Short: fmt.Sprintf("%s create: creates a new VEX document", appname),
		Long: fmt.Sprintf(`%s create: creates a new VEX document

The create subcommand generates a single statement document
from the command line. This is intended for simple use cases
or to get a base document to get started.

You can specify multiple products and customize the metadata of
the document via the command line flags. %s will honor the
SOURCE_DATE_EPOCH environment variable and use that date for 
the document (it can be formatted in UNIX time or RFC3339).

If you don't specify an ID for the document, one will be generated
using its canonicalization hash.

Examples:

# Generate a document stating that CVE-2023-12345 was fixed in the 
# git package of Wolfi:

%s create "pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64" CVE-2023-12345 fixed

# You can specify more than one product. %s will read one from
# the argument but you can control all parameters through command line
# flags. Here's an example with two products in the same document:

%s create --product="pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64" \
              --product="pkg:apk/wolfi/git@2.39.0-r1?arch=armv7" \
              --vuln="CVE-2023-12345" \
              --status="fixed"

# not_affected statements need a justification:

%s create --product="pkg:apk/wolfi/trivy@0.36.1-r0?arch=x86_64" \
              --vuln="CVE-2023-12345" \
              --status="not_affected" \
              --justification="component_not_present" 

`, appname, appname, appname, appname, appname, appname),
		Use:               "create [flags] [product_id [vuln_id [status]]]",
		Example:           fmt.Sprintf("%s create \"pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64\" CVE-2022-39260 fixed ", appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		RunE: func(cmd *cobra.Command, args []string) error {
			// If we have arguments, add them
			for i := range args {
				switch i {
				case 0:
					opts.Product = args[i]
				case 1:
					opts.Vulnerability = args[i]
				case 2:
					opts.Status = args[i]
				}
			}

			if err := opts.Validate(args); err != nil {
				return err
			}

			newDoc := vex.New()

			newDoc.Metadata.Author = opts.Author
			newDoc.Metadata.AuthorRole = opts.AuthorRole

			if opts.DocumentID != "" {
				newDoc.Metadata.ID = opts.DocumentID
			}

			statement := vex.Statement{
				Vulnerability: vex.Vulnerability{
					Name: vex.VulnerabilityID(opts.Vulnerability),
				},
				Products: []vex.Product{
					{
						Component: vex.Component{
							ID:          opts.Product,
							Hashes:      map[vex.Algorithm]vex.Hash{},
							Identifiers: map[vex.IdentifierType]string{},
						},
						Subcomponents: []vex.Subcomponent{},
					},
				},
				Status:          vex.Status(opts.Status),
				StatusNotes:     opts.StatusNotes,
				Justification:   vex.Justification(opts.Justification),
				ImpactStatement: opts.ImpactStatement,
				ActionStatement: opts.ActionStatement,
			}

			for _, sc := range opts.Subcomponents {
				statement.Products[0].Subcomponents = append(
					statement.Products[0].Subcomponents,
					vex.Subcomponent{Component: vex.Component{ID: sc}},
				)
			}

			if err := statement.Validate(); err != nil {
				return fmt.Errorf("invalid statement: %w", err)
			}

			newDoc.Statements = append(newDoc.Statements, statement)
			if _, err := newDoc.GenerateCanonicalID(); err != nil {
				return fmt.Errorf("generating document id: %w", err)
			}

			out := os.Stdout

			if opts.outFilePath != "" {
				f, err := os.Create(opts.outFilePath)
				if err != nil {
					return fmt.Errorf("opening VEX file to write document: %w", err)
				}
				out = f
				defer f.Close()
			}

			if err := newDoc.ToJSON(out); err != nil {
				return fmt.Errorf("writing new VEX document: %w", err)
			}

			if opts.outFilePath != "" {
				fmt.Fprintf(os.Stderr, " > VEX document written to %s\n", opts.outFilePath)
			}
			return nil
		},
	}

	createCmd.PersistentFlags().StringVar(
		&opts.DocumentID,
		"id",
		"",
		"ID string for the new VEX document (autogenerated by default)",
	)

	createCmd.PersistentFlags().StringVar(
		&opts.Author,
		"author",
		vex.DefaultAuthor,
		"author to record in the new document",
	)

	createCmd.PersistentFlags().StringVar(
		&opts.AuthorRole,
		"author-role",
		vex.DefaultRole,
		"optional author role to record in the new document",
	)

	createCmd.PersistentFlags().StringVarP(
		&opts.Vulnerability,
		"vuln",
		"v",
		"",
		"vulnerability to add to the statement (eg CVE-2023-12345)",
	)

	createCmd.PersistentFlags().StringVarP(
		&opts.Product,
		"product",
		"p",
		"",
		"main identifier of the product, a package URL or another IRI",
	)

	createCmd.PersistentFlags().StringVarP(
		&opts.Status,
		"status",
		"s",
		"",
		"impact status of the product vs the vulnerability",
	)

	createCmd.PersistentFlags().StringVar(
		&opts.StatusNotes,
		"status-note",
		"",
		"statement on how status was determined",
	)

	createCmd.PersistentFlags().StringSliceVar(
		&opts.Subcomponents,
		"subcomponents",
		[]string{},
		"list of subcomponents to add to the statement, package URLs or other IRIs",
	)

	createCmd.PersistentFlags().StringVarP(
		&opts.Justification,
		"justification",
		"j",
		"",
		"justification for not_affected status",
	)

	createCmd.PersistentFlags().StringVarP(
		&opts.ActionStatement,
		"action-statement",
		"a",
		vex.NoActionStatementMsg,
		"action statement for affected status (only when status=affected)",
	)

	createCmd.PersistentFlags().StringVar(
		&opts.outFilePath,
		"file",
		"",
		"file to write the document to (default is STDOUT)",
	)

	createCmd.PersistentFlags().StringVar(
		&opts.ImpactStatement,
		"impact-statement",
		"",
		"text explaining why a vulnerability cannot be exploited (only when status=not_affected)",
	)

	parentCmd.AddCommand(createCmd)
}
