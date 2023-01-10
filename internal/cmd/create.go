/*
Copyright 2023 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"chainguard.dev/vex/pkg/vex"
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
	if len(args) == 0 && len(o.Products) == 0 {
		return errors.New("a required product id is required to generate a valid VEX statement")
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
		SilenceErrors:     false,
		PersistentPreRunE: initLogging,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(args); err != nil {
				return err
			}
			// If we have arguments, add them
			for i := range args {
				switch i {
				case 0:
					opts.Products = append(opts.Products, args[i])
				case 1:
					opts.Vulnerability = args[i]
				case 2:
					opts.Status = args[i]
				}
			}
			newDoc := vex.New()

			statement := vex.Statement{
				Vulnerability:   opts.Vulnerability,
				Products:        opts.Products,
				Subcomponents:   opts.Subcomponents,
				Status:          vex.Status(opts.Status),
				StatusNotes:     opts.StatusNotes,
				Justification:   vex.Justification(opts.Justification),
				ImpactStatement: opts.ImpactStatement,
				ActionStatement: opts.ActionStatement,
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
		"ID for the new VEX document (default will be computed)",
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
		"author role to record in the new document",
	)

	createCmd.PersistentFlags().StringVarP(
		&opts.Vulnerability,
		"vuln",
		"v",
		"",
		"vulnerability to add to the statement (eg CVE-2023-12345)",
	)

	createCmd.PersistentFlags().StringSliceVarP(
		&opts.Products,
		"product",
		"p",
		[]string{},
		"list of products to list in the statement, at least one is required",
	)

	createCmd.PersistentFlags().StringVarP(
		&opts.Status,
		"status",
		"s",
		"",
		fmt.Sprintf("status of the product vs the vulnerability, see '%s show statuses' for list", appname),
	)

	createCmd.PersistentFlags().StringSliceVar(
		&opts.Products,
		"subcomponents",
		[]string{},
		"list of subcomponents to add to the statement",
	)

	createCmd.PersistentFlags().StringVarP(
		&opts.Justification,
		"justification",
		"j",
		"",
		fmt.Sprintf("justification for not_affected status, see '%s show justifications' for list", appname),
	)

	createCmd.PersistentFlags().StringVarP(
		&opts.ActionStatement,
		"action-statement",
		"a",
		vex.NoActionStatementMsg,
		"action statement for affected status",
	)

	createCmd.PersistentFlags().StringVar(
		&opts.outFilePath,
		"file",
		"",
		"file to write the document (default is STDOUT)",
	)

	parentCmd.AddCommand(createCmd)
}
