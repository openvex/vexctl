/*
Copyright 2022 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/openvex/go-vex/pkg/vex"
)

type createOptions struct {
	vexDocOptions
	vexStatementOptions
	outFilePath string
}

// Validates the options in context with arguments
func (o *createOptions) Validate() error {
	if err := o.vexStatementOptions.Validate(); err != nil {
		return err
	}
	return o.vexDocOptions.Validate()
}

func (o *createOptions) AddFlags(cmd *cobra.Command) {
	o.vexDocOptions.AddFlags(cmd)
	o.vexStatementOptions.AddFlags(cmd)

	cmd.PersistentFlags().StringVar(
		&o.outFilePath,
		"file",
		"",
		"file to write the document to (default is STDOUT)",
	)
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
					if opts.Product != "" && opts.Product != args[i] {
						return errors.New("product can only be specified once")
					}
					opts.Product = args[i]
				case 1:
					if opts.Vulnerability != "" && opts.Vulnerability != args[i] {
						return errors.New("vulnerability can only be specified once")
					}
					opts.Vulnerability = args[i]
				case 2:
					if opts.Status != "" && opts.Status != args[i] {
						return errors.New("status can only be specified once")
					}
					opts.Status = args[i]
				}
			}

			if err := opts.Validate(); err != nil {
				return err
			}

			newDoc := vex.New()

			newDoc.Metadata.Author = opts.Author
			newDoc.Metadata.AuthorRole = opts.AuthorRole

			if opts.DocumentID != "" {
				newDoc.Metadata.ID = opts.DocumentID
			}

			statement := opts.ToStatement()

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

	opts.AddFlags(createCmd)
	parentCmd.AddCommand(createCmd)
}
