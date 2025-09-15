/*
Copyright 2022 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/openvex/go-vex/pkg/vex"
)

type createOptions struct {
	vexDocOptions
	vexStatementOptions
	outFileOption
}

// Validates the options in context with arguments
func (o *createOptions) Validate() error {
	return errors.Join(
		o.vexStatementOptions.Validate(),
		o.outFileOption.Validate(),
		o.vexDocOptions.Validate(),
	)
}

func (o *createOptions) AddFlags(cmd *cobra.Command) {
	o.vexDocOptions.AddFlags(cmd)
	o.vexStatementOptions.AddFlags(cmd)
	o.outFileOption.AddFlags(cmd)
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
		RunE: func(_ *cobra.Command, args []string) error {
			// If we have arguments, add them
			for i := range args {
				switch i {
				case 0:
					if len(opts.Products) > 0 && args[i] != "" {
						return errors.New("multiple products can only be specified using the --product flag")
					}
					// Specifying multiple products through args is not supported as we can't tell how many products are provided:
					// e.g the second argument could be a vulnerability or a status instead of a product, for example.
					// When using args only the first one is considered a product.
					// To specify multiple products, use the --product flag multiple times instead.
					opts.Products = append(opts.Products, args[i])
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

			newDoc.Author = opts.Author
			newDoc.AuthorRole = opts.AuthorRole

			if opts.DocumentID != "" {
				newDoc.ID = opts.DocumentID
			}

			statement := opts.ToStatement()

			if err := statement.Validate(); err != nil {
				return fmt.Errorf("invalid statement: %w", err)
			}

			newDoc.Statements = append(newDoc.Statements, statement)
			if _, err := newDoc.GenerateCanonicalID(); err != nil {
				return fmt.Errorf("generating document id: %w", err)
			}

			if err := writeDocument(&newDoc, opts.outFilePath); err != nil {
				return fmt.Errorf("writing openvex document: %w", err)
			}
			return nil
		},
	}

	opts.AddFlags(createCmd)
	parentCmd.AddCommand(createCmd)
}
