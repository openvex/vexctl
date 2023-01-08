/*
Copyright 2022 Chainguard, Inc.
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
}

// Validates the options in context with arguments
func (o *createOptions) Validate(args []string) error {
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

	statusString := o.Status
	if statusString == "" {
		if len(args) < 3 {
			return fmt.Errorf("a valid status is required to generate a valid VEX statement")
		}
		statusString = args[2]
	}
	status := vex.Status(statusString)
	if !status.Valid() {
		return fmt.Errorf(
			"invalid VEX impact status '%s', valid status are: %s",
			status, strings.Join(vex.Statuses(), ", "),
		)
	}

	if status == vex.StatusNotAffected {
		if o.Justification == "" {
			return fmt.Errorf("an '%s' statement requires a valid justification: [%s]", vex.StatusAffected, strings.Join(vex.Justifications(), ", "))
		}

		if !vex.Justification(o.Justification).Valid() {
			return fmt.Errorf("%s is not a valid VEX justification, valid justifications: %s", vex.StatusAffected, strings.Join(vex.Justifications(), ", "))
		}
	} else if o.Justification == "" {
		return fmt.Errorf("a %s impact status must not have a justification", status)
	}

	return nil
}

func addCreate(parentCmd *cobra.Command) {
	opts := createOptions{}
	mergeCmd := &cobra.Command{
		Short: fmt.Sprintf("%s create: creates a new VEX document", appname),
		Long: fmt.Sprintf(`%s create: creates a new VEX document

The create subcommand generates a single statement document
from the command line. This is intended for simple use cases
or to get a base document to get started.

You can specify multiple products and customize the metadata of
the document via the command line flags. vexctl will honor the
SOURCE_DATE_EPOCH environment variable and use that date for 
the document (it can be formated in unix time or RFC3339).

If you don't specify an ID for the document, one will be generated
using its canonicalization hash.

Examples:

# Generate a document stating that CVE-2023-12345 was fixed in the 
# git package of Wolfi:

%s create "pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64" CVE-2023-12345 fixed

# You can specify more than one product. vexctl will read one from
# the argument but you can control all parameters through command line
# flags. Here's an example with two products in the same document:

%s create --product="pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64" \
              --product="pkg:apk/wolfi/git@2.39.0-r1?arch=armv7" \
              --vuln="CVE-2023-12345"
              --status="fixed"

# not_affected statements need a justification:

%s create --product="pkg:apk/wolfi/trivy@0.36.1-r0?arch=x86_64"
              --vuln="CVE-2023-12345"
              --status="not_affected"
              --justification="component_not_present"

`, appname, appname, appname, appname),
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
			}
			newDoc.Statements = append(newDoc.Statements, statement)

			out := os.Stdout

			if err := newDoc.ToJSON(out); err != nil {
				return fmt.Errorf("writing new vex document: %w", err)
			}
			return nil
		},
	}

	mergeCmd.PersistentFlags().StringVar(
		&opts.DocumentID,
		"docid",
		"",
		"ID for the new VEX document (default will be computed)",
	)

	mergeCmd.PersistentFlags().StringVar(
		&opts.Author,
		"author",
		vex.DefaultAuthor,
		"author to record in the new document",
	)

	mergeCmd.PersistentFlags().StringVar(
		&opts.AuthorRole,
		"author-role",
		vex.DefaultRole,
		"author role to record in the new document",
	)

	mergeCmd.PersistentFlags().StringVar(
		&opts.Vulnerability,
		"vuln",
		"",
		"vulnerability to add to the statement (eg CVE-2023-12345)",
	)

	mergeCmd.PersistentFlags().StringSliceVar(
		&opts.Products,
		"product",
		[]string{},
		"list of products to list in the statement, at least one is required",
	)

	mergeCmd.PersistentFlags().StringSliceVar(
		&opts.Products,
		"subcomponents",
		[]string{},
		"list of subcomponents to add to the statement",
	)

	mergeCmd.PersistentFlags().StringVarP(
		&opts.Justification,
		"justification",
		"j",
		"",
		"list of subcomponents to add to the statement",
	)

	mergeCmd.MarkFlagRequired("products") //nolint:errcheck
	mergeCmd.MarkFlagRequired("vuln")     //nolint:errcheck
	mergeCmd.MarkFlagRequired("status")   //nolint:errcheck

	parentCmd.AddCommand(mergeCmd)
}
