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

When composing VEX data out of multiple sources it may be necessary to mix
all statements into a single doc. The merge subcommand mixes the statements
from one or more vex documents into a single, new one.

Examples:

# Merge two documents into one
%s merge document1.vex.json document2.vex.json > new.vex.json

# Merge two documents into one, but only one product
%s merge --product="pkg:apk/wolfi/bash@1.0" document1.vex.json document2.vex.json 

# Merge vulnerability data from two documents into one
%s merge --vulnerability=CVE-2022-3294 document1.vex.json document2.vex.json 

`, appname, appname, appname, appname),
		Use:               "create <filename.vex.json>",
		Example:           fmt.Sprintf("%s create \"pkg:apk/wolfi/trivy@0.36.1-r0?arch=x86_64\" CVE-2022-39260 fixed ", appname),
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
