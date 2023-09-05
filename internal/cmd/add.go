/*
Copyright 2023 The OpenVEX Authors
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

type addOptions struct {
	vexStatementOptions
	outFileOption
	documentPath string
	inPlace      bool
}

func (o *addOptions) Validate() error {
	var fileError error
	if o.outFilePath != "" && o.inPlace {
		fileError = fmt.Errorf("you cannot specify --in-place and an output file at the same time")
	}
	return errors.Join(
		o.vexStatementOptions.Validate(),
		o.outFileOption.Validate(),
		fileError,
	)
}

func (o *addOptions) AddFlags(cmd *cobra.Command) {
	o.vexStatementOptions.AddFlags(cmd)
	o.outFileOption.AddFlags(cmd)

	cmd.PersistentFlags().BoolVarP(
		&o.inPlace,
		"in-place",
		"i",
		false,
		"add a statement to an existing file",
	)
}

func addAdd(parentCmd *cobra.Command) {
	opts := addOptions{}
	addCmd := &cobra.Command{
		Short: fmt.Sprintf("%s add: adds a new statement to an OpenVEX document", appname),
		Long: fmt.Sprintf(`%s add: adds a new statement to an OpenVEX document

The add subcommand lets users add new statements to an existing OpenVEX document.

For example, this invocation will add a statement statung that CVE-2023-12345 is
fixed:

%s add file.openvex.json "pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64" CVE-2023-12345 fixed

When adding statements, the document version is increased by 1 and the last 
updated date is set to now or, if the SOURCE_DATE_EPOCH environment variable
is set, it will be read there (dates can be formatted in UNIX time or RFC3339).

%s will output the file to STDOUT by default. Using the -i|--in-place flag will
cause the specified document to be rewritten with the new version. You can also
specify a new file using the --file flag.

`, appname, appname, appname),
		Use:               "add [flags] [document [product_id [vuln_id [status]]]]",
		Example:           fmt.Sprintf("%s add file.openvex.json \"pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64\" CVE-2022-39260 fixed ", appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		RunE: func(cmd *cobra.Command, args []string) error {
			// If we have arguments, add them
			for i := range args {
				switch i {
				case 0:
					if opts.documentPath != "" && opts.documentPath != args[i] {
						return errors.New("document path can only be specified once")
					}
					opts.documentPath = args[i]
				case 1:
					if opts.Product != "" && opts.Product != args[i] {
						return errors.New("product can only be specified once")
					}
					opts.Product = args[i]
				case 2:
					if opts.Vulnerability != "" && opts.Vulnerability != args[i] {
						return errors.New("vulnerability can only be specified once")
					}
					opts.Vulnerability = args[i]
				case 3:
					if opts.Status != "" && opts.Status != args[i] {
						return errors.New("status can only be specified once")
					}
					opts.Status = args[i]
				}
			}

			if err := opts.Validate(); err != nil {
				return err
			}

			doc, err := vex.Open(opts.documentPath)
			if err != nil {
				return fmt.Errorf("opening %s: %w", opts.documentPath, err)
			}

			t, err := timeFromEnv()
			if err != nil {
				return err
			}

			statement := opts.ToStatement()
			if err := statement.Validate(); err != nil {
				return fmt.Errorf("invalid statement: %w", err)
			}

			if doc.Timestamp != nil && doc.Timestamp.After(t) {
				return fmt.Errorf("date cannot be older than document's timestamp")
			}

			if doc.LastUpdated != nil && doc.LastUpdated.After(t) {
				return fmt.Errorf("new date cannot be before document last updated date")
			}

			// Grab the last date to update missing dates in the statements.
			docLastDate := doc.Timestamp
			if doc.LastUpdated != nil {
				docLastDate = doc.LastUpdated
			}

			// Check that dates in statements are newer and
			// propagate the document's date to older statements
			for i := range doc.Statements {
				if doc.Statements[i].LastUpdated != nil && doc.Statements[i].LastUpdated.After(t) {
					return fmt.Errorf(
						"date cannot be older than other statements' last update (found older date in #%d)", i,
					)
				}
				if doc.Statements[i].Timestamp == nil {
					doc.Statements[i].Timestamp = docLastDate
				} else if doc.Statements[i].Timestamp.After(t) {
					return fmt.Errorf(
						"date cannot be older than other statements (found older date in #%d)", i,
					)
				}
			}

			doc.LastUpdated = &t
			if doc.Timestamp == nil {
				doc.Timestamp = &t
			}
			doc.Statements = append(doc.Statements, statement)
			doc.Version++
			out := os.Stdout

			if opts.inPlace {
				opts.outFilePath = opts.documentPath
			}

			if opts.outFilePath != "" {
				f, err := os.Create(opts.outFilePath)
				if err != nil {
					return fmt.Errorf("opening VEX file to write document: %w", err)
				}
				out = f
				defer f.Close()
			}

			if err := doc.ToJSON(out); err != nil {
				return fmt.Errorf("writing new VEX document: %w", err)
			}

			if opts.outFilePath != "" {
				fmt.Fprintf(os.Stderr, " > VEX document written to %s\n", opts.outFilePath)
			}
			return nil
		},
	}

	opts.AddFlags(addCmd)
	parentCmd.AddCommand(addCmd)
}
