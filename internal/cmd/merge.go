/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/openvex/vex/pkg/vex"

	"github.com/openvex/vexctl/pkg/ctl"
)

type mergeOptions struct {
	ctl.MergeOptions
}

func addMerge(parentCmd *cobra.Command) {
	opts := mergeOptions{}
	mergeCmd := &cobra.Command{
		Short: fmt.Sprintf("%s merge: merges two or more VEX documents into one", appname),
		Long: fmt.Sprintf(`%s merge: merge one or more documents into one

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
		Use:               "merge",
		SilenceUsage:      false,
		SilenceErrors:     false,
		PersistentPreRunE: initLogging,
		RunE: func(cmd *cobra.Command, args []string) error {
			vexctl := ctl.New()
			newVex, err := vexctl.MergeFiles(context.Background(), &opts.MergeOptions, args)
			if err != nil {
				return fmt.Errorf("merging documents: %w", err)
			}
			if err := newVex.ToJSON(os.Stdout); err != nil {
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

	mergeCmd.PersistentFlags().StringSliceVar(
		&opts.Vulnerabilities,
		"vuln",
		[]string{},
		"list of vulnerabilities to extract",
	)

	mergeCmd.PersistentFlags().StringSliceVar(
		&opts.Products,
		"product",
		[]string{},
		"list of products to merge, all others will be ignored",
	)

	parentCmd.AddCommand(mergeCmd)
}
