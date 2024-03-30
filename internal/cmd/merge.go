/*
Copyright 2022 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/openvex/vexctl/pkg/ctl"
)

type mergeOptions struct {
	vexDocOptions
	productsListOption
	vulnerabilityListOption
}

func (mo *mergeOptions) AddFlags(cmd *cobra.Command) {
	mo.productsListOption.AddFlags(cmd)
	mo.vulnerabilityListOption.AddFlags(cmd)
	mo.vexDocOptions.AddFlags(cmd)
}

func (mo *mergeOptions) Validate() error {
	return errors.Join(
		mo.productsListOption.Validate(),
		mo.vulnerabilityListOption.Validate(),
		mo.vexDocOptions.Validate(),
	)
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
		RunE: func(_ *cobra.Command, args []string) error {
			vexctl := ctl.New()

			// TODO(puerco): Change this to vex merge options when we move
			// the merge logic out of vexctl
			newVex, err := vexctl.MergeFiles(context.Background(), &ctl.MergeOptions{
				DocumentID:      opts.vexDocOptions.DocumentID,
				Author:          opts.vexDocOptions.Author,
				AuthorRole:      opts.vexDocOptions.AuthorRole,
				Products:        opts.Products,
				Vulnerabilities: opts.Vulnerabilities,
			}, args)
			if err != nil {
				return fmt.Errorf("merging documents: %w", err)
			}
			if err := newVex.ToJSON(os.Stdout); err != nil {
				return fmt.Errorf("writing new vex document: %w", err)
			}
			return nil
		},
	}

	opts.productsListOption.AddFlags(mergeCmd)
	opts.vulnerabilityListOption.AddFlags(mergeCmd)
	opts.vexDocOptions.AddFlags(mergeCmd)

	parentCmd.AddCommand(mergeCmd)
}
