/*
Copyright 2021 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

type attestOptions struct {
	attach bool
}

func addAttest(parentCmd *cobra.Command) {
	opts := attestOptions{}
		generateCmd := &cobra.Command{
			Short: fmt.Sprintf("%s attest: generate vex golden data"),
			Long: ``,
			Use:               "attest",
			SilenceUsage:      false,
			SilenceErrors:     false,
			PersistentPreRunE: initLogging,
			RunE: func(cmd *cobra.Command, args []string) error {
				
			}
}
