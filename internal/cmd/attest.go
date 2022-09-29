/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"errors"
	"fmt"
	"os"

	"chainguard.dev/mrclean/pkg/mrc"
	"github.com/spf13/cobra"
)

type attestOptions struct {
	attach bool
	sign   bool
}

func addAttest(parentCmd *cobra.Command) {
	opts := attestOptions{}
	generateCmd := &cobra.Command{
		Short:         fmt.Sprintf("%s attest: generate a VEX  attestation", appname),
		Long:          ``,
		Use:           "attest",
		SilenceUsage:  false,
		SilenceErrors: false,
		// PersistentPreRunE: initLogging,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				return errors.New("not enough arguments")
			}
			cmd.SilenceUsage = true

			mrc := mrc.New()
			mrc.Options.Sign = opts.sign

			attestation, err := mrc.Attest(args[0], args[1:])
			if err != nil {
				return fmt.Errorf("generating attestation: %w", err)
			}

			if err := attestation.ToJSON(os.Stdout); err != nil {
				return fmt.Errorf("marshaling attestation to json")
			}

			if opts.attach {
				mrc.Attach(attestation, args[1:])
			}

			return nil
		},
	}

	generateCmd.PersistentFlags().BoolVar(
		&opts.attach,
		"attach",
		true,
		"attach the generated attestation to an image",
	)

	generateCmd.PersistentFlags().BoolVar(
		&opts.sign,
		"sign",
		true,
		"sign the attestation with sigstore",
	)

	parentCmd.AddCommand(generateCmd)
}
