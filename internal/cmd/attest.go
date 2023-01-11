/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/openvex/vexctl/pkg/ctl"
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

			ctx := context.Background()

			vexctl := ctl.New()
			vexctl.Options.Sign = opts.sign

			attestation, err := vexctl.Attest(args[0], args[1:])
			if err != nil {
				return fmt.Errorf("generating attestation: %w", err)
			}

			if opts.attach {
				if err := vexctl.Attach(ctx, attestation, args[1:]); err != nil {
					return fmt.Errorf("attaching attestation: %w", err)
				}
			}

			if err := attestation.ToJSON(os.Stdout); err != nil {
				return fmt.Errorf("marshaling attestation to json")
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
