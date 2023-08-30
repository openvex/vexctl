/*
Copyright 2022 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/openvex/go-vex/pkg/vex"
)

func addShow(parentCmd *cobra.Command) {
	showCmd := &cobra.Command{
		Short: fmt.Sprintf("%s show: shows valid status or justification options", appname),
		Long: fmt.Sprintf(`%s show: show the valid input options according to the OpenVEX spec

When composing VEX documents it is important to ensure the VEX specification
is being adhered to for fields that require specific values. The show subcommand
will provide the valid options for fields such as status or justification.

Examples:

# Show the status options
%s show status

# show the justification options
%s show justification


`, appname, appname, appname),
		Use:               "show",
		SilenceUsage:      false,
		SilenceErrors:     false,
		PersistentPreRunE: initLogging,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("Selection of 'status' or 'justification' is required")
			}
			for _, v := range args {
				switch v {
				case "status":
					fmt.Printf("Valid Statuses:\n")
					for _, status := range vex.Statuses() {
						fmt.Printf("\t%s\n", status)
					}
				case "justification":
					fmt.Printf("Valid Justifications:\n")
					for _, justification := range vex.Justifications() {
						fmt.Printf("\t%s\n", justification)
					}
				default:
					return fmt.Errorf("%s is not a valid selection - available options are 'status' and 'justification' \n", v)
				}
			}
			return nil
		},
	}

	parentCmd.AddCommand(showCmd)
}
