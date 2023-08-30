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

func addList(parentCmd *cobra.Command) {
	listCmd := &cobra.Command{
		Short: fmt.Sprintf("%s list: lists valid status or justification options", appname),
		Long: fmt.Sprintf(`%s list: list the valid input options according to the OpenVEX spec

When composing VEX documents it is important to ensure the VEX specification
is being adhered to for fields that require specific values. The list subcommand
will provide the valid options for fields such as status or justification.

Examples:

# list the status options
%s list status

# list the justification options
%s list justification


`, appname, appname, appname),
		Use:               "list",
		SilenceUsage:      false,
		SilenceErrors:     false,
		PersistentPreRunE: initLogging,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("selection of 'status' or 'justification' is required")
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
					return fmt.Errorf("%s is not a valid selection - available options are 'status' and 'justification'", v)
				}
			}
			return nil
		},
	}

	parentCmd.AddCommand(listCmd)
}
