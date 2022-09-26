/*
Copyright 2021 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"

	"chainguard.dev/mrclean/pkg/mrc"
	"chainguard.dev/mrclean/pkg/sarif"
	"chainguard.dev/mrclean/pkg/vex"
	"github.com/spf13/cobra"
)

type vexOptions struct {
	reportFormat string
}

func addVEX(parentCmd *cobra.Command) {
	//opts := attestOptions{}
	vexCmd := &cobra.Command{
		Short:         fmt.Sprintf("%s vex: apply a vex document to a results set", appname),
		Long:          ``,
		Use:           "vex",
		SilenceUsage:  false,
		SilenceErrors: false,
		//PersistentPreRunE: initLogging,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				return errors.New("not enough arguments")
			}
			// TODO: Autodetect piped stdin
			reportFileName := args[0]
			if args[0] == "-" {
				tmp, err := os.CreateTemp("", "tmp-*.sarif.json")
				if err != nil {
					return fmt.Errorf("creating temp sarif file")
				}
				defer os.Remove(tmp.Name())
				if _, err := io.Copy(tmp, os.Stdin); err != nil {
					return fmt.Errorf("writing stdin: %w", err)
				}
				reportFileName = tmp.Name()
			}

			// Open all docs
			report, err := sarif.Open(reportFileName)
			if err != nil {
				return fmt.Errorf("opening sarif report")
			}
			vexes := []*vex.VEX{}
			for i := 1; i < len(args); i++ {
				doc, err := vex.OpenJSON(args[i])
				if err != nil {
					return fmt.Errorf("opening %s: %w", args[i], err)
				}
				vexes = append(vexes, doc)
			}
			mr := mrc.New()
			report, err = mr.Apply(report, vexes)
			if err != nil {
				return fmt.Errorf("applying vexes to report: %w", err)
			}

			return report.ToJSON(os.Stdout)

		},
	}

	parentCmd.AddCommand(vexCmd)
}
