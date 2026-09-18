/*
Copyright 2022 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/openvex/go-vex/pkg/sarif"
	"github.com/openvex/go-vex/pkg/vex"

	"github.com/openvex/vexctl/pkg/ctl"
)

type filterOptions struct {
	reportFormat string
	products     []string
}

func (o *filterOptions) Validate() error {
	if o.reportFormat != "vex" && o.reportFormat != "csaf" && o.reportFormat != "cyclonedx" {
		return errors.New("invalid vex document format (must be one of vex, cyclonedx or csaf)")
	}
	return nil
}

// openSarifReport reads a SARIF report from a path, or from stdin when the
// path is "-".
func openSarifReport(path string) (*sarif.Report, error) {
	if path != "-" {
		return sarif.Open(path)
	}
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("reading stdin: %w", err)
	}
	report := sarif.New()
	if err := json.Unmarshal(data, report); err != nil {
		return nil, fmt.Errorf("unmarshalling sarif report: %w", err)
	}
	return report, nil
}

func addFilter(parentCmd *cobra.Command) {
	opts := filterOptions{}
	filterCmd := &cobra.Command{
		Short: fmt.Sprintf("%s filter: apply a vex document to a results set", appname),
		Long: fmt.Sprintf(`%s filter: apply a vex document to a results set

When using the filter subcommand, %s will read a scanner results file
and apply one or more VEX files to the results. The output will be
the same results file with the VEX'ed vulnerabilities removed.

Examples:

# VEX a SARIF report from vex files:
vexctl filter myreport.sarif.json data1.vex.json data2.vex.json

# VEX a SARIF report from an atestation in an image:
vexctl filter myreport.sarif.json cgr.dev/image@sha256:e4cf37d568d195b4b5af4c3.....

VEX information can be read from CSAF, CycloneDX or our own simpler VEX
format.

It can also be read from an attestation attached to a container image.

When dealing with CSAF files, you can specify which of the products in the
document should be VEX'ed by specifying --product=PRODUCT_ID.


`, appname, appname),
		Use:               "filter",
		SilenceUsage:      false,
		SilenceErrors:     false,
		PersistentPreRunE: initLogging,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) < 2 {
				fmt.Println(cmd.Long)
				return errors.New("not enough arguments")
			}
			if err := opts.Validate(); err != nil {
				return fmt.Errorf("validating options: %w", err)
			}

			ctx := context.Background()
			vexctl := ctl.New()
			vexctl.Options.Products = opts.products
			vexctl.Options.Format = opts.reportFormat

			// TODO: Autodetect piped stdin
			report, err := openSarifReport(args[0])
			if err != nil {
				return fmt.Errorf("opening sarif report: %w", err)
			}
			vexes := make([]*vex.VEX, 0, len(args)-1)
			for i := 1; i < len(args); i++ {
				doc, err := vexctl.VexFromURI(ctx, args[i])
				if err != nil {
					return fmt.Errorf("opening %s: %w", args[i], err)
				}
				vexes = append(vexes, doc)
			}

			report, err = vexctl.Apply(report, vexes)
			if err != nil {
				return fmt.Errorf("applying vexes to report: %w", err)
			}

			return report.ToJSON(os.Stdout)
		},
	}

	filterCmd.PersistentFlags().StringVar(
		&opts.reportFormat,
		"format",
		"vex",
		"format of the vex document (vex | csaf | cyclonedx)",
	)

	filterCmd.PersistentFlags().StringSliceVar(
		&opts.products,
		"product",
		[]string{},
		"IDs of products in a CSAF document to VEX (defaults to first one found)",
	)

	parentCmd.AddCommand(filterCmd)
}
