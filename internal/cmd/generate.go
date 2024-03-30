/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"errors"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/openvex/vexctl/pkg/ctl"
)

type generateOptions struct {
	vexDocOptions
	outFileOption
	Product       string
	TemplatesPath string
	Init          bool
}

// Validates the options in context with arguments
func (o *generateOptions) Validate() error {
	var err, errInit error
	if o.Product == "" && !o.Init {
		err = errors.New("a required product id is needed to generate a valid VEX statement")
	}

	if o.Init && o.Product != "" {
		errInit = errors.New("when specifying --init, no product can be set")
	}

	return errors.Join(
		err, errInit,
		o.outFileOption.Validate(),
		o.vexDocOptions.Validate(),
	)
}

func (o *generateOptions) AddFlags(cmd *cobra.Command) {
	o.vexDocOptions.AddFlags(cmd)
	o.outFileOption.AddFlags(cmd)

	cmd.PersistentFlags().StringVarP(
		&o.Product,
		productLongFlag,
		"p",
		"",
		"main identifier of the product, a package URL or another IRI",
	)

	cmd.PersistentFlags().StringVarP(
		&o.TemplatesPath,
		"templates",
		"t",
		ctl.DefaultTemplatesPath,
		"path to templates directory",
	)

	cmd.PersistentFlags().BoolVar(
		&o.Init,
		"init",
		false,
		"initialize a new templates directory in the path specified with -t",
	)
}

func addGenerate(parentCmd *cobra.Command) {
	opts := generateOptions{}
	generateCmd := &cobra.Command{
		Short: fmt.Sprintf("%s generate: generates VEX data", appname),
		Long: fmt.Sprintf(`%s generate: generates VEX data from golden templates

The generate subcommand reads a set of golden template files and
creates a new document for a new artifact based on the golden samples.

To start, create your golden templates directory. You can initialize a new
templates directory using the --init flag:

vexctl generate --init --templates=".openvex/templates"

That invocation will create a new directory and add a new empty openvex document.
You can add more statements to it with "vexctl add" (see vexctl add --help).

The golden templates are normal OpenVEX documents. Their only difference is that
statements have generic identifiers that will be included in the generated data
when matched by a more specific data.

For example, to create a golden template for an OCI image, add a product with 
an unversioned purl like this:

"statements": [
    {
      "vulnerability": { "name": "CVE-1234-5678" },
      "products": [
        { "@id": "pkg:oci/test" }
      ],
      "status": "fixed",
      "timestamp": "2023-12-05T05:04:34.77929922Z"
    }
],

You can add that statement using the following invocation:

vexctl add --in-place main.openvex.json "pkg:oci/test" "CVE-1234-5678" fixed

The added statement will cause vexctl to generate a VEX document with data for
CVE-1234-5678 for every version of the test image. In other words, when generating
VEX data, products identified by these purls will get a statement with a status of
fixed:

  # Versioned purl (image with digest)
  pkg:oci/test@sha256%%3Af87abf1735e79b70407288f665316644d414dbf7bdf38c2f1c8e3a541d304d84

  # Image with tag
  pkg:oci/test?tag=latest

  # Image with tag and repository
  pkg:oci/test?tag=latest&repository_url=ghcr.io%%2Fopenvex

Examples:

# Generate a document with all data for the an image with the reference
# ghcr.io/openvex/test@sha256:f87abf1735e79b70407288f665316644d414dbf7bdf38c2f1c8e3a541d304d84

%s generate --templates=".openvex/templates/" \
  --product="pkg:oci/test@sha256%%3Af87abf1735e79b70407288f665316644d414dbf7bdf38c2f1c8e3a541d304d84&repository_url=ghcr.io%%2Fopenvex"

With that invocation, %s will read all template data from a directory
called .openvex/templates, filter out the relevant statements and generate a
VEX document for the specified product (the test image).

Note, that in this iteration, %s can only match products, subcomponents
are not considered when filtering out statements.

You can customize the metadata of the document via the command line flags.
%s will honor the SOURCE_DATE_EPOCH environment variable and use that date for 
the document (it can be formatted in UNIX time or RFC3339).

If you don't specify an ID for the document, one will be generated
using its canonicalization hash.

`, appname, appname, appname, appname, appname),
		Use:               "generate [flags] [product_id]",
		Example:           fmt.Sprintf("%s generate \"pkg:apk/wolfi/git", appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				if opts.Product != "" && opts.Product != args[0] {
					return errors.New("product can only be specified once")
				}
				opts.Product = args[0]
			}

			if err := opts.Validate(); err != nil {
				return err
			}

			// Options are relatively simple for now
			genopts := ctl.GenerateOpts{
				TemplatesPath: opts.TemplatesPath,
			}

			vexctl := ctl.New()

			// If initializing, do that and exit
			if opts.Init {
				if err := vexctl.InitTemplatesDirectory(&genopts); err != nil {
					return fmt.Errorf("initializing templates directory: %w", err)
				}
				logrus.Infof("Initialized new templates directory in %s", genopts.TemplatesPath)
				return nil
			}

			newDoc, err := vexctl.Generate(&genopts, []*vex.Product{
				{Component: vex.Component{ID: opts.Product}},
			})
			if err != nil {
				return fmt.Errorf("generating VEX data: %w", err)
			}

			if newDoc == nil {
				logrus.Warnf("No VEX data found for %s", opts.Product)
				return nil
			}

			newDoc.Metadata.Author = opts.Author
			newDoc.Metadata.AuthorRole = opts.AuthorRole

			if opts.DocumentID != "" {
				newDoc.Metadata.ID = opts.DocumentID
			}

			if err := writeDocument(newDoc, opts.outFilePath); err != nil {
				return fmt.Errorf("writing openvex document: %w", err)
			}
			return nil
		},
	}

	opts.AddFlags(generateCmd)
	parentCmd.AddCommand(generateCmd)
}
