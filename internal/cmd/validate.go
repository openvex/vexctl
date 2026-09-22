/*
Copyright 2026 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/openvex/go-vex/pkg/validate"
)

const (
	formatText = "text"
	formatJSON = "json"
)

type validateOptions struct {
	format string
	strict bool
}

func (o *validateOptions) Validate() error {
	if o.format != formatText && o.format != formatJSON {
		return fmt.Errorf("invalid output format %q, must be %q or %q", o.format, formatText, formatJSON)
	}
	return nil
}

func (o *validateOptions) AddFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(
		&o.format,
		"format",
		formatText,
		fmt.Sprintf("format of the report, either %q or %q", formatText, formatJSON),
	)

	cmd.PersistentFlags().BoolVar(
		&o.strict,
		"strict",
		false,
		"fail when a document has warnings, not just errors",
	)
}

// jsonReport is the document the --format=json report is written as.
type jsonReport struct {
	Valid   bool               `json:"valid"`
	Files   []*validate.Result `json:"files"`
	Summary jsonSummary        `json:"summary"`
}

type jsonSummary struct {
	Files    int `json:"files"`
	Invalid  int `json:"invalid"`
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
}

func addValidate(parentCmd *cobra.Command) {
	opts := validateOptions{}
	validateCmd := &cobra.Command{
		Short: fmt.Sprintf("%s validate: checks OpenVEX documents for problems", appname),
		Long: fmt.Sprintf(`%s validate: checks OpenVEX documents for problems

The validate subcommand reads one or more OpenVEX documents and checks them
for conformance with the OpenVEX specification, whatever produced them. Use it
to check the output of a tool that writes VEX, as a gate in the pipeline that
publishes your documents, or on a document you edited yourself.

It earns its keep because readers are forgiving: %s, like most consumers,
ignores data it does not recognize. A misspelled field or a malformed package
URL is not rejected, it is quietly dropped, and the statement ends up saying
less than whoever wrote it meant.

Findings come in two severities:

  error    the document breaks the OpenVEX spec. Tools reading it may reject
           it or read it differently than intended.
  warning  the document parses, but carries data that is ignored, redundant or
           no longer part of the spec.

%s exits with a non-zero status when any document has errors. Pass --strict
to fail on warnings too, which is what you want in CI.

Among other things, validate checks that:

  * the file is JSON and holds a single OpenVEX document
  * every field is one the OpenVEX spec defines and holds a value of the right
    type, so that misspelled fields are reported instead of dropped
  * the document has an @id, an author, a timestamp and a version
  * every statement names a vulnerability, a status and at least one product,
    and can be placed in time
  * statuses, justifications, action statements and impact statements are
    used in the combinations the spec allows
  * package URLs parse, CPEs are well formed and hashes match the length of
    the algorithm naming them

Examples:

# Check a single document
%s validate vex.json

# Check every document in a directory, failing on warnings too
%s validate --strict .openvex/*.json

# Report the findings as JSON, for another tool to read
%s validate --format=json vex.json

Note that validate checks documents written against OpenVEX v0.2.0. Documents
declaring an older spec version are reported as such and left alone; running
them through "%s merge" rewrites them in the current version.

`, appname, appname, appname, appname, appname, appname, appname),
		Use:               "validate [flags] file [file...]",
		Example:           fmt.Sprintf("%s validate vex.json", appname),
		Args:              cobra.MinimumNArgs(1),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		RunE: func(cmd *cobra.Command, args []string) error {
			// A document that fails validation is not a usage error, so from
			// here on errors should not drag the command's help along.
			cmd.SilenceUsage = true

			if err := opts.Validate(); err != nil {
				return err
			}

			results := make([]*validate.Result, 0, len(args))
			for _, path := range args {
				results = append(results, validate.File(path))
			}

			if err := writeReport(cmd.OutOrStdout(), results, opts.format); err != nil {
				return err
			}

			return validationError(results, opts.strict)
		},
	}

	opts.AddFlags(validateCmd)
	parentCmd.AddCommand(validateCmd)
}

// writeReport renders the results of a run in the requested format.
func writeReport(w io.Writer, results []*validate.Result, format string) error {
	if format == formatJSON {
		return writeJSONReport(w, results)
	}
	return writeTextReport(w, results)
}

func writeTextReport(w io.Writer, results []*validate.Result) error {
	for _, res := range results {
		if len(res.Findings) == 0 {
			if _, err := fmt.Fprintf(w, "%s: ok\n", res.File); err != nil {
				return fmt.Errorf("writing report: %w", err)
			}
			continue
		}

		if _, err := fmt.Fprintf(
			w, "%s: %s\n", res.File, countsOf(res.Errors(), res.Warnings()),
		); err != nil {
			return fmt.Errorf("writing report: %w", err)
		}

		for i := range res.Findings {
			if _, err := fmt.Fprintf(w, "  %s\n", res.Findings[i].String()); err != nil {
				return fmt.Errorf("writing report: %w", err)
			}
		}
	}

	errs, warns, invalid := totals(results)
	if _, err := fmt.Fprintf(
		w, "\n%s checked, %d valid, %d invalid (%s)\n",
		pluralize(len(results), "document", "documents"),
		len(results)-invalid, invalid, countsOf(errs, warns),
	); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	return nil
}

func writeJSONReport(w io.Writer, results []*validate.Result) error {
	errs, warns, invalid := totals(results)

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	if err := enc.Encode(jsonReport{
		Valid: invalid == 0,
		Files: results,
		Summary: jsonSummary{
			Files:    len(results),
			Invalid:  invalid,
			Errors:   errs,
			Warnings: warns,
		},
	}); err != nil {
		return fmt.Errorf("writing report: %w", err)
	}
	return nil
}

// validationError turns the results of a run into the command's exit status.
func validationError(results []*validate.Result, strict bool) error {
	errs, warns, invalid := totals(results)

	if invalid > 0 {
		return fmt.Errorf(
			"%s invalid (%s)",
			pluralize(invalid, "document is", "documents are"), countsOf(errs, warns),
		)
	}

	if strict && warns > 0 {
		return fmt.Errorf("%s reported and --strict is set", pluralize(warns, "warning was", "warnings were"))
	}

	return nil
}

func totals(results []*validate.Result) (errs, warns, invalid int) {
	for _, res := range results {
		errs += res.Errors()
		warns += res.Warnings()
		if !res.Valid() {
			invalid++
		}
	}
	return errs, warns, invalid
}

// countsOf renders a tally of errors and warnings, "2 errors, 1 warning".
func countsOf(errs, warns int) string {
	return fmt.Sprintf(
		"%s, %s",
		pluralize(errs, "error", "errors"),
		pluralize(warns, "warning", "warnings"),
	)
}

func pluralize(n int, singular, plural string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, plural)
}
