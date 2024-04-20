/*
Copyright 2022 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/charmbracelet/huh"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/spf13/cobra"
)

var (
	vulnID        string
	status        string
	justification string
)

type commitOptions struct {
	vexDocOptions
	vexStatementOptions
	outFileOption
}

// Validates the options in context with arguments
func (o *commitOptions) Validate() error {
	return errors.Join(
		o.vexStatementOptions.Validate(),
		o.outFileOption.Validate(),
		o.vexDocOptions.Validate(),
	)
}

func (o *commitOptions) AddFlags(cmd *cobra.Command) {
}

func addCommit(parentCmd *cobra.Command) {
	commitCmd := &cobra.Command{
		Short: fmt.Sprintf("%s commit: creates a new VEX statement in a commit", appname),
		Long: fmt.Sprintf(`%s commit: creates a new VEX document in a commit

The commit subcommand generates a single statement inside a commit
from the command line. This is intended for developers to submit statements that are
 later picked up and aggregated inside a release workflow.

Examples:

# Generate a document stating that CVE-2023-12345 was fixed in the 
# git package of Wolfi:

%s create "pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64" CVE-2023-12345 fixed

# You can specify more than one product. %s will read one from
# the argument but you can control all parameters through command line
# flags. Here's an example with two products in the same document:

%s create --product="pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64" \
              --product="pkg:apk/wolfi/git@2.39.0-r1?arch=armv7" \
              --vuln="CVE-2023-12345" \
              --status="fixed"

# not_affected statements need a justification:

%s create --product="pkg:apk/wolfi/trivy@0.36.1-r0?arch=x86_64" \
              --vuln="CVE-2023-12345" \
              --status="not_affected" \
              --justification="component_not_present" 

`, appname, appname, appname, appname, appname, appname),
		Use:               "commit [flags]",
		Example:           fmt.Sprintf("%s commit", appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		RunE: func(cmd *cobra.Command, args []string) error {
			form := huh.NewForm(
				huh.NewGroup(
					huh.NewInput().
						Title("Enter the vulnerability ID").
						Value(&vulnID),
					huh.NewSelect[string]().
						Options(huh.NewOption("not_affected", "not_affected"), huh.NewOption("affected", "affected"), huh.NewOption("fixed", "fixed"), huh.NewOption("under_investigation", "under_investigation")).
						Title("Select the status").
						Value(&status),
					huh.NewSelect[string]().
						Options(huh.NewOption("component_not_present", "component_not_present"), huh.NewOption("vulnerable_code_not_present", "vulnerable_code_not_present"), huh.NewOption("vulnerable_code_not_in_execute_path", "vulnerable_code_not_in_execute_path"), huh.NewOption("vulnerable_code_cannot_be_controlled_by_adversary", "vulnerable_code_cannot_be_controlled_by_adversary"), huh.NewOption("inline_mitigations_already_exist", "inline_mitigations_already_exist")).
						Title("Select the justification").
						Value(&justification),
				),
			)

			err := form.Run()
			if err != nil {
				log.Fatal(err)
			}

			t := time.Now()

			state := vex.Statement{
				Vulnerability:            vex.Vulnerability{ID: vulnID},
				Timestamp:                &t,
				LastUpdated:              nil,
				Status:                   vex.Status(status),
				Justification:            vex.Justification(justification),
				ActionStatementTimestamp: nil,
			}

			json, err := json.Marshal(state)
			if err != nil {
				log.Fatal(err)
			}

			r, err := git.PlainOpen(".")
			if err != nil {
				log.Fatal(err)
			}

			w, err := r.Worktree()
			if err != nil {
				log.Fatal(err)
			}

			c, err := r.ConfigScoped(config.GlobalScope)
			if err != nil {
				log.Fatal(err)
			}

			// TODO: Need to add signing key and some other stuff
			w.Commit(string(json), &git.CommitOptions{
				All: false,
				Author: &object.Signature{
					Name:  c.User.Name,
					Email: c.User.Email,
					When:  t,
				},
				AllowEmptyCommits: true,
			},
			)
			return nil
		},
	}

	parentCmd.AddCommand(commitCmd)
}
