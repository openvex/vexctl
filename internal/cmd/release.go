/*
Copyright 2022 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/caarlos0/log"
	"github.com/google/go-github/v61/github"
	"github.com/goreleaser/goreleaser/pkg/config"
	"github.com/goreleaser/goreleaser/pkg/context"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/openvex/vexctl/internal/client"
	"github.com/openvex/vexctl/internal/pipe/git"
	"github.com/spf13/cobra"
)

type releaseOptions struct{}

func (ro *releaseOptions) AddFlags(cmd *cobra.Command) {
}

func (ro *releaseOptions) Validate() error {
	return errors.Join()
}

func addRelease(parentCmd *cobra.Command) {
	opts := mergeOptions{}
	releaseCmd := &cobra.Command{
		Short: fmt.Sprintf("%s release: runs the release workflow finding and attesting vex statements", appname),
		Long: fmt.Sprintf(`%s merge: runs the release workflow finding and attesting vex statements

# TODO: UPDATE EXAMPLES
Examples:

# Merge two documents into one
%s merge document1.vex.json document2.vex.json > new.vex.json

# Merge two documents into one, but only one product
%s merge --product="pkg:apk/wolfi/bash@1.0" document1.vex.json document2.vex.json

# Merge vulnerability data from two documents into one
%s merge --vulnerability=CVE-2022-3294 document1.vex.json document2.vex.json

`, appname, appname, appname, appname),
		Use:               "release",
		SilenceUsage:      false,
		SilenceErrors:     false,
		PersistentPreRunE: initLogging,
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Info("Running release command")
			log.Debug("Getting latest git tag")

			proj := config.Project{}
			ctx := context.New(proj)
			pipe := git.Pipe{}
			err := pipe.Run(ctx)
			if err != nil {
				log.Fatal(err.Error())
			}

			prev, current := git.ComparePair(*ctx)

			tok := os.Getenv("GITHUB_TOKEN")
			if tok == "" {
				log.Fatal("GITHUB_TOKEN environment variable not set. Currently only Github Actions is supported.")
			}

			repo := os.Getenv("GITHUB_REPOSITORY")
			if tok == "" {
				log.Fatal("GITHUB_REPOSITORY environment variable not set. Currently only Github Actions is supported.")
			}

			split := strings.Split(repo, "/")
			owner := split[0]
			name := split[1]

			ghc, err := client.NewGitHubClient(ctx, tok)
			opts := &github.ListOptions{PerPage: 100}

			release, _, err := ghc.Repositories.GetReleaseByTag(ctx, owner, name, current)
			if err != nil {
				log.Fatal(err.Error())
			}

			statements := []vex.Statement{}
			for {

				result, resp, err := ghc.Repositories.CompareCommits(ctx, owner, name, prev, current, &github.ListOptions{PerPage: 100})
				if err != nil {
					log.Fatal(err.Error())
				}

				for _, commit := range result.Commits {
					var state vex.Statement
					mess := commit.GetCommit().Message
					err := json.Unmarshal([]byte(*mess), &state)
					if err != nil {
						log.Debug("Failed to parse message %s, assuming not a vex statement and continuing")
						continue
					}
					statements = append(statements, state)
				}
				if resp.NextPage == 0 {
					break
				}
				opts.Page = resp.NextPage
			}

			if len(statements) == 0 {
				log.Info("No vex statements found")
				return nil
			} else {
				now := time.Now()
				for _, statement := range statements {
					statement.Timestamp = &now
					statement.Products = append(statement.Products, vex.Product{
						Component:     vex.Component{ID: fmt.Sprintf("pkg:%s/%s", owner, name)},
						Subcomponents: []vex.Subcomponent{{vex.Component{ID: release.GetTagName()}}},
					})
				}
				vex := &vex.VEX{
					Metadata: vex.Metadata{
						Author:     release.Author.GetEmail(),
						Timestamp:  &now,
						AuthorRole: "releaser",
						Supplier:   owner,
						Tooling:    "Generated using vexctl release",
					},
					Statements: statements,
				}

				log.Info("Printing VEX Document for testing")
				json, err := json.Marshal(vex)
				if err != nil {
					log.Fatal(err.Error())
				}

				log.Info(string(json))

			}
			return err
		},
	}

	opts.productsListOption.AddFlags(releaseCmd)
	opts.vulnerabilityListOption.AddFlags(releaseCmd)
	opts.vexDocOptions.AddFlags(releaseCmd)

	parentCmd.AddCommand(releaseCmd)
}
