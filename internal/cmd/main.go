/*
Copyright 2022 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"sigs.k8s.io/release-utils/log"
	"sigs.k8s.io/release-utils/version"
)

const appname = "vexctl"

var rootCmd = &cobra.Command{
	Short: "A tool for working with VEX data",
	Long: `A tool for working with VEX data

vexctl is a tool to work with VEX (Vulnerability Exploitability eXchange)
data and to use it to interpret security scanner results.

It enables users to attach vex information to container images and to
filter result sets using the VEX information to get a clear view of which
vulnerabilities apply to their project.

For more information see the --attest and --filter subcomands

`,
	Use:               appname,
	SilenceUsage:      false,
	PersistentPreRunE: initLogging,
}

type commandLineOptions struct {
	logLevel string
}

var commandLineOpts = commandLineOptions{}

func init() {
	rootCmd.PersistentFlags().StringVar(
		&commandLineOpts.logLevel,
		"log-level",
		"info",
		fmt.Sprintf("the logging verbosity, either %s", log.LevelNames()),
	)

	addFilter(rootCmd)
	addAttest(rootCmd)
	addMerge(rootCmd)
	addCreate(rootCmd)
	addList(rootCmd)
	addAdd(rootCmd)
	addGenerate(rootCmd)
	rootCmd.AddCommand(version.WithFont("doom"))
}

func initLogging(*cobra.Command, []string) error {
	return log.SetupGlobalLogger(commandLineOpts.logLevel)
}

// Execute builds the command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		logrus.Fatal(err)
	}
}
