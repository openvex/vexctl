/*
Copyright 2022 Chainguard, Inc.
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

const appname = "mrclean"

var rootCmd = &cobra.Command{
	Short: "A tool for working with VEX",
	Long: `A tool for working with VEX

Intro Coming Soon™

`,
	Use:               "bom",
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

	addVEX(rootCmd)
	addAttest(rootCmd)
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
