/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package mrc

import (
	"regexp"

	gosarif "github.com/owenrumney/go-sarif/sarif"
	"github.com/sirupsen/logrus"

	"chainguard.dev/mrclean/pkg/sarif"
	"chainguard.dev/mrclean/pkg/vex"
)

type Implementation interface {
	ApplySingleVEX(*sarif.Report, *vex.VEX) (*sarif.Report, error)
	SortDocuments([]*vex.VEX) []*vex.VEX
}

type defaultMRCImplementation struct{}

var cveRegexp regexp.Regexp

func init() {
	cveRegexp = *regexp.MustCompile(`^(CVE-\d+-\d+)`)
}

func (impl *defaultMRCImplementation) SortDocuments(docs []*vex.VEX) []*vex.VEX {
	return vex.Sort(docs)
}

func (impl *defaultMRCImplementation) ApplySingleVEX(report *sarif.Report, vexDoc *vex.VEX) (*sarif.Report, error) {
	newReport := *report
	logrus.Infof("VEX document contains %d statements", len(vexDoc.Statements))
	logrus.Infof("+%v Runs: %d\n", report, len(report.Runs))
	// Search for negative VEX statements, that is those that cancel a CVE
	for i := range report.Runs {
		newResults := []*gosarif.Result{}
		logrus.Infof("Inspecting run #%d containing %d results", i, len(report.Runs[i].Results))
		for _, res := range report.Runs[i].Results {
			// Normalize the CVE IDs
			m := cveRegexp.FindStringSubmatch(*res.RuleID)
			if len(m) != 2 {
				logrus.Errorf(
					"Invalid rulename in sarif report, expected CVE identifier, got %s",
					*res.RuleID,
				)
				newResults = append(newResults, res)
				continue
			}
			id := m[1]
			// TODO: Trim rule ID to CVE as Grype adds junk to the CVE ID
			statement := vexDoc.StatementFromID(id)
			logrus.Infof("Checking %s", id)
			if statement != nil {
				logrus.Infof("Statement is for %s and status is %s", statement.Vulnerability, statement.Status)
				if statement.Status == vex.StatusNotAffected ||
					statement.Status == vex.StatusFixed {
					logrus.Infof("Found VEX Statement for %s: %s", id, statement.Status)
					continue
				}
			}
			newResults = append(newResults, res)
		}
		newReport.Runs[i].Results = newResults
	}
	return &newReport, nil
}
