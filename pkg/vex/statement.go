/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package vex

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// A Statement is a declaration conveying a single [status] for a single [vul_id] for one or more [product_id]s. A VEX Statement exists within a VEX Document.
type Statement struct {
	// [vul_id] SHOULD use existing and well known identifiers, for example:
	// CVE, the Global Security Database (GSD), or a supplier’s vulnerability
	// tracking system. It is expected that vulnerability identification systems
	// are external to and maintained separately from VEX.
	//
	// [vul_id] MAY be URIs or URLs.
	// [vul_id] MAY be arbitrary and MAY be created by the VEX statement [author].
	Vulnerability   string `json:"vulnerability"`
	VulnDescription string `json:"vuln_description,omitempty"`

	// Timestamp is the time at which the information expressed in the Statement
	// was known to be true.
	Timestamp time.Time `json:"timestamp"`

	// ProductIdentifiers
	// Product details MUST specify what Status applies to.
	// Product details MUST include [product_id] and MAY include [subcomponent_id].
	Products      []string `json:"products"`
	Subcomponents []string `json:"subcomponents,omitempty"`

	// A VEX statement MUST provide Status of the vulnerabilities with respect to the
	// products and components listed in the statement. Status MUST be one of the
	// Status const values, some of which have further options and requirements.
	Status Status `json:"status"`

	// [status_notes] MAY convey information about how [status] was determined
	// and MAY reference other VEX information.
	StatusNotes string `json:"status_notes,omitempty"`

	// For ”not_affected” status, a VEX statement MUST include a status Justification
	// that further explains the status.
	Justification Justification `json:"justification,omitempty"`

	// For ”not_affected” status, a VEX statement MAY include an ImpactStatement
	// that contains a description why the vulnerability cannot be exploited.
	ImpactStatement string `json:"impact_statement,omitempty"`

	// For "affected" status, a VEX statement MUST include an ActionStatement that
	// SHOULD describe actions to remediate or mitigate [vul_id].
	ActionStatement          string    `json:"action_statement,omitempty"`
	ActionStatementTimestamp time.Time `json:"action_statement_timestamp,omitempty"`
}

// Validate checks to see whether the given Statement is valid. If it's not, an
// error is returned explaining the reason the Statement is invalid. Otherwise,
// nil is returned.
func (stmt Statement) Validate() error { //nolint:gocritic // turning off for rule hugeParam
	if s := stmt.Status; !s.Valid() {
		return fmt.Errorf("invalid status value %q, must be one of [%s]", s, strings.Join(Statuses(), ", "))
	}

	if stmt.Status == StatusNotAffected {
		// require a justification
		j := stmt.Justification
		if j == "" {
			return fmt.Errorf("justification missing, it's required when using status %q", StatusNotAffected)
		}

		if !j.Valid() {
			return fmt.Errorf("invalid justification value %q, must be one of [%s]", j, strings.Join(Justifications(), ", "))
		}
	}

	if stmt.Status == StatusAffected {
		// require an action statement
		if stmt.ActionStatement == "" {
			return fmt.Errorf("action statement missing, it's required when using status %q", StatusAffected)
		}
	}

	return nil
}

// SortStatements does an "in-place" sort of the given slice of VEX statements.
//
// The documentTimestamp parameter is needed because statements without timestamps inherit the timestamp of the document.
func SortStatements(stmts []Statement, documentTimestamp time.Time) {
	sort.SliceStable(stmts, func(i, j int) bool {
		vulnComparison := strings.Compare(stmts[i].Vulnerability, stmts[j].Vulnerability)
		if vulnComparison != 0 {
			// i.e. different vulnerabilities; sort by string comparison
			return vulnComparison < 0
		}

		// i.e. the same vulnerability; sort statements by timestamp

		iTime := stmts[i].Timestamp
		if iTime.IsZero() {
			iTime = documentTimestamp
		}

		jTime := stmts[j].Timestamp
		if jTime.IsZero() {
			jTime = documentTimestamp
		}

		return iTime.Before(jTime)
	})
}
