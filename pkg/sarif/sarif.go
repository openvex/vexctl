/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package sarif

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	gosarif "github.com/owenrumney/go-sarif/sarif"
)

type Report struct {
	gosarif.Report
}

func Open(path string) (*Report, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opening yaml file: %w", err)
	}
	report := New()
	if err := json.Unmarshal(data, report); err != nil {
		return nil, fmt.Errorf("unmarshalling vex data: %w", err)
	}
	return report, nil
}

func New() *Report {
	return &Report{
		Report: gosarif.Report{},
	}
}

func (report *Report) ToJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encoding sarif report: %w", err)
	}
	return nil

}
