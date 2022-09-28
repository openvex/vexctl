/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package mrc

import (
	"fmt"

	"chainguard.dev/mrclean/pkg/sarif"
	"chainguard.dev/mrclean/pkg/vex"
)

type MRC struct {
	impl    Implementation
	Options Options
}

type Options struct {
	Products []string // List of products to match in CSAF docs
	Format   string   // Firmat of the vex documents
}

func New() *MRC {
	return &MRC{
		impl: &defaultMRCImplementation{},
	}
}

// ApplyFiles takes a list of paths to vex files and applies them to a report
func (mrc *MRC) ApplyFiles(r *sarif.Report, files []string) (*sarif.Report, error) {
	vexes := []*vex.VEX{}
	for _, path := range files {
		var v *vex.VEX
		var err error
		switch mrc.Options.Format {
		case "vex", "json", "":
			v, err = vex.OpenJSON(path)
		case "yaml":
			v, err = vex.OpenYAML(path)
		case "csaf":
			v, err = vex.OpenCSAF(path, mrc.Options.Products)
		}
		if err != nil {
			return nil, fmt.Errorf("opening document: %w", err)
		}
		vexes = append(vexes, v)
	}
	return mrc.Apply(r, vexes)
}

// Apply takes a sarif report and applies one or more vex documents
func (mrc *MRC) Apply(r *sarif.Report, vexDocs []*vex.VEX) (*sarif.Report, error) {
	vexDocs = vex.Sort(vexDocs)
	var err error
	for i, doc := range vexDocs {
		r, err = mrc.impl.ApplySingleVEX(r, doc)
		if err != nil {
			return nil, fmt.Errorf("applying vex document #%d: %w", i, err)
		}
	}

	return r, nil
}
