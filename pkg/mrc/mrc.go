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
	impl MRCImplementation
}

func New() *MRC {
	return &MRC{
		impl: &defaultMRCImplementation{},
	}
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
