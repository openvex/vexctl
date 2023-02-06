/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package ctl

import (
	"context"
	"fmt"

	"github.com/openvex/go-vex/pkg/sarif"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/sirupsen/logrus"

	"github.com/openvex/vexctl/pkg/attestation"
)

const errNoImage = "some entries are not container images: %v"

type VexCtl struct {
	impl    Implementation
	Options Options
}

type Options struct {
	Products []string // List of products to match in CSAF docs
	Format   string   // Firmat of the vex documents
	Sign     bool     // When true, attestations will be signed before attaching
}

func New() *VexCtl {
	return &VexCtl{
		impl: &defaultVexCtlImplementation{},
	}
}

// ApplyFiles takes a list of paths to vex files and applies them to a report
func (vexctl *VexCtl) ApplyFiles(r *sarif.Report, files []string) (*sarif.Report, error) {
	vexes, err := vexctl.impl.OpenVexData(vexctl.Options, files)
	if err != nil {
		return nil, fmt.Errorf("opening vex data: %w", err)
	}

	return vexctl.Apply(r, vexes)
}

// Apply takes a sarif report and applies one or more vex documents
func (vexctl *VexCtl) Apply(r *sarif.Report, vexDocs []*vex.VEX) (finalReport *sarif.Report, err error) {
	// Sort the docs by date
	vexDocs = vexctl.impl.Sort(vexDocs)

	// Apply the sorted documents to the report
	for i, doc := range vexDocs {
		finalReport, err = vexctl.impl.ApplySingleVEX(r, doc)
		if err != nil {
			return nil, fmt.Errorf("applying vex document #%d: %w", i, err)
		}
	}

	return finalReport, nil
}

// Generate an attestation from a VEX
func (vexctl *VexCtl) Attest(vexDataPath string, manSubjects []string) (*attestation.Attestation, error) {
	doc, err := vexctl.impl.OpenVexData(vexctl.Options, []string{vexDataPath})
	if err != nil {
		return nil, fmt.Errorf("opening vex data: %w", err)
	}

	// Generate the attestation
	att := attestation.New()
	att.Predicate = *doc[0]
	subjects := manSubjects

	// If we did not get a specific list of subjects to attest, we default
	// to the products of the VEX document.
	if len(manSubjects) == 0 {
		subjects, err = vexctl.impl.ListDocumentProducts(doc[0])
		if err != nil {
			return nil, fmt.Errorf("listing document products")
		}
	}

	imageSubjects, otherSubjects, err := vexctl.impl.NormalizeImageRefs(subjects)
	if err != nil {
		return nil, fmt.Errorf("normalizing VEX products to attest: %w", err)
	}

	if len(otherSubjects) != 0 {
		// if subject are manual, fail
		if len(manSubjects) > 0 {
			return nil, fmt.Errorf(errNoImage, otherSubjects)
		}
		// if from a doc, we ignore and skip
		logrus.Warnf(errNoImage, otherSubjects)
	}

	if err := att.AddImageSubjects(imageSubjects); err != nil {
		return nil, fmt.Errorf("adding image references to attestation: %w", err)
	}

	// Validate subjects came from the doc
	if err := vexctl.impl.VerifyImageSubjects(att, doc[0]); err != nil {
		return nil, fmt.Errorf("checking subjects: %w", err)
	}

	// Sign the attestation
	if vexctl.Options.Sign {
		if err := att.Sign(); err != nil {
			return att, fmt.Errorf("signing attestation: %w", err)
		}
	}

	return att, nil
}

// Attach attaches an attestation to a list of images
func (vexctl *VexCtl) Attach(ctx context.Context, att *attestation.Attestation) (err error) {
	if err := vexctl.impl.Attach(ctx, att); err != nil {
		return fmt.Errorf("attaching attestation: %w", err)
	}

	return nil
}

// VexFromURI return a vex doc from a path, image ref or URI
func (vexctl *VexCtl) VexFromURI(ctx context.Context, uri string) (vexData *vex.VEX, err error) {
	sourceType, err := vexctl.impl.SourceType(uri)
	if err != nil {
		return nil, fmt.Errorf("resolving VEX source: %w", err)
	}
	var vexes []*vex.VEX
	switch sourceType {
	case "file":
		vexes, err = vexctl.impl.OpenVexData(vexctl.Options, []string{uri})
		if err == nil {
			vexData = vexes[0]
		}
	case "image":
		vexes, err = vexctl.impl.ReadImageAttestations(ctx, vexctl.Options, uri)
		if err == nil {
			if len(vexes) == 0 {
				return nil, fmt.Errorf("no attestations found in image")
			}
			vexData = vexes[0]
		}
	default:
		return nil, fmt.Errorf("unable to resolve source type (file or image)")
	}

	if err != nil {
		return nil, fmt.Errorf("opening vex data from %s: %w", uri, err)
	}
	return vexData, err
}

// Merge combines several documents into one
func (vexctl *VexCtl) Merge(ctx context.Context, opts *MergeOptions, vexes []*vex.VEX) (*vex.VEX, error) {
	doc, err := vexctl.impl.Merge(ctx, opts, vexes)
	if err != nil {
		return nil, fmt.Errorf("merging %d documents: %w", len(vexes), err)
	}
	return doc, nil
}

// MergeFiles is like Merge but takes filepaths instead of actual VEX documents
func (vexctl *VexCtl) MergeFiles(ctx context.Context, opts *MergeOptions, filePaths []string) (*vex.VEX, error) {
	vexes, err := vexctl.impl.LoadFiles(ctx, filePaths)
	if err != nil {
		return nil, fmt.Errorf("loading files: %w", err)
	}

	// Merge'em Dano
	doc, err := vexctl.impl.Merge(ctx, opts, vexes)
	if err != nil {
		return nil, fmt.Errorf("merging %d documents: %w", len(vexes), err)
	}
	return doc, nil
}
