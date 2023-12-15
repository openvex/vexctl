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

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/openvex/vexctl/pkg/attestation"
)

const errNotAttestable = "some entries are not attestable as they don't have a hash: %v"

type VexCtl struct {
	impl    Implementation
	Options Options
}

type Options struct {
	Products []string // List of products to match in CSAF docs
	Format   string   // Firmat of the vex documents
	Sign     bool     // When true, attestations will be signed before attaching
}

// ProductRefs is a struct that captures a resolved component reference string
// and any hashes associated with it.
type productRef struct {
	Name   string
	Hashes map[vex.Algorithm]vex.Hash
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

// Attest generates an attestation from a list of identifiers
func (vexctl *VexCtl) Attest(vexDataPath string, subjectStrings []string) (*attestation.Attestation, error) {
	doc, err := vexctl.impl.OpenVexData(vexctl.Options, []string{vexDataPath})
	if err != nil {
		return nil, fmt.Errorf("opening vex data: %w", err)
	}

	// Generate the attestation
	att := attestation.New()
	att.Predicate = *doc[0]
	subjects := []productRef{}
	for _, s := range subjectStrings {
		subjects = append(subjects, productRef{Name: s})
	}

	// If we did not get a specific list of subjects to attest, we default
	// to the products of the VEX document.
	if len(subjects) == 0 {
		subjects, err = vexctl.impl.ListDocumentProducts(doc[0])
		if err != nil {
			return nil, fmt.Errorf("listing document products: %w", err)
		}
	}

	imageSubjects, otherSubjects, unattestableSubjects, err := vexctl.impl.NormalizeProducts(subjects)
	if err != nil {
		return nil, fmt.Errorf("normalizing VEX products to attest: %w", err)
	}

	if len(unattestableSubjects) != 0 {
		// If subjects are manual, fail
		if len(subjectStrings) > 0 {
			return nil, fmt.Errorf(errNotAttestable, unattestableSubjects)
		}
		// If we are just checking an existing document, we dont err. We skip
		// any unattestable subjects.
		logrus.Warnf(errNotAttestable, unattestableSubjects)
	}

	allSubjects := []productRef{}
	allSubjects = append(allSubjects, imageSubjects...)
	allSubjects = append(allSubjects, otherSubjects...)
	subs := []intoto.Subject{}
	for _, sub := range allSubjects {
		d := map[string]string{}
		// TODO(puerco): Move this logic to the go-vex hash structs
		for a, h := range sub.Hashes {
			switch a {
			case vex.SHA256:
				d["sha256"] = string(h)
			case vex.SHA512:
				d["sha512"] = string(h)
			}
		}
		subs = append(subs, intoto.Subject{
			Name:   sub.Name,
			Digest: d,
		})
	}

	if err := att.AddSubjects(subs); err != nil {
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
func (vexctl *VexCtl) Attach(ctx context.Context, att *attestation.Attestation, refs ...string) (err error) {
	if err := vexctl.impl.Attach(ctx, att, refs...); err != nil {
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

type GenerateOpts struct {
	// TemplatesPath is a file or directory containing the OpenVEX files to be
	// used as templates to generate the data.
	TemplatesPath string
}

const DefaultTemplatesPath = ".openvex/templates"

// Generate generates the upt to date vex data about an artifact from information
// captured in golden VEX documents.
func (vexctl *VexCtl) Generate(opts *GenerateOpts, products []*vex.Product) (*vex.VEX, error) {
	// Read the golden data files. This returns a vex document with all
	// statements applicable to the products
	doc, err := vexctl.impl.ReadTemplateData(opts, products)
	if err != nil {
		return nil, fmt.Errorf("reading template data: %w", err)
	}

	// TODO(puerco): Normalize identifiers
	return doc, nil
}
