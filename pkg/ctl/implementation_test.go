/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package ctl

import (
	"context"
	"testing"

	intoto "github.com/in-toto/in-toto-golang/in_toto"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/openvex/vexctl/pkg/attestation"
	"github.com/stretchr/testify/require"
)

func TestNormalizeImageRefs(t *testing.T) {
	impl := defaultVexCtlImplementation{}
	for _, tc := range []struct {
		products     []string
		expectedGood []string
		expectedBad  []string
		shouldFail   bool
	}{
		// docker hub reference
		{
			products:     []string{"nginx"},
			expectedGood: []string{"nginx"},
			expectedBad:  []string{},
			shouldFail:   false,
		},
		// Custom registry
		{
			products:     []string{"registry.k8s.io/kube-apiserver"},
			expectedGood: []string{"registry.k8s.io/kube-apiserver"},
			expectedBad:  []string{},
			shouldFail:   false,
		},
		// Custom registry, tagged image
		{
			products:     []string{"registry.k8s.io/kube-apiserver:v1.26.0"},
			expectedGood: []string{"registry.k8s.io/kube-apiserver:v1.26.0"},
			expectedBad:  []string{},
			shouldFail:   false,
		},
		// purl, custom registry
		{
			products:     []string{"pkg:oci/kube-apiserver?repository_url=registry.k8s.io&tag=v1.26.0"},
			expectedGood: []string{"registry.k8s.io/kube-apiserver:v1.26.0"},
			expectedBad:  []string{},
			shouldFail:   false,
		},
		// purl, dockerhub
		{
			products:     []string{"pkg:oci/nginx"},
			expectedGood: []string{"nginx"},
			expectedBad:  []string{},
			shouldFail:   false,
		},
		// purl, with digest
		{
			products:     []string{"pkg:oci/alpine@sha256%3Af271e74b17ced29b915d351685fd4644785c6d1559dd1f2d4189a5e851ef753a"},
			expectedGood: []string{"alpine@sha256:f271e74b17ced29b915d351685fd4644785c6d1559dd1f2d4189a5e851ef753a"},
			expectedBad:  []string{},
			shouldFail:   false,
		},
		// other purl
		{
			products:     []string{"pkg:apk/wolfi/bash@1.0.0"},
			expectedGood: []string{},
			expectedBad:  []string{"pkg:apk/wolfi/bash@1.0.0"},
			shouldFail:   false,
		},
		// mixed good and bad
		{
			products:     []string{"pkg:apk/wolfi/bash@1.0.0", "nginx"},
			expectedGood: []string{"nginx"},
			expectedBad:  []string{"pkg:apk/wolfi/bash@1.0.0"},
			shouldFail:   false,
		},
	} {
		good, bad, err := impl.NormalizeImageRefs(tc.products)
		if tc.shouldFail {
			require.Error(t, err)
			continue
		}
		require.Equal(t, tc.expectedGood, good)
		require.Equal(t, tc.expectedBad, bad)
	}
}

func TestListDocumentProducts(t *testing.T) {
	impl := defaultVexCtlImplementation{}
	for _, tc := range []struct {
		path     string
		expected []string
	}{
		{
			"testdata/images.vex.json",
			[]string{
				"nginx",
				"pkg:oci/alpine@sha256%3Af271e74b17ced29b915d351685fd4644785c6d1559dd1f2d4189a5e851ef753a",
				"pkg:oci/kube-apiserver?repository_url=registry.k8s.io&tag=v1.26.0",
				"registry.k8s.io/kube-apiserver:v1.26.0",
			},
		},
		{
			"testdata/v001-1.vex.json",
			[]string{"pkg:apk/wolfi/bash@1.0.0"},
		},
		{
			"testdata/v020-1.vex.json",
			[]string{"pkg:apk/wolfi/bash@1.0.0"},
		},
	} {
		doc, err := vex.Open(tc.path)
		require.NoError(t, err)
		prods, err := impl.ListDocumentProducts(doc)
		require.NoError(t, err)
		require.Equal(t, tc.expected, prods)
	}
}

func TestVerifyImageSubjects(t *testing.T) {
	impl := defaultVexCtlImplementation{}
	att := attestation.New()
	for _, tc := range []struct {
		subjects []intoto.Subject
		products []string
		mustErr  bool
	}{
		{
			// Literal match
			[]intoto.Subject{
				{Name: "ghcr.io/test/image:canary"},
			},
			[]string{"ghcr.io/test/image:canary"},
			false,
		},
		{
			// Tags are note translated
			[]intoto.Subject{
				{Name: "ghcr.io/test/image:canary"},
			},
			[]string{"ghcr.io/test/image@sha256:74634d9736a45ca9f6e1187e783492199e020f4a5c19d0b1abc2b604f894ac99"},
			true,
		},
		{
			// purls need to be translated
			[]intoto.Subject{
				{Name: "ghcr.io/test/image@sha256:74634d9736a45ca9f6e1187e783492199e020f4a5c19d0b1abc2b604f894ac99"},
			},
			[]string{"pkg:oci/image@sha256:74634d9736a45ca9f6e1187e783492199e020f4a5c19d0b1abc2b604f894ac99?repository_url=ghcr.io/test"},
			false,
		},
	} {
		att.Subject = tc.subjects
		doc := vex.New()
		for _, p := range tc.products {
			doc.Statements = append(
				doc.Statements, vex.Statement{
					Products: []vex.Product{
						{
							Component: vex.Component{
								ID:          p,
								Hashes:      map[vex.Algorithm]vex.Hash{},
								Identifiers: map[vex.IdentifierType]string{},
							},
							Subcomponents: []vex.Subcomponent{},
						},
					},
				},
			)
		}
		err := impl.VerifyImageSubjects(att, &doc)
		if tc.mustErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
	}
}

func TestMerge(t *testing.T) {
	ctx := context.Background()
	doc1, err := vex.Open("testdata/v001-1.vex.json")
	require.NoError(t, err)
	doc2, err := vex.Open("testdata/v001-2.vex.json")
	require.NoError(t, err)

	doc3, err := vex.Open("testdata/v020-1.vex.json")
	require.NoError(t, err)
	doc4, err := vex.Open("testdata/v020-2.vex.json")
	require.NoError(t, err)

	impl := defaultVexCtlImplementation{}
	for _, tc := range []struct {
		opts        MergeOptions
		docs        []*vex.VEX
		expectedDoc *vex.VEX
		shouldErr   bool
	}{
		// Zero docs should fail
		{
			opts:        MergeOptions{},
			docs:        []*vex.VEX{},
			expectedDoc: &vex.VEX{},
			shouldErr:   true,
		},
		// One doc results in the same doc
		{
			opts:        MergeOptions{},
			docs:        []*vex.VEX{doc1},
			expectedDoc: doc1,
			shouldErr:   false,
		},
		// Two docs, as they are
		{
			opts: MergeOptions{},
			docs: []*vex.VEX{doc1, doc2},
			expectedDoc: &vex.VEX{
				Metadata: vex.Metadata{},
				Statements: []vex.Statement{
					doc1.Statements[0],
					doc2.Statements[0],
				},
			},
			shouldErr: false,
		},
		// Two docs, filter product
		{
			opts: MergeOptions{
				Products: []string{"pkg:apk/wolfi/git@2.41.0-1"},
			},
			docs: []*vex.VEX{doc3, doc4},
			expectedDoc: &vex.VEX{
				Metadata: vex.Metadata{},
				Statements: []vex.Statement{
					doc4.Statements[0],
				},
			},
			shouldErr: false,
		},
		// Two docs, filter vulnerability
		{
			opts: MergeOptions{
				Vulnerabilities: []string{"CVE-9876-54321"},
			},
			docs: []*vex.VEX{doc3, doc4},
			expectedDoc: &vex.VEX{
				Metadata: vex.Metadata{},
				Statements: []vex.Statement{
					doc3.Statements[0],
				},
			},
			shouldErr: false,
		},
	} {
		doc, err := impl.Merge(ctx, &tc.opts, tc.docs)
		if tc.shouldErr {
			require.Error(t, err)
			continue
		}

		// Check doc
		require.Len(t, doc.Statements, len(tc.expectedDoc.Statements))
		require.Equal(t, doc.Statements, tc.expectedDoc.Statements)
	}
}
