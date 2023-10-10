/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package ctl

import (
	"context"
	"testing"

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/stretchr/testify/require"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/openvex/vexctl/pkg/attestation"
)

func TestNormalizeProducts(t *testing.T) {
	impl := defaultVexCtlImplementation{}
	for _, tc := range []struct {
		name                 string
		products             []productRef
		expectedImage        []productRef
		expectedOther        []productRef
		expectedUnattestable []productRef
		shouldFail           bool
	}{
		{
			name:                 "docker hub reference",
			products:             []productRef{{Name: "nginx"}},
			expectedImage:        []productRef{{Name: "nginx", Hashes: make(map[vex.Algorithm]vex.Hash)}},
			expectedOther:        []productRef{},
			expectedUnattestable: []productRef{},
			shouldFail:           false,
		},
		{
			name:                 "custom registry",
			products:             []productRef{{Name: "registry.k8s.io/kube-apiserver"}},
			expectedImage:        []productRef{{Name: "registry.k8s.io/kube-apiserver", Hashes: make(map[vex.Algorithm]vex.Hash)}},
			expectedOther:        []productRef{},
			expectedUnattestable: []productRef{},
			shouldFail:           false,
		},
		{
			name:                 "Custom registry, tagged image",
			products:             []productRef{{Name: "registry.k8s.io/kube-apiserver:v1.26.0"}},
			expectedImage:        []productRef{{Name: "registry.k8s.io/kube-apiserver:v1.26.0", Hashes: make(map[vex.Algorithm]vex.Hash)}},
			expectedOther:        []productRef{},
			expectedUnattestable: []productRef{},
			shouldFail:           false,
		},
		{
			name:                 "purl, custom registry",
			products:             []productRef{{Name: "pkg:oci/kube-apiserver?repository_url=registry.k8s.io&tag=v1.26.0"}},
			expectedImage:        []productRef{{Name: "registry.k8s.io/kube-apiserver:v1.26.0", Hashes: make(map[vex.Algorithm]vex.Hash)}},
			expectedOther:        []productRef{},
			expectedUnattestable: []productRef{},
			shouldFail:           false,
		},
		{
			name:                 "purl, dockerhub",
			products:             []productRef{{Name: "pkg:oci/nginx"}},
			expectedImage:        []productRef{{Name: "nginx", Hashes: make(map[vex.Algorithm]vex.Hash)}},
			expectedOther:        []productRef{},
			expectedUnattestable: []productRef{},
			shouldFail:           false,
		},
		{
			name:     "purl, with digest",
			products: []productRef{{Name: "pkg:oci/alpine@sha256%3Af271e74b17ced29b915d351685fd4644785c6d1559dd1f2d4189a5e851ef753a"}},
			expectedImage: []productRef{{
				Name: "alpine@sha256:f271e74b17ced29b915d351685fd4644785c6d1559dd1f2d4189a5e851ef753a",
				Hashes: map[vex.Algorithm]vex.Hash{
					vex.SHA256: vex.Hash("f271e74b17ced29b915d351685fd4644785c6d1559dd1f2d4189a5e851ef753a"),
				},
			}},
			expectedOther:        []productRef{},
			expectedUnattestable: []productRef{},
			shouldFail:           false,
		},
		{
			name:                 "other purl",
			products:             []productRef{{Name: "pkg:apk/wolfi/bash@1.0.0"}},
			expectedImage:        []productRef{},
			expectedOther:        []productRef{},
			expectedUnattestable: []productRef{{Name: "pkg:apk/wolfi/bash@1.0.0", Hashes: make(map[vex.Algorithm]vex.Hash)}},
			shouldFail:           false,
		},
		{
			name: "other purl with hashes",
			products: []productRef{
				{
					Name: "pkg:apk/wolfi/bash@1.0.0",
					Hashes: map[vex.Algorithm]vex.Hash{
						vex.SHA256: vex.Hash("805f9e876d84aa72b0c10a810d4e16bf84b16c5399ddab86fb973e561e86de37"),
					},
				},
			},
			expectedImage: []productRef{},
			expectedOther: []productRef{
				{
					Name: "pkg:apk/wolfi/bash@1.0.0",
					Hashes: map[vex.Algorithm]vex.Hash{
						vex.SHA256: vex.Hash("805f9e876d84aa72b0c10a810d4e16bf84b16c5399ddab86fb973e561e86de37"),
					},
				},
			},
			expectedUnattestable: []productRef{},
			shouldFail:           false,
		},
		{
			name:                 "mixed image ref and non-oci purl",
			products:             []productRef{{Name: "pkg:apk/wolfi/bash@1.0.0"}, {Name: "nginx"}},
			expectedImage:        []productRef{{Name: "nginx", Hashes: make(map[vex.Algorithm]vex.Hash)}},
			expectedOther:        []productRef{},
			expectedUnattestable: []productRef{{Name: "pkg:apk/wolfi/bash@1.0.0", Hashes: make(map[vex.Algorithm]vex.Hash)}},
			shouldFail:           false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			image, other, unattestable, err := impl.NormalizeProducts(tc.products)
			if tc.shouldFail {
				require.Error(t, err)
				return
			}
			require.Equal(t, tc.expectedImage, image, "image matches")
			require.Equal(t, tc.expectedOther, other, "other matches")
			require.Equal(t, tc.expectedUnattestable, unattestable, "unattestable matches")
		})
	}
}

func TestListDocumentProducts(t *testing.T) {
	impl := defaultVexCtlImplementation{}
	for _, tc := range []struct {
		name     string
		path     string
		expected []productRef
	}{
		{
			"image identifiers",
			"testdata/images.vex.json",
			[]productRef{
				{Name: "nginx", Hashes: make(map[vex.Algorithm]vex.Hash)},
				{Name: "pkg:oci/alpine@sha256%3Af271e74b17ced29b915d351685fd4644785c6d1559dd1f2d4189a5e851ef753a", Hashes: make(map[vex.Algorithm]vex.Hash)},
				{Name: "pkg:oci/kube-apiserver?repository_url=registry.k8s.io&tag=v1.26.0", Hashes: make(map[vex.Algorithm]vex.Hash)},
				{Name: "registry.k8s.io/kube-apiserver:v1.26.0", Hashes: make(map[vex.Algorithm]vex.Hash)},
			},
		},
		{
			"openvex-v0.0.1",
			"testdata/v001-1.vex.json",
			[]productRef{{Name: "pkg:apk/wolfi/bash@1.0.0", Hashes: make(map[vex.Algorithm]vex.Hash)}},
		},
		{
			"openvex-v0.2.0",
			"testdata/v020-1.vex.json",
			[]productRef{{Name: "pkg:apk/wolfi/bash@1.0.0", Hashes: make(map[vex.Algorithm]vex.Hash)}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := vex.Open(tc.path)
			require.NoError(t, err)
			prods, err := impl.ListDocumentProducts(doc)
			require.NoError(t, err)
			require.Equal(t, tc.expected, prods)
		})
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
			// Tags are not translated
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

	tests := []struct {
		name        string
		opts        MergeOptions
		docs        []*vex.VEX
		expectedDoc *vex.VEX
		shouldErr   bool
	}{
		// Zero docs should fail
		{
			name:        "Zero docs should fail",
			opts:        MergeOptions{},
			docs:        []*vex.VEX{},
			expectedDoc: &vex.VEX{},
			shouldErr:   true,
		},
		// One doc results in the same doc
		{
			name:        "One doc results in the same doc",
			opts:        MergeOptions{},
			docs:        []*vex.VEX{doc1},
			expectedDoc: doc1,
			shouldErr:   false,
		},
		// Two docs, as they are
		{
			name: "Two docs, as they are",
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
			name: "Two docs, filter product",
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
			name: " Two docs, filter vulnerability",
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
	}

	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			impl := defaultVexCtlImplementation{}
			doc, err := impl.Merge(ctx, &tests[i].opts, test.docs)
			if test.shouldErr {
				require.Error(t, err)
				return
			}
			// Check doc
			require.Len(t, doc.Statements, len(test.expectedDoc.Statements))
			require.Equal(t, doc.Statements, test.expectedDoc.Statements)
		})
	}
}
