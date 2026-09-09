/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package ctl

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	intoto "github.com/in-toto/attestation/go/v1"
	gosarif "github.com/owenrumney/go-sarif/sarif"
	"github.com/stretchr/testify/require"

	"github.com/openvex/go-vex/pkg/sarif"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/openvex/vexctl/pkg/attestation"
)

const (
	productNginx           = "nginx"
	productKubeAPIv1260    = "registry.k8s.io/kube-apiserver:v1.26.0"
	productWolfiBash       = "pkg:apk/wolfi/bash@1.0.0"
	productGHCRImage       = "ghcr.io/test/image:canary"
	productGHCRImageDigest = "ghcr.io/test/image@sha256:74634d9736a45ca9f6e1187e783492199e020f4a5c19d0b1abc2b604f894ac99"
	testdataTemplates      = "testdata/templates/"
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
			products:             []productRef{{Name: productNginx}},
			expectedImage:        []productRef{{Name: productNginx, Hashes: make(map[vex.Algorithm]vex.Hash)}},
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
			products:             []productRef{{Name: productKubeAPIv1260}},
			expectedImage:        []productRef{{Name: productKubeAPIv1260, Hashes: make(map[vex.Algorithm]vex.Hash)}},
			expectedOther:        []productRef{},
			expectedUnattestable: []productRef{},
			shouldFail:           false,
		},
		{
			name:                 "purl, custom registry",
			products:             []productRef{{Name: "pkg:oci/kube-apiserver?repository_url=registry.k8s.io/kube-apiserver/&tag=v1.26.0"}},
			expectedImage:        []productRef{{Name: productKubeAPIv1260, Hashes: make(map[vex.Algorithm]vex.Hash)}},
			expectedOther:        []productRef{},
			expectedUnattestable: []productRef{},
			shouldFail:           false,
		},
		{
			name:                 "purl, repository_url without package name",
			products:             []productRef{{Name: "pkg:oci/ubuntu?repository_url=localhost:5000/demo&tag=24.04"}},
			expectedImage:        []productRef{{Name: "localhost:5000/demo/ubuntu:24.04", Hashes: make(map[vex.Algorithm]vex.Hash)}},
			expectedOther:        []productRef{},
			expectedUnattestable: []productRef{},
			shouldFail:           false,
		},
		{
			name:                 "purl, dockerhub",
			products:             []productRef{{Name: "pkg:oci/nginx"}},
			expectedImage:        []productRef{{Name: productNginx, Hashes: make(map[vex.Algorithm]vex.Hash)}},
			expectedOther:        []productRef{},
			expectedUnattestable: []productRef{},
			shouldFail:           false,
		},
		{
			name:     "image reference with digest",
			products: []productRef{{Name: "ghcr.io/test/image@sha256:8b0d3f1c6d7f9a2b4c5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4"}},
			expectedImage: []productRef{{
				Name:   "ghcr.io/test/image@sha256:8b0d3f1c6d7f9a2b4c5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4",
				Hashes: map[vex.Algorithm]vex.Hash{vex.SHA256: "8b0d3f1c6d7f9a2b4c5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4"},
			}},
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
			products:             []productRef{{Name: productWolfiBash}},
			expectedImage:        []productRef{},
			expectedOther:        []productRef{},
			expectedUnattestable: []productRef{{Name: productWolfiBash, Hashes: make(map[vex.Algorithm]vex.Hash)}},
			shouldFail:           false,
		},
		{
			name: "other purl with hashes",
			products: []productRef{
				{
					Name: productWolfiBash,
					Hashes: map[vex.Algorithm]vex.Hash{
						vex.SHA256: vex.Hash("805f9e876d84aa72b0c10a810d4e16bf84b16c5399ddab86fb973e561e86de37"),
					},
				},
			},
			expectedImage: []productRef{},
			expectedOther: []productRef{
				{
					Name: productWolfiBash,
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
			products:             []productRef{{Name: productWolfiBash}, {Name: productNginx}},
			expectedImage:        []productRef{{Name: productNginx, Hashes: make(map[vex.Algorithm]vex.Hash)}},
			expectedOther:        []productRef{},
			expectedUnattestable: []productRef{{Name: productWolfiBash, Hashes: make(map[vex.Algorithm]vex.Hash)}},
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
				{Name: productNginx, Hashes: make(map[vex.Algorithm]vex.Hash)},
				{Name: "pkg:oci/alpine@sha256%3Af271e74b17ced29b915d351685fd4644785c6d1559dd1f2d4189a5e851ef753a", Hashes: make(map[vex.Algorithm]vex.Hash)},
				{Name: "pkg:oci/kube-apiserver?repository_url=registry.k8s.io&tag=v1.26.0", Hashes: make(map[vex.Algorithm]vex.Hash)},
				{Name: productKubeAPIv1260, Hashes: make(map[vex.Algorithm]vex.Hash)},
			},
		},
		{
			"openvex-v0.0.1",
			"testdata/v001-1.vex.json",
			[]productRef{{Name: productWolfiBash, Hashes: make(map[vex.Algorithm]vex.Hash)}},
		},
		{
			"openvex-v0.2.0",
			"testdata/v020-1.vex.json",
			[]productRef{{Name: productWolfiBash, Hashes: make(map[vex.Algorithm]vex.Hash)}},
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
		subjects []*intoto.ResourceDescriptor
		products []string
		mustErr  bool
	}{
		{
			// Literal match
			[]*intoto.ResourceDescriptor{
				{Name: productGHCRImage},
			},
			[]string{productGHCRImage},
			false,
		},
		{
			// Tags are not translated
			[]*intoto.ResourceDescriptor{
				{Name: productGHCRImage},
			},
			[]string{productGHCRImageDigest},
			true,
		},
		{
			// purls need to be translated
			[]*intoto.ResourceDescriptor{
				{Name: productGHCRImageDigest},
			},
			[]string{"pkg:oci/image@sha256:74634d9736a45ca9f6e1187e783492199e020f4a5c19d0b1abc2b604f894ac99?repository_url=ghcr.io/test/image"},
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

func TestReadGoldenData(t *testing.T) {
	sut := defaultVexCtlImplementation{}
	for _, tc := range []struct {
		name        string
		opts        *GenerateOpts
		products    []*vex.Product
		expectedLen int
		mustErr     bool
	}{
		{
			name: "same identifier",
			opts: &GenerateOpts{
				TemplatesPath: testdataTemplates,
			},
			products: []*vex.Product{
				{Component: vex.Component{ID: "pkg:oci/vexctl"}},
			},
			expectedLen: 1,
		},
		{
			name: "no matching purl",
			opts: &GenerateOpts{
				TemplatesPath: testdataTemplates,
			},
			products: []*vex.Product{
				{Component: vex.Component{ID: "pkg:oci/otherimage"}},
			},
			expectedLen: 0,
		},
		{
			name: "versioned purl",
			opts: &GenerateOpts{
				TemplatesPath: testdataTemplates,
			},
			products: []*vex.Product{
				{Component: vex.Component{ID: "pkg:oci/vexctl@sha256%3Af87abf1735e79b70407288f665316644d414dbf7bdf38c2f1c8e3a541d304d84"}},
			},
			expectedLen: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, err := sut.ReadTemplateData(tc.opts, tc.products)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NotNil(t, doc)
			require.Len(t, doc.Statements, tc.expectedLen, "unexpected number of statements")
		})
	}
}

func TestInitTemplatesDir(t *testing.T) {
	sut := defaultVexCtlImplementation{}
	for _, tc := range []struct {
		name      string
		prepare   func(string)
		shouldErr bool
	}{
		{
			name:      "normal",
			prepare:   func(_ string) {},
			shouldErr: false,
		},
		{
			name: "not clean dir",
			prepare: func(s string) {
				require.NoError(t, os.WriteFile(filepath.Join(s, "test.txt"), []byte("abc"), os.FileMode(0o644)))
			},
			shouldErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.prepare(dir)
			err := sut.InitTemplatesDir(dir)
			if tc.shouldErr {
				require.Error(t, err)
				return
			}
			require.FileExists(t, filepath.Join(dir, "README.md"))
			require.FileExists(t, filepath.Join(dir, "main.openvex.json"))
			require.NoError(t, err)
		})
	}
}

func TestApplySingleVEXNoDocumentTimestamp(t *testing.T) {
	// The document timestamp is optional, and vex.Open returns a document
	// without one, so ApplySingleVEX must not dereference it.
	doc := `{"@context":"https://openvex.dev/ns/v0.2.0","@id":"https://example.com/vex/1",` +
		`"author":"test","version":1,"statements":[{"vulnerability":{"name":"CVE-2024-0001"},` +
		`"products":[{"@id":"pkg:oci/test"}],"status":"not_affected",` +
		`"justification":"component_not_present"}]}`

	path := filepath.Join(t.TempDir(), "no-timestamp.vex.json")
	require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))

	vexDoc, err := vex.Open(path)
	require.NoError(t, err)
	require.Nil(t, vexDoc.Timestamp)

	// A rule ID that is not a vulnerability identifier, so the result is kept
	// as is and the assertion stays on the timestamp handling.
	report := sarif.New()
	run := gosarif.NewRun("test", "https://example.com")
	ruleID := "gosec-G101"
	run.Results = append(run.Results, &gosarif.Result{RuleID: &ruleID})
	report.Runs = append(report.Runs, run)

	impl := defaultVexCtlImplementation{}
	newReport, err := impl.ApplySingleVEX(report, vexDoc)
	require.NoError(t, err)
	require.Len(t, newReport.Runs[0].Results, 1)
}

func TestHashFromDigest(t *testing.T) {
	for _, tc := range []struct {
		digest string
		algo   vex.Algorithm
		hash   vex.Hash
		ok     bool
	}{
		{"sha256:0a1b", vex.SHA256, "0a1b", true},
		{"sha512:2c3d", vex.SHA512, "2c3d", true},
		{"md5:4e5f", "", "", false},
		{"sha256:", "", "", false},
		{"nodigest", "", "", false},
	} {
		algo, hash, ok := hashFromDigest(tc.digest)
		require.Equal(t, tc.ok, ok, tc.digest)
		require.Equal(t, tc.algo, algo, tc.digest)
		require.Equal(t, tc.hash, hash, tc.digest)
	}
}

func TestResolveImageDigestsKeepsExistingHashes(t *testing.T) {
	impl := defaultVexCtlImplementation{}
	refs := []productRef{{
		Name:   "ghcr.io/test/image@sha256:abc",
		Hashes: map[vex.Algorithm]vex.Hash{vex.SHA256: "abc"},
	}}
	// References with hashes are not looked up, so no network access happens
	got, err := impl.ResolveImageDigests(refs)
	require.NoError(t, err)
	require.Equal(t, refs, got)
}

func TestSourceType(t *testing.T) {
	impl := defaultVexCtlImplementation{}
	dir := t.TempDir()
	file := filepath.Join(dir, "vex.json")
	require.NoError(t, os.WriteFile(file, []byte("{}"), 0o600))

	for _, tc := range []struct {
		name     string
		uri      string
		expected string
		mustErr  bool
	}{
		{"existing file", file, SourceTypeFile, false},
		{"directory is not a source", dir, "", true},
		{"image reference", productGHCRImage, SourceTypeImage, false},
		{"image reference with digest", productGHCRImageDigest, SourceTypeImage, false},
		{"local registry reference", "127.0.0.1:5000/test/image:v1", SourceTypeImage, false},
		{"missing file that is not a reference", filepath.Join(dir, "missing file.json"), "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := impl.SourceType(tc.uri)
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, got)
		})
	}
}
