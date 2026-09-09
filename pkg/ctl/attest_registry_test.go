/*
Copyright 2022 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package ctl

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/carabiner-dev/signer"
	"github.com/carabiner-dev/signer/key"
	"github.com/carabiner-dev/signer/options"
	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/stretchr/testify/require"

	"github.com/openvex/vexctl/pkg/attestation"
)

// testRegistry starts an in-memory OCI registry with referrers support and
// returns its host:port. The loopback address makes the registry clients talk
// plain HTTP to it.
func testRegistry(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(registry.New(registry.WithReferrersSupport(true)))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return u.Host
}

// pushTestImage pushes an empty image to ref and returns its digest hex.
func pushTestImage(t *testing.T, ref string) string {
	t.Helper()
	require.NoError(t, crane.Push(empty.Image, ref))
	digest, err := crane.Digest(ref)
	require.NoError(t, err)
	return strings.TrimPrefix(digest, "sha256:")
}

// writeTestVEX writes an OpenVEX document with a single statement about the
// product and returns its path.
func writeTestVEX(t *testing.T, id, product string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vex.json")
	doc := fmt.Sprintf(`{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": %q,
  "author": "vexctl tests",
  "timestamp": "2026-01-01T00:00:00Z",
  "version": 1,
  "statements": [{
    "vulnerability": {"name": "CVE-2026-0001"},
    "products": [{"@id": %q}],
    "status": "not_affected",
    "justification": "component_not_present"
  }]
}`, id, product)
	require.NoError(t, os.WriteFile(path, []byte(doc), 0o600))
	return path
}

// fakeBundleArtifact wraps the attestation in a sigstore bundle with dummy
// verification material. It is not verifiable, but it has the shape the
// attach code needs to store it as a referrer.
func fakeBundleArtifact(t *testing.T, att *attestation.Attestation) signer.SignedArtifact {
	t.Helper()
	data, err := att.StatementJSON()
	require.NoError(t, err)
	mt, err := sbundle.MediaTypeString("v0.3")
	require.NoError(t, err)
	return &signer.BundleArtifact{Bundle: &sbundle.Bundle{Bundle: &protobundle.Bundle{
		MediaType: mt,
		Content: &protobundle.Bundle_DsseEnvelope{DsseEnvelope: &protodsse.Envelope{
			PayloadType: "application/vnd.in-toto+json",
			Payload:     data,
			Signatures:  []*protodsse.Signature{{Keyid: "test", Sig: []byte("sig")}},
		}},
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_X509CertificateChain{
				X509CertificateChain: &protocommon.X509CertificateChain{
					Certificates: []*protocommon.X509Certificate{{RawBytes: []byte{0x30, 0x82, 0x01, 0x0a}}},
				},
			},
		},
	}}}
}

// keySignedArtifact signs the attestation with a throwaway key into a bare
// DSSE envelope.
func keySignedArtifact(t *testing.T, att *attestation.Attestation) signer.SignedArtifact {
	t.Helper()
	data, err := att.StatementJSON()
	require.NoError(t, err)
	pk, err := key.NewGenerator().GenerateKeyPair()
	require.NoError(t, err)
	env, err := signer.NewSigner().SignStatementToDSSE(data, options.WithKey(pk))
	require.NoError(t, err)
	return &signer.EnvelopeArtifact{Envelope: env}
}

// TestAttestSubjectDigests checks that attesting resolves the digest of the
// image subjects from the reference or the registry no matter how they are
// specified (see https://github.com/openvex/vexctl/issues/139).
func TestAttestSubjectDigests(t *testing.T) {
	host := testRegistry(t)
	tagRef := host + "/attest/subjects:v1"
	digest := pushTestImage(t, tagRef)
	digestRef := host + "/attest/subjects@sha256:" + digest
	tagPurl := "pkg:oci/subjects?repository_url=" + host + "/attest/subjects&tag=v1"
	digestPurl := "pkg:oci/subjects@sha256:" + digest + "?repository_url=" + host + "/attest/subjects"

	for _, tc := range []struct {
		name         string
		product      string   // product in the VEX document
		subjects     []string // subjects passed to attest, none = doc products
		expectedName string
	}{
		{"digest reference", tagPurl, []string{digestRef}, digestRef},
		{"tag reference", tagPurl, []string{tagRef}, tagRef},
		{"tag purl", tagPurl, []string{tagPurl}, tagRef},
		{"digest purl", tagPurl, []string{digestPurl}, digestRef},
		{"tag purl from document", tagPurl, nil, tagRef},
		{"digest purl from document", digestPurl, nil, digestRef},
	} {
		t.Run(tc.name, func(t *testing.T) {
			att, err := New().Attest(writeTestVEX(t, "https://openvex.dev/docs/subjects", tc.product), tc.subjects)
			require.NoError(t, err)
			require.Len(t, att.Subject, 1)
			require.Equal(t, tc.expectedName, att.Subject[0].Name)
			require.Equal(t, map[string]string{"sha256": digest}, att.Subject[0].Digest)
		})
	}

	t.Run("unknown tag fails", func(t *testing.T) {
		_, err := New().Attest(writeTestVEX(t, "https://openvex.dev/docs/subjects", tagPurl), []string{host + "/attest/subjects:missing"})
		require.Error(t, err)
	})
}

// TestAttestAttach attests a VEX document, attaches it to an image in the
// test registry with each attach method and reads it back from the image.
func TestAttestAttach(t *testing.T) {
	ctx := context.Background()
	host := testRegistry(t)

	for i, tc := range []struct {
		name   string
		method AttachMethod
		sign   func(*testing.T, *attestation.Attestation) signer.SignedArtifact
	}{
		{"referrers/bundle", AttachMethodReferrers, fakeBundleArtifact},
		{"legacy/bundle", AttachMethodLegacy, fakeBundleArtifact},
		{"legacy/envelope", AttachMethodLegacy, keySignedArtifact},
	} {
		t.Run(tc.name, func(t *testing.T) {
			image := fmt.Sprintf("attach-%d", i)
			ref := fmt.Sprintf("%s/attest/%s:v1", host, image)
			pushTestImage(t, ref)
			docID := "https://openvex.dev/docs/attach/" + t.Name()

			v := New()
			v.Options.AttachMethod = tc.method
			att, err := v.Attest(writeTestVEX(t, docID, fmt.Sprintf("pkg:oci/%s?repository_url=%s/attest/%s&tag=v1", image, host, image)), []string{ref})
			require.NoError(t, err)

			// Sign it (no sigstore in tests) and attach it to the image
			att.Artifact = tc.sign(t, att)
			att.Signed = true
			require.NoError(t, v.Attach(ctx, att))

			// Read it back from the registry
			doc, err := v.VexFromURI(ctx, ref)
			require.NoError(t, err)
			require.Equal(t, docID, doc.ID)
			require.Len(t, doc.Statements, 1)
		})
	}

	t.Run("envelope over referrers is refused", func(t *testing.T) {
		ref := host + "/attest/attach-refused:v1"
		pushTestImage(t, ref)
		v := New()
		v.Options.AttachMethod = AttachMethodReferrers
		att, err := v.Attest(writeTestVEX(t, "https://openvex.dev/docs/refused", ref), []string{ref})
		require.NoError(t, err)
		att.Artifact = keySignedArtifact(t, att)
		att.Signed = true
		require.Error(t, v.Attach(ctx, att))
	})

	t.Run("unsigned attestation is refused", func(t *testing.T) {
		ref := host + "/attest/attach-unsigned:v1"
		pushTestImage(t, ref)
		v := New()
		att, err := v.Attest(writeTestVEX(t, "https://openvex.dev/docs/unsigned", ref), []string{ref})
		require.NoError(t, err)
		require.Error(t, v.Attach(ctx, att))
	})
}
