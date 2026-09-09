/*
Copyright 2022 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package attestation

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/carabiner-dev/signer"
	"github.com/carabiner-dev/signer/key"
	"github.com/carabiner-dev/signer/options"
	intoto "github.com/in-toto/attestation/go/v1"
	gvattestation "github.com/openvex/go-vex/pkg/attestation"
	"github.com/openvex/go-vex/pkg/vex"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protodsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	sbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/stretchr/testify/require"
)

func testAttestation(t *testing.T) *Attestation {
	t.Helper()
	doc := vex.New()
	doc.ID = "https://openvex.dev/docs/test"
	att := New()
	att.Predicate = gvattestation.NewPredicate(&doc)
	require.NoError(t, att.AddSubjects([]*intoto.ResourceDescriptor{{
		Name:   "registry.example.com/image",
		Digest: map[string]string{"sha256": "6c5bd0a4a3e9c2b8c0b1a2d3e4f5061728394a5b6c7d8e9f0a1b2c3d4e5f6071"},
	}}))
	return att
}

func TestParseFormat(t *testing.T) {
	for _, tc := range []struct {
		in       string
		expected Format
		mustErr  bool
	}{
		{"", FormatBundle, false},
		{"bundle", FormatBundle, false},
		{"BUNDLE", FormatBundle, false},
		{"dsse", FormatDSSE, false},
		{"cosign", "", true},
	} {
		f, err := ParseFormat(tc.in)
		if tc.mustErr {
			require.Error(t, err, tc.in)
			continue
		}
		require.NoError(t, err, tc.in)
		require.Equal(t, tc.expected, f, tc.in)
	}
}

func TestWriteUnsigned(t *testing.T) {
	att := testAttestation(t)
	for _, f := range []Format{FormatBundle, FormatDSSE} {
		var b bytes.Buffer
		require.NoError(t, att.Write(&b, f))
		statement := map[string]any{}
		require.NoError(t, json.Unmarshal(b.Bytes(), &statement))
		require.Equal(t, string(gvattestation.PredicateType), statement["predicateType"])
		require.Len(t, statement["subject"], 1)
	}
}

func TestWriteSignedWithKey(t *testing.T) {
	att := testAttestation(t)
	data, err := att.StatementJSON()
	require.NoError(t, err)

	pk, err := key.NewGenerator().GenerateKeyPair()
	require.NoError(t, err)
	env, err := signer.NewSigner().SignStatementToDSSE(data, options.WithKey(pk))
	require.NoError(t, err)
	att.Artifact = &signer.EnvelopeArtifact{Envelope: env}
	att.Signed = true

	// Key signed attestations are envelopes regardless of the format
	for _, f := range []Format{FormatBundle, FormatDSSE} {
		var b bytes.Buffer
		require.NoError(t, att.Write(&b, f))
		out := map[string]any{}
		require.NoError(t, json.Unmarshal(b.Bytes(), &out))
		require.Equal(t, "https://in-toto.io/Statement/v1", out["payloadType"])
		require.Len(t, out["signatures"], 1)
	}
}

func TestWriteSignedBundle(t *testing.T) {
	att := testAttestation(t)
	data, err := att.StatementJSON()
	require.NoError(t, err)

	pb := &protobundle.Bundle{
		MediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{},
		},
		Content: &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &protodsse.Envelope{
				Payload:     data,
				PayloadType: "application/vnd.in-toto+json",
				Signatures:  []*protodsse.Signature{{Sig: []byte("sig"), Keyid: "test"}},
			},
		},
	}
	att.Artifact = &signer.BundleArtifact{Bundle: &sbundle.Bundle{Bundle: pb}}
	att.Signed = true

	// Default output is the whole bundle
	var b bytes.Buffer
	require.NoError(t, att.Write(&b, FormatBundle))
	out := map[string]any{}
	require.NoError(t, json.Unmarshal(b.Bytes(), &out))
	require.Contains(t, out, "dsseEnvelope")
	require.Contains(t, out, "verificationMaterial")
	require.Equal(t, pb.MediaType, out["mediaType"])

	// The DSSE format extracts the envelope from the bundle
	b.Reset()
	require.NoError(t, att.Write(&b, FormatDSSE))
	out = map[string]any{}
	require.NoError(t, json.Unmarshal(b.Bytes(), &out))
	require.NotContains(t, out, "dsseEnvelope")
	require.Equal(t, "application/vnd.in-toto+json", out["payloadType"])
	require.Len(t, out["signatures"], 1)

	// The payload in the envelope is the statement
	payloadString, ok := out["payload"].(string)
	require.True(t, ok)
	payload, err := base64.StdEncoding.DecodeString(payloadString)
	require.NoError(t, err)
	require.JSONEq(t, string(data), string(payload))

	// Unknown formats fail
	require.Error(t, att.Write(&b, Format("cosign")))
}
