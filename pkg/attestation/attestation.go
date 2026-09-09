/*
Copyright 2022 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package attestation

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/carabiner-dev/signer"
	"github.com/google/go-containerregistry/pkg/crane"
	intoto "github.com/in-toto/attestation/go/v1"
	ovattest "github.com/openvex/go-vex/pkg/attestation"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"
)

// Format selects how a signed attestation is serialized.
type Format string

const (
	// FormatBundle writes the signed attestation as a sigstore bundle. The
	// bundle carries the DSSE envelope together with the signing certificate
	// and the transparency log entry, which makes it verifiable on its own.
	FormatBundle Format = "bundle"

	// FormatDSSE writes only the DSSE envelope wrapping the signed statement.
	// This is the legacy vexctl output. Envelopes signed with a sigstore
	// certificate cannot be verified on their own as the certificate and
	// the transparency log entry only travel in the bundle.
	FormatDSSE Format = "dsse"
)

// DefaultFormat is the format used when none is specified.
const DefaultFormat = FormatBundle

// ParseFormat returns the Format matching a string. An empty string
// resolves to the default format.
func ParseFormat(s string) (Format, error) {
	switch f := Format(strings.ToLower(s)); f {
	case "":
		return DefaultFormat, nil
	case FormatBundle, FormatDSSE:
		return f, nil
	default:
		return "", fmt.Errorf("unknown attestation format %q (supported: %s, %s)", s, FormatBundle, FormatDSSE)
	}
}

type Attestation struct {
	ovattest.Attestation

	// Signed is boolean that signals if the attestation has been signed
	Signed bool `json:"-"`

	// Artifact holds the signed attestation as returned by the signer: a
	// sigstore bundle when signed with a certificate or a bare DSSE envelope
	// when signed with a key. It is nil until the attestation is signed.
	Artifact signer.SignedArtifact `json:"-"`
}

func New() *Attestation {
	openVexAttestation := ovattest.New()
	return &Attestation{
		Attestation: *openVexAttestation,
	}
}

// StatementJSON returns the in-toto statement serialized as JSON. This is
// the payload that gets signed.
func (att *Attestation) StatementJSON() ([]byte, error) {
	var b bytes.Buffer
	if err := att.Attestation.ToJSON(&b); err != nil {
		return nil, fmt.Errorf("serializing attestation to json: %w", err)
	}
	return b.Bytes(), nil
}

// Sign signs the attestation with sigstore. The signing flow uses ambient
// credentials when they are available and falls back to the interactive
// OIDC flow otherwise. The resulting sigstore bundle, which includes the
// signing certificate and the transparency log entry, is stored in the
// attestation's Artifact field.
func (att *Attestation) Sign() error {
	data, err := att.StatementJSON()
	if err != nil {
		return err
	}

	s := signer.NewSigner()
	defer func() {
		if err := s.Close(); err != nil {
			logrus.Warnf("closing signer: %v", err)
		}
	}()

	artifact, err := s.SignStatement(data)
	if err != nil {
		return fmt.Errorf("signing attestation: %w", err)
	}

	att.Artifact = artifact
	att.Signed = true

	if bundle, ok := artifact.(*signer.BundleArtifact); ok && bundle.Bundle != nil {
		for _, entry := range bundle.Bundle.GetVerificationMaterial().GetTlogEntries() {
			logrus.Infof("transparency log entry created with index %d", entry.GetLogIndex())
		}
	}

	return nil
}

func (att *Attestation) AddImageSubjects(imageRefs []string) error {
	subs := []*intoto.ResourceDescriptor{}
	for _, refString := range imageRefs {
		digest, err := crane.Digest(refString)
		if err != nil {
			return fmt.Errorf("getting image digest: %w", err)
		}
		s := &intoto.ResourceDescriptor{
			Name:   refString,
			Digest: map[string]string{"sha256": strings.TrimPrefix(digest, "sha256:")},
		}

		subs = append(subs, s)
	}

	if err := att.AddSubjects(subs); err != nil {
		return fmt.Errorf("adding image subjects to attestation: %w", err)
	}

	return nil
}

// Write serializes the attestation to w. Unsigned attestations are always
// written as bare in-toto statements. Signed attestations are written in the
// requested format: the sigstore bundle produced by the signer or just the
// DSSE envelope it wraps.
func (att *Attestation) Write(w io.Writer, format Format) error {
	if !att.Signed {
		return att.Attestation.ToJSON(w)
	}
	if att.Artifact == nil {
		return errors.New("consistency error: attestation is signed but data is empty")
	}

	switch format {
	case FormatBundle, "":
		if _, err := att.Artifact.WriteTo(w); err != nil {
			return fmt.Errorf("writing signed attestation: %w", err)
		}
		return nil
	case FormatDSSE:
		bundle, ok := att.Artifact.(*signer.BundleArtifact)
		if !ok {
			// Attestations signed with a key are already bare envelopes
			if _, err := att.Artifact.WriteTo(w); err != nil {
				return fmt.Errorf("writing signed attestation: %w", err)
			}
			return nil
		}
		env := bundle.Bundle.GetDsseEnvelope()
		if env == nil {
			return errors.New("signed bundle does not contain a DSSE envelope")
		}
		data, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(env)
		if err != nil {
			return fmt.Errorf("marshaling DSSE envelope: %w", err)
		}
		if _, err := w.Write(data); err != nil {
			return fmt.Errorf("writing DSSE envelope: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unknown attestation format %q", format)
	}
}

// ToJSON writes the attestation as JSON to w. Signed attestations are
// written in the default format, use Write to choose another one.
func (att *Attestation) ToJSON(w io.Writer) error {
	return att.Write(w, DefaultFormat)
}
