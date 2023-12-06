/*
Copyright 2022 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package attestation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	ovattest "github.com/openvex/go-vex/pkg/attestation"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

type Attestation struct {
	ovattest.Attestation

	// Sign is boolean that signals if the attestation has been signed
	Signed bool `json:"-"`

	// signatureData embeds the signed attestaion, the certificate used to sign
	// it and the transparency log inclusion proof
	SignatureData *SignatureData `json:"-"`
}

type SignatureData struct {
	// CertData of the cert used to sign the attestation encodeded in PEM
	CertData []byte `json:"-"`

	// Chain contains the intermediate certificate chain of the attestation's cert
	Chain []byte `json:"-"`

	// Entry contains the proof of inclusion to the transparency log
	Entry *models.LogEntryAnon `json:"-"`

	// signedPayload contains the resulting blob after the attestation was
	// signed.
	signedPayload []byte
}

func New() *Attestation {
	openVexAttestation := ovattest.New()
	return &Attestation{
		Attestation: *openVexAttestation,
	}
}

// Sign the attestation
func (att *Attestation) Sign() error {
	ctx, ko := initSigning()

	// Sign the attestaion.
	if err := signAttestation(ctx, ko, att); err != nil {
		return fmt.Errorf("signing attestation: %w", err)
	}

	// Register the signature in rekor
	if err := appendSignatureDataToTLog(ctx, ko, att); err != nil {
		return fmt.Errorf("recording signature data to transparency log: %w", err)
	}

	return nil
}

func (att *Attestation) AddImageSubjects(imageRefs []string) error {
	subs := []intoto.Subject{}
	for _, refString := range imageRefs {
		digest, err := crane.Digest(refString)
		if err != nil {
			return fmt.Errorf("getting image digest: %w", err)
		}
		s := intoto.Subject{
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

// ToJSON intercepts the openves to json call and if the attestation is signed
// writes the signed data to io.Writer w instead of the original attestation.
func (att *Attestation) ToJSON(w io.Writer) error {
	if !att.Signed {
		return att.Attestation.ToJSON(w)
	}
	if att.SignatureData == nil || len(att.SignatureData.signedPayload) == 0 {
		return errors.New("consistency error: attestation is signed but data is empty")
	}

	if _, err := w.Write(att.SignatureData.signedPayload); err != nil {
		return fmt.Errorf("writing signed attestation: %w", err)
	}
	return nil
}

// initSigning initializes the options and context needed to sign. Right now
// it only sets up some default options and a backgrous context but we
// should wire the options set from the CLI to this function
func initSigning() (context.Context, options.KeyOpts) {
	ko := options.KeyOpts{
		FulcioURL:                options.DefaultFulcioURL,
		RekorURL:                 options.DefaultRekorURL,
		OIDCIssuer:               options.DefaultOIDCIssuerURL,
		OIDCClientID:             "sigstore",
		InsecureSkipFulcioVerify: false,
		SkipConfirmation:         true,
	}

	ctx := context.Background()
	// TODO(puerco): Support context.WithTimeout(ctx, timeout)

	return ctx, ko
}

// signAttestation creates a signer and signs the attestation. The attestation's
// SignatureData field will be populated with the certificate, chain and the
// attestaion data wrapped in its DSSE envelope.
func signAttestation(ctx context.Context, ko options.KeyOpts, att *Attestation) error {
	// TODO(puerco): Investigate supporting certificates preloaded in the
	// attestation. We would need to dump them to disk and load them into
	// the args here and if we're reusing the bundle, set it in ko.BundlePath
	// Note that in this call we hardocde the pats empty, but we should get them
	// from somewhere.
	sv, err := sign.SignerFromKeyOpts(ctx, "", "", ko)
	if err != nil {
		return fmt.Errorf("getting signer: %w", err)
	}
	defer sv.Close()

	// Wrap the attestation in the DSSE envelope
	wrapped := dsse.WrapSigner(sv, "application/vnd.in-toto+json")

	var b bytes.Buffer
	if err := att.ToJSON(&b); err != nil {
		return fmt.Errorf("serializing attestation to json: %w", err)
	}

	// SIGN!
	signedPayload, err := wrapped.SignMessage(
		bytes.NewReader(b.Bytes()), signatureoptions.WithContext(ctx),
	)
	if err != nil {
		return fmt.Errorf("signing attestation: %w", err)
	}

	// Assign the new data to the attestation
	att.SignatureData = &SignatureData{
		CertData:      sv.Cert,
		Chain:         sv.Chain,
		signedPayload: signedPayload,
	}
	att.Signed = true

	return nil
}

// appendSignatureDataToTLog records the signature data to the transparency log
// (rekor). The proof of inclusion will be added to the attestation's SignatureData
// struct.
// If uploading fails, the signature data will be destroyed to guarantee an atomic
// operation of attesation.Sign()
func appendSignatureDataToTLog(ctx context.Context, ko options.KeyOpts, att *Attestation) error {
	tlogClient, err := rekor.NewClient(ko.RekorURL)
	if err != nil {
		att.SignatureData = nil
		return fmt.Errorf("creating rekor client: %w", err)
	}

	// ...and upload the signature data
	entry, err := cosign.TLogUploadDSSEEnvelope(
		ctx, tlogClient, att.SignatureData.signedPayload, att.SignatureData.CertData,
	)
	if err != nil {
		att.SignatureData = nil
		return fmt.Errorf("uploading to transparency log: %w", err)
	}

	att.SignatureData.Entry = entry
	fmt.Fprintln(os.Stderr, "tlog entry created with index:", *entry.LogIndex)

	return nil
}
