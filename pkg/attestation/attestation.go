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
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/crane"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	ovattest "github.com/openvex/go-vex/pkg/attestation"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

type Attestation struct {
	signedData []byte `json:"-"`
	ovattest.Attestation
	Signed bool `json:"-"`
}

func New() *Attestation {
	openVexAttestation := ovattest.New()
	return &Attestation{
		Attestation: *openVexAttestation,
	}
}

// Sign the attestation
func (att *Attestation) Sign() error {
	ctx := context.Background()
	var timeout time.Duration /// TODO move to options
	var certPath, certChainPath string
	ko := options.KeyOpts{
		// KeyRef:     s.options.PrivateKeyPath,
		// IDToken:    identityToken,
		FulcioURL:    options.DefaultFulcioURL,
		RekorURL:     options.DefaultRekorURL,
		OIDCIssuer:   options.DefaultOIDCIssuerURL,
		OIDCClientID: "sigstore",

		InsecureSkipFulcioVerify: false,
		SkipConfirmation:         true,
		// FulcioAuthFlow:           "",
	}

	if timeout != 0 {
		var cancelFn context.CancelFunc
		ctx, cancelFn = context.WithTimeout(ctx, timeout)
		defer cancelFn()
	}

	sv, err := sign.SignerFromKeyOpts(ctx, certPath, certChainPath, ko)
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

	signedPayload, err := wrapped.SignMessage(
		bytes.NewReader(b.Bytes()), signatureoptions.WithContext(ctx),
	)
	if err != nil {
		return fmt.Errorf("signing attestation: %w", err)
	}

	att.Signed = true
	att.signedData = signedPayload
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
	if len(att.signedData) == 0 {
		return errors.New("consistency error: attestation is signed but data is empty")
	}

	if _, err := w.Write(att.signedData); err != nil {
		return fmt.Errorf("writing signed attestation: %w", err)
	}
	return nil
}
