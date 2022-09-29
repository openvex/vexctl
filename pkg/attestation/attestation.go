/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package attestation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/google/go-containerregistry/pkg/crane"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"

	"chainguard.dev/vex/pkg/vex"
)

type Attestation struct {
	intoto.StatementHeader
	// Predicate contains type specific metadata.
	Predicate  vex.VEX `json:"predicate"`
	Siged      bool    `json:"-"`
	signedData []byte  `json:"-"`
}

func New() *Attestation {
	return &Attestation{
		StatementHeader: intoto.StatementHeader{
			Type:          intoto.StatementInTotoV01,
			PredicateType: vex.MimeType,
			Subject:       []intoto.Subject{},
		},
		Predicate: vex.New(),
	}
}

// ToJSON returns the attestation as a JSON byte array
func (att *Attestation) ToJSON(w io.Writer) error {
	if att.Siged {
		if _, err := w.Write(att.signedData); err != nil {
			return fmt.Errorf("writing signed attestation")
		}
		return nil
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)

	if err := enc.Encode(att); err != nil {
		return fmt.Errorf("encoding attestation: %w", err)
	}
	return nil
}

func (att *Attestation) AddImageSubjects(imageRefs []string) error {
	for _, refString := range imageRefs {
		digest, err := crane.Digest(refString)
		if err != nil {
			return fmt.Errorf("getting image digest: %w", err)
		}
		s := intoto.Subject{
			Name:   refString,
			Digest: map[string]string{"sha256": strings.TrimPrefix(digest, "sha256:")},
		}

		att.Subject = append(att.Subject, s)
	}
	return nil
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

	att.signedData = signedPayload
	att.Siged = true
	return nil
}
