/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package mrc

import (
	"bytes"
	"context"
	"fmt"
	"regexp"
	"time"

	gosarif "github.com/owenrumney/go-sarif/sarif"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
	"github.com/sirupsen/logrus"

	"chainguard.dev/mrclean/pkg/attestation"
	"chainguard.dev/mrclean/pkg/sarif"
	"chainguard.dev/mrclean/pkg/vex"
)

type Implementation interface {
	ApplySingleVEX(*sarif.Report, *vex.VEX) (*sarif.Report, error)
	SortDocuments([]*vex.VEX) []*vex.VEX
	OpenVexData(Options, []string) ([]*vex.VEX, error)
	Sort(docs []*vex.VEX) []*vex.VEX
	SignAttestation(*attestation.Attestation) ([]byte, error)
	AttestationBytes(*attestation.Attestation) ([]byte, error)
}

type defaultMRCImplementation struct{}

var cveRegexp regexp.Regexp

func init() {
	cveRegexp = *regexp.MustCompile(`^(CVE-\d+-\d+)`)
}

func (impl *defaultMRCImplementation) SortDocuments(docs []*vex.VEX) []*vex.VEX {
	return vex.Sort(docs)
}

func (impl *defaultMRCImplementation) ApplySingleVEX(report *sarif.Report, vexDoc *vex.VEX) (*sarif.Report, error) {
	newReport := *report
	logrus.Infof("VEX document contains %d statements", len(vexDoc.Statements))
	logrus.Infof("+%v Runs: %d\n", report, len(report.Runs))
	// Search for negative VEX statements, that is those that cancel a CVE
	for i := range report.Runs {
		newResults := []*gosarif.Result{}
		logrus.Infof("Inspecting run #%d containing %d results", i, len(report.Runs[i].Results))
		for _, res := range report.Runs[i].Results {
			// Normalize the CVE IDs
			m := cveRegexp.FindStringSubmatch(*res.RuleID)
			if len(m) != 2 {
				logrus.Errorf(
					"Invalid rulename in sarif report, expected CVE identifier, got %s",
					*res.RuleID,
				)
				newResults = append(newResults, res)
				continue
			}
			id := m[1]
			// TODO: Trim rule ID to CVE as Grype adds junk to the CVE ID
			statement := vexDoc.StatementFromID(id)
			logrus.Infof("Checking %s", id)
			if statement != nil {
				logrus.Infof("Statement is for %s and status is %s", statement.Vulnerability, statement.Status)
				if statement.Status == vex.StatusNotAffected ||
					statement.Status == vex.StatusFixed {
					logrus.Infof("Found VEX Statement for %s: %s", id, statement.Status)
					continue
				}
			}
			newResults = append(newResults, res)
		}
		newReport.Runs[i].Results = newResults
	}
	return &newReport, nil
}

// OpenVexData returns a set of vex documents from the paths received
func (impl *defaultMRCImplementation) OpenVexData(opts Options, paths []string) ([]*vex.VEX, error) {
	vexes := []*vex.VEX{}
	for _, path := range paths {
		var v *vex.VEX
		var err error
		switch opts.Format {
		case "vex", "json", "":
			v, err = vex.OpenJSON(path)
		case "yaml":
			v, err = vex.OpenYAML(path)
		case "csaf":
			v, err = vex.OpenCSAF(path, opts.Products)
		}
		if err != nil {
			return nil, fmt.Errorf("opening document: %w", err)
		}
		vexes = append(vexes, v)
	}
	return vexes, nil
}

func (impl *defaultMRCImplementation) Sort(docs []*vex.VEX) []*vex.VEX {
	return vex.Sort(docs)
}

func (impl *defaultMRCImplementation) AttestationBytes(att *attestation.Attestation) ([]byte, error) {
	var b bytes.Buffer
	if err := att.ToJSON(&b); err != nil {
		return nil, fmt.Errorf("serializing attestation to json: %w", err)
	}
	return b.Bytes(), nil
}

func (impl *defaultMRCImplementation) SignAttestation(att *attestation.Attestation) ([]byte, error) {
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
		return nil, fmt.Errorf("getting signer: %w", err)
	}
	defer sv.Close()

	// Wrap the attestation in the DSSE envelope
	wrapped := dsse.WrapSigner(sv, "application/vnd.in-toto+json")

	var b bytes.Buffer
	if err := att.ToJSON(&b); err != nil {
		return nil, fmt.Errorf("serializing attestation to json: %w", err)
	}

	signedPayload, err := wrapped.SignMessage(
		bytes.NewReader(b.Bytes()), signatureoptions.WithContext(ctx),
	)
	if err != nil {
		return nil, fmt.Errorf("signing attestation: %w", err)
	}

	fmt.Println(string(signedPayload))
	return signedPayload, nil
}

func (impl *defaultMRCImplementation) Attach(att attestation.Attestation, imageRef string) error {
	/*
		attestationFile, err := os.Open(signedPayload)
		if err != nil {
			return err
		}

		env := ssldsse.Envelope{}
		decoder := json.NewDecoder()
		for decoder.More() {
			if err := decoder.Decode(&env); err != nil {
				return err
			}

			payload, err := json.Marshal(env)
			if err != nil {
				return err
			}

			if env.PayloadType != types.IntotoPayloadType {
				return fmt.Errorf("invalid payloadType %s on envelope. Expected %s", env.PayloadType, types.IntotoPayloadType)
			}

			ref, err := name.ParseReference(imageRef)
			if err != nil {
				return err
			}
			digest, err := ociremote.ResolveDigest(ref, remoteOpts...)
			if err != nil {
				return err
			}
			// Overwrite "ref" with a digest to avoid a race where we use a tag
			// multiple times, and it potentially points to different things at
			// each access.
			ref = digest // nolint

			opts := []static.Option{static.WithLayerMediaType(types.DssePayloadType)}
			att, err := static.NewAttestation(payload, opts...)
			if err != nil {
				return err
			}

			se, err := ociremote.SignedEntity(digest, remoteOpts...)
			if err != nil {
				return err
			}

			newSE, err := mutate.AttachAttestationToEntity(se, att)
			if err != nil {
				return err
			}

			// Publish the signatures associated with this entity
			err = ociremote.WriteAttestations(digest.Repository, newSE, remoteOpts...)
			if err != nil {
				return err
			}
		}
	*/
	return nil
}
