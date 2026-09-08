/*
Copyright 2022 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package attestation

import (
	"context"
	"testing"

	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
)

// TestSignAttestationKeylessFollowsUpWithKeylessSigner reproduces the failure
// reported in issue #428 ("vexctl attest" / "Attestation signing is
// broken"):
//
//	Error: generating attestation: signing attestation: recording signature
//	data to transparency log: uploading to transparency log: public key
//	provided has 0 length
//
// Root cause: signAttestation() called sign.SignerFromKeyOpts() but discarded
// the returned "genKey" bool (`sv, _, err := sign.SignerFromKeyOpts(...)`)
// and never followed up with sign.KeylessSigner(), which is the call that
// actually talks to the OIDC issuer and Fulcio to populate
// SignerVerifier.Cert. Compare with cosign's own
// cmd/cosign/cli/attest/attest.go (same dependency version), which does:
//
//	sv, genKey, err := cosign_sign.SignerFromKeyOpts(...)
//	if genKey || c.IssueCertificateForExistingKey {
//	        sv, err = cosign_sign.KeylessSigner(ctx, c.KeyOpts, sv)
//	}
//
// Because vexctl skipped that step, for the default keyless code path (no
// --sk, no --key -- exactly what "vexctl attest" without extra flags uses)
// SignerVerifier.Cert stayed nil, so att.SignatureData.CertData ended up
// empty. appendSignatureDataToTLog() then hands this empty CertData to
// cosign.TLogUploadDSSEEnvelope() as the certificate/public key, which Rekor
// rejects with "public key provided has 0 length".
//
// Exercising the real KeylessSigner() success path needs a live interactive
// OIDC device-code login against a Fulcio instance, which is not viable in
// an automated test. Instead this test points KeyOpts.OIDCIssuer at an
// address nothing listens on, so the OIDC token exchange that KeylessSigner
// performs fails fast (connection refused) instead of blocking on user
// interaction. That gives an observable, network-independent difference
// between the buggy and the fixed code:
//
//   - Buggy code: signAttestation() never reaches sign.KeylessSigner(), so a
//     bogus OIDCIssuer is never even contacted -- signAttestation() returns
//     nil error and a signer with an empty (nil) certificate.
//   - Fixed code: signAttestation() calls sign.KeylessSigner() whenever
//     genKey is true, which tries to reach the (bogus) OIDC issuer and
//     fails -- signAttestation() returns a non-nil error.
func TestSignAttestationKeylessFollowsUpWithKeylessSigner(t *testing.T) {
	att := New()

	ko := options.KeyOpts{
		FulcioURL: options.DefaultFulcioURL,
		RekorURL:  options.DefaultRekorURL,
		// Nothing listens on this address, so the OIDC token exchange that
		// KeylessSigner performs fails immediately instead of falling back
		// to an interactive device-code login.
		OIDCIssuer:               "http://127.0.0.1:1",
		OIDCClientID:             "sigstore",
		InsecureSkipFulcioVerify: false,
		SkipConfirmation:         true,
	}

	err := signAttestation(context.Background(), &ko, att)
	if err == nil {
		t.Fatalf("BUG REPRODUCED (vexctl#428): signAttestation() returned no " +
			"error for a bogus OIDCIssuer on the default keyless signing " +
			"path -- this means sign.KeylessSigner() was never called, so " +
			"the resulting certificate is empty. appendSignatureDataToTLog() " +
			"later uploads that empty certificate to Rekor, which fails " +
			"with 'public key provided has 0 length'")
	}
}
