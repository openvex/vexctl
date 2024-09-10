/*
Copyright 2022 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package ctl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	gosarif "github.com/owenrumney/go-sarif/sarif"
	purl "github.com/package-url/packageurl-go"
	ssldsse "github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	cbundle "github.com/sigstore/cosign/v2/pkg/cosign/bundle"
	"github.com/sigstore/cosign/v2/pkg/oci/mutate"
	ociremote "github.com/sigstore/cosign/v2/pkg/oci/remote"
	"github.com/sigstore/cosign/v2/pkg/oci/static"
	"github.com/sigstore/cosign/v2/pkg/types"
	"github.com/sirupsen/logrus"
	"sigs.k8s.io/release-utils/util"

	"github.com/openvex/go-vex/pkg/sarif"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/openvex/vexctl/pkg/attestation"
)

const (
	IntotoPayloadType = "application/vnd.in-toto+json"

	initReadmeMarkdown = "# OpenVEX Templates Directory\n\n" +
		"This directory contains the OpenVEX data for this repository.\n" +
		"The files stored in this directory are used as templates by\n" +
		"`vexctl generate` when generating VEX data for a release or\n" +
		"a specific artifact.\n\n" +
		"To add new statements to publish data about a vulnerability,\n" +
		"download [vexctl] and append new statements using\n" +
		"`vexctl add`. For example:\n\n" +
		"```\n" +
		"vexctl add --in-place main.openvex.json --product pkg:oci/test --vuln CVE-2014-1234567 --status under_investigation\n" +
		"```\n\n" +
		"That will add a new VEX statement expressing that the impact of\n" +
		"CVE-2014-1234567 is under investigation in the test image. When\n" +
		"cutting a new release, for `pkg:oci/test` the new file can be\n" +
		"incorporated to the release's VEX data.\n\n" +
		"## Read more about OpenVEX\n\n" +
		"To know more about generating, publishing and using VEX data\n" +
		"in your project, please check out the [vexctl repository and\n" +
		"documentation][vexctl].\n\n" +
		"OpenVEX also has an [examples repository] with samples and docs.\n\n\n" +
		"[vexctl]: https://github.com/openvex/vexctl\n" +
		"[examples repository]: https://github.com/openvex/examples\n"
)

type Implementation interface {
	ApplySingleVEX(*sarif.Report, *vex.VEX) (*sarif.Report, error)
	SortDocuments([]*vex.VEX) []*vex.VEX
	OpenVexData(Options, []string) ([]*vex.VEX, error)
	Sort(docs []*vex.VEX) []*vex.VEX
	AttestationBytes(*attestation.Attestation) ([]byte, error)
	Attach(context.Context, *attestation.Attestation, ...string) error
	SourceType(uri string) (string, error)
	ReadImageAttestations(context.Context, Options, string) ([]*vex.VEX, error)
	Merge(context.Context, *MergeOptions, []*vex.VEX) (*vex.VEX, error)
	LoadFiles(context.Context, []string) ([]*vex.VEX, error)
	ListDocumentProducts(doc *vex.VEX) ([]productRef, error)
	NormalizeProducts([]productRef) ([]productRef, []productRef, []productRef, error)
	VerifyImageSubjects(*attestation.Attestation, *vex.VEX) error
	ReadTemplateData(*GenerateOpts, []*vex.Product) (*vex.VEX, error)
	InitTemplatesDir(string) error
}

type defaultVexCtlImplementation struct{}

var cveRegexp regexp.Regexp

func init() {
	cveRegexp = *regexp.MustCompile(`^(CVE-\d+-\d+)`)
}

func (impl *defaultVexCtlImplementation) SortDocuments(docs []*vex.VEX) []*vex.VEX {
	return vex.SortDocuments(docs)
}

func (impl *defaultVexCtlImplementation) ApplySingleVEX(report *sarif.Report, vexDoc *vex.VEX) (*sarif.Report, error) {
	newReport := *report
	logrus.Infof("VEX document contains %d statements", len(vexDoc.Statements))

	sortedStatements := vexDoc.Statements
	vex.SortStatements(sortedStatements, *vexDoc.Timestamp)

	// Search for negative VEX statements, that is those that cancel a CVE
	for i := range report.Runs {
		newResults := []*gosarif.Result{}
		logrus.Infof("Inspecting SARIF run #%d containing %d results", i, len(report.Runs[i].Results))
		for _, res := range report.Runs[i].Results {
			id := ""
			parts := strings.SplitN(strings.TrimSpace(*res.RuleID), "-", 2)
			switch parts[0] {
			case "CVE":
				// Trim rule ID to CVE as Grype adds junk to the CVE ID
				m := cveRegexp.FindStringSubmatch(*res.RuleID)
				if len(m) == 2 {
					id = m[1]
				} else {
					logrus.Errorf(
						"Invalid rulename in sarif report, expected CVE identifier, got %s",
						*res.RuleID,
					)
					newResults = append(newResults, res)
					continue
				}
			case "GHSA", "GO", "PRISMA", "RHSA", "RUSTSEC", "SNYK":
				id = strings.TrimSpace(*res.RuleID)
			default:
				newResults = append(newResults, res)
				continue
			}

			statements := vexDoc.StatementsByVulnerability(id)

			// OpenVEX doc has no data for this vulnerability ID
			if len(statements) == 0 {
				newResults = append(newResults, res)
				continue
			}

			switch statements[0].Status {
			case vex.StatusNotAffected, vex.StatusFixed:
				logrus.Debugf(
					" >> found VEX statement for %s with status %q",
					statements[0].Vulnerability, statements[0].Status,
				)
			default:
				newResults = append(newResults, res)
			}
		}
		newReport.Runs[i].Results = newResults
	}
	return &newReport, nil
}

// OpenVexData returns a set of vex documents from the paths received
func (impl *defaultVexCtlImplementation) OpenVexData(_ Options, paths []string) ([]*vex.VEX, error) {
	vexes := []*vex.VEX{}
	for _, path := range paths {
		doc, err := vex.Open(path)
		if err != nil {
			return nil, fmt.Errorf("opening VEX document: %w", err)
		}
		vexes = append(vexes, doc)
	}
	return vexes, nil
}

// Sort sorts a list of documents
func (impl *defaultVexCtlImplementation) Sort(docs []*vex.VEX) []*vex.VEX {
	return vex.SortDocuments(docs)
}

func (impl *defaultVexCtlImplementation) AttestationBytes(att *attestation.Attestation) ([]byte, error) {
	var b bytes.Buffer
	if err := att.ToJSON(&b); err != nil {
		return nil, fmt.Errorf("serializing attestation to json: %w", err)
	}
	return b.Bytes(), nil
}

// Attach attaches an attestation to a container image in the registry using
// the sigstore libraries. If No references are provided, vexctl will try to
// attach it to all the attestation subjects that parse as image references.
func (impl *defaultVexCtlImplementation) Attach(ctx context.Context, att *attestation.Attestation, refs ...string) error {
	env := ssldsse.Envelope{}

	var b bytes.Buffer
	if err := att.ToJSON(&b); err != nil {
		return fmt.Errorf("getting attestation JSON")
	}
	decoder := json.NewDecoder(&b)
	for decoder.More() {
		if err := decoder.Decode(&env); err != nil {
			return err
		}

		payload, err := json.Marshal(env)
		if err != nil {
			return err
		}

		if env.PayloadType != IntotoPayloadType {
			return fmt.Errorf("invalid payloadType %s on envelope, expected %s", env.PayloadType, types.IntotoPayloadType)
		}

		if len(refs) == 0 {
			for _, s := range att.Subject {
				if _, err := name.ParseReference(s.Name); err != nil {
					logrus.Infof("Skipping attaching to %s. It is not an image reference", s.Name)
					continue
				}
				refs = append(refs, s.Name)
			}
		}

		for _, ref := range refs {
			if err := attachAttestation(ctx, att, payload, ref); err != nil {
				return fmt.Errorf("attaching attestation to %s: %w", ref, err)
			}
		}
	}

	return nil
}

// attachAttestation is a utility function to do the actual attachment of
// the signed attestation
func attachAttestation(ctx context.Context, original *attestation.Attestation, payload []byte, imageRef string) error {
	regOpts := options.RegistryOptions{}
	remoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return fmt.Errorf("getting OCI remote options: %w", err)
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return err
	}

	digest, err := ociremote.ResolveDigest(ref, remoteOpts...)
	if err != nil {
		return fmt.Errorf("resolving entity: %w", err)
	}

	ref = digest //nolint:ineffassign

	opts := []static.Option{static.WithLayerMediaType(types.DssePayloadType)}

	// Add the attestation certificate:
	opts = append(opts, static.WithCertChain(original.SignatureData.CertData, original.SignatureData.Chain))

	// Add the tlog entry to the annotations
	if original.SignatureData.Entry != nil {
		opts = append(opts, static.WithBundle(
			cbundle.EntryToBundle(original.SignatureData.Entry),
		))
	}

	// Add predicateType as manifest annotation
	opts = append(opts, static.WithAnnotations(map[string]string{
		"predicateType": vex.Context,
	}))

	att, err := static.NewAttestation(payload, opts...)
	if err != nil {
		return err
	}

	se, err := ociremote.SignedEntity(digest, remoteOpts...)
	if err != nil {
		return fmt.Errorf("creating signed entity from image: %w", err)
	}

	newSE, err := mutate.AttachAttestationToEntity(se, att)
	if err != nil {
		return fmt.Errorf("attaching attestation: %w", err)
	}

	// Publish the signatures
	if err := ociremote.WriteAttestations(digest.Repository, newSE, remoteOpts...); err != nil {
		return fmt.Errorf("writing attestations to registry: %w", err)
	}
	return nil
}

// SourceType returns a string indicating what kind of vex
// source a URI points to
func (impl *defaultVexCtlImplementation) SourceType(uri string) (string, error) {
	if util.Exists(uri) {
		return "file", nil
	}

	_, err := name.ParseReference(uri)
	if err == nil {
		return "image", nil
	}

	return "", errors.New("unable to resolve the vex source location")
}

// DownloadAttestation
func (impl *defaultVexCtlImplementation) ReadImageAttestations(
	ctx context.Context, _ Options, refString string,
) (vexes []*vex.VEX, err error) {
	// Parsae the image reference
	ref, err := name.ParseReference(refString)
	if err != nil {
		return nil, fmt.Errorf("parsing image reference: %w", err)
	}
	regOpts := &options.RegistryOptions{}
	remoteOpts, err := regOpts.ClientOpts(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting OCI remote options: %w", err)
	}
	payloads, err := cosign.FetchAttestationsForReference(ctx, ref, "", remoteOpts...)
	if err != nil {
		return nil, fmt.Errorf("fetching attached attestation: %w", err)
	}
	vexes = []*vex.VEX{}
	for _, dssePayload := range payloads {
		vexData, err := impl.ReadSignedVEX(dssePayload)
		if err != nil {
			return nil, fmt.Errorf("opening dsse payload: %w", err)
		}
		vexes = append(vexes, vexData)
	}
	return vexes, nil
}

// ReadSignedVEX returns the vex data inside a signed envelope
func (impl *defaultVexCtlImplementation) ReadSignedVEX(dssePayload cosign.AttestationPayload) (*vex.VEX, error) {
	if dssePayload.PayloadType != IntotoPayloadType {
		logrus.Info("Signed envelope does not contain an in-toto attestation")
		return nil, nil
	}

	data, err := base64.StdEncoding.DecodeString(dssePayload.PayLoad)
	if err != nil {
		return nil, fmt.Errorf("decoding signed attestation: %w", err)
	}
	fmt.Printf("%s\n", string(data))

	// Unmarshall the attestation
	att := &attestation.Attestation{}
	if err := json.Unmarshal(data, att); err != nil {
		return nil, fmt.Errorf("unmarshalling attestation JSON: %w", err)
	}

	if att.PredicateType != vex.TypeURI {
		return nil, nil
	}

	return &att.Predicate, nil
}

type MergeOptions struct {
	DocumentID      string   // ID to use in the new document
	Author          string   // Author to use in the new document
	AuthorRole      string   // Role of the document author
	Products        []string // Product IDs to consider
	Vulnerabilities []string // IDs of vulnerabilities to merge
}

// Merge combines the statements from a number of documents into
// a new one, preserving time context from each of them.
func (impl *defaultVexCtlImplementation) Merge(
	_ context.Context, mergeOpts *MergeOptions, docs []*vex.VEX,
) (*vex.VEX, error) {
	if len(docs) == 0 {
		return nil, fmt.Errorf("at least one vex document is required to merge")
	}

	docID := mergeOpts.DocumentID
	// If no document id is specified we compute a
	// deterministic ID using the merged docs
	if docID == "" {
		ids := []string{}
		for i, d := range docs {
			if d.ID == "" {
				ids = append(ids, fmt.Sprintf("VEX-DOC-%d", i))
			} else {
				ids = append(ids, d.ID)
			}
		}

		sort.Strings(ids)
		h := sha256.New()
		h.Write([]byte(strings.Join(ids, ":")))
		// Hash the sorted IDs list
		docID = fmt.Sprintf("merged-vex-%x", h.Sum(nil))
	}

	newDoc := vex.New()

	newDoc.ID = docID
	if author := mergeOpts.Author; author != "" {
		newDoc.Author = author
	}
	if authorRole := mergeOpts.AuthorRole; authorRole != "" {
		newDoc.AuthorRole = authorRole
	}

	ss := []vex.Statement{}

	// Create an inverse dict of products and vulnerabilities to filter
	// these will only be used if ids to filter on are defined in the options.
	iProds := map[string]struct{}{}
	iVulns := map[string]struct{}{}
	for _, id := range mergeOpts.Products {
		iProds[id] = struct{}{}
	}
	for _, id := range mergeOpts.Vulnerabilities {
		iVulns[id] = struct{}{}
	}

	for _, doc := range docs {
		for _, s := range doc.Statements { //nolint:gocritic // this IS supposed to copy
			matchesProduct := false
			for id := range iProds {
				if s.MatchesProduct(id, "") {
					matchesProduct = true
					break
				}
			}
			if len(iProds) > 0 && !matchesProduct {
				continue
			}

			matchesVuln := false
			for id := range iVulns {
				if s.Vulnerability.Matches(id) {
					matchesVuln = true
					break
				}
			}
			if len(iVulns) > 0 && !matchesVuln {
				continue
			}

			// If statement does not have a timestamp, cascade
			// the timestamp down from the document.
			// See https://github.com/chainguard-dev/vex/issues/49
			if s.Timestamp == nil {
				if doc.Timestamp == nil {
					return nil, errors.New("unable to cascade timestamp from doc to timeless statement")
				}
				s.Timestamp = doc.Timestamp
			}

			ss = append(ss, s)
		}
	}

	vex.SortStatements(ss, *newDoc.Metadata.Timestamp)

	newDoc.Statements = ss

	return &newDoc, nil
}

// LoadFiles loads multiple vex files from disk
func (impl *defaultVexCtlImplementation) LoadFiles(
	_ context.Context, filePaths []string,
) ([]*vex.VEX, error) {
	vexes := make([]*vex.VEX, len(filePaths))
	for i, path := range filePaths {
		doc, err := vex.Open(path)
		if err != nil {
			return nil, fmt.Errorf("error loading file: %w", err)
		}
		vexes[i] = doc
	}

	return vexes, nil
}

// ListDocumentProducts returns an array of all the prodicts in the document
func (impl *defaultVexCtlImplementation) ListDocumentProducts(doc *vex.VEX) ([]productRef, error) {
	if doc == nil {
		return nil, errors.New("cannot read subjects, vex document is nil")
	}
	inv := map[string]map[vex.Algorithm]vex.Hash{}
	products := []productRef{}
	for i := range doc.Statements {
		for _, p := range doc.Statements[i].Products {
			switch {
			case p.ID != "":
				inv[p.ID] = p.Hashes
			case len(p.Identifiers) > 0:
				if i, ok := p.Identifiers[vex.PURL]; ok {
					inv[i] = p.Hashes
					continue
				}
				for _, id := range p.Identifiers {
					inv[id] = p.Hashes
				}
			case len(p.Hashes) > 0:
				for _, hash := range p.Hashes {
					inv[string(hash)] = p.Hashes
					continue
				}
			}
		}
	}

	// Sort the identifier list to make the return value deterministic
	ids := []string{}
	for id := range inv {
		ids = append(ids, id)
	}

	sort.Strings(ids)

	for _, id := range ids {
		h := inv[id]
		if h == nil {
			h = make(map[vex.Algorithm]vex.Hash)
		}
		products = append(products, productRef{
			Name:   id,
			Hashes: h,
		})
	}
	return products, nil
}

// NormalizeImageRefs returns a list of image references from a list of
// VEX products. oci:purls are transformed into image references. All non
// container image identifiers are untouched and returned in their own array.
func (impl *defaultVexCtlImplementation) NormalizeProducts(subjects []productRef) (
	imageRefs, otherRefs, unattestableRefs []productRef, err error,
) {
	imageRefs = []productRef{}
	otherRefs = []productRef{}
	unattestableRefs = []productRef{}

	for _, pref := range subjects {
		if pref.Hashes == nil {
			pref.Hashes = make(map[vex.Algorithm]vex.Hash)
		}
		switch {
		case strings.HasPrefix(pref.Name, "pkg:/oci/"),
			strings.HasPrefix(pref.Name, "pkg:oci/"):
			// Deduct image purls to the reference as much as possible
			p, err := purl.FromString(pref.Name)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("parsing OCI purl subject: %s", err)
			}

			ref := ""
			qs := p.Qualifiers.Map()
			if r, ok := qs["repository_url"]; ok {
				ref = strings.TrimSuffix(r, "/")
			} else {
				// digest or image
				ref = p.Name
			}
			var hash vex.Hash
			var algo vex.Algorithm
			if p.Version != "" {
				ref += "@" + p.Version
				parts := strings.Split(p.Version, ":")
				if len(parts) > 1 {
					hash = vex.Hash(parts[1])
					switch parts[0] {
					case "sha256":
						algo = vex.SHA256
					case "sha512":
						algo = vex.SHA3512
					}
				}
			} else if tag, ok := qs["tag"]; ok {
				ref += ":" + tag
			}
			if algo != "" {
				pref.Hashes[algo] = hash
			}
			pref.Name = ref
			logrus.Debugf("%s is a purl for %s", pref.Name, ref)
			imageRefs = append(imageRefs, pref)
		case strings.HasPrefix(pref.Name, "pkg:"):
			// When there are other purls, we only attest them as subjects if
			// the product reference has hashes
			if pref.Hashes != nil && len(pref.Hashes) > 0 { //nolint: gosimple
				otherRefs = append(otherRefs, pref)
			} else {
				unattestableRefs = append(unattestableRefs, pref)
			}
		default:
			// If not,try to parse the string as an image reference. If they can
			// be parsed as image references but they cannot be looked up, attestting
			// will fail trying to fetch their digests.
			if _, err := name.ParseReference(pref.Name); err == nil {
				imageRefs = append(imageRefs, pref)
			} else {
				otherRefs = append(otherRefs, pref)
			}
		}
	}
	return imageRefs, otherRefs, unattestableRefs, nil
}

// VerifySubjectsPresent takes a list of references and ensures they are present
// in the document that is being attested
func (impl *defaultVexCtlImplementation) VerifyImageSubjects(
	att *attestation.Attestation, doc *vex.VEX,
) error {
	products, err := impl.ListDocumentProducts(doc)
	if err != nil {
		return fmt.Errorf("listing products in the document: %w", err)
	}

	imageRefs, _, _, err := impl.NormalizeProducts(products)
	if err != nil {
		return fmt.Errorf("normalizing references: %s", err)
	}

	found := false
	for _, r := range imageRefs {
		for _, sb := range att.Subject {
			found = false
			if sb.Name == r.Name {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("entry for %s not found in subjects %v", r, imageRefs)
		}
	}
	return nil
}

// ReadTemplateData reads a set of golden documents with data used to generate
// VEX information for a given artifact.
func (impl *defaultVexCtlImplementation) ReadTemplateData(opts *GenerateOpts, products []*vex.Product) (*vex.VEX, error) {
	goldenPath := opts.TemplatesPath
	if goldenPath == "" {
		goldenPath = DefaultTemplatesPath
	}

	info, err := os.Stat(goldenPath)
	if err != nil {
		return nil, fmt.Errorf("checking filepath: %w", err)
	}

	vexFiles := []string{}
	if info.IsDir() {
		entries, err := os.ReadDir(goldenPath)
		if err != nil {
			return nil, fmt.Errorf("reading golden data directory: %w", err)
		}

		for _, f := range entries {
			if !strings.HasSuffix(f.Name(), "vex.json") {
				continue
			}
			vexFiles = append(vexFiles, filepath.Join(goldenPath, f.Name()))
		}
	} else {
		vexFiles = []string{goldenPath}
	}

	// If we have no files, then noop
	if len(vexFiles) == 0 {
		return nil, nil
	}

	// The VEX options only support matching products with a string.
	// We unpack all the product data and match on it
	productsIdentifiers := []string{}
	for _, p := range products {
		productsIdentifiers = append(productsIdentifiers, p.ID)
		for _, id := range p.Identifiers {
			productsIdentifiers = append(productsIdentifiers, id)
		}
		for _, h := range p.Hashes {
			productsIdentifiers = append(productsIdentifiers, string(h))
		}
	}

	// Generate the full VEX history
	document, err := vex.MergeFilesWithOptions(&vex.MergeOptions{
		Products: productsIdentifiers,
	}, vexFiles)
	if err != nil {
		return nil, fmt.Errorf("merging golden data: %w", err)
	}

	return document, nil
}

// InitTemplatesDir initializes the templates directory with an emptuy file and
// a readme.
func (impl *defaultVexCtlImplementation) InitTemplatesDir(path string) error {
	if !util.Exists(path) {
		if err := os.MkdirAll(path, os.FileMode(0o755)); err != nil {
			return fmt.Errorf("creating templates dir: %s", err)
		}
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("reading templates dir: %w", err)
	}

	if len(entries) != 0 {
		return fmt.Errorf("unable to initialize templates dir, path is not empty")
	}

	mainFile, err := os.Create(filepath.Join(path, "main.openvex.json"))
	if err != nil {
		return fmt.Errorf("creating initial openvex document: %w", err)
	}
	newDoc := vex.New()
	newDoc.Metadata.Author = "vexctl (automated template)"
	// TODO(puerco) This should be randomized
	if _, err := newDoc.GenerateCanonicalID(); err != nil {
		return fmt.Errorf("generating document ID: %w", err)
	}
	if err := newDoc.ToJSON(mainFile); err != nil {
		return fmt.Errorf("writing initial openvex file to disk: %w", err)
	}

	if err := os.WriteFile(filepath.Join(path, "README.md"), []byte(initReadmeMarkdown), os.FileMode(0o644)); err != nil {
		return fmt.Errorf("writing OpenVEX template dir readme file: %w", err)
	}
	return nil
}
