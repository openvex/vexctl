/*
Copyright 2026 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package validate

import (
	"maps"
	"slices"
	"strings"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/package-url/packageurl-go"
)

const (
	purlScheme  = "pkg:"
	cpe22Prefix = "cpe:/"
	cpe23Prefix = "cpe:2.3:"

	// cpe23Components is the number of colon separated components of a CPE 2.3
	// formatted string, the "cpe:2.3" prefix included.
	cpe23Components = 13

	// cpe22Components is the largest number of colon separated components a
	// CPE 2.2 URI can have after its "cpe:/" prefix.
	cpe22Components = 7
)

// hashLengths maps the hash algorithms OpenVEX names to the length of their
// hexadecimal representation.
var hashLengths = map[vex.Algorithm]int{
	vex.MD5:        32,
	vex.SHA1:       40,
	vex.SHA256:     64,
	vex.SHA384:     96,
	vex.SHA512:     128,
	vex.SHA3224:    56,
	vex.SHA3256:    64,
	vex.SHA3384:    96,
	vex.SHA3512:    128,
	vex.BLAKE2S256: 64,
	vex.BLAKE2B256: 64,
	vex.BLAKE2B512: 128,
	vex.BLAKE3:     64,
}

// checkIdentifier checks one entry of a component's identifiers map.
func (r *Result) checkIdentifier(idType vex.IdentifierType, id, path string) {
	if id == "" {
		r.errorf(CheckIdentifier, path, "the identifier is empty")
		return
	}

	switch idType {
	case vex.PURL:
		r.checkPurl(id, path)
	case vex.CPE22:
		r.checkCPE22(id, path)
	case vex.CPE23:
		r.checkCPE23(id, path)
	default:
		r.warnf(
			CheckIdentifier, path,
			"%q is not a software identifier type OpenVEX defines (%s), so tools matching this component will ignore it",
			idType, strings.Join([]string{string(vex.PURL), string(vex.CPE22), string(vex.CPE23)}, ", "),
		)
	}
}

// checkPurl checks that a string is a package URL.
func (r *Result) checkPurl(purl, path string) {
	parsed, err := packageurl.FromString(purl)
	if err != nil {
		r.errorf(CheckPurl, path, "%q is not a valid package URL: %v", purl, err)
		return
	}

	// The purl spec defines the type as case insensitive and its canonical
	// form as lowercase. The rest of the purl is compared as written, so only
	// the type can be corrected without guessing at the ecosystem's rules.
	if written := purlType(purl); written != parsed.Type {
		r.warnf(
			CheckPurl, path,
			"the package URL type %q should be written in lowercase as %q; tools comparing package URLs as text will not match it otherwise",
			written, parsed.Type,
		)
	}
}

// purlType returns the type segment of a package URL as its author wrote it.
func purlType(purl string) string {
	// The scheme may be followed by slashes, which the purl spec tolerates.
	rest := strings.TrimLeft(strings.TrimPrefix(purl, purlScheme), "/")
	if end := strings.IndexByte(rest, '/'); end >= 0 {
		return rest[:end]
	}
	return rest
}

// checkCPE dispatches on the flavor of CPE a string announces itself to be.
func (r *Result) checkCPE(cpe, path string) {
	if strings.HasPrefix(cpe, cpe23Prefix) {
		r.checkCPE23(cpe, path)
		return
	}
	r.checkCPE22(cpe, path)
}

// checkCPE23 checks a CPE 2.3 formatted string, which names all thirteen of
// its components even when they are wildcards.
func (r *Result) checkCPE23(cpe, path string) {
	if !strings.HasPrefix(cpe, cpe23Prefix) {
		r.errorf(CheckCPE, path, "%q is not a CPE 2.3 identifier, they start with %q", cpe, cpe23Prefix)
		return
	}

	if parts := splitCPE(cpe); len(parts) != cpe23Components {
		r.errorf(
			CheckCPE, path,
			"a CPE 2.3 identifier has %d colon separated components, %q has %d; unused components are written as \"*\"",
			cpe23Components, cpe, len(parts),
		)
	}
}

// checkCPE22 checks a CPE 2.2 URI, which may leave its trailing components out.
func (r *Result) checkCPE22(cpe, path string) {
	if !strings.HasPrefix(cpe, cpe22Prefix) {
		r.errorf(CheckCPE, path, "%q is not a CPE 2.2 identifier, they start with %q", cpe, cpe22Prefix)
		return
	}

	if parts := splitCPE(strings.TrimPrefix(cpe, cpe22Prefix)); len(parts) > cpe22Components {
		r.errorf(
			CheckCPE, path,
			"a CPE 2.2 identifier has at most %d colon separated components, %q has %d",
			cpe22Components, cpe, len(parts),
		)
	}
}

// splitCPE splits a CPE on its component separator. Colons that are part of a
// component are escaped with a backslash and do not separate anything.
func splitCPE(cpe string) []string {
	parts := []string{}
	current := strings.Builder{}

	for i := 0; i < len(cpe); i++ {
		switch {
		case cpe[i] == '\\' && i+1 < len(cpe):
			current.WriteByte(cpe[i])
			i++
			current.WriteByte(cpe[i])
		case cpe[i] == ':':
			parts = append(parts, current.String())
			current.Reset()
		default:
			current.WriteByte(cpe[i])
		}
	}

	return append(parts, current.String())
}

// checkHash checks one entry of a component's hashes map.
func (r *Result) checkHash(algo vex.Algorithm, hash vex.Hash, path string) {
	length, known := hashLengths[algo]
	if !known {
		r.warnf(
			CheckHash, path,
			"%q is not a hash algorithm OpenVEX names, so tools matching this component will ignore it; the supported names are %s",
			algo, strings.Join(knownAlgorithms(), ", "),
		)
		return
	}

	value := string(hash)
	if value == "" {
		r.errorf(CheckHash, path, "the %s hash is empty", algo)
		return
	}

	if !isHex(value) {
		r.errorf(CheckHash, path, "%q is not a hexadecimal %s hash", value, algo)
		return
	}

	if len(value) != length {
		r.errorf(
			CheckHash, path,
			"a %s hash is %d hexadecimal characters long, %q has %d",
			algo, length, value, len(value),
		)
	}
}

func knownAlgorithms() []string {
	algorithms := slices.Sorted(maps.Keys(hashLengths))

	names := make([]string, 0, len(algorithms))
	for _, algo := range algorithms {
		names = append(names, string(algo))
	}
	return names
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] >= '0' && s[i] <= '9':
		case s[i] >= 'a' && s[i] <= 'f':
		case s[i] >= 'A' && s[i] <= 'F':
		default:
			return false
		}
	}
	return true
}
