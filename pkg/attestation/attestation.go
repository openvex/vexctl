/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package attestation

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	intoto "github.com/in-toto/in-toto-golang/in_toto"

	"chainguard.dev/mrclean/pkg/vex"
)

type (
	Attestation intoto.Statement
)

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
