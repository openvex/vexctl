/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package attestation

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/vex/pkg/vex"
)

func TestSerialize(t *testing.T) {
	att := New()
	pred := vex.New()
	pred.Author = "Chainguard"
	att.Predicate = pred

	var b bytes.Buffer
	err := att.ToJSON(&b)
	require.NoError(t, err)

	att2 := New()
	err = json.Unmarshal(b.Bytes(), &att2)
	require.NoError(t, err)
	require.Equal(t, att2.Predicate.Author, "Chainguard")
}
