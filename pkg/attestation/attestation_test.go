/*
Copyright 2022 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package attestation

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"chainguard.dev/mrclean/pkg/vex"
)

func TestSerialize(t *testing.T) {
	att := New()
	_, ok := att.Predicate.(vex.VEX)
	require.True(t, ok)

	pred := vex.New()
	pred.Author = "Puerco"

	att.Predicate = pred
	var b bytes.Buffer
	err := att.ToJSON(&b)
	require.NoError(t, err)
	require.Equal(t, "", b.String())
}
