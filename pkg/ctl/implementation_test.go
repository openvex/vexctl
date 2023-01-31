/*
Copyright 2023 Chainguard, Inc.
SPDX-License-Identifier: Apache-2.0
*/
package ctl

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeImageRefs(t *testing.T) {
	impl := defaultVexCtlImplementation{}
	for _, tc := range []struct {
		products     []string
		expectedGood []string
		expectedBad  []string
		shouldFail   bool
	}{
		// docker hub reference
		{
			products:     []string{"nginx"},
			expectedGood: []string{"nginx"},
			expectedBad:  []string{},
			shouldFail:   false,
		},
		// Custom registry
		{
			products:     []string{"registry.k8s.io/kube-apiserver"},
			expectedGood: []string{"registry.k8s.io/kube-apiserver"},
			expectedBad:  []string{},
			shouldFail:   false,
		},
		// Custom registry, tagged image
		{
			products:     []string{"registry.k8s.io/kube-apiserver:v1.26.0"},
			expectedGood: []string{"registry.k8s.io/kube-apiserver:v1.26.0"},
			expectedBad:  []string{},
			shouldFail:   false,
		},
		// purl, custom registry
		{
			products:     []string{"pkg:oci/kube-apiserver?repository_url=registry.k8s.io&tag=v1.26.0"},
			expectedGood: []string{"registry.k8s.io/kube-apiserver:v1.26.0"},
			expectedBad:  []string{},
			shouldFail:   false,
		},
		// purl, dockerhub
		{
			products:     []string{"pkg:oci/nginx"},
			expectedGood: []string{"nginx"},
			expectedBad:  []string{},
			shouldFail:   false,
		},
		// purl, with digest
		{
			products:     []string{"pkg:oci/alpine@sha256%3Af271e74b17ced29b915d351685fd4644785c6d1559dd1f2d4189a5e851ef753a"},
			expectedGood: []string{"alpine@sha256:f271e74b17ced29b915d351685fd4644785c6d1559dd1f2d4189a5e851ef753a"},
			expectedBad:  []string{},
			shouldFail:   false,
		},
		// other purl
		{
			products:     []string{"pkg:apk/wolfi/bash@1.0.0"},
			expectedGood: []string{},
			expectedBad:  []string{"pkg:apk/wolfi/bash@1.0.0"},
			shouldFail:   false,
		},
		// mixed good and bad
		{
			products:     []string{"pkg:apk/wolfi/bash@1.0.0", "nginx"},
			expectedGood: []string{"nginx"},
			expectedBad:  []string{"pkg:apk/wolfi/bash@1.0.0"},
			shouldFail:   false,
		},
	} {
		good, bad, err := impl.NormalizeImageRefs(tc.products)
		if tc.shouldFail {
			require.Error(t, err)
			continue
		}
		require.Equal(t, tc.expectedGood, good)
		require.Equal(t, tc.expectedBad, bad)
	}
}
