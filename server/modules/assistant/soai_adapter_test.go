// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"context"
	"strings"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/stretchr/testify/assert"
)

func TestSOAiConstructor(t *testing.T) {
	// an expired test key for buildApiKey
	license := `H4sIAAziJWgC/z2NW4+iQBSE/8qEV2YiCC3gGzcvKALSoONms2mgQZSbNFc3+98XZ5JJ6qFO6qs6fykcxzhs0g5TS2rOzMEHAz5YABlm+aUL9U7hoUpr1KRl8cMsPlgezrklkCa9mALlrwUXh22dNuObVUz4m12XU5ZGU5LUKEzxnwaTJkPBn9cMA1gwxVka4oLgV339Bb3Bb2jKYoyatsaEWv76/U61BNeTZaZ3ZYS/HSlDr86m7kRHqEE/B0mT4qs8nbuw6Ub6wm2eUb6wNUmQK+Q/R77J284zPDXT+dPdcRcFOEjrDd5Vea/LKwuuDgBZUazDLpk57PFuNX3VPZkTUK0EtIdkmHf0eNKGWrwLW6vnxj4k3W5XpAYnMwa5XirVZnucc9sWbV1QrfW4T7vOPaQsvc8VDrXPvSL4RyHbrOJS05HoJP1Je9SEjVMZGJxipot6iLz8qNKFMhb051otF0JM3w4mHYnyeYBzwUEQDHQYHUS1gFgY1MZktoocKMFKSmlxDe73HMbXlSQrSsjbZ4ueXc+fkOgqv9YJseX98NgwXDK2+Ix6ceRZfy88ofGQLG8UzN3xiFwZ841emhpub+LNWxCvz/Kszcx2P7K+thPVI6NwQUcLRmhZCdekz+21daPOCPNNU0vZfjazNdX0g4VuwCowUNQn5AIln547vL+y1xrcOkiaH9LHg+d7/tnVW77zN7JK63UYeD68MOx4+RRNQcCVfXYDseP5EpQKgSa4XE+wthTAtIRd6WJgtqHjHg0mvzm3ZsfZ1L//d3LBEekCAAA=`
	licensing.Init(license)

	testCases := []struct {
		name                         string
		config                       map[string]interface{}
		expectedApiUrl               string
		expectedHealthTimeoutSeconds int
		expectError                  bool
	}{
		{
			name:                         "default config",
			config:                       map[string]interface{}{},
			expectedApiUrl:               DEFAULT_APIURL,
			expectedHealthTimeoutSeconds: DEFAULT_HEALTH_TIMEOUT_SECONDS,
			expectError:                  false,
		},
		{
			name: "custom apiUrl",
			config: map[string]interface{}{
				"apiUrl": "https://custom.api.com",
			},
			expectedApiUrl:               "https://custom.api.com",
			expectedHealthTimeoutSeconds: DEFAULT_HEALTH_TIMEOUT_SECONDS,
			expectError:                  false,
		},
		{
			name: "custom healthTimeoutSeconds",
			config: map[string]interface{}{
				"healthTimeoutSeconds": float64(10),
			},
			expectedApiUrl:               DEFAULT_APIURL,
			expectedHealthTimeoutSeconds: 10,
			expectError:                  false,
		},
		{
			name: "custom systemPromptAddendum",
			config: map[string]interface{}{
				"systemPromptAddendum": "Custom addendum text",
			},
			expectedApiUrl:               DEFAULT_APIURL,
			expectedHealthTimeoutSeconds: DEFAULT_HEALTH_TIMEOUT_SECONDS,
			expectError:                  false,
		},
		{
			name: "systemPromptAddendum exceeds max length",
			config: map[string]interface{}{
				"systemPromptAddendum":          strings.Repeat("A", 60000),
				"systemPromptAddendumMaxLength": float64(1000),
			},
			expectedApiUrl:               DEFAULT_APIURL,
			expectedHealthTimeoutSeconds: DEFAULT_HEALTH_TIMEOUT_SECONDS,
			expectError:                  false,
		},
		{
			name: "all custom config",
			config: map[string]interface{}{
				"apiUrl":               "https://another.api.com",
				"healthTimeoutSeconds": float64(15),
				"systemPromptAddendum": "Another custom addendum",
			},
			expectedApiUrl:               "https://another.api.com",
			expectedHealthTimeoutSeconds: 15,
			expectError:                  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := &server.Server{}
			adapter, err := NewSOAiCloudAdapter(context.Background(), srv, tc.config)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				br := adapter.(*SOAiCloudAdapter)
				assert.NotEmpty(t, br.apiKey)
				assert.Contains(t, br.apiKey, "sk-")
				assert.Equal(t, tc.expectedApiUrl, br.apiUrl)
				assert.Equal(t, tc.expectedHealthTimeoutSeconds, br.healthTimeoutSeconds)
			}
		})
	}
}
