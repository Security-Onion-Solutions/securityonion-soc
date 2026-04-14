// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package assistant

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/licensing"
	"github.com/security-onion-solutions/securityonion-soc/server"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/detections/mock"
	"github.com/security-onion-solutions/securityonion-soc/web"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
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

func TestSOAiConstructorWithLicense(t *testing.T) {
	// a test key with aiGatewayUrl = https://license.api.com
	license := `H4sIAAAAAAAA/zyS246qSBiFX6VTt9hbEEoOd4B4QBHUEm0nk50CCizlJFWAOJl3n9g92cl/8a/kW+vq+weQNCUxpx0BBpiIE/gpwk8JIlE0vu8CRoA8a9pgTqvyDzP9lBQ0kQ2oG1B/MyUu3gsHErcN5cOHX9Kq/AiaCowATYABsgbHlPzmhPEcR7/fMyKUIBiBnMakZORdX3xDH+gHAiOQEszbhjBg/PX3CLSMNAwY4giUVUJ+PlbFxyYHBgAjkGCO/wRGs/K7DAywjnk3CBd5+UqKaTDTVbPG4WtQeNF2R/do545yuu8O0xJu9cWSrOuid8y5j+ZbiP0kdVCXjXfS/u7zvu5e4gnafgbbbfacdMJwmj0b7a6u/F4e+ph163VJXdkUXXa91HYg9aSQVy1eHWC9cNKedt1hSyVhU1gybl8bSw33ar6cp9XMwdou60+zR8OklJrQlS2PTptnciz2tlBaQyl8LexqqqbCbesJiWaen2ii7jCCTyFOtppdIqI+be6JK8uMrGiuU0FbwPu9QOl1rpuWFSvB2RfG1/MXYo6tLBzGAnPzfCxFORtacsa9NihSuFFfyH3o/nFQvfV+jw8mUbhTeTPS3rTbccqOfV7kbe61m0EKZ2vN3ouWHHWC6sa+n8mcvlbX9pB0blwseaPnm/E4mNleGE0dF9WRi5M+Yxekh8Jkp4TzYDFDqx3WJ1v6eChKr7y6ZqV04dK0BaeJo2OILqI0XL40T1VJHZwPkdYpSgUriyEPXq4n1PgWFFsmzR0t8tp4d9i7YnHb3fhaDsAIYLrAnPR4+BHkynnNjPH4f/l+4Zr+iqsC/PtfAAAA//+k/vXDEgMAAA==`
	licensing.Init(license)

	srv := &server.Server{}

	t.Run("license URL used when config is default", func(t *testing.T) {
		config := map[string]interface{}{}
		adapter, err := NewSOAiCloudAdapter(context.Background(), srv, config)

		assert.NoError(t, err)
		br := adapter.(*SOAiCloudAdapter)
		assert.Equal(t, "https://license.api.com", br.apiUrl)
	})

	t.Run("custom config overrides license URL", func(t *testing.T) {
		config := map[string]interface{}{
			"apiUrl": "https://custom.api.com",
		}
		adapter, err := NewSOAiCloudAdapter(context.Background(), srv, config)

		assert.NoError(t, err)
		br := adapter.(*SOAiCloudAdapter)
		assert.Equal(t, "https://custom.api.com", br.apiUrl)
	})
}

func TestSOAiGetHealth(t *testing.T) {
	// an expired test key for buildApiKey
	license := `H4sIAAziJWgC/z2NW4+iQBSE/8qEV2YiCC3gGzcvKALSoONms2mgQZSbNFc3+98XZ5JJ6qFO6qs6fykcxzhs0g5TS2rOzMEHAz5YABlm+aUL9U7hoUpr1KRl8cMsPlgezrklkCa9mALlrwUXh22dNuObVUz4m12XU5ZGU5LUKEzxnwaTJkPBn9cMA1gwxVka4oLgV339Bb3Bb2jKYoyatsaEWv76/U61BNeTZaZ3ZYS/HSlDr86m7kRHqEE/B0mT4qs8nbuw6Ub6wm2eUb6wNUmQK+Q/R77J284zPDXT+dPdcRcFOEjrDd5Vea/LKwuuDgBZUazDLpk57PFuNX3VPZkTUK0EtIdkmHf0eNKGWrwLW6vnxj4k3W5XpAYnMwa5XirVZnucc9sWbV1QrfW4T7vOPaQsvc8VDrXPvSL4RyHbrOJS05HoJP1Je9SEjVMZGJxipot6iLz8qNKFMhb051otF0JM3w4mHYnyeYBzwUEQDHQYHUS1gFgY1MZktoocKMFKSmlxDe73HMbXlSQrSsjbZ4ueXc+fkOgqv9YJseX98NgwXDK2+Ix6ceRZfy88ofGQLG8UzN3xiFwZ841emhpub+LNWxCvz/Kszcx2P7K+thPVI6NwQUcLRmhZCdekz+21daPOCPNNU0vZfjazNdX0g4VuwCowUNQn5AIln547vL+y1xrcOkiaH9LHg+d7/tnVW77zN7JK63UYeD68MOx4+RRNQcCVfXYDseP5EpQKgSa4XE+wthTAtIRd6WJgtqHjHg0mvzm3ZsfZ1L//d3LBEekCAAA=`
	licensing.Init(license)

	testCases := []struct {
		name           string
		config         map[string]interface{}
		mockResponse   *http.Response
		mockError      error
		expectError    bool
		expectedStatus string
	}{
		{
			name: "successful health check",
			config: map[string]interface{}{
				"apiUrl": "https://test.api.com",
			},
			mockResponse: &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ok"}`)),
			},
			mockError:      nil,
			expectError:    false,
			expectedStatus: "ok",
		},
		{
			name: "health check with error status",
			config: map[string]interface{}{
				"apiUrl": "https://test.api.com",
			},
			mockResponse: &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status":"degraded"}`)),
			},
			mockError:      nil,
			expectError:    false,
			expectedStatus: "degraded",
		},
		{
			name: "network error",
			config: map[string]interface{}{
				"apiUrl": "https://test.api.com",
			},
			mockResponse: nil,
			mockError:    errors.New("connection timeout"),
			expectError:  true,
		},
		{
			name: "invalid JSON response",
			config: map[string]interface{}{
				"apiUrl": "https://test.api.com",
			},
			mockResponse: &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewBufferString(`{invalid json`)),
			},
			mockError:   nil,
			expectError: true,
		},
		{
			name: "custom timeout configuration",
			config: map[string]interface{}{
				"apiUrl":               "https://test.api.com",
				"healthTimeoutSeconds": float64(5),
			},
			mockResponse: &http.Response{
				StatusCode: 200,
				Body:       io.NopCloser(bytes.NewBufferString(`{"status":"ok"}`)),
			},
			mockError:      nil,
			expectError:    false,
			expectedStatus: "ok",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockIO := mock.NewMockIOManager(ctrl)

			// Set up expectation for MakeRequest
			mockIO.EXPECT().
				MakeRequest(gomock.Any(), false).
				Return(tc.mockResponse, tc.mockError).
				Times(1)

			srv := &server.Server{
				Host: &web.Host{
					Version: "test-version",
				},
			}
			adapter, err := NewSOAiCloudAdapter(context.Background(), srv, tc.config)
			assert.NoError(t, err)

			// Replace the IOManager with our mock
			soaiAdapter := adapter.(*SOAiCloudAdapter)
			soaiAdapter.IOManager = mockIO

			// Call GetHealth
			ctx := context.Background()
			health, err := soaiAdapter.GetHealth(ctx)

			if tc.expectError {
				assert.Error(t, err)
				if tc.mockError != nil {
					assert.Nil(t, health)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, health)
				assert.Equal(t, tc.expectedStatus, health.Status)
			}
		})
	}
}
