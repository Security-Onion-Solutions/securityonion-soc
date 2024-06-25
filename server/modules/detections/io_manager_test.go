package detections

import (
	"net/http"
	"testing"

	"github.com/security-onion-solutions/securityonion-soc/config"
	"github.com/tj/assert"
)

func TestBuildHttpClient(t *testing.T) {
	t.Parallel()

	tests := []struct {
		Name                 string
		Proxy                string
		RootCA               string
		InsecureSkipVerify   bool
		ExpectEmptyTransport bool
	}{
		{
			Name:                 "Empty",
			ExpectEmptyTransport: true,
		},
		{
			Name:  "Has Proxy",
			Proxy: "http://myProxy:3128",
		},
		{
			Name:   "Has Root CA",
			RootCA: "pubkey",
		},
		{
			Name:               "InvalidSkipVerify",
			InsecureSkipVerify: true,
		},
		{
			Name:   "Proxy + Root CA",
			Proxy:  "http://myProxy:3128",
			RootCA: "pubkey",
		},
		{
			Name:               "Proxy + InsecureSkipVerify",
			Proxy:              "http://myProxy:3128",
			InsecureSkipVerify: true,
		},
		{
			Name:               "Proxy + Root CA + InsecureSkipVerify",
			Proxy:              "http://myProxy:3128",
			RootCA:             "pubkey",
			InsecureSkipVerify: true,
		},
		{
			Name:                 "Invalid Proxy",
			Proxy:                "%",
			ExpectEmptyTransport: true,
		},
	}

	proxy := "http://myProxy:3128"

	resman := &ResourceManager{
		Config: &config.ServerConfig{
			Proxy: "",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.Name, func(t *testing.T) {
			resman.Config.Proxy = test.Proxy
			resman.Config.AdditionalCA = test.RootCA
			resman.Config.InsecureSkipVerify = test.InsecureSkipVerify

			client := resman.buildHttpClient()
			transport := client.Transport.(*http.Transport)

			if test.ExpectEmptyTransport {
				assert.Equal(t, &http.Transport{}, transport)
				return
			}

			if test.Proxy != "" {
				assert.NotNil(t, transport)
				assert.NotNil(t, transport.Proxy)

				proxyURL, err := transport.Proxy(nil)
				assert.NoError(t, err)
				assert.Equal(t, proxy, proxyURL.String())
			}

			if test.RootCA != "" {
				assert.NotNil(t, transport.TLSClientConfig)
				assert.NotNil(t, transport.TLSClientConfig.RootCAs)
			} else {
				if transport.TLSClientConfig != nil {
					assert.Nil(t, transport.TLSClientConfig.RootCAs)
				}
			}

			if test.InsecureSkipVerify {
				assert.True(t, transport.TLSClientConfig.InsecureSkipVerify)
			} else {
				if transport.TLSClientConfig != nil {
					assert.False(t, transport.TLSClientConfig.InsecureSkipVerify)
				}
			}
		})
	}
}
