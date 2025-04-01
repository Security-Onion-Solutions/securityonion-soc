package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/security-onion-solutions/securityonion-soc/model"
	"github.com/security-onion-solutions/securityonion-soc/rbac"
	"github.com/security-onion-solutions/securityonion-soc/web"

	"github.com/apex/log"
	"github.com/elastic/go-elasticsearch/v8" // Import the actual client
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/security-onion-solutions/securityonion-soc/server/modules/elastic" // Import the elastic module package
)

// ElasticsearchProxyRequest defines the structure for requests from the frontend
type ElasticsearchProxyRequest struct {
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body"` // Use RawMessage to pass JSON through
}

// RegisterElasticsearchRoutes sets up the routing for the ES proxy endpoint
func RegisterElasticsearchRoutes(server *Server, r chi.Router, basePath string) {
	logger := log.WithFields(log.Fields{
		"module": "server",
		"route":  basePath,
	})
	logger.Info("Registering Elasticsearch proxy routes")

	r.Post(basePath+"/proxy", server.handleElasticsearchProxy())
}

// handleElasticsearchProxy handles requests to proxy Elasticsearch queries
func (server *Server) handleElasticsearchProxy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := log.FromContext(r.Context())

		// --- Authorization Check ---
		// Define the required permission. Let's create a new one for this specific action.
		requiredPermission := rbac.Operation{Name: "elasticsearch:proxy:execute"}
		targetResource := "elasticsearch" // General target for now

		// Check if the user has the required permission
		// NOTE: This assumes the standard middleware populates user context correctly.
		err := server.CheckAuthorized(r.Context(), requiredPermission.Name, targetResource)
		if err != nil {
			logger.WithError(err).Warn("Authorization check failed for Elasticsearch proxy")
			web.Respond(w, r, http.StatusForbidden, model.NewError(err))
			return
		}

		// --- Decode Request Body ---
		var proxyReq ElasticsearchProxyRequest
		if err := json.NewDecoder(r.Body).Decode(&proxyReq); err != nil {
			logger.WithError(err).Warn("Failed to decode Elasticsearch proxy request body")
			web.Respond(w, r, http.StatusBadRequest, model.NewError(fmt.Errorf("invalid request body: %w", err)))
			return
		}
		defer r.Body.Close()

		// --- Validate Request ---
		proxyReq.Method = strings.ToUpper(proxyReq.Method)
		if proxyReq.Method == "" || proxyReq.Path == "" {
			web.Respond(w, r, http.StatusBadRequest, model.NewError(fmt.Errorf("method and path are required")))
			return
		}
		// Ensure path starts with '/'
		if !strings.HasPrefix(proxyReq.Path, "/") {
			proxyReq.Path = "/" + proxyReq.Path
		}

		logger = logger.WithFields(log.Fields{
			"es_method": proxyReq.Method,
			"es_path":   proxyReq.Path,
		})
		logger.Info("Processing Elasticsearch proxy request")

		// --- Get Elasticsearch Client ---
		// --- Get Elasticsearch Client ---
		esStore, ok := server.Eventstore.(*elastic.ElasticEventstore)
		if !ok || esStore == nil {
			logger.Error("Eventstore is not an ElasticEventstore or is nil")
			web.Respond(w, r, http.StatusInternalServerError, model.NewError(fmt.Errorf("elasticsearch client provider not available")))
			return
		}
		esClient := esStore.GetClient() // Assuming ElasticEventstore has a GetClient() method or direct access
		if esClient == nil {
			logger.Error("Elasticsearch client is not available within ElasticEventstore")
			web.Respond(w, r, http.StatusInternalServerError, model.NewError(fmt.Errorf("elasticsearch client not configured or available")))
			return
		}

		// --- Perform Elasticsearch Request ---
		var reqBody io.Reader
		if len(proxyReq.Body) > 0 && proxyReq.Body.String() != "null" {
			reqBody = strings.NewReader(string(proxyReq.Body))
		}

		// --- Build Elasticsearch Request using esapi ---
		// The Perform method takes an esapi.Request struct
		req := esapi.Request{
			Method: proxyReq.Method,
			Path:   proxyReq.Path,
			Body:   reqBody,
			// We might need to set other options like headers if required
		}

		// --- Perform Elasticsearch Request ---
		res, err := esClient.Perform(req.WithContext(r.Context())) // Use the Perform method with esapi.Request

		if err != nil {
			logger.WithError(err).Errorf("Error performing Elasticsearch request")
			web.Respond(w, r, http.StatusInternalServerError, model.NewError(fmt.Errorf("elasticsearch request failed: %w", err)))
			return
		}
		defer res.Body.Close()

		// --- Handle Elasticsearch Response ---
		// Check for Elasticsearch error status codes
		if res.IsError() {
			logger.WithField("status_code", res.StatusCode).Warn("Elasticsearch returned an error status")
			// Read the error body from Elasticsearch response
			bodyBytes, _ := io.ReadAll(res.Body)
			// Try to parse as JSON, otherwise return raw string
			var errorResp map[string]interface{}
			if json.Unmarshal(bodyBytes, &errorResp) == nil {
				web.Respond(w, r, res.StatusCode, errorResp) // Forward ES error JSON
			} else {
				web.Respond(w, r, res.StatusCode, model.NewError(fmt.Errorf("elasticsearch error: %s", string(bodyBytes))))
			}
			return
		}

		// --- Stream Response Back to Client ---
		// Read the successful response body
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			logger.WithError(err).Error("Failed to read Elasticsearch response body")
			web.Respond(w, r, http.StatusInternalServerError, model.NewError(fmt.Errorf("failed to read elasticsearch response: %w", err)))
			return
		}

		// Attempt to decode as JSON for logging/potential manipulation, but send raw bytes
		var respData interface{}
		if json.Unmarshal(bodyBytes, &respData) != nil {
			// If not JSON, treat as plain text (though ES usually returns JSON)
			logger.Warn("Elasticsearch response was not valid JSON")
			w.Header().Set("Content-Type", "text/plain") // Or determine from ES response header
		} else {
			w.Header().Set("Content-Type", "application/json")
		}

		w.WriteHeader(res.StatusCode) // Use the status code from Elasticsearch
		_, writeErr := w.Write(bodyBytes)
		if writeErr != nil {
			logger.WithError(writeErr).Error("Failed to write Elasticsearch response to client")
			// Can't send another response here as header/body might be partially written
		}
	}
}

// NOTE: getElasticsearchClient function is removed as the logic is now inline in the handler.
// The interface is also removed as we are using the concrete *elasticsearch.Client type.

// Mock implementation for the interface (useful for testing later)
// We might need a mock that implements the *elasticsearch.Client interface or uses a wrapper.
/*
type MockESClient struct{}

func (m *MockESClient) Perform(req esapi.Request) (*esapi.Response, error) {
	// Return a mock response for testing
	mockRespBody := `{"mock": "response"}`
	resp := &esapi.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(mockRespBody)),
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")
	return resp, nil
}
*/

// We need to add a public GetClient method to ElasticEventstore
// or make the esClient field public if it isn't already.
// Let's assume we add a GetClient method for better encapsulation.

// Placeholder for the actual GetClient method in elasticeventstore.go
// func (store *ElasticEventstore) GetClient() *elasticsearch.Client {
//     return store.esClient
// }