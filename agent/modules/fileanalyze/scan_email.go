// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
)

type EmailScanner struct{}

func NewEmailScanner() *EmailScanner {
	return &EmailScanner{}
}

func (s *EmailScanner) Name() string { return "ScanEmail" }

func (s *EmailScanner) Init(config map[string]interface{}) error { return nil }

func (s *EmailScanner) Flavors() []string {
	return []string{"message/rfc822"}
}

func (s *EmailScanner) Priority() int { return 5 }

func (s *EmailScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(file))
	if err != nil {
		return nil, err
	}

	headers := make(map[string]interface{})
	for _, key := range []string{"From", "To", "Subject", "Date", "Message-ID",
		"Content-Type", "X-Mailer", "Reply-To", "Cc", "Bcc",
		"X-Originating-IP", "Received-SPF", "DKIM-Signature"} {
		if v := msg.Header.Get(key); v != "" {
			headers[key] = v
		}
	}

	// Count Received headers (hop count)
	receivedHeaders := msg.Header["Received"]

	// Extract attachments from MIME parts
	var attachments []interface{}
	var extracted []ExtractedFile

	contentType := msg.Header.Get("Content-Type")
	if contentType != "" {
		mediaType, params, err := mime.ParseMediaType(contentType)
		if err == nil && strings.HasPrefix(mediaType, "multipart/") {
			boundary := params["boundary"]
			if boundary != "" {
				body, err := io.ReadAll(msg.Body)
				if err == nil {
					parts := parseMIMEParts(body, boundary)
					for _, part := range parts {
						if part.filename != "" {
							attachments = append(attachments, map[string]interface{}{
								"filename":    part.filename,
								"contentType": part.contentType,
								"size":        len(part.data),
							})
							extracted = append(extracted, ExtractedFile{
								Name:    part.filename,
								Content: part.data,
							})
						}
					}
				}
			}
		}
	}

	result := map[string]interface{}{
		"headers":  headers,
		"hopCount": len(receivedHeaders),
	}

	if len(attachments) > 0 {
		result["attachments"] = attachments
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data:    result,
		Files:   extracted,
	}, nil
}

type mimePart struct {
	filename    string
	contentType string
	data        []byte
}

func parseMIMEParts(body []byte, boundary string) []mimePart {
	var parts []mimePart
	reader := multipart.NewReader(bytes.NewReader(body), boundary)

	for {
		part, err := reader.NextPart()
		if err != nil {
			break
		}

		filename := part.FileName()
		ct := part.Header.Get("Content-Type")

		data, err := io.ReadAll(io.LimitReader(part, DEFAULT_MAX_FILE_SIZE))
		part.Close()
		if err != nil {
			continue
		}

		if filename != "" {
			parts = append(parts, mimePart{
				filename:    filename,
				contentType: ct,
				data:        data,
			})
		} else if strings.HasPrefix(ct, "multipart/") {
			// Nested multipart — recurse
			_, params, err := mime.ParseMediaType(ct)
			if err == nil {
				nested := parseMIMEParts(data, params["boundary"])
				parts = append(parts, nested...)
			}
		}
	}

	return parts
}
