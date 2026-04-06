// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"time"
)

// X509Scanner parses X.509 certificates (DER and PEM)
type X509Scanner struct{}

func NewX509Scanner() *X509Scanner { return &X509Scanner{} }

func (s *X509Scanner) Name() string                                  { return "ScanX509" }
func (s *X509Scanner) Init(config map[string]interface{}) error       { return nil }
func (s *X509Scanner) Flavors() []string                              { return []string{"application/x-x509"} }
func (s *X509Scanner) Priority() int                                  { return 5 }

func (s *X509Scanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	var cert *x509.Certificate
	var err error

	// Try PEM first
	block, _ := pem.Decode(file)
	if block != nil {
		cert, err = x509.ParseCertificate(block.Bytes)
	} else {
		// Try DER
		cert, err = x509.ParseCertificate(file)
	}

	if err != nil {
		return nil, err
	}

	result := map[string]interface{}{
		"subject":      cert.Subject.String(),
		"issuer":       cert.Issuer.String(),
		"serialNumber": cert.SerialNumber.String(),
		"notBefore":    cert.NotBefore.Format(time.RFC3339),
		"notAfter":     cert.NotAfter.Format(time.RFC3339),
		"isCA":         cert.IsCA,
		"keyAlgorithm": cert.PublicKeyAlgorithm.String(),
		"sigAlgorithm": cert.SignatureAlgorithm.String(),
		"version":      cert.Version,
	}

	// Check if expired
	now := time.Now()
	result["isExpired"] = now.After(cert.NotAfter)
	result["isNotYetValid"] = now.Before(cert.NotBefore)

	// SANs
	var sans []interface{}
	for _, dns := range cert.DNSNames {
		sans = append(sans, dns)
	}
	for _, email := range cert.EmailAddresses {
		sans = append(sans, email)
	}
	for _, ip := range cert.IPAddresses {
		sans = append(sans, ip.String())
	}
	if len(sans) > 0 {
		result["subjectAltNames"] = sans
	}

	// Key usage
	var keyUsage []interface{}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		keyUsage = append(keyUsage, "DigitalSignature")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		keyUsage = append(keyUsage, "KeyEncipherment")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		keyUsage = append(keyUsage, "CertSign")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		keyUsage = append(keyUsage, "CRLSign")
	}
	if len(keyUsage) > 0 {
		result["keyUsage"] = keyUsage
	}

	// Extended key usage
	var extKeyUsage []interface{}
	for _, usage := range cert.ExtKeyUsage {
		switch usage {
		case x509.ExtKeyUsageServerAuth:
			extKeyUsage = append(extKeyUsage, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			extKeyUsage = append(extKeyUsage, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			extKeyUsage = append(extKeyUsage, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			extKeyUsage = append(extKeyUsage, "EmailProtection")
		}
	}
	if len(extKeyUsage) > 0 {
		result["extKeyUsage"] = extKeyUsage
	}

	// Self-signed check
	if cert.Subject.String() == cert.Issuer.String() {
		result["isSelfSigned"] = true
	}

	return &ScanResult{Scanner: s.Name(), Data: result}, nil
}

// Pkcs7Scanner parses PKCS#7 / CMS signatures
type Pkcs7Scanner struct{}

func NewPkcs7Scanner() *Pkcs7Scanner { return &Pkcs7Scanner{} }

func (s *Pkcs7Scanner) Name() string                                  { return "ScanPkcs7" }
func (s *Pkcs7Scanner) Init(config map[string]interface{}) error       { return nil }
func (s *Pkcs7Scanner) Flavors() []string                              { return []string{"application/pkcs7-mime"} }
func (s *Pkcs7Scanner) Priority() int                                  { return 5 }

func (s *Pkcs7Scanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	// Try to parse embedded certificates from PKCS#7 data
	// The Go stdlib doesn't have a PKCS7 parser, so we extract DER certs if present
	var certs []*x509.Certificate

	// Try PEM decode first
	rest := file
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" || block.Type == "PKCS7" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				certs = append(certs, cert)
			}
		}
	}

	// Try parsing as DER-encoded PKCS7
	if len(certs) == 0 {
		// PKCS7 ContentInfo starts with SEQUENCE, then OID
		// Try to extract embedded certificates
		parsedCerts, err := x509.ParseCertificates(file)
		if err == nil {
			certs = parsedCerts
		}
	}

	var certInfo []interface{}
	for _, cert := range certs {
		certInfo = append(certInfo, map[string]interface{}{
			"subject": cert.Subject.String(),
			"issuer":  cert.Issuer.String(),
			"serial":  cert.SerialNumber.String(),
		})
	}

	return &ScanResult{
		Scanner: s.Name(),
		Data: map[string]interface{}{
			"certificates": certInfo,
			"certCount":    len(certs),
		},
	}, nil
}

// PgpScanner analyzes PGP/GPG armored and binary data
type PgpScanner struct{}

func NewPgpScanner() *PgpScanner { return &PgpScanner{} }

func (s *PgpScanner) Name() string                                  { return "ScanPgp" }
func (s *PgpScanner) Init(config map[string]interface{}) error       { return nil }
func (s *PgpScanner) Flavors() []string                              { return []string{"application/pgp"} }
func (s *PgpScanner) Priority() int                                  { return 5 }

func (s *PgpScanner) Scan(file []byte, metadata FileMetadata) (*ScanResult, error) {
	content := string(file)
	result := make(map[string]interface{})

	// Detect PGP message type from armor headers
	if strings.Contains(content, "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		result["type"] = "public_key"
	} else if strings.Contains(content, "-----BEGIN PGP PRIVATE KEY BLOCK-----") {
		result["type"] = "private_key"
	} else if strings.Contains(content, "-----BEGIN PGP MESSAGE-----") {
		result["type"] = "encrypted_message"
	} else if strings.Contains(content, "-----BEGIN PGP SIGNATURE-----") {
		result["type"] = "detached_signature"
	} else if strings.Contains(content, "-----BEGIN PGP SIGNED MESSAGE-----") {
		result["type"] = "signed_message"
	} else {
		// Binary PGP - check packet tag
		if len(file) > 0 {
			tag := file[0]
			if tag&0x80 != 0 { // Valid PGP packet
				packetTag := (tag & 0x3C) >> 2
				switch packetTag {
				case 1:
					result["type"] = "public_key_encrypted_session_key"
				case 2:
					result["type"] = "signature"
				case 5:
					result["type"] = "secret_key"
				case 6:
					result["type"] = "public_key"
				case 8:
					result["type"] = "compressed_data"
				case 9:
					result["type"] = "symmetrically_encrypted_data"
				case 11:
					result["type"] = "literal_data"
				default:
					result["type"] = "binary_pgp"
				}
			}
		}
	}

	result["isArmored"] = strings.Contains(content, "-----BEGIN PGP")

	return &ScanResult{Scanner: s.Name(), Data: result}, nil
}
