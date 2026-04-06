// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestX509ScannerInit(t *testing.T) {
	s := NewX509Scanner()
	assert.Equal(t, "ScanX509", s.Name())
	assert.Contains(t, s.Flavors(), "application/x-x509")
}

func TestPkcs7ScannerInit(t *testing.T) {
	s := NewPkcs7Scanner()
	assert.Equal(t, "ScanPkcs7", s.Name())
}

func TestPgpScannerArmoredPublicKey(t *testing.T) {
	s := NewPgpScanner()

	pgp := []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----\nsome key data\n-----END PGP PUBLIC KEY BLOCK-----")
	result, err := s.Scan(pgp, FileMetadata{Name: "key.asc"})
	require.NoError(t, err)
	assert.Equal(t, "public_key", result.Data["type"])
	assert.True(t, result.Data["isArmored"].(bool))
}

func TestPgpScannerArmoredMessage(t *testing.T) {
	s := NewPgpScanner()

	pgp := []byte("-----BEGIN PGP MESSAGE-----\nencrypted data\n-----END PGP MESSAGE-----")
	result, err := s.Scan(pgp, FileMetadata{Name: "message.gpg"})
	require.NoError(t, err)
	assert.Equal(t, "encrypted_message", result.Data["type"])
}

func TestPgpScannerSignature(t *testing.T) {
	s := NewPgpScanner()

	pgp := []byte("-----BEGIN PGP SIGNATURE-----\nsig data\n-----END PGP SIGNATURE-----")
	result, err := s.Scan(pgp, FileMetadata{Name: "sig.asc"})
	require.NoError(t, err)
	assert.Equal(t, "detached_signature", result.Data["type"])
}
