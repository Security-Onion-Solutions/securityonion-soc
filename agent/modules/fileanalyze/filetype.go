// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package fileanalyze

import (
	"bytes"
	"strings"
)

// magicSignature maps magic bytes to MIME types
type magicSignature struct {
	magic  []byte
	offset int
	mime   string
}

var magicSignatures = []magicSignature{
	// Archives
	{magic: []byte{0x50, 0x4B, 0x03, 0x04}, mime: "application/zip"},
	{magic: []byte{0x50, 0x4B, 0x05, 0x06}, mime: "application/zip"},                           // Empty archive
	{magic: []byte{0x1F, 0x8B}, mime: "application/gzip"},                                       // Gzip
	{magic: []byte{0x42, 0x5A, 0x68}, mime: "application/x-bzip2"},                              // Bzip2
	{magic: []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C}, mime: "application/x-7z-compressed"},   // 7z
	{magic: []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07}, mime: "application/x-rar"},              // RAR
	{magic: []byte{0x78, 0x01}, mime: "application/zlib"},                                       // Zlib (low compression)
	{magic: []byte{0x78, 0x9C}, mime: "application/zlib"},                                       // Zlib (default)
	{magic: []byte{0x78, 0xDA}, mime: "application/zlib"},                                       // Zlib (best compression)
	{magic: []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}, mime: "application/x-xz"},              // XZ
	{magic: []byte{0x5D, 0x00, 0x00}, mime: "application/x-lzma"},                               // LZMA

	// Executables
	{magic: []byte{0x4D, 0x5A}, mime: "application/x-dosexec"},                                  // PE/MZ
	{magic: []byte{0x7F, 0x45, 0x4C, 0x46}, mime: "application/x-elf"},                          // ELF
	{magic: []byte{0xFE, 0xED, 0xFA, 0xCE}, mime: "application/x-mach-binary"},                  // Mach-O 32-bit
	{magic: []byte{0xFE, 0xED, 0xFA, 0xCF}, mime: "application/x-mach-binary"},                  // Mach-O 64-bit
	{magic: []byte{0xCE, 0xFA, 0xED, 0xFE}, mime: "application/x-mach-binary"},                  // Mach-O 32-bit (reversed)
	{magic: []byte{0xCF, 0xFA, 0xED, 0xFE}, mime: "application/x-mach-binary"},                  // Mach-O 64-bit (reversed)

	// Documents
	{magic: []byte{0x25, 0x50, 0x44, 0x46}, mime: "application/pdf"},                            // PDF
	{magic: []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}, mime: "application/x-ole"}, // OLE

	// Images
	{magic: []byte{0xFF, 0xD8, 0xFF}, mime: "image/jpeg"},                                       // JPEG
	{magic: []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}, mime: "image/png"},         // PNG
	{magic: []byte{0x47, 0x49, 0x46, 0x38}, mime: "image/gif"},                                  // GIF
	{magic: []byte{0x42, 0x4D}, mime: "image/bmp"},                                              // BMP

	// Email
	{magic: []byte{0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x64, 0x3A}, mime: "message/rfc822"}, // "Received:"
	{magic: []byte{0x46, 0x72, 0x6F, 0x6D, 0x3A}, mime: "message/rfc822"},                          // "From:"

	// Crypto
	{magic: []byte{0x30, 0x82}, mime: "application/x-x509"},                                     // DER certificate

	// ISO
	{magic: []byte{0x43, 0x44, 0x30, 0x30, 0x31}, offset: 0x8001, mime: "application/x-iso9660-image"}, // CD001 at offset 0x8001

	// RTF
	{magic: []byte{0x7B, 0x5C, 0x72, 0x74, 0x66}, mime: "application/rtf"},                     // {\rtf

	// TNEF (winmail.dat)
	{magic: []byte{0x78, 0x9F, 0x3E, 0x22}, mime: "application/ms-tnef"},

	// OneNote
	{magic: []byte{0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D,
		0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3}, mime: "application/onenote"},

	// SWF (Flash)
	{magic: []byte{0x46, 0x57, 0x53}, mime: "application/x-shockwave-flash"}, // FWS
	{magic: []byte{0x43, 0x57, 0x53}, mime: "application/x-shockwave-flash"}, // CWS (zlib)
	{magic: []byte{0x5A, 0x57, 0x53}, mime: "application/x-shockwave-flash"}, // ZWS (lzma)

	// LNK (Windows shortcut)
	{magic: []byte{0x4C, 0x00, 0x00, 0x00}, mime: "application/x-ms-shortcut"},
}

// IdentifyType returns a list of MIME types that match the file content
func IdentifyType(data []byte) []string {
	var types []string

	for _, sig := range magicSignatures {
		if sig.offset > 0 {
			if len(data) > sig.offset+len(sig.magic) {
				if bytes.Equal(data[sig.offset:sig.offset+len(sig.magic)], sig.magic) {
					types = append(types, sig.mime)
				}
			}
		} else {
			if bytes.HasPrefix(data, sig.magic) {
				types = append(types, sig.mime)
			}
		}
	}

	// Check for tar (ustar magic at offset 257)
	if len(data) > 262 {
		if string(data[257:262]) == "ustar" {
			types = append(types, "application/x-tar")
		}
	}

	// Text-based detection
	if len(types) == 0 && len(data) > 0 {
		sample := data
		if len(sample) > 4096 {
			sample = sample[:4096]
		}
		text := string(sample)
		textLower := strings.ToLower(text)

		if strings.HasPrefix(text, "<!DOCTYPE html") || strings.HasPrefix(text, "<html") || strings.HasPrefix(textLower, "<!doctype html") {
			types = append(types, "text/html")
		} else if strings.HasPrefix(text, "<?xml") || strings.HasPrefix(text, "<") {
			types = append(types, "text/xml")
		} else if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
			types = append(types, "application/json")
		} else if strings.HasPrefix(text, "Received:") || strings.HasPrefix(text, "From:") || strings.HasPrefix(text, "MIME-Version:") {
			types = append(types, "message/rfc822")
		}

		// Script detection
		if strings.Contains(textLower, "<?php") {
			types = append(types, "application/x-php")
		}
		if strings.Contains(textLower, "<script") || strings.Contains(text, "function(") || strings.Contains(text, "function (") {
			types = append(types, "application/javascript")
		}
		if strings.HasPrefix(textLower, "@echo off") || strings.HasPrefix(textLower, "rem ") {
			types = append(types, "application/x-bat")
		}
		if strings.Contains(textLower, "wscript") || strings.Contains(textLower, "createobject") {
			types = append(types, "text/vbscript")
		}
		if strings.Contains(text, "-----BEGIN PGP") {
			types = append(types, "application/pgp")
		}
		if strings.Contains(text, "-----BEGIN CERTIFICATE-----") {
			types = append(types, "application/x-x509")
		}
		if strings.HasPrefix(text, "[InternetShortcut]") {
			types = append(types, "application/x-url")
		}
		if strings.HasPrefix(text, "WEB\n") || strings.HasPrefix(text, "WEB\r\n") {
			types = append(types, "application/x-iqy")
		}
		if strings.Contains(text, "Manifest-Version:") {
			types = append(types, "application/x-jar-manifest")
		}
	}

	// Always include wildcard for universal scanners
	types = append(types, "*")

	return types
}
