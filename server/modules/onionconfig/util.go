// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package onionconfig

import (
	"fmt"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/json"
)

// FlattenInterfaceSliceToString converts a slice of interface{} to a newline-separated string,
// where nested slices/maps are JSON encoded.
func FlattenInterfaceSliceToString(val []interface{}) string {
	var newValue string
	for _, item := range val {
		var str string
		switch item.(type) {
		case []interface{}, map[string]interface{}:
			bytes, _ := json.WriteJson(item)
			str = string(bytes)
		default:
			str = fmt.Sprintf("%v", item)
		}

		if str != "" {
			newValue = newValue + str + "\n"
		}
	}
	return newValue
}


// RelPathFromId converts a setting ID (dot-separated) to a relative file path.
// Example: soc.files.soc.banner_md -> soc/files/soc/banner.md
func RelPathFromId(id string) string {
	relpath := strings.ReplaceAll(id, ".", "/")
	relpath = strings.ReplaceAll(relpath, "__", ".")
	relpath = strings.ReplaceAll(relpath, "..", "____") // Shenannigans
	return relpath
}

func CastToStringArray(value interface{}) []string {
	values := make([]string, 0)
	tmpArray := value.([]interface{})
	for _, tmp := range tmpArray {
		values = append(values, tmp.(string))
	}
	return values
}
