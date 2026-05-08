// Copyright 2019 Jason Ertel (github.com/jertel).
// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package salt

import (
	"strings"
)

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
