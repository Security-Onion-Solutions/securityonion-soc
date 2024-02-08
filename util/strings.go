package util

import "strings"

func Unquote(value string) string {
	if strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
		value = strings.TrimSuffix(strings.TrimPrefix(value, `"`), `"`)
	} else if strings.HasPrefix(value, "'") && strings.HasSuffix(value, "'") {
		value = strings.TrimSuffix(strings.TrimPrefix(value, "'"), "'")
	}

	return value
}
