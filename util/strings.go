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

func TabsToSpaces(s string, spaceCount uint) string {
	lines := strings.Split(s, "\n")
	fakeTab := strings.Repeat(" ", int(spaceCount))

	for i := range lines {
		tabs := 0
		for _, c := range lines[i] {
			if c == '\t' {
				tabs++
			} else {
				break
			}
		}

		if tabs != 0 {
			lines[i] = strings.Repeat(fakeTab, tabs) + strings.TrimLeft(lines[i], "\t")
		}
	}

	return strings.Join(lines, "\n")
}

func Compare(a, b *string) bool {
	if a == nil && b == nil {
		return true
	} else if a == nil || b == nil {
		return false
	}

	return *a == *b
}
