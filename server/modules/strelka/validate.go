// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package strelka

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/security-onion-solutions/securityonion-soc/util"
)

type parseState int

const (
	parseStateImportsID parseState = iota
	parseStateWatchForHeader
	parseStateInSection
)

type YaraRule struct {
	Imports    []string
	Identifier string
	Meta       Metadata
	Strings    []string
	Condition  string
}

type Metadata struct {
	Author      *string
	Date        *string
	Version     *string
	Reference   *string
	Description *string
	Rest        map[string]string
}

func (md *Metadata) IsEmpty() bool {
	return md.Author == nil && md.Date == nil && md.Version == nil && md.Reference == nil && md.Description == nil && len(md.Rest) == 0
}

func (md *Metadata) Set(key, value string) {
	key = strings.ToLower(key)
	switch key {
	case "author":
		md.Author = util.Ptr(value)
	case "date":
		md.Date = util.Ptr(value)
	case "version":
		md.Version = util.Ptr(value)
	case "reference":
		md.Reference = util.Ptr(value)
	case "description":
		md.Description = util.Ptr(value)
	default:
		if md.Rest == nil {
			md.Rest = make(map[string]string)
		}
		md.Rest[key] = value
	}
}

func ParseYaraRules(data []byte) ([]*YaraRule, error) {
	rules := []*YaraRule{}
	rule := &YaraRule{}

	state := parseStateImportsID

	raw := string(data)
	buffer := bytes.NewBuffer([]byte{})
	last := ' '
	curCommentType := ' ' // either '/' or '*' if in a comment, ' ' if not in comment
	curHeader := ""       // meta, strings, condition, or empty if not yet in a section
	curQuotes := ' '      // either ' or " if in a string, ' ' if not in a string

	for i, r := range raw {
		if r == '\r' {
			continue
		}
		if (curCommentType == '*' && last == '*' && r == '/') ||
			(curCommentType == '/' && r == '\n') {
			curCommentType = ' '

			if last == '*' {
				last = r
				continue
			}
		}

		if last == '/' && curQuotes == ' ' && curCommentType == ' ' {
			if r == '/' {
				curCommentType = '/'
				if buffer.Len() != 0 {
					buffer.Truncate(buffer.Len() - 1)
				}
			} else if r == '*' {
				curCommentType = '*'
				if buffer.Len() != 0 {
					buffer.Truncate(buffer.Len() - 1)
				}
			}
		}

		if curCommentType != ' ' {
			// in a comment, skip everything
			last = r
			continue
		}

	reevaluateState:
		switch state {
		case parseStateImportsID:
			switch r {
			case '\n':
				// is this an import?
				buf := buffer.String() // expected: `import "foo"`
				if strings.HasPrefix(buf, "import ") {
					buf = strings.TrimSpace(strings.TrimPrefix(buf, "import "))
					buf = strings.Trim(buf, `"`)

					rule.Imports = append(rule.Imports, buf)

					buffer.Reset()
				}
			case '{':
				buf := strings.TrimSpace(buffer.String()) // expected: `rule foo {` or `rule foo\n{`
				buf = strings.TrimSpace(strings.TrimPrefix(buf, "rule"))

				if strings.Contains(buf, ":") {
					// gets rid of inheritance?
					// rule This : That {...} becomes "This"
					parts := strings.SplitN(buf, ":", 2)
					buf = strings.TrimSpace(parts[0])
				}

				if buf != "" {
					rule.Identifier = buf
				} else {
					return nil, errors.New(fmt.Sprintf("expected rule identifier at %d", i))
				}

				buffer.Reset()

				state = parseStateWatchForHeader
			default:
				buffer.WriteRune(r)
			}
		case parseStateWatchForHeader:
			buf := strings.TrimSpace(buffer.String())
			if r == '\n' && len(buf) != 0 && buf[len(buf)-1] == ':' {
				curHeader = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(buf, ":")))
				buffer.Reset()

				if curHeader != "meta" &&
					curHeader != "strings" &&
					curHeader != "condition" {
					return nil, errors.New(fmt.Sprintf("unexpected header at %d: %s", i, curHeader))
				}

				state = parseStateInSection
			} else {
				buffer.WriteRune(r)
			}
		case parseStateInSection:
			if r == '\n' {
				buf := strings.TrimSpace(buffer.String())
				if len(buf) != 0 && buf[len(buf)-1] == ':' && !strings.HasPrefix(buf, "for ") {
					// found a header, new section
					state = parseStateWatchForHeader
					goto reevaluateState
				} else {
					if buf != "" {
						switch curHeader {
						case "meta":
							parts := strings.SplitN(buf, "=", 2)
							if len(parts) != 2 {
								return nil, errors.New(fmt.Sprintf("invalid meta line at %d: %s", i, buf))
							}

							key := strings.TrimSpace(parts[0])
							value := strings.TrimSpace(parts[1])

							rule.Meta.Set(key, value)
						case "strings":
							rule.Strings = append(rule.Strings, buf)
						case "condition":
							rule.Condition = strings.TrimSpace(rule.Condition + " " + buf)
						}
					}

					buffer.Reset()
				}
			} else if r == '}' && len(strings.TrimSpace(buffer.String())) == 0 && curQuotes != '}' {
				// end of rule
				rules = append(rules, rule)
				imports := rule.Imports
				buffer.Reset()

				state = parseStateImportsID
				curHeader = ""
				curQuotes = ' '
				rule = &YaraRule{}

				if len(imports) > 0 {
					rule.Imports = append([]string{}, imports...)
				}
			} else {
				buffer.WriteRune(r)
				if (r == '\'' || r == '"' || r == '{') && last != '\\' && curQuotes == ' ' {
					// starting a string
					if r == '{' {
						curQuotes = '}'
					} else {
						curQuotes = r
					}
				} else if curQuotes != ' ' && r == curQuotes && last != '\\' {
					// ending a string
					curQuotes = ' '
				}
			}
		}

		if r == '\\' && last == '\\' && curQuotes != ' ' {
			// this is an escaped slash in the middle of a string,
			// so we need to remove the previous slash so it's not
			// mistaken for an escape character in case this is the
			// last character in the string
			last = ' '
		} else {
			last = r
		}
	}

	if state != parseStateImportsID || len(strings.TrimSpace(buffer.String())) != 0 {
		return nil, errors.New("unexpected end of rule")
	}

	return rules, nil
}

func (r *YaraRule) String() string {
	buffer := bytes.NewBuffer([]byte{})

	// imports
	for _, i := range r.Imports {
		line := fmt.Sprintf("import \"%s\"\n", i)
		buffer.WriteString(line)
	}

	if len(r.Imports) > 0 {
		buffer.WriteString("\n")
	}

	// identifier
	buffer.WriteString(fmt.Sprintf("rule %s {\n", r.Identifier))

	// meta
	if !r.Meta.IsEmpty() {
		buffer.WriteString("\tmeta:\n")

		if r.Meta.Author != nil {
			buffer.WriteString(fmt.Sprintf("\t\tauthor = %s\n", *r.Meta.Author))
		}

		if r.Meta.Date != nil {
			buffer.WriteString(fmt.Sprintf("\t\tdate = %s\n", *r.Meta.Date))
		}

		if r.Meta.Version != nil {
			buffer.WriteString(fmt.Sprintf("\t\tversion = %s\n", *r.Meta.Version))
		}

		if r.Meta.Reference != nil {
			buffer.WriteString(fmt.Sprintf("\t\treference = %s\n", *r.Meta.Reference))
		}

		if r.Meta.Description != nil {
			buffer.WriteString(fmt.Sprintf("\t\tdescription = %s\n", *r.Meta.Description))
		}

		keys := []string{}
		for k := range r.Meta.Rest {
			keys = append(keys, k)
		}

		sort.Strings(keys)

		for _, k := range keys {
			buffer.WriteString(fmt.Sprintf("\t\t%s = %s\n", k, r.Meta.Rest[k]))
		}

		buffer.WriteString("\n")
	}

	// strings
	if len(r.Strings) > 0 {
		buffer.WriteString("\tstrings:\n")

		for _, s := range r.Strings {
			buffer.WriteString(fmt.Sprintf("\t\t%s\n", s))
		}
	}

	// condition and closing bracket
	buffer.WriteString(fmt.Sprintf("\n\tcondition:\n\t\t%s\n}", r.Condition))

	return buffer.String()
}

func (r *YaraRule) Validate() error {
	missing := []string{}

	if r.Identifier == "" {
		missing = append(missing, "identifier")
	}

	if r.Condition == "" {
		missing = append(missing, "condition")
	}

	if len(missing) > 0 {
		return fmt.Errorf("missing required fields: %s", strings.Join(missing, ", "))
	}

	return nil
}
