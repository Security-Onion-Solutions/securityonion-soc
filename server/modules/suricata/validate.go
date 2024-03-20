// Copyright 2020-2023 Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0 as shown at
// https://securityonion.net/license; you may not use this file except in compliance with the
// Elastic License 2.0.

package suricata

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/samber/lo"
	"github.com/security-onion-solutions/securityonion-soc/util"
)

type SuricataRule struct {
	Action      string
	Protocol    string
	Source      string
	Direction   string
	Destination string
	Options     []*RuleOption
}

type RuleOption struct {
	Name  string
	Value *string
}

type MetaData struct {
	Key   string
	Value string
}

type state int

const (
	stateAction state = iota
	stateProtocol
	stateSource
	stateDirection
	stateDestination
	stateOptions
)

func ParseSuricataRule(rule string) (*SuricataRule, error) {
	r := strings.NewReader(rule)
	curState := stateAction
	buf := strings.Builder{}
	inQuotes := false
	isEscaping := false

	out := &SuricataRule{
		Options: []*RuleOption{},
	}

	for r.Len() != 0 {
		ch, _, _ := r.ReadRune()

		switch curState {
		case stateAction:
			if ch == ' ' && buf.Len() != 0 {
				out.Action = strings.TrimSpace(buf.String())
				buf.Reset()
				curState = stateProtocol
			} else if !unicode.IsSpace(ch) {
				buf.WriteRune(ch)
			}
		case stateProtocol:
			if ch == ' ' && buf.Len() != 0 {
				out.Protocol = strings.TrimSpace(buf.String())
				buf.Reset()
				curState = stateSource
			} else if !unicode.IsSpace(ch) {
				buf.WriteRune(ch)
			}
		case stateSource:
			if ch == '<' || ch == '-' {
				out.Source = strings.TrimSpace(buf.String())
				buf.Reset()
				buf.WriteRune(ch)
				curState = stateDirection
			} else {
				buf.WriteRune(ch)
			}
		case stateDirection:
			if ch == ' ' {
				out.Direction = strings.TrimSpace(buf.String())
				if out.Direction != "<>" && out.Direction != "->" {
					return nil, fmt.Errorf("invalid direction, must be '<>' or '->', got %s", out.Direction)
				}

				buf.Reset()
				curState = stateDestination
			} else {
				buf.WriteRune(ch)
			}
		case stateDestination:
			if ch == '(' {
				out.Destination = strings.TrimSpace(buf.String())
				buf.Reset()
				curState = stateOptions
			} else {
				buf.WriteRune(ch)
			}
		case stateOptions:
			if ch == ')' && !inQuotes && !isEscaping && len(strings.TrimSpace(buf.String())) == 0 {
				if r.Len() != 0 {
					// end of options, but not end of rule?
					return nil, fmt.Errorf("invalid rule, expected end of rule, got %d more bytes", r.Len())
				}
			} else if ch == ';' && !inQuotes && !isEscaping {
				option := strings.TrimSpace(buf.String())
				buf.Reset()

				split := strings.SplitN(option, ":", 2)
				opt := &RuleOption{
					Name: strings.TrimSpace(split[0]),
				}

				if len(split) == 2 {
					opt.Value = util.Ptr(strings.TrimSpace(split[1]))
				}

				out.Options = append(out.Options, opt)
			} else if ch == '"' {
				buf.WriteRune(ch)
				if isEscaping {
					isEscaping = false
				} else {
					if strings.Contains(buf.String(), "pcre:") {
						// is the current option a regular expression?
						// if so, only end the quotes if the next character is a semicolon
						next, _, _ := r.ReadRune()
						r.UnreadRune()

						if next == ';' {
							inQuotes = false
						}
					} else {
						inQuotes = !inQuotes
					}
				}
			} else if ch == '\\' && !isEscaping {
				isEscaping = true
				buf.WriteRune(ch)
			} else {
				isEscaping = false
				buf.WriteRune(ch)
			}
		}
	}

	if curState != stateOptions || len(strings.TrimSpace(buf.String())) != 0 {
		// We're unexpectedly done parsing the rule.
		return nil, fmt.Errorf("invalid rule, unexpected end of rule")
	}

	return out, nil
}

func (rule *SuricataRule) GetOption(key string) (value *string, ok bool) {
	for _, opt := range rule.Options {
		if strings.EqualFold(opt.Name, key) {
			return opt.Value, true
		}
	}

	return nil, false
}

func (rule *SuricataRule) ParseMetaData() []*MetaData {
	mdOpt, ok := rule.GetOption("metadata")
	if !ok || mdOpt == nil {
		return nil
	}

	md := []*MetaData{}

	parts := strings.Split(*mdOpt, ",")
	for _, part := range parts {
		part = strings.TrimSuffix(strings.TrimSpace(part), ",")
		kv := strings.SplitN(part, " ", 2)
		if len(kv) == 1 {
			kv = append(kv, "")
		}

		md = append(md, &MetaData{Key: strings.TrimSpace(kv[0]), Value: strings.TrimSpace(kv[1])})
	}

	return md
}

func (rule *SuricataRule) String() string {
	opts := make([]string, 0, len(rule.Options))
	md := rule.ParseMetaData()
	for _, opt := range rule.Options {
		if opt.Name == "metadata" && len(md) != 0 {
			value := strings.Join(lo.Map(md, func(m *MetaData, _ int) string {
				return fmt.Sprintf("%s %s", m.Key, m.Value)
			}), ", ")
			opts = append(opts, fmt.Sprintf("%s:%s;", opt.Name, value))
		} else if opt.Value == nil {
			opts = append(opts, fmt.Sprintf("%s;", opt.Name))
		} else {
			opts = append(opts, fmt.Sprintf("%s:%s;", opt.Name, *opt.Value))
		}
	}

	return fmt.Sprintf("%s %s %s %s %s (%s)", rule.Action, rule.Protocol, rule.Source, rule.Direction, rule.Destination, strings.Join(opts, " "))
}
